use crate::AcmeError;
use crate::clients::{AccountClient, CertClient};
use crate::cryptex::keys::generate_acme_key_with_jwk;
use claviron::ssl::{Algorithm, Organization, generators};

use crate::issuer::{self, Reply, order_replies};

#[tokio::test]
async fn acme_response_rejects_errors_at_every_certificate_endpoint() {
    let (key, jwk) = generate_acme_key_with_jwk(&Algorithm::ES256).unwrap();
    let csr_key = generators::generate_private_key().unwrap();
    let csr = generators::generate_server_csr(
        &csr_key,
        &"example.test".parse().unwrap(),
        vec!["example.test".into()],
        &Organization::default(),
    )
    .unwrap();
    let problem = r#"{"type":"urn:ietf:params:acme:error:unauthorized","detail":"fixture denied","subproblems":[{"detail":"identifier rejected"}]}"#;
    // Include the repeated nonce, challenge and order exchanges, not just
    // their first occurrence: every signed response crosses the same check.
    for index in 0..order_replies("certificate fixture", true).len() {
        for (status, body) in [
            (500, "fixture-error-body"),
            (403, problem),
            (302, "unexpected redirect"),
        ] {
            let mut replies = order_replies("certificate fixture", true);
            let path = replies[index].path;
            replies[index].status = status;
            // HEAD cannot carry a body; its status must still be retained.
            let expected = if path == "/acme/new-nonce" { "" } else { body };
            replies[index].body = expected.into();
            let (http, mock) = issuer::scripted(replies).await;
            let client = CertClient::with_client(
                http,
                &key,
                "http://issuer.test/acme/account/1",
            )
            .unwrap();
            let root = tempfile::tempdir().unwrap();
            let result =
                client.request_certificate(csr.der(), &jwk, root.path()).await;
            mock.task.abort();
            let _ = mock.task.await;
            match result {
                Err(AcmeError::HttpResponse { status: actual, url, body }) => {
                    assert_eq!(actual.as_u16(), status);
                    assert_eq!(url, format!("http://issuer.test{path}"));
                    assert_eq!(body, expected);
                }
                other => panic!("endpoint {path} returned {other:?}"),
            }
            assert_eq!(std::fs::read_dir(root.path()).unwrap().count(), 0);
        }
    }
}

#[tokio::test]
async fn acme_response_preserves_success_and_invalid_order_behavior() {
    let (key, jwk) = generate_acme_key_with_jwk(&Algorithm::ES256).unwrap();
    let csr_key = generators::generate_private_key().unwrap();
    let csr = generators::generate_server_csr(
        &csr_key,
        &"example.test".parse().unwrap(),
        vec!["example.test".into()],
        &Organization::default(),
    )
    .unwrap();
    for invalid in [false, true] {
        let mut replies = order_replies("certificate fixture", false);
        if invalid {
            replies
                .iter_mut()
                .find(|reply| reply.path == "/order")
                .unwrap()
                .body = r#"{"status":"invalid"}"#.into();
        }
        let (http, mock) = issuer::scripted(replies).await;
        let client = CertClient::with_client(
            http,
            &key,
            "http://issuer.test/acme/account/1",
        )
        .unwrap();
        let root = tempfile::tempdir().unwrap();
        let result =
            client.request_certificate(csr.der(), &jwk, root.path()).await;
        mock.task.abort();
        let _ = mock.task.await;
        if invalid {
            assert!(matches!(result, Err(AcmeError::InvalidOrderStatus)));
        } else {
            assert_eq!(result.unwrap(), "certificate fixture");
        }
        assert_eq!(std::fs::read_dir(root.path()).unwrap().count(), 0);
    }
}

#[tokio::test]
async fn acme_response_accounts_use_the_same_status_and_problem_check() {
    let (key, jwk) = generate_acme_key_with_jwk(&Algorithm::ES256).unwrap();
    for failed in [None, Some(0), Some(1), Some(2)] {
        let mut account = Reply::new("/account", 201, "{}");
        account.headers =
            "Location: http://issuer.test/acme/account/1\r\n".into();
        let mut replies = vec![
            Reply::new(
                "/directory",
                200,
                r#"{"newNonce":"http://issuer.test/acme/new-nonce","newAccount":"http://issuer.test/account"}"#,
            ),
            Reply::nonce(),
            account,
        ];
        if let Some(index) = failed {
            replies[index].status = 503;
            replies[index].body =
                if index == 1 { "" } else { "account unavailable" }.into();
        }
        let (http, mock) = issuer::scripted(replies).await;
        let result = AccountClient::with_client(http, "http://issuer.test")
            .register_account(&key, &jwk)
            .await;
        mock.task.abort();
        let _ = mock.task.await;
        if failed.is_some() {
            assert!(
                matches!(result, Err(AcmeError::HttpResponse { status, .. }) if status.as_u16() == 503)
            );
        } else {
            assert_eq!(result.unwrap(), "http://issuer.test/acme/account/1");
        }
    }
}
