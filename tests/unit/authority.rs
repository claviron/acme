use super::*;

#[tokio::test]
async fn dns01_waits_for_visibility_before_asking_the_ca() {
    use std::sync::atomic::{AtomicBool, Ordering};

    use crate::cryptex::keys::generate_acme_key_with_jwk;
    use crate::dns01::{
        PublishError, TxtPublication, TxtPublisher, Visibility,
    };
    use crate::issuer::{self, Reply, order_replies};
    use claviron::ssl::{Organization, generators};
    use tokio::sync::{Notify, Semaphore};

    struct Publisher {
        waiting: Notify,
        visible: Semaphore,
        removed: AtomicBool,
    }

    #[derive(Clone)]
    struct Publication(std::sync::Arc<Publisher>);

    #[async_trait::async_trait]
    impl TxtPublisher for Publication {
        async fn publish(
            &self,
            record: TxtRecord,
        ) -> Result<Box<dyn TxtPublication>, PublishError> {
            assert_eq!(record.owner(), "_acme-challenge.example.test.");
            assert_eq!(record.value().len(), 43);
            Ok(Box::new(self.clone()))
        }
    }

    #[async_trait::async_trait]
    impl TxtPublication for Publication {
        async fn wait_visible(
            &self,
            _: Visibility,
        ) -> Result<(), PublishError> {
            self.0.waiting.notify_one();
            self.0.visible.acquire().await?.forget();
            Ok(())
        }

        async fn remove(self: Box<Self>) -> Result<(), PublishError> {
            self.0.removed.store(true, Ordering::Release);
            Ok(())
        }
    }

    let publisher = Publication(std::sync::Arc::new(Publisher {
        waiting: Notify::new(),
        visible: Semaphore::new(0),
        removed: AtomicBool::new(false),
    }));
    let (key, jwk) = generate_acme_key_with_jwk(&Algorithm::ES256).unwrap();
    let csr_key = generators::generate_private_key().unwrap();
    let csr = generators::generate_server_csr(
        &csr_key,
        &"example.test".parse().unwrap(),
        vec!["*.example.test".into()],
        &Organization::default(),
    )
    .unwrap();
    let mut replies = order_replies("issued", false);
    replies[3] = Reply::new("/auth", 200, json!({
        "status": "pending",
        "identifier": {"type": "dns", "value": "example.test"},
        "wildcard": true,
        "challenges": [{"type": "dns-01", "token": "fixture", "url": "http://issuer.test/challenge"}],
    }).to_string());
    let (http, mut mock) = issuer::scripted(replies).await;
    let client = CertClient::with_client(
        http,
        &key,
        "http://issuer.test/acme/account/1",
    )
    .unwrap();
    let mut issuance = std::pin::pin!(
        client.request_certificate_with_challenge(
            csr.der(),
            &jwk,
            OrderChallenge::Dns01(Dns01::new(
                &publisher,
                Visibility::new(
                    Duration::from_secs(60),
                    Duration::from_secs(1)
                )
                .unwrap()
            )),
        )
    );
    tokio::select! {
        result = &mut issuance => panic!("order finished before TXT publication: {result:?}"),
        () = publisher.0.waiting.notified() => {}
    }
    assert!(matches!(
        mock.entered.try_recv(),
        Err(tokio::sync::oneshot::error::TryRecvError::Empty)
    ));
    publisher.0.visible.add_permits(1);
    assert_eq!(issuance.await.unwrap(), "issued");
    mock.entered.await.unwrap();
    mock.task.await.unwrap();
    assert!(publisher.0.removed.load(Ordering::Acquire));
}

#[test]
fn acme_authority_rejects_invalid_account_urls_without_panicking() {
    let http = AcmeClient::builder().no_proxy().build().unwrap();
    for account in [
        "",
        "not-a-url",
        "/acme/account/1",
        "acme/account/1",
        "//issuer.test/acme/account/1",
        "http://",
        "https://",
        "https://?query",
        "https://#fragment",
        "http://[]/account",
        "http://[2001:db8::1/account",
        "https://issuer.test:invalid/account",
        "https://issuer.test:65536/account",
        "https://exa mple.test/account",
        "mailto:operator@example.test",
        "data:text/plain,account",
        "file:///account",
        "file://issuer.test/account",
        "ftp://issuer.test/account",
        "ws://issuer.test/account",
        "wss://[2001:db8::1]:8443/account",
        "about:blank",
    ] {
        assert!(
            matches!(
                CertClient::with_client(http.clone(), "", account),
                Err(AcmeError::ClientCreationFailed(_))
            ),
            "accepted invalid account URL {account:?}"
        );
    }
}

#[test]
fn acme_authority_preserves_ports_ipv6_and_the_account_binding() {
    let http = AcmeClient::builder().no_proxy().build().unwrap();
    for (account, origin) in [
        ("http://issuer.test/acme/account/1", "http://issuer.test"),
        ("http://issuer.test:80/acme/account/1", "http://issuer.test"),
        ("https://issuer.test:443/acme/account/1", "https://issuer.test"),
        ("http://issuer.test:8080/acme/account/1", "http://issuer.test:8080"),
        ("https://issuer.test:8443/acme/account/1", "https://issuer.test:8443"),
        ("HTTPS://ISSUER.TEST:8443/acme/account/1", "https://issuer.test:8443"),
        ("http://192.0.2.1:8080/acme/account/1", "http://192.0.2.1:8080"),
        ("http://[2001:db8::1]:80/acme/account/1", "http://[2001:db8::1]"),
        ("https://[2001:db8::1]:443/acme/account/1", "https://[2001:db8::1]"),
        (
            "http://[2001:db8::1]:8080/acme/account/1",
            "http://[2001:db8::1]:8080",
        ),
        (
            "https://[2001:db8::1]:8443/acme/account/1",
            "https://[2001:db8::1]:8443",
        ),
    ] {
        let client =
            CertClient::with_client(http.clone(), "", account).unwrap();
        assert_eq!(client.base_url, origin);
        assert_eq!(client.account_url, account);
    }
}

#[tokio::test]
async fn acme_authority_routes_nonce_and_order_to_the_configured_port() {
    use crate::cryptex::keys::generate_acme_key_with_jwk;
    use crate::issuer::{self, Reply};
    use claviron::ssl::{Organization, generators};
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use tokio::net::TcpListener;

    let (key, jwk) = generate_acme_key_with_jwk(&Algorithm::ES256).unwrap();
    let csr_key = generators::generate_private_key().unwrap();
    let csr = generators::generate_server_csr(
        &csr_key,
        &"example.test".parse().unwrap(),
        vec!["example.test".into()],
        &Organization::default(),
    )
    .unwrap();
    for ip in [IpAddr::V4(Ipv4Addr::LOCALHOST), IpAddr::V6(Ipv6Addr::LOCALHOST)]
    {
        let listener = TcpListener::bind((ip, 0)).await.unwrap();
        let address = listener.local_addr().unwrap();
        let origin = format!("http://{address}");
        let account = format!("{origin}/acme/account/1");
        let (http, mock) = issuer::direct(
            listener,
            vec![
                Reply::nonce(),
                Reply::new("/acme/new-order", 400, "fixture order reached"),
            ],
        );
        let client = CertClient::with_client(http, &key, &account).unwrap();
        // Check before any network IO: an unfixed client must not probe a
        // default port that may belong to an unrelated local service.
        assert_eq!(client.base_url, origin);
        let directory = tempfile::tempdir().unwrap();
        let result =
            client.request_certificate(csr.der(), &jwk, directory.path()).await;
        mock.task.abort();
        let _ = mock.task.await;
        match result {
            Err(AcmeError::HttpResponse { status, url, body }) => {
                assert_eq!(status.as_u16(), 400);
                assert_eq!(url, format!("{origin}/acme/new-order"));
                assert_eq!(body, "fixture order reached");
            }
            other => panic!("configured endpoint was not reached: {other:?}"),
        }
        assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 0);
    }
}
