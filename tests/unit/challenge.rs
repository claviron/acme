use std::fs;
use std::os::unix::fs::symlink;

use super::*;

const TOKEN: &str = "LoqXcYV8q5ONbJQxbmR7SCTNo3tiAXDfowyjxAjEuX0";

#[tokio::test]
async fn http01_rejects_non_protocol_tokens_before_filesystem_access() {
    let root = tempfile::tempdir().unwrap();
    let missing = root.path().join("missing");
    for token in [
        "",
        ".",
        "..",
        "../sentinel",
        "/absolute",
        "nested/token",
        "..\\sentinel",
        "C:\\sentinel",
        "token=",
        "token+suffix",
        "%2e%2e%2fsentinel",
        "a.b",
        "a\0b",
        "a b",
        "a\nb",
        "ü",
    ] {
        assert!(
            matches!(
                Challenge::create(&missing, token, "authorization".into())
                    .await,
                Err(AcmeError::InvalidChallengeToken)
            ),
            "accepted token {token:?}"
        );
    }
    assert!(!missing.exists());
    assert_eq!(fs::read_dir(root.path()).unwrap().count(), 0);
}

#[tokio::test]
async fn http01_owns_one_file_without_overwriting_an_existing_challenge() {
    let root = tempfile::tempdir().unwrap();
    let file = Challenge::create(root.path(), TOKEN, "authorization".into())
        .await
        .unwrap();
    assert_eq!(fs::read(root.path().join(TOKEN)).unwrap(), b"authorization");
    assert!(
        Challenge::create(root.path(), TOKEN, "replacement".into())
            .await
            .is_err()
    );
    assert_eq!(fs::read(root.path().join(TOKEN)).unwrap(), b"authorization");
    drop(file);
    assert!(!root.path().join(TOKEN).exists());
    let file =
        Challenge::create(root.path(), TOKEN, "new authorization".into())
            .await
            .unwrap();
    drop(file);
    assert_eq!(fs::read_dir(root.path()).unwrap().count(), 0);
}

#[tokio::test]
async fn http01_rejects_symlinks_hardlinks_and_regular_file_collisions() {
    let root = tempfile::tempdir().unwrap();
    let directory = root.path().join("challenges");
    fs::create_dir(&directory).unwrap();
    let sentinel = root.path().join("sentinel");
    fs::write(&sentinel, "untouched").unwrap();
    let path = directory.join(TOKEN);
    for kind in ["symlink", "hardlink", "regular"] {
        match kind {
            "symlink" => symlink(&sentinel, &path).unwrap(),
            "hardlink" => fs::hard_link(&sentinel, &path).unwrap(),
            _ => fs::write(&path, "untouched").unwrap(),
        }
        assert!(
            Challenge::create(&directory, TOKEN, "replacement".into())
                .await
                .is_err()
        );
        assert_eq!(fs::read(&sentinel).unwrap(), b"untouched");
        assert_eq!(fs::read(&path).unwrap(), b"untouched");
        fs::remove_file(&path).unwrap();
    }
    symlink(root.path().join("absent"), &path).unwrap();
    assert!(
        Challenge::create(&directory, TOKEN, "replacement".into())
            .await
            .is_err()
    );
    assert!(!root.path().join("absent").exists());
    assert!(fs::symlink_metadata(&path).unwrap().is_symlink());
}

#[tokio::test]
async fn http01_cleanup_stays_in_the_pinned_directory_after_parent_replacement()
{
    let root = tempfile::tempdir().unwrap();
    let directory = root.path().join("challenges");
    let outside = root.path().join("outside");
    let moved = root.path().join("original");
    fs::create_dir(&directory).unwrap();
    fs::create_dir(&outside).unwrap();
    fs::write(outside.join(TOKEN), "untouched").unwrap();
    let file = Challenge::create(&directory, TOKEN, "authorization".into())
        .await
        .unwrap();
    fs::rename(&directory, &moved).unwrap();
    symlink(&outside, &directory).unwrap();
    drop(file);
    assert_eq!(fs::read(outside.join(TOKEN)).unwrap(), b"untouched");
    assert!(!moved.join(TOKEN).exists());
}

#[tokio::test]
async fn http01_request_rejects_traversal_and_cleans_up_errors_and_cancellation()
 {
    use crate::clients::CertClient;
    use crate::cryptex::keys::generate_acme_key_with_jwk;
    use claviron::ssl::{Algorithm, Organization, generators};

    for (token, cancel) in
        [("../sentinel", false), (TOKEN, false), (TOKEN, true)]
    {
        let root = tempfile::tempdir().unwrap();
        let directory = root.path().join("challenges");
        fs::create_dir(&directory).unwrap();
        let sentinel = root.path().join("sentinel");
        fs::write(&sentinel, "untouched").unwrap();
        let (http, mut mock) = issuer::start(token, cancel).await;
        let (key, jwk) = generate_acme_key_with_jwk(&Algorithm::ES256).unwrap();
        let client = CertClient::with_client(
            http,
            &key,
            "http://issuer.test/acme/account/1",
        )
        .unwrap();
        let csr_key = generators::generate_private_key().unwrap();
        let csr = generators::generate_server_csr(
            &csr_key,
            &"example.test".parse().unwrap(),
            vec!["example.test".into()],
            &Organization::default(),
        )
        .unwrap();
        let request_directory = directory.clone();
        let mut request = tokio::spawn(async move {
            client.request_certificate(csr.der(), &jwk, request_directory).await
        });
        if cancel {
            tokio::select! {
                result = &mut mock.entered => result.unwrap(),
                result = &mut request => panic!("request ended before challenge acknowledgement: {result:?}"),
            }
            assert!(directory.join(TOKEN).is_file());
            request.abort();
            assert!(request.await.unwrap_err().is_cancelled());
        } else {
            let result = request.await.unwrap();
            if token == "../sentinel" {
                assert!(matches!(
                    result,
                    Err(AcmeError::InvalidChallengeToken)
                ));
            } else {
                assert!(matches!(result, Err(AcmeError::InvalidOrderStatus)));
            }
        }
        mock.task.abort();
        let _ = mock.task.await;
        assert_eq!(fs::read(sentinel).unwrap(), b"untouched");
        assert_eq!(fs::read_dir(directory).unwrap().count(), 0);
    }
}

use crate::issuer;
