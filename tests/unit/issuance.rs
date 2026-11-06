use super::*;
use crate::cryptex::keys::generate_acme_key_with_jwk;
use crate::issuer::{self, Reply, order_replies};
use claviron::ssl::{Algorithm, generators};

#[tokio::test]
async fn acme_response_issuance_logs_cover_validation_and_persistence() {
    let (account_key, jwk) =
        generate_acme_key_with_jwk(&Algorithm::ES256).unwrap();
    let ca_key = generators::generate_ca_key().unwrap();
    let ca = generators::generate_ca_cert(
        &"authority.test".parse().unwrap(),
        &ca_key,
        30,
        &Default::default(),
    )
    .unwrap();
    let key = generators::generate_private_key().unwrap();
    let certificate = generators::generate_leaf_cert(
        claviron::hosting::CertificateKind::Server,
        &"example.test".parse().unwrap(),
        &key,
        ca.as_ref(),
        &ca_key,
        1,
        &[] as &[String],
    )
    .unwrap();
    let pem = certificate_chain_to_pem(certificate.as_ref()).unwrap();
    let original_der = certificate.to_vec();

    for renew in [false, true] {
        for failure in ["http", "pem", "storage", "none"] {
            let root = tempfile::tempdir().unwrap();
            let cfg: AcmeConfig = serde_json::from_value(serde_json::json!({
                "base_dir":root.path(), "challenges_dir":root.path(),
                "production_url":"http://issuer.test", "staging_url":"http://issuer.test",
                "organization":{"name":"Example", "email":"operator@example.test"},
                "pre-validation":false, "renew_before":30, "algorithm":"ES256"
            })).unwrap();
            let pool = sqlx::sqlite::SqlitePoolOptions::new()
                .max_connections(1)
                .connect("sqlite::memory:")
                .await
                .unwrap();
            sqlx::raw_sql(include_str!("fixtures/issuance.sql"))
                .execute(&pool)
                .await
                .unwrap();
            sqlx::query("INSERT INTO hosting_acme_accounts (id, name, url, issuer_id, private_key, jwk, algorithm, email, organization, created_at, is_default) VALUES (1, 'fixture', 'http://issuer.test/acme/account/1', 1, $1, $2, 'ES256', 'operator@example.test', 'Example', $3, TRUE)")
                .bind(&account_key).bind(serde_json::to_value(&jwk).unwrap()).bind(OffsetDateTime::now_utc()).execute(&pool).await.unwrap();
            sqlx::query("INSERT INTO hosting_certificate_issuers (id, name, kind, acme_account_id) VALUES (1, 'fixture', 'acme', 1)").execute(&pool).await.unwrap();
            let hosting = HostingStore::sqlite(pool.clone());
            let acme = AcmeStore::sqlite(pool.clone());
            let cn: Sni = "example.test".parse().unwrap();
            let existing = if renew {
                Some(
                    hosting
                        .insert_certificate(
                            NewCertificate {
                                kind:
                                    claviron::hosting::CertificateKind::Server,
                                issuer_id: Some(1),
                                cn: cn.to_string(),
                                certs_der: original_der.clone(),
                                key_der: key.serialize_der(),
                                expires_at: OffsetDateTime::now_utc(),
                                issued_at: OffsetDateTime::now_utc(),
                                enabled: true,
                            },
                            &[],
                            1,
                        )
                        .await
                        .unwrap(),
                )
            } else {
                None
            };

            // The database observes the real operation boundary: success must
            // not be recorded before either creation or renewal is persisted.
            sqlx::raw_sql("CREATE TRIGGER require_pending_insert BEFORE INSERT ON hosting_certificates BEGIN SELECT CASE WHEN (SELECT status FROM hosting_acme_logs ORDER BY id DESC LIMIT 1) <> 'pending' THEN RAISE(ABORT, 'success recorded before insert') END; END;
                CREATE TRIGGER require_pending_update BEFORE UPDATE ON hosting_certificates BEGIN SELECT CASE WHEN (SELECT status FROM hosting_acme_logs ORDER BY id DESC LIMIT 1) <> 'pending' THEN RAISE(ABORT, 'success recorded before update') END; END;")
                .execute(&pool).await.unwrap();
            if failure == "storage" {
                sqlx::raw_sql("CREATE TRIGGER reject_insert BEFORE INSERT ON hosting_certificates BEGIN SELECT RAISE(ABORT, 'fixture persistence error'); END;
                    CREATE TRIGGER reject_update BEFORE UPDATE ON hosting_certificates BEGIN SELECT RAISE(ABORT, 'fixture persistence error'); END;")
                    .execute(&pool).await.unwrap();
            }
            let body =
                if failure == "pem" { "not a certificate" } else { &pem };
            let mut replies = order_replies(body, false);
            if failure == "http" {
                *replies.last_mut().unwrap() =
                    Reply::new("/certificate", 500, "fixture-error-body");
            }
            let (http, mock) = issuer::scripted(replies).await;
            let result = if let Some(existing) = existing {
                renew_with_client(
                    &acme,
                    &hosting,
                    &cfg,
                    existing,
                    false,
                    || Ok(http),
                )
                .await
                .map(|_| ())
            } else {
                add_with_client(
                    &acme,
                    &hosting,
                    1,
                    &cn,
                    std::slice::from_ref(&cn),
                    &cfg,
                    || Ok(http),
                )
                .await
                .map(|_| ())
            };
            mock.task.abort();
            let _ = mock.task.await;
            let (status, detail): (String, Option<String>) = sqlx::query_as(
                "SELECT status, error_message FROM hosting_acme_logs",
            )
            .fetch_one(&pool)
            .await
            .unwrap();
            assert_eq!(
                result.is_ok(),
                failure == "none",
                "renew={renew}, failure={failure}: {result:?}"
            );
            assert_eq!(
                status,
                if failure == "none" { "success" } else { "failed" }
            );
            if failure == "none" {
                assert!(detail.is_none());
            } else {
                assert!(
                    detail.as_ref().is_some_and(|message| !message.is_empty())
                );
            }
            if failure == "http" {
                assert!(
                    matches!(result, Err(AcmeError::HttpResponse { status, .. }) if status.as_u16() == 500)
                );
                assert!(detail.unwrap().contains("fixture-error-body"));
            }
            let saved = hosting.certificate_by_cn(cn.as_str()).await.unwrap();
            assert_eq!(saved.is_some(), renew || failure == "none");
            if renew && failure != "none" {
                assert_eq!(saved.unwrap().certificate.certs_der, original_der);
            }
        }
    }
}
