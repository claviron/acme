use std::fs;
use std::path::PathBuf;
use std::sync::Arc;

use account::{CERT_META_PATH, CERT_TEXT_PATH, CSR_FILE_NAME};
use claviron::ssl::certstore::FULLCHAIN_CERT_FILENAME;
use claviron::ssl::formatters::parse_text_from_pem;
use claviron::ssl::parsers::sanitize_pem_content_to_der;
use tracing::{debug, error, warn};

use crate::account::Account;
use crate::clients::{CertClient, acme_client};
use crate::meta::CertMeta;
use crate::{AcmeError, account};

pub async fn renew_cert(
    account: Arc<Account>,
    meta: &mut CertMeta,
    challenges_dir: &PathBuf,
) -> Result<(), AcmeError> {
    if !account.mode.is_production() {
        return Err(AcmeError::from(
            "Renewal requests are processed only in production mode",
        ));
    }

    let account_key = account.private_key();

    let cname = &meta.cn;
    let cert_dir = account.cert_dir(cname);

    if !cert_dir.exists() {
        return Err(
            "Certificate directory does not exist! Please generate a new certificate.".into()
        );
    }

    let csr_path = cert_dir.join(CSR_FILE_NAME);
    let fullchain_path = cert_dir.join(FULLCHAIN_CERT_FILENAME);
    let text_path = cert_dir.join(CERT_TEXT_PATH);
    let meta_path = cert_dir.join(CERT_META_PATH);

    let csr_content = fs::read(&csr_path).map_err(|e| {
        AcmeError::io_error("❌ Failed to read CSR", &csr_path, e)
    })?;
    let csr = sanitize_pem_content_to_der(&csr_content);

    debug!("CSR file path: {}", csr_path.to_string_lossy().to_string());

    // Create the staging client
    let acme_client = acme_client()?;
    let client =
        CertClient::with_client(acme_client, account_key, &account.url)
            .map_err(|e| AcmeError::ClientCreationFailed(e.to_string()))?;

    let cert = client
        .request_certificate(csr.as_ref(), &account.jwk, challenges_dir)
        .await
        .map_err(|e| {
            AcmeError::CertificateFailed(format!("Staging failed: {:?}", e))
        })?;

    meta.update_with_renewed(cert.as_bytes())?;

    debug!("Certificate client successful");

    let text = parse_text_from_pem(cert.as_bytes()).unwrap_or_else(|e| {
        warn!("❌ Failed to parse certificate text: {}", e);
        String::new()
    });

    let meta_json = serde_json::to_string_pretty(&meta)?;

    fs::write(&fullchain_path, &cert).map_err(|e| {
        AcmeError::io_error(
            "❌  Failed to write CERT to file",
            &fullchain_path,
            e,
        )
    })?;

    if fs::write(&meta_path, &meta_json).is_err() {
        error!("❌️ Failed to write Meta file {}", csr_path.to_string_lossy())
    }

    if fs::write(&text_path, &text).is_err() {
        warn!("⚠️  Failed to write certificate text to file");
    }

    Ok(())
}
