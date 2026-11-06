use std::fs;
use std::path::PathBuf;
use std::sync::Arc;

use claviron::ssl::certstore::{FULLCHAIN_CERT_FILENAME, PRIVKEY_FILENAME};
use claviron::ssl::formatters::parse_text_from_pem;
use claviron::ssl::generators::{generate_private_key, generate_server_csr};
use claviron::ssl::{Aliases, Organization, SSLError, Sni};
use tracing::{debug, error, warn};

use crate::AcmeError;
use crate::account::{Account, CERT_META_PATH, CERT_TEXT_PATH, CSR_FILE_NAME};
use crate::clients::{CertClient, acme_client};
use crate::meta::CertMeta;
use crate::validate::validate_acme_url;

pub async fn new_cert(
    account: Arc<Account>,
    cname: &Sni,
    domains: &[Sni],
    organization: &Organization,
    challenges_dir: &PathBuf,
    pre_validation: bool,
) -> Result<String, AcmeError> {
    let cert_dir = account.cert_dir(cname.as_str());
    // Ensure certificate directory exists to avoid ENOENT on writes
    if cert_dir.exists() {
        return Err("Certificate directory already exists! Please try renew or delete dir.".into());
    }

    debug!("Create: new ACME certificate for {:?}", domains);

    if pre_validation {
        validate_acme_url(&challenges_dir, domains).await?;
        debug!("Pre-validation completed successfully");
    }

    let private_key = generate_private_key()?;

    let csr = generate_server_csr(
        &private_key,
        &cname.as_str().parse()?,
        Aliases::from(domains),
        organization,
    )?;

    let csr_pem = csr.pem().map_err(|e| {
        SSLError::Other(format!("❌ Failed to convert CSR to PEM: {}", e))
    })?;

    let account_key = account.private_key();

    // Create the staging client
    let http_client = acme_client()?;
    let client =
        CertClient::with_client(http_client, account_key, &account.url)
            .map_err(|e| AcmeError::ClientCreationFailed(e.to_string()))?;

    debug!("starting certificate creation.");

    let cert = client
        .request_certificate(csr.der(), &account.jwk, challenges_dir)
        .await
        .map_err(|e| {
            AcmeError::CertificateFailed(format!("Staging failed: {:?}", e))
        })?;

    debug!("Certificate creation successful");

    let meta = CertMeta::from_cert(&account, cert.as_bytes())?;
    let meta_json = serde_json::to_string_pretty(&meta)?;

    // Build human-readable text (OpenSSL-like) for debugging/inspection
    let text = parse_text_from_pem(cert.as_bytes()).unwrap_or_else(|e| {
        warn!("❌ Failed to parse certificate text: {}", e);
        String::new()
    });

    let content = format!("{}\n{}\n{}", cert, meta_json, text);

    if !account.mode.is_production() {
        // In staging/non-production, return combined content for display, but keep files for re-use
        return Ok(content);
    }

    fs::create_dir_all(&cert_dir).map_err(|e| {
        AcmeError::io_error(
            "Failed to create certificate directory",
            &cert_dir,
            e,
        )
    })?;

    let csr_path = cert_dir.join(CSR_FILE_NAME);
    let key_path = cert_dir.join(PRIVKEY_FILENAME);
    let fullchain_path = cert_dir.join(FULLCHAIN_CERT_FILENAME);
    let text_path = cert_dir.join(CERT_TEXT_PATH);
    let meta_path = cert_dir.join(CERT_META_PATH);

    let pem_key = private_key.serialize_pem();
    fs::write(&key_path, pem_key.as_bytes()).map_err(|e| {
        AcmeError::io_error(
            "‼️  Failed to write private key to file",
            &key_path,
            e,
        )
    })?;

    fs::write(&fullchain_path, &cert).map_err(|e| {
        AcmeError::io_error(
            "‼️  Failed to write CERT to file",
            &fullchain_path,
            e,
        )
    })?;

    if fs::write(&csr_path, &csr_pem).is_err() {
        error!("❌️ Failed to write CSR file {}", csr_path.to_string_lossy())
    }

    if fs::write(&meta_path, &meta_json).is_err() {
        error!("❌️ Failed to write Meta file {}", csr_path.to_string_lossy())
    }

    if fs::write(&text_path, &text).is_err() {
        warn!("⚠️  Failed to write certificate text to file");
    }

    Ok(content)
}
