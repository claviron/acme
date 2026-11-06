use std::str::FromStr;

use claviron::hosting::{
    Certificate, HostedCertificate, HostingStore, NewCertificate,
};
use claviron::ssl::formatters::certificate_chain_to_pem;
use claviron::ssl::generators::{
    generate_private_key, generate_server_csr, read_private_key_from_der,
};
use claviron::ssl::parsers::{
    concat_chain_bytes_from_pem, take_first_cert_from_der,
};
use claviron::ssl::{Aliases, CommonName, Organization, Sni};
use time::OffsetDateTime;
use tokio::time::Instant;
use tracing::{debug, error, info, warn};

use crate::clients::{AcmeClient, CertClient, acme_client};
use crate::cryptex::jwk::AcmeJwk;
use crate::validate::validate_acme_url;
use crate::{AcmeConfig, AcmeError, AcmeOperation, AcmeStore};

pub struct AddCertificateResult {
    pub certificate: Certificate,
    pub content: String,
    pub attached_existing: bool,
}

/// Attach an existing certificate to this server or issue a fresh one.
pub async fn add_cert_to_db(
    acme_store: &AcmeStore,
    hosting: &HostingStore,
    server_id: i32,
    cn: &Sni,
    aliases: &[Sni],
    cfg: &AcmeConfig,
) -> Result<AddCertificateResult, AcmeError> {
    add_with_client(
        acme_store,
        hosting,
        server_id,
        cn,
        aliases,
        cfg,
        acme_client,
    )
    .await
}

async fn add_with_client(
    acme_store: &AcmeStore,
    hosting: &HostingStore,
    server_id: i32,
    cn: &Sni,
    aliases: &[Sni],
    cfg: &AcmeConfig,
    make_client: impl FnOnce() -> Result<AcmeClient, AcmeError>,
) -> Result<AddCertificateResult, AcmeError> {
    let start_time = Instant::now();
    if let Some(existing) = hosting
        .certificate_by_cn(cn.as_str())
        .await
        .map_err(|error| AcmeError::Database(error.to_string()))?
    {
        if existing.certificate.kind
            != claviron::hosting::CertificateKind::Server
        {
            return Err(AcmeError::from(
                "Certificate belongs to a non-ACME source",
            ));
        }
        acme_account_id(hosting, &existing.certificate).await?;
        let attached = hosting
            .attach_certificate_to_server(existing.certificate.id, server_id)
            .await
            .map_err(|error| AcmeError::Database(error.to_string()))?;
        if !attached {
            return Err(AcmeError::from(format!(
                "Certificate '{}' already exists for this server",
                cn
            )));
        }
        let content =
            certificate_chain_to_pem(&existing.certificate.certs_der)?;
        info!(
            cn = %cn,
            certificate_id = existing.certificate.id,
            server_id,
            "existing certificate attached to server"
        );
        return Ok(AddCertificateResult {
            certificate: existing.certificate,
            content,
            attached_existing: true,
        });
    }

    let pending_aliases = Some(serde_json::json!(
        aliases.iter().map(|sni| sni.as_str()).collect::<Vec<_>>()
    ));
    let log_id = acme_store
        .insert_pending_log(cn.as_str(), AcmeOperation::Create, pending_aliases)
        .await?;

    // Every way out of the attempt closes the log row it opened: a row left
    // pending refuses the next attempt for this CN.
    let mut account_id = None;
    let attempt = async {
        if cfg.pre_validation {
            validate_acme_url(cfg.challenges_dir(), aliases).await?;
            debug!("Pre-validation completed successfully");
        }

        let account = acme_store
            .default_account()
            .await?
            .ok_or_else(|| AcmeError::from("No default ACME account found"))?;
        account_id = Some(account.id);

        debug!(aliases = ?aliases, "creating ACME certificate in database mode");
        let private_key = generate_private_key()?;
        let organization = Organization::from_name(&account.organization);
        let csr =
            generate_server_csr(&private_key, &cn.as_str().parse()?, Aliases::from(aliases), &organization)?;
        let client = CertClient::with_client(make_client()?, &account.private_key, &account.url)
            .map_err(|error| AcmeError::ClientCreationFailed(error.to_string()))?;
        let jwk: AcmeJwk = serde_json::from_value(account.jwk.clone())
            .map_err(|error| AcmeError::from(format!("Invalid JWK JSON: {error}")))?;
        jwk.validate_key(&account.private_key, account.algorithm)?;
        let fullchain_pem = client.request_certificate(csr.der(), &jwk, cfg.challenges_dir()).await.inspect_err(
            |error| {
                error!(cn = %cn, error = ?error, "ACME create request failed");
            }
        )?;
        let certs_der = concat_chain_bytes_from_pem(fullchain_pem.as_bytes())?;
        let leaf = take_first_cert_from_der(&certs_der)?;
        let expires_at = OffsetDateTime::from_unix_timestamp(
            leaf.validity().not_after.to_datetime().unix_timestamp(),
        )
        .map_err(|_| AcmeError::from("Invalid expires_at timestamp"))?;
        let alias_names =
            aliases.iter().map(|alias| alias.key_string()).collect::<Vec<_>>();
        let issuer = hosting
            .ensure_acme_issuer(account.id)
            .await
            .map_err(|error| AcmeError::Database(error.to_string()))?;
        let hosted = hosting
            .insert_certificate(
                NewCertificate {
                    kind: claviron::hosting::CertificateKind::Server,
                    issuer_id: Some(issuer.id),
                    cn: cn.to_string(),
                    certs_der,
                    key_der: private_key.serialize_der(),
                    expires_at,
                    issued_at: OffsetDateTime::now_utc(),
                    enabled: true,
                },
                &alias_names,
                server_id,
            )
            .await
            .map_err(|error| AcmeError::Database(error.to_string()))?;

        info!(cn = %cn, certificate_id = hosted.certificate.id, "certificate persisted");
        Ok::<_, AcmeError>(AddCertificateResult {
            certificate: hosted.certificate,
            content: fullchain_pem,
            attached_existing: false,
        })
    }
    .await;
    let duration = start_time.elapsed().as_secs() as i32;
    let failure = attempt.as_ref().err().map(ToString::to_string);
    finish_log_best_effort(
        acme_store,
        log_id,
        account_id,
        duration,
        failure.as_deref(),
    )
    .await;
    attempt
}

/// Renew a certificate already loaded from the hosting store.
pub async fn renew_cert_from_db(
    acme_store: &AcmeStore,
    hosting: &HostingStore,
    cfg: &AcmeConfig,
    hosted: HostedCertificate,
    enforce_throttle: bool,
) -> Result<(Certificate, String), AcmeError> {
    renew_with_client(
        acme_store,
        hosting,
        cfg,
        hosted,
        enforce_throttle,
        acme_client,
    )
    .await
}

async fn renew_with_client(
    acme_store: &AcmeStore,
    hosting: &HostingStore,
    cfg: &AcmeConfig,
    hosted: HostedCertificate,
    enforce_throttle: bool,
    make_client: impl FnOnce() -> Result<AcmeClient, AcmeError>,
) -> Result<(Certificate, String), AcmeError> {
    let start_time = Instant::now();
    let cert = hosted.certificate;
    let account_id = acme_account_id(hosting, &cert).await?;
    if enforce_throttle {
        enforce_acme_throttle(acme_store, cfg, &cert.cn).await?;
    }

    let account = acme_store
        .account_by_id(account_id)
        .await?
        .ok_or_else(|| AcmeError::from("Account not found"))?;
    let mut aliases = Aliases::default();
    aliases.push_unique(
        Sni::from_str(&cert.cn)
            .map_err(|error| AcmeError::from(error.to_string()))?
            .into(),
    );
    for row in hosted.aliases {
        aliases.push_unique(
            Sni::from_str(&row.hostname)
                .map_err(|error| AcmeError::from(error.to_string()))?
                .into(),
        );
    }
    let aliases_json = Some(serde_json::json!(
        aliases
            .iter()
            .filter_map(|host| host.as_str_if_textual())
            .collect::<Vec<_>>()
    ));
    let log_id = acme_store
        .insert_pending_log(&cert.cn, AcmeOperation::Renew, aliases_json)
        .await?;

    // Every way out of the attempt closes the log row it opened: a row left
    // pending refuses the next renewal of this CN.
    let key_der = cert.key_der.clone();
    let attempt = async {
        let private_key = read_private_key_from_der(&key_der)?;
        let organization = Organization::from_name(&account.organization);
        let csr = generate_server_csr(
            &private_key,
            &cert.cn.parse::<CommonName>()?,
            &aliases,
            &organization,
        )?;
        let client = CertClient::with_client(
            make_client()?,
            &account.private_key,
            &account.url,
        )
        .map_err(|error| AcmeError::ClientCreationFailed(error.to_string()))?;
        let jwk: AcmeJwk = serde_json::from_value(account.jwk.clone())
            .map_err(|error| {
                AcmeError::from(format!("Invalid JWK JSON: {error}"))
            })?;
        jwk.validate_key(&account.private_key, account.algorithm)?;
        let cert_pem = client
            .request_certificate(csr.der(), &jwk, cfg.challenges_dir())
            .await?;
        let certs_der = concat_chain_bytes_from_pem(cert_pem.as_bytes())?;
        let leaf = take_first_cert_from_der(&certs_der)?;
        let expires_at = OffsetDateTime::from_unix_timestamp(
            leaf.validity().not_after.to_datetime().unix_timestamp(),
        )
        .map_err(|_| AcmeError::from("Invalid expires_at timestamp"))?;
        let updated = hosting
            .update_certificate_material(
                cert.id, certs_der, key_der, expires_at,
            )
            .await
            .map_err(|error| AcmeError::Database(error.to_string()))?;
        info!(cn = %cert.cn, "certificate renewed");
        Ok::<_, AcmeError>((updated.certificate, cert_pem))
    }
    .await;
    let duration = start_time.elapsed().as_secs() as i32;
    let failure = attempt.as_ref().err().map(ToString::to_string);
    finish_log_best_effort(
        acme_store,
        log_id,
        Some(account.id),
        duration,
        failure.as_deref(),
    )
    .await;
    attempt
}

/// Renew by CN, applying the configured due-date rule before network I/O.
pub async fn renew_cert_to_db(
    acme_store: &AcmeStore,
    hosting: &HostingStore,
    cfg: &AcmeConfig,
    cn: &Sni,
    renew_before_days: Option<u32>,
    enforce_throttle: bool,
) -> Result<(Certificate, String), AcmeError> {
    let hosted = hosting
        .certificate_by_cn(cn.as_str())
        .await
        .map_err(|error| AcmeError::Database(error.to_string()))?
        .ok_or_else(|| {
            AcmeError::from(format!("Certificate '{}' not found", cn))
        })?;
    acme_account_id(hosting, &hosted.certificate).await?;
    let renew_before = renew_before_days.unwrap_or(cfg.renew_before);
    let days_until_expiry = (hosted.certificate.expires_at
        - OffsetDateTime::now_utc())
    .whole_days();
    if days_until_expiry > i64::from(renew_before) {
        return Err(AcmeError::RenewalNotDue {
            cn: cn.to_string(),
            days_until_expiry,
        });
    }
    if days_until_expiry < 0 {
        warn!(cn = %cn, days_expired = days_until_expiry.unsigned_abs(), "renewing expired certificate");
    } else {
        debug!(cn = %cn, days_until_expiry, "renewing certificate");
    }
    renew_cert_from_db(acme_store, hosting, cfg, hosted, enforce_throttle).await
}

/// Renewing a CN is refused while a renewal of it succeeded within the
/// throttle window (that certificate is fresh; another would only spend the
/// issuer's duplicate-certificate limit), and after `max_attempts_per_cn`
/// failed renewals within it. Pending rows count for neither: the database
/// already refuses a second one.
async fn enforce_acme_throttle(
    store: &AcmeStore,
    cfg: &AcmeConfig,
    cn: &str,
) -> Result<(), AcmeError> {
    let cutoff = OffsetDateTime::now_utc() - cfg.throttle_window;
    if store.succeeded_since(cn, AcmeOperation::Renew, cutoff).await? {
        return Err(AcmeError::RecentlyDone(cn.to_owned()));
    }
    let failures =
        store.failures_since(cn, AcmeOperation::Renew, cutoff).await?;
    if failures >= i64::from(cfg.max_attempts_per_cn) {
        return Err(AcmeError::TooMany(cn.to_owned()));
    }
    Ok(())
}

async fn finish_log_best_effort(
    store: &AcmeStore,
    log_id: i32,
    account_id: Option<i32>,
    duration_seconds: i32,
    error_message: Option<&str>,
) {
    if let Err(error) = store
        .finish_log(log_id, account_id, duration_seconds, error_message)
        .await
    {
        warn!(log_id, error = %error, "failed to finalize ACME operation log");
    }
}

async fn acme_account_id(
    hosting: &HostingStore,
    cert: &Certificate,
) -> Result<i32, AcmeError> {
    if cert.kind != claviron::hosting::CertificateKind::Server {
        return Err(AcmeError::from("ACME only manages server certificates"));
    }
    let id = cert
        .issuer_id
        .ok_or_else(|| AcmeError::from("Certificate has no issuer"))?;
    let issuer = hosting
        .issuer_by_id(id)
        .await
        .map_err(|error| AcmeError::Database(error.to_string()))?
        .ok_or_else(|| AcmeError::from("Certificate issuer not found"))?;
    if issuer.kind != claviron::hosting::IssuerKind::Acme {
        return Err(AcmeError::from(
            "Certificate belongs to a non-ACME issuer",
        ));
    }
    issuer
        .acme_account_id
        .ok_or_else(|| AcmeError::from("ACME issuer has no account"))
}

#[cfg(all(test, unix, feature = "sqlite"))]
#[path = "../../tests/unit/issuance.rs"]
mod tests;
