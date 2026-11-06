use std::fs;
use std::path::Path;

use claviron::ssl::{Sni, generators};
use tracing::{info, warn};

use super::AcmeError;
use super::clients::acme_client;

/// Pre-flight HTTP-01 reachability check — runs before kicking off
/// the real ACME order.
///
/// Why pre-validate at all? Let's Encrypt's per-account / per-domain
/// rate limits are strict (50 certs/registered domain/week, lower
/// per-account-and-hostname limits). A misconfigured DNS record or a
/// firewall blocking port 80 would burn a slot on every retry. By
/// writing a randomly-named challenge file and fetching
/// `http://<alias>/.well-known/acme-challenge/<token>` ourselves
/// **before** involving the CA, we catch reachability issues without
/// touching the CA's quota.
///
/// What's checked: every alias resolves, port 80 reachable, the
/// cleartext `claviron-hyper` listener actually serves the challenge file
/// for that hostname. The token is random per call — caching can't
/// produce a false positive.
///
/// What's not checked: TLS, port 443, the cert delivery chain
/// itself, or any other ACME-specific error class. Pre-validation is
/// scoped strictly to "would the CA be able to reach us?".
///
/// Activated via `acme.yaml::pre-validation: true`. Recommended for
/// production; safe to leave off in dev where rate limits don't
/// matter.
pub async fn validate_acme_url(
    challenges_dir: impl AsRef<Path>,
    aliases: &[Sni],
) -> Result<(), AcmeError> {
    let challenges_dir = challenges_dir.as_ref();
    if !challenges_dir.is_dir() {
        return Err(format!(
            "ACME challenges directory does not exist: {}",
            challenges_dir.display()
        )
        .into());
    }

    let random_string = generators::random_alphanum(16);

    // Create a unique, tokenized filename and write the token as content
    let fname = format!("acme-pre-validate-{}", random_string);
    let challenge_file_path = challenges_dir.join(&fname);
    fs::write(&challenge_file_path, &random_string).map_err(|e| {
        AcmeError::io_error(
            "Failed to write challenge file",
            &challenge_file_path,
            e,
        )
    })?;

    let client = acme_client()?;

    for alias in aliases {
        let validate_url = format!(
            "http://{}/.well-known/acme-challenge/{}?_ts={}",
            alias, fname, random_string
        );

        warn!("trying pre-validation URL {}", validate_url);

        let response = client
            .get(&validate_url)
            .header("Cache-Control", "no-cache")
            .send()
            .await?
            .text()
            .await?;

        if response.trim() != random_string {
            let _ = fs::remove_file(&challenge_file_path);
            return Err(format!(
                "Request pre-validation failed for {} (got {:?})",
                alias,
                response.trim()
            )
            .into());
        }
    }

    fs::remove_file(&challenge_file_path).map_err(|e| {
        AcmeError::io_error(
            "Failed to remove challenge file",
            &challenge_file_path,
            e,
        )
    })?;
    info!("✅ Pre-validation successful for all domains");

    Ok(())
}
