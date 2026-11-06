use std::fs;
use std::path::Path;

use claviron::ssl::parsers::{
    sanitize_pem_content_to_der, take_first_cert_from_der,
};
use claviron::ssl::{
    Algorithm, Aliases, Host, Issuer, KeyString, Organization,
    SSLError as Error,
};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use time::serde::rfc3339;

use crate::AcmeMode;
use crate::account::Account;

/// Sidecar metadata written next to a file-backed certificate.
///
/// Lives at `<cert_dir>/meta.json` and captures everything the cert
/// itself encodes (subject, SANs, issuer, validity) plus what the
/// cert can't tell you on its own (which ACME account ordered it,
/// which `AcmeMode` it was issued in, when *we* recorded it). The
/// renewal task reads this to decide "is this cert due for renewal
/// yet?" without re-parsing the certificate body.
///
/// Two construction paths:
/// - [`from_cert`](Self::from_cert) — fresh meta from a freshly
///   ordered cert (used by `new_cert` flow); fills `created_at` from
///   wall clock.
/// - [`from_path`](Self::from_path) — re-hydrate from existing
///   `meta.json` (used by renewal flow before deciding whether to
///   reorder).
///
/// On renewal, [`update_with_renewed`](Self::update_with_renewed)
/// merges the post-renew cert's `valid_until` and `issued_by` back
/// into the existing meta — keeping `account`, `cn`, and `created_at`
/// stable across renewals.
///
/// The DB path doesn't use this struct — the equivalent fields live
/// directly on `hosting.certificates` rows.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertMeta {
    pub account: String,
    pub cn: String,
    pub aliases: Aliases,
    pub organization: String,
    pub algorithm: Algorithm,
    #[serde(with = "rfc3339")]
    pub valid_until: OffsetDateTime,
    #[serde(with = "rfc3339")]
    pub created_at: OffsetDateTime,
    pub issued_by: String,
    pub mode: AcmeMode,
}

impl CertMeta {
    pub fn from_path(path: impl AsRef<Path>) -> Result<Self, Error> {
        let meta_content =
            fs::read(&path).map_err(|e| Error::io_error(&path, e))?;

        let meta = serde_json::from_slice(&meta_content)?;

        Ok(meta)
    }

    /// Build CertMeta from a PEM/DER certificate string.
    /// This is forgiving: on parse errors it falls back to sensible defaults.
    pub fn from_cert(
        account: &Account,
        data: &[u8],
    ) -> Result<Self, Error> {
        let der = sanitize_pem_content_to_der(data);
        let cert = take_first_cert_from_der(&der)?;

        // CN (subject)
        let host = Host::try_from(&cert)?;
        let cn = host.key_string();
        let aliases = Aliases::try_from(&cert)?;

        let org = Organization::try_from(&cert)?;
        let organization = org.name.into_string();

        // Issuer CN
        let issuer = Issuer::try_from(&cert)?;
        let issued_by = issuer.cn.unwrap_or_default().to_owned();

        // Validity
        let valid_until = cert.validity().not_after.to_datetime();
        let created_at: OffsetDateTime =
            OffsetDateTime::now_utc().replace_nanosecond(0).unwrap();

        let algorithm = account.alg;

        Ok(Self {
            cn,
            aliases,
            organization,
            created_at,
            valid_until,
            issued_by,
            account: account.name.clone(),
            algorithm,
            mode: account.mode,
        })
    }

    pub fn should_be_renewed(
        &self,
        days_before_renewal: u32,
    ) -> bool {
        let now = OffsetDateTime::now_utc();
        if now >= self.valid_until {
            return true; // already expired or exactly at expiry => renew
        }
        let remaining = self.valid_until - now; // time::Duration
        remaining <= time::Duration::days(days_before_renewal as i64)
    }

    pub fn update_with_renewed(
        &mut self,
        data: &[u8],
    ) -> Result<(), Error> {
        let der = sanitize_pem_content_to_der(data);
        let cert = take_first_cert_from_der(&der)?;

        // CN (subject)
        let host = Host::try_from(&cert)?;
        let cn = host.key_string();

        if cn != self.cn {
            return Err(Error::Other(format!(
                "CN mismatch: expected {}, got {}",
                self.cn, cn
            )));
        }

        // Issuer CN
        let issuer = Issuer::try_from(&cert)?;
        self.issued_by = issuer.cn.unwrap_or_default().to_owned();
        // Validity
        self.valid_until = cert.validity().not_after.to_datetime();

        Ok(())
    }

    pub fn as_json(&self) -> Result<String, Error> {
        serde_json::to_string_pretty(self)
            .map_err(|e| Error::Other(format!("JSON encode error: {e}")))
    }
}
