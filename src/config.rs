use std::fmt;
use std::path::PathBuf;
use std::str::FromStr;
use std::time::Duration;

use claviron::helpers::de::deserialize_duration;
use claviron::ssl::certstore::{
    FULLCHAIN_CERT_FILENAME, PRIVKEY_FILENAME, SERVER_CERTS_DIRNAME,
};
use claviron::ssl::{Algorithm, Organization};
use serde::{Deserialize, Serialize};

use crate::account::{ACCOUNT_FILE_NAME, ACCOUNTS_PATH};

fn default_pkg_name() -> String {
    env!("CARGO_PKG_NAME").to_string()
}

/// Parsed contents of `etc/claviron/acme.yaml`. The single source of
/// truth for ACME-side configuration: paths (where account keys and
/// certs live), URLs (production vs staging directory endpoints), the
/// global organisation block injected into CSRs, and rate-limiting
/// knobs (`throttle_window`, `max_attempts_per_cn`) used by the DB
/// throttle in `actions::database::enforce_acme_throttle`.
///
/// One `AcmeConfig` covers **all** accounts and **all** certs handled
/// by this process — account-specific state (URL, JWK, key path)
/// lives in [`crate::account::Account`] models on disk or in the
/// `hosting.accounts` table.
///
/// Read by Congif for [`crate::provider::AcmeProvider`], before boot and
/// on reload. Consumers (renewal task, gRPC ACME endpoint, cleanup task)
/// resolve `AcmeProvider` and pull the snapshot — nothing else reads the
/// file.
#[derive(Deserialize, Clone, Debug, PartialEq)]
pub struct AcmeConfig {
    base_dir: PathBuf,
    #[serde(default = "default_pkg_name", alias = "account")]
    default_account: String,
    #[serde(default)]
    challenges_dir: PathBuf,
    #[serde(default, rename = "http-0", alias = "http-01")]
    http01: Option<Http01Config>,
    /// Default for orders which do not specify a method.
    #[serde(default)]
    pub method: Option<ChallengeMethod>,
    #[serde(default, rename = "dns-01")]
    dns01: Option<Dns01Config>,
    production_url: String,
    staging_url: String,
    organization: Organization,
    /// Check reachability using the selected challenge method.
    #[serde(default, rename = "pre-validation", alias = "prevalidation")]
    pub pre_validation: bool,
    pub renew_before: u32,
    #[serde(alias = "algo", alias = "algorithm")]
    pub alg: Algorithm,

    #[serde(
        default = "default_rate_limit_window",
        deserialize_with = "deserialize_duration"
    )]
    pub throttle_window: Duration,
    #[serde(default = "default_max_attempts_per_cn", alias = "max_attempts")]
    pub max_attempts_per_cn: u8,
}

/// Challenge method selected for a certificate order.
#[derive(Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChallengeMethod {
    #[serde(rename = "http-0", alias = "http-01")]
    Http0,
    #[serde(rename = "dns-01")]
    Dns01,
    #[serde(rename = "tls-alpn-01")]
    TlsAlpn01,
}

#[derive(Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Http01Config {
    challenges_dir: PathBuf,
}

#[derive(Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Dns01Config {
    #[serde(deserialize_with = "deserialize_duration")]
    visibility_timeout: Duration,
    #[serde(deserialize_with = "deserialize_duration")]
    check_interval: Duration,
}

fn default_rate_limit_window() -> Duration {
    Duration::from_secs(3600)
}

fn default_max_attempts_per_cn() -> u8 {
    3
}

impl AcmeConfig {
    #[cfg(all(feature = "db", feature = "server"))]
    pub(crate) fn file_challenge(
        &self
    ) -> Result<crate::clients::OrderChallenge<'_>, crate::AcmeError> {
        match self.method {
            None | Some(ChallengeMethod::Http0) => Ok(
                crate::clients::OrderChallenge::Http01(self.challenges_dir()),
            ),
            Some(ChallengeMethod::Dns01) => {
                Err(crate::AcmeError::MissingTxtPublisher)
            }
            Some(ChallengeMethod::TlsAlpn01) => {
                Err("TLS-ALPN-01 requires a challenge publisher".into())
            }
        }
    }

    #[cfg(all(feature = "server", feature = "dns-01"))]
    pub(crate) fn dns_visibility(
        &self
    ) -> Result<crate::methods::dns01::Visibility, crate::AcmeError> {
        let dns = self.dns01.ok_or("DNS-01 requires the dns-01 block")?;
        crate::methods::dns01::Visibility::new(
            dns.visibility_timeout,
            dns.check_interval,
        )
    }

    pub fn account_dir(
        &self,
        name: &str,
        mode: &AcmeMode,
    ) -> PathBuf {
        self.base_dir.join(ACCOUNTS_PATH).join(mode.to_str()).join(name)
    }

    pub fn default_account_path(
        &self,
        mode: &AcmeMode,
    ) -> PathBuf {
        self.account_dir(&self.default_account, mode).join(ACCOUNT_FILE_NAME)
    }

    pub fn account_path(
        &self,
        name: &str,
        mode: &AcmeMode,
    ) -> PathBuf {
        self.account_dir(name, mode).join(ACCOUNT_FILE_NAME)
    }

    pub fn base_url(
        &self,
        mode: &AcmeMode,
    ) -> &str {
        match mode {
            AcmeMode::Staging => &self.staging_url,
            AcmeMode::Production => &self.production_url,
        }
    }

    pub fn default_account(&self) -> &str {
        &self.default_account
    }

    pub fn cert_dir(
        &self,
        cname: &str,
    ) -> PathBuf {
        self.base_dir.join(SERVER_CERTS_DIRNAME).join(cname)
    }

    pub fn cert_path(
        &self,
        cname: &str,
    ) -> PathBuf {
        self.cert_dir(cname).join(FULLCHAIN_CERT_FILENAME)
    }

    pub fn key_path(
        &self,
        cname: &str,
    ) -> PathBuf {
        self.cert_dir(cname).join(PRIVKEY_FILENAME)
    }

    pub fn base_dir(&self) -> &PathBuf {
        &self.base_dir
    }

    pub fn challenges_dir(&self) -> &PathBuf {
        self.http01
            .as_ref()
            .map_or(&self.challenges_dir, |config| &config.challenges_dir)
    }

    #[cfg(feature = "http-0")]
    pub(crate) fn serves_http01(&self) -> bool {
        self.http01.is_some() || self.method == Some(ChallengeMethod::Http0)
    }

    pub fn organization(&self) -> &Organization {
        &self.organization
    }

    pub fn pre_validation(&self) -> bool {
        self.pre_validation
    }
}

/// Which ACME directory endpoint the workspace talks to.
///
/// **Staging** — Let's Encrypt staging endpoint
/// (`acme-staging-v02.api.letsencrypt.org`). Issued certs are signed
/// by the *Fake LE* root, which no browser trusts; useful for
/// integration testing and avoiding real rate limits during dev. The
/// file-based [`crate::actions::certificate::new_cert`] path
/// deliberately does **not** persist staging certs to disk to prevent
/// accidental promotion.
///
/// **Production** — the real endpoint. Subject to strict rate limits
/// (50 certs/registered domain/week and lower per-account quotas);
/// `pre_validation: true` and `max_attempts_per_cn` exist to defend
/// these limits.
///
/// Mode also routes account storage: account dirs nest under
/// `accounts/<staging|production>/<account>/`, so the same operator
/// can hold separate accounts on each side without collision.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")] // serialize as "staging"/"production"
pub enum AcmeMode {
    Staging,
    Production,
}

impl fmt::Display for AcmeMode {
    fn fmt(
        &self,
        f: &mut fmt::Formatter<'_>,
    ) -> fmt::Result {
        f.write_str(self.to_str())
    }
}

impl FromStr for AcmeMode {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "staging" => Ok(AcmeMode::Staging),
            "production" | "prod" => Ok(AcmeMode::Production),
            _ => Err("invalid ACME mode"),
        }
    }
}

impl AcmeMode {
    pub fn to_str(&self) -> &'static str {
        match self {
            AcmeMode::Staging => "staging",
            AcmeMode::Production => "production",
        }
    }

    pub fn is_production(&self) -> bool {
        self == &AcmeMode::Production
    }
}
