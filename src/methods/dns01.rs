//! Publication contract for RFC 8555 DNS-01 validation.

use std::time::Duration;

use async_trait::async_trait;
use claviron::helpers::base64::base64_encode;
use claviron::ssl::Sni;
use sha2::{Digest, Sha256};

use crate::AcmeError;

/// A single TXT value to append at the absolute DNS owner name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxtRecord {
    owner: String,
    value: String,
}

impl TxtRecord {
    pub(crate) fn from_authorization(
        identifier: &str,
        key_authorization: &str,
    ) -> Result<Self, AcmeError> {
        // RFC 8555 puts the base name of a wildcard in the authorization.
        let identifier: Sni = identifier.parse()?;
        let identifier = identifier.as_str();
        let owner = format!("_acme-challenge.{identifier}.");
        if identifier.starts_with("*.") || owner.len() > 254 {
            return Err(AcmeError::from("Invalid DNS-01 authorization name"));
        }
        Ok(Self {
            owner,
            value: base64_encode(&Sha256::digest(key_authorization)),
        })
    }

    pub fn owner(&self) -> &str {
        &self.owner
    }

    pub fn value(&self) -> &str {
        &self.value
    }
}

pub type PublishError = Box<dyn std::error::Error + Send + Sync>;

/// The application's budget and cadence for authoritative DNS checks.
#[derive(Clone, Copy, Debug)]
pub struct Visibility {
    timeout: Duration,
    interval: Duration,
}

impl Visibility {
    pub fn new(
        timeout: Duration,
        interval: Duration,
    ) -> Result<Self, AcmeError> {
        if interval.is_zero()
            || timeout <= interval
            || std::time::Instant::now().checked_add(timeout).is_none()
        {
            return Err(
                "visibility_timeout must exceed a positive check_interval"
                    .into(),
            );
        }
        Ok(Self { timeout, interval })
    }

    pub fn timeout(self) -> Duration {
        self.timeout
    }

    pub fn interval(self) -> Duration {
        self.interval
    }
}

/// DNS-01 proof publication and optional system-resolver verification.
pub struct Dns01<'a> {
    pub(crate) publisher: &'a dyn TxtPublisher,
    pub(crate) visibility: Visibility,
    #[cfg(feature = "resolver")]
    resolver: Option<claviron::resolver::HickoryResolver>,
}

impl<'a> Dns01<'a> {
    pub fn new(
        publisher: &'a dyn TxtPublisher,
        visibility: Visibility,
    ) -> Self {
        Self {
            publisher,
            visibility,
            #[cfg(feature = "resolver")]
            resolver: None,
        }
    }

    pub fn with_system_resolver(mut self) -> Result<Self, AcmeError> {
        #[cfg(feature = "resolver")]
        {
            use claviron::resolver::{HickoryResolver, ResolverConfig};
            self.resolver = Some(
                HickoryResolver::new(&ResolverConfig {
                    timeout: self.visibility.interval(),
                    ..ResolverConfig::default()
                })
                .map_err(|error| AcmeError::Dns01(Box::new(error)))?,
            );
            Ok(self)
        }
        #[cfg(not(feature = "resolver"))]
        {
            let _ = &mut self;
            Err("DNS-01 pre-validation requires the resolver feature".into())
        }
    }

    pub(crate) async fn verify(
        &self,
        record: &TxtRecord,
    ) -> Result<(), AcmeError> {
        #[cfg(feature = "resolver")]
        if let Some(resolver) = &self.resolver {
            use claviron::resolver::{Query, Record, RecordType, Resolver};
            loop {
                let next =
                    tokio::time::Instant::now() + self.visibility.interval();
                if resolver.lookup(Query::new(record.owner(), RecordType::Txt))
                    .await.is_ok_and(|answer| answer.records.iter().any(|value| {
                        matches!(value, Record::Txt(parts) if parts.iter().flatten().copied().eq(record.value().bytes()))
                    }))
                {
                    return Ok(());
                }
                tokio::time::sleep_until(next).await;
            }
        }
        let _ = record;
        Ok(())
    }
}

/// Appends a challenge value while preserving other records at the owner.
#[async_trait]
pub trait TxtPublisher: Send + Sync {
    async fn publish(
        &self,
        record: TxtRecord,
    ) -> Result<Box<dyn TxtPublication>, PublishError>;
}

/// Owns one published value. Implementations arrange cleanup on drop as
/// well, since an issuance future can be cancelled.
#[async_trait]
pub trait TxtPublication: Send + Sync {
    /// Return only once the exact value is visible on the serving DNS path.
    /// The caller bounds this wait by the configured visibility timeout.
    async fn wait_visible(
        &self,
        visibility: Visibility,
    ) -> Result<(), PublishError>;

    /// Remove this publication without disturbing concurrent challenges.
    async fn remove(self: Box<Self>) -> Result<(), PublishError>;
}
