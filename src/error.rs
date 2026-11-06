use std::path::{Path, PathBuf};

use claviron::ssl::{Algorithm, SSLError};

pub(crate) type Result<T> = std::result::Result<T, AcmeError>;

#[derive(thiserror::Error, Debug)]
pub enum ValidationError {
    #[error("Certificate is expired")]
    Expired(String),

    #[error("Certificate is not yet valid")]
    NotYetValid,
}

#[derive(thiserror::Error, Debug)]
pub enum AcmeError {
    #[error("Io error: {message}  {source} {kind}  (path: {path:?})")]
    Io {
        source: std::io::Error,
        kind: std::io::ErrorKind,
        path: PathBuf,
        message: String,
    },

    #[error("client error: {0}")]
    ClientCreationFailed(String),

    #[error(
        "Certificate for `{cn}` not due yet (expires in {days_until_expiry} days)"
    )]
    RenewalNotDue { cn: String, days_until_expiry: i64 },

    #[error("certificate failed: {0}")]
    CertificateFailed(String),

    #[error("validation error: {0}")]
    Validation(#[from] ValidationError),

    #[error("HTTP header to string conversion error: {0}")]
    HeaderToStr(#[from] http::header::ToStrError),

    #[error("HTTP client error: {0}")]
    ClientError(#[from] reqwest::Error),

    /// A completed HTTP exchange rejected by the CA, including its original
    /// problem document or plain-text explanation.
    #[error("ACME endpoint {url} returned HTTP {status}: {body}")]
    HttpResponse { status: http::StatusCode, url: String, body: String },

    #[cfg(feature = "db")]
    #[error("database error: {0}")]
    Database(String),

    #[error("Serialization error: {0}")]
    Serde(#[from] serde_json::Error),

    #[error("Unexpected: {0}")]
    Unexpected(String),

    #[error("Invalid order status")]
    InvalidOrderStatus,

    #[error("HTTP-01 challenge token must be nonempty unpadded base64url")]
    InvalidChallengeToken,

    #[error("Request signing error: {0}")]
    SignRequest(String),

    #[error("Jwk error: {0}")]
    Jwk(String),

    #[error("file not found: {0}")]
    NotFound(String),

    #[error("too many requests for cname `{0}`")]
    TooMany(String),

    #[error("`{0}` was renewed within the throttle window")]
    RecentlyDone(String),

    #[error("UTF-8 decode failed: {0}")]
    Utf8(#[from] std::str::Utf8Error),

    // #[error("PKCS#8 error: {0}")]
    // Pkcs8(#[from] pkcs8::Error),
    #[error("PKCS#8 (p256) error: {0}")]
    P256Pkcs8(#[from] p256::pkcs8::Error),

    #[error("ECDSA error: {0}")]
    Ecdsa(#[from] p256::ecdsa::Error),

    #[error("Elliptic curve error: {0}")]
    EllipticCurve(#[from] p256::elliptic_curve::Error),

    #[error("failed: {0}")]
    RegistrationFailed(String),

    #[error("payload not provided in response body")]
    NoPayloadProvided,

    #[error("account url not found in response")]
    MissingLocationHeader,

    #[error("unsupported algorithm: {0}")]
    UnsupportedAlgorithm(Algorithm),

    #[error(transparent)]
    Ssl(#[from] SSLError),
}

impl From<String> for AcmeError {
    fn from(s: String) -> Self {
        AcmeError::Unexpected(s)
    }
}

impl From<&str> for AcmeError {
    fn from(s: &str) -> Self {
        AcmeError::Unexpected(s.to_string())
    }
}

impl AcmeError {
    #[cfg(feature = "db")]
    pub(crate) fn database(error: sqlx::Error) -> Self {
        Self::Database(error.to_string())
    }

    pub fn io_error(
        message: impl Into<String>,
        path: impl AsRef<Path>,
        e: std::io::Error,
    ) -> Self {
        let kind = e.kind();
        AcmeError::Io {
            source: e,
            kind,
            path: path.as_ref().to_path_buf(),
            message: message.into(),
        }
    }
}
