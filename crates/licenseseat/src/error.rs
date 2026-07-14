//! Error types for the LicenseSeat SDK.

use std::collections::HashMap;

/// Result type alias for LicenseSeat operations.
pub type Result<T> = std::result::Result<T, Error>;

/// Error types that can occur when using the LicenseSeat SDK.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// Configuration error (missing required fields, invalid values).
    #[error("configuration error: {0}")]
    Configuration(String),

    /// Product slug is required but not configured.
    #[error("product_slug is required - set it in Config")]
    ProductSlugRequired,

    /// API key is required but not configured.
    #[error("api_key is required - set it in Config")]
    ApiKeyRequired,

    /// No active license to operate on.
    #[error("no active license - call activate() first")]
    NoActiveLicense,

    /// A response did not match the requested license, product, installation,
    /// or activation and was rejected before it could mutate cached state.
    #[error("response identity mismatch: {0}")]
    ResponseMismatch(String),

    /// A newer state-changing operation superseded an in-flight request.
    #[error("{operation} was superseded by a newer license-state operation")]
    OperationSuperseded {
        /// Human-readable operation name.
        operation: &'static str,
    },

    /// API error with status code and details.
    #[error("API error ({status}): {message}")]
    Api {
        /// HTTP status code
        status: u16,
        /// Error code from API (e.g., "license_not_found")
        code: Option<String>,
        /// Human-readable error message
        message: String,
        /// Additional error details
        details: Option<HashMap<String, serde_json::Value>>,
    },

    /// Network error (connection failed, timeout, etc.).
    #[error("network error: {0}")]
    Network(#[from] reqwest::Error),

    /// JSON serialization/deserialization error.
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// A serialized API request exceeded the SDK's outbound body limit.
    #[error("API request exceeded the {limit_bytes}-byte safety limit")]
    RequestTooLarge {
        /// Maximum accepted request size.
        limit_bytes: usize,
    },

    /// An API response exceeded the SDK's bounded in-memory body limit.
    #[error("API response exceeded the {limit_bytes}-byte safety limit")]
    ResponseTooLarge {
        /// Maximum accepted response size.
        limit_bytes: usize,
    },

    /// Cryptographic verification failed (offline validation).
    #[cfg(feature = "offline")]
    #[error("crypto error: {0}")]
    Crypto(String),

    /// Offline token is expired or not yet valid.
    #[error("offline token expired")]
    OfflineTokenExpired,

    /// Offline token failed verification.
    #[error("offline token verification failed: {0}")]
    OfflineVerificationFailed(String),

    /// Clock tampering detected.
    #[error("clock tampering detected: system time appears to have been manipulated")]
    ClockTamperingDetected,

    /// Grace period exceeded for offline use.
    #[error("offline grace period exceeded: last online validation was {days} days ago")]
    GracePeriodExceeded {
        /// Days since last online validation
        days: u32,
    },

    /// Cache error (storage unavailable, corruption, etc.).
    #[error("cache error: {0}")]
    Cache(String),

    /// URL parsing error.
    #[error("URL error: {0}")]
    Url(#[from] url::ParseError),
}

impl Error {
    /// Create an API error from response details.
    pub fn api(
        status: u16,
        code: Option<String>,
        message: impl Into<String>,
        details: Option<HashMap<String, serde_json::Value>>,
    ) -> Self {
        Self::Api {
            status,
            code,
            message: message.into(),
            details,
        }
    }

    /// Check if this error is a network/transport error (retriable).
    pub fn is_network_error(&self) -> bool {
        match self {
            Self::Network(_) => true,
            Self::Api { status, .. } => {
                *status == 0 || *status == 408 || (500..600).contains(status)
            }
            _ => false,
        }
    }

    /// Check if this error is a business logic error (not retriable).
    pub fn is_business_error(&self) -> bool {
        match self {
            Self::Api { status, .. } => {
                (400..500).contains(status) && *status != 401 && *status != 429
            }
            _ => false,
        }
    }

    /// Get the error code if this is an API error.
    pub fn code(&self) -> Option<&str> {
        match self {
            Self::Api { code, .. } => code.as_deref(),
            _ => None,
        }
    }

    /// Get the HTTP status if this is an API error.
    pub fn status(&self) -> Option<u16> {
        match self {
            Self::Api { status, .. } => Some(*status),
            _ => None,
        }
    }

    /// Return a bounded, credential-safe summary suitable for automatic logs.
    ///
    /// Full errors remain available to the direct caller. Background tasks
    /// must not format them automatically because API messages and reqwest
    /// errors can contain server-controlled data or a request URL whose path
    /// includes the license key.
    pub(crate) fn redacted_log_summary(&self) -> String {
        match self {
            Self::Api { status, .. } => format!("API request rejected (HTTP {status})"),
            Self::Network(error) if error.is_timeout() => "network timeout".into(),
            Self::Network(error) if error.is_connect() => "network connection failure".into(),
            Self::Network(_) => "network transport failure".into(),
            Self::Configuration(_) | Self::ApiKeyRequired | Self::ProductSlugRequired => {
                "invalid SDK configuration".into()
            }
            Self::NoActiveLicense => "no active license".into(),
            Self::ResponseMismatch(_) => "response identity mismatch".into(),
            Self::OperationSuperseded { .. } => "operation superseded".into(),
            Self::Json(_) => "invalid JSON response".into(),
            Self::RequestTooLarge { .. } => "request exceeded safety limit".into(),
            Self::ResponseTooLarge { .. } => "response exceeded safety limit".into(),
            #[cfg(feature = "offline")]
            Self::Crypto(_) => "cryptographic operation failed".into(),
            Self::OfflineTokenExpired => "offline artifact expired".into(),
            Self::OfflineVerificationFailed(_) => "offline verification failed".into(),
            Self::ClockTamperingDetected => "clock rollback detected".into(),
            Self::GracePeriodExceeded { .. } => "offline grace period exceeded".into(),
            Self::Cache(_) => "durable cache operation failed".into(),
            Self::Url(_) => "invalid URL".into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Error;

    #[test]
    fn automatic_log_summary_never_echoes_api_data() {
        let error = Error::api(
            422,
            Some("SECRET-LICENSE-KEY".into()),
            "server echoed SECRET-LICENSE-KEY",
            None,
        );
        let summary = error.redacted_log_summary();

        assert_eq!(summary, "API request rejected (HTTP 422)");
        assert!(!summary.contains("SECRET"));
    }
}

/// Common API error codes returned by LicenseSeat.
///
/// These constants can be used to match against `Error::code()` for
/// programmatic error handling.
#[allow(dead_code)]
pub mod codes {
    /// License key doesn't exist.
    pub const LICENSE_NOT_FOUND: &str = "license_not_found";
    /// License has expired.
    pub const LICENSE_EXPIRED: &str = "license_expired";
    /// License has been suspended.
    pub const LICENSE_SUSPENDED: &str = "license_suspended";
    /// License has been revoked.
    pub const LICENSE_REVOKED: &str = "license_revoked";
    /// No available seats for activation.
    pub const SEAT_LIMIT_EXCEEDED: &str = "seat_limit_exceeded";
    /// Device ID doesn't match the activation.
    pub const DEVICE_MISMATCH: &str = "device_mismatch";
    /// Device fingerprint is not activated for this license.
    pub const DEVICE_NOT_ACTIVATED: &str = "DEVICE_NOT_ACTIVATED";
    /// License is not valid for this product.
    pub const PRODUCT_MISMATCH: &str = "product_mismatch";
    /// Release was not found.
    pub const RELEASE_NOT_FOUND: &str = "release_not_found";
    /// Activation was already deactivated.
    pub const ALREADY_DEACTIVATED: &str = "already_deactivated";
    /// Invalid API key.
    pub const INVALID_API_KEY: &str = "invalid_api_key";
    /// Machine-file decryption failed.
    pub const DECRYPTION_FAILED: &str = "DECRYPTION_FAILED";
    /// Machine file or offline token expired.
    pub const TOKEN_EXPIRED: &str = "TOKEN_EXPIRED";
    /// Machine file or offline token is not yet valid.
    pub const TOKEN_NOT_YET_VALID: &str = "TOKEN_NOT_YET_VALID";
    /// Machine file or offline token fingerprint mismatch.
    pub const FINGERPRINT_MISMATCH: &str = "FINGERPRINT_MISMATCH";
}
