//! SDK configuration types.

use std::path::PathBuf;
use std::time::Duration;

/// SDK configuration options.
///
/// Use a `pk_*` publishable API key in desktop and client applications.
/// Keep `sk_*` secret keys server-side only.
///
/// # Example
///
/// ```rust
/// use licenseseat::{Config, OfflineFallbackMode};
/// use std::time::Duration;
///
/// let config = Config {
///     api_key: "pk_live_xxx".into(),
///     product_slug: "my-app".into(),
///     auto_validate_interval: Duration::from_secs(1800), // 30 minutes
///     offline_fallback_mode: OfflineFallbackMode::NetworkOnly,
///     max_offline_days: 7,
///     debug: true,
///     ..Default::default()
/// };
/// ```
#[derive(Debug, Clone)]
pub struct Config {
    /// Base URL for the LicenseSeat API.
    /// Default: `https://licenseseat.com/api/v1`
    pub api_base_url: String,

    /// Your publishable LicenseSeat API key (`pk_*`, required for most operations).
    ///
    /// This key is safe to embed in desktop and client applications.
    /// Keep `sk_*` secret keys server-side only.
    pub api_key: String,

    /// Product slug - identifies your product (required).
    pub product_slug: String,

    /// Prefix for cache storage keys.
    /// Default: `licenseseat_`
    pub storage_prefix: String,

    /// Optional directory for persisted SDK state.
    ///
    /// When omitted, the SDK uses the platform cache directory under
    /// `licenseseat/`.
    pub storage_path: Option<PathBuf>,

    /// Custom device fingerprint. If not set, auto-generated from hardware.
    ///
    /// This remains named `device_identifier` for backwards compatibility, but
    /// the API now treats `fingerprint` as the canonical field name.
    pub device_identifier: Option<String>,

    /// Ed25519 signing public key used for offline artifact verification.
    ///
    /// If omitted, the SDK will fetch and cache the key by `kid` on first use.
    pub signing_public_key: Option<String>,

    /// Key identifier for the configured signing public key.
    pub signing_key_id: Option<String>,

    /// Interval for automatic license re-validation.
    /// Default: 1 hour
    pub auto_validate_interval: Duration,

    /// Interval for standalone heartbeat pings.
    /// Set to zero to disable auto-heartbeat.
    /// Default: 5 minutes
    pub heartbeat_interval: Duration,

    /// Interval to check network connectivity when offline.
    /// Default: 30 seconds
    pub network_recheck_interval: Duration,

    /// HTTP request timeout.
    /// Default: 30 seconds
    pub request_timeout: Duration,

    /// Whether TLS certificates should be verified.
    /// Default: true
    pub verify_ssl: bool,

    /// Maximum number of retry attempts for failed API calls.
    /// Default: 3
    pub max_retries: u32,

    /// Initial delay between retries (exponential backoff applied).
    /// Default: 1 second
    pub retry_delay: Duration,

    /// Offline fallback strategy.
    /// Default: `NetworkOnly`
    pub offline_fallback_mode: OfflineFallbackMode,

    /// Interval to refresh offline artifacts.
    ///
    /// Machine files are refreshed first. Legacy offline tokens are only fetched
    /// when `enable_legacy_offline_tokens` is enabled.
    /// Default: 72 hours
    pub offline_token_refresh_interval: Duration,

    /// Enable legacy offline-token fetching as a fallback after machine-file sync fails.
    ///
    /// Disabled by default; machine files are the preferred offline artifact.
    pub enable_legacy_offline_tokens: bool,

    /// Maximum days a license can be used offline (0 = disabled).
    /// Default: 0
    pub max_offline_days: u32,

    /// Maximum allowed clock skew for offline validation.
    /// Default: 5 minutes
    pub max_clock_skew: Duration,

    /// Enable telemetry collection (set false for GDPR compliance).
    /// Default: true
    pub telemetry_enabled: bool,

    /// Enable debug logging.
    /// Default: false
    pub debug: bool,

    /// User-provided app version for telemetry.
    pub app_version: Option<String>,

    /// User-provided app build for telemetry.
    pub app_build: Option<String>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            api_base_url: "https://licenseseat.com/api/v1".into(),
            api_key: String::new(),
            product_slug: String::new(),
            storage_prefix: "licenseseat_".into(),
            storage_path: None,
            device_identifier: None,
            signing_public_key: None,
            signing_key_id: None,
            auto_validate_interval: Duration::from_secs(3600), // 1 hour
            heartbeat_interval: Duration::from_secs(300),      // 5 minutes
            network_recheck_interval: Duration::from_secs(30),
            request_timeout: Duration::from_secs(30),
            verify_ssl: true,
            max_retries: 3,
            retry_delay: Duration::from_secs(1),
            offline_fallback_mode: OfflineFallbackMode::NetworkOnly,
            offline_token_refresh_interval: Duration::from_secs(72 * 3600), // 72 hours
            enable_legacy_offline_tokens: false,
            max_offline_days: 0,
            max_clock_skew: Duration::from_secs(300), // 5 minutes
            telemetry_enabled: true,
            debug: false,
            app_version: None,
            app_build: None,
        }
    }
}

impl Config {
    /// Create a new configuration with required fields.
    ///
    /// `api_key` should be your publishable `pk_*` API key for client apps.
    pub fn new(api_key: impl Into<String>, product_slug: impl Into<String>) -> Self {
        Self {
            api_key: api_key.into(),
            product_slug: product_slug.into(),
            ..Default::default()
        }
    }

    /// Builder-style method to set debug mode.
    pub fn with_debug(mut self, debug: bool) -> Self {
        self.debug = debug;
        self
    }

    /// Builder-style method to set a custom storage directory.
    pub fn with_storage_path(mut self, path: impl Into<PathBuf>) -> Self {
        self.storage_path = Some(path.into());
        self
    }

    /// Builder-style method to set auto-validate interval.
    pub fn with_auto_validate_interval(mut self, interval: Duration) -> Self {
        self.auto_validate_interval = interval;
        self
    }

    /// Builder-style method to set the HTTP request timeout.
    pub fn with_request_timeout(mut self, timeout: Duration) -> Self {
        self.request_timeout = timeout;
        self
    }

    /// Builder-style method to enable or disable TLS verification.
    pub fn with_verify_ssl(mut self, verify_ssl: bool) -> Self {
        self.verify_ssl = verify_ssl;
        self
    }

    /// Builder-style method to set offline fallback mode.
    pub fn with_offline_fallback(mut self, mode: OfflineFallbackMode) -> Self {
        self.offline_fallback_mode = mode;
        self
    }

    /// Builder-style method to set max offline days.
    pub fn with_max_offline_days(mut self, days: u32) -> Self {
        self.max_offline_days = days;
        self
    }
}

/// Offline fallback behavior when network validation fails.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum OfflineFallbackMode {
    /// Only fall back to offline validation for network errors
    /// (timeouts, connectivity issues, 5xx responses).
    /// Business logic errors (4xx) immediately invalidate the license.
    #[default]
    NetworkOnly,

    /// Always attempt offline validation on any failure.
    Always,
}
