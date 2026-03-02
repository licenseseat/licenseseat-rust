//! SDK configuration types.

use std::time::Duration;

/// SDK configuration options.
///
/// # Example
///
/// ```rust
/// use licenseseat::{Config, OfflineFallbackMode};
/// use std::time::Duration;
///
/// let config = Config {
///     api_key: "sk_live_xxx".into(),
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

    /// Your LicenseSeat API key (required for most operations).
    pub api_key: String,

    /// Product slug - identifies your product (required).
    pub product_slug: String,

    /// Prefix for cache storage keys.
    /// Default: `licenseseat_`
    pub storage_prefix: String,

    /// Custom device identifier. If not set, auto-generated from hardware.
    pub device_identifier: Option<String>,

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

    /// Maximum number of retry attempts for failed API calls.
    /// Default: 3
    pub max_retries: u32,

    /// Initial delay between retries (exponential backoff applied).
    /// Default: 1 second
    pub retry_delay: Duration,

    /// Offline fallback strategy.
    /// Default: `NetworkOnly`
    pub offline_fallback_mode: OfflineFallbackMode,

    /// Interval to refresh offline token.
    /// Default: 72 hours
    pub offline_token_refresh_interval: Duration,

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
            device_identifier: None,
            auto_validate_interval: Duration::from_secs(3600),      // 1 hour
            heartbeat_interval: Duration::from_secs(300),           // 5 minutes
            network_recheck_interval: Duration::from_secs(30),
            max_retries: 3,
            retry_delay: Duration::from_secs(1),
            offline_fallback_mode: OfflineFallbackMode::NetworkOnly,
            offline_token_refresh_interval: Duration::from_secs(72 * 3600), // 72 hours
            max_offline_days: 0,
            max_clock_skew: Duration::from_secs(300),               // 5 minutes
            telemetry_enabled: true,
            debug: false,
            app_version: None,
            app_build: None,
        }
    }
}

impl Config {
    /// Create a new configuration with required fields.
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

    /// Builder-style method to set auto-validate interval.
    pub fn with_auto_validate_interval(mut self, interval: Duration) -> Self {
        self.auto_validate_interval = interval;
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
