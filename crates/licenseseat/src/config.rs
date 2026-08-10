//! SDK configuration types.

use crate::error::{Error, Result};
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
#[derive(Clone)]
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

    /// Prefix for persisted state keys.
    ///
    /// The default `licenseseat_` marker is automatically replaced with a
    /// deterministic product-scoped prefix, preventing different product slugs
    /// from sharing installation or license state. Two non-Tauri applications
    /// that reuse one product slug and the default shared directory should set
    /// an app-specific `storage_path` or custom prefix. A custom value is used
    /// verbatim after filename-safety normalization.
    pub storage_prefix: String,

    /// Optional directory for persisted SDK state.
    ///
    /// When omitted, the SDK uses the platform application-data directory under
    /// `licenseseat/`.
    pub storage_path: Option<PathBuf>,

    /// Custom installation fingerprint. If not set, the SDK generates and
    /// persists a random storage-scope installation identifier.
    ///
    /// This remains named `device_identifier` for backwards compatibility, but
    /// the API now treats `fingerprint` as the canonical field name.
    pub device_identifier: Option<String>,

    /// Automatically collect and send raw hardware fingerprint components
    /// (for example hostname or platform machine identifiers) when the SDK
    /// checks out a machine file for its own installation fingerprint.
    ///
    /// This is disabled by default for data minimization. Callers can still
    /// provide an explicit `fingerprint_components` map through
    /// `MachineFileCheckoutOptions` without enabling this global opt-in.
    pub send_fingerprint_components: bool,

    /// Ed25519 signing public key used for offline artifact verification.
    ///
    /// If omitted, the SDK can fetch the key by `kid` for verification during
    /// the current online process. Persisted fetched keys are diagnostic cache,
    /// not cross-process trust anchors. Offline startup requires both this
    /// value and [`Self::signing_key_id`] to be pinned in the application.
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

    /// Maximum age of a signed offline grant in days (`0` = no additional
    /// host-side age cap; the artifact's signed expiration still applies).
    /// Default: 0
    pub max_offline_days: u32,

    /// Maximum allowed clock skew for offline validation.
    /// Default: 5 minutes
    pub max_clock_skew: Duration,

    /// Send SDK, OS, architecture, coarse hardware-capacity, locale/timezone,
    /// and optional app-version/build telemetry with API requests.
    ///
    /// Applications are responsible for deciding whether collection is
    /// appropriate for their privacy policy and jurisdiction.
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
            send_fingerprint_components: false,
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

impl std::fmt::Debug for Config {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let api_key = (!self.api_key.is_empty()).then_some("[REDACTED]");
        let api_base_url = debug_api_base_url(&self.api_base_url);
        let device_identifier = self.device_identifier.as_ref().map(|_| "[REDACTED]");
        let signing_public_key = self.signing_public_key.as_ref().map(|_| "[REDACTED]");

        formatter
            .debug_struct("Config")
            .field("api_base_url", &api_base_url)
            .field("api_key", &api_key)
            .field("product_slug", &self.product_slug)
            .field("storage_prefix", &self.storage_prefix)
            .field("storage_path", &self.storage_path)
            .field("device_identifier", &device_identifier)
            .field(
                "send_fingerprint_components",
                &self.send_fingerprint_components,
            )
            .field("signing_public_key", &signing_public_key)
            .field("signing_key_id", &self.signing_key_id)
            .field("auto_validate_interval", &self.auto_validate_interval)
            .field("heartbeat_interval", &self.heartbeat_interval)
            .field("network_recheck_interval", &self.network_recheck_interval)
            .field("request_timeout", &self.request_timeout)
            .field("verify_ssl", &self.verify_ssl)
            .field("max_retries", &self.max_retries)
            .field("retry_delay", &self.retry_delay)
            .field("offline_fallback_mode", &self.offline_fallback_mode)
            .field(
                "offline_token_refresh_interval",
                &self.offline_token_refresh_interval,
            )
            .field(
                "enable_legacy_offline_tokens",
                &self.enable_legacy_offline_tokens,
            )
            .field("max_offline_days", &self.max_offline_days)
            .field("max_clock_skew", &self.max_clock_skew)
            .field("telemetry_enabled", &self.telemetry_enabled)
            .field("debug", &self.debug)
            .field("app_version", &self.app_version)
            .field("app_build", &self.app_build)
            .finish()
    }
}

fn debug_api_base_url(value: &str) -> String {
    url::Url::parse(value)
        .ok()
        .filter(|url| !url.cannot_be_a_base() && url.host().is_some())
        .map(|url| format!("{}{}", url.origin().ascii_serialization(), url.path()))
        .unwrap_or_else(|| "[INVALID URL]".into())
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

    /// Validate all configuration that can be checked without making a request.
    ///
    /// Individual API methods also validate their relevant fields so existing
    /// `LicenseSeat::new` callers remain fail closed. Applications that load
    /// configuration at startup can call this method to surface errors early.
    pub fn validate(&self) -> Result<()> {
        self.validate_network()?;
        self.validate_product_slug()?;

        let max_interval = Duration::from_secs(366 * 86_400);
        if !safe_config_text(&self.storage_prefix, 255)
            || self
                .device_identifier
                .as_deref()
                .is_some_and(|value| !safe_config_text_range(value, 8, 255))
            || self.auto_validate_interval > max_interval
            || self.heartbeat_interval > max_interval
            || self.network_recheck_interval > max_interval
            || self.offline_token_refresh_interval > max_interval
        {
            return Err(Error::Configuration(
                "SDK configuration exceeds supported safety limits".into(),
            ));
        }

        match (
            self.signing_public_key.as_deref(),
            self.signing_key_id.as_deref(),
        ) {
            (None, None) => {}
            (Some(public_key), Some(key_id))
                if safe_config_text_range(public_key, 40, 128) && safe_key_id(key_id) => {}
            _ => {
                return Err(Error::Configuration(
                    "signing_public_key and signing_key_id must be configured together".into(),
                ));
            }
        }

        Ok(())
    }

    pub(crate) fn validate_network(&self) -> Result<()> {
        if self
            .api_base_url
            .bytes()
            .any(|byte| byte.is_ascii_control())
            || self.api_base_url.contains('\\')
        {
            return Err(Error::Configuration("api_base_url is invalid".into()));
        }
        let url = url::Url::parse(&self.api_base_url)
            .map_err(|_| Error::Configuration("api_base_url is invalid".into()))?;
        let host = url
            .host_str()
            .ok_or_else(|| Error::Configuration("api_base_url must include a host".into()))?;
        let loopback = is_loopback_host(host);
        if url.scheme() != "https" && !(url.scheme() == "http" && loopback) {
            return Err(Error::Configuration(
                "api_base_url must use HTTPS (HTTP is allowed only for loopback development)"
                    .into(),
            ));
        }
        if !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
        {
            return Err(Error::Configuration(
                "api_base_url cannot contain credentials, a query, or a fragment".into(),
            ));
        }
        if !self.verify_ssl && !loopback {
            return Err(Error::Configuration(
                "TLS verification can only be disabled for a loopback endpoint".into(),
            ));
        }
        if self.api_base_url.len() > 2_048
            || self.api_key.len() > 512
            || self
                .api_key
                .bytes()
                .any(|byte| !(0x21..=0x7e).contains(&byte))
            || self.request_timeout.is_zero()
            || self.request_timeout > Duration::from_secs(300)
            || self.max_retries > 10
            || self.retry_delay > Duration::from_secs(60)
            || self
                .app_version
                .as_deref()
                .is_some_and(|value| !safe_config_text(value, 255))
            || self
                .app_build
                .as_deref()
                .is_some_and(|value| !safe_config_text(value, 255))
            || self.max_offline_days > 36_600
            || self.max_clock_skew > Duration::from_secs(86_400)
        {
            return Err(Error::Configuration(
                "network configuration exceeds supported safety limits".into(),
            ));
        }
        Ok(())
    }

    pub(crate) fn validate_product_slug(&self) -> Result<()> {
        if self.product_slug.is_empty() {
            return Err(Error::ProductSlugRequired);
        }
        if self.product_slug.len() > 100
            || !self.product_slug.bytes().enumerate().all(|(index, byte)| {
                byte.is_ascii_lowercase()
                    || byte.is_ascii_digit()
                    || (byte == b'-' && index > 0 && index + 1 < self.product_slug.len())
            })
            || self.product_slug.contains("--")
        {
            return Err(Error::Configuration("product_slug is invalid".into()));
        }
        Ok(())
    }
}

fn safe_config_text(value: &str, maximum_bytes: usize) -> bool {
    safe_config_text_range(value, 1, maximum_bytes)
}

fn safe_config_text_range(value: &str, minimum_bytes: usize, maximum_bytes: usize) -> bool {
    (minimum_bytes..=maximum_bytes).contains(&value.len())
        && !value.bytes().any(|byte| byte.is_ascii_control())
}

fn safe_key_id(value: &str) -> bool {
    safe_config_text(value, 255)
        && value.bytes().enumerate().all(|(index, byte)| {
            byte.is_ascii_alphanumeric() || (index > 0 && matches!(byte, b'-' | b'_' | b'.' | b':'))
        })
}

pub(crate) fn is_loopback_host(host: &str) -> bool {
    host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|address| address.is_loopback())
}

/// Offline fallback behavior when network validation fails.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum OfflineFallbackMode {
    /// Only fall back to offline validation for availability errors: transport
    /// failures, timeouts, HTTP 408, and 5xx responses.
    ///
    /// Other 4xx responses, malformed/substituted responses, configuration
    /// errors, and local state races return an error without consulting an
    /// older offline grant. Only specifically recognized authoritative license
    /// denials clear the last trusted grant.
    #[default]
    NetworkOnly,

    /// Attempt offline validation for transport errors, retryable server errors,
    /// and rate limiting. Authoritative 4xx decisions, malformed responses,
    /// configuration errors, and local state races always fail closed.
    Always,
}
