//! Plugin configuration from tauri.conf.json.

use serde::Deserialize;

/// Plugin configuration read from tauri.conf.json.
///
/// Use a `pk_*` publishable API key in Tauri applications.
/// Keep `sk_*` secret keys server-side only.
///
/// ```json
/// {
///   "plugins": {
///     "licenseseat": {
///       "apiKey": "pk_live_xxx",
///       "productSlug": "your-product",
///       "autoValidateInterval": 3600,
///       "debug": false
///     }
///   }
/// }
/// ```
#[derive(Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PluginConfig {
    /// Your publishable LicenseSeat API key (`pk_*`, required).
    ///
    /// This key is safe to compile into a Tauri app binary.
    /// Keep `sk_*` secret keys server-side only.
    pub api_key: String,

    /// Your product slug (required).
    pub product_slug: String,

    /// Base URL for the LicenseSeat API.
    /// Default: `https://licenseseat.com/api/v1`
    #[serde(default)]
    pub api_base_url: Option<String>,

    /// Prefix for cached SDK state.
    #[serde(default)]
    pub storage_prefix: Option<String>,

    /// Optional directory for persisted SDK state.
    #[serde(default)]
    pub storage_path: Option<String>,

    /// Canonical fingerprint override for activation/device binding.
    ///
    /// This maps to the core SDK's backward-compatible `device_identifier` field.
    #[serde(default)]
    pub device_identifier: Option<String>,

    /// Opt in to collecting and sending raw hardware fingerprint components
    /// during automatic machine-file checkout. Default: false.
    #[serde(default)]
    pub send_fingerprint_components: Option<bool>,

    /// Optional Ed25519 public key used for machine-file/offline-token verification.
    #[serde(default)]
    pub signing_public_key: Option<String>,

    /// Optional key identifier associated with `signing_public_key`.
    #[serde(default)]
    pub signing_key_id: Option<String>,

    /// Interval for automatic license re-validation (in seconds).
    /// Default: 3600 (1 hour)
    #[serde(default)]
    pub auto_validate_interval: Option<u64>,

    /// Interval for heartbeat pings (in seconds).
    /// Default: 300 (5 minutes). Set to 0 to disable.
    #[serde(default)]
    pub heartbeat_interval: Option<u64>,

    /// Interval for network connectivity rechecks while offline (in seconds).
    /// Default: 30
    #[serde(default)]
    pub network_recheck_interval: Option<u64>,

    /// HTTP request timeout in seconds.
    /// Default: 30
    #[serde(default)]
    pub timeout_seconds: Option<u64>,

    /// Maximum retry attempts for retryable requests.
    /// Default: 3
    #[serde(default)]
    pub max_retries: Option<u32>,

    /// Initial retry delay in seconds. Exponential backoff is capped by the SDK.
    /// Default: 1
    #[serde(default)]
    pub retry_delay_seconds: Option<u64>,

    /// Whether TLS certificates should be verified.
    /// Default: true
    #[serde(default)]
    pub verify_ssl: Option<bool>,

    /// Offline fallback mode: "networkOnly", "always", or "allow_offline".
    ///
    /// - "networkOnly": Only fall back to offline validation for network errors
    /// - "always" / "allow_offline": Also fall back for rate limiting; signed
    ///   offline state never overrides authoritative client/business errors
    ///
    /// Default: "networkOnly"
    #[serde(default)]
    pub offline_fallback_mode: Option<String>,

    /// Maximum age of a signed offline grant in days.
    /// Default: 0 (no additional age cap)
    #[serde(default)]
    pub max_offline_days: Option<u32>,

    /// Maximum accepted clock skew for signed offline artifacts (in seconds).
    /// Default: 300 (5 minutes)
    #[serde(default)]
    pub max_clock_skew_seconds: Option<u64>,

    /// Interval for refreshing cached offline artifacts (in seconds).
    /// Default: 259200 (72 hours)
    #[serde(default)]
    pub offline_token_refresh_interval: Option<u64>,

    /// Enable legacy offline-token fallback after machine-file sync fails.
    /// Default: false
    #[serde(default)]
    pub enable_legacy_offline_tokens: Option<bool>,

    /// Enable telemetry collection.
    /// Default: true
    #[serde(default)]
    pub telemetry_enabled: Option<bool>,

    /// Enable debug logging.
    /// Default: false
    #[serde(default)]
    pub debug: Option<bool>,

    /// App version (for telemetry).
    #[serde(default)]
    pub app_version: Option<String>,

    /// App build (for telemetry).
    #[serde(default)]
    pub app_build: Option<String>,
}

impl std::fmt::Debug for PluginConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PluginConfig")
            .field(
                "api_key",
                &(!self.api_key.is_empty()).then_some("[REDACTED]"),
            )
            .field("product_slug", &self.product_slug)
            .field("api_base_url", &self.api_base_url)
            .field("storage_prefix", &self.storage_prefix)
            .field("storage_path", &self.storage_path)
            .field(
                "device_identifier",
                &self.device_identifier.as_ref().map(|_| "[REDACTED]"),
            )
            .field(
                "send_fingerprint_components",
                &self.send_fingerprint_components,
            )
            .field(
                "signing_public_key",
                &self.signing_public_key.as_ref().map(|_| "[REDACTED]"),
            )
            .field("signing_key_id", &self.signing_key_id)
            .field("auto_validate_interval", &self.auto_validate_interval)
            .field("heartbeat_interval", &self.heartbeat_interval)
            .field("network_recheck_interval", &self.network_recheck_interval)
            .field("timeout_seconds", &self.timeout_seconds)
            .field("max_retries", &self.max_retries)
            .field("retry_delay_seconds", &self.retry_delay_seconds)
            .field("verify_ssl", &self.verify_ssl)
            .field("offline_fallback_mode", &self.offline_fallback_mode)
            .field("max_offline_days", &self.max_offline_days)
            .field("max_clock_skew_seconds", &self.max_clock_skew_seconds)
            .field(
                "offline_token_refresh_interval",
                &self.offline_token_refresh_interval,
            )
            .field(
                "enable_legacy_offline_tokens",
                &self.enable_legacy_offline_tokens,
            )
            .field("telemetry_enabled", &self.telemetry_enabled)
            .field("debug", &self.debug)
            .field("app_version", &self.app_version)
            .field("app_build", &self.app_build)
            .finish()
    }
}
