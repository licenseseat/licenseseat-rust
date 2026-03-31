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
#[derive(Debug, Clone, Default, Deserialize)]
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

    /// Whether TLS certificates should be verified.
    /// Default: true
    #[serde(default)]
    pub verify_ssl: Option<bool>,

    /// Offline fallback mode: "networkOnly", "always", or "allow_offline".
    ///
    /// - "networkOnly": Only fall back to offline validation for network errors
    /// - "always" / "allow_offline": Always fall back to offline validation
    ///
    /// Default: "networkOnly"
    #[serde(default)]
    pub offline_fallback_mode: Option<String>,

    /// Maximum days a license can be used offline.
    /// Default: 0 (disabled)
    #[serde(default)]
    pub max_offline_days: Option<u32>,

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
