//! Plugin configuration from tauri.conf.json.

use serde::Deserialize;

/// Plugin configuration read from tauri.conf.json.
///
/// ```json
/// {
///   "plugins": {
///     "licenseseat": {
///       "apiKey": "your-api-key",
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
    /// Your LicenseSeat API key (required).
    pub api_key: String,

    /// Your product slug (required).
    pub product_slug: String,

    /// Base URL for the LicenseSeat API.
    /// Default: `https://licenseseat.com/api/v1`
    #[serde(default)]
    pub api_base_url: Option<String>,

    /// Interval for automatic license re-validation (in seconds).
    /// Default: 3600 (1 hour)
    #[serde(default)]
    pub auto_validate_interval: Option<u64>,

    /// Interval for heartbeat pings (in seconds).
    /// Default: 300 (5 minutes). Set to 0 to disable.
    #[serde(default)]
    pub heartbeat_interval: Option<u64>,

    /// Offline fallback mode: "networkOnly", "always", or "allow_offline".
    /// - "networkOnly": Only fall back to offline validation for network errors
    /// - "always" / "allow_offline": Always fall back to offline validation
    /// Default: "networkOnly"
    #[serde(default)]
    pub offline_fallback_mode: Option<String>,

    /// Maximum days a license can be used offline.
    /// Default: 0 (disabled)
    #[serde(default)]
    pub max_offline_days: Option<u32>,

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
