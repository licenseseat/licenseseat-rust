//! # Tauri Plugin for LicenseSeat
//!
//! This plugin provides LicenseSeat software licensing integration for Tauri apps.
//!
//! ## Features
//!
//! - License activation, validation, and deactivation
//! - Offline validation with Ed25519 signatures
//! - Automatic re-validation in the background
//! - Entitlement checking for feature flags
//! - Event emission to the frontend
//!
//! ## Installation
//!
//! Add the plugin to your `Cargo.toml`:
//!
//! ```toml
//! [dependencies]
//! tauri-plugin-licenseseat = "0.1"
//! ```
//!
//! Register the plugin in your Tauri app:
//!
//! ```rust,ignore
//! fn main() {
//!     tauri::Builder::default()
//!         .plugin(tauri_plugin_licenseseat::init())
//!         .run(tauri::generate_context!())
//!         .expect("error while running tauri application");
//! }
//! ```
//!
//! ## Configuration
//!
//! Add configuration to `tauri.conf.json`:
//!
//! ```json
//! {
//!   "plugins": {
//!     "licenseseat": {
//!       "apiKey": "your-api-key",
//!       "productSlug": "your-product"
//!     }
//!   }
//! }
//! ```
//!
//! ## JavaScript API
//!
//! ```typescript
//! import { activate, validate, deactivate, checkEntitlement } from '@licenseseat/tauri-plugin';
//!
//! // Activate a license
//! const license = await activate('LICENSE-KEY');
//!
//! // Check entitlements
//! const hasPro = await checkEntitlement('pro-features');
//! ```

// Re-export the core SDK for Rust users
pub use licenseseat;

mod commands;
mod config;
mod error;

use tauri::{
    Manager, Runtime,
    plugin::{Builder, TauriPlugin},
};

pub use config::PluginConfig;
pub use error::{Error, Result};

/// Initialize the LicenseSeat plugin.
///
/// # Example
///
/// ```rust,ignore
/// fn main() {
///     tauri::Builder::default()
///         .plugin(tauri_plugin_licenseseat::init())
///         .run(tauri::generate_context!())
///         .expect("error while running tauri application");
/// }
/// ```
pub fn init<R: Runtime>() -> TauriPlugin<R, PluginConfig> {
    Builder::<R, PluginConfig>::new("licenseseat")
        .setup(|app, api| {
            let config = api.config().clone();

            // Auto-detect app version from Tauri package info if not explicitly set
            let app_version = config
                .app_version
                .clone()
                .or_else(|| Some(app.package_info().version.to_string()));

            // Auto-detect app name for build info if not set
            let app_build = config
                .app_build
                .clone()
                .or_else(|| Some(app.package_info().name.clone()));

            // Parse offline fallback mode from config string
            let offline_fallback_mode = match config.offline_fallback_mode.as_deref() {
                Some("always") | Some("allow_offline") => licenseseat::OfflineFallbackMode::Always,
                _ => licenseseat::OfflineFallbackMode::NetworkOnly,
            };

            // Convert plugin config to SDK config
            let sdk_config = licenseseat::Config {
                api_key: config.api_key.clone(),
                product_slug: config.product_slug.clone(),
                api_base_url: config
                    .api_base_url
                    .unwrap_or_else(|| "https://licenseseat.com/api/v1".into()),
                auto_validate_interval: std::time::Duration::from_secs(
                    config.auto_validate_interval.unwrap_or(3600),
                ),
                heartbeat_interval: std::time::Duration::from_secs(
                    config.heartbeat_interval.unwrap_or(300),
                ),
                offline_fallback_mode,
                max_offline_days: config.max_offline_days.unwrap_or(0),
                debug: config.debug.unwrap_or(false),
                telemetry_enabled: config.telemetry_enabled.unwrap_or(true),
                app_version,
                app_build,
                ..Default::default()
            };

            // Create the SDK instance and manage it
            let sdk = licenseseat::LicenseSeat::new(sdk_config);
            app.manage(sdk);

            tracing::info!("LicenseSeat plugin initialized");
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::activate,
            commands::validate,
            commands::deactivate,
            commands::heartbeat,
            commands::get_status,
            commands::check_entitlement,
            commands::has_entitlement,
            commands::get_license,
            commands::reset,
        ])
        .build()
}
