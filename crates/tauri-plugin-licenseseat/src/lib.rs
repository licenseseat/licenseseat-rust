//! # Tauri Plugin for LicenseSeat
//!
//! This plugin provides LicenseSeat software licensing integration for Tauri apps.
//!
//! ## Features
//!
//! - License activation, validation, and deactivation
//! - Machine-file-first offline validation with Ed25519 + AES-256-GCM
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
//! tauri-plugin-licenseseat = "0.5.1"
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
//! Use a `pk_*` publishable API key in Tauri applications.
//! Keep `sk_*` secret keys server-side only.
//!
//! Add configuration to `tauri.conf.json`:
//!
//! ```json
//! {
//!   "plugins": {
//!     "licenseseat": {
//!       "apiKey": "pk_live_xxx",
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
    Emitter, Manager, Runtime,
    plugin::{Builder, TauriPlugin},
};

pub use config::PluginConfig;
pub use error::{Error, Result};

fn resolve_env_placeholder(value: String) -> String {
    if let Some(name) = value.strip_prefix('$') {
        std::env::var(name).unwrap_or(value)
    } else {
        value
    }
}

fn resolve_optional_env_placeholder(value: Option<String>) -> Option<String> {
    value.map(resolve_env_placeholder)
}

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
            let api_key = resolve_env_placeholder(config.api_key.clone());
            let product_slug = resolve_env_placeholder(config.product_slug.clone());
            let api_base_url = resolve_optional_env_placeholder(config.api_base_url.clone());
            let storage_prefix = resolve_optional_env_placeholder(config.storage_prefix.clone());
            let storage_path = resolve_optional_env_placeholder(config.storage_path.clone());
            let device_identifier =
                resolve_optional_env_placeholder(config.device_identifier.clone());
            let signing_public_key =
                resolve_optional_env_placeholder(config.signing_public_key.clone());
            let signing_key_id = resolve_optional_env_placeholder(config.signing_key_id.clone());
            let app_version = resolve_optional_env_placeholder(
                config
                    .app_version
                    .clone()
                    .or_else(|| Some(app.package_info().version.to_string())),
            );
            let app_build = resolve_optional_env_placeholder(
                config
                    .app_build
                    .clone()
                    .or_else(|| Some(app.package_info().name.clone())),
            );

            let offline_fallback_mode = match config.offline_fallback_mode.as_deref() {
                Some("always")
                | Some("allow_offline")
                | Some("offline_first")
                | Some("offlineFirst") => licenseseat::OfflineFallbackMode::Always,
                _ => licenseseat::OfflineFallbackMode::NetworkOnly,
            };

            // Convert plugin config to SDK config
            let sdk_config = licenseseat::Config {
                api_key,
                product_slug,
                api_base_url: api_base_url
                    .unwrap_or_else(|| "https://licenseseat.com/api/v1".into()),
                storage_prefix: storage_prefix.unwrap_or_else(|| "licenseseat_".into()),
                storage_path: storage_path.map(Into::into),
                device_identifier,
                signing_public_key,
                signing_key_id,
                auto_validate_interval: std::time::Duration::from_secs(
                    config.auto_validate_interval.unwrap_or(3600),
                ),
                heartbeat_interval: std::time::Duration::from_secs(
                    config.heartbeat_interval.unwrap_or(300),
                ),
                network_recheck_interval: std::time::Duration::from_secs(
                    config.network_recheck_interval.unwrap_or(30),
                ),
                request_timeout: std::time::Duration::from_secs(
                    config.timeout_seconds.unwrap_or(30),
                ),
                verify_ssl: config.verify_ssl.unwrap_or(true),
                offline_fallback_mode,
                offline_token_refresh_interval: std::time::Duration::from_secs(
                    config.offline_token_refresh_interval.unwrap_or(72 * 3600),
                ),
                enable_legacy_offline_tokens: config.enable_legacy_offline_tokens.unwrap_or(false),
                max_offline_days: config.max_offline_days.unwrap_or(0),
                debug: config.debug.unwrap_or(false),
                telemetry_enabled: config.telemetry_enabled.unwrap_or(true),
                app_version,
                app_build,
                ..Default::default()
            };

            // Create the SDK instance and manage it
            app.manage(sdk_config);
            let sdk =
                licenseseat::LicenseSeat::new(app.state::<licenseseat::Config>().inner().clone());
            let event_sdk = sdk.clone();
            let app_handle = app.clone();
            tauri::async_runtime::spawn(async move {
                let mut rx = event_sdk.subscribe();
                while let Ok(event) = rx.recv().await {
                    let event_name =
                        format!("licenseseat://{}", event.kind.to_string().replace(':', "-"));
                    let payload = commands::event_payload_to_json(event.data);
                    let _ = app_handle.emit(&event_name, payload);
                }
            });
            app.manage(sdk);

            tracing::info!("LicenseSeat plugin initialized");
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::activate,
            commands::validate_key,
            commands::validate,
            commands::deactivate,
            commands::deactivate_key,
            commands::heartbeat,
            commands::heartbeat_key,
            commands::get_status,
            commands::get_client_status,
            commands::is_online,
            commands::get_fingerprint,
            commands::restore_license,
            commands::health,
            commands::check_entitlement,
            commands::get_entitlements,
            commands::has_entitlement,
            commands::get_license,
            commands::get_state,
            commands::get_admin_snapshot,
            commands::get_latest_release,
            commands::list_releases,
            commands::generate_download_token,
            commands::generate_offline_token,
            commands::verify_offline_token,
            commands::checkout_machine_file,
            commands::fetch_signing_key,
            commands::sync_offline_assets,
            commands::verify_machine_file,
            commands::reset,
        ])
        .build()
}
