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
//! tauri-plugin-licenseseat = "0.6.0"
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

fn resolve_env_placeholder(
    value: String,
    field: &str,
) -> std::result::Result<String, licenseseat::Error> {
    resolve_env_placeholder_with_policy(value, field, cfg!(debug_assertions))
}

fn resolve_env_placeholder_with_policy(
    value: String,
    field: &str,
    allow_runtime_environment: bool,
) -> std::result::Result<String, licenseseat::Error> {
    if let Some(name) = value.strip_prefix('$') {
        if name.is_empty() {
            return Err(licenseseat::Error::Configuration(format!(
                "{field} contains an empty environment-variable placeholder"
            )));
        }
        if !allow_runtime_environment {
            return Err(licenseseat::Error::Configuration(format!(
                "{field} uses a runtime environment-variable placeholder, which is disabled in release builds because licensing trust configuration must be compiled into the application"
            )));
        }
        std::env::var(name).map_err(|_| {
            licenseseat::Error::Configuration(format!(
                "{field} references unset environment variable {name}"
            ))
        })
    } else {
        Ok(value)
    }
}

fn resolve_optional_env_placeholder(
    value: Option<String>,
    field: &str,
) -> std::result::Result<Option<String>, licenseseat::Error> {
    value
        .map(|value| resolve_env_placeholder(value, field))
        .transpose()
}

fn parse_offline_fallback_mode(
    value: Option<&str>,
) -> std::result::Result<licenseseat::OfflineFallbackMode, licenseseat::Error> {
    match value {
        None | Some("networkOnly" | "network_only") => {
            Ok(licenseseat::OfflineFallbackMode::NetworkOnly)
        }
        Some("always" | "allow_offline" | "allowOffline" | "offline_first" | "offlineFirst") => {
            Ok(licenseseat::OfflineFallbackMode::Always)
        }
        Some(value) => Err(licenseseat::Error::Configuration(format!(
            "unsupported offlineFallbackMode {value:?}; expected networkOnly or always"
        ))),
    }
}

fn validate_plugin_config(config: &PluginConfig) -> std::result::Result<(), licenseseat::Error> {
    if config.timeout_seconds == Some(0) {
        return Err(licenseseat::Error::Configuration(
            "timeoutSeconds must be greater than zero".into(),
        ));
    }
    if config.max_retries.is_some_and(|retries| retries > 10) {
        return Err(licenseseat::Error::Configuration(
            "maxRetries may not exceed 10".into(),
        ));
    }
    Ok(())
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
            validate_plugin_config(&config)?;
            let api_key = resolve_env_placeholder(config.api_key.clone(), "apiKey")?;
            let product_slug =
                resolve_env_placeholder(config.product_slug.clone(), "productSlug")?;
            if api_key.trim().is_empty() || api_key != api_key.trim() {
                return Err(licenseseat::Error::Configuration(
                    "apiKey is required and may not contain surrounding whitespace".into(),
                )
                .into());
            }
            if api_key.starts_with("sk_") {
                return Err(licenseseat::Error::Configuration(
                    "secret sk_* API keys must never be embedded in a Tauri application; use a publishable pk_* key"
                        .into(),
                )
                .into());
            }
            if product_slug.trim().is_empty() || product_slug != product_slug.trim() {
                return Err(licenseseat::Error::Configuration(
                    "productSlug is required and may not contain surrounding whitespace".into(),
                )
                .into());
            }
            let api_base_url =
                resolve_optional_env_placeholder(config.api_base_url.clone(), "apiBaseUrl")?;
            let storage_prefix =
                resolve_optional_env_placeholder(config.storage_prefix.clone(), "storagePrefix")?;
            let storage_path =
                resolve_optional_env_placeholder(config.storage_path.clone(), "storagePath")?;
            let device_identifier = resolve_optional_env_placeholder(
                config.device_identifier.clone(),
                "deviceIdentifier",
            )?;
            let signing_public_key = resolve_optional_env_placeholder(
                config.signing_public_key.clone(),
                "signingPublicKey",
            )?;
            let signing_key_id =
                resolve_optional_env_placeholder(config.signing_key_id.clone(), "signingKeyId")?;
            let app_version = resolve_optional_env_placeholder(
                config
                    .app_version
                    .clone()
                    .or_else(|| Some(app.package_info().version.to_string())),
                "appVersion",
            )?;
            let app_build =
                resolve_optional_env_placeholder(config.app_build.clone(), "appBuild")?;

            let offline_fallback_mode =
                parse_offline_fallback_mode(config.offline_fallback_mode.as_deref())?;
            // Convert plugin config to SDK config
            let sdk_config = licenseseat::Config {
                api_key,
                product_slug,
                api_base_url: api_base_url
                    .unwrap_or_else(|| "https://licenseseat.com/api/v1".into()),
                storage_prefix: storage_prefix.unwrap_or_else(|| "licenseseat_".into()),
                storage_path: match storage_path {
                    Some(path) => Some(path.into()),
                    None => Some(app.path().app_data_dir()?.join("licenseseat")),
                },
                device_identifier,
                send_fingerprint_components: config.send_fingerprint_components.unwrap_or(false),
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
                max_retries: config.max_retries.unwrap_or(3),
                retry_delay: std::time::Duration::from_secs(
                    config.retry_delay_seconds.unwrap_or(1),
                ),
                verify_ssl: config.verify_ssl.unwrap_or(true),
                offline_fallback_mode,
                offline_token_refresh_interval: std::time::Duration::from_secs(
                    config.offline_token_refresh_interval.unwrap_or(72 * 3600),
                ),
                enable_legacy_offline_tokens: config.enable_legacy_offline_tokens.unwrap_or(false),
                max_offline_days: config.max_offline_days.unwrap_or(0),
                max_clock_skew: std::time::Duration::from_secs(
                    config.max_clock_skew_seconds.unwrap_or(300),
                ),
                debug: config.debug.unwrap_or(false),
                telemetry_enabled: config.telemetry_enabled.unwrap_or(true),
                app_version,
                app_build,
            };

            let sdk = licenseseat::LicenseSeat::try_new(sdk_config)?;
            // Subscribe synchronously before either spawned task can run. This
            // prevents the automatic restore task from winning scheduler order
            // and dropping its first lifecycle events before the bridge exists.
            let mut event_rx = sdk.subscribe();
            let app_handle = app.clone();
            tauri::async_runtime::spawn(async move {
                loop {
                    match event_rx.recv().await {
                        Ok(event) => {
                            let event_name = format!(
                                "licenseseat://{}",
                                event.kind.to_string().replace(':', "-")
                            );
                            let payload = commands::event_payload_to_json(event.data);
                            let _ = app_handle.emit(&event_name, payload);
                        }
                        Err(tokio::sync::broadcast::error::RecvError::Lagged(skipped)) => {
                            tracing::warn!(
                                skipped,
                                "LicenseSeat Tauri event bridge lagged; continuing with current events"
                            );
                        }
                        Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                    }
                }
            });
            app.manage(sdk.clone());

            tauri::async_runtime::spawn(async move {
                let restore = sdk.restore_license().await;
                if !restore.restored && restore.error.is_some() {
                    tracing::warn!(
                        error = restore.error.as_deref().unwrap_or_default(),
                        "LicenseSeat cached-session restore failed"
                    );
                }
            });

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fallback_mode_parser_accepts_documented_and_legacy_spellings() {
        assert_eq!(
            parse_offline_fallback_mode(None).unwrap(),
            licenseseat::OfflineFallbackMode::NetworkOnly
        );
        assert_eq!(
            parse_offline_fallback_mode(Some("networkOnly")).unwrap(),
            licenseseat::OfflineFallbackMode::NetworkOnly
        );
        for value in [
            "always",
            "allow_offline",
            "allowOffline",
            "offline_first",
            "offlineFirst",
        ] {
            assert_eq!(
                parse_offline_fallback_mode(Some(value)).unwrap(),
                licenseseat::OfflineFallbackMode::Always
            );
        }
    }

    #[test]
    fn fallback_mode_parser_rejects_typos() {
        assert!(parse_offline_fallback_mode(Some("allways")).is_err());
        assert!(parse_offline_fallback_mode(Some("")).is_err());
    }

    #[test]
    fn release_policy_rejects_runtime_environment_configuration() {
        let error = resolve_env_placeholder_with_policy(
            "$LICENSESEAT_UNTRUSTED_RUNTIME_VALUE".into(),
            "apiBaseUrl",
            false,
        )
        .unwrap_err();
        assert!(matches!(
            error,
            licenseseat::Error::Configuration(message)
                if message.contains("disabled in release builds")
                    && message.contains("compiled into the application")
        ));

        assert_eq!(
            resolve_env_placeholder_with_policy(
                "https://licenseseat.com/api/v1".into(),
                "apiBaseUrl",
                false,
            )
            .unwrap(),
            "https://licenseseat.com/api/v1"
        );
    }

    #[test]
    fn plugin_config_debug_redacts_credentials_and_device_identity() {
        let config = PluginConfig {
            api_key: "pk_live_do-not-log".into(),
            product_slug: "product".into(),
            device_identifier: Some("private-device".into()),
            signing_public_key: Some("private-public-key-material".into()),
            ..Default::default()
        };
        let output = format!("{config:?}");
        assert!(!output.contains("pk_live_do-not-log"));
        assert!(!output.contains("private-device"));
        assert!(!output.contains("private-public-key-material"));
        assert!(output.contains("[REDACTED]"));
    }

    #[test]
    fn plugin_config_exposes_resilience_and_clock_controls() {
        let config: PluginConfig = serde_json::from_value(serde_json::json!({
            "apiKey": "pk_test",
            "productSlug": "product",
            "timeoutSeconds": 15,
            "maxRetries": 5,
            "retryDelaySeconds": 2,
            "maxClockSkewSeconds": 60,
            "sendFingerprintComponents": true
        }))
        .unwrap();
        assert_eq!(config.timeout_seconds, Some(15));
        assert_eq!(config.max_retries, Some(5));
        assert_eq!(config.retry_delay_seconds, Some(2));
        assert_eq!(config.max_clock_skew_seconds, Some(60));
        assert_eq!(config.send_fingerprint_components, Some(true));
        assert!(validate_plugin_config(&config).is_ok());

        let mut invalid = config;
        invalid.timeout_seconds = Some(0);
        assert!(validate_plugin_config(&invalid).is_err());

        invalid.timeout_seconds = Some(15);
        invalid.network_recheck_interval = Some(0);
        invalid.offline_token_refresh_interval = Some(0);
        assert!(validate_plugin_config(&invalid).is_ok());

        invalid.max_retries = Some(11);
        assert!(validate_plugin_config(&invalid).is_err());
    }
}
