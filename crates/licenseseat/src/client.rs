//! Main LicenseSeat client implementation.

use crate::cache::LicenseCache;
use crate::config::{Config, OfflineFallbackMode};
use crate::device::generate_fingerprint;
use crate::error::{Error, Result};
use crate::events::{Event, EventKind};
use crate::models::*;
use crate::telemetry::Telemetry;

use chrono::Utc;
use reqwest::header::{AUTHORIZATION, CONTENT_TYPE, HeaderMap, HeaderValue, USER_AGENT};
use serde::de::DeserializeOwned;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::broadcast;
use tracing::{debug, warn};

#[cfg(feature = "offline")]
use crate::device::collect_fingerprint_components;
#[cfg(feature = "offline")]
use base64::Engine;

/// The main LicenseSeat SDK client.
///
/// This is the primary interface for interacting with the LicenseSeat API.
/// Create an instance with [`LicenseSeat::new`] and use it to activate,
/// validate, and manage licenses.
///
/// # Example
///
/// ```rust,no_run
/// use licenseseat::{LicenseSeat, Config};
///
/// #[tokio::main]
/// async fn main() -> licenseseat::Result<()> {
///     let sdk = LicenseSeat::new(Config::new("api-key", "product-slug"));
///
///     // Activate a license
///     let license = sdk.activate("LICENSE-KEY").await?;
///
///     // Check entitlements
///     if sdk.check_entitlement("pro").active {
///         println!("Pro features enabled!");
///     }
///
///     Ok(())
/// }
/// ```
#[derive(Clone)]
pub struct LicenseSeat {
    inner: Arc<LicenseSeatInner>,
}

struct LicenseSeatInner {
    config: Config,
    http: reqwest::Client,
    cache: LicenseCache,
    event_tx: broadcast::Sender<Event>,
    fingerprint: String,
    is_online: AtomicBool,
    /// Flag to stop support/background tasks.
    background_tasks_running: AtomicBool,
    support_tasks_generation: AtomicU64,
    auto_validation_running: AtomicBool,
    auto_validation_generation: AtomicU64,
    heartbeat_running: AtomicBool,
    heartbeat_generation: AtomicU64,
    last_heartbeat: Mutex<Option<HeartbeatResponse>>,
    last_heartbeat_error: Mutex<Option<String>>,
    last_health: Mutex<Option<HealthResponse>>,
    last_health_error: Mutex<Option<String>>,
    next_auto_validation_at: Mutex<Option<chrono::DateTime<Utc>>>,
}

impl LicenseSeat {
    /// Create a new LicenseSeat SDK instance.
    pub fn new(config: Config) -> Self {
        let fingerprint = config
            .device_identifier
            .as_deref()
            .filter(|value| !value.is_empty())
            .map(ToString::to_string)
            .unwrap_or_else(generate_fingerprint);
        let http = build_http_client(&config);
        let cache = LicenseCache::new(&config.storage_prefix, config.storage_path.clone());
        let (event_tx, _) = broadcast::channel(64);

        let inner = Arc::new(LicenseSeatInner {
            config,
            http,
            cache,
            event_tx,
            fingerprint,
            is_online: AtomicBool::new(true),
            background_tasks_running: AtomicBool::new(false),
            support_tasks_generation: AtomicU64::new(0),
            auto_validation_running: AtomicBool::new(false),
            auto_validation_generation: AtomicU64::new(0),
            heartbeat_running: AtomicBool::new(false),
            heartbeat_generation: AtomicU64::new(0),
            last_heartbeat: Mutex::new(None),
            last_heartbeat_error: Mutex::new(None),
            last_health: Mutex::new(None),
            last_health_error: Mutex::new(None),
            next_auto_validation_at: Mutex::new(None),
        });

        let sdk = Self { inner };

        // Check for cached license on startup
        if let Some(license) = sdk.inner.cache.get_license() {
            debug!("Loaded cached license: {}", license.license_key);
            sdk.emit(Event::with_license(
                EventKind::LicenseLoaded,
                license.clone(),
            ));

            // Start background tasks if we have a cached license
            sdk.start_background_tasks();
        }

        sdk
    }

    // ========================================================================
    // Public API
    // ========================================================================

    /// Activate a license key.
    ///
    /// This registers the current device against the license and returns
    /// the activation details.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The license key is invalid or not found
    /// - The seat limit has been exceeded
    /// - Network errors occur
    pub async fn activate(&self, license_key: &str) -> Result<License> {
        self.activate_with_options(license_key, ActivationOptions::default())
            .await
    }

    /// Activate a license with custom options.
    pub async fn activate_with_options(
        &self,
        license_key: &str,
        options: ActivationOptions,
    ) -> Result<License> {
        let product_slug = self.require_product_slug()?;
        let device_id = select_fingerprint_alias(
            options.fingerprint.as_deref(),
            options.device_id.as_deref(),
            options.device_fingerprint.as_deref(),
        )
        .map(ToString::to_string)
        .unwrap_or_else(|| self.inner.fingerprint.clone());
        debug!("Starting activation request");

        self.emit(Event::new(EventKind::ActivationStart));

        let mut body = fingerprint_alias_payload(&device_id, true);

        if let Some(name) = &options.device_name {
            body["device_name"] = serde_json::json!(name);
        }

        if let Some(metadata) = &options.metadata {
            body["metadata"] = serde_json::json!(metadata);
        }

        let path = build_license_action_path(product_slug, license_key, "activate");

        match self.post::<ActivationResponse>(&path, Some(body)).await {
            Ok(activation) => {
                let license = License {
                    license_key: license_key.to_string(),
                    device_id: activation.device_id,
                    activation_id: activation.id,
                    activated_at: activation.activated_at,
                    last_validated: Utc::now(),
                    validation: None,
                };

                self.inner.cache.set_license(&license)?;
                self.emit(Event::with_license(
                    EventKind::ActivationSuccess,
                    license.clone(),
                ));

                // Start background tasks
                self.start_background_tasks();

                // Sync offline assets (non-blocking)
                #[cfg(feature = "offline")]
                {
                    let sdk = self.clone();
                    tokio::spawn(async move {
                        if let Err(e) = sdk.sync_offline_assets().await {
                            warn!("Failed to sync offline assets: {}", e);
                        }
                    });
                }

                debug!("License activated successfully");
                Ok(license)
            }
            Err(e) => {
                self.emit(Event::with_error(EventKind::ActivationError, e.to_string()));
                Err(e)
            }
        }
    }

    /// Validate the current license.
    ///
    /// This checks with the server that the license is still valid.
    /// If validation fails and offline fallback is enabled, it will
    /// attempt offline validation.
    pub async fn validate(&self) -> Result<ValidationResult> {
        let license = self
            .inner
            .cache
            .get_license()
            .ok_or(Error::NoActiveLicense)?;
        self.validate_key(&license.license_key).await
    }

    /// Validate a specific license key.
    pub async fn validate_key(&self, license_key: &str) -> Result<ValidationResult> {
        let product_slug = self.require_product_slug()?;
        let device_id = self
            .inner
            .cache
            .get_fingerprint()
            .unwrap_or_else(|| self.inner.fingerprint.clone());

        self.emit(Event::new(EventKind::ValidationStart));

        let path = build_license_action_path(product_slug, license_key, "validate");
        let body = Some(fingerprint_alias_payload(&device_id, false));

        match self.post::<ValidationResult>(&path, body).await {
            Ok(mut result) => {
                result.offline = false;
                self.inner.cache.update_validation(&result)?;
                self.inner
                    .cache
                    .set_last_seen_timestamp(Utc::now().timestamp())?;
                self.set_online(true);

                if is_revocation_code(result.code.as_deref()) {
                    self.inner.cache.clear();
                    self.emit(Event::with_error(
                        EventKind::LicenseRevoked,
                        result
                            .message
                            .clone()
                            .or_else(|| result.code.clone())
                            .unwrap_or_else(|| "License revoked".into()),
                    ));
                }

                if result.valid {
                    self.emit(Event::with_validation(
                        EventKind::ValidationSuccess,
                        result.clone(),
                    ));
                    debug!("License validated successfully");
                } else {
                    self.emit(Event::with_validation(
                        EventKind::ValidationFailed,
                        result.clone(),
                    ));
                    warn!("License validation failed: {:?}", result.code);
                }

                Ok(result)
            }
            Err(e) => {
                if is_auth_failure_error(&e) {
                    self.emit(Event::with_error(
                        EventKind::ValidationAuthFailed,
                        e.to_string(),
                    ));
                }
                self.emit(Event::with_error(EventKind::ValidationError, e.to_string()));

                if is_revocation_error(&e) {
                    self.inner.cache.clear();
                    self.emit(Event::with_error(EventKind::LicenseRevoked, e.to_string()));
                    return Err(e);
                }

                // Check for business logic errors (non-retriable)
                if e.is_business_error() {
                    return Err(e);
                }

                if e.is_network_error() {
                    self.set_online(false);
                    self.start_support_tasks();
                }

                // Try offline fallback for network errors
                if self.should_fallback_offline(&e) {
                    #[cfg(feature = "offline")]
                    {
                        return self.validate_offline().await;
                    }
                }

                Err(e)
            }
        }
    }

    /// Deactivate the current license.
    ///
    /// This releases the seat so it can be used on another device.
    pub async fn deactivate(&self) -> Result<()> {
        let license = self
            .inner
            .cache
            .get_license()
            .ok_or(Error::NoActiveLicense)?;
        self.deactivate_key(&license.license_key, Some(&license.device_id))
            .await
    }

    /// Deactivate a specific license/fingerprint pair.
    pub async fn deactivate_key(&self, license_key: &str, fingerprint: Option<&str>) -> Result<()> {
        let product_slug = self.require_product_slug()?;
        if license_key.is_empty() {
            return Err(Error::Configuration("license_key is required".into()));
        }

        let resolved_fingerprint = self.resolve_request_fingerprint(fingerprint);
        let should_clear_cache = self
            .inner
            .cache
            .get_license()
            .map(|license| license.license_key == license_key)
            .unwrap_or(false);

        if should_clear_cache {
            self.stop_background_tasks();
        }

        self.emit(Event::new(EventKind::DeactivationStart));

        let path = build_license_action_path(product_slug, license_key, "deactivate");
        let body = fingerprint_alias_payload(&resolved_fingerprint, true);

        match self.post::<DeactivationResponse>(&path, Some(body)).await {
            Ok(_) => {
                if should_clear_cache {
                    self.inner.cache.clear();
                }
                self.emit(Event::new(EventKind::DeactivationSuccess));
                debug!("License deactivated");
                Ok(())
            }
            Err(e) => {
                // Treat certain errors as success (already deactivated, not found, etc.)
                if let Error::Api { status, code, .. } = &e {
                    if *status == 404 || *status == 410 {
                        if should_clear_cache {
                            self.inner.cache.clear();
                        }
                        self.emit(Event::new(EventKind::DeactivationSuccess));
                        return Ok(());
                    }
                    if *status == 422 {
                        if let Some(c) = code {
                            if [
                                "revoked",
                                "already_deactivated",
                                "not_active",
                                "not_found",
                                "suspended",
                                "expired",
                            ]
                            .contains(&c.as_str())
                            {
                                if should_clear_cache {
                                    self.inner.cache.clear();
                                }
                                self.emit(Event::new(EventKind::DeactivationSuccess));
                                return Ok(());
                            }
                        }
                    }
                }

                self.emit(Event::with_error(
                    EventKind::DeactivationError,
                    e.to_string(),
                ));
                Err(e)
            }
        }
    }

    /// Send a heartbeat for the current license.
    pub async fn heartbeat(&self) -> Result<HeartbeatResponse> {
        let license = self
            .inner
            .cache
            .get_license()
            .ok_or(Error::NoActiveLicense)?;
        self.heartbeat_key(&license.license_key, Some(&license.device_id))
            .await
    }

    /// Send a heartbeat for a specific license/fingerprint pair.
    pub async fn heartbeat_key(
        &self,
        license_key: &str,
        fingerprint: Option<&str>,
    ) -> Result<HeartbeatResponse> {
        let product_slug = self.require_product_slug()?;
        if license_key.is_empty() {
            return Err(Error::Configuration("license_key is required".into()));
        }
        let resolved_fingerprint = self.resolve_request_fingerprint(fingerprint);

        let path = build_license_action_path(product_slug, license_key, "heartbeat");
        let body = fingerprint_alias_payload(&resolved_fingerprint, true);

        match self.post::<HeartbeatResponse>(&path, Some(body)).await {
            Ok(response) => {
                self.set_online(true);
                self.set_last_heartbeat(Some(response.clone()));
                self.set_last_heartbeat_error(None);
                self.emit(Event::new(EventKind::HeartbeatSuccess));
                debug!("Heartbeat sent successfully");
                Ok(response)
            }
            Err(e) => {
                self.set_last_heartbeat_error(Some(e.to_string()));
                if e.is_network_error() {
                    self.set_online(false);
                    self.start_support_tasks();
                }
                self.emit(Event::with_error(EventKind::HeartbeatError, e.to_string()));
                Err(e)
            }
        }
    }

    /// Check if an entitlement is active.
    pub fn check_entitlement(&self, entitlement_key: &str) -> EntitlementStatus {
        let Some(license) = self.inner.cache.get_license() else {
            return EntitlementStatus {
                active: false,
                reason: Some(EntitlementReason::NoLicense),
                expires_at: None,
                entitlement: None,
            };
        };

        let Some(validation) = &license.validation else {
            return EntitlementStatus {
                active: false,
                reason: Some(EntitlementReason::NoLicense),
                expires_at: None,
                entitlement: None,
            };
        };

        let entitlements = &validation.license.active_entitlements;
        let entitlement = entitlements.iter().find(|e| e.key == entitlement_key);

        match entitlement {
            None => EntitlementStatus {
                active: false,
                reason: Some(EntitlementReason::NotFound),
                expires_at: None,
                entitlement: None,
            },
            Some(e) => {
                if let Some(expires_at) = e.expires_at {
                    if expires_at < Utc::now() {
                        return EntitlementStatus {
                            active: false,
                            reason: Some(EntitlementReason::Expired),
                            expires_at: Some(expires_at),
                            entitlement: Some(e.clone()),
                        };
                    }
                }

                EntitlementStatus {
                    active: true,
                    reason: None,
                    expires_at: e.expires_at,
                    entitlement: Some(e.clone()),
                }
            }
        }
    }

    /// Check if a specific entitlement is active (convenience method).
    pub fn has_entitlement(&self, entitlement_key: &str) -> bool {
        self.check_entitlement(entitlement_key).active
    }

    /// Get the current license status.
    pub fn status(&self) -> LicenseStatus {
        let Some(license) = self.inner.cache.get_license() else {
            return LicenseStatus::Inactive {
                message: "No license activated".into(),
            };
        };

        let Some(validation) = &license.validation else {
            return LicenseStatus::Pending {
                message: "License pending validation".into(),
            };
        };

        if !validation.valid {
            let message = validation
                .message
                .clone()
                .or_else(|| validation.code.clone())
                .unwrap_or_else(|| "License invalid".into());

            return if validation.offline {
                LicenseStatus::OfflineInvalid { message }
            } else {
                LicenseStatus::Invalid { message }
            };
        }

        let details = LicenseStatusDetails {
            license: license.license_key,
            device: license.device_id,
            activated_at: license.activated_at,
            last_validated: license.last_validated,
            entitlements: validation.license.active_entitlements.clone(),
        };

        if validation.offline {
            LicenseStatus::OfflineValid { details }
        } else {
            LicenseStatus::Active { details }
        }
    }

    /// Get the last cached validation result.
    pub fn get_status(&self) -> ValidationResult {
        self.inner
            .cache
            .get_license()
            .and_then(|license| license.validation)
            .unwrap_or_else(default_validation_status)
    }

    /// Get a compact summary of the client status.
    pub fn get_client_status(&self) -> ClientStatus {
        match self.status() {
            LicenseStatus::Active { .. } => ClientStatus::Active,
            LicenseStatus::OfflineValid { .. } => ClientStatus::OfflineValid,
            LicenseStatus::OfflineInvalid { .. } => ClientStatus::OfflineInvalid,
            LicenseStatus::Inactive { .. } => ClientStatus::Inactive,
            LicenseStatus::Invalid { .. } => ClientStatus::Invalid,
            LicenseStatus::Pending { .. } => ClientStatus::Pending,
        }
    }

    /// Preferred alias for the canonical device fingerprint.
    pub fn fingerprint(&self) -> &str {
        &self.inner.fingerprint
    }

    /// Backward-compatible device-id accessor.
    pub fn device_id(&self) -> &str {
        self.fingerprint()
    }

    /// Whether the SDK currently believes the API is reachable.
    pub fn is_online(&self) -> bool {
        self.inner.is_online.load(Ordering::SeqCst)
    }

    /// Get the current cached license.
    pub fn current_license(&self) -> Option<License> {
        self.inner.cache.get_license()
    }

    /// Get the cached offline token, if one has been stored.
    pub fn current_offline_token(&self) -> Option<OfflineTokenResponse> {
        self.inner.cache.get_offline_token()
    }

    /// Get the cached machine file, if one has been stored.
    pub fn current_machine_file(&self) -> Option<MachineFile> {
        self.inner.cache.get_machine_file()
    }

    /// Get the signing-key id embedded in the cached machine-file certificate, if present.
    #[cfg(feature = "offline")]
    pub fn current_machine_file_key_id(&self) -> Option<String> {
        self.current_machine_file()
            .as_ref()
            .and_then(|machine_file| self.machine_file_key_id(machine_file))
    }

    /// Extract the signing-key id embedded in a machine-file certificate.
    #[cfg(feature = "offline")]
    pub fn machine_file_key_id(&self, machine_file: &MachineFile) -> Option<String> {
        extract_machine_file_key_id(&machine_file.certificate)
            .or_else(|| self.inner.config.signing_key_id.clone())
    }

    /// Get a cached signing key by key id.
    pub fn cached_signing_key(&self, key_id: &str) -> Option<SigningKeyResponse> {
        self.inner.cache.get_signing_key(key_id)
    }

    /// Get the last seen timestamp recorded for clock-tampering protection.
    pub fn last_seen_timestamp(&self) -> Option<i64> {
        self.inner.cache.get_last_seen_timestamp()
    }

    /// Get the most recent successful heartbeat response observed in this process.
    pub fn last_heartbeat_response(&self) -> Option<HeartbeatResponse> {
        self.lock_snapshot(&self.inner.last_heartbeat)
    }

    /// Get the most recent heartbeat error observed in this process.
    pub fn last_heartbeat_error(&self) -> Option<String> {
        self.lock_snapshot(&self.inner.last_heartbeat_error)
    }

    /// Get the most recent successful health response observed in this process.
    pub fn last_health_response(&self) -> Option<HealthResponse> {
        self.lock_snapshot(&self.inner.last_health)
    }

    /// Get the most recent health-check error observed in this process.
    pub fn last_health_error(&self) -> Option<String> {
        self.lock_snapshot(&self.inner.last_health_error)
    }

    /// Get the next scheduled auto-validation time observed in this process.
    pub fn next_auto_validation_at(&self) -> Option<chrono::DateTime<Utc>> {
        self.lock_snapshot(&self.inner.next_auto_validation_at)
    }

    /// Restore the cached session.
    pub async fn restore_license(&self) -> RestoreResult {
        let Some(license) = self.inner.cache.get_license() else {
            return RestoreResult::default();
        };

        let mut result = RestoreResult {
            restored: false,
            status: LicenseStatus::Pending {
                message: "Restoring cached license".into(),
            },
            license: Some(license.clone()),
            validation: None,
            error: None,
        };

        let mut should_start_background_tasks = false;
        let mut should_start_support_tasks = false;

        match self.health_check().await {
            Ok(_) => match self.validate_key(&license.license_key).await {
                Ok(validation) => {
                    result.restored = validation.valid;
                    result.validation = Some(validation);
                    result.status = self.status();
                    should_start_background_tasks = result.restored;
                }
                Err(error) => {
                    result.status = LicenseStatus::Invalid {
                        message: error.to_string(),
                    };
                    result.error = Some(error.to_string());
                }
            },
            Err(network_error) => {
                #[cfg(feature = "offline")]
                {
                    if self.should_fallback_offline(&network_error) {
                        match self.validate_offline().await {
                            Ok(validation) => {
                                result.restored = validation.valid;
                                result.validation = Some(validation);
                                result.status = self.status();
                            }
                            Err(offline_error) => {
                                result.status = LicenseStatus::OfflineInvalid {
                                    message: offline_error.to_string(),
                                };
                                result.error = Some(offline_error.to_string());
                            }
                        }
                    } else {
                        result.status = LicenseStatus::Invalid {
                            message: network_error.to_string(),
                        };
                        result.error = Some(network_error.to_string());
                    }
                    should_start_support_tasks = network_error.is_network_error();
                }

                #[cfg(not(feature = "offline"))]
                {
                    result.status = LicenseStatus::Invalid {
                        message: network_error.to_string(),
                    };
                    result.error = Some(network_error.to_string());
                    should_start_support_tasks = network_error.is_network_error();
                }
            }
        }

        if should_start_background_tasks {
            self.start_background_tasks();
        } else if should_start_support_tasks {
            self.start_support_tasks();
        }

        result
    }

    /// Check API health.
    pub async fn health_check(&self) -> Result<HealthResponse> {
        match self.get::<HealthResponse>("/health").await {
            Ok(response) => {
                self.set_online(true);
                self.set_last_health(Some(response.clone()));
                self.set_last_health_error(None);
                Ok(response)
            }
            Err(error) => {
                self.set_last_health_error(Some(error.to_string()));
                if error.is_network_error() {
                    self.set_online(false);
                    self.start_support_tasks();
                }
                Err(error)
            }
        }
    }

    /// Convenience health endpoint that mirrors the C++ helper.
    pub async fn health(&self) -> Result<bool> {
        self.health_check().await.map(|_| true)
    }

    /// Get the latest release for a product.
    pub async fn get_latest_release(
        &self,
        product_slug: Option<&str>,
        channel: Option<&str>,
        platform: Option<&str>,
    ) -> Result<Release> {
        let product_slug = product_slug
            .filter(|slug| !slug.is_empty())
            .unwrap_or(&self.inner.config.product_slug);
        if product_slug.is_empty() {
            return Err(Error::Configuration("product_slug is required".into()));
        }

        let path = build_release_path(
            &build_path(&["products", product_slug, "releases", "latest"]),
            &ReleaseListOptions {
                channel: channel.map(ToString::to_string),
                platform: platform.map(ToString::to_string),
                limit: None,
            },
        );
        self.get(&path).await
    }

    /// List published releases for a product.
    pub async fn list_releases(
        &self,
        product_slug: Option<&str>,
        channel: Option<&str>,
        platform: Option<&str>,
    ) -> Result<Vec<Release>> {
        let options = ReleaseListOptions {
            channel: channel.map(ToString::to_string),
            platform: platform.map(ToString::to_string),
            limit: None,
        };

        Ok(self
            .list_releases_with_options(product_slug, options)
            .await?
            .data)
    }

    /// List published releases for a product with full response metadata.
    pub async fn list_releases_with_options(
        &self,
        product_slug: Option<&str>,
        options: ReleaseListOptions,
    ) -> Result<ReleaseList> {
        let product_slug = product_slug
            .filter(|slug| !slug.is_empty())
            .unwrap_or(&self.inner.config.product_slug);
        if product_slug.is_empty() {
            return Err(Error::Configuration("product_slug is required".into()));
        }

        let path = build_release_path(
            &build_path(&["products", product_slug, "releases"]),
            &options,
        );
        let body: serde_json::Value = self.get(&path).await?;
        parse_release_list(&body)
    }

    /// Generate a download token for a release.
    pub async fn generate_download_token(
        &self,
        version: &str,
        license_key: &str,
        product_slug: Option<&str>,
        platform: Option<&str>,
    ) -> Result<DownloadToken> {
        if version.is_empty() {
            return Err(Error::Configuration("version is required".into()));
        }
        if license_key.is_empty() {
            return Err(Error::Configuration("license_key is required".into()));
        }

        let product_slug = product_slug
            .filter(|slug| !slug.is_empty())
            .unwrap_or(&self.inner.config.product_slug);
        if product_slug.is_empty() {
            return Err(Error::Configuration("product_slug is required".into()));
        }

        let path = build_path(&[
            "products",
            product_slug,
            "releases",
            version,
            "download_token",
        ]);
        let body = build_download_token_request(license_key, platform);
        self.post(&path, Some(body)).await
    }

    /// Reset SDK state (clears cache and stops timers).
    pub fn reset(&self) {
        // Stop background tasks first
        self.stop_background_tasks();
        self.inner.cache.clear();
        self.emit(Event::new(EventKind::SdkReset));
        debug!("SDK state reset");
    }

    /// Subscribe to SDK events.
    pub fn subscribe(&self) -> broadcast::Receiver<Event> {
        self.inner.event_tx.subscribe()
    }

    // ========================================================================
    // Background Tasks
    // ========================================================================

    /// Start background validation, heartbeat, and support tasks.
    ///
    /// This is called automatically after activation or when loading a cached license.
    /// You typically don't need to call this manually.
    pub fn start_background_tasks(&self) {
        let Some(license) = self.inner.cache.get_license() else {
            debug!("No active license, skipping background task startup");
            return;
        };

        self.start_auto_validation(&license.license_key);
        self.start_heartbeat(&license.license_key);
        self.start_support_tasks();
    }

    /// Start periodic auto-validation for the given license.
    pub fn start_auto_validation(&self, license_key: &str) {
        self.stop_auto_validation();

        if license_key.is_empty() {
            self.emit(Event::with_error(
                EventKind::SdkError,
                "license_key is required for auto-validation",
            ));
            return;
        }

        let interval = self.inner.config.auto_validate_interval;
        if interval.is_zero() {
            return;
        }

        let generation = self
            .inner
            .auto_validation_generation
            .fetch_add(1, Ordering::SeqCst)
            + 1;
        self.inner
            .auto_validation_running
            .store(true, Ordering::SeqCst);

        let sdk = self.clone();
        let license_key = license_key.to_string();
        std::thread::Builder::new()
            .name("licenseseat-auto-validation".into())
            .spawn(move || {
                let rt = match tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                {
                    Ok(rt) => rt,
                    Err(e) => {
                        sdk.emit(Event::with_error(
                            EventKind::SdkError,
                            format!("Failed to create auto-validation runtime: {e}"),
                        ));
                        sdk.inner
                            .auto_validation_running
                            .store(false, Ordering::SeqCst);
                        return;
                    }
                };

                rt.block_on(async {
                    sdk.emit_auto_validation_cycle(interval);

                    loop {
                        tokio::time::sleep(interval).await;

                        if !sdk.auto_validation_should_continue(generation) {
                            break;
                        }

                        debug!("Running auto-validation");
                        match sdk.validate_key(&license_key).await {
                            Ok(result) if result.valid => debug!("Auto-validation successful"),
                            Ok(result) => {
                                warn!("Auto-validation failed: {:?}", result.code);
                                sdk.emit(Event::with_error(
                                    EventKind::ValidationAutoFailed,
                                    result
                                        .code
                                        .clone()
                                        .or(result.message.clone())
                                        .unwrap_or_else(|| "Auto-validation failed".into()),
                                ));
                            }
                            Err(e) => {
                                warn!("Auto-validation error: {}", e);
                                sdk.emit(Event::with_error(
                                    EventKind::ValidationAutoFailed,
                                    e.to_string(),
                                ));
                            }
                        }

                        let _ = sdk.heartbeat_key(&license_key, None).await;

                        if !sdk.auto_validation_should_continue(generation) {
                            break;
                        }

                        sdk.emit_auto_validation_cycle(interval);
                    }
                });
            })
            .expect("Failed to spawn auto-validation thread");
    }

    /// Stop periodic auto-validation.
    pub fn stop_auto_validation(&self) {
        let was_running = self
            .inner
            .auto_validation_running
            .swap(false, Ordering::SeqCst);
        self.inner
            .auto_validation_generation
            .fetch_add(1, Ordering::SeqCst);

        if was_running {
            self.set_next_auto_validation_at(None);
            self.emit(Event::new(EventKind::AutoValidationStopped));
        }
    }

    /// Whether auto-validation is currently running.
    pub fn is_auto_validating(&self) -> bool {
        self.inner.auto_validation_running.load(Ordering::SeqCst)
    }

    /// Start periodic heartbeats for the given license.
    pub fn start_heartbeat(&self, license_key: &str) {
        self.stop_heartbeat();

        if license_key.is_empty() {
            self.emit(Event::with_error(
                EventKind::SdkError,
                "license_key is required for heartbeat",
            ));
            return;
        }

        let interval = self.inner.config.heartbeat_interval;
        if interval.is_zero() {
            return;
        }

        let generation = self
            .inner
            .heartbeat_generation
            .fetch_add(1, Ordering::SeqCst)
            + 1;
        self.inner.heartbeat_running.store(true, Ordering::SeqCst);

        let sdk = self.clone();
        let license_key = license_key.to_string();
        std::thread::Builder::new()
            .name("licenseseat-heartbeat".into())
            .spawn(move || {
                let rt = match tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                {
                    Ok(rt) => rt,
                    Err(e) => {
                        sdk.emit(Event::with_error(
                            EventKind::SdkError,
                            format!("Failed to create heartbeat runtime: {e}"),
                        ));
                        sdk.inner.heartbeat_running.store(false, Ordering::SeqCst);
                        return;
                    }
                };

                rt.block_on(async {
                    loop {
                        tokio::time::sleep(interval).await;

                        if !sdk.heartbeat_should_continue(generation) {
                            break;
                        }

                        debug!("Sending heartbeat");
                        if let Err(e) = sdk.heartbeat_key(&license_key, None).await {
                            warn!("Heartbeat error: {}", e);
                        }
                    }
                });
            })
            .expect("Failed to spawn heartbeat thread");
    }

    /// Stop periodic heartbeats.
    pub fn stop_heartbeat(&self) {
        self.inner.heartbeat_running.store(false, Ordering::SeqCst);
        self.inner
            .heartbeat_generation
            .fetch_add(1, Ordering::SeqCst);
    }

    /// Whether the heartbeat timer is currently running.
    pub fn is_heartbeat_running(&self) -> bool {
        self.inner.heartbeat_running.load(Ordering::SeqCst)
    }

    /// Stop all background tasks.
    pub fn stop_background_tasks(&self) {
        self.stop_auto_validation();
        self.stop_heartbeat();
        self.stop_support_tasks();
    }

    fn start_support_tasks(&self) {
        let network_recheck_interval = self.inner.config.network_recheck_interval;
        #[cfg(feature = "offline")]
        let refresh_interval = self.inner.config.offline_token_refresh_interval;
        #[cfg(feature = "offline")]
        let has_support_tasks = !network_recheck_interval.is_zero() || !refresh_interval.is_zero();
        #[cfg(not(feature = "offline"))]
        let has_support_tasks = !network_recheck_interval.is_zero();

        if !has_support_tasks {
            return;
        }

        if self
            .inner
            .background_tasks_running
            .swap(true, Ordering::SeqCst)
        {
            return;
        }

        let generation = self
            .inner
            .support_tasks_generation
            .fetch_add(1, Ordering::SeqCst)
            + 1;

        debug!("Starting support background tasks");
        let sdk = self.clone();

        std::thread::Builder::new()
            .name("licenseseat-background".into())
            .spawn(move || {
                let rt = match tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                {
                    Ok(rt) => rt,
                    Err(e) => {
                        sdk.emit(Event::with_error(
                            EventKind::SdkError,
                            format!("Failed to create background runtime: {e}"),
                        ));
                        sdk.inner
                            .background_tasks_running
                            .store(false, Ordering::SeqCst);
                        return;
                    }
                };

                rt.block_on(async {
                    let mut tasks = Vec::new();

                    if !network_recheck_interval.is_zero() {
                        let sdk_clone = sdk.clone();
                        tasks.push(tokio::spawn(async move {
                            sdk_clone
                                .network_recheck_loop(network_recheck_interval, generation)
                                .await;
                        }));
                    }

                    #[cfg(feature = "offline")]
                    if !refresh_interval.is_zero() {
                        let sdk_clone = sdk.clone();
                        tasks.push(tokio::spawn(async move {
                            sdk_clone
                                .offline_refresh_loop(refresh_interval, generation)
                                .await;
                        }));
                    }

                    for task in tasks {
                        let _ = task.await;
                    }
                });

                debug!("Background tasks thread exiting");
            })
            .expect("Failed to spawn background thread");
    }

    fn stop_support_tasks(&self) {
        debug!("Stopping support background tasks");
        self.inner
            .background_tasks_running
            .store(false, Ordering::SeqCst);
        self.inner
            .support_tasks_generation
            .fetch_add(1, Ordering::SeqCst);
    }

    /// Generic background task loop runner.
    /// Handles the common pattern of: sleep -> check stop flag -> check license -> run task.
    async fn run_background_loop<F, Fut>(
        &self,
        name: &str,
        interval: Duration,
        generation: u64,
        task: F,
    ) where
        F: Fn() -> Fut,
        Fut: std::future::Future<Output = ()>,
    {
        debug!("{} loop started with interval {:?}", name, interval);

        loop {
            tokio::time::sleep(interval).await;

            if !self.support_tasks_should_continue(generation) {
                debug!("{} loop stopping", name);
                break;
            }

            if self.inner.cache.get_license().is_none() {
                debug!("No active license, skipping {}", name);
                continue;
            }

            task().await;
        }
    }

    /// Network recheck loop that restores online state after outages.
    async fn network_recheck_loop(&self, interval: Duration, generation: u64) {
        self.run_background_loop("Network recheck", interval, generation, || async {
            if self.is_online() {
                return;
            }

            debug!("Rechecking API connectivity");
            if self.health_check().await.is_ok() {
                if let Some(license) = self.inner.cache.get_license() {
                    if let Ok(result) = self.validate_key(&license.license_key).await {
                        if result.valid {
                            self.start_auto_validation(&license.license_key);
                            self.start_heartbeat(&license.license_key);
                        }
                    }
                }
            }
        })
        .await;
    }

    /// Offline asset refresh loop.
    #[cfg(feature = "offline")]
    async fn offline_refresh_loop(&self, interval: Duration, generation: u64) {
        self.run_background_loop("Offline refresh", interval, generation, || async {
            debug!("Refreshing offline assets");
            if let Err(e) = self.sync_offline_assets().await {
                warn!("Offline asset refresh error: {}", e);
            }
        })
        .await;
    }

    // ========================================================================
    // Offline Validation
    // ========================================================================

    /// Generate a legacy offline token from the server.
    #[cfg(feature = "offline")]
    pub async fn generate_offline_token(
        &self,
        license_key: &str,
        fingerprint: Option<&str>,
        ttl_days: Option<i64>,
    ) -> Result<OfflineTokenResponse> {
        let product_slug = self.require_product_slug()?;
        let fingerprint = fingerprint
            .filter(|value| !value.is_empty())
            .map(ToString::to_string)
            .unwrap_or_else(|| self.inner.fingerprint.clone());

        self.emit(Event::new(EventKind::OfflineTokenFetching));

        let path = build_license_action_path(product_slug, license_key, "offline_token");
        let body = build_offline_token_request(&fingerprint, ttl_days);
        match self.post::<OfflineTokenResponse>(&path, Some(body)).await {
            Ok(token) => {
                self.inner.cache.set_offline_token(&token)?;
                self.emit(Event::new(EventKind::OfflineTokenFetched));
                self.emit(Event::new(EventKind::OfflineTokenReady));
                Ok(token)
            }
            Err(error) => {
                self.emit(Event::with_error(
                    EventKind::OfflineTokenFetchError,
                    error.to_string(),
                ));
                Err(error)
            }
        }
    }

    /// Checkout a machine file from the server.
    #[cfg(feature = "offline")]
    pub async fn checkout_machine_file(
        &self,
        license_key: &str,
        fingerprint: Option<&str>,
        ttl_days: Option<i64>,
    ) -> Result<MachineFile> {
        let options = MachineFileCheckoutOptions {
            fingerprint: fingerprint.map(ToString::to_string),
            ttl_days,
            ..Default::default()
        };
        self.checkout_machine_file_with_options(license_key, options)
            .await
    }

    /// Checkout a machine file from the server with full request options.
    #[cfg(feature = "offline")]
    pub async fn checkout_machine_file_with_options(
        &self,
        license_key: &str,
        options: MachineFileCheckoutOptions,
    ) -> Result<MachineFile> {
        let product_slug = self.require_product_slug()?;
        let MachineFileCheckoutOptions {
            fingerprint,
            device_id,
            device_fingerprint,
            ttl_days,
            grace_period_days,
            include_license,
            fingerprint_components,
        } = options;
        let fingerprint = select_fingerprint_alias(
            fingerprint.as_deref(),
            device_id.as_deref(),
            device_fingerprint.as_deref(),
        )
        .map(ToString::to_string)
        .unwrap_or_else(|| self.inner.fingerprint.clone());

        self.emit(Event::new(EventKind::MachineFileFetching));

        let fingerprint_components =
            if fingerprint_components.is_empty() && fingerprint == self.inner.fingerprint {
                collect_fingerprint_components()
            } else {
                fingerprint_components
            };
        let path = build_license_action_path(product_slug, license_key, "machine-file");
        let body = build_machine_file_request(
            &fingerprint,
            ttl_days,
            grace_period_days,
            include_license,
            &fingerprint_components,
        );
        match self.post::<serde_json::Value>(&path, Some(body)).await {
            Ok(response) => {
                let mut machine_file = match parse_machine_file_response(&response) {
                    Ok(machine_file) => machine_file,
                    Err(error) => {
                        self.emit(Event::with_error(
                            EventKind::MachineFileFetchError,
                            error.to_string(),
                        ));
                        return Err(error);
                    }
                };
                if machine_file.license_key.is_empty() {
                    machine_file.license_key = license_key.to_string();
                }
                if machine_file.fingerprint.is_empty() {
                    machine_file.fingerprint = fingerprint.clone();
                }
                self.inner.cache.set_machine_file(&machine_file)?;

                if let Some(key_id) = extract_machine_file_key_id(&machine_file.certificate) {
                    if self.resolve_public_key(&key_id, None).is_none() {
                        let _ = self.fetch_signing_key(&key_id).await;
                    }
                }

                self.emit(Event::new(EventKind::MachineFileFetched));
                self.emit(Event::new(EventKind::MachineFileReady));
                Ok(machine_file)
            }
            Err(error) => {
                self.emit(Event::with_error(
                    EventKind::MachineFileFetchError,
                    error.to_string(),
                ));
                Err(error)
            }
        }
    }

    /// Fetch a signing key from the API and cache it locally.
    #[cfg(feature = "offline")]
    pub async fn fetch_signing_key(&self, key_id: &str) -> Result<String> {
        if key_id.is_empty() {
            return Err(Error::Configuration("key_id is required".into()));
        }

        let path = format!("/signing_keys/{}", key_id);
        let response: SigningKeyResponse = self.get(&path).await?;
        let key = response.public_key.clone();
        self.inner.cache.set_signing_key(key_id, &response)?;
        Ok(key)
    }

    /// Verify a legacy offline token locally.
    #[cfg(feature = "offline")]
    pub fn verify_offline_token(
        &self,
        offline_token: &OfflineTokenResponse,
        public_key_b64: Option<&str>,
    ) -> Result<bool> {
        if offline_token.token.license_key.is_empty() {
            return Err(Error::Configuration("license_key is required".into()));
        }

        crate::offline::check_token_validity(offline_token)?;

        let token_fingerprint = offline_token.token.device_id.as_deref().unwrap_or_default();
        if !token_fingerprint.is_empty() && token_fingerprint != self.inner.fingerprint {
            return Err(Error::OfflineVerificationFailed(
                "FINGERPRINT_MISMATCH".into(),
            ));
        }

        let key = public_key_b64
            .map(ToString::to_string)
            .or_else(|| {
                self.inner
                    .config
                    .signing_public_key
                    .as_ref()
                    .map(ToString::to_string)
            })
            .or_else(|| {
                self.inner
                    .cache
                    .get_signing_key(&offline_token.signature.key_id)
                    .map(|key| key.public_key)
            })
            .ok_or_else(|| Error::Configuration("public_key is required".into()))?;

        let signing_key = SigningKeyResponse {
            object: "signing_key".into(),
            key_id: offline_token.signature.key_id.clone(),
            algorithm: offline_token.signature.algorithm.clone(),
            public_key: key,
            created_at: None,
            status: "active".into(),
        };

        let result = crate::offline::verify_token(offline_token, &signing_key)?;
        if result {
            self.emit(Event::new(EventKind::OfflineTokenVerified));
        } else {
            self.emit(Event::new(EventKind::OfflineTokenVerificationFailed));
        }
        Ok(result)
    }

    /// Verify a machine file locally.
    #[cfg(feature = "offline")]
    fn verify_machine_file_inner(
        &self,
        machine_file: &MachineFile,
        public_key_b64: Option<&str>,
        license_key: Option<&str>,
        fingerprint: Option<&str>,
        emit_events: bool,
    ) -> Result<MachineFileVerificationResult> {
        let resolved_license_key = license_key
            .filter(|value| !value.is_empty())
            .map(ToString::to_string)
            .or_else(|| {
                (!machine_file.license_key.is_empty()).then(|| machine_file.license_key.clone())
            })
            .or_else(|| {
                self.inner
                    .cache
                    .get_license()
                    .map(|license| license.license_key)
            })
            .ok_or_else(|| Error::Configuration("license_key is required".into()))?;

        let resolved_fingerprint = fingerprint
            .filter(|value| !value.is_empty())
            .map(ToString::to_string)
            .unwrap_or_else(|| self.inner.fingerprint.clone());

        let key_id = extract_machine_file_key_id(&machine_file.certificate)
            .unwrap_or_else(|| self.inner.config.signing_key_id.clone().unwrap_or_default());
        let public_key = self
            .resolve_public_key(&key_id, public_key_b64)
            .ok_or_else(|| Error::Configuration("public_key is required".into()))?;

        match crate::offline::verify_machine_file(
            machine_file,
            &resolved_license_key,
            &resolved_fingerprint,
            &public_key,
        ) {
            Ok(payload) => {
                if emit_events {
                    self.emit(Event::new(EventKind::MachineFileVerified));
                }
                Ok(MachineFileVerificationResult {
                    valid: true,
                    code: None,
                    message: None,
                    payload: Some(payload),
                })
            }
            Err(error) => {
                let code = error_code_string_from_error(&error);
                if emit_events {
                    self.emit(Event::with_error(
                        EventKind::MachineFileVerificationFailed,
                        error.to_string(),
                    ));
                }
                Ok(MachineFileVerificationResult {
                    valid: false,
                    code: Some(code),
                    message: Some(error.to_string()),
                    payload: None,
                })
            }
        }
    }

    /// Verify a machine file locally and emit the standard SDK verification events.
    pub fn verify_machine_file(
        &self,
        machine_file: &MachineFile,
        public_key_b64: Option<&str>,
        license_key: Option<&str>,
        fingerprint: Option<&str>,
    ) -> Result<MachineFileVerificationResult> {
        self.verify_machine_file_inner(machine_file, public_key_b64, license_key, fingerprint, true)
    }

    /// Verify a machine file locally without emitting SDK events.
    pub fn inspect_machine_file(
        &self,
        machine_file: &MachineFile,
        public_key_b64: Option<&str>,
        license_key: Option<&str>,
        fingerprint: Option<&str>,
    ) -> Result<MachineFileVerificationResult> {
        self.verify_machine_file_inner(
            machine_file,
            public_key_b64,
            license_key,
            fingerprint,
            false,
        )
    }

    /// Sync offline assets (machine files first, legacy tokens only if enabled).
    #[cfg(feature = "offline")]
    pub async fn sync_offline_assets(&self) -> Result<()> {
        let license = self
            .inner
            .cache
            .get_license()
            .ok_or(Error::NoActiveLicense)?;

        debug!("Syncing offline assets");

        let machine_file_result = self
            .checkout_machine_file(&license.license_key, Some(&license.device_id), Some(30))
            .await;
        if let Ok(machine_file) = machine_file_result {
            match self.verify_machine_file(&machine_file, None, None, None) {
                Ok(verification) if verification.valid => {
                    self.emit(Event::new(EventKind::OfflineAssetsRefreshed));
                    return Ok(());
                }
                Ok(_) | Err(_) => {}
            }
        }

        if !self.inner.config.enable_legacy_offline_tokens {
            return Err(Error::OfflineVerificationFailed(
                "Machine-file sync failed and legacy offline tokens are disabled".into(),
            ));
        }

        let token = self
            .generate_offline_token(&license.license_key, Some(&license.device_id), Some(30))
            .await?;
        let key_id = token.signature.key_id.clone();
        let _ = self.fetch_signing_key(&key_id).await?;
        self.emit(Event::new(EventKind::OfflineAssetsRefreshed));
        Ok(())
    }

    // ========================================================================
    // Private methods
    // ========================================================================

    fn require_product_slug(&self) -> Result<&str> {
        if self.inner.config.product_slug.is_empty() {
            return Err(Error::ProductSlugRequired);
        }
        Ok(&self.inner.config.product_slug)
    }

    fn emit(&self, event: Event) {
        let _ = self.inner.event_tx.send(event);
    }

    fn set_online(&self, online: bool) {
        let was_online = self.inner.is_online.swap(online, Ordering::SeqCst);
        if was_online != online {
            self.emit(Event::new(if online {
                EventKind::NetworkOnline
            } else {
                EventKind::NetworkOffline
            }));
        }
    }

    fn should_fallback_offline(&self, error: &Error) -> bool {
        match self.inner.config.offline_fallback_mode {
            OfflineFallbackMode::Always => true,
            OfflineFallbackMode::NetworkOnly => error.is_network_error(),
        }
    }

    #[cfg(feature = "offline")]
    async fn validate_offline(&self) -> Result<ValidationResult> {
        debug!("Attempting offline validation");
        self.emit(Event::new(EventKind::OfflineValidationStart));
        let mut last_invalid: Option<ValidationResult> = None;

        if let Some(machine_file) = self.inner.cache.get_machine_file() {
            match self.verify_machine_file(&machine_file, None, None, None) {
                Ok(verify_result) if verify_result.valid => {
                    let mut result = crate::offline::machine_file_to_validation_result(
                        verify_result.payload.as_ref().unwrap(),
                    );
                    self.finalize_offline_validation(&mut result)?;
                    self.emit(Event::with_validation(
                        EventKind::OfflineValidationSuccess,
                        result.clone(),
                    ));
                    self.emit(Event::with_validation(
                        EventKind::ValidationOfflineSuccess,
                        result.clone(),
                    ));
                    return Ok(result);
                }
                Ok(verify_result) => {
                    last_invalid = Some(offline_invalid_result(
                        verify_result.code,
                        verify_result.message,
                    ));
                }
                Err(error) => {
                    last_invalid = Some(offline_invalid_result(
                        Some(error_code_string_from_error(&error)),
                        Some(error.to_string()),
                    ));
                }
            }
        }

        if self.inner.config.enable_legacy_offline_tokens {
            if let Some(token) = self.inner.cache.get_offline_token() {
                match self.verify_offline_token(&token, None) {
                    Ok(true) => {
                        let mut result = crate::offline::token_to_validation_result(&token);
                        self.finalize_offline_validation(&mut result)?;
                        self.emit(Event::with_validation(
                            EventKind::OfflineValidationSuccess,
                            result.clone(),
                        ));
                        self.emit(Event::with_validation(
                            EventKind::ValidationOfflineSuccess,
                            result.clone(),
                        ));
                        return Ok(result);
                    }
                    Ok(false) => {
                        last_invalid = Some(offline_invalid_result(
                            Some("verification_failed".into()),
                            Some("Offline token verification failed".into()),
                        ));
                    }
                    Err(error) => {
                        last_invalid = Some(offline_invalid_result(
                            Some(error_code_string_from_error(&error)),
                            Some(error.to_string()),
                        ));
                    }
                }
            }
        }

        let mut result = last_invalid.unwrap_or_else(|| {
            offline_invalid_result(
                Some("no_offline_artifact".into()),
                Some("No cached machine file or offline token available".into()),
            )
        });
        self.finalize_offline_validation(&mut result)?;
        self.emit(Event::with_validation(
            EventKind::OfflineValidationFailed,
            result.clone(),
        ));
        self.emit(Event::with_validation(
            EventKind::ValidationOfflineFailed,
            result.clone(),
        ));
        Ok(result)
    }

    #[cfg(feature = "offline")]
    fn finalize_offline_validation(&self, result: &mut ValidationResult) -> Result<()> {
        result.offline = true;

        if self.inner.config.max_offline_days > 0 {
            if let Some(last_validated) = self.inner.cache.get_license().map(|l| l.last_validated) {
                let offline_duration = Utc::now().signed_duration_since(last_validated);
                let max_offline = chrono::Duration::days(self.inner.config.max_offline_days as i64);
                if offline_duration > max_offline {
                    *result = offline_invalid_result(
                        Some("grace_period_expired".into()),
                        Some(format!(
                            "Exceeded maximum offline period ({} days)",
                            self.inner.config.max_offline_days
                        )),
                    );
                }
            }
        }

        let now = Utc::now().timestamp();
        if let Some(last_seen) = self.inner.cache.get_last_seen_timestamp() {
            let max_skew = self.inner.config.max_clock_skew.as_secs() as i64;
            if now < last_seen - max_skew {
                *result = offline_invalid_result(
                    Some("clock_tamper".into()),
                    Some("Clock tampering detected".into()),
                );
            }
        }

        self.inner.cache.set_last_seen_timestamp(now)?;
        self.inner.cache.update_validation(result)?;
        Ok(())
    }

    #[cfg(feature = "offline")]
    fn resolve_public_key(&self, key_id: &str, override_key: Option<&str>) -> Option<String> {
        override_key
            .filter(|value| !value.is_empty())
            .map(ToString::to_string)
            .or_else(|| {
                self.inner
                    .config
                    .signing_public_key
                    .as_ref()
                    .map(ToString::to_string)
            })
            .or_else(|| {
                if key_id.is_empty() {
                    self.inner
                        .config
                        .signing_key_id
                        .as_ref()
                        .and_then(|configured_id| self.inner.cache.get_signing_key(configured_id))
                        .map(|key| key.public_key)
                } else {
                    self.inner
                        .cache
                        .get_signing_key(key_id)
                        .map(|key| key.public_key)
                }
            })
    }

    fn resolve_request_fingerprint(&self, fingerprint: Option<&str>) -> String {
        fingerprint
            .filter(|value| !value.is_empty())
            .map(ToString::to_string)
            .or_else(|| self.inner.cache.get_fingerprint())
            .unwrap_or_else(|| self.inner.fingerprint.clone())
    }

    fn support_tasks_should_continue(&self, generation: u64) -> bool {
        self.inner.background_tasks_running.load(Ordering::SeqCst)
            && self.inner.support_tasks_generation.load(Ordering::SeqCst) == generation
    }

    fn auto_validation_should_continue(&self, generation: u64) -> bool {
        self.inner.auto_validation_running.load(Ordering::SeqCst)
            && self.inner.auto_validation_generation.load(Ordering::SeqCst) == generation
    }

    fn heartbeat_should_continue(&self, generation: u64) -> bool {
        self.inner.heartbeat_running.load(Ordering::SeqCst)
            && self.inner.heartbeat_generation.load(Ordering::SeqCst) == generation
    }

    fn emit_auto_validation_cycle(&self, interval: Duration) {
        if let Ok(delta) = chrono::Duration::from_std(interval) {
            let next_run_at = Utc::now() + delta;
            self.set_next_auto_validation_at(Some(next_run_at));
            self.emit(Event::with_next_run_at(
                EventKind::AutoValidationCycle,
                next_run_at,
            ));
        } else {
            self.set_next_auto_validation_at(None);
            self.emit(Event::new(EventKind::AutoValidationCycle));
        }
    }

    fn lock_snapshot<T: Clone>(&self, mutex: &Mutex<Option<T>>) -> Option<T> {
        mutex.lock().ok().and_then(|guard| guard.clone())
    }

    fn set_last_heartbeat(&self, response: Option<HeartbeatResponse>) {
        if let Ok(mut guard) = self.inner.last_heartbeat.lock() {
            *guard = response;
        }
    }

    fn set_last_heartbeat_error(&self, error: Option<String>) {
        if let Ok(mut guard) = self.inner.last_heartbeat_error.lock() {
            *guard = error;
        }
    }

    fn set_last_health(&self, response: Option<HealthResponse>) {
        if let Ok(mut guard) = self.inner.last_health.lock() {
            *guard = response;
        }
    }

    fn set_last_health_error(&self, error: Option<String>) {
        if let Ok(mut guard) = self.inner.last_health_error.lock() {
            *guard = error;
        }
    }

    fn set_next_auto_validation_at(&self, next_auto_validation_at: Option<chrono::DateTime<Utc>>) {
        if let Ok(mut guard) = self.inner.next_auto_validation_at.lock() {
            *guard = next_auto_validation_at;
        }
    }

    async fn get<T: DeserializeOwned>(&self, path: &str) -> Result<T> {
        self.request(reqwest::Method::GET, path, None::<()>).await
    }

    async fn post<T: DeserializeOwned>(
        &self,
        path: &str,
        body: Option<serde_json::Value>,
    ) -> Result<T> {
        self.request(reqwest::Method::POST, path, body).await
    }

    async fn request<T: DeserializeOwned, B: serde::Serialize>(
        &self,
        method: reqwest::Method,
        path: &str,
        body: Option<B>,
    ) -> Result<T> {
        let url = build_request_url(&self.inner.config.api_base_url, path)?;

        // Prepare body once (with telemetry if enabled)
        let json_body: Option<serde_json::Value> = if let Some(b) = body {
            let mut json_body = serde_json::to_value(&b)?;

            // Add telemetry if enabled
            if self.inner.config.telemetry_enabled {
                if let serde_json::Value::Object(ref mut map) = json_body {
                    let telemetry = Telemetry::collect(
                        self.inner.config.app_version.clone(),
                        self.inner.config.app_build.clone(),
                    );
                    map.insert("telemetry".into(), serde_json::to_value(telemetry)?);
                }
            }

            Some(json_body)
        } else {
            None
        };

        // Retry logic - rebuild request for each attempt (reqwest bodies can't always be cloned)
        let mut last_error = None;
        for attempt in 0..=self.inner.config.max_retries {
            if attempt > 0 {
                let delay = self.inner.config.retry_delay * 2u32.pow(attempt - 1);
                tokio::time::sleep(delay).await;
                debug!("Retry attempt {} for {}", attempt, path);
            }

            // Build fresh request for each attempt
            debug!("Building request for {path} (attempt {attempt})");
            let mut request = self.inner.http.request(method.clone(), url.clone());
            if let Some(ref body) = json_body {
                request = request.json(body);
            }

            match request.send().await {
                Ok(response) => {
                    let status = response.status().as_u16();
                    debug!("Received response for {path} with status {status}");

                    if response.status().is_success() {
                        return response.json().await.map_err(Error::from);
                    }

                    let error_body = response.text().await.unwrap_or_default();
                    let (code, message, details) = parse_error_response_text(&error_body);

                    let error = Error::api(status, code, message, details);

                    // Don't retry business logic errors
                    if error.is_business_error() {
                        return Err(error);
                    }

                    last_error = Some(error);
                }
                Err(e) => {
                    let error = Error::Network(e);
                    if matches!(&error, Error::Network(source) if source.is_builder()) {
                        return Err(error);
                    }
                    last_error = Some(error);
                }
            }
        }

        Err(last_error.unwrap())
    }
}

// ============================================================================
// Helper types and functions
// ============================================================================

/// Options for license activation.
#[derive(Debug, Clone, Default)]
pub struct ActivationOptions {
    /// Custom fingerprint (canonical field).
    pub fingerprint: Option<String>,
    /// Backward-compatible device ID alias.
    pub device_id: Option<String>,
    /// Legacy compatibility alias for the canonical fingerprint.
    pub device_fingerprint: Option<String>,
    /// Human-readable device name.
    pub device_name: Option<String>,
    /// Additional metadata.
    pub metadata: Option<HashMap<String, serde_json::Value>>,
}

impl ActivationOptions {
    /// Create new activation options with a device name.
    pub fn with_device_name(name: impl Into<String>) -> Self {
        Self {
            device_name: Some(name.into()),
            ..Default::default()
        }
    }
}

/// Options for paginated release listing.
#[derive(Debug, Clone, Default)]
pub struct ReleaseListOptions {
    /// Optional channel filter.
    pub channel: Option<String>,
    /// Optional platform filter.
    pub platform: Option<String>,
    /// Maximum number of releases to return.
    ///
    /// The API defaults to 20 and caps the value at 100.
    pub limit: Option<u32>,
}

/// Options for machine-file checkout.
#[cfg(feature = "offline")]
#[derive(Debug, Clone)]
pub struct MachineFileCheckoutOptions {
    /// Preferred canonical fingerprint.
    pub fingerprint: Option<String>,
    /// Legacy `device_id` alias.
    pub device_id: Option<String>,
    /// Legacy `device_fingerprint` alias.
    pub device_fingerprint: Option<String>,
    /// Requested machine-file lifetime in days.
    pub ttl_days: Option<i64>,
    /// Requested grace period in days after expiry.
    pub grace_period_days: Option<i64>,
    /// Whether license data should be embedded in the encrypted payload.
    pub include_license: bool,
    /// Optional structured fingerprint components.
    pub fingerprint_components: HashMap<String, String>,
}

#[cfg(feature = "offline")]
impl Default for MachineFileCheckoutOptions {
    fn default() -> Self {
        Self {
            fingerprint: None,
            device_id: None,
            device_fingerprint: None,
            ttl_days: None,
            grace_period_days: None,
            include_license: true,
            fingerprint_components: HashMap::new(),
        }
    }
}

fn build_http_client(config: &Config) -> reqwest::Client {
    let mut headers = HeaderMap::new();

    headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    headers.insert(
        USER_AGENT,
        HeaderValue::from_str(&format!("licenseseat-rust/{}", crate::VERSION)).unwrap(),
    );

    if !config.api_key.is_empty() {
        if let Ok(value) = HeaderValue::from_str(&format!("Bearer {}", config.api_key)) {
            headers.insert(AUTHORIZATION, value);
        }
    }

    reqwest::Client::builder()
        .default_headers(headers)
        .timeout(config.request_timeout)
        .danger_accept_invalid_certs(!config.verify_ssl)
        .build()
        .expect("Failed to build HTTP client")
}

fn parse_error_response_text(
    body: &str,
) -> (
    Option<String>,
    String,
    Option<HashMap<String, serde_json::Value>>,
) {
    let trimmed = body.trim();
    if trimmed.is_empty() {
        return (None, "Unknown error".into(), None);
    }

    if let Ok(json) = serde_json::from_str::<serde_json::Value>(trimmed) {
        return parse_error_response(&json);
    }

    (None, trimmed.to_string(), None)
}

fn parse_error_response(
    body: &serde_json::Value,
) -> (
    Option<String>,
    String,
    Option<HashMap<String, serde_json::Value>>,
) {
    if let Some(errors) = body.get("errors").and_then(|value| value.as_array()) {
        if let Some(error) = errors.first().and_then(|value| value.as_object()) {
            let code = error.get("code").and_then(|c| c.as_str()).map(String::from);
            let message = error
                .get("detail")
                .or_else(|| error.get("title"))
                .and_then(|m| m.as_str())
                .unwrap_or("Unknown error")
                .to_string();
            let details = error
                .iter()
                .filter(|(key, _)| !matches!(key.as_str(), "code" | "title" | "detail"))
                .map(|(key, value)| (key.clone(), value.clone()))
                .collect::<HashMap<_, _>>();
            return (code, message, (!details.is_empty()).then_some(details));
        }
    }

    // Try new nested format: { "error": { "code": "...", "message": "...", "details": {...} } }
    if let Some(error) = body.get("error").and_then(|e| e.as_object()) {
        let code = error.get("code").and_then(|c| c.as_str()).map(String::from);
        let message = error
            .get("message")
            .and_then(|m| m.as_str())
            .unwrap_or("Unknown error")
            .to_string();
        let details = error.get("details").and_then(|d| {
            d.as_object()
                .map(|obj| obj.iter().map(|(k, v)| (k.clone(), v.clone())).collect())
        });
        return (code, message, details);
    }

    // Fallback: flat format
    let code = body.get("code").and_then(|c| c.as_str()).map(String::from);
    let message = body
        .get("message")
        .and_then(|m| m.as_str())
        .unwrap_or("Unknown error")
        .to_string();

    (code, message, None)
}

fn fingerprint_alias_payload(fingerprint: &str, include_when_empty: bool) -> serde_json::Value {
    let mut map = serde_json::Map::new();
    if include_when_empty || !fingerprint.is_empty() {
        map.insert("fingerprint".into(), serde_json::json!(fingerprint));
        map.insert("device_id".into(), serde_json::json!(fingerprint));
        map.insert("device_fingerprint".into(), serde_json::json!(fingerprint));
    }
    serde_json::Value::Object(map)
}

#[cfg(feature = "offline")]
fn build_offline_token_request(fingerprint: &str, ttl_days: Option<i64>) -> serde_json::Value {
    let mut body = fingerprint_alias_payload(fingerprint, true);
    if let Some(ttl_days) = ttl_days.filter(|value| *value > 0) {
        body["ttl_days"] = serde_json::json!(ttl_days);
    }
    body
}

#[cfg(feature = "offline")]
fn build_machine_file_request(
    fingerprint: &str,
    ttl_days: Option<i64>,
    grace_period_days: Option<i64>,
    include_license: bool,
    fingerprint_components: &HashMap<String, String>,
) -> serde_json::Value {
    let mut body = fingerprint_alias_payload(fingerprint, true);
    if let Some(ttl_days) = ttl_days.filter(|value| *value > 0) {
        body["ttl"] = serde_json::json!(ttl_days);
    }
    if let Some(grace_period_days) = grace_period_days.filter(|value| *value > 0) {
        body["grace_period"] = serde_json::json!(grace_period_days);
    }
    if !fingerprint_components.is_empty() {
        body["fingerprint_components"] = serde_json::json!(fingerprint_components);
    }
    if include_license {
        body["include"] = serde_json::json!(["license"]);
    }
    body
}

fn build_download_token_request(license_key: &str, platform: Option<&str>) -> serde_json::Value {
    let mut body = serde_json::json!({
        "license_key": license_key,
    });
    if let Some(platform) = platform.filter(|value| !value.is_empty()) {
        body["platform"] = serde_json::json!(platform);
    }
    body
}

fn build_request_url(base_url: &str, path: &str) -> Result<url::Url> {
    let normalized_base = base_url.trim_end_matches('/');
    let normalized_path = path.trim_start_matches('/');
    let combined = if normalized_path.is_empty() {
        normalized_base.to_string()
    } else {
        format!("{normalized_base}/{normalized_path}")
    };

    url::Url::parse(&combined).map_err(Error::from)
}

fn build_license_action_path(product_slug: &str, license_key: &str, action: &str) -> String {
    build_path(&["products", product_slug, "licenses", license_key, action])
}

fn build_path(segments: &[&str]) -> String {
    let mut url = url::Url::parse("https://licenseseat.invalid").unwrap();
    {
        let mut path_segments = url.path_segments_mut().unwrap();
        path_segments.clear();
        for segment in segments {
            path_segments.push(segment);
        }
    }
    url.path().to_string()
}

fn build_release_path(base_path: &str, options: &ReleaseListOptions) -> String {
    let mut serializer = url::form_urlencoded::Serializer::new(String::new());
    if let Some(channel) = options.channel.as_deref().filter(|value| !value.is_empty()) {
        serializer.append_pair("channel", channel);
    }
    if let Some(platform) = options
        .platform
        .as_deref()
        .filter(|value| !value.is_empty())
    {
        serializer.append_pair("platform", platform);
    }
    if let Some(limit) = options.limit {
        serializer.append_pair("limit", &limit.clamp(1, 100).to_string());
    }

    let query = serializer.finish();
    if query.is_empty() {
        base_path.to_string()
    } else {
        format!("{base_path}?{query}")
    }
}

fn parse_release_list(body: &serde_json::Value) -> Result<ReleaseList> {
    if body
        .get("data")
        .and_then(|value| value.as_array())
        .is_some()
    {
        return serde_json::from_value(body.clone()).map_err(Error::from);
    }

    if let Some(array) = body.as_array() {
        let data = array
            .iter()
            .cloned()
            .map(serde_json::from_value::<Release>)
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(Error::from)?;
        return Ok(ReleaseList {
            object: "list".into(),
            data,
            has_more: false,
            next_cursor: None,
        });
    }

    Err(Error::Json(serde_json::Error::io(std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        "Invalid release list response",
    ))))
}

fn select_fingerprint_alias<'a>(
    fingerprint: Option<&'a str>,
    device_id: Option<&'a str>,
    device_fingerprint: Option<&'a str>,
) -> Option<&'a str> {
    fingerprint
        .filter(|value| !value.is_empty())
        .or_else(|| device_id.filter(|value| !value.is_empty()))
        .or_else(|| device_fingerprint.filter(|value| !value.is_empty()))
}

#[cfg(feature = "offline")]
fn parse_machine_file_response(body: &serde_json::Value) -> Result<MachineFile> {
    let data = body.get("data").unwrap_or(body);
    let attributes = data
        .get("attributes")
        .and_then(|value| value.as_object())
        .ok_or_else(|| {
            Error::Json(serde_json::Error::io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Invalid machine-file response",
            )))
        })?;

    let relationships = data
        .get("relationships")
        .and_then(|value| value.as_object());

    Ok(MachineFile {
        certificate: attributes
            .get("certificate")
            .and_then(|value| value.as_str())
            .unwrap_or_default()
            .to_string(),
        algorithm: attributes
            .get("algorithm")
            .and_then(|value| value.as_str())
            .unwrap_or("aes-256-gcm+ed25519")
            .to_string(),
        ttl: attributes
            .get("ttl")
            .and_then(|value| value.as_i64())
            .unwrap_or_default(),
        issued_at: attributes
            .get("issued")
            .and_then(|value| value.as_str())
            .and_then(parse_rfc3339),
        expires_at: attributes
            .get("expiry")
            .and_then(|value| value.as_str())
            .and_then(parse_rfc3339),
        license_key: relationships
            .and_then(|relationships| relationships.get("license"))
            .and_then(|value| value.get("data"))
            .and_then(|value| value.get("id"))
            .and_then(|value| value.as_str())
            .unwrap_or_default()
            .to_string(),
        fingerprint: relationships
            .and_then(|relationships| relationships.get("machine"))
            .and_then(|value| value.get("data"))
            .and_then(|value| value.get("id"))
            .and_then(|value| value.as_str())
            .unwrap_or_default()
            .to_string(),
    })
}

#[cfg(feature = "offline")]
fn extract_machine_file_key_id(certificate: &str) -> Option<String> {
    let cleaned = certificate
        .replace("-----BEGIN MACHINE FILE-----", "")
        .replace("-----END MACHINE FILE-----", "")
        .chars()
        .filter(|ch| !ch.is_whitespace())
        .collect::<String>();
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(cleaned)
        .ok()?;
    let envelope: serde_json::Value = serde_json::from_slice(&decoded).ok()?;
    envelope
        .get("kid")
        .and_then(|value| value.as_str())
        .map(ToString::to_string)
}

#[cfg(feature = "offline")]
fn error_code_string_from_error(error: &Error) -> String {
    match error {
        Error::OfflineVerificationFailed(message) => {
            if message.contains("DECRYPTION_FAILED") {
                "decryption_failed".into()
            } else if message.contains("TOKEN_EXPIRED") {
                "token_expired".into()
            } else if message.contains("TOKEN_NOT_YET_VALID") {
                "token_not_yet_valid".into()
            } else if message.contains("FINGERPRINT_MISMATCH") {
                "fingerprint_mismatch".into()
            } else {
                "verification_failed".into()
            }
        }
        Error::OfflineTokenExpired => "token_expired".into(),
        Error::Api { code, .. } => code.clone().unwrap_or_else(|| "api_error".into()),
        _ => "verification_failed".into(),
    }
}

#[cfg(feature = "offline")]
fn offline_invalid_result(code: Option<String>, message: Option<String>) -> ValidationResult {
    ValidationResult {
        object: "validation_result".into(),
        valid: false,
        code,
        message,
        warnings: None,
        license: LicenseResponse {
            object: "license".into(),
            key: String::new(),
            status: "invalid".into(),
            starts_at: None,
            expires_at: None,
            mode: String::new(),
            plan_key: String::new(),
            seat_limit: None,
            active_seats: 0,
            active_entitlements: Vec::new(),
            metadata: None,
            product: Product {
                slug: String::new(),
                name: String::new(),
            },
        },
        activation: None,
        offline: true,
    }
}

fn default_validation_status() -> ValidationResult {
    ValidationResult {
        object: "validation_result".into(),
        valid: false,
        code: None,
        message: Some("No license validated".into()),
        warnings: None,
        license: LicenseResponse {
            object: "license".into(),
            key: String::new(),
            status: "unknown".into(),
            starts_at: None,
            expires_at: None,
            mode: String::new(),
            plan_key: String::new(),
            seat_limit: None,
            active_seats: 0,
            active_entitlements: Vec::new(),
            metadata: None,
            product: Product {
                slug: String::new(),
                name: String::new(),
            },
        },
        activation: None,
        offline: false,
    }
}

fn is_auth_failure_error(error: &Error) -> bool {
    matches!(
        error,
        Error::Api {
            status: 401 | 501,
            ..
        }
    )
}

fn is_revocation_error(error: &Error) -> bool {
    match error {
        Error::Api { code, .. } => is_revocation_code(code.as_deref()),
        _ => false,
    }
}

fn is_revocation_code(code: Option<&str>) -> bool {
    matches!(
        code,
        Some("revoked") | Some("suspended") | Some("license_revoked") | Some("license_suspended")
    )
}

fn parse_rfc3339(value: &str) -> Option<chrono::DateTime<chrono::Utc>> {
    chrono::DateTime::parse_from_rfc3339(value)
        .ok()
        .map(|value| value.with_timezone(&chrono::Utc))
}
