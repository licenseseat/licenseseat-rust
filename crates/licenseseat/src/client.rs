//! Main LicenseSeat client implementation.

use crate::cache::LicenseCache;
use crate::config::{Config, OfflineFallbackMode};
use crate::device::generate_fingerprint;
use crate::error::{Error, Result};
use crate::events::{Event, EventKind};
use crate::models::*;
use crate::telemetry::Telemetry;

use chrono::Utc;
use reqwest::header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE, HeaderMap, HeaderValue, USER_AGENT};
use serde::de::DeserializeOwned;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::broadcast;
use tracing::{debug, warn};

const MAX_API_REQUEST_BYTES: usize = 1024 * 1024;
const MAX_API_RESPONSE_BYTES: usize = 2 * 1024 * 1024;
const MAX_RESPONSE_METADATA_BYTES: usize = 1024 * 1024;
const MAX_ERROR_DETAILS_BYTES: usize = 64 * 1024;
const MAX_ERROR_MESSAGE_BYTES: usize = 1_024;
const MAX_JSON_DEPTH: usize = 20;
const MAX_JSON_NODES: usize = 10_000;
const MAX_OFFLINE_DAYS: u32 = 36_600;
#[cfg(feature = "offline")]
const MAX_MACHINE_FILE_TTL_SECONDS: i64 = 36_600 * 86_400;
const MAX_BACKGROUND_INTERVAL: Duration = Duration::from_secs(366 * 86_400);

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
    // Client construction can fail (for example when the platform TLS backend
    // cannot initialize). Keep that failure sticky and fail closed at request
    // time instead of silently falling back to reqwest defaults, which would
    // re-enable redirects and discard the configured headers and timeout.
    http: Option<reqwest::Client>,
    cache: LicenseCache,
    // Persisted online validation is only a recovery hint: local cache files are
    // writable by the end user and therefore cannot be an authorization root.
    license: Mutex<Option<License>>,
    #[cfg(feature = "offline")]
    // Keys fetched over authenticated HTTPS are trusted only for this process.
    // A persisted public-key cache is diagnostic data, not a trust anchor.
    trusted_signing_keys: Mutex<HashMap<String, SigningKeyResponse>>,
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
        let cached_license = cache.get_license().and_then(|mut license| {
            if validate_cached_license_shape(&license).is_err() {
                cache.clear();
                return None;
            }

            // HTTPS responses cached by an earlier process are not locally
            // authenticated. Preserve activation identity for recovery, but
            // require fresh online or cryptographically verified validation.
            license.validation = None;
            license.trusted_license = None;
            let _ = cache.set_license(&license);
            Some(license)
        });
        let (event_tx, _) = broadcast::channel(64);

        let inner = Arc::new(LicenseSeatInner {
            config,
            http,
            cache,
            license: Mutex::new(cached_license),
            #[cfg(feature = "offline")]
            trusted_signing_keys: Mutex::new(HashMap::new()),
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
        if let Some(license) = sdk.current_license() {
            debug!("Loaded cached license state");
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
        validate_license_key(license_key)?;
        let device_id = resolve_fingerprint_alias(
            options.fingerprint.as_deref(),
            options.device_id.as_deref(),
            options.device_fingerprint.as_deref(),
        )?
        .map(ToString::to_string)
        .unwrap_or_else(|| self.inner.fingerprint.clone());
        validate_fingerprint(&device_id)?;
        validate_optional_text_input(options.device_name.as_deref(), 255, "device_name")?;
        validate_metadata_input(options.metadata.as_ref(), "metadata")?;
        debug!("Starting activation request");

        self.emit(Event::new(EventKind::ActivationStart));

        let mut body = fingerprint_alias_payload(&device_id, true);
        body["license_key"] = serde_json::json!(license_key);

        if let Some(name) = &options.device_name {
            body["device_name"] = serde_json::json!(name);
        }

        if let Some(metadata) = &options.metadata {
            body["metadata"] = serde_json::json!(metadata);
        }

        let path = build_license_action_path(product_slug, "activate");

        match self.post::<ActivationResponse>(&path, Some(body)).await {
            Ok(activation) => {
                if let Err(error) =
                    validate_activation_response(&activation, license_key, &device_id, product_slug)
                {
                    self.emit(Event::with_error(
                        EventKind::ActivationError,
                        error.to_string(),
                    ));
                    return Err(error);
                }
                let license = License {
                    license_key: license_key.to_string(),
                    device_id: activation.device_id,
                    activation_id: activation.id,
                    activated_at: activation.activated_at,
                    last_validated: Utc::now(),
                    trusted_license: Some(activation.license.clone()),
                    validation: None,
                };

                self.store_license(license.clone())?;
                self.emit(Event::with_license(
                    EventKind::ActivationSuccess,
                    license.clone(),
                ));

                // Start background tasks
                self.start_background_tasks();

                // Sync offline assets (non-blocking) only when local policy
                // grants offline authority. A zero-day policy is documented as
                // disabled and must not prefetch or persist offline credentials.
                #[cfg(feature = "offline")]
                if self.offline_policy_is_enabled() {
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
        let license = self.current_license().ok_or(Error::NoActiveLicense)?;
        self.validate_key(&license.license_key).await
    }

    /// Validate a specific license key.
    pub async fn validate_key(&self, license_key: &str) -> Result<ValidationResult> {
        let product_slug = self.require_product_slug()?;
        validate_license_key(license_key)?;
        let current_license = self.current_license();
        let validates_current_license = current_license
            .as_ref()
            .is_some_and(|license| constant_time_equal(&license.license_key, license_key));
        let device_id = current_license
            .map(|license| license.device_id)
            .unwrap_or_else(|| self.inner.fingerprint.clone());
        validate_fingerprint(&device_id)?;

        self.emit(Event::new(EventKind::ValidationStart));

        let path = build_license_action_path(product_slug, "validate");
        let mut body = fingerprint_alias_payload(&device_id, false);
        body["license_key"] = serde_json::json!(license_key);
        let body = Some(body);

        match self.post::<ValidationResult>(&path, body).await {
            Ok(mut result) => {
                if let Err(error) =
                    validate_validation_response(&result, license_key, &device_id, product_slug)
                {
                    self.emit(Event::with_error(
                        EventKind::ValidationError,
                        error.to_string(),
                    ));
                    return Err(error);
                }
                result.offline = false;
                if validates_current_license {
                    self.update_validation_state(&result)?;
                    self.inner
                        .cache
                        .set_last_seen_timestamp(Utc::now().timestamp())?;
                }
                self.set_online(true);

                if validates_current_license && is_revocation_code(result.code.as_deref()) {
                    self.clear_license_state();
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

                if validates_current_license && is_revocation_error(&e) {
                    self.clear_license_state();
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
                if validates_current_license && self.should_fallback_offline(&e) {
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
        let license = self.current_license().ok_or(Error::NoActiveLicense)?;
        self.deactivate_key(&license.license_key, Some(&license.device_id))
            .await
    }

    /// Deactivate a specific license/fingerprint pair.
    pub async fn deactivate_key(&self, license_key: &str, fingerprint: Option<&str>) -> Result<()> {
        let product_slug = self.require_product_slug()?;
        validate_license_key(license_key)?;

        let resolved_fingerprint = self.resolve_request_fingerprint(fingerprint);
        validate_fingerprint(&resolved_fingerprint)?;
        let current_activation_id = self.current_license().and_then(|license| {
            (constant_time_equal(&license.license_key, license_key)
                && constant_time_equal(&license.device_id, &resolved_fingerprint))
            .then_some(license.activation_id)
        });
        let should_clear_cache = current_activation_id.is_some();

        self.emit(Event::new(EventKind::DeactivationStart));

        let path = build_license_action_path(product_slug, "deactivate");
        let mut body = fingerprint_alias_payload(&resolved_fingerprint, true);
        body["license_key"] = serde_json::json!(license_key);

        match self.post::<DeactivationResponse>(&path, Some(body)).await {
            Ok(response) => {
                if let Err(error) =
                    validate_deactivation_response(&response, current_activation_id.as_deref())
                {
                    self.emit(Event::with_error(
                        EventKind::DeactivationError,
                        error.to_string(),
                    ));
                    return Err(error);
                }
                if should_clear_cache {
                    self.clear_license_state();
                }
                self.emit(Event::new(EventKind::DeactivationSuccess));
                debug!("License deactivated");
                Ok(())
            }
            Err(e) => {
                // Treat certain errors as success (already deactivated, not found, etc.)
                if let Error::Api { status, code, .. } = &e {
                    if matches!(*status, 404 | 410)
                        && code.as_deref().is_some_and(|code| {
                            [
                                "activation_not_found",
                                "license_not_found",
                                "already_deactivated",
                                "revoked",
                                "license_revoked",
                            ]
                            .contains(&code)
                        })
                    {
                        if should_clear_cache {
                            self.clear_license_state();
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
                                    self.clear_license_state();
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
        let license = self.current_license().ok_or(Error::NoActiveLicense)?;
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
        validate_license_key(license_key)?;
        let resolved_fingerprint = self.resolve_request_fingerprint(fingerprint);
        validate_fingerprint(&resolved_fingerprint)?;

        let path = build_license_action_path(product_slug, "heartbeat");
        let mut body = fingerprint_alias_payload(&resolved_fingerprint, true);
        body["license_key"] = serde_json::json!(license_key);

        match self.post::<HeartbeatResponse>(&path, Some(body)).await {
            Ok(response) => {
                if let Err(error) =
                    validate_heartbeat_response(&response, license_key, product_slug)
                {
                    let response_identity_is_trusted = response.object == "heartbeat"
                        && validate_license_response_identity(
                            &response.license,
                            license_key,
                            product_slug,
                        )
                        .is_ok();
                    let heartbeat_invalidates_current_license = response_identity_is_trusted
                        && !license_response_is_currently_active(&response.license)
                        && self.current_license().is_some_and(|license| {
                            constant_time_equal(&license.license_key, license_key)
                        });
                    if heartbeat_invalidates_current_license {
                        self.clear_license_state();
                    }
                    self.set_last_heartbeat_error(Some(error.to_string()));
                    self.emit(Event::with_error(
                        EventKind::HeartbeatError,
                        error.to_string(),
                    ));
                    return Err(error);
                }
                self.set_trusted_license_state(&response.license)?;
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
        let Some(license) = self.current_license() else {
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

        if !validation.valid || !license_response_is_currently_active(&validation.license) {
            return EntitlementStatus {
                active: false,
                reason: Some(EntitlementReason::NoLicense),
                expires_at: None,
                entitlement: None,
            };
        }

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
                    if expires_at <= Utc::now() {
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
        let Some(license) = self.current_license() else {
            return LicenseStatus::Inactive {
                message: "No license activated".into(),
            };
        };

        let Some(validation) = &license.validation else {
            return LicenseStatus::Pending {
                message: "License pending validation".into(),
            };
        };

        if !validation.valid || !license_response_is_currently_active(&validation.license) {
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
        self.current_license()
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
        self.inner
            .license
            .lock()
            .ok()
            .and_then(|guard| guard.clone())
    }

    /// Get the last trusted rich license metadata cached for offline recovery.
    #[cfg(feature = "offline")]
    pub fn current_trusted_license(&self) -> Option<LicenseResponse> {
        self.current_trusted_license_record()
            .map(|(license, _)| license)
    }

    /// Get the source of the current trusted rich license metadata, if any.
    #[cfg(feature = "offline")]
    pub fn current_trusted_license_source(&self) -> Option<TrustedLicenseSource> {
        self.current_trusted_license_record()
            .map(|(_, source)| source)
    }

    /// Get the cached offline token, if one has been stored.
    #[cfg(feature = "offline")]
    pub fn current_offline_token(&self) -> Option<OfflineTokenResponse> {
        self.inner.cache.get_offline_token()
    }

    /// Get the cached machine file, if one has been stored.
    #[cfg(feature = "offline")]
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
        crate::offline::machine_file_key_id(&machine_file.certificate).ok()
    }

    /// Get a signing key fetched over authenticated HTTPS during this process.
    ///
    /// Persisted key files are intentionally not trusted as verification roots.
    #[cfg(feature = "offline")]
    pub fn cached_signing_key(&self, key_id: &str) -> Option<SigningKeyResponse> {
        self.inner
            .trusted_signing_keys
            .lock()
            .ok()
            .and_then(|keys| keys.get(key_id).cloned())
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
        let Some(license) = self.current_license() else {
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
                if let Err(error) = validate_health_response(&response) {
                    self.set_last_health_error(Some(error.to_string()));
                    self.set_online(false);
                    return Err(error);
                }
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
        validate_product_slug_input(product_slug)?;
        validate_release_channel(channel)?;
        validate_release_platform(platform)?;

        let path = build_release_path(
            &build_path(&["products", product_slug, "releases", "latest"]),
            &ReleaseListOptions {
                channel: channel.map(ToString::to_string),
                platform: platform.map(ToString::to_string),
                limit: None,
            },
        );
        let release = self.get(&path).await?;
        validate_release_response(&release, product_slug)?;
        Ok(release)
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
        validate_product_slug_input(product_slug)?;
        validate_release_channel(options.channel.as_deref())?;
        validate_release_platform(options.platform.as_deref())?;
        if options.limit == Some(0) || options.limit.is_some_and(|limit| limit > 100) {
            return Err(Error::Configuration("release limit is invalid".into()));
        }

        let path = build_release_path(
            &build_path(&["products", product_slug, "releases"]),
            &options,
        );
        let body: serde_json::Value = self.get(&path).await?;
        let releases = parse_release_list(&body)?;
        validate_release_list_response(&releases, product_slug)?;
        Ok(releases)
    }

    /// Generate a download token for a release.
    pub async fn generate_download_token(
        &self,
        version: &str,
        license_key: &str,
        product_slug: Option<&str>,
        platform: Option<&str>,
    ) -> Result<DownloadToken> {
        validate_release_version(version)?;
        validate_license_key(license_key)?;
        validate_release_platform(platform)?;

        let product_slug = product_slug
            .filter(|slug| !slug.is_empty())
            .unwrap_or(&self.inner.config.product_slug);
        validate_product_slug_input(product_slug)?;

        let path = build_path(&[
            "products",
            product_slug,
            "releases",
            version,
            "download_token",
        ]);
        let body = build_download_token_request(license_key, platform);
        let token = self.post(&path, Some(body)).await?;
        validate_download_token_response(&token)?;
        Ok(token)
    }

    /// Reset SDK state (clears cache and stops timers).
    pub fn reset(&self) {
        // Stop background tasks first
        self.stop_background_tasks();
        self.clear_license_state();
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
        let Some(license) = self.current_license() else {
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

        if validate_license_key(license_key).is_err() {
            self.emit(Event::with_error(
                EventKind::SdkError,
                "license_key is invalid for auto-validation",
            ));
            return;
        }

        let interval = self.inner.config.auto_validate_interval;
        if interval.is_zero() {
            return;
        }
        if interval > MAX_BACKGROUND_INTERVAL {
            self.emit(Event::with_error(
                EventKind::SdkError,
                "auto-validation interval exceeds the supported limit",
            ));
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
        let spawn_error_sdk = self.clone();
        let license_key = license_key.to_string();
        let spawn_result = std::thread::Builder::new()
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

                        if !sdk.auto_validation_should_continue(generation) {
                            break;
                        }

                        let _ = sdk.heartbeat_key(&license_key, None).await;

                        if !sdk.auto_validation_should_continue(generation) {
                            break;
                        }

                        sdk.emit_auto_validation_cycle(interval);
                    }
                });
            });
        if let Err(error) = spawn_result {
            spawn_error_sdk
                .inner
                .auto_validation_running
                .store(false, Ordering::SeqCst);
            spawn_error_sdk.emit(Event::with_error(
                EventKind::SdkError,
                format!("Failed to spawn auto-validation thread: {error}"),
            ));
        }
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

        if validate_license_key(license_key).is_err() {
            self.emit(Event::with_error(
                EventKind::SdkError,
                "license_key is invalid for heartbeat",
            ));
            return;
        }

        let interval = self.inner.config.heartbeat_interval;
        if interval.is_zero() {
            return;
        }
        if interval > MAX_BACKGROUND_INTERVAL {
            self.emit(Event::with_error(
                EventKind::SdkError,
                "heartbeat interval exceeds the supported limit",
            ));
            return;
        }

        let generation = self
            .inner
            .heartbeat_generation
            .fetch_add(1, Ordering::SeqCst)
            + 1;
        self.inner.heartbeat_running.store(true, Ordering::SeqCst);

        let sdk = self.clone();
        let spawn_error_sdk = self.clone();
        let license_key = license_key.to_string();
        let spawn_result = std::thread::Builder::new()
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
            });
        if let Err(error) = spawn_result {
            spawn_error_sdk
                .inner
                .heartbeat_running
                .store(false, Ordering::SeqCst);
            spawn_error_sdk.emit(Event::with_error(
                EventKind::SdkError,
                format!("Failed to spawn heartbeat thread: {error}"),
            ));
        }
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
        let refresh_enabled = self.offline_policy_is_enabled() && !refresh_interval.is_zero();
        #[cfg(feature = "offline")]
        let has_support_tasks = !network_recheck_interval.is_zero() || refresh_enabled;
        #[cfg(not(feature = "offline"))]
        let has_support_tasks = !network_recheck_interval.is_zero();

        if !has_support_tasks {
            return;
        }
        #[cfg(feature = "offline")]
        let interval_is_invalid = network_recheck_interval > MAX_BACKGROUND_INTERVAL
            || refresh_interval > MAX_BACKGROUND_INTERVAL;
        #[cfg(not(feature = "offline"))]
        let interval_is_invalid = network_recheck_interval > MAX_BACKGROUND_INTERVAL;
        if interval_is_invalid {
            self.emit(Event::with_error(
                EventKind::SdkError,
                "background interval exceeds the supported limit",
            ));
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
        let spawn_error_sdk = self.clone();

        let spawn_result = std::thread::Builder::new()
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
                    if refresh_enabled {
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
            });
        if let Err(error) = spawn_result {
            spawn_error_sdk
                .inner
                .background_tasks_running
                .store(false, Ordering::SeqCst);
            spawn_error_sdk.emit(Event::with_error(
                EventKind::SdkError,
                format!("Failed to spawn background thread: {error}"),
            ));
        }
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

            if self.current_license().is_none() {
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
                if let Some(license) = self.current_license() {
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
        validate_license_key(license_key)?;
        let fingerprint = fingerprint
            .filter(|value| !value.is_empty())
            .map(ToString::to_string)
            .or_else(|| self.current_license().map(|license| license.device_id))
            .unwrap_or_else(|| self.inner.fingerprint.clone());
        validate_fingerprint(&fingerprint)?;
        validate_ttl_days(ttl_days)?;

        self.emit(Event::new(EventKind::OfflineTokenFetching));

        let path = build_license_action_path(product_slug, "offline-token");
        let body = build_offline_token_request(license_key, &fingerprint, ttl_days);
        match self.post::<OfflineTokenResponse>(&path, Some(body)).await {
            Ok(token) => {
                let verification = async {
                    let key_id = token.signature.key_id.clone();
                    validate_key_id(&key_id)?;
                    let public_key = match self.resolve_public_key(&key_id, None) {
                        Some(public_key) => public_key,
                        None => self.fetch_signing_key(&key_id).await?,
                    };
                    if !self.verify_offline_token(&token, Some(&public_key))? {
                        return Err(Error::OfflineVerificationFailed(
                            "Offline token signature is invalid".into(),
                        ));
                    }
                    Ok(())
                }
                .await;
                match verification {
                    Ok(()) => {
                        self.emit(Event::new(EventKind::OfflineTokenFetched));
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
        validate_license_key(license_key)?;
        let MachineFileCheckoutOptions {
            fingerprint,
            device_id,
            device_fingerprint,
            ttl_days,
            grace_period_days,
            include_license,
            fingerprint_components,
        } = options;
        let fingerprint = resolve_fingerprint_alias(
            fingerprint.as_deref(),
            device_id.as_deref(),
            device_fingerprint.as_deref(),
        )?
        .map(ToString::to_string)
        .or_else(|| self.current_license().map(|license| license.device_id))
        .unwrap_or_else(|| self.inner.fingerprint.clone());
        validate_fingerprint(&fingerprint)?;
        validate_ttl_days(ttl_days)?;
        validate_grace_period_days(grace_period_days)?;
        validate_fingerprint_components(&fingerprint_components)?;

        self.emit(Event::new(EventKind::MachineFileFetching));

        let fingerprint_components =
            if fingerprint_components.is_empty() && fingerprint == self.inner.fingerprint {
                collect_fingerprint_components()
            } else {
                fingerprint_components
            };
        validate_fingerprint_components(&fingerprint_components)?;
        let path = build_license_action_path(product_slug, "machine-file");
        let body = build_machine_file_request(
            license_key,
            &fingerprint,
            ttl_days,
            grace_period_days,
            include_license,
            &fingerprint_components,
        );
        match self.post::<serde_json::Value>(&path, Some(body)).await {
            Ok(response) => {
                let machine_file = match parse_machine_file_response(&response) {
                    Ok(machine_file) => machine_file,
                    Err(error) => {
                        self.emit(Event::with_error(
                            EventKind::MachineFileFetchError,
                            error.to_string(),
                        ));
                        return Err(error);
                    }
                };
                if !constant_time_equal(&machine_file.license_key, license_key) {
                    return Err(Error::OfflineVerificationFailed(
                        "Machine-file response license does not match request".into(),
                    ));
                }
                if !constant_time_equal(&machine_file.fingerprint, &fingerprint) {
                    return Err(Error::OfflineVerificationFailed(
                        "Machine-file response fingerprint does not match request".into(),
                    ));
                }
                let key_id = crate::offline::machine_file_key_id(&machine_file.certificate)?;
                let public_key = match self.fetch_signing_key(&key_id).await {
                    Ok(key) => key,
                    Err(error) => self.resolve_public_key(&key_id, None).ok_or(error)?,
                };
                crate::offline::verify_machine_file(
                    &machine_file,
                    license_key,
                    &fingerprint,
                    &public_key,
                )?;
                self.inner.cache.set_machine_file(&machine_file)?;

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
        validate_key_id(key_id)?;

        let path = build_path(&["signing_keys", key_id]);
        let response: SigningKeyResponse = self.get(&path).await?;
        let decoded_key = base64::engine::general_purpose::STANDARD
            .decode(&response.public_key)
            .map_err(|_| Error::OfflineVerificationFailed("Invalid signing key response".into()))?;
        if response.object != "signing_key"
            || response.key_id != key_id
            || response.algorithm != "Ed25519"
            || response.status != "active"
            || decoded_key.len() != 32
        {
            return Err(Error::OfflineVerificationFailed(
                "Invalid signing key response".into(),
            ));
        }
        let key = response.public_key.clone();
        if let Ok(mut keys) = self.inner.trusted_signing_keys.lock() {
            keys.insert(key_id.to_string(), response);
        }
        Ok(key)
    }

    /// Verify a legacy offline token locally.
    #[cfg(feature = "offline")]
    pub fn verify_offline_token(
        &self,
        offline_token: &OfflineTokenResponse,
        public_key_b64: Option<&str>,
    ) -> Result<bool> {
        validate_license_key(&offline_token.token.license_key)?;
        self.inner.config.validate_product_slug()?;

        let expected_fingerprint = self
            .current_license()
            .map(|license| license.device_id)
            .unwrap_or_else(|| self.inner.fingerprint.clone());
        let token_fingerprint = offline_token.token.device_id.as_deref().unwrap_or_default();
        if !constant_time_equal(token_fingerprint, &expected_fingerprint) {
            return Err(Error::OfflineVerificationFailed(
                "FINGERPRINT_MISMATCH".into(),
            ));
        }
        if offline_token.token.product_slug != self.inner.config.product_slug {
            return Err(Error::OfflineVerificationFailed("PRODUCT_MISMATCH".into()));
        }
        if self
            .current_license()
            .is_some_and(|license| license.license_key != offline_token.token.license_key)
        {
            return Err(Error::OfflineVerificationFailed("LICENSE_MISMATCH".into()));
        }

        let signing_key = self
            .resolve_signing_key(&offline_token.signature.key_id, public_key_b64)
            .ok_or_else(|| {
                Error::Configuration(
                    "a pinned or freshly fetched public key is required for offline verification"
                        .into(),
                )
            })?;

        let result = crate::offline::verify_token(offline_token, &signing_key)?;
        crate::offline::check_token_validity(offline_token)?;
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
        let current_license = self.current_license();
        let resolved_license_key = license_key
            .filter(|value| !value.is_empty())
            .map(ToString::to_string)
            .or_else(|| {
                current_license
                    .as_ref()
                    .map(|license| license.license_key.clone())
            })
            .or_else(|| {
                (!machine_file.license_key.is_empty()).then(|| machine_file.license_key.clone())
            })
            .ok_or_else(|| Error::Configuration("license_key is required".into()))?;

        let resolved_fingerprint = fingerprint
            .filter(|value| !value.is_empty())
            .map(ToString::to_string)
            .or_else(|| {
                current_license
                    .as_ref()
                    .map(|license| license.device_id.clone())
            })
            .or_else(|| {
                (!machine_file.fingerprint.is_empty()).then(|| machine_file.fingerprint.clone())
            })
            .unwrap_or_else(|| self.inner.fingerprint.clone());

        let key_id = crate::offline::machine_file_key_id(&machine_file.certificate)?;
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
                if payload.product_slug != self.inner.config.product_slug {
                    return Err(Error::OfflineVerificationFailed("PRODUCT_MISMATCH".into()));
                }
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
    #[cfg(feature = "offline")]
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
    #[cfg(feature = "offline")]
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
        self.require_offline_policy_enabled()?;
        let license = self.current_license().ok_or(Error::NoActiveLicense)?;

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
        self.inner.cache.set_offline_token(&token)?;
        self.emit(Event::new(EventKind::OfflineTokenReady));
        self.emit(Event::new(EventKind::OfflineAssetsRefreshed));
        Ok(())
    }

    // ========================================================================
    // Private methods
    // ========================================================================

    fn require_product_slug(&self) -> Result<&str> {
        self.inner.config.validate_product_slug()?;
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
        if !self.offline_policy_is_enabled() {
            return false;
        }

        match self.inner.config.offline_fallback_mode {
            OfflineFallbackMode::Always => true,
            OfflineFallbackMode::NetworkOnly => error.is_network_error(),
        }
    }

    fn offline_policy_is_enabled(&self) -> bool {
        (1..=MAX_OFFLINE_DAYS).contains(&self.inner.config.max_offline_days)
    }

    #[cfg(feature = "offline")]
    fn require_offline_policy_enabled(&self) -> Result<()> {
        match self.inner.config.max_offline_days {
            0 => Err(Error::Configuration(
                "offline validation is disabled by local policy".into(),
            )),
            days if days > MAX_OFFLINE_DAYS => Err(Error::Configuration(
                "max_offline_days exceeds the supported limit".into(),
            )),
            _ => Ok(()),
        }
    }

    #[cfg(feature = "offline")]
    async fn validate_offline(&self) -> Result<ValidationResult> {
        self.require_offline_policy_enabled()?;
        debug!("Attempting offline validation");
        self.emit(Event::new(EventKind::OfflineValidationStart));
        let mut last_invalid: Option<ValidationResult> = None;

        if let Some(machine_file) = self.inner.cache.get_machine_file() {
            match self.verify_machine_file(&machine_file, None, None, None) {
                Ok(verify_result) if verify_result.valid => {
                    let Some(payload) = verify_result.payload.as_ref() else {
                        return Err(Error::OfflineVerificationFailed(
                            "Verified machine file did not contain a payload".into(),
                        ));
                    };
                    let mut result = crate::offline::machine_file_to_validation_result(payload);
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
        self.require_offline_policy_enabled()?;
        result.offline = true;
        if result.valid && !license_response_is_currently_active(&result.license) {
            *result = offline_invalid_result(
                Some("license_inactive".into()),
                Some("Offline artifact contains an inactive license".into()),
            );
        }
        if result.valid
            && self.current_license().is_none_or(|license| {
                !constant_time_equal(&license.license_key, &result.license.key)
                    || result.license.product.slug != self.inner.config.product_slug
            })
        {
            *result = offline_invalid_result(
                Some("license_mismatch".into()),
                Some("Offline artifact identity does not match the active license".into()),
            );
        }
        if self.inner.config.max_clock_skew > Duration::from_secs(86_400) {
            return Err(Error::Configuration(
                "max_clock_skew exceeds the supported limit".into(),
            ));
        }

        if let Some(last_validated) = self.current_license().map(|l| l.last_validated) {
            let offline_duration = Utc::now().signed_duration_since(last_validated);
            let max_offline = chrono::Duration::days(self.inner.config.max_offline_days as i64);
            let max_skew = chrono::Duration::from_std(self.inner.config.max_clock_skew)
                .map_err(|_| Error::Configuration("max_clock_skew is invalid".into()))?;
            if offline_duration < -max_skew {
                *result = offline_invalid_result(
                    Some("clock_tamper".into()),
                    Some("Clock tampering detected".into()),
                );
            } else if offline_duration > max_offline {
                *result = offline_invalid_result(
                    Some("grace_period_expired".into()),
                    Some(format!(
                        "Exceeded maximum offline period ({} days)",
                        self.inner.config.max_offline_days
                    )),
                );
            }
        }

        let now = Utc::now().timestamp();
        if let Some(last_seen) = self.inner.cache.get_last_seen_timestamp() {
            let max_skew = i64::try_from(self.inner.config.max_clock_skew.as_secs())
                .map_err(|_| Error::Configuration("max_clock_skew is invalid".into()))?;
            if now.saturating_add(max_skew) < last_seen {
                *result = offline_invalid_result(
                    Some("clock_tamper".into()),
                    Some("Clock tampering detected".into()),
                );
            }
        }

        if result.valid {
            self.inner.cache.set_last_seen_timestamp(now)?;
        }
        self.update_offline_validation_state(result)?;
        Ok(())
    }

    #[cfg(feature = "offline")]
    fn resolve_public_key(&self, key_id: &str, override_key: Option<&str>) -> Option<String> {
        self.resolve_signing_key(key_id, override_key)
            .map(|key| key.public_key)
    }

    #[cfg(feature = "offline")]
    fn resolve_signing_key(
        &self,
        key_id: &str,
        override_key: Option<&str>,
    ) -> Option<SigningKeyResponse> {
        if let Some(public_key) = override_key.filter(|value| !value.is_empty()) {
            return Some(signing_key_record(key_id, public_key));
        }
        if self.inner.config.signing_key_id.as_deref() == Some(key_id) {
            if let Some(public_key) = self.inner.config.signing_public_key.as_deref() {
                return Some(signing_key_record(key_id, public_key));
            }
        }
        self.inner
            .trusted_signing_keys
            .lock()
            .ok()
            .and_then(|keys| keys.get(key_id).cloned())
            .filter(|key| {
                key.object == "signing_key"
                    && key.key_id == key_id
                    && key.algorithm == "Ed25519"
                    && key.status == "active"
            })
    }

    fn resolve_request_fingerprint(&self, fingerprint: Option<&str>) -> String {
        fingerprint
            .filter(|value| !value.is_empty())
            .map(ToString::to_string)
            .or_else(|| self.current_license().map(|license| license.device_id))
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

    fn store_license(&self, license: License) -> Result<()> {
        self.inner.cache.set_license(&license)?;
        let mut state = self
            .inner
            .license
            .lock()
            .map_err(|_| Error::Cache("in-memory license state is unavailable".into()))?;
        *state = Some(license);
        Ok(())
    }

    fn update_validation_state(&self, result: &ValidationResult) -> Result<()> {
        let Some(mut license) = self.current_license() else {
            return Ok(());
        };
        if !constant_time_equal(&license.license_key, &result.license.key) {
            return Ok(());
        }
        if result.valid && !result.offline {
            license.trusted_license = Some(result.license.clone());
            license.last_validated = Utc::now();
        }
        license.validation = Some(result.clone());
        self.store_license(license)
    }

    #[cfg(feature = "offline")]
    fn update_offline_validation_state(&self, result: &ValidationResult) -> Result<()> {
        if result.valid {
            return self.update_validation_state(result);
        }

        let Some(mut license) = self.current_license() else {
            return Ok(());
        };

        // Invalid offline results intentionally contain no artifact-controlled
        // license identity or entitlements. Bind that failure only to the
        // already-active session so status becomes OfflineInvalid without
        // allowing an untrusted artifact to replace authorization state.
        let mut stored_result = result.clone();
        stored_result.license.key = license.license_key.clone();
        stored_result.license.product.slug = self.inner.config.product_slug.clone();
        stored_result.license.product.name = self.inner.config.product_slug.clone();
        license.validation = Some(stored_result);
        self.store_license(license)
    }

    fn set_trusted_license_state(&self, trusted_license: &LicenseResponse) -> Result<()> {
        let Some(mut license) = self.current_license() else {
            return Ok(());
        };
        if license.license_key == trusted_license.key {
            license.trusted_license = Some(trusted_license.clone());
            self.store_license(license)?;
        }
        Ok(())
    }

    fn clear_license_state(&self) {
        self.stop_background_tasks();
        if let Ok(mut state) = self.inner.license.lock() {
            *state = None;
        }
        self.inner.cache.clear();
    }

    #[cfg(feature = "offline")]
    fn current_trusted_license_record(&self) -> Option<(LicenseResponse, TrustedLicenseSource)> {
        self.current_license()
            .and_then(|license| license.trusted_license)
            .map(|license| (license, TrustedLicenseSource::CachedLicense))
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
        self.inner.config.validate_network()?;
        let http = self.inner.http.as_ref().ok_or_else(|| {
            Error::Configuration("secure HTTP client initialization failed".into())
        })?;
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
        if json_body
            .as_ref()
            .map(serde_json::to_vec)
            .transpose()?
            .is_some_and(|bytes| bytes.len() > MAX_API_REQUEST_BYTES)
        {
            return Err(Error::Configuration(
                "API request exceeds the supported size".into(),
            ));
        }

        // Retry logic - rebuild request for each attempt (reqwest bodies can't always be cloned)
        let mut last_error = None;
        for attempt in 0..=self.inner.config.max_retries {
            if attempt > 0 {
                let multiplier = 1u32.checked_shl(attempt - 1).unwrap_or(u32::MAX);
                let delay = self
                    .inner
                    .config
                    .retry_delay
                    .checked_mul(multiplier)
                    .unwrap_or(Duration::from_secs(60))
                    .min(Duration::from_secs(60));
                tokio::time::sleep(delay).await;
                debug!("Retry attempt {} for {}", attempt, path);
            }

            // Build fresh request for each attempt
            debug!("Building request for {path} (attempt {attempt})");
            let mut request = http.request(method.clone(), url.clone());
            if let Some(ref body) = json_body {
                request = request.json(body);
            }

            match request.send().await {
                Ok(response) => {
                    let status = response.status().as_u16();
                    debug!("Received response for {path} with status {status}");
                    let response_body = read_response_limited(response).await?;

                    if (200..300).contains(&status) {
                        return crate::strict_json::from_slice(&response_body).map_err(Error::from);
                    }

                    let error_body = String::from_utf8_lossy(&response_body);
                    let (code, message, details) = parse_error_response_text(&error_body);

                    let error = Error::api(status, code, message, details);

                    // Don't retry business logic errors
                    if error.is_business_error() {
                        return Err(error);
                    }
                    if !error.is_network_error() && status != 429 {
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

        Err(last_error.unwrap_or_else(|| Error::Configuration("request did not execute".into())))
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

fn build_http_client(config: &Config) -> Option<reqwest::Client> {
    let mut headers = HeaderMap::new();

    headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    headers.insert(ACCEPT, HeaderValue::from_static("application/json"));
    headers.insert(
        USER_AGENT,
        HeaderValue::from_static(concat!("licenseseat-rust/", env!("CARGO_PKG_VERSION"))),
    );

    if !config.api_key.is_empty() {
        if let Ok(value) = HeaderValue::from_str(&format!("Bearer {}", config.api_key)) {
            headers.insert(AUTHORIZATION, value);
        }
    }

    let allow_invalid_loopback_certificate = !config.verify_ssl
        && url::Url::parse(&config.api_base_url)
            .ok()
            .and_then(|url| url.host_str().map(crate::config::is_loopback_host))
            .unwrap_or(false);

    let builder = reqwest::Client::builder()
        .default_headers(headers)
        .timeout(config.request_timeout)
        .redirect(reqwest::redirect::Policy::none());
    #[cfg(any(feature = "rustls", feature = "native-tls"))]
    let builder = builder.danger_accept_invalid_certs(allow_invalid_loopback_certificate);
    #[cfg(not(any(feature = "rustls", feature = "native-tls")))]
    let _ = allow_invalid_loopback_certificate;
    builder.build().ok()
}

async fn read_response_limited(mut response: reqwest::Response) -> Result<Vec<u8>> {
    if response
        .content_length()
        .is_some_and(|length| length > MAX_API_RESPONSE_BYTES as u64)
    {
        return Err(Error::Configuration(
            "API response exceeds the supported size".into(),
        ));
    }
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(Error::from)? {
        if body.len().saturating_add(chunk.len()) > MAX_API_RESPONSE_BYTES {
            return Err(Error::Configuration(
                "API response exceeds the supported size".into(),
            ));
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
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

    if let Ok(json) = crate::strict_json::parse(trimmed.as_bytes()) {
        return parse_error_response(&json);
    }

    (None, "Request failed".into(), None)
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
            let code = error
                .get("code")
                .and_then(|c| c.as_str())
                .and_then(sanitize_error_code);
            let message = error
                .get("detail")
                .or_else(|| error.get("title"))
                .and_then(|m| m.as_str())
                .and_then(sanitize_error_message)
                .unwrap_or_else(|| "Request failed".into());
            let details = error
                .iter()
                .filter(|(key, _)| !matches!(key.as_str(), "code" | "title" | "detail"))
                .map(|(key, value)| (key.clone(), value.clone()))
                .collect::<HashMap<_, _>>();
            return (code, message, sanitize_error_details(details));
        }
    }

    // Try new nested format: { "error": { "code": "...", "message": "...", "details": {...} } }
    if let Some(error) = body.get("error").and_then(|e| e.as_object()) {
        let code = error
            .get("code")
            .and_then(|c| c.as_str())
            .and_then(sanitize_error_code);
        let message = error
            .get("message")
            .and_then(|m| m.as_str())
            .and_then(sanitize_error_message)
            .unwrap_or_else(|| "Request failed".into());
        let details = error.get("details").and_then(|d| {
            d.as_object()
                .map(|obj| obj.iter().map(|(k, v)| (k.clone(), v.clone())).collect())
                .and_then(sanitize_error_details)
        });
        return (code, message, details);
    }

    // Fallback: flat format
    let code = body
        .get("code")
        .and_then(|c| c.as_str())
        .and_then(sanitize_error_code);
    let message = body
        .get("message")
        .and_then(|m| m.as_str())
        .and_then(sanitize_error_message)
        .unwrap_or_else(|| "Request failed".into());

    (code, message, None)
}

fn sanitize_error_code(value: &str) -> Option<String> {
    safe_error_code(value).then(|| value.to_string())
}

fn sanitize_error_message(value: &str) -> Option<String> {
    let value = value.trim();
    safe_text(value, 1, MAX_ERROR_MESSAGE_BYTES).then(|| value.to_string())
}

fn sanitize_error_details(
    details: HashMap<String, serde_json::Value>,
) -> Option<HashMap<String, serde_json::Value>> {
    if details.is_empty()
        || details.len() > 64
        || details.keys().any(|key| !safe_text(key, 1, 100))
        || serde_json::to_vec(&details)
            .map(|bytes| bytes.len() > MAX_ERROR_DETAILS_BYTES)
            .unwrap_or(true)
    {
        None
    } else {
        Some(details)
    }
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
fn build_offline_token_request(
    license_key: &str,
    fingerprint: &str,
    ttl_days: Option<i64>,
) -> serde_json::Value {
    let mut body = fingerprint_alias_payload(fingerprint, true);
    body["license_key"] = serde_json::json!(license_key);
    if let Some(ttl_days) = ttl_days {
        body["ttl_days"] = serde_json::json!(ttl_days);
    }
    body
}

#[cfg(feature = "offline")]
fn build_machine_file_request(
    license_key: &str,
    fingerprint: &str,
    ttl_days: Option<i64>,
    grace_period_days: Option<i64>,
    include_license: bool,
    fingerprint_components: &HashMap<String, String>,
) -> serde_json::Value {
    let mut body = fingerprint_alias_payload(fingerprint, true);
    body["license_key"] = serde_json::json!(license_key);
    if let Some(ttl_days) = ttl_days {
        body["ttl"] = serde_json::json!(ttl_days);
    }
    if let Some(grace_period_days) = grace_period_days {
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
    if path.is_empty()
        || !path.starts_with('/')
        || path.len() > 4_096
        || path.contains('\\')
        || path.contains('#')
        || path.bytes().any(|byte| byte.is_ascii_control())
    {
        return Err(Error::Configuration("API request path is invalid".into()));
    }
    let normalized_base = base_url.trim_end_matches('/');
    let normalized_path = path.trim_start_matches('/');
    let combined = if normalized_path.is_empty() {
        normalized_base.to_string()
    } else {
        format!("{normalized_base}/{normalized_path}")
    };

    let base = url::Url::parse(base_url)?;
    let combined = url::Url::parse(&combined)?;
    if base.scheme() != combined.scheme()
        || base.host_str() != combined.host_str()
        || base.port_or_known_default() != combined.port_or_known_default()
        || !combined.username().is_empty()
        || combined.password().is_some()
    {
        return Err(Error::Configuration(
            "API request URL escaped the configured origin".into(),
        ));
    }
    Ok(combined)
}

fn build_license_action_path(product_slug: &str, action: &str) -> String {
    build_path(&["products", product_slug, "licenses", action])
}

fn validate_license_key(license_key: &str) -> Result<()> {
    if license_key.is_empty()
        || license_key.len() > 512
        || license_key.bytes().any(|byte| byte.is_ascii_control())
    {
        return Err(Error::Configuration("license_key is invalid".into()));
    }
    Ok(())
}

fn validate_optional_text_input(
    value: Option<&str>,
    maximum_bytes: usize,
    name: &str,
) -> Result<()> {
    if value.is_some_and(|value| !safe_text(value, 1, maximum_bytes)) {
        return Err(Error::Configuration(format!("{name} is invalid")));
    }
    Ok(())
}

fn validate_metadata_input(
    metadata: Option<&HashMap<String, serde_json::Value>>,
    name: &str,
) -> Result<()> {
    if !metadata_within_limits(metadata) {
        return Err(Error::Configuration(format!("{name} is invalid")));
    }
    Ok(())
}

#[cfg(feature = "offline")]
fn validate_fingerprint_components(components: &HashMap<String, String>) -> Result<()> {
    if components.len() > 64
        || components
            .iter()
            .any(|(key, value)| !safe_text(key, 1, 100) || !safe_text(value, 1, 1_024))
        || serde_json::to_vec(components)
            .map(|bytes| bytes.len() > MAX_API_REQUEST_BYTES)
            .unwrap_or(true)
    {
        return Err(Error::Configuration(
            "fingerprint_components are invalid".into(),
        ));
    }
    Ok(())
}

fn valid_product_slug(product_slug: &str) -> bool {
    !product_slug.is_empty()
        && product_slug.len() <= 100
        && product_slug.bytes().enumerate().all(|(index, byte)| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || (byte == b'-' && index > 0 && index + 1 < product_slug.len())
        })
        && !product_slug.contains("--")
}

fn validate_product_slug_input(product_slug: &str) -> Result<()> {
    if !valid_product_slug(product_slug) {
        return Err(Error::Configuration("product_slug is invalid".into()));
    }
    Ok(())
}

fn validate_release_channel(channel: Option<&str>) -> Result<()> {
    if channel.is_some_and(|channel| !matches!(channel, "stable" | "beta" | "alpha")) {
        return Err(Error::Configuration("release channel is invalid".into()));
    }
    Ok(())
}

fn validate_release_platform(platform: Option<&str>) -> Result<()> {
    if platform.is_some_and(|platform| !matches!(platform, "macos" | "windows" | "linux" | "any")) {
        return Err(Error::Configuration("release platform is invalid".into()));
    }
    Ok(())
}

fn validate_release_version(version: &str) -> Result<()> {
    if !safe_text(version, 1, 255) {
        return Err(Error::Configuration("version is invalid".into()));
    }
    Ok(())
}

fn validate_cached_license_shape(license: &License) -> Result<()> {
    validate_license_key(&license.license_key)?;
    validate_fingerprint(&license.device_id)?;
    let now = Utc::now();
    let future_tolerance = chrono::Duration::minutes(5);
    if license.activation_id.is_empty()
        || license.activation_id.len() > 255
        || license
            .activation_id
            .bytes()
            .any(|byte| byte.is_ascii_control())
        || license.activated_at > now + future_tolerance
        || license.last_validated > now + future_tolerance
        || license.last_validated < license.activated_at
    {
        return Err(Error::Cache("cached license state is invalid".into()));
    }
    Ok(())
}

fn validate_fingerprint(fingerprint: &str) -> Result<()> {
    if !(8..=255).contains(&fingerprint.len())
        || fingerprint.bytes().any(|byte| byte.is_ascii_control())
    {
        return Err(Error::Configuration("fingerprint is invalid".into()));
    }
    Ok(())
}

#[cfg(feature = "offline")]
fn validate_ttl_days(ttl_days: Option<i64>) -> Result<()> {
    if ttl_days.is_some_and(|days| !(1..=36_600).contains(&days)) {
        return Err(Error::Configuration("ttl_days is invalid".into()));
    }
    Ok(())
}

#[cfg(feature = "offline")]
fn validate_grace_period_days(grace_period_days: Option<i64>) -> Result<()> {
    if grace_period_days.is_some_and(|days| !(0..=30).contains(&days)) {
        return Err(Error::Configuration("grace_period_days is invalid".into()));
    }
    Ok(())
}

fn license_response_is_currently_active(license: &LicenseResponse) -> bool {
    let now = Utc::now();
    license.status == "active"
        && license.starts_at.is_none_or(|starts_at| starts_at <= now)
        && license.expires_at.is_none_or(|expires_at| expires_at > now)
}

#[cfg(feature = "offline")]
fn validate_key_id(key_id: &str) -> Result<()> {
    if key_id.is_empty()
        || key_id.len() > 255
        || !key_id.bytes().enumerate().all(|(index, byte)| {
            byte.is_ascii_alphanumeric() || (index > 0 && matches!(byte, b'-' | b'_' | b'.' | b':'))
        })
    {
        return Err(Error::Configuration("key_id is invalid".into()));
    }
    Ok(())
}

#[cfg(feature = "offline")]
fn signing_key_record(key_id: &str, public_key: &str) -> SigningKeyResponse {
    SigningKeyResponse {
        object: "signing_key".into(),
        key_id: key_id.to_string(),
        algorithm: "Ed25519".into(),
        public_key: public_key.to_string(),
        created_at: None,
        status: "active".into(),
    }
}

fn validate_license_response_identity(
    license: &LicenseResponse,
    expected_license_key: &str,
    expected_product_slug: &str,
) -> Result<()> {
    let mut entitlement_keys = std::collections::HashSet::new();
    if license.object != "license"
        || !constant_time_equal(&license.key, expected_license_key)
        || license.product.slug != expected_product_slug
        || !valid_product_slug(&license.product.slug)
        || !safe_text(&license.product.name, 1, 255)
        || !matches!(
            license.status.as_str(),
            "pending" | "active" | "suspended" | "revoked" | "expired"
        )
        || !matches!(
            license.mode.as_str(),
            "hardware_locked" | "floating" | "named_user"
        )
        || !safe_text(&license.plan_key, 1, 100)
        || license.seat_limit == Some(0)
        || license
            .starts_at
            .zip(license.expires_at)
            .is_some_and(|(starts_at, expires_at)| starts_at >= expires_at)
        || !metadata_within_limits(license.metadata.as_ref())
        || license.active_entitlements.len() > 500
        || license.active_entitlements.iter().any(|entitlement| {
            !safe_identifier(&entitlement.key, 100)
                || !entitlement_keys.insert(entitlement.key.as_str())
                || !metadata_within_limits(entitlement.metadata.as_ref())
        })
    {
        return Err(Error::InvalidResponse(
            "license identity or schema is invalid".into(),
        ));
    }
    Ok(())
}

fn validate_activation_response(
    activation: &ActivationResponse,
    expected_license_key: &str,
    expected_fingerprint: &str,
    expected_product_slug: &str,
) -> Result<()> {
    let now = Utc::now();
    if activation.object != "activation"
        || !constant_time_equal(&activation.license_key, expected_license_key)
        || !constant_time_equal(&activation.device_id, expected_fingerprint)
        || !safe_text(&activation.id, 1, 255)
        || activation.activated_at > now + chrono::Duration::minutes(5)
        || activation.deactivated_at.is_some()
        || activation
            .device_name
            .as_deref()
            .is_some_and(|value| !safe_text(value, 1, 255))
        || activation
            .ip_address
            .as_deref()
            .is_some_and(|value| value.parse::<std::net::IpAddr>().is_err())
        || !metadata_within_limits(activation.metadata.as_ref())
    {
        return Err(Error::InvalidResponse(
            "activation response identity or schema is invalid".into(),
        ));
    }
    validate_license_response_identity(
        &activation.license,
        expected_license_key,
        expected_product_slug,
    )?;
    if !license_response_is_currently_active(&activation.license) {
        return Err(Error::InvalidResponse(
            "activation response contained an inactive license".into(),
        ));
    }
    Ok(())
}

fn validate_validation_response(
    result: &ValidationResult,
    expected_license_key: &str,
    expected_fingerprint: &str,
    expected_product_slug: &str,
) -> Result<()> {
    if result.object != "validation_result"
        || result
            .code
            .as_deref()
            .is_some_and(|value| !safe_error_code(value))
        || result
            .message
            .as_deref()
            .is_some_and(|value| !safe_text(value, 1, MAX_ERROR_MESSAGE_BYTES))
        || result.warnings.as_ref().is_some_and(|warnings| {
            warnings.len() > 32
                || warnings.iter().any(|warning| {
                    !safe_error_code(&warning.code)
                        || !safe_text(&warning.message, 1, MAX_ERROR_MESSAGE_BYTES)
                })
        })
    {
        return Err(Error::InvalidResponse(
            "validation response schema is invalid".into(),
        ));
    }

    validate_license_response_identity(
        &result.license,
        expected_license_key,
        expected_product_slug,
    )?;
    if result.valid && !license_response_is_currently_active(&result.license) {
        return Err(Error::InvalidResponse(
            "valid validation response contained an inactive license".into(),
        ));
    }

    let validate_activation = |activation: &ActivationNested| {
        let now = Utc::now();
        (activation.object.is_empty() || activation.object == "activation")
            && safe_text(&activation.id, 1, 255)
            && constant_time_equal(&activation.license_key, expected_license_key)
            && constant_time_equal(&activation.device_id, expected_fingerprint)
            && activation.activated_at <= now + chrono::Duration::minutes(5)
            && (!result.valid || activation.deactivated_at.is_none())
            && activation
                .device_name
                .as_deref()
                .is_none_or(|value| safe_text(value, 1, 255))
            && activation
                .ip_address
                .as_deref()
                .is_none_or(|value| value.parse::<std::net::IpAddr>().is_ok())
            && metadata_within_limits(activation.metadata.as_ref())
    };
    if result.activation.as_ref().is_none_or(validate_activation)
        && (!result.valid || result.activation.is_some())
    {
        Ok(())
    } else {
        Err(Error::InvalidResponse(
            "validation activation identity or schema is invalid".into(),
        ))
    }
}

fn validate_deactivation_response(
    response: &DeactivationResponse,
    expected_activation_id: Option<&str>,
) -> Result<()> {
    if response.object != "deactivation"
        || !safe_text(&response.activation_id, 1, 255)
        || expected_activation_id
            .is_some_and(|expected| !constant_time_equal(&response.activation_id, expected))
        || response.deactivated_at > Utc::now() + chrono::Duration::minutes(5)
    {
        return Err(Error::InvalidResponse(
            "deactivation response identity or schema is invalid".into(),
        ));
    }
    Ok(())
}

fn validate_heartbeat_response(
    response: &HeartbeatResponse,
    expected_license_key: &str,
    expected_product_slug: &str,
) -> Result<()> {
    if response.object != "heartbeat"
        || response.received_at > Utc::now() + chrono::Duration::minutes(5)
    {
        return Err(Error::InvalidResponse(
            "heartbeat response schema is invalid".into(),
        ));
    }
    validate_license_response_identity(
        &response.license,
        expected_license_key,
        expected_product_slug,
    )?;
    if !license_response_is_currently_active(&response.license) {
        return Err(Error::InvalidResponse(
            "heartbeat response contained an inactive license".into(),
        ));
    }
    Ok(())
}

fn validate_health_response(response: &HealthResponse) -> Result<()> {
    if response.object != "health"
        || response.status != "healthy"
        || !safe_text(&response.api_version, 1, 100)
        || response.timestamp > Utc::now() + chrono::Duration::minutes(5)
    {
        return Err(Error::InvalidResponse(
            "health response schema is invalid".into(),
        ));
    }
    Ok(())
}

fn validate_release_response(release: &Release, expected_product_slug: &str) -> Result<()> {
    if release.object != "release"
        || !safe_text(&release.version, 1, 255)
        || !matches!(release.channel.as_str(), "stable" | "beta" | "alpha")
        || !matches!(
            release.platform.as_str(),
            "macos" | "windows" | "linux" | "any"
        )
        || release.product_slug != expected_product_slug
        || release.published_at.is_none()
        || release
            .published_at
            .is_some_and(|published_at| published_at > Utc::now() + chrono::Duration::minutes(5))
    {
        return Err(Error::InvalidResponse(
            "release response identity or schema is invalid".into(),
        ));
    }
    Ok(())
}

fn validate_release_list_response(
    releases: &ReleaseList,
    expected_product_slug: &str,
) -> Result<()> {
    if releases.object != "list"
        || releases.data.len() > 100
        || releases
            .next_cursor
            .as_deref()
            .is_some_and(|cursor| !safe_text(cursor, 1, 1_024))
    {
        return Err(Error::InvalidResponse(
            "release list response schema is invalid".into(),
        ));
    }
    for release in &releases.data {
        validate_release_response(release, expected_product_slug)?;
    }
    Ok(())
}

fn validate_download_token_response(token: &DownloadToken) -> Result<()> {
    let now = Utc::now();
    if token.object != "download_token"
        || !safe_text(&token.token, 16, 32 * 1024)
        || token.expires_at.is_none_or(|expires_at| {
            expires_at <= now || expires_at > now + chrono::Duration::days(30)
        })
    {
        return Err(Error::InvalidResponse(
            "download-token response schema is invalid".into(),
        ));
    }
    Ok(())
}

fn safe_text(value: &str, minimum_bytes: usize, maximum_bytes: usize) -> bool {
    (minimum_bytes..=maximum_bytes).contains(&value.len())
        && !value.bytes().any(|byte| byte.is_ascii_control())
}

fn safe_identifier(value: &str, maximum_bytes: usize) -> bool {
    safe_text(value, 1, maximum_bytes)
        && value.bytes().enumerate().all(|(index, byte)| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || (index > 0 && matches!(byte, b'-' | b'_'))
        })
}

fn safe_error_code(value: &str) -> bool {
    safe_text(value, 1, 100)
        && value.bytes().enumerate().all(|(index, byte)| {
            byte.is_ascii_alphanumeric() || (index > 0 && matches!(byte, b'-' | b'_' | b'.' | b':'))
        })
}

fn metadata_within_limits(metadata: Option<&HashMap<String, serde_json::Value>>) -> bool {
    let Some(metadata) = metadata else {
        return true;
    };
    if metadata.len() > MAX_JSON_NODES
        || serde_json::to_vec(metadata)
            .map(|bytes| bytes.len() > MAX_RESPONSE_METADATA_BYTES)
            .unwrap_or(true)
    {
        return false;
    }
    let mut nodes = 0;
    json_object_within_limits(metadata, 0, &mut nodes)
}

#[cfg(feature = "offline")]
fn json_map_contains_only(
    object: &serde_json::Map<String, serde_json::Value>,
    allowed: &[&str],
) -> bool {
    object.keys().all(|key| allowed.contains(&key.as_str()))
}

fn json_object_within_limits(
    object: &HashMap<String, serde_json::Value>,
    depth: usize,
    nodes: &mut usize,
) -> bool {
    if depth > MAX_JSON_DEPTH {
        return false;
    }
    object.iter().all(|(key, value)| {
        safe_text(key, 0, 256) && json_value_within_limits(value, depth + 1, nodes)
    })
}

fn json_value_within_limits(value: &serde_json::Value, depth: usize, nodes: &mut usize) -> bool {
    *nodes = nodes.saturating_add(1);
    if *nodes > MAX_JSON_NODES || depth > MAX_JSON_DEPTH {
        return false;
    }
    match value {
        serde_json::Value::Null | serde_json::Value::Bool(_) | serde_json::Value::Number(_) => true,
        serde_json::Value::String(value) => value.len() <= 64 * 1024,
        serde_json::Value::Array(values) => values
            .iter()
            .all(|value| json_value_within_limits(value, depth + 1, nodes)),
        serde_json::Value::Object(object) => object.iter().all(|(key, value)| {
            safe_text(key, 0, 256) && json_value_within_limits(value, depth + 1, nodes)
        }),
    }
}

fn constant_time_equal(left: &str, right: &str) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.bytes()
        .zip(right.bytes())
        .fold(0u8, |difference, (left, right)| difference | (left ^ right))
        == 0
}

fn build_path(segments: &[&str]) -> String {
    let Ok(mut url) = url::Url::parse("https://licenseseat.invalid") else {
        return String::new();
    };
    {
        let Ok(mut path_segments) = url.path_segments_mut() else {
            return String::new();
        };
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

fn resolve_fingerprint_alias<'a>(
    fingerprint: Option<&'a str>,
    device_id: Option<&'a str>,
    device_fingerprint: Option<&'a str>,
) -> Result<Option<&'a str>> {
    let values = [fingerprint, device_id, device_fingerprint]
        .into_iter()
        .flatten()
        .filter(|value| !value.is_empty())
        .collect::<Vec<_>>();
    let Some(first) = values.first().copied() else {
        return Ok(None);
    };
    if values.iter().any(|value| *value != first) {
        return Err(Error::Configuration(
            "conflicting fingerprint aliases were provided".into(),
        ));
    }
    Ok(Some(first))
}

#[cfg(feature = "offline")]
fn parse_machine_file_response(body: &serde_json::Value) -> Result<MachineFile> {
    let root = body
        .as_object()
        .filter(|root| json_map_contains_only(root, &["data"]))
        .ok_or_else(|| Error::InvalidResponse("machine-file response is invalid".into()))?;
    let data = root
        .get("data")
        .and_then(serde_json::Value::as_object)
        .filter(|data| json_map_contains_only(data, &["type", "attributes", "relationships"]))
        .ok_or_else(|| Error::InvalidResponse("machine-file response is invalid".into()))?;
    if data.get("type").and_then(serde_json::Value::as_str) != Some("machine-files") {
        return Err(Error::InvalidResponse(
            "machine-file response object type is invalid".into(),
        ));
    }
    let attributes = data
        .get("attributes")
        .and_then(|value| value.as_object())
        .filter(|attributes| {
            json_map_contains_only(
                attributes,
                &["certificate", "algorithm", "ttl", "issued", "expiry"],
            )
        })
        .ok_or_else(|| Error::InvalidResponse("machine-file response is invalid".into()))?;

    let relationships = data
        .get("relationships")
        .and_then(|value| value.as_object())
        .filter(|relationships| json_map_contains_only(relationships, &["license", "machine"]))
        .ok_or_else(|| Error::InvalidResponse("machine-file relationships are invalid".into()))?;

    let certificate = attributes
        .get("certificate")
        .and_then(serde_json::Value::as_str)
        .filter(|value| !value.is_empty() && value.len() <= 1024 * 1024)
        .ok_or_else(|| Error::InvalidResponse("machine-file certificate is invalid".into()))?;
    let algorithm = attributes
        .get("algorithm")
        .and_then(serde_json::Value::as_str)
        .filter(|value| *value == "aes-256-gcm+ed25519")
        .ok_or_else(|| Error::InvalidResponse("machine-file algorithm is invalid".into()))?;
    let ttl = attributes
        .get("ttl")
        .and_then(serde_json::Value::as_i64)
        .filter(|value| (1..=MAX_MACHINE_FILE_TTL_SECONDS).contains(value))
        .ok_or_else(|| Error::InvalidResponse("machine-file lifetime is invalid".into()))?;
    let issued_at = attributes
        .get("issued")
        .and_then(serde_json::Value::as_str)
        .and_then(parse_rfc3339)
        .ok_or_else(|| Error::InvalidResponse("machine-file issued time is invalid".into()))?;
    let expires_at = attributes
        .get("expiry")
        .and_then(serde_json::Value::as_str)
        .and_then(parse_rfc3339)
        .ok_or_else(|| Error::InvalidResponse("machine-file expiry is invalid".into()))?;
    if expires_at
        .signed_duration_since(issued_at)
        .num_seconds()
        .abs_diff(ttl)
        > 2
    {
        return Err(Error::InvalidResponse(
            "machine-file lifetime claims are inconsistent".into(),
        ));
    }

    let relationship_id = |name: &str, expected_type: &str| {
        relationships
            .get(name)
            .and_then(serde_json::Value::as_object)
            .filter(|wrapper| json_map_contains_only(wrapper, &["data"]))
            .and_then(|wrapper| wrapper.get("data"))
            .and_then(serde_json::Value::as_object)
            .filter(|relationship| {
                json_map_contains_only(relationship, &["type", "id"])
                    && relationship.get("type").and_then(serde_json::Value::as_str)
                        == Some(expected_type)
            })
            .and_then(|relationship| relationship.get("id"))
            .and_then(serde_json::Value::as_str)
            .filter(|value| {
                if name == "license" {
                    safe_text(value, 1, 512)
                } else {
                    safe_text(value, 8, 255)
                }
            })
            .map(ToString::to_string)
            .ok_or_else(|| {
                Error::InvalidResponse(format!("machine-file {name} relationship is invalid"))
            })
    };

    Ok(MachineFile {
        certificate: certificate.to_string(),
        algorithm: algorithm.to_string(),
        ttl,
        issued_at: Some(issued_at),
        expires_at: Some(expires_at),
        license_key: relationship_id("license", "licenses")?,
        fingerprint: relationship_id("machine", "machines")?,
    })
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
            status: 401 | 403,
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

#[cfg(feature = "offline")]
fn parse_rfc3339(value: &str) -> Option<chrono::DateTime<chrono::Utc>> {
    chrono::DateTime::parse_from_rfc3339(value)
        .ok()
        .map(|value| value.with_timezone(&chrono::Utc))
}
