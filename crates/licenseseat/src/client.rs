//! Main LicenseSeat client implementation.

use crate::cache::LicenseCache;
use crate::config::{Config, OfflineFallbackMode};
use crate::error::{Error, Result};
use crate::events::{Event, EventKind};
use crate::models::*;
use crate::telemetry::Telemetry;

use chrono::Utc;
use reqwest::header::{AUTHORIZATION, CONTENT_TYPE, HeaderMap, HeaderValue, USER_AGENT};
use serde::de::DeserializeOwned;
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, Instant};
use tokio::sync::{Mutex as AsyncMutex, broadcast, watch};
use tracing::{debug, warn};

#[cfg(feature = "offline")]
use crate::device::collect_fingerprint_components;

const MAX_RESPONSE_BODY_BYTES: usize = 4 * 1024 * 1024;
const MAX_REQUEST_BODY_BYTES: usize = 1024 * 1024;
const MAX_API_ERROR_MESSAGE_CHARS: usize = 4096;

/// The main LicenseSeat SDK client.
///
/// This is the primary interface for interacting with the LicenseSeat API.
/// Create an instance with [`LicenseSeat::try_new`] and use it to activate,
/// validate, and manage licenses.
///
/// # Example
///
/// ```rust,no_run
/// use licenseseat::{LicenseSeat, Config};
///
/// #[tokio::main]
/// async fn main() -> licenseseat::Result<()> {
///     let sdk = LicenseSeat::try_new(Config::new("api-key", "product-slug"))?;
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
    state_commit_lock: Mutex<()>,
    operation_sequence: AtomicU64,
    current_license_state_operation: AtomicU64,
    current_activation_operation: AtomicU64,
    current_deactivation_operation: AtomicU64,
    current_validation_operation: AtomicU64,
    current_heartbeat_operation: AtomicU64,
    current_offline_sync_operation: AtomicU64,
    restore_lock: AsyncMutex<()>,
    #[cfg(feature = "offline")]
    offline_request_lock: AsyncMutex<()>,
    #[cfg(feature = "offline")]
    runtime_signing_keys: Mutex<HashMap<String, String>>,
    runtime_license_state: Mutex<Option<RuntimeLicenseState>>,
    is_online: AtomicBool,
    /// Flag to stop support/background tasks.
    background_tasks_running: AtomicBool,
    support_tasks_generation: AtomicU64,
    support_tasks_cancel: Mutex<Option<watch::Sender<()>>>,
    auto_validation_running: AtomicBool,
    auto_validation_generation: AtomicU64,
    auto_validation_cancel: Mutex<Option<watch::Sender<()>>>,
    heartbeat_running: AtomicBool,
    heartbeat_generation: AtomicU64,
    heartbeat_cancel: Mutex<Option<watch::Sender<()>>>,
    last_heartbeat: Mutex<Option<HeartbeatResponse>>,
    last_heartbeat_error: Mutex<Option<String>>,
    last_health: Mutex<Option<HealthResponse>>,
    last_health_error: Mutex<Option<String>>,
    next_auto_validation_at: Mutex<Option<chrono::DateTime<Utc>>>,
}

#[derive(Clone)]
struct RuntimeLicenseState {
    license: License,
    source: TrustedLicenseSource,
    /// Signed offline authorization deadline. Online responses and denials use
    /// the license response's own time/status contract instead.
    authorization_expires_at: Option<i64>,
    /// Wall-clock anchor paired with a monotonic process clock. Authorization
    /// time never moves backwards while the process remains alive, even if the
    /// system clock is rolled back after offline verification.
    observed_wall_time: i64,
    observed_monotonic: Instant,
    /// Greatest effective authorization timestamp observed in this process.
    /// This closes the forward-then-backward clock sequence that a fixed
    /// monotonic floor alone cannot detect.
    last_effective_timestamp: i64,
    /// Next active-entitlement expiry that should notify state subscribers.
    next_entitlement_transition_at: Option<i64>,
}

impl RuntimeLicenseState {
    fn effective_now(&self) -> chrono::DateTime<Utc> {
        let wall_now = Utc::now();
        let elapsed =
            i64::try_from(self.observed_monotonic.elapsed().as_secs()).unwrap_or(i64::MAX);
        let effective_timestamp = effective_runtime_timestamp(
            wall_now.timestamp(),
            self.observed_wall_time,
            elapsed,
            self.last_effective_timestamp,
        );
        if effective_timestamp > wall_now.timestamp() {
            chrono::DateTime::from_timestamp(effective_timestamp, 0)
                .unwrap_or(chrono::DateTime::<Utc>::MAX_UTC)
        } else {
            wall_now
        }
    }

    fn observe_effective_now(&mut self) -> chrono::DateTime<Utc> {
        let now = self.effective_now();
        self.last_effective_timestamp = now.timestamp();
        now
    }
}

struct OperationGuard<'a> {
    slot: &'a AtomicU64,
    id: u64,
}

impl<'a> OperationGuard<'a> {
    fn new(slot: &'a AtomicU64, id: u64) -> Self {
        Self { slot, id }
    }
}

impl Drop for OperationGuard<'_> {
    fn drop(&mut self) {
        let _ = self
            .slot
            .compare_exchange(self.id, 0, Ordering::SeqCst, Ordering::SeqCst);
    }
}

impl LicenseSeat {
    /// Create an SDK instance, panicking if configuration or durable storage
    /// cannot be initialized.
    ///
    /// This convenience constructor never bypasses the same security and
    /// persistence checks enforced by [`Self::try_new`]. Production
    /// applications should normally use [`Self::try_new`] so they can present
    /// an actionable startup error instead of terminating.
    ///
    /// # Panics
    ///
    /// Panics when [`Self::try_new`] returns an initialization error.
    #[track_caller]
    pub fn new(config: Config) -> Self {
        Self::try_new(config).unwrap_or_else(|error| {
            panic!(
                "LicenseSeat initialization failed: {error}; use LicenseSeat::try_new to handle this error"
            )
        })
    }

    /// Create a new SDK instance and report persistent-storage failures instead
    /// of falling back to the legacy hardware-derived identifier.
    ///
    /// Production desktop applications should prefer this constructor so a
    /// storage outage cannot silently rotate the installation identity.
    pub fn try_new(mut config: Config) -> Result<Self> {
        validate_api_base_url(&config.api_base_url, config.verify_ssl)?;
        #[cfg(not(any(feature = "rustls", feature = "native-tls")))]
        if url::Url::parse(&config.api_base_url).is_ok_and(|url| url.scheme() == "https") {
            return Err(Error::Configuration(
                "HTTPS requires either the rustls or native-tls Cargo feature".into(),
            ));
        }
        if config.request_timeout.is_zero() {
            return Err(Error::Configuration(
                "request_timeout must be greater than zero".into(),
            ));
        }
        if !config.api_key.is_empty()
            && (config.api_key.len() > 4096
                || config.api_key.trim() != config.api_key
                || HeaderValue::from_str(&format!("Bearer {}", config.api_key)).is_err())
        {
            return Err(Error::Configuration(
                "api_key contains characters that cannot be sent in an HTTP header".into(),
            ));
        }
        if config.api_key.starts_with("sk_") {
            return Err(Error::Configuration(
                "secret sk_* API keys must never be embedded in a client SDK; use a publishable pk_* key"
                    .into(),
            ));
        }
        if config.max_retries > 10 {
            return Err(Error::Configuration("max_retries may not exceed 10".into()));
        }
        if !config.product_slug.is_empty()
            && (config.product_slug.len() > 255
                || config.product_slug.trim() != config.product_slug
                || config.product_slug.chars().any(char::is_control))
        {
            return Err(Error::Configuration(
                "product_slug may not contain surrounding whitespace or control characters".into(),
            ));
        }
        if config
            .storage_path
            .as_ref()
            .is_some_and(|path| path.as_os_str().is_empty())
        {
            return Err(Error::Configuration("storage_path may not be empty".into()));
        }
        if config
            .device_identifier
            .as_deref()
            .is_some_and(|value| !is_valid_fingerprint(value))
        {
            return Err(Error::Configuration(
                "device_identifier must be 8-255 non-control characters without surrounding whitespace"
                    .into(),
            ));
        }
        if config.signing_key_id.as_ref().is_some_and(|value| {
            value.trim().is_empty()
                || value.trim() != value
                || value.len() > 255
                || value.chars().any(char::is_control)
        }) {
            return Err(Error::Configuration(
                "signing_key_id must be 1-255 non-control characters without surrounding whitespace"
                    .into(),
            ));
        }
        if config.signing_public_key.is_some() != config.signing_key_id.is_some() {
            return Err(Error::Configuration(
                "signing_public_key and signing_key_id must be configured together".into(),
            ));
        }
        #[cfg(feature = "offline")]
        if let (Some(public_key), Some(key_id)) = (
            config.signing_public_key.as_ref(),
            config.signing_key_id.as_ref(),
        ) {
            crate::offline::validate_signing_key(
                &SigningKeyResponse {
                    object: "signing_key".into(),
                    key_id: key_id.clone(),
                    algorithm: "Ed25519".into(),
                    public_key: public_key.clone(),
                    created_at: None,
                    status: "active".into(),
                },
                key_id,
            )?;
        }
        let configured_prefix = LicenseCache::normalized_prefix(&config.storage_prefix);
        let effective_prefix = LicenseCache::normalized_prefix(&effective_storage_prefix(&config));
        let cache = LicenseCache::new(&effective_prefix, config.storage_path.clone());
        cache.initialize()?;
        let mut startup_license = cache.get_license_for_initialization()?;
        if effective_prefix != configured_prefix && startup_license.is_none() {
            let legacy_cache = LicenseCache::new(&configured_prefix, config.storage_path.clone());
            if legacy_cache
                .get_license_for_initialization()?
                .as_ref()
                .is_some_and(|license| {
                    cached_license_matches_product(license, &config.product_slug)
                })
            {
                cache.migrate_from(&legacy_cache)?;
                startup_license = cache.get_license_for_initialization()?;
            }
        }
        config.storage_prefix = effective_prefix;
        let fingerprint = config
            .device_identifier
            .as_deref()
            .filter(|value| !value.is_empty())
            .map(ToString::to_string)
            .map(Ok)
            .unwrap_or_else(|| {
                let legacy_identifier = startup_license.map(|license| license.device_id);
                cache.get_or_create_installation_identifier(legacy_identifier.as_deref())
            })?;
        Self::build_with_cache(config, fingerprint, cache)
    }

    fn build_with_cache(config: Config, fingerprint: String, cache: LicenseCache) -> Result<Self> {
        let http = build_http_client(&config)?;
        let (event_tx, _) = broadcast::channel(64);

        let inner = Arc::new(LicenseSeatInner {
            config,
            http,
            cache,
            event_tx,
            fingerprint,
            state_commit_lock: Mutex::new(()),
            operation_sequence: AtomicU64::new(0),
            current_license_state_operation: AtomicU64::new(0),
            current_activation_operation: AtomicU64::new(0),
            current_deactivation_operation: AtomicU64::new(0),
            current_validation_operation: AtomicU64::new(0),
            current_heartbeat_operation: AtomicU64::new(0),
            current_offline_sync_operation: AtomicU64::new(0),
            restore_lock: AsyncMutex::new(()),
            #[cfg(feature = "offline")]
            offline_request_lock: AsyncMutex::new(()),
            #[cfg(feature = "offline")]
            runtime_signing_keys: Mutex::new(HashMap::new()),
            // Persisted online validation is unsigned cache data. Only this
            // process-local snapshot may drive status and entitlement grants.
            runtime_license_state: Mutex::new(None),
            // Reachability is unknown until this process completes an API
            // request. An optimistic `true` is misleading during startup.
            is_online: AtomicBool::new(false),
            background_tasks_running: AtomicBool::new(false),
            support_tasks_generation: AtomicU64::new(0),
            support_tasks_cancel: Mutex::new(None),
            auto_validation_running: AtomicBool::new(false),
            auto_validation_generation: AtomicU64::new(0),
            auto_validation_cancel: Mutex::new(None),
            heartbeat_running: AtomicBool::new(false),
            heartbeat_generation: AtomicU64::new(0),
            heartbeat_cancel: Mutex::new(None),
            last_heartbeat: Mutex::new(None),
            last_heartbeat_error: Mutex::new(None),
            last_health: Mutex::new(None),
            last_health_error: Mutex::new(None),
            next_auto_validation_at: Mutex::new(None),
        });

        let sdk = Self { inner };

        // Check for cached license on startup
        if let Some(license) = sdk.inner.cache.get_license() {
            debug!("Loaded cached LicenseSeat state");
            sdk.emit(Event::with_license(
                EventKind::LicenseLoaded,
                license.clone(),
            ));

            // A cached record is not an authoritative grant. The host must call
            // `restore_license()` before background networking is started.
        }

        Ok(sdk)
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
        self.require_api_key()?;
        validate_request_identifier("license_key", license_key)?;
        let operation = self.begin_license_operation(&self.inner.current_activation_operation);
        let _operation_guard =
            OperationGuard::new(&self.inner.current_activation_operation, operation);
        let device_id = select_fingerprint_alias(
            options.fingerprint.as_deref(),
            options.device_id.as_deref(),
            options.device_fingerprint.as_deref(),
        )?
        .map(ToString::to_string)
        .unwrap_or_else(|| self.inner.fingerprint.clone());
        validate_fingerprint(&device_id)?;
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

        let outcome = match self.post::<ActivationResponse>(&path, Some(body)).await {
            Ok(activation) => (|| -> Result<(License, Vec<String>)> {
                let _state_guard = self.lock_state_for_commit();
                self.ensure_current_license_operation(
                    &self.inner.current_activation_operation,
                    operation,
                    "activation",
                )?;
                verify_activation_response(&activation, license_key, product_slug, &device_id)?;

                let observed_at = Utc::now();
                let validation = ValidationResult {
                    object: "validation_result".into(),
                    valid: true,
                    code: None,
                    message: None,
                    warnings: None,
                    license: activation.license.clone(),
                    activation: None,
                    offline: false,
                };

                let license = License {
                    license_key: license_key.to_string(),
                    device_id,
                    activation_id: activation.id,
                    activated_at: activation.activated_at,
                    last_validated: observed_at,
                    trusted_license: Some(activation.license.clone()),
                    validation: Some(validation),
                };

                let cache_warnings = self
                    .inner
                    .cache
                    .commit_activation(&license, observed_at.timestamp())?;
                self.invalidate_license_operations_except_activation(operation);
                self.stop_background_tasks();
                self.set_runtime_license_state(
                    license.clone(),
                    TrustedLicenseSource::OnlineResponse,
                );
                Ok((license, cache_warnings))
            })(),
            Err(error) => Err(error),
        };

        match &outcome {
            Ok((license, cache_warnings)) => {
                self.emit(Event::with_license(
                    EventKind::ActivationSuccess,
                    license.clone(),
                ));

                for warning in cache_warnings {
                    self.emit(Event::with_error(EventKind::SdkError, warning.clone()));
                    warn!("License activation cache cleanup reported a diagnostic warning");
                }

                self.start_background_tasks();

                #[cfg(feature = "offline")]
                {
                    let sdk = self.clone();
                    tokio::spawn(async move {
                        if let Err(error) = sdk.sync_offline_assets().await {
                            warn!(
                                "Failed to sync offline assets: {}",
                                error.redacted_log_summary()
                            );
                        }
                    });
                }

                debug!("License activated successfully");
            }
            Err(error) => self.emit(Event::with_error(
                EventKind::ActivationError,
                error.to_string(),
            )),
        }
        let _ = self.inner.current_activation_operation.compare_exchange(
            operation,
            0,
            Ordering::SeqCst,
            Ordering::SeqCst,
        );
        outcome.map(|(license, _)| license)
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
        self.require_product_slug()?;
        self.require_api_key()?;
        validate_request_identifier("license_key", license_key)?;
        let (operation, cached_license) = self
            .begin_target_operation(&self.inner.current_validation_operation, |license| {
                license.license_key == license_key
            });
        let stateful = cached_license.is_some();
        let _operation_guard =
            OperationGuard::new(&self.inner.current_validation_operation, operation);
        let outcome = self
            .perform_validation_operation(license_key, operation, cached_license, stateful)
            .await;
        let _ = self.inner.current_validation_operation.compare_exchange(
            operation,
            0,
            Ordering::SeqCst,
            Ordering::SeqCst,
        );
        outcome
    }

    async fn perform_validation_operation(
        &self,
        license_key: &str,
        operation: u64,
        cached_license: Option<License>,
        stateful: bool,
    ) -> Result<ValidationResult> {
        let product_slug = self.require_product_slug()?;
        let cached_identity = cached_license.as_ref().map(License::identity);
        let device_id = cached_license
            .as_ref()
            .map(|license| license.device_id.clone())
            .unwrap_or_else(|| self.inner.fingerprint.clone());

        self.emit(Event::new(EventKind::ValidationStart));

        let path = build_license_action_path(product_slug, license_key, "validate");
        let body = Some(fingerprint_alias_payload(&device_id, false));

        let online_result = match self.post::<ValidationResult>(&path, body).await {
            Ok(mut result) => (|| -> Result<ValidationResult> {
                let _state_guard = self.lock_state_for_commit();
                self.ensure_current_target_operation(
                    &self.inner.current_validation_operation,
                    operation,
                    stateful,
                    "validation",
                )?;
                result.offline = false;
                verify_validation_response(
                    &result,
                    license_key,
                    product_slug,
                    Some(&device_id),
                    cached_identity.as_ref(),
                )?;
                let observed_at = Utc::now();
                if let Some(identity) = cached_identity.as_ref() {
                    if !self
                        .inner
                        .cache
                        .update_validation(identity, &result, observed_at)?
                    {
                        return Err(Error::OperationSuperseded {
                            operation: "validation",
                        });
                    }
                    let mut runtime_license = cached_license
                        .clone()
                        .expect("cached identity requires a cached license");
                    runtime_license.validation = Some(result.clone());
                    runtime_license.last_validated = observed_at;
                    runtime_license.trusted_license = result.valid.then(|| result.license.clone());
                    if !result.valid {
                        self.inner
                            .current_offline_sync_operation
                            .store(0, Ordering::SeqCst);
                        // Persist the authoritative denial before deleting any
                        // older signed grant. If deletion fails, the denial
                        // remains the fail-closed state observed on restart.
                        if let Err(error) = self.inner.cache.clear_offline_assets() {
                            self.emit(Event::with_error(EventKind::SdkError, error.to_string()));
                        }
                        self.stop_background_tasks();
                    }
                    self.set_runtime_license_state(
                        runtime_license,
                        TrustedLicenseSource::OnlineResponse,
                    );
                }
                if result.valid && stateful {
                    if let Err(error) = self
                        .inner
                        .cache
                        .set_last_seen_timestamp(observed_at.timestamp())
                    {
                        self.emit(Event::with_error(EventKind::SdkError, error.to_string()));
                        if let Err(cleanup_error) = self.inner.cache.clear_offline_assets() {
                            self.emit(Event::with_error(
                                EventKind::SdkError,
                                cleanup_error.to_string(),
                            ));
                        }
                    }
                }
                Ok(result)
            })(),
            Err(error) => Err(error),
        };

        match online_result {
            Ok(result) => {
                if stateful && is_revocation_code(result.code.as_deref()) {
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
                    warn!("License validation was not accepted");
                }

                Ok(result)
            }
            Err(e) => {
                let current_operation = {
                    let _state_guard = self.lock_state_for_commit();
                    self.ensure_current_target_operation(
                        &self.inner.current_validation_operation,
                        operation,
                        stateful,
                        "validation",
                    )
                };
                if let Err(superseded) = current_operation {
                    self.emit(Event::with_error(
                        EventKind::ValidationError,
                        superseded.to_string(),
                    ));
                    return Err(superseded);
                }
                if is_auth_failure_error(&e) {
                    self.emit(Event::with_error(
                        EventKind::ValidationAuthFailed,
                        e.to_string(),
                    ));
                }
                self.emit(Event::with_error(EventKind::ValidationError, e.to_string()));

                if is_authoritative_invalidation_error(&e) {
                    let _state_guard = self.lock_state_for_commit();
                    self.ensure_current_target_operation(
                        &self.inner.current_validation_operation,
                        operation,
                        stateful,
                        "validation",
                    )?;
                    if let Some(identity) = cached_identity.as_ref() {
                        self.invalidate_license_operations();
                        self.stop_background_tasks();
                        if let Err(cleanup_error) = self.clear_cached_license_with_denial(
                            identity,
                            e.code().unwrap_or("authoritative_invalidation"),
                            &e.to_string(),
                        ) {
                            self.emit(Event::with_error(
                                EventKind::SdkError,
                                cleanup_error.to_string(),
                            ));
                        }
                        self.emit(Event::with_error(EventKind::LicenseRevoked, e.to_string()));
                    }
                    return Err(e);
                }

                // Check for business logic errors (non-retriable)
                if e.is_business_error() {
                    return Err(e);
                }

                let should_fallback_offline = self.should_fallback_offline(&e);

                // A fallback grant must keep probing for authoritative online
                // state. This includes a reachable-but-rate-limited API, not
                // just transport and 5xx failures.
                if should_fallback_offline && stateful {
                    self.start_support_tasks();
                }

                // Try offline fallback for retryable availability failures.
                if should_fallback_offline {
                    #[cfg(feature = "offline")]
                    {
                        if let Some(identity) = cached_identity.as_ref() {
                            if self.inner.cache.matches_identity(identity) {
                                return self.validate_offline(identity).await;
                            }
                        }
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
        self.require_api_key()?;
        validate_request_identifier("license_key", license_key)?;
        if let Some(fingerprint) = fingerprint {
            validate_fingerprint(fingerprint)?;
        }

        let resolved_fingerprint = self.resolve_request_fingerprint(fingerprint);
        validate_fingerprint(&resolved_fingerprint)?;
        let (operation, cached_license) =
            self.begin_target_operation(&self.inner.current_deactivation_operation, |license| {
                license.license_key == license_key && license.device_id == resolved_fingerprint
            });
        let cached_identity = cached_license.as_ref().map(License::identity);
        let stateful = cached_identity.is_some();
        if cached_identity.is_some() {
            self.inner
                .current_activation_operation
                .store(0, Ordering::SeqCst);
        }
        let _operation_guard =
            OperationGuard::new(&self.inner.current_deactivation_operation, operation);

        self.emit(Event::new(EventKind::DeactivationStart));

        let path = build_license_action_path(product_slug, license_key, "deactivate");
        let body = fingerprint_alias_payload(&resolved_fingerprint, true);

        let outcome = match self.post::<DeactivationResponse>(&path, Some(body)).await {
            Ok(response) => (|| -> Result<()> {
                let _state_guard = self.lock_state_for_commit();
                self.ensure_current_target_operation(
                    &self.inner.current_deactivation_operation,
                    operation,
                    stateful,
                    "deactivation",
                )?;
                if response.object != "deactivation"
                    || response.activation_id.is_empty()
                    || cached_identity
                        .as_ref()
                        .is_some_and(|identity| response.activation_id != identity.activation_id)
                {
                    return Err(Error::ResponseMismatch(
                        "deactivation response did not match the active installation".into(),
                    ));
                }
                if let Some(identity) = cached_identity.as_ref() {
                    self.complete_local_deactivation(identity)?;
                }
                Ok(())
            })(),
            Err(error) => {
                // Treat certain errors as success (already deactivated, not found, etc.)
                let idempotent = if let Error::Api { status, code, .. } = &error {
                    let normalized_code = code.as_deref().map(str::to_ascii_lowercase);
                    match *status {
                        404 => normalized_code.as_deref().is_some_and(|code| {
                            matches!(
                                code,
                                "license_not_found"
                                    | "activation_not_found"
                                    | "already_deactivated"
                            )
                        }),
                        410 => true,
                        422 => normalized_code.as_deref().is_some_and(|code| {
                            matches!(
                                code,
                                "already_deactivated"
                                    | "license_expired"
                                    | "license_revoked"
                                    | "license_suspended"
                                    | "expired"
                                    | "revoked"
                                    | "suspended"
                                    | "not_active"
                            )
                        }),
                        _ => false,
                    }
                } else {
                    false
                };

                if idempotent {
                    (|| -> Result<()> {
                        let _state_guard = self.lock_state_for_commit();
                        self.ensure_current_target_operation(
                            &self.inner.current_deactivation_operation,
                            operation,
                            stateful,
                            "deactivation",
                        )?;
                        if let Some(identity) = cached_identity.as_ref() {
                            self.complete_local_deactivation(identity)?;
                        }
                        Ok(())
                    })()
                } else {
                    Err(error)
                }
            }
        };

        match &outcome {
            Ok(()) => {
                self.emit(Event::new(EventKind::DeactivationSuccess));
                debug!("License deactivated");
            }
            Err(error) => self.emit(Event::with_error(
                EventKind::DeactivationError,
                error.to_string(),
            )),
        }
        let _ = self.inner.current_deactivation_operation.compare_exchange(
            operation,
            0,
            Ordering::SeqCst,
            Ordering::SeqCst,
        );
        outcome
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
        self.require_api_key()?;
        validate_request_identifier("license_key", license_key)?;
        if let Some(fingerprint) = fingerprint {
            validate_fingerprint(fingerprint)?;
        }
        let resolved_fingerprint = self.resolve_request_fingerprint(fingerprint);
        validate_fingerprint(&resolved_fingerprint)?;
        let (operation, cached_license) =
            self.begin_target_operation(&self.inner.current_heartbeat_operation, |license| {
                license.license_key == license_key && license.device_id == resolved_fingerprint
            });
        let cached_identity = cached_license.as_ref().map(License::identity);
        let stateful = cached_identity.is_some();
        let _operation_guard =
            OperationGuard::new(&self.inner.current_heartbeat_operation, operation);

        let path = build_license_action_path(product_slug, license_key, "heartbeat");
        let body = fingerprint_alias_payload(&resolved_fingerprint, true);

        let outcome = match self.post::<HeartbeatResponse>(&path, Some(body)).await {
            Ok(response) => (|| -> Result<HeartbeatResponse> {
                let _state_guard = self.lock_state_for_commit();
                self.ensure_current_target_operation(
                    &self.inner.current_heartbeat_operation,
                    operation,
                    stateful,
                    "heartbeat",
                )?;
                verify_heartbeat_response(&response, license_key, product_slug)?;
                let observed_at = Utc::now();
                if let Some(identity) = cached_identity.as_ref() {
                    let validation = ValidationResult {
                        object: "validation_result".into(),
                        valid: true,
                        code: None,
                        message: None,
                        warnings: None,
                        license: response.license.clone(),
                        activation: None,
                        offline: false,
                    };
                    if !self
                        .inner
                        .cache
                        .update_validation(identity, &validation, observed_at)?
                    {
                        return Err(Error::OperationSuperseded {
                            operation: "heartbeat",
                        });
                    }
                    if let Err(error) = self
                        .inner
                        .cache
                        .set_last_seen_timestamp(observed_at.timestamp())
                    {
                        self.emit(Event::with_error(EventKind::SdkError, error.to_string()));
                        if let Err(cleanup_error) = self.inner.cache.clear_offline_assets() {
                            self.emit(Event::with_error(
                                EventKind::SdkError,
                                cleanup_error.to_string(),
                            ));
                        }
                    }
                    let mut runtime_license = cached_license
                        .clone()
                        .expect("cached identity requires a cached license");
                    runtime_license.validation = Some(validation);
                    runtime_license.trusted_license = Some(response.license.clone());
                    runtime_license.last_validated = observed_at;
                    self.set_runtime_license_state(
                        runtime_license,
                        TrustedLicenseSource::OnlineResponse,
                    );
                }
                Ok(response)
            })(),
            Err(error) => Err(error),
        };

        match outcome {
            Ok(response) => {
                self.set_last_heartbeat(Some(response.clone()));
                self.set_last_heartbeat_error(None);
                self.emit(Event::new(EventKind::HeartbeatSuccess));
                debug!("Heartbeat sent successfully");
                Ok(response)
            }
            Err(e) => {
                let current_operation = {
                    let _state_guard = self.lock_state_for_commit();
                    self.ensure_current_target_operation(
                        &self.inner.current_heartbeat_operation,
                        operation,
                        stateful,
                        "heartbeat",
                    )
                };
                if let Err(superseded) = current_operation {
                    self.emit(Event::with_error(
                        EventKind::HeartbeatError,
                        superseded.to_string(),
                    ));
                    return Err(superseded);
                }
                self.set_last_heartbeat_error(Some(e.to_string()));
                if is_authoritative_invalidation_error(&e) {
                    if let Some(identity) = cached_identity.as_ref() {
                        self.invalidate_license_operations();
                        self.stop_background_tasks();
                        if let Err(cleanup_error) = self.clear_cached_license_with_denial(
                            identity,
                            e.code().unwrap_or("authoritative_invalidation"),
                            &e.to_string(),
                        ) {
                            self.emit(Event::with_error(
                                EventKind::SdkError,
                                cleanup_error.to_string(),
                            ));
                        }
                        self.emit(Event::with_error(EventKind::LicenseRevoked, e.to_string()));
                    }
                }
                if e.is_network_error() && stateful {
                    self.start_support_tasks();
                }
                self.emit(Event::with_error(EventKind::HeartbeatError, e.to_string()));
                Err(e)
            }
        }
    }

    /// Check if an entitlement is active.
    pub fn check_entitlement(&self, entitlement_key: &str) -> EntitlementStatus {
        let Some(runtime_state) = self.runtime_license_state() else {
            return EntitlementStatus {
                active: false,
                reason: Some(if self.inner.cache.get_license().is_some() {
                    EntitlementReason::InvalidLicense
                } else {
                    EntitlementReason::NoLicense
                }),
                expires_at: None,
                entitlement: None,
            };
        };
        let now = runtime_state.effective_now();
        let license = runtime_state.license;

        let Some(validation) = &license.validation else {
            return EntitlementStatus {
                active: false,
                reason: Some(EntitlementReason::NoLicense),
                expires_at: None,
                entitlement: None,
            };
        };

        if !validation.valid
            || !license_response_matches_active_grant(
                &validation.license,
                &license.license_key,
                &self.inner.config.product_slug,
                &now,
            )
        {
            return EntitlementStatus {
                active: false,
                reason: Some(EntitlementReason::InvalidLicense),
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
                    if expires_at <= now {
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

    /// Return currently active entitlements only after this process has
    /// established the cached license state through an authoritative source.
    pub fn active_entitlements(&self) -> Vec<Entitlement> {
        self.state_snapshot().active_entitlements
    }

    /// Get the current license status.
    pub fn status(&self) -> LicenseStatus {
        self.state_snapshot().status
    }

    /// Get the current validation result only after this process has restored
    /// the cached state through an authoritative online or signed-offline
    /// source.
    ///
    /// [`Self::current_license`] returns this same process-local state after it
    /// is established and falls back to the untrusted persisted restoration
    /// candidate only while state is pending.
    pub fn get_status(&self) -> ValidationResult {
        self.current_authoritative_validation()
            .unwrap_or_else(default_validation_status)
    }

    /// Get a compact summary of the client status.
    pub fn get_client_status(&self) -> ClientStatus {
        self.state_snapshot().client_status
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

    /// Capture one coherent point-in-time view of the current license state.
    ///
    /// Prefer this method when presenting multiple related fields in a UI or
    /// serializing state across an IPC boundary. Separate calls to [`Self::status`],
    /// [`Self::current_authoritative_validation`], and
    /// [`Self::active_entitlements`] may legitimately observe different
    /// operations when validation or deactivation is running concurrently.
    pub fn state_snapshot(&self) -> LicenseStateSnapshot {
        let _state_guard = self.lock_state_for_commit();
        let is_online = self.inner.is_online.load(Ordering::SeqCst);

        let Some(runtime_state) = self.runtime_license_state() else {
            let license = self.inner.cache.get_license();
            let status = if license.is_some() {
                LicenseStatus::Pending {
                    message: "Cached license requires authoritative restoration".into(),
                }
            } else {
                LicenseStatus::Inactive {
                    message: "No license activated".into(),
                }
            };
            return LicenseStateSnapshot {
                client_status: client_status_for_status(&status),
                status,
                is_online,
                license,
                validation: None,
                active_entitlements: Vec::new(),
                trusted_source: None,
            };
        };

        let now = runtime_state.effective_now();
        let status = license_status_for_observation(
            &runtime_state.license,
            &self.inner.config.product_slug,
            &now,
        );
        let active_entitlements = match &status {
            LicenseStatus::Active { details } | LicenseStatus::OfflineValid { details } => {
                details.entitlements.clone()
            }
            _ => Vec::new(),
        };
        let validation = runtime_state
            .license
            .validation
            .clone()
            .map(|validation| validation_for_observation(validation, &now));

        LicenseStateSnapshot {
            client_status: client_status_for_status(&status),
            status,
            is_online,
            license: Some(runtime_state.license),
            validation,
            active_entitlements,
            trusted_source: Some(runtime_state.source),
        }
    }

    /// Get the authoritative process-local license, or the untrusted persisted
    /// restoration candidate when no runtime decision has been established.
    pub fn current_license(&self) -> Option<License> {
        self.runtime_license()
            .or_else(|| self.inner.cache.get_license())
    }

    /// Get the current process-authoritative validation decision.
    ///
    /// Unlike [`Self::current_license`], this never falls back to unsigned
    /// persisted restoration data. `None` means the current process has not
    /// yet established an online decision or verified a signed offline
    /// artifact.
    pub fn current_authoritative_validation(&self) -> Option<ValidationResult> {
        self.current_authoritative_validation_record()
            .map(|(validation, _)| validation)
    }

    /// Whether this process has established the current cached state through
    /// activation, an online API decision, or signed offline verification.
    pub fn is_license_state_trusted(&self) -> bool {
        self.runtime_license_state().is_some()
    }

    /// Get the authoritative rich license metadata held by this process.
    ///
    /// This never returns unsigned snapshot/cache metadata from a previous
    /// process.
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

    /// Get a cached signing key by key id.
    ///
    /// Cached fetched keys are exposed for diagnostics and online revalidation,
    /// but are not treated as trust anchors in a new process. Offline startup
    /// requires a key pinned in [`Config::signing_public_key`].
    #[cfg(feature = "offline")]
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
        // Plugin setup and frontend bootstrap can legitimately request restore
        // at the same time. Serialize them and make the second caller observe
        // the already-established runtime state instead of superseding the
        // first caller's validation operation.
        let _restore_guard = self.inner.restore_lock.lock().await;
        if let Some(license) = self.runtime_license() {
            let status = self.status();
            return RestoreResult {
                restored: status.is_active(),
                status,
                validation: license.validation.clone(),
                license: Some(license),
                error: None,
            };
        }
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

        // Validation is both the connectivity probe and the authoritative
        // restore operation. A separate health request creates a race where
        // health succeeds but validation loses connectivity, incorrectly
        // bypassing an otherwise valid signed-offline fallback.
        match self.validate_key(&license.license_key).await {
            Ok(validation) => {
                result.validation = Some(validation);
                result.status = self.status();
                result.restored = result.status.is_active();
                should_start_background_tasks = result.restored;
            }
            Err(validation_error) => {
                #[cfg(feature = "offline")]
                {
                    if self.should_fallback_offline(&validation_error) {
                        match self.validate_offline(&license.identity()).await {
                            Ok(validation) => {
                                result.validation = Some(validation);
                                result.status = self.status();
                                result.restored = result.status.is_active();
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
                            message: validation_error.to_string(),
                        };
                        result.error = Some(validation_error.to_string());
                    }
                    should_start_support_tasks = self.should_fallback_offline(&validation_error);
                }

                #[cfg(not(feature = "offline"))]
                {
                    result.status = LicenseStatus::Invalid {
                        message: validation_error.to_string(),
                    };
                    result.error = Some(validation_error.to_string());
                    should_start_support_tasks = validation_error.is_network_error();
                }
            }
        }

        if should_start_background_tasks {
            self.start_background_tasks();
        } else if should_start_support_tasks {
            self.start_support_tasks();
        }

        // Return the state that actually survived response binding and the
        // final commit, not branch-local guesses or the stale cache snapshot
        // captured before network or offline verification began.
        result.status = self.status();
        result.restored = result.status.is_active();
        result.license = self.current_license();
        // `current_license` intentionally exposes the persisted restoration
        // candidate for diagnostics while the state is pending. Its embedded
        // validation is unsigned and must never be returned as the decision
        // that drove this restore result.
        result.validation = self.current_authoritative_validation();

        result
    }

    /// Check API health.
    pub async fn health_check(&self) -> Result<HealthResponse> {
        match self.get::<HealthResponse>("/health").await {
            Ok(response) => {
                if response.object != "health"
                    || response.status != "healthy"
                    || response.api_version.trim().is_empty()
                {
                    let error = Error::ResponseMismatch(
                        "health response did not match the LicenseSeat health contract".into(),
                    );
                    self.set_last_health_error(Some(error.to_string()));
                    return Err(error);
                }
                self.set_last_health(Some(response.clone()));
                self.set_last_health_error(None);
                Ok(response)
            }
            Err(error) => {
                self.set_last_health_error(Some(error.to_string()));
                if error.is_network_error() {
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
        validate_request_identifier("product_slug", product_slug)?;
        validate_optional_request_identifier("channel", channel)?;
        validate_optional_request_identifier("platform", platform)?;

        let path = build_release_path(
            &build_path(&["products", product_slug, "releases", "latest"]),
            &ReleaseListOptions {
                channel: channel.map(ToString::to_string),
                platform: platform.map(ToString::to_string),
                limit: None,
            },
        );
        let release = self.get(&path).await?;
        verify_release_response(&release, product_slug, channel, platform)?;
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
        if product_slug.is_empty() {
            return Err(Error::Configuration("product_slug is required".into()));
        }
        validate_request_identifier("product_slug", product_slug)?;
        validate_optional_request_identifier("channel", options.channel.as_deref())?;
        validate_optional_request_identifier("platform", options.platform.as_deref())?;

        let path = build_release_path(
            &build_path(&["products", product_slug, "releases"]),
            &options,
        );
        let body: serde_json::Value = self.get(&path).await?;
        let releases = parse_release_list(&body)?;
        if releases.object != "list"
            || (releases.has_more && releases.next_cursor.as_deref().is_none_or(str::is_empty))
            || releases.data.iter().any(|release| {
                verify_release_response(
                    release,
                    product_slug,
                    options.channel.as_deref(),
                    options.platform.as_deref(),
                )
                .is_err()
            })
        {
            return Err(Error::ResponseMismatch(
                "release list did not match the requested product or filters".into(),
            ));
        }
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
        self.require_api_key()?;
        validate_request_identifier("version", version)?;
        validate_request_identifier("license_key", license_key)?;

        let product_slug = product_slug
            .filter(|slug| !slug.is_empty())
            .unwrap_or(&self.inner.config.product_slug);
        if product_slug.is_empty() {
            return Err(Error::Configuration("product_slug is required".into()));
        }
        validate_request_identifier("product_slug", product_slug)?;
        validate_optional_request_identifier("platform", platform)?;

        let path = build_path(&[
            "products",
            product_slug,
            "releases",
            version,
            "download_token",
        ]);
        let body = build_download_token_request(license_key, platform);
        let token: DownloadToken = self.post(&path, Some(body)).await?;
        if token.object != "download_token"
            || token.token.trim().is_empty()
            || token
                .expires_at
                .is_none_or(|expires_at| expires_at <= Utc::now())
        {
            return Err(Error::ResponseMismatch(
                "download-token response was empty, expired, or malformed".into(),
            ));
        }
        Ok(token)
    }

    /// Reset SDK state (clears cache and stops timers).
    ///
    /// Prefer [`Self::try_reset`] when the caller can surface persistent
    /// storage cleanup failures.
    pub fn reset(&self) {
        if let Err(error) = self.try_reset() {
            self.emit(Event::with_error(EventKind::SdkError, error.to_string()));
        }
    }

    /// Reset SDK state and report persistent-storage cleanup failures.
    pub fn try_reset(&self) -> Result<()> {
        let _state_guard = self.lock_state_for_commit();
        // Stop background tasks first
        self.invalidate_license_operations();
        self.stop_background_tasks();
        let identity = self.current_license().map(|license| license.identity());
        self.clear_runtime_license_state();
        if let Some(identity) = identity.as_ref() {
            self.inner.cache.invalidate_and_clear(
                identity,
                "locally_reset",
                "License state was reset locally",
                Utc::now(),
            )?;
        } else {
            self.inner.cache.clear()?;
        }
        self.emit(Event::new(EventKind::SdkReset));
        debug!("SDK state reset");
        Ok(())
    }

    /// Subscribe to SDK events.
    pub fn subscribe(&self) -> broadcast::Receiver<Event> {
        self.inner.event_tx.subscribe()
    }

    /// Return the effective runtime configuration.
    ///
    /// This includes the normalized, product-scoped storage prefix. It also
    /// contains the configured API key, so callers must not serialize or expose
    /// it to an untrusted frontend.
    pub fn config(&self) -> &Config {
        &self.inner.config
    }

    // ========================================================================
    // Background Tasks
    // ========================================================================

    /// Start background validation, heartbeat, and support tasks.
    ///
    /// This is called automatically after activation or a successful
    /// [`Self::restore_license`]. A raw cached record never starts networking.
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

        let (cancel_tx, mut cancel_rx) = watch::channel(());
        let generation = {
            let mut guard = self
                .inner
                .auto_validation_cancel
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let generation = self
                .inner
                .auto_validation_generation
                .fetch_add(1, Ordering::SeqCst)
                + 1;
            self.inner
                .auto_validation_running
                .store(true, Ordering::SeqCst);
            *guard = Some(cancel_tx);
            generation
        };

        let weak = Arc::downgrade(&self.inner);
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
                        if let Some(inner) = weak.upgrade() {
                            let sdk = Self { inner };
                            sdk.emit(Event::with_error(
                                EventKind::SdkError,
                                format!("Failed to create auto-validation runtime: {e}"),
                            ));
                            if sdk.auto_validation_should_continue(generation) {
                                sdk.stop_auto_validation();
                            }
                        }
                        return;
                    }
                };

                rt.block_on(async {
                    let Some(inner) = weak.upgrade() else {
                        return;
                    };
                    let sdk = Self { inner };
                    if !sdk.auto_validation_should_continue(generation) {
                        return;
                    }
                    sdk.emit_auto_validation_cycle(interval);
                    drop(sdk);

                    loop {
                        tokio::select! {
                            _ = tokio::time::sleep(interval) => {}
                            changed = cancel_rx.changed() => {
                                let _ = changed;
                                break;
                            }
                        }

                        let Some(inner) = weak.upgrade() else {
                            break;
                        };
                        let sdk = Self { inner };
                        if !sdk.auto_validation_should_continue(generation) {
                            break;
                        }

                        debug!("Running auto-validation");
                        match sdk.validate_key(&license_key).await {
                            Ok(result) if result.valid => debug!("Auto-validation successful"),
                            Ok(result) => {
                                warn!("Auto-validation was not accepted");
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
                                warn!("Auto-validation error: {}", e.redacted_log_summary());
                                sdk.emit(Event::with_error(
                                    EventKind::ValidationAutoFailed,
                                    e.to_string(),
                                ));
                            }
                        }

                        if !sdk.auto_validation_should_continue(generation) {
                            break;
                        }

                        sdk.emit_auto_validation_cycle(interval);
                    }
                });
            });

        if let Err(error) = spawn_result {
            if self.auto_validation_should_continue(generation) {
                self.stop_auto_validation();
            }
            self.emit(Event::with_error(
                EventKind::SdkError,
                format!("Failed to spawn auto-validation thread: {error}"),
            ));
        }
    }

    /// Stop periodic auto-validation.
    pub fn stop_auto_validation(&self) {
        let (was_running, cancel) = {
            let mut guard = self
                .inner
                .auto_validation_cancel
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let was_running = self
                .inner
                .auto_validation_running
                .swap(false, Ordering::SeqCst);
            self.inner
                .auto_validation_generation
                .fetch_add(1, Ordering::SeqCst);
            (was_running, guard.take())
        };
        if let Some(cancel) = cancel {
            let _ = cancel.send(());
        }

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

        let (cancel_tx, mut cancel_rx) = watch::channel(());
        let generation = {
            let mut guard = self
                .inner
                .heartbeat_cancel
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let generation = self
                .inner
                .heartbeat_generation
                .fetch_add(1, Ordering::SeqCst)
                + 1;
            self.inner.heartbeat_running.store(true, Ordering::SeqCst);
            *guard = Some(cancel_tx);
            generation
        };

        let weak = Arc::downgrade(&self.inner);
        let license_key = license_key.to_string();
        // An activation may deliberately override the SDK's installation
        // fingerprint. Background heartbeats must continue using the exact
        // fingerprint that consumed the seat, not the config-level default.
        let heartbeat_fingerprint = self
            .current_license()
            .filter(|license| license.license_key == license_key)
            .map(|license| license.device_id)
            .unwrap_or_else(|| self.inner.fingerprint.clone());
        let spawn_result = std::thread::Builder::new()
            .name("licenseseat-heartbeat".into())
            .spawn(move || {
                let rt = match tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                {
                    Ok(rt) => rt,
                    Err(e) => {
                        if let Some(inner) = weak.upgrade() {
                            let sdk = Self { inner };
                            sdk.emit(Event::with_error(
                                EventKind::SdkError,
                                format!("Failed to create heartbeat runtime: {e}"),
                            ));
                            if sdk.heartbeat_should_continue(generation) {
                                sdk.stop_heartbeat();
                            }
                        }
                        return;
                    }
                };

                rt.block_on(async {
                    loop {
                        tokio::select! {
                            _ = tokio::time::sleep(interval) => {}
                            changed = cancel_rx.changed() => {
                                let _ = changed;
                                break;
                            }
                        }

                        let Some(inner) = weak.upgrade() else {
                            break;
                        };
                        let sdk = Self { inner };
                        if !sdk.heartbeat_should_continue(generation) {
                            break;
                        }

                        debug!("Sending heartbeat");
                        if let Err(e) = sdk
                            .heartbeat_key(&license_key, Some(&heartbeat_fingerprint))
                            .await
                        {
                            warn!("Heartbeat error: {}", e.redacted_log_summary());
                        }
                    }
                });
            });

        if let Err(error) = spawn_result {
            if self.heartbeat_should_continue(generation) {
                self.stop_heartbeat();
            }
            self.emit(Event::with_error(
                EventKind::SdkError,
                format!("Failed to spawn heartbeat thread: {error}"),
            ));
        }
    }

    /// Stop periodic heartbeats.
    pub fn stop_heartbeat(&self) {
        let cancel = {
            let mut guard = self
                .inner
                .heartbeat_cancel
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            self.inner.heartbeat_running.store(false, Ordering::SeqCst);
            self.inner
                .heartbeat_generation
                .fetch_add(1, Ordering::SeqCst);
            guard.take()
        };
        if let Some(cancel) = cancel {
            let _ = cancel.send(());
        }
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

        let (cancel_tx, cancel_rx) = watch::channel(());
        let generation = {
            let mut guard = self
                .inner
                .support_tasks_cancel
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if self.inner.background_tasks_running.load(Ordering::SeqCst) {
                return;
            }
            let generation = self
                .inner
                .support_tasks_generation
                .fetch_add(1, Ordering::SeqCst)
                + 1;
            self.inner
                .background_tasks_running
                .store(true, Ordering::SeqCst);
            *guard = Some(cancel_tx);
            generation
        };

        debug!("Starting support background tasks");
        let weak = Arc::downgrade(&self.inner);

        let spawn_result = std::thread::Builder::new()
            .name("licenseseat-background".into())
            .spawn(move || {
                let rt = match tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                {
                    Ok(rt) => rt,
                    Err(e) => {
                        if let Some(inner) = weak.upgrade() {
                            let sdk = Self { inner };
                            sdk.emit(Event::with_error(
                                EventKind::SdkError,
                                format!("Failed to create background runtime: {e}"),
                            ));
                            if sdk.support_tasks_should_continue(generation) {
                                sdk.stop_support_tasks();
                            }
                        }
                        return;
                    }
                };

                rt.block_on(async {
                    let mut tasks = Vec::new();

                    if !network_recheck_interval.is_zero() {
                        let weak_clone = weak.clone();
                        let cancel = cancel_rx.clone();
                        tasks.push(tokio::spawn(async move {
                            Self::network_recheck_loop(
                                weak_clone,
                                network_recheck_interval,
                                generation,
                                cancel,
                            )
                            .await;
                        }));
                    }

                    #[cfg(feature = "offline")]
                    if !refresh_interval.is_zero() {
                        let weak_clone = weak.clone();
                        let cancel = cancel_rx.clone();
                        tasks.push(tokio::spawn(async move {
                            Self::offline_refresh_loop(
                                weak_clone,
                                refresh_interval,
                                generation,
                                cancel,
                            )
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
            if self.support_tasks_should_continue(generation) {
                self.stop_support_tasks();
            }
            self.emit(Event::with_error(
                EventKind::SdkError,
                format!("Failed to spawn background thread: {error}"),
            ));
        }
    }

    fn stop_support_tasks(&self) {
        debug!("Stopping support background tasks");
        let cancel = {
            let mut guard = self
                .inner
                .support_tasks_cancel
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            self.inner
                .background_tasks_running
                .store(false, Ordering::SeqCst);
            self.inner
                .support_tasks_generation
                .fetch_add(1, Ordering::SeqCst);
            guard.take()
        };
        if let Some(cancel) = cancel {
            let _ = cancel.send(());
        }
    }

    /// Network recheck loop that restores online state after outages.
    async fn network_recheck_loop(
        weak: Weak<LicenseSeatInner>,
        interval: Duration,
        generation: u64,
        mut cancel: watch::Receiver<()>,
    ) {
        debug!("Network recheck loop started with interval {:?}", interval);

        loop {
            tokio::select! {
                _ = tokio::time::sleep(interval) => {}
                changed = cancel.changed() => {
                    let _ = changed;
                    break;
                }
            }

            let Some(inner) = weak.upgrade() else {
                break;
            };
            let sdk = Self { inner };
            if !sdk.support_tasks_should_continue(generation) {
                debug!("Network recheck loop stopping");
                break;
            }

            if sdk.current_license().is_none() {
                debug!("No active license, skipping network recheck");
                continue;
            }

            let has_offline_state = matches!(
                sdk.status(),
                LicenseStatus::OfflineValid { .. } | LicenseStatus::OfflineInvalid { .. }
            );
            if sdk.is_online() && !has_offline_state {
                continue;
            }

            debug!("Rechecking API connectivity");
            if sdk.health_check().await.is_ok() {
                if let Some(license) = sdk.current_license() {
                    if let Ok(result) = sdk.validate_key(&license.license_key).await {
                        if result.valid {
                            sdk.start_auto_validation(&license.license_key);
                            sdk.start_heartbeat(&license.license_key);
                        }
                    }
                }
            }
        }
    }

    /// Offline asset refresh loop.
    #[cfg(feature = "offline")]
    async fn offline_refresh_loop(
        weak: Weak<LicenseSeatInner>,
        interval: Duration,
        generation: u64,
        mut cancel: watch::Receiver<()>,
    ) {
        debug!("Offline refresh loop started with interval {:?}", interval);
        loop {
            tokio::select! {
                _ = tokio::time::sleep(interval) => {}
                changed = cancel.changed() => {
                    let _ = changed;
                    break;
                }
            }

            let Some(inner) = weak.upgrade() else {
                break;
            };
            let sdk = Self { inner };
            if !sdk.support_tasks_should_continue(generation) {
                debug!("Offline refresh loop stopping");
                break;
            }
            if sdk.current_license().is_none() {
                debug!("No active license, skipping offline refresh");
                continue;
            }

            debug!("Refreshing offline assets");
            if let Err(e) = sdk.sync_offline_assets().await {
                warn!("Offline asset refresh error: {}", e.redacted_log_summary());
            }
        }
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
        self.require_api_key()?;
        validate_request_identifier("license_key", license_key)?;
        validate_positive_days("ttl_days", ttl_days)?;
        if let Some(fingerprint) = fingerprint {
            validate_fingerprint(fingerprint)?;
        }
        // Automatic refresh and host-initiated checkout share one state slot.
        // Serialize them so a refresh scheduled immediately after activation
        // cannot supersede a foreground operation that the host is awaiting.
        let _request_guard = self.inner.offline_request_lock.lock().await;
        let fingerprint = fingerprint
            .filter(|value| !value.is_empty())
            .map(ToString::to_string)
            .unwrap_or_else(|| self.resolve_request_fingerprint(None));
        validate_fingerprint(&fingerprint)?;
        let cached_identity = self
            .current_license()
            .filter(|license| {
                license.license_key == license_key && license.device_id == fingerprint
            })
            .map(|license| license.identity());
        let operation = self.begin_operation(&self.inner.current_offline_sync_operation);
        let _operation_guard =
            OperationGuard::new(&self.inner.current_offline_sync_operation, operation);

        self.emit(Event::new(EventKind::OfflineTokenFetching));

        let path = build_license_action_path(product_slug, license_key, "offline_token");
        let body = build_offline_token_request(&fingerprint, ttl_days);
        let outcome = match self.post::<OfflineTokenResponse>(&path, Some(body)).await {
            Ok(token) => async {
                self.ensure_current_operation(
                    &self.inner.current_offline_sync_operation,
                    operation,
                    "offline-token fetch",
                )?;
                crate::offline::validate_token_envelope(&token)?;
                if !secure_string_eq(&token.token.license_key, license_key)
                    || !secure_string_eq(&token.token.product_slug, product_slug)
                    || token
                        .token
                        .device_id
                        .as_deref()
                        .is_none_or(|value| !secure_string_eq(value, &fingerprint))
                {
                    return Err(Error::ResponseMismatch(
                        "offline token did not match the requested license, product, or installation"
                            .into(),
                    ));
                }
                let key_id = token.token.kid.clone();
                let public_key = match self.resolve_public_key(&key_id, None) {
                    Some(key) => key,
                    None => self.fetch_signing_key(&key_id).await?,
                };
                let _state_guard = self.lock_state_for_commit();
                self.ensure_current_operation(
                    &self.inner.current_offline_sync_operation,
                    operation,
                    "offline-token fetch",
                )?;
                let signing_key = SigningKeyResponse {
                    object: "signing_key".into(),
                    key_id,
                    algorithm: "Ed25519".into(),
                    public_key,
                    created_at: None,
                    status: "active".into(),
                };
                crate::offline::verify_token(&token, &signing_key)?;
                crate::offline::check_token_validity_at(
                    &token,
                    Utc::now().timestamp(),
                    duration_seconds_i64(self.inner.config.max_clock_skew),
                )?;
                if let Some(identity) = cached_identity.as_ref() {
                    if !self.inner.cache.matches_identity(identity) {
                        return Err(Error::OperationSuperseded {
                            operation: "offline-token fetch",
                        });
                    }
                    self.inner.cache.set_offline_token(&token)?;
                }
                Ok(token)
            }
            .await,
            Err(error) => Err(error),
        };

        match &outcome {
            Ok(_) => {
                self.emit(Event::new(EventKind::OfflineTokenFetched));
                self.emit(Event::new(EventKind::OfflineTokenReady));
            }
            Err(error) => self.emit(Event::with_error(
                EventKind::OfflineTokenFetchError,
                error.to_string(),
            )),
        }
        outcome
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
        self.require_api_key()?;
        validate_request_identifier("license_key", license_key)?;
        let MachineFileCheckoutOptions {
            fingerprint,
            device_id,
            device_fingerprint,
            ttl_days,
            grace_period_days,
            include_license,
            fingerprint_components,
        } = options;
        validate_positive_days("ttl_days", ttl_days)?;
        validate_positive_days("grace_period_days", grace_period_days)?;
        let _request_guard = self.inner.offline_request_lock.lock().await;
        let fingerprint = select_fingerprint_alias(
            fingerprint.as_deref(),
            device_id.as_deref(),
            device_fingerprint.as_deref(),
        )?
        .map(ToString::to_string)
        .unwrap_or_else(|| self.resolve_request_fingerprint(None));
        validate_fingerprint(&fingerprint)?;
        let cached_identity = self
            .current_license()
            .filter(|license| {
                license.license_key == license_key && license.device_id == fingerprint
            })
            .map(|license| license.identity());
        let operation = self.begin_operation(&self.inner.current_offline_sync_operation);
        let _operation_guard =
            OperationGuard::new(&self.inner.current_offline_sync_operation, operation);

        self.emit(Event::new(EventKind::MachineFileFetching));

        let fingerprint_components = if fingerprint_components.is_empty()
            && fingerprint == self.inner.fingerprint
            && self.inner.config.send_fingerprint_components
        {
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
        let outcome = match self.post::<serde_json::Value>(&path, Some(body)).await {
            Ok(response) => {
                async {
                    self.ensure_current_operation(
                        &self.inner.current_offline_sync_operation,
                        operation,
                        "machine-file checkout",
                    )?;
                    let machine_file = parse_machine_file_response(&response)?;
                    if machine_file.certificate.is_empty()
                        || machine_file.algorithm != "aes-256-gcm+ed25519"
                        || !secure_string_eq(&machine_file.license_key, license_key)
                        || !secure_string_eq(&machine_file.fingerprint, &fingerprint)
                    {
                        return Err(Error::ResponseMismatch(
                        "machine-file response did not match the requested license or installation"
                            .into(),
                    ));
                    }

                    let key_id = crate::offline::machine_file_key_id(&machine_file.certificate)?;
                    if self.resolve_public_key(&key_id, None).is_none() {
                        self.fetch_signing_key(&key_id).await?;
                    }
                    let _state_guard = self.lock_state_for_commit();
                    self.ensure_current_operation(
                        &self.inner.current_offline_sync_operation,
                        operation,
                        "machine-file checkout",
                    )?;
                    let verification = self.inspect_machine_file(
                        &machine_file,
                        None,
                        Some(license_key),
                        Some(&fingerprint),
                    )?;
                    if !verification.valid {
                        return Err(Error::OfflineVerificationFailed(
                            verification.code.unwrap_or_else(|| {
                                verification
                                    .message
                                    .unwrap_or_else(|| "VERIFICATION_FAILED".into())
                            }),
                        ));
                    }
                    if let Some(identity) = cached_identity.as_ref() {
                        if !self.inner.cache.matches_identity(identity) {
                            return Err(Error::OperationSuperseded {
                                operation: "machine-file checkout",
                            });
                        }
                        self.inner.cache.set_machine_file(&machine_file)?;
                    }
                    Ok(machine_file)
                }
                .await
            }
            Err(error) => Err(error),
        };

        match &outcome {
            Ok(_) => {
                self.emit(Event::new(EventKind::MachineFileFetched));
                self.emit(Event::new(EventKind::MachineFileReady));
            }
            Err(error) => self.emit(Event::with_error(
                EventKind::MachineFileFetchError,
                error.to_string(),
            )),
        }
        outcome
    }

    /// Fetch a signing key from the API and cache it locally.
    #[cfg(feature = "offline")]
    pub async fn fetch_signing_key(&self, key_id: &str) -> Result<String> {
        validate_request_identifier("key_id", key_id)?;

        let path = build_path(&["signing_keys", key_id]);
        let response: SigningKeyResponse = self.get(&path).await?;
        crate::offline::validate_signing_key(&response, key_id)?;
        let key = response.public_key.clone();
        self.inner.cache.set_signing_key(key_id, &response)?;
        self.inner
            .runtime_signing_keys
            .lock()
            .map_err(|_| Error::Cache("runtime signing-key lock poisoned".into()))?
            .insert(key_id.to_string(), key.clone());
        Ok(key)
    }

    /// Verify a legacy offline token locally.
    #[cfg(feature = "offline")]
    pub fn verify_offline_token(
        &self,
        offline_token: &OfflineTokenResponse,
        public_key_b64: Option<&str>,
    ) -> Result<bool> {
        let outcome = (|| -> Result<bool> {
            if offline_token.token.license_key.is_empty() {
                return Err(Error::Configuration("license_key is required".into()));
            }

            crate::offline::validate_token_envelope(offline_token)?;
            crate::offline::check_token_validity_at(
                offline_token,
                Utc::now().timestamp(),
                duration_seconds_i64(self.inner.config.max_clock_skew),
            )?;

            let cached_license = self.current_license().ok_or(Error::NoActiveLicense)?;
            if !secure_string_eq(
                &offline_token.token.license_key,
                &cached_license.license_key,
            ) {
                return Err(Error::OfflineVerificationFailed("LICENSE_MISMATCH".into()));
            }
            if !secure_string_eq(
                &offline_token.token.product_slug,
                self.require_product_slug()?,
            ) {
                return Err(Error::OfflineVerificationFailed("PRODUCT_MISMATCH".into()));
            }

            let token_fingerprint = offline_token.token.device_id.as_deref().unwrap_or_default();
            if token_fingerprint.is_empty() {
                return Err(Error::OfflineVerificationFailed(
                    "FINGERPRINT_MISSING".into(),
                ));
            }
            if !secure_string_eq(token_fingerprint, &cached_license.device_id) {
                return Err(Error::OfflineVerificationFailed(
                    "FINGERPRINT_MISMATCH".into(),
                ));
            }
            if self.inner.config.max_offline_days > 0 {
                let maximum_age =
                    i64::from(self.inner.config.max_offline_days).saturating_mul(86_400);
                let age = Utc::now()
                    .timestamp()
                    .saturating_sub(offline_token.token.iat);
                if age >= maximum_age {
                    return Err(Error::OfflineVerificationFailed(
                        "GRACE_PERIOD_EXPIRED".into(),
                    ));
                }
            }

            let key = self
                .resolve_public_key(&offline_token.signature.key_id, public_key_b64)
                .ok_or_else(|| Error::Configuration("public_key is required".into()))?;

            let signing_key = SigningKeyResponse {
                object: "signing_key".into(),
                key_id: offline_token.signature.key_id.clone(),
                algorithm: offline_token.signature.algorithm.clone(),
                public_key: key,
                created_at: None,
                status: "active".into(),
            };

            crate::offline::verify_token(offline_token, &signing_key)
        })();

        match &outcome {
            Ok(true) => self.emit(Event::new(EventKind::OfflineTokenVerified)),
            Ok(false) => self.emit(Event::new(EventKind::OfflineTokenVerificationFailed)),
            Err(error) => self.emit(Event::with_error(
                EventKind::OfflineTokenVerificationFailed,
                error.to_string(),
            )),
        }
        outcome
    }

    /// Verify a machine file locally.
    #[cfg(feature = "offline")]
    fn verify_machine_file_inner(
        &self,
        machine_file: &MachineFile,
        public_key_b64: Option<&str>,
        license_key: Option<&str>,
        fingerprint: Option<&str>,
    ) -> Result<MachineFileVerificationResult> {
        let resolved_license_key = license_key
            .filter(|value| !value.is_empty())
            .map(ToString::to_string)
            .or_else(|| {
                (!machine_file.license_key.is_empty()).then(|| machine_file.license_key.clone())
            })
            .or_else(|| self.current_license().map(|license| license.license_key))
            .ok_or_else(|| Error::Configuration("license_key is required".into()))?;

        let resolved_fingerprint = fingerprint
            .filter(|value| !value.is_empty())
            .map(ToString::to_string)
            .unwrap_or_else(|| self.resolve_request_fingerprint(None));

        let key_id = crate::offline::machine_file_key_id(&machine_file.certificate)?;
        let public_key = self
            .resolve_public_key(&key_id, public_key_b64)
            .ok_or_else(|| Error::Configuration("public_key is required".into()))?;

        match crate::offline::verify_machine_file(
            machine_file,
            &resolved_license_key,
            &resolved_fingerprint,
            &public_key,
            Some(self.require_product_slug()?),
            self.inner.config.max_offline_days,
            duration_seconds_i64(self.inner.config.max_clock_skew),
        ) {
            Ok(payload) => {
                if self
                    .current_license()
                    .filter(|license| {
                        secure_string_eq(&license.license_key, &resolved_license_key)
                            && secure_string_eq(&license.device_id, &resolved_fingerprint)
                    })
                    .is_some_and(|license| {
                        !secure_string_eq(&license.activation_id, &payload.machine_id)
                    })
                {
                    let error = Error::OfflineVerificationFailed("ACTIVATION_MISMATCH".into());
                    return Ok(MachineFileVerificationResult {
                        valid: false,
                        code: Some("activation_mismatch".into()),
                        message: Some(error.to_string()),
                        payload: None,
                    });
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
        let outcome =
            self.verify_machine_file_inner(machine_file, public_key_b64, license_key, fingerprint);
        match &outcome {
            Ok(result) if result.valid => {
                self.emit(Event::new(EventKind::MachineFileVerified));
            }
            Ok(result) => self.emit(Event::with_error(
                EventKind::MachineFileVerificationFailed,
                result
                    .message
                    .clone()
                    .or_else(|| result.code.clone())
                    .unwrap_or_else(|| "machine-file verification failed".into()),
            )),
            Err(error) => self.emit(Event::with_error(
                EventKind::MachineFileVerificationFailed,
                error.to_string(),
            )),
        }
        outcome
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
        self.verify_machine_file_inner(machine_file, public_key_b64, license_key, fingerprint)
    }

    /// Sync offline assets (machine files first, legacy tokens only if enabled).
    #[cfg(feature = "offline")]
    pub async fn sync_offline_assets(&self) -> Result<()> {
        let license = self.current_license().ok_or(Error::NoActiveLicense)?;
        let expected_identity = license.identity();

        debug!("Syncing offline assets");

        let machine_file_error = match self
            .checkout_machine_file(&license.license_key, Some(&license.device_id), Some(30))
            .await
        {
            Ok(_) => {
                // Checkout verifies the signature, binding, lifetime, and
                // active-license identity before committing the artifact.
                if !self.inner.cache.matches_identity(&expected_identity) {
                    return Err(Error::OperationSuperseded {
                        operation: "offline asset sync",
                    });
                }
                self.emit(Event::new(EventKind::OfflineAssetsRefreshed));
                return Ok(());
            }
            Err(error) => error,
        };

        if !self.inner.config.enable_legacy_offline_tokens {
            return Err(machine_file_error);
        }

        let _token = self
            .generate_offline_token(&license.license_key, Some(&license.device_id), Some(30))
            .await?;
        if !self.inner.cache.matches_identity(&expected_identity) {
            return Err(Error::OperationSuperseded {
                operation: "offline asset sync",
            });
        }
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

    fn require_api_key(&self) -> Result<&str> {
        if self.inner.config.api_key.trim().is_empty() {
            return Err(Error::ApiKeyRequired);
        }
        Ok(&self.inner.config.api_key)
    }

    #[cfg(feature = "offline")]
    fn begin_operation(&self, slot: &AtomicU64) -> u64 {
        let _state_guard = self.lock_state_for_commit();
        let id = self.next_operation_id();
        slot.store(id, Ordering::SeqCst);
        id
    }

    fn begin_license_operation(&self, slot: &AtomicU64) -> u64 {
        let _state_guard = self.lock_state_for_commit();
        let id = self.next_operation_id();
        slot.store(id, Ordering::SeqCst);
        self.inner
            .current_license_state_operation
            .store(id, Ordering::SeqCst);
        id
    }

    fn begin_target_operation(
        &self,
        slot: &AtomicU64,
        matches_target: impl FnOnce(&License) -> bool,
    ) -> (u64, Option<License>) {
        let _state_guard = self.lock_state_for_commit();
        let cached_license = self.current_license().filter(matches_target);
        // Explicit-key helpers can also be used for a license other than the
        // installation currently managed by this SDK instance. Such a call
        // has no local state to commit, so it must not supersede an in-flight
        // validation, heartbeat, or deactivation for the active installation.
        if cached_license.is_none() {
            return (0, None);
        }
        let id = self.next_operation_id();
        slot.store(id, Ordering::SeqCst);
        self.inner
            .current_license_state_operation
            .store(id, Ordering::SeqCst);
        (id, cached_license)
    }

    fn next_operation_id(&self) -> u64 {
        self.inner
            .operation_sequence
            .fetch_add(1, Ordering::SeqCst)
            .saturating_add(1)
    }

    fn ensure_current_operation(
        &self,
        slot: &AtomicU64,
        id: u64,
        operation: &'static str,
    ) -> Result<()> {
        if slot.load(Ordering::SeqCst) == id {
            Ok(())
        } else {
            Err(Error::OperationSuperseded { operation })
        }
    }

    fn ensure_current_license_operation(
        &self,
        slot: &AtomicU64,
        id: u64,
        operation: &'static str,
    ) -> Result<()> {
        self.ensure_current_operation(slot, id, operation)?;
        if self
            .inner
            .current_license_state_operation
            .load(Ordering::SeqCst)
            == id
        {
            Ok(())
        } else {
            Err(Error::OperationSuperseded { operation })
        }
    }

    fn ensure_current_target_operation(
        &self,
        slot: &AtomicU64,
        id: u64,
        stateful: bool,
        operation: &'static str,
    ) -> Result<()> {
        if stateful {
            self.ensure_current_license_operation(slot, id, operation)
        } else {
            Ok(())
        }
    }

    fn lock_state_for_commit(&self) -> std::sync::MutexGuard<'_, ()> {
        self.inner
            .state_commit_lock
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn invalidate_license_operations_except_activation(&self, activation_operation: u64) {
        if self
            .inner
            .current_activation_operation
            .load(Ordering::SeqCst)
            != activation_operation
        {
            return;
        }
        self.inner
            .current_license_state_operation
            .store(activation_operation, Ordering::SeqCst);
        self.inner
            .current_deactivation_operation
            .store(0, Ordering::SeqCst);
        self.inner
            .current_validation_operation
            .store(0, Ordering::SeqCst);
        self.inner
            .current_heartbeat_operation
            .store(0, Ordering::SeqCst);
        self.inner
            .current_offline_sync_operation
            .store(0, Ordering::SeqCst);
    }

    fn invalidate_license_operations(&self) {
        self.inner
            .current_license_state_operation
            .store(0, Ordering::SeqCst);
        self.inner
            .current_activation_operation
            .store(0, Ordering::SeqCst);
        self.inner
            .current_deactivation_operation
            .store(0, Ordering::SeqCst);
        self.inner
            .current_validation_operation
            .store(0, Ordering::SeqCst);
        self.inner
            .current_heartbeat_operation
            .store(0, Ordering::SeqCst);
        self.inner
            .current_offline_sync_operation
            .store(0, Ordering::SeqCst);
    }

    fn complete_local_deactivation(&self, expected_identity: &LicenseIdentity) -> Result<bool> {
        self.invalidate_license_operations();
        self.stop_background_tasks();
        self.clear_cached_license_with_denial(
            expected_identity,
            "deactivated",
            "License was deactivated on this installation",
        )
    }

    fn clear_cached_license_with_denial(
        &self,
        expected_identity: &LicenseIdentity,
        code: &str,
        message: &str,
    ) -> Result<bool> {
        self.clear_runtime_license_state();
        // This conditional mutation holds the cache's cross-process lock from
        // identity comparison through cleanup. A replacement activation from
        // another SDK instance therefore cannot be deleted in the gap.
        self.inner
            .cache
            .invalidate_and_clear(expected_identity, code, message, Utc::now())
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
        let retryable_server_or_transport =
            error.is_network_error() || matches!(error, Error::Api { status: 429, .. });
        match self.inner.config.offline_fallback_mode {
            OfflineFallbackMode::Always => retryable_server_or_transport,
            OfflineFallbackMode::NetworkOnly => error.is_network_error(),
        }
    }

    #[cfg(feature = "offline")]
    async fn validate_offline(
        &self,
        expected_identity: &LicenseIdentity,
    ) -> Result<ValidationResult> {
        debug!("Attempting offline validation");
        let expected_state_operation = self
            .inner
            .current_license_state_operation
            .load(Ordering::SeqCst);
        if !self.inner.cache.matches_identity(expected_identity) {
            return Err(Error::OperationSuperseded {
                operation: "offline validation",
            });
        }
        self.emit(Event::new(EventKind::OfflineValidationStart));
        let outcome = self.perform_offline_validation(expected_identity, expected_state_operation);
        match &outcome {
            Ok(result) if result.valid => {
                self.emit(Event::with_validation(
                    EventKind::OfflineValidationSuccess,
                    result.clone(),
                ));
                self.emit(Event::with_validation(
                    EventKind::ValidationOfflineSuccess,
                    result.clone(),
                ));
            }
            Ok(result) => {
                self.emit(Event::with_validation(
                    EventKind::OfflineValidationFailed,
                    result.clone(),
                ));
                self.emit(Event::with_validation(
                    EventKind::ValidationOfflineFailed,
                    result.clone(),
                ));
            }
            Err(error) => {
                self.emit(Event::with_error(
                    EventKind::OfflineValidationFailed,
                    error.to_string(),
                ));
                self.emit(Event::with_error(
                    EventKind::ValidationOfflineFailed,
                    error.to_string(),
                ));
            }
        }
        outcome
    }

    #[cfg(feature = "offline")]
    fn perform_offline_validation(
        &self,
        expected_identity: &LicenseIdentity,
        expected_state_operation: u64,
    ) -> Result<ValidationResult> {
        let mut last_invalid: Option<ValidationResult> = None;

        // A previously committed online or local denial is stronger than any
        // older signed offline grant. This also prevents an undeletable or
        // restored machine-file cache entry from resurrecting a license after
        // the API has marked it invalid or the host has reset/deactivated it.
        if let Some((mut denial_license, authoritative_denial)) = self
            .inner
            .cache
            .get_license()
            .filter(|license| license.identity() == *expected_identity)
            .and_then(|license| {
                license
                    .validation
                    .clone()
                    .filter(|validation| !validation.offline && !validation.valid)
                    .map(|validation| (license, validation))
            })
        {
            let _state_guard = self.lock_state_for_commit();
            if self
                .inner
                .current_license_state_operation
                .load(Ordering::SeqCst)
                != expected_state_operation
                || !self.inner.cache.matches_identity(expected_identity)
            {
                return Err(Error::OperationSuperseded {
                    operation: "offline validation",
                });
            }
            denial_license.validation = Some(authoritative_denial.clone());
            denial_license.trusted_license = None;
            self.set_runtime_license_state(denial_license, TrustedLicenseSource::FailClosedDenial);
            return Ok(authoritative_denial);
        }

        if let Some(machine_file) = self.inner.cache.get_machine_file() {
            match self.verify_machine_file(&machine_file, None, None, None) {
                Ok(verify_result) if verify_result.valid => {
                    if let Some(payload) = verify_result.payload.as_ref() {
                        let authorization_expires_at =
                            crate::offline::machine_file_authorization_deadline(
                                payload,
                                self.inner.config.max_offline_days,
                            )?;
                        let mut result =
                            crate::offline::machine_file_to_validation_result(payload)?;
                        if payload.license.is_none() {
                            debug!(
                                "Verified machine file omitted embedded license data; unsigned cached metadata is intentionally not used for grants"
                            );
                        }
                        self.finalize_offline_validation(
                            expected_identity,
                            expected_state_operation,
                            &mut result,
                            Some(authorization_expires_at),
                        )?;
                        return Ok(result);
                    }
                    last_invalid = Some(offline_invalid_result(
                        Some("missing_verified_payload".into()),
                        Some("Verified machine file did not contain a payload".into()),
                    ));
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
                        let authorization_expires_at =
                            crate::offline::offline_token_authorization_deadline(
                                &token,
                                self.inner.config.max_offline_days,
                            )?;
                        let mut result = crate::offline::token_to_validation_result(&token)?;
                        self.finalize_offline_validation(
                            expected_identity,
                            expected_state_operation,
                            &mut result,
                            Some(authorization_expires_at),
                        )?;
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
        self.finalize_offline_validation(
            expected_identity,
            expected_state_operation,
            &mut result,
            None,
        )?;
        Ok(result)
    }

    #[cfg(feature = "offline")]
    fn finalize_offline_validation(
        &self,
        expected_identity: &LicenseIdentity,
        expected_state_operation: u64,
        result: &mut ValidationResult,
        authorization_expires_at: Option<i64>,
    ) -> Result<()> {
        let _state_guard = self.lock_state_for_commit();
        result.offline = true;
        if self
            .inner
            .current_license_state_operation
            .load(Ordering::SeqCst)
            != expected_state_operation
            || !self.inner.cache.matches_identity(expected_identity)
        {
            return Err(Error::OperationSuperseded {
                operation: "offline validation",
            });
        }
        let mut runtime_license = self
            .inner
            .cache
            .get_license()
            .filter(|license| license.identity() == *expected_identity)
            .ok_or(Error::OperationSuperseded {
                operation: "offline validation",
            })?;

        let now = Utc::now().timestamp();
        if let Some(last_seen) = self.inner.cache.get_last_seen_timestamp() {
            let max_skew = duration_seconds_i64(self.inner.config.max_clock_skew);
            if now < last_seen.saturating_sub(max_skew) {
                *result = offline_invalid_result(
                    Some("clock_tamper".into()),
                    Some("Clock tampering detected".into()),
                );
            }
        }

        if result.valid {
            if !license_response_matches_active_grant(
                &result.license,
                &expected_identity.license_key,
                self.require_product_slug()?,
                &Utc::now(),
            ) {
                *result = offline_invalid_result(
                    Some("offline_identity_mismatch".into()),
                    Some("Offline artifact did not match the active license or product".into()),
                );
            } else {
                self.inner.cache.set_last_seen_timestamp(now)?;
            }
        }
        if !self
            .inner
            .cache
            .update_validation(expected_identity, result, Utc::now())?
        {
            return Err(Error::OperationSuperseded {
                operation: "offline validation",
            });
        }
        runtime_license.validation = Some(result.clone());
        runtime_license.trusted_license = result.valid.then(|| result.license.clone());
        self.set_runtime_license_state_until(
            runtime_license,
            if result.valid {
                TrustedLicenseSource::SignedOfflineArtifact
            } else {
                TrustedLicenseSource::FailClosedDenial
            },
            authorization_expires_at.filter(|_| result.valid),
        );
        Ok(())
    }

    #[cfg(feature = "offline")]
    fn resolve_public_key(&self, key_id: &str, override_key: Option<&str>) -> Option<String> {
        override_key
            .filter(|value| !value.is_empty())
            .map(ToString::to_string)
            .or_else(|| {
                (self.inner.config.signing_key_id.as_deref() == Some(key_id))
                    .then(|| self.inner.config.signing_public_key.clone())
                    .flatten()
            })
            .or_else(|| {
                self.inner
                    .runtime_signing_keys
                    .lock()
                    .ok()
                    .and_then(|keys| keys.get(key_id).cloned())
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

    fn runtime_license_state(&self) -> Option<RuntimeLicenseState> {
        let (state, transition_events) = {
            let mut guard = self
                .inner
                .runtime_license_state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let state = guard.as_mut()?;
            let now = state.observe_effective_now();
            let mut transition_events = Vec::new();
            let artifact_expired = state
                .authorization_expires_at
                .is_some_and(|deadline| now.timestamp() >= deadline);
            if artifact_expired {
                if let Some(validation) = state.license.validation.as_mut() {
                    if validation.valid {
                        validation.valid = false;
                        validation.code = Some("offline_artifact_expired".into());
                        validation.message =
                            Some("Signed offline authorization has expired".into());
                        validation.license.status = "inactive".into();
                        validation.license.active_seats = 0;
                        validation.license.active_entitlements.clear();
                        transition_events.push(Event::with_validation(
                            EventKind::OfflineValidationFailed,
                            validation.clone(),
                        ));
                        transition_events.push(Event::with_validation(
                            EventKind::ValidationOfflineFailed,
                            validation.clone(),
                        ));
                    }
                }
                state.license.trusted_license = None;
                // Persist this transition in process memory so callers receive
                // one terminal event instead of an event on every status read.
                state.authorization_expires_at = None;
                state.next_entitlement_transition_at = None;
            } else {
                let active_grant = state.license.validation.as_ref().is_some_and(|validation| {
                    !validation.valid
                        || license_response_matches_active_grant(
                            &validation.license,
                            &state.license.license_key,
                            &self.inner.config.product_slug,
                            &now,
                        )
                });
                if !active_grant {
                    if let Some(validation) = state.license.validation.as_mut() {
                        validation.valid = false;
                        validation.code = Some(if validation.offline {
                            "offline_license_grant_expired".into()
                        } else {
                            "license_grant_expired".into()
                        });
                        validation.message = Some("License authorization has expired".into());
                        validation.license.status = "inactive".into();
                        validation.license.active_seats = 0;
                        validation.license.active_entitlements.clear();
                        if validation.offline {
                            transition_events.push(Event::with_validation(
                                EventKind::OfflineValidationFailed,
                                validation.clone(),
                            ));
                            transition_events.push(Event::with_validation(
                                EventKind::ValidationOfflineFailed,
                                validation.clone(),
                            ));
                        } else {
                            transition_events.push(Event::with_validation(
                                EventKind::ValidationFailed,
                                validation.clone(),
                            ));
                        }
                    }
                    state.license.trusted_license = None;
                    state.authorization_expires_at = None;
                    state.next_entitlement_transition_at = None;
                } else if state
                    .next_entitlement_transition_at
                    .is_some_and(|deadline| now.timestamp() >= deadline)
                {
                    state.next_entitlement_transition_at =
                        next_entitlement_transition(&state.license, now.timestamp());
                    if let Some(validation) = state
                        .license
                        .validation
                        .clone()
                        .map(|validation| validation_for_observation(validation, &now))
                    {
                        transition_events.push(Event::with_validation(
                            EventKind::LicenseStateChanged,
                            validation,
                        ));
                    }
                }
            }
            (state.clone(), transition_events)
        };
        for event in transition_events {
            self.emit(event);
        }
        Some(state)
    }

    fn runtime_license(&self) -> Option<License> {
        self.runtime_license_state().map(|state| state.license)
    }

    fn set_runtime_license_state(&self, license: License, source: TrustedLicenseSource) {
        self.set_runtime_license_state_until(license, source, None);
    }

    fn set_runtime_license_state_until(
        &self,
        license: License,
        source: TrustedLicenseSource,
        authorization_expires_at: Option<i64>,
    ) {
        let observed_wall_time = Utc::now().timestamp();
        let next_entitlement_transition_at =
            next_entitlement_transition(&license, observed_wall_time);
        *self
            .inner
            .runtime_license_state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(RuntimeLicenseState {
            license,
            source,
            authorization_expires_at,
            observed_wall_time,
            observed_monotonic: Instant::now(),
            last_effective_timestamp: observed_wall_time,
            next_entitlement_transition_at,
        });
    }

    fn clear_runtime_license_state(&self) {
        *self
            .inner
            .runtime_license_state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = None;
    }

    #[cfg(feature = "offline")]
    fn current_trusted_license_record(&self) -> Option<(LicenseResponse, TrustedLicenseSource)> {
        self.current_authoritative_validation_record()
            .map(|(validation, source)| (validation.license, source))
    }

    fn current_authoritative_validation_record(
        &self,
    ) -> Option<(ValidationResult, TrustedLicenseSource)> {
        let state = self.runtime_license_state()?;
        let now = state.effective_now();
        state
            .license
            .validation
            .map(|validation| (validation_for_observation(validation, &now), state.source))
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
        let url = build_request_url(
            &self.inner.config.api_base_url,
            path,
            self.inner.config.verify_ssl,
        )?;

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
        if let Some(body) = json_body.as_ref() {
            if serde_json::to_vec(body)?.len() > MAX_REQUEST_BODY_BYTES {
                return Err(Error::RequestTooLarge {
                    limit_bytes: MAX_REQUEST_BODY_BYTES,
                });
            }
        }

        // Retry logic - rebuild request for each attempt (reqwest bodies can't always be cloned)
        let mut last_error = None;
        for attempt in 0..=self.inner.config.max_retries {
            if attempt > 0 {
                let delay = bounded_retry_delay(self.inner.config.retry_delay, attempt);
                tokio::time::sleep(delay).await;
                debug!("Retrying LicenseSeat request (attempt {attempt})");
            }

            // Build fresh request for each attempt
            // License keys are URL path segments in the public API. Never log
            // the path, even at debug level.
            debug!("Building LicenseSeat request (attempt {attempt})");
            let mut request = self.inner.http.request(method.clone(), url.clone());
            if let Some(ref body) = json_body {
                request = request.json(body);
            }

            match request.send().await {
                Ok(response) => {
                    let status = response.status().as_u16();
                    let success = response.status().is_success();
                    debug!("Received LicenseSeat response with status {status}");
                    if success {
                        self.set_online(true);
                    }
                    let response_body = match read_response_body_limited(response).await {
                        Ok(body) => body,
                        Err(error) => {
                            let response_was_reachable = !matches!(error, Error::Network(_));
                            self.set_online(response_was_reachable && (success || status < 500));
                            return Err(error);
                        }
                    };

                    if success {
                        return serde_json::from_slice(&response_body).map_err(Error::from);
                    }

                    let error_body = String::from_utf8_lossy(&response_body);
                    let (code, message, details) = parse_error_response_text(&error_body);
                    let message = sanitize_api_error_message(&message);

                    let error = Error::api(status, code, message, details);

                    if !is_retryable_request_error(&error)
                        || attempt == self.inner.config.max_retries
                    {
                        // A final 4xx proves the API is reachable. A final 5xx
                        // means the service is unavailable and should trigger
                        // the same support path as a transport outage.
                        self.set_online(status < 500);
                        return Err(error);
                    }

                    last_error = Some(error);
                }
                Err(e) => {
                    // reqwest errors may retain the full request URL. License
                    // keys are path segments, so strip the URL before the
                    // error can reach tracing, events, or a frontend.
                    let error = Error::Network(e.without_url());
                    if matches!(&error, Error::Network(source) if source.is_builder()) {
                        return Err(error);
                    }
                    if attempt == self.inner.config.max_retries {
                        self.set_online(false);
                        return Err(error);
                    }
                    last_error = Some(error);
                }
            }
        }

        Err(last_error
            .unwrap_or_else(|| Error::Configuration("request retry loop did not execute".into())))
    }
}

// ============================================================================
// Helper types and functions
// ============================================================================

fn verify_activation_response(
    activation: &ActivationResponse,
    requested_license_key: &str,
    requested_product_slug: &str,
    requested_fingerprint: &str,
) -> Result<()> {
    if activation.object != "activation"
        || activation.id.is_empty()
        || activation.deactivated_at.is_some()
        || !secure_string_eq(&activation.license_key, requested_license_key)
        || !secure_string_eq(&activation.device_id, requested_fingerprint)
        || !license_response_matches_active_grant(
            &activation.license,
            requested_license_key,
            requested_product_slug,
            &Utc::now(),
        )
    {
        return Err(Error::ResponseMismatch(
            "activation response did not match the requested active license, product, or installation"
                .into(),
        ));
    }
    Ok(())
}

fn verify_validation_response(
    result: &ValidationResult,
    requested_license_key: &str,
    requested_product_slug: &str,
    requested_fingerprint: Option<&str>,
    cached_identity: Option<&LicenseIdentity>,
) -> Result<()> {
    if result.object != "validation_result"
        || !license_response_matches_identity(
            &result.license,
            requested_license_key,
            requested_product_slug,
        )
    {
        return Err(Error::ResponseMismatch(
            "validation response did not match the requested license or product".into(),
        ));
    }

    if result.valid
        && (result.code.is_some()
            || result.message.is_some()
            || !license_response_matches_active_grant(
                &result.license,
                requested_license_key,
                requested_product_slug,
                &Utc::now(),
            ))
    {
        return Err(Error::ResponseMismatch(
            "validation response contained a contradictory valid decision".into(),
        ));
    }

    if let Some(activation) = result.activation.as_ref() {
        if (!activation.object.is_empty() && activation.object != "activation")
            || activation.id.is_empty()
            || activation.deactivated_at.is_some()
            || !secure_string_eq(&activation.license_key, requested_license_key)
            || requested_fingerprint
                .is_some_and(|fingerprint| !secure_string_eq(&activation.device_id, fingerprint))
            || cached_identity
                .is_some_and(|identity| !secure_string_eq(&activation.id, &identity.activation_id))
        {
            return Err(Error::ResponseMismatch(
                "validation response contained an activation for another installation".into(),
            ));
        }
    }
    Ok(())
}

fn verify_heartbeat_response(
    response: &HeartbeatResponse,
    requested_license_key: &str,
    requested_product_slug: &str,
) -> Result<()> {
    if response.object != "heartbeat"
        || !license_response_matches_active_grant(
            &response.license,
            requested_license_key,
            requested_product_slug,
            &Utc::now(),
        )
    {
        return Err(Error::ResponseMismatch(
            "heartbeat response did not match the active license or product".into(),
        ));
    }
    Ok(())
}

fn secure_string_eq(left: &str, right: &str) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.as_bytes()
        .iter()
        .zip(right.as_bytes())
        .fold(0_u8, |difference, (left, right)| {
            difference | (left ^ right)
        })
        == 0
}

fn license_response_matches_identity(
    license: &LicenseResponse,
    expected_license_key: &str,
    expected_product_slug: &str,
) -> bool {
    license.object == "license"
        && secure_string_eq(&license.key, expected_license_key)
        && secure_string_eq(&license.product.slug, expected_product_slug)
        && entitlement_records_are_well_formed(&license.active_entitlements)
}

fn entitlement_records_are_well_formed(entitlements: &[Entitlement]) -> bool {
    let mut keys = HashSet::with_capacity(entitlements.len());
    entitlements.iter().all(|entitlement| {
        !entitlement.key.is_empty()
            && entitlement.key.len() <= 255
            && entitlement.key.trim() == entitlement.key
            && !entitlement.key.chars().any(char::is_control)
            && keys.insert(entitlement.key.as_str())
    })
}

fn license_response_matches_active_grant(
    license: &LicenseResponse,
    expected_license_key: &str,
    expected_product_slug: &str,
    now: &chrono::DateTime<Utc>,
) -> bool {
    license_response_matches_identity(license, expected_license_key, expected_product_slug)
        && license.status.eq_ignore_ascii_case("active")
        && license.starts_at.is_none_or(|starts_at| starts_at <= *now)
        && license
            .expires_at
            .is_none_or(|expires_at| expires_at > *now)
}

fn client_status_for_status(status: &LicenseStatus) -> ClientStatus {
    match status {
        LicenseStatus::Active { .. } => ClientStatus::Active,
        LicenseStatus::OfflineValid { .. } => ClientStatus::OfflineValid,
        LicenseStatus::OfflineInvalid { .. } => ClientStatus::OfflineInvalid,
        LicenseStatus::Inactive { .. } => ClientStatus::Inactive,
        LicenseStatus::Invalid { .. } => ClientStatus::Invalid,
        LicenseStatus::Pending { .. } => ClientStatus::Pending,
    }
}

fn license_status_for_observation(
    license: &License,
    expected_product_slug: &str,
    now: &chrono::DateTime<Utc>,
) -> LicenseStatus {
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

    if !license_response_matches_active_grant(
        &validation.license,
        &license.license_key,
        expected_product_slug,
        now,
    ) {
        let message = "Cached validation is not an active grant".to_string();
        return if validation.offline {
            LicenseStatus::OfflineInvalid { message }
        } else {
            LicenseStatus::Invalid { message }
        };
    }

    let details = LicenseStatusDetails {
        license: license.license_key.clone(),
        device: license.device_id.clone(),
        activated_at: license.activated_at,
        last_validated: license.last_validated,
        entitlements: validation
            .license
            .active_entitlements
            .iter()
            .filter(|entitlement| entitlement.expires_at.is_none_or(|expiry| expiry > *now))
            .cloned()
            .collect(),
    };

    if validation.offline {
        LicenseStatus::OfflineValid { details }
    } else {
        LicenseStatus::Active { details }
    }
}

fn next_entitlement_transition(license: &License, after: i64) -> Option<i64> {
    license
        .validation
        .as_ref()
        .filter(|validation| validation.valid)
        .into_iter()
        .flat_map(|validation| validation.license.active_entitlements.iter())
        .filter_map(|entitlement| entitlement.expires_at.map(|expiry| expiry.timestamp()))
        .filter(|expiry| *expiry > after)
        .min()
}

fn validation_for_observation(
    mut validation: ValidationResult,
    now: &chrono::DateTime<Utc>,
) -> ValidationResult {
    validation
        .license
        .active_entitlements
        .retain(|entitlement| entitlement.expires_at.is_none_or(|expiry| expiry > *now));
    validation
}

fn effective_runtime_timestamp(
    wall_now: i64,
    observed_wall_time: i64,
    elapsed: i64,
    last_effective_timestamp: i64,
) -> i64 {
    wall_now
        .max(observed_wall_time.saturating_add(elapsed.max(0)))
        .max(last_effective_timestamp)
        .min(chrono::DateTime::<Utc>::MAX_UTC.timestamp())
}

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

fn build_http_client(config: &Config) -> Result<reqwest::Client> {
    let mut headers = HeaderMap::new();

    headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    let user_agent = HeaderValue::from_str(&format!("licenseseat-rust/{}", crate::VERSION))
        .map_err(|error| Error::Configuration(format!("invalid SDK user agent: {error}")))?;
    headers.insert(USER_AGENT, user_agent);

    if !config.api_key.is_empty() {
        let value =
            HeaderValue::from_str(&format!("Bearer {}", config.api_key)).map_err(|error| {
                Error::Configuration(format!("api_key cannot be sent in an HTTP header: {error}"))
            })?;
        headers.insert(AUTHORIZATION, value);
    }

    let builder = reqwest::Client::builder()
        .default_headers(headers)
        .timeout(config.request_timeout)
        // Licensing requests contain a publishable credential plus license
        // keys/fingerprints in their path or body. Do not let an unexpected
        // 30x replay that data to a different origin (or silently change the
        // HTTP method on a legacy redirect). The configured API endpoint must
        // be canonical.
        .redirect(reqwest::redirect::Policy::none());
    #[cfg(any(feature = "rustls", feature = "native-tls"))]
    let builder = builder.danger_accept_invalid_certs(
        !config.verify_ssl
            && validate_api_base_url(&config.api_base_url, config.verify_ssl).is_ok(),
    );
    // Cargo features are additive. If both backends are enabled through a
    // dependency graph, keep the crate's default rustls behavior explicit.
    #[cfg(feature = "rustls")]
    let builder = builder.use_rustls_tls();
    #[cfg(all(not(feature = "rustls"), feature = "native-tls"))]
    let builder = builder.use_native_tls();

    builder.build().map_err(Error::from)
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

fn sanitize_api_error_message(message: &str) -> String {
    let trimmed = message.trim();
    let lower_prefix = trimmed
        .chars()
        .take(32)
        .collect::<String>()
        .to_ascii_lowercase();
    if lower_prefix.starts_with("<!doctype html") || lower_prefix.starts_with("<html") {
        return "License server returned an HTML error response".into();
    }

    let mut sanitized = trimmed
        .chars()
        .map(|character| {
            if character.is_control() {
                ' '
            } else {
                character
            }
        })
        .take(MAX_API_ERROR_MESSAGE_CHARS + 1)
        .collect::<String>();
    if sanitized.chars().count() > MAX_API_ERROR_MESSAGE_CHARS {
        sanitized = sanitized
            .chars()
            .take(MAX_API_ERROR_MESSAGE_CHARS.saturating_sub(3))
            .collect();
        sanitized.push_str("...");
    }
    if sanitized.is_empty() {
        "Unknown error".into()
    } else {
        sanitized
    }
}

async fn read_response_body_limited(mut response: reqwest::Response) -> Result<Vec<u8>> {
    if response
        .content_length()
        .is_some_and(|length| length > MAX_RESPONSE_BODY_BYTES as u64)
    {
        return Err(Error::ResponseTooLarge {
            limit_bytes: MAX_RESPONSE_BODY_BYTES,
        });
    }

    let mut body = Vec::with_capacity(
        response
            .content_length()
            .and_then(|length| usize::try_from(length).ok())
            .unwrap_or_default()
            .min(MAX_RESPONSE_BODY_BYTES),
    );
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|error| Error::Network(error.without_url()))?
    {
        let next_length = body
            .len()
            .checked_add(chunk.len())
            .ok_or(Error::ResponseTooLarge {
                limit_bytes: MAX_RESPONSE_BODY_BYTES,
            })?;
        if next_length > MAX_RESPONSE_BODY_BYTES {
            return Err(Error::ResponseTooLarge {
                limit_bytes: MAX_RESPONSE_BODY_BYTES,
            });
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
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
    if let Some(ttl_days) = ttl_days {
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

fn build_request_url(base_url: &str, path: &str, verify_ssl: bool) -> Result<url::Url> {
    validate_api_base_url(base_url, verify_ssl)?;
    let normalized_base = base_url.trim_end_matches('/');
    let normalized_path = path.trim_start_matches('/');
    let combined = if normalized_path.is_empty() {
        normalized_base.to_string()
    } else {
        format!("{normalized_base}/{normalized_path}")
    };

    let url = url::Url::parse(&combined).map_err(Error::from)?;
    validate_api_endpoint(&url, verify_ssl)?;
    Ok(url)
}

fn validate_api_base_url(base_url: &str, verify_ssl: bool) -> Result<url::Url> {
    if base_url.len() > 2048 || base_url.trim() != base_url {
        return Err(Error::Configuration(
            "api_base_url must be at most 2048 characters and contain no surrounding whitespace"
                .into(),
        ));
    }
    let url = url::Url::parse(base_url.trim()).map_err(Error::from)?;
    if url.cannot_be_a_base()
        || url.host().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(Error::Configuration(
            "api_base_url must be an absolute HTTP(S) origin/path without credentials, query, or fragment"
                .into(),
        ));
    }
    validate_api_endpoint(&url, verify_ssl)?;
    Ok(url)
}

fn validate_api_endpoint(url: &url::Url, verify_ssl: bool) -> Result<()> {
    let is_loopback = match url.host() {
        Some(url::Host::Domain(host)) => host.eq_ignore_ascii_case("localhost"),
        Some(url::Host::Ipv4(host)) => host.is_loopback(),
        Some(url::Host::Ipv6(host)) => host.is_loopback(),
        None => false,
    };

    match url.scheme() {
        "https" => {}
        "http" if is_loopback => {}
        _ => {
            return Err(Error::Configuration(
                "api_base_url must use HTTPS; plain HTTP is allowed only for loopback development servers"
                    .into(),
            ));
        }
    }
    if !verify_ssl && !is_loopback {
        return Err(Error::Configuration(
            "verify_ssl=false is allowed only for loopback development servers".into(),
        ));
    }
    Ok(())
}

fn is_retryable_request_error(error: &Error) -> bool {
    matches!(
        error,
        Error::Network(_)
            | Error::Api {
                status: 408 | 429 | 500..=599,
                ..
            }
    )
}

fn bounded_retry_delay(initial: Duration, attempt: u32) -> Duration {
    const MAX_RETRY_DELAY: Duration = Duration::from_secs(30);
    let exponent = attempt.saturating_sub(1).min(31);
    let multiplier = 1_u32.checked_shl(exponent).unwrap_or(u32::MAX);
    initial
        .checked_mul(multiplier)
        .unwrap_or(MAX_RETRY_DELAY)
        .min(MAX_RETRY_DELAY)
}

#[cfg(feature = "offline")]
fn duration_seconds_i64(duration: Duration) -> i64 {
    i64::try_from(duration.as_secs()).unwrap_or(i64::MAX)
}

fn effective_storage_prefix(config: &Config) -> String {
    if config.storage_prefix == "licenseseat_" && !config.product_slug.trim().is_empty() {
        LicenseCache::product_scoped_prefix(config.product_slug.trim())
    } else {
        config.storage_prefix.clone()
    }
}

fn cached_license_matches_product(license: &License, product_slug: &str) -> bool {
    license
        .trusted_license
        .as_ref()
        .or_else(|| license.validation.as_ref().map(|result| &result.license))
        .is_some_and(|trusted| trusted.product.slug == product_slug)
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

fn verify_release_response(
    release: &Release,
    expected_product_slug: &str,
    expected_channel: Option<&str>,
    expected_platform: Option<&str>,
) -> Result<()> {
    if release.object != "release"
        || release.version.trim().is_empty()
        || release.channel.trim().is_empty()
        || release.platform.trim().is_empty()
        || !secure_string_eq(&release.product_slug, expected_product_slug)
        || expected_channel
            .filter(|value| !value.is_empty())
            .is_some_and(|channel| release.channel != channel)
        || expected_platform
            .filter(|value| !value.is_empty())
            .is_some_and(|platform| release.platform != platform)
    {
        return Err(Error::ResponseMismatch(
            "release response did not match the requested product or filters".into(),
        ));
    }
    Ok(())
}

fn select_fingerprint_alias<'a>(
    fingerprint: Option<&'a str>,
    device_id: Option<&'a str>,
    device_fingerprint: Option<&'a str>,
) -> Result<Option<&'a str>> {
    for value in [fingerprint, device_id, device_fingerprint]
        .into_iter()
        .flatten()
    {
        validate_fingerprint(value)?;
    }

    let selected = fingerprint.or(device_id).or(device_fingerprint);

    if let Some(selected) = selected {
        if [fingerprint, device_id, device_fingerprint]
            .into_iter()
            .flatten()
            .any(|value| value != selected)
        {
            return Err(Error::Configuration(
                "fingerprint, device_id, and device_fingerprint must match when more than one alias is provided"
                    .into(),
            ));
        }
    }

    Ok(selected)
}

fn validate_request_identifier(field: &str, value: &str) -> Result<()> {
    if value.trim().is_empty() {
        return Err(Error::Configuration(format!("{field} is required")));
    }
    if value.trim() != value || value.len() > 255 || value.chars().any(char::is_control) {
        return Err(Error::Configuration(format!(
            "{field} must be 1-255 non-control characters without surrounding whitespace"
        )));
    }
    Ok(())
}

fn validate_optional_request_identifier(field: &str, value: Option<&str>) -> Result<()> {
    if let Some(value) = value.filter(|value| !value.is_empty()) {
        validate_request_identifier(field, value)?;
    }
    Ok(())
}

fn is_valid_fingerprint(value: &str) -> bool {
    value.trim() == value
        && (8..=255).contains(&value.len())
        && !value.chars().any(char::is_control)
}

fn validate_fingerprint(value: &str) -> Result<()> {
    if is_valid_fingerprint(value) {
        Ok(())
    } else {
        Err(Error::Configuration(
            "fingerprint must be 8-255 non-control characters without surrounding whitespace"
                .into(),
        ))
    }
}

#[cfg(feature = "offline")]
fn parse_machine_file_response(body: &serde_json::Value) -> Result<MachineFile> {
    let data = body.get("data").unwrap_or(body);
    if data.get("type").and_then(|value| value.as_str()) != Some("machine-files") {
        return Err(Error::ResponseMismatch(
            "machine-file response had an invalid JSON:API type".into(),
        ));
    }
    let attributes = data
        .get("attributes")
        .and_then(|value| value.as_object())
        .ok_or_else(|| Error::ResponseMismatch("machine-file attributes were missing".into()))?;

    let relationships = data
        .get("relationships")
        .and_then(|value| value.as_object())
        .ok_or_else(|| Error::ResponseMismatch("machine-file relationships were missing".into()))?;

    let relationship_id = |name: &str, expected_type: &str| -> Result<String> {
        let relationship = relationships
            .get(name)
            .and_then(|value| value.get("data"))
            .and_then(|value| value.as_object())
            .ok_or_else(|| {
                Error::ResponseMismatch(format!("machine-file {name} relationship was missing"))
            })?;
        if relationship.get("type").and_then(|value| value.as_str()) != Some(expected_type) {
            return Err(Error::ResponseMismatch(format!(
                "machine-file {name} relationship had an invalid type"
            )));
        }
        relationship
            .get("id")
            .and_then(|value| value.as_str())
            .filter(|value| !value.is_empty())
            .map(ToString::to_string)
            .ok_or_else(|| {
                Error::ResponseMismatch(format!("machine-file {name} relationship had no ID"))
            })
    };

    let certificate = attributes
        .get("certificate")
        .and_then(|value| value.as_str())
        .filter(|value| !value.is_empty())
        .ok_or_else(|| Error::ResponseMismatch("machine-file certificate was missing".into()))?;
    let algorithm = attributes
        .get("algorithm")
        .and_then(|value| value.as_str())
        .filter(|value| !value.is_empty())
        .ok_or_else(|| Error::ResponseMismatch("machine-file algorithm was missing".into()))?;
    let ttl = attributes
        .get("ttl")
        .and_then(|value| value.as_i64())
        .filter(|value| *value > 0)
        .ok_or_else(|| Error::ResponseMismatch("machine-file TTL was invalid".into()))?;
    let issued_at = attributes
        .get("issued")
        .and_then(|value| value.as_str())
        .and_then(parse_rfc3339)
        .ok_or_else(|| Error::ResponseMismatch("machine-file issue time was invalid".into()))?;
    let expires_at = attributes
        .get("expiry")
        .and_then(|value| value.as_str())
        .and_then(parse_rfc3339)
        .ok_or_else(|| Error::ResponseMismatch("machine-file expiry was invalid".into()))?;
    if expires_at <= issued_at {
        return Err(Error::ResponseMismatch(
            "machine-file response had a non-positive validity window".into(),
        ));
    }

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

#[cfg(feature = "offline")]
fn validate_positive_days(field: &str, value: Option<i64>) -> Result<()> {
    if value.is_some_and(|days| days <= 0) {
        return Err(Error::Configuration(format!(
            "{field} must be greater than zero when provided"
        )));
    }
    Ok(())
}

fn is_revocation_code(code: Option<&str>) -> bool {
    code.is_some_and(|code| {
        matches!(
            code.to_ascii_lowercase().as_str(),
            "revoked" | "suspended" | "license_revoked" | "license_suspended"
        )
    })
}

/// Return true only for API outcomes that authoritatively prove that the
/// currently cached activation can no longer be used. Generic 404/422 errors
/// are intentionally excluded: an intermediary, route mismatch, malformed
/// request, or server regression must never erase locally verifiable state.
fn is_authoritative_invalidation_error(error: &Error) -> bool {
    let Error::Api { status, code, .. } = error else {
        return false;
    };

    // These are the only status classes used by the LicenseSeat API for
    // authoritative missing/invalid license-state decisions. Never trust a
    // denial-looking error code attached to authentication, rate-limit, or
    // server-failure responses: a proxy or regressed server could otherwise
    // erase a valid local activation with a non-authoritative response.
    if !matches!(*status, 404 | 410 | 422) {
        return false;
    }

    code.as_deref().is_some_and(|code| {
        matches!(
            code.to_ascii_lowercase().as_str(),
            "activation_not_found"
                | "device_not_activated"
                | "expired"
                | "invalid_license"
                | "license_expired"
                | "license_invalid"
                | "license_not_found"
                | "license_revoked"
                | "license_suspended"
                | "not_active"
                | "product_mismatch"
                | "revoked"
                | "suspended"
        )
    })
}

#[cfg(feature = "offline")]
fn parse_rfc3339(value: &str) -> Option<chrono::DateTime<chrono::Utc>> {
    chrono::DateTime::parse_from_rfc3339(value)
        .ok()
        .map(|value| value.with_timezone(&chrono::Utc))
}

#[cfg(test)]
mod runtime_clock_tests {
    use super::effective_runtime_timestamp;

    #[test]
    fn runtime_authorization_clock_never_moves_backwards() {
        assert_eq!(effective_runtime_timestamp(900, 1_000, 20, 1_000), 1_020);
        assert_eq!(effective_runtime_timestamp(1_100, 1_000, 20, 1_000), 1_100);
        assert_eq!(effective_runtime_timestamp(900, 1_000, -20, 1_000), 1_000);

        // A previously observed forward wall-clock jump remains authoritative
        // after the wall clock is moved backwards again.
        assert_eq!(effective_runtime_timestamp(950, 1_000, 21, 1_100), 1_100);
    }
}
