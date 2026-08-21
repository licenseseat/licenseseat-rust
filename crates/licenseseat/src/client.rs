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
const MAX_API_ERROR_MESSAGE_BYTES: usize = 1_024;
const MAX_API_ERROR_DETAILS_BYTES: usize = 64 * 1024;
const MAX_RESPONSE_METADATA_BYTES: usize = 1024 * 1024;
const MAX_JSON_DEPTH: usize = 20;
const MAX_JSON_NODES: usize = 10_000;
#[cfg(feature = "offline")]
const MAX_MACHINE_FILE_TTL_SECONDS: i64 = 36_600 * 86_400;

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
    // Snapshot of the untrusted recovery candidate observed at construction.
    // A running instance never re-reads mutable cache state written by another
    // process as if it were its own current license.
    recovery_license: Mutex<Option<License>>,
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
        // Persisted HTTPS response fields are writable local recovery hints,
        // never an authorization root. Keep only the activation identity that
        // is required to revalidate the same seat; a fresh process must obtain
        // an online decision or verify a signed offline artifact before it can
        // expose trusted status or entitlements.
        if let Some(license) = startup_license.as_mut() {
            // A persisted denial is safe to retain: local tampering can only
            // remove access, and retaining the tombstone prevents an older
            // signed artifact from resurrecting access after revocation or
            // reset. Positive unsigned decisions are always discarded.
            if license
                .validation
                .as_ref()
                .is_none_or(|validation| validation.valid)
            {
                license.validation = None;
            }
            license.trusted_license = None;
            cache.set_license(license)?;
        }
        config.storage_prefix = effective_prefix;
        let fingerprint = config
            .device_identifier
            .as_deref()
            .filter(|value| !value.is_empty())
            .map(ToString::to_string)
            .map(Ok)
            .unwrap_or_else(|| {
                let legacy_identifier = startup_license
                    .as_ref()
                    .map(|license| license.device_id.as_str());
                cache.get_or_create_installation_identifier(legacy_identifier)
            })?;
        Self::build_with_cache(config, fingerprint, cache, startup_license)
    }

    fn build_with_cache(
        config: Config,
        fingerprint: String,
        cache: LicenseCache,
        startup_license: Option<License>,
    ) -> Result<Self> {
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
            recovery_license: Mutex::new(startup_license.clone()),
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
        if let Some(license) = startup_license {
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
        // Explicit new aliases were strictly validated above; the fallback may
        // be a short installation identifier adopted from an existing cached
        // activation, which stays acceptable.
        self.validate_request_fingerprint(&device_id)?;
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
                    let weak = Arc::downgrade(&self.inner);
                    let generation = self.inner.support_tasks_generation.load(Ordering::SeqCst);
                    tokio::spawn(async move {
                        Self::sync_offline_assets_after_activation(weak, generation).await;
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

        let path = build_license_action_path(product_slug, "validate");
        let mut body = fingerprint_alias_payload(&device_id, false);
        body["license_key"] = serde_json::json!(license_key);
        let body = Some(body);

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
                    let authoritative_revocation =
                        !result.valid && is_revocation_code(result.code.as_deref());
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
                    if authoritative_revocation {
                        if let Err(error) = self.clear_cached_license_with_denial(
                            identity,
                            result.code.as_deref().unwrap_or("license_revoked"),
                            result.message.as_deref().unwrap_or("License revoked"),
                        ) {
                            self.emit(Event::with_error(EventKind::SdkError, error.to_string()));
                            // If hostile filesystem state prevents cleanup, the
                            // persisted denial tombstone and matching runtime
                            // denial remain authoritative. This exposes no
                            // grant while preventing an older signed artifact
                            // from being resurrected in the current process.
                            self.set_runtime_license_state(
                                runtime_license,
                                TrustedLicenseSource::FailClosedDenial,
                            );
                        }
                    } else {
                        self.set_runtime_license_state(
                            runtime_license,
                            TrustedLicenseSource::OnlineResponse,
                        );
                    }
                }
                if result.valid && stateful {
                    // The server has just accepted this authenticated
                    // validation, so the local clock that observed the
                    // acceptance is the best available trust anchor: re-anchor
                    // the rollback watermark (possibly lowering it) instead of
                    // ratcheting. This recovers installations whose watermark
                    // was poisoned by a transiently future-set clock. Offline
                    // verification keeps the ratcheting
                    // `set_last_seen_timestamp`. See
                    // `LicenseCache::anchor_last_seen_timestamp`.
                    if let Err(error) = self
                        .inner
                        .cache
                        .anchor_last_seen_timestamp(observed_at.timestamp())
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
        // Deactivation targets an existing seat, so a fingerprint sourced from
        // (or equal to) the cached activation is exempt from the new-input
        // length floor; `deactivate()` forwards the cached `device_id` here.
        if let Some(fingerprint) = fingerprint {
            self.validate_request_fingerprint(fingerprint)?;
        }

        let resolved_fingerprint = self.resolve_request_fingerprint(fingerprint);
        self.validate_request_fingerprint(&resolved_fingerprint)?;
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

        let path = build_license_action_path(product_slug, "deactivate");
        let mut body = fingerprint_alias_payload(&resolved_fingerprint, true);
        body["license_key"] = serde_json::json!(license_key);

        let outcome = match self.post::<DeactivationResponse>(&path, Some(body)).await {
            Ok(response) => (|| -> Result<()> {
                let _state_guard = self.lock_state_for_commit();
                self.ensure_current_target_operation(
                    &self.inner.current_deactivation_operation,
                    operation,
                    stateful,
                    "deactivation",
                )?;
                verify_deactivation_response(
                    &response,
                    cached_identity
                        .as_ref()
                        .map(|identity| identity.activation_id.as_str()),
                )?;
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
        // Heartbeats renew an existing seat: fingerprints sourced from the
        // cached activation (including the short pre-floor ones forwarded by
        // `heartbeat()` and the background heartbeat task) stay acceptable.
        if let Some(fingerprint) = fingerprint {
            self.validate_request_fingerprint(fingerprint)?;
        }
        let resolved_fingerprint = self.resolve_request_fingerprint(fingerprint);
        self.validate_request_fingerprint(&resolved_fingerprint)?;
        let (operation, cached_license) =
            self.begin_target_operation(&self.inner.current_heartbeat_operation, |license| {
                license.license_key == license_key && license.device_id == resolved_fingerprint
            });
        let cached_identity = cached_license.as_ref().map(License::identity);
        let stateful = cached_identity.is_some();
        let _operation_guard =
            OperationGuard::new(&self.inner.current_heartbeat_operation, operation);

        let path = build_license_action_path(product_slug, "heartbeat");
        let mut body = fingerprint_alias_payload(&resolved_fingerprint, true);
        body["license_key"] = serde_json::json!(license_key);

        let outcome = match self.post::<HeartbeatResponse>(&path, Some(body)).await {
            Ok(response) => (|| -> Result<HeartbeatResponse> {
                let _state_guard = self.lock_state_for_commit();
                self.ensure_current_target_operation(
                    &self.inner.current_heartbeat_operation,
                    operation,
                    stateful,
                    "heartbeat",
                )?;
                if let Err(error) = verify_heartbeat_response(&response, license_key, product_slug)
                {
                    // An authenticated heartbeat for the exact current
                    // license/product is authoritative when it reports that
                    // the grant is no longer active. Clear both runtime and
                    // signed-offline state before returning the contract error.
                    if cached_identity.as_ref().is_some_and(|identity| {
                        response.object == "heartbeat"
                            && license_response_matches_identity(
                                &response.license,
                                license_key,
                                product_slug,
                            )
                            && !license_response_is_currently_active(&response.license)
                            && identity.license_key == license_key
                    }) {
                        let identity = cached_identity
                            .as_ref()
                            .expect("checked current heartbeat identity");
                        self.stop_background_tasks();
                        self.clear_cached_license_with_denial(
                            identity,
                            response.license.status.as_str(),
                            "Heartbeat returned an inactive license",
                        )?;
                    }
                    return Err(error);
                }
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
                    // A server-accepted heartbeat is an authoritative online
                    // success like validation above: re-anchor (possibly
                    // lower) the rollback watermark rather than ratcheting.
                    // See `LicenseCache::anchor_last_seen_timestamp`.
                    if let Err(error) = self
                        .inner
                        .cache
                        .anchor_last_seen_timestamp(observed_at.timestamp())
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
        self.runtime_license().or_else(|| {
            self.inner
                .recovery_license
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone()
        })
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
        // `has_more` and `next_cursor` are deliberately not cross-checked. The
        // server's `releases_controller#index` derives `has_more` from the page
        // count while hard-coding `next_cursor: nil`, so a truthful `has_more`
        // with no cursor is the normal response for a paginated product.
        // Requiring the pair to agree rejected valid responses; callers that
        // need to page must treat a missing cursor as "no cursor available".
        if releases.object != "list"
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
        let token: DownloadToken = self.post(&path, Some(body)).await?;
        validate_download_token_response(&token)?;
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
        let cleanup = if let Some(identity) = identity.as_ref() {
            self.inner
                .cache
                .invalidate_and_clear(
                    identity,
                    "locally_reset",
                    "License state was reset locally",
                    Utc::now(),
                )
                .map(|_| ())
        } else {
            self.inner.cache.clear()
        };
        if let Err(error) = cleanup {
            // `invalidate_and_clear` persists a denial before destructive
            // cleanup. If hostile filesystem state blocks deletion, retain
            // only that explicit fail-closed tombstone as a diagnostic
            // recovery candidate; never resurrect the prior positive grant.
            if let Some(denial) = self.inner.cache.get_license().filter(|license| {
                license.trusted_license.is_none()
                    && license
                        .validation
                        .as_ref()
                        .is_some_and(|validation| !validation.valid)
            }) {
                *self
                    .inner
                    .recovery_license
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(denial);
            }
            return Err(error);
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

    /// Fetch the offline artifact right after activation, retrying briefly.
    ///
    /// This was a single attempt whose failure was logged and dropped. The only
    /// other chance was `offline_refresh_loop`, one whole
    /// `offline_token_refresh_interval` later — 72 hours on hosts that raise it
    /// from the default. So an activation that happened to land in a network
    /// gap left the install with no cached artifact for days, and any
    /// validation in that window had nothing to fall back on: exactly the
    /// state that used to surface as a bogus denial.
    ///
    /// Short, bounded, and front-loaded, because a gap at activation is
    /// normally over in seconds. Anything still failing after this belongs to
    /// the refresh loop rather than to a task kept alive indefinitely.
    #[cfg(feature = "offline")]
    async fn sync_offline_assets_after_activation(weak: Weak<LicenseSeatInner>, generation: u64) {
        const RETRY_DELAYS: [Duration; 4] = [
            Duration::from_secs(5),
            Duration::from_secs(30),
            Duration::from_secs(120),
            Duration::from_secs(600),
        ];

        let mut delays = RETRY_DELAYS.iter().copied();
        let mut attempt = 1usize;

        loop {
            // Rebuilt per attempt from a Weak so a retry schedule can never be
            // what keeps the SDK alive after the host drops it.
            let outcome = {
                let Some(inner) = weak.upgrade() else {
                    return;
                };
                let sdk = Self { inner };
                if !sdk.support_tasks_should_continue(generation) {
                    debug!("Offline asset sync stopping: background tasks superseded");
                    return;
                }
                sdk.sync_offline_assets().await
            };

            match outcome {
                Ok(()) => return,
                // The activation this artifact would belong to is gone or has
                // been replaced. Whatever replaced it runs its own sync.
                Err(error @ (Error::NoActiveLicense | Error::OperationSuperseded { .. })) => {
                    debug!(
                        "Offline asset sync stopping: {}",
                        error.redacted_log_summary()
                    );
                    return;
                }
                Err(error) => {
                    let Some(delay) = delays.next() else {
                        warn!(
                            "Failed to sync offline assets after {} attempts, leaving it to the refresh loop: {}",
                            attempt,
                            error.redacted_log_summary()
                        );
                        return;
                    };
                    warn!(
                        "Offline asset sync attempt {} failed, retrying in {:?}: {}",
                        attempt,
                        delay,
                        error.redacted_log_summary()
                    );
                    tokio::time::sleep(delay).await;
                    attempt += 1;
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
        validate_ttl_days(ttl_days)?;
        // Offline tokens are issued for an existing activation, so a
        // fingerprint sourced from the cached record is exempt from the
        // new-input length floor.
        if let Some(fingerprint) = fingerprint {
            self.validate_request_fingerprint(fingerprint)?;
        }
        // Automatic refresh and host-initiated checkout share one state slot.
        // Serialize them so a refresh scheduled immediately after activation
        // cannot supersede a foreground operation that the host is awaiting.
        let _request_guard = self.inner.offline_request_lock.lock().await;
        let fingerprint = fingerprint
            .filter(|value| !value.is_empty())
            .map(ToString::to_string)
            .unwrap_or_else(|| self.resolve_request_fingerprint(None));
        self.validate_request_fingerprint(&fingerprint)?;
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

        let path = build_license_action_path(product_slug, "offline-token");
        let body = build_offline_token_request(license_key, &fingerprint, ttl_days);
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
        validate_ttl_days(ttl_days)?;
        validate_grace_period_days(grace_period_days)?;
        let _request_guard = self.inner.offline_request_lock.lock().await;
        let fingerprint = select_fingerprint_alias(
            fingerprint.as_deref(),
            device_id.as_deref(),
            device_fingerprint.as_deref(),
        )?
        .map(ToString::to_string)
        .unwrap_or_else(|| self.resolve_request_fingerprint(None));
        // Explicit new aliases were strictly validated above; the fallback
        // resolved from the cached activation is exempt from the new-input
        // length floor so pre-floor activations can still check out and
        // refresh machine files.
        self.validate_request_fingerprint(&fingerprint)?;
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

            let cached_license = self.current_license();
            if cached_license.as_ref().is_some_and(|license| {
                !secure_string_eq(&offline_token.token.license_key, &license.license_key)
            }) {
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
            let expected_fingerprint = cached_license
                .as_ref()
                .map(|license| license.device_id.as_str())
                .unwrap_or(self.inner.fingerprint.as_str());
            if !secure_string_eq(token_fingerprint, expected_fingerprint) {
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
            // Bind verification to the expected activation's license key.
            // Without it, `verify_machine_file_inner` falls back to the
            // artifact's own unsigned metadata, which makes the expected
            // license check vacuous for a restored foreign-license artifact:
            // it would emit `MachineFileVerified` and only fail later in
            // `finalize_offline_validation`.
            match self.verify_machine_file(
                &machine_file,
                None,
                Some(&expected_identity.license_key),
                None,
            ) {
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

        // Nothing to inspect at all. Every branch above examined an artifact
        // and rejected it, which is a verdict; this is the absence of one.
        //
        // `OfflineFallbackMode`'s contract is explicit that "only specifically
        // recognized authoritative license denials clear the last trusted
        // grant", so committing this as a denial — which is what
        // `finalize_offline_validation` does with any invalid result — would
        // revoke a perfectly good license because the network happened to be
        // down before the first machine-file sync succeeded. Report it as an
        // error instead and leave the established grant exactly as it was.
        let Some(mut result) = last_invalid else {
            return Err(Error::NoOfflineArtifact);
        };
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
                // Offline verification is not authoritative for time: it may
                // only ratchet the watermark forward. Lowering the watermark
                // is reserved for authoritative online successes
                // (`LicenseCache::anchor_last_seen_timestamp`), otherwise a
                // rolled-back clock plus a re-imported signed artifact could
                // stretch the offline window.
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

    /// Validate a fingerprint that is about to be sent in a request.
    ///
    /// New fingerprints keep the strict 8-255 character configuration floor
    /// (`validate_fingerprint`). A fingerprint that matches this SDK's stable
    /// installation identifier or the existing cached activation record is
    /// exempt from the length floor: such identifiers were accepted by the
    /// server when the seat was consumed (possibly by an older SDK release or
    /// another platform without the floor), and rejecting them here would
    /// strand the activation — it could never be validated, heartbeated, or
    /// deactivated, and the next activation would burn a second seat. Exempt
    /// values must still be 1-255 control-free characters without surrounding
    /// whitespace.
    fn validate_request_fingerprint(&self, value: &str) -> Result<()> {
        if is_valid_fingerprint(value) {
            return Ok(());
        }
        if self.inner.fingerprint == value
            || self
                .current_license()
                .is_some_and(|license| license.device_id == value)
        {
            return validate_request_identifier("fingerprint", value);
        }
        validate_fingerprint(value)
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
        *self
            .inner
            .recovery_license
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = None;
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
        *self
            .inner
            .recovery_license
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
            // Paths are still treated as sensitive operational metadata and
            // are never logged. License keys are carried only in request
            // bodies by the hardened API contract.
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
                        return crate::strict_json::from_slice(&response_body).map_err(Error::from);
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
    let now = Utc::now();
    if activation.object != "activation"
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
        || !license_response_schema_is_valid(&activation.license)
    {
        return Err(Error::InvalidResponse(
            "activation response schema is invalid".into(),
        ));
    }
    if !secure_string_eq(&activation.license_key, requested_license_key)
        || !secure_string_eq(&activation.device_id, requested_fingerprint)
        || !license_response_matches_identity(
            &activation.license,
            requested_license_key,
            requested_product_slug,
        )
    {
        return Err(Error::ResponseMismatch(
            "activation response did not match the requested license, product, or installation"
                .into(),
        ));
    }
    if !license_response_is_currently_active(&activation.license) {
        return Err(Error::InvalidResponse(
            "activation response contained an inactive license".into(),
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
        || result
            .code
            .as_deref()
            .is_some_and(|value| !safe_error_code(value))
        || result
            .message
            .as_deref()
            .is_some_and(|value| !safe_text(value, 1, MAX_API_ERROR_MESSAGE_BYTES))
        || result.warnings.as_ref().is_some_and(|warnings| {
            warnings.len() > 32
                || warnings.iter().any(|warning| {
                    !safe_error_code(&warning.code)
                        || !safe_text(&warning.message, 1, MAX_API_ERROR_MESSAGE_BYTES)
                })
        })
        || !license_response_schema_is_valid(&result.license)
    {
        return Err(Error::InvalidResponse(
            "validation response schema is invalid".into(),
        ));
    }
    if !license_response_matches_identity(
        &result.license,
        requested_license_key,
        requested_product_slug,
    ) {
        return Err(Error::ResponseMismatch(
            "validation response did not match the requested license or product".into(),
        ));
    }

    if result.valid
        && (result.code.is_some()
            || result.message.is_some()
            || !license_response_is_currently_active(&result.license))
    {
        return Err(Error::InvalidResponse(
            "validation response contained a contradictory valid decision".into(),
        ));
    }

    if result.valid && result.activation.is_none() {
        return Err(Error::InvalidResponse(
            "valid validation response did not prove the installation activation".into(),
        ));
    }

    if let Some(activation) = result.activation.as_ref() {
        if (!activation.object.is_empty() && activation.object != "activation")
            || !safe_text(&activation.id, 1, 255)
            || activation.activated_at > Utc::now() + chrono::Duration::minutes(5)
            || (result.valid && activation.deactivated_at.is_some())
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
                "validation activation schema is invalid".into(),
            ));
        }
        if !secure_string_eq(&activation.license_key, requested_license_key)
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

fn verify_deactivation_response(
    response: &DeactivationResponse,
    expected_activation_id: Option<&str>,
) -> Result<()> {
    if response.object != "deactivation"
        || !safe_text(&response.activation_id, 1, 255)
        || response.deactivated_at > Utc::now() + chrono::Duration::minutes(5)
    {
        return Err(Error::InvalidResponse(
            "deactivation response schema is invalid".into(),
        ));
    }
    if expected_activation_id
        .is_some_and(|expected| !secure_string_eq(&response.activation_id, expected))
    {
        return Err(Error::ResponseMismatch(
            "deactivation response did not match the active installation".into(),
        ));
    }
    Ok(())
}

fn verify_heartbeat_response(
    response: &HeartbeatResponse,
    requested_license_key: &str,
    requested_product_slug: &str,
) -> Result<()> {
    if response.object != "heartbeat"
        || response.received_at > Utc::now() + chrono::Duration::minutes(5)
        || !license_response_schema_is_valid(&response.license)
    {
        return Err(Error::InvalidResponse(
            "heartbeat response schema is invalid".into(),
        ));
    }
    if !license_response_matches_identity(
        &response.license,
        requested_license_key,
        requested_product_slug,
    ) {
        return Err(Error::ResponseMismatch(
            "heartbeat response did not match the requested license or product".into(),
        ));
    }
    if !license_response_is_currently_active(&response.license) {
        return Err(Error::InvalidResponse(
            "heartbeat response contained an inactive license".into(),
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
    secure_string_eq(&license.key, expected_license_key)
        && secure_string_eq(&license.product.slug, expected_product_slug)
}

fn license_response_schema_is_valid(license: &LicenseResponse) -> bool {
    let mut entitlement_keys = HashSet::with_capacity(license.active_entitlements.len());
    license.object == "license"
        && safe_text(&license.key, 1, 512)
        && valid_product_slug(&license.product.slug)
        && safe_text(&license.product.name, 1, 255)
        && matches!(
            license.status.as_str(),
            "pending" | "active" | "suspended" | "revoked" | "expired"
        )
        && matches!(
            license.mode.as_str(),
            "hardware_locked" | "floating" | "named_user"
        )
        && safe_text(&license.plan_key, 1, 100)
        && license.seat_limit != Some(0)
        && license
            .starts_at
            .zip(license.expires_at)
            .is_none_or(|(starts_at, expires_at)| starts_at < expires_at)
        && metadata_within_limits(license.metadata.as_ref())
        && license.active_entitlements.len() <= 500
        && license.active_entitlements.iter().all(|entitlement| {
            safe_identifier(&entitlement.key, 100)
                && entitlement_keys.insert(entitlement.key.as_str())
                && metadata_within_limits(entitlement.metadata.as_ref())
        })
}

fn license_response_is_currently_active(license: &LicenseResponse) -> bool {
    let now = Utc::now();
    license.status == "active"
        && license.starts_at.is_none_or(|starts_at| starts_at <= now)
        && license.expires_at.is_none_or(|expires_at| expires_at > now)
}

fn license_response_matches_active_grant(
    license: &LicenseResponse,
    expected_license_key: &str,
    expected_product_slug: &str,
    now: &chrono::DateTime<Utc>,
) -> bool {
    license_response_matches_identity(license, expected_license_key, expected_product_slug)
        && entitlement_records_are_well_formed(&license.active_entitlements)
        && license.status == "active"
        && license.starts_at.is_none_or(|starts_at| starts_at <= *now)
        && license
            .expires_at
            .is_none_or(|expires_at| expires_at > *now)
}

fn entitlement_records_are_well_formed(entitlements: &[Entitlement]) -> bool {
    let mut keys = HashSet::with_capacity(entitlements.len());
    entitlements.len() <= 500
        && entitlements.iter().all(|entitlement| {
            safe_identifier(&entitlement.key, 100)
                && keys.insert(entitlement.key.as_str())
                && metadata_within_limits(entitlement.metadata.as_ref())
        })
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

    if let Ok(json) = crate::strict_json::parse(trimmed.as_bytes()) {
        return parse_error_response(&json);
    }

    let prefix = trimmed
        .chars()
        .take(32)
        .collect::<String>()
        .to_ascii_lowercase();
    if prefix.starts_with("<!doctype html") || prefix.starts_with("<html") {
        return (None, trimmed.to_string(), None);
    }

    (None, "Request failed".into(), None)
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

    sanitize_error_message(trimmed).unwrap_or_else(|| "Request failed".into())
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
    safe_text(value, 1, MAX_API_ERROR_MESSAGE_BYTES).then(|| value.to_string())
}

fn sanitize_error_details(
    details: HashMap<String, serde_json::Value>,
) -> Option<HashMap<String, serde_json::Value>> {
    if details.is_empty()
        || details.len() > 64
        || details.keys().any(|key| !safe_text(key, 1, 100))
        || serde_json::to_vec(&details)
            .map(|bytes| bytes.len() > MAX_API_ERROR_DETAILS_BYTES)
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

fn build_license_action_path(product_slug: &str, action: &str) -> String {
    build_path(&["products", product_slug, "licenses", action])
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

/// Whether a release's platform satisfies a requested platform filter.
///
/// The server's `by_platform` scope is
/// `where("platform = ? OR platform = 'any'")`, so a request filtered to, say,
/// `macos` legitimately returns cross-platform (`"any"`) releases alongside the
/// macOS-specific ones. Rejecting those was a false positive that made
/// `get_latest_release`/`list_releases` fail against products that publish a
/// single universal artifact.
fn release_platform_matches(release_platform: &str, requested_platform: &str) -> bool {
    release_platform == requested_platform || release_platform == "any"
}

fn verify_release_response(
    release: &Release,
    expected_product_slug: &str,
    expected_channel: Option<&str>,
    expected_platform: Option<&str>,
) -> Result<()> {
    if !secure_string_eq(&release.product_slug, expected_product_slug)
        || expected_channel
            .filter(|value| !value.is_empty())
            .is_some_and(|channel| release.channel != channel)
        || expected_platform
            .filter(|value| !value.is_empty())
            .is_some_and(|platform| !release_platform_matches(&release.platform, platform))
    {
        return Err(Error::ResponseMismatch(
            "release response did not match the requested product or filters".into(),
        ));
    }
    if release.object != "release"
        || !safe_text(&release.version, 1, 255)
        || !matches!(release.channel.as_str(), "stable" | "beta" | "alpha")
        || !matches!(
            release.platform.as_str(),
            "macos" | "windows" | "linux" | "any"
        )
        || release.published_at.is_none()
        || release
            .published_at
            .is_some_and(|published_at| published_at > Utc::now() + chrono::Duration::minutes(5))
    {
        return Err(Error::InvalidResponse(
            "release response schema is invalid".into(),
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

fn validate_license_key(license_key: &str) -> Result<()> {
    if !safe_text(license_key, 1, 512) {
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
            .map(|bytes| bytes.len() > MAX_REQUEST_BODY_BYTES)
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

#[cfg(feature = "offline")]
fn json_map_contains_only(
    object: &serde_json::Map<String, serde_json::Value>,
    expected: &[&str],
) -> bool {
    object.len() == expected.len() && expected.iter().all(|key| object.contains_key(*key))
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
        .and_then(serde_json::Value::as_object)
        .filter(|attributes| {
            json_map_contains_only(
                attributes,
                &["certificate", "algorithm", "ttl", "issued", "expiry"],
            )
        })
        .ok_or_else(|| Error::InvalidResponse("machine-file response is invalid".into()))?;

    let relationships = data
        .get("relationships")
        .and_then(serde_json::Value::as_object)
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
                    is_valid_fingerprint(value)
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
            } else if message.contains("PRODUCT_MISMATCH") {
                "product_mismatch".into()
            } else if message.contains("LICENSE_MISMATCH") {
                "license_mismatch".into()
            } else if message.contains("FINGERPRINT_MISMATCH") {
                "fingerprint_mismatch".into()
            } else if message.contains("ACTIVATION_MISMATCH") {
                "activation_mismatch".into()
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
fn validate_ttl_days(ttl_days: Option<i64>) -> Result<()> {
    if ttl_days.is_some_and(|days| days <= 0) {
        return Err(Error::Configuration(
            "ttl_days must be greater than zero when provided".into(),
        ));
    }
    if ttl_days.is_some_and(|days| days > 36_600) {
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
