//! Main LicenseSeat client implementation.

use crate::cache::LicenseCache;
use crate::config::{Config, OfflineFallbackMode};
use crate::error::{Error, Result};
use crate::events::{Event, EventKind};
use crate::models::*;
use crate::telemetry::{generate_device_id, Telemetry};

use chrono::Utc;
use reqwest::header::{HeaderMap, HeaderValue, AUTHORIZATION, CONTENT_TYPE, USER_AGENT};
use serde::de::DeserializeOwned;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::broadcast;
use tracing::{debug, info, warn};

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
    /// Flag to stop background tasks.
    background_tasks_running: AtomicBool,
}

impl LicenseSeat {
    /// Create a new LicenseSeat SDK instance.
    pub fn new(config: Config) -> Self {
        let http = build_http_client(&config);
        let cache = LicenseCache::new(&config.storage_prefix);
        let (event_tx, _) = broadcast::channel(64);

        let inner = Arc::new(LicenseSeatInner {
            config,
            http,
            cache,
            event_tx,
            background_tasks_running: AtomicBool::new(false),
        });

        let sdk = Self { inner };

        // Check for cached license on startup
        if let Some(license) = sdk.inner.cache.get_license() {
            debug!("Loaded cached license: {}", license.license_key);
            sdk.emit(Event::with_license(EventKind::LicenseLoaded, license.clone()));

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
        self.activate_with_options(license_key, ActivationOptions::default()).await
    }

    /// Activate a license with custom options.
    pub async fn activate_with_options(
        &self,
        license_key: &str,
        options: ActivationOptions,
    ) -> Result<License> {
        let product_slug = self.require_product_slug()?;
        let device_id = options
            .device_id
            .or_else(|| self.inner.config.device_identifier.clone())
            .unwrap_or_else(generate_device_id);

        self.emit(Event::new(EventKind::ActivationStart));

        let mut body = serde_json::json!({
            "device_id": device_id,
        });

        if let Some(name) = &options.device_name {
            body["device_name"] = serde_json::json!(name);
        }

        if let Some(metadata) = &options.metadata {
            body["metadata"] = serde_json::json!(metadata);
        }

        let path = format!("/products/{}/licenses/{}/activate", product_slug, license_key);

        match self.post::<ActivationResponse>(&path, Some(body)).await {
            Ok(activation) => {
                let license = License {
                    license_key: license_key.to_string(),
                    device_id,
                    activation_id: activation.id,
                    activated_at: activation.activated_at,
                    last_validated: Utc::now(),
                    validation: None,
                };

                self.inner.cache.set_license(&license)?;
                self.emit(Event::with_license(EventKind::ActivationSuccess, license.clone()));

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

                info!("License activated: {}", license_key);
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
        let license = self.inner.cache.get_license().ok_or(Error::NoActiveLicense)?;
        self.validate_key(&license.license_key).await
    }

    /// Validate a specific license key.
    pub async fn validate_key(&self, license_key: &str) -> Result<ValidationResult> {
        let product_slug = self.require_product_slug()?;
        let device_id = self.inner.cache.get_device_id();

        self.emit(Event::new(EventKind::ValidationStart));

        let mut body = serde_json::Map::new();
        if let Some(id) = &device_id {
            body.insert("device_id".into(), serde_json::json!(id));
        }

        let path = format!("/products/{}/licenses/{}/validate", product_slug, license_key);
        let body = if body.is_empty() { None } else { Some(serde_json::Value::Object(body)) };

        match self.post::<ValidationResult>(&path, body).await {
            Ok(result) => {
                self.inner.cache.update_validation(&result)?;
                self.inner.cache.set_last_seen_timestamp(Utc::now().timestamp())?;

                if result.valid {
                    self.emit(Event::with_validation(EventKind::ValidationSuccess, result.clone()));
                    info!("License validated successfully");
                } else {
                    self.emit(Event::with_validation(EventKind::ValidationFailed, result.clone()));
                    warn!("License validation failed: {:?}", result.code);
                }

                Ok(result)
            }
            Err(e) => {
                self.emit(Event::with_error(EventKind::ValidationError, e.to_string()));

                // Check for business logic errors (non-retriable)
                if e.is_business_error() {
                    self.inner.cache.clear();
                    self.emit(Event::with_error(EventKind::LicenseRevoked, e.to_string()));
                    return Err(e);
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
        let product_slug = self.require_product_slug()?;
        let license = self.inner.cache.get_license().ok_or(Error::NoActiveLicense)?;

        // Stop background tasks
        self.stop_background_tasks();

        self.emit(Event::new(EventKind::DeactivationStart));

        let path = format!(
            "/products/{}/licenses/{}/deactivate",
            product_slug, license.license_key
        );
        let body = serde_json::json!({ "device_id": license.device_id });

        match self.post::<DeactivationResponse>(&path, Some(body)).await {
            Ok(_) => {
                self.inner.cache.clear();
                self.emit(Event::new(EventKind::DeactivationSuccess));
                info!("License deactivated");
                Ok(())
            }
            Err(e) => {
                // Treat certain errors as success (already deactivated, not found, etc.)
                if let Error::Api { status, code, .. } = &e {
                    if *status == 404 || *status == 410 {
                        self.inner.cache.clear();
                        self.emit(Event::new(EventKind::DeactivationSuccess));
                        return Ok(());
                    }
                    if *status == 422 {
                        if let Some(c) = code {
                            if ["revoked", "already_deactivated", "not_active", "not_found", "suspended", "expired"]
                                .contains(&c.as_str())
                            {
                                self.inner.cache.clear();
                                self.emit(Event::new(EventKind::DeactivationSuccess));
                                return Ok(());
                            }
                        }
                    }
                }

                self.emit(Event::with_error(EventKind::DeactivationError, e.to_string()));
                Err(e)
            }
        }
    }

    /// Send a heartbeat for the current license.
    pub async fn heartbeat(&self) -> Result<HeartbeatResponse> {
        let product_slug = self.require_product_slug()?;
        let license = self.inner.cache.get_license().ok_or(Error::NoActiveLicense)?;

        let path = format!(
            "/products/{}/licenses/{}/heartbeat",
            product_slug, license.license_key
        );
        let body = serde_json::json!({ "device_id": license.device_id });

        match self.post::<HeartbeatResponse>(&path, Some(body)).await {
            Ok(response) => {
                self.emit(Event::new(EventKind::HeartbeatSuccess));
                debug!("Heartbeat sent successfully");
                Ok(response)
            }
            Err(e) => {
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
            return LicenseStatus::Invalid {
                message: validation
                    .message
                    .clone()
                    .or_else(|| validation.code.clone())
                    .unwrap_or_else(|| "License invalid".into()),
            };
        }

        LicenseStatus::Active {
            details: LicenseStatusDetails {
                license: license.license_key,
                device: license.device_id,
                activated_at: license.activated_at,
                last_validated: license.last_validated,
                entitlements: validation.license.active_entitlements.clone(),
            },
        }
    }

    /// Get the current cached license.
    pub fn current_license(&self) -> Option<License> {
        self.inner.cache.get_license()
    }

    /// Check API health.
    pub async fn health_check(&self) -> Result<HealthResponse> {
        self.get("/health").await
    }

    /// Reset SDK state (clears cache and stops timers).
    pub fn reset(&self) {
        // Stop background tasks first
        self.stop_background_tasks();
        self.inner.cache.clear();
        self.emit(Event::new(EventKind::SdkReset));
        info!("SDK state reset");
    }

    /// Subscribe to SDK events.
    pub fn subscribe(&self) -> broadcast::Receiver<Event> {
        self.inner.event_tx.subscribe()
    }

    // ========================================================================
    // Background Tasks
    // ========================================================================

    /// Start background validation and heartbeat tasks.
    ///
    /// This is called automatically after activation or when loading a cached license.
    /// You typically don't need to call this manually.
    pub fn start_background_tasks(&self) {
        // Don't start if already running
        if self.inner.background_tasks_running.swap(true, Ordering::SeqCst) {
            debug!("Background tasks already running");
            return;
        }

        info!("Starting background tasks");

        // Try to spawn on existing runtime, fall back to creating a new one
        let validate_interval = self.inner.config.auto_validate_interval;
        let heartbeat_interval = self.inner.config.heartbeat_interval;
        #[cfg(feature = "offline")]
        let refresh_interval = self.inner.config.offline_token_refresh_interval;

        // Clone SDK for the background thread
        let sdk = self.clone();

        // Spawn a dedicated thread with its own Tokio runtime for background tasks
        // This ensures the tasks run regardless of the caller's runtime context
        std::thread::Builder::new()
            .name("licenseseat-background".into())
            .spawn(move || {
                let rt = match tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                {
                    Ok(rt) => rt,
                    Err(e) => {
                        warn!("Failed to create background runtime: {}", e);
                        sdk.inner.background_tasks_running.store(false, Ordering::SeqCst);
                        return;
                    }
                };

                rt.block_on(async {
                    let mut tasks = Vec::new();

                    // Start auto-validation task
                    if !validate_interval.is_zero() {
                        let sdk_clone = sdk.clone();
                        tasks.push(tokio::spawn(async move {
                            sdk_clone.auto_validation_loop(validate_interval).await;
                        }));
                    }

                    // Start heartbeat task
                    if !heartbeat_interval.is_zero() {
                        let sdk_clone = sdk.clone();
                        tasks.push(tokio::spawn(async move {
                            sdk_clone.heartbeat_loop(heartbeat_interval).await;
                        }));
                    }

                    // Start offline asset refresh task
                    #[cfg(feature = "offline")]
                    if !refresh_interval.is_zero() {
                        let sdk_clone = sdk.clone();
                        tasks.push(tokio::spawn(async move {
                            sdk_clone.offline_refresh_loop(refresh_interval).await;
                        }));
                    }

                    // Wait for all tasks (they run until stopped)
                    for task in tasks {
                        let _ = task.await;
                    }
                });

                info!("Background tasks thread exiting");
            })
            .expect("Failed to spawn background thread");
    }

    /// Stop all background tasks.
    pub fn stop_background_tasks(&self) {
        info!("Stopping background tasks");
        self.inner.background_tasks_running.store(false, Ordering::SeqCst);
    }

    /// Generic background task loop runner.
    /// Handles the common pattern of: sleep -> check stop flag -> check license -> run task.
    async fn run_background_loop<F, Fut>(&self, name: &str, interval: Duration, task: F)
    where
        F: Fn() -> Fut,
        Fut: std::future::Future<Output = ()>,
    {
        debug!("{} loop started with interval {:?}", name, interval);

        loop {
            tokio::time::sleep(interval).await;

            if !self.inner.background_tasks_running.load(Ordering::SeqCst) {
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

    /// Auto-validation loop that runs in the background.
    async fn auto_validation_loop(&self, interval: Duration) {
        self.run_background_loop("Auto-validation", interval, || async {
            debug!("Running auto-validation");
            match self.validate().await {
                Ok(result) if result.valid => debug!("Auto-validation successful"),
                Ok(result) => warn!("Auto-validation failed: {:?}", result.code),
                Err(e) => warn!("Auto-validation error: {}", e),
            }
        })
        .await;
    }

    /// Heartbeat loop that runs in the background.
    async fn heartbeat_loop(&self, interval: Duration) {
        self.run_background_loop("Heartbeat", interval, || async {
            debug!("Sending heartbeat");
            match self.heartbeat().await {
                Ok(_) => debug!("Heartbeat sent successfully"),
                Err(e) => warn!("Heartbeat error: {}", e),
            }
        })
        .await;
    }

    /// Offline asset refresh loop.
    #[cfg(feature = "offline")]
    async fn offline_refresh_loop(&self, interval: Duration) {
        self.run_background_loop("Offline refresh", interval, || async {
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

    /// Sync offline assets (token and signing key) from the server.
    ///
    /// This downloads and caches the offline token and signing key for
    /// offline validation when network is unavailable.
    #[cfg(feature = "offline")]
    pub async fn sync_offline_assets(&self) -> Result<()> {
        use crate::models::{OfflineTokenResponse, SigningKeyResponse};

        let license = self.inner.cache.get_license().ok_or(Error::NoActiveLicense)?;
        let product_slug = self.require_product_slug()?;

        info!("Syncing offline assets");

        // Fetch offline token via POST with device_id in body
        let path = format!(
            "/products/{}/licenses/{}/offline_token",
            product_slug, license.license_key
        );
        let body = serde_json::json!({
            "device_id": license.device_id
        });
        let token: OfflineTokenResponse = self.post(&path, Some(body)).await?;

        // Cache the offline token
        self.inner.cache.set_offline_token(&token)?;
        debug!("Offline token cached (expires: {})", token.token.exp);

        // Fetch the signing key for this token
        let key_id = &token.signature.key_id;
        let key_path = format!("/signing_keys/{}", key_id);
        let signing_key: SigningKeyResponse = self.get(&key_path).await?;

        // Cache the signing key
        self.inner.cache.set_signing_key(key_id, &signing_key)?;
        debug!("Signing key cached: {}", key_id);

        self.emit(Event::new(EventKind::OfflineAssetsRefreshed));
        info!("Offline assets synced successfully");

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

    fn should_fallback_offline(&self, error: &Error) -> bool {
        match self.inner.config.offline_fallback_mode {
            OfflineFallbackMode::Always => true,
            OfflineFallbackMode::NetworkOnly => error.is_network_error(),
        }
    }

    #[cfg(feature = "offline")]
    async fn validate_offline(&self) -> Result<ValidationResult> {
        use crate::offline;

        info!("Attempting offline validation");
        self.emit(Event::new(EventKind::OfflineValidationStart));

        // Get cached offline token
        let token = self.inner.cache.get_offline_token().ok_or_else(|| {
            Error::OfflineVerificationFailed("No offline token cached".into())
        })?;

        // Get cached signing key
        let key_id = &token.signature.key_id;
        let signing_key = self.inner.cache.get_signing_key(key_id).ok_or_else(|| {
            Error::OfflineVerificationFailed(format!("Signing key {} not found", key_id))
        })?;

        // Verify the signature
        let signature_valid = offline::verify_token(&token, &signing_key)?;
        if !signature_valid {
            self.emit(Event::with_error(
                EventKind::OfflineValidationFailed,
                "Signature verification failed",
            ));
            return Err(Error::OfflineVerificationFailed(
                "Signature verification failed".to_string(),
            ));
        }
        debug!("Offline token signature verified");

        // Check token validity (expiration, not-before)
        offline::check_token_validity(&token)?;
        debug!("Offline token time validity confirmed");

        // Check max offline days
        if self.inner.config.max_offline_days > 0 {
            if let Some(last_validated) = self.inner.cache.get_license().map(|l| l.last_validated) {
                let offline_duration = Utc::now().signed_duration_since(last_validated);
                let max_offline = chrono::Duration::days(self.inner.config.max_offline_days as i64);
                if offline_duration > max_offline {
                    self.emit(Event::with_error(
                        EventKind::OfflineValidationFailed,
                        "Exceeded maximum offline days",
                    ));
                    return Err(Error::OfflineVerificationFailed(format!(
                        "Exceeded maximum offline period ({} days)",
                        self.inner.config.max_offline_days
                    )));
                }
            }
        }

        // Clock tampering detection
        let now = Utc::now().timestamp();
        if let Some(last_seen) = self.inner.cache.get_last_seen_timestamp() {
            let max_skew = self.inner.config.max_clock_skew.as_secs() as i64;
            if now < last_seen - max_skew {
                self.emit(Event::with_error(
                    EventKind::OfflineValidationFailed,
                    "Clock tampering detected",
                ));
                return Err(Error::OfflineVerificationFailed(
                    "Clock tampering detected: system clock appears to have gone backwards".to_string(),
                ));
            }
        }
        // Update last seen timestamp
        let _ = self.inner.cache.set_last_seen_timestamp(now);

        // Convert token to ValidationResult
        let result = offline::token_to_validation_result(&token);

        // Update cache with offline validation result
        self.inner.cache.update_validation(&result)?;

        self.emit(Event::with_validation(
            EventKind::OfflineValidationSuccess,
            result.clone(),
        ));
        info!("Offline validation successful");

        Ok(result)
    }

    async fn get<T: DeserializeOwned>(&self, path: &str) -> Result<T> {
        self.request(reqwest::Method::GET, path, None::<()>).await
    }

    async fn post<T: DeserializeOwned>(&self, path: &str, body: Option<serde_json::Value>) -> Result<T> {
        self.request(reqwest::Method::POST, path, body).await
    }

    async fn request<T: DeserializeOwned, B: serde::Serialize>(
        &self,
        method: reqwest::Method,
        path: &str,
        body: Option<B>,
    ) -> Result<T> {
        let url = format!("{}{}", self.inner.config.api_base_url, path);

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
            let mut request = self.inner.http.request(method.clone(), &url);
            if let Some(ref body) = json_body {
                request = request.json(body);
            }

            match request.send().await {
                Ok(response) => {
                    let status = response.status().as_u16();

                    if response.status().is_success() {
                        return response.json().await.map_err(Error::from);
                    }

                    // Parse error response
                    let error_body: serde_json::Value = response.json().await.unwrap_or_default();
                    let (code, message, details) = parse_error_response(&error_body);

                    let error = Error::api(status, code, message, details);

                    // Don't retry business logic errors
                    if error.is_business_error() {
                        return Err(error);
                    }

                    last_error = Some(error);
                }
                Err(e) => {
                    last_error = Some(Error::Network(e));
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
    /// Custom device ID (auto-generated if not provided).
    pub device_id: Option<String>,
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
        .timeout(Duration::from_secs(30))
        .build()
        .expect("Failed to build HTTP client")
}

fn parse_error_response(
    body: &serde_json::Value,
) -> (Option<String>, String, Option<HashMap<String, serde_json::Value>>) {
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
