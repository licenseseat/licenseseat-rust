//! Auto-validation and heartbeat timer tests.
//!
//! These tests mirror the auto-validation tests from Swift and C# SDKs.

use licenseseat::{ActivationOptions, Config, EventKind, LicenseSeat};
use serde_json::json;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use wiremock::matchers::{method, path_regex};
use wiremock::{Mock, MockServer, ResponseTemplate};

static TEST_COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

fn test_config(base_url: &str) -> Config {
    let unique_prefix = format!(
        "auto_val_test_{}_{}_{}_",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos(),
        TEST_COUNTER.fetch_add(1, Ordering::SeqCst)
    );

    Config {
        api_key: "test-api-key".into(),
        product_slug: "test-product".into(),
        api_base_url: base_url.into(),
        storage_prefix: unique_prefix,
        device_identifier: Some("device-123".into()),
        auto_validate_interval: Duration::from_secs(0), // Disabled by default
        heartbeat_interval: Duration::from_secs(0),     // Disabled by default
        debug: true,
        ..Default::default()
    }
}

/// Wait until `kind` is emitted. The cap is a hang guard for a genuinely
/// missing event, not a timing expectation: the wait returns as soon as the
/// event arrives, however slow the machine is.
async fn wait_for_event(
    events: &mut tokio::sync::broadcast::Receiver<licenseseat::Event>,
    kind: EventKind,
) {
    tokio::time::timeout(Duration::from_secs(60), async {
        loop {
            match events.recv().await {
                Ok(event) if event.kind == kind => return,
                Ok(_) => {}
                Err(error) => panic!("event stream broke before {kind:?}: {error}"),
            }
        }
    })
    .await
    .unwrap_or_else(|_| panic!("{kind:?} was never emitted"));
}

fn activation_response() -> serde_json::Value {
    json!({
        "object": "activation",
        "id": "act-12345-uuid",
        "device_id": "device-123",
        "device_name": "Test Device",
        "license_key": "TEST-KEY",
        "activated_at": "2025-01-01T00:00:00Z",
        "deactivated_at": null,
        "ip_address": "127.0.0.1",
        "metadata": null,
        "license": {
            "object": "license",
            "key": "TEST-KEY",
            "status": "active",
            "starts_at": null,
            "expires_at": null,
            "mode": "hardware_locked",
            "plan_key": "pro",
            "seat_limit": 5,
            "active_seats": 1,
            "active_entitlements": [],
            "metadata": null,
            "product": {
                "slug": "test-product",
                "name": "Test App"
            }
        }
    })
}

fn validation_response() -> serde_json::Value {
    json!({
        "object": "validation_result",
        "valid": true,
        "code": null,
        "message": null,
        "warnings": null,
        "license": {
            "object": "license",
            "key": "TEST-KEY",
            "status": "active",
            "starts_at": null,
            "expires_at": null,
            "mode": "hardware_locked",
            "plan_key": "pro",
            "seat_limit": 5,
            "active_seats": 1,
            "active_entitlements": [],
            "metadata": null,
            "product": {
                "slug": "test-product",
                "name": "Test App"
            }
        },
        "activation": {
            "object": "activation",
            "id": "act-12345-uuid",
            "device_id": "device-123",
            "device_name": "Test Device",
            "license_key": "TEST-KEY",
            "activated_at": "2025-01-01T00:00:00Z",
            "deactivated_at": null,
            "ip_address": "127.0.0.1",
            "metadata": null
        }
    })
}

fn heartbeat_response() -> serde_json::Value {
    json!({
        "object": "heartbeat",
        "received_at": "2025-01-01T00:00:00Z",
        "license": {
            "object": "license",
            "key": "TEST-KEY",
            "status": "active",
            "starts_at": null,
            "expires_at": null,
            "mode": "hardware_locked",
            "plan_key": "pro",
            "seat_limit": 5,
            "active_seats": 1,
            "active_entitlements": [],
            "metadata": null,
            "product": {
                "slug": "test-product",
                "name": "Test App"
            }
        }
    })
}

#[tokio::test]
async fn background_heartbeat_reuses_an_activation_fingerprint_override() {
    let server = MockServer::start().await;
    let mut activation = activation_response();
    activation["device_id"] = json!("custom-installation");

    Mock::given(method("POST"))
        .and(path_regex(r"/products/.*/licenses/activate"))
        .respond_with(ResponseTemplate::new(201).set_body_json(activation))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path_regex(r"/products/.*/licenses/heartbeat"))
        .respond_with(ResponseTemplate::new(200).set_body_json(heartbeat_response()))
        .mount(&server)
        .await;

    let sdk = LicenseSeat::try_new(Config {
        heartbeat_interval: Duration::from_millis(10),
        network_recheck_interval: Duration::ZERO,
        offline_token_refresh_interval: Duration::ZERO,
        max_retries: 0,
        ..test_config(&server.uri())
    })
    .unwrap();
    sdk.activate_with_options(
        "TEST-KEY",
        ActivationOptions {
            fingerprint: Some("custom-installation".into()),
            ..Default::default()
        },
    )
    .await
    .unwrap();

    tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            let requests = server.received_requests().await.unwrap();
            if requests
                .iter()
                .any(|request| request.url.path().ends_with("/heartbeat"))
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("background heartbeat was not sent");
    sdk.stop_background_tasks();

    let requests = server.received_requests().await.unwrap();
    let heartbeat = requests
        .iter()
        .find(|request| request.url.path().ends_with("/heartbeat"))
        .expect("heartbeat request");
    let body: serde_json::Value = serde_json::from_slice(&heartbeat.body).unwrap();
    for field in ["fingerprint", "device_id", "device_fingerprint"] {
        assert_eq!(body[field], "custom-installation");
    }
}

// ============================================================================
// Validation Timing Tests
// ============================================================================

#[tokio::test]
async fn test_validation_updates_last_validated() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path_regex(r"/products/.*/licenses/activate"))
        .respond_with(ResponseTemplate::new(201).set_body_json(activation_response()))
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path_regex(r"/products/.*/licenses/validate"))
        .respond_with(ResponseTemplate::new(200).set_body_json(validation_response()))
        .mount(&server)
        .await;

    let sdk = LicenseSeat::new(test_config(&server.uri()));

    // Activate
    sdk.activate("TEST-KEY").await.unwrap();
    let initial_license = sdk.current_license().unwrap();
    let initial_validated = initial_license.last_validated;

    // Wait a moment
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Validate
    sdk.validate().await.unwrap();

    let updated_license = sdk.current_license().unwrap();
    let updated_validated = updated_license.last_validated;

    // last_validated should be updated
    assert!(updated_validated > initial_validated);
}

#[tokio::test]
async fn test_validation_stores_result() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path_regex(r"/products/.*/licenses/activate"))
        .respond_with(ResponseTemplate::new(201).set_body_json(activation_response()))
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path_regex(r"/products/.*/licenses/validate"))
        .respond_with(ResponseTemplate::new(200).set_body_json(validation_response()))
        .mount(&server)
        .await;

    let sdk = LicenseSeat::new(test_config(&server.uri()));

    // Activation immediately establishes a successful online validation.
    sdk.activate("TEST-KEY").await.unwrap();
    let license_before = sdk.current_license().unwrap();
    assert!(
        license_before
            .validation
            .as_ref()
            .is_some_and(|result| result.valid)
    );

    // After validation, result is stored
    sdk.validate().await.unwrap();
    let license_after = sdk.current_license().unwrap();
    assert!(license_after.validation.is_some());
    assert!(license_after.validation.unwrap().valid);
}

// ============================================================================
// Auto-Validation Configuration Tests
// ============================================================================

#[test]
fn test_auto_validation_interval_disabled_by_zero() {
    let config = Config {
        auto_validate_interval: Duration::from_secs(0),
        ..Default::default()
    };

    assert_eq!(config.auto_validate_interval, Duration::ZERO);
}

#[test]
fn test_auto_validation_interval_can_be_set() {
    let config = Config {
        auto_validate_interval: Duration::from_secs(1800), // 30 minutes
        ..Default::default()
    };

    assert_eq!(config.auto_validate_interval, Duration::from_secs(1800));
}

#[test]
fn test_heartbeat_interval_disabled_by_zero() {
    let config = Config {
        heartbeat_interval: Duration::from_secs(0),
        ..Default::default()
    };

    assert_eq!(config.heartbeat_interval, Duration::ZERO);
}

#[test]
fn test_heartbeat_interval_can_be_set() {
    let config = Config {
        heartbeat_interval: Duration::from_secs(300), // 5 minutes
        ..Default::default()
    };

    assert_eq!(config.heartbeat_interval, Duration::from_secs(300));
}

// ============================================================================
// Validation Event Tests
// ============================================================================

#[tokio::test]
async fn test_validation_emits_start_event() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path_regex(r"/products/.*/licenses/activate"))
        .respond_with(ResponseTemplate::new(201).set_body_json(activation_response()))
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path_regex(r"/products/.*/licenses/validate"))
        .respond_with(ResponseTemplate::new(200).set_body_json(validation_response()))
        .mount(&server)
        .await;

    let sdk = LicenseSeat::new(test_config(&server.uri()));

    let start_count = Arc::new(AtomicUsize::new(0));
    let start_clone = start_count.clone();

    let mut rx = sdk.subscribe();
    tokio::spawn(async move {
        while let Ok(event) = rx.recv().await {
            if matches!(event.kind, EventKind::ValidationStart) {
                start_clone.fetch_add(1, Ordering::SeqCst);
            }
        }
    });

    sdk.activate("TEST-KEY").await.unwrap();
    sdk.validate().await.unwrap();

    tokio::time::sleep(Duration::from_millis(50)).await;

    assert_eq!(start_count.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn test_validation_emits_success_event() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path_regex(r"/products/.*/licenses/activate"))
        .respond_with(ResponseTemplate::new(201).set_body_json(activation_response()))
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path_regex(r"/products/.*/licenses/validate"))
        .respond_with(ResponseTemplate::new(200).set_body_json(validation_response()))
        .mount(&server)
        .await;

    let sdk = LicenseSeat::new(test_config(&server.uri()));

    let success_count = Arc::new(AtomicUsize::new(0));
    let success_clone = success_count.clone();

    let mut rx = sdk.subscribe();
    tokio::spawn(async move {
        while let Ok(event) = rx.recv().await {
            if matches!(event.kind, EventKind::ValidationSuccess) {
                success_clone.fetch_add(1, Ordering::SeqCst);
            }
        }
    });

    sdk.activate("TEST-KEY").await.unwrap();
    sdk.validate().await.unwrap();

    tokio::time::sleep(Duration::from_millis(50)).await;

    assert_eq!(success_count.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn test_validation_emits_error_event_on_network_failure() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path_regex(r"/products/.*/licenses/activate"))
        .respond_with(ResponseTemplate::new(201).set_body_json(activation_response()))
        .mount(&server)
        .await;

    // Make validation fail
    Mock::given(method("POST"))
        .and(path_regex(r"/products/.*/licenses/validate"))
        .respond_with(ResponseTemplate::new(500).set_body_json(json!({
            "error": {"message": "Internal server error"}
        })))
        .mount(&server)
        .await;

    let mut config = test_config(&server.uri());
    config.max_retries = 0; // Disable retries

    let sdk = LicenseSeat::new(config);

    let error_count = Arc::new(AtomicUsize::new(0));
    let error_clone = error_count.clone();

    let mut rx = sdk.subscribe();
    tokio::spawn(async move {
        while let Ok(event) = rx.recv().await {
            if matches!(event.kind, EventKind::ValidationError) {
                error_clone.fetch_add(1, Ordering::SeqCst);
            }
        }
    });

    sdk.activate("TEST-KEY").await.unwrap();
    let _ = sdk.validate().await;

    tokio::time::sleep(Duration::from_millis(50)).await;

    assert!(error_count.load(Ordering::SeqCst) >= 1);
}

// ============================================================================
// Heartbeat Event Tests
// ============================================================================

#[tokio::test]
async fn test_heartbeat_emits_success_event() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path_regex(r"/products/.*/licenses/activate"))
        .respond_with(ResponseTemplate::new(201).set_body_json(activation_response()))
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path_regex(r"/products/.*/licenses/heartbeat"))
        .respond_with(ResponseTemplate::new(200).set_body_json(heartbeat_response()))
        .mount(&server)
        .await;

    let sdk = LicenseSeat::new(test_config(&server.uri()));

    let success_count = Arc::new(AtomicUsize::new(0));
    let success_clone = success_count.clone();

    let mut rx = sdk.subscribe();
    tokio::spawn(async move {
        while let Ok(event) = rx.recv().await {
            if matches!(event.kind, EventKind::HeartbeatSuccess) {
                success_clone.fetch_add(1, Ordering::SeqCst);
            }
        }
    });

    sdk.activate("TEST-KEY").await.unwrap();
    sdk.heartbeat().await.unwrap();

    tokio::time::sleep(Duration::from_millis(50)).await;

    assert_eq!(success_count.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn test_heartbeat_emits_error_event() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path_regex(r"/products/.*/licenses/activate"))
        .respond_with(ResponseTemplate::new(201).set_body_json(activation_response()))
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path_regex(r"/products/.*/licenses/heartbeat"))
        .respond_with(ResponseTemplate::new(500).set_body_json(json!({
            "error": {"message": "Server error"}
        })))
        .mount(&server)
        .await;

    let mut config = test_config(&server.uri());
    config.max_retries = 0;

    let sdk = LicenseSeat::new(config);

    let error_count = Arc::new(AtomicUsize::new(0));
    let error_clone = error_count.clone();

    let mut rx = sdk.subscribe();
    tokio::spawn(async move {
        while let Ok(event) = rx.recv().await {
            if matches!(event.kind, EventKind::HeartbeatError) {
                error_clone.fetch_add(1, Ordering::SeqCst);
            }
        }
    });

    sdk.activate("TEST-KEY").await.unwrap();
    let _ = sdk.heartbeat().await;

    tokio::time::sleep(Duration::from_millis(50)).await;

    assert!(error_count.load(Ordering::SeqCst) >= 1);
}

/// Records the arrival instant of every machine-file request.
#[cfg(feature = "offline")]
struct RecordingMachineFile {
    arrivals: Arc<std::sync::Mutex<Vec<std::time::Instant>>>,
    body: serde_json::Value,
}

#[cfg(feature = "offline")]
impl wiremock::Respond for RecordingMachineFile {
    fn respond(&self, _: &wiremock::Request) -> ResponseTemplate {
        self.arrivals
            .lock()
            .unwrap()
            .push(std::time::Instant::now());
        ResponseTemplate::new(201).set_body_json(self.body.clone())
    }
}

/// Wait until `condition` holds. The cap is a hang guard for a genuinely
/// missing request, not a timing expectation.
#[cfg(feature = "offline")]
async fn wait_until(mut condition: impl FnMut() -> bool) {
    tokio::time::timeout(Duration::from_secs(60), async {
        while !condition() {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("condition never held");
}

/// A restarted support-task set must replace the old refresh loop, not run
/// beside it.
///
/// This used to count requests inside fixed 40 ms windows, which failed under
/// parallel load whenever a window slipped past the next legitimate tick
/// (licenseseat-rust#12). It now relies on a property of a single loop that
/// holds however slow the machine is: the loop sleeps `interval` only after
/// its previous fetch has completed, so one loop's consecutive requests
/// arrive more than `interval` apart. A surviving old loop would put a
/// second request well inside that spacing.
#[cfg(feature = "offline")]
#[tokio::test]
async fn test_support_tasks_do_not_duplicate_after_restart() {
    const INTERVAL: Duration = Duration::from_secs(1);
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path_regex(r"/products/.*/licenses/activate"))
        .respond_with(ResponseTemplate::new(201).set_body_json(activation_response()))
        .mount(&server)
        .await;

    let arrivals = Arc::new(std::sync::Mutex::new(Vec::new()));
    Mock::given(method("POST"))
        .and(path_regex(r"/products/.*/licenses/machine-file"))
        .respond_with(RecordingMachineFile {
            arrivals: arrivals.clone(),
            body: json!({
                "data": {
                    "type": "machine-files",
                    "attributes": {
                        "certificate": "not-a-real-machine-file",
                        "algorithm": "aes-256-gcm+ed25519",
                        "ttl": 2592000,
                        "issued": "2025-01-01T00:00:00Z",
                        "expiry": "2025-02-01T00:00:00Z"
                    },
                    "relationships": {
                        "license": { "data": { "type": "licenses", "id": "TEST-KEY" } },
                        "machine": { "data": { "type": "machines", "id": "device-123" } }
                    }
                }
            }),
        })
        .mount(&server)
        .await;

    let mut config = test_config(&server.uri());
    config.network_recheck_interval = Duration::ZERO;
    config.offline_token_refresh_interval = INTERVAL;
    config.max_offline_days = 7;

    let sdk = LicenseSeat::new(config);
    let before_activation = std::time::Instant::now();
    sdk.activate("TEST-KEY").await.unwrap();

    // The activation-time one-shot sync_offline_assets() request.
    wait_until(|| !arrivals.lock().unwrap().is_empty()).await;
    // Restart while the first refresh loop is (normally) still sleeping.
    sdk.stop_background_tasks();
    sdk.start_background_tasks();
    let restarted = std::time::Instant::now();

    // One-shot plus three ticks of the replacement loop (a surviving old loop
    // would pair with each of them).
    wait_until(|| arrivals.lock().unwrap().len() >= 4).await;
    let arrivals = arrivals.lock().unwrap().clone();

    // If the restart completed less than one interval after activation began,
    // the first loop (started inside activate) cannot have sent anything
    // before it was stopped, and arrivals[0] is the one-shot sync. Otherwise
    // a pre-stop tick of the old loop is legitimate and the arrivals cannot
    // be attributed; only liveness (above) is asserted.
    if restarted.duration_since(before_activation) < INTERVAL {
        assert!(
            arrivals[0] < restarted,
            "one-shot sync precedes the restart"
        );
        for pair in arrivals.windows(2) {
            assert!(
                pair[1].duration_since(pair[0]) > INTERVAL,
                "two refreshes {:?} apart: a stopped refresh loop is still running",
                pair[1].duration_since(pair[0])
            );
        }
    }
}

#[tokio::test]
async fn revoked_auto_validation_does_not_send_a_followup_heartbeat() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path_regex(r"/products/.*/licenses/activate"))
        .respond_with(ResponseTemplate::new(201).set_body_json(activation_response()))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path_regex(r"/products/.*/licenses/validate"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "object": "validation_result",
            "valid": false,
            "code": "license_revoked",
            "message": "License has been revoked",
            "warnings": null,
            "license": {
                "object": "license",
                "key": "TEST-KEY",
                "status": "revoked",
                "starts_at": null,
                "expires_at": null,
                "mode": "hardware_locked",
                "plan_key": "pro",
                "seat_limit": 5,
                "active_seats": 0,
                "active_entitlements": [],
                "metadata": null,
                "product": { "slug": "test-product", "name": "Test App" }
            },
            "activation": null
        })))
        .mount(&server)
        .await;

    let mut config = test_config(&server.uri());
    config.auto_validate_interval = Duration::from_millis(40);
    config.heartbeat_interval = Duration::ZERO;
    config.network_recheck_interval = Duration::ZERO;
    #[cfg(feature = "offline")]
    {
        config.offline_token_refresh_interval = Duration::ZERO;
    }
    let sdk = LicenseSeat::new(config);
    let mut events = sdk.subscribe();
    sdk.activate("TEST-KEY").await.unwrap();

    // Wait for the SDK to report that the revocation was committed rather
    // than polling against a 2 s budget: under parallel load activation alone
    // took over 2 s (licenseseat-rust#12). `license:revoked` is emitted only
    // after the denial has been written and background tasks stopped.
    wait_for_event(&mut events, EventKind::LicenseRevoked).await;

    let requests = server.received_requests().await.unwrap();
    assert!(
        requests
            .iter()
            .any(|request| request.url.path().ends_with("/validate"))
    );
    assert!(
        requests
            .iter()
            .all(|request| !request.url.path().ends_with("/heartbeat"))
    );
    assert!(sdk.current_license().is_none());
}

// ============================================================================
// Multiple Validation Cycles Tests
// ============================================================================

#[tokio::test]
async fn test_multiple_validations_update_timestamp() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path_regex(r"/products/.*/licenses/activate"))
        .respond_with(ResponseTemplate::new(201).set_body_json(activation_response()))
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path_regex(r"/products/.*/licenses/validate"))
        .respond_with(ResponseTemplate::new(200).set_body_json(validation_response()))
        .mount(&server)
        .await;

    let sdk = LicenseSeat::new(test_config(&server.uri()));
    sdk.activate("TEST-KEY").await.unwrap();

    let mut prev_timestamp = sdk.current_license().unwrap().last_validated;

    for _ in 0..3 {
        tokio::time::sleep(Duration::from_millis(10)).await;
        sdk.validate().await.unwrap();

        let new_timestamp = sdk.current_license().unwrap().last_validated;
        assert!(new_timestamp >= prev_timestamp);
        prev_timestamp = new_timestamp;
    }
}

// ============================================================================
// Validation Failed Tests
// ============================================================================

#[tokio::test]
async fn test_validation_failed_emits_event() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path_regex(r"/products/.*/licenses/activate"))
        .respond_with(ResponseTemplate::new(201).set_body_json(activation_response()))
        .mount(&server)
        .await;

    // Return invalid validation
    Mock::given(method("POST"))
        .and(path_regex(r"/products/.*/licenses/validate"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "object": "validation_result",
            "valid": false,
            "code": "license_suspended",
            "message": "License has been suspended",
            "warnings": null,
            "license": {
                "object": "license",
                "key": "TEST-KEY",
                "status": "suspended",
                "starts_at": null,
                "expires_at": null,
                "mode": "hardware_locked",
                "plan_key": "pro",
                "seat_limit": 5,
                "active_seats": 1,
                "active_entitlements": [],
                "metadata": null,
                "product": {
                    "slug": "test-product",
                    "name": "Test App"
                }
            },
            "activation": null
        })))
        .mount(&server)
        .await;

    let sdk = LicenseSeat::new(test_config(&server.uri()));

    let failed_count = Arc::new(AtomicUsize::new(0));
    let failed_clone = failed_count.clone();

    let mut rx = sdk.subscribe();
    tokio::spawn(async move {
        while let Ok(event) = rx.recv().await {
            if matches!(event.kind, EventKind::ValidationFailed) {
                failed_clone.fetch_add(1, Ordering::SeqCst);
            }
        }
    });

    sdk.activate("TEST-KEY").await.unwrap();
    let result = sdk.validate().await.unwrap();

    assert!(!result.valid);

    tokio::time::sleep(Duration::from_millis(50)).await;

    assert_eq!(failed_count.load(Ordering::SeqCst), 1);
}

// ============================================================================
// Heartbeat Response Tests
// ============================================================================

#[tokio::test]
async fn test_heartbeat_returns_response() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path_regex(r"/products/.*/licenses/activate"))
        .respond_with(ResponseTemplate::new(201).set_body_json(activation_response()))
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path_regex(r"/products/.*/licenses/heartbeat"))
        .respond_with(ResponseTemplate::new(200).set_body_json(heartbeat_response()))
        .mount(&server)
        .await;

    let sdk = LicenseSeat::new(test_config(&server.uri()));
    sdk.activate("TEST-KEY").await.unwrap();

    let response = sdk.heartbeat().await.unwrap();

    assert!(!response.received_at.to_string().is_empty());
    assert_eq!(response.license.key, "TEST-KEY");
}

// ============================================================================
// Timestamp Tests
// ============================================================================

#[tokio::test]
async fn test_validation_updates_last_validated_timestamp() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path_regex(r"/products/.*/licenses/activate"))
        .respond_with(ResponseTemplate::new(201).set_body_json(activation_response()))
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path_regex(r"/products/.*/licenses/validate"))
        .respond_with(ResponseTemplate::new(200).set_body_json(validation_response()))
        .mount(&server)
        .await;

    let sdk = LicenseSeat::new(test_config(&server.uri()));
    sdk.activate("TEST-KEY").await.unwrap();

    let before = sdk.current_license().unwrap().last_validated;
    tokio::time::sleep(Duration::from_millis(50)).await;

    sdk.validate().await.unwrap();

    let after = sdk.current_license().unwrap().last_validated;
    assert!(after > before);
}
