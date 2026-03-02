//! Auto-validation and heartbeat timer tests.
//!
//! These tests mirror the auto-validation tests from Swift and C# SDKs.

use licenseseat::{Config, EventKind, LicenseSeat};
use serde_json::json;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
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
        auto_validate_interval: Duration::from_secs(0), // Disabled by default
        heartbeat_interval: Duration::from_secs(0), // Disabled by default
        debug: true,
        ..Default::default()
    }
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
        "activation": null
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

// ============================================================================
// Validation Timing Tests
// ============================================================================

#[tokio::test]
async fn test_validation_updates_last_validated() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path_regex(r"/products/.*/licenses/.*/activate"))
        .respond_with(ResponseTemplate::new(201).set_body_json(activation_response()))
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path_regex(r"/products/.*/licenses/.*/validate"))
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
        .and(path_regex(r"/products/.*/licenses/.*/activate"))
        .respond_with(ResponseTemplate::new(201).set_body_json(activation_response()))
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path_regex(r"/products/.*/licenses/.*/validate"))
        .respond_with(ResponseTemplate::new(200).set_body_json(validation_response()))
        .mount(&server)
        .await;

    let sdk = LicenseSeat::new(test_config(&server.uri()));

    // Before validation, no validation result
    sdk.activate("TEST-KEY").await.unwrap();
    let license_before = sdk.current_license().unwrap();
    assert!(license_before.validation.is_none());

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
        .and(path_regex(r"/products/.*/licenses/.*/activate"))
        .respond_with(ResponseTemplate::new(201).set_body_json(activation_response()))
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path_regex(r"/products/.*/licenses/.*/validate"))
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
        .and(path_regex(r"/products/.*/licenses/.*/activate"))
        .respond_with(ResponseTemplate::new(201).set_body_json(activation_response()))
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path_regex(r"/products/.*/licenses/.*/validate"))
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
        .and(path_regex(r"/products/.*/licenses/.*/activate"))
        .respond_with(ResponseTemplate::new(201).set_body_json(activation_response()))
        .mount(&server)
        .await;

    // Make validation fail
    Mock::given(method("POST"))
        .and(path_regex(r"/products/.*/licenses/.*/validate"))
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
        .and(path_regex(r"/products/.*/licenses/.*/activate"))
        .respond_with(ResponseTemplate::new(201).set_body_json(activation_response()))
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path_regex(r"/products/.*/licenses/.*/heartbeat"))
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
        .and(path_regex(r"/products/.*/licenses/.*/activate"))
        .respond_with(ResponseTemplate::new(201).set_body_json(activation_response()))
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path_regex(r"/products/.*/licenses/.*/heartbeat"))
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

// ============================================================================
// Multiple Validation Cycles Tests
// ============================================================================

#[tokio::test]
async fn test_multiple_validations_update_timestamp() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path_regex(r"/products/.*/licenses/.*/activate"))
        .respond_with(ResponseTemplate::new(201).set_body_json(activation_response()))
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path_regex(r"/products/.*/licenses/.*/validate"))
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
        .and(path_regex(r"/products/.*/licenses/.*/activate"))
        .respond_with(ResponseTemplate::new(201).set_body_json(activation_response()))
        .mount(&server)
        .await;

    // Return invalid validation
    Mock::given(method("POST"))
        .and(path_regex(r"/products/.*/licenses/.*/validate"))
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
        .and(path_regex(r"/products/.*/licenses/.*/activate"))
        .respond_with(ResponseTemplate::new(201).set_body_json(activation_response()))
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path_regex(r"/products/.*/licenses/.*/heartbeat"))
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
        .and(path_regex(r"/products/.*/licenses/.*/activate"))
        .respond_with(ResponseTemplate::new(201).set_body_json(activation_response()))
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path_regex(r"/products/.*/licenses/.*/validate"))
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
