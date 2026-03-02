//! Concurrency and thread safety tests.
//!
//! These tests mirror the thread safety tests from C++ and C# SDKs,
//! ensuring the SDK handles concurrent operations correctly.

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
        "concurrency_test_{}_{}_{}_",
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
        auto_validate_interval: Duration::from_secs(0),
        heartbeat_interval: Duration::from_secs(0),
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
// Concurrent API Calls Tests
// ============================================================================

#[tokio::test]
async fn test_concurrent_validations() {
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

    let sdk = Arc::new(LicenseSeat::new(test_config(&server.uri())));
    sdk.activate("CONCURRENT-KEY").await.unwrap();

    // Spawn multiple concurrent validation tasks
    let mut handles = vec![];
    for _ in 0..10 {
        let sdk_clone = Arc::clone(&sdk);
        handles.push(tokio::spawn(async move {
            sdk_clone.validate().await
        }));
    }

    // All validations should succeed
    for handle in handles {
        let result = handle.await.unwrap();
        assert!(result.is_ok());
        assert!(result.unwrap().valid);
    }
}

#[tokio::test]
async fn test_concurrent_heartbeats() {
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

    let sdk = Arc::new(LicenseSeat::new(test_config(&server.uri())));
    sdk.activate("HEARTBEAT-KEY").await.unwrap();

    // Spawn multiple concurrent heartbeat tasks
    let mut handles = vec![];
    for _ in 0..10 {
        let sdk_clone = Arc::clone(&sdk);
        handles.push(tokio::spawn(async move {
            sdk_clone.heartbeat().await
        }));
    }

    // All heartbeats should succeed
    for handle in handles {
        let result = handle.await.unwrap();
        assert!(result.is_ok());
    }
}

#[tokio::test]
async fn test_concurrent_status_checks() {
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

    let sdk = Arc::new(LicenseSeat::new(test_config(&server.uri())));
    sdk.activate("STATUS-KEY").await.unwrap();
    sdk.validate().await.unwrap();

    // Spawn multiple threads checking status concurrently
    let mut handles = vec![];
    for _ in 0..100 {
        let sdk_clone = Arc::clone(&sdk);
        handles.push(std::thread::spawn(move || {
            let status = sdk_clone.status();
            matches!(status, licenseseat::LicenseStatus::Active { .. })
        }));
    }

    // All status checks should return Active
    for handle in handles {
        let is_active = handle.join().unwrap();
        assert!(is_active);
    }
}

#[tokio::test]
async fn test_concurrent_entitlement_checks() {
    let server = MockServer::start().await;

    let entitlements = vec![
        json!({"key": "feature-1", "expires_at": null, "metadata": null}),
        json!({"key": "feature-2", "expires_at": null, "metadata": null}),
        json!({"key": "feature-3", "expires_at": null, "metadata": null}),
    ];

    Mock::given(method("POST"))
        .and(path_regex(r"/products/.*/licenses/.*/activate"))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({
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
                "active_entitlements": entitlements,
                "metadata": null,
                "product": {
                    "slug": "test-product",
                    "name": "Test App"
                }
            }
        })))
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path_regex(r"/products/.*/licenses/.*/validate"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
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
                "active_entitlements": [
                    {"key": "feature-1", "expires_at": null, "metadata": null},
                    {"key": "feature-2", "expires_at": null, "metadata": null},
                    {"key": "feature-3", "expires_at": null, "metadata": null}
                ],
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

    let sdk = Arc::new(LicenseSeat::new(test_config(&server.uri())));
    sdk.activate("ENTITLEMENT-KEY").await.unwrap();
    sdk.validate().await.unwrap();

    // Spawn threads checking different entitlements concurrently
    let mut handles = vec![];
    for i in 0..100 {
        let sdk_clone = Arc::clone(&sdk);
        let feature = format!("feature-{}", (i % 3) + 1);
        handles.push(std::thread::spawn(move || {
            sdk_clone.has_entitlement(&feature)
        }));
    }

    // All entitlement checks should succeed
    for handle in handles {
        let has = handle.join().unwrap();
        assert!(has);
    }
}

// ============================================================================
// Event Subscription Concurrency Tests
// ============================================================================

#[tokio::test]
async fn test_concurrent_event_subscriptions() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path_regex(r"/products/.*/licenses/.*/activate"))
        .respond_with(ResponseTemplate::new(201).set_body_json(activation_response()))
        .mount(&server)
        .await;

    let sdk = LicenseSeat::new(test_config(&server.uri()));

    // Create multiple subscribers
    let counters: Vec<Arc<AtomicUsize>> = (0..5)
        .map(|_| Arc::new(AtomicUsize::new(0)))
        .collect();

    let mut handles = vec![];
    for counter in &counters {
        let mut rx = sdk.subscribe();
        let counter = Arc::clone(counter);
        handles.push(tokio::spawn(async move {
            while let Ok(event) = rx.recv().await {
                if matches!(event.kind, EventKind::ActivationStart | EventKind::ActivationSuccess) {
                    counter.fetch_add(1, Ordering::SeqCst);
                }
            }
        }));
    }

    // Perform activation
    sdk.activate("EVENT-KEY").await.unwrap();

    // Wait for events to propagate
    tokio::time::sleep(Duration::from_millis(100)).await;

    // All subscribers should have received events
    for counter in &counters {
        let count = counter.load(Ordering::SeqCst);
        assert!(count >= 2, "Expected at least 2 events, got {}", count);
    }
}

// ============================================================================
// SDK Clone Tests
// ============================================================================

#[tokio::test]
async fn test_sdk_clone_shares_state() {
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

    let sdk1 = LicenseSeat::new(test_config(&server.uri()));
    let sdk2 = sdk1.clone();

    // Activate with first clone
    sdk1.activate("CLONE-KEY").await.unwrap();

    // Second clone should see the license (same internal state)
    assert!(sdk2.current_license().is_some());

    // Validate with second clone
    sdk2.validate().await.unwrap();

    // First clone should see the validation
    let status1 = sdk1.status();
    let status2 = sdk2.status();

    assert!(matches!(status1, licenseseat::LicenseStatus::Active { .. }));
    assert!(matches!(status2, licenseseat::LicenseStatus::Active { .. }));
}

#[tokio::test]
async fn test_sdk_clone_concurrent_operations() {
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

    Mock::given(method("POST"))
        .and(path_regex(r"/products/.*/licenses/.*/heartbeat"))
        .respond_with(ResponseTemplate::new(200).set_body_json(heartbeat_response()))
        .mount(&server)
        .await;

    let sdk = LicenseSeat::new(test_config(&server.uri()));
    sdk.activate("CLONE-CONCURRENT-KEY").await.unwrap();

    // Create multiple clones and perform operations concurrently
    let mut validate_handles = vec![];
    let mut heartbeat_handles = vec![];

    for i in 0..10 {
        let sdk_clone = sdk.clone();
        if i % 2 == 0 {
            validate_handles.push(tokio::spawn(async move {
                sdk_clone.validate().await
            }));
        } else {
            heartbeat_handles.push(tokio::spawn(async move {
                sdk_clone.heartbeat().await
            }));
        }
    }

    // All validate operations should complete successfully
    for handle in validate_handles {
        let result = handle.await;
        assert!(result.is_ok());
    }

    // All heartbeat operations should complete successfully
    for handle in heartbeat_handles {
        let result = handle.await;
        assert!(result.is_ok());
    }
}

// ============================================================================
// Race Condition Tests
// ============================================================================

#[tokio::test]
async fn test_no_race_on_status() {
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

    let sdk = Arc::new(LicenseSeat::new(test_config(&server.uri())));
    sdk.activate("RACE-KEY").await.unwrap();

    // Concurrently validate and check status
    let sdk_validate = Arc::clone(&sdk);
    let sdk_status = Arc::clone(&sdk);

    let validate_handle = tokio::spawn(async move {
        for _ in 0..10 {
            let _ = sdk_validate.validate().await;
        }
    });

    let status_handle = tokio::spawn(async move {
        for _ in 0..100 {
            let _ = sdk_status.status();
        }
    });

    // Both should complete without panic or deadlock
    let (v_result, s_result) = tokio::join!(validate_handle, status_handle);
    assert!(v_result.is_ok());
    assert!(s_result.is_ok());
}

// ============================================================================
// Stress Tests
// ============================================================================

#[tokio::test]
async fn test_high_concurrency_stress() {
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

    let sdk = Arc::new(LicenseSeat::new(test_config(&server.uri())));
    sdk.activate("STRESS-KEY").await.unwrap();
    sdk.validate().await.unwrap();

    // High concurrency stress test
    let mut handles = vec![];
    for _ in 0..50 {
        let sdk_clone = Arc::clone(&sdk);
        handles.push(tokio::spawn(async move {
            for _ in 0..20 {
                let _ = sdk_clone.status();
                let _ = sdk_clone.current_license();
                let _ = sdk_clone.has_entitlement("test");
                let _ = sdk_clone.check_entitlement("test");
            }
        }));
    }

    // All tasks should complete without issues
    for handle in handles {
        assert!(handle.await.is_ok());
    }
}

// ============================================================================
// Multiple Instance Tests
// ============================================================================

#[tokio::test]
async fn test_multiple_independent_instances() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path_regex(r"/products/.*/licenses/.*/activate"))
        .respond_with(ResponseTemplate::new(201).set_body_json(activation_response()))
        .mount(&server)
        .await;

    // Create multiple independent SDK instances
    let mut sdks = vec![];
    for _ in 0..5 {
        sdks.push(Arc::new(LicenseSeat::new(test_config(&server.uri()))));
    }

    // Activate all concurrently
    let mut handles = vec![];
    for sdk in &sdks {
        let sdk_clone = Arc::clone(sdk);
        handles.push(tokio::spawn(async move {
            sdk_clone.activate("MULTI-KEY").await
        }));
    }

    // All should succeed
    for handle in handles {
        let result = handle.await.unwrap();
        assert!(result.is_ok());
    }

    // Each instance should have its own license
    for sdk in &sdks {
        assert!(sdk.current_license().is_some());
    }
}

// ============================================================================
// Thread-Local State Tests
// ============================================================================

#[test]
fn test_sdk_thread_safe() {
    // Verify LicenseSeat can be shared across threads
    fn assert_send<T: Send>() {}
    fn assert_sync<T: Sync>() {}

    assert_send::<LicenseSeat>();
    assert_sync::<LicenseSeat>();
}

#[test]
fn test_config_clone() {
    let config = Config {
        api_key: "test-key".into(),
        product_slug: "test-product".into(),
        debug: true,
        ..Default::default()
    };

    let cloned = config.clone();

    assert_eq!(config.api_key, cloned.api_key);
    assert_eq!(config.product_slug, cloned.product_slug);
    assert_eq!(config.debug, cloned.debug);
}
