//! Event system tests - subscription, emission, cancellation.

use licenseseat::{Config, Event, EventKind, LicenseSeat};
use serde_json::json;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use wiremock::matchers::{method, path_regex};
use wiremock::{Mock, MockServer, ResponseTemplate};

static TEST_COUNTER: AtomicU64 = AtomicU64::new(0);

fn test_config(base_url: &str) -> Config {
    let unique_prefix = format!(
        "events_test_{}_{}_{}_",
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

fn deactivation_response() -> serde_json::Value {
    json!({
        "object": "deactivation",
        "activation_id": "act-12345-uuid",
        "deactivated_at": "2025-01-01T00:00:00Z"
    })
}

// ============================================================================
// Event Subscription Tests
// ============================================================================

#[tokio::test]
async fn test_event_subscription() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path_regex(r"/products/.*/licenses/.*/activate"))
        .respond_with(ResponseTemplate::new(201).set_body_json(activation_response()))
        .mount(&server)
        .await;

    let sdk = LicenseSeat::new(test_config(&server.uri()));

    let event_received = Arc::new(AtomicUsize::new(0));
    let event_received_clone = event_received.clone();

    let mut rx = sdk.subscribe();

    // Spawn a task to listen for events
    let handle = tokio::spawn(async move {
        while let Ok(event) = rx.recv().await {
            if matches!(
                event.kind,
                EventKind::ActivationStart | EventKind::ActivationSuccess
            ) {
                event_received_clone.fetch_add(1, Ordering::SeqCst);
            }
        }
    });

    // Perform activation
    let _ = sdk.activate("TEST-KEY").await;

    // Give time for events to propagate
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Should have received at least activation:start and activation:success
    assert!(event_received.load(Ordering::SeqCst) >= 2);

    drop(handle);
}

#[tokio::test]
async fn test_activation_events() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path_regex(r"/products/.*/licenses/.*/activate"))
        .respond_with(ResponseTemplate::new(201).set_body_json(activation_response()))
        .mount(&server)
        .await;

    let sdk = LicenseSeat::new(test_config(&server.uri()));

    let start_received = Arc::new(AtomicUsize::new(0));
    let success_received = Arc::new(AtomicUsize::new(0));

    let start_clone = start_received.clone();
    let success_clone = success_received.clone();

    let mut rx = sdk.subscribe();

    let handle = tokio::spawn(async move {
        while let Ok(event) = rx.recv().await {
            match event.kind {
                EventKind::ActivationStart => {
                    start_clone.fetch_add(1, Ordering::SeqCst);
                }
                EventKind::ActivationSuccess => {
                    success_clone.fetch_add(1, Ordering::SeqCst);
                }
                _ => {}
            }
        }
    });

    let _ = sdk.activate("TEST-KEY").await;
    tokio::time::sleep(Duration::from_millis(100)).await;

    assert_eq!(start_received.load(Ordering::SeqCst), 1);
    assert_eq!(success_received.load(Ordering::SeqCst), 1);

    drop(handle);
}

#[tokio::test]
async fn test_validation_events() {
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

    let validation_events = Arc::new(AtomicUsize::new(0));
    let events_clone = validation_events.clone();

    let mut rx = sdk.subscribe();

    let handle = tokio::spawn(async move {
        while let Ok(event) = rx.recv().await {
            match event.kind {
                EventKind::ValidationStart | EventKind::ValidationSuccess => {
                    events_clone.fetch_add(1, Ordering::SeqCst);
                }
                _ => {}
            }
        }
    });

    let _ = sdk.activate("TEST-KEY").await;
    let _ = sdk.validate().await;
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Should have received at least one validation event
    // (ValidationStart or ValidationSuccess)
    assert!(
        validation_events.load(Ordering::SeqCst) >= 1,
        "Should have received validation events, got: {}",
        validation_events.load(Ordering::SeqCst)
    );

    drop(handle);
}

#[tokio::test]
async fn test_deactivation_events() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path_regex(r"/products/.*/licenses/.*/activate"))
        .respond_with(ResponseTemplate::new(201).set_body_json(activation_response()))
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path_regex(r"/products/.*/licenses/.*/deactivate"))
        .respond_with(ResponseTemplate::new(200).set_body_json(deactivation_response()))
        .mount(&server)
        .await;

    let sdk = LicenseSeat::new(test_config(&server.uri()));

    let start_received = Arc::new(AtomicUsize::new(0));
    let success_received = Arc::new(AtomicUsize::new(0));

    let start_clone = start_received.clone();
    let success_clone = success_received.clone();

    let mut rx = sdk.subscribe();

    let handle = tokio::spawn(async move {
        while let Ok(event) = rx.recv().await {
            match event.kind {
                EventKind::DeactivationStart => {
                    start_clone.fetch_add(1, Ordering::SeqCst);
                }
                EventKind::DeactivationSuccess => {
                    success_clone.fetch_add(1, Ordering::SeqCst);
                }
                _ => {}
            }
        }
    });

    let _ = sdk.activate("TEST-KEY").await;
    let _ = sdk.deactivate().await;
    tokio::time::sleep(Duration::from_millis(100)).await;

    assert_eq!(start_received.load(Ordering::SeqCst), 1);
    assert_eq!(success_received.load(Ordering::SeqCst), 1);

    drop(handle);
}

#[tokio::test]
async fn test_activation_error_event() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path_regex(r"/products/.*/licenses/.*/activate"))
        .respond_with(ResponseTemplate::new(404).set_body_json(json!({
            "error": {
                "code": "license_not_found",
                "message": "License not found"
            }
        })))
        .mount(&server)
        .await;

    let sdk = LicenseSeat::new(test_config(&server.uri()));

    let error_received = Arc::new(AtomicUsize::new(0));
    let error_clone = error_received.clone();

    let mut rx = sdk.subscribe();

    let handle = tokio::spawn(async move {
        while let Ok(event) = rx.recv().await {
            if matches!(event.kind, EventKind::ActivationError) {
                error_clone.fetch_add(1, Ordering::SeqCst);
            }
        }
    });

    let _ = sdk.activate("INVALID-KEY").await;
    tokio::time::sleep(Duration::from_millis(100)).await;

    assert_eq!(error_received.load(Ordering::SeqCst), 1);

    drop(handle);
}

#[tokio::test]
async fn test_multiple_subscribers() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path_regex(r"/products/.*/licenses/.*/activate"))
        .respond_with(ResponseTemplate::new(201).set_body_json(activation_response()))
        .mount(&server)
        .await;

    let sdk = LicenseSeat::new(test_config(&server.uri()));

    let sub1_count = Arc::new(AtomicUsize::new(0));
    let sub2_count = Arc::new(AtomicUsize::new(0));

    let sub1_clone = sub1_count.clone();
    let sub2_clone = sub2_count.clone();

    let mut rx1 = sdk.subscribe();
    let mut rx2 = sdk.subscribe();

    let handle1 = tokio::spawn(async move {
        while rx1.recv().await.is_ok() {
            sub1_clone.fetch_add(1, Ordering::SeqCst);
        }
    });

    let handle2 = tokio::spawn(async move {
        while rx2.recv().await.is_ok() {
            sub2_clone.fetch_add(1, Ordering::SeqCst);
        }
    });

    let _ = sdk.activate("TEST-KEY").await;
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Both subscribers should receive events
    assert!(sub1_count.load(Ordering::SeqCst) > 0);
    assert!(sub2_count.load(Ordering::SeqCst) > 0);
    assert_eq!(
        sub1_count.load(Ordering::SeqCst),
        sub2_count.load(Ordering::SeqCst)
    );

    drop(handle1);
    drop(handle2);
}

// ============================================================================
// Event Kind Tests
// ============================================================================

#[test]
fn test_event_kind_variants() {
    // Ensure all expected event kinds exist
    let kinds = vec![
        EventKind::ActivationStart,
        EventKind::ActivationSuccess,
        EventKind::ActivationError,
        EventKind::ValidationStart,
        EventKind::ValidationSuccess,
        EventKind::ValidationError,
        EventKind::DeactivationStart,
        EventKind::DeactivationSuccess,
        EventKind::DeactivationError,
        EventKind::HeartbeatSuccess,
        EventKind::HeartbeatError,
        EventKind::SdkReset,
    ];

    // All should be displayable
    for kind in kinds {
        let event = Event::new(kind);
        // Event has kind and data fields
        assert!(!format!("{:?}", event.kind).is_empty());
    }
}

#[test]
fn test_event_kind_display() {
    // Test Display trait implementation
    assert_eq!(
        format!("{}", EventKind::ActivationStart),
        "activation:start"
    );
    assert_eq!(
        format!("{}", EventKind::ActivationSuccess),
        "activation:success"
    );
    assert_eq!(
        format!("{}", EventKind::ValidationSuccess),
        "validation:success"
    );
    assert_eq!(
        format!("{}", EventKind::DeactivationSuccess),
        "deactivation:success"
    );
}

#[test]
fn test_event_new() {
    let event = Event::new(EventKind::ActivationStart);

    // Event should have the correct kind
    assert!(matches!(event.kind, EventKind::ActivationStart));
    // And no data
    assert!(event.data.is_none());
}

#[test]
fn test_event_with_error() {
    let event = Event::with_error(EventKind::ActivationError, "Something went wrong");

    assert!(matches!(event.kind, EventKind::ActivationError));
    assert!(event.data.is_some());
}
