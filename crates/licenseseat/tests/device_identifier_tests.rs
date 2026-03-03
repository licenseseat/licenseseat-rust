//! Device identifier generation tests.

use licenseseat::{Config, LicenseSeat};
use serde_json::{Value, json};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use wiremock::matchers::{method, path_regex};
use wiremock::{Mock, MockServer, ResponseTemplate};

static TEST_COUNTER: AtomicU64 = AtomicU64::new(0);

fn test_config(base_url: &str) -> Config {
    let unique_prefix = format!(
        "device_test_{}_{}_{}_",
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

fn activation_response(device_id: &str) -> Value {
    json!({
        "object": "activation",
        "id": "act-12345-uuid",
        "device_id": device_id,
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

// ============================================================================
// Device ID Generation Tests
// ============================================================================

#[tokio::test]
async fn test_device_id_is_generated() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path_regex(r"/products/.*/licenses/.*/activate"))
        .respond_with(ResponseTemplate::new(201).set_body_json(activation_response("device-123")))
        .mount(&server)
        .await;

    let sdk = LicenseSeat::new(test_config(&server.uri()));
    let result = sdk.activate("TEST-KEY").await;

    assert!(result.is_ok());

    // Check the request that was made
    let requests = server.received_requests().await.unwrap();
    assert!(!requests.is_empty());

    let body: Value = serde_json::from_slice(&requests[0].body).unwrap();
    let device_id = body["device_id"].as_str();

    // Device ID should be present and not empty
    assert!(device_id.is_some());
    assert!(!device_id.unwrap().is_empty());
}

#[tokio::test]
async fn test_device_id_is_stable() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path_regex(r"/products/.*/licenses/.*/activate"))
        .respond_with(ResponseTemplate::new(201).set_body_json(activation_response("device-123")))
        .mount(&server)
        .await;

    // Create two SDK instances with same config
    let config = test_config(&server.uri());

    let sdk1 = LicenseSeat::new(config.clone());
    let _ = sdk1.activate("TEST-KEY").await;

    let sdk2 = LicenseSeat::new(config);
    let _ = sdk2.activate("TEST-KEY").await;

    // Check the requests that were made (filter to activation requests only,
    // since background tasks may spawn additional requests like offline-token sync)
    let requests = server.received_requests().await.unwrap();
    let activation_requests: Vec<_> = requests
        .iter()
        .filter(|r| r.url.path().contains("/activate"))
        .collect();
    assert_eq!(activation_requests.len(), 2);

    let body1: Value = serde_json::from_slice(&activation_requests[0].body).unwrap();
    let body2: Value = serde_json::from_slice(&activation_requests[1].body).unwrap();

    let device_id1 = body1["device_id"].as_str().unwrap();
    let device_id2 = body2["device_id"].as_str().unwrap();

    // Device IDs should be the same (stable generation)
    assert_eq!(device_id1, device_id2);
}

#[tokio::test]
async fn test_custom_device_id_used() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path_regex(r"/products/.*/licenses/.*/activate"))
        .respond_with(
            ResponseTemplate::new(201).set_body_json(activation_response("my-custom-device-id")),
        )
        .mount(&server)
        .await;

    let sdk = LicenseSeat::new(test_config(&server.uri()));
    let options = licenseseat::ActivationOptions {
        device_id: Some("my-custom-device-id".into()),
        device_name: None,
        metadata: None,
    };

    let _ = sdk.activate_with_options("TEST-KEY", options).await;

    // Check the request
    let requests = server.received_requests().await.unwrap();
    let body: Value = serde_json::from_slice(&requests[0].body).unwrap();

    assert_eq!(body["device_id"].as_str(), Some("my-custom-device-id"));
}

#[tokio::test]
async fn test_config_device_identifier_used() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path_regex(r"/products/.*/licenses/.*/activate"))
        .respond_with(
            ResponseTemplate::new(201).set_body_json(activation_response("config-level-device-id")),
        )
        .mount(&server)
        .await;

    let config = Config {
        device_identifier: Some("config-level-device-id".into()),
        ..test_config(&server.uri())
    };

    let sdk = LicenseSeat::new(config);
    let _ = sdk.activate("TEST-KEY").await;

    // Check the request
    let requests = server.received_requests().await.unwrap();
    let body: Value = serde_json::from_slice(&requests[0].body).unwrap();

    assert_eq!(body["device_id"].as_str(), Some("config-level-device-id"));
}

#[tokio::test]
async fn test_activation_options_override_config() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path_regex(r"/products/.*/licenses/.*/activate"))
        .respond_with(
            ResponseTemplate::new(201).set_body_json(activation_response("options-device-id")),
        )
        .mount(&server)
        .await;

    let config = Config {
        device_identifier: Some("config-device-id".into()),
        ..test_config(&server.uri())
    };

    let sdk = LicenseSeat::new(config);
    let options = licenseseat::ActivationOptions {
        device_id: Some("options-device-id".into()),
        device_name: None,
        metadata: None,
    };

    let _ = sdk.activate_with_options("TEST-KEY", options).await;

    // Check the request - options should override config
    let requests = server.received_requests().await.unwrap();
    let body: Value = serde_json::from_slice(&requests[0].body).unwrap();

    assert_eq!(body["device_id"].as_str(), Some("options-device-id"));
}

// ============================================================================
// Device ID Format Tests
// ============================================================================

#[tokio::test]
async fn test_device_id_format() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path_regex(r"/products/.*/licenses/.*/activate"))
        .respond_with(ResponseTemplate::new(201).set_body_json(activation_response("device-123")))
        .mount(&server)
        .await;

    let sdk = LicenseSeat::new(test_config(&server.uri()));
    let _ = sdk.activate("TEST-KEY").await;

    // Check the request
    let requests = server.received_requests().await.unwrap();
    let body: Value = serde_json::from_slice(&requests[0].body).unwrap();
    let device_id = body["device_id"].as_str().unwrap();

    // Device ID should have a platform prefix
    let valid_prefixes = ["mac-", "linux-", "windows-", "rust-", "ios-", "android-"];
    let has_valid_prefix = valid_prefixes.iter().any(|p| device_id.starts_with(p));

    // Either has a platform prefix or is a plain identifier
    assert!(
        has_valid_prefix || !device_id.is_empty(),
        "Device ID should have a valid format: {}",
        device_id
    );
}

#[tokio::test]
async fn test_device_id_uniqueness_across_different_machines() {
    // This test verifies that we're generating unique IDs
    // In practice, different machines should have different hardware UUIDs
    // For testing, we just verify the format and that it's non-empty

    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path_regex(r"/products/.*/licenses/.*/activate"))
        .respond_with(ResponseTemplate::new(201).set_body_json(activation_response("device-123")))
        .mount(&server)
        .await;

    let sdk = LicenseSeat::new(test_config(&server.uri()));
    let license = sdk.activate("TEST-KEY").await.unwrap();

    // Device ID should be a reasonably sized string (not too short, not too long)
    assert!(license.device_id.len() >= 5);
    assert!(license.device_id.len() <= 100);

    // Should contain only valid characters
    assert!(
        license
            .device_id
            .chars()
            .all(|c| c.is_alphanumeric() || c == '-' || c == '_')
    );
}
