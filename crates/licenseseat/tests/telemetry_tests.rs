//! Telemetry collection and API integration tests.

use licenseseat::{Config, LicenseSeat};
use serde_json::{Value, json};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use wiremock::matchers::{method, path_regex};
use wiremock::{Mock, MockServer, ResponseTemplate};

static TEST_COUNTER: AtomicU64 = AtomicU64::new(0);

fn test_config(base_url: &str, telemetry_enabled: bool) -> Config {
    let unique_prefix = format!(
        "telemetry_test_{}_{}_{}_",
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
        telemetry_enabled,
        app_version: Some("1.2.3".into()),
        app_build: Some("42".into()),
        ..Default::default()
    }
}

fn activation_response() -> Value {
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

fn heartbeat_response() -> Value {
    json!({
        "object": "heartbeat",
        "status": "ok",
        "received_at": "2025-01-01T00:00:00Z"
    })
}

fn validation_response() -> Value {
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

// ============================================================================
// Telemetry Payload Tests
// ============================================================================

#[tokio::test]
async fn test_telemetry_included_in_activation_request() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path_regex(r"/products/.*/licenses/.*/activate"))
        .respond_with(ResponseTemplate::new(201).set_body_json(activation_response()))
        .mount(&server)
        .await;

    let sdk = LicenseSeat::new(test_config(&server.uri(), true));
    let _ = sdk.activate("TEST-KEY").await;

    // Check the request that was made
    let requests = server.received_requests().await.unwrap();
    assert!(!requests.is_empty());

    let body: Value = serde_json::from_slice(&requests[0].body).unwrap();
    let telemetry = &body["telemetry"];

    // Check required telemetry fields
    assert!(telemetry["sdk_name"].is_string());
    assert_eq!(telemetry["sdk_name"].as_str(), Some("rust"));

    assert!(telemetry["sdk_version"].is_string());

    // OS info should be present
    assert!(telemetry["os_name"].is_string());
    assert!(telemetry["os_version"].is_string());

    // Platform should be present
    assert!(telemetry["platform"].is_string());
}

#[tokio::test]
async fn test_telemetry_includes_app_version() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path_regex(r"/products/.*/licenses/.*/activate"))
        .respond_with(ResponseTemplate::new(201).set_body_json(activation_response()))
        .mount(&server)
        .await;

    let sdk = LicenseSeat::new(test_config(&server.uri(), true));
    let _ = sdk.activate("TEST-KEY").await;

    let requests = server.received_requests().await.unwrap();
    let body: Value = serde_json::from_slice(&requests[0].body).unwrap();
    let telemetry = &body["telemetry"];

    assert_eq!(telemetry["app_version"].as_str(), Some("1.2.3"));
    assert_eq!(telemetry["app_build"].as_str(), Some("42"));
}

#[tokio::test]
async fn test_telemetry_excluded_when_disabled() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path_regex(r"/products/.*/licenses/.*/activate"))
        .respond_with(ResponseTemplate::new(201).set_body_json(activation_response()))
        .mount(&server)
        .await;

    let sdk = LicenseSeat::new(test_config(&server.uri(), false)); // telemetry disabled
    let _ = sdk.activate("TEST-KEY").await;

    let requests = server.received_requests().await.unwrap();
    assert!(!requests.is_empty());

    let body: Value = serde_json::from_slice(&requests[0].body).unwrap();
    // Telemetry should be null or missing
    assert!(body["telemetry"].is_null() || !body.as_object().unwrap().contains_key("telemetry"));
}

#[tokio::test]
async fn test_telemetry_included_in_heartbeat() {
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

    let sdk = LicenseSeat::new(test_config(&server.uri(), true));
    let _ = sdk.activate("TEST-KEY").await;
    let _ = sdk.heartbeat().await;

    let requests = server.received_requests().await.unwrap();
    // Find the heartbeat request
    let heartbeat_req = requests
        .iter()
        .find(|r| r.url.path().contains("heartbeat"))
        .expect("Should have heartbeat request");

    let body: Value = serde_json::from_slice(&heartbeat_req.body).unwrap();
    let telemetry = &body["telemetry"];

    assert!(telemetry["sdk_name"].is_string());
    assert!(telemetry["sdk_version"].is_string());
}

#[tokio::test]
async fn test_telemetry_included_in_validation() {
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

    let sdk = LicenseSeat::new(test_config(&server.uri(), true));
    let _ = sdk.activate("TEST-KEY").await;
    let _ = sdk.validate().await;

    let requests = server.received_requests().await.unwrap();
    // Find the validate request
    let validate_req = requests
        .iter()
        .find(|r| r.url.path().contains("validate"))
        .expect("Should have validate request");

    let body: Value = serde_json::from_slice(&validate_req.body).unwrap();
    let telemetry = &body["telemetry"];

    assert!(telemetry["sdk_name"].is_string());
    assert!(telemetry["sdk_version"].is_string());
}

// ============================================================================
// Telemetry Field Validation Tests
// ============================================================================

#[tokio::test]
async fn test_telemetry_has_required_fields() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path_regex(r"/products/.*/licenses/.*/activate"))
        .respond_with(ResponseTemplate::new(201).set_body_json(activation_response()))
        .mount(&server)
        .await;

    let sdk = LicenseSeat::new(test_config(&server.uri(), true));
    let _ = sdk.activate("TEST-KEY").await;

    let requests = server.received_requests().await.unwrap();
    let body: Value = serde_json::from_slice(&requests[0].body).unwrap();
    let telemetry = &body["telemetry"];

    // Required fields (should always be present)
    assert!(telemetry.get("sdk_name").is_some());
    assert!(telemetry.get("sdk_version").is_some());
    assert!(telemetry.get("os_name").is_some());
    assert!(telemetry.get("platform").is_some());
}

#[tokio::test]
async fn test_telemetry_fields_are_snake_case() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path_regex(r"/products/.*/licenses/.*/activate"))
        .respond_with(ResponseTemplate::new(201).set_body_json(activation_response()))
        .mount(&server)
        .await;

    let sdk = LicenseSeat::new(test_config(&server.uri(), true));
    let _ = sdk.activate("TEST-KEY").await;

    let requests = server.received_requests().await.unwrap();
    let body: Value = serde_json::from_slice(&requests[0].body).unwrap();
    let telemetry = body["telemetry"].as_object().unwrap();

    // All keys should be snake_case
    for key in telemetry.keys() {
        assert!(
            key.chars()
                .all(|c| c.is_lowercase() || c.is_numeric() || c == '_'),
            "Key '{}' should be snake_case",
            key
        );
    }
}

#[tokio::test]
async fn test_telemetry_no_null_values() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path_regex(r"/products/.*/licenses/.*/activate"))
        .respond_with(ResponseTemplate::new(201).set_body_json(activation_response()))
        .mount(&server)
        .await;

    let sdk = LicenseSeat::new(test_config(&server.uri(), true));
    let _ = sdk.activate("TEST-KEY").await;

    let requests = server.received_requests().await.unwrap();
    let body: Value = serde_json::from_slice(&requests[0].body).unwrap();
    let telemetry = body["telemetry"].as_object().unwrap();

    // No values should be null (they should be omitted instead)
    for (key, value) in telemetry {
        assert!(
            !value.is_null(),
            "Telemetry key '{}' should not have null value",
            key
        );
    }
}

// ============================================================================
// Config Tests for Telemetry
// ============================================================================

#[test]
fn test_telemetry_enabled_default() {
    let config = Config::default();
    assert!(config.telemetry_enabled);
}

#[test]
fn test_telemetry_can_be_disabled() {
    let config = Config {
        telemetry_enabled: false,
        ..Default::default()
    };
    assert!(!config.telemetry_enabled);
}

#[test]
fn test_app_version_default_none() {
    let config = Config::default();
    assert!(config.app_version.is_none());
    assert!(config.app_build.is_none());
}

#[test]
fn test_app_version_can_be_set() {
    let config = Config {
        app_version: Some("2.0.0".into()),
        app_build: Some("100".into()),
        ..Default::default()
    };
    assert_eq!(config.app_version.as_deref(), Some("2.0.0"));
    assert_eq!(config.app_build.as_deref(), Some("100"));
}
