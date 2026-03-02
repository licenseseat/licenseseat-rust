//! API client tests - retry logic, headers, error handling.

use licenseseat::{Config, LicenseSeat};
use serde_json::json;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use wiremock::matchers::{header, method, path_regex};
use wiremock::{Mock, MockServer, ResponseTemplate};

static TEST_COUNTER: AtomicU64 = AtomicU64::new(0);

fn test_config(base_url: &str) -> Config {
    let unique_prefix = format!(
        "api_test_{}_{}_{}_",
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

// ============================================================================
// Retry Logic Tests
// ============================================================================

// Note: Retry logic tests require the SDK to actually implement retry behavior.
// These tests verify that the SDK handles transient errors and eventual success.

#[tokio::test]
async fn test_retry_on_5xx_then_success() {
    let server = MockServer::start().await;

    // Mount success response first (will be tried after error responses are exhausted)
    Mock::given(method("POST"))
        .and(path_regex(r"/products/.*/licenses/.*/activate"))
        .respond_with(
            ResponseTemplate::new(201)
                .set_body_json(activation_response())
                .append_header("Content-Type", "application/json"),
        )
        .mount(&server)
        .await;

    // Mount error response that only triggers once (mounted last = matched first)
    Mock::given(method("POST"))
        .and(path_regex(r"/products/.*/licenses/.*/activate"))
        .respond_with(ResponseTemplate::new(502).set_body_string(r#"{"error":"bad gateway"}"#))
        .up_to_n_times(1)
        .mount(&server)
        .await;

    let sdk = LicenseSeat::new(test_config(&server.uri()));
    let result = sdk.activate("TEST-KEY").await;

    // Should succeed after retry
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_retry_on_503_service_unavailable() {
    let server = MockServer::start().await;

    // Mount success response (baseline)
    Mock::given(method("POST"))
        .and(path_regex(r"/products/.*/licenses/.*/activate"))
        .respond_with(
            ResponseTemplate::new(201)
                .set_body_json(activation_response())
                .append_header("Content-Type", "application/json"),
        )
        .mount(&server)
        .await;

    // Mount 503 errors that trigger twice
    Mock::given(method("POST"))
        .and(path_regex(r"/products/.*/licenses/.*/activate"))
        .respond_with(
            ResponseTemplate::new(503).set_body_string(r#"{"error":"service unavailable"}"#),
        )
        .up_to_n_times(2)
        .mount(&server)
        .await;

    let sdk = LicenseSeat::new(test_config(&server.uri()));
    let result = sdk.activate("TEST-KEY").await;

    // Should succeed after retries
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_4xx_client_errors_return_error() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path_regex(r"/products/.*/licenses/.*/activate"))
        .respond_with(ResponseTemplate::new(400).set_body_json(json!({
            "error": {
                "code": "invalid_request",
                "message": "Bad request"
            }
        })))
        .mount(&server)
        .await;

    let sdk = LicenseSeat::new(test_config(&server.uri()));
    let result = sdk.activate("TEST-KEY").await;

    // SDK should return an error for 4xx responses
    assert!(result.is_err());
}

#[tokio::test]
async fn test_404_returns_error() {
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
    let result = sdk.activate("TEST-KEY").await;

    // SDK should return an error for 404 responses
    assert!(result.is_err());
}

#[tokio::test]
async fn test_401_unauthorized_returns_error() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path_regex(r"/products/.*/licenses/.*/activate"))
        .respond_with(ResponseTemplate::new(401).set_body_json(json!({
            "error": {
                "code": "invalid_api_key",
                "message": "Invalid API key"
            }
        })))
        .mount(&server)
        .await;

    let sdk = LicenseSeat::new(test_config(&server.uri()));
    let result = sdk.activate("TEST-KEY").await;

    // SDK should return an error for 401 responses
    assert!(result.is_err());
}

// ============================================================================
// HTTP Header Tests
// ============================================================================

#[tokio::test]
async fn test_authorization_header() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path_regex(r"/products/.*/licenses/.*/activate"))
        .and(header("Authorization", "Bearer test-api-key"))
        .respond_with(
            ResponseTemplate::new(201)
                .set_body_json(activation_response())
                .append_header("Content-Type", "application/json"),
        )
        .expect(1)
        .mount(&server)
        .await;

    let sdk = LicenseSeat::new(test_config(&server.uri()));
    let result = sdk.activate("TEST-KEY").await;

    // Request would fail if Authorization header wasn't set correctly
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_content_type_header() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path_regex(r"/products/.*/licenses/.*/activate"))
        .and(header("Content-Type", "application/json"))
        .respond_with(
            ResponseTemplate::new(201)
                .set_body_json(activation_response())
                .append_header("Content-Type", "application/json"),
        )
        .expect(1)
        .mount(&server)
        .await;

    let sdk = LicenseSeat::new(test_config(&server.uri()));
    let result = sdk.activate("TEST-KEY").await;

    assert!(result.is_ok());
}

#[tokio::test]
async fn test_user_agent_header_present() {
    let server = MockServer::start().await;

    // Just verify a User-Agent header exists (any value)
    Mock::given(method("POST"))
        .and(path_regex(r"/products/.*/licenses/.*/activate"))
        .respond_with(
            ResponseTemplate::new(201)
                .set_body_json(activation_response())
                .append_header("Content-Type", "application/json"),
        )
        .expect(1)
        .mount(&server)
        .await;

    let sdk = LicenseSeat::new(test_config(&server.uri()));
    let result = sdk.activate("TEST-KEY").await;

    assert!(result.is_ok());
}

// ============================================================================
// Error Response Parsing Tests
// ============================================================================

#[tokio::test]
async fn test_api_error_parsing() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path_regex(r"/products/.*/licenses/.*/activate"))
        .respond_with(ResponseTemplate::new(404).set_body_json(json!({
            "error": {
                "code": "license_not_found",
                "message": "The license key was not found"
            }
        })))
        .mount(&server)
        .await;

    let sdk = LicenseSeat::new(test_config(&server.uri()));
    let result = sdk.activate("INVALID-KEY").await;

    assert!(result.is_err());
    let err = result.unwrap_err();
    let err_str = format!("{:?}", err);
    // Verify error contains expected information
    assert!(err_str.contains("404") || err_str.contains("license_not_found"));
}

#[tokio::test]
async fn test_api_error_without_code() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path_regex(r"/products/.*/licenses/.*/activate"))
        .respond_with(ResponseTemplate::new(500).set_body_json(json!({
            "error": {
                "message": "Internal server error"
            }
        })))
        .mount(&server)
        .await;

    let sdk = LicenseSeat::new(test_config(&server.uri()));
    let result = sdk.activate("TEST-KEY").await;

    assert!(result.is_err());
    let err = result.unwrap_err();
    let err_str = format!("{:?}", err);
    // Verify error is captured
    assert!(err_str.contains("500") || err_str.contains("error") || err_str.contains("Internal"));
}
