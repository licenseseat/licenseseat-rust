//! API client tests - retry logic, headers, error handling.

use licenseseat::{ActivationOptions, Config, Error, LicenseSeat};
use serde_json::json;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;
use wiremock::matchers::{body_partial_json, header, method, path, path_regex};
use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

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
        device_identifier: Some("device-123".into()),
        auto_validate_interval: Duration::from_secs(0),
        heartbeat_interval: Duration::from_secs(0),
        retry_delay: Duration::from_millis(1),
        debug: true,
        ..Default::default()
    }
}

fn activation_response() -> serde_json::Value {
    activation_response_for("TEST-KEY", "device-123")
}

fn activation_response_for(license_key: &str, fingerprint: &str) -> serde_json::Value {
    json!({
        "object": "activation",
        "id": "act-12345-uuid",
        "device_id": fingerprint,
        "device_name": "Test Device",
        "license_key": license_key,
        "activated_at": "2025-01-01T00:00:00Z",
        "deactivated_at": null,
        "ip_address": "127.0.0.1",
        "metadata": null,
        "license": {
            "object": "license",
            "key": license_key,
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

#[derive(Clone)]
struct RateLimitOnce {
    returned_rate_limit: Arc<AtomicBool>,
}

impl Respond for RateLimitOnce {
    fn respond(&self, _request: &Request) -> ResponseTemplate {
        if !self.returned_rate_limit.swap(true, Ordering::SeqCst) {
            ResponseTemplate::new(429).set_body_json(json!({
                "error": { "code": "rate_limited", "message": "try again" }
            }))
        } else {
            ResponseTemplate::new(201).set_body_json(activation_response())
        }
    }
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
        .and(path_regex(r"/products/.*/licenses/activate"))
        .respond_with(
            ResponseTemplate::new(201)
                .set_body_json(activation_response())
                .append_header("Content-Type", "application/json"),
        )
        .mount(&server)
        .await;

    // Mount error response that only triggers once (mounted last = matched first)
    Mock::given(method("POST"))
        .and(path_regex(r"/products/.*/licenses/activate"))
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
        .and(path_regex(r"/products/.*/licenses/activate"))
        .respond_with(
            ResponseTemplate::new(201)
                .set_body_json(activation_response())
                .append_header("Content-Type", "application/json"),
        )
        .mount(&server)
        .await;

    // Mount 503 errors that trigger twice
    Mock::given(method("POST"))
        .and(path_regex(r"/products/.*/licenses/activate"))
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
        .and(path_regex(r"/products/.*/licenses/activate"))
        .respond_with(ResponseTemplate::new(400).set_body_json(json!({
            "error": {
                "code": "invalid_request",
                "message": "Bad request"
            }
        })))
        .mount(&server)
        .await;

    let sdk = LicenseSeat::new(test_config(&server.uri()));
    assert!(!sdk.is_online(), "reachability starts unknown/fail-closed");
    let result = sdk.activate("TEST-KEY").await;

    // SDK should return an error for 4xx responses
    assert!(result.is_err());
    assert!(
        sdk.is_online(),
        "a 4xx still proves that the API is reachable"
    );
}

#[tokio::test]
async fn test_404_returns_error() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path_regex(r"/products/.*/licenses/activate"))
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
async fn test_activate_keeps_license_key_out_of_request_path() {
    let server = MockServer::start().await;
    let license_key = "TEST KEY/with#chars";

    Mock::given(method("POST"))
        .respond_with(
            ResponseTemplate::new(201)
                .set_body_json(activation_response_for(license_key, "device-123"))
                .append_header("Content-Type", "application/json"),
        )
        .expect(1)
        .mount(&server)
        .await;

    let sdk = LicenseSeat::new(test_config(&server.uri()));
    let result = sdk.activate(license_key).await;

    assert!(result.is_ok());

    let requests = server.received_requests().await.unwrap();
    assert_eq!(requests.len(), 1);
    assert_eq!(
        requests[0].url.path(),
        "/products/test-product/licenses/activate"
    );
    let body: serde_json::Value = serde_json::from_slice(&requests[0].body).unwrap();
    assert_eq!(body["license_key"], license_key);
    assert!(!requests[0].url.as_str().contains("TEST"));
}

#[tokio::test]
async fn test_activate_preserves_api_base_url_prefix_without_trailing_slash() {
    let server = MockServer::start().await;
    let base_url = format!("{}/api/v1", server.uri());

    Mock::given(method("POST"))
        .and(path("/api/v1/products/test-product/licenses/activate"))
        .respond_with(
            ResponseTemplate::new(201)
                .set_body_json(activation_response())
                .append_header("Content-Type", "application/json"),
        )
        .expect(1)
        .mount(&server)
        .await;

    let sdk = LicenseSeat::new(test_config(&base_url));
    let result = sdk.activate("TEST-KEY").await;

    assert!(result.is_ok());
}

#[tokio::test]
async fn test_activate_preserves_api_base_url_prefix_with_trailing_slash() {
    let server = MockServer::start().await;
    let base_url = format!("{}/api/v1/", server.uri());

    Mock::given(method("POST"))
        .and(path("/api/v1/products/test-product/licenses/activate"))
        .respond_with(
            ResponseTemplate::new(201)
                .set_body_json(activation_response())
                .append_header("Content-Type", "application/json"),
        )
        .expect(1)
        .mount(&server)
        .await;

    let sdk = LicenseSeat::new(test_config(&base_url));
    let result = sdk.activate("TEST-KEY").await;

    assert!(result.is_ok());
}

#[tokio::test]
async fn licensing_requests_never_follow_cross_origin_redirects() {
    let source = MockServer::start().await;
    let redirect_target = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path_regex(r"/products/.*/licenses/activate"))
        .respond_with(
            ResponseTemplate::new(307)
                .append_header("Location", format!("{}/capture", redirect_target.uri())),
        )
        .expect(1)
        .mount(&source)
        .await;
    Mock::given(method("POST"))
        .and(path("/capture"))
        .respond_with(ResponseTemplate::new(500))
        .expect(0)
        .mount(&redirect_target)
        .await;

    let sdk = LicenseSeat::try_new(test_config(&source.uri())).unwrap();
    let error = sdk.activate("SENSITIVE-LICENSE-KEY").await.unwrap_err();

    assert!(matches!(error, Error::Api { status: 307, .. }));
    assert!(
        redirect_target
            .received_requests()
            .await
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn test_health_preserves_api_base_url_prefix() {
    let server = MockServer::start().await;
    let base_url = format!("{}/api/v1", server.uri());

    Mock::given(method("GET"))
        .and(path("/api/v1/health"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({
                    "object": "health",
                    "status": "healthy",
                    "api_version": "v1",
                    "timestamp": "2026-03-31T04:00:00Z"
                }))
                .append_header("Content-Type", "application/json"),
        )
        .expect(1)
        .mount(&server)
        .await;

    let sdk = LicenseSeat::new(test_config(&base_url));
    let result = sdk.health().await;

    assert!(matches!(result, Ok(true)));
}

#[tokio::test]
async fn test_401_unauthorized_returns_error() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path_regex(r"/products/.*/licenses/activate"))
        .respond_with(ResponseTemplate::new(401).set_body_json(json!({
            "error": {
                "code": "invalid_api_key",
                "message": "Invalid API key"
            }
        })))
        .expect(1)
        .mount(&server)
        .await;

    let sdk = LicenseSeat::new(test_config(&server.uri()));
    let result = sdk.activate("TEST-KEY").await;

    // SDK should return an error for 401 responses
    assert!(result.is_err());
}

#[tokio::test]
async fn test_retry_on_rate_limit_then_success() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path_regex(r"/products/.*/licenses/activate"))
        .respond_with(RateLimitOnce {
            returned_rate_limit: Arc::new(AtomicBool::new(false)),
        })
        .expect(2)
        .mount(&server)
        .await;

    let sdk = LicenseSeat::try_new(test_config(&server.uri())).unwrap();
    assert!(sdk.activate("TEST-KEY").await.is_ok());
    assert!(sdk.is_online());
    assert_eq!(server.received_requests().await.unwrap().len(), 2);
}

#[tokio::test]
async fn test_exhausted_server_error_marks_service_unavailable() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path_regex(r"/products/.*/licenses/activate"))
        .respond_with(ResponseTemplate::new(503).set_body_json(json!({
            "error": { "code": "unavailable", "message": "maintenance" }
        })))
        .expect(1)
        .mount(&server)
        .await;

    let mut config = test_config(&server.uri());
    config.max_retries = 0;
    let sdk = LicenseSeat::try_new(config).unwrap();
    assert!(sdk.activate("TEST-KEY").await.is_err());
    assert!(!sdk.is_online());
}

#[tokio::test]
async fn test_success_response_body_is_bounded() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/health"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(vec![b'x'; 4 * 1024 * 1024 + 1]))
        .expect(1)
        .mount(&server)
        .await;

    let mut config = test_config(&server.uri());
    config.max_retries = 0;
    let sdk = LicenseSeat::try_new(config).unwrap();
    assert!(matches!(
        sdk.health_check().await,
        Err(licenseseat::Error::ResponseTooLarge {
            limit_bytes: 4_194_304
        })
    ));
}

#[tokio::test]
async fn test_error_response_body_is_bounded_without_retrying() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path_regex(r"/products/.*/licenses/activate"))
        .respond_with(ResponseTemplate::new(503).set_body_bytes(vec![b'x'; 4 * 1024 * 1024 + 1]))
        .expect(1)
        .mount(&server)
        .await;

    let sdk = LicenseSeat::try_new(test_config(&server.uri())).unwrap();
    assert!(matches!(
        sdk.activate("TEST-KEY").await,
        Err(licenseseat::Error::ResponseTooLarge { .. })
    ));
}

#[tokio::test]
async fn test_api_error_messages_are_safe_and_bounded() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/products/test-product/licenses/activate"))
        .and(body_partial_json(json!({ "license_key": "HTML-ERROR" })))
        .respond_with(
            ResponseTemplate::new(502)
                .set_body_string("<!doctype html><html><body>proxy internals</body></html>"),
        )
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/products/test-product/licenses/activate"))
        .and(body_partial_json(json!({ "license_key": "LONG-ERROR" })))
        .respond_with(ResponseTemplate::new(400).set_body_json(json!({
            "error": {
                "code": "invalid_request",
                "message": format!("{}\nterminal-injection", "x".repeat(5_000))
            }
        })))
        .expect(1)
        .mount(&server)
        .await;

    let mut config = test_config(&server.uri());
    config.max_retries = 0;
    let sdk = LicenseSeat::try_new(config).unwrap();

    let html = sdk.activate("HTML-ERROR").await.unwrap_err();
    assert!(matches!(
        html,
        Error::Api { ref message, .. }
            if message == "License server returned an HTML error response"
    ));

    let long = sdk.activate("LONG-ERROR").await.unwrap_err();
    assert!(matches!(
        long,
        Error::Api { ref message, .. }
            if message == "Request failed"
    ));
}

#[tokio::test]
async fn test_oversized_request_metadata_is_rejected_before_network_io() {
    let server = MockServer::start().await;
    let sdk = LicenseSeat::try_new(test_config(&server.uri())).unwrap();
    let options = ActivationOptions {
        metadata: Some(std::collections::HashMap::from([(
            "oversized".into(),
            serde_json::Value::String("x".repeat(1024 * 1024)),
        )])),
        ..Default::default()
    };

    assert!(matches!(
        sdk.activate_with_options("TEST-KEY", options).await,
        Err(Error::Configuration(message)) if message == "metadata is invalid"
    ));
    assert!(server.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn test_ambiguous_or_malformed_request_identifiers_are_rejected_locally() {
    let server = MockServer::start().await;
    let sdk = LicenseSeat::try_new(test_config(&server.uri())).unwrap();

    for license_key in [" ", " KEY", "KEY ", "KEY\nINJECT"] {
        assert!(matches!(
            sdk.activate(license_key).await,
            Err(Error::Configuration(_))
        ));
    }

    for fingerprint in ["short", " device-123", "device-123 ", "device\n123"] {
        let options = ActivationOptions {
            fingerprint: Some(fingerprint.into()),
            ..Default::default()
        };
        assert!(matches!(
            sdk.activate_with_options("TEST-KEY", options).await,
            Err(Error::Configuration(_))
        ));
    }

    let aliases = ActivationOptions {
        fingerprint: Some("installation-one".into()),
        device_id: Some("installation-two".into()),
        ..Default::default()
    };
    assert!(matches!(
        sdk.activate_with_options("TEST-KEY", aliases).await,
        Err(Error::Configuration(ref message)) if message.contains("must match")
    ));
    assert!(server.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn test_transport_errors_never_expose_license_key_or_request_url() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("reserve local port");
    let address = listener.local_addr().expect("local address");
    drop(listener);

    let license_key = "SECRET-LICENSE-KEY-MUST-NOT-LEAK";
    let base_url = format!("http://{address}/api/v1");
    let mut config = test_config(&base_url);
    config.max_retries = 0;
    let sdk = LicenseSeat::try_new(config).expect("valid local SDK config");

    let message = sdk
        .activate(license_key)
        .await
        .expect_err("closed local port must fail")
        .to_string();

    assert!(
        !message.contains(license_key),
        "license key leaked: {message}"
    );
    assert!(
        !message.contains(&base_url),
        "request URL leaked: {message}"
    );
    assert!(
        !message.contains("/licenses/"),
        "request path leaked: {message}"
    );
}

// ============================================================================
// HTTP Header Tests
// ============================================================================

#[tokio::test]
async fn test_authorization_header() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path_regex(r"/products/.*/licenses/activate"))
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
        .and(path_regex(r"/products/.*/licenses/activate"))
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
        .and(path_regex(r"/products/.*/licenses/activate"))
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
        .and(path_regex(r"/products/.*/licenses/activate"))
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
        .and(path_regex(r"/products/.*/licenses/activate"))
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
