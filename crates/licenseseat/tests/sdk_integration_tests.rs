//! Integration tests for the LicenseSeat SDK.
//!
//! These tests use wiremock to mock HTTP responses and verify the full
//! SDK flow from activation through validation and deactivation.

use chrono::Utc;
use licenseseat::{
    Config, EntitlementReason, LicenseSeat, LicenseStatus, OfflineFallbackMode,
};
use serde_json::json;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use wiremock::matchers::{header, method, path_regex};
use wiremock::{Mock, MockServer, ResponseTemplate};

// ============================================================================
// Test Helpers
// ============================================================================

// Counter to generate unique prefixes for test isolation
static TEST_COUNTER: AtomicU64 = AtomicU64::new(0);

fn test_config(base_url: &str) -> Config {
    // Use a unique prefix for each test to isolate the cache
    let unique_prefix = format!(
        "test_{}_{}_{}_",
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
        auto_validate_interval: Duration::from_secs(0), // Disable for tests
        heartbeat_interval: Duration::from_secs(0),     // Disable for tests
        offline_fallback_mode: OfflineFallbackMode::NetworkOnly,
        max_offline_days: 0,
        debug: true,
        telemetry_enabled: true,
        ..Default::default()
    }
}

fn activation_response(license_key: &str, device_id: &str) -> serde_json::Value {
    json!({
        "object": "activation",
        "id": "act-12345-uuid",
        "device_id": device_id,
        "device_name": "Test Device",
        "license_key": license_key,
        "activated_at": Utc::now().to_rfc3339(),
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

fn validation_response(valid: bool, license_key: &str) -> serde_json::Value {
    let status = if valid { "active" } else { "expired" };
    let mut response = json!({
        "object": "validation_result",
        "valid": valid,
        "warnings": null,
        "license": {
            "object": "license",
            "key": license_key,
            "status": status,
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
    });
    if valid {
        response["code"] = serde_json::Value::Null;
        response["message"] = serde_json::Value::Null;
    } else {
        response["code"] = json!("license_expired");
        response["message"] = json!("License has expired");
    }
    response
}

fn validation_with_entitlements(license_key: &str) -> serde_json::Value {
    json!({
        "object": "validation_result",
        "valid": true,
        "code": null,
        "message": null,
        "warnings": null,
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
            "active_entitlements": [
                {
                    "key": "pro-features",
                    "expires_at": null,
                    "metadata": null
                },
                {
                    "key": "api-access",
                    "expires_at": null,
                    "metadata": null
                }
            ],
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
        "deactivated_at": Utc::now().to_rfc3339()
    })
}

fn heartbeat_response(license_key: &str) -> serde_json::Value {
    json!({
        "object": "heartbeat",
        "received_at": Utc::now().to_rfc3339(),
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

fn api_error_response(code: &str, message: &str) -> serde_json::Value {
    json!({
        "error": {
            "code": code,
            "message": message
        }
    })
}

// ============================================================================
// Configuration Tests
// ============================================================================

#[tokio::test]
async fn test_default_configuration() {
    let config = Config::default();

    assert_eq!(config.api_base_url, "https://licenseseat.com/api/v1");
    assert_eq!(config.auto_validate_interval, Duration::from_secs(3600));
    assert_eq!(config.heartbeat_interval, Duration::from_secs(300));
    assert!(!config.debug);
    assert!(config.telemetry_enabled);
}

#[tokio::test]
async fn test_custom_configuration() {
    let config = Config {
        api_key: "custom-key".into(),
        product_slug: "custom-product".into(),
        api_base_url: "https://custom.api.com".into(),
        auto_validate_interval: Duration::from_secs(1800),
        heartbeat_interval: Duration::from_secs(60),
        max_offline_days: 7,
        debug: true,
        telemetry_enabled: false,
        ..Default::default()
    };

    assert_eq!(config.api_key, "custom-key");
    assert_eq!(config.product_slug, "custom-product");
    assert_eq!(config.api_base_url, "https://custom.api.com");
    assert_eq!(config.auto_validate_interval, Duration::from_secs(1800));
    assert_eq!(config.heartbeat_interval, Duration::from_secs(60));
    assert_eq!(config.max_offline_days, 7);
    assert!(config.debug);
    assert!(!config.telemetry_enabled);
}

#[tokio::test]
async fn test_offline_fallback_mode_default() {
    let config = Config::default();
    assert!(matches!(
        config.offline_fallback_mode,
        OfflineFallbackMode::NetworkOnly
    ));
}

// ============================================================================
// Activation Tests
// ============================================================================

#[tokio::test]
async fn test_activation_success() {
    let server = MockServer::start().await;
    let license_key = "TEST-LICENSE-KEY";

    Mock::given(method("POST"))
        .and(path_regex(r"/products/.*/licenses/.*/activate"))
        .respond_with(
            ResponseTemplate::new(201)
                .set_body_json(activation_response(license_key, "device-123")),
        )
        .mount(&server)
        .await;

    let sdk = LicenseSeat::new(test_config(&server.uri()));
    let result = sdk.activate(license_key).await;

    assert!(result.is_ok());
    let license = result.unwrap();
    assert_eq!(license.license_key, license_key);
    assert_eq!(license.activation_id, "act-12345-uuid");
    assert!(!license.device_id.is_empty());
}

#[tokio::test]
async fn test_activation_caches_license() {
    let server = MockServer::start().await;
    let license_key = "TEST-LICENSE-KEY";

    Mock::given(method("POST"))
        .and(path_regex(r"/products/.*/licenses/.*/activate"))
        .respond_with(
            ResponseTemplate::new(201)
                .set_body_json(activation_response(license_key, "device-123")),
        )
        .mount(&server)
        .await;

    let sdk = LicenseSeat::new(test_config(&server.uri()));
    let _ = sdk.activate(license_key).await.unwrap();

    // License should now be cached
    let cached = sdk.current_license();
    assert!(cached.is_some());
    assert_eq!(cached.unwrap().license_key, license_key);
}

#[tokio::test]
async fn test_activation_with_custom_device_id() {
    let server = MockServer::start().await;
    let license_key = "TEST-LICENSE-KEY";
    let custom_device_id = "custom-device-12345";

    Mock::given(method("POST"))
        .and(path_regex(r"/products/.*/licenses/.*/activate"))
        .respond_with(
            ResponseTemplate::new(201)
                .set_body_json(activation_response(license_key, custom_device_id)),
        )
        .mount(&server)
        .await;

    let sdk = LicenseSeat::new(test_config(&server.uri()));
    let options = licenseseat::ActivationOptions {
        device_id: Some(custom_device_id.into()),
        device_name: Some("My Custom Device".into()),
        metadata: None,
    };

    let result = sdk.activate_with_options(license_key, options).await;
    assert!(result.is_ok());
    let license = result.unwrap();
    assert_eq!(license.device_id, custom_device_id);
}

#[tokio::test]
async fn test_activation_invalid_license() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path_regex(r"/products/.*/licenses/.*/activate"))
        .respond_with(
            ResponseTemplate::new(404)
                .set_body_json(api_error_response("license_not_found", "License key not found")),
        )
        .mount(&server)
        .await;

    let sdk = LicenseSeat::new(test_config(&server.uri()));
    let result = sdk.activate("INVALID-KEY").await;

    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(matches!(err, licenseseat::Error::Api { status: 404, .. }));
}

#[tokio::test]
async fn test_product_slug_required() {
    let config = Config {
        api_key: "test-key".into(),
        product_slug: "".into(), // Empty product slug
        ..Default::default()
    };

    let sdk = LicenseSeat::new(config);
    let result = sdk.activate("TEST-KEY").await;

    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        licenseseat::Error::ProductSlugRequired
    ));
}

// ============================================================================
// Validation Tests
// ============================================================================

#[tokio::test]
async fn test_validation_success() {
    let server = MockServer::start().await;
    let license_key = "TEST-LICENSE-KEY";

    Mock::given(method("POST"))
        .and(path_regex(r"/products/.*/licenses/.*/activate"))
        .respond_with(
            ResponseTemplate::new(201)
                .set_body_json(activation_response(license_key, "device-123")),
        )
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path_regex(r"/products/.*/licenses/.*/validate"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(validation_response(true, license_key)),
        )
        .mount(&server)
        .await;

    let sdk = LicenseSeat::new(test_config(&server.uri()));
    let _ = sdk.activate(license_key).await.unwrap();

    let result = sdk.validate().await;
    assert!(result.is_ok());
    let validation = result.unwrap();
    assert!(validation.valid);
}

#[tokio::test]
async fn test_validation_with_entitlements() {
    let server = MockServer::start().await;
    let license_key = "TEST-LICENSE-KEY";

    Mock::given(method("POST"))
        .and(path_regex(r"/products/.*/licenses/.*/activate"))
        .respond_with(
            ResponseTemplate::new(201)
                .set_body_json(activation_response(license_key, "device-123")),
        )
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path_regex(r"/products/.*/licenses/.*/validate"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(validation_with_entitlements(license_key)),
        )
        .mount(&server)
        .await;

    let sdk = LicenseSeat::new(test_config(&server.uri()));
    let _ = sdk.activate(license_key).await.unwrap();
    let _ = sdk.validate().await.unwrap();

    // Check entitlements
    assert!(sdk.has_entitlement("pro-features"));
    assert!(sdk.has_entitlement("api-access"));
    assert!(!sdk.has_entitlement("nonexistent"));
}

#[tokio::test]
async fn test_validation_invalid() {
    let server = MockServer::start().await;
    let license_key = "TEST-LICENSE-KEY";

    Mock::given(method("POST"))
        .and(path_regex(r"/products/.*/licenses/.*/activate"))
        .respond_with(
            ResponseTemplate::new(201)
                .set_body_json(activation_response(license_key, "device-123")),
        )
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path_regex(r"/products/.*/licenses/.*/validate"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(validation_response(false, license_key)),
        )
        .mount(&server)
        .await;

    let sdk = LicenseSeat::new(test_config(&server.uri()));
    let _ = sdk.activate(license_key).await.unwrap();

    let result = sdk.validate().await;
    assert!(result.is_ok());
    let validation = result.unwrap();
    assert!(!validation.valid);
    assert_eq!(validation.code.as_deref(), Some("license_expired"));
}

// ============================================================================
// Entitlement Tests
// ============================================================================

#[tokio::test]
async fn test_entitlement_active() {
    let server = MockServer::start().await;
    let license_key = "TEST-LICENSE-KEY";

    Mock::given(method("POST"))
        .and(path_regex(r"/products/.*/licenses/.*/activate"))
        .respond_with(
            ResponseTemplate::new(201)
                .set_body_json(activation_response(license_key, "device-123")),
        )
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path_regex(r"/products/.*/licenses/.*/validate"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(validation_with_entitlements(license_key)),
        )
        .mount(&server)
        .await;

    let sdk = LicenseSeat::new(test_config(&server.uri()));
    let _ = sdk.activate(license_key).await.unwrap();
    let _ = sdk.validate().await.unwrap();

    let status = sdk.check_entitlement("pro-features");
    assert!(status.active);
    assert!(status.reason.is_none());
    assert!(status.entitlement.is_some());
    assert_eq!(status.entitlement.unwrap().key, "pro-features");
}

#[tokio::test]
async fn test_entitlement_not_found() {
    let server = MockServer::start().await;
    let license_key = "TEST-LICENSE-KEY";

    Mock::given(method("POST"))
        .and(path_regex(r"/products/.*/licenses/.*/activate"))
        .respond_with(
            ResponseTemplate::new(201)
                .set_body_json(activation_response(license_key, "device-123")),
        )
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path_regex(r"/products/.*/licenses/.*/validate"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(validation_with_entitlements(license_key)),
        )
        .mount(&server)
        .await;

    let sdk = LicenseSeat::new(test_config(&server.uri()));
    let _ = sdk.activate(license_key).await.unwrap();
    let _ = sdk.validate().await.unwrap();

    let status = sdk.check_entitlement("nonexistent");
    assert!(!status.active);
    assert_eq!(status.reason, Some(EntitlementReason::NotFound));
}

#[tokio::test]
async fn test_entitlement_no_license() {
    // Use isolated config to avoid shared cache issues
    let config = test_config("http://localhost:9999");
    let sdk = LicenseSeat::new(config);

    let status = sdk.check_entitlement("any-feature");
    assert!(!status.active);
    assert_eq!(status.reason, Some(EntitlementReason::NoLicense));
}

// ============================================================================
// Deactivation Tests
// ============================================================================

#[tokio::test]
async fn test_deactivation_success() {
    let server = MockServer::start().await;
    let license_key = "TEST-LICENSE-KEY";

    Mock::given(method("POST"))
        .and(path_regex(r"/products/.*/licenses/.*/activate"))
        .respond_with(
            ResponseTemplate::new(201)
                .set_body_json(activation_response(license_key, "device-123")),
        )
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path_regex(r"/products/.*/licenses/.*/deactivate"))
        .respond_with(ResponseTemplate::new(200).set_body_json(deactivation_response()))
        .mount(&server)
        .await;

    let sdk = LicenseSeat::new(test_config(&server.uri()));
    let _ = sdk.activate(license_key).await.unwrap();

    assert!(sdk.current_license().is_some());

    let result = sdk.deactivate().await;
    assert!(result.is_ok());

    // License should be cleared
    assert!(sdk.current_license().is_none());
}

#[tokio::test]
async fn test_deactivation_no_license() {
    // Use isolated config to avoid shared cache issues
    let config = test_config("http://localhost:9999");
    let sdk = LicenseSeat::new(config);

    let result = sdk.deactivate().await;
    assert!(result.is_err());
    // SDK should return an error when deactivating without active license
    // (might be NoActiveLicense or ProductSlugRequired depending on config)
}

// ============================================================================
// Status Tests
// ============================================================================

#[tokio::test]
async fn test_status_inactive() {
    // Use isolated config to avoid shared cache issues
    let config = test_config("http://localhost:9999");
    let sdk = LicenseSeat::new(config);

    let status = sdk.status();
    assert!(matches!(status, LicenseStatus::Inactive { .. }));
}

#[tokio::test]
async fn test_status_pending_before_validation() {
    let server = MockServer::start().await;
    let license_key = "TEST-LICENSE-KEY";

    Mock::given(method("POST"))
        .and(path_regex(r"/products/.*/licenses/.*/activate"))
        .respond_with(
            ResponseTemplate::new(201)
                .set_body_json(activation_response(license_key, "device-123")),
        )
        .mount(&server)
        .await;

    let sdk = LicenseSeat::new(test_config(&server.uri()));
    let _ = sdk.activate(license_key).await.unwrap();

    let status = sdk.status();
    // After activation but before validation, status should be pending
    assert!(matches!(status, LicenseStatus::Pending { .. }));
}

#[tokio::test]
async fn test_status_active_after_validation() {
    let server = MockServer::start().await;
    let license_key = "TEST-LICENSE-KEY";

    Mock::given(method("POST"))
        .and(path_regex(r"/products/.*/licenses/.*/activate"))
        .respond_with(
            ResponseTemplate::new(201)
                .set_body_json(activation_response(license_key, "device-123")),
        )
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path_regex(r"/products/.*/licenses/.*/validate"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(validation_response(true, license_key)),
        )
        .mount(&server)
        .await;

    let sdk = LicenseSeat::new(test_config(&server.uri()));
    let _ = sdk.activate(license_key).await.unwrap();
    let _ = sdk.validate().await.unwrap();

    let status = sdk.status();
    assert!(matches!(status, LicenseStatus::Active { .. }));
}

// ============================================================================
// Heartbeat Tests
// ============================================================================

#[tokio::test]
async fn test_heartbeat_success() {
    let server = MockServer::start().await;
    let license_key = "TEST-LICENSE-KEY";

    Mock::given(method("POST"))
        .and(path_regex(r"/products/.*/licenses/.*/activate"))
        .respond_with(
            ResponseTemplate::new(201)
                .set_body_json(activation_response(license_key, "device-123")),
        )
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path_regex(r"/products/.*/licenses/.*/heartbeat"))
        .respond_with(ResponseTemplate::new(200).set_body_json(heartbeat_response(license_key)))
        .mount(&server)
        .await;

    let sdk = LicenseSeat::new(test_config(&server.uri()));
    let _ = sdk.activate(license_key).await.unwrap();

    let result = sdk.heartbeat().await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_heartbeat_no_license() {
    // Use isolated config to avoid shared cache issues
    let config = test_config("http://localhost:9999");
    let sdk = LicenseSeat::new(config);

    let result = sdk.heartbeat().await;
    assert!(result.is_err());
}

// ============================================================================
// Reset Tests
// ============================================================================

#[tokio::test]
async fn test_reset_clears_license() {
    let server = MockServer::start().await;
    let license_key = "TEST-LICENSE-KEY";

    Mock::given(method("POST"))
        .and(path_regex(r"/products/.*/licenses/.*/activate"))
        .respond_with(
            ResponseTemplate::new(201)
                .set_body_json(activation_response(license_key, "device-123")),
        )
        .mount(&server)
        .await;

    let sdk = LicenseSeat::new(test_config(&server.uri()));
    let _ = sdk.activate(license_key).await.unwrap();

    assert!(sdk.current_license().is_some());

    sdk.reset();

    assert!(sdk.current_license().is_none());
    assert!(matches!(sdk.status(), LicenseStatus::Inactive { .. }));
}

// ============================================================================
// API Error Handling Tests
// ============================================================================

#[tokio::test]
async fn test_api_error_401_unauthorized() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path_regex(r"/products/.*/licenses/.*/activate"))
        .respond_with(
            ResponseTemplate::new(401)
                .set_body_json(api_error_response("invalid_api_key", "Invalid API key")),
        )
        .mount(&server)
        .await;

    let sdk = LicenseSeat::new(test_config(&server.uri()));
    let result = sdk.activate("TEST-KEY").await;

    assert!(result.is_err());
    if let licenseseat::Error::Api {
        status,
        code,
        message,
        ..
    } = result.unwrap_err()
    {
        assert_eq!(status, 401);
        assert_eq!(code.as_deref(), Some("invalid_api_key"));
        assert_eq!(message, "Invalid API key");
    } else {
        panic!("Expected API error");
    }
}

#[tokio::test]
async fn test_api_error_422_seat_limit() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path_regex(r"/products/.*/licenses/.*/activate"))
        .respond_with(
            ResponseTemplate::new(422).set_body_json(api_error_response(
                "seat_limit_exceeded",
                "License seat limit exceeded",
            )),
        )
        .mount(&server)
        .await;

    let sdk = LicenseSeat::new(test_config(&server.uri()));
    let result = sdk.activate("TEST-KEY").await;

    assert!(result.is_err());
    if let licenseseat::Error::Api {
        status,
        code,
        ..
    } = result.unwrap_err()
    {
        assert_eq!(status, 422);
        assert_eq!(code.as_deref(), Some("seat_limit_exceeded"));
    } else {
        panic!("Expected API error");
    }
}

// ============================================================================
// Full Activation -> Validation -> Deactivation Flow
// ============================================================================

#[tokio::test]
async fn test_full_license_lifecycle() {
    let server = MockServer::start().await;
    let license_key = "TEST-LICENSE-KEY";

    // Setup all mocks
    Mock::given(method("POST"))
        .and(path_regex(r"/products/.*/licenses/.*/activate"))
        .respond_with(
            ResponseTemplate::new(201)
                .set_body_json(activation_response(license_key, "device-123")),
        )
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path_regex(r"/products/.*/licenses/.*/validate"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(validation_with_entitlements(license_key)),
        )
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path_regex(r"/products/.*/licenses/.*/deactivate"))
        .respond_with(ResponseTemplate::new(200).set_body_json(deactivation_response()))
        .mount(&server)
        .await;

    let sdk = LicenseSeat::new(test_config(&server.uri()));

    // Initial state
    assert!(matches!(sdk.status(), LicenseStatus::Inactive { .. }));
    assert!(sdk.current_license().is_none());

    // Activate
    let license = sdk.activate(license_key).await.unwrap();
    assert_eq!(license.license_key, license_key);
    assert!(matches!(sdk.status(), LicenseStatus::Pending { .. }));

    // Validate
    let validation = sdk.validate().await.unwrap();
    assert!(validation.valid);
    assert!(matches!(sdk.status(), LicenseStatus::Active { .. }));

    // Check entitlements
    assert!(sdk.has_entitlement("pro-features"));
    assert!(sdk.has_entitlement("api-access"));
    assert!(!sdk.has_entitlement("nonexistent"));

    // Deactivate
    sdk.deactivate().await.unwrap();
    assert!(matches!(sdk.status(), LicenseStatus::Inactive { .. }));
    assert!(sdk.current_license().is_none());
}

// ============================================================================
// Auth Header Tests
// ============================================================================

#[tokio::test]
async fn test_auth_header_present() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path_regex(r"/products/.*/licenses/.*/activate"))
        .and(header("Authorization", "Bearer test-api-key"))
        .respond_with(
            ResponseTemplate::new(201)
                .set_body_json(activation_response("TEST-KEY", "device-123")),
        )
        .mount(&server)
        .await;

    let sdk = LicenseSeat::new(test_config(&server.uri()));
    let result = sdk.activate("TEST-KEY").await;

    // If the auth header wasn't present, the mock wouldn't match
    assert!(result.is_ok());
}
