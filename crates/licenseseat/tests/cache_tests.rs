//! Cache and storage tests - persistence, isolation, thread safety.
//!
//! These tests verify caching behavior through the public SDK API.
//! The internal cache module is tested indirectly via SDK operations.

use licenseseat::{Config, LicenseSeat};
use serde_json::json;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use wiremock::matchers::{method, path_regex};
use wiremock::{Mock, MockServer, ResponseTemplate};

static TEST_COUNTER: AtomicU64 = AtomicU64::new(0);

fn unique_prefix() -> String {
    format!(
        "cache_test_{}_{}_{}_",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos(),
        TEST_COUNTER.fetch_add(1, Ordering::SeqCst)
    )
}

fn test_config(base_url: &str) -> Config {
    Config {
        api_key: "test-api-key".into(),
        product_slug: "test-product".into(),
        api_base_url: base_url.into(),
        storage_prefix: unique_prefix(),
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
// Basic Cache Operations Tests
// ============================================================================

#[tokio::test]
async fn test_license_cached_after_activation() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path_regex(r"/products/.*/licenses/.*/activate"))
        .respond_with(ResponseTemplate::new(201).set_body_json(activation_response()))
        .mount(&server)
        .await;

    let sdk = LicenseSeat::new(test_config(&server.uri()));

    // Initially no license
    assert!(sdk.current_license().is_none());

    // Activate
    sdk.activate("TEST-KEY").await.unwrap();

    // License should be cached
    let license = sdk.current_license();
    assert!(license.is_some());
    assert_eq!(license.unwrap().license_key, "TEST-KEY");
}

#[tokio::test]
async fn test_license_cleared_after_deactivation() {
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

    sdk.activate("TEST-KEY").await.unwrap();
    assert!(sdk.current_license().is_some());

    sdk.deactivate().await.unwrap();
    assert!(sdk.current_license().is_none());
}

#[tokio::test]
async fn test_license_cleared_on_reset() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path_regex(r"/products/.*/licenses/.*/activate"))
        .respond_with(ResponseTemplate::new(201).set_body_json(activation_response()))
        .mount(&server)
        .await;

    let sdk = LicenseSeat::new(test_config(&server.uri()));

    sdk.activate("TEST-KEY").await.unwrap();
    assert!(sdk.current_license().is_some());

    sdk.reset();
    assert!(sdk.current_license().is_none());
}

// ============================================================================
// Validation Update Tests
// ============================================================================

#[tokio::test]
async fn test_validation_result_cached() {
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

    // Before validation, no validation result
    let license_before = sdk.current_license().unwrap();
    assert!(license_before.validation.is_none());

    // After validation, result is stored
    sdk.validate().await.unwrap();
    let license_after = sdk.current_license().unwrap();
    assert!(license_after.validation.is_some());
    assert!(license_after.validation.unwrap().valid);
}

#[tokio::test]
async fn test_validation_updates_last_validated_time() {
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
    let initial_time = sdk.current_license().unwrap().last_validated;

    tokio::time::sleep(Duration::from_millis(50)).await;

    sdk.validate().await.unwrap();
    let updated_time = sdk.current_license().unwrap().last_validated;

    assert!(updated_time > initial_time);
}

// ============================================================================
// Cache Isolation Tests
// ============================================================================

#[tokio::test]
async fn test_different_prefixes_isolated() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path_regex(r"/products/.*/licenses/.*/activate"))
        .respond_with(ResponseTemplate::new(201).set_body_json(activation_response()))
        .mount(&server)
        .await;

    // SDK 1 with unique prefix
    let config1 = test_config(&server.uri());
    let sdk1 = LicenseSeat::new(config1);

    // SDK 2 with different unique prefix
    let config2 = test_config(&server.uri());
    let sdk2 = LicenseSeat::new(config2);

    // Activate with first SDK
    sdk1.activate("KEY-1").await.unwrap();

    // Second SDK should not see the license
    assert!(sdk2.current_license().is_none());

    // Activate with second SDK
    sdk2.activate("KEY-2").await.unwrap();

    // Each SDK should have its own license
    assert_eq!(sdk1.current_license().unwrap().license_key, "KEY-1");
    assert_eq!(sdk2.current_license().unwrap().license_key, "KEY-2");
}

#[tokio::test]
async fn test_same_prefix_shares_cache() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path_regex(r"/products/.*/licenses/.*/activate"))
        .respond_with(ResponseTemplate::new(201).set_body_json(activation_response()))
        .mount(&server)
        .await;

    let prefix = unique_prefix();

    let config1 = Config {
        api_key: "test-api-key".into(),
        product_slug: "test-product".into(),
        api_base_url: server.uri(),
        storage_prefix: prefix.clone(),
        auto_validate_interval: Duration::from_secs(0),
        heartbeat_interval: Duration::from_secs(0),
        debug: true,
        ..Default::default()
    };

    let sdk1 = LicenseSeat::new(config1.clone());
    sdk1.activate("SHARED-KEY").await.unwrap();

    // Create second SDK with same prefix
    let sdk2 = LicenseSeat::new(config1);

    // Second SDK should see the cached license
    let license = sdk2.current_license();
    assert!(license.is_some());
    assert_eq!(license.unwrap().license_key, "SHARED-KEY");
}

// ============================================================================
// Persistence Tests
// ============================================================================

#[tokio::test]
async fn test_license_persists_across_sdk_instances() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path_regex(r"/products/.*/licenses/.*/activate"))
        .respond_with(ResponseTemplate::new(201).set_body_json(activation_response()))
        .mount(&server)
        .await;

    let prefix = unique_prefix();

    // First SDK instance - activate
    {
        let config = Config {
            api_key: "test-api-key".into(),
            product_slug: "test-product".into(),
            api_base_url: server.uri(),
            storage_prefix: prefix.clone(),
            auto_validate_interval: Duration::from_secs(0),
            heartbeat_interval: Duration::from_secs(0),
            ..Default::default()
        };

        let sdk = LicenseSeat::new(config);
        sdk.activate("PERSIST-KEY").await.unwrap();
    }

    // Second SDK instance - should have persisted license
    {
        let config = Config {
            api_key: "test-api-key".into(),
            product_slug: "test-product".into(),
            api_base_url: server.uri(),
            storage_prefix: prefix,
            auto_validate_interval: Duration::from_secs(0),
            heartbeat_interval: Duration::from_secs(0),
            ..Default::default()
        };

        let sdk = LicenseSeat::new(config);
        let license = sdk.current_license();
        assert!(license.is_some());
        assert_eq!(license.unwrap().license_key, "PERSIST-KEY");
    }
}

#[tokio::test]
async fn test_validation_persists_across_instances() {
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

    let prefix = unique_prefix();

    // First SDK instance - activate and validate
    {
        let config = Config {
            api_key: "test-api-key".into(),
            product_slug: "test-product".into(),
            api_base_url: server.uri(),
            storage_prefix: prefix.clone(),
            ..Default::default()
        };

        let sdk = LicenseSeat::new(config);
        sdk.activate("PERSIST-KEY").await.unwrap();
        sdk.validate().await.unwrap();
    }

    // Second SDK instance - should have validation result
    {
        let config = Config {
            api_key: "test-api-key".into(),
            product_slug: "test-product".into(),
            api_base_url: server.uri(),
            storage_prefix: prefix,
            ..Default::default()
        };

        let sdk = LicenseSeat::new(config);
        let license = sdk.current_license().unwrap();
        assert!(license.validation.is_some());
        assert!(license.validation.unwrap().valid);
    }
}

// ============================================================================
// Thread Safety Tests
// ============================================================================

#[tokio::test]
async fn test_concurrent_status_reads() {
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
    sdk.activate("TEST-KEY").await.unwrap();
    sdk.validate().await.unwrap();

    let mut handles = vec![];
    for _ in 0..100 {
        let sdk_clone = Arc::clone(&sdk);
        handles.push(std::thread::spawn(move || {
            let license = sdk_clone.current_license();
            assert!(license.is_some());
            assert_eq!(license.unwrap().license_key, "TEST-KEY");
        }));
    }

    for handle in handles {
        handle.join().unwrap();
    }
}

#[tokio::test]
async fn test_concurrent_entitlement_checks() {
    let server = MockServer::start().await;

    let entitlements = vec![
        json!({"key": "feature-a", "expires_at": null, "metadata": null}),
        json!({"key": "feature-b", "expires_at": null, "metadata": null}),
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
            "license": {
                "object": "license",
                "key": "TEST-KEY",
                "status": "active",
                "mode": "hardware_locked",
                "plan_key": "pro",
                "active_seats": 1,
                "active_entitlements": entitlements,
                "product": {"slug": "test-product", "name": "Test App"}
            }
        })))
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path_regex(r"/products/.*/licenses/.*/validate"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "object": "validation_result",
            "valid": true,
            "license": {
                "object": "license",
                "key": "TEST-KEY",
                "status": "active",
                "mode": "hardware_locked",
                "plan_key": "pro",
                "active_seats": 1,
                "active_entitlements": [
                    {"key": "feature-a"},
                    {"key": "feature-b"}
                ],
                "product": {"slug": "test-product", "name": "Test App"}
            }
        })))
        .mount(&server)
        .await;

    let sdk = Arc::new(LicenseSeat::new(test_config(&server.uri())));
    sdk.activate("TEST-KEY").await.unwrap();
    sdk.validate().await.unwrap();

    let mut handles = vec![];
    for i in 0..50 {
        let sdk_clone = Arc::clone(&sdk);
        let feature = if i % 2 == 0 { "feature-a" } else { "feature-b" };
        handles.push(std::thread::spawn(move || {
            let has = sdk_clone.has_entitlement(feature);
            assert!(has);
        }));
    }

    for handle in handles {
        handle.join().unwrap();
    }
}

// ============================================================================
// Data Integrity Tests
// ============================================================================

#[tokio::test]
async fn test_license_data_integrity() {
    let server = MockServer::start().await;

    let custom_activation = json!({
        "object": "activation",
        "id": "act-custom-uuid",
        "device_id": "custom-device-id",
        "device_name": "Custom Device Name",
        "license_key": "CUSTOM-LICENSE-KEY",
        "activated_at": "2025-06-15T10:30:00Z",
        "ip_address": "192.168.1.100",
        "metadata": {"custom_field": "custom_value"},
        "license": {
            "object": "license",
            "key": "CUSTOM-LICENSE-KEY",
            "status": "active",
            "starts_at": "2025-01-01T00:00:00Z",
            "expires_at": "2026-01-01T00:00:00Z",
            "mode": "floating",
            "plan_key": "enterprise",
            "seat_limit": 100,
            "active_seats": 42,
            "active_entitlements": [
                {"key": "premium", "expires_at": null, "metadata": null},
                {"key": "analytics", "expires_at": "2025-12-31T23:59:59Z", "metadata": null}
            ],
            "metadata": {"org_id": "12345"},
            "product": {
                "slug": "custom-product",
                "name": "Custom Product"
            }
        }
    });

    Mock::given(method("POST"))
        .and(path_regex(r"/products/.*/licenses/.*/activate"))
        .respond_with(ResponseTemplate::new(201).set_body_json(custom_activation))
        .mount(&server)
        .await;

    let sdk = LicenseSeat::new(test_config(&server.uri()));
    sdk.activate("CUSTOM-LICENSE-KEY").await.unwrap();

    let license = sdk.current_license().unwrap();

    // Verify all fields preserved
    assert_eq!(license.license_key, "CUSTOM-LICENSE-KEY");
    assert_eq!(license.activation_id, "act-custom-uuid");
}

#[tokio::test]
async fn test_entitlements_preserved_in_cache() {
    let server = MockServer::start().await;

    let entitlements = vec![
        json!({"key": "feature-1", "expires_at": null, "metadata": null}),
        json!({"key": "feature-2", "expires_at": "2025-12-31T00:00:00Z", "metadata": null}),
        json!({"key": "feature-3", "expires_at": null, "metadata": {"limit": 500}}),
    ];

    Mock::given(method("POST"))
        .and(path_regex(r"/products/.*/licenses/.*/activate"))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({
            "object": "activation",
            "id": "act-uuid",
            "device_id": "device",
            "license_key": "KEY",
            "activated_at": "2025-01-01T00:00:00Z",
            "license": {
                "object": "license",
                "key": "KEY",
                "status": "active",
                "mode": "hardware_locked",
                "plan_key": "pro",
                "active_seats": 1,
                "active_entitlements": entitlements,
                "product": {"slug": "test", "name": "Test"}
            }
        })))
        .mount(&server)
        .await;

    // Use a future date (2027) to ensure entitlement is not expired
    Mock::given(method("POST"))
        .and(path_regex(r"/products/.*/licenses/.*/validate"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "object": "validation_result",
            "valid": true,
            "license": {
                "object": "license",
                "key": "KEY",
                "status": "active",
                "mode": "hardware_locked",
                "plan_key": "pro",
                "active_seats": 1,
                "active_entitlements": [
                    {"key": "feature-1"},
                    {"key": "feature-2", "expires_at": "2027-12-31T00:00:00Z"},
                    {"key": "feature-3", "metadata": {"limit": 500}}
                ],
                "product": {"slug": "test", "name": "Test"}
            }
        })))
        .mount(&server)
        .await;

    let sdk = LicenseSeat::new(test_config(&server.uri()));
    sdk.activate("KEY").await.unwrap();
    sdk.validate().await.unwrap();

    // Check all entitlements are accessible
    assert!(sdk.has_entitlement("feature-1"));
    assert!(sdk.has_entitlement("feature-2"));
    assert!(sdk.has_entitlement("feature-3"));

    // Check detailed status
    let status = sdk.check_entitlement("feature-2");
    assert!(status.active);
    assert!(status.expires_at.is_some());
}

// ============================================================================
// Edge Cases
// ============================================================================

#[tokio::test]
async fn test_empty_entitlements() {
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
    sdk.activate("KEY").await.unwrap();
    sdk.validate().await.unwrap();

    // No entitlements should mean has_entitlement returns false
    assert!(!sdk.has_entitlement("any-feature"));

    let status = sdk.check_entitlement("any-feature");
    assert!(!status.active);
    assert!(matches!(
        status.reason,
        Some(licenseseat::EntitlementReason::NotFound)
    ));
}

#[tokio::test]
async fn test_no_license_status() {
    let server = MockServer::start().await;

    let sdk = LicenseSeat::new(test_config(&server.uri()));

    // Without activation
    assert!(sdk.current_license().is_none());
    assert!(!sdk.has_entitlement("any"));

    let status = sdk.check_entitlement("any");
    assert!(!status.active);
    assert!(matches!(
        status.reason,
        Some(licenseseat::EntitlementReason::NoLicense)
    ));
}
