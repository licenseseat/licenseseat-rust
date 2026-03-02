//! Real-world scenario tests - user journeys, edge cases, integration flows.
//!
//! These tests mirror the scenario and journey tests from C++, C#, and Swift SDKs.

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
        "scenario_test_{}_{}_{}_",
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

fn activation_response(entitlements: Vec<serde_json::Value>) -> serde_json::Value {
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
            "active_entitlements": entitlements,
            "metadata": null,
            "product": {
                "slug": "test-product",
                "name": "Test App"
            }
        }
    })
}

fn validation_response(valid: bool, entitlements: Vec<serde_json::Value>) -> serde_json::Value {
    let code = if valid { serde_json::Value::Null } else { json!("license_invalid") };
    let message = if valid { serde_json::Value::Null } else { json!("License is invalid") };
    let status = if valid { "active" } else { "suspended" };

    json!({
        "object": "validation_result",
        "valid": valid,
        "code": code,
        "message": message,
        "warnings": null,
        "license": {
            "object": "license",
            "key": "TEST-KEY",
            "status": status,
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
        },
        "activation": null
    })
}

fn deactivation_response() -> serde_json::Value {
    json!({
        "object": "deactivation",
        "activation_id": "act-12345-uuid",
        "deactivated_at": "2025-01-01T01:00:00Z"
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
// User Journey: New User Activation
// ============================================================================

#[tokio::test]
async fn test_scenario_new_user_activation() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path_regex(r"/products/.*/licenses/.*/activate"))
        .respond_with(ResponseTemplate::new(201).set_body_json(activation_response(vec![
            json!({"key": "basic", "expires_at": null, "metadata": null}),
        ])))
        .mount(&server)
        .await;

    let sdk = LicenseSeat::new(test_config(&server.uri()));

    // Initially no license
    assert!(sdk.current_license().is_none());
    assert!(matches!(sdk.status(), licenseseat::LicenseStatus::Inactive { .. }));

    // Activate
    let license = sdk.activate("NEW-USER-KEY").await.unwrap();

    // Verify activation
    assert_eq!(license.license_key, "NEW-USER-KEY");
    assert!(!license.device_id.is_empty());

    // License should now be cached
    assert!(sdk.current_license().is_some());
}

#[tokio::test]
async fn test_scenario_returning_user_with_cached_license() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path_regex(r"/products/.*/licenses/.*/activate"))
        .respond_with(ResponseTemplate::new(201).set_body_json(activation_response(vec![])))
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path_regex(r"/products/.*/licenses/.*/validate"))
        .respond_with(ResponseTemplate::new(200).set_body_json(validation_response(true, vec![])))
        .mount(&server)
        .await;

    let config = test_config(&server.uri());

    // First session - activate
    {
        let sdk = LicenseSeat::new(config.clone());
        let _ = sdk.activate("RETURNING-USER-KEY").await.unwrap();
    }

    // Second session - should have cached license
    {
        let sdk = LicenseSeat::new(config);
        let cached = sdk.current_license();
        assert!(cached.is_some());
        assert_eq!(cached.unwrap().license_key, "RETURNING-USER-KEY");

        // Can validate without re-activating
        let validation = sdk.validate().await.unwrap();
        assert!(validation.valid);
    }
}

// ============================================================================
// User Journey: Entitlement Checking
// ============================================================================

#[tokio::test]
async fn test_scenario_feature_gating_with_entitlements() {
    let server = MockServer::start().await;

    let entitlements = vec![
        json!({"key": "basic-features", "expires_at": null, "metadata": null}),
        json!({"key": "pro-features", "expires_at": null, "metadata": null}),
    ];

    Mock::given(method("POST"))
        .and(path_regex(r"/products/.*/licenses/.*/activate"))
        .respond_with(ResponseTemplate::new(201).set_body_json(activation_response(entitlements.clone())))
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path_regex(r"/products/.*/licenses/.*/validate"))
        .respond_with(ResponseTemplate::new(200).set_body_json(validation_response(true, entitlements)))
        .mount(&server)
        .await;

    let sdk = LicenseSeat::new(test_config(&server.uri()));
    sdk.activate("FEATURE-KEY").await.unwrap();
    sdk.validate().await.unwrap();

    // Basic features should be active
    assert!(sdk.has_entitlement("basic-features"));

    // Pro features should be active
    assert!(sdk.has_entitlement("pro-features"));

    // Enterprise features should NOT be active
    assert!(!sdk.has_entitlement("enterprise-features"));

    // Check detailed entitlement status
    let status = sdk.check_entitlement("pro-features");
    assert!(status.active);
    assert!(status.entitlement.is_some());
}

#[tokio::test]
async fn test_scenario_expired_entitlement() {
    let server = MockServer::start().await;

    // Entitlement that expired in the past
    let past_time = (chrono::Utc::now() - chrono::Duration::hours(1)).to_rfc3339();
    let entitlements = vec![
        json!({"key": "expired-feature", "expires_at": past_time, "metadata": null}),
    ];

    Mock::given(method("POST"))
        .and(path_regex(r"/products/.*/licenses/.*/activate"))
        .respond_with(ResponseTemplate::new(201).set_body_json(activation_response(entitlements.clone())))
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path_regex(r"/products/.*/licenses/.*/validate"))
        .respond_with(ResponseTemplate::new(200).set_body_json(validation_response(true, entitlements)))
        .mount(&server)
        .await;

    let sdk = LicenseSeat::new(test_config(&server.uri()));
    sdk.activate("EXPIRED-KEY").await.unwrap();
    sdk.validate().await.unwrap();

    // Expired entitlement should not be active
    let status = sdk.check_entitlement("expired-feature");
    assert!(!status.active);
    assert!(matches!(
        status.reason,
        Some(licenseseat::EntitlementReason::Expired)
    ));
}

// ============================================================================
// User Journey: License Deactivation
// ============================================================================

#[tokio::test]
async fn test_scenario_clean_deactivation() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path_regex(r"/products/.*/licenses/.*/activate"))
        .respond_with(ResponseTemplate::new(201).set_body_json(activation_response(vec![])))
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path_regex(r"/products/.*/licenses/.*/deactivate"))
        .respond_with(ResponseTemplate::new(200).set_body_json(deactivation_response()))
        .mount(&server)
        .await;

    let sdk = LicenseSeat::new(test_config(&server.uri()));

    // Activate
    sdk.activate("DEACTIVATE-KEY").await.unwrap();
    assert!(sdk.current_license().is_some());

    // Deactivate
    sdk.deactivate().await.unwrap();

    // License should be cleared
    assert!(sdk.current_license().is_none());
    assert!(matches!(sdk.status(), licenseseat::LicenseStatus::Inactive { .. }));
}

#[tokio::test]
async fn test_scenario_deactivate_already_deactivated() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path_regex(r"/products/.*/licenses/.*/activate"))
        .respond_with(ResponseTemplate::new(201).set_body_json(activation_response(vec![])))
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path_regex(r"/products/.*/licenses/.*/deactivate"))
        .respond_with(ResponseTemplate::new(422).set_body_json(json!({
            "error": {
                "code": "already_deactivated",
                "message": "This activation has already been deactivated"
            }
        })))
        .mount(&server)
        .await;

    let sdk = LicenseSeat::new(test_config(&server.uri()));
    sdk.activate("ALREADY-DEACTIVATED-KEY").await.unwrap();

    // Should succeed even though API says already deactivated
    let result = sdk.deactivate().await;
    assert!(result.is_ok());

    // Cache should still be cleared
    assert!(sdk.current_license().is_none());
}

// ============================================================================
// User Journey: License Validation Failures
// ============================================================================

#[tokio::test]
async fn test_scenario_license_revoked() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path_regex(r"/products/.*/licenses/.*/activate"))
        .respond_with(ResponseTemplate::new(201).set_body_json(activation_response(vec![])))
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path_regex(r"/products/.*/licenses/.*/validate"))
        .respond_with(ResponseTemplate::new(403).set_body_json(json!({
            "error": {
                "code": "license_revoked",
                "message": "This license has been revoked"
            }
        })))
        .mount(&server)
        .await;

    let sdk = LicenseSeat::new(test_config(&server.uri()));

    // Track revocation event
    let revoked = Arc::new(AtomicUsize::new(0));
    let revoked_clone = revoked.clone();

    let mut rx = sdk.subscribe();
    tokio::spawn(async move {
        while let Ok(event) = rx.recv().await {
            if matches!(event.kind, EventKind::LicenseRevoked) {
                revoked_clone.fetch_add(1, Ordering::SeqCst);
            }
        }
    });

    sdk.activate("REVOKED-KEY").await.unwrap();

    // Validation should fail
    let result = sdk.validate().await;
    assert!(result.is_err());

    // Give time for event
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Should have received revocation event
    assert!(revoked.load(Ordering::SeqCst) >= 1);

    // Cache should be cleared on revocation
    assert!(sdk.current_license().is_none());
}

#[tokio::test]
async fn test_scenario_license_suspended() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path_regex(r"/products/.*/licenses/.*/activate"))
        .respond_with(ResponseTemplate::new(201).set_body_json(activation_response(vec![])))
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path_regex(r"/products/.*/licenses/.*/validate"))
        .respond_with(ResponseTemplate::new(200).set_body_json(validation_response(false, vec![])))
        .mount(&server)
        .await;

    let sdk = LicenseSeat::new(test_config(&server.uri()));
    sdk.activate("SUSPENDED-KEY").await.unwrap();

    let validation = sdk.validate().await.unwrap();
    assert!(!validation.valid);

    // Status should reflect invalid license
    let status = sdk.status();
    assert!(matches!(status, licenseseat::LicenseStatus::Invalid { .. }));
}

// ============================================================================
// User Journey: Heartbeat Flow
// ============================================================================

#[tokio::test]
async fn test_scenario_regular_heartbeat() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path_regex(r"/products/.*/licenses/.*/activate"))
        .respond_with(ResponseTemplate::new(201).set_body_json(activation_response(vec![])))
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path_regex(r"/products/.*/licenses/.*/heartbeat"))
        .respond_with(ResponseTemplate::new(200).set_body_json(heartbeat_response()))
        .expect(3)
        .mount(&server)
        .await;

    let sdk = LicenseSeat::new(test_config(&server.uri()));
    sdk.activate("HEARTBEAT-KEY").await.unwrap();

    // Send multiple heartbeats
    for _ in 0..3 {
        let response = sdk.heartbeat().await.unwrap();
        assert!(!response.received_at.to_string().is_empty());
    }
}

// ============================================================================
// User Journey: Network Resilience
// ============================================================================

#[tokio::test]
async fn test_scenario_temporary_network_failure() {
    let server = MockServer::start().await;

    // Fail first two attempts, succeed on third
    Mock::given(method("POST"))
        .and(path_regex(r"/products/.*/licenses/.*/activate"))
        .respond_with(ResponseTemplate::new(201).set_body_json(activation_response(vec![])))
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path_regex(r"/products/.*/licenses/.*/activate"))
        .respond_with(ResponseTemplate::new(503).set_body_json(json!({
            "error": {"message": "Service temporarily unavailable"}
        })))
        .up_to_n_times(2)
        .mount(&server)
        .await;

    let sdk = LicenseSeat::new(test_config(&server.uri()));

    // Should succeed after retries
    let result = sdk.activate("RETRY-KEY").await;
    assert!(result.is_ok());
}

// ============================================================================
// User Journey: SDK Reset
// ============================================================================

#[tokio::test]
async fn test_scenario_sdk_reset() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path_regex(r"/products/.*/licenses/.*/activate"))
        .respond_with(ResponseTemplate::new(201).set_body_json(activation_response(vec![])))
        .mount(&server)
        .await;

    let sdk = LicenseSeat::new(test_config(&server.uri()));

    // Track reset event
    let reset_received = Arc::new(AtomicUsize::new(0));
    let reset_clone = reset_received.clone();

    let mut rx = sdk.subscribe();
    tokio::spawn(async move {
        while let Ok(event) = rx.recv().await {
            if matches!(event.kind, EventKind::SdkReset) {
                reset_clone.fetch_add(1, Ordering::SeqCst);
            }
        }
    });

    // Activate
    sdk.activate("RESET-KEY").await.unwrap();
    assert!(sdk.current_license().is_some());

    // Reset
    sdk.reset();

    tokio::time::sleep(Duration::from_millis(50)).await;

    // All state should be cleared
    assert!(sdk.current_license().is_none());
    assert!(reset_received.load(Ordering::SeqCst) >= 1);
}

// ============================================================================
// Edge Cases
// ============================================================================

#[tokio::test]
async fn test_scenario_validate_without_activation() {
    let server = MockServer::start().await;

    let sdk = LicenseSeat::new(test_config(&server.uri()));

    // Try to validate without activating
    let result = sdk.validate().await;
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), licenseseat::Error::NoActiveLicense));
}

#[tokio::test]
async fn test_scenario_deactivate_without_activation() {
    let server = MockServer::start().await;

    let sdk = LicenseSeat::new(test_config(&server.uri()));

    // Try to deactivate without activating
    let result = sdk.deactivate().await;
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), licenseseat::Error::NoActiveLicense));
}

#[tokio::test]
async fn test_scenario_heartbeat_without_activation() {
    let server = MockServer::start().await;

    let sdk = LicenseSeat::new(test_config(&server.uri()));

    // Try to heartbeat without activating
    let result = sdk.heartbeat().await;
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), licenseseat::Error::NoActiveLicense));
}

#[tokio::test]
async fn test_scenario_check_entitlement_without_validation() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path_regex(r"/products/.*/licenses/.*/activate"))
        .respond_with(ResponseTemplate::new(201).set_body_json(activation_response(vec![])))
        .mount(&server)
        .await;

    let sdk = LicenseSeat::new(test_config(&server.uri()));

    // Entitlement check before activation
    let status = sdk.check_entitlement("any-feature");
    assert!(!status.active);
    assert!(matches!(
        status.reason,
        Some(licenseseat::EntitlementReason::NoLicense)
    ));

    // After activation but before validation
    sdk.activate("KEY").await.unwrap();
    let status = sdk.check_entitlement("any-feature");
    assert!(!status.active);
}

// ============================================================================
// Multi-instance Scenarios
// ============================================================================

#[tokio::test]
async fn test_scenario_multiple_sdk_instances_same_config() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path_regex(r"/products/.*/licenses/.*/activate"))
        .respond_with(ResponseTemplate::new(201).set_body_json(activation_response(vec![])))
        .mount(&server)
        .await;

    let config = test_config(&server.uri());

    let sdk1 = LicenseSeat::new(config.clone());
    let sdk2 = LicenseSeat::new(config);

    // Activate with first instance
    sdk1.activate("SHARED-KEY").await.unwrap();

    // Second instance should see the cached license
    // (since they share the same storage prefix)
    let license = sdk2.current_license();
    assert!(license.is_some());
    assert_eq!(license.unwrap().license_key, "SHARED-KEY");
}

#[tokio::test]
async fn test_scenario_isolated_sdk_instances() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path_regex(r"/products/.*/licenses/.*/activate"))
        .respond_with(ResponseTemplate::new(201).set_body_json(activation_response(vec![])))
        .mount(&server)
        .await;

    // Different storage prefixes = isolated instances
    let config1 = test_config(&server.uri());
    let config2 = test_config(&server.uri()); // Gets different prefix due to TEST_COUNTER

    let sdk1 = LicenseSeat::new(config1);
    let sdk2 = LicenseSeat::new(config2);

    // Activate with first instance
    sdk1.activate("ISOLATED-KEY-1").await.unwrap();

    // Second instance should NOT see the first's license
    assert!(sdk2.current_license().is_none());

    // Each can have their own license
    sdk2.activate("ISOLATED-KEY-2").await.unwrap();

    assert_eq!(
        sdk1.current_license().unwrap().license_key,
        "ISOLATED-KEY-1"
    );
    assert_eq!(
        sdk2.current_license().unwrap().license_key,
        "ISOLATED-KEY-2"
    );
}
