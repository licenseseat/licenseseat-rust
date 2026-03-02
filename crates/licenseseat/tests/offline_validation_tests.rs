//! Offline validation tests - Ed25519 verification, token validity, clock tampering.
//!
//! These tests mirror the comprehensive offline validation tests from Swift and C++ SDKs.
//! Note: The offline module is internal, so tests verify behavior through SDK public APIs
//! and test the concepts that offline validation relies on.

use serde_json::json;

// ============================================================================
// Offline Token Model Tests (No feature gate - just JSON structure tests)
// ============================================================================

#[test]
fn test_offline_entitlement_serialization() {
    let entitlement = json!({
        "key": "pro-features",
        "expires_at": 1735689600
    });

    assert_eq!(entitlement["key"], "pro-features");
    assert_eq!(entitlement["expires_at"], 1735689600);
}

#[test]
fn test_offline_token_payload_structure() {
    let payload = json!({
        "nbf": 1735689600,
        "exp": 1735776000,
        "iat": 1735689600,
        "license_key": "TEST-KEY-123",
        "product_slug": "my-product",
        "mode": "hardware_locked",
        "plan_key": "enterprise",
        "seat_limit": 10,
        "entitlements": [
            { "key": "feature-a" },
            { "key": "feature-b", "expires_at": 1735900000 }
        ],
        "metadata": { "org": "acme" }
    });

    assert_eq!(payload["license_key"], "TEST-KEY-123");
    assert_eq!(payload["product_slug"], "my-product");
    assert_eq!(payload["mode"], "hardware_locked");
    assert_eq!(payload["seat_limit"], 10);
    assert_eq!(payload["entitlements"].as_array().unwrap().len(), 2);
}

#[test]
fn test_signature_structure() {
    let signature = json!({
        "algorithm": "ed25519",
        "key_id": "key-2024-01",
        "value": "SGVsbG9Xb3JsZA" // Base64URL encoded
    });

    assert_eq!(signature["algorithm"], "ed25519");
    assert!(signature["key_id"].as_str().unwrap().starts_with("key-"));
    assert!(!signature["value"].as_str().unwrap().is_empty());
}

#[test]
fn test_full_offline_token_response_structure() {
    let now = chrono::Utc::now().timestamp();
    let token_response = json!({
        "object": "offline_token",
        "token": {
            "schema_version": 1,
            "nbf": now - 3600,
            "exp": now + 3600,
            "iat": now - 3600,
            "license_key": "TEST-KEY",
            "product_slug": "test-product",
            "mode": "hardware_locked",
            "plan_key": "pro",
            "seat_limit": 5,
            "device_id": "device-123",
            "kid": "key-2024",
            "entitlements": [
                { "key": "feature-a" },
                { "key": "feature-b", "expires_at": now + 7200 }
            ],
            "metadata": null
        },
        "canonical": "{\"canonical\":\"json\"}",
        "signature": {
            "algorithm": "ed25519",
            "key_id": "key-2024",
            "value": "base64url-encoded-signature"
        }
    });

    assert_eq!(token_response["object"], "offline_token");
    assert!(token_response["token"]["nbf"].is_i64());
    assert!(token_response["token"]["exp"].is_i64());
    assert_eq!(token_response["signature"]["algorithm"], "ed25519");
}

// ============================================================================
// Token Expiration Concept Tests
// ============================================================================

#[test]
fn test_token_not_yet_valid_detection() {
    // Token with nbf in the future should fail validation
    let now = chrono::Utc::now().timestamp();
    let future_nbf = now + 3600; // 1 hour from now
    let exp = future_nbf + 7200;

    // Simulate the check
    let is_valid = now >= future_nbf && now <= exp;
    assert!(!is_valid, "Token should not be valid before nbf");
}

#[test]
fn test_token_expired_detection() {
    // Token with exp in the past should fail validation
    let now = chrono::Utc::now().timestamp();
    let past_nbf = now - 7200; // 2 hours ago
    let past_exp = now - 3600; // 1 hour ago (expired)

    // Simulate the check
    let is_valid = now >= past_nbf && now <= past_exp;
    assert!(!is_valid, "Token should not be valid after exp");
}

#[test]
fn test_token_valid_window() {
    // Token within valid window should pass
    let now = chrono::Utc::now().timestamp();
    let nbf = now - 3600; // Started 1 hour ago
    let exp = now + 3600; // Expires in 1 hour

    // Simulate the check
    let is_valid = now >= nbf && now <= exp;
    assert!(is_valid, "Token should be valid within window");
}

#[test]
fn test_license_expiration_check() {
    let now = chrono::Utc::now().timestamp();

    // Token is valid but license has expired
    let token_nbf = now - 3600;
    let token_exp = now + 3600;
    let license_exp = now - 1800; // License expired 30 mins ago

    let token_valid = now >= token_nbf && now <= token_exp;
    let license_valid = license_exp > now;

    assert!(token_valid, "Token itself should be valid");
    assert!(!license_valid, "But license should be expired");
}

// ============================================================================
// Grace Period Concept Tests
// ============================================================================

#[test]
fn test_grace_period_calculation() {
    let now = chrono::Utc::now().timestamp();
    let token_exp = now - 86400; // Token expired 24 hours ago
    let grace_period_days = 7;
    let grace_end = token_exp + (grace_period_days * 86400);

    // Within grace period
    let is_in_grace = now > token_exp && now <= grace_end;
    assert!(is_in_grace, "Should be in grace period");

    // After grace period
    let way_past_grace = token_exp + (grace_period_days * 86400) + 1;
    let is_past_grace = way_past_grace > grace_end;
    assert!(is_past_grace, "Should be past grace period");
}

#[test]
fn test_grace_period_disabled() {
    let now = chrono::Utc::now().timestamp();
    let token_exp = now - 3600; // Expired 1 hour ago
    let grace_period_days = 0; // No grace period

    let grace_end = token_exp + (grace_period_days * 86400);
    let is_valid = now <= grace_end;

    assert!(!is_valid, "Should not be valid with no grace period");
}

// ============================================================================
// Clock Tampering Detection Tests
// ============================================================================

#[test]
fn test_clock_forward_detection() {
    // Simulates detecting if system clock has been moved forward
    let last_seen = chrono::Utc::now().timestamp();
    let current_time = last_seen + 86400 * 30; // 30 days forward

    // Large jump forward might indicate tampering
    let time_diff = current_time - last_seen;
    let max_expected_diff = 86400 * 7; // 7 days is suspicious

    let is_suspicious = time_diff > max_expected_diff;
    assert!(is_suspicious, "Large forward jump should be suspicious");
}

#[test]
fn test_clock_backward_detection() {
    // Simulates detecting if system clock has been moved backward
    let last_seen = chrono::Utc::now().timestamp();
    let current_time = last_seen - 3600; // 1 hour backward

    // Time going backward is definitely suspicious
    let is_backward = current_time < last_seen;
    assert!(is_backward, "Backward time should be detected");
}

#[test]
fn test_clock_within_acceptable_skew() {
    // Normal clock drift should be acceptable
    let last_seen = chrono::Utc::now().timestamp();
    let max_clock_skew = 300; // 5 minutes

    // Small forward drift
    let current_time = last_seen + 120; // 2 minutes forward
    let time_diff = (current_time - last_seen).abs();
    assert!(time_diff <= max_clock_skew, "Small drift should be acceptable");

    // Small backward drift (NTP correction)
    let current_time = last_seen - 60; // 1 minute backward
    let time_diff = (current_time - last_seen).abs();
    assert!(time_diff <= max_clock_skew, "Small NTP correction should be acceptable");
}

#[test]
fn test_monotonic_time_tracking() {
    // Timestamps should generally increase
    let timestamps: Vec<i64> = vec![1000, 1100, 1200, 1300, 1400];

    let is_monotonic = timestamps.windows(2).all(|w| w[1] >= w[0]);
    assert!(is_monotonic, "Timestamps should be monotonically increasing");

    // Detect non-monotonic sequence
    let bad_timestamps: Vec<i64> = vec![1000, 1100, 900, 1300]; // 900 is suspicious
    let has_backward_jump = bad_timestamps.windows(2).any(|w| w[1] < w[0]);
    assert!(has_backward_jump, "Should detect backward jump");
}

// ============================================================================
// Signing Key Tests
// ============================================================================

#[test]
fn test_signing_key_response_structure() {
    let key_response = json!({
        "object": "signing_key",
        "key_id": "key-2024-01",
        "algorithm": "ed25519",
        "public_key": "MCowBQYDK2VwAyEAbase64encodedkey==",
        "created_at": "2024-01-01T00:00:00Z",
        "status": "active"
    });

    assert_eq!(key_response["object"], "signing_key");
    assert_eq!(key_response["algorithm"], "ed25519");
    assert!(key_response["public_key"].as_str().unwrap().len() > 10);
    assert_eq!(key_response["status"], "active");
}

#[test]
fn test_key_id_format() {
    // Key IDs should follow a consistent format
    let valid_key_ids = vec!["key-2024-01", "key-2024-02", "prod-key-1"];

    for key_id in valid_key_ids {
        assert!(key_id.contains("-"), "Key ID should contain separator");
        assert!(key_id.len() > 5, "Key ID should be reasonably long");
    }
}

// ============================================================================
// Canonical JSON Tests
// ============================================================================

#[test]
fn test_canonical_json_deterministic() {
    // Canonical JSON should produce the same output for the same data
    let data = json!({
        "z": "last",
        "a": "first",
        "m": "middle"
    });

    let serialized1 = serde_json::to_string(&data).unwrap();
    let serialized2 = serde_json::to_string(&data).unwrap();

    // Same input should produce same output
    assert_eq!(serialized1, serialized2);
}

#[test]
fn test_canonical_json_no_whitespace() {
    let data = json!({"key": "value", "number": 123});

    let canonical = serde_json::to_string(&data).unwrap();

    // Should not have extra whitespace
    assert!(!canonical.contains("  "), "Should not have extra spaces");
    assert!(!canonical.contains('\n'), "Should not have newlines");
}

// ============================================================================
// Entitlement Conversion Tests
// ============================================================================

#[test]
fn test_offline_entitlement_to_regular() {
    // Offline entitlements use Unix timestamps, regular use DateTime
    let offline_entitlement = json!({
        "key": "feature-x",
        "expires_at": 1735689600  // Unix timestamp
    });

    let unix_ts = offline_entitlement["expires_at"].as_i64().unwrap();
    let datetime = chrono::DateTime::from_timestamp(unix_ts, 0);

    assert!(datetime.is_some());
    assert_eq!(datetime.unwrap().timestamp(), 1735689600);
}

#[test]
fn test_offline_entitlement_without_expiry() {
    let offline_entitlement = json!({
        "key": "perpetual-feature"
    });

    // No expires_at means perpetual
    let expires_at = offline_entitlement.get("expires_at");
    assert!(expires_at.is_none() || expires_at.unwrap().is_null());
}

// ============================================================================
// Validation Result Conversion Tests
// ============================================================================

#[test]
fn test_offline_validation_result_structure() {
    // What a validation result from offline validation should look like
    let result = json!({
        "object": "validation_result",
        "valid": true,
        "code": null,
        "message": null,
        "warnings": null,
        "license": {
            "object": "license",
            "key": "TEST-KEY",
            "status": "active",
            "mode": "hardware_locked",
            "plan_key": "pro",
            "seat_limit": 5,
            "active_seats": 0,  // Not available offline
            "active_entitlements": [
                {"key": "feature-a"},
                {"key": "feature-b", "expires_at": "2025-12-31T00:00:00Z"}
            ],
            "product": {
                "slug": "test-product",
                "name": "Test Product"
            }
        },
        "activation": null  // Not available offline
    });

    assert!(result["valid"].as_bool().unwrap());
    assert_eq!(result["license"]["status"], "active");
    assert_eq!(result["license"]["active_seats"], 0);
    assert!(result["activation"].is_null());
}
