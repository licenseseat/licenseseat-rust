//! Integration tests for the LicenseSeat SDK.
//!
//! These tests use wiremock to mock HTTP responses and verify the full
//! SDK flow from activation through validation and deactivation.

use chrono::Utc;
use licenseseat::{
    ClientStatus, Config, EntitlementReason, LicenseSeat, LicenseStatus, OfflineFallbackMode,
};
use serde_json::json;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use wiremock::matchers::{header, method, path, path_regex, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[cfg(feature = "offline")]
use aes_gcm::Aes256Gcm;
#[cfg(feature = "offline")]
use aes_gcm::aead::{Aead, KeyInit};
#[cfg(feature = "offline")]
use base64::Engine;
#[cfg(feature = "offline")]
use ed25519_dalek::{Signer, SigningKey};
#[cfg(feature = "offline")]
use sha2::{Digest, Sha256};

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
        device_identifier: Some("device-123".into()),
        api_base_url: base_url.into(),
        storage_prefix: unique_prefix,
        auto_validate_interval: Duration::from_secs(0), // Disable for tests
        heartbeat_interval: Duration::from_secs(0),     // Disable for tests
        offline_fallback_mode: OfflineFallbackMode::NetworkOnly,
        // Offline-oriented integration tests opt in explicitly. The production
        // default remains zero, which disables offline authority.
        max_offline_days: 7,
        debug: true,
        telemetry_enabled: true,
        ..Default::default()
    }
}

fn entitlement_json(key: &str) -> serde_json::Value {
    json!({
        "key": key,
        "expires_at": null,
        "metadata": null
    })
}

fn license_json(
    license_key: &str,
    status: &str,
    plan_key: &str,
    mode: &str,
    entitlements: &[&str],
    product_name: &str,
) -> serde_json::Value {
    json!({
        "type": "licenses",
        "object": "license",
        "key": license_key,
        "status": status,
        "starts_at": null,
        "expires_at": null,
        "mode": mode,
        "plan_key": plan_key,
        "seat_limit": 5,
        "active_seats": 1,
        "active_entitlements": entitlements
            .iter()
            .map(|key| entitlement_json(key))
            .collect::<Vec<_>>(),
        "metadata": null,
        "product": {
            "slug": "test-product",
            "name": product_name
        }
    })
}

fn activation_response(license_key: &str, device_id: &str) -> serde_json::Value {
    activation_response_with_license(
        license_key,
        device_id,
        license_json(
            license_key,
            "active",
            "pro",
            "hardware_locked",
            &[],
            "Test App",
        ),
    )
}

fn activation_response_with_license(
    license_key: &str,
    device_id: &str,
    license: serde_json::Value,
) -> serde_json::Value {
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
        "license": license
    })
}

fn validation_response(valid: bool, license_key: &str) -> serde_json::Value {
    validation_response_for_fingerprint(valid, license_key, "device-123")
}

fn validation_response_for_fingerprint(
    valid: bool,
    license_key: &str,
    fingerprint: &str,
) -> serde_json::Value {
    let status = if valid { "active" } else { "expired" };
    let mut response = json!({
        "object": "validation_result",
        "valid": valid,
        "warnings": null,
        "license": license_json(license_key, status, "pro", "hardware_locked", &[], "Test App"),
        "activation": if valid {
            Some(json!({
                "object": "activation",
                "id": "act-12345-uuid",
                "device_id": fingerprint,
                "device_name": "Test Device",
                "license_key": license_key,
                "activated_at": Utc::now().to_rfc3339(),
                "deactivated_at": null,
                "ip_address": "127.0.0.1",
                "metadata": null
            }))
        } else {
            None
        }
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
    validation_with_entitlements_for_fingerprint(license_key, "device-123")
}

fn validation_with_entitlements_for_fingerprint(
    license_key: &str,
    fingerprint: &str,
) -> serde_json::Value {
    json!({
        "object": "validation_result",
        "valid": true,
        "code": null,
        "message": null,
        "warnings": null,
        "license": license_json(
            license_key,
            "active",
            "pro",
            "hardware_locked",
            &["pro-features", "api-access"],
            "Test App"
        ),
        "activation": {
            "object": "activation",
            "id": "act-12345-uuid",
            "device_id": fingerprint,
            "device_name": "Test Device",
            "license_key": license_key,
            "activated_at": Utc::now().to_rfc3339(),
            "deactivated_at": null,
            "ip_address": "127.0.0.1",
            "metadata": null
        }
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
    heartbeat_response_with_license(license_json(
        license_key,
        "active",
        "pro",
        "hardware_locked",
        &[],
        "Test App",
    ))
}

fn heartbeat_response_with_license(license: serde_json::Value) -> serde_json::Value {
    json!({
        "object": "heartbeat",
        "received_at": Utc::now().to_rfc3339(),
        "license": license
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

fn release_response(version: &str, channel: &str, platform: &str) -> serde_json::Value {
    json!({
        "object": "release",
        "version": version,
        "channel": channel,
        "platform": platform,
        "published_at": Utc::now().to_rfc3339(),
        "product_slug": "test-product"
    })
}

fn release_list_response() -> serde_json::Value {
    json!({
        "object": "list",
        "data": [
            release_response("2.1.0", "stable", "macos"),
            release_response("2.0.0", "stable", "windows")
        ],
        "has_more": false,
        "next_cursor": null
    })
}

fn download_token_response() -> serde_json::Value {
    json!({
        "object": "download_token",
        "token": "signed-download-token",
        "expires_at": (Utc::now() + chrono::Duration::minutes(5)).to_rfc3339()
    })
}

#[cfg(feature = "offline")]
fn hex_to_bytes(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&hex[index..index + 2], 16).unwrap())
        .collect()
}

#[cfg(feature = "offline")]
fn build_machine_file_fixture_with_options(
    license_key: &str,
    fingerprint: &str,
    embedded_license: Option<serde_json::Value>,
) -> (serde_json::Value, String) {
    let signing_key = SigningKey::try_from(
        hex_to_bytes("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60").as_slice(),
    )
    .unwrap();
    let public_key_b64 =
        base64::engine::general_purpose::STANDARD.encode(signing_key.verifying_key().as_bytes());

    let included = embedded_license
        .map(|license| json!([machine_file_license_json(&license)]))
        .unwrap_or_else(|| json!([]));

    let now = chrono::DateTime::<Utc>::from_timestamp(Utc::now().timestamp(), 0).unwrap();
    let expires_at = now + chrono::Duration::days(30);

    let payload = json!({
        "meta": {
            "schema_version": 2,
            "issued": now.to_rfc3339(),
            "iat": now.timestamp(),
            "expiry": expires_at.to_rfc3339(),
            "exp": expires_at.timestamp(),
            "nbf": now.timestamp(),
            "ttl": 30 * 24 * 60 * 60,
            "grace_period": 3600,
            "lic": license_key,
            "license_exp": null,
            "kid": "key-2026",
            "sdk_version": "0.5.3"
        },
        "data": {
            "type": "machines",
            "id": "machine-123",
            "attributes": {
                "fingerprint": fingerprint,
                "fingerprint_components": {
                    "schema_version": "1",
                    "platform": "macos"
                },
                "name": "Test Device",
                "platform": "macos",
                "created": Utc::now().to_rfc3339(),
                "metadata": {
                    "source": "rust-test"
                }
            },
            "relationships": {
                "license": { "data": { "type": "licenses", "id": license_key } },
                "product": { "data": { "type": "products", "id": "test-product" } }
            }
        },
        "included": included
    });

    let payload_bytes = serde_json::to_vec(&payload).unwrap();
    let mut hasher = Sha256::new();
    hasher.update(license_key.as_bytes());
    hasher.update(fingerprint.as_bytes());
    let key = hasher.finalize();
    let cipher = Aes256Gcm::new_from_slice(&key).unwrap();
    let nonce_bytes = [1_u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
    let ciphertext_and_tag = cipher
        .encrypt(
            aes_gcm::Nonce::from_slice(&nonce_bytes),
            payload_bytes.as_ref(),
        )
        .unwrap();
    let split_at = ciphertext_and_tag.len() - 16;
    let (ciphertext, tag) = ciphertext_and_tag.split_at(split_at);
    let enc = format!(
        "{}.{}.{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(ciphertext),
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(nonce_bytes),
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(tag),
    );
    let signature = signing_key.sign(format!("machine/{enc}").as_bytes());
    let envelope = json!({
        "enc": enc,
        "sig": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(signature.to_bytes()),
        "alg": "aes-256-gcm+ed25519",
        "kid": "key-2026"
    });
    let encoded_envelope =
        base64::engine::general_purpose::STANDARD.encode(serde_json::to_vec(&envelope).unwrap());
    let wrapped_envelope = encoded_envelope
        .as_bytes()
        .chunks(64)
        .map(|chunk| std::str::from_utf8(chunk).unwrap())
        .collect::<Vec<_>>()
        .join("\n");
    let certificate =
        format!("-----BEGIN MACHINE FILE-----\n{wrapped_envelope}\n-----END MACHINE FILE-----");

    (
        json!({
            "data": {
                "type": "machine-files",
                "attributes": {
                    "certificate": certificate,
                    "algorithm": "aes-256-gcm+ed25519",
                    "ttl": 30 * 24 * 60 * 60,
                    "issued": now.to_rfc3339(),
                    "expiry": expires_at.to_rfc3339()
                },
                "relationships": {
                    "license": { "data": { "type": "licenses", "id": license_key } },
                    "machine": { "data": { "type": "machines", "id": fingerprint } }
                }
            }
        }),
        public_key_b64,
    )
}

#[cfg(feature = "offline")]
fn machine_file_license_json(license: &serde_json::Value) -> serde_json::Value {
    let key = license["key"].as_str().unwrap();
    let entitlements = license["active_entitlements"]
        .as_array()
        .unwrap()
        .iter()
        .map(|entitlement| {
            json!({
                "key": entitlement["key"],
                "expires_at": entitlement["expires_at"]
            })
        })
        .collect::<Vec<_>>();
    json!({
        "type": "licenses",
        "id": key,
        "attributes": {
            "key": key,
            "status": license["status"],
            "mode": license["mode"],
            "seat_limit": license["seat_limit"],
            "plan_key": license["plan_key"],
            "product_slug": license["product"]["slug"],
            "starts_at": license["starts_at"],
            "ends_at": license["expires_at"],
            "entitlements": entitlements,
            "metadata": {}
        }
    })
}

#[cfg(feature = "offline")]
fn build_machine_file_fixture(license_key: &str, fingerprint: &str) -> (serde_json::Value, String) {
    build_machine_file_fixture_with_options(
        license_key,
        fingerprint,
        Some(license_json(
            license_key,
            "active",
            "pro",
            "hardware_locked",
            &["pro-features"],
            "Test Product",
        )),
    )
}

#[cfg(feature = "offline")]
fn build_machine_file_fixture_without_license(
    license_key: &str,
    fingerprint: &str,
) -> (serde_json::Value, String) {
    build_machine_file_fixture_with_options(license_key, fingerprint, None)
}

#[cfg(feature = "offline")]
fn build_machine_file_fixture_with_embedded_license(
    license_key: &str,
    fingerprint: &str,
    embedded_license: serde_json::Value,
) -> (serde_json::Value, String) {
    build_machine_file_fixture_with_options(license_key, fingerprint, Some(embedded_license))
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
        .and(path_regex(r"/products/.*/licenses/activate"))
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
        .and(path_regex(r"/products/.*/licenses/activate"))
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
        .and(path_regex(r"/products/.*/licenses/activate"))
        .respond_with(
            ResponseTemplate::new(201)
                .set_body_json(activation_response(license_key, custom_device_id)),
        )
        .mount(&server)
        .await;

    let sdk = LicenseSeat::new(test_config(&server.uri()));
    let options = licenseseat::ActivationOptions {
        fingerprint: None,
        device_id: Some(custom_device_id.into()),
        device_fingerprint: None,
        device_name: Some("My Custom Device".into()),
        metadata: None,
    };

    let result = sdk.activate_with_options(license_key, options).await;
    assert!(result.is_ok());
    let license = result.unwrap();
    assert_eq!(license.device_id, custom_device_id);
}

#[tokio::test]
async fn test_conflicting_fingerprint_aliases_are_rejected_before_network_access() {
    let server = MockServer::start().await;
    let sdk = LicenseSeat::new(test_config(&server.uri()));
    let result = sdk
        .activate_with_options(
            "TEST-LICENSE-KEY",
            licenseseat::ActivationOptions {
                fingerprint: Some("fingerprint-one".into()),
                device_id: Some("fingerprint-two".into()),
                ..Default::default()
            },
        )
        .await;

    assert!(matches!(result, Err(licenseseat::Error::Configuration(_))));
    assert!(server.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn test_invalid_fingerprint_is_rejected_before_network_access() {
    let server = MockServer::start().await;
    let sdk = LicenseSeat::new(test_config(&server.uri()));
    let result = sdk
        .activate_with_options(
            "TEST-LICENSE-KEY",
            licenseseat::ActivationOptions {
                fingerprint: Some("short".into()),
                ..Default::default()
            },
        )
        .await;

    assert!(matches!(result, Err(licenseseat::Error::Configuration(_))));
    assert!(server.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn test_activation_invalid_license() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path_regex(r"/products/.*/licenses/activate"))
        .respond_with(ResponseTemplate::new(404).set_body_json(api_error_response(
            "license_not_found",
            "License key not found",
        )))
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
        .and(path_regex(r"/products/.*/licenses/activate"))
        .respond_with(
            ResponseTemplate::new(201)
                .set_body_json(activation_response(license_key, "device-123")),
        )
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path_regex(r"/products/.*/licenses/validate"))
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
        .and(path_regex(r"/products/.*/licenses/activate"))
        .respond_with(
            ResponseTemplate::new(201)
                .set_body_json(activation_response(license_key, "device-123")),
        )
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path_regex(r"/products/.*/licenses/validate"))
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
        .and(path_regex(r"/products/.*/licenses/activate"))
        .respond_with(
            ResponseTemplate::new(201)
                .set_body_json(activation_response(license_key, "device-123")),
        )
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path_regex(r"/products/.*/licenses/validate"))
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

#[tokio::test]
async fn test_invalid_validation_cannot_grant_returned_entitlements() {
    let server = MockServer::start().await;
    let license_key = "TEST-LICENSE-KEY";
    let mut invalid = validation_with_entitlements(license_key);
    invalid["valid"] = json!(false);
    invalid["code"] = json!("license_suspended");
    invalid["message"] = json!("License is suspended");
    invalid["license"]["status"] = json!("suspended");

    Mock::given(method("POST"))
        .and(path_regex(r"/products/.*/licenses/activate"))
        .respond_with(
            ResponseTemplate::new(201)
                .set_body_json(activation_response(license_key, "device-123")),
        )
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path_regex(r"/products/.*/licenses/validate"))
        .respond_with(ResponseTemplate::new(200).set_body_json(invalid))
        .mount(&server)
        .await;

    let sdk = LicenseSeat::new(test_config(&server.uri()));
    sdk.activate(license_key).await.unwrap();
    assert!(!sdk.validate().await.unwrap().valid);
    assert!(!sdk.has_entitlement("pro-features"));
    assert!(!sdk.check_entitlement("pro-features").active);
}

#[tokio::test]
async fn test_valid_flag_with_expired_license_fails_closed() {
    let server = MockServer::start().await;
    let license_key = "TEST-LICENSE-KEY";
    let mut inconsistent = validation_with_entitlements(license_key);
    inconsistent["license"]["status"] = json!("expired");

    Mock::given(method("POST"))
        .and(path_regex(r"/products/.*/licenses/activate"))
        .respond_with(
            ResponseTemplate::new(201)
                .set_body_json(activation_response(license_key, "device-123")),
        )
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path_regex(r"/products/.*/licenses/validate"))
        .respond_with(ResponseTemplate::new(200).set_body_json(inconsistent))
        .mount(&server)
        .await;

    let sdk = LicenseSeat::new(test_config(&server.uri()));
    sdk.activate(license_key).await.unwrap();
    assert!(matches!(
        sdk.validate().await,
        Err(licenseseat::Error::InvalidResponse(_))
    ));
    assert!(!sdk.has_entitlement("pro-features"));
}

// ============================================================================
// Entitlement Tests
// ============================================================================

#[tokio::test]
async fn test_entitlement_active() {
    let server = MockServer::start().await;
    let license_key = "TEST-LICENSE-KEY";

    Mock::given(method("POST"))
        .and(path_regex(r"/products/.*/licenses/activate"))
        .respond_with(
            ResponseTemplate::new(201)
                .set_body_json(activation_response(license_key, "device-123")),
        )
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path_regex(r"/products/.*/licenses/validate"))
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
        .and(path_regex(r"/products/.*/licenses/activate"))
        .respond_with(
            ResponseTemplate::new(201)
                .set_body_json(activation_response(license_key, "device-123")),
        )
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path_regex(r"/products/.*/licenses/validate"))
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
        .and(path_regex(r"/products/.*/licenses/activate"))
        .respond_with(
            ResponseTemplate::new(201)
                .set_body_json(activation_response(license_key, "device-123")),
        )
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path_regex(r"/products/.*/licenses/deactivate"))
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
async fn test_deactivate_key_uses_explicit_license_and_fingerprint() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/products/test-product/licenses/deactivate"))
        .respond_with(ResponseTemplate::new(200).set_body_json(deactivation_response()))
        .mount(&server)
        .await;

    let sdk = LicenseSeat::new(test_config(&server.uri()));
    sdk.deactivate_key("TEST-LICENSE-KEY", Some("explicit-fingerprint"))
        .await
        .unwrap();

    let requests = server.received_requests().await.unwrap();
    let body: serde_json::Value = serde_json::from_slice(&requests[0].body).unwrap();
    assert_eq!(body["fingerprint"].as_str(), Some("explicit-fingerprint"));
    assert_eq!(body["device_id"].as_str(), Some("explicit-fingerprint"));
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
        .and(path_regex(r"/products/.*/licenses/activate"))
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
        .and(path_regex(r"/products/.*/licenses/activate"))
        .respond_with(
            ResponseTemplate::new(201)
                .set_body_json(activation_response(license_key, "device-123")),
        )
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path_regex(r"/products/.*/licenses/validate"))
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
    assert_eq!(sdk.get_client_status(), ClientStatus::Active);
}

// ============================================================================
// Heartbeat Tests
// ============================================================================

#[tokio::test]
async fn test_heartbeat_success() {
    let server = MockServer::start().await;
    let license_key = "TEST-LICENSE-KEY";

    Mock::given(method("POST"))
        .and(path_regex(r"/products/.*/licenses/activate"))
        .respond_with(
            ResponseTemplate::new(201)
                .set_body_json(activation_response(license_key, "device-123")),
        )
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path_regex(r"/products/.*/licenses/heartbeat"))
        .respond_with(ResponseTemplate::new(200).set_body_json(heartbeat_response(license_key)))
        .mount(&server)
        .await;

    let sdk = LicenseSeat::new(test_config(&server.uri()));
    let _ = sdk.activate(license_key).await.unwrap();

    let result = sdk.heartbeat().await;
    assert!(result.is_ok());
}

#[cfg(feature = "offline")]
#[tokio::test]
async fn test_unsigned_cached_heartbeat_metadata_is_not_used_for_offline_authorization() {
    let server = MockServer::start().await;
    let license_key = "TEST-LICENSE-KEY";
    let fingerprint = "stable-fingerprint-heartbeat-snapshot";
    let activation_license = license_json(
        license_key,
        "active",
        "starter",
        "hardware_locked",
        &[],
        "Activation Product",
    );
    let heartbeat_license = license_json(
        license_key,
        "active",
        "pro",
        "named_user",
        &["pro-features", "team-sync"],
        "Heartbeat Product",
    );
    let (machine_file_response, public_key_b64) =
        build_machine_file_fixture_without_license(license_key, fingerprint);

    Mock::given(method("POST"))
        .and(path_regex(r"/products/.*/licenses/activate"))
        .respond_with(
            ResponseTemplate::new(201).set_body_json(activation_response_with_license(
                license_key,
                fingerprint,
                activation_license,
            )),
        )
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path_regex(r"/products/.*/licenses/heartbeat"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(heartbeat_response_with_license(heartbeat_license)),
        )
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path("/products/test-product/licenses/machine-file"))
        .respond_with(ResponseTemplate::new(201).set_body_json(machine_file_response))
        .mount(&server)
        .await;

    let mut online_config = test_config(&server.uri());
    online_config.device_identifier = Some(fingerprint.into());
    online_config.signing_public_key = Some(public_key_b64);
    online_config.signing_key_id = Some("key-2026".into());

    let sdk = LicenseSeat::new(online_config.clone());
    sdk.activate(license_key).await.unwrap();
    assert!(matches!(sdk.status(), LicenseStatus::Pending { .. }));
    let heartbeat = sdk.heartbeat().await.unwrap();
    assert_eq!(heartbeat.license.plan_key, "pro");
    assert_eq!(heartbeat.license.mode, "named_user");
    assert_eq!(heartbeat.license.active_entitlements.len(), 2);
    let machine_file = sdk
        .checkout_machine_file(license_key, Some(fingerprint), Some(30))
        .await
        .unwrap();
    let verification = sdk
        .verify_machine_file(
            &machine_file,
            online_config.signing_public_key.as_deref(),
            Some(license_key),
            Some(fingerprint),
        )
        .unwrap();
    assert!(verification.valid);
    assert!(verification.payload.as_ref().unwrap().license.is_none());

    let mut offline_config = online_config.clone();
    offline_config.api_base_url = "http://127.0.0.1:9".into();
    let restored_sdk = LicenseSeat::new(offline_config);
    let restore = restored_sdk.restore_license().await;

    assert!(restore.restored);
    assert!(matches!(restore.status, LicenseStatus::OfflineValid { .. }));
    let validation = restore.validation.as_ref().unwrap();
    assert!(validation.valid);
    assert!(validation.offline);
    assert!(validation.license.plan_key.is_empty());
    assert_eq!(validation.license.mode, "hardware_locked");
    assert_eq!(validation.license.product.slug, "test-product");
    assert!(validation.license.active_entitlements.is_empty());
}

#[tokio::test]
async fn test_heartbeat_key_uses_explicit_license_and_fingerprint() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/products/test-product/licenses/heartbeat"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(heartbeat_response("TEST-LICENSE-KEY")),
        )
        .mount(&server)
        .await;

    let sdk = LicenseSeat::new(test_config(&server.uri()));
    let response = sdk
        .heartbeat_key("TEST-LICENSE-KEY", Some("explicit-fingerprint"))
        .await
        .unwrap();

    assert_eq!(response.license.key, "TEST-LICENSE-KEY");

    let requests = server.received_requests().await.unwrap();
    let body: serde_json::Value = serde_json::from_slice(&requests[0].body).unwrap();
    assert_eq!(body["fingerprint"].as_str(), Some("explicit-fingerprint"));
    assert_eq!(body["device_id"].as_str(), Some("explicit-fingerprint"));
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
        .and(path_regex(r"/products/.*/licenses/activate"))
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
        .and(path_regex(r"/products/.*/licenses/activate"))
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
        .and(path_regex(r"/products/.*/licenses/activate"))
        .respond_with(ResponseTemplate::new(422).set_body_json(api_error_response(
            "seat_limit_exceeded",
            "License seat limit exceeded",
        )))
        .mount(&server)
        .await;

    let sdk = LicenseSeat::new(test_config(&server.uri()));
    let result = sdk.activate("TEST-KEY").await;

    assert!(result.is_err());
    if let licenseseat::Error::Api { status, code, .. } = result.unwrap_err() {
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
        .and(path_regex(r"/products/.*/licenses/activate"))
        .respond_with(
            ResponseTemplate::new(201)
                .set_body_json(activation_response(license_key, "device-123")),
        )
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path_regex(r"/products/.*/licenses/validate"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(validation_with_entitlements(license_key)),
        )
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path_regex(r"/products/.*/licenses/deactivate"))
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
// Release API Tests
// ============================================================================

#[tokio::test]
async fn test_get_latest_release() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/products/test-product/releases/latest"))
        .and(query_param("channel", "stable"))
        .and(query_param("platform", "macos"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(release_response("2.1.0", "stable", "macos")),
        )
        .mount(&server)
        .await;

    let sdk = LicenseSeat::new(test_config(&server.uri()));
    let result = sdk
        .get_latest_release(None, Some("stable"), Some("macos"))
        .await
        .unwrap();

    assert_eq!(result.version, "2.1.0");
    assert_eq!(result.channel, "stable");
    assert_eq!(result.platform, "macos");
}

#[tokio::test]
async fn test_list_releases() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/products/test-product/releases"))
        .and(query_param("channel", "stable"))
        .respond_with(ResponseTemplate::new(200).set_body_json(release_list_response()))
        .mount(&server)
        .await;

    let sdk = LicenseSeat::new(test_config(&server.uri()));
    let result = sdk.list_releases(None, Some("stable"), None).await.unwrap();

    assert_eq!(result.len(), 2);
    assert_eq!(result[0].version, "2.1.0");
    assert_eq!(result[1].platform, "windows");
}

#[tokio::test]
async fn test_list_releases_with_options_returns_envelope() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/products/test-product/releases"))
        .and(query_param("channel", "stable"))
        .and(query_param("platform", "macos"))
        .and(query_param("limit", "1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "object": "list",
            "data": [release_response("2.1.0", "stable", "macos")],
            "has_more": true,
            "next_cursor": "cursor-2"
        })))
        .mount(&server)
        .await;

    let sdk = LicenseSeat::new(test_config(&server.uri()));
    let result = sdk
        .list_releases_with_options(
            None,
            licenseseat::ReleaseListOptions {
                channel: Some("stable".into()),
                platform: Some("macos".into()),
                limit: Some(1),
            },
        )
        .await
        .unwrap();

    assert_eq!(result.object, "list");
    assert_eq!(result.data.len(), 1);
    assert_eq!(result.data[0].version, "2.1.0");
    assert!(result.has_more);
    assert_eq!(result.next_cursor.as_deref(), Some("cursor-2"));
}

#[tokio::test]
async fn test_generate_download_token() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/products/test-product/releases/2.1.0/download_token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(download_token_response()))
        .mount(&server)
        .await;

    let sdk = LicenseSeat::new(test_config(&server.uri()));
    let result = sdk
        .generate_download_token("2.1.0", "TEST-LICENSE-KEY", None, Some("macos"))
        .await
        .unwrap();

    assert_eq!(result.token, "signed-download-token");

    let requests = server.received_requests().await.unwrap();
    let body: serde_json::Value = serde_json::from_slice(&requests[0].body).unwrap();
    assert_eq!(body["license_key"].as_str(), Some("TEST-LICENSE-KEY"));
    assert_eq!(body["platform"].as_str(), Some("macos"));
}

// ============================================================================
// Machine File / Offline Tests
// ============================================================================

#[cfg(feature = "offline")]
#[tokio::test]
async fn test_invalid_machine_file_lifetime_options_are_rejected_before_network_access() {
    let server = MockServer::start().await;
    let sdk = LicenseSeat::new(test_config(&server.uri()));

    let invalid_ttl = sdk
        .checkout_machine_file("TEST-LICENSE-KEY", Some("fingerprint-123"), Some(0))
        .await;
    assert!(matches!(
        invalid_ttl,
        Err(licenseseat::Error::Configuration(_))
    ));

    let invalid_grace = sdk
        .checkout_machine_file_with_options(
            "TEST-LICENSE-KEY",
            licenseseat::MachineFileCheckoutOptions {
                fingerprint: Some("fingerprint-123".into()),
                grace_period_days: Some(31),
                ..Default::default()
            },
        )
        .await;
    assert!(matches!(
        invalid_grace,
        Err(licenseseat::Error::Configuration(_))
    ));
    assert!(server.received_requests().await.unwrap().is_empty());
}

#[cfg(feature = "offline")]
#[tokio::test]
async fn test_checkout_machine_file() {
    let server = MockServer::start().await;
    let license_key = "TEST-LICENSE-KEY";
    let fingerprint = "custom-fingerprint-123";
    let (machine_file_response, public_key_b64) =
        build_machine_file_fixture(license_key, fingerprint);

    Mock::given(method("POST"))
        .and(path("/products/test-product/licenses/machine-file"))
        .respond_with(ResponseTemplate::new(201).set_body_json(machine_file_response))
        .mount(&server)
        .await;

    let mut config = test_config(&server.uri());
    config.signing_public_key = Some(public_key_b64);
    config.signing_key_id = Some("key-2026".into());
    let sdk = LicenseSeat::new(config);
    let result = sdk
        .checkout_machine_file(license_key, Some(fingerprint), Some(45))
        .await
        .unwrap();

    assert_eq!(result.algorithm, "aes-256-gcm+ed25519");
    assert_eq!(result.license_key, license_key);
    assert_eq!(result.fingerprint, fingerprint);

    let requests = server.received_requests().await.unwrap();
    let body: serde_json::Value = serde_json::from_slice(&requests[0].body).unwrap();
    assert_eq!(body["fingerprint"].as_str(), Some(fingerprint));
    assert_eq!(body["device_id"].as_str(), Some(fingerprint));
    assert_eq!(body["device_fingerprint"].as_str(), Some(fingerprint));
    assert_eq!(body["ttl"].as_i64(), Some(45));
    assert_eq!(body["include"][0].as_str(), Some("license"));
}

#[cfg(feature = "offline")]
#[tokio::test]
async fn test_checkout_machine_file_parses_errors_array() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/products/test-product/licenses/machine-file"))
        .respond_with(ResponseTemplate::new(422).set_body_json(json!({
            "errors": [
                {
                    "code": "DEVICE_NOT_ACTIVATED",
                    "title": "Device not activated",
                    "detail": "Activate the device before checking out a machine file."
                }
            ]
        })))
        .mount(&server)
        .await;

    let sdk = LicenseSeat::new(test_config(&server.uri()));
    let result = sdk
        .checkout_machine_file("TEST-LICENSE-KEY", Some("fingerprint-123"), Some(30))
        .await;

    match result.unwrap_err() {
        licenseseat::Error::Api {
            status,
            code,
            message,
            ..
        } => {
            assert_eq!(status, 422);
            assert_eq!(code.as_deref(), Some("DEVICE_NOT_ACTIVATED"));
            assert!(message.contains("Activate the device"));
        }
        other => panic!("unexpected error: {other:?}"),
    }
}

#[cfg(feature = "offline")]
#[tokio::test]
async fn test_checkout_machine_file_with_options_sends_extended_fields() {
    let server = MockServer::start().await;
    let license_key = "TEST-LICENSE-KEY";
    let fingerprint = "custom-fingerprint-456";
    let (machine_file_response, public_key_b64) =
        build_machine_file_fixture_without_license(license_key, fingerprint);

    Mock::given(method("POST"))
        .and(path("/products/test-product/licenses/machine-file"))
        .respond_with(ResponseTemplate::new(201).set_body_json(machine_file_response))
        .mount(&server)
        .await;

    let mut config = test_config(&server.uri());
    config.signing_public_key = Some(public_key_b64);
    config.signing_key_id = Some("key-2026".into());
    let sdk = LicenseSeat::new(config);
    let result = sdk
        .checkout_machine_file_with_options(
            license_key,
            licenseseat::MachineFileCheckoutOptions {
                fingerprint: None,
                device_id: None,
                device_fingerprint: Some(fingerprint.into()),
                ttl_days: Some(45),
                grace_period_days: Some(7),
                include_license: false,
                fingerprint_components: std::collections::HashMap::from([(
                    "platform".into(),
                    "macos".into(),
                )]),
            },
        )
        .await
        .unwrap();

    assert_eq!(result.algorithm, "aes-256-gcm+ed25519");
    assert_eq!(result.license_key, license_key);
    assert_eq!(result.fingerprint, fingerprint);

    let requests = server.received_requests().await.unwrap();
    let body: serde_json::Value = serde_json::from_slice(&requests[0].body).unwrap();
    assert_eq!(body["fingerprint"].as_str(), Some(fingerprint));
    assert_eq!(body["device_id"].as_str(), Some(fingerprint));
    assert_eq!(body["device_fingerprint"].as_str(), Some(fingerprint));
    assert_eq!(body["ttl"].as_i64(), Some(45));
    assert_eq!(body["grace_period"].as_i64(), Some(7));
    assert!(body.get("include").is_none());
    assert_eq!(
        body["fingerprint_components"]["platform"].as_str(),
        Some("macos")
    );
}

#[cfg(feature = "offline")]
#[tokio::test]
async fn test_checkout_machine_file_preserves_json_api_error_details() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/products/test-product/licenses/machine-file"))
        .respond_with(ResponseTemplate::new(422).set_body_json(json!({
            "errors": [
                {
                    "code": "DEVICE_NOT_ACTIVATED",
                    "title": "Device not activated",
                    "detail": "Activate the device before checking out a machine file.",
                    "meta": {
                        "parameter": "fingerprint"
                    },
                    "links": {
                        "about": "https://docs.licenseseat.com/errors/device-not-activated"
                    }
                }
            ]
        })))
        .mount(&server)
        .await;

    let sdk = LicenseSeat::new(test_config(&server.uri()));
    let result = sdk
        .checkout_machine_file("TEST-LICENSE-KEY", Some("fingerprint-123"), Some(30))
        .await;

    match result.unwrap_err() {
        licenseseat::Error::Api {
            status,
            code,
            message,
            details,
        } => {
            assert_eq!(status, 422);
            assert_eq!(code.as_deref(), Some("DEVICE_NOT_ACTIVATED"));
            assert!(message.contains("Activate the device"));
            let details = details.expect("expected JSON:API details");
            assert_eq!(
                details
                    .get("meta")
                    .and_then(|value| value.get("parameter"))
                    .and_then(|value| value.as_str()),
                Some("fingerprint")
            );
            assert_eq!(
                details
                    .get("links")
                    .and_then(|value| value.get("about"))
                    .and_then(|value| value.as_str()),
                Some("https://docs.licenseseat.com/errors/device-not-activated")
            );
        }
        other => panic!("unexpected error: {other:?}"),
    }
}

#[cfg(feature = "offline")]
#[tokio::test]
async fn test_verify_machine_file_and_restore_offline() {
    let server = MockServer::start().await;
    let license_key = "TEST-LICENSE-KEY";
    let fingerprint = "stable-fingerprint-123";
    let (machine_file_response, public_key_b64) =
        build_machine_file_fixture(license_key, fingerprint);

    Mock::given(method("POST"))
        .and(path_regex(r"/products/.*/licenses/activate"))
        .respond_with(
            ResponseTemplate::new(201).set_body_json(activation_response(license_key, fingerprint)),
        )
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path("/products/test-product/licenses/machine-file"))
        .respond_with(ResponseTemplate::new(201).set_body_json(machine_file_response.clone()))
        .mount(&server)
        .await;

    let mut online_config = test_config(&server.uri());
    online_config.device_identifier = Some(fingerprint.into());
    online_config.signing_public_key = Some(public_key_b64.clone());
    online_config.signing_key_id = Some("key-2026".into());

    let sdk = LicenseSeat::new(online_config.clone());
    sdk.activate(license_key).await.unwrap();
    let machine_file = sdk
        .checkout_machine_file(license_key, Some(fingerprint), Some(30))
        .await
        .unwrap();

    let verification = sdk
        .verify_machine_file(
            &machine_file,
            Some(&public_key_b64),
            Some(license_key),
            Some(fingerprint),
        )
        .unwrap();
    assert!(verification.valid);
    assert!(
        verification
            .payload
            .as_ref()
            .unwrap()
            .has_entitlement("pro-features")
    );

    let mut offline_config = online_config.clone();
    offline_config.api_base_url = "http://127.0.0.1:9".into();
    let restored_sdk = LicenseSeat::new(offline_config);
    let restore = restored_sdk.restore_license().await;

    assert!(restore.restored);
    assert!(matches!(restore.status, LicenseStatus::OfflineValid { .. }));
    assert!(restore.validation.as_ref().unwrap().valid);
    assert!(restore.validation.as_ref().unwrap().offline);
}

#[cfg(feature = "offline")]
#[tokio::test]
async fn test_zero_day_policy_disables_offline_sync_and_fallback() {
    let server = MockServer::start().await;
    let license_key = "TEST-LICENSE-KEY";
    let fingerprint = "stable-fingerprint-offline-disabled";
    let (machine_file_response, public_key_b64) =
        build_machine_file_fixture(license_key, fingerprint);

    Mock::given(method("POST"))
        .and(path_regex(r"/products/.*/licenses/activate"))
        .respond_with(
            ResponseTemplate::new(201).set_body_json(activation_response(license_key, fingerprint)),
        )
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/products/test-product/licenses/machine-file"))
        .respond_with(ResponseTemplate::new(201).set_body_json(machine_file_response))
        .mount(&server)
        .await;

    let mut config = test_config(&server.uri());
    config.device_identifier = Some(fingerprint.into());
    config.signing_public_key = Some(public_key_b64);
    config.signing_key_id = Some("key-2026".into());
    config.max_offline_days = 0;
    config.offline_fallback_mode = OfflineFallbackMode::Always;

    let sdk = LicenseSeat::new(config.clone());
    sdk.activate(license_key).await.unwrap();

    let sync_error = sdk.sync_offline_assets().await.unwrap_err();
    assert!(
        sync_error
            .to_string()
            .contains("offline validation is disabled")
    );
    let requests = server.received_requests().await.unwrap();
    assert!(
        requests
            .iter()
            .all(|request| !request.url.path().ends_with("/machine-file"))
    );

    // A caller can still inspect/check out a signed artifact explicitly, but
    // local authorization must refuse to use it while policy is disabled.
    sdk.checkout_machine_file(license_key, Some(fingerprint), Some(30))
        .await
        .unwrap();

    config.api_base_url = "http://127.0.0.1:9".into();
    config.max_retries = 0;
    config.retry_delay = Duration::ZERO;
    let restore = LicenseSeat::new(config).restore_license().await;

    assert!(!restore.restored);
    assert!(matches!(restore.status, LicenseStatus::Invalid { .. }));
    assert!(restore.validation.is_none());
}

#[cfg(feature = "offline")]
#[tokio::test]
async fn test_fetched_signing_key_is_not_a_persisted_trust_anchor() {
    let server = MockServer::start().await;
    let license_key = "TEST-LICENSE-KEY";
    let fingerprint = "stable-fingerprint-unpinned-key";
    let (machine_file_response, public_key_b64) =
        build_machine_file_fixture(license_key, fingerprint);

    Mock::given(method("POST"))
        .and(path_regex(r"/products/.*/licenses/activate"))
        .respond_with(
            ResponseTemplate::new(201).set_body_json(activation_response(license_key, fingerprint)),
        )
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/products/test-product/licenses/machine-file"))
        .respond_with(ResponseTemplate::new(201).set_body_json(machine_file_response))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/signing_keys/key-2026"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "object": "signing_key",
            "key_id": "key-2026",
            "algorithm": "Ed25519",
            "public_key": public_key_b64,
            "created_at": null,
            "status": "active"
        })))
        .mount(&server)
        .await;

    let mut online_config = test_config(&server.uri());
    online_config.device_identifier = Some(fingerprint.into());
    let sdk = LicenseSeat::new(online_config.clone());
    sdk.activate(license_key).await.unwrap();
    sdk.checkout_machine_file(license_key, Some(fingerprint), Some(30))
        .await
        .unwrap();

    let mut offline_config = online_config;
    offline_config.api_base_url = "http://127.0.0.1:9".into();
    offline_config.max_retries = 0;
    offline_config.retry_delay = Duration::ZERO;
    let restored = LicenseSeat::new(offline_config).restore_license().await;

    assert!(!restored.restored);
    assert!(matches!(
        restored.status,
        LicenseStatus::OfflineInvalid { .. }
    ));
    assert!(restored.validation.is_some_and(|result| !result.valid));
}

#[cfg(feature = "offline")]
#[tokio::test]
async fn test_offline_validation_does_not_renew_last_online_validation_time() {
    let server = MockServer::start().await;
    let license_key = "TEST-LICENSE-KEY";
    let fingerprint = "stable-fingerprint-grace-window";
    let (machine_file_response, public_key_b64) =
        build_machine_file_fixture(license_key, fingerprint);

    Mock::given(method("POST"))
        .and(path_regex(r"/products/.*/licenses/activate"))
        .respond_with(
            ResponseTemplate::new(201).set_body_json(activation_response(license_key, fingerprint)),
        )
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/products/test-product/licenses/validate"))
        .respond_with(ResponseTemplate::new(200).set_body_json(
            validation_response_for_fingerprint(true, license_key, fingerprint),
        ))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/products/test-product/licenses/machine-file"))
        .respond_with(ResponseTemplate::new(201).set_body_json(machine_file_response))
        .mount(&server)
        .await;

    let mut config = test_config(&server.uri());
    config.device_identifier = Some(fingerprint.into());
    config.signing_public_key = Some(public_key_b64);
    config.signing_key_id = Some("key-2026".into());
    config.max_retries = 0;
    config.retry_delay = Duration::ZERO;
    config.max_offline_days = 7;
    let sdk = LicenseSeat::new(config.clone());
    sdk.activate(license_key).await.unwrap();
    sdk.checkout_machine_file(license_key, Some(fingerprint), Some(30))
        .await
        .unwrap();
    sdk.validate().await.unwrap();
    let last_online_validation = sdk.current_license().unwrap().last_validated;

    let mut offline_config = config;
    offline_config.api_base_url = "http://127.0.0.1:9".into();
    let offline_sdk = LicenseSeat::new(offline_config);
    assert_eq!(
        offline_sdk.current_license().unwrap().last_validated,
        last_online_validation
    );

    tokio::time::sleep(Duration::from_millis(20)).await;
    let offline = offline_sdk.validate().await.unwrap();

    assert!(offline.valid);
    assert!(offline.offline);
    assert_eq!(
        offline_sdk.current_license().unwrap().last_validated,
        last_online_validation
    );
}

#[cfg(feature = "offline")]
#[tokio::test]
async fn test_unsigned_cached_activation_metadata_is_not_used_for_offline_authorization() {
    let server = MockServer::start().await;
    let license_key = "TEST-LICENSE-KEY";
    let fingerprint = "stable-fingerprint-activation-only";
    let activation_license = license_json(
        license_key,
        "active",
        "pro",
        "named_user",
        &["pro-features"],
        "Test App",
    );
    let (machine_file_response, public_key_b64) =
        build_machine_file_fixture_without_license(license_key, fingerprint);

    Mock::given(method("POST"))
        .and(path_regex(r"/products/.*/licenses/activate"))
        .respond_with(
            ResponseTemplate::new(201).set_body_json(activation_response_with_license(
                license_key,
                fingerprint,
                activation_license,
            )),
        )
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path("/products/test-product/licenses/machine-file"))
        .respond_with(ResponseTemplate::new(201).set_body_json(machine_file_response))
        .mount(&server)
        .await;

    let mut online_config = test_config(&server.uri());
    online_config.device_identifier = Some(fingerprint.into());
    online_config.signing_public_key = Some(public_key_b64);
    online_config.signing_key_id = Some("key-2026".into());

    let sdk = LicenseSeat::new(online_config.clone());
    sdk.activate(license_key).await.unwrap();
    assert!(matches!(sdk.status(), LicenseStatus::Pending { .. }));
    let machine_file = sdk
        .checkout_machine_file(license_key, Some(fingerprint), Some(30))
        .await
        .unwrap();
    let verification = sdk
        .verify_machine_file(
            &machine_file,
            online_config.signing_public_key.as_deref(),
            Some(license_key),
            Some(fingerprint),
        )
        .unwrap();
    assert!(verification.valid);
    assert!(verification.payload.as_ref().unwrap().license.is_none());

    let mut offline_config = online_config.clone();
    offline_config.api_base_url = "http://127.0.0.1:9".into();
    let restored_sdk = LicenseSeat::new(offline_config);
    let restore = restored_sdk.restore_license().await;

    assert!(restore.restored);
    assert!(matches!(restore.status, LicenseStatus::OfflineValid { .. }));
    let validation = restore.validation.as_ref().unwrap();
    assert!(validation.valid);
    assert!(validation.offline);
    assert!(validation.license.plan_key.is_empty());
    assert_eq!(validation.license.mode, "hardware_locked");
    assert_eq!(validation.license.product.slug, "test-product");
    assert!(validation.license.active_entitlements.is_empty());
}

#[cfg(feature = "offline")]
#[tokio::test]
async fn test_unsigned_cached_validation_metadata_is_not_used_for_offline_authorization() {
    let server = MockServer::start().await;
    let license_key = "TEST-LICENSE-KEY";
    let fingerprint = "stable-fingerprint-123";
    let (machine_file_response, public_key_b64) =
        build_machine_file_fixture_without_license(license_key, fingerprint);

    Mock::given(method("POST"))
        .and(path_regex(r"/products/.*/licenses/activate"))
        .respond_with(
            ResponseTemplate::new(201).set_body_json(activation_response(license_key, fingerprint)),
        )
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path("/products/test-product/licenses/validate"))
        .respond_with(ResponseTemplate::new(200).set_body_json(
            validation_with_entitlements_for_fingerprint(license_key, fingerprint),
        ))
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path("/products/test-product/licenses/machine-file"))
        .respond_with(ResponseTemplate::new(201).set_body_json(machine_file_response))
        .mount(&server)
        .await;

    let mut online_config = test_config(&server.uri());
    online_config.device_identifier = Some(fingerprint.into());
    online_config.signing_public_key = Some(public_key_b64);
    online_config.signing_key_id = Some("key-2026".into());

    let sdk = LicenseSeat::new(online_config.clone());
    sdk.activate(license_key).await.unwrap();

    let online_validation = sdk.validate().await.unwrap();
    assert_eq!(online_validation.license.plan_key, "pro");
    assert_eq!(online_validation.license.product.slug, "test-product");
    assert_eq!(online_validation.license.active_entitlements.len(), 2);
    let machine_file = sdk
        .checkout_machine_file(license_key, Some(fingerprint), Some(30))
        .await
        .unwrap();
    let verification = sdk
        .verify_machine_file(
            &machine_file,
            online_config.signing_public_key.as_deref(),
            Some(license_key),
            Some(fingerprint),
        )
        .unwrap();
    assert!(verification.valid);
    assert!(verification.payload.as_ref().unwrap().license.is_none());

    let mut offline_config = online_config.clone();
    offline_config.api_base_url = "http://127.0.0.1:9".into();
    let restored_sdk = LicenseSeat::new(offline_config);
    let restore = restored_sdk.restore_license().await;

    assert!(restore.restored);
    assert!(matches!(restore.status, LicenseStatus::OfflineValid { .. }));
    let validation = restore.validation.as_ref().unwrap();
    assert!(validation.valid);
    assert!(validation.offline);
    assert!(validation.license.plan_key.is_empty());
    assert_eq!(validation.license.product.slug, "test-product");
    assert!(validation.license.active_entitlements.is_empty());
}

#[cfg(feature = "offline")]
#[tokio::test]
async fn test_restore_offline_prefers_embedded_machine_file_license_over_cached_snapshot() {
    let server = MockServer::start().await;
    let license_key = "TEST-LICENSE-KEY";
    let fingerprint = "stable-fingerprint-embedded-license";
    let embedded_license = license_json(
        license_key,
        "active",
        "starter",
        "floating",
        &["starter-features"],
        "Embedded Product",
    );
    let (machine_file_response, public_key_b64) = build_machine_file_fixture_with_embedded_license(
        license_key,
        fingerprint,
        embedded_license,
    );

    Mock::given(method("POST"))
        .and(path_regex(r"/products/.*/licenses/activate"))
        .respond_with(
            ResponseTemplate::new(201).set_body_json(activation_response(license_key, fingerprint)),
        )
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path("/products/test-product/licenses/validate"))
        .respond_with(ResponseTemplate::new(200).set_body_json(
            validation_with_entitlements_for_fingerprint(license_key, fingerprint),
        ))
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path("/products/test-product/licenses/machine-file"))
        .respond_with(ResponseTemplate::new(201).set_body_json(machine_file_response))
        .mount(&server)
        .await;

    let mut online_config = test_config(&server.uri());
    online_config.device_identifier = Some(fingerprint.into());
    online_config.signing_public_key = Some(public_key_b64);
    online_config.signing_key_id = Some("key-2026".into());

    let sdk = LicenseSeat::new(online_config.clone());
    sdk.activate(license_key).await.unwrap();
    let online_validation = sdk.validate().await.unwrap();
    assert_eq!(online_validation.license.plan_key, "pro");
    assert_eq!(online_validation.license.mode, "hardware_locked");
    assert_eq!(online_validation.license.active_entitlements.len(), 2);
    let machine_file = sdk
        .checkout_machine_file(license_key, Some(fingerprint), Some(30))
        .await
        .unwrap();
    let verification = sdk
        .verify_machine_file(
            &machine_file,
            online_config.signing_public_key.as_deref(),
            Some(license_key),
            Some(fingerprint),
        )
        .unwrap();
    assert!(verification.valid);
    assert_eq!(
        verification
            .payload
            .as_ref()
            .unwrap()
            .license
            .as_ref()
            .unwrap()
            .plan_key,
        "starter"
    );

    let mut offline_config = online_config.clone();
    offline_config.api_base_url = "http://127.0.0.1:9".into();
    let restored_sdk = LicenseSeat::new(offline_config);
    let restore = restored_sdk.restore_license().await;

    assert!(restore.restored);
    assert!(matches!(restore.status, LicenseStatus::OfflineValid { .. }));
    let validation = restore.validation.as_ref().unwrap();
    assert!(validation.valid);
    assert!(validation.offline);
    assert_eq!(validation.license.plan_key, "starter");
    assert_eq!(validation.license.mode, "floating");
    // Machine-file schema v2 signs the product slug, not the mutable display name.
    assert_eq!(validation.license.product.name, "test-product");
    assert_eq!(validation.license.active_entitlements.len(), 1);
    assert_eq!(
        validation.license.active_entitlements[0].key,
        "starter-features"
    );
}

// ============================================================================
// Auth Header Tests
// ============================================================================

#[tokio::test]
async fn test_auth_header_present() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path_regex(r"/products/.*/licenses/activate"))
        .and(header("Authorization", "Bearer test-api-key"))
        .respond_with(
            ResponseTemplate::new(201).set_body_json(activation_response("TEST-KEY", "device-123")),
        )
        .mount(&server)
        .await;

    let sdk = LicenseSeat::new(test_config(&server.uri()));
    let result = sdk.activate("TEST-KEY").await;

    // If the auth header wasn't present, the mock wouldn't match
    assert!(result.is_ok());
}

// ============================================================================
// Adversarial Trust-Boundary Regression Tests
// ============================================================================

#[tokio::test]
async fn test_valid_validation_for_another_key_cannot_replace_current_authorization() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path_regex(r"/products/.*/licenses/activate"))
        .respond_with(
            ResponseTemplate::new(201)
                .set_body_json(activation_response("CURRENT-KEY", "device-123")),
        )
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path_regex(r"/products/.*/licenses/validate"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(validation_with_entitlements("OTHER-KEY")),
        )
        .mount(&server)
        .await;

    let sdk = LicenseSeat::new(test_config(&server.uri()));
    sdk.activate("CURRENT-KEY").await.unwrap();
    let other = sdk.validate_key("OTHER-KEY").await.unwrap();

    assert!(other.valid);
    assert_eq!(other.license.key, "OTHER-KEY");
    assert!(sdk.current_license().unwrap().validation.is_none());
    assert!(!sdk.has_entitlement("pro-features"));
    assert!(matches!(sdk.status(), LicenseStatus::Pending { .. }));
}

#[tokio::test]
async fn test_valid_validation_requires_matching_activation_proof() {
    let server = MockServer::start().await;
    let mut response = validation_with_entitlements("TEST-LICENSE-KEY");
    response["activation"] = serde_json::Value::Null;

    Mock::given(method("POST"))
        .and(path_regex(r"/products/.*/licenses/activate"))
        .respond_with(
            ResponseTemplate::new(201)
                .set_body_json(activation_response("TEST-LICENSE-KEY", "device-123")),
        )
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path_regex(r"/products/.*/licenses/validate"))
        .respond_with(ResponseTemplate::new(200).set_body_json(response))
        .mount(&server)
        .await;

    let sdk = LicenseSeat::new(test_config(&server.uri()));
    sdk.activate("TEST-LICENSE-KEY").await.unwrap();

    assert!(matches!(
        sdk.validate().await,
        Err(licenseseat::Error::InvalidResponse(_))
    ));
    assert!(sdk.current_license().unwrap().validation.is_none());
    assert!(!sdk.has_entitlement("pro-features"));
}

#[tokio::test]
async fn test_inactive_activation_response_is_rejected() {
    let server = MockServer::start().await;
    let mut response = activation_response("TEST-LICENSE-KEY", "device-123");
    response["license"]["status"] = json!("revoked");

    Mock::given(method("POST"))
        .and(path_regex(r"/products/.*/licenses/activate"))
        .respond_with(ResponseTemplate::new(201).set_body_json(response))
        .mount(&server)
        .await;

    let sdk = LicenseSeat::new(test_config(&server.uri()));
    assert!(matches!(
        sdk.activate("TEST-LICENSE-KEY").await,
        Err(licenseseat::Error::InvalidResponse(_))
    ));
    assert!(sdk.current_license().is_none());
}

#[tokio::test]
async fn test_mismatched_deactivation_response_does_not_clear_current_license() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path_regex(r"/products/.*/licenses/activate"))
        .respond_with(
            ResponseTemplate::new(201)
                .set_body_json(activation_response("TEST-LICENSE-KEY", "device-123")),
        )
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path_regex(r"/products/.*/licenses/deactivate"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "object": "deactivation",
            "activation_id": "different-activation",
            "deactivated_at": Utc::now().to_rfc3339()
        })))
        .mount(&server)
        .await;

    let sdk = LicenseSeat::new(test_config(&server.uri()));
    sdk.activate("TEST-LICENSE-KEY").await.unwrap();

    assert!(matches!(
        sdk.deactivate().await,
        Err(licenseseat::Error::InvalidResponse(_))
    ));
    assert!(sdk.current_license().is_some());
}

#[tokio::test]
async fn test_inactive_heartbeat_revokes_current_in_memory_state() {
    let server = MockServer::start().await;
    let mut heartbeat = heartbeat_response("TEST-LICENSE-KEY");
    heartbeat["license"]["status"] = json!("suspended");

    Mock::given(method("POST"))
        .and(path_regex(r"/products/.*/licenses/activate"))
        .respond_with(
            ResponseTemplate::new(201)
                .set_body_json(activation_response("TEST-LICENSE-KEY", "device-123")),
        )
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path_regex(r"/products/.*/licenses/heartbeat"))
        .respond_with(ResponseTemplate::new(200).set_body_json(heartbeat))
        .mount(&server)
        .await;

    let sdk = LicenseSeat::new(test_config(&server.uri()));
    sdk.activate("TEST-LICENSE-KEY").await.unwrap();

    assert!(matches!(
        sdk.heartbeat().await,
        Err(licenseseat::Error::InvalidResponse(_))
    ));
    assert!(sdk.current_license().is_none());
}

#[tokio::test]
async fn test_untrusted_api_error_text_is_sanitized() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path_regex(r"/products/.*/licenses/activate"))
        .respond_with(ResponseTemplate::new(422).set_body_json(json!({
            "error": {
                "code": "invalid\nforged_code",
                "message": "attacker text\nforged log line"
            }
        })))
        .mount(&server)
        .await;

    let sdk = LicenseSeat::new(test_config(&server.uri()));
    let error = sdk.activate("TEST-LICENSE-KEY").await.unwrap_err();

    match &error {
        licenseseat::Error::Api { code, message, .. } => {
            assert!(code.is_none());
            assert_eq!(message, "Request failed");
        }
        other => panic!("expected API error, got {other:?}"),
    }
    let display = error.to_string();
    assert!(!display.contains("forged"));
    assert!(!display.contains('\n'));
}

#[tokio::test]
async fn test_malformed_health_and_release_responses_fail_closed() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/health"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "object": "health",
            "status": "degraded",
            "api_version": "test",
            "timestamp": Utc::now().to_rfc3339()
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/products/test-product/releases/latest"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "object": "release",
            "version": "9.9.9",
            "channel": "stable",
            "platform": "macos",
            "published_at": Utc::now().to_rfc3339(),
            "product_slug": "other-product"
        })))
        .mount(&server)
        .await;

    let sdk = LicenseSeat::new(test_config(&server.uri()));
    assert!(matches!(
        sdk.health_check().await,
        Err(licenseseat::Error::InvalidResponse(_))
    ));
    assert!(!sdk.is_online());
    assert!(sdk.last_health_error().is_some());
    assert!(matches!(
        sdk.get_latest_release(None, None, None).await,
        Err(licenseseat::Error::InvalidResponse(_))
    ));
}

#[tokio::test]
async fn test_expired_download_token_response_is_rejected() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/products/test-product/releases/2.1.0/download_token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "object": "download_token",
            "token": "signed-download-token",
            "expires_at": (Utc::now() - chrono::Duration::minutes(1)).to_rfc3339()
        })))
        .mount(&server)
        .await;

    let sdk = LicenseSeat::new(test_config(&server.uri()));
    assert!(matches!(
        sdk.generate_download_token("2.1.0", "TEST-LICENSE-KEY", None, Some("macos"))
            .await,
        Err(licenseseat::Error::InvalidResponse(_))
    ));
}

#[tokio::test]
async fn test_invalid_release_filter_is_rejected_before_network_access() {
    let server = MockServer::start().await;
    let sdk = LicenseSeat::new(test_config(&server.uri()));

    assert!(matches!(
        sdk.get_latest_release(None, Some("../../beta"), None).await,
        Err(licenseseat::Error::Configuration(_))
    ));
    assert!(server.received_requests().await.unwrap().is_empty());
}

#[cfg(feature = "offline")]
#[tokio::test]
async fn test_signed_machine_file_is_bound_to_configured_product() {
    let server = MockServer::start().await;
    let license_key = "TEST-LICENSE-KEY";
    let fingerprint = "stable-product-bound-fingerprint";
    let (machine_file_response, public_key) =
        build_machine_file_fixture_without_license(license_key, fingerprint);
    Mock::given(method("POST"))
        .and(path("/products/test-product/licenses/machine-file"))
        .respond_with(ResponseTemplate::new(201).set_body_json(machine_file_response))
        .mount(&server)
        .await;

    let mut config = test_config(&server.uri());
    config.device_identifier = Some(fingerprint.into());
    config.signing_public_key = Some(public_key.clone());
    config.signing_key_id = Some("key-2026".into());
    let sdk = LicenseSeat::new(config);
    let machine_file = sdk
        .checkout_machine_file(license_key, Some(fingerprint), Some(30))
        .await
        .unwrap();

    let mut other_product_config = test_config(&server.uri());
    other_product_config.product_slug = "other-product".into();
    other_product_config.device_identifier = Some(fingerprint.into());
    other_product_config.signing_public_key = Some(public_key);
    other_product_config.signing_key_id = Some("key-2026".into());
    let other_product_sdk = LicenseSeat::new(other_product_config);

    assert!(matches!(
        other_product_sdk.inspect_machine_file(
            &machine_file,
            None,
            Some(license_key),
            Some(fingerprint)
        ),
        Err(licenseseat::Error::OfflineVerificationFailed(message))
            if message == "PRODUCT_MISMATCH"
    ));
}

#[tokio::test]
async fn test_unclassified_deactivation_404_does_not_clear_local_state() {
    let server = MockServer::start().await;
    let license_key = "TEST-LICENSE-KEY";
    let fingerprint = "stable-deactivation-404-fingerprint";

    Mock::given(method("POST"))
        .and(path("/products/test-product/licenses/activate"))
        .respond_with(
            ResponseTemplate::new(201).set_body_json(activation_response(license_key, fingerprint)),
        )
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/products/test-product/licenses/deactivate"))
        .respond_with(ResponseTemplate::new(404).set_body_json(json!({
            "error": {
                "code": "product_not_found",
                "message": "Product not found"
            }
        })))
        .mount(&server)
        .await;

    let mut config = test_config(&server.uri());
    config.device_identifier = Some(fingerprint.into());
    let sdk = LicenseSeat::new(config);
    sdk.activate(license_key).await.unwrap();

    assert!(matches!(
        sdk.deactivate().await,
        Err(licenseseat::Error::Api {
            status: 404,
            code: Some(code),
            ..
        }) if code == "product_not_found"
    ));
    assert_eq!(
        sdk.current_license()
            .as_ref()
            .map(|license| license.license_key.as_str()),
        Some(license_key)
    );
}

#[tokio::test]
async fn test_duplicate_keys_in_nested_api_metadata_are_rejected() {
    let server = MockServer::start().await;
    let response = r#"{
        "object":"activation",
        "id":"act-12345-uuid",
        "device_id":"device-123",
        "device_name":"Test Device",
        "license_key":"TEST-LICENSE-KEY",
        "activated_at":"2026-01-01T00:00:00Z",
        "deactivated_at":null,
        "ip_address":"127.0.0.1",
        "metadata":{"role":"user","role":"admin"},
        "license":{
            "object":"license",
            "key":"TEST-LICENSE-KEY",
            "status":"active",
            "starts_at":null,
            "expires_at":null,
            "mode":"hardware_locked",
            "plan_key":"pro",
            "seat_limit":5,
            "active_seats":1,
            "active_entitlements":[],
            "metadata":null,
            "product":{"slug":"test-product","name":"Test App"}
        }
    }"#;
    Mock::given(method("POST"))
        .and(path("/products/test-product/licenses/activate"))
        .respond_with(ResponseTemplate::new(201).set_body_raw(response, "application/json"))
        .mount(&server)
        .await;

    let sdk = LicenseSeat::new(test_config(&server.uri()));
    assert!(matches!(
        sdk.activate("TEST-LICENSE-KEY").await,
        Err(licenseseat::Error::Json(_))
    ));
    assert!(sdk.current_license().is_none());
}
