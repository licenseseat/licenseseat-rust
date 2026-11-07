//! Integration tests for the LicenseSeat SDK.
//!
//! These tests use wiremock to mock HTTP responses and verify the full
//! SDK flow from activation through validation and deactivation.

use chrono::Utc;
use licenseseat::{
    ClientStatus, Config, EntitlementReason, LicenseSeat, LicenseStatus, OfflineFallbackMode,
    TrustedLicenseSource,
};
use serde_json::json;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use wiremock::matchers::{body_partial_json, header, method, path, path_regex, query_param};
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
        api_base_url: base_url.into(),
        storage_prefix: unique_prefix,
        device_identifier: Some("device-123".into()),
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

#[cfg(feature = "offline")]
fn cache_path_for(prefix: &str, key: &str) -> std::path::PathBuf {
    let namespace = Sha256::digest(prefix.as_bytes());
    let namespace = namespace
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    dirs::data_local_dir()
        .or_else(dirs::data_dir)
        .expect("application data dir")
        .join("licenseseat")
        .join(format!("v2_{namespace}__{key}.json"))
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
    build_machine_file_fixture_with_timing(
        license_key,
        fingerprint,
        embedded_license,
        Utc::now() - chrono::Duration::minutes(1),
        chrono::Duration::days(30).num_seconds(),
        3600,
        None,
    )
}

#[cfg(feature = "offline")]
fn build_machine_file_fixture_with_timing(
    license_key: &str,
    fingerprint: &str,
    embedded_license: Option<serde_json::Value>,
    issued_at: chrono::DateTime<Utc>,
    ttl: i64,
    grace_period: i64,
    not_before_override: Option<i64>,
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
    let expires_at = issued_at + chrono::Duration::seconds(ttl);

    let payload = json!({
        "meta": {
            "schema_version": 2,
            "issued": issued_at.to_rfc3339(),
            "iat": issued_at.timestamp(),
            "expiry": expires_at.to_rfc3339(),
            "exp": expires_at.timestamp(),
            "nbf": not_before_override.unwrap_or_else(|| issued_at.timestamp()),
            "ttl": ttl,
            "grace_period": grace_period,
            "lic": license_key,
            "license_exp": null,
            "kid": "key-2026",
            "sdk_version": env!("CARGO_PKG_VERSION")
        },
        "data": {
            "type": "machines",
            "id": "act-12345-uuid",
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
                    "ttl": ttl,
                    "issued": issued_at.to_rfc3339(),
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
        api_base_url: "http://127.0.0.1:9".into(),
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
async fn stateless_deactivation_does_not_stop_or_clear_the_cached_license() {
    let server = MockServer::start().await;
    let active_key = "ACTIVE-LICENSE";

    Mock::given(method("POST"))
        .and(path_regex(r"/products/.*/licenses/activate"))
        .respond_with(
            ResponseTemplate::new(201).set_body_json(activation_response(active_key, "device-123")),
        )
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/products/test-product/licenses/deactivate"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "object": "deactivation",
            "activation_id": "other-activation",
            "deactivated_at": Utc::now().to_rfc3339()
        })))
        .mount(&server)
        .await;

    let mut config = test_config(&server.uri());
    config.auto_validate_interval = Duration::from_secs(3_600);
    config.heartbeat_interval = Duration::from_secs(3_600);
    let sdk = LicenseSeat::try_new(config).unwrap();
    sdk.activate(active_key).await.unwrap();
    assert!(sdk.is_auto_validating());
    assert!(sdk.is_heartbeat_running());

    sdk.deactivate_key("OTHER-LICENSE", Some("other-installation"))
        .await
        .unwrap();

    assert_eq!(
        sdk.current_license()
            .as_ref()
            .map(|license| license.license_key.as_str()),
        Some(active_key)
    );
    assert!(sdk.is_license_state_trusted());
    assert!(matches!(sdk.status(), LicenseStatus::Active { .. }));
    assert!(sdk.is_auto_validating());
    assert!(sdk.is_heartbeat_running());
    sdk.reset();
}

#[tokio::test]
async fn stateless_validation_does_not_supersede_active_license_validation() {
    let server = MockServer::start().await;
    let active_key = "ACTIVE-LICENSE";

    Mock::given(method("POST"))
        .and(path_regex(r"/products/.*/licenses/activate"))
        .respond_with(
            ResponseTemplate::new(201).set_body_json(activation_response(active_key, "device-123")),
        )
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/products/test-product/licenses/validate"))
        .and(body_partial_json(
            json!({ "license_key": "ACTIVE-LICENSE" }),
        ))
        .respond_with(
            ResponseTemplate::new(200)
                .set_delay(Duration::from_millis(200))
                .set_body_json(validation_with_entitlements(active_key)),
        )
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/products/test-product/licenses/validate"))
        .and(body_partial_json(json!({ "license_key": "OTHER-LICENSE" })))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(validation_response(true, "OTHER-LICENSE")),
        )
        .mount(&server)
        .await;

    let sdk = LicenseSeat::try_new(test_config(&server.uri())).unwrap();
    sdk.activate(active_key).await.unwrap();

    let active_validation = {
        let sdk = sdk.clone();
        tokio::spawn(async move { sdk.validate().await })
    };
    tokio::time::sleep(Duration::from_millis(50)).await;
    let unrelated_validation = sdk.validate_key("OTHER-LICENSE").await.unwrap();

    assert!(unrelated_validation.valid);
    assert!(active_validation.await.unwrap().unwrap().valid);
    assert_eq!(
        sdk.current_license()
            .as_ref()
            .map(|license| license.license_key.as_str()),
        Some(active_key)
    );
    assert!(sdk.has_entitlement("pro-features"));
    assert!(matches!(sdk.status(), LicenseStatus::Active { .. }));
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
async fn test_status_active_immediately_after_activation() {
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
    // Activation is an authoritative online grant; a redundant validation is
    // not required before the host can enable licensed functionality.
    assert!(matches!(status, LicenseStatus::Active { .. }));
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

#[tokio::test]
async fn state_snapshot_is_internally_consistent_during_deactivation() {
    let server = MockServer::start().await;
    let license_key = "SNAPSHOT-LICENSE";

    Mock::given(method("POST"))
        .and(path_regex(r"/products/.*/licenses/activate"))
        .respond_with(
            ResponseTemplate::new(201).set_body_json(activation_response_with_license(
                license_key,
                "device-123",
                license_json(
                    license_key,
                    "active",
                    "pro",
                    "hardware_locked",
                    &["pro-features"],
                    "Test App",
                ),
            )),
        )
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path_regex(r"/products/.*/licenses/deactivate"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_delay(Duration::from_millis(100))
                .set_body_json(deactivation_response()),
        )
        .mount(&server)
        .await;

    let sdk = LicenseSeat::try_new(test_config(&server.uri())).unwrap();
    sdk.activate(license_key).await.unwrap();

    let task = {
        let sdk = sdk.clone();
        tokio::spawn(async move { sdk.deactivate().await })
    };

    while !task.is_finished() {
        assert_coherent_snapshot(&sdk);
        tokio::task::yield_now().await;
    }
    task.await.unwrap().unwrap();
    assert_coherent_snapshot(&sdk);
}

fn assert_coherent_snapshot(sdk: &LicenseSeat) {
    let snapshot = sdk.state_snapshot();
    match snapshot.client_status {
        ClientStatus::Active => {
            assert!(matches!(snapshot.status, LicenseStatus::Active { .. }));
            assert!(snapshot.license.is_some());
            assert!(
                snapshot
                    .validation
                    .as_ref()
                    .is_some_and(|value| value.valid)
            );
            assert_eq!(snapshot.active_entitlements.len(), 1);
            assert_eq!(
                snapshot.trusted_source,
                Some(TrustedLicenseSource::OnlineResponse)
            );
        }
        ClientStatus::Inactive => {
            assert!(matches!(snapshot.status, LicenseStatus::Inactive { .. }));
            assert!(snapshot.license.is_none());
            assert!(snapshot.validation.is_none());
            assert!(snapshot.active_entitlements.is_empty());
            assert!(snapshot.trusted_source.is_none());
        }
        other => panic!("impossible mixed snapshot during deactivation: {other}"),
    }
}

/// Wait until the wall clock (which the SDK reads for entitlement expiry)
/// has reached `instant`. This is a condition wait, not a timing guess: it
/// returns as soon as the condition holds, however loaded the machine is.
async fn wait_for_wall_clock(instant: chrono::DateTime<Utc>) {
    loop {
        let remaining = instant - Utc::now();
        if remaining <= chrono::Duration::zero() {
            return;
        }
        tokio::time::sleep(remaining.to_std().unwrap_or(Duration::from_millis(1))).await;
    }
}

fn drain_state_changes(
    events: &mut tokio::sync::broadcast::Receiver<licenseseat::Event>,
) -> Vec<licenseseat::Event> {
    let mut changes = Vec::new();
    loop {
        match events.try_recv() {
            Ok(event) if event.kind == licenseseat::EventKind::LicenseStateChanged => {
                changes.push(event)
            }
            Ok(_) => {}
            Err(tokio::sync::broadcast::error::TryRecvError::Empty) => return changes,
            Err(error) => panic!("event stream broke: {error:?}"),
        }
    }
}

/// licenseseat-rust#9. Entitlement expiries carry sub-second precision; the
/// state-change deadline used to be truncated to whole seconds, so a read in
/// `[floor(expiry), expiry)` emitted the change early (entitlement still
/// listed) and nothing was emitted at the real expiry. Under load that read
/// was usually the test's own pre-subscribe `has_entitlement`, and the test
/// timed out waiting for an event that had already gone to no subscriber.
///
/// The test no longer depends on scheduling: it subscribes before
/// activation, stamps the expiry when the server responds, waits on the wall
/// clock rather than a fixed sleep, and asserts the emitted events
/// synchronously (emission happens inside the observing call).
#[tokio::test]
async fn entitlement_expiry_notifies_subscribers_and_revokes_access_in_process() {
    struct ExpiringEntitlementActivation {
        license_key: &'static str,
        expiry: std::sync::Arc<std::sync::Mutex<Option<chrono::DateTime<Utc>>>>,
    }

    impl wiremock::Respond for ExpiringEntitlementActivation {
        fn respond(&self, _: &wiremock::Request) -> ResponseTemplate {
            // A deliberate sub-second component puts the old truncated
            // deadline a full 500ms ahead of the real expiry.
            let next_second = Utc::now().timestamp() + 1;
            let expiry = chrono::DateTime::from_timestamp(next_second + 2, 500_000_000).unwrap();
            *self.expiry.lock().unwrap() = Some(expiry);
            let mut license = license_json(
                self.license_key,
                "active",
                "pro",
                "hardware_locked",
                &[],
                "Test App",
            );
            license["active_entitlements"] = json!([{
                "key": "short-lived-feature",
                "expires_at": expiry.to_rfc3339(),
                "metadata": null
            }]);
            ResponseTemplate::new(201).set_body_json(activation_response_with_license(
                self.license_key,
                "device-123",
                license,
            ))
        }
    }

    let server = MockServer::start().await;
    let license_key = "EXPIRING-ENTITLEMENT-LICENSE";
    let stamped_expiry = std::sync::Arc::new(std::sync::Mutex::new(None));
    Mock::given(method("POST"))
        .and(path_regex(r"/products/.*/licenses/activate"))
        .respond_with(ExpiringEntitlementActivation {
            license_key,
            expiry: stamped_expiry.clone(),
        })
        .mount(&server)
        .await;

    let mut config = test_config(&server.uri());
    // No background observers: only this test's own calls observe state.
    config.network_recheck_interval = Duration::ZERO;
    config.offline_token_refresh_interval = Duration::ZERO;
    let sdk = LicenseSeat::try_new(config).unwrap();
    let mut events = sdk.subscribe();
    let activated = sdk.activate(license_key).await.unwrap();
    // The SDK installs its runtime state (and the entitlement deadline)
    // before `activate` returns, so if we are still before the expiry here,
    // the entitlement was live when installed and its expiry must be
    // announced exactly once. Only if the machine stalled past the expiry
    // during activation is "already expired on arrival, never announced"
    // also correct.
    let activation_returned_at = Utc::now();
    let expiry = stamped_expiry
        .lock()
        .unwrap()
        .expect("activation responded");
    let installed_before_expiry_is_certain = activation_returned_at < expiry;
    let activated_entitlements = &activated
        .validation
        .as_ref()
        .expect("activation validation")
        .license
        .active_entitlements;
    assert_eq!(activated_entitlements.len(), 1);
    assert_eq!(activated_entitlements[0].expires_at, Some(expiry));

    // Observe inside the last (partial) second before expiry. Whenever this
    // observation lands before the real expiry, the entitlement must still be
    // active and no state change may have been announced.
    let truncated_deadline = chrono::DateTime::from_timestamp(expiry.timestamp(), 0).unwrap();
    wait_for_wall_clock(truncated_deadline).await;
    let observed = sdk.check_entitlement("short-lived-feature");
    let early_changes = drain_state_changes(&mut events);
    // Sampled after the drain: if even the drain finished before the expiry,
    // no observer (ours or a background task) can legitimately have announced
    // it yet, so any drained state change is the early-announcement bug.
    let drained_before_expiry = Utc::now() < expiry;
    if drained_before_expiry {
        assert!(observed.active, "entitlement is active until its expiry");
        assert!(
            early_changes.is_empty(),
            "no state change before the entitlement lapses: {early_changes:?}"
        );
    }

    wait_for_wall_clock(expiry).await;
    let entitlement = sdk.check_entitlement("short-lived-feature");
    assert!(!entitlement.active);
    assert_eq!(entitlement.reason, Some(EntitlementReason::Expired));
    assert!(sdk.active_entitlements().is_empty());
    assert!(matches!(sdk.status(), LicenseStatus::Active { .. }));

    let changes: Vec<_> = early_changes
        .into_iter()
        .chain(drain_state_changes(&mut events))
        .collect();
    if installed_before_expiry_is_certain {
        assert_eq!(
            changes.len(),
            1,
            "exactly one state change for one expiry: {changes:?}"
        );
    } else {
        assert!(changes.len() <= 1, "at most one state change: {changes:?}");
    }
    for change in changes {
        let licenseseat::EventData::Validation(event_validation) =
            change.data.expect("state change validation payload")
        else {
            panic!("state change should carry the current validation");
        };
        assert!(
            event_validation.license.active_entitlements.is_empty(),
            "the state change must announce the lapsed entitlement as gone"
        );
    }
    assert!(
        sdk.current_authoritative_validation()
            .expect("authoritative validation")
            .license
            .active_entitlements
            .is_empty(),
        "every public authoritative snapshot must prune expired entitlements"
    );

    // Further observations must not re-announce the same expiry.
    sdk.check_entitlement("short-lived-feature");
    sdk.status();
    assert!(drain_state_changes(&mut events).is_empty());
}

/// `restore_license` on an already-established state answers from one
/// observation: after an entitlement lapses, the returned validation must not
/// still list it beside a status that excludes it (#16 review, round 2).
#[tokio::test]
async fn restore_on_an_established_state_answers_from_one_observation() {
    let server = MockServer::start().await;
    let license_key = "RESTORE-OBSERVATION-LICENSE";
    let expiry = Utc::now() + chrono::Duration::milliseconds(1_500);
    let mut license = license_json(
        license_key,
        "active",
        "pro",
        "hardware_locked",
        &[],
        "Test App",
    );
    license["active_entitlements"] = json!([{
        "key": "short-lived-feature",
        "expires_at": expiry.to_rfc3339(),
        "metadata": null
    }]);
    Mock::given(method("POST"))
        .and(path_regex(r"/products/.*/licenses/activate"))
        .respond_with(
            ResponseTemplate::new(201).set_body_json(activation_response_with_license(
                license_key,
                "device-123",
                license,
            )),
        )
        .mount(&server)
        .await;

    let mut config = test_config(&server.uri());
    config.network_recheck_interval = Duration::ZERO;
    config.offline_token_refresh_interval = Duration::ZERO;
    let sdk = LicenseSeat::try_new(config).unwrap();
    sdk.activate(license_key).await.unwrap();
    wait_for_wall_clock(expiry).await;

    let restore = sdk.restore_license().await;
    assert!(restore.restored, "the license itself is still active");
    let LicenseStatus::Active { details } = &restore.status else {
        panic!("unexpected status {:?}", restore.status);
    };
    assert!(details.entitlements.is_empty());
    let validation = restore.validation.expect("established validation");
    assert!(validation.valid);
    assert!(
        validation.license.active_entitlements.is_empty(),
        "restore returned a validation that still lists a lapsed entitlement"
    );
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
async fn test_offline_restore_does_not_reuse_unsigned_heartbeat_metadata() {
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
    assert!(matches!(sdk.status(), LicenseStatus::Active { .. }));
    let heartbeat = sdk.heartbeat().await.unwrap();
    assert_eq!(heartbeat.license.plan_key, "pro");
    assert_eq!(heartbeat.license.mode, "named_user");
    assert_eq!(heartbeat.license.active_entitlements.len(), 2);
    assert!(sdk.has_entitlement("pro-features"));
    assert!(sdk.has_entitlement("team-sync"));
    assert_eq!(sdk.active_entitlements().len(), 2);
    assert_eq!(
        sdk.current_trusted_license_source(),
        Some(licenseseat::TrustedLicenseSource::OnlineResponse)
    );
    let snapshot_path = cache_path_for(&online_config.storage_prefix, "license_snapshot");
    assert!(!snapshot_path.exists());

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

    assert!(restore.restored, "restore failed: {restore:?}");
    assert!(matches!(restore.status, LicenseStatus::OfflineValid { .. }));
    let validation = restore.validation.as_ref().unwrap();
    assert!(validation.valid);
    assert!(validation.offline);
    assert_eq!(validation.license.plan_key, "");
    assert_eq!(validation.license.mode, "hardware_locked");
    assert_eq!(validation.license.product.name, "test-product");
    assert!(validation.license.active_entitlements.is_empty());
    assert!(!snapshot_path.exists());
}

/// Serves one machine file whose short validity window starts when the first
/// machine-file request arrives, not when the test started. Under parallel
/// load activation alone (durable cache commits use F_FULLFSYNC on macOS) can
/// take seconds, which used to consume a window stamped up front
/// (licenseseat-rust#12).
#[cfg(feature = "offline")]
struct MachineFileStampedOnFirstRequest {
    license_key: &'static str,
    fingerprint: &'static str,
    embedded_license: serde_json::Value,
    ttl: i64,
    issued: std::sync::Arc<std::sync::Mutex<Option<(serde_json::Value, i64)>>>,
}

#[cfg(feature = "offline")]
impl wiremock::Respond for MachineFileStampedOnFirstRequest {
    fn respond(&self, _: &wiremock::Request) -> ResponseTemplate {
        let mut issued = self.issued.lock().unwrap();
        let (response, _) = issued.get_or_insert_with(|| {
            let issued_at = Utc::now() - chrono::Duration::seconds(1);
            let (response, _) = build_machine_file_fixture_with_timing(
                self.license_key,
                self.fingerprint,
                Some(self.embedded_license.clone()),
                issued_at,
                self.ttl,
                0,
                None,
            );
            (response, issued_at.timestamp() + self.ttl)
        });
        ResponseTemplate::new(201).set_body_json(response.clone())
    }
}

#[cfg(feature = "offline")]
#[tokio::test]
async fn signed_offline_runtime_grant_expires_without_process_restart() {
    let server = MockServer::start().await;
    let license_key = "SHORT-LIVED-OFFLINE-LICENSE";
    let fingerprint = "short-lived-offline-installation";
    let embedded_license = license_json(
        license_key,
        "active",
        "pro",
        "hardware_locked",
        &["pro-features"],
        "Test Product",
    );
    // Only for the (fixed) public key; the served file is stamped later.
    let (_, public_key_b64) = build_machine_file_fixture_with_timing(
        license_key,
        fingerprint,
        None,
        Utc::now(),
        6,
        0,
        None,
    );
    let issued = std::sync::Arc::new(std::sync::Mutex::new(None));

    Mock::given(method("POST"))
        .and(path_regex(r"/products/.*/licenses/activate"))
        .respond_with(
            ResponseTemplate::new(201).set_body_json(activation_response_with_license(
                license_key,
                fingerprint,
                embedded_license.clone(),
            )),
        )
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/products/test-product/licenses/machine-file"))
        .respond_with(MachineFileStampedOnFirstRequest {
            license_key,
            fingerprint,
            embedded_license,
            ttl: 6,
            issued: issued.clone(),
        })
        .mount(&server)
        .await;

    let mut online_config = test_config(&server.uri());
    online_config.device_identifier = Some(fingerprint.into());
    online_config.signing_public_key = Some(public_key_b64);
    online_config.signing_key_id = Some("key-2026".into());

    let online_sdk = LicenseSeat::try_new(online_config.clone()).unwrap();
    online_sdk.activate(license_key).await.unwrap();
    let checkout = online_sdk
        .checkout_machine_file(license_key, Some(fingerprint), Some(30))
        .await;
    let authorization_deadline = issued
        .lock()
        .unwrap()
        .as_ref()
        .expect("machine file served")
        .1;
    if let Err(error) = checkout {
        // Checkout verifies the file before persisting it, so its return time
        // says nothing about when verification ran; a successful checkout is
        // accepted whenever it returns. A refusal is only correct once the
        // window has closed, which this check proves after the fact. A stall
        // that long leaves nothing below to exercise; the in-process
        // transition itself is covered deterministically by
        // `client::runtime_state_tests::signed_offline_grant_expires_in_process`.
        assert!(
            Utc::now().timestamp() >= authorization_deadline,
            "checkout refused a machine file inside its validity window: {error}"
        );
        return;
    }
    drop(online_sdk);

    let mut offline_config = online_config;
    offline_config.api_base_url = "http://127.0.0.1:9".into();
    offline_config.max_retries = 0;
    offline_config.retry_delay = Duration::ZERO;
    let offline_sdk = LicenseSeat::try_new(offline_config).unwrap();
    let mut expiry_events = offline_sdk.subscribe();
    let restored = offline_sdk.restore_license().await;
    let entitled_after_restore = offline_sdk.has_entitlement("pro-features");
    // Each comparison below is only claimed for instants the test can prove
    // were before the (whole-second) authorization deadline. If the machine
    // stalled past it, only the expired side is asserted; the in-process
    // transition is covered deterministically by
    // `client::runtime_state_tests::signed_offline_grant_expires_in_process`.
    let observed_before_deadline = Utc::now().timestamp() < authorization_deadline;
    if observed_before_deadline {
        assert!(restored.restored);
        assert!(matches!(
            restored.status,
            LicenseStatus::OfflineValid { .. }
        ));
        assert!(entitled_after_restore);
    }

    wait_for_wall_clock(
        chrono::DateTime::from_timestamp(authorization_deadline, 0).expect("deadline"),
    )
    .await;

    assert!(!offline_sdk.has_entitlement("pro-features"));
    assert!(offline_sdk.active_entitlements().is_empty());
    assert!(!offline_sdk.get_status().valid);
    if !observed_before_deadline {
        return;
    }
    assert!(offline_sdk.is_license_state_trusted());
    assert!(matches!(
        offline_sdk.status(),
        LicenseStatus::OfflineInvalid { .. }
    ));
    assert_eq!(
        offline_sdk.get_client_status(),
        ClientStatus::OfflineInvalid
    );
    let validation = offline_sdk.get_status();
    assert!(validation.offline);
    assert_eq!(validation.code.as_deref(), Some("offline_artifact_expired"));
    assert_eq!(
        offline_sdk.current_trusted_license_source(),
        Some(licenseseat::TrustedLicenseSource::SignedOfflineArtifact)
    );
    let failures: Vec<_> = std::iter::from_fn(|| expiry_events.try_recv().ok())
        .map(|event| event.kind)
        .filter(|kind| {
            matches!(
                kind,
                licenseseat::EventKind::OfflineValidationFailed
                    | licenseseat::EventKind::ValidationOfflineFailed
            )
        })
        .collect();
    assert_eq!(
        failures,
        vec![
            licenseseat::EventKind::OfflineValidationFailed,
            licenseseat::EventKind::ValidationOfflineFailed,
        ],
        "one terminal expiry announcement"
    );
}

#[cfg(feature = "offline")]
#[tokio::test]
async fn machine_file_grace_cannot_resurrect_a_zero_width_validity_window() {
    let server = MockServer::start().await;
    let license_key = "ZERO-WINDOW-LICENSE";
    let fingerprint = "zero-window-installation";
    let issued_at = Utc::now() - chrono::Duration::minutes(2);
    let ttl = 60;
    let expires_at = issued_at.timestamp() + ttl;
    let (machine_file_response, public_key_b64) = build_machine_file_fixture_with_timing(
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
        issued_at,
        ttl,
        3600,
        Some(expires_at),
    );

    Mock::given(method("POST"))
        .and(path("/products/test-product/licenses/machine-file"))
        .respond_with(ResponseTemplate::new(201).set_body_json(machine_file_response))
        .mount(&server)
        .await;

    let mut config = test_config(&server.uri());
    config.device_identifier = Some(fingerprint.into());
    config.signing_public_key = Some(public_key_b64);
    config.signing_key_id = Some("key-2026".into());
    let sdk = LicenseSeat::try_new(config).unwrap();
    let error = sdk
        .checkout_machine_file(license_key, Some(fingerprint), Some(30))
        .await
        .unwrap_err();

    assert!(
        matches!(
        error,
        licenseseat::Error::OfflineVerificationFailed(ref code)
            if code == "verification_failed"
        ),
        "unexpected error: {error:?}"
    );
    assert!(sdk.current_machine_file().is_none());
    assert!(!sdk.has_entitlement("pro-features"));
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
    assert!(matches!(sdk.status(), LicenseStatus::Active { .. }));

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
async fn test_get_latest_release_accepts_any_platform() {
    // Regression: the server's `by_platform` scope is
    // `where("platform = ? OR platform = 'any'")` (release.rb:50), so a request
    // filtered to `macos` legitimately resolves to a cross-platform release.
    // The SDK used to reject `platform: "any"` as a response mismatch.
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/products/test-product/releases/latest"))
        .and(query_param("channel", "stable"))
        .and(query_param("platform", "macos"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(release_response("3.0.0", "stable", "any")),
        )
        .mount(&server)
        .await;

    let sdk = LicenseSeat::new(test_config(&server.uri()));
    let result = sdk
        .get_latest_release(None, Some("stable"), Some("macos"))
        .await
        .unwrap();

    assert_eq!(result.version, "3.0.0");
    assert_eq!(result.platform, "any");
}

#[tokio::test]
async fn test_list_releases_accepts_any_platform_alongside_filtered_ones() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/products/test-product/releases"))
        .and(query_param("platform", "windows"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "object": "list",
            "data": [
                release_response("3.0.0", "stable", "any"),
                release_response("2.0.0", "stable", "windows")
            ],
            "has_more": false
        })))
        .mount(&server)
        .await;

    let sdk = LicenseSeat::new(test_config(&server.uri()));
    let result = sdk
        .list_releases(None, None, Some("windows"))
        .await
        .unwrap();

    assert_eq!(result.len(), 2);
    assert_eq!(result[0].platform, "any");
    assert_eq!(result[1].platform, "windows");
}

#[tokio::test]
async fn test_list_releases_with_options_tolerates_has_more_without_cursor() {
    // Regression: `releases_controller#index` sets `has_more` from the page
    // count but hard-codes `next_cursor: nil`. The SDK used to reject that
    // combination, which made every paginated product fail closed.
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/products/test-product/releases"))
        .and(query_param("limit", "1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "object": "list",
            "data": [release_response("2.1.0", "stable", "macos")],
            "has_more": true,
            "next_cursor": null
        })))
        .mount(&server)
        .await;

    let sdk = LicenseSeat::new(test_config(&server.uri()));
    let result = sdk
        .list_releases_with_options(
            None,
            licenseseat::ReleaseListOptions {
                channel: None,
                platform: None,
                limit: Some(1),
            },
        )
        .await
        .unwrap();

    assert_eq!(result.data.len(), 1);
    assert!(result.has_more);
    assert_eq!(result.next_cursor, None);
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
    config.device_identifier = Some(fingerprint.into());
    config.signing_public_key = Some(public_key_b64);
    config.signing_key_id = Some("key-2026".into());
    let sdk = LicenseSeat::try_new(config).unwrap();
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
    config.device_identifier = Some(fingerprint.into());
    config.signing_public_key = Some(public_key_b64);
    config.signing_key_id = Some("key-2026".into());
    let sdk = LicenseSeat::try_new(config).unwrap();
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
async fn test_automatic_machine_file_checkout_minimizes_hardware_data_by_default() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/products/test-product/licenses/machine-file"))
        .respond_with(ResponseTemplate::new(422).set_body_json(json!({
            "error": {
                "code": "device_not_activated",
                "message": "test response"
            }
        })))
        .expect(2)
        .mount(&server)
        .await;

    let default_sdk = LicenseSeat::try_new(test_config(&server.uri())).unwrap();
    assert!(
        default_sdk
            .checkout_machine_file("TEST-LICENSE-KEY", None, Some(30))
            .await
            .is_err()
    );

    let mut opted_in_config = test_config(&server.uri());
    opted_in_config.send_fingerprint_components = true;
    let opted_in_sdk = LicenseSeat::try_new(opted_in_config).unwrap();
    assert!(
        opted_in_sdk
            .checkout_machine_file("TEST-LICENSE-KEY", None, Some(30))
            .await
            .is_err()
    );

    let requests = server.received_requests().await.unwrap();
    let minimized: serde_json::Value = serde_json::from_slice(&requests[0].body).unwrap();
    let opted_in: serde_json::Value = serde_json::from_slice(&requests[1].body).unwrap();
    assert!(minimized.get("fingerprint_components").is_none());
    assert_eq!(
        opted_in["fingerprint_components"]["schema_version"].as_str(),
        Some("1")
    );
    assert!(opted_in["fingerprint_components"]["platform"].is_string());
}

#[cfg(feature = "offline")]
#[tokio::test]
async fn test_offline_checkout_rejects_invalid_input_before_network_io() {
    let server = MockServer::start().await;
    let sdk = LicenseSeat::try_new(test_config(&server.uri())).unwrap();

    for invalid_ttl in [0, -1] {
        let error = sdk
            .generate_offline_token("TEST-LICENSE-KEY", None, Some(invalid_ttl))
            .await
            .unwrap_err();
        assert!(matches!(
            error,
            licenseseat::Error::Configuration(ref message)
                if message == "ttl_days must be greater than zero when provided"
        ));
    }

    let blank_key_error = sdk
        .checkout_machine_file(" \t", None, Some(30))
        .await
        .unwrap_err();
    assert!(matches!(
        blank_key_error,
        licenseseat::Error::Configuration(ref message)
            if message == "license_key is required"
    ));

    for (ttl_days, grace_period_days, expected_field) in [
        (Some(0), None, "ttl_days"),
        (Some(-7), None, "ttl_days"),
        (None, Some(-7), "grace_period_days"),
    ] {
        let error = sdk
            .checkout_machine_file_with_options(
                "TEST-LICENSE-KEY",
                licenseseat::MachineFileCheckoutOptions {
                    ttl_days,
                    grace_period_days,
                    ..Default::default()
                },
            )
            .await
            .unwrap_err();
        assert!(matches!(
            error,
            licenseseat::Error::Configuration(ref message)
                if message.contains(expected_field)
        ));
    }

    assert!(server.received_requests().await.unwrap().is_empty());
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

    assert!(restore.restored, "restore failed: {restore:?}");
    assert!(matches!(restore.status, LicenseStatus::OfflineValid { .. }));
    assert!(restore.validation.as_ref().unwrap().valid);
    assert!(restore.validation.as_ref().unwrap().offline);
}

#[cfg(feature = "offline")]
#[tokio::test]
async fn activation_sync_retries_without_periodic_workers_and_restores_offline() {
    use licenseseat::EventKind;
    use std::sync::Arc;
    use std::sync::atomic::AtomicUsize;

    let server = MockServer::start().await;
    let license_key = "OFFLINE-RETRY-KEY";
    let fingerprint = "stable-fingerprint-123";
    let (machine_file, public_key) = build_machine_file_fixture(license_key, fingerprint);
    Mock::given(method("POST"))
        .and(path_regex(r"/products/.*/licenses/activate"))
        .respond_with(
            ResponseTemplate::new(201).set_body_json(activation_response(license_key, fingerprint)),
        )
        .mount(&server)
        .await;
    let attempts = Arc::new(AtomicUsize::new(0));
    let observed_attempts = attempts.clone();
    Mock::given(method("POST"))
        .and(path("/products/test-product/licenses/machine-file"))
        .respond_with(move |_: &wiremock::Request| {
            if observed_attempts.fetch_add(1, Ordering::SeqCst) == 0 {
                ResponseTemplate::new(503)
            } else {
                ResponseTemplate::new(201).set_body_json(machine_file.clone())
            }
        })
        .mount(&server)
        .await;

    let mut config = test_config(&server.uri());
    let storage = tempfile::tempdir().unwrap();
    config.storage_path = Some(storage.path().into());
    config.device_identifier = Some(fingerprint.into());
    config.signing_public_key = Some(public_key);
    config.signing_key_id = Some("key-2026".into());
    config.network_recheck_interval = Duration::ZERO;
    config.offline_token_refresh_interval = Duration::ZERO;
    config.max_retries = 0;
    let sdk = LicenseSeat::try_new(config.clone()).unwrap();
    let mut events = sdk.subscribe();
    sdk.activate(license_key).await.unwrap();
    tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            if events.recv().await.unwrap().kind == EventKind::OfflineAssetsRefreshed {
                break;
            }
        }
    })
    .await
    .expect("activation-time retry did not download the artifact");
    assert_eq!(attempts.load(Ordering::SeqCst), 2);
    assert!(sdk.current_machine_file().is_some());
    drop(sdk);

    config.api_base_url = "http://127.0.0.1:9".into();
    let restored = LicenseSeat::try_new(config)
        .unwrap()
        .restore_license()
        .await;
    assert!(restored.restored, "offline restore failed: {restored:?}");
    assert!(matches!(
        restored.status,
        LicenseStatus::OfflineValid { .. }
    ));
}

#[cfg(feature = "offline")]
#[tokio::test]
async fn test_offline_restore_does_not_reuse_unsigned_activation_metadata_when_snapshot_is_missing()
{
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
    assert!(matches!(sdk.status(), LicenseStatus::Active { .. }));
    let snapshot_path = cache_path_for(&online_config.storage_prefix, "license_snapshot");
    assert!(!snapshot_path.exists());
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

    assert!(restore.restored, "restore failed: {restore:?}");
    assert!(matches!(restore.status, LicenseStatus::OfflineValid { .. }));
    let validation = restore.validation.as_ref().unwrap();
    assert!(validation.valid);
    assert!(validation.offline);
    assert_eq!(validation.license.plan_key, "");
    assert_eq!(validation.license.mode, "hardware_locked");
    assert_eq!(validation.license.product.slug, "test-product");
    assert_eq!(validation.license.product.name, "test-product");
    assert!(validation.license.active_entitlements.is_empty());
    assert!(!snapshot_path.exists());
}

#[cfg(feature = "offline")]
#[tokio::test]
async fn test_offline_restore_does_not_reuse_unsigned_validation_metadata_when_snapshot_is_missing()
{
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
    let snapshot_path = cache_path_for(&online_config.storage_prefix, "license_snapshot");
    assert!(!snapshot_path.exists());

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

    assert!(restore.restored, "restore failed: {restore:?}");
    assert!(matches!(restore.status, LicenseStatus::OfflineValid { .. }));
    let validation = restore.validation.as_ref().unwrap();
    assert!(validation.valid);
    assert!(validation.offline);
    assert_eq!(validation.license.plan_key, "");
    assert_eq!(validation.license.product.slug, "test-product");
    assert_eq!(validation.license.product.name, "test-product");
    assert!(validation.license.active_entitlements.is_empty());
    assert!(!snapshot_path.exists());
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

    assert!(restore.restored, "restore failed: {restore:?}");
    assert!(matches!(restore.status, LicenseStatus::OfflineValid { .. }));
    let validation = restore.validation.as_ref().unwrap();
    assert!(validation.valid);
    assert!(validation.offline);
    assert_eq!(validation.license.plan_key, "starter");
    assert_eq!(validation.license.mode, "floating");
    // The server's v2 embedded-license schema intentionally carries the
    // product slug, not mutable display metadata such as the product name.
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
    let original = sdk.current_license().unwrap();
    let other = sdk.validate_key("OTHER-KEY").await.unwrap();

    assert!(other.valid);
    assert_eq!(other.license.key, "OTHER-KEY");
    assert_eq!(sdk.current_license(), Some(original));
    assert!(!sdk.has_entitlement("pro-features"));
    assert!(matches!(sdk.status(), LicenseStatus::Active { .. }));
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
    let original = sdk.current_license().unwrap();

    assert!(matches!(
        sdk.validate().await,
        Err(licenseseat::Error::InvalidResponse(_))
    ));
    assert_eq!(sdk.current_license(), Some(original));
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
        Err(licenseseat::Error::ResponseMismatch(_))
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
        Err(licenseseat::Error::ResponseMismatch(_))
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

    let verification = other_product_sdk
        .inspect_machine_file(&machine_file, None, Some(license_key), Some(fingerprint))
        .unwrap();
    assert!(!verification.valid);
    assert_eq!(verification.code.as_deref(), Some("product_mismatch"));
    assert!(verification.payload.is_none());
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

// ============================================================================
// Authoritative denials never fall back to the offline grant
// ============================================================================

/// The cross-SDK contract (licenseseat-swift#26): a denial with one of these
/// codes, thrown or returned as `200 valid:false`, is the current decision.
/// It must never be answered by the cached offline grant, in either fallback
/// mode, now or after a later outage or relaunch. The grant itself is kept
/// (a later online `valid:true` restores it); only revocation purges.
#[cfg(feature = "offline")]
const AUTHORITATIVE_DENIALS: [(u16, &str); 5] = [
    (403, "version_not_entitled"),
    (403, "not_entitled"),
    (422, "product_mismatch"),
    (501, "floating_not_implemented"),
    (501, "named_user_not_implemented"),
];

/// Activate and check out a long-lived signed machine file, so the offline
/// grant is present and valid; returns the online SDK and its config.
#[cfg(feature = "offline")]
async fn sdk_with_valid_offline_grant(
    server: &MockServer,
    mode: OfflineFallbackMode,
) -> (LicenseSeat, Config) {
    sdk_with_valid_offline_grant_configured(server, mode, |_| {}).await
}

#[cfg(feature = "offline")]
async fn sdk_with_valid_offline_grant_configured(
    server: &MockServer,
    mode: OfflineFallbackMode,
    customize: impl FnOnce(&mut Config),
) -> (LicenseSeat, Config) {
    let license_key = "DENIAL-LICENSE";
    let fingerprint = "denial-installation";
    let embedded_license = license_json(
        license_key,
        "active",
        "pro",
        "hardware_locked",
        &["pro-features"],
        "Test Product",
    );
    let (machine_file_response, public_key_b64) = build_machine_file_fixture_with_timing(
        license_key,
        fingerprint,
        Some(embedded_license.clone()),
        Utc::now() - chrono::Duration::minutes(1),
        86_400,
        0,
        None,
    );
    Mock::given(method("POST"))
        .and(path_regex(r"/products/.*/licenses/activate"))
        .respond_with(
            ResponseTemplate::new(201).set_body_json(activation_response_with_license(
                license_key,
                fingerprint,
                embedded_license,
            )),
        )
        .mount(server)
        .await;
    Mock::given(method("POST"))
        .and(path("/products/test-product/licenses/machine-file"))
        .respond_with(ResponseTemplate::new(201).set_body_json(machine_file_response))
        .mount(server)
        .await;

    let mut config = test_config(&server.uri());
    config.device_identifier = Some(fingerprint.into());
    config.signing_public_key = Some(public_key_b64);
    config.signing_key_id = Some("key-2026".into());
    config.offline_fallback_mode = mode;
    config.max_retries = 0;
    config.retry_delay = Duration::ZERO;
    customize(&mut config);

    let sdk = LicenseSeat::try_new(config.clone()).unwrap();
    sdk.activate(license_key).await.unwrap();
    sdk.checkout_machine_file(license_key, Some(fingerprint), Some(30))
        .await
        .unwrap();
    assert!(sdk.has_entitlement("pro-features"));
    (sdk, config)
}

/// After a denial: the SDK is not entitled, the grant is still on disk, a
/// later outage (5xx without a denial code, which normally falls back in
/// both modes) answers with the denial, and a relaunch while offline does not
/// restore the license.
#[cfg(feature = "offline")]
async fn assert_denial_is_the_current_decision(
    server: &MockServer,
    sdk: &LicenseSeat,
    config: &Config,
    label: &str,
) {
    assert!(
        !sdk.has_entitlement("pro-features"),
        "{label}: entitled after denial"
    );
    assert!(!sdk.status().is_active(), "{label}: active after denial");
    assert!(
        cache_path_for(&config.storage_prefix, "machine_file").exists(),
        "{label}: an authoritative denial must not purge the offline grant"
    );

    server.reset().await;
    Mock::given(method("POST"))
        .and(path_regex(r"/products/.*/licenses/validate"))
        .respond_with(ResponseTemplate::new(503))
        .mount(server)
        .await;
    if let Ok(validation) = sdk.validate().await {
        assert!(
            !validation.valid,
            "{label}: outage revived the offline grant"
        );
    }
    assert!(
        !sdk.has_entitlement("pro-features"),
        "{label}: entitled after outage"
    );

    let mut offline_config = config.clone();
    offline_config.api_base_url = "http://127.0.0.1:9".into();
    let relaunched = LicenseSeat::try_new(offline_config).unwrap();
    let restore = relaunched.restore_license().await;
    assert!(
        !restore.restored,
        "{label}: relaunch revived the offline grant"
    );
    assert!(
        !relaunched.has_entitlement("pro-features"),
        "{label}: entitled after relaunch"
    );
}

#[cfg(feature = "offline")]
#[tokio::test]
async fn thrown_authoritative_denials_never_fall_back_to_the_offline_grant() {
    for mode in [
        OfflineFallbackMode::NetworkOnly,
        OfflineFallbackMode::Always,
    ] {
        for (status, code) in AUTHORITATIVE_DENIALS {
            // Mixed case: the contract compares codes case-insensitively.
            let wire_code = if status == 501 {
                code.to_ascii_uppercase()
            } else {
                code.to_string()
            };
            let label = format!("{mode:?} {status} {wire_code}");
            let server = MockServer::start().await;
            let (sdk, config) = sdk_with_valid_offline_grant(&server, mode).await;
            Mock::given(method("POST"))
                .and(path_regex(r"/products/.*/licenses/validate"))
                .respond_with(
                    ResponseTemplate::new(status)
                        .set_body_json(api_error_response(&wire_code, "denied")),
                )
                .mount(&server)
                .await;

            match sdk.validate().await {
                Err(error) => assert_eq!(
                    error.code().map(str::to_ascii_lowercase).as_deref(),
                    Some(code),
                    "{label}"
                ),
                Ok(validation) => panic!("{label}: fell back to {validation:?}"),
            }
            assert_denial_is_the_current_decision(&server, &sdk, &config, &label).await;
        }
    }
}

/// Codex #20 finding 1: a retried request must not replace an authoritative
/// denial with a later codeless 5xx that would fall back to the grant.
#[cfg(feature = "offline")]
#[tokio::test]
async fn retries_never_discard_an_authoritative_denial() {
    let server = MockServer::start().await;
    let (sdk, config) =
        sdk_with_valid_offline_grant_configured(&server, OfflineFallbackMode::Always, |config| {
            config.max_retries = 2;
            config.retry_delay = Duration::from_millis(1);
        })
        .await;
    Mock::given(method("POST"))
        .and(path_regex(r"/products/.*/licenses/validate"))
        .respond_with(
            ResponseTemplate::new(501)
                .set_body_json(api_error_response("floating_not_implemented", "denied")),
        )
        .up_to_n_times(1)
        .with_priority(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path_regex(r"/products/.*/licenses/validate"))
        .respond_with(ResponseTemplate::new(503))
        .with_priority(2)
        .mount(&server)
        .await;

    match sdk.validate().await {
        Err(error) => assert_eq!(error.code(), Some("floating_not_implemented")),
        Ok(validation) => panic!("retry masked the denial: {validation:?}"),
    }
    assert_denial_is_the_current_decision(&server, &sdk, &config, "retried 501").await;
}

/// Codex #20 finding 2: a denial from machine-file checkout, legacy offline
/// token issuance or re-activation of the current activation is recorded too.
#[cfg(feature = "offline")]
#[tokio::test]
async fn lifecycle_authoritative_denials_are_recorded() {
    for (endpoint, status, code) in [
        ("machine-file", 403_u16, "not_entitled"),
        ("offline-token", 403, "version_not_entitled"),
        ("activate", 403, "not_entitled"),
        ("machine-file", 501, "NAMED_USER_NOT_IMPLEMENTED"),
    ] {
        let label = format!("{endpoint} {status} {code}");
        let server = MockServer::start().await;
        let (sdk, config) = sdk_with_valid_offline_grant_configured(
            &server,
            OfflineFallbackMode::Always,
            |config| config.enable_legacy_offline_tokens = true,
        )
        .await;
        server.reset().await;
        Mock::given(method("POST"))
            .and(path_regex(format!(r"/products/.*/licenses/{endpoint}$")))
            .respond_with(
                ResponseTemplate::new(status).set_body_json(api_error_response(code, "denied")),
            )
            .mount(&server)
            .await;
        let license = sdk.current_license().expect("current license");
        let outcome = match endpoint {
            "machine-file" => sdk
                .checkout_machine_file(&license.license_key, Some(&license.device_id), Some(30))
                .await
                .map(|_| ()),
            "offline-token" => sdk
                .generate_offline_token(&license.license_key, Some(&license.device_id), Some(30))
                .await
                .map(|_| ()),
            _ => sdk.activate(&license.license_key).await.map(|_| ()),
        };
        assert!(outcome.is_err(), "{label}: request succeeded");
        assert_denial_is_the_current_decision(&server, &sdk, &config, &label).await;
    }
}

#[cfg(feature = "offline")]
#[tokio::test]
async fn offline_sync_stops_after_a_machine_file_denial() {
    let server = MockServer::start().await;
    let (sdk, _config) =
        sdk_with_valid_offline_grant_configured(&server, OfflineFallbackMode::Always, |config| {
            config.enable_legacy_offline_tokens = true
        })
        .await;
    server.reset().await;
    Mock::given(method("POST"))
        .and(path_regex(r"/products/.*/licenses/machine-file$"))
        .respond_with(
            ResponseTemplate::new(403).set_body_json(api_error_response("not_entitled", "denied")),
        )
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path_regex(r"/products/.*/licenses/offline-token$"))
        .respond_with(ResponseTemplate::new(500))
        .expect(0)
        .mount(&server)
        .await;
    assert!(sdk.sync_offline_assets().await.is_err());
    server.verify().await;
}

/// Codex #20 finding 3: if the denial cannot be written, it still holds for
/// this process and later outages here cannot fall back past it.
// The SDK re-asserts 0o700 on its cache directory, so a plain chmod cannot
// make writes fail; the macOS user-immutable flag can.
#[cfg(all(feature = "offline", target_os = "macos"))]
#[tokio::test]
async fn unpersistable_denial_still_holds_in_process() {
    let set_immutable = |path: &std::path::Path, on: bool| {
        let status = std::process::Command::new("chflags")
            .arg(if on { "uchg" } else { "nouchg" })
            .arg(path)
            .status()
            .expect("chflags");
        assert!(status.success());
    };
    for valid_false in [false, true] {
        let label = if valid_false {
            "200 valid:false"
        } else {
            "403"
        };
        let server = MockServer::start().await;
        // A private cache directory, so making it read-only affects no other test.
        let storage = tempfile::tempdir().unwrap();
        let storage_path = storage.path().to_path_buf();
        let (sdk, _config) = sdk_with_valid_offline_grant_configured(
            &server,
            OfflineFallbackMode::Always,
            |config| config.storage_path = Some(storage_path.clone()),
        )
        .await;
        let response = if valid_false {
            let mut denied = license_json(
                "DENIAL-LICENSE",
                "active",
                "pro",
                "hardware_locked",
                &[],
                "Test Product",
            );
            denied["active_seats"] = json!(1);
            ResponseTemplate::new(200).set_body_json(json!({
                "object": "validation_result",
                "valid": false,
                "code": "not_entitled",
                "message": "denied",
                "license": denied,
            }))
        } else {
            ResponseTemplate::new(403).set_body_json(api_error_response("not_entitled", "denied"))
        };
        Mock::given(method("POST"))
            .and(path_regex(r"/products/.*/licenses/validate"))
            .respond_with(response)
            .mount(&server)
            .await;

        set_immutable(&storage_path, true);
        let denied = sdk.validate().await;
        let entitled_after_denial = sdk.has_entitlement("pro-features");
        server.reset().await;
        Mock::given(method("POST"))
            .and(path_regex(r"/products/.*/licenses/validate"))
            .respond_with(ResponseTemplate::new(503))
            .mount(&server)
            .await;
        let during_outage = sdk.validate().await;
        let entitled_during_outage = sdk.has_entitlement("pro-features");
        set_immutable(&storage_path, false);

        assert!(
            matches!(denied, Err(licenseseat::Error::Cache(_))),
            "{label}: the denial write was expected to fail, got {denied:?}"
        );
        assert!(
            !entitled_after_denial,
            "{label}: entitled after an unpersisted denial"
        );
        if let Ok(validation) = during_outage {
            assert!(!validation.valid, "{label}: outage revived the grant");
        }
        assert!(
            !entitled_during_outage,
            "{label}: entitled during the outage"
        );
    }
}

/// A denial delivered by a heartbeat is the same server decision as one from
/// validate: it must be recorded so no later outage or relaunch revives the grant.
#[cfg(feature = "offline")]
#[tokio::test]
async fn heartbeat_authoritative_denials_are_recorded_like_validation_denials() {
    for (status, code) in AUTHORITATIVE_DENIALS {
        let label = format!("heartbeat {status} {code}");
        let server = MockServer::start().await;
        let (sdk, config) =
            sdk_with_valid_offline_grant(&server, OfflineFallbackMode::Always).await;
        Mock::given(method("POST"))
            .and(path_regex(r"/products/.*/licenses/heartbeat"))
            .respond_with(
                ResponseTemplate::new(status).set_body_json(api_error_response(code, "denied")),
            )
            .mount(&server)
            .await;

        match sdk.heartbeat().await {
            Err(error) => assert_eq!(
                error.code().map(str::to_ascii_lowercase).as_deref(),
                Some(code),
                "{label}"
            ),
            Ok(response) => panic!("{label}: heartbeat succeeded with {response:?}"),
        }
        assert_denial_is_the_current_decision(&server, &sdk, &config, &label).await;
    }
}

#[cfg(feature = "offline")]
#[tokio::test]
async fn valid_false_authoritative_denials_keep_the_grant_but_never_revive_it() {
    for (_, code) in AUTHORITATIVE_DENIALS {
        let label = format!("200 valid:false {code}");
        let server = MockServer::start().await;
        let (sdk, config) =
            sdk_with_valid_offline_grant(&server, OfflineFallbackMode::Always).await;
        let mut denied = license_json(
            "DENIAL-LICENSE",
            "active",
            "pro",
            "hardware_locked",
            &[],
            "Test Product",
        );
        denied["active_seats"] = json!(1);
        Mock::given(method("POST"))
            .and(path_regex(r"/products/.*/licenses/validate"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "object": "validation_result",
                "valid": false,
                "code": code,
                "message": "denied",
                "warnings": null,
                "license": denied,
                "activation": null
            })))
            .mount(&server)
            .await;

        let validation = sdk.validate().await.expect(&label);
        assert!(!validation.valid, "{label}");
        assert_denial_is_the_current_decision(&server, &sdk, &config, &label).await;
    }
}

#[cfg(feature = "offline")]
#[tokio::test]
async fn codeless_server_failures_still_fall_back_to_the_offline_grant() {
    for (status, mode) in [
        (503, OfflineFallbackMode::NetworkOnly),
        (501, OfflineFallbackMode::NetworkOnly),
        (429, OfflineFallbackMode::Always),
    ] {
        let label = format!("{mode:?} {status}");
        let server = MockServer::start().await;
        let (sdk, _config) = sdk_with_valid_offline_grant(&server, mode).await;
        Mock::given(method("POST"))
            .and(path_regex(r"/products/.*/licenses/validate"))
            .respond_with(ResponseTemplate::new(status))
            .mount(&server)
            .await;
        let validation = sdk.validate().await.expect(&label);
        assert!(
            validation.valid && validation.offline,
            "{label}: {validation:?}"
        );
        assert!(sdk.has_entitlement("pro-features"), "{label}");
    }
}

/// A network blip before the first machine-file sync landed used to revoke a
/// perfectly valid license.
///
/// `perform_offline_validation` ends in a fallback for "there is no artifact to
/// check", and `finalize_offline_validation` committed *any* invalid result
/// with `trusted_license = None` and `TrustedLicenseSource::FailClosedDenial`.
/// That contradicts `OfflineFallbackMode`'s own contract — "only specifically
/// recognized authoritative license denials clear the last trusted grant" —
/// because an absent artifact is not a denial, it is the absence of a verdict.
/// Downstream, a paid perpetual license read as revoked and the host app
/// dropped the user onto its paywall until the network came back.
#[cfg(feature = "offline")]
#[tokio::test]
async fn no_cached_artifact_does_not_revoke_an_established_grant() {
    let server = MockServer::start().await;
    let license_key = "PERPETUAL-KEY-0001";

    Mock::given(method("POST"))
        .and(path_regex(r"/products/.*/licenses/activate"))
        .respond_with(
            ResponseTemplate::new(201).set_body_json(activation_response_with_license(
                license_key,
                "device-123",
                license_json(
                    license_key,
                    "active",
                    "perpetual",
                    "hardware_locked",
                    &["unlimited_history"],
                    "Test App",
                ),
            )),
        )
        .mount(&server)
        .await;

    let sdk = LicenseSeat::try_new(test_config(&server.uri())).unwrap();
    sdk.activate(license_key).await.expect("activation");
    assert!(matches!(sdk.status(), LicenseStatus::Active { .. }));
    assert!(
        sdk.current_authoritative_validation()
            .expect("activation establishes an authoritative grant")
            .valid
    );

    // No machine file was ever checked out — this server never offered one,
    // which is the position an install is in when its post-activation sync
    // failed and the 72h refresh has not come round yet.
    assert!(
        sdk.current_machine_file().is_none(),
        "precondition: nothing cached to validate against"
    );

    // Make the service unavailable. NetworkOnly is documented to fall back to
    // offline validation for availability errors — transport failures,
    // timeouts, 408, and 5xx — which is the situation this test is about.
    Mock::given(method("POST"))
        .and(path_regex(r"/products/.*/licenses/validate"))
        .respond_with(ResponseTemplate::new(503))
        .mount(&server)
        .await;

    let error = sdk
        .validate()
        .await
        .expect_err("offline validation cannot reach a verdict with no artifact");
    assert!(
        matches!(error, licenseseat::Error::NoOfflineArtifact),
        "expected an inconclusive outcome, got {error:?}"
    );

    // The point of the test: the grant established online is still standing.
    assert!(
        matches!(sdk.status(), LicenseStatus::Active { .. }),
        "an absent artifact must not revoke an established grant, got {:?}",
        sdk.status()
    );
    assert!(
        sdk.current_authoritative_validation()
            .expect("authoritative grant must survive an inconclusive offline check")
            .valid
    );
    assert!(sdk.has_entitlement("unlimited_history"));
}
