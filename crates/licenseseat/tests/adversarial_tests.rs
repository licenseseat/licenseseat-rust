//! Adversarial protocol and state-machine tests.
//!
//! These cases deliberately return valid JSON with the wrong identity, or let
//! older requests complete after newer state mutations. The SDK must reject the
//! response before it can grant access or overwrite the newer state.

mod common;

use common::activation_responder;
use licenseseat::{Config, Error, EventKind, LicenseSeat, LicenseStatus};
#[cfg(feature = "offline")]
use licenseseat::{OfflineTokenPayload, OfflineTokenResponse, OfflineTokenSignature};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::time::Duration;
use tempfile::TempDir;
use wiremock::matchers::{method, path, path_regex};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn test_config(server: &MockServer, storage: &TempDir) -> Config {
    Config {
        api_key: "pk_test_adversarial".into(),
        product_slug: "test-product".into(),
        api_base_url: server.uri(),
        storage_path: Some(storage.path().into()),
        device_identifier: Some("device-123".into()),
        auto_validate_interval: Duration::ZERO,
        heartbeat_interval: Duration::ZERO,
        max_retries: 0,
        retry_delay: Duration::ZERO,
        ..Default::default()
    }
}

fn cache_path(storage: &TempDir, prefix: &str, key: &str) -> std::path::PathBuf {
    let namespace = Sha256::digest(prefix.as_bytes());
    let namespace = namespace
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    storage.path().join(format!("v2_{namespace}__{key}.json"))
}

fn license_json(license_key: &str, product_slug: &str) -> Value {
    json!({
        "object": "license",
        "key": license_key,
        "status": "active",
        "starts_at": null,
        "expires_at": null,
        "mode": "hardware_locked",
        "plan_key": "pro",
        "seat_limit": 1,
        "active_seats": 1,
        "active_entitlements": [],
        "metadata": null,
        "product": { "slug": product_slug, "name": "Test App" }
    })
}

fn validation_json(license_key: &str, product_slug: &str) -> Value {
    json!({
        "object": "validation_result",
        "valid": true,
        "code": null,
        "message": null,
        "warnings": null,
        "license": license_json(license_key, product_slug),
        "activation": null
    })
}

fn heartbeat_json(license_key: &str, product_slug: &str) -> Value {
    json!({
        "object": "heartbeat",
        "received_at": "2026-07-14T12:00:00Z",
        "license": license_json(license_key, product_slug)
    })
}

async fn mount_activation(server: &MockServer) {
    Mock::given(method("POST"))
        .and(path_regex(r"/products/.*/licenses/activate"))
        .respond_with(activation_responder())
        .mount(server)
        .await;
}

async fn event_kinds_through(
    receiver: &mut tokio::sync::broadcast::Receiver<licenseseat::Event>,
    terminal: EventKind,
) -> Vec<EventKind> {
    let mut kinds = Vec::new();
    loop {
        let event = tokio::time::timeout(Duration::from_secs(1), receiver.recv())
            .await
            .expect("timed out waiting for terminal SDK event")
            .expect("SDK event channel closed unexpectedly");
        kinds.push(event.kind);
        if event.kind == terminal {
            return kinds;
        }
    }
}

#[tokio::test]
async fn substituted_activation_response_never_creates_local_state() {
    let server = MockServer::start().await;
    let storage = tempfile::tempdir().unwrap();
    let mut response = json!({
        "object": "activation",
        "id": "attacker-activation",
        "device_id": "device-123",
        "license_key": "OTHER-LICENSE",
        "activated_at": "2026-07-14T12:00:00Z",
        "deactivated_at": null,
        "license": license_json("OTHER-LICENSE", "test-product")
    });
    response["license"]["active_entitlements"] = json!([{"key": "paid-feature"}]);
    Mock::given(method("POST"))
        .and(path_regex(r"/activate$"))
        .respond_with(ResponseTemplate::new(201).set_body_json(response))
        .mount(&server)
        .await;

    let sdk = LicenseSeat::try_new(test_config(&server, &storage)).unwrap();
    let mut events = sdk.subscribe();
    assert!(matches!(
        sdk.activate("EXPECTED-LICENSE").await,
        Err(Error::ResponseMismatch(_))
    ));
    let kinds = event_kinds_through(&mut events, EventKind::ActivationError).await;
    assert!(kinds.contains(&EventKind::ActivationStart));
    assert!(!kinds.contains(&EventKind::ActivationSuccess));
    assert!(sdk.current_license().is_none());
    assert!(!sdk.has_entitlement("paid-feature"));
    assert!(matches!(sdk.status(), LicenseStatus::Inactive { .. }));
}

#[tokio::test]
async fn substituted_validation_and_heartbeat_preserve_the_last_trusted_grant() {
    let server = MockServer::start().await;
    let storage = tempfile::tempdir().unwrap();
    mount_activation(&server).await;
    Mock::given(method("POST"))
        .and(path_regex(r"/validate$"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(validation_json("ACTIVE-LICENSE", "other-product")),
        )
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path_regex(r"/heartbeat$"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(heartbeat_json("OTHER-LICENSE", "test-product")),
        )
        .mount(&server)
        .await;

    let sdk = LicenseSeat::try_new(test_config(&server, &storage)).unwrap();
    sdk.activate("ACTIVE-LICENSE").await.unwrap();
    let original = sdk.current_license().unwrap();

    let mut validation_events = sdk.subscribe();
    assert!(matches!(
        sdk.validate().await,
        Err(Error::ResponseMismatch(_))
    ));
    let kinds = event_kinds_through(&mut validation_events, EventKind::ValidationError).await;
    assert!(kinds.contains(&EventKind::ValidationStart));
    assert!(!kinds.contains(&EventKind::ValidationSuccess));
    assert_eq!(sdk.current_license(), Some(original.clone()));
    assert!(sdk.is_license_state_trusted());
    assert!(matches!(sdk.status(), LicenseStatus::Active { .. }));

    let mut heartbeat_events = sdk.subscribe();
    assert!(matches!(
        sdk.heartbeat().await,
        Err(Error::ResponseMismatch(_))
    ));
    let kinds = event_kinds_through(&mut heartbeat_events, EventKind::HeartbeatError).await;
    assert!(!kinds.contains(&EventKind::HeartbeatSuccess));
    assert_eq!(sdk.current_license(), Some(original));
    assert!(matches!(sdk.status(), LicenseStatus::Active { .. }));
}

#[tokio::test]
async fn duplicate_online_entitlements_are_rejected_before_state_commit() {
    let server = MockServer::start().await;
    let storage = tempfile::tempdir().unwrap();
    mount_activation(&server).await;
    let mut malformed = validation_json("ACTIVE-LICENSE", "test-product");
    malformed["license"]["active_entitlements"] = json!([
        { "key": "paid-feature", "expires_at": null, "metadata": null },
        { "key": "paid-feature", "expires_at": null, "metadata": null }
    ]);
    Mock::given(method("POST"))
        .and(path_regex(r"/validate$"))
        .respond_with(ResponseTemplate::new(200).set_body_json(malformed))
        .mount(&server)
        .await;

    let sdk = LicenseSeat::try_new(test_config(&server, &storage)).unwrap();
    sdk.activate("ACTIVE-LICENSE").await.unwrap();
    let original = sdk.current_license().unwrap();

    assert!(matches!(
        sdk.validate().await,
        Err(Error::InvalidResponse(_))
    ));
    assert_eq!(sdk.current_license(), Some(original));
    assert!(matches!(sdk.status(), LicenseStatus::Active { .. }));
}

#[tokio::test]
async fn denial_code_on_rate_limit_response_cannot_erase_a_trusted_grant() {
    let server = MockServer::start().await;
    let storage = tempfile::tempdir().unwrap();
    mount_activation(&server).await;
    Mock::given(method("POST"))
        .and(path_regex(r"/validate$"))
        .respond_with(ResponseTemplate::new(429).set_body_json(json!({
            "error": {
                "code": "license_revoked",
                "message": "misclassified upstream response"
            }
        })))
        .mount(&server)
        .await;

    let sdk = LicenseSeat::try_new(test_config(&server, &storage)).unwrap();
    sdk.activate("ACTIVE-LICENSE").await.unwrap();
    let original = sdk.current_license().unwrap();
    let mut events = sdk.subscribe();

    assert!(matches!(
        sdk.validate().await,
        Err(Error::Api { status: 429, .. })
    ));
    let kinds = event_kinds_through(&mut events, EventKind::ValidationError).await;
    assert!(!kinds.contains(&EventKind::LicenseRevoked));
    assert_eq!(sdk.current_license(), Some(original));
    assert!(sdk.is_license_state_trusted());
    assert!(matches!(sdk.status(), LicenseStatus::Active { .. }));
}

#[tokio::test]
async fn uncoded_gone_response_cannot_erase_a_trusted_grant() {
    let server = MockServer::start().await;
    let storage = tempfile::tempdir().unwrap();
    mount_activation(&server).await;
    Mock::given(method("POST"))
        .and(path_regex(r"/validate$"))
        .respond_with(ResponseTemplate::new(410).set_body_string("route retired"))
        .mount(&server)
        .await;

    let sdk = LicenseSeat::try_new(test_config(&server, &storage)).unwrap();
    sdk.activate("ACTIVE-LICENSE").await.unwrap();
    let original = sdk.current_license().unwrap();

    assert!(matches!(
        sdk.validate().await,
        Err(Error::Api {
            status: 410,
            code: None,
            ..
        })
    ));
    assert_eq!(sdk.current_license(), Some(original));
    assert!(sdk.is_license_state_trusted());
    assert!(matches!(sdk.status(), LicenseStatus::Active { .. }));
}

#[tokio::test]
async fn offline_asset_cleanup_failure_is_reported_but_online_denial_stays_authoritative() {
    let server = MockServer::start().await;
    let storage = tempfile::tempdir().unwrap();
    mount_activation(&server).await;
    let mut invalid = validation_json("ACTIVE-LICENSE", "test-product");
    invalid["valid"] = json!(false);
    invalid["code"] = json!("license_suspended");
    invalid["message"] = json!("Suspended");
    invalid["license"]["status"] = json!("suspended");
    Mock::given(method("POST"))
        .and(path_regex(r"/validate$"))
        .respond_with(ResponseTemplate::new(200).set_body_json(invalid))
        .mount(&server)
        .await;

    let sdk = LicenseSeat::try_new(test_config(&server, &storage)).unwrap();
    sdk.activate("ACTIVE-LICENSE").await.unwrap();
    let snapshot_path = cache_path(&storage, &sdk.config().storage_prefix, "license_snapshot");
    assert!(!snapshot_path.exists());
    std::fs::create_dir(&snapshot_path).unwrap();

    let mut events = sdk.subscribe();
    let validation = sdk.validate().await.unwrap();
    assert!(!validation.valid);
    let kinds = event_kinds_through(&mut events, EventKind::ValidationFailed).await;
    assert!(kinds.contains(&EventKind::SdkError));
    assert!(sdk.is_license_state_trusted());
    assert!(matches!(sdk.status(), LicenseStatus::Invalid { .. }));
    assert!(!sdk.has_entitlement("paid-feature"));
}

#[tokio::test]
async fn failed_reset_cleanup_revokes_runtime_trust_before_returning() {
    let server = MockServer::start().await;
    let storage = tempfile::tempdir().unwrap();
    mount_activation(&server).await;
    let sdk = LicenseSeat::try_new(test_config(&server, &storage)).unwrap();
    sdk.activate("ACTIVE-LICENSE").await.unwrap();
    let snapshot_path = cache_path(&storage, &sdk.config().storage_prefix, "license_snapshot");
    assert!(!snapshot_path.exists());
    std::fs::create_dir(&snapshot_path).unwrap();

    assert!(matches!(sdk.try_reset(), Err(Error::Cache(_))));
    assert!(!sdk.is_license_state_trusted());
    assert!(!sdk.has_entitlement("paid-feature"));
    let retained_denial = sdk
        .current_license()
        .expect("a failed cleanup must retain its fail-closed tombstone");
    assert!(retained_denial.trusted_license.is_none());
    assert!(
        retained_denial
            .validation
            .as_ref()
            .is_some_and(|validation| !validation.valid)
    );
    assert!(matches!(sdk.status(), LicenseStatus::Pending { .. }));
}

#[tokio::test]
async fn restore_result_reports_the_state_that_was_actually_committed() {
    let server = MockServer::start().await;
    let storage = tempfile::tempdir().unwrap();
    mount_activation(&server).await;
    Mock::given(method("GET"))
        .and(path("/health"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "object": "health",
            "status": "healthy",
            "api_version": "v1",
            "timestamp": "2026-07-14T12:00:00Z"
        })))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path_regex(r"/validate$"))
        .respond_with(ResponseTemplate::new(401).set_body_json(json!({
            "error": {
                "code": "invalid_api_key",
                "message": "Unauthorized"
            }
        })))
        .mount(&server)
        .await;

    let config = test_config(&server, &storage);
    let activated = LicenseSeat::try_new(config.clone()).unwrap();
    activated.activate("ACTIVE-LICENSE").await.unwrap();
    drop(activated);

    let restored = LicenseSeat::try_new(config).unwrap();
    assert!(matches!(restored.status(), LicenseStatus::Pending { .. }));
    let result = restored.restore_license().await;

    assert!(!result.restored);
    assert!(result.error.is_some());
    assert!(matches!(result.status, LicenseStatus::Pending { .. }));
    assert!(result.validation.is_none());
    assert!(matches!(restored.status(), LicenseStatus::Pending { .. }));
    assert!(!restored.is_license_state_trusted());
}

#[tokio::test]
async fn substituted_deactivation_response_does_not_release_local_state() {
    let server = MockServer::start().await;
    let storage = tempfile::tempdir().unwrap();
    mount_activation(&server).await;
    Mock::given(method("POST"))
        .and(path_regex(r"/deactivate$"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "object": "deactivation",
            "activation_id": "another-installation",
            "deactivated_at": "2026-07-14T12:00:00Z"
        })))
        .mount(&server)
        .await;

    let sdk = LicenseSeat::try_new(test_config(&server, &storage)).unwrap();
    sdk.activate("ACTIVE-LICENSE").await.unwrap();
    let mut events = sdk.subscribe();
    assert!(matches!(
        sdk.deactivate().await,
        Err(Error::ResponseMismatch(_))
    ));
    let kinds = event_kinds_through(&mut events, EventKind::DeactivationError).await;
    assert!(kinds.contains(&EventKind::DeactivationStart));
    assert!(!kinds.contains(&EventKind::DeactivationSuccess));
    assert!(sdk.current_license().is_some());
    assert!(matches!(sdk.status(), LicenseStatus::Active { .. }));
}

#[cfg(feature = "offline")]
#[tokio::test]
async fn substituted_offline_artifacts_emit_terminal_fetch_errors() {
    let server = MockServer::start().await;
    let storage = tempfile::tempdir().unwrap();
    let now = chrono::Utc::now();
    let payload = OfflineTokenPayload {
        schema_version: 1,
        license_key: "OTHER-LICENSE".into(),
        product_slug: "test-product".into(),
        plan_key: "pro".into(),
        mode: "hardware_locked".into(),
        seat_limit: Some(1),
        device_id: Some("device-123".into()),
        iat: now.timestamp(),
        exp: (now + chrono::Duration::days(30)).timestamp(),
        nbf: now.timestamp(),
        license_expires_at: None,
        kid: "key-2026".into(),
        entitlements: Vec::new(),
        metadata: None,
    };
    let canonical = serde_json::to_string(&serde_json::to_value(&payload).unwrap()).unwrap();
    let token = OfflineTokenResponse {
        object: "offline_token".into(),
        canonical,
        token: payload,
        signature: OfflineTokenSignature {
            algorithm: "Ed25519".into(),
            key_id: "key-2026".into(),
            value: "not-used-after-binding-rejection".into(),
        },
    };

    Mock::given(method("POST"))
        .and(path_regex(r"/offline-token$"))
        .respond_with(ResponseTemplate::new(200).set_body_json(token))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path_regex(r"/machine-file$"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": {
                "type": "machine-files",
                "attributes": {
                    "certificate": "not-used-after-binding-rejection",
                    "algorithm": "aes-256-gcm+ed25519",
                    "ttl": 2_592_000,
                    "issued": now.to_rfc3339(),
                    "expiry": (now + chrono::Duration::days(30)).to_rfc3339()
                },
                "relationships": {
                    "license": { "data": { "type": "licenses", "id": "OTHER-LICENSE" } },
                    "machine": { "data": { "type": "machines", "id": "device-123" } }
                }
            }
        })))
        .mount(&server)
        .await;

    let sdk = LicenseSeat::try_new(test_config(&server, &storage)).unwrap();

    let mut token_events = sdk.subscribe();
    let token_result = sdk
        .generate_offline_token("EXPECTED-LICENSE", Some("device-123"), Some(30))
        .await;
    assert!(
        matches!(token_result, Err(Error::ResponseMismatch(_))),
        "unexpected offline-token result: {token_result:?}"
    );
    let kinds = event_kinds_through(&mut token_events, EventKind::OfflineTokenFetchError).await;
    assert!(kinds.contains(&EventKind::OfflineTokenFetching));
    assert!(!kinds.contains(&EventKind::OfflineTokenFetched));

    let mut machine_file_events = sdk.subscribe();
    assert!(matches!(
        sdk.checkout_machine_file("EXPECTED-LICENSE", Some("device-123"), Some(30))
            .await,
        Err(Error::ResponseMismatch(_))
    ));
    let kinds =
        event_kinds_through(&mut machine_file_events, EventKind::MachineFileFetchError).await;
    assert!(kinds.contains(&EventKind::MachineFileFetching));
    assert!(!kinds.contains(&EventKind::MachineFileFetched));
}

#[tokio::test]
async fn uncoded_not_found_during_deactivation_is_not_treated_as_success() {
    let server = MockServer::start().await;
    let storage = tempfile::tempdir().unwrap();
    mount_activation(&server).await;
    Mock::given(method("POST"))
        .and(path_regex(r"/deactivate$"))
        .respond_with(ResponseTemplate::new(404).set_body_json(json!({
            "error": { "message": "proxy generated not found" }
        })))
        .mount(&server)
        .await;

    let sdk = LicenseSeat::try_new(test_config(&server, &storage)).unwrap();
    sdk.activate("ACTIVE-LICENSE").await.unwrap();
    assert!(matches!(
        sdk.deactivate().await,
        Err(Error::Api {
            status: 404,
            code: None,
            ..
        })
    ));
    assert!(sdk.current_license().is_some());
    assert!(matches!(sdk.status(), LicenseStatus::Active { .. }));
}

#[tokio::test]
async fn malformed_health_release_and_download_metadata_fail_closed() {
    let server = MockServer::start().await;
    let storage = tempfile::tempdir().unwrap();
    Mock::given(method("GET"))
        .and(path("/health"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "object": "health",
            "status": "degraded",
            "api_version": "v1",
            "timestamp": "2026-07-14T12:00:00Z"
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/products/test-product/releases/latest"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "object": "release",
            "version": "9.9.9",
            "channel": "nightly",
            "platform": "windows",
            "product_slug": "other-product"
        })))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/products/test-product/releases/1.0.0/download_token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "object": "download_token",
            "token": "expired-token",
            "expires_at": "2020-01-01T00:00:00Z"
        })))
        .mount(&server)
        .await;

    let sdk = LicenseSeat::try_new(test_config(&server, &storage)).unwrap();
    assert!(matches!(
        sdk.health_check().await,
        Err(Error::InvalidResponse(_))
    ));
    assert!(sdk.last_health_response().is_none());
    assert!(sdk.last_health_error().is_some());
    assert!(matches!(
        sdk.get_latest_release(None, Some("stable"), Some("macos"))
            .await,
        Err(Error::ResponseMismatch(_))
    ));
    assert!(matches!(
        sdk.generate_download_token("1.0.0", "LICENSE", None, Some("macos"))
            .await,
        Err(Error::InvalidResponse(_))
    ));
}

#[tokio::test]
async fn release_list_rejects_one_substituted_item() {
    let server = MockServer::start().await;
    let storage = tempfile::tempdir().unwrap();
    Mock::given(method("GET"))
        .and(path("/products/test-product/releases"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "object": "list",
            "data": [{
                "object": "release",
                "version": "1.0.0",
                "channel": "stable",
                "platform": "macos",
                "product_slug": "other-product"
            }],
            "has_more": false
        })))
        .mount(&server)
        .await;

    let sdk = LicenseSeat::try_new(test_config(&server, &storage)).unwrap();
    assert!(matches!(
        sdk.list_releases(None, Some("stable"), Some("macos")).await,
        Err(Error::ResponseMismatch(_))
    ));
}

#[tokio::test]
async fn release_list_requires_a_nonempty_cursor_when_more_pages_exist() {
    for next_cursor in [None, Some("")] {
        let server = MockServer::start().await;
        let storage = tempfile::tempdir().unwrap();
        let mut response = json!({
            "object": "list",
            "data": [{
                "object": "release",
                "version": "1.0.0",
                "channel": "stable",
                "platform": "macos",
                "product_slug": "test-product"
            }],
            "has_more": true
        });
        if let Some(next_cursor) = next_cursor {
            response["next_cursor"] = json!(next_cursor);
        }
        Mock::given(method("GET"))
            .and(path("/products/test-product/releases"))
            .respond_with(ResponseTemplate::new(200).set_body_json(response))
            .mount(&server)
            .await;

        let sdk = LicenseSeat::try_new(test_config(&server, &storage)).unwrap();
        assert!(matches!(
            sdk.list_releases(None, Some("stable"), Some("macos")).await,
            Err(Error::ResponseMismatch(_))
        ));
    }
}

#[tokio::test]
async fn delayed_validation_cannot_overwrite_a_new_activation() {
    let server = MockServer::start().await;
    let storage = tempfile::tempdir().unwrap();
    mount_activation(&server).await;
    Mock::given(method("POST"))
        .and(path_regex(r"/validate$"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_delay(Duration::from_millis(200))
                .set_body_json(validation_json("FIRST-LICENSE", "test-product")),
        )
        .mount(&server)
        .await;

    let sdk = LicenseSeat::try_new(test_config(&server, &storage)).unwrap();
    sdk.activate("FIRST-LICENSE").await.unwrap();
    let mut events = sdk.subscribe();
    let validating = {
        let sdk = sdk.clone();
        tokio::spawn(async move { sdk.validate().await })
    };
    tokio::time::sleep(Duration::from_millis(30)).await;
    sdk.activate("SECOND-LICENSE").await.unwrap();

    assert!(matches!(
        validating.await.unwrap(),
        Err(Error::OperationSuperseded {
            operation: "validation"
        })
    ));
    let kinds = event_kinds_through(&mut events, EventKind::ValidationError).await;
    assert!(kinds.contains(&EventKind::ValidationStart));
    assert!(!kinds.contains(&EventKind::ValidationSuccess));
    let current = sdk.current_license().unwrap();
    assert_eq!(current.license_key, "SECOND-LICENSE");
    assert_eq!(current.validation.unwrap().license.key, "SECOND-LICENSE");
    assert!(matches!(sdk.status(), LicenseStatus::Active { .. }));
}

#[tokio::test]
async fn delayed_heartbeat_emits_a_terminal_error_when_reset_supersedes_it() {
    let server = MockServer::start().await;
    let storage = tempfile::tempdir().unwrap();
    mount_activation(&server).await;
    Mock::given(method("POST"))
        .and(path_regex(r"/heartbeat$"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_delay(Duration::from_millis(200))
                .set_body_json(heartbeat_json("ACTIVE-LICENSE", "test-product")),
        )
        .mount(&server)
        .await;

    let sdk = LicenseSeat::try_new(test_config(&server, &storage)).unwrap();
    sdk.activate("ACTIVE-LICENSE").await.unwrap();
    let mut events = sdk.subscribe();
    let heartbeat = {
        let sdk = sdk.clone();
        tokio::spawn(async move { sdk.heartbeat().await })
    };
    tokio::time::sleep(Duration::from_millis(30)).await;
    sdk.try_reset().unwrap();

    assert!(matches!(
        heartbeat.await.unwrap(),
        Err(Error::OperationSuperseded {
            operation: "heartbeat"
        })
    ));
    let kinds = event_kinds_through(&mut events, EventKind::HeartbeatError).await;
    assert!(!kinds.contains(&EventKind::HeartbeatSuccess));
    assert!(sdk.current_license().is_none());
}

#[tokio::test]
async fn delayed_deactivation_cannot_delete_a_replacement_from_another_sdk_instance() {
    let server = MockServer::start().await;
    let storage = tempfile::tempdir().unwrap();
    mount_activation(&server).await;
    Mock::given(method("POST"))
        .and(path("/products/test-product/licenses/deactivate"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_delay(Duration::from_millis(200))
                .set_body_json(json!({
                    "object": "deactivation",
                    "activation_id": "act-12345-uuid",
                    "deactivated_at": "2026-07-14T12:00:00Z"
                })),
        )
        .mount(&server)
        .await;

    let config = test_config(&server, &storage);
    let first = LicenseSeat::try_new(config.clone()).unwrap();
    first.activate("FIRST-LICENSE").await.unwrap();
    let deactivating = {
        let first = first.clone();
        tokio::spawn(async move { first.deactivate().await })
    };
    tokio::time::sleep(Duration::from_millis(30)).await;

    let replacement = LicenseSeat::try_new(config).unwrap();
    replacement.activate("SECOND-LICENSE").await.unwrap();
    deactivating.await.unwrap().unwrap();

    assert_eq!(
        replacement
            .current_license()
            .as_ref()
            .map(|license| license.license_key.as_str()),
        Some("SECOND-LICENSE")
    );
    assert!(replacement.is_license_state_trusted());
    assert!(matches!(replacement.status(), LicenseStatus::Active { .. }));
}

#[tokio::test]
async fn reset_invalidates_an_in_flight_validation_commit() {
    let server = MockServer::start().await;
    let storage = tempfile::tempdir().unwrap();
    mount_activation(&server).await;
    Mock::given(method("POST"))
        .and(path_regex(r"/validate$"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_delay(Duration::from_millis(200))
                .set_body_json(validation_json("ACTIVE-LICENSE", "test-product")),
        )
        .mount(&server)
        .await;

    let sdk = LicenseSeat::try_new(test_config(&server, &storage)).unwrap();
    sdk.activate("ACTIVE-LICENSE").await.unwrap();
    let validating = {
        let sdk = sdk.clone();
        tokio::spawn(async move { sdk.validate().await })
    };
    tokio::time::sleep(Duration::from_millis(30)).await;
    sdk.reset();

    assert!(matches!(
        validating.await.unwrap(),
        Err(Error::OperationSuperseded {
            operation: "validation"
        })
    ));
    assert!(sdk.current_license().is_none());
    assert!(matches!(sdk.status(), LicenseStatus::Inactive { .. }));
}
