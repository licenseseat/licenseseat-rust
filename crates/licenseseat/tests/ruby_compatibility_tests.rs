//! Cross-language compatibility tests using deterministic artifacts generated
//! with the LicenseSeat Ruby core's canonical JSON and machine-file contract.

#![cfg(feature = "offline")]

mod common;

use base64::Engine;
use chrono::Utc;
use common::{activation_responder, invalid_validation_responder};
use licenseseat::{
    Config, EventKind, LicenseSeat, LicenseStatus, MachineFile, OfflineFallbackMode,
    OfflineTokenResponse,
};
use serde_json::Value;
use std::time::Duration;
use wiremock::matchers::{method, path, path_regex};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn fixture() -> Value {
    serde_json::from_str(include_str!("fixtures/ruby_compat.json")).unwrap()
}

fn config(server: &MockServer, storage: &tempfile::TempDir, fixture: &Value) -> Config {
    Config {
        api_key: "pk_test_ruby_compatibility".into(),
        product_slug: fixture["product_slug"].as_str().unwrap().into(),
        api_base_url: server.uri(),
        storage_path: Some(storage.path().into()),
        device_identifier: Some(fixture["fingerprint"].as_str().unwrap().into()),
        signing_public_key: Some(fixture["public_key"].as_str().unwrap().into()),
        signing_key_id: Some(fixture["key_id"].as_str().unwrap().into()),
        auto_validate_interval: Duration::ZERO,
        heartbeat_interval: Duration::ZERO,
        max_retries: 0,
        ..Default::default()
    }
}

fn machine_file_api_response(fixture: &Value) -> Value {
    serde_json::json!({
        "data": {
            "type": "machine-files",
            "id": "ruby-fixture-machine-file",
            "attributes": {
                "certificate": fixture["machine_file"]["certificate"],
                "algorithm": fixture["machine_file"]["algorithm"],
                "ttl": fixture["machine_file"]["ttl"],
                "issued": fixture["machine_file"]["issued_at"],
                "expiry": fixture["machine_file"]["expires_at"]
            },
            "relationships": {
                "license": {
                    "data": {
                        "type": "licenses",
                        "id": fixture["license_key"]
                    }
                },
                "machine": {
                    "data": {
                        "type": "machines",
                        "id": fixture["fingerprint"]
                    }
                }
            }
        }
    })
}

async fn activated_sdk(
    server: &MockServer,
    storage: &tempfile::TempDir,
    fixture: &Value,
) -> LicenseSeat {
    Mock::given(method("POST"))
        .and(path_regex(r"/activate$"))
        .respond_with(activation_responder())
        .mount(server)
        .await;
    let sdk = LicenseSeat::try_new(config(server, storage, fixture)).unwrap();
    sdk.activate(fixture["license_key"].as_str().unwrap())
        .await
        .unwrap();
    sdk
}

async fn sdk_with_cached_machine_file(
    server: &MockServer,
    storage: &tempfile::TempDir,
    fixture: &Value,
    storage_prefix: &str,
) -> (LicenseSeat, Config) {
    Mock::given(method("POST"))
        .and(path_regex(r"/machine-file$"))
        .respond_with(ResponseTemplate::new(201).set_body_json(machine_file_api_response(fixture)))
        .expect(1)
        .mount(server)
        .await;
    Mock::given(method("POST"))
        .and(path_regex(r"/activate$"))
        .respond_with(activation_responder())
        .expect(1)
        .mount(server)
        .await;

    let mut sdk_config = config(server, storage, fixture);
    sdk_config.storage_prefix = storage_prefix.into();
    sdk_config.offline_token_refresh_interval = Duration::ZERO;
    let sdk = LicenseSeat::try_new(sdk_config.clone()).unwrap();
    sdk.activate(fixture["license_key"].as_str().unwrap())
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(2), async {
        while sdk.current_machine_file().is_none() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("activation should acquire and cache an offline machine file");

    (sdk, sdk_config)
}

#[tokio::test]
async fn ruby_issued_offline_token_and_machine_file_verify_in_rust() {
    let fixture = fixture();
    let server = MockServer::start().await;
    let storage = tempfile::tempdir().unwrap();
    let sdk = activated_sdk(&server, &storage, &fixture).await;
    let token: OfflineTokenResponse =
        serde_json::from_value(fixture["offline_token"].clone()).unwrap();
    let machine_file: MachineFile =
        serde_json::from_value(fixture["machine_file"].clone()).unwrap();

    assert_eq!(
        serde_json::to_string(&serde_json::to_value(&token.token).unwrap()).unwrap(),
        token.canonical
    );
    let mut token_events = sdk.subscribe();
    assert!(sdk.verify_offline_token(&token, None).unwrap());
    assert_eq!(
        token_events.recv().await.unwrap().kind,
        EventKind::OfflineTokenVerified
    );

    let mut machine_file_events = sdk.subscribe();
    let verification = sdk
        .verify_machine_file(&machine_file, None, None, None)
        .unwrap();
    assert!(verification.valid, "{verification:?}");
    assert_eq!(
        machine_file_events.recv().await.unwrap().kind,
        EventKind::MachineFileVerified
    );
    let payload = verification.payload.unwrap();
    assert_eq!(payload.schema_version, 2);
    assert_eq!(payload.key_id, fixture["key_id"].as_str().unwrap());
    assert_eq!(
        payload.product_slug,
        fixture["product_slug"].as_str().unwrap()
    );
    assert_eq!(
        payload.fingerprint,
        fixture["fingerprint"].as_str().unwrap()
    );
    assert_eq!(
        payload.machine_id,
        fixture["activation_id"].as_str().unwrap()
    );
    assert_eq!(payload.platform, "macos");
    assert!(payload.has_entitlement("pro-feature"));
    assert!(payload.has_entitlement("perpetual-feature"));
}

#[tokio::test]
async fn ruby_token_rejects_noncanonical_and_claim_tampering() {
    let fixture = fixture();
    let server = MockServer::start().await;
    let storage = tempfile::tempdir().unwrap();
    let sdk = activated_sdk(&server, &storage, &fixture).await;
    let token: OfflineTokenResponse =
        serde_json::from_value(fixture["offline_token"].clone()).unwrap();

    let mut noncanonical = token.clone();
    noncanonical.canonical = format!(" {}", noncanonical.canonical);
    let mut events = sdk.subscribe();
    assert!(sdk.verify_offline_token(&noncanonical, None).is_err());
    assert_eq!(
        events.recv().await.unwrap().kind,
        EventKind::OfflineTokenVerificationFailed
    );

    let mut changed_claim = token;
    changed_claim.token.product_slug = "attacker-product".into();
    assert!(sdk.verify_offline_token(&changed_claim, None).is_err());
}

#[tokio::test]
async fn ruby_machine_file_rejects_signature_fingerprint_and_product_substitution() {
    let fixture = fixture();
    let server = MockServer::start().await;
    let storage = tempfile::tempdir().unwrap();
    let sdk = activated_sdk(&server, &storage, &fixture).await;
    let machine_file: MachineFile =
        serde_json::from_value(fixture["machine_file"].clone()).unwrap();

    let wrong_fingerprint = sdk
        .inspect_machine_file(&machine_file, None, None, Some("another-installation"))
        .unwrap();
    assert!(!wrong_fingerprint.valid);

    let mut tampered = machine_file.clone();
    let lines = tampered.certificate.lines().collect::<Vec<_>>();
    let encoded = lines[1..lines.len() - 1].join("");
    let mut envelope: Value = serde_json::from_slice(
        &base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .unwrap(),
    )
    .unwrap();
    let signature = envelope["sig"].as_str().unwrap();
    envelope["sig"] = format!(
        "{}{}",
        if signature.starts_with('A') { "B" } else { "A" },
        &signature[1..]
    )
    .into();
    let encoded =
        base64::engine::general_purpose::STANDARD.encode(serde_json::to_vec(&envelope).unwrap());
    tampered.certificate = format!(
        "-----BEGIN MACHINE FILE-----\n{}\n-----END MACHINE FILE-----",
        encoded
    );
    let mut events = sdk.subscribe();
    let tampered_result = sdk
        .verify_machine_file(&tampered, None, None, None)
        .unwrap();
    assert!(!tampered_result.valid);
    assert_eq!(
        events.recv().await.unwrap().kind,
        EventKind::MachineFileVerificationFailed
    );

    let other_storage = tempfile::tempdir().unwrap();
    let mut other_config = config(&server, &other_storage, &fixture);
    other_config.product_slug = "another-product".into();
    let other_product = LicenseSeat::try_new(other_config).unwrap();
    let product_result = other_product
        .inspect_machine_file(
            &machine_file,
            None,
            Some(fixture["license_key"].as_str().unwrap()),
            Some(fixture["fingerprint"].as_str().unwrap()),
        )
        .unwrap();
    assert!(!product_result.valid);
}

#[tokio::test]
async fn fetched_signing_key_cache_is_not_a_cross_process_trust_anchor() {
    let fixture = fixture();
    let server = MockServer::start().await;
    let storage = tempfile::tempdir().unwrap();
    Mock::given(method("POST"))
        .and(path_regex(r"/activate$"))
        .respond_with(activation_responder())
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/signing_keys/ruby-fixture-key-v1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "object": "signing_key",
            "key_id": fixture["key_id"],
            "algorithm": "Ed25519",
            "public_key": fixture["public_key"],
            "created_at": "2025-01-01T00:00:00Z",
            "status": "active"
        })))
        .expect(1)
        .mount(&server)
        .await;
    let machine_file: MachineFile =
        serde_json::from_value(fixture["machine_file"].clone()).unwrap();

    let mut unpinned = config(&server, &storage, &fixture);
    unpinned.signing_public_key = None;
    unpinned.signing_key_id = None;
    let first_process = LicenseSeat::try_new(unpinned.clone()).unwrap();
    first_process
        .activate(fixture["license_key"].as_str().unwrap())
        .await
        .unwrap();
    first_process
        .fetch_signing_key(fixture["key_id"].as_str().unwrap())
        .await
        .unwrap();
    assert!(
        first_process
            .inspect_machine_file(&machine_file, None, None, None)
            .unwrap()
            .valid
    );
    assert!(
        first_process
            .cached_signing_key(fixture["key_id"].as_str().unwrap())
            .is_some()
    );
    drop(first_process);

    let second_process = LicenseSeat::try_new(unpinned).unwrap();
    assert!(
        second_process
            .cached_signing_key(fixture["key_id"].as_str().unwrap())
            .is_some(),
        "the response may remain as a diagnostic/online cache"
    );
    assert!(
        second_process
            .inspect_machine_file(&machine_file, None, None, None)
            .is_err(),
        "a mutable fetched-key file must not authorize offline startup"
    );

    let pinned_storage = tempfile::tempdir().unwrap();
    let pinned = LicenseSeat::try_new(config(&server, &pinned_storage, &fixture)).unwrap();
    assert!(
        pinned
            .inspect_machine_file(
                &machine_file,
                None,
                Some(fixture["license_key"].as_str().unwrap()),
                Some(fixture["fingerprint"].as_str().unwrap()),
            )
            .unwrap()
            .valid
    );
}

#[tokio::test]
async fn ruby_machine_file_restore_fails_closed_after_clock_rollback() {
    let fixture = fixture();
    let server = MockServer::start().await;
    let storage = tempfile::tempdir().unwrap();
    let (sdk, online_config) =
        sdk_with_cached_machine_file(&server, &storage, &fixture, "ruby_clock_rollback_").await;
    drop(sdk);

    let last_seen_path = storage.path().join("ruby_clock_rollback_last_seen_ts.json");
    let future_timestamp = Utc::now().timestamp() + 3_600;
    std::fs::write(
        &last_seen_path,
        serde_json::to_vec_pretty(&future_timestamp).unwrap(),
    )
    .unwrap();

    let mut offline_config = online_config;
    offline_config.api_base_url = "http://127.0.0.1:9".into();
    offline_config.request_timeout = Duration::from_millis(100);
    let restored_sdk = LicenseSeat::try_new(offline_config).unwrap();
    let restore = restored_sdk.restore_license().await;

    assert!(!restore.restored);
    assert!(matches!(
        restore.status,
        LicenseStatus::OfflineInvalid { .. }
    ));
    let validation = restore.validation.expect("offline validation result");
    assert!(!validation.valid);
    assert!(validation.offline);
    assert_eq!(validation.code.as_deref(), Some("clock_tamper"));
    assert!(!restored_sdk.has_entitlement("pro-feature"));
    assert!(restored_sdk.active_entitlements().is_empty());
}

#[tokio::test]
async fn offline_restore_cache_failure_emits_both_terminal_failure_events() {
    let fixture = fixture();
    let server = MockServer::start().await;
    let storage = tempfile::tempdir().unwrap();
    let prefix = "ruby_offline_cache_failure_";
    let (sdk, mut restored_config) =
        sdk_with_cached_machine_file(&server, &storage, &fixture, prefix).await;
    drop(sdk);

    restored_config.api_base_url = "http://127.0.0.1:9".into();
    restored_config.request_timeout = Duration::from_millis(100);
    let restored_sdk = LicenseSeat::try_new(restored_config).unwrap();
    let last_seen_path = storage.path().join(format!("{prefix}last_seen_ts.json"));
    std::fs::remove_file(&last_seen_path).unwrap();
    std::fs::create_dir(&last_seen_path).unwrap();
    let mut events = restored_sdk.subscribe();

    let restore = restored_sdk.restore_license().await;
    assert!(!restore.restored);
    assert!(
        restore
            .error
            .as_deref()
            .is_some_and(|error| error.contains("cache"))
    );

    let mut saw_core_failure = false;
    let mut saw_compatibility_failure = false;
    for _ in 0..16 {
        let event = tokio::time::timeout(Duration::from_secs(1), events.recv())
            .await
            .expect("terminal offline event")
            .unwrap();
        saw_core_failure |= event.kind == EventKind::OfflineValidationFailed;
        saw_compatibility_failure |= event.kind == EventKind::ValidationOfflineFailed;
        if saw_core_failure && saw_compatibility_failure {
            break;
        }
    }
    assert!(saw_core_failure);
    assert!(saw_compatibility_failure);
}

#[tokio::test]
async fn rate_limited_offline_restore_keeps_rechecking_authoritative_state() {
    let fixture = fixture();
    let server = MockServer::start().await;
    let storage = tempfile::tempdir().unwrap();
    let (sdk, mut restored_config) =
        sdk_with_cached_machine_file(&server, &storage, &fixture, "ruby_rate_limit_").await;
    drop(sdk);

    Mock::given(method("POST"))
        .and(path_regex(r"/validate$"))
        .respond_with(ResponseTemplate::new(429).set_body_json(serde_json::json!({
            "error": {
                "code": "rate_limited",
                "message": "Retry later"
            }
        })))
        .mount(&server)
        .await;

    restored_config.offline_fallback_mode = OfflineFallbackMode::Always;
    restored_config.network_recheck_interval = Duration::from_millis(20);
    let restored_sdk = LicenseSeat::try_new(restored_config).unwrap();
    let restore = restored_sdk.restore_license().await;
    assert!(restore.restored);
    assert!(matches!(restore.status, LicenseStatus::OfflineValid { .. }));
    assert!(
        restored_sdk.is_online(),
        "a 429 still proves API reachability"
    );

    tokio::time::sleep(Duration::from_millis(100)).await;
    let health_requests = server
        .received_requests()
        .await
        .unwrap()
        .into_iter()
        .filter(|request| request.method.as_str() == "GET" && request.url.path() == "/health")
        .count();
    restored_sdk.stop_background_tasks();
    assert!(
        health_requests >= 2,
        "offline state should recheck after rate limiting; saw {health_requests} health requests"
    );
}

#[tokio::test]
async fn validation_outage_after_reachable_health_uses_signed_offline_restore() {
    let fixture = fixture();
    let server = MockServer::start().await;
    let storage = tempfile::tempdir().unwrap();
    let (sdk, mut restored_config) =
        sdk_with_cached_machine_file(&server, &storage, &fixture, "ruby_validation_outage_").await;
    drop(sdk);

    // This deliberately reproduces the health-to-validation race: a health
    // probe would succeed, while the authoritative validation operation is
    // temporarily unavailable. Restore must classify the validation failure
    // itself and use the already-verified signed artifact.
    Mock::given(method("GET"))
        .and(path("/health"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "object": "health",
            "status": "healthy",
            "api_version": "v1",
            "timestamp": "2026-07-14T12:00:00Z"
        })))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path_regex(r"/validate$"))
        .respond_with(ResponseTemplate::new(503).set_body_json(serde_json::json!({
            "error": {
                "code": "temporarily_unavailable",
                "message": "Retry later"
            }
        })))
        .expect(1)
        .mount(&server)
        .await;

    restored_config.network_recheck_interval = Duration::ZERO;
    let restored_sdk = LicenseSeat::try_new(restored_config).unwrap();
    let restore = restored_sdk.restore_license().await;

    assert!(restore.restored);
    assert!(matches!(restore.status, LicenseStatus::OfflineValid { .. }));
    assert!(
        restore
            .validation
            .as_ref()
            .is_some_and(|value| value.offline)
    );
    let health_requests = server
        .received_requests()
        .await
        .unwrap()
        .into_iter()
        .filter(|request| request.method.as_str() == "GET" && request.url.path() == "/health")
        .count();
    assert_eq!(
        health_requests, 0,
        "restore should make one validation probe"
    );
}

#[tokio::test]
async fn cached_online_denial_overrides_a_restored_signed_machine_file() {
    let fixture = fixture();
    let server = MockServer::start().await;
    let storage = tempfile::tempdir().unwrap();
    let (sdk, mut offline_config) =
        sdk_with_cached_machine_file(&server, &storage, &fixture, "ruby_online_denial_").await;
    Mock::given(method("POST"))
        .and(path_regex(r"/validate$"))
        .respond_with(invalid_validation_responder())
        .expect(1)
        .mount(&server)
        .await;

    let denial = sdk.validate().await.unwrap();
    assert!(!denial.valid);
    assert!(!denial.offline);
    assert!(sdk.current_machine_file().is_none());

    // Simulate interrupted cleanup or rollback of the older, still correctly
    // signed artifact. The newer online denial must remain authoritative.
    let stale_machine_file: MachineFile =
        serde_json::from_value(fixture["machine_file"].clone()).unwrap();
    std::fs::write(
        storage.path().join("ruby_online_denial_machine_file.json"),
        serde_json::to_vec_pretty(&stale_machine_file).unwrap(),
    )
    .unwrap();
    drop(sdk);

    offline_config.api_base_url = "http://127.0.0.1:9".into();
    offline_config.request_timeout = Duration::from_millis(100);
    let restored_sdk = LicenseSeat::try_new(offline_config).unwrap();
    let restore = restored_sdk.restore_license().await;

    assert!(!restore.restored);
    assert!(matches!(restore.status, LicenseStatus::Invalid { .. }));
    let restored_denial = restore.validation.expect("cached online denial");
    assert!(!restored_denial.valid);
    assert!(!restored_denial.offline);
    assert!(!restored_sdk.has_entitlement("pro-feature"));
}

#[test]
fn fixture_records_its_ruby_core_provenance() {
    let fixture = fixture();
    assert_eq!(
        fixture["provenance"]["canonical_json_source"],
        "license_seat/lib/license_seat/utils/json_utils.rb"
    );
    assert_eq!(
        fixture["provenance"]["machine_file_contract_source"],
        "license_seat/lib/license_seat/services/offline_machine_file.rb"
    );
}
