//! Fail-fast configuration and durable-storage security checks.

use licenseseat::{Config, Error, LicenseSeat};
use sha2::{Digest, Sha256};

fn cache_path(directory: &std::path::Path, prefix: &str, key: &str) -> std::path::PathBuf {
    let namespace = Sha256::digest(prefix.as_bytes());
    let namespace = namespace
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    directory.join(format!("v2_{namespace}__{key}.json"))
}

fn config(storage: &tempfile::TempDir) -> Config {
    Config {
        api_key: "pk_test_configuration".into(),
        product_slug: "test-product".into(),
        // Keep configuration-only tests independent of optional TLS backends.
        api_base_url: "http://127.0.0.1:4567/api/v1".into(),
        storage_path: Some(storage.path().join("state")),
        device_identifier: Some("installation-123".into()),
        ..Default::default()
    }
}

#[test]
fn remote_plain_http_is_rejected_but_loopback_http_is_allowed() {
    let storage = tempfile::tempdir().unwrap();
    let mut remote = config(&storage);
    remote.api_base_url = "http://licenseseat.example/api/v1".into();
    assert!(matches!(
        LicenseSeat::try_new(remote),
        Err(Error::Configuration(_))
    ));

    let mut loopback = config(&storage);
    loopback.api_base_url = "http://127.0.0.1:4567/api/v1".into();
    assert!(LicenseSeat::try_new(loopback).is_ok());
}

#[cfg(not(any(feature = "rustls", feature = "native-tls")))]
#[test]
fn https_requires_an_explicit_tls_backend_when_defaults_are_disabled() {
    let storage = tempfile::tempdir().unwrap();
    let mut candidate = config(&storage);
    candidate.api_base_url = "https://api.example.test/api/v1".into();

    let error = match LicenseSeat::try_new(candidate) {
        Ok(_) => panic!("HTTPS client unexpectedly initialized without a TLS backend"),
        Err(error) => error,
    };
    assert!(matches!(error, Error::Configuration(message) if message.contains("Cargo feature")));
}

#[test]
fn convenience_constructor_never_bypasses_fail_fast_validation() {
    let storage = tempfile::tempdir().unwrap();
    let mut remote = config(&storage);
    remote.api_base_url = "http://licenseseat.example/api/v1".into();

    let panic = std::panic::catch_unwind(|| LicenseSeat::new(remote));
    assert!(panic.is_err());
}

#[test]
fn tls_verification_can_only_be_disabled_for_loopback() {
    let storage = tempfile::tempdir().unwrap();
    let mut remote = config(&storage);
    remote.api_base_url = "https://licenseseat.example/api/v1".into();
    remote.verify_ssl = false;
    assert!(matches!(
        LicenseSeat::try_new(remote),
        Err(Error::Configuration(_))
    ));

    let mut loopback = config(&storage);
    loopback.api_base_url = "https://localhost:4567/api/v1".into();
    loopback.verify_ssl = false;
    #[cfg(any(feature = "rustls", feature = "native-tls"))]
    assert!(LicenseSeat::try_new(loopback).is_ok());
    #[cfg(not(any(feature = "rustls", feature = "native-tls")))]
    assert!(matches!(
        LicenseSeat::try_new(loopback),
        Err(Error::Configuration(message)) if message.contains("Cargo feature")
    ));
}

#[test]
fn base_url_credentials_query_and_fragment_are_rejected() {
    let storage = tempfile::tempdir().unwrap();
    for value in [
        "https://user:password@licenseseat.example/api/v1",
        "https://licenseseat.example/api/v1?redirect=evil",
        "https://licenseseat.example/api/v1#fragment",
        "file:///tmp/licenseseat",
        " https://licenseseat.example/api/v1",
        "https://licenseseat.example/api/v1 ",
    ] {
        let mut candidate = config(&storage);
        candidate.api_base_url = value.into();
        assert!(
            matches!(
                LicenseSeat::try_new(candidate),
                Err(Error::Configuration(_))
            ),
            "accepted unsafe API base URL: {value}"
        );
    }
}

#[test]
fn malformed_authorization_values_are_rejected_before_client_creation() {
    let storage = tempfile::tempdir().unwrap();
    for api_key in [" pk_test_key", "pk_test_key ", "pk_test\nheader"] {
        let mut candidate = config(&storage);
        candidate.api_key = api_key.into();
        assert!(matches!(
            LicenseSeat::try_new(candidate),
            Err(Error::Configuration(_))
        ));
    }

    let mut oversized = config(&storage);
    oversized.api_key = "k".repeat(4097);
    assert!(matches!(
        LicenseSeat::try_new(oversized),
        Err(Error::Configuration(_))
    ));

    let mut secret = config(&storage);
    secret.api_key = "sk_live_server_authority".into();
    assert!(matches!(
        LicenseSeat::try_new(secret),
        Err(Error::Configuration(_))
    ));

    let mut excessive_retries = config(&storage);
    excessive_retries.max_retries = 11;
    assert!(matches!(
        LicenseSeat::try_new(excessive_retries),
        Err(Error::Configuration(_))
    ));
}

#[test]
fn ambiguous_identity_and_timeout_configuration_is_rejected() {
    let storage = tempfile::tempdir().unwrap();

    let mut zero_timeout = config(&storage);
    zero_timeout.request_timeout = std::time::Duration::ZERO;
    assert!(matches!(
        LicenseSeat::try_new(zero_timeout),
        Err(Error::Configuration(_))
    ));

    // Zero support intervals are an explicit opt-out. The background-task
    // launcher skips them, so they cannot create a busy loop.
    let mut support_tasks_disabled = config(&storage);
    support_tasks_disabled.network_recheck_interval = std::time::Duration::ZERO;
    support_tasks_disabled.offline_token_refresh_interval = std::time::Duration::ZERO;
    assert!(LicenseSeat::try_new(support_tasks_disabled).is_ok());

    for product_slug in [" product", "product ", "product\nslug"] {
        let mut candidate = config(&storage);
        candidate.product_slug = product_slug.into();
        assert!(matches!(
            LicenseSeat::try_new(candidate),
            Err(Error::Configuration(_))
        ));
    }

    let mut oversized_product = config(&storage);
    oversized_product.product_slug = "p".repeat(256);
    assert!(matches!(
        LicenseSeat::try_new(oversized_product),
        Err(Error::Configuration(_))
    ));

    // "dev-1" exercises the 8-character minimum, which applies to NEW
    // configuration only; fingerprints adopted from existing cached
    // activations are exempt (see cache_tests.rs).
    for identifier in [" ", " device", "device ", "device\nidentifier", "dev-1"] {
        let mut candidate = config(&storage);
        candidate.device_identifier = Some(identifier.into());
        assert!(matches!(
            LicenseSeat::try_new(candidate),
            Err(Error::Configuration(_))
        ));
    }

    let mut oversized_identifier = config(&storage);
    oversized_identifier.device_identifier = Some("x".repeat(256));
    assert!(matches!(
        LicenseSeat::try_new(oversized_identifier),
        Err(Error::Configuration(_))
    ));

    let mut empty_storage = config(&storage);
    empty_storage.storage_path = Some(std::path::PathBuf::new());
    assert!(matches!(
        LicenseSeat::try_new(empty_storage),
        Err(Error::Configuration(_))
    ));
}

#[cfg(feature = "offline")]
#[test]
fn offline_trust_anchor_must_be_a_complete_valid_pair() {
    let storage = tempfile::tempdir().unwrap();
    let mut missing_id = config(&storage);
    missing_id.signing_public_key = Some("11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=".into());
    assert!(matches!(
        LicenseSeat::try_new(missing_id),
        Err(Error::Configuration(_))
    ));

    let mut invalid_key = config(&storage);
    invalid_key.signing_public_key = Some("not-a-public-key".into());
    invalid_key.signing_key_id = Some("key-v1".into());
    assert!(matches!(
        LicenseSeat::try_new(invalid_key),
        Err(Error::OfflineVerificationFailed(_))
    ));

    for key_id in [" ", " key-v1", "key-v1 ", "key\nid"] {
        let mut invalid_id = config(&storage);
        invalid_id.signing_public_key = Some("11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=".into());
        invalid_id.signing_key_id = Some(key_id.into());
        assert!(matches!(
            LicenseSeat::try_new(invalid_id),
            Err(Error::Configuration(_))
        ));
    }
}

#[test]
fn storage_is_preflighted_even_with_an_explicit_identifier() {
    let storage = tempfile::tempdir().unwrap();
    let state_path = storage.path().join("not-a-directory");
    std::fs::write(&state_path, b"file").unwrap();
    let mut candidate = config(&storage);
    candidate.storage_path = Some(state_path);
    assert!(matches!(
        LicenseSeat::try_new(candidate),
        Err(Error::Cache(_))
    ));
}

#[test]
fn storage_preflight_does_not_leave_probe_artifacts() {
    let storage = tempfile::tempdir().unwrap();
    let candidate = config(&storage);
    let state_path = candidate.storage_path.clone().unwrap();
    let sdk = LicenseSeat::try_new(candidate).unwrap();
    assert!(sdk.current_license().is_none());
    let entries = std::fs::read_dir(state_path)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect::<Vec<_>>();
    assert!(
        entries.iter().all(|entry| entry.ends_with("state.lock")),
        "preflight must remove every probe/JSON artifact: {entries:?}"
    );
    #[cfg(any(unix, windows))]
    assert!(
        !entries.is_empty(),
        "advisory locks for the product and legacy migration scopes are durable"
    );
}

#[test]
fn corrupt_product_state_blocks_legacy_license_resurrection() {
    let storage = tempfile::tempdir().unwrap();
    let candidate = config(&storage);
    let state_path = candidate.storage_path.clone().unwrap();
    let first = LicenseSeat::try_new(candidate.clone()).unwrap();
    let current_prefix = first.config().storage_prefix.clone();
    drop(first);

    let current_path = cache_path(&state_path, &current_prefix, "license");
    std::fs::write(&current_path, b"not-json").unwrap();
    let legacy_path = state_path.join("licenseseat_license.json");
    std::fs::write(
        &legacy_path,
        serde_json::to_vec(&serde_json::json!({
            "license_key": "LEGACY-LICENSE",
            "device_id": "legacy-installation",
            "activation_id": "legacy-activation",
            "activated_at": "2026-01-01T00:00:00Z",
            "last_validated": "2026-01-01T00:00:00Z",
            "trusted_license": {
                "object": "license",
                "key": "LEGACY-LICENSE",
                "status": "active",
                "starts_at": null,
                "expires_at": null,
                "mode": "hardware_locked",
                "plan_key": "pro",
                "seat_limit": 1,
                "active_seats": 1,
                "active_entitlements": [],
                "metadata": null,
                "product": { "slug": "test-product", "name": "Test Product" }
            },
            "validation": null
        }))
        .unwrap(),
    )
    .unwrap();

    assert!(matches!(
        LicenseSeat::try_new(candidate),
        Err(Error::Cache(_))
    ));
    assert_eq!(std::fs::read(&current_path).unwrap(), b"not-json");
    assert!(legacy_path.exists(), "legacy state must not be migrated");
}

#[cfg(unix)]
#[test]
fn symlinked_storage_directory_is_rejected() {
    use std::os::unix::fs::symlink;

    let storage = tempfile::tempdir().unwrap();
    let real = storage.path().join("real");
    let linked = storage.path().join("linked");
    std::fs::create_dir(&real).unwrap();
    symlink(&real, &linked).unwrap();
    let mut candidate = config(&storage);
    candidate.storage_path = Some(linked);
    assert!(matches!(
        LicenseSeat::try_new(candidate),
        Err(Error::Cache(_))
    ));
}
