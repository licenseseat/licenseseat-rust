//! Version-ceiling compatibility (server API 2026-08-19).
//!
//! The server can bound a license to app versions below a ceiling
//! (`below_version` on the `updates` entitlement) and refuses gated
//! activation/validation with `version_not_entitled`. The gate reads the
//! version THIS SDK declares — `telemetry.app_version` — so these tests pin
//! the three contracts the feature stands on: the field parses, the code
//! surfaces, and the declaration actually rides the wire.

mod common;

use common::activation_responder_with_entitlements;
use licenseseat::{Config, Entitlement, LicenseSeat};
use serde_json::json;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use wiremock::matchers::{body_partial_json, method, path_regex};
use wiremock::{Mock, MockServer, ResponseTemplate};

static TEST_COUNTER: AtomicU64 = AtomicU64::new(0);

fn test_config(base_url: &str) -> Config {
    Config {
        api_key: "test-api-key".into(),
        product_slug: "test-product".into(),
        api_base_url: base_url.into(),
        storage_prefix: format!(
            "version_gate_test_{}_{}_{}_",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos(),
            TEST_COUNTER.fetch_add(1, Ordering::SeqCst)
        ),
        device_identifier: Some("device-123".into()),
        auto_validate_interval: Duration::from_secs(0),
        heartbeat_interval: Duration::from_secs(0),
        debug: true,
        ..Default::default()
    }
}

/// `below_version` must parse, and its absence (every response from an older
/// server) must parse as `None` — additive in both directions.
#[test]
fn below_version_parses_and_older_payloads_stay_none() {
    let bounded: Entitlement = serde_json::from_value(json!({
        "key": "updates",
        "expires_at": null,
        "below_version": "3.0.0",
        "metadata": {}
    }))
    .expect("bounded entitlement must parse");
    assert_eq!(bounded.below_version.as_deref(), Some("3.0.0"));

    let legacy: Entitlement = serde_json::from_value(json!({
        "key": "updates",
        "expires_at": null
    }))
    .expect("legacy entitlement must parse");
    assert_eq!(legacy.below_version, None);
}

/// A version-gated refusal is a normal `valid: false` envelope carrying the
/// `version_not_entitled` code — the SDK must store it like any other
/// invalid result, code intact, bounded entitlement parsed.
#[tokio::test]
async fn version_not_entitled_validation_surfaces_code() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path_regex(r"/products/.*/licenses/activate"))
        .respond_with(activation_responder_with_entitlements(vec![json!({
            "key": "updates",
            "expires_at": null,
            "below_version": "3.0.0",
            "metadata": {}
        })]))
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path_regex(r"/products/.*/licenses/validate"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "object": "validation_result",
            "valid": false,
            "code": "version_not_entitled",
            "message": "This license does not cover version 3.0.1 — it is valid for versions below 3.0.0.",
            "license": {
                "object": "license",
                "key": "TEST-KEY",
                "status": "active",
                "starts_at": null,
                "expires_at": null,
                "mode": "hardware_locked",
                "plan_key": "personal-lifetime",
                "seat_limit": 1,
                "active_seats": 1,
                "active_entitlements": [
                    {"key": "updates", "expires_at": null, "below_version": "3.0.0", "metadata": {}}
                ],
                "metadata": null,
                "product": { "slug": "test-product", "name": "Test App" }
            }
        })))
        .mount(&server)
        .await;

    let sdk = LicenseSeat::new(test_config(&server.uri()));
    sdk.activate("TEST-KEY").await.expect("activation below the ceiling succeeds");

    let _ = sdk.validate().await;
    let license = sdk.current_license().expect("license cached");
    let validation = license.validation.expect("validation stored");
    assert!(!validation.valid);
    assert_eq!(validation.code.as_deref(), Some("version_not_entitled"));
}

/// The whole server-side gate reads the version the SDK declares — so the
/// declaration must actually ride the validate body when telemetry is on.
#[tokio::test]
async fn telemetry_app_version_rides_the_validate_body() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path_regex(r"/products/.*/licenses/activate"))
        .and(body_partial_json(json!({
            "telemetry": { "app_version": "2.9.9" }
        })))
        .respond_with(activation_responder_with_entitlements(vec![]))
        .expect(1)
        .mount(&server)
        .await;

    let mut config = test_config(&server.uri());
    config.telemetry_enabled = true;
    config.app_version = Some("2.9.9".into());

    let sdk = LicenseSeat::new(config);
    sdk.activate("TEST-KEY")
        .await
        .expect("the activate body must carry telemetry.app_version — the server's version gate reads it");

    server.verify().await;
}
