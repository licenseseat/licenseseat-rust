# `licenseseat`

Async Rust SDK for LicenseSeat. It supports online license lifecycle operations, fail-closed entitlement gates, signed offline operation, background validation/heartbeat workers, health diagnostics, and release/download-token discovery.

## Install

```toml
[dependencies]
licenseseat = "0.6.0"
```

Default features are `rustls` and `offline`. Rust 1.85 or newer is required.

```toml
# Use the platform TLS backend instead.
licenseseat = {
  version = "0.6.0",
  default-features = false,
  features = ["native-tls", "offline"]
}
```

Remote endpoints require HTTPS and a TLS feature. A build with neither `rustls` nor `native-tls` is useful only for loopback HTTP tests. Plain HTTP and disabled certificate validation are rejected for non-loopback hosts.

## Initialize safely

```rust,no_run
use licenseseat::{Config, LicenseSeat, OfflineFallbackMode};
use std::time::Duration;

fn build_sdk() -> licenseseat::Result<LicenseSeat> {
    LicenseSeat::try_new(Config {
        api_key: "pk_live_your_publishable_key".into(),
        product_slug: "your-product".into(),
        offline_fallback_mode: OfflineFallbackMode::NetworkOnly,
        auto_validate_interval: Duration::from_secs(60 * 60),
        heartbeat_interval: Duration::from_secs(5 * 60),
        signing_public_key: Some("BASE64_ED25519_PUBLIC_KEY".into()),
        signing_key_id: Some("production-key-v1".into()),
        ..Default::default()
    })
}
```

Use a publishable `pk_*` key in a desktop/client binary. Never embed an `sk_*` secret key. `try_new` validates transport, identifiers, key pairing, timing, and storage before it constructs the client. It also creates or loads the durable installation identity. `new` performs the same work but panics if it fails.

## Recommended lifecycle

```rust,no_run
# use licenseseat::{Config, LicenseSeat};
# async fn example() -> licenseseat::Result<()> {
let sdk = LicenseSeat::try_new(Config::new("pk_live_xxx", "your-product"))?;

let restore = sdk.restore_license().await;
if !restore.restored {
    sdk.activate("CUSTOMER-LICENSE-KEY").await?;
}

match sdk.status() {
    licenseseat::LicenseStatus::Active { .. }
    | licenseseat::LicenseStatus::OfflineValid { .. } => {
        // The current process has established a trusted grant.
    }
    _ => {
        // Show activation/recovery UI and keep paid behavior disabled.
    }
}

if sdk.has_entitlement("cloud-sync") {
    // Gate both UI and the value-producing operation.
}

// Send when appropriate for the product's seat semantics.
sdk.heartbeat().await?;

// Explicit sign-out/device release:
sdk.deactivate().await?;
# Ok(())
# }
```

Activation itself is an authoritative online grant and becomes `Active` immediately. Validation and heartbeat refresh the trusted license metadata. Deactivation is idempotent only for recognized API codes; a generic/uncoded 404 does not erase the local activation.

`restore_license` is serialized and idempotent. Concurrent setup/frontend callers share one restoration instead of superseding each other. A persisted unsigned online snapshot starts as `Pending`; it grants nothing until current online validation or signed-offline verification succeeds.

## Authorization APIs

Use these for decisions:

- `status()` / `get_client_status()`
- `get_status()`
- `current_authoritative_validation()` when an optional exact runtime decision
  is preferable to `get_status()`'s fail-closed default result
- `check_entitlement(key)` / `has_entitlement(key)`
- `active_entitlements()`
- `state_snapshot()` when a UI/IPC response needs one coherent observation of
  status, client status, license, validation, trust source, and entitlements
- `is_license_state_trusted()` when diagnostics need the trust distinction

`has_entitlement` checks all of the following: this process established trust, validation is valid, the license key/product/status/time window still represents an active grant, the entitlement exists, and its own expiry is in the future.

`current_license()`, `current_machine_file()`, `current_offline_token()`, and cached signing-key accessors are diagnostic/cache APIs. The existence of one of those values is not authorization.

## State and concurrency guarantees

Before committing an API response, the SDK verifies the response object and binds it to the requested:

- product slug;
- license key;
- installation fingerprint;
- activation identity where the protocol supplies one;
- release channel/platform/product for distribution responses.

Activation, validation, heartbeat, deactivation, reset, restoration, and offline refresh use operation generations plus a commit lock. A delayed response cannot overwrite a newer state-changing operation. `state_snapshot()` uses that same boundary to prevent a consumer from combining fields from different commits. Rejected or superseded responses leave the newer/last trusted state intact and return `ResponseMismatch` or `OperationSuperseded`.

Recognized authoritative invalidation codes write a durable denial before removing cached grant artifacts. If cleanup is partially unavailable, the denial remains and authorization fails closed. Availability failures, malformed responses, and unrelated 4xx errors do not silently destroy a trusted in-process state.

## Installation identity and storage

When `device_identifier` is omitted, initialization creates a cryptographically random installation UUID and persists it. The default prefix is deterministically product-scoped so two products cannot accidentally share activation state. Existing legacy identifiers and cache locations are adopted/migrated where safe.

The SDK does not derive its default identifier from the machine and does not send raw hardware components by default. Set `send_fingerprint_components = true` only for a deployment that explicitly needs legacy hardware-component interoperability. `MachineFileCheckoutOptions::fingerprint_components` can opt in for one request.

Persisted files are placed under platform application data (or `storage_path`) and use:

- private directory/file permissions where the OS supports them;
- atomic same-directory replacement;
- bounded reads and writes;
- symlink and unsafe-path rejection;
- safe normalized prefixes/key identifiers;
- a monotonic last-seen timestamp for rollback detection.

Initialization fails if durable storage cannot be used or existing license state is corrupt/unreadable; it never silently rotates to a hardware-derived identity or treats corruption as permission to consume another seat.

## Offline validation

Enable the `offline` feature (included by default). Machine files are preferred over legacy offline tokens.

```rust,no_run
# use licenseseat::{Config, LicenseSeat};
# async fn example() -> licenseseat::Result<()> {
let sdk = LicenseSeat::try_new(Config {
    api_key: "pk_live_xxx".into(),
    product_slug: "your-product".into(),
    signing_public_key: Some("BASE64_ED25519_PUBLIC_KEY".into()),
    signing_key_id: Some("production-key-v1".into()),
    max_offline_days: 7,
    ..Default::default()
})?;

sdk.activate("CUSTOMER-LICENSE-KEY").await?;
# Ok(())
# }
```

A successful activation already starts one one-shot offline-asset sync. Do not
normally call `sync_offline_assets()` immediately afterward: that starts a
second, serialized checkout. Use the method later when an explicit refresh or
retry is intentional. If the application needs to observe initial readiness,
subscribe to the machine-file/offline-asset events before activation.

### Trust anchor

Both `signing_public_key` and `signing_key_id` must be supplied together. The SDK can fetch a key by `kid` while online, but a fetched/persisted key is not accepted as a trust anchor by a new process. Pin the public key pair into the release for offline startup.

This prevents mutable local cache from replacing the verifier key and authorizing an attacker-created artifact.

### Machine-file checks

The verifier checks:

- PEM-like envelope shape and 4 MiB size bounds;
- exact `aes-256-gcm+ed25519` algorithm and Ed25519 signature;
- schema, key ID, canonical relationships, and positive signed lifetime;
- license, product, fingerprint, and activation binding;
- issue, not-before, expiry, grace period, and optional license expiry;
- optional host `max_offline_days` and configured clock skew;
- cached last-seen watermark against clock rollback;
- embedded license status/product/time window and entitlement expiries.

Rich plan/product/entitlement metadata is restored only from the signed embedded license. If a valid machine file omits that object, it still proves the bound license/product/activation/time contract but restores a minimal identity-bound license with no plan or entitlements. Unsigned snapshots and cached online metadata are diagnostic restoration inputs, never offline grant enrichment. An online/local denial always outranks an older signed artifact.

Legacy token signatures use standard Base64, matching the Ruby core. Machine-file encrypted components/signatures use the format defined by the core service. Cross-language fixtures in `tests/fixtures/ruby_compat.json` are generated by the Ruby implementation and verified byte-for-byte in Rust tests.

### Fallback policy

`OfflineFallbackMode::NetworkOnly` consults signed offline state only after transport failure, timeout, HTTP 408, or 5xx. `Always` additionally permits fallback after HTTP 429.

Neither mode permits an older offline artifact to override authentication/configuration failures, ordinary business/client errors, invalid JSON or response identity, or a superseded local operation.

`network_recheck_interval = Duration::ZERO` disables connectivity probing.
`offline_token_refresh_interval = Duration::ZERO` disables periodic artifact
refresh, but not the one-shot sync after activation. The periodic task launcher
skips disabled intervals, so zero cannot create a tight loop.

## Configuration reference

| Field | Default | Notes |
| --- | --- | --- |
| `api_base_url` | `https://licenseseat.com/api/v1` | HTTPS required remotely; query, fragment, and embedded credentials rejected |
| `api_key` | empty | Publishable client key; required for API operations |
| `product_slug` | empty | Required product identity |
| `storage_prefix` | product-scoped `licenseseat_` | Custom values are filename-normalized |
| `storage_path` | platform app-data `licenseseat/` | Preflighted at startup |
| `device_identifier` | durable random UUID | Explicit installation override |
| `send_fingerprint_components` | `false` | Opt-in raw hardware component collection |
| `signing_public_key` / `signing_key_id` | none | Must be a complete valid pair |
| `auto_validate_interval` | 1 hour | Zero disables |
| `heartbeat_interval` | 5 minutes | Zero disables |
| `network_recheck_interval` | 30 seconds | Zero disables |
| `request_timeout` | 30 seconds | Must be greater than zero |
| `verify_ssl` | `true` | May be false only for loopback |
| `max_retries` | 3 | Retries only retryable availability failures |
| `retry_delay` | 1 second | Exponential delay is capped |
| `offline_fallback_mode` | `NetworkOnly` | See policy above |
| `offline_token_refresh_interval` | 72 hours | Zero disables periodic refresh; activation still starts one one-shot sync |
| `enable_legacy_offline_tokens` | `false` | Machine files remain preferred |
| `max_offline_days` | 0 | No extra host-age cap; signed expiry still enforced |
| `max_clock_skew` | 5 minutes | Used by signed time checks |
| `telemetry_enabled` | `true` | See privacy section below |
| `debug` | `false` | Credentials/keys/identity remain redacted |
| `app_version` / `app_build` | none | Caller-provided telemetry fields |

Request identifiers are 1–255 non-control characters without surrounding whitespace. API keys are bounded and must be valid HTTP header content. Request JSON and response bodies are bounded at 1 MiB and 4 MiB respectively.

## Telemetry

When enabled, requests can include SDK name/version, OS name/version, native platform/device class, CPU architecture/core count, coarse memory capacity, locale/language/timezone, and caller-provided app version/build. It does not add raw hostname or hardware identifiers. Hosts remain responsible for their privacy disclosure and can set `telemetry_enabled = false`.

## Events

`subscribe()` returns a Tokio broadcast receiver. Lifecycle operations emit a start (where defined) and a terminal success/failure event even when a well-formed server response is rejected during binding or local commit. Network-status and background-offline events are global and can interleave; consumers should filter by `EventKind`, not assume adjacent pairs.

The event model covers activation, validation, deactivation, heartbeat, offline token/machine-file fetch and verification, offline validation, background auto-validation, network status, revocation, reset, and SDK errors. A lagged broadcast receiver should resynchronize from `status()`/`get_status()`.

## Errors and retries

`Error` preserves structured API status/code/details and adds explicit variants for response substitution, superseded state, request/response size bounds, cache failure, crypto failure, and offline timing.

API messages are bounded, control characters are normalized, and an HTML proxy page becomes a generic safe message. Reqwest URLs are removed from surfaced transport errors because license keys are API path segments. Debug logs do not print request paths or cached keys.

Retries apply to transport failures, HTTP 408, HTTP 429, and 5xx. Authentication, configuration, response parsing/binding, cache, crypto, and business errors are not retried.

## Releases and downloads

`get_latest_release`, `list_releases`, and `generate_download_token` support LicenseSeat distribution metadata. Returned release product/channel/platform and download-token expiry are validated before use.

The SDK does not install updates or verify an artifact hash/signature in this release. A download service must verify each token cryptographically and bind its subject, product, release, and platform claims to the requested artifact.

## Verification

```bash
cargo fmt --all -- --check
cargo +1.85.0 check -p licenseseat --all-features --locked
cargo +1.88.0 check -p tauri-plugin-licenseseat --all-features --locked
cargo test --workspace --all-features --locked
cargo test -p licenseseat --no-default-features --locked
cargo test -p licenseseat --no-default-features --features rustls --locked
cargo test -p licenseseat --no-default-features --features native-tls --locked
cargo test -p licenseseat --no-default-features --features rustls,offline --locked
cargo test -p licenseseat --no-default-features --features native-tls,offline --locked
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --all-features --no-deps --locked
cargo package --workspace --locked --allow-dirty
cargo audit
```

See the workspace [production hardening audit](../../docs/releases/production-hardening-audit.md) for the threat model, regression inventory, compatibility evidence, residual framework warnings, and release checklist.
