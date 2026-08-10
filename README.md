# LicenseSeat Rust SDK

[![Crates.io](https://img.shields.io/crates/v/licenseseat.svg)](https://crates.io/crates/licenseseat)
[![Tauri Plugin](https://img.shields.io/crates/v/tauri-plugin-licenseseat.svg?label=tauri-plugin)](https://crates.io/crates/tauri-plugin-licenseseat)
[![Documentation](https://docs.rs/licenseseat/badge.svg)](https://docs.rs/licenseseat)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

The official LicenseSeat SDK for Rust applications and Tauri 2 desktop apps. The workspace contains:

| Package | Purpose |
| --- | --- |
| [`licenseseat`](crates/licenseseat) | Async Rust SDK for licensing, entitlements, signed offline operation, and release discovery |
| [`tauri-plugin-licenseseat`](crates/tauri-plugin-licenseseat) | Tauri 2 plugin, capability definitions, and Rust command bridge |
| [`@licenseseat/tauri-plugin`](crates/tauri-plugin-licenseseat) | Typed JavaScript API and serialized state subscriptions |

The standalone core SDK supports Rust 1.85+. The Tauri plugin requires Rust
1.88+ so its locked Tauri dependency graph includes patched XML/time parsers.
Client applications must embed a publishable `pk_*` key. A secret `sk_*` key
is server authority and must never ship in an application.

## Production quick start

### Rust

```toml
[dependencies]
licenseseat = "0.6.0"
```

```rust,no_run
use licenseseat::{Config, LicenseSeat};

#[tokio::main]
async fn main() -> licenseseat::Result<()> {
    let sdk = LicenseSeat::try_new(Config::new(
        "pk_live_your_publishable_key",
        "your-product",
    ))?;

    // At startup, restore persisted state before gating paid features.
    let restored = sdk.restore_license().await;
    if !restored.restored {
        sdk.activate("CUSTOMER-LICENSE-KEY").await?;
    }

    // These helpers fail closed unless this process has established trust.
    if sdk.has_entitlement("pro-features") {
        // Enable the paid capability.
    }

    Ok(())
}
```

Use `LicenseSeat::try_new` in production so invalid configuration or unavailable durable storage becomes a recoverable startup error. `LicenseSeat::new` enforces the same checks but panics on failure.

### Tauri 2

Install both halves:

```bash
cargo add tauri-plugin-licenseseat
npm add @licenseseat/tauri-plugin
```

Register the plugin:

```rust,ignore
tauri::Builder::default()
    .plugin(tauri_plugin_licenseseat::init())
    .run(tauri::generate_context!())
    .expect("failed to run Tauri application");
```

Compile production trust configuration into `tauri.conf.json`:

```json
{
  "plugins": {
    "licenseseat": {
      "apiKey": "pk_live_your_publishable_key",
      "productSlug": "your-product",
      "signingPublicKey": "BASE64_ED25519_PUBLIC_KEY",
      "signingKeyId": "production-key-v1"
    }
  }
}
```

Grant only the commands that the renderer needs. The default set covers ordinary lifecycle, status, and entitlement operations:

```json
{
  "identifier": "main",
  "windows": ["main"],
  "permissions": ["licenseseat:default"]
}
```

```typescript
import {
  activateAndGetState,
  bootstrapState,
  stateHasEntitlement,
  subscribeState,
} from '@licenseseat/tauri-plugin';

let state = await bootstrapState();

const unsubscribe = await subscribeState(
  ({ state: next }) => {
    state = next;
    renderPaidFeatures(stateHasEntitlement(state, 'pro-features'));
  },
  {
    emitCurrent: true,
    onError: (error) => reportLicensingError(error),
  },
);

// From the activation UI:
state = await activateAndGetState(customerLicenseKey);
```

The plugin starts one native restore automatically. `bootstrapState()` is idempotent and does not perform an extra validation by default; pass `{ validateIfActivated: true }` only when an additional online check is intentional.

## Trust and state model

The SDK separates “data exists on disk” from “this process may grant access.”

| Situation | Status | Entitlements grant? |
| --- | --- | --- |
| No cached activation | `inactive` | No |
| Unsigned online cache loaded after restart | `pending` | No |
| Activation or current online validation succeeded | `active` | Yes, while the license and entitlement are active |
| Pinned-key signed artifact verified locally | `offline_valid` | Yes, within every signed and host-side time limit |
| Online or offline validation denied the grant | `invalid` / `offline_invalid` | No |

Use `status()`, `get_status()`, `has_entitlement()`, and `active_entitlements()` for authorization. Use `state_snapshot()` when several related fields must cross an IPC/UI boundary coherently. `current_license()` intentionally exposes persisted diagnostic data and must not be treated as an authorization decision.

Every server response is bound to the requested product, license, installation fingerprint, and activation where applicable before it can commit state. A stale async request cannot overwrite a newer activation, deactivation, reset, or validation. Exact authoritative denial codes leave a durable fail-closed tombstone before cached grants are removed; transport failures, malformed responses, and unrelated client errors do not erase the last trusted in-process grant.

## Installation identity and privacy

By default the SDK creates a random, durable, product-scoped installation identifier in private application-data storage. It does not derive the identifier from hardware and does not automatically send raw hostname or hardware identifiers.

`send_fingerprint_components` / `sendFingerprintComponents` is an explicit opt-in for legacy interoperability. A caller can also supply an explicit component map for one machine-file request. Telemetry is a separate option and defaults on; it contains SDK/app version, OS/architecture, coarse capacity, locale/language, and timezone fields. Disable it when that data is not appropriate for the host application's privacy policy.

## Offline operation

Machine files are the preferred offline artifact. They are encrypted with AES-256-GCM, signed with Ed25519, and bound to the license, product, activation, and installation fingerprint. Legacy offline tokens are disabled unless `enable_legacy_offline_tokens` is enabled.

Production offline startup requires a pinned pair:

- `signing_public_key` / `signingPublicKey`
- `signing_key_id` / `signingKeyId`

A key fetched from the API can verify artifacts during the current online process. Its persisted copy is diagnostic cache and is deliberately not accepted as a trust anchor in a new process.

The verifier enforces the signed issue/not-before/expiry window, optional license expiry, fingerprint, product, activation, algorithm, schema, entitlement expiry, maximum clock skew, and optional `max_offline_days` age cap. A monotonic last-seen watermark detects meaningful clock rollback. An online denial always outranks an older signed grant.

### Fallback policy

| Mode | May consult a signed offline artifact after |
| --- | --- |
| `NetworkOnly` (default) | Transport failure, timeout, HTTP 408, or 5xx |
| `Always` | Everything above plus HTTP 429 rate limiting |

Neither mode falls back for authentication/configuration failures, ordinary business/client errors, malformed or identity-substituted responses, or superseded local operations.

Set `network_recheck_interval` or `offline_token_refresh_interval` to zero to disable that worker. Zero does not create a busy loop. Machine-file refresh is attempted before any enabled legacy-token refresh.

## TLS, transport, and persistence

- Remote API URLs must use HTTPS.
- Plain HTTP and disabled certificate verification are accepted only for loopback development endpoints.
- The default `rustls` feature provides TLS. `native-tls` can be selected independently.
- A no-default-features build without either TLS backend supports loopback HTTP testing only and rejects HTTPS configuration with an actionable error.
- Requests and responses are bounded before allocation/processing; retries are limited to transport, HTTP 408/429, and 5xx conditions as appropriate.
- URLs containing license keys and bearer credentials are stripped from logs and surfaced transport errors.
- Cache files use private permissions where supported, bounded reads, atomic replacement, symlink/reparse-point rejection, opaque SHA-256 product scoping, and transactional one-way legacy migration.

When upgrading an installation with an existing pre-0.6 cache, stop every old
SDK process before the first 0.6 launch. The two formats intentionally use
different lock names, and a successful hardened write removes the legacy copy;
rolling the storage back to an older SDK after migration is therefore not a
supported authorization-state rollback path.

```toml
# Default: rustls + offline support
licenseseat = "0.6.0"

# System TLS + offline support
licenseseat = { version = "0.6.0", default-features = false, features = ["native-tls", "offline"] }
```

## Tauri capability boundary

`licenseseat:default` is intentionally smaller than the entire plugin API. Additional sets are:

| Permission set | Adds |
| --- | --- |
| `licenseseat:diagnostics` | Detailed admin snapshot with cached artifacts and local paths |
| `licenseseat:advanced-lifecycle` | Explicit key/fingerprint operations and destructive reset |
| `licenseseat:offline-management` | Raw artifact checkout, verification, signing-key lookup, and refresh |
| `licenseseat:releases` | Release lookup and license-bound download-token generation |

Do not load untrusted remote content into a window that has LicenseSeat permissions. The generic renderer API necessarily handles customer-entered license keys and returns license state. Higher-assurance apps should keep the generic permissions off the renderer, manage the re-exported core SDK in Rust, and expose a narrow app-specific command facade with redacted state and native entitlement gates.

## Releases and downloads

The SDK can list releases, select the latest release by channel/platform, and request a short-lived license-bound download token. It validates returned product/channel/platform metadata and token expiry before returning it. A consuming download endpoint must still verify the token's signature and bind its subject, product, release, and platform claims to the requested artifact.

Packaging, code signing, update installation, rollout, and rollback remain host/application responsibilities in this release.

## Local release verification

GitHub Actions may be unavailable independently of code health. The release gate is reproducible locally:

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

cd crates/tauri-plugin-licenseseat
npm ci
npm test
npm run pack:check
```

The cross-language fixtures under `crates/licenseseat/tests/fixtures` are generated by the LicenseSeat Ruby core and prove that Ruby-issued offline tokens and machine files verify in Rust, including tampering, product/fingerprint/activation substitution, cache restart, denial precedence, and clock rollback cases.

See [the core SDK guide](crates/licenseseat/README.md), [the Tauri guide](crates/tauri-plugin-licenseseat/README.md), [the changelog](CHANGELOG.md), and [the production hardening audit](docs/releases/production-hardening-audit.md).

## License

MIT. See [LICENSE](LICENSE).
