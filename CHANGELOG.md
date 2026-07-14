# Changelog

## [Unreleased]

Planned release line: **0.6.0**. A minor version bump is required because the
hardening adds fields to public configuration/signed-payload structs and adds
fail-closed public error/reason variants.

This is a security and production-readiness hardening pass. See
[`docs/releases/production-hardening-audit.md`](docs/releases/production-hardening-audit.md)
for the threat model, migration notes, compatibility evidence, residual risks,
and complete local release gate.

### Added

- Durable random, product-scoped installation identity with safe legacy adoption
  and explicit opt-in hardware fingerprint components.
- Strict response binding for activation, validation, heartbeat, deactivation,
  health, releases, download tokens, offline tokens, and machine files.
- Global state-operation sequencing, commit serialization, restore
  single-flight behavior, cancellable weak-owned workers, and stale-response
  rejection.
- A coherent `LicenseStateSnapshot` API so IPC/UI consumers observe status,
  validation, license, trust source, and entitlements from one state decision.
- Advisory cross-process cache locking and MSRV-aware Cargo resolver/CI gates:
  Rust 1.85 for the core and Rust 1.88 for the Tauri plugin.
- Explicit request/response size errors, bounded transport bodies, safe API
  message normalization, and URL-free transport errors.
- Pinned-key cross-process offline trust, complete signed claim/time/identity
  checks, denial tombstones, and clock-rollback coverage.
- Least-privilege Tauri permission sets for diagnostics, advanced lifecycle,
  offline management, and releases.
- Typed Tauri `init_with_config` setup and an `emitFrontendEvents` control for
  high-assurance native facades that must not broadcast generic payloads.
- Serialized JavaScript state subscriptions with error recovery and
  unsubscribe/drain semantics.
- Generated Ruby-core compatibility fixtures and adversarial integration tests.

### Changed

- The Tauri plugin MSRV is now Rust 1.88 so its lockfile can use patched
  `quick-xml >=0.41` and `time >=0.3.47`; the standalone core remains Rust 1.85.
- The audited workspace lockfile is committed, all CI Cargo commands use
  `--locked`, and a scheduled RustSec audit prevents silent dependency drift.
- Legacy tenant-specific offline examples were consolidated into one
  environment-driven signed-restoration example with no embedded credentials.
- Historical fieldless-enum discriminants remain stable; regression tests
  protect downstream code that previously cast event/trust-source values.

- Persisted unsigned online state is pending and grants no entitlements until
  the current process completes online or signed-offline restoration.
- Signed offline artifacts grant rich plan/product/entitlement metadata only
  when that metadata is embedded in the signed payload. Unsigned snapshots and
  cached online records no longer enrich stripped machine files.
- Activation is an immediately trusted online grant; entitlement/status helpers
  consistently enforce active license, product, time, and entitlement state.
- Machine files are the preferred offline artifact; legacy offline tokens
  remain opt-in.
- Fetched signing-key files are diagnostic cache only. Offline startup requires
  a public key and matching key ID pinned into the application.
- The default Tauri capability no longer grants admin, raw offline, explicit
  arbitrary-key, reset, or release commands.
- Tauri release builds reject runtime environment placeholders for licensing
  trust configuration; debug builds retain the development convenience.
- `bootstrapState` no longer performs a redundant validation by default.
- `rustls` and `native-tls` now select independent reqwest backends.
- Zero network-recheck/offline-refresh intervals explicitly disable those
  workers without creating a busy loop.
- `Error`, `EntitlementReason`, and `TrustedLicenseSource` are non-exhaustive so
  future diagnostic additions do not require another source-breaking release.
- `LicenseStatus`, `ClientStatus`, `OfflineFallbackMode`, `EventKind`, and
  `EventData` are also non-exhaustive; downstream matches must include a
  wildcard arm.
- Startup restore uses validation itself as the single reachability/authority
  probe, avoiding a redundant health request and health-to-validation race.

### Fixed

- Prevented substituted or stale responses from creating, replacing, or
  deleting the wrong local grant.
- Prevented cached fetched keys, corrupt current cache files, symlinked paths,
  and legacy fallback files from becoming unintended trust roots.
- Made corrupt/unreadable startup license state an actionable initialization
  error instead of silently treating it as a missing activation.
- Fixed validation authentication classification to use HTTP 401/403 rather
  than 401/501.
- Fixed missing terminal error events for response-verification, crypto, cache,
  and superseded-operation failures after a lifecycle start/fetch event.
- Prevented logs and surfaced reqwest errors from exposing license keys embedded
  in request paths.
- Prevented concurrent frontend state handlers from overlapping or observing
  out-of-order snapshots.
- Prevented Tauri state responses from mixing fields across concurrent commits,
  ensured the native event bridge subscribes before automatic restore, and
  refreshed renderer state after heartbeat-delivered entitlement changes.
- Fixed signed-offline fallback when health would succeed but validation itself
  returns a transient outage, and guaranteed terminal offline failure events
  for cache/commit errors.
- Corrected documentation for fallback policy, Base64 encoding, telemetry,
  signing-key pinning, installation identity, Tauri permissions, and trusted
  entitlement use.

## [0.5.3] - 2026-04-01

For a detailed technical note covering the root cause, final implementation shape, regression coverage, and release verification, see [`docs/releases/0.5.3.md`](docs/releases/0.5.3.md) and [`docs/releases/offline-validation-metadata-preservation.md`](docs/releases/offline-validation-metadata-preservation.md).

- Hardened offline machine-file restore so trusted plan, entitlement, and product metadata survive even when the machine-file payload is stripped and the separate `license_snapshot` file is missing.
- Trusted rich license metadata is now persisted on the cached `license.json` record itself, with offline recovery preferring embedded machine-file license data first, snapshot-file metadata second, cached trusted metadata third, and blank fallback only last.
- Offline restore now self-heals the dedicated snapshot file when trusted cached metadata exists, reducing the chance that a missing snapshot file can cause future downgrade behavior on the same machine.
- Added release-blocking regression coverage for the production failure mode: stripped machine file, deleted snapshot file, app restart, then offline restore after activation, validation, and heartbeat paths.
- Clarified the Tauri admin/debug surface so it now exposes `trustedLicense`, `trustedLicenseSource`, and the snapshot-file path separately.

## [0.5.2] - 2026-04-01

For a detailed technical note covering the root cause, implementation shape, regression coverage, and release verification, see [`docs/releases/0.5.2.md`](docs/releases/0.5.2.md) and [`docs/releases/offline-validation-metadata-preservation.md`](docs/releases/offline-validation-metadata-preservation.md).

- Fixed offline machine-file restore so cached plan, entitlement, and product metadata are preserved instead of being downgraded to empty fallback values when the machine-file payload lacks an embedded license object.
- Activation, validation, and heartbeat now refresh a trusted cached license snapshot, so offline restore can preserve plan, product, and entitlement metadata without changing the SDK's pending-before-validation status semantics.
- Added dedicated regression coverage for offline restore with a valid machine file but no embedded license object, including activation-only, validated, and heartbeat-refreshed snapshot paths.
- Added a technical note documenting the issue and fix in [`docs/releases/offline-validation-metadata-preservation.md`](docs/releases/offline-validation-metadata-preservation.md).

## [0.5.1] - 2026-03-31

This release brings the Rust SDK and the Tauri plugin up to parity with the current C++ reference implementation, expands the public API for offline/manual workflows, and hardens the production defaults for mixed-SDK deployments.

For a detailed technical inventory of the release, including subsystem-by-subsystem notes, compatibility details, file-level change coverage, and release sequencing guidance, see [`docs/releases/0.5.1.md`](docs/releases/0.5.1.md).

### Added
- C++-compatible default device fingerprinting strategy with structured fingerprint components
- Machine-file-first offline validation flow, manual machine-file verification helpers, signing-key fetch/cache support, and restore/session recovery APIs
- Release listing, latest-release lookup, and download-token APIs in the Rust core SDK
- Explicit stateless validation/deactivation/heartbeat helpers and richer client/runtime status APIs
- Expanded event model for offline lifecycle, authentication failures, auto-validation failures, network state changes, and SDK/runtime errors
- Tauri plugin coverage for release APIs, manual offline token/machine-file workflows, client status, fingerprint access, restore, health, and event forwarding
- High-level Tauri JS helpers for consolidated state snapshots, startup flows, and normalized error handling
- New plugin `get_state` / `get_admin_snapshot` surfaces for frontend state and admin/debug inspection
- Direct plugin-side unit coverage for command payload conversions and structured event serialization

### Changed
- The Rust SDK now defaults to the same fingerprinting strategy and identifier shape as the C++ reference implementation
- Background support-task lifecycle handling now prevents duplicated loops across stop/start cycles
- Tauri status values are normalized to the stable snake_case contract: `offline_valid` and `offline_invalid`
- The JS bindings now ship a production-oriented integration path centered on `getState()`, `subscribeState()`, `activateAndGetState()`, and `bootstrapState()`
- The npm package now builds during `prepare`/`prepack` and is validated in CI with explicit build and pack checks instead of a checked-in `dist` policy
- Public docs and examples now reflect the parity-expanded Rust and Tauri surfaces

### Fixed
- Legacy offline-token fallback now remains reachable when machine-file verification/setup fails
- Restore/offline fallback behavior now follows the configured fallback policy more closely
- Machine-file test fixtures and request/response handling were aligned with the compact core API payload shape
- Tauri event documentation now matches the implementation for `licenseseat://validation-failed`
- The Tauri plugin build script and default permission set now match the actual exported command surface, including `sync_offline_assets`

## [0.2.0] - 2026-03-02

### Added
- Background auto-validation and heartbeat tasks
- Offline license validation with Ed25519 signature verification
- Automatic offline asset syncing after activation
- Telemetry collection for usage analytics
- Cap simulation test for end-to-end offline validation

### Fixed
- Offline token endpoint now uses correct POST path with device_id body
- Base64 decoding for signatures (STANDARD encoding, not URL_SAFE)
- Request retry logic for POST requests with bodies
- Config parsing for `offlineFallbackMode` in Tauri plugin
- Compiler warnings cleaned up for production readiness

### Changed
- Entitlements now work correctly in offline mode
- Improved error messages for offline validation failures

## [0.1.0] - 2026-02-28

### Added
- Initial release
- Core SDK with license activation, validation, and deactivation
- Tauri v2 plugin with TypeScript bindings
- Configurable API endpoints and timeouts
