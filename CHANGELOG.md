# Changelog

## [Unreleased]

## [0.6.4] - Unreleased (proposed)

### Fixed

- **Authoritative denials never fall back to the offline grant.** A
  validation answered with `version_not_entitled`, `not_entitled`,
  `product_mismatch`, `floating_not_implemented` or
  `named_user_not_implemented` (codes compared case-insensitively), whether
  thrown or returned as `200 valid:false`, is now the current decision in
  both `OfflineFallbackMode`s:
  - 501 `floating_not_implemented` / `named_user_not_implemented` were
    classified as network errors (5xx) and answered by the cached signed
    grant, in both modes.
  - A thrown 403 `not_entitled` / `version_not_entitled` changed nothing:
    the SDK stayed entitled, and a later outage or relaunch kept the grant.
  - The denial is now persisted as a `valid:false` validation and the
    runtime state becomes a fail-closed denial, so a later outage or an
    offline relaunch answers with the denial, not the grant.
  - The signed grant is **kept** (it was purged for `valid:false` denials and
    422 `product_mismatch`, which also removed the activation); the next
    online `valid:true` restores entitlement. Revocation/suspension still
    purge.
  - 401/403/429/5xx without one of these codes keep their existing fallback.
- Entitlement-expiry `license:state-changed` events are now emitted by the
  first observation at or after the entitlement's real expiry. The SDK
  detects entitlement transitions when its license state is observed
  (`check_entitlement`, `has_entitlement`, `status`, snapshots, ...); the
  transition deadline was truncated to whole seconds while observations
  compare the full-precision `expires_at`, so an observation in the last
  partial second before expiry announced a state change that still listed
  the entitlement as active, cleared the deadline, and then announced nothing
  when the entitlement really lapsed. Subscribers could keep showing an
  expired entitlement until some unrelated state change. (#9)
- One observation now uses one instant: the transition check and the answer
  returned to the caller share the same `now`. Previously the caller
  re-sampled the clock, so an observation straddling the expiry could return
  "expired" while leaving the notification pending.
- The in-process anti-rollback clock (monotonic floor and high-water mark)
  keeps sub-second precision. Truncating it let a wall-clock rollback move
  effective time back to the start of the current second, so an entitlement
  already observed (and announced) as expired could read as active again for
  up to a second, then lapse with no event.
- The anti-rollback clock now holds across runtime-state replacements in
  one process. Re-installing state from a signed offline artifact (for
  example an offline revalidation during an outage) used to anchor a fresh
  clock at the wall clock, so after a wall-clock rollback an artifact whose
  deadline had already passed in process time verified again. Offline and
  denial installs now inherit the process-wide floor, and offline
  revalidation judges the artifact's deadline at that time; an
  authenticated online answer still re-anchors to the wall clock, as it
  re-anchors the persisted watermark.
- State-change announcements reach subscribers in the order they were
  claimed. Concurrent observers released the state lock before publishing,
  so a later "nothing left" announcement could overtake an earlier one
  that still listed an entitlement, leaving subscribers on stale state.
- `restore_license` on an already-established state answers from one
  observation; it returned the raw validation (still listing a lapsed
  entitlement) beside a status computed at another instant.

### Tests

- `entitlement_expiry_notifies_subscribers_and_revokes_access_in_process` no
  longer depends on scheduling: it subscribes before activating, stamps the
  expiry when the mock server responds, waits on the wall clock instead of a
  fixed sleep, and asserts emitted events synchronously. (#9)
- Three more tests asserted inside fixed wall-clock budgets that durable
  cache commits (`File::sync_all` is `F_FULLFSYNC` on macOS) overran under
  parallel load: `revoked_auto_validation_does_not_send_a_followup_heartbeat`
  now waits for `license:revoked`;
  `test_support_tasks_do_not_duplicate_after_restart` checks request
  spacing instead of counting inside 40 ms windows; and
  `signed_offline_runtime_grant_expires_without_process_restart` stamps its
  5 s machine-file window when the file is first served. (#12)
- Review follow-ups for those tests (#12): the duplicate-loop test now
  bounds the number of short request gaps after the restart instead of
  skipping its check when activation is slow; the revocation test uses the
  event stream closing after the SDK is dropped as a barrier for the whole
  auto-validation cycle; the offline-expiry test accepts a successful
  checkout whenever it returns and only accepts a refusal once the window
  has provably closed; and the in-process expiry of a signed offline grant
  is now also covered deterministically by
  `runtime_state_tests::signed_offline_grant_expires_in_process`.

## [0.6.3] - 2026-08-19

### Added

- `Entitlement::covers_version`: the client-side half of the server's
  version gate, so apps enforcing the ceiling locally (belt-and-suspenders
  for requests that never declared a version) share one tested comparison
  instead of hand-rolling it. Matches the server's rule exactly —
  exclusive, core versions, lenient parsing (`"3.0"` counts as `3.0.0`),
  fail-open on unparseable strings.

## [0.6.2] - 2026-08-19

### Added

- `Entitlement.below_version`: the server's exclusive core-semver version
  ceiling on the `updates` entitlement (LicenseSeat API 2026-08-19). `None`
  from older servers; offline artifacts do not carry it yet by design.
- Version-gating compatibility tests pinning the three contracts the
  server-side gate stands on: `below_version` parses (and its absence stays
  `None`), a `version_not_entitled` validation refusal surfaces its code
  through the SDK, and `telemetry.app_version` — which the server's gate
  reads — actually rides licensing request bodies when telemetry is enabled.

## [0.6.1] - 2026-08-17

### Fixed

- Telemetry now reports the real macOS/iOS product version (for example
  `15.7.3`) instead of `unknown`. It reads the `kern.osproductversion` sysctl
  — not `kern.osrelease`, which is the Darwin kernel version — and falls back
  to `ProductVersion` in `/System/Library/CoreServices/SystemVersion.plist` on
  systems predating that sysctl.
- Telemetry now reports `memory_gb` on macOS/iOS from the `hw.memsize` sysctl,
  using the same truncating GB conversion as the Linux `/proc/meminfo` path.
  The field was previously omitted on every non-Linux platform.
- Telemetry now reports the real Windows version (for example `10.0.26100`)
  instead of `unknown`. It reads `ntdll!RtlGetVersion`, which — unlike
  `GetVersionExW` — is never shimmed to 6.2 for host applications whose
  manifest omits a `supportedOS` entry, so the reading does not depend on how
  the embedding application is manifested.
- Telemetry now reports `memory_gb` on Windows from `GlobalMemoryStatusEx`
  (`ullTotalPhys`), using the same truncating GB conversion as the macOS and
  Linux paths. With this and the macOS fix, `os_version` and `memory_gb` are
  populated on every desktop platform the SDK supports.
- `device_type` now distinguishes iPad from iPhone on iOS by reading the
  `hw.machine` model identifier, rather than always reporting `phone`.
- `get_latest_release` and `list_releases` no longer reject releases whose
  `platform` is `"any"`. The server's `by_platform` scope matches
  `platform = ? OR platform = 'any'`, so a request filtered to a specific
  platform legitimately resolves to a cross-platform release; the SDK failed
  closed on products publishing a single universal artifact. Platforms outside
  the requested filter are still rejected.
- `list_releases_with_options` no longer errors when `has_more` is true and
  `next_cursor` is absent or empty. The releases index derives `has_more` from
  the page count while leaving `next_cursor` unset, so cross-checking the two
  fields rejected valid paginated responses.

## [0.6.0] - 2026-08-10

A minor version bump is required because the hardening adds fields to public
configuration/signed-payload structs and adds fail-closed public error/reason
variants.

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
- Opaque SHA-256 cache namespaces, one-way legacy-cache migration, strict JSON
  duplicate-key rejection, and explicit offline-artifact complexity limits.

### Changed

- The Tauri plugin MSRV is now Rust 1.88 so its lockfile can use patched
  `quick-xml >=0.41` and `time >=0.3.47`; the standalone core remains Rust 1.85.
- The audited workspace lockfile is committed, all CI Cargo commands use
  `--locked`, and a scheduled RustSec audit prevents silent dependency drift.
- The Tauri dependency disables unused default features. This reduces the
  transitive desktop dependency graph while retaining the base runtime needed
  by the plugin.
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
- HTTP redirects are no longer followed (0.5.3 followed up to 10);
  `api_base_url` must point at the canonical, redirect-free API endpoint.
- New `device_identifier`/fingerprint configuration and creation input must be
  8-255 characters. Fingerprints and installation identifiers sourced from an
  existing cached activation are exempt, so seats activated before the floor
  (or by another SDK without it) can still validate, heartbeat, deactivate,
  and be adopted instead of burning a second seat.
- `max_retries` above 10 now fails construction with a configuration error.
- The Tauri admin snapshot replaces `apiKey`, `deviceIdentifier`,
  `signingPublicKey`, and `SigningKeyRecord.publicKey` with
  `apiKeyConfigured`/`deviceIdentifierConfigured`/`signingPublicKeyConfigured`/
  `publicKeyConfigured` presence booleans and removes
  `cachePaths.signingKeyPath`; `PluginConfig` is no longer `app.manage`d.
- `activateAndGetState` no longer issues an extra validation request; it
  returns the activation plus one state snapshot.
- The clock-rollback watermark (`last_seen_ts`) now survives `clear()`/reset
  like the installation identifier. Authoritative online successes
  (activation, validation, heartbeat) re-anchor it — and may lower it, which
  recovers installations poisoned by a transiently future-set clock — while
  offline verification still only ratchets it forward.

### Fixed

- Prevented substituted or stale responses from creating, replacing, or
  deleting the wrong local grant.
- Prevented cached fetched keys, corrupt current cache files, symlinked paths,
  and legacy fallback files from becoming unintended trust roots.
- Prevented product slugs from appearing in cache filenames or lock names,
  rejected Windows reparse-point cache handles, and made legacy adoption
  transactional before legacy files are removed.
- Rejected duplicate JSON object keys and bounded offline envelope fields,
  nested metadata, entitlement counts, ciphertext, lifetimes, and PEM lines
  before expensive parsing or cryptographic work.
- Made corrupt/unreadable startup license state an actionable initialization
  error instead of silently treating it as a missing activation.
- Fixed validation authentication classification to use HTTP 401/403 rather
  than 401/501.
- Fixed missing terminal error events for response-verification, crypto, cache,
  and superseded-operation failures after a lifecycle start/fetch event.
- Prevented logs and surfaced reqwest errors from exposing license keys embedded
  in request paths.
- Redacted API/transport diagnostics from automatic validation, heartbeat,
  offline-refresh, activation-support, and Tauri restore logs; direct callers
  and typed lifecycle events retain their explicit diagnostic contract.
- Prevented concurrent frontend state handlers from overlapping or observing
  out-of-order snapshots.
- Prevented Tauri state responses from mixing fields across concurrent commits,
  ensured the native event bridge subscribes before automatic restore, and
  refreshed renderer state after heartbeat-delivered entitlement changes.
- Fixed signed-offline fallback when health would succeed but validation itself
  returns a transient outage, and guaranteed terminal offline failure events
  for cache/commit errors.
- Bound cached machine-file verification during offline validation to the
  expected license key, so a restored foreign-license artifact fails
  verification with `LICENSE_MISMATCH` instead of emitting
  `MachineFileVerified` and relying on the final grant binding.
- Moved the synchronous Tauri commands (status/state/entitlement/license
  reads, offline verification helpers, and reset) onto the blocking pool so
  the core commit mutex, cross-process file lock, crypto, and cache IO can no
  longer stall Tauri's main thread.
- Added a plugin test that pins the triplicated command registry: the
  `build.rs` command list and the default plus opt-in permission sets must
  exactly partition the command surface.
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
