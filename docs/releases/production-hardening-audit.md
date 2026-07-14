# Production hardening audit

Date: 2026-07-14
Audit baseline: `v0.5.3` / `6a34776`
Scope: Rust core SDK, Tauri 2 Rust plugin, TypeScript bindings, permissions, persistence, offline interoperability, release APIs, documentation, and local release gates

## Executive summary

The work started as a parity and production-readiness pass for a real Tauri application. The adversarial review showed that API breadth was not the main remaining problem. The release-critical gaps were at trust boundaries:

- unsigned persisted online state could be mistaken for a current grant after restart;
- asynchronous responses were not globally ordered against every state-changing operation;
- several successful HTTP responses were not bound tightly enough to the requested license/product/installation;
- mutable fetched signing-key cache could become a cross-process trust anchor;
- default installation identity and raw hardware-component behavior did not meet data-minimization expectations;
- cache durability, privacy, path safety, size limits, and failure semantics were underspecified;
- generic Tauri permissions were broader than a least-privilege production renderer needs;
- renderers received globally broadcast generic lifecycle payloads even when
  they had no generic LicenseSeat command permissions;
- frontend subscriptions could overlap and deliver stale state out of order;
- Tauri state responses could combine status, validation, and entitlements from
  different concurrent commits;
- a successful health probe followed by a validation outage bypassed signed
  offline restore;
- transport features and logs could accidentally undermine the intended TLS/privacy contract;
- the committed dependency graph did not actually satisfy the declared Rust
  1.85 minimum, and its first MSRV-compatible resolution selected newly
  vulnerable XML/time parser versions in the Tauri graph;
- documentation described behavior that the code either never implemented or no longer considered safe.

This hardening pass changes the governing invariant to:

> A LicenseSeat client grants an entitlement only after the current process establishes an identity-bound authoritative online decision or verifies a signed, pinned-key offline artifact whose complete time and identity contract is valid.

Cached data remains useful for diagnostics and restoration, but mere persistence is never authority.

## Goals

1. Make activation, validation, heartbeat, deactivation, restoration, offline operation, and release discovery fail closed under malformed, substituted, replayed, stale, oversized, or partially persisted inputs.
2. Preserve the last trusted in-process grant across transient availability and unrelated protocol failures without allowing an older grant to override an authoritative denial.
3. Prove Ruby-core-to-Rust offline compatibility with generated fixtures rather than hand-authored approximations.
4. Give Tauri applications a least-privilege capability model and deterministic frontend state delivery.
5. Make privacy, TLS, storage, and logging defaults suitable for a shipped desktop application.
6. Establish a local release gate that does not depend on GitHub Actions availability.
7. Use Clipbasket as an application-level integration proving ground before publishing/tagging.

## Explicit non-goals

- packaging, notarization, code signing, artifact upload, staged rollout, automatic installation, rollback, and update UX;
- treating JavaScript UI hiding as a security boundary;
- turning a publishable client API key into a secret;
- accepting mutable network-fetched keys as offline root authority;
- inventing a new distribution token protocol in the SDK;
- silently preserving insecure legacy behavior when a clear migration error is safer.

## Threat model

The review assumes an attacker or failure can:

- edit, truncate, replace, symlink, or restore old local cache files;
- copy license/offline artifacts between products, users, installations, or activations;
- return valid JSON for the wrong request identity through a compromised/misconfigured proxy;
- delay responses so an old request finishes after activation, reset, or deactivation;
- return HTML, huge bodies, huge structured error messages, or huge outbound metadata;
- manipulate the wall clock within or beyond an allowed skew;
- trigger concurrent restore/bootstrap calls and bursty frontend events;
- inspect a desktop binary and renderer process;
- control untrusted remote content if the host grants it a Tauri capability;
- cause partial disk cleanup or persistence failure;
- observe application logs and surfaced errors;
- cause connectivity failures, timeouts, rate limiting, or server errors.

The model does not claim to defend a fully compromised host process or OS. License keys entered into a generic renderer API are visible to that renderer. A host needing a stronger boundary must expose a narrow native facade and gate native value-producing operations.

## Findings and resolutions

### 1. Startup trust was ambiguous

Finding: an unsigned cached online validation is replayable local data. Loading it after process restart must not immediately grant.

Resolution:

- a new SDK process loads cached license data as `Pending`;
- the immutable process-local authoritative state starts empty;
- `restore_license` establishes trust through online validation or valid signed-offline verification;
- validation itself is the single restore reachability/authority probe, so an
  outage after a separate health request cannot bypass signed fallback;
- `status`, `get_status`, `active_entitlements`, and entitlement helpers fail closed while pending;
- `current_license` remains explicitly diagnostic, while
  `current_authoritative_validation` never falls back to persisted data;
- plugin state conversion applies the same rule.

Regression proof:

- persisted unsigned validation cannot grant across instances;
- plugin `get_state` is inactive/untrusted before restore;
- restore reports the state that actually survived commit, not a branch-local guess.

### 2. Response substitution was possible at protocol boundaries

Finding: deserialization and HTTP success are insufficient. A response for another product/license/device can be structurally valid.

Resolution:

- activation binds object, license key, product, and fingerprint;
- validation binds object, license, product, cached identity, and nested activation/fingerprint;
- heartbeat binds object, license, and product;
- deactivation binds object and active activation ID when local identity exists;
- health requires the exact healthy contract;
- release responses bind product/channel/platform and validate pagination;
- download tokens require correct object and future expiry;
- offline token and machine-file checkout bind requested license/product/fingerprint before cache commit;
- constant-time string comparison is used for sensitive binding checks where appropriate.

Rejected responses emit the operation's terminal error event and do not emit success.

Regression proof deliberately substitutes each identity while keeping JSON valid and verifies no grant/state replacement occurs.

### 3. Stale async operations could overwrite newer state

Finding: independent per-operation concurrency was not enough. A delayed validation must not overwrite a later activation, reset, deactivation, or restoration.

Resolution:

- one monotonic operation sequence covers state-changing work;
- per-operation slots identify the current request;
- a global license-state generation invalidates incompatible in-flight work;
- a commit lock makes “is current?” and state persistence one ordered critical section;
- `state_snapshot` derives every grant-bearing observation from one critical
  section rather than composing independent public reads;
- per-product advisory file locks extend cache transaction ordering across SDK
  instances/processes that share storage;
- RAII guards clear only the slot they own;
- offline refresh has its own serialized request lock and generation;
- reset/deactivation invalidate all relevant work before cleanup.

Regression proof:

- delayed validation versus new activation;
- delayed validation versus reset;
- concurrent validation/heartbeat/status/entitlement stress;
- single-flight concurrent restoration;
- independent instances remain isolated.

### 4. Background tasks could duplicate or retain the SDK

Finding: stop/start races and strong ownership can duplicate loops or keep instances alive.

Resolution:

- generation counters and cancellation channels govern every loop;
- workers capture weak SDK state;
- restart cannot duplicate an existing generation;
- support workers are created only when at least one interval is nonzero;
- zero means disabled and cannot create a tight loop;
- bridge lag warns and continues rather than permanently ending event delivery.

Regression proof covers repeated lifecycle starts/stops and zero-interval disable behavior.

### 5. Installation identity and privacy defaults were wrong for application scope

Finding: hardware-derived identity is brittle across repair/OS behavior and unnecessarily collects stable machine data. Multiple products can also collide if persistence is not scoped.

Resolution:

- default identity is a random UUID persisted in durable application data;
- default storage prefix is deterministically product-scoped;
- existing legacy identity/cache is adopted when safe;
- storage failure is a startup error, not a silent identity rotation;
- raw fingerprint components are omitted by default;
- automatic component collection requires `send_fingerprint_components = true`;
- one checkout can explicitly supply a component map without enabling the global option;
- Tauri defaults storage to its application-data directory.

The separate telemetry option is documented by exact field classes and does not claim automatic legal compliance.

### 6. Offline trust-anchor persistence was unsafe

Finding: a signing public key fetched from the same API and written to mutable cache cannot authorize offline startup in a later process.

Resolution:

- configured public key and key ID must be a complete valid pair;
- the pair is the cross-process offline trust anchor;
- fetched keys are available only through the current runtime trust set;
- persisted fetched-key responses remain diagnostic/online cache;
- offline startup fails if the required key was not pinned into the application.

Regression proof:

- same-process fetched key verifies;
- fetched key file remains inspectable;
- a new unpinned process rejects it;
- a pinned process verifies the same Ruby-issued artifact.

### 7. Offline artifact validation needed a complete contract

Resolution enforces:

- exact algorithms and schema versions;
- bounded certificate/canonical payload sizes;
- canonical JSON equality for legacy tokens;
- Ed25519 signatures using the encoding emitted by the Ruby core;
- AES-256-GCM machine-file envelope decryption;
- license, product, fingerprint, key ID, and activation binding;
- positive and internally consistent `iat`, `nbf`, `exp`, TTL, grace, and human-readable timestamps;
- optional license expiry;
- entitlement expiry;
- maximum clock skew;
- optional maximum offline age;
- monotonic last-seen clock rollback detection;
- a process-monotonic effective clock that never moves backward, including a
  forward-then-backward wall-clock sequence after verification;
- embedded license active status/product/time window;
- denial precedence over older artifacts.

Machine-file checkout verifies before persistence. Machine-file restore accepts rich plan/product/entitlement metadata only from the signed embedded license. A valid artifact without that embedded object restores only its signed identity/time contract and no entitlements; unsigned snapshot/cache metadata cannot enrich the grant.

### 8. Cache operations needed a security/durability boundary

Resolution:

- app/product-scoped directories and filenames;
- strict cache-key/signing-key-ID path validation;
- no symlink reads or symlinked storage root;
- private permissions where supported;
- 4 MiB maximum file reads;
- serialization before replacement;
- temporary file in the destination directory, flush/sync, rename, and private mode;
- corrupt current-format files do not resurrect an older legacy grant;
- corrupt, substituted, oversized, or unreadable startup license state is an
  initialization error rather than an absent activation;
- cache transactions use a durable per-prefix advisory lock across processes;
- activation persists its new license commit marker first and reports
  identity-bound stale-artifact cleanup failures as diagnostics, so a consumed
  server seat is not lost to obsolete local cleanup;
- clearing is exact and preserves installation identity;
- denial tombstone is written before destructive cleanup;
- `try_reset` surfaces cleanup failures while `reset` remains compatibility convenience.

### 9. Transport and error handling could leak or overconsume

Resolution:

- remote plain HTTP is rejected;
- TLS verification can be disabled only on loopback;
- `rustls` and `native-tls` are truly independent reqwest features;
- HTTPS without either backend returns an actionable initialization error;
- both features are additive, with explicit rustls selection when both are enabled;
- request JSON is bounded at 1 MiB before network I/O;
- response bodies are streamed with a 4 MiB cap;
- license-key-bearing paths are not logged;
- reqwest URLs are stripped from transport errors;
- API messages are control-normalized and bounded;
- automatic background-task and Tauri restore logs use credential-safe error
  classes instead of formatting caller-visible/server-controlled diagnostics;
- HTML proxy responses become generic summaries;
- retries are restricted to transport, 408, 429, and 5xx conditions and use capped exponential delay.

Tests prove oversized requests never reach the mock server and transport errors contain neither the license key, base URL, nor license path.

### 10. Failure events were inconsistent

Finding: `?` inside successful-HTTP branches could return response-binding, crypto, or cache errors without a terminal lifecycle error event.

Resolution:

- HTTP and post-response verification/commit are normalized into one operation outcome;
- every operation emits its success events only after complete commit;
- all errors after a start/fetch event emit the matching terminal error;
- local token/machine-file verification emits explicit success/failure even for early structural/configuration errors;
- offline validation centralizes both event families so cache, commit, and
  superseded-operation errors always terminate an emitted start event;
- unrelated network/background events may interleave and are documented as such.

Tests accept interleaved global events while requiring the correct start/error pair and forbidding success for substituted responses.

### 11. Tauri configuration and capabilities were too permissive

Resolution:

- plugin setup rejects empty/whitespace keys and product slugs;
- `sk_*` keys are rejected;
- fallback-mode typos fail fast;
- release builds reject runtime `$VARIABLE` trust placeholders;
- debug builds retain placeholder convenience;
- timeout, retry, clock-skew, fingerprint-component, and storage settings map exactly to core config;
- default capability is limited to ordinary lifecycle/state/entitlement commands;
- diagnostics, advanced lifecycle/reset, raw offline management, and release commands are separate opt-in sets;
- a high-assurance native facade can disable generic renderer event
  broadcasting while retaining the complete native Rust event stream;
- `init_with_config` accepts one typed compile-time configuration instead of
  forcing an application to maintain a second JSON source of truth;
- config/admin debug output redacts API keys, signing public key, and installation override;
- detailed admin state is explicitly diagnostic/non-authoritative.

### 12. Frontend state delivery could race

Resolution:

- `subscribeState` owns one promise delivery queue;
- core `LicenseStateSnapshot` prevents the native IPC response itself from
  mixing concurrent decisions;
- state refreshes and async listeners execute serially;
- `onError` receives normalized failures;
- listener/onError failures cannot terminate later delivery;
- unsubscribe marks the stream inactive, removes all listeners, and drains queued work;
- duplicate event registrations are collapsed and partial listener-registration
  failure removes every successfully registered listener;
- heartbeat success refreshes state because heartbeat responses can change
  plans and entitlements;
- the native event bridge subscribes synchronously before automatic restore can
  emit lifecycle events;
- `bootstrapState` defaults to no redundant validation;
- nested error normalization is depth- and message-bounded;
- npm metadata declares no side effects, Node 18+, and Tauri API 2-only compatibility.

Tests prove serialized state reads/listeners, ordered snapshots, recovery after a throwing handler, queue suppression/drain during unsubscribe, structured nested errors, HTML summarization, and recursion/message limits.

### 13. Release/distribution responses required defensive validation

The SDK now validates release product/channel/platform, pagination invariants, and download-token expiry. It still deliberately does not install or authenticate artifacts by itself.

Cross-repository review found an additional server-side requirement: token issuance and token consumption must bind the licensed product and requested release in the LicenseSeat core service. That service-side remediation is a release dependency for production distribution use, even though ordinary activation/offline licensing does not depend on it.

### 14. Rust compatibility and dependency security needed separate contracts

Finding: the workspace declared Rust 1.85 while using resolver v2. A lockfile
refreshed by a newer toolchain selected ICU, Tauri-support, and time crates that
required Rust 1.86–1.88, so the advertised MSRV did not build. Resolving every
workspace package for Rust 1.85 then selected `quick-xml 0.38.4` and `time
0.3.45`, which fail current RustSec denial-of-service advisories. The patched
Tauri graph requires Rust 1.88 through `plist` and `time`.

Resolution:

- the Edition 2024 workspace uses Cargo resolver v3;
- the standalone `licenseseat` core retains and proves Rust 1.85 support;
- `tauri-plugin-licenseseat` explicitly requires and proves Rust 1.88;
- the committed lock uses `plist 1.10`, `quick-xml 0.41`, and `time 0.3.53`,
  eliminating the three known parser vulnerabilities rather than ignoring
  them;
- CI and the local gate check both declared MSRVs independently with `--locked`;
- `Cargo.lock` is committed, every CI Cargo invocation is locked, and a weekly
  RustSec job detects advisories disclosed after a release;
- a separate stable-toolchain matrix still exercises current dependencies and
  all core feature combinations;
- workspace packaging is performed in dependency order with one
  `cargo package --workspace` invocation, allowing the unpublished matching
  core crate to verify the Tauri package.

## Compatibility and behavior changes

These changes are security-significant and should be called out even when the Rust type-level API remains compatible:

| Previous assumption | Hardened behavior |
| --- | --- |
| Cached online validation could appear active at construction | It is pending until restore |
| Unsigned cached metadata could enrich a stripped machine file | Only signed embedded license metadata can grant plan/entitlements |
| Hardware-derived default fingerprint | Durable random product/app-scoped installation ID |
| Raw hardware components sent automatically | Explicit opt-in |
| Fetched signing key could support later offline startup | New process requires pinned key + ID |
| `LicenseSeat::new` could conceal initialization fallback | Same strict checks as `try_new`, panic on error |
| Any deactivation 404 could be success | Only recognized idempotent codes |
| Fallback mode spelling could silently default | Unknown values fail setup |
| Tauri default exposed every command | Least-privilege lifecycle/state/entitlements |
| Renderer state callbacks could overlap | Serialized queue |
| `get_state` called several independent accessors | One coherent core snapshot |
| Restore probed health before validation | Validation is the single restore probe |
| `bootstrapState` revalidated by default | Restore only unless explicitly requested |
| TLS backend flags were additive accidentally | Backend selection is explicit and independently tested |
| One Rust 1.85 contract covered core and Tauri | Core 1.85 + Tauri 1.88 locked CI gates; patched parser graph |

Migration guidance:

1. Use `try_new` and present initialization failures.
2. Call `restore_license` during startup and treat `Pending` as no grant.
3. Pin the offline signing public key and key ID in release configuration.
4. Gate from trusted status/entitlement helpers, not raw cache structures. A
   machine file that omits its embedded license intentionally restores no
   entitlements; configure issuance to include the signed license object when
   offline feature grants are required.
5. Review Tauri capability sets and remove broad renderer permissions.
6. If legacy hardware correlation is required, opt in intentionally and update privacy disclosure.
7. Use canonical fallback values `networkOnly` or `always`.
8. Add wildcard arms when matching `Error`, `EntitlementReason`,
   `LicenseStatus`, `ClientStatus`, `TrustedLicenseSource`, `EventKind`,
   `EventData`, or `OfflineFallbackMode`; these are non-exhaustive to avoid
   repeating this source break for future additions.

## Test inventory

The workspace suite covers:

- activation, validation, heartbeat, deactivation, reset, restore, and full lifecycle scenarios;
- entitlements, expiry, pending state, invalid state, and offline state;
- cache isolation, permissions, atomic writes, corruption, symlinks, bounds, migration, and denial precedence;
- device identity stability, alias ambiguity, and component data minimization;
- response substitution for all state/release/offline boundaries;
- concurrent requests, stale commits, task lifecycle, and restoration single-flight;
- coherent state snapshots during concurrent deactivation and terminal offline
  events after persistence failure;
- retry classification, API error shapes, URL privacy, request/response caps, and URL-prefix handling;
- Ed25519/AES/canonical JSON primitives and signed time boundaries;
- Ruby-issued machine-file and offline-token verification;
- fetched-key restart rejection and pinned-key success;
- clock rollback and rate-limited offline recovery;
- Tauri state/admin conversions, permission metadata, config validation, redaction, and release placeholder policy;
- JavaScript error normalization, state queue ordering, listener recovery, and unsubscribe semantics;
- heartbeat-driven state refresh, duplicate registration collapse, and
  pre-restore native event subscription;
- locked Rust 1.85 core and Rust 1.88 Tauri-plugin compatibility;
- patched `quick-xml`/`time` resolution with no known vulnerability failures;
- full Windows GNU cross-compilation with TLS, offline crypto, Tauri, and the
  Windows cache/atomic-replacement paths;
- Rust doc tests and package contents.

## Local release gate

GitHub Actions billing/availability is not evidence about the code. Before a release tag, run:

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

Regenerate the Ruby compatibility fixture with the checked-out LicenseSeat core and require an exact diff:

```bash
LICENSE_SEAT_CORE=/path/to/license_seat \
  ruby crates/licenseseat/tests/fixtures/generate_ruby_compat_fixtures.rb \
  > /tmp/ruby_compat.generated.json
diff -u crates/licenseseat/tests/fixtures/ruby_compat.json \
  /tmp/ruby_compat.generated.json
```

## Dependency audit

`cargo audit` reports no known vulnerability failures in the locked graph. The
gate initially found and blocked release on `RUSTSEC-2026-0194` and
`RUSTSEC-2026-0195` in `quick-xml 0.38.4`, plus `RUSTSEC-2026-0009` in `time
0.3.45`. The split MSRV and updated lock resolve them with `quick-xml 0.41.0`
and `time 0.3.53`.

The audit still reports 17 allowed warnings inherited through the current Tauri Linux webview stack:

- unmaintained GTK3/ATK/GDK bindings and `proc-macro-error`;
- unmaintained `unic-*` crates through Tauri's `urlpattern`;
- the `glib 0.18` `VariantStrIter` soundness advisory.

These dependencies are selected transitively by current Tauri 2/Wry on Linux rather than by LicenseSeat core code. They must remain visible in release notes and be re-audited whenever Tauri updates. A Linux product should additionally assess its actual WebKit/GTK runtime and packaging baseline.

## SemVer review

`cargo semver-checks` classifies `0.5.3 -> 0.6.0` as the expected pre-1.0 major
change. A second forced-minor review was used to expose every otherwise-hidden
break. Its remaining findings are intentional and documented:

- core: the `Config.send_fingerprint_components` and signed
  `MachineFilePayload.product_slug` fields, plus public enums marked
  `#[non_exhaustive]` for safe future evolution;
- Tauri: new `PluginConfig` fingerprint, retry, clock-skew, and renderer-event
  controls. `init_with_config` is an additive constructor.

The forced review also found accidental numeric discriminant movement caused
by inserted enum variants. The new variants were moved after the historical
v0.5 variants, and regression tests now pin all prior `EventKind` and
`TrustedLicenseSource` numeric values. No unreviewed semver finding remains.

## Release sequencing

Do not tag or publish from this audit branch until all of the following are true:

1. the full local gate above passes from a clean checkout;
2. `cargo semver-checks` is reviewed against `v0.5.3`;
3. Clipbasket integrates a pinned revision and passes native + renderer tests;
4. Clipbasket gates value-producing Rust commands as well as UI state;
5. the LicenseSeat core distribution product-binding issue is fixed and tested before enabling production download tokens;
6. companion SDK protocol bugs found by the audit are patched or explicitly excluded from the intended release surface;
7. version/changelog/release notes are finalized;
8. package dry-runs contain only intended files;
9. a maintainer explicitly authorizes tagging/publishing.

## Residual risks

- A compromised desktop host can inspect client state and alter its process. Server-side enforcement remains necessary for server resources.
- A renderer with LicenseSeat capability can access the generic command responses. Use a native facade for stronger isolation.
- The Linux Tauri dependency warnings remain until the framework ecosystem replaces those transitive components.
- Update packaging/signing/install/rollback are not implemented by this SDK release.
- Clock rollback detection is bounded by persisted watermark integrity and configured skew; it is not trusted hardware time.
- Offline availability depends on release-time key pinning and successful artifact refresh before disconnection.

## Production acceptance criterion

The SDK side is ready for release only when the clean local gate, semver review, generated Ruby fixture diff, and Clipbasket application integration all pass, and every cross-repository release dependency above is either closed or explicitly removed from the production feature scope.
