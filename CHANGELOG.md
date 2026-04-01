# Changelog

## [Unreleased]

- No unreleased changes yet.

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
