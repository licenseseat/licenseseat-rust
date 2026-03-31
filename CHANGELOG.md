# Changelog

## [Unreleased]

### Added
- High-level Tauri JS helpers for consolidated state snapshots, state subscriptions, stable event constants, and grouped entitlement checks
- New plugin `get_state` command that exposes status, validation, entitlements, plan key, fingerprint, and online/offline flags in one response
- Expanded generated permission coverage for the full Tauri command surface, including offline/manual workflow and release APIs

### Changed
- The JS bindings now ship a production-oriented integration path centered on `getState()` and `subscribeState()`
- The npm package now builds during `prepare`/`prepack` and is validated in CI with explicit build and pack checks
- Root and plugin README examples now use the higher-level state/event helpers instead of raw event strings and ad hoc status polling

### Fixed
- The Tauri plugin build script now matches the actual command surface instead of a stale subset
- Generated JS `dist` artifacts, types, and examples are now checked in CI so source/package drift is caught before release

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
- Direct plugin-side unit coverage for command payload conversions and structured event serialization

### Changed
- The Rust SDK now defaults to the same fingerprinting strategy and identifier shape as the C++ reference implementation
- Background support-task lifecycle handling now prevents duplicated loops across stop/start cycles
- Tauri status values are normalized to the stable snake_case contract: `offline_valid` and `offline_invalid`
- Public docs and examples now reflect the parity-expanded Rust and Tauri surfaces

### Fixed
- Legacy offline-token fallback now remains reachable when machine-file verification/setup fails
- Restore/offline fallback behavior now follows the configured fallback policy more closely
- Machine-file test fixtures and request/response handling were aligned with the compact core API payload shape
- Tauri event documentation now matches the implementation for `licenseseat://validation-failed`

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
