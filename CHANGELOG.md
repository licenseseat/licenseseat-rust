# Changelog

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
