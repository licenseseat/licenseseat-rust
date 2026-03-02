# LicenseSeat Rust SDK

[![Crates.io](https://img.shields.io/crates/v/licenseseat.svg)](https://crates.io/crates/licenseseat)
[![Tauri Plugin](https://img.shields.io/crates/v/tauri-plugin-licenseseat.svg?label=tauri-plugin)](https://crates.io/crates/tauri-plugin-licenseseat)
[![Documentation](https://docs.rs/licenseseat/badge.svg)](https://docs.rs/licenseseat)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.70%2B-orange.svg)](https://www.rust-lang.org)

Official Rust SDK and Tauri plugin for [LicenseSeat](https://licenseseat.com) — the simple, secure licensing platform for desktop apps, games, and plugins.

## Table of Contents

- [Features](#features)
- [Packages](#packages)
- [Quick Start](#quick-start)
  - [Tauri Apps](#tauri-apps)
  - [Pure Rust](#pure-rust)
- [License Lifecycle](#license-lifecycle)
- [Entitlements](#entitlements)
- [Offline Validation](#offline-validation)
- [Heartbeat & Seat Tracking](#heartbeat--seat-tracking)
- [Event System](#event-system)
- [Configuration Reference](#configuration-reference)
- [Examples](#examples)
- [Documentation](#documentation)
- [Publishing](#publishing)
- [Other SDKs](#other-sdks)
- [License](#license)

## Features

- **License Lifecycle** — Activate, validate, and deactivate licenses with a simple API
- **Offline Validation** — Ed25519 cryptographic verification for air-gapped environments
- **Automatic Re-validation** — Background validation with configurable intervals
- **Heartbeat** — Periodic health-check pings for real-time seat tracking
- **Entitlement Management** — Fine-grained feature access control with expiration support
- **Device Telemetry** — Auto-collected device metadata (OS, platform, app version)
- **Network Resilience** — Automatic retry with exponential backoff
- **Tauri Integration** — First-class Tauri v2 plugin with TypeScript bindings
- **Secure by Default** — TLS with rustls, no unsafe code

## Packages

This monorepo contains:

| Package | Description | Links |
|---------|-------------|-------|
| [`licenseseat`](./crates/licenseseat) | Core Rust SDK for any Rust application | [![crates.io](https://img.shields.io/crates/v/licenseseat.svg)](https://crates.io/crates/licenseseat) [![docs](https://docs.rs/licenseseat/badge.svg)](https://docs.rs/licenseseat) |
| [`tauri-plugin-licenseseat`](./crates/tauri-plugin-licenseseat) | Tauri v2 plugin (Rust side) | [![crates.io](https://img.shields.io/crates/v/tauri-plugin-licenseseat.svg)](https://crates.io/crates/tauri-plugin-licenseseat) |
| [`@licenseseat/tauri-plugin`](./crates/tauri-plugin-licenseseat) | Tauri v2 plugin (JS/TS bindings) | [![npm](https://img.shields.io/npm/v/@licenseseat/tauri-plugin.svg)](https://www.npmjs.com/package/@licenseseat/tauri-plugin) |

## Quick Start

### Tauri Apps

**1. Install the Rust plugin and JS bindings:**

```bash
# Rust side
cargo add tauri-plugin-licenseseat

# JavaScript side
npm add @licenseseat/tauri-plugin
```

**2. Register the plugin in your Tauri app:**

```rust
// src-tauri/src/main.rs
fn main() {
    tauri::Builder::default()
        .plugin(tauri_plugin_licenseseat::init())
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
```

**3. Add your configuration:**

```json
// tauri.conf.json
{
  "plugins": {
    "licenseseat": {
      "apiKey": "your-api-key",
      "productSlug": "your-product"
    }
  }
}
```

**4. Add permissions:**

```json
// src-tauri/capabilities/default.json
{
  "permissions": ["licenseseat:default"]
}
```

**5. Use in your frontend:**

```typescript
import { activate, hasEntitlement, deactivate } from '@licenseseat/tauri-plugin';

// Activate a license
const license = await activate('USER-LICENSE-KEY');
console.log(`Device ID: ${license.deviceId}`);

// Check entitlements
if (await hasEntitlement('pro-features')) {
  enableProFeatures();
}

// Deactivate when uninstalling
await deactivate();
```

### Pure Rust

```bash
cargo add licenseseat
```

```rust
use licenseseat::{LicenseSeat, Config};

#[tokio::main]
async fn main() -> licenseseat::Result<()> {
    let sdk = LicenseSeat::new(Config::new("api-key", "product-slug"));

    // Activate a license
    let license = sdk.activate("USER-LICENSE-KEY").await?;
    println!("Activated! Device ID: {}", license.device_id);

    // Validate the license
    let result = sdk.validate().await?;
    if result.valid {
        println!("License is valid!");
    }

    // Check entitlements
    if sdk.has_entitlement("pro-features") {
        println!("Pro features enabled!");
    }

    // Deactivate when done
    sdk.deactivate().await?;

    Ok(())
}
```

## License Lifecycle

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│   Activate  │────▶│   Validate  │────▶│  Deactivate │
└─────────────┘     └─────────────┘     └─────────────┘
                          │
                          ▼
                    ┌─────────────┐
                    │  Heartbeat  │ (periodic)
                    └─────────────┘
```

| Method | Description |
|--------|-------------|
| `activate(key)` | Activates a license key on this device. Returns device ID and activation details. |
| `validate()` | Validates the current license. Returns validity status, entitlements, and warnings. |
| `deactivate()` | Releases the seat. Call on uninstall or when switching devices. |
| `heartbeat()` | Sends a health-check ping. Used for real-time seat tracking. |

## Entitlements

Entitlements provide fine-grained feature gating. Each entitlement has a key and optional expiration.

```rust
// Check if an entitlement is active
if sdk.has_entitlement("cloud-sync") {
    enable_cloud_sync();
}

// Get detailed status
let status = sdk.check_entitlement("pro-features");
match status.reason {
    EntitlementReason::Active => println!("Active!"),
    EntitlementReason::Expired => println!("Expired at {:?}", status.expires_at),
    EntitlementReason::NotFound => println!("Not included in plan"),
    EntitlementReason::NoLicense => println!("No active license"),
}

// List all entitlements
for entitlement in sdk.entitlements() {
    println!("{}: {:?}", entitlement.key, entitlement.expires_at);
}
```

## Offline Validation

For air-gapped or unreliable network environments, enable Ed25519 cryptographic offline validation:

```bash
cargo add licenseseat --features offline
```

```rust
use licenseseat::{Config, OfflineFallbackMode};

let config = Config {
    api_key: "your-api-key".into(),
    product_slug: "your-product".into(),
    offline_fallback_mode: OfflineFallbackMode::AllowOffline,
    max_offline_days: 7,  // Grace period
    ..Default::default()
};
```

**Fallback modes:**

| Mode | Description |
|------|-------------|
| `NetworkOnly` | Always require network validation (default) |
| `AllowOffline` | Fall back to cached offline token when network unavailable |
| `OfflineFirst` | Prefer offline validation, sync when online |

## Heartbeat & Seat Tracking

Heartbeats enable real-time seat tracking for concurrent user limits:

```rust
use std::time::Duration;

let config = Config {
    heartbeat_interval: Duration::from_secs(300), // 5 minutes
    ..Default::default()
};

// Manual heartbeat
let response = sdk.heartbeat().await?;
println!("Server received at: {}", response.received_at);
```

If heartbeats stop (app crash, network loss), the seat is released after the grace period configured in your LicenseSeat dashboard.

## Event System

Subscribe to SDK events for reactive UI updates:

```rust
use licenseseat::{LicenseSeat, EventKind};

let sdk = LicenseSeat::new(config);
let mut events = sdk.subscribe();

tokio::spawn(async move {
    while let Ok(event) = events.recv().await {
        match event.kind {
            EventKind::ActivationSuccess => println!("License activated!"),
            EventKind::ValidationFailed => println!("Validation failed"),
            EventKind::HeartbeatSuccess => println!("Heartbeat OK"),
            EventKind::HeartbeatError => println!("Heartbeat failed"),
            _ => {}
        }
    }
});
```

**Available events:**

| Event | Description |
|-------|-------------|
| `ActivationSuccess` | License successfully activated |
| `ActivationError` | Activation failed |
| `ValidationSuccess` | License validated successfully |
| `ValidationFailed` | Validation failed (invalid, expired, etc.) |
| `DeactivationSuccess` | License deactivated |
| `DeactivationError` | Deactivation failed |
| `HeartbeatSuccess` | Heartbeat acknowledged by server |
| `HeartbeatError` | Heartbeat failed |

## Configuration Reference

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `api_key` | `String` | — | Your LicenseSeat API key (required) |
| `product_slug` | `String` | — | Your product slug (required) |
| `api_base_url` | `String` | `https://licenseseat.com/api/v1` | API base URL |
| `auto_validate_interval` | `Duration` | 1 hour | Background validation interval |
| `heartbeat_interval` | `Duration` | 5 minutes | Heartbeat interval |
| `offline_fallback_mode` | `OfflineFallbackMode` | `NetworkOnly` | Offline validation behavior |
| `max_offline_days` | `u32` | `0` | Grace period for offline mode |
| `telemetry_enabled` | `bool` | `true` | Send device telemetry |
| `app_version` | `Option<String>` | `None` | Your app version (for analytics) |
| `debug` | `bool` | `false` | Enable debug logging |

## Examples

The SDK includes runnable examples:

```bash
# Simple heartbeat demo (mimics real app lifecycle)
LICENSESEAT_API_KEY=your_key \
LICENSESEAT_PRODUCT_SLUG=your_product \
LICENSESEAT_LICENSE_KEY=your_license \
cargo run --example dev_heartbeat

# Comprehensive stress test (12 scenarios)
cargo run --example stress_test
```

## Documentation

- **Core SDK:** [docs.rs/licenseseat](https://docs.rs/licenseseat)
- **Tauri Plugin:** [docs.rs/tauri-plugin-licenseseat](https://docs.rs/tauri-plugin-licenseseat)
- **Platform Docs:** [docs.licenseseat.com](https://docs.licenseseat.com)
- **API Reference:** [docs.licenseseat.com/api](https://docs.licenseseat.com/api)

## Publishing

To release a new version:

**1. Bump version in `Cargo.toml` (workspace) and `package.json`:**

```bash
# Edit Cargo.toml workspace version
# Edit crates/tauri-plugin-licenseseat/package.json version
# Edit crates/tauri-plugin-licenseseat/Cargo.toml dependency version
```

**2. Update CHANGELOG.md**

**3. Commit, tag, and push:**

```bash
git add -A
git commit -m "Bump version to X.Y.Z"
git tag -a vX.Y.Z -m "Release vX.Y.Z"
git push origin main --tags
```

**4. Create GitHub release:**

```bash
gh release create vX.Y.Z --title "vX.Y.Z" --generate-notes
```

**5. Publish to crates.io (order matters):**

```bash
# Core SDK first
cd crates/licenseseat && cargo publish

# Wait for it to be available, then Tauri plugin
cd ../tauri-plugin-licenseseat && cargo publish
```

**6. Publish to npm:**

```bash
cd crates/tauri-plugin-licenseseat
npm run build
npm publish --access public
```

## Other SDKs

| Platform | Package | Repository |
|----------|---------|------------|
| JavaScript/TypeScript | `@licenseseat/js` | [licenseseat-js](https://github.com/licenseseat/licenseseat-js) |
| Swift (macOS/iOS) | `LicenseSeat` | [licenseseat-swift](https://github.com/licenseseat/licenseseat-swift) |
| C# (.NET) | `LicenseSeat` | [licenseseat-csharp](https://github.com/licenseseat/licenseseat-csharp) |
| C++ | `licenseseat` | [licenseseat-cpp](https://github.com/licenseseat/licenseseat-cpp) |

## License

MIT License. See [LICENSE](LICENSE) for details.
