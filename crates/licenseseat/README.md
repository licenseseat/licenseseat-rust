# LicenseSeat Rust SDK

[![Crates.io](https://img.shields.io/crates/v/licenseseat.svg)](https://crates.io/crates/licenseseat)
[![Documentation](https://docs.rs/licenseseat/badge.svg)](https://docs.rs/licenseseat)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](../../LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.70%2B-orange.svg)](https://www.rust-lang.org)

Official Rust SDK for [LicenseSeat](https://licenseseat.com) — simple, secure software licensing for desktop apps, games, CLI tools, and plugins.

## Table of Contents

- [Installation](#installation)
- [Quick Start](#quick-start)
- [License Lifecycle](#license-lifecycle)
  - [Activation](#activation)
  - [Validation](#validation)
  - [Deactivation](#deactivation)
- [Entitlements](#entitlements)
- [Offline Validation](#offline-validation)
- [Heartbeat & Seat Tracking](#heartbeat--seat-tracking)
- [Event System](#event-system)
- [Configuration](#configuration)
- [Error Handling](#error-handling)
- [Telemetry & Privacy](#telemetry--privacy)
- [Examples](#examples)
- [Feature Flags](#feature-flags)
- [API Reference](#api-reference)

## Installation

Add to your `Cargo.toml`:

```bash
cargo add licenseseat
```

Or manually:

```toml
[dependencies]
licenseseat = "0.1"
```

### With Offline Validation

For Ed25519 cryptographic offline validation:

```bash
cargo add licenseseat --features offline
```

### With Native TLS

To use your system's TLS instead of rustls:

```bash
cargo add licenseseat --no-default-features --features native-tls
```

## Quick Start

```rust
use licenseseat::{LicenseSeat, Config};

#[tokio::main]
async fn main() -> licenseseat::Result<()> {
    // 1. Create SDK instance
    let sdk = LicenseSeat::new(Config::new("your-api-key", "your-product"));

    // 2. Activate a license (typically on first launch)
    let license = sdk.activate("USER-LICENSE-KEY").await?;
    println!("Activated on device: {}", license.device_id);

    // 3. Validate the license (on subsequent launches)
    let result = sdk.validate().await?;
    if result.valid {
        println!("License valid until: {:?}", result.license.expires_at);
    }

    // 4. Check entitlements for feature gating
    if sdk.has_entitlement("pro-features") {
        enable_pro_features();
    }

    // 5. Deactivate when uninstalling (releases the seat)
    sdk.deactivate().await?;

    Ok(())
}
```

## License Lifecycle

### Activation

Activation binds a license key to this device and consumes a seat:

```rust
use licenseseat::{LicenseSeat, Config, ActivationOptions};

let sdk = LicenseSeat::new(Config::new("api-key", "product"));

// Simple activation
let license = sdk.activate("USER-LICENSE-KEY").await?;
println!("Device ID: {}", license.device_id);
println!("Activation ID: {:?}", license.activation_id);

// Activation with options
let license = sdk.activate_with_options(
    "USER-LICENSE-KEY",
    ActivationOptions {
        device_name: Some("John's MacBook".into()),
        ..Default::default()
    }
).await?;
```

**When to activate:**
- First app launch with a new license key
- When the user enters a different license key
- After a deactivation (switching devices)

### Validation

Validation checks the license status without consuming a new seat:

```rust
let result = sdk.validate().await?;

if result.valid {
    println!("License is valid!");
    println!("Plan: {}", result.license.plan_key);
    println!("Entitlements: {:?}", result.license.active_entitlements);
} else {
    match result.code.as_deref() {
        Some("license_expired") => show_renewal_prompt(),
        Some("device_limit_exceeded") => show_device_limit_error(),
        Some("license_suspended") => show_suspension_notice(),
        _ => show_generic_error(),
    }
}

// Check for warnings (e.g., expiring soon)
if let Some(warnings) = &result.warnings {
    for warning in warnings {
        println!("Warning: {}", warning);
    }
}
```

**When to validate:**
- On app launch (after initial activation)
- Periodically in the background (SDK does this automatically)
- Before performing license-gated operations

### Deactivation

Deactivation releases the seat, allowing activation on another device:

```rust
// Deactivate current device
sdk.deactivate().await?;
println!("Seat released successfully");
```

**When to deactivate:**
- User clicks "Deactivate" in settings
- During app uninstall (if you have an uninstaller)
- When switching to a different license key

## Entitlements

Entitlements provide fine-grained feature gating beyond simple license validity.

### Quick Check

```rust
// Simple boolean check
if sdk.has_entitlement("cloud-sync") {
    enable_cloud_sync();
}

if sdk.has_entitlement("api-access") {
    enable_api_features();
}
```

### Detailed Status

```rust
use licenseseat::EntitlementReason;

let status = sdk.check_entitlement("pro-features");

println!("Active: {}", status.active);
println!("Expires: {:?}", status.expires_at);

match status.reason {
    EntitlementReason::Active => {
        // Entitlement is active and valid
        enable_feature();
    }
    EntitlementReason::Expired => {
        // Was active, now expired
        show_upgrade_prompt();
    }
    EntitlementReason::NotFound => {
        // Not included in the user's plan
        show_plan_upgrade_prompt();
    }
    EntitlementReason::NoLicense => {
        // No license is active
        show_activation_prompt();
    }
}
```

### List All Entitlements

```rust
for entitlement in sdk.entitlements() {
    println!("Key: {}", entitlement.key);
    println!("Expires: {:?}", entitlement.expires_at);
    println!("Metadata: {:?}", entitlement.metadata);
}
```

## Offline Validation

For environments with unreliable network or air-gapped systems, enable offline validation:

```bash
cargo add licenseseat --features offline
```

```rust
use licenseseat::{Config, OfflineFallbackMode};
use std::time::Duration;

let config = Config {
    api_key: "your-api-key".into(),
    product_slug: "your-product".into(),

    // Enable offline validation
    offline_fallback_mode: OfflineFallbackMode::AllowOffline,

    // Grace period: how long offline validation remains valid
    max_offline_days: 7,

    ..Default::default()
};

let sdk = LicenseSeat::new(config);
```

### Fallback Modes

| Mode | Behavior |
|------|----------|
| `NetworkOnly` | Always require network. Fail if offline. (Default) |
| `AllowOffline` | Try network first, fall back to cached token if unavailable |
| `OfflineFirst` | Use cached token first, sync with server when online |

### How It Works

1. On successful validation, the server returns a signed offline token
2. The token is cryptographically signed with Ed25519
3. The SDK caches the token locally
4. When offline, the SDK verifies the signature and checks expiration
5. After `max_offline_days`, the token expires and network is required

### Clock Tampering Protection

The SDK includes safeguards against clock manipulation:
- Tokens include `nbf` (not before) and `exp` (expiration) timestamps
- Significant clock jumps are detected and flagged
- Backward clock movement invalidates offline tokens

## Heartbeat & Seat Tracking

Heartbeats enable real-time seat tracking for concurrent user limits:

```rust
use std::time::Duration;

let config = Config {
    api_key: "your-api-key".into(),
    product_slug: "your-product".into(),
    heartbeat_interval: Duration::from_secs(300), // 5 minutes
    ..Default::default()
};

let sdk = LicenseSeat::new(config);

// Manual heartbeat
let response = sdk.heartbeat().await?;
println!("Acknowledged at: {}", response.received_at);
```

### Seat Release

If heartbeats stop (app crash, network loss, user closes app), the seat is released after the grace period configured in your LicenseSeat dashboard.

### Continuous Heartbeat Loop

```rust
use tokio::time::interval;

let sdk = LicenseSeat::new(config);
let sdk_clone = sdk.clone();

tokio::spawn(async move {
    let mut ticker = interval(Duration::from_secs(300));

    loop {
        ticker.tick().await;

        match sdk_clone.heartbeat().await {
            Ok(resp) => println!("Heartbeat OK: {}", resp.received_at),
            Err(e) => eprintln!("Heartbeat failed: {}", e),
        }
    }
});
```

## Event System

Subscribe to SDK events for reactive UI updates:

```rust
use licenseseat::{LicenseSeat, Config, EventKind};

let sdk = LicenseSeat::new(config);

// Get event receiver
let mut events = sdk.subscribe();

// Spawn event handler
tokio::spawn(async move {
    while let Ok(event) = events.recv().await {
        match event.kind {
            EventKind::ActivationSuccess => {
                update_ui_license_active();
            }
            EventKind::ActivationError => {
                show_activation_error();
            }
            EventKind::ValidationSuccess => {
                refresh_entitlements_ui();
            }
            EventKind::ValidationFailed => {
                show_validation_error();
            }
            EventKind::DeactivationSuccess => {
                reset_to_unlicensed_state();
            }
            EventKind::HeartbeatSuccess => {
                update_connection_indicator(true);
            }
            EventKind::HeartbeatError => {
                update_connection_indicator(false);
            }
            _ => {}
        }
    }
});
```

### Event Types

| Event | Description |
|-------|-------------|
| `ActivationSuccess` | License successfully activated |
| `ActivationError` | Activation failed (invalid key, limit exceeded, etc.) |
| `ValidationSuccess` | License validated successfully |
| `ValidationFailed` | Validation failed (expired, suspended, etc.) |
| `DeactivationSuccess` | License deactivated, seat released |
| `DeactivationError` | Deactivation failed |
| `HeartbeatSuccess` | Server acknowledged heartbeat |
| `HeartbeatError` | Heartbeat failed (network error, etc.) |

## Configuration

### Full Configuration Example

```rust
use licenseseat::{Config, OfflineFallbackMode};
use std::time::Duration;

let config = Config {
    // Required
    api_key: "your-api-key".into(),
    product_slug: "your-product".into(),

    // API endpoint (default: production)
    api_base_url: "https://licenseseat.com/api/v1".into(),

    // Background validation interval (default: 1 hour)
    auto_validate_interval: Duration::from_secs(3600),

    // Heartbeat interval (default: 5 minutes)
    heartbeat_interval: Duration::from_secs(300),

    // Offline validation (requires `offline` feature)
    offline_fallback_mode: OfflineFallbackMode::AllowOffline,
    max_offline_days: 7,

    // Telemetry
    telemetry_enabled: true,
    app_version: Some("1.2.3".into()),

    // Debug logging
    debug: false,
};

let sdk = LicenseSeat::new(config);
```

### Configuration Reference

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `api_key` | `String` | — | Your LicenseSeat API key (required) |
| `product_slug` | `String` | — | Your product slug (required) |
| `api_base_url` | `String` | `https://licenseseat.com/api/v1` | API base URL |
| `auto_validate_interval` | `Duration` | 1 hour | Background validation interval |
| `heartbeat_interval` | `Duration` | 5 minutes | Heartbeat interval |
| `offline_fallback_mode` | `OfflineFallbackMode` | `NetworkOnly` | Offline validation behavior |
| `max_offline_days` | `u32` | `0` | Grace period for offline mode (days) |
| `telemetry_enabled` | `bool` | `true` | Send device telemetry |
| `app_version` | `Option<String>` | `None` | Your app version (for analytics) |
| `debug` | `bool` | `false` | Enable debug logging |

## Error Handling

The SDK uses a unified `Error` type:

```rust
use licenseseat::{LicenseSeat, Config, Error};

async fn activate_license(sdk: &LicenseSeat, key: &str) {
    match sdk.activate(key).await {
        Ok(license) => {
            println!("Activated: {}", license.device_id);
        }
        Err(Error::InvalidLicenseKey) => {
            show_error("Invalid license key");
        }
        Err(Error::DeviceLimitExceeded) => {
            show_error("Too many devices. Deactivate one first.");
        }
        Err(Error::LicenseExpired) => {
            show_error("License has expired");
        }
        Err(Error::NetworkError(e)) => {
            show_error(&format!("Network error: {}", e));
        }
        Err(e) => {
            show_error(&format!("Unexpected error: {}", e));
        }
    }
}
```

### Error Types

| Error | Description |
|-------|-------------|
| `InvalidLicenseKey` | The license key is invalid or doesn't exist |
| `LicenseExpired` | The license has expired |
| `LicenseSuspended` | The license has been suspended |
| `DeviceLimitExceeded` | Maximum device limit reached |
| `NotActivated` | Tried to validate/deactivate without activation |
| `NetworkError` | Network request failed |
| `OfflineValidationFailed` | Offline token invalid or expired |
| `InvalidSignature` | Ed25519 signature verification failed |

## Telemetry & Privacy

The SDK collects minimal telemetry to help you understand your user base:

**Collected automatically:**
- Device ID (hardware-based, stable identifier)
- OS name and version
- Platform (e.g., "macos-arm64")
- SDK version

**You can add:**
- App version via `config.app_version`

**Not collected:**
- Personal information
- File system data
- Network information beyond API calls
- User behavior or analytics

### Disabling Telemetry

```rust
let config = Config {
    telemetry_enabled: false,
    ..Default::default()
};
```

## Examples

### DevHeartbeat

Simple demo showing the full license lifecycle:

```bash
LICENSESEAT_API_KEY=your_key \
LICENSESEAT_PRODUCT_SLUG=your_product \
LICENSESEAT_LICENSE_KEY=your_license \
cargo run --example dev_heartbeat
```

### Stress Test

Comprehensive test covering 12 scenarios:

```bash
cargo run --example stress_test
```

Scenarios tested:
1. Activation with valid key
2. Validation after activation
3. Heartbeat functionality
4. Telemetry collection
5. Entitlement checking
6. Non-existent entitlement handling
7. Offline configuration
8. Event subscription
9. Multiple subscriptions
10. Concurrent operations
11. Full lifecycle
12. SDK cloning

## Feature Flags

| Feature | Description | Dependencies Added |
|---------|-------------|--------------------|
| `default` | Uses rustls for TLS | `reqwest/rustls-tls` |
| `native-tls` | Use system TLS instead | `reqwest/native-tls` |
| `offline` | Ed25519 offline validation | `ed25519-dalek`, `sha2`, `base64` |

## API Reference

Full API documentation is available at [docs.rs/licenseseat](https://docs.rs/licenseseat).

### Key Types

```rust
// Main SDK instance
pub struct LicenseSeat { ... }

// Configuration
pub struct Config { ... }
pub enum OfflineFallbackMode { NetworkOnly, AllowOffline, OfflineFirst }

// License data
pub struct License { ... }
pub enum LicenseStatus { Active, Expired, Suspended, Revoked }

// Entitlements
pub struct Entitlement { ... }
pub struct EntitlementStatus { ... }
pub enum EntitlementReason { Active, Expired, NotFound, NoLicense }

// Events
pub struct Event { ... }
pub enum EventKind { ... }

// Responses
pub struct ValidationResult { ... }
pub struct ActivationResponse { ... }
pub struct DeactivationResponse { ... }
pub struct HeartbeatResponse { ... }

// Errors
pub enum Error { ... }
pub type Result<T> = std::result::Result<T, Error>;
```

## License

MIT License. See [LICENSE](../../LICENSE) for details.
