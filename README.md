# LicenseSeat Rust SDK

Official Rust SDK and Tauri plugin for [LicenseSeat](https://licenseseat.com) — the simple, secure licensing platform for apps, games, and plugins.

## Packages

This monorepo contains two crates:

| Crate | Description | crates.io |
|-------|-------------|-----------|
| [`licenseseat`](./crates/licenseseat) | Core Rust SDK for any Rust application | [![crates.io](https://img.shields.io/crates/v/licenseseat.svg)](https://crates.io/crates/licenseseat) |
| [`tauri-plugin-licenseseat`](./crates/tauri-plugin-licenseseat) | Tauri plugin with JS bindings | [![crates.io](https://img.shields.io/crates/v/tauri-plugin-licenseseat.svg)](https://crates.io/crates/tauri-plugin-licenseseat) |

## Quick Start

### For Tauri Apps

```bash
# Add the plugin
cargo add tauri-plugin-licenseseat

# Add the JS bindings
npm add @licenseseat/tauri-plugin
```

```rust
// src-tauri/src/main.rs
fn main() {
    tauri::Builder::default()
        .plugin(tauri_plugin_licenseseat::init())
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
```

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

```typescript
// In your frontend
import { activate, hasEntitlement } from '@licenseseat/tauri-plugin';

const license = await activate('USER-LICENSE-KEY');

if (await hasEntitlement('pro-features')) {
  // Enable pro features
}
```

### For Pure Rust Applications

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

    // Check entitlements
    if sdk.has_entitlement("pro-features") {
        println!("Pro features enabled!");
    }

    Ok(())
}
```

## Features

- **License Lifecycle** — Activate, validate, and deactivate licenses
- **Offline Validation** — Ed25519 cryptographic verification (optional)
- **Automatic Re-validation** — Background validation with configurable intervals
- **Heartbeat** — Periodic health-check pings for real-time seat tracking
- **Entitlement Management** — Fine-grained feature access control
- **Device Telemetry** — Auto-collected device metadata for analytics
- **Network Resilience** — Automatic retry with exponential backoff

## Documentation

- [Core SDK Documentation](https://docs.rs/licenseseat)
- [Tauri Plugin Documentation](https://docs.rs/tauri-plugin-licenseseat)
- [LicenseSeat Platform Docs](https://docs.licenseseat.com)

## Other SDKs

- [JavaScript SDK](https://github.com/licenseseat/licenseseat-js) — `@licenseseat/js`
- [Swift SDK](https://github.com/licenseseat/licenseseat-swift) — For macOS/iOS apps
- [C# SDK](https://github.com/licenseseat/licenseseat-csharp) — For .NET applications
- [C++ SDK](https://github.com/licenseseat/licenseseat-cpp) — For native applications

## License

MIT License. See [LICENSE](LICENSE) for details.
