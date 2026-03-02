# LicenseSeat Rust SDK

Official Rust SDK for [LicenseSeat](https://licenseseat.com) — simple, secure software licensing.

## Installation

```bash
cargo add licenseseat
```

For offline validation support:

```bash
cargo add licenseseat --features offline
```

## Quick Start

```rust
use licenseseat::{LicenseSeat, Config};

#[tokio::main]
async fn main() -> licenseseat::Result<()> {
    // Create SDK instance
    let sdk = LicenseSeat::new(Config::new("your-api-key", "your-product"));

    // Activate a license
    let license = sdk.activate("USER-LICENSE-KEY").await?;
    println!("Activated! Device: {}", license.device_id);

    // Check entitlements
    if sdk.has_entitlement("pro-features") {
        println!("Pro features enabled!");
    }

    // Validate periodically
    let result = sdk.validate().await?;
    println!("Valid: {}", result.valid);

    // Deactivate when done
    sdk.deactivate().await?;

    Ok(())
}
```

## Configuration

```rust
use licenseseat::{Config, OfflineFallbackMode};
use std::time::Duration;

let config = Config {
    api_key: "your-api-key".into(),
    product_slug: "your-product".into(),
    auto_validate_interval: Duration::from_secs(1800), // 30 minutes
    heartbeat_interval: Duration::from_secs(300),      // 5 minutes
    offline_fallback_mode: OfflineFallbackMode::NetworkOnly,
    max_offline_days: 7,
    debug: true,
    ..Default::default()
};

let sdk = LicenseSeat::new(config);
```

## Features

- `default` — Uses rustls for TLS
- `native-tls` — Use system TLS instead
- `offline` — Enable Ed25519 offline validation

## License

MIT
