# LicenseSeat Tauri Plugin

Tauri plugin for [LicenseSeat](https://licenseseat.com) software licensing.

## Installation

### Rust

```bash
cargo add tauri-plugin-licenseseat
```

### JavaScript/TypeScript

```bash
npm add @licenseseat/tauri-plugin
# or
pnpm add @licenseseat/tauri-plugin
```

## Setup

### 1. Register the plugin

```rust
// src-tauri/src/main.rs
fn main() {
    tauri::Builder::default()
        .plugin(tauri_plugin_licenseseat::init())
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
```

### 2. Add configuration

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

### 3. Add permissions

```json
// src-tauri/capabilities/default.json
{
  "permissions": [
    "licenseseat:default"
  ]
}
```

## Usage

```typescript
import {
  activate,
  deactivate,
  getStatus,
  hasEntitlement
} from '@licenseseat/tauri-plugin';

// Activate a license
const license = await activate('USER-LICENSE-KEY');
console.log(`Device ID: ${license.deviceId}`);

// Check status
const status = await getStatus();
if (status.status === 'active') {
  console.log('License is active!');
}

// Check entitlements
if (await hasEntitlement('pro-features')) {
  enableProFeatures();
}

// Deactivate
await deactivate();
```

## Configuration Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `apiKey` | string | — | Your LicenseSeat API key (required) |
| `productSlug` | string | — | Your product slug (required) |
| `apiBaseUrl` | string | `https://licenseseat.com/api/v1` | API base URL |
| `autoValidateInterval` | number | `3600` | Auto-validation interval (seconds) |
| `heartbeatInterval` | number | `300` | Heartbeat interval (seconds) |
| `maxOfflineDays` | number | `0` | Max offline days (0 = disabled) |
| `telemetryEnabled` | boolean | `true` | Enable telemetry |
| `debug` | boolean | `false` | Enable debug logging |

## License

MIT
