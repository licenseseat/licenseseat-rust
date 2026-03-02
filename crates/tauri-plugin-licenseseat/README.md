# LicenseSeat Tauri Plugin

[![Crates.io](https://img.shields.io/crates/v/tauri-plugin-licenseseat.svg)](https://crates.io/crates/tauri-plugin-licenseseat)
[![npm](https://img.shields.io/npm/v/@licenseseat/tauri-plugin.svg)](https://www.npmjs.com/package/@licenseseat/tauri-plugin)
[![Documentation](https://docs.rs/tauri-plugin-licenseseat/badge.svg)](https://docs.rs/tauri-plugin-licenseseat)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](../../LICENSE)
[![Tauri](https://img.shields.io/badge/tauri-v2-24C8D8.svg)](https://v2.tauri.app)

Official Tauri v2 plugin for [LicenseSeat](https://licenseseat.com) — simple, secure software licensing for your Tauri apps.

## Table of Contents

- [Features](#features)
- [Requirements](#requirements)
- [Installation](#installation)
- [Setup](#setup)
- [Usage](#usage)
  - [TypeScript/JavaScript](#typescriptjavascript)
  - [Rust (Backend)](#rust-backend)
- [API Reference](#api-reference)
- [Configuration](#configuration)
- [Entitlements](#entitlements)
- [Event Handling](#event-handling)
- [Offline Support](#offline-support)
- [React Integration](#react-integration)
- [Vue Integration](#vue-integration)
- [Svelte Integration](#svelte-integration)
- [Error Handling](#error-handling)
- [Security](#security)
- [Troubleshooting](#troubleshooting)

## Features

- **Full License Lifecycle** — Activate, validate, deactivate from your frontend
- **TypeScript Bindings** — Fully typed API with autocomplete
- **Entitlement Checking** — Feature gating made simple
- **Event System** — React to license changes in real-time
- **Offline Support** — Ed25519 cryptographic validation (optional)
- **Zero Config** — Just add your API key and product slug
- **Tauri v2** — Built for the latest Tauri architecture

## Requirements

- Tauri v2.0.0 or later
- Rust 1.70+
- Node.js 18+ (for the JS bindings)

## Installation

### 1. Add the Rust Plugin

```bash
cd src-tauri
cargo add tauri-plugin-licenseseat
```

### 2. Add the JavaScript Bindings

```bash
# npm
npm add @licenseseat/tauri-plugin

# pnpm
pnpm add @licenseseat/tauri-plugin

# yarn
yarn add @licenseseat/tauri-plugin

# bun
bun add @licenseseat/tauri-plugin
```

## Setup

### 1. Register the Plugin

```rust
// src-tauri/src/main.rs (or lib.rs for Tauri v2)
fn main() {
    tauri::Builder::default()
        .plugin(tauri_plugin_licenseseat::init())
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
```

### 2. Add Configuration

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

### 3. Add Permissions

```json
// src-tauri/capabilities/default.json
{
  "identifier": "default",
  "windows": ["main"],
  "permissions": [
    "core:default",
    "licenseseat:default"
  ]
}
```

The `licenseseat:default` permission grants access to all licensing commands. For fine-grained control, see [Permissions](#permissions).

## Usage

### TypeScript/JavaScript

```typescript
import {
  activate,
  validate,
  deactivate,
  getStatus,
  hasEntitlement,
  checkEntitlement,
  heartbeat
} from '@licenseseat/tauri-plugin';

// Activate a license (first launch or new key)
async function activateLicense(key: string) {
  try {
    const license = await activate(key);
    console.log(`Activated! Device ID: ${license.deviceId}`);
    return license;
  } catch (error) {
    console.error('Activation failed:', error);
    throw error;
  }
}

// Validate the current license (subsequent launches)
async function validateLicense() {
  const result = await validate();

  if (result.valid) {
    console.log('License is valid!');
    console.log('Plan:', result.license.planKey);
    return true;
  } else {
    console.log('Invalid:', result.code, result.message);
    return false;
  }
}

// Check entitlements for feature gating
async function checkFeatures() {
  if (await hasEntitlement('pro-features')) {
    enableProFeatures();
  }

  if (await hasEntitlement('cloud-sync')) {
    enableCloudSync();
  }
}

// Get current license status
async function showStatus() {
  const status = await getStatus();

  switch (status.status) {
    case 'active':
      showActiveBadge();
      break;
    case 'expired':
      showRenewalPrompt();
      break;
    case 'not_activated':
      showActivationPrompt();
      break;
  }
}

// Deactivate (release the seat)
async function deactivateLicense() {
  await deactivate();
  console.log('License deactivated');
}
```

### Rust (Backend)

Access the SDK directly from Rust for advanced use cases:

```rust
use tauri::Manager;
use tauri_plugin_licenseseat::LicenseSeatExt;

#[tauri::command]
async fn custom_validation(app: tauri::AppHandle) -> Result<bool, String> {
    let sdk = app.licenseseat();

    match sdk.validate().await {
        Ok(result) => Ok(result.valid),
        Err(e) => Err(e.to_string()),
    }
}
```

## API Reference

### Functions

| Function | Description | Returns |
|----------|-------------|---------|
| `activate(key)` | Activate a license key | `Promise<License>` |
| `validate()` | Validate current license | `Promise<ValidationResult>` |
| `deactivate()` | Deactivate and release seat | `Promise<void>` |
| `getStatus()` | Get current license status | `Promise<LicenseStatus>` |
| `hasEntitlement(key)` | Check if entitlement is active | `Promise<boolean>` |
| `checkEntitlement(key)` | Get detailed entitlement status | `Promise<EntitlementStatus>` |
| `heartbeat()` | Send heartbeat ping | `Promise<HeartbeatResponse>` |
| `getEntitlements()` | List all entitlements | `Promise<Entitlement[]>` |

### Types

```typescript
interface License {
  key: string;
  status: 'active' | 'expired' | 'suspended' | 'revoked';
  planKey: string;
  seatLimit: number;
  expiresAt?: string;
  deviceId: string;
  activationId?: string;
}

interface ValidationResult {
  valid: boolean;
  code?: string;
  message?: string;
  warnings?: string[];
  license: License;
}

interface LicenseStatus {
  status: 'active' | 'expired' | 'suspended' | 'not_activated';
  license?: License;
  expiresAt?: string;
}

interface Entitlement {
  key: string;
  expiresAt?: string;
  metadata?: Record<string, unknown>;
}

interface EntitlementStatus {
  active: boolean;
  reason: 'active' | 'expired' | 'not_found' | 'no_license';
  expiresAt?: string;
}

interface HeartbeatResponse {
  receivedAt: string;
}
```

## Configuration

### Full Configuration Options

```json
// tauri.conf.json
{
  "plugins": {
    "licenseseat": {
      "apiKey": "your-api-key",
      "productSlug": "your-product",
      "apiBaseUrl": "https://licenseseat.com/api/v1",
      "autoValidateInterval": 3600,
      "heartbeatInterval": 300,
      "offlineFallbackMode": "network_only",
      "maxOfflineDays": 0,
      "telemetryEnabled": true,
      "debug": false
    }
  }
}
```

### Configuration Reference

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `apiKey` | `string` | — | Your LicenseSeat API key (required) |
| `productSlug` | `string` | — | Your product slug (required) |
| `apiBaseUrl` | `string` | `https://licenseseat.com/api/v1` | API base URL |
| `autoValidateInterval` | `number` | `3600` | Background validation interval (seconds) |
| `heartbeatInterval` | `number` | `300` | Heartbeat interval (seconds) |
| `offlineFallbackMode` | `string` | `"network_only"` | `"network_only"`, `"allow_offline"`, or `"offline_first"` |
| `maxOfflineDays` | `number` | `0` | Grace period for offline mode (days) |
| `telemetryEnabled` | `boolean` | `true` | Send device telemetry |
| `debug` | `boolean` | `false` | Enable debug logging |

### Environment-Specific Config

Use Tauri's environment configuration for different API keys:

```json
// tauri.conf.json (development)
{
  "plugins": {
    "licenseseat": {
      "apiKey": "$LICENSESEAT_DEV_API_KEY",
      "productSlug": "my-app-dev"
    }
  }
}
```

## Entitlements

### Simple Check

```typescript
if (await hasEntitlement('cloud-sync')) {
  enableCloudSync();
}
```

### Detailed Status

```typescript
const status = await checkEntitlement('pro-features');

if (status.active) {
  enableProFeatures();
} else {
  switch (status.reason) {
    case 'expired':
      showUpgradePrompt('Your Pro features have expired');
      break;
    case 'not_found':
      showUpgradePrompt('Upgrade to Pro for this feature');
      break;
    case 'no_license':
      showActivationPrompt();
      break;
  }
}
```

### List All Entitlements

```typescript
const entitlements = await getEntitlements();

for (const ent of entitlements) {
  console.log(`${ent.key}: expires ${ent.expiresAt ?? 'never'}`);
}
```

## Event Handling

Listen to license events from Rust using Tauri's event system:

```typescript
import { listen } from '@tauri-apps/api/event';

// Listen for license events
await listen('licenseseat://validation-success', (event) => {
  console.log('License validated!', event.payload);
  refreshUI();
});

await listen('licenseseat://validation-failed', (event) => {
  console.log('Validation failed:', event.payload);
  showLicenseError();
});

await listen('licenseseat://heartbeat-success', () => {
  updateConnectionStatus(true);
});

await listen('licenseseat://heartbeat-error', () => {
  updateConnectionStatus(false);
});
```

### Available Events

| Event | Payload | Description |
|-------|---------|-------------|
| `licenseseat://activation-success` | `License` | License activated |
| `licenseseat://activation-error` | `string` | Activation failed |
| `licenseseat://validation-success` | `ValidationResult` | Validation succeeded |
| `licenseseat://validation-failed` | `string` | Validation failed |
| `licenseseat://deactivation-success` | — | License deactivated |
| `licenseseat://heartbeat-success` | — | Heartbeat acknowledged |
| `licenseseat://heartbeat-error` | `string` | Heartbeat failed |

## Offline Support

Enable offline validation for air-gapped or unreliable network environments:

```json
{
  "plugins": {
    "licenseseat": {
      "offlineFallbackMode": "allow_offline",
      "maxOfflineDays": 7
    }
  }
}
```

**Modes:**

| Mode | Description |
|------|-------------|
| `network_only` | Always require network (default) |
| `allow_offline` | Fall back to cached token when offline |
| `offline_first` | Prefer offline, sync when online |

## React Integration

```tsx
import { useState, useEffect } from 'react';
import { getStatus, hasEntitlement, activate } from '@licenseseat/tauri-plugin';

function useLicense() {
  const [status, setStatus] = useState<LicenseStatus | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    getStatus()
      .then(setStatus)
      .finally(() => setLoading(false));
  }, []);

  return { status, loading };
}

function useEntitlement(key: string) {
  const [active, setActive] = useState(false);

  useEffect(() => {
    hasEntitlement(key).then(setActive);
  }, [key]);

  return active;
}

// Usage
function App() {
  const { status, loading } = useLicense();
  const hasProFeatures = useEntitlement('pro-features');

  if (loading) return <Loading />;

  if (status?.status !== 'active') {
    return <ActivationScreen />;
  }

  return (
    <div>
      <h1>Welcome!</h1>
      {hasProFeatures && <ProFeatures />}
    </div>
  );
}
```

## Vue Integration

```vue
<script setup lang="ts">
import { ref, onMounted } from 'vue';
import { getStatus, hasEntitlement } from '@licenseseat/tauri-plugin';

const status = ref<LicenseStatus | null>(null);
const hasProFeatures = ref(false);

onMounted(async () => {
  status.value = await getStatus();
  hasProFeatures.value = await hasEntitlement('pro-features');
});
</script>

<template>
  <div v-if="status?.status === 'active'">
    <h1>Welcome!</h1>
    <ProFeatures v-if="hasProFeatures" />
  </div>
  <ActivationScreen v-else />
</template>
```

## Svelte Integration

```svelte
<script lang="ts">
  import { onMount } from 'svelte';
  import { getStatus, hasEntitlement } from '@licenseseat/tauri-plugin';

  let status: LicenseStatus | null = null;
  let hasProFeatures = false;

  onMount(async () => {
    status = await getStatus();
    hasProFeatures = await hasEntitlement('pro-features');
  });
</script>

{#if status?.status === 'active'}
  <h1>Welcome!</h1>
  {#if hasProFeatures}
    <ProFeatures />
  {/if}
{:else}
  <ActivationScreen />
{/if}
```

## Error Handling

```typescript
import { activate } from '@licenseseat/tauri-plugin';

try {
  const license = await activate(key);
  showSuccess('License activated!');
} catch (error) {
  // Error is a string message from the backend
  const message = error as string;

  if (message.includes('invalid')) {
    showError('Invalid license key');
  } else if (message.includes('limit')) {
    showError('Device limit reached. Deactivate another device first.');
  } else if (message.includes('expired')) {
    showError('This license has expired');
  } else if (message.includes('network')) {
    showError('Network error. Please check your connection.');
  } else {
    showError(`Activation failed: ${message}`);
  }
}
```

## Security

### API Key Protection

Your API key is stored in `tauri.conf.json` and compiled into your app binary. It is not exposed to the JavaScript frontend.

### Permissions

The plugin uses Tauri's permission system. Available permissions:

| Permission | Description |
|------------|-------------|
| `licenseseat:default` | All commands (recommended) |
| `licenseseat:allow-activate` | Only activation |
| `licenseseat:allow-validate` | Only validation |
| `licenseseat:allow-deactivate` | Only deactivation |
| `licenseseat:allow-status` | Only status checks |
| `licenseseat:allow-entitlements` | Only entitlement checks |

### Device Fingerprinting

The SDK generates a stable device ID based on hardware characteristics. This ID is used to:
- Track seat usage
- Prevent unauthorized device transfers
- Enable offline validation

The device ID is not personally identifiable.

## Troubleshooting

### Plugin Not Loading

1. Ensure the plugin is registered in `main.rs`:
   ```rust
   .plugin(tauri_plugin_licenseseat::init())
   ```

2. Check that permissions are added to your capability file.

3. Rebuild the Rust backend:
   ```bash
   cd src-tauri && cargo build
   ```

### "Command not found" Error

Make sure you've installed the JS bindings:
```bash
npm add @licenseseat/tauri-plugin
```

### Network Errors

1. Check your API key is correct
2. Verify network connectivity
3. Enable debug mode for detailed logs:
   ```json
   { "plugins": { "licenseseat": { "debug": true } } }
   ```

### Offline Validation Not Working

1. Ensure the `offline` feature is enabled (it's built-in for the Tauri plugin)
2. Check that `offlineFallbackMode` is set to `"allow_offline"` or `"offline_first"`
3. Verify `maxOfflineDays` is greater than 0

### Debug Logging

Enable debug mode to see detailed SDK logs:

```json
{
  "plugins": {
    "licenseseat": {
      "debug": true
    }
  }
}
```

Then check the Tauri console output for `[licenseseat]` prefixed messages.

## License

MIT License. See [LICENSE](../../LICENSE) for details.
