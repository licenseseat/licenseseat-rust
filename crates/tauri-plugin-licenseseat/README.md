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
- **High-level State Helpers** — Get a consolidated state snapshot and subscribe to state changes
- **Entitlement Checking** — Feature gating made simple
- **Event System** — React to license changes in real-time
- **Offline Support** — Machine-file-first Ed25519 + AES-256-GCM offline validation
- **Zero Config** — Just add your publishable API key and product slug
- **Tauri v2** — Built for the latest Tauri architecture

## Requirements

- Tauri v2.0.0 or later
- Rust 1.85+
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

Use your `pk_*` publishable API key in Tauri apps. Do not embed `sk_*` secret keys here.

```json
// tauri.conf.json
{
  "plugins": {
    "licenseseat": {
      "apiKey": "pk_live_xxx",
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
  deactivate,
  getState,
  bootstrapState,
  subscribeState,
  hasAnyEntitlement,
  LICENSESEAT_EVENTS,
  listenEvent,
  normalizeError,
} from '@licenseseat/tauri-plugin';

// Activate a license (first launch or new key)
async function activateLicense(key: string) {
  try {
    const license = await activate(key);
    console.log(`Activated! Fingerprint: ${license.deviceId}`);
    return license;
  } catch (error) {
    console.error('Activation failed:', error);
    throw error;
  }
}

// Restore and read the current state (app startup)
async function bootstrapLicense() {
  const state = await bootstrapState();

  console.log('Client status:', state.clientStatus);
  console.log('Online:', state.isOnline);
  console.log('Fingerprint:', state.fingerprint);
  console.log('Plan:', state.planKey);

  return state;
}

// Check entitlements for feature gating
async function checkFeatures() {
  if (await hasAnyEntitlement(['pro-features', 'cloud-sync'])) {
    enableProFeatures();
  }
}

// Subscribe to future state changes
const unlisten = await subscribeState(({ state, eventName }) => {
  console.log('State changed via:', eventName);
  console.log('New client status:', state.clientStatus);
}, { emitCurrent: true });

// Listen to a specific raw event when you need it
await listenEvent(LICENSESEAT_EVENTS.LICENSE_REVOKED, () => {
  showRenewalPrompt();
});

// Or fetch a one-off snapshot
async function showStatus() {
  const state = await getState();
  console.log(state.status.status);
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
use tauri::State;

#[tauri::command]
async fn custom_validation(
    sdk: State<'_, licenseseat::LicenseSeat>,
) -> Result<bool, String> {
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
| `validateKey(key)` | Validate an explicit license key | `Promise<ValidationResult>` |
| `validate()` | Validate current license | `Promise<ValidationResult>` |
| `deactivate()` | Deactivate and release seat | `Promise<void>` |
| `deactivateKey(key, fingerprint?)` | Deactivate an explicit license/fingerprint pair | `Promise<void>` |
| `getStatus()` | Get current license status | `Promise<LicenseStatus>` |
| `getClientStatus()` | Get the stable client-status string | `Promise<LicenseStatus['status']>` |
| `isOnline()` | Check whether the SDK currently believes the API is reachable | `Promise<boolean>` |
| `getFingerprint()` | Get the current SDK fingerprint | `Promise<string>` |
| `restoreLicense()` | Restore a cached license session | `Promise<RestoreResult>` |
| `getState()` | Get a consolidated state snapshot | `Promise<LicenseSeatState>` |
| `getAdminSnapshot()` | Get a detailed admin/debug snapshot | `Promise<LicenseSeatAdminSnapshot>` |
| `restoreAndGetState()` | Restore a cached session and return the refreshed state | `Promise<LicenseSeatState>` |
| `activateAndGetState(key, options?)` | Activate, attempt validation, and return the refreshed state | `Promise<LicenseSeatState>` |
| `bootstrapState(options?)` | Restore, optionally validate, and return the latest state | `Promise<LicenseSeatState>` |
| `health()` | Check API reachability | `Promise<boolean>` |
| `hasEntitlement(key)` | Check if entitlement is active | `Promise<boolean>` |
| `hasAnyEntitlement(keys)` | Check whether any provided entitlement is active | `Promise<boolean>` |
| `hasAllEntitlements(keys)` | Check whether all provided entitlements are active | `Promise<boolean>` |
| `checkEntitlement(key)` | Get detailed entitlement status | `Promise<EntitlementStatus>` |
| `getEntitlements()` | List active entitlements from the cached validation result | `Promise<Entitlement[]>` |
| `getActiveEntitlementKeys()` | List active entitlement keys from the current state snapshot | `Promise<string[]>` |
| `getPlanKey()` | Get the active plan key from the validation snapshot | `Promise<string \| null>` |
| `getLicenseMode()` | Get the active license mode from the validation snapshot | `Promise<string \| null>` |
| `listenEvent(name, handler)` | Listen for a specific stable plugin event | `Promise<UnlistenFn>` |
| `subscribeState(listener, options?)` | Subscribe to state-changing lifecycle events | `Promise<UnlistenFn>` |
| `heartbeat()` | Send heartbeat ping | `Promise<void>` |
| `heartbeatKey(key, fingerprint?)` | Send a heartbeat for an explicit license/fingerprint pair | `Promise<void>` |
| `getLatestRelease(...)` | Get the latest published release | `Promise<Release>` |
| `listReleases(...)` | List releases with pagination metadata | `Promise<ReleaseList>` |
| `generateDownloadToken(...)` | Generate a release download token | `Promise<DownloadToken>` |
| `generateOfflineToken(key, fingerprint?, ttlDays?)` | Generate a legacy offline token | `Promise<OfflineToken>` |
| `verifyOfflineToken(token, publicKeyB64?)` | Verify a legacy offline token locally | `Promise<boolean>` |
| `checkoutMachineFile(...)` | Checkout a machine file for offline validation | `Promise<MachineFile>` |
| `fetchSigningKey(keyId)` | Fetch and cache a signing key | `Promise<string>` |
| `syncOfflineAssets()` | Refresh the offline machine-file/signing-key/token set | `Promise<void>` |
| `verifyMachineFile(file, options?)` | Verify a machine file locally | `Promise<MachineFileVerificationResult>` |
| `normalizeError(error)` | Normalize unknown invoke/plugin errors into `LicenseSeatError` | `LicenseSeatPluginError` |

### Types

```typescript
interface License {
  licenseKey: string;
  deviceId: string;
  activationId: string;
  activatedAt: string;
}

interface ValidationResult {
  object: string;
  valid: boolean;
  code?: string;
  message?: string;
  license: {
    key: string;
    status: string;
    planKey: string;
    activeEntitlements: Array<{
      key: string;
      expiresAt?: string;
    }>;
  };
}

interface LicenseStatus {
  status: 'active' | 'inactive' | 'invalid' | 'pending' | 'offline_valid' | 'offline_invalid';
  message?: string;
  license?: string;
  device?: string;
  activatedAt?: string;
  lastValidated?: string;
}

interface EntitlementStatus {
  active: boolean;
  reason?: 'nolicense' | 'notfound' | 'expired';
  expiresAt?: string;
}

interface Entitlement {
  key: string;
  expiresAt?: string;
  metadata?: Record<string, unknown>;
}
```

## Configuration

### Full Configuration Options

```json
// tauri.conf.json
{
  "plugins": {
    "licenseseat": {
      "apiKey": "pk_live_xxx",
      "productSlug": "your-product",
      "apiBaseUrl": "https://licenseseat.com/api/v1",
      "storagePrefix": "licenseseat_",
      "deviceIdentifier": "stable-fingerprint",
      "signingPublicKey": null,
      "signingKeyId": null,
      "autoValidateInterval": 3600,
      "heartbeatInterval": 300,
      "networkRecheckInterval": 30,
      "offlineFallbackMode": "network_only",
      "offlineTokenRefreshInterval": 259200,
      "enableLegacyOfflineTokens": false,
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
| `apiKey` | `string` | — | Your publishable LicenseSeat API key (`pk_*`, required). Keep `sk_*` server-side only. |
| `productSlug` | `string` | — | Your product slug (required) |
| `apiBaseUrl` | `string` | `https://licenseseat.com/api/v1` | API base URL |
| `storagePrefix` | `string` | `"licenseseat_"` | Cache namespace prefix |
| `deviceIdentifier` | `string` | auto-generated | Override the canonical fingerprint |
| `signingPublicKey` | `string` | `null` | Optional pinned public key for offline verification |
| `signingKeyId` | `string` | `null` | Optional key ID for `signingPublicKey` |
| `autoValidateInterval` | `number` | `3600` | Background validation interval (seconds) |
| `heartbeatInterval` | `number` | `300` | Heartbeat interval (seconds) |
| `networkRecheckInterval` | `number` | `30` | Network recheck interval while offline (seconds) |
| `offlineFallbackMode` | `string` | `"network_only"` | `"network_only"` or `"always"`; `"allow_offline"` / `"offline_first"` remain accepted legacy aliases |
| `offlineTokenRefreshInterval` | `number` | `259200` | Offline artifact refresh interval (seconds) |
| `enableLegacyOfflineTokens` | `boolean` | `false` | Allow legacy offline-token fallback after machine-file sync fails |
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
    case 'notfound':
      showUpgradePrompt('Upgrade to Pro for this feature');
      break;
    case 'nolicense':
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

Use the exported event constants and state subscription helpers:

```typescript
import {
  LICENSESEAT_EVENTS,
  listenEvent,
  subscribeState,
} from '@licenseseat/tauri-plugin';

await listenEvent(LICENSESEAT_EVENTS.VALIDATION_SUCCESS, (event) => {
  console.log('License validated!', event.payload);
});

const unlisten = await subscribeState(({ state, eventName }) => {
  console.log('State changed via', eventName);
  refreshUI(state);
}, { emitCurrent: true });

await listenEvent(LICENSESEAT_EVENTS.LICENSE_REVOKED, () => {
  showRenewalPrompt();
});
```

### Available Events

| Event | Payload | Description |
|-------|---------|-------------|
| `licenseseat://activation-success` | `License` | License activated |
| `licenseseat://activation-error` | `string` | Activation failed |
| `LICENSESEAT_EVENTS.VALIDATION_SUCCESS` | `ValidationResult` | Validation succeeded |
| `LICENSESEAT_EVENTS.VALIDATION_FAILED` | `ValidationResult` | Validation failed |
| `LICENSESEAT_EVENTS.LICENSE_LOADED` | `License` | Cached license loaded on startup |
| `LICENSESEAT_EVENTS.LICENSE_REVOKED` | `License \| string` | License was revoked |
| `LICENSESEAT_EVENTS.DEACTIVATION_SUCCESS` | — | License deactivated |
| `LICENSESEAT_EVENTS.HEARTBEAT_SUCCESS` | — | Heartbeat acknowledged |
| `LICENSESEAT_EVENTS.HEARTBEAT_ERROR` | `string` | Heartbeat failed |

Use `subscribeState()` when your UI only needs the latest state snapshot. Use `listenEvent()` when you care about a specific lifecycle event.

## Offline Support

Enable offline validation for air-gapped or unreliable network environments:

```json
{
  "plugins": {
    "licenseseat": {
      "offlineFallbackMode": "always",
      "maxOfflineDays": 7
    }
  }
}
```

**Modes:**

| Mode | Description |
|------|-------------|
| `network_only` | Always require network (default) |
| `always` | Fall back to cached machine files, then legacy offline tokens if explicitly enabled |

## React Integration

```tsx
import { useState, useEffect } from 'react';
import {
  activate,
  getState,
  subscribeState,
  type LicenseSeatState,
} from '@licenseseat/tauri-plugin';

function useLicense() {
  const [state, setState] = useState<LicenseSeatState | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let cleanup: (() => Promise<void>) | undefined;

    getState()
      .then(setState)
      .finally(() => setLoading(false));

    subscribeState(({ state }) => {
      setState(state);
    }).then((unlisten) => {
      cleanup = unlisten;
    });

    return () => {
      void cleanup?.();
    };
  }, []);

  return { state, loading };
}

// Usage
function App() {
  const { state, loading } = useLicense();

  if (loading) return <Loading />;

  if (!state?.isValid) {
    return <ActivationScreen />;
  }

  return (
    <div>
      <h1>Welcome!</h1>
      {state.entitlements.some((entitlement) => entitlement.key === 'pro-features') && <ProFeatures />}
    </div>
  );
}
```

## Vue Integration

```vue
<script setup lang="ts">
import { ref, onMounted, onUnmounted } from 'vue';
import {
  getState,
  subscribeState,
  type LicenseSeatState,
} from '@licenseseat/tauri-plugin';

const state = ref<LicenseSeatState | null>(null);
let unlisten: (() => Promise<void>) | undefined;

onMounted(async () => {
  state.value = await getState();
  unlisten = await subscribeState(({ state: nextState }) => {
    state.value = nextState;
  });
});

onUnmounted(() => {
  void unlisten?.();
});
</script>

<template>
  <div v-if="state?.isValid">
    <h1>Welcome!</h1>
    <ProFeatures v-if="state.entitlements.some((entitlement) => entitlement.key === 'pro-features')" />
  </div>
  <ActivationScreen v-else />
</template>
```

## Svelte Integration

```svelte
<script lang="ts">
  import { onMount } from 'svelte';
  import {
    getState,
    subscribeState,
    type LicenseSeatState,
  } from '@licenseseat/tauri-plugin';

  let state: LicenseSeatState | null = null;

  onMount(() => {
    let unlisten: (() => Promise<void>) | undefined;

    void getState().then((nextState) => {
      state = nextState;
    });

    void subscribeState(({ state: nextState }) => {
      state = nextState;
    }).then((cleanup) => {
      unlisten = cleanup;
    });

    return () => {
      void unlisten?.();
    };
  });
</script>

{#if state?.isValid}
  <h1>Welcome!</h1>
  {#if state.entitlements.some((entitlement) => entitlement.key === 'pro-features')}
    <ProFeatures />
  {/if}
{:else}
  <ActivationScreen />
{/if}
```

## Error Handling

```typescript
import { activate, normalizeError } from '@licenseseat/tauri-plugin';

try {
  const license = await activate(key);
  showSuccess('License activated!');
} catch (error) {
  const licenseError = normalizeError(error);
  const message = licenseError.message;

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

Use a `pk_*` publishable API key in your Tauri app. This key is intended for client applications, may be stored in `tauri.conf.json`, and is compiled into your app binary. It is not exposed to the JavaScript frontend. Do not embed `sk_*` secret keys in the plugin configuration.

### Permissions

The plugin uses Tauri's permission system. Available permissions:

| Permission | Description |
|------------|-------------|
| `licenseseat:default` | All plugin commands, including offline/admin helpers (recommended) |
| `licenseseat:allow-activate` | Only activation |
| `licenseseat:allow-validate` | Only validation |
| `licenseseat:allow-deactivate` | Only deactivation |
| `licenseseat:allow-get-state` | Consolidated state snapshots |
| `licenseseat:allow-sync-offline-assets` | Refresh offline assets for the active license |

All command-specific permission identifiers are generated under `permissions/autogenerated/commands/`.

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

1. Check your publishable API key (`pk_*`) is correct
2. Verify network connectivity
3. Enable debug mode for detailed logs:
   ```json
   { "plugins": { "licenseseat": { "debug": true } } }
   ```

### Offline Validation Not Working

1. Ensure the `offline` feature is enabled (it's built-in for the Tauri plugin)
2. Check that `offlineFallbackMode` is set to `"always"` (or a legacy alias such as `"allow_offline"`)
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
