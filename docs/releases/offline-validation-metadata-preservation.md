# Offline Validation Metadata Preservation

## Summary

A production desktop app integrating the Rust SDK and the Tauri plugin exposed an offline-state regression:

- a valid `pro` license could come back as a lower-tier license when the server was unavailable
- the machine file still verified correctly
- the cached validation lost `plan_key`, `active_entitlements`, and product metadata
- downstream apps that derive feature access from those fields could show a valid license as `personal`

The root cause was in the SDK, not in the app.

## User-Visible Symptom

The observed sequence was:

1. Activate a valid `pro` license while the server is reachable.
2. Shut the server down.
3. Restart the app or trigger offline restore/validation.
4. The SDK restores successfully and reports an offline-valid license.
5. The cached validation now contains:
   - `plan_key: ""`
   - `active_entitlements: []`
   - `product.slug: ""`
6. The app can no longer infer the paid tier correctly.

This was especially visible in desktop apps that map plan and entitlement state directly to UI and feature gates.

## Root Cause

There were two related issues.

### 1. The SDK did not retain a trusted license snapshot early enough, or refresh it on all online license-bearing responses

On activation, the SDK cached a `License` object with:

- activation id
- device id
- activated timestamp

but it did not separately retain the server-returned embedded license snapshot for later offline enrichment.

That meant offline restore had no trusted plan or entitlement metadata to fall back to unless a separate online validation had already run. It also meant long-running apps could miss fresher online metadata if heartbeat was the most recent successful online response.

### 2. Offline machine-file fallback could overwrite richer cached state

During offline validation:

1. the SDK verified the cached machine file
2. it converted the machine-file payload into a `ValidationResult`
3. it persisted that result back into the cache

If the machine-file payload did not include an embedded license object, the conversion path synthesized a fallback license with minimal fields:

- empty `plan_key`
- empty `active_entitlements`
- empty product metadata

That degraded validation result was then written back to the cached license state, replacing the richer online-derived metadata.

So the machine file itself was still valid, but the persisted cached validation became materially less informative.

## Why It Happened In Practice

The regression requires this combination:

- the app has a valid activated license
- the app falls back to machine-file offline validation
- the verified machine-file payload does not carry an embedded license object

In that case, the SDK had enough information to prove validity, but not enough information in the current conversion path to preserve the original commercial tier metadata unless it explicitly merged from cached online state.

## SDK Fix

The SDK was changed in two places.

### 1. Cache and refresh a trusted license snapshot from online license-bearing responses

Practical effect:

- the SDK keeps the activation response's embedded license snapshot for later offline enrichment
- the SDK refreshes that trusted snapshot again on successful validation and heartbeat responses
- activation still remains `Pending` until validation runs
- offline restore can preserve plan and entitlement metadata even if the first offline recovery happens before a separate online validation round
- long-running apps can carry forward fresher license metadata into offline restore even when heartbeat is the most recent online round-trip

### 2. Preserve richer cached metadata during offline validation

Offline validation now preserves the last trusted cached license snapshot when a verified machine-file payload omits the embedded license object.

The restore path preserves or restores fields such as:

- `plan_key`
- `active_entitlements`
- `product.slug`
- `product.name`
- seat metadata
- license mode
- timestamps and metadata when present in the trusted snapshot

Practical effect:

- a valid paid license remains a valid paid license when the server is down
- offline restore no longer downgrades the tier view to a lower plan solely because the machine file omitted embedded license data
- embedded machine-file license data still wins when it is present; the cache is only used to hydrate stripped fallback results

## Regression Coverage Added

A dedicated SDK integration test now covers the exact degraded path:

1. activate online
2. optionally validate online and cache richer entitlements
3. fetch a machine file without an embedded license object
4. go offline
5. restore from offline state
6. assert that plan and entitlements are still preserved

Additional coverage verifies that:

- activation remains `Pending` before validation
- activation-only snapshots can still hydrate offline restore when the machine file omits its embedded license
- heartbeat-refreshed snapshots can still hydrate offline restore when they are newer than activation state
- embedded machine-file license objects are not overwritten by stale cached metadata

## Downstream Impact

Before this fix, downstream apps sometimes needed an app-level shadow cache or recovery shim to avoid visually downgrading a license when offline.

After this fix:

- the SDK remains the correct source of truth
- downstream apps should not need to preserve plan metadata separately just to survive normal offline restore
- machine-file-first offline behavior becomes safer for production tiered apps

## Relevant Files

- `crates/licenseseat/src/client.rs`
- `crates/licenseseat/src/cache.rs`
- `crates/licenseseat/src/offline.rs`
- `crates/licenseseat/tests/sdk_integration_tests.rs`

## Short Version

The problem was not that offline verification failed.

The problem was that offline verification could succeed while still erasing the cached plan and entitlement metadata that downstream apps rely on.

The fix was to retain a trusted license snapshot separately from validation state and use it only to hydrate stripped machine-file fallback results, without changing the SDK's activate-then-pending semantics.
