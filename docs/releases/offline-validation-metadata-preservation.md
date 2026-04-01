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

There were two phases to the problem.

### 1. The original metadata-loss bug

During offline validation:

1. the SDK verified the cached machine file
2. it converted the machine-file payload into a `ValidationResult`
3. it persisted that result back into the cache

If the machine-file payload did not include an embedded license object, the conversion path synthesized a fallback license with minimal fields:

- empty `plan_key`
- empty `active_entitlements`
- empty product metadata

That degraded validation result was then written back to the cached license state, replacing richer online-derived metadata.

So the machine file itself was still valid, but the persisted cached validation became materially less informative.

### 2. The remaining hardening gap discovered after `0.5.2`

`0.5.2` introduced a dedicated trusted `license_snapshot` cache file and used it to enrich stripped
machine-file results.

That was the right direction, but it still left a single-point dependency:

- if the machine file was stripped
- and the dedicated `license_snapshot` file was missing
- offline restore could still fall back to the blank synthesized license

In other words, the SDK had the right idea but not yet the full invariant. Tier preservation still
depended too heavily on one sidecar cache file.

## Why It Happened In Practice

The regression requires this combination:

- the app has a valid activated license
- the app falls back to machine-file offline validation
- the verified machine-file payload does not carry an embedded license object

In that case, the SDK had enough information to prove validity, but not enough information in the current conversion path to preserve the original commercial tier metadata unless it explicitly merged from cached online state.

## SDK Fix

The final SDK fix now guarantees trusted metadata durability in two layers.

### 1. Trusted rich license metadata is persisted on the cached license record itself

Successful online license-bearing responses now update:

- the dedicated `license_snapshot` cache file
- the cached `license.json` record via `trusted_license`

Practical effect:

- trusted plan and entitlement metadata survives even if the sidecar snapshot file disappears
- activation still remains `Pending` until validation runs
- validation and heartbeat can continue refreshing the trusted metadata source without changing public status semantics

### 2. Offline restore now uses an explicit trusted-source order

For stripped machine-file payloads, offline restore now prefers:

1. embedded machine-file license
2. snapshot-file metadata
3. trusted cached metadata on `license.json`
4. blank fallback only as a true last resort

The restore path preserves or restores fields such as:

- `plan_key`
- `active_entitlements`
- `product.slug`
- `product.name`
- seat metadata
- license mode
- timestamps and metadata when present in the trusted source

Practical effect:

- a valid paid license remains a valid paid license when the server is down
- offline restore no longer downgrades the tier view to a lower plan solely because the machine file omitted embedded license data
- embedded machine-file license data still wins when it is present

### 3. The SDK now self-heals the snapshot file

If trusted cached metadata exists on `license.json` but the dedicated `license_snapshot` file is
missing, the SDK recreates the snapshot file before continuing offline validation.

That does not invent metadata that was never seen online. It only restores durability for metadata
the SDK already trusts.

## Regression Coverage Added

Dedicated SDK integration coverage now covers the exact degraded production path:

1. activate or validate or heartbeat online
2. fetch a machine file without an embedded license object
3. delete the dedicated `license_snapshot` file
4. go offline
5. restore from offline state
6. assert that plan and entitlements are still preserved

Additional coverage verifies that:

- activation remains `Pending` before validation
- activation-only metadata can still hydrate offline restore when the machine file omits its embedded license
- validation-refreshed metadata can still hydrate offline restore when the snapshot file is gone
- heartbeat-refreshed metadata can still hydrate offline restore when it is newer than activation state
- embedded machine-file license objects are not overwritten by cached metadata

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

The problem was that offline verification could succeed while still erasing the cached plan and entitlement metadata that downstream apps rely on, and the first snapshot-based fix still depended too much on a separate sidecar file.

The final fix was:

- keep trusted metadata separately from validation semantics
- persist that trusted metadata on the cached license record itself
- use embedded machine-file data first, then trusted metadata, and only fall back to blanks last
- recreate the dedicated snapshot file when trusted cached metadata already exists
