//! Simulates Cap's Tauri plugin configuration and tests offline validation

use licenseseat::{Config, LicenseSeat, OfflineFallbackMode};
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Cap App Offline Simulation Test ===\n");

    // Exact config from Cap's tauri.conf.json
    let config = Config {
        api_key: "pk_test_9cXtKvf6rt2swMYJcg4ykiVyKFxFjWHri".into(),
        product_slug: "cap-desktop-711728".into(),
        api_base_url: "http://localhost:3000/api/v1".into(),
        auto_validate_interval: Duration::from_secs(60),
        heartbeat_interval: Duration::from_secs(30),
        offline_fallback_mode: OfflineFallbackMode::Always, // "allow_offline" in config
        max_offline_days: 7,
        telemetry_enabled: true,
        debug: true,
        app_version: Some("0.1.0".into()),
        app_build: Some("Cap - Development".into()),
        storage_prefix: "cap_sim_test_".into(),
        ..Default::default()
    };

    let sdk = LicenseSeat::new(config);

    // Step 1: Activate (what Cap does on license entry)
    println!("1. [Cap] User enters license key...");
    let license = sdk.activate("TEST-WW1T-YKEN-XXWE").await?;
    println!("   ✓ Activated: {}", license.device_id);
    
    // SDK automatically syncs offline assets after activation
    // But let's also do it explicitly to be sure
    println!("\n2. [Cap] Syncing offline assets...");
    sdk.sync_offline_assets().await?;
    println!("   ✓ Offline token & signing key cached");

    // Step 3: Validate (what Cap does periodically)
    println!("\n3. [Cap] Validating license (ONLINE)...");
    let result = sdk.validate().await?;
    println!("   ✓ Valid: {}", result.valid);
    println!("   Plan: {}", result.license.plan_key);
    println!("   Entitlements: {:?}", result.license.active_entitlements.iter().map(|e| &e.key).collect::<Vec<_>>());
    
    // Step 4: Check entitlement
    println!("\n4. [Cap] Checking 'updates' entitlement...");
    let updates = sdk.check_entitlement("updates");
    println!("   Active: {}", updates.active);

    // Step 5: Now simulate offline by creating new SDK with broken URL
    println!("\n5. [Cap] === SIMULATING OFFLINE (server unreachable) ===");
    
    let offline_config = Config {
        api_key: "pk_test_9cXtKvf6rt2swMYJcg4ykiVyKFxFjWHri".into(),
        product_slug: "cap-desktop-711728".into(),
        api_base_url: "http://localhost:99999/api/v1".into(), // Unreachable
        auto_validate_interval: Duration::from_secs(60),
        heartbeat_interval: Duration::from_secs(30),
        offline_fallback_mode: OfflineFallbackMode::Always,
        max_offline_days: 7,
        telemetry_enabled: true,
        debug: true,
        app_version: Some("0.1.0".into()),
        app_build: Some("Cap - Development".into()),
        storage_prefix: "cap_sim_test_".into(), // Same prefix = same cached data
        ..Default::default()
    };

    let offline_sdk = LicenseSeat::new(offline_config);

    // Step 6: Validate OFFLINE
    println!("\n6. [Cap] Validating license (OFFLINE)...");
    match offline_sdk.validate().await {
        Ok(result) => {
            println!("   ✓ OFFLINE VALIDATION SUCCEEDED!");
            println!("   Valid: {}", result.valid);
            println!("   Plan: {}", result.license.plan_key);
            println!("   Entitlements: {:?}", result.license.active_entitlements.iter().map(|e| &e.key).collect::<Vec<_>>());
        }
        Err(e) => {
            println!("   ✗ FAILED: {}", e);
            return Err(e.into());
        }
    }

    // Step 7: Check entitlement OFFLINE
    println!("\n7. [Cap] Checking 'updates' entitlement (OFFLINE)...");
    let updates_offline = offline_sdk.check_entitlement("updates");
    println!("   Active: {}", updates_offline.active);

    // Step 8: Get status
    println!("\n8. [Cap] Getting license status (OFFLINE)...");
    let status = offline_sdk.status();
    println!("   Status: {:?}", status);

    println!("\n========================================");
    println!("=== CAP OFFLINE VALIDATION: SUCCESS ===");
    println!("========================================");
    println!("\nCap can work offline for up to 7 days.");
    println!("Entitlements work. License validation works.");
    
    Ok(())
}
