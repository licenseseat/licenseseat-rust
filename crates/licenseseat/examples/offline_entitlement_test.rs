//! Test entitlements work with offline validation

use licenseseat::{Config, LicenseSeat, OfflineFallbackMode};
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Offline Entitlement Test ===\n");

    let config = Config {
        api_key: "pk_test_9cXtKvf6rt2swMYJcg4ykiVyKFxFjWHri".into(),
        product_slug: "cap-desktop-711728".into(),
        api_base_url: "http://localhost:3000/api/v1".into(),
        offline_fallback_mode: OfflineFallbackMode::Always,
        max_offline_days: 7,
        auto_validate_interval: Duration::ZERO,
        heartbeat_interval: Duration::ZERO,
        storage_prefix: "entitlement_test_".into(),
        debug: true,
        ..Default::default()
    };

    let sdk = LicenseSeat::new(config);

    // Step 1: Activate
    println!("1. Activating...");
    sdk.activate("TEST-WW1T-YKEN-XXWE").await?;
    println!("   ✓ Activated\n");

    // Step 2: Sync offline assets (should get new token with entitlements)
    println!("2. Syncing offline assets...");
    sdk.sync_offline_assets().await?;
    println!("   ✓ Synced\n");

    // Step 3: Online validation - check entitlements
    println!("3. Online validation...");
    let result = sdk.validate().await?;
    println!("   Valid: {}", result.valid);
    println!("   Entitlements from API: {:?}", result.license.active_entitlements);
    
    let updates = sdk.check_entitlement("updates");
    println!("   check_entitlement('updates'): active={}, reason={:?}\n", updates.active, updates.reason);

    // Step 4: Test offline (broken URL)
    println!("4. Testing OFFLINE validation with entitlements...");
    let offline_config = Config {
        api_key: "pk_test_9cXtKvf6rt2swMYJcg4ykiVyKFxFjWHri".into(),
        product_slug: "cap-desktop-711728".into(),
        api_base_url: "http://localhost:99999/api/v1".into(), // Broken
        offline_fallback_mode: OfflineFallbackMode::Always,
        max_offline_days: 7,
        auto_validate_interval: Duration::ZERO,
        heartbeat_interval: Duration::ZERO,
        storage_prefix: "entitlement_test_".into(), // Same prefix
        debug: true,
        ..Default::default()
    };

    let offline_sdk = LicenseSeat::new(offline_config);
    
    match offline_sdk.validate().await {
        Ok(result) => {
            println!("   ✓ Offline validation succeeded!");
            println!("   Entitlements from offline token: {:?}", result.license.active_entitlements);
            
            let updates = offline_sdk.check_entitlement("updates");
            println!("   check_entitlement('updates'): active={}, reason={:?}", updates.active, updates.reason);
            
            if updates.active {
                println!("\n=== SUCCESS: Entitlements work offline! ===");
            } else {
                println!("\n=== FAIL: Entitlement not active offline ===");
            }
        }
        Err(e) => {
            println!("   ✗ Failed: {}", e);
        }
    }

    Ok(())
}
