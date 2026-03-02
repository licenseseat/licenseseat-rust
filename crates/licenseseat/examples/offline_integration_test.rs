//! Integration test for offline validation

use licenseseat::{Config, LicenseSeat, OfflineFallbackMode};
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();
    
    println!("=== Offline Validation Integration Test ===\n");

    // Create SDK with Cap's config
    let config = Config {
        api_key: "pk_test_9cXtKvf6rt2swMYJcg4ykiVyKFxFjWHri".into(),
        product_slug: "cap-desktop-711728".into(),
        api_base_url: "http://localhost:3000/api/v1".into(),
        offline_fallback_mode: OfflineFallbackMode::Always,
        max_offline_days: 7,
        auto_validate_interval: Duration::ZERO,
        heartbeat_interval: Duration::ZERO,
        storage_prefix: "offline_int_test_".into(),
        debug: true,
        ..Default::default()
    };

    let sdk = LicenseSeat::new(config);

    // Step 1: Activate while online
    println!("1. Activating license (online)...");
    let license = sdk.activate("TEST-WW1T-YKEN-XXWE").await?;
    println!("   ✓ Activated: {}\n", license.device_id);

    // Step 2: Sync offline assets
    println!("2. Syncing offline assets...");
    sdk.sync_offline_assets().await?;
    println!("   ✓ Offline token and signing key cached\n");

    // Step 3: Online validation
    println!("3. Online validation...");
    let result = sdk.validate().await?;
    println!("   ✓ Valid: {} (online)\n", result.valid);

    // Step 4: Now test with a broken URL (simulates offline)
    println!("4. Testing offline fallback (broken URL simulates network failure)...");
    let offline_config = Config {
        api_key: "pk_test_9cXtKvf6rt2swMYJcg4ykiVyKFxFjWHri".into(),
        product_slug: "cap-desktop-711728".into(),
        api_base_url: "http://localhost:99999/api/v1".into(), // Broken URL
        offline_fallback_mode: OfflineFallbackMode::Always,
        max_offline_days: 7,
        auto_validate_interval: Duration::ZERO,
        heartbeat_interval: Duration::ZERO,
        storage_prefix: "offline_int_test_".into(), // Same prefix to use cached data
        debug: true,
        ..Default::default()
    };

    let offline_sdk = LicenseSeat::new(offline_config);
    
    // This should fail online but succeed offline
    match offline_sdk.validate().await {
        Ok(result) => {
            println!("   ✓ Valid: {} (OFFLINE FALLBACK WORKED!)", result.valid);
            println!("   License key: {}", result.license.key);
            println!("   Plan: {}", result.license.plan_key);
        }
        Err(e) => {
            println!("   ✗ Offline validation failed: {}", e);
            return Err(e.into());
        }
    }

    println!("\n=== SUCCESS: Offline validation works! ===");
    println!("The license can be validated offline for up to 7 days (maxOfflineDays config)");
    println!("The offline token itself is valid for 30 days from the server");
    Ok(())
}
