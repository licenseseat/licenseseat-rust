//! DevHeartbeat - Simple heartbeat demo for LicenseSeat Rust SDK
//!
//! This example mimics a real Tauri/Rust application that:
//! 1. Activates a license on startup
//! 2. Sends periodic heartbeats to keep the license alive
//! 3. Handles graceful shutdown
//!
//! Usage:
//!   LICENSESEAT_API_KEY=your_api_key \
//!   LICENSESEAT_PRODUCT_SLUG=your_product \
//!   LICENSESEAT_LICENSE_KEY=your_license_key \
//!   cargo run --example dev_heartbeat
//!
//! Optional environment variables:
//!   LICENSESEAT_BASE_URL - API base URL (default: https://licenseseat.com/api/v1)
//!   HEARTBEAT_INTERVAL_SECS - Heartbeat interval in seconds (default: 30)

use licenseseat::{LicenseSeat, Config, EventKind};
use std::env;
use std::time::Duration;
use tokio::signal;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing for logging
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("licenseseat=debug".parse()?)
        )
        .init();

    println!("=== LicenseSeat DevHeartbeat Demo ===\n");

    // Read configuration from environment
    let api_key = env::var("LICENSESEAT_API_KEY")
        .expect("LICENSESEAT_API_KEY environment variable required");
    let product_slug = env::var("LICENSESEAT_PRODUCT_SLUG")
        .expect("LICENSESEAT_PRODUCT_SLUG environment variable required");
    let license_key = env::var("LICENSESEAT_LICENSE_KEY")
        .expect("LICENSESEAT_LICENSE_KEY environment variable required");

    let base_url = env::var("LICENSESEAT_BASE_URL")
        .unwrap_or_else(|_| "https://licenseseat.com/api/v1".to_string());
    let heartbeat_interval: u64 = env::var("HEARTBEAT_INTERVAL_SECS")
        .unwrap_or_else(|_| "30".to_string())
        .parse()
        .unwrap_or(30);

    println!("Configuration:");
    println!("  Product: {}", product_slug);
    println!("  License: {}...", &license_key[..8.min(license_key.len())]);
    println!("  Base URL: {}", base_url);
    println!("  Heartbeat interval: {}s\n", heartbeat_interval);

    // Build SDK configuration
    let config = Config {
        api_key,
        product_slug,
        api_base_url: base_url,
        heartbeat_interval: Duration::from_secs(heartbeat_interval),
        telemetry_enabled: true,
        app_version: Some("1.0.0-demo".to_string()),
        ..Default::default()
    };

    // Create SDK instance
    let sdk = LicenseSeat::new(config);

    // Set up event subscriber to monitor SDK events
    let mut event_rx = sdk.subscribe();
    tokio::spawn(async move {
        while let Ok(event) = event_rx.recv().await {
            match event.kind {
                EventKind::HeartbeatSuccess => {
                    println!("[EVENT] Heartbeat sent successfully");
                }
                EventKind::HeartbeatError => {
                    println!("[EVENT] Heartbeat failed");
                }
                EventKind::ValidationSuccess => {
                    println!("[EVENT] License validated");
                }
                EventKind::ValidationFailed => {
                    println!("[EVENT] Validation failed");
                }
                EventKind::ActivationSuccess => {
                    println!("[EVENT] Activation successful");
                }
                EventKind::ActivationError => {
                    println!("[EVENT] Activation failed");
                }
                EventKind::DeactivationSuccess => {
                    println!("[EVENT] Deactivation successful");
                }
                EventKind::DeactivationError => {
                    println!("[EVENT] Deactivation failed");
                }
                kind => {
                    println!("[EVENT] {:?}", kind);
                }
            }
        }
    });

    // Step 1: Activate the license
    println!("Step 1: Activating license...");
    match sdk.activate(&license_key).await {
        Ok(license) => {
            println!("  License activated successfully!");
            println!("  Device ID: {}", license.device_id);
            println!("  Activation ID: {:?}", license.activation_id);
        }
        Err(e) => {
            println!("  Activation error: {}", e);
            return Ok(());
        }
    }

    // Step 2: Validate to get entitlements
    println!("\nStep 2: Validating license...");
    match sdk.validate().await {
        Ok(result) => {
            if result.valid {
                println!("  License valid!");
                println!("  Entitlements: {:?}",
                    result.license.active_entitlements.len()
                );
            } else {
                println!("  License invalid: {:?}", result.code);
            }
        }
        Err(e) => {
            println!("  Validation error: {}", e);
        }
    }

    // Step 3: Start heartbeat loop
    println!("\nStep 3: Starting heartbeat loop (Ctrl+C to stop)...\n");

    let sdk_clone = sdk.clone();
    let heartbeat_handle = tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(heartbeat_interval));
        let mut heartbeat_count = 0u64;

        loop {
            interval.tick().await;
            heartbeat_count += 1;

            print!("[{}] Sending heartbeat... ", heartbeat_count);
            match sdk_clone.heartbeat().await {
                Ok(response) => {
                    println!("OK (received_at: {})", response.received_at);
                }
                Err(e) => {
                    println!("FAILED: {}", e);
                }
            }
        }
    });

    // Wait for Ctrl+C signal
    println!("Press Ctrl+C to stop the demo and deactivate the license.\n");

    signal::ctrl_c().await?;
    println!("\n\nReceived shutdown signal...");

    // Abort the heartbeat loop
    heartbeat_handle.abort();

    // Step 4: Deactivate license on shutdown
    println!("\nStep 4: Deactivating license...");
    match sdk.deactivate().await {
        Ok(_) => {
            println!("  License deactivated successfully!");
        }
        Err(e) => {
            println!("  Deactivation error: {} (this is normal if already deactivated)", e);
        }
    }

    println!("\n=== DevHeartbeat Demo Complete ===");
    Ok(())
}
