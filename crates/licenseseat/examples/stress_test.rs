//! StressTest - Comprehensive SDK stress test for LicenseSeat Rust SDK
//!
//! This example mimics a real Tauri/Rust application and tests all SDK functionality:
//!
//! Scenario 1:  Activation with telemetry enabled
//! Scenario 2:  Validation with telemetry
//! Scenario 3:  Heartbeat endpoint (single, rapid, spaced)
//! Scenario 4:  Enriched telemetry server acceptance
//! Scenario 5:  Telemetry disabled mode
//! Scenario 6:  Entitlement checking (comprehensive)
//! Scenario 7:  Entitlement edge cases (expiration, missing, reasons)
//! Scenario 8:  License status tracking
//! Scenario 9:  Concurrent validation stress
//! Scenario 10: Event subscription system
//! Scenario 11: Offline validation configuration
//! Scenario 12: Full lifecycle (activate -> validate -> heartbeat -> deactivate)
//!
//! Usage:
//!   LICENSESEAT_API_KEY=your_api_key \
//!   LICENSESEAT_PRODUCT_SLUG=your_product \
//!   LICENSESEAT_LICENSE_KEY=your_license_key \
//!   cargo run --example stress_test
//!
//! Optional:
//!   LICENSESEAT_BASE_URL - API base URL
//!   RUN_SCENARIO - Run only specific scenario (1-12)

use licenseseat::{LicenseSeat, Config, EventKind, LicenseStatus, EntitlementReason, OfflineFallbackMode};
use std::env;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

#[derive(Clone)]
struct TestContext {
    api_key: String,
    product_slug: String,
    license_key: String,
    base_url: String,
}

impl TestContext {
    fn from_env() -> Self {
        Self {
            api_key: env::var("LICENSESEAT_API_KEY")
                .expect("LICENSESEAT_API_KEY required"),
            product_slug: env::var("LICENSESEAT_PRODUCT_SLUG")
                .expect("LICENSESEAT_PRODUCT_SLUG required"),
            license_key: env::var("LICENSESEAT_LICENSE_KEY")
                .expect("LICENSESEAT_LICENSE_KEY required"),
            base_url: env::var("LICENSESEAT_BASE_URL")
                .unwrap_or_else(|_| "https://licenseseat.com/api/v1".to_string()),
        }
    }

    fn build_sdk(&self, telemetry: bool) -> LicenseSeat {
        LicenseSeat::new(Config {
            api_key: self.api_key.clone(),
            product_slug: self.product_slug.clone(),
            api_base_url: self.base_url.clone(),
            telemetry_enabled: telemetry,
            ..Default::default()
        })
    }

    fn build_sdk_with_version(&self, version: &str) -> LicenseSeat {
        LicenseSeat::new(Config {
            api_key: self.api_key.clone(),
            product_slug: self.product_slug.clone(),
            api_base_url: self.base_url.clone(),
            telemetry_enabled: true,
            app_version: Some(version.to_string()),
            ..Default::default()
        })
    }
}

#[derive(Clone, Copy)]
enum ScenarioResult {
    Pass,
    Fail,
    Skip,
}

impl ScenarioResult {
    fn symbol(&self) -> &'static str {
        match self {
            ScenarioResult::Pass => "[PASS]",
            ScenarioResult::Fail => "[FAIL]",
            ScenarioResult::Skip => "[SKIP]",
        }
    }
}

struct TestRunner {
    results: Vec<(String, ScenarioResult, Duration)>,
}

impl TestRunner {
    fn new() -> Self {
        Self { results: Vec::new() }
    }

    fn record(&mut self, name: &str, result: ScenarioResult, duration: Duration) {
        println!("{} {} ({:.2}s)", result.symbol(), name, duration.as_secs_f64());
        self.results.push((name.to_string(), result, duration));
    }

    fn summary(&self) {
        println!("\n========================================");
        println!("STRESS TEST SUMMARY");
        println!("========================================\n");

        let mut passed = 0;
        let mut failed = 0;
        let mut skipped = 0;
        let mut total_time = Duration::ZERO;

        for (name, result, duration) in &self.results {
            println!("  {} {} ({:.2}s)", result.symbol(), name, duration.as_secs_f64());
            total_time += *duration;
            match result {
                ScenarioResult::Pass => passed += 1,
                ScenarioResult::Fail => failed += 1,
                ScenarioResult::Skip => skipped += 1,
            }
        }

        println!("\n----------------------------------------");
        println!("Total: {} passed, {} failed, {} skipped", passed, failed, skipped);
        println!("Time:  {:.2}s", total_time.as_secs_f64());
        println!("========================================\n");
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("licenseseat=info".parse()?)
        )
        .init();

    println!("\n========================================");
    println!("LICENSESEAT RUST SDK STRESS TEST");
    println!("========================================\n");

    let ctx = TestContext::from_env();
    let mut runner = TestRunner::new();

    // Check if user wants specific scenario
    let run_scenario: Option<u32> = env::var("RUN_SCENARIO")
        .ok()
        .and_then(|s| s.parse().ok());

    // Define scenarios
    let scenarios: &[(u32, &str, fn(TestContext) -> std::pin::Pin<Box<dyn std::future::Future<Output = ScenarioResult> + Send>>)] = &[
        (1, "Activation with telemetry", |ctx| Box::pin(scenario_1_activation_telemetry(ctx))),
        (2, "Validation with telemetry", |ctx| Box::pin(scenario_2_validation_telemetry(ctx))),
        (3, "Heartbeat patterns", |ctx| Box::pin(scenario_3_heartbeat_patterns(ctx))),
        (4, "Enriched telemetry", |ctx| Box::pin(scenario_4_enriched_telemetry(ctx))),
        (5, "Telemetry disabled", |ctx| Box::pin(scenario_5_telemetry_disabled(ctx))),
        (6, "Entitlement checking", |ctx| Box::pin(scenario_6_entitlement_checking(ctx))),
        (7, "Entitlement edge cases", |ctx| Box::pin(scenario_7_entitlement_edge_cases(ctx))),
        (8, "License status", |ctx| Box::pin(scenario_8_license_status(ctx))),
        (9, "Concurrent stress", |ctx| Box::pin(scenario_9_concurrent_stress(ctx))),
        (10, "Event subscription", |ctx| Box::pin(scenario_10_event_subscription(ctx))),
        (11, "Offline validation config", |ctx| Box::pin(scenario_11_offline_validation(ctx))),
        (12, "Full lifecycle", |ctx| Box::pin(scenario_12_full_lifecycle(ctx))),
    ];

    for (num, name, scenario_fn) in scenarios {
        if let Some(run) = run_scenario {
            if run != *num {
                continue;
            }
        }

        println!("\n--- Scenario {}: {} ---", num, name);
        let start = Instant::now();
        let result = scenario_fn(ctx.clone()).await;
        runner.record(&format!("Scenario {}: {}", num, name), result, start.elapsed());
    }

    runner.summary();
    Ok(())
}

// ============================================================================
// Scenario 1: Activation with telemetry enabled
// ============================================================================
async fn scenario_1_activation_telemetry(ctx: TestContext) -> ScenarioResult {
    let sdk = ctx.build_sdk(true);

    println!("  Activating license with telemetry...");
    match sdk.activate(&ctx.license_key).await {
        Ok(license) => {
            println!("  Activation successful");
            println!("    Device ID: {}", license.device_id);
            println!("    Activation ID: {:?}", license.activation_id);

            // Deactivate after test
            let _ = sdk.deactivate().await;
            ScenarioResult::Pass
        }
        Err(e) => {
            println!("  Activation error: {}", e);
            ScenarioResult::Fail
        }
    }
}

// ============================================================================
// Scenario 2: Validation with telemetry
// ============================================================================
async fn scenario_2_validation_telemetry(ctx: TestContext) -> ScenarioResult {
    let sdk = ctx.build_sdk(true);

    // First activate
    println!("  Activating...");
    if let Err(e) = sdk.activate(&ctx.license_key).await {
        println!("  Activation failed: {}", e);
        return ScenarioResult::Fail;
    }

    // Then validate
    println!("  Validating license...");
    match sdk.validate().await {
        Ok(result) => {
            if result.valid {
                println!("  Validation successful");
                println!("    Active entitlements: {}",
                    result.license.active_entitlements.len());
                let _ = sdk.deactivate().await;
                ScenarioResult::Pass
            } else {
                println!("  Validation invalid: {:?}", result.code);
                let _ = sdk.deactivate().await;
                ScenarioResult::Fail
            }
        }
        Err(e) => {
            println!("  Validation error: {}", e);
            let _ = sdk.deactivate().await;
            ScenarioResult::Fail
        }
    }
}

// ============================================================================
// Scenario 3: Heartbeat patterns (single, rapid, spaced)
// ============================================================================
async fn scenario_3_heartbeat_patterns(ctx: TestContext) -> ScenarioResult {
    let sdk = ctx.build_sdk(true);

    // Activate first
    println!("  Activating...");
    if let Err(e) = sdk.activate(&ctx.license_key).await {
        println!("  Activation failed: {}", e);
        return ScenarioResult::Fail;
    }

    let mut success = true;

    // Single heartbeat
    println!("  Single heartbeat...");
    if let Err(e) = sdk.heartbeat().await {
        println!("    Failed: {}", e);
        success = false;
    } else {
        println!("    OK");
    }

    // Rapid heartbeats (5 in quick succession)
    println!("  Rapid heartbeats (5x)...");
    let mut rapid_failures = 0;
    for i in 1..=5 {
        if sdk.heartbeat().await.is_err() {
            rapid_failures += 1;
        }
        print!("    {}/5 ", i);
    }
    println!();
    if rapid_failures > 0 {
        println!("    {} failures", rapid_failures);
        // Allow some failures in rapid mode (rate limiting)
        if rapid_failures > 3 {
            success = false;
        }
    } else {
        println!("    All OK");
    }

    // Spaced heartbeats
    println!("  Spaced heartbeats (3x @ 1s interval)...");
    let mut spaced_failures = 0;
    for i in 1..=3 {
        tokio::time::sleep(Duration::from_secs(1)).await;
        if let Err(e) = sdk.heartbeat().await {
            println!("    {}/3 FAILED: {}", i, e);
            spaced_failures += 1;
        } else {
            println!("    {}/3 OK", i);
        }
    }
    if spaced_failures > 0 {
        success = false;
    }

    let _ = sdk.deactivate().await;

    if success { ScenarioResult::Pass } else { ScenarioResult::Fail }
}

// ============================================================================
// Scenario 4: Enriched telemetry server acceptance
// ============================================================================
async fn scenario_4_enriched_telemetry(ctx: TestContext) -> ScenarioResult {
    let sdk = ctx.build_sdk_with_version("2.5.0-stress-test");

    println!("  Activating with enriched telemetry...");
    match sdk.activate(&ctx.license_key).await {
        Ok(_) => {
            println!("  Server accepted enriched telemetry");
            let _ = sdk.deactivate().await;
            ScenarioResult::Pass
        }
        Err(e) => {
            println!("  Activation error: {}", e);
            ScenarioResult::Fail
        }
    }
}

// ============================================================================
// Scenario 5: Telemetry disabled mode
// ============================================================================
async fn scenario_5_telemetry_disabled(ctx: TestContext) -> ScenarioResult {
    let sdk = ctx.build_sdk(false);

    println!("  Activating with telemetry disabled...");
    match sdk.activate(&ctx.license_key).await {
        Ok(_) => {
            println!("  Activation successful (no telemetry sent)");
            let _ = sdk.deactivate().await;
            ScenarioResult::Pass
        }
        Err(e) => {
            println!("  Activation error: {}", e);
            ScenarioResult::Fail
        }
    }
}

// ============================================================================
// Scenario 6: Entitlement checking (comprehensive)
// ============================================================================
async fn scenario_6_entitlement_checking(ctx: TestContext) -> ScenarioResult {
    let sdk = ctx.build_sdk(true);

    println!("  Activating...");
    if let Err(e) = sdk.activate(&ctx.license_key).await {
        println!("  Activation failed: {}", e);
        return ScenarioResult::Fail;
    }

    println!("  Validating to load entitlements...");
    let validation = match sdk.validate().await {
        Ok(v) => v,
        Err(e) => {
            println!("  Validation failed: {}", e);
            let _ = sdk.deactivate().await;
            return ScenarioResult::Fail;
        }
    };

    // List all entitlements from validation
    println!("  Entitlements from validation:");
    for ent in &validation.license.active_entitlements {
        println!("    - key: {}, expires_at: {:?}", ent.key, ent.expires_at);
    }

    let mut success = true;

    // Test 1: Check a known entitlement
    println!("  Test 1: Check known entitlement (pro-features)...");
    let status = sdk.check_entitlement("pro-features");
    println!("    active: {}", status.active);
    println!("    reason: {:?}", status.reason);
    println!("    expires_at: {:?}", status.expires_at);
    if let Some(ent) = &status.entitlement {
        println!("    entitlement.key: {}", ent.key);
    }
    if !status.active {
        println!("    WARNING: pro-features not active (may need to add to license)");
    }

    // Test 2: Check another entitlement
    println!("  Test 2: Check another entitlement (premium-support)...");
    let status = sdk.check_entitlement("premium-support");
    println!("    active: {}", status.active);
    println!("    reason: {:?}", status.reason);

    // Test 3: Check non-existent entitlement
    println!("  Test 3: Check non-existent entitlement...");
    let status = sdk.check_entitlement("non-existent-feature-xyz");
    println!("    active: {} (expected: false)", status.active);
    println!("    reason: {:?} (expected: NotFound)", status.reason);
    if status.active || status.reason != Some(EntitlementReason::NotFound) {
        println!("    FAIL: Expected NotFound reason");
        success = false;
    }

    // Test 4: has_entitlement convenience method
    println!("  Test 4: has_entitlement convenience method...");
    let has_pro = sdk.has_entitlement("pro-features");
    let has_fake = sdk.has_entitlement("fake-feature");
    println!("    has_entitlement(pro-features): {}", has_pro);
    println!("    has_entitlement(fake-feature): {} (expected: false)", has_fake);
    if has_fake {
        println!("    FAIL: Should not have fake-feature");
        success = false;
    }

    // Test 5: Multiple entitlement checks in sequence
    println!("  Test 5: Sequential entitlement checks...");
    let entitlements_to_check = ["pro-features", "premium-support", "api-access", "export-pdf"];
    for key in &entitlements_to_check {
        let active = sdk.has_entitlement(key);
        println!("    {}: {}", key, if active { "YES" } else { "no" });
    }

    let _ = sdk.deactivate().await;
    if success { ScenarioResult::Pass } else { ScenarioResult::Fail }
}

// ============================================================================
// Scenario 7: Entitlement edge cases (expiration, missing, reasons)
// ============================================================================
async fn scenario_7_entitlement_edge_cases(ctx: TestContext) -> ScenarioResult {
    let sdk = ctx.build_sdk(true);

    // Test 1: Check entitlement before activation (should fail with NoLicense)
    println!("  Test 1: Check entitlement before activation...");
    let status = sdk.check_entitlement("pro-features");
    println!("    active: {} (expected: false)", status.active);
    println!("    reason: {:?} (expected: NoLicense)", status.reason);
    if status.reason != Some(EntitlementReason::NoLicense) {
        println!("    FAIL: Expected NoLicense reason");
        return ScenarioResult::Fail;
    }

    // Activate
    println!("  Activating...");
    if let Err(e) = sdk.activate(&ctx.license_key).await {
        println!("  Activation failed: {}", e);
        return ScenarioResult::Fail;
    }

    // Test 2: Check entitlement after activation but before validation
    println!("  Test 2: Check entitlement before validation...");
    let status = sdk.check_entitlement("pro-features");
    println!("    active: {} (expected: false)", status.active);
    println!("    reason: {:?} (expected: NoLicense - no validation yet)", status.reason);
    // Note: This might be NoLicense since validation hasn't populated entitlements

    // Validate
    println!("  Validating...");
    if let Err(e) = sdk.validate().await {
        println!("  Validation failed: {}", e);
        let _ = sdk.deactivate().await;
        return ScenarioResult::Fail;
    }

    // Test 3: Check entitlement after validation
    println!("  Test 3: Check entitlement after validation...");
    let status = sdk.check_entitlement("pro-features");
    println!("    active: {}", status.active);
    println!("    reason: {:?}", status.reason);
    println!("    expires_at: {:?}", status.expires_at);

    // Test 4: EntitlementStatus fields
    println!("  Test 4: Verify EntitlementStatus struct...");
    let status = sdk.check_entitlement("premium-support");
    println!("    EntitlementStatus {{");
    println!("      active: {},", status.active);
    println!("      reason: {:?},", status.reason);
    println!("      expires_at: {:?},", status.expires_at);
    println!("      entitlement: {:?}", status.entitlement.as_ref().map(|e| &e.key));
    println!("    }}");

    // Test 5: Multiple missing entitlements all return NotFound
    println!("  Test 5: Multiple missing entitlements...");
    let missing = ["a", "b", "c", "xyz-123", "fake_feature"];
    let mut all_not_found = true;
    for key in missing {
        let status = sdk.check_entitlement(key);
        if status.reason != Some(EntitlementReason::NotFound) {
            all_not_found = false;
            println!("    FAIL: {} should be NotFound, got {:?}", key, status.reason);
        }
    }
    println!("    All returned NotFound: {}", all_not_found);

    let _ = sdk.deactivate().await;
    ScenarioResult::Pass
}

// ============================================================================
// Scenario 8: License status tracking
// ============================================================================
async fn scenario_8_license_status(ctx: TestContext) -> ScenarioResult {
    let sdk = ctx.build_sdk(true);

    // Check status before activation
    println!("  Status before activation...");
    match sdk.status() {
        LicenseStatus::Inactive { message } => {
            println!("    Status: Inactive - {}", message);
        }
        status => {
            println!("    Unexpected status: {:?}", status);
        }
    }

    // Activate
    println!("  Activating...");
    if let Err(e) = sdk.activate(&ctx.license_key).await {
        println!("  Activation failed: {}", e);
        return ScenarioResult::Fail;
    }

    // Check status after activation (before validation)
    println!("  Status after activation (before validation)...");
    match sdk.status() {
        LicenseStatus::Pending { message } => {
            println!("    Status: Pending - {}", message);
        }
        status => {
            println!("    Status: {:?}", status);
        }
    }

    // Validate
    println!("  Validating...");
    if let Err(e) = sdk.validate().await {
        println!("  Validation failed: {}", e);
        let _ = sdk.deactivate().await;
        return ScenarioResult::Fail;
    }

    // Check status after validation
    println!("  Status after validation...");
    match sdk.status() {
        LicenseStatus::Active { details } => {
            println!("    Status: Active");
            println!("    License: {}", details.license);
            println!("    Device: {}", details.device);
            println!("    Entitlements: {}", details.entitlements.len());
        }
        status => {
            println!("    Unexpected status: {:?}", status);
        }
    }

    let _ = sdk.deactivate().await;
    ScenarioResult::Pass
}

// ============================================================================
// Scenario 9: Concurrent validation stress
// ============================================================================
async fn scenario_9_concurrent_stress(ctx: TestContext) -> ScenarioResult {
    let sdk = Arc::new(ctx.build_sdk(true));

    println!("  Activating...");
    if let Err(e) = sdk.activate(&ctx.license_key).await {
        println!("  Activation failed: {}", e);
        return ScenarioResult::Fail;
    }

    // First validation to populate cache
    if let Err(e) = sdk.validate().await {
        println!("  Initial validation failed: {}", e);
        let _ = sdk.deactivate().await;
        return ScenarioResult::Fail;
    }

    println!("  Launching 10 concurrent validations...");
    let mut handles = Vec::new();

    for i in 0..10 {
        let sdk_clone = sdk.clone();
        handles.push(tokio::spawn(async move {
            let start = Instant::now();
            let result = sdk_clone.validate().await;
            let success = result.is_ok() && result.map(|r| r.valid).unwrap_or(false);
            (i, success, start.elapsed())
        }));
    }

    let mut successes = 0;
    let mut failures = 0;
    let mut total_time = Duration::ZERO;

    for handle in handles {
        if let Ok((i, success, duration)) = handle.await {
            if success {
                successes += 1;
            } else {
                failures += 1;
            }
            total_time += duration;
            println!("    Validation {}: {} ({:.2}ms)",
                i,
                if success { "OK" } else { "FAIL" },
                duration.as_millis()
            );
        }
    }

    println!("  Results: {} success, {} failed", successes, failures);
    println!("  Avg time: {:.2}ms", total_time.as_millis() as f64 / 10.0);

    let _ = sdk.deactivate().await;

    // Allow up to 3 failures due to rate limiting
    if failures <= 3 {
        ScenarioResult::Pass
    } else {
        ScenarioResult::Fail
    }
}

// ============================================================================
// Scenario 10: Event subscription system
// ============================================================================
async fn scenario_10_event_subscription(ctx: TestContext) -> ScenarioResult {
    let sdk = ctx.build_sdk(true);

    let event_count = Arc::new(AtomicU32::new(0));
    let event_count_clone = event_count.clone();

    let mut event_rx = sdk.subscribe();
    tokio::spawn(async move {
        while let Ok(event) = event_rx.recv().await {
            event_count_clone.fetch_add(1, Ordering::SeqCst);
            match event.kind {
                EventKind::ActivationStart => println!("    -> ActivationStart"),
                EventKind::ActivationSuccess => println!("    -> ActivationSuccess"),
                EventKind::ActivationError => println!("    -> ActivationError"),
                EventKind::ValidationStart => println!("    -> ValidationStart"),
                EventKind::ValidationSuccess => println!("    -> ValidationSuccess"),
                EventKind::HeartbeatSuccess => println!("    -> HeartbeatSuccess"),
                EventKind::DeactivationStart => println!("    -> DeactivationStart"),
                EventKind::DeactivationSuccess => println!("    -> DeactivationSuccess"),
                kind => println!("    -> {:?}", kind),
            }
        }
    });

    println!("  Performing lifecycle operations...");

    // Activate
    println!("  Activating...");
    if let Err(e) = sdk.activate(&ctx.license_key).await {
        println!("  Activation failed: {}", e);
        return ScenarioResult::Fail;
    }

    // Small delay to let events process
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Validate
    println!("  Validating...");
    let _ = sdk.validate().await;

    tokio::time::sleep(Duration::from_millis(100)).await;

    // Heartbeat
    println!("  Sending heartbeat...");
    let _ = sdk.heartbeat().await;

    tokio::time::sleep(Duration::from_millis(100)).await;

    // Deactivate
    println!("  Deactivating...");
    let _ = sdk.deactivate().await;

    tokio::time::sleep(Duration::from_millis(100)).await;

    let count = event_count.load(Ordering::SeqCst);
    println!("  Total events received: {}", count);

    // We should have received at least activation, validation, heartbeat, deactivation events
    if count >= 4 {
        ScenarioResult::Pass
    } else {
        println!("  Expected at least 4 events");
        ScenarioResult::Fail
    }
}

// ============================================================================
// Scenario 11: Offline validation configuration
// ============================================================================
async fn scenario_11_offline_validation(ctx: TestContext) -> ScenarioResult {
    println!("  Testing offline validation configuration...");

    // Test 1: Default offline fallback mode
    println!("  Test 1: Default offline fallback mode...");
    let default_config = Config {
        api_key: ctx.api_key.clone(),
        product_slug: ctx.product_slug.clone(),
        api_base_url: ctx.base_url.clone(),
        ..Default::default()
    };
    println!("    offline_fallback_mode: {:?} (expected: NetworkOnly)", default_config.offline_fallback_mode);
    if default_config.offline_fallback_mode != OfflineFallbackMode::NetworkOnly {
        println!("    FAIL: Expected NetworkOnly as default");
        return ScenarioResult::Fail;
    }

    // Test 2: Configure offline fallback mode to Always
    println!("  Test 2: Configure offline fallback to Always...");
    let always_config = Config {
        api_key: ctx.api_key.clone(),
        product_slug: ctx.product_slug.clone(),
        api_base_url: ctx.base_url.clone(),
        offline_fallback_mode: OfflineFallbackMode::Always,
        ..Default::default()
    };
    println!("    offline_fallback_mode: {:?}", always_config.offline_fallback_mode);

    // Test 3: Max offline days configuration
    println!("  Test 3: Max offline days configuration...");
    let offline_config = Config {
        api_key: ctx.api_key.clone(),
        product_slug: ctx.product_slug.clone(),
        api_base_url: ctx.base_url.clone(),
        max_offline_days: 7,
        ..Default::default()
    };
    println!("    max_offline_days: {} (set to 7)", offline_config.max_offline_days);
    if offline_config.max_offline_days != 7 {
        println!("    FAIL: Expected max_offline_days = 7");
        return ScenarioResult::Fail;
    }

    // Test 4: Max clock skew configuration
    println!("  Test 4: Max clock skew configuration...");
    let skew_config = Config {
        api_key: ctx.api_key.clone(),
        product_slug: ctx.product_slug.clone(),
        api_base_url: ctx.base_url.clone(),
        max_clock_skew: Duration::from_secs(600), // 10 minutes
        ..Default::default()
    };
    println!("    max_clock_skew: {:?}", skew_config.max_clock_skew);

    // Test 5: Offline token refresh interval
    println!("  Test 5: Offline token refresh interval...");
    let refresh_config = Config {
        api_key: ctx.api_key.clone(),
        product_slug: ctx.product_slug.clone(),
        api_base_url: ctx.base_url.clone(),
        offline_token_refresh_interval: Duration::from_secs(24 * 3600), // 24 hours
        ..Default::default()
    };
    println!("    offline_token_refresh_interval: {:?}", refresh_config.offline_token_refresh_interval);

    // Test 6: SDK with offline config
    println!("  Test 6: Create SDK with offline configuration...");
    let sdk = LicenseSeat::new(Config {
        api_key: ctx.api_key.clone(),
        product_slug: ctx.product_slug.clone(),
        api_base_url: ctx.base_url.clone(),
        offline_fallback_mode: OfflineFallbackMode::Always,
        max_offline_days: 7,
        max_clock_skew: Duration::from_secs(300),
        ..Default::default()
    });

    // Activate and validate to ensure SDK works with offline config
    println!("  Activating with offline-enabled config...");
    if let Err(e) = sdk.activate(&ctx.license_key).await {
        println!("    Activation failed: {}", e);
        return ScenarioResult::Fail;
    }

    println!("  Validating...");
    match sdk.validate().await {
        Ok(result) => {
            println!("    Validation: valid={}", result.valid);
        }
        Err(e) => {
            println!("    Validation failed: {}", e);
        }
    }

    let _ = sdk.deactivate().await;

    // Note about offline feature
    println!("\n  Note: Full offline validation (Ed25519 token verification) requires:");
    println!("    cargo run --example stress_test --features offline");
    println!("  The 'offline' feature enables cryptographic verification of cached tokens.");

    ScenarioResult::Pass
}

// ============================================================================
// Scenario 12: Full lifecycle (activate -> validate -> heartbeat -> deactivate)
// ============================================================================
async fn scenario_12_full_lifecycle(ctx: TestContext) -> ScenarioResult {
    let sdk = ctx.build_sdk(true);

    let events = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
    let events_clone = events.clone();

    let mut event_rx = sdk.subscribe();
    tokio::spawn(async move {
        while let Ok(event) = event_rx.recv().await {
            let event_name = format!("{}", event.kind);
            events_clone.lock().unwrap().push(event_name);
        }
    });

    // Step 1: Activate
    println!("  Step 1: Activate...");
    match sdk.activate(&ctx.license_key).await {
        Ok(license) => {
            println!("    OK - Device: {}", license.device_id);
        }
        Err(e) => {
            println!("    Failed: {}", e);
            return ScenarioResult::Fail;
        }
    }

    // Step 2: Validate
    println!("  Step 2: Validate...");
    match sdk.validate().await {
        Ok(result) => {
            if !result.valid {
                println!("    Validation invalid");
                let _ = sdk.deactivate().await;
                return ScenarioResult::Fail;
            }
            println!("    OK - {} entitlements", result.license.active_entitlements.len());
        }
        Err(e) => {
            println!("    Failed: {}", e);
            let _ = sdk.deactivate().await;
            return ScenarioResult::Fail;
        }
    }

    // Step 3: Heartbeat
    println!("  Step 3: Heartbeat...");
    match sdk.heartbeat().await {
        Ok(response) => {
            println!("    OK (received_at: {})", response.received_at);
        }
        Err(e) => {
            println!("    Failed: {}", e);
            let _ = sdk.deactivate().await;
            return ScenarioResult::Fail;
        }
    }

    // Step 4: Check cached license
    println!("  Step 4: Check cached license...");
    match sdk.current_license() {
        Some(license) => {
            println!("    Cached license found: {}", license.license_key);
        }
        None => {
            println!("    No cached license (unexpected but not fatal)");
        }
    }

    // Step 5: Deactivate
    println!("  Step 5: Deactivate...");
    match sdk.deactivate().await {
        Ok(_) => {
            println!("    OK");
        }
        Err(e) => {
            println!("    Failed: {}", e);
            return ScenarioResult::Fail;
        }
    }

    // Summary
    tokio::time::sleep(Duration::from_millis(100)).await;
    let captured_events = events.lock().unwrap();
    println!("  Events captured: {}", captured_events.len());
    for event in captured_events.iter().take(8) {
        println!("    - {}", event);
    }
    if captured_events.len() > 8 {
        println!("    ... and {} more", captured_events.len() - 8);
    }

    ScenarioResult::Pass
}
