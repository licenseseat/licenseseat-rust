//! Configuration tests - validation, defaults, builder pattern.
//!
//! These tests mirror config validation tests from JS, C#, and Swift SDKs.

use licenseseat::{Config, OfflineFallbackMode};
use std::time::Duration;

// ============================================================================
// Default Configuration Tests
// ============================================================================

#[test]
fn test_config_default_values() {
    let config = Config::default();

    assert_eq!(config.api_base_url, "https://licenseseat.com/api/v1");
    assert!(config.api_key.is_empty());
    assert!(config.product_slug.is_empty());
    assert_eq!(config.storage_prefix, "licenseseat_");
    assert!(config.device_identifier.is_none());
    assert_eq!(config.auto_validate_interval, Duration::from_secs(3600));
    assert_eq!(config.heartbeat_interval, Duration::from_secs(300));
    assert_eq!(config.network_recheck_interval, Duration::from_secs(30));
    assert_eq!(config.max_retries, 3);
    assert_eq!(config.retry_delay, Duration::from_secs(1));
    assert_eq!(
        config.offline_fallback_mode,
        OfflineFallbackMode::NetworkOnly
    );
    assert_eq!(
        config.offline_token_refresh_interval,
        Duration::from_secs(72 * 3600)
    );
    assert_eq!(config.max_offline_days, 0);
    assert_eq!(config.max_clock_skew, Duration::from_secs(300));
    assert!(config.telemetry_enabled);
    assert!(!config.debug);
    assert!(config.app_version.is_none());
    assert!(config.app_build.is_none());
}

#[test]
fn test_config_new_with_required_fields() {
    let config = Config::new("sk_live_test123", "my-product");

    assert_eq!(config.api_key, "sk_live_test123");
    assert_eq!(config.product_slug, "my-product");
    // Other values should be defaults
    assert_eq!(config.api_base_url, "https://licenseseat.com/api/v1");
}

// ============================================================================
// Builder Pattern Tests
// ============================================================================

#[test]
fn test_config_builder_with_debug() {
    let config = Config::new("key", "product").with_debug(true);

    assert!(config.debug);
    assert_eq!(config.api_key, "key");
}

#[test]
fn test_config_builder_with_auto_validate_interval() {
    let config =
        Config::new("key", "product").with_auto_validate_interval(Duration::from_secs(1800)); // 30 minutes

    assert_eq!(config.auto_validate_interval, Duration::from_secs(1800));
}

#[test]
fn test_config_builder_with_offline_fallback() {
    let config = Config::new("key", "product").with_offline_fallback(OfflineFallbackMode::Always);

    assert_eq!(config.offline_fallback_mode, OfflineFallbackMode::Always);
}

#[test]
fn test_config_builder_with_max_offline_days() {
    let config = Config::new("key", "product").with_max_offline_days(7);

    assert_eq!(config.max_offline_days, 7);
}

#[test]
fn test_config_builder_chaining() {
    let config = Config::new("key", "product")
        .with_debug(true)
        .with_auto_validate_interval(Duration::from_secs(600))
        .with_offline_fallback(OfflineFallbackMode::Always)
        .with_max_offline_days(14);

    assert!(config.debug);
    assert_eq!(config.auto_validate_interval, Duration::from_secs(600));
    assert_eq!(config.offline_fallback_mode, OfflineFallbackMode::Always);
    assert_eq!(config.max_offline_days, 14);
}

// ============================================================================
// Custom Configuration Tests
// ============================================================================

#[test]
fn test_config_custom_api_base_url() {
    let config = Config {
        api_base_url: "https://custom.api.example.com/v1".into(),
        api_key: "key".into(),
        product_slug: "product".into(),
        ..Default::default()
    };

    assert_eq!(config.api_base_url, "https://custom.api.example.com/v1");
}

#[test]
fn test_config_custom_storage_prefix() {
    let config = Config {
        storage_prefix: "my_app_".into(),
        ..Default::default()
    };

    assert_eq!(config.storage_prefix, "my_app_");
}

#[test]
fn test_config_custom_device_identifier() {
    let config = Config {
        device_identifier: Some("my-custom-device-id".into()),
        ..Default::default()
    };

    assert_eq!(
        config.device_identifier,
        Some("my-custom-device-id".to_string())
    );
}

#[test]
fn test_config_app_version_and_build() {
    let config = Config {
        app_version: Some("2.1.0".into()),
        app_build: Some("456".into()),
        ..Default::default()
    };

    assert_eq!(config.app_version, Some("2.1.0".to_string()));
    assert_eq!(config.app_build, Some("456".to_string()));
}

#[test]
fn test_config_telemetry_disabled() {
    let config = Config {
        telemetry_enabled: false,
        ..Default::default()
    };

    assert!(!config.telemetry_enabled);
}

// ============================================================================
// Interval Configuration Tests
// ============================================================================

#[test]
fn test_config_zero_auto_validate_disables() {
    let config = Config {
        auto_validate_interval: Duration::from_secs(0),
        ..Default::default()
    };

    assert_eq!(config.auto_validate_interval, Duration::ZERO);
}

#[test]
fn test_config_zero_heartbeat_disables() {
    let config = Config {
        heartbeat_interval: Duration::from_secs(0),
        ..Default::default()
    };

    assert_eq!(config.heartbeat_interval, Duration::ZERO);
}

#[test]
fn test_config_custom_retry_settings() {
    let config = Config {
        max_retries: 5,
        retry_delay: Duration::from_millis(500),
        ..Default::default()
    };

    assert_eq!(config.max_retries, 5);
    assert_eq!(config.retry_delay, Duration::from_millis(500));
}

// ============================================================================
// Offline Configuration Tests
// ============================================================================

#[test]
fn test_offline_fallback_mode_network_only() {
    let mode = OfflineFallbackMode::NetworkOnly;
    assert_eq!(mode, OfflineFallbackMode::default());
}

#[test]
fn test_offline_fallback_mode_always() {
    let mode = OfflineFallbackMode::Always;
    assert_ne!(mode, OfflineFallbackMode::NetworkOnly);
}

#[test]
fn test_config_offline_settings() {
    let config = Config {
        offline_fallback_mode: OfflineFallbackMode::Always,
        offline_token_refresh_interval: Duration::from_secs(24 * 3600), // 24 hours
        max_offline_days: 30,
        max_clock_skew: Duration::from_secs(600), // 10 minutes
        ..Default::default()
    };

    assert_eq!(config.offline_fallback_mode, OfflineFallbackMode::Always);
    assert_eq!(
        config.offline_token_refresh_interval,
        Duration::from_secs(24 * 3600)
    );
    assert_eq!(config.max_offline_days, 30);
    assert_eq!(config.max_clock_skew, Duration::from_secs(600));
}

// ============================================================================
// Clone and Debug Tests
// ============================================================================

#[test]
fn test_config_clone() {
    let original = Config {
        api_key: "secret-key".into(),
        product_slug: "my-product".into(),
        debug: true,
        app_version: Some("1.0.0".into()),
        ..Default::default()
    };

    let cloned = original.clone();

    assert_eq!(cloned.api_key, original.api_key);
    assert_eq!(cloned.product_slug, original.product_slug);
    assert_eq!(cloned.debug, original.debug);
    assert_eq!(cloned.app_version, original.app_version);
}

#[test]
fn test_config_debug_format() {
    let config = Config::new("api-key", "product");
    let debug_str = format!("{:?}", config);

    // Debug output should contain key field names
    assert!(debug_str.contains("api_key"));
    assert!(debug_str.contains("product_slug"));
    assert!(debug_str.contains("api_base_url"));
}

#[test]
fn test_offline_fallback_mode_debug() {
    let mode = OfflineFallbackMode::Always;
    let debug_str = format!("{:?}", mode);
    assert!(debug_str.contains("Always"));

    let mode = OfflineFallbackMode::NetworkOnly;
    let debug_str = format!("{:?}", mode);
    assert!(debug_str.contains("NetworkOnly"));
}

// ============================================================================
// Edge Cases
// ============================================================================

#[test]
fn test_config_empty_strings() {
    let config = Config {
        api_key: "".into(),
        product_slug: "".into(),
        storage_prefix: "".into(),
        ..Default::default()
    };

    assert!(config.api_key.is_empty());
    assert!(config.product_slug.is_empty());
    assert!(config.storage_prefix.is_empty());
}

#[test]
fn test_config_special_characters_in_slug() {
    let config = Config {
        product_slug: "my-app_v2.0".into(),
        ..Default::default()
    };

    assert_eq!(config.product_slug, "my-app_v2.0");
}

#[test]
fn test_config_unicode_in_values() {
    let config = Config {
        product_slug: "产品".into(),          // Chinese for "product"
        storage_prefix: "ライセンス_".into(), // Japanese for "license"
        ..Default::default()
    };

    assert_eq!(config.product_slug, "产品");
    assert_eq!(config.storage_prefix, "ライセンス_");
}

#[test]
fn test_config_very_long_values() {
    let long_string = "a".repeat(10000);
    let config = Config {
        api_key: long_string.clone(),
        ..Default::default()
    };

    assert_eq!(config.api_key.len(), 10000);
}

// ============================================================================
// Duration Edge Cases
// ============================================================================

#[test]
fn test_config_very_short_intervals() {
    let config = Config {
        auto_validate_interval: Duration::from_millis(1),
        heartbeat_interval: Duration::from_millis(1),
        retry_delay: Duration::from_micros(1),
        ..Default::default()
    };

    assert_eq!(config.auto_validate_interval, Duration::from_millis(1));
    assert_eq!(config.heartbeat_interval, Duration::from_millis(1));
    assert_eq!(config.retry_delay, Duration::from_micros(1));
}

#[test]
fn test_config_very_long_intervals() {
    let config = Config {
        auto_validate_interval: Duration::from_secs(86400 * 365), // 1 year
        heartbeat_interval: Duration::from_secs(86400 * 30),      // 30 days
        ..Default::default()
    };

    assert_eq!(
        config.auto_validate_interval,
        Duration::from_secs(86400 * 365)
    );
    assert_eq!(config.heartbeat_interval, Duration::from_secs(86400 * 30));
}

// ============================================================================
// Typical Use Case Configurations
// ============================================================================

#[test]
fn test_config_development_setup() {
    let config = Config {
        api_key: "sk_test_development".into(),
        product_slug: "my-app-dev".into(),
        api_base_url: "http://localhost:3000/api/v1".into(),
        debug: true,
        telemetry_enabled: false,                        // Disable for dev
        auto_validate_interval: Duration::from_secs(60), // Faster for testing
        ..Default::default()
    };

    assert!(config.debug);
    assert!(!config.telemetry_enabled);
    assert!(config.api_base_url.contains("localhost"));
}

#[test]
fn test_config_production_setup() {
    let config = Config {
        api_key: "sk_live_production_key".into(),
        product_slug: "my-app".into(),
        debug: false,
        telemetry_enabled: true,
        app_version: Some("2.5.1".into()),
        app_build: Some("1234".into()),
        auto_validate_interval: Duration::from_secs(3600),
        heartbeat_interval: Duration::from_secs(300),
        max_retries: 3,
        ..Default::default()
    };

    assert!(!config.debug);
    assert!(config.telemetry_enabled);
    assert!(config.api_key.starts_with("sk_live"));
}

#[test]
fn test_config_offline_first_setup() {
    let config = Config {
        api_key: "sk_live_key".into(),
        product_slug: "offline-app".into(),
        offline_fallback_mode: OfflineFallbackMode::Always,
        max_offline_days: 14,
        offline_token_refresh_interval: Duration::from_secs(12 * 3600), // 12 hours
        max_clock_skew: Duration::from_secs(3600),                      // 1 hour tolerance
        ..Default::default()
    };

    assert_eq!(config.offline_fallback_mode, OfflineFallbackMode::Always);
    assert_eq!(config.max_offline_days, 14);
}
