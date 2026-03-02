//! Unit tests for data models and types.

use chrono::{TimeZone, Utc};
use licenseseat::{
    ActivationOptions, Config, Entitlement, EntitlementReason, EntitlementStatus,
    LicenseStatus, LicenseStatusDetails, OfflineFallbackMode,
};

// ============================================================================
// LicenseStatus Tests
// ============================================================================

#[test]
fn test_license_status_inactive() {
    let status = LicenseStatus::Inactive {
        message: "No license activated".into(),
    };

    if let LicenseStatus::Inactive { message } = status {
        assert_eq!(message, "No license activated");
    } else {
        panic!("Expected Inactive status");
    }
}

#[test]
fn test_license_status_pending() {
    let status = LicenseStatus::Pending {
        message: "License not yet validated".into(),
    };

    if let LicenseStatus::Pending { message } = status {
        assert_eq!(message, "License not yet validated");
    } else {
        panic!("Expected Pending status");
    }
}

#[test]
fn test_license_status_active() {
    let now = Utc::now();
    let status = LicenseStatus::Active {
        details: LicenseStatusDetails {
            license: "TEST-KEY".into(),
            device: "device-123".into(),
            activated_at: now,
            last_validated: now,
            entitlements: vec![],
        },
    };

    if let LicenseStatus::Active { details } = status {
        assert_eq!(details.license, "TEST-KEY");
        assert_eq!(details.device, "device-123");
    } else {
        panic!("Expected Active status");
    }
}

#[test]
fn test_license_status_invalid() {
    let status = LicenseStatus::Invalid {
        message: "License has expired".into(),
    };

    if let LicenseStatus::Invalid { message } = status {
        assert_eq!(message, "License has expired");
    } else {
        panic!("Expected Invalid status");
    }
}

#[test]
fn test_license_status_offline_valid() {
    let now = Utc::now();
    let status = LicenseStatus::OfflineValid {
        details: LicenseStatusDetails {
            license: "OFFLINE-KEY".into(),
            device: "device-offline".into(),
            activated_at: now,
            last_validated: now,
            entitlements: vec![],
        },
    };

    if let LicenseStatus::OfflineValid { details } = status {
        assert_eq!(details.license, "OFFLINE-KEY");
    } else {
        panic!("Expected OfflineValid status");
    }
}

#[test]
fn test_license_status_offline_invalid() {
    let status = LicenseStatus::OfflineInvalid {
        message: "Offline token expired".into(),
    };

    if let LicenseStatus::OfflineInvalid { message } = status {
        assert_eq!(message, "Offline token expired");
    } else {
        panic!("Expected OfflineInvalid status");
    }
}

#[test]
fn test_license_status_is_active() {
    let now = Utc::now();

    // Active status should return true
    let active_status = LicenseStatus::Active {
        details: LicenseStatusDetails {
            license: "KEY".into(),
            device: "dev".into(),
            activated_at: now,
            last_validated: now,
            entitlements: vec![],
        },
    };
    assert!(active_status.is_active());

    // OfflineValid should return true
    let offline_valid = LicenseStatus::OfflineValid {
        details: LicenseStatusDetails {
            license: "KEY".into(),
            device: "dev".into(),
            activated_at: now,
            last_validated: now,
            entitlements: vec![],
        },
    };
    assert!(offline_valid.is_active());

    // Inactive should return false
    let inactive = LicenseStatus::Inactive {
        message: "No license".into(),
    };
    assert!(!inactive.is_active());

    // Invalid should return false
    let invalid = LicenseStatus::Invalid {
        message: "Expired".into(),
    };
    assert!(!invalid.is_active());
}

// ============================================================================
// Entitlement Tests
// ============================================================================

#[test]
fn test_entitlement_creation() {
    let expiry = Utc.with_ymd_and_hms(2025, 12, 31, 23, 59, 59).unwrap();
    let entitlement = Entitlement {
        key: "pro-features".into(),
        expires_at: Some(expiry),
        metadata: None,
    };

    assert_eq!(entitlement.key, "pro-features");
    assert!(entitlement.expires_at.is_some());
    assert!(entitlement.metadata.is_none());
}

#[test]
fn test_entitlement_permanent() {
    let entitlement = Entitlement {
        key: "lifetime".into(),
        expires_at: None, // No expiration = permanent
        metadata: None,
    };

    assert_eq!(entitlement.key, "lifetime");
    assert!(entitlement.expires_at.is_none());
}

#[test]
fn test_entitlement_is_expired() {
    let past = Utc.with_ymd_and_hms(2020, 1, 1, 0, 0, 0).unwrap();
    let entitlement = Entitlement {
        key: "expired-feature".into(),
        expires_at: Some(past),
        metadata: None,
    };

    // Check if expired (expires_at is in the past)
    assert!(entitlement.expires_at.unwrap() < Utc::now());
}

#[test]
fn test_entitlement_is_active() {
    let future = Utc.with_ymd_and_hms(2030, 12, 31, 23, 59, 59).unwrap();
    let entitlement = Entitlement {
        key: "active-feature".into(),
        expires_at: Some(future),
        metadata: None,
    };

    // Check if active (expires_at is in the future)
    assert!(entitlement.expires_at.unwrap() > Utc::now());
}

// ============================================================================
// EntitlementStatus Tests
// ============================================================================

#[test]
fn test_entitlement_status_active() {
    let status = EntitlementStatus {
        active: true,
        reason: None,
        entitlement: Some(Entitlement {
            key: "pro".into(),
            expires_at: None,
            metadata: None,
        }),
        expires_at: None,
    };

    assert!(status.active);
    assert!(status.reason.is_none());
    assert!(status.entitlement.is_some());
}

#[test]
fn test_entitlement_status_not_found() {
    let status = EntitlementStatus {
        active: false,
        reason: Some(EntitlementReason::NotFound),
        entitlement: None,
        expires_at: None,
    };

    assert!(!status.active);
    assert_eq!(status.reason, Some(EntitlementReason::NotFound));
}

#[test]
fn test_entitlement_status_expired() {
    let past = Utc.with_ymd_and_hms(2020, 1, 1, 0, 0, 0).unwrap();
    let status = EntitlementStatus {
        active: false,
        reason: Some(EntitlementReason::Expired),
        entitlement: Some(Entitlement {
            key: "trial".into(),
            expires_at: Some(past),
            metadata: None,
        }),
        expires_at: Some(past),
    };

    assert!(!status.active);
    assert_eq!(status.reason, Some(EntitlementReason::Expired));
    assert!(status.expires_at.is_some());
}

#[test]
fn test_entitlement_status_no_license() {
    let status = EntitlementStatus {
        active: false,
        reason: Some(EntitlementReason::NoLicense),
        entitlement: None,
        expires_at: None,
    };

    assert!(!status.active);
    assert_eq!(status.reason, Some(EntitlementReason::NoLicense));
}

#[test]
fn test_entitlement_reason_variants() {
    let reasons = vec![
        EntitlementReason::NotFound,
        EntitlementReason::Expired,
        EntitlementReason::NoLicense,
    ];

    // All reasons should be distinct
    for (i, r1) in reasons.iter().enumerate() {
        for (j, r2) in reasons.iter().enumerate() {
            if i != j {
                assert_ne!(r1, r2);
            }
        }
    }
}

// ============================================================================
// ActivationOptions Tests
// ============================================================================

#[test]
fn test_activation_options_default() {
    let opts = ActivationOptions::default();

    assert!(opts.device_id.is_none());
    assert!(opts.device_name.is_none());
    assert!(opts.metadata.is_none());
}

#[test]
fn test_activation_options_with_device_name() {
    let opts = ActivationOptions::with_device_name("My MacBook Pro");

    assert!(opts.device_id.is_none());
    assert_eq!(opts.device_name.as_deref(), Some("My MacBook Pro"));
    assert!(opts.metadata.is_none());
}

#[test]
fn test_activation_options_full() {
    use std::collections::HashMap;

    let mut metadata = HashMap::new();
    metadata.insert("env".into(), serde_json::json!("production"));

    let opts = ActivationOptions {
        device_id: Some("custom-device-id".into()),
        device_name: Some("Production Server".into()),
        metadata: Some(metadata),
    };

    assert_eq!(opts.device_id.as_deref(), Some("custom-device-id"));
    assert_eq!(opts.device_name.as_deref(), Some("Production Server"));
    assert!(opts.metadata.is_some());
}

// ============================================================================
// Config Tests
// ============================================================================

#[test]
fn test_config_default_values() {
    let config = Config::default();

    assert_eq!(config.api_base_url, "https://licenseseat.com/api/v1");
    assert_eq!(
        config.auto_validate_interval,
        std::time::Duration::from_secs(3600)
    );
    assert_eq!(
        config.heartbeat_interval,
        std::time::Duration::from_secs(300)
    );
    assert!(!config.debug);
    assert!(config.telemetry_enabled);
    assert_eq!(config.max_offline_days, 0);
}

#[test]
fn test_config_new() {
    let config = Config::new("my-api-key", "my-product");

    assert_eq!(config.api_key, "my-api-key");
    assert_eq!(config.product_slug, "my-product");
}

#[test]
fn test_offline_fallback_mode_variants() {
    let modes = vec![
        OfflineFallbackMode::NetworkOnly,
        OfflineFallbackMode::Always,
    ];

    // All modes should be distinct
    for (i, m1) in modes.iter().enumerate() {
        for (j, m2) in modes.iter().enumerate() {
            if i != j {
                assert_ne!(m1, m2);
            }
        }
    }
}

#[test]
fn test_config_builder_methods() {
    let config = Config::new("key", "product")
        .with_debug(true)
        .with_auto_validate_interval(std::time::Duration::from_secs(1800))
        .with_offline_fallback(OfflineFallbackMode::Always)
        .with_max_offline_days(7);

    assert!(config.debug);
    assert_eq!(
        config.auto_validate_interval,
        std::time::Duration::from_secs(1800)
    );
    assert!(matches!(
        config.offline_fallback_mode,
        OfflineFallbackMode::Always
    ));
    assert_eq!(config.max_offline_days, 7);
}

#[test]
fn test_config_custom_values() {
    let config = Config {
        api_key: "custom-key".into(),
        product_slug: "custom-product".into(),
        api_base_url: "https://custom.api.com".into(),
        auto_validate_interval: std::time::Duration::from_secs(1800),
        heartbeat_interval: std::time::Duration::from_secs(60),
        offline_fallback_mode: OfflineFallbackMode::Always,
        max_offline_days: 7,
        debug: true,
        telemetry_enabled: false,
        device_identifier: Some("my-device".into()),
        app_version: Some("1.0.0".into()),
        app_build: Some("42".into()),
        ..Default::default()
    };

    assert_eq!(config.api_key, "custom-key");
    assert_eq!(config.product_slug, "custom-product");
    assert_eq!(config.api_base_url, "https://custom.api.com");
    assert_eq!(
        config.auto_validate_interval,
        std::time::Duration::from_secs(1800)
    );
    assert_eq!(
        config.heartbeat_interval,
        std::time::Duration::from_secs(60)
    );
    assert!(matches!(
        config.offline_fallback_mode,
        OfflineFallbackMode::Always
    ));
    assert_eq!(config.max_offline_days, 7);
    assert!(config.debug);
    assert!(!config.telemetry_enabled);
    assert_eq!(config.device_identifier.as_deref(), Some("my-device"));
    assert_eq!(config.app_version.as_deref(), Some("1.0.0"));
    assert_eq!(config.app_build.as_deref(), Some("42"));
}
