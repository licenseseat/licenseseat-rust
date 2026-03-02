//! Data models for the LicenseSeat SDK.
//!
//! These types mirror the LicenseSeat API response formats.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ============================================================================
// API Response Types
// ============================================================================

/// Product information included in license responses.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Product {
    /// Product slug identifier.
    pub slug: String,
    /// Product display name.
    pub name: String,
}

/// Entitlement (feature flag) attached to a license.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Entitlement {
    /// Unique entitlement key.
    pub key: String,
    /// Expiration date (if applicable).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
    /// Additional metadata.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<HashMap<String, serde_json::Value>>,
}

/// License object as returned by the API.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LicenseResponse {
    /// Object type (always "license").
    pub object: String,
    /// The license key.
    pub key: String,
    /// License status ("active", "revoked", "suspended", etc.).
    pub status: String,
    /// Start date (if applicable).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub starts_at: Option<DateTime<Utc>>,
    /// Expiration date (null for perpetual).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
    /// License mode ("hardware_locked", "floating", "named_user").
    pub mode: String,
    /// License plan key.
    pub plan_key: String,
    /// Maximum allowed seats (null for unlimited).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seat_limit: Option<u32>,
    /// Currently active seats.
    pub active_seats: u32,
    /// List of active entitlements.
    pub active_entitlements: Vec<Entitlement>,
    /// Additional metadata.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<HashMap<String, serde_json::Value>>,
    /// Product information.
    pub product: Product,
}

/// Activation response from the API.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ActivationResponse {
    /// Object type (always "activation").
    pub object: String,
    /// Activation ID (UUID).
    pub id: String,
    /// Device ID used for activation.
    pub device_id: String,
    /// Human-readable device name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_name: Option<String>,
    /// The license key.
    pub license_key: String,
    /// When the license was activated.
    pub activated_at: DateTime<Utc>,
    /// When the license was deactivated (null if active).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deactivated_at: Option<DateTime<Utc>>,
    /// IP address of activation request.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ip_address: Option<String>,
    /// Additional metadata.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<HashMap<String, serde_json::Value>>,
    /// The license object.
    pub license: LicenseResponse,
}

/// Deactivation response from the API.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeactivationResponse {
    /// Object type (always "deactivation").
    pub object: String,
    /// The deactivated activation ID.
    pub activation_id: String,
    /// When the license was deactivated.
    pub deactivated_at: DateTime<Utc>,
}

/// Validation warning returned by the API.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidationWarning {
    /// Warning code (e.g., "license_expiring_soon").
    pub code: String,
    /// Human-readable warning message.
    pub message: String,
}

/// Nested activation in validation response (avoids circular reference).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ActivationNested {
    /// Activation ID (UUID).
    pub id: String,
    /// Device ID.
    pub device_id: String,
    /// Device name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_name: Option<String>,
    /// License key.
    pub license_key: String,
    /// Activation timestamp.
    pub activated_at: DateTime<Utc>,
    /// Deactivation timestamp.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deactivated_at: Option<DateTime<Utc>>,
    /// IP address.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ip_address: Option<String>,
    /// Metadata.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<HashMap<String, serde_json::Value>>,
}

/// Validation result from the API.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ValidationResult {
    /// Object type (always "validation_result").
    pub object: String,
    /// Whether the license is valid.
    pub valid: bool,
    /// Error code if invalid.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
    /// Error message if invalid.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    /// Non-fatal warnings.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub warnings: Option<Vec<ValidationWarning>>,
    /// The license object.
    pub license: LicenseResponse,
    /// The activation object (if device_id provided).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub activation: Option<ActivationNested>,
}

/// Heartbeat response from the API.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HeartbeatResponse {
    /// Object type (always "heartbeat").
    pub object: String,
    /// When the heartbeat was received.
    pub received_at: DateTime<Utc>,
    /// The license object.
    pub license: LicenseResponse,
}

/// Health check response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HealthResponse {
    /// Object type (always "health").
    pub object: String,
    /// Health status ("healthy").
    pub status: String,
    /// API version string.
    pub api_version: String,
    /// Current server timestamp.
    pub timestamp: DateTime<Utc>,
}

// ============================================================================
// SDK Internal Types
// ============================================================================

/// Cached license data used by the SDK.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct License {
    /// The license key.
    pub license_key: String,
    /// Device ID this license is activated on.
    pub device_id: String,
    /// Activation ID (UUID) from the server.
    pub activation_id: String,
    /// When the license was activated.
    pub activated_at: DateTime<Utc>,
    /// When the license was last validated.
    pub last_validated: DateTime<Utc>,
    /// Current validation state.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub validation: Option<ValidationResult>,
}

/// License status enum for easy status checking.
#[derive(Debug, Clone, PartialEq)]
pub enum LicenseStatus {
    /// No license is activated.
    Inactive {
        /// Reason message.
        message: String,
    },
    /// License is pending validation.
    Pending {
        /// Status message.
        message: String,
    },
    /// License is invalid.
    Invalid {
        /// Reason message.
        message: String,
    },
    /// License is valid (online validated).
    Active {
        /// License details.
        details: LicenseStatusDetails,
    },
    /// License is valid (offline validated).
    OfflineValid {
        /// License details.
        details: LicenseStatusDetails,
    },
    /// License failed offline validation.
    OfflineInvalid {
        /// Reason message.
        message: String,
    },
}

impl LicenseStatus {
    /// Returns true if the license is in an active/valid state.
    pub fn is_active(&self) -> bool {
        matches!(self, Self::Active { .. } | Self::OfflineValid { .. })
    }
}

/// Details for an active license.
#[derive(Debug, Clone, PartialEq)]
pub struct LicenseStatusDetails {
    /// The license key.
    pub license: String,
    /// Device ID.
    pub device: String,
    /// Activation timestamp.
    pub activated_at: DateTime<Utc>,
    /// Last validation timestamp.
    pub last_validated: DateTime<Utc>,
    /// Active entitlements.
    pub entitlements: Vec<Entitlement>,
}

/// Result of checking a specific entitlement.
#[derive(Debug, Clone, PartialEq)]
pub struct EntitlementStatus {
    /// Whether the entitlement is active.
    pub active: bool,
    /// Reason if not active.
    pub reason: Option<EntitlementReason>,
    /// Expiration date if applicable.
    pub expires_at: Option<DateTime<Utc>>,
    /// Full entitlement object if found.
    pub entitlement: Option<Entitlement>,
}

/// Reason why an entitlement is not active.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntitlementReason {
    /// No license is activated.
    NoLicense,
    /// Entitlement not found on the license.
    NotFound,
    /// Entitlement has expired.
    Expired,
}

// ============================================================================
// Offline Token Types (for Ed25519 verification)
// ============================================================================

/// Offline token response from the API.
#[cfg(feature = "offline")]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OfflineTokenResponse {
    /// Object type (always "offline_token").
    pub object: String,
    /// Token payload.
    pub token: OfflineTokenPayload,
    /// Signature block.
    pub signature: OfflineTokenSignature,
    /// Canonical JSON string that was signed.
    pub canonical: String,
}

/// Offline token payload.
#[cfg(feature = "offline")]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OfflineTokenPayload {
    /// Token schema version.
    pub schema_version: u32,
    /// License key.
    pub license_key: String,
    /// Product slug.
    pub product_slug: String,
    /// Plan key.
    pub plan_key: String,
    /// License mode.
    pub mode: String,
    /// Seat limit.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seat_limit: Option<u32>,
    /// Device ID.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_id: Option<String>,
    /// Issued at (Unix timestamp).
    pub iat: i64,
    /// Expires at (Unix timestamp).
    pub exp: i64,
    /// Not before (Unix timestamp).
    pub nbf: i64,
    /// License expiration (Unix timestamp).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub license_expires_at: Option<i64>,
    /// Key ID for signature verification.
    pub kid: String,
    /// Active entitlements.
    pub entitlements: Vec<OfflineEntitlement>,
    /// Metadata.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<HashMap<String, serde_json::Value>>,
}

/// Entitlement in offline token (uses Unix timestamps).
#[cfg(feature = "offline")]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OfflineEntitlement {
    /// Entitlement key.
    pub key: String,
    /// Expiration (Unix timestamp).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<i64>,
}

/// Offline token signature block.
#[cfg(feature = "offline")]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OfflineTokenSignature {
    /// Signature algorithm (e.g., "Ed25519").
    pub algorithm: String,
    /// Key ID for public key lookup.
    pub key_id: String,
    /// Base64URL-encoded signature value.
    pub value: String,
}

/// Signing key from the API.
#[cfg(feature = "offline")]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SigningKeyResponse {
    /// Object type (always "signing_key").
    pub object: String,
    /// Key ID.
    pub key_id: String,
    /// Algorithm.
    pub algorithm: String,
    /// Base64-encoded public key.
    pub public_key: String,
    /// Creation timestamp.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_at: Option<DateTime<Utc>>,
    /// Key status.
    pub status: String,
}
