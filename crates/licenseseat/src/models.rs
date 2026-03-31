//! Data models for the LicenseSeat SDK.
//!
//! These types mirror the LicenseSeat API response formats and the SDK's
//! offline machine-file/offline-token cache state.

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
    /// Activation ID (UUID/integer serialized as string).
    pub id: String,
    /// Canonical fingerprint used for activation.
    #[serde(alias = "fingerprint", alias = "device_fingerprint")]
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
    /// Object type (optional on nested activation payloads).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub object: String,
    /// Activation ID (UUID/integer serialized as string).
    pub id: String,
    /// Canonical fingerprint.
    #[serde(alias = "fingerprint", alias = "device_fingerprint")]
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

/// Validation result from the API or local offline verification.
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
    /// The activation object (if fingerprint/device_id provided).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub activation: Option<ActivationNested>,
    /// Whether this result came from local offline verification.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub offline: bool,
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

/// Release metadata returned by the API.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Release {
    /// Object type (always "release").
    #[serde(default)]
    pub object: String,
    /// Release version.
    pub version: String,
    /// Release channel.
    pub channel: String,
    /// Release platform.
    pub platform: String,
    /// Product slug the release belongs to.
    pub product_slug: String,
    /// When the release was published.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub published_at: Option<DateTime<Utc>>,
}

/// Paginated release list response returned by the API.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReleaseList {
    /// Envelope object type (typically "list").
    #[serde(default)]
    pub object: String,
    /// Release items.
    #[serde(default)]
    pub data: Vec<Release>,
    /// Whether more pages are available.
    #[serde(default)]
    pub has_more: bool,
    /// Cursor for the next page when available.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
}

/// Download-token response returned by the releases API.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DownloadToken {
    /// Object type (always "download_token").
    #[serde(default)]
    pub object: String,
    /// Signed authorization token.
    pub token: String,
    /// Expiration timestamp.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
}

// ============================================================================
// SDK Internal Types
// ============================================================================

/// Cached license data used by the SDK.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct License {
    /// The license key.
    pub license_key: String,
    /// Canonical fingerprint this license is activated on.
    pub device_id: String,
    /// Activation ID from the server.
    pub activation_id: String,
    /// When the license was activated.
    pub activated_at: DateTime<Utc>,
    /// When the license was last validated online or offline.
    pub last_validated: DateTime<Utc>,
    /// Current validation state.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub validation: Option<ValidationResult>,
}

impl License {
    /// Preferred alias for the canonical fingerprint.
    pub fn fingerprint(&self) -> &str {
        &self.device_id
    }
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

/// Summary status for the overall SDK/client state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClientStatus {
    /// Online-validated license.
    Active,
    /// Offline-validated license.
    OfflineValid,
    /// Offline validation failed.
    OfflineInvalid,
    /// No active license.
    Inactive,
    /// Online validation failed.
    Invalid,
    /// Validation is pending.
    Pending,
}

impl ClientStatus {
    /// Returns the stable string value used by other SDKs.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::OfflineValid => "offline_valid",
            Self::OfflineInvalid => "offline_invalid",
            Self::Inactive => "inactive",
            Self::Invalid => "invalid",
            Self::Pending => "pending",
        }
    }
}

impl std::fmt::Display for ClientStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Details for an active license.
#[derive(Debug, Clone, PartialEq)]
pub struct LicenseStatusDetails {
    /// The license key.
    pub license: String,
    /// Canonical fingerprint.
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

/// Result of restoring a cached license session.
#[derive(Debug, Clone, PartialEq)]
pub struct RestoreResult {
    /// Whether a cached session was restored.
    pub restored: bool,
    /// Current SDK status after the restore attempt.
    pub status: LicenseStatus,
    /// Cached license, if available.
    pub license: Option<License>,
    /// Validation result that drove the final state, if any.
    pub validation: Option<ValidationResult>,
    /// Error message if restore failed.
    pub error: Option<String>,
}

impl Default for RestoreResult {
    fn default() -> Self {
        Self {
            restored: false,
            status: LicenseStatus::Inactive {
                message: "No cached license".into(),
            },
            license: None,
            validation: None,
            error: None,
        }
    }
}

// ============================================================================
// Offline Token / Machine File Types
// ============================================================================

/// Offline token response from the API.
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
    /// Canonical fingerprint / legacy device id.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        alias = "fingerprint",
        alias = "device_fingerprint"
    )]
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
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OfflineEntitlement {
    /// Entitlement key.
    pub key: String,
    /// Expiration (Unix timestamp).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<i64>,
}

/// Offline token signature block.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OfflineTokenSignature {
    /// Signature algorithm (e.g., "Ed25519").
    pub algorithm: String,
    /// Key ID for public key lookup.
    #[serde(alias = "kid")]
    pub key_id: String,
    /// Base64URL-encoded signature value.
    pub value: String,
}

/// Signing key from the API.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SigningKeyResponse {
    /// Object type (always "signing_key").
    pub object: String,
    /// Key ID.
    #[serde(alias = "kid")]
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

/// Cached machine-file metadata and certificate.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MachineFile {
    /// PEM-like certificate returned by the API.
    pub certificate: String,
    /// Machine-file algorithm.
    #[serde(default = "default_machine_file_algorithm")]
    pub algorithm: String,
    /// Requested/actual TTL in seconds.
    #[serde(default)]
    pub ttl: i64,
    /// Issued timestamp.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issued_at: Option<DateTime<Utc>>,
    /// Expiry timestamp.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
    /// License key relationship ID.
    #[serde(default)]
    pub license_key: String,
    /// Machine fingerprint relationship ID.
    #[serde(default)]
    pub fingerprint: String,
}

impl Default for MachineFile {
    fn default() -> Self {
        Self {
            certificate: String::new(),
            algorithm: default_machine_file_algorithm(),
            ttl: 0,
            issued_at: None,
            expires_at: None,
            license_key: String::new(),
            fingerprint: String::new(),
        }
    }
}

/// Decrypted machine-file payload used for offline validation.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MachineFilePayload {
    /// Payload schema version.
    #[serde(default)]
    pub schema_version: u32,
    /// Human-readable issue timestamp.
    #[serde(default)]
    pub issued: String,
    /// Issued-at Unix timestamp.
    #[serde(default)]
    pub iat: i64,
    /// Human-readable expiry timestamp.
    #[serde(default)]
    pub expiry: String,
    /// Expiry Unix timestamp.
    #[serde(default)]
    pub exp: i64,
    /// Not-before Unix timestamp.
    #[serde(default)]
    pub nbf: i64,
    /// TTL in seconds.
    #[serde(default)]
    pub ttl: i64,
    /// Grace period in seconds.
    #[serde(default)]
    pub grace_period: i64,
    /// License key.
    #[serde(default)]
    pub license_key: String,
    /// Underlying license expiration.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub license_expires_at: Option<i64>,
    /// Signing key id.
    #[serde(default)]
    pub key_id: String,
    /// SDK version metadata from the issuer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sdk_version: Option<String>,
    /// Machine/activation id.
    #[serde(default)]
    pub machine_id: String,
    /// Embedded fingerprint.
    #[serde(default)]
    pub fingerprint: String,
    /// Optional structured fingerprint components.
    #[serde(default)]
    pub fingerprint_components: HashMap<String, String>,
    /// Human-readable device name.
    #[serde(default)]
    pub device_name: String,
    /// Platform name.
    #[serde(default)]
    pub platform: String,
    /// Activation creation timestamp.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_at: Option<DateTime<Utc>>,
    /// Activation/device metadata.
    #[serde(default)]
    pub metadata: HashMap<String, serde_json::Value>,
    /// Embedded license object, when included by the API.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub license: Option<LicenseResponse>,
}

impl MachineFilePayload {
    /// Check whether an entitlement is active in this payload.
    pub fn has_entitlement(&self, entitlement_key: &str) -> bool {
        self.license
            .as_ref()
            .map(|license| {
                license
                    .active_entitlements
                    .iter()
                    .any(|entitlement| entitlement.key == entitlement_key)
            })
            .unwrap_or(false)
    }
}

/// Result of local machine-file verification.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MachineFileVerificationResult {
    /// Whether the machine file is valid for this device and license.
    pub valid: bool,
    /// Error code for invalid results.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
    /// Human-readable message.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    /// Decrypted payload on success.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload: Option<MachineFilePayload>,
}

fn default_machine_file_algorithm() -> String {
    "aes-256-gcm+ed25519".to_string()
}
