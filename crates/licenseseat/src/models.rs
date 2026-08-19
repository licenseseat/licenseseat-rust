//! Data models for the LicenseSeat SDK.
//!
//! These types mirror the LicenseSeat API response formats and the SDK's
//! offline machine-file/offline-token cache state.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;

#[derive(Clone, Copy)]
struct Redacted;

impl fmt::Debug for Redacted {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("<redacted>")
    }
}

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
#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct Entitlement {
    /// Unique entitlement key.
    pub key: String,
    /// Expiration date (if applicable).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
    /// Exclusive core-semver version ceiling (server-enforced on the
    /// `updates` entitlement since LicenseSeat API 2026-08-19): the license
    /// covers app versions strictly below this. `None` means unbounded, and
    /// servers older than the field never send it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub below_version: Option<String>,
    /// Additional metadata.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<HashMap<String, serde_json::Value>>,
}

impl Entitlement {
    /// Whether this entitlement's version ceiling covers the given app
    /// version — the client-side half of the server's version gate, for
    /// apps that want to enforce locally as well (belt-and-suspenders when
    /// the server was never told the app's version).
    ///
    /// No ceiling covers everything. The comparison matches the server's
    /// rule exactly: **exclusive**, on **core** versions (`"3.0"` counts as
    /// `3.0.0`; a prerelease OF the ceiling is not below it), failing
    /// **open** on unparseable strings — local gating is a second line of
    /// defense and must never brick an app; the server stays authoritative.
    pub fn covers_version(&self, version: &str) -> bool {
        let Some(ceiling) = self.below_version.as_deref() else {
            return true;
        };
        match (core_components(version), core_components(ceiling)) {
            (Some(lhs), Some(rhs)) => lhs < rhs,
            _ => true,
        }
    }
}

/// Lenient core-version parse: `"3.0"` pads to `[3, 0, 0]`, prerelease and
/// build metadata are ignored, anything else is `None`.
fn core_components(version: &str) -> Option<[u64; 3]> {
    let core = version
        .trim()
        .split(['-', '+'])
        .next()
        .filter(|part| !part.is_empty())?;
    let mut numbers = [0u64; 3];
    let mut count = 0;
    for part in core.split('.') {
        if count >= 3 {
            return None;
        }
        numbers[count] = part.parse().ok()?;
        count += 1;
    }
    (count >= 1).then_some(numbers)
}

/// License object as returned by the API.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
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
#[derive(Clone, PartialEq, Serialize, Deserialize)]
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
#[derive(Clone, PartialEq, Serialize, Deserialize)]
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
#[derive(Clone, PartialEq, Serialize, Deserialize)]
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
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
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
#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct License {
    /// The license key.
    pub license_key: String,
    /// Canonical fingerprint this license is activated on.
    pub device_id: String,
    /// Activation ID from the server.
    pub activation_id: String,
    /// When the license was activated.
    pub activated_at: DateTime<Utc>,
    /// When the license was last validated by the authoritative online API.
    ///
    /// Offline verification deliberately does not advance this timestamp. This
    /// preserves a non-sliding record of the last online decision for hosts that
    /// use it in their own policy or diagnostics.
    pub last_validated: DateTime<Utc>,
    /// Last rich license metadata seen from an online response.
    ///
    /// This field is persisted for compatibility and diagnostics. Persistence
    /// is unsigned, so callers must not use it as authorization after process
    /// restart. Use the SDK's status and entitlement APIs instead.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trusted_license: Option<LicenseResponse>,
    /// Current validation state.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub validation: Option<ValidationResult>,
}

impl License {
    /// Preferred alias for the canonical fingerprint.
    pub fn fingerprint(&self) -> &str {
        &self.device_id
    }

    /// Return the immutable fields that identify this exact cached activation.
    pub fn identity(&self) -> LicenseIdentity {
        LicenseIdentity::from(self)
    }
}

/// Immutable identity of one cached activation.
///
/// A license key alone is insufficient to correlate asynchronous responses: the
/// same key can be activated again with a different fingerprint or activation ID
/// while an older request is still in flight.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LicenseIdentity {
    /// License key bound to the activation.
    pub license_key: String,
    /// Canonical installation fingerprint bound to the activation.
    pub fingerprint: String,
    /// Server activation identifier.
    pub activation_id: String,
}

impl From<&License> for LicenseIdentity {
    fn from(license: &License) -> Self {
        Self {
            license_key: license.license_key.clone(),
            fingerprint: license.device_id.clone(),
            activation_id: license.activation_id.clone(),
        }
    }
}

/// License status enum for easy status checking.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
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

/// Source of the authoritative license state held by the current process.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum TrustedLicenseSource {
    /// Legacy diagnostic value for a dedicated unsigned snapshot file.
    ///
    /// Unsigned persisted snapshots are no longer returned as authoritative
    /// runtime state.
    SnapshotFile,
    /// Legacy diagnostic value for an unsigned cached license record.
    ///
    /// Unsigned persisted records are no longer returned as authoritative
    /// runtime state.
    CachedLicense,
    /// State was established by an authenticated online API response.
    OnlineResponse,
    /// State was established by a locally verified signed offline artifact.
    SignedOfflineArtifact,
    /// State is an authoritative or conservative fail-closed denial.
    FailClosedDenial,
}

/// Summary status for the overall SDK/client state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
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

/// A coherent point-in-time view of the license decision held by this SDK.
///
/// The fields in this value are derived from one runtime-state observation.
/// This prevents consumers from combining a status from one license operation
/// with validation or entitlement data committed by another operation.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub struct LicenseStateSnapshot {
    /// Rich status derived from the observed decision.
    pub status: LicenseStatus,
    /// Compact status derived from [`Self::status`].
    pub client_status: ClientStatus,
    /// Whether the most recent API operation considered the service reachable.
    pub is_online: bool,
    /// Runtime-established license, or an untrusted persisted restoration
    /// candidate when no runtime decision exists yet.
    pub license: Option<License>,
    /// Process-authoritative validation decision, if one has been established.
    pub validation: Option<ValidationResult>,
    /// Unexpired entitlements from the same active decision.
    pub active_entitlements: Vec<Entitlement>,
    /// Source that established the process-authoritative decision.
    pub trusted_source: Option<TrustedLicenseSource>,
}

/// Details for an active license.
#[derive(Clone, PartialEq)]
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
#[non_exhaustive]
pub enum EntitlementReason {
    /// No license is activated.
    NoLicense,
    /// Entitlement not found on the license.
    NotFound,
    /// Entitlement has expired.
    Expired,
    /// A license exists, but its latest validation is not an active grant.
    ///
    /// Kept after the original variants so their numeric discriminants remain
    /// stable for compatibility with callers that cast this field.
    InvalidLicense,
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
#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
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
#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
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
        rename = "fingerprint",
        skip_serializing_if = "Option::is_none",
        alias = "device_id",
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
#[serde(deny_unknown_fields)]
pub struct OfflineEntitlement {
    /// Entitlement key.
    pub key: String,
    /// Expiration (Unix timestamp).
    #[serde(default)]
    pub expires_at: Option<i64>,
}

/// Offline token signature block.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OfflineTokenSignature {
    /// Signature algorithm (e.g., "Ed25519").
    pub algorithm: String,
    /// Key ID for public key lookup.
    #[serde(alias = "kid")]
    pub key_id: String,
    /// Standard Base64-encoded signature value used by legacy offline tokens.
    pub value: String,
}

/// Signing key from the API.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
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
#[derive(Clone, PartialEq, Serialize, Deserialize)]
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
#[derive(Clone, PartialEq, Serialize, Deserialize)]
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
    /// Product slug bound through the machine relationship.
    #[serde(default)]
    pub product_slug: String,
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
    /// Check whether an entitlement is currently active in this verified
    /// payload's embedded license.
    ///
    /// This is a convenience for payloads returned by machine-file
    /// verification; it does not independently verify a raw payload.
    pub fn has_entitlement(&self, entitlement_key: &str) -> bool {
        let now = Utc::now();
        self.license
            .as_ref()
            .filter(|license| {
                license.status.eq_ignore_ascii_case("active")
                    && license.starts_at.is_none_or(|start| start <= now)
                    && license.expires_at.is_none_or(|expiry| expiry > now)
            })
            .map(|license| {
                license.active_entitlements.iter().any(|entitlement| {
                    entitlement.key == entitlement_key
                        && entitlement.expires_at.is_none_or(|expiry| expiry > now)
                })
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

impl fmt::Debug for Entitlement {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Entitlement")
            .field("key", &self.key)
            .field("expires_at", &self.expires_at)
            .field("metadata", &Redacted)
            .finish()
    }
}

impl fmt::Debug for LicenseResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LicenseResponse")
            .field("object", &self.object)
            .field("key", &Redacted)
            .field("status", &self.status)
            .field("starts_at", &self.starts_at)
            .field("expires_at", &self.expires_at)
            .field("mode", &self.mode)
            .field("plan_key", &self.plan_key)
            .field("seat_limit", &self.seat_limit)
            .field("active_seats", &self.active_seats)
            .field("active_entitlements", &self.active_entitlements)
            .field("metadata", &Redacted)
            .field("product", &self.product)
            .finish()
    }
}

impl fmt::Debug for ActivationResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ActivationResponse")
            .field("object", &self.object)
            .field("id", &Redacted)
            .field("device_id", &Redacted)
            .field("device_name", &Redacted)
            .field("license_key", &Redacted)
            .field("activated_at", &self.activated_at)
            .field("deactivated_at", &self.deactivated_at)
            .field("ip_address", &Redacted)
            .field("metadata", &Redacted)
            .field("license", &self.license)
            .finish()
    }
}

impl fmt::Debug for ActivationNested {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ActivationNested")
            .field("object", &self.object)
            .field("id", &Redacted)
            .field("device_id", &Redacted)
            .field("device_name", &Redacted)
            .field("license_key", &Redacted)
            .field("activated_at", &self.activated_at)
            .field("deactivated_at", &self.deactivated_at)
            .field("ip_address", &Redacted)
            .field("metadata", &Redacted)
            .finish()
    }
}

impl fmt::Debug for ValidationResult {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ValidationResult")
            .field("object", &self.object)
            .field("valid", &self.valid)
            .field("code", &self.code)
            .field("message", &self.message.as_ref().map(|_| Redacted))
            .field("warnings", &self.warnings)
            .field("license", &self.license)
            .field("activation", &self.activation)
            .field("offline", &self.offline)
            .finish()
    }
}

impl fmt::Debug for DownloadToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DownloadToken")
            .field("object", &self.object)
            .field("token", &Redacted)
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

impl fmt::Debug for License {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("License")
            .field("license_key", &Redacted)
            .field("device_id", &Redacted)
            .field("activation_id", &Redacted)
            .field("activated_at", &self.activated_at)
            .field("last_validated", &self.last_validated)
            .field("trusted_license", &self.trusted_license)
            .field("validation", &self.validation)
            .finish()
    }
}

impl fmt::Debug for LicenseStatusDetails {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LicenseStatusDetails")
            .field("license", &Redacted)
            .field("device", &Redacted)
            .field("activated_at", &self.activated_at)
            .field("last_validated", &self.last_validated)
            .field("entitlements", &self.entitlements)
            .finish()
    }
}

impl fmt::Debug for OfflineTokenResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OfflineTokenResponse")
            .field("object", &self.object)
            .field("token", &self.token)
            .field("signature", &self.signature)
            .field("canonical", &Redacted)
            .finish()
    }
}

impl fmt::Debug for OfflineTokenPayload {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OfflineTokenPayload")
            .field("schema_version", &self.schema_version)
            .field("license_key", &Redacted)
            .field("product_slug", &self.product_slug)
            .field("plan_key", &self.plan_key)
            .field("mode", &self.mode)
            .field("seat_limit", &self.seat_limit)
            .field("device_id", &Redacted)
            .field("iat", &self.iat)
            .field("exp", &self.exp)
            .field("nbf", &self.nbf)
            .field("license_expires_at", &self.license_expires_at)
            .field("kid", &self.kid)
            .field("entitlements", &self.entitlements)
            .field("metadata", &Redacted)
            .finish()
    }
}

impl fmt::Debug for OfflineTokenSignature {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OfflineTokenSignature")
            .field("algorithm", &self.algorithm)
            .field("key_id", &self.key_id)
            .field("value", &Redacted)
            .finish()
    }
}

impl fmt::Debug for SigningKeyResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SigningKeyResponse")
            .field("object", &self.object)
            .field("key_id", &self.key_id)
            .field("algorithm", &self.algorithm)
            .field("public_key", &Redacted)
            .field("created_at", &self.created_at)
            .field("status", &self.status)
            .finish()
    }
}

impl fmt::Debug for MachineFile {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MachineFile")
            .field("certificate", &Redacted)
            .field("algorithm", &self.algorithm)
            .field("ttl", &self.ttl)
            .field("issued_at", &self.issued_at)
            .field("expires_at", &self.expires_at)
            .field("license_key", &Redacted)
            .field("fingerprint", &Redacted)
            .finish()
    }
}

impl fmt::Debug for MachineFilePayload {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MachineFilePayload")
            .field("schema_version", &self.schema_version)
            .field("issued", &self.issued)
            .field("iat", &self.iat)
            .field("expiry", &self.expiry)
            .field("exp", &self.exp)
            .field("nbf", &self.nbf)
            .field("ttl", &self.ttl)
            .field("grace_period", &self.grace_period)
            .field("license_key", &Redacted)
            .field("product_slug", &self.product_slug)
            .field("license_expires_at", &self.license_expires_at)
            .field("key_id", &self.key_id)
            .field("sdk_version", &self.sdk_version)
            .field("machine_id", &Redacted)
            .field("fingerprint", &Redacted)
            .field("fingerprint_components", &Redacted)
            .field("device_name", &Redacted)
            .field("platform", &self.platform)
            .field("created_at", &self.created_at)
            .field("metadata", &Redacted)
            .field("license", &self.license)
            .finish()
    }
}

#[cfg(test)]
mod debug_redaction_tests {
    use super::*;

    const SECRET: &str = "LS-SECRET-LICENSE-KEY";

    #[test]
    fn sensitive_model_debug_output_is_redacted() {
        let now = Utc::now();
        let license = License {
            license_key: SECRET.into(),
            device_id: "secret-fingerprint".into(),
            activation_id: "secret-activation".into(),
            activated_at: now,
            last_validated: now,
            trusted_license: None,
            validation: None,
        };
        let machine_file = MachineFile {
            certificate: "secret-certificate".into(),
            license_key: SECRET.into(),
            fingerprint: "secret-fingerprint".into(),
            ..Default::default()
        };
        let download_token = DownloadToken {
            object: "download_token".into(),
            token: "secret-download-token".into(),
            expires_at: Some(now),
        };

        let output = format!("{license:?} {machine_file:?} {download_token:?}");
        for secret in [
            SECRET,
            "secret-fingerprint",
            "secret-activation",
            "secret-certificate",
            "secret-download-token",
        ] {
            assert!(!output.contains(secret));
        }
        assert!(output.contains("<redacted>"));
    }
}
