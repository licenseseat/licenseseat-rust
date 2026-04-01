//! Tauri commands for the LicenseSeat plugin.

use crate::error::Result;
use licenseseat::{
    ActivationNested, ClientStatus, DownloadToken, EntitlementStatus, EventData, HealthResponse,
    HeartbeatResponse, License, LicenseStatus, MachineFile, MachineFilePayload,
    MachineFileVerificationResult, OfflineEntitlement, OfflineTokenPayload,
    OfflineTokenResponse as CoreOfflineTokenResponse, OfflineTokenSignature, Release, ReleaseList,
    RestoreResult, SigningKeyResponse, ValidationResult,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use tauri::State;

/// Activation options passed from the frontend.
#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ActivationOptions {
    /// Canonical fingerprint.
    pub fingerprint: Option<String>,
    /// Custom device ID.
    pub device_id: Option<String>,
    /// Legacy compatibility alias for the canonical fingerprint.
    pub device_fingerprint: Option<String>,
    /// Human-readable device name.
    pub device_name: Option<String>,
    /// Additional metadata.
    pub metadata: Option<HashMap<String, serde_json::Value>>,
}

/// Simplified license response for the frontend.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LicenseResponse {
    pub license_key: String,
    pub device_id: String,
    pub activation_id: String,
    pub activated_at: String,
}

impl From<License> for LicenseResponse {
    fn from(license: License) -> Self {
        Self {
            license_key: license.license_key,
            device_id: license.device_id,
            activation_id: license.activation_id,
            activated_at: license.activated_at.to_rfc3339(),
        }
    }
}

/// Product details in a validation response.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProductResponse {
    pub slug: String,
    pub name: String,
}

/// Active entitlement included in validation or listing responses.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EntitlementRecordResponse {
    pub key: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<HashMap<String, serde_json::Value>>,
}

impl From<licenseseat::Entitlement> for EntitlementRecordResponse {
    fn from(entitlement: licenseseat::Entitlement) -> Self {
        Self {
            key: entitlement.key,
            expires_at: entitlement.expires_at.map(|value| value.to_rfc3339()),
            metadata: entitlement.metadata,
        }
    }
}

/// Validation warning returned to the frontend.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ValidationWarningResponse {
    pub code: String,
    pub message: String,
}

/// License details in a validation response.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ValidationLicenseResponse {
    pub object: String,
    pub key: String,
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub starts_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
    pub mode: String,
    pub plan_key: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub seat_limit: Option<u32>,
    pub active_seats: u32,
    pub active_entitlements: Vec<EntitlementRecordResponse>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<HashMap<String, serde_json::Value>>,
    pub product: ProductResponse,
}

/// Activation details in a validation response.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ActivationSummaryResponse {
    pub object: String,
    pub id: String,
    pub device_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_name: Option<String>,
    pub license_key: String,
    pub activated_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deactivated_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip_address: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<HashMap<String, serde_json::Value>>,
}

/// Validation result returned to the frontend.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ValidationResultResponse {
    pub object: String,
    pub valid: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub warnings: Option<Vec<ValidationWarningResponse>>,
    pub license: ValidationLicenseResponse,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub activation: Option<ActivationSummaryResponse>,
    pub offline: bool,
}

impl From<ValidationResult> for ValidationResultResponse {
    fn from(result: ValidationResult) -> Self {
        let ValidationResult {
            object,
            valid,
            code,
            message,
            warnings,
            license,
            activation,
            offline,
        } = result;

        let warnings = warnings.map(map_validation_warnings);
        let license = map_validation_license_response(license);
        let activation = activation.map(map_activation_summary_response);

        Self {
            object,
            valid,
            code,
            message,
            warnings,
            license,
            activation,
            offline,
        }
    }
}

fn map_validation_warnings(
    warnings: Vec<licenseseat::ValidationWarning>,
) -> Vec<ValidationWarningResponse> {
    warnings
        .into_iter()
        .map(|warning| ValidationWarningResponse {
            code: warning.code,
            message: warning.message,
        })
        .collect()
}

fn map_validation_license_response(
    license: licenseseat::LicenseResponse,
) -> ValidationLicenseResponse {
    ValidationLicenseResponse {
        object: license.object,
        key: license.key,
        status: license.status,
        starts_at: license.starts_at.map(|value| value.to_rfc3339()),
        expires_at: license.expires_at.map(|value| value.to_rfc3339()),
        mode: license.mode,
        plan_key: license.plan_key,
        seat_limit: license.seat_limit,
        active_seats: license.active_seats,
        active_entitlements: license
            .active_entitlements
            .into_iter()
            .map(Into::into)
            .collect(),
        metadata: license.metadata,
        product: ProductResponse {
            slug: license.product.slug,
            name: license.product.name,
        },
    }
}

impl From<licenseseat::LicenseResponse> for ValidationLicenseResponse {
    fn from(license: licenseseat::LicenseResponse) -> Self {
        map_validation_license_response(license)
    }
}

fn map_activation_summary_response(activation: ActivationNested) -> ActivationSummaryResponse {
    ActivationSummaryResponse {
        object: activation.object,
        id: activation.id,
        device_id: activation.device_id,
        device_name: activation.device_name,
        license_key: activation.license_key,
        activated_at: activation.activated_at.to_rfc3339(),
        deactivated_at: activation.deactivated_at.map(|value| value.to_rfc3339()),
        ip_address: activation.ip_address,
        metadata: activation.metadata,
    }
}

/// Release metadata returned to the frontend.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReleaseResponse {
    pub object: String,
    pub version: String,
    pub channel: String,
    pub platform: String,
    pub product_slug: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub published_at: Option<String>,
}

impl From<Release> for ReleaseResponse {
    fn from(release: Release) -> Self {
        Self {
            object: release.object,
            version: release.version,
            channel: release.channel,
            platform: release.platform,
            product_slug: release.product_slug,
            published_at: release.published_at.map(|value| value.to_rfc3339()),
        }
    }
}

/// Paginated release list returned to the frontend.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReleaseListResponse {
    pub object: String,
    pub data: Vec<ReleaseResponse>,
    pub has_more: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
}

impl From<ReleaseList> for ReleaseListResponse {
    fn from(releases: ReleaseList) -> Self {
        Self {
            object: releases.object,
            data: releases.data.into_iter().map(Into::into).collect(),
            has_more: releases.has_more,
            next_cursor: releases.next_cursor,
        }
    }
}

/// Download token returned to the frontend.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DownloadTokenResponse {
    pub object: String,
    pub token: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
}

impl From<DownloadToken> for DownloadTokenResponse {
    fn from(token: DownloadToken) -> Self {
        Self {
            object: token.object,
            token: token.token,
            expires_at: token.expires_at.map(|value| value.to_rfc3339()),
        }
    }
}

/// Machine-file metadata returned to the frontend.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MachineFileResponse {
    pub certificate: String,
    pub algorithm: String,
    pub ttl: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issued_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
    pub license_key: String,
    pub fingerprint: String,
}

impl From<MachineFile> for MachineFileResponse {
    fn from(machine_file: MachineFile) -> Self {
        Self {
            certificate: machine_file.certificate,
            algorithm: machine_file.algorithm,
            ttl: machine_file.ttl,
            issued_at: machine_file.issued_at.map(|value| value.to_rfc3339()),
            expires_at: machine_file.expires_at.map(|value| value.to_rfc3339()),
            license_key: machine_file.license_key,
            fingerprint: machine_file.fingerprint,
        }
    }
}

impl From<MachineFileResponse> for MachineFile {
    fn from(machine_file: MachineFileResponse) -> Self {
        Self {
            certificate: machine_file.certificate,
            algorithm: machine_file.algorithm,
            ttl: machine_file.ttl,
            issued_at: machine_file
                .issued_at
                .and_then(|value| chrono::DateTime::parse_from_rfc3339(&value).ok())
                .map(|value| value.with_timezone(&chrono::Utc)),
            expires_at: machine_file
                .expires_at
                .and_then(|value| chrono::DateTime::parse_from_rfc3339(&value).ok())
                .map(|value| value.with_timezone(&chrono::Utc)),
            license_key: machine_file.license_key,
            fingerprint: machine_file.fingerprint,
        }
    }
}

/// Offline entitlement returned to the frontend.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OfflineEntitlementResponse {
    pub key: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<i64>,
}

impl From<OfflineEntitlement> for OfflineEntitlementResponse {
    fn from(entitlement: OfflineEntitlement) -> Self {
        Self {
            key: entitlement.key,
            expires_at: entitlement.expires_at,
        }
    }
}

impl From<OfflineEntitlementResponse> for OfflineEntitlement {
    fn from(entitlement: OfflineEntitlementResponse) -> Self {
        Self {
            key: entitlement.key,
            expires_at: entitlement.expires_at,
        }
    }
}

/// Offline token payload returned to or accepted from the frontend.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OfflineTokenPayloadResponse {
    pub schema_version: u32,
    pub license_key: String,
    pub product_slug: String,
    pub plan_key: String,
    pub mode: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub seat_limit: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_id: Option<String>,
    pub iat: i64,
    pub exp: i64,
    pub nbf: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub license_expires_at: Option<i64>,
    pub kid: String,
    pub entitlements: Vec<OfflineEntitlementResponse>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<HashMap<String, serde_json::Value>>,
}

impl From<OfflineTokenPayload> for OfflineTokenPayloadResponse {
    fn from(payload: OfflineTokenPayload) -> Self {
        Self {
            schema_version: payload.schema_version,
            license_key: payload.license_key,
            product_slug: payload.product_slug,
            plan_key: payload.plan_key,
            mode: payload.mode,
            seat_limit: payload.seat_limit,
            device_id: payload.device_id,
            iat: payload.iat,
            exp: payload.exp,
            nbf: payload.nbf,
            license_expires_at: payload.license_expires_at,
            kid: payload.kid,
            entitlements: payload.entitlements.into_iter().map(Into::into).collect(),
            metadata: payload.metadata,
        }
    }
}

impl From<OfflineTokenPayloadResponse> for OfflineTokenPayload {
    fn from(payload: OfflineTokenPayloadResponse) -> Self {
        Self {
            schema_version: payload.schema_version,
            license_key: payload.license_key,
            product_slug: payload.product_slug,
            plan_key: payload.plan_key,
            mode: payload.mode,
            seat_limit: payload.seat_limit,
            device_id: payload.device_id,
            iat: payload.iat,
            exp: payload.exp,
            nbf: payload.nbf,
            license_expires_at: payload.license_expires_at,
            kid: payload.kid,
            entitlements: payload.entitlements.into_iter().map(Into::into).collect(),
            metadata: payload.metadata,
        }
    }
}

/// Offline token signature returned to or accepted from the frontend.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OfflineTokenSignatureResponse {
    pub algorithm: String,
    pub key_id: String,
    pub value: String,
}

impl From<OfflineTokenSignature> for OfflineTokenSignatureResponse {
    fn from(signature: OfflineTokenSignature) -> Self {
        Self {
            algorithm: signature.algorithm,
            key_id: signature.key_id,
            value: signature.value,
        }
    }
}

impl From<OfflineTokenSignatureResponse> for OfflineTokenSignature {
    fn from(signature: OfflineTokenSignatureResponse) -> Self {
        Self {
            algorithm: signature.algorithm,
            key_id: signature.key_id,
            value: signature.value,
        }
    }
}

/// Legacy offline token returned to or accepted from the frontend.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OfflineTokenResponse {
    pub object: String,
    pub token: OfflineTokenPayloadResponse,
    pub signature: OfflineTokenSignatureResponse,
    pub canonical: String,
}

impl From<CoreOfflineTokenResponse> for OfflineTokenResponse {
    fn from(response: CoreOfflineTokenResponse) -> Self {
        Self {
            object: response.object,
            token: response.token.into(),
            signature: response.signature.into(),
            canonical: response.canonical,
        }
    }
}

impl From<OfflineTokenResponse> for CoreOfflineTokenResponse {
    fn from(response: OfflineTokenResponse) -> Self {
        Self {
            object: response.object,
            token: response.token.into(),
            signature: response.signature.into(),
            canonical: response.canonical,
        }
    }
}

/// Decrypted machine-file payload returned to the frontend.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MachineFilePayloadResponse {
    pub schema_version: u32,
    pub issued: String,
    pub iat: i64,
    pub expiry: String,
    pub exp: i64,
    pub nbf: i64,
    pub ttl: i64,
    pub grace_period: i64,
    pub license_key: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub license_expires_at: Option<i64>,
    pub key_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sdk_version: Option<String>,
    pub machine_id: String,
    pub fingerprint: String,
    pub fingerprint_components: HashMap<String, String>,
    pub device_name: String,
    pub platform: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_at: Option<String>,
    pub metadata: HashMap<String, serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub license: Option<ValidationLicenseResponse>,
}

impl From<MachineFilePayload> for MachineFilePayloadResponse {
    fn from(payload: MachineFilePayload) -> Self {
        Self {
            schema_version: payload.schema_version,
            issued: payload.issued,
            iat: payload.iat,
            expiry: payload.expiry,
            exp: payload.exp,
            nbf: payload.nbf,
            ttl: payload.ttl,
            grace_period: payload.grace_period,
            license_key: payload.license_key,
            license_expires_at: payload.license_expires_at,
            key_id: payload.key_id,
            sdk_version: payload.sdk_version,
            machine_id: payload.machine_id,
            fingerprint: payload.fingerprint,
            fingerprint_components: payload.fingerprint_components,
            device_name: payload.device_name,
            platform: payload.platform,
            created_at: payload.created_at.map(|value| value.to_rfc3339()),
            metadata: payload.metadata,
            license: payload.license.map(map_validation_license_response),
        }
    }
}

/// Result of machine-file verification returned to the frontend.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MachineFileVerificationResultResponse {
    pub valid: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payload: Option<MachineFilePayloadResponse>,
}

impl From<MachineFileVerificationResult> for MachineFileVerificationResultResponse {
    fn from(result: MachineFileVerificationResult) -> Self {
        Self {
            valid: result.valid,
            code: result.code,
            message: result.message,
            payload: result.payload.map(Into::into),
        }
    }
}

/// Restore result returned to the frontend.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RestoreResponse {
    pub restored: bool,
    pub status: StatusResponse,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub license: Option<LicenseResponse>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub validation: Option<ValidationResultResponse>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl From<RestoreResult> for RestoreResponse {
    fn from(result: RestoreResult) -> Self {
        Self {
            restored: result.restored,
            status: result.status.into(),
            license: result.license.map(Into::into),
            validation: result.validation.map(Into::into),
            error: result.error,
        }
    }
}

/// Aggregated runtime state returned to the frontend.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StateResponse {
    pub status: StatusResponse,
    pub client_status: String,
    pub is_online: bool,
    pub fingerprint: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub license: Option<LicenseResponse>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub validation: Option<ValidationResultResponse>,
    pub entitlements: Vec<EntitlementRecordResponse>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub plan_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub license_mode: Option<String>,
    pub is_activated: bool,
    pub is_valid: bool,
    pub is_offline: bool,
}

fn map_state_response(sdk: &licenseseat::LicenseSeat) -> StateResponse {
    let status = sdk.status();
    let client_status = sdk.get_client_status();
    let license = sdk.current_license();
    let validation = license
        .as_ref()
        .and_then(|cached| cached.validation.clone());
    let entitlements = validation
        .as_ref()
        .map(|result| {
            result
                .license
                .active_entitlements
                .clone()
                .into_iter()
                .map(Into::into)
                .collect()
        })
        .unwrap_or_default();
    let plan_key = validation
        .as_ref()
        .map(|result| result.license.plan_key.clone());
    let license_mode = validation
        .as_ref()
        .map(|result| result.license.mode.clone());
    let is_activated = license.is_some();
    let is_valid = matches!(
        client_status,
        ClientStatus::Active | ClientStatus::OfflineValid
    );
    let is_offline = matches!(
        client_status,
        ClientStatus::OfflineValid | ClientStatus::OfflineInvalid
    );

    StateResponse {
        status: status.into(),
        client_status: client_status.to_string(),
        is_online: sdk.is_online(),
        fingerprint: sdk.fingerprint().to_string(),
        license: license.map(Into::into),
        validation: validation.map(Into::into),
        entitlements,
        plan_key,
        license_mode,
        is_activated,
        is_valid,
        is_offline,
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HeartbeatResponseRecord {
    pub object: String,
    pub received_at: String,
    pub license: ValidationLicenseResponse,
}

impl From<HeartbeatResponse> for HeartbeatResponseRecord {
    fn from(response: HeartbeatResponse) -> Self {
        Self {
            object: response.object,
            received_at: response.received_at.to_rfc3339(),
            license: map_validation_license_response(response.license),
        }
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HealthResponseRecord {
    pub object: String,
    pub status: String,
    pub api_version: String,
    pub timestamp: String,
}

impl From<HealthResponse> for HealthResponseRecord {
    fn from(response: HealthResponse) -> Self {
        Self {
            object: response.object,
            status: response.status,
            api_version: response.api_version,
            timestamp: response.timestamp.to_rfc3339(),
        }
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SigningKeyResponseRecord {
    pub object: String,
    pub key_id: String,
    pub algorithm: String,
    pub public_key: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_at: Option<String>,
    pub status: String,
}

impl From<SigningKeyResponse> for SigningKeyResponseRecord {
    fn from(response: SigningKeyResponse) -> Self {
        Self {
            object: response.object,
            key_id: response.key_id,
            algorithm: response.algorithm,
            public_key: response.public_key,
            created_at: response.created_at.map(|value| value.to_rfc3339()),
            status: response.status,
        }
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AdminConfigResponse {
    pub api_base_url: String,
    pub api_key: String,
    pub product_slug: String,
    pub storage_prefix: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub storage_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_identifier: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signing_public_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signing_key_id: Option<String>,
    pub auto_validate_interval_seconds: u64,
    pub heartbeat_interval_seconds: u64,
    pub network_recheck_interval_seconds: u64,
    pub request_timeout_seconds: u64,
    pub verify_ssl: bool,
    pub offline_fallback_mode: String,
    pub offline_token_refresh_interval_seconds: u64,
    pub enable_legacy_offline_tokens: bool,
    pub max_offline_days: u32,
    pub telemetry_enabled: bool,
    pub debug: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub app_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub app_build: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AdminCachePathsResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cache_dir: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub license_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub license_snapshot_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub machine_file_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub offline_token_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_seen_timestamp_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signing_key_path: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AdminRuntimeResponse {
    pub is_auto_validating: bool,
    pub is_heartbeat_running: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_auto_validation_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_seen_timestamp: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_heartbeat: Option<HeartbeatResponseRecord>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_heartbeat_error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_health: Option<HealthResponseRecord>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_health_error: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AdminSnapshotResponse {
    pub captured_at: String,
    pub config: AdminConfigResponse,
    pub cache_paths: AdminCachePathsResponse,
    pub state: StateResponse,
    pub runtime: AdminRuntimeResponse,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signing_key_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trusted_license: Option<ValidationLicenseResponse>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trusted_license_source: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub offline_token: Option<OfflineTokenResponse>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub machine_file: Option<MachineFileResponse>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub machine_file_verification: Option<MachineFileVerificationResultResponse>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signing_key: Option<SigningKeyResponseRecord>,
}

fn cache_dir_for_config(config: &licenseseat::Config) -> Option<PathBuf> {
    config
        .storage_path
        .clone()
        .or_else(|| dirs::cache_dir().map(|dir| dir.join("licenseseat")))
}

fn cache_path_for_key(config: &licenseseat::Config, key: &str) -> Option<String> {
    cache_dir_for_config(config)
        .map(|dir| dir.join(format!("{}{}.json", config.storage_prefix, key)))
        .map(|path| path.to_string_lossy().into_owned())
}

fn build_admin_config_response(config: &licenseseat::Config) -> AdminConfigResponse {
    let offline_fallback_mode = match config.offline_fallback_mode {
        licenseseat::OfflineFallbackMode::Always => "always",
        licenseseat::OfflineFallbackMode::NetworkOnly => "networkOnly",
    };

    AdminConfigResponse {
        api_base_url: config.api_base_url.clone(),
        api_key: config.api_key.clone(),
        product_slug: config.product_slug.clone(),
        storage_prefix: config.storage_prefix.clone(),
        storage_path: config
            .storage_path
            .as_ref()
            .map(|value| value.to_string_lossy().into_owned()),
        device_identifier: config.device_identifier.clone(),
        signing_public_key: config.signing_public_key.clone(),
        signing_key_id: config.signing_key_id.clone(),
        auto_validate_interval_seconds: config.auto_validate_interval.as_secs(),
        heartbeat_interval_seconds: config.heartbeat_interval.as_secs(),
        network_recheck_interval_seconds: config.network_recheck_interval.as_secs(),
        request_timeout_seconds: config.request_timeout.as_secs(),
        verify_ssl: config.verify_ssl,
        offline_fallback_mode: offline_fallback_mode.into(),
        offline_token_refresh_interval_seconds: config.offline_token_refresh_interval.as_secs(),
        enable_legacy_offline_tokens: config.enable_legacy_offline_tokens,
        max_offline_days: config.max_offline_days,
        telemetry_enabled: config.telemetry_enabled,
        debug: config.debug,
        app_version: config.app_version.clone(),
        app_build: config.app_build.clone(),
    }
}

fn build_admin_cache_paths_response(
    config: &licenseseat::Config,
    signing_key_id: Option<&str>,
) -> AdminCachePathsResponse {
    AdminCachePathsResponse {
        cache_dir: cache_dir_for_config(config).map(|value| value.to_string_lossy().into_owned()),
        license_path: cache_path_for_key(config, "license"),
        license_snapshot_path: cache_path_for_key(config, "license_snapshot"),
        machine_file_path: cache_path_for_key(config, "machine_file"),
        offline_token_path: cache_path_for_key(config, "offline_token"),
        last_seen_timestamp_path: cache_path_for_key(config, "last_seen_ts"),
        signing_key_path: signing_key_id.and_then(|value| {
            if value.is_empty() {
                None
            } else {
                cache_path_for_key(config, &format!("signing_key_{value}"))
            }
        }),
    }
}

fn map_admin_snapshot_response(
    sdk: &licenseseat::LicenseSeat,
    config: &licenseseat::Config,
) -> AdminSnapshotResponse {
    let trusted_license = sdk.current_trusted_license().map(Into::into);
    let trusted_license_source = sdk
        .current_trusted_license_source()
        .map(|source| match source {
            licenseseat::TrustedLicenseSource::SnapshotFile => "snapshot_file".to_string(),
            licenseseat::TrustedLicenseSource::CachedLicense => "cached_license".to_string(),
        });
    let machine_file = sdk.current_machine_file();
    let signing_key_id = sdk
        .current_machine_file_key_id()
        .or_else(|| config.signing_key_id.clone());
    let machine_file_verification = machine_file.as_ref().map(|value| {
        sdk.inspect_machine_file(value, None, None, None)
            .map(Into::into)
            .unwrap_or_else(|error| MachineFileVerificationResultResponse {
                valid: false,
                code: None,
                message: Some(error.to_string()),
                payload: None,
            })
    });
    let signing_key_id = machine_file_verification
        .as_ref()
        .and_then(|value| value.payload.as_ref().map(|payload| payload.key_id.clone()))
        .or_else(|| signing_key_id.clone())
        .or_else(|| config.signing_key_id.clone());
    let signing_key = signing_key_id
        .as_deref()
        .and_then(|value| {
            if value.is_empty() {
                None
            } else {
                sdk.cached_signing_key(value)
            }
        })
        .map(Into::into);

    AdminSnapshotResponse {
        captured_at: chrono::Utc::now().to_rfc3339(),
        config: build_admin_config_response(config),
        cache_paths: build_admin_cache_paths_response(config, signing_key_id.as_deref()),
        state: map_state_response(sdk),
        runtime: AdminRuntimeResponse {
            is_auto_validating: sdk.is_auto_validating(),
            is_heartbeat_running: sdk.is_heartbeat_running(),
            next_auto_validation_at: sdk
                .next_auto_validation_at()
                .map(|value| value.to_rfc3339()),
            last_seen_timestamp: sdk.last_seen_timestamp(),
            last_heartbeat: sdk.last_heartbeat_response().map(Into::into),
            last_heartbeat_error: sdk.last_heartbeat_error(),
            last_health: sdk.last_health_response().map(Into::into),
            last_health_error: sdk.last_health_error(),
        },
        signing_key_id,
        trusted_license,
        trusted_license_source,
        offline_token: sdk.current_offline_token().map(Into::into),
        machine_file: machine_file.map(Into::into),
        machine_file_verification,
        signing_key,
    }
}

/// Release-list options passed from the frontend.
#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReleaseListOptionsInput {
    pub channel: Option<String>,
    pub platform: Option<String>,
    pub limit: Option<u32>,
}

/// Machine-file checkout options passed from the frontend.
#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MachineFileCheckoutOptionsInput {
    pub fingerprint: Option<String>,
    pub device_id: Option<String>,
    pub device_fingerprint: Option<String>,
    pub ttl_days: Option<i64>,
    pub grace_period_days: Option<i64>,
    pub include_license: Option<bool>,
    pub fingerprint_components: Option<HashMap<String, String>>,
}

/// Manual machine-file verification options passed from the frontend.
#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MachineFileVerificationOptionsInput {
    pub public_key_b64: Option<String>,
    pub license_key: Option<String>,
    pub fingerprint: Option<String>,
}

/// Status response for the frontend.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StatusResponse {
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub license: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub activated_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_validated: Option<String>,
}

impl From<LicenseStatus> for StatusResponse {
    fn from(status: LicenseStatus) -> Self {
        match status {
            LicenseStatus::Inactive { message } => Self {
                status: "inactive".into(),
                message: Some(message),
                license: None,
                device: None,
                activated_at: None,
                last_validated: None,
            },
            LicenseStatus::Pending { message } => Self {
                status: "pending".into(),
                message: Some(message),
                license: None,
                device: None,
                activated_at: None,
                last_validated: None,
            },
            LicenseStatus::Invalid { message } => Self {
                status: "invalid".into(),
                message: Some(message),
                license: None,
                device: None,
                activated_at: None,
                last_validated: None,
            },
            LicenseStatus::Active { details } => Self {
                status: "active".into(),
                message: None,
                license: Some(details.license),
                device: Some(details.device),
                activated_at: Some(details.activated_at.to_rfc3339()),
                last_validated: Some(details.last_validated.to_rfc3339()),
            },
            LicenseStatus::OfflineValid { details } => Self {
                status: "offline_valid".into(),
                message: None,
                license: Some(details.license),
                device: Some(details.device),
                activated_at: Some(details.activated_at.to_rfc3339()),
                last_validated: Some(details.last_validated.to_rfc3339()),
            },
            LicenseStatus::OfflineInvalid { message } => Self {
                status: "offline_invalid".into(),
                message: Some(message),
                license: None,
                device: None,
                activated_at: None,
                last_validated: None,
            },
        }
    }
}

/// Entitlement response for the frontend.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EntitlementResponse {
    pub active: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
}

impl From<EntitlementStatus> for EntitlementResponse {
    fn from(status: EntitlementStatus) -> Self {
        Self {
            active: status.active,
            reason: status.reason.map(|r| format!("{:?}", r).to_lowercase()),
            expires_at: status.expires_at.map(|d| d.to_rfc3339()),
        }
    }
}

// ============================================================================
// Commands
// ============================================================================

/// Activate a license key.
#[tauri::command]
pub async fn activate(
    sdk: State<'_, licenseseat::LicenseSeat>,
    license_key: String,
    options: Option<ActivationOptions>,
) -> Result<LicenseResponse> {
    let opts = options.unwrap_or_default();

    let sdk_opts = licenseseat::ActivationOptions {
        fingerprint: opts.fingerprint,
        device_id: opts.device_id,
        device_fingerprint: opts.device_fingerprint,
        device_name: opts.device_name,
        metadata: opts.metadata,
    };

    let license = sdk.activate_with_options(&license_key, sdk_opts).await?;
    Ok(license.into())
}

/// Validate a specific license key.
#[tauri::command]
pub async fn validate_key(
    sdk: State<'_, licenseseat::LicenseSeat>,
    license_key: String,
) -> Result<ValidationResultResponse> {
    let result = sdk.validate_key(&license_key).await?;
    Ok(result.into())
}

/// Validate the current license.
#[tauri::command]
pub async fn validate(
    sdk: State<'_, licenseseat::LicenseSeat>,
) -> Result<ValidationResultResponse> {
    let result = sdk.validate().await?;
    Ok(result.into())
}

/// Deactivate the current license.
#[tauri::command]
pub async fn deactivate(sdk: State<'_, licenseseat::LicenseSeat>) -> Result<()> {
    sdk.deactivate().await?;
    Ok(())
}

/// Deactivate an explicit license/fingerprint pair.
#[tauri::command]
pub async fn deactivate_key(
    sdk: State<'_, licenseseat::LicenseSeat>,
    license_key: String,
    fingerprint: Option<String>,
) -> Result<()> {
    sdk.deactivate_key(&license_key, fingerprint.as_deref())
        .await?;
    Ok(())
}

/// Send a heartbeat.
#[tauri::command]
pub async fn heartbeat(sdk: State<'_, licenseseat::LicenseSeat>) -> Result<()> {
    sdk.heartbeat().await?;
    Ok(())
}

/// Send a heartbeat for an explicit license/fingerprint pair.
#[tauri::command]
pub async fn heartbeat_key(
    sdk: State<'_, licenseseat::LicenseSeat>,
    license_key: String,
    fingerprint: Option<String>,
) -> Result<()> {
    sdk.heartbeat_key(&license_key, fingerprint.as_deref())
        .await?;
    Ok(())
}

/// Get the current license status.
#[tauri::command]
pub fn get_status(sdk: State<'_, licenseseat::LicenseSeat>) -> StatusResponse {
    sdk.status().into()
}

/// Get the stable client status string.
#[tauri::command]
pub fn get_client_status(sdk: State<'_, licenseseat::LicenseSeat>) -> String {
    sdk.get_client_status().to_string()
}

/// Whether the SDK currently believes the API is reachable.
#[tauri::command]
pub fn is_online(sdk: State<'_, licenseseat::LicenseSeat>) -> bool {
    sdk.is_online()
}

/// Get the current SDK fingerprint.
#[tauri::command]
pub fn get_fingerprint(sdk: State<'_, licenseseat::LicenseSeat>) -> String {
    sdk.fingerprint().to_string()
}

/// Restore a cached license session.
#[tauri::command]
pub async fn restore_license(sdk: State<'_, licenseseat::LicenseSeat>) -> Result<RestoreResponse> {
    Ok(sdk.restore_license().await.into())
}

/// Check whether the API is reachable.
#[tauri::command]
pub async fn health(sdk: State<'_, licenseseat::LicenseSeat>) -> Result<bool> {
    Ok(sdk.health().await?)
}

/// Check if an entitlement is active.
#[tauri::command]
pub fn check_entitlement(
    sdk: State<'_, licenseseat::LicenseSeat>,
    entitlement_key: String,
) -> EntitlementResponse {
    sdk.check_entitlement(&entitlement_key).into()
}

/// List the current active entitlements from the cached validation result.
#[tauri::command]
pub fn get_entitlements(
    sdk: State<'_, licenseseat::LicenseSeat>,
) -> Vec<EntitlementRecordResponse> {
    sdk.current_license()
        .and_then(|license| license.validation)
        .map(|validation| {
            validation
                .license
                .active_entitlements
                .into_iter()
                .map(Into::into)
                .collect()
        })
        .unwrap_or_default()
}

/// Check if an entitlement is active (returns bool).
#[tauri::command]
pub fn has_entitlement(sdk: State<'_, licenseseat::LicenseSeat>, entitlement_key: String) -> bool {
    sdk.has_entitlement(&entitlement_key)
}

/// Get the current cached license.
#[tauri::command]
pub fn get_license(sdk: State<'_, licenseseat::LicenseSeat>) -> Option<LicenseResponse> {
    sdk.current_license().map(Into::into)
}

/// Get a consolidated view of the current plugin state.
#[tauri::command]
pub fn get_state(sdk: State<'_, licenseseat::LicenseSeat>) -> StateResponse {
    map_state_response(&sdk)
}

#[tauri::command]
pub fn get_admin_snapshot(
    sdk: State<'_, licenseseat::LicenseSeat>,
    config: State<'_, licenseseat::Config>,
) -> AdminSnapshotResponse {
    map_admin_snapshot_response(&sdk, &config)
}

/// Get the latest release for a product.
#[tauri::command]
pub async fn get_latest_release(
    sdk: State<'_, licenseseat::LicenseSeat>,
    product_slug: Option<String>,
    channel: Option<String>,
    platform: Option<String>,
) -> Result<ReleaseResponse> {
    let release = sdk
        .get_latest_release(
            product_slug.as_deref(),
            channel.as_deref(),
            platform.as_deref(),
        )
        .await?;
    Ok(release.into())
}

/// List releases for a product with pagination metadata.
#[tauri::command]
pub async fn list_releases(
    sdk: State<'_, licenseseat::LicenseSeat>,
    product_slug: Option<String>,
    options: Option<ReleaseListOptionsInput>,
) -> Result<ReleaseListResponse> {
    let options = options.unwrap_or_default();
    let releases = sdk
        .list_releases_with_options(
            product_slug.as_deref(),
            licenseseat::ReleaseListOptions {
                channel: options.channel,
                platform: options.platform,
                limit: options.limit,
            },
        )
        .await?;
    Ok(releases.into())
}

/// Generate a download token for a release.
#[tauri::command]
pub async fn generate_download_token(
    sdk: State<'_, licenseseat::LicenseSeat>,
    version: String,
    license_key: String,
    product_slug: Option<String>,
    platform: Option<String>,
) -> Result<DownloadTokenResponse> {
    let token = sdk
        .generate_download_token(
            &version,
            &license_key,
            product_slug.as_deref(),
            platform.as_deref(),
        )
        .await?;
    Ok(token.into())
}

/// Generate a legacy offline token for manual/offline workflows.
#[tauri::command]
pub async fn generate_offline_token(
    sdk: State<'_, licenseseat::LicenseSeat>,
    license_key: String,
    fingerprint: Option<String>,
    ttl_days: Option<i64>,
) -> Result<OfflineTokenResponse> {
    let token = sdk
        .generate_offline_token(&license_key, fingerprint.as_deref(), ttl_days)
        .await?;
    Ok(token.into())
}

/// Verify a legacy offline token locally.
#[tauri::command]
pub fn verify_offline_token(
    sdk: State<'_, licenseseat::LicenseSeat>,
    offline_token: OfflineTokenResponse,
    public_key_b64: Option<String>,
) -> Result<bool> {
    let offline_token: CoreOfflineTokenResponse = offline_token.into();
    Ok(sdk.verify_offline_token(&offline_token, public_key_b64.as_deref())?)
}

/// Checkout a machine file for offline validation.
#[tauri::command]
pub async fn checkout_machine_file(
    sdk: State<'_, licenseseat::LicenseSeat>,
    license_key: String,
    options: Option<MachineFileCheckoutOptionsInput>,
) -> Result<MachineFileResponse> {
    let options = options.unwrap_or_default();
    let machine_file = sdk
        .checkout_machine_file_with_options(
            &license_key,
            licenseseat::MachineFileCheckoutOptions {
                fingerprint: options.fingerprint,
                device_id: options.device_id,
                device_fingerprint: options.device_fingerprint,
                ttl_days: options.ttl_days,
                grace_period_days: options.grace_period_days,
                include_license: options.include_license.unwrap_or(true),
                fingerprint_components: options.fingerprint_components.unwrap_or_default(),
            },
        )
        .await?;
    Ok(machine_file.into())
}

/// Fetch and cache a signing key for offline verification.
#[tauri::command]
pub async fn fetch_signing_key(
    sdk: State<'_, licenseseat::LicenseSeat>,
    key_id: String,
) -> Result<String> {
    Ok(sdk.fetch_signing_key(&key_id).await?)
}

/// Refresh offline assets for the current license.
#[tauri::command]
pub async fn sync_offline_assets(sdk: State<'_, licenseseat::LicenseSeat>) -> Result<()> {
    sdk.sync_offline_assets().await?;
    Ok(())
}

/// Verify a machine file locally.
#[tauri::command]
pub fn verify_machine_file(
    sdk: State<'_, licenseseat::LicenseSeat>,
    machine_file: MachineFileResponse,
    options: Option<MachineFileVerificationOptionsInput>,
) -> Result<MachineFileVerificationResultResponse> {
    let options = options.unwrap_or_default();
    let machine_file: MachineFile = machine_file.into();
    let result = sdk.verify_machine_file(
        &machine_file,
        options.public_key_b64.as_deref(),
        options.license_key.as_deref(),
        options.fingerprint.as_deref(),
    )?;
    Ok(result.into())
}

/// Reset the SDK state.
#[tauri::command]
pub fn reset(sdk: State<'_, licenseseat::LicenseSeat>) {
    sdk.reset();
}

pub(crate) fn event_payload_to_json(data: Option<EventData>) -> serde_json::Value {
    match data {
        Some(EventData::License(license)) => {
            serde_json::to_value(LicenseResponse::from(*license)).unwrap_or(serde_json::Value::Null)
        }
        Some(EventData::Validation(result)) => {
            serde_json::to_value(ValidationResultResponse::from(*result))
                .unwrap_or(serde_json::Value::Null)
        }
        Some(EventData::Error(error)) | Some(EventData::Message(error)) => {
            serde_json::Value::String(error)
        }
        Some(EventData::NextRunAt(next_run_at)) => {
            serde_json::Value::String(next_run_at.to_rfc3339())
        }
        None => serde_json::Value::Null,
    }
}

#[cfg(test)]
mod tests {
    use super::{
        MachineFileResponse, OfflineTokenResponse, event_payload_to_json,
        map_admin_snapshot_response, map_state_response,
    };
    use chrono::Utc;
    use licenseseat::{
        ActivationNested, Config, Entitlement, EventData, License, LicenseResponse, MachineFile,
        OfflineEntitlement, OfflineTokenPayload, OfflineTokenResponse as CoreOfflineTokenResponse,
        OfflineTokenSignature, Product, SigningKeyResponse, ValidationResult, ValidationWarning,
    };
    use serde_json::json;
    use std::collections::HashMap;
    use std::fs;
    use std::path::{Path, PathBuf};

    fn unique_storage_path(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "{label}-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("system time should be after unix epoch")
                .as_nanos()
        ))
    }

    fn write_cache_value<T: serde::Serialize>(
        storage_path: &Path,
        prefix: &str,
        key: &str,
        value: &T,
    ) {
        fs::create_dir_all(storage_path).expect("storage path should be created");
        let json = serde_json::to_string_pretty(value).expect("cache value should serialize");
        let path = storage_path.join(format!("{prefix}{key}.json"));
        fs::write(path, json).expect("cache file should be written");
    }

    fn sample_validation_result() -> ValidationResult {
        ValidationResult {
            object: "validation_result".into(),
            valid: true,
            code: None,
            message: None,
            warnings: None,
            license: LicenseResponse {
                object: "license".into(),
                key: "TEST-KEY".into(),
                status: "active".into(),
                starts_at: None,
                expires_at: None,
                mode: "hardware_locked".into(),
                plan_key: "pro".into(),
                seat_limit: Some(1),
                active_seats: 1,
                active_entitlements: vec![Entitlement {
                    key: "pro".into(),
                    expires_at: None,
                    metadata: None,
                }],
                metadata: None,
                product: Product {
                    slug: "demo".into(),
                    name: "Demo".into(),
                },
            },
            activation: Some(ActivationNested {
                object: "activation".into(),
                id: "act_123".into(),
                device_id: "device-123".into(),
                device_name: Some("Demo Device".into()),
                license_key: "TEST-KEY".into(),
                activated_at: Utc::now(),
                deactivated_at: None,
                ip_address: None,
                metadata: None,
            }),
            offline: false,
        }
    }

    #[test]
    fn test_offline_token_round_trip_preserves_shape() {
        let token = CoreOfflineTokenResponse {
            object: "offline_token".into(),
            token: OfflineTokenPayload {
                schema_version: 1,
                license_key: "TEST-KEY".into(),
                product_slug: "demo".into(),
                plan_key: "pro".into(),
                mode: "hardware_locked".into(),
                seat_limit: Some(3),
                device_id: Some("device-123".into()),
                iat: 1_700_000_000,
                exp: 1_700_086_400,
                nbf: 1_700_000_000,
                license_expires_at: None,
                kid: "kid_123".into(),
                entitlements: vec![OfflineEntitlement {
                    key: "pro".into(),
                    expires_at: Some(1_700_086_400),
                }],
                metadata: Some(HashMap::from([("tier".into(), json!("gold"))])),
            },
            signature: OfflineTokenSignature {
                algorithm: "Ed25519".into(),
                key_id: "kid_123".into(),
                value: "signature".into(),
            },
            canonical: "{\"license_key\":\"TEST-KEY\"}".into(),
        };

        let response = OfflineTokenResponse::from(token.clone());
        let round_trip: CoreOfflineTokenResponse = response.into();

        assert_eq!(round_trip, token);
    }

    #[test]
    fn test_machine_file_round_trip_preserves_shape() {
        let machine_file = MachineFile {
            certificate: "-----BEGIN MACHINE FILE-----".into(),
            algorithm: "aes-256-gcm+ed25519".into(),
            ttl: 2_592_000,
            issued_at: None,
            expires_at: None,
            license_key: "TEST-KEY".into(),
            fingerprint: "device-123".into(),
        };

        let response = MachineFileResponse::from(machine_file.clone());
        let round_trip: MachineFile = response.into();

        assert_eq!(round_trip, machine_file);
    }

    #[test]
    fn test_validation_event_payload_is_structured() {
        let payload =
            event_payload_to_json(Some(EventData::Validation(Box::new(ValidationResult {
                object: "validation_result".into(),
                valid: false,
                code: Some("license_invalid".into()),
                message: Some("License is invalid".into()),
                warnings: Some(vec![ValidationWarning {
                    code: "clock_skew".into(),
                    message: "Clock skew detected".into(),
                }]),
                license: licenseseat::LicenseResponse {
                    object: "license".into(),
                    key: "TEST-KEY".into(),
                    status: "inactive".into(),
                    starts_at: None,
                    expires_at: None,
                    mode: "hardware_locked".into(),
                    plan_key: "pro".into(),
                    seat_limit: Some(1),
                    active_seats: 0,
                    active_entitlements: vec![],
                    metadata: None,
                    product: Product {
                        slug: "demo".into(),
                        name: "Demo".into(),
                    },
                },
                activation: None,
                offline: false,
            }))));

        assert_eq!(payload["valid"], json!(false));
        assert_eq!(payload["license"]["planKey"], json!("pro"));
        assert_eq!(payload["message"], json!("License is invalid"));
    }

    #[test]
    fn test_state_response_for_fresh_sdk_is_inactive() {
        let storage_path = unique_storage_path("licenseseat-plugin-state-test");
        let sdk = licenseseat::LicenseSeat::new(
            Config::new("pk_test_123", "demo-product")
                .with_storage_path(storage_path)
                .with_debug(false),
        );

        let state = map_state_response(&sdk);

        assert_eq!(state.client_status, "inactive");
        assert_eq!(state.status.status, "inactive");
        assert!(!state.is_activated);
        assert!(!state.is_valid);
        assert!(!state.is_offline);
        assert!(state.license.is_none());
        assert!(state.validation.is_none());
        assert!(state.entitlements.is_empty());
        assert!(state.plan_key.is_none());
        assert!(state.license_mode.is_none());
        assert!(!state.fingerprint.is_empty());
    }

    #[test]
    fn test_state_response_for_cached_license_exposes_entitlements() {
        let storage_path = unique_storage_path("licenseseat-plugin-state-populated-test");
        let config = Config::new("pk_test_123", "demo-product")
            .with_storage_path(storage_path.clone())
            .with_debug(false);
        let validation = sample_validation_result();
        let license = License {
            license_key: "TEST-KEY".into(),
            device_id: "device-123".into(),
            activation_id: "act_123".into(),
            activated_at: Utc::now(),
            last_validated: Utc::now(),
            trusted_license: Some(validation.license.clone()),
            validation: Some(validation),
        };
        write_cache_value(&storage_path, &config.storage_prefix, "license", &license);

        let sdk = licenseseat::LicenseSeat::new(config);
        let state = map_state_response(&sdk);

        assert_eq!(state.client_status, "active");
        assert!(state.is_activated);
        assert!(state.is_valid);
        assert_eq!(state.plan_key.as_deref(), Some("pro"));
        assert_eq!(state.license_mode.as_deref(), Some("hardware_locked"));
        assert_eq!(state.entitlements.len(), 1);
        assert_eq!(state.entitlements[0].key, "pro");
        assert_eq!(
            state.license.as_ref().map(|value| value.device_id.as_str()),
            Some("device-123")
        );
    }

    #[test]
    fn test_admin_snapshot_for_fresh_sdk_exposes_config_and_runtime() {
        let storage_path = unique_storage_path("licenseseat-plugin-admin-test");
        let config = Config::new("pk_test_123", "demo-product")
            .with_storage_path(storage_path.clone())
            .with_debug(true);
        let sdk = licenseseat::LicenseSeat::new(config.clone());

        let snapshot = map_admin_snapshot_response(&sdk, &config);

        assert_eq!(snapshot.config.api_key, "pk_test_123");
        assert_eq!(snapshot.config.product_slug, "demo-product");
        assert_eq!(
            snapshot.cache_paths.cache_dir,
            Some(storage_path.to_string_lossy().into_owned())
        );
        assert_eq!(snapshot.state.client_status, "inactive");
        assert!(!snapshot.runtime.is_auto_validating);
        assert!(!snapshot.runtime.is_heartbeat_running);
        assert!(snapshot.trusted_license.is_none());
        assert!(snapshot.trusted_license_source.is_none());
        assert!(snapshot.offline_token.is_none());
        assert!(snapshot.machine_file.is_none());
        assert!(snapshot.machine_file_verification.is_none());
        assert!(snapshot.signing_key.is_none());
    }

    #[test]
    fn test_admin_snapshot_reports_cached_offline_artifacts() {
        let storage_path = unique_storage_path("licenseseat-plugin-admin-populated-test");
        let mut config = Config::new("pk_test_123", "demo-product")
            .with_storage_path(storage_path.clone())
            .with_debug(true);
        config.signing_key_id = Some("kid_123".into());

        let validation = sample_validation_result();
        let license = License {
            license_key: "TEST-KEY".into(),
            device_id: "device-123".into(),
            activation_id: "act_123".into(),
            activated_at: Utc::now(),
            last_validated: Utc::now(),
            trusted_license: Some(validation.license.clone()),
            validation: Some(validation.clone()),
        };
        let offline_token = CoreOfflineTokenResponse {
            object: "offline_token".into(),
            token: OfflineTokenPayload {
                schema_version: 1,
                license_key: "TEST-KEY".into(),
                product_slug: "demo-product".into(),
                plan_key: "pro".into(),
                mode: "hardware_locked".into(),
                seat_limit: Some(1),
                device_id: Some("device-123".into()),
                iat: 1_700_000_000,
                exp: 1_700_086_400,
                nbf: 1_700_000_000,
                license_expires_at: None,
                kid: "kid_123".into(),
                entitlements: vec![OfflineEntitlement {
                    key: "pro".into(),
                    expires_at: None,
                }],
                metadata: None,
            },
            signature: OfflineTokenSignature {
                algorithm: "Ed25519".into(),
                key_id: "kid_123".into(),
                value: "signature".into(),
            },
            canonical: "{\"license_key\":\"TEST-KEY\"}".into(),
        };
        let machine_file = MachineFile {
            certificate: "-----BEGIN MACHINE FILE-----\ninvalid\n-----END MACHINE FILE-----".into(),
            algorithm: "aes-256-gcm+ed25519".into(),
            ttl: 2_592_000,
            issued_at: None,
            expires_at: None,
            license_key: "TEST-KEY".into(),
            fingerprint: "device-123".into(),
        };
        let signing_key = SigningKeyResponse {
            object: "signing_key".into(),
            key_id: "kid_123".into(),
            algorithm: "Ed25519".into(),
            public_key: "public-key".into(),
            created_at: None,
            status: "active".into(),
        };

        write_cache_value(&storage_path, &config.storage_prefix, "license", &license);
        write_cache_value(
            &storage_path,
            &config.storage_prefix,
            "offline_token",
            &offline_token,
        );
        write_cache_value(
            &storage_path,
            &config.storage_prefix,
            "machine_file",
            &machine_file,
        );
        write_cache_value(
            &storage_path,
            &config.storage_prefix,
            "signing_key_kid_123",
            &signing_key,
        );

        let sdk = licenseseat::LicenseSeat::new(config.clone());
        let snapshot = map_admin_snapshot_response(&sdk, &config);

        assert_eq!(
            snapshot
                .offline_token
                .as_ref()
                .map(|value| value.token.license_key.as_str()),
            Some("TEST-KEY")
        );
        assert_eq!(
            snapshot
                .machine_file
                .as_ref()
                .map(|value| value.license_key.as_str()),
            Some("TEST-KEY")
        );
        assert_eq!(
            snapshot
                .trusted_license
                .as_ref()
                .map(|value| value.plan_key.as_str()),
            Some("pro")
        );
        assert_eq!(
            snapshot.trusted_license_source.as_deref(),
            Some("cached_license")
        );
        assert!(snapshot.machine_file_verification.is_some());
        assert_eq!(snapshot.signing_key_id.as_deref(), Some("kid_123"));
        assert_eq!(
            snapshot
                .signing_key
                .as_ref()
                .map(|value| value.key_id.as_str()),
            Some("kid_123")
        );
        assert!(snapshot.cache_paths.license_snapshot_path.is_some());
        assert!(snapshot.cache_paths.signing_key_path.is_some());
    }

    #[test]
    fn test_admin_snapshot_prefers_snapshot_file_for_trusted_license() {
        let storage_path = unique_storage_path("licenseseat-plugin-admin-snapshot-source-test");
        let config = Config::new("pk_test_123", "demo-product")
            .with_storage_path(storage_path.clone())
            .with_debug(true);

        let validation = sample_validation_result();
        let license = License {
            license_key: "TEST-KEY".into(),
            device_id: "device-123".into(),
            activation_id: "act_123".into(),
            activated_at: Utc::now(),
            last_validated: Utc::now(),
            trusted_license: Some(validation.license.clone()),
            validation: Some(validation),
        };
        let snapshot_license = licenseseat::LicenseResponse {
            object: "license".into(),
            key: "TEST-KEY".into(),
            status: "active".into(),
            starts_at: None,
            expires_at: None,
            mode: "named_user".into(),
            plan_key: "enterprise".into(),
            seat_limit: Some(5),
            active_seats: 2,
            active_entitlements: vec![licenseseat::Entitlement {
                key: "enterprise".into(),
                expires_at: None,
                metadata: None,
            }],
            metadata: None,
            product: licenseseat::Product {
                slug: "enterprise-demo".into(),
                name: "Enterprise Demo".into(),
            },
        };

        write_cache_value(&storage_path, &config.storage_prefix, "license", &license);
        write_cache_value(
            &storage_path,
            &config.storage_prefix,
            "license_snapshot",
            &snapshot_license,
        );

        let sdk = licenseseat::LicenseSeat::new(config.clone());
        let snapshot = map_admin_snapshot_response(&sdk, &config);

        assert_eq!(
            snapshot
                .trusted_license
                .as_ref()
                .map(|value| value.plan_key.as_str()),
            Some("enterprise")
        );
        assert_eq!(
            snapshot.trusted_license_source.as_deref(),
            Some("snapshot_file")
        );
    }
}
