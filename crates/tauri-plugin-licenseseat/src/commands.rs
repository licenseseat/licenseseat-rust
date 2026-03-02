//! Tauri commands for the LicenseSeat plugin.

use crate::error::Result;
use licenseseat::{EntitlementStatus, License, LicenseStatus, ValidationResult};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tauri::State;

/// Activation options passed from the frontend.
#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ActivationOptions {
    /// Custom device ID.
    pub device_id: Option<String>,
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
                status: "offlineValid".into(),
                message: None,
                license: Some(details.license),
                device: Some(details.device),
                activated_at: Some(details.activated_at.to_rfc3339()),
                last_validated: Some(details.last_validated.to_rfc3339()),
            },
            LicenseStatus::OfflineInvalid { message } => Self {
                status: "offlineInvalid".into(),
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
        device_id: opts.device_id,
        device_name: opts.device_name,
        metadata: opts.metadata,
    };

    let license = sdk.activate_with_options(&license_key, sdk_opts).await?;
    Ok(license.into())
}

/// Validate the current license.
#[tauri::command]
pub async fn validate(
    sdk: State<'_, licenseseat::LicenseSeat>,
) -> Result<ValidationResult> {
    let result = sdk.validate().await?;
    Ok(result)
}

/// Deactivate the current license.
#[tauri::command]
pub async fn deactivate(
    sdk: State<'_, licenseseat::LicenseSeat>,
) -> Result<()> {
    sdk.deactivate().await?;
    Ok(())
}

/// Send a heartbeat.
#[tauri::command]
pub async fn heartbeat(
    sdk: State<'_, licenseseat::LicenseSeat>,
) -> Result<()> {
    sdk.heartbeat().await?;
    Ok(())
}

/// Get the current license status.
#[tauri::command]
pub fn get_status(
    sdk: State<'_, licenseseat::LicenseSeat>,
) -> StatusResponse {
    sdk.status().into()
}

/// Check if an entitlement is active.
#[tauri::command]
pub fn check_entitlement(
    sdk: State<'_, licenseseat::LicenseSeat>,
    entitlement_key: String,
) -> EntitlementResponse {
    sdk.check_entitlement(&entitlement_key).into()
}

/// Check if an entitlement is active (returns bool).
#[tauri::command]
pub fn has_entitlement(
    sdk: State<'_, licenseseat::LicenseSeat>,
    entitlement_key: String,
) -> bool {
    sdk.has_entitlement(&entitlement_key)
}

/// Get the current cached license.
#[tauri::command]
pub fn get_license(
    sdk: State<'_, licenseseat::LicenseSeat>,
) -> Option<LicenseResponse> {
    sdk.current_license().map(Into::into)
}

/// Reset the SDK state.
#[tauri::command]
pub fn reset(sdk: State<'_, licenseseat::LicenseSeat>) {
    sdk.reset();
}
