//! Event system for SDK lifecycle notifications.

use crate::models::{License, ValidationResult};

/// Event emitted by the SDK during license lifecycle operations.
#[derive(Debug, Clone)]
pub struct Event {
    /// The kind of event.
    pub kind: EventKind,
    /// Associated data (if any).
    pub data: Option<EventData>,
}

/// Types of events emitted by the SDK.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EventKind {
    // Activation lifecycle
    /// Activation started.
    ActivationStart,
    /// Activation succeeded.
    ActivationSuccess,
    /// Activation failed.
    ActivationError,

    // Validation lifecycle
    /// Validation started.
    ValidationStart,
    /// Online validation succeeded.
    ValidationSuccess,
    /// Validation failed (invalid license).
    ValidationFailed,
    /// Validation encountered an error.
    ValidationError,
    /// Offline validation succeeded.
    ValidationOfflineSuccess,
    /// Offline validation failed.
    ValidationOfflineFailed,

    // Deactivation lifecycle
    /// Deactivation started.
    DeactivationStart,
    /// Deactivation succeeded.
    DeactivationSuccess,
    /// Deactivation failed.
    DeactivationError,

    // Heartbeat
    /// Heartbeat sent successfully.
    HeartbeatSuccess,
    /// Heartbeat failed.
    HeartbeatError,

    // License state changes
    /// Cached license loaded at startup.
    LicenseLoaded,
    /// License was revoked by the server.
    LicenseRevoked,

    // Offline token
    /// Offline token verified successfully.
    OfflineTokenVerified,
    /// Offline token verification failed.
    OfflineTokenVerificationFailed,

    // Offline validation
    /// Offline validation started.
    OfflineValidationStart,
    /// Offline validation succeeded.
    OfflineValidationSuccess,
    /// Offline validation failed.
    OfflineValidationFailed,
    /// Offline assets (token + key) refreshed.
    OfflineAssetsRefreshed,

    // Auto-validation
    /// Auto-validation cycle triggered.
    AutoValidationCycle,
    /// Auto-validation stopped.
    AutoValidationStopped,

    // Network status
    /// Network came online.
    NetworkOnline,
    /// Network went offline.
    NetworkOffline,

    // SDK state
    /// SDK state was reset.
    SdkReset,
}

/// Data associated with an event.
#[derive(Debug, Clone)]
pub enum EventData {
    /// License data.
    License(Box<License>),
    /// Validation result.
    Validation(Box<ValidationResult>),
    /// Error message.
    Error(String),
    /// Generic string data.
    Message(String),
    /// Next auto-validation time.
    NextRunAt(chrono::DateTime<chrono::Utc>),
}

impl Event {
    /// Create a new event with no data.
    pub fn new(kind: EventKind) -> Self {
        Self { kind, data: None }
    }

    /// Create a new event with license data.
    pub fn with_license(kind: EventKind, license: License) -> Self {
        Self {
            kind,
            data: Some(EventData::License(Box::new(license))),
        }
    }

    /// Create a new event with validation data.
    pub fn with_validation(kind: EventKind, result: ValidationResult) -> Self {
        Self {
            kind,
            data: Some(EventData::Validation(Box::new(result))),
        }
    }

    /// Create a new event with an error message.
    pub fn with_error(kind: EventKind, error: impl Into<String>) -> Self {
        Self {
            kind,
            data: Some(EventData::Error(error.into())),
        }
    }
}

impl std::fmt::Display for EventKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::ActivationStart => "activation:start",
            Self::ActivationSuccess => "activation:success",
            Self::ActivationError => "activation:error",
            Self::ValidationStart => "validation:start",
            Self::ValidationSuccess => "validation:success",
            Self::ValidationFailed => "validation:failed",
            Self::ValidationError => "validation:error",
            Self::ValidationOfflineSuccess => "validation:offline-success",
            Self::ValidationOfflineFailed => "validation:offline-failed",
            Self::DeactivationStart => "deactivation:start",
            Self::DeactivationSuccess => "deactivation:success",
            Self::DeactivationError => "deactivation:error",
            Self::HeartbeatSuccess => "heartbeat:success",
            Self::HeartbeatError => "heartbeat:error",
            Self::LicenseLoaded => "license:loaded",
            Self::LicenseRevoked => "license:revoked",
            Self::OfflineTokenVerified => "offlineToken:verified",
            Self::OfflineTokenVerificationFailed => "offlineToken:verificationFailed",
            Self::OfflineValidationStart => "offlineValidation:start",
            Self::OfflineValidationSuccess => "offlineValidation:success",
            Self::OfflineValidationFailed => "offlineValidation:failed",
            Self::OfflineAssetsRefreshed => "offlineAssets:refreshed",
            Self::AutoValidationCycle => "autovalidation:cycle",
            Self::AutoValidationStopped => "autovalidation:stopped",
            Self::NetworkOnline => "network:online",
            Self::NetworkOffline => "network:offline",
            Self::SdkReset => "sdk:reset",
        };
        write!(f, "{}", s)
    }
}
