//! # LicenseSeat Rust SDK
//!
//! Official Rust SDK for [LicenseSeat](https://licenseseat.com) - the simple, secure
//! licensing platform for apps, games, and plugins.
//!
//! ## Features
//!
//! - **License Lifecycle** - Activate, validate, and deactivate licenses
//! - **Offline Validation** - Machine-file-first Ed25519 + AES-256-GCM verification
//! - **Automatic Re-validation** - Background validation with configurable intervals
//! - **Heartbeat** - Periodic health-check pings for real-time seat tracking
//! - **Entitlement Management** - Fine-grained feature access control
//! - **Device Telemetry** - Auto-collected device metadata for analytics
//! - **Network Resilience** - Automatic retry with exponential backoff
//!
//! ## Quick Start
//!
//! Use a `pk_*` publishable API key in client applications.
//! Keep `sk_*` secret keys server-side only.
//!
//! ```rust,no_run
//! use licenseseat::{LicenseSeat, Config};
//!
//! #[tokio::main]
//! async fn main() -> Result<(), licenseseat::Error> {
//!     // Create SDK instance
//!     let sdk = LicenseSeat::new(Config {
//!         api_key: "pk_live_xxx".into(),
//!         product_slug: "your-product".into(),
//!         ..Default::default()
//!     });
//!
//!     // Activate a license
//!     let license = sdk.activate("USER-LICENSE-KEY").await?;
//!     println!("Activated! Device ID: {}", license.device_id);
//!
//!     // Check entitlements
//!     let status = sdk.check_entitlement("pro-features");
//!     if status.active {
//!         println!("Pro features enabled!");
//!     }
//!
//!     // Deactivate when done
//!     sdk.deactivate().await?;
//!
//!     Ok(())
//! }
//! ```
//!
//! ## Feature Flags
//!
//! - `default` - Uses rustls for TLS and enables offline support
//! - `native-tls` - Use system TLS instead of rustls
//! - `offline` - Enable offline support when you disable default features

#![warn(missing_docs)]
#![warn(rustdoc::missing_crate_level_docs)]

mod cache;
mod client;
mod config;
mod device;
mod error;
mod events;
mod models;
mod telemetry;

#[cfg(feature = "offline")]
mod offline;

#[cfg(feature = "offline")]
pub use client::MachineFileCheckoutOptions;
pub use client::{ActivationOptions, LicenseSeat, ReleaseListOptions};
pub use config::{Config, OfflineFallbackMode};
pub use error::{Error, Result};
pub use events::{Event, EventData, EventKind};
pub use models::{
    ActivationNested, ActivationResponse, ClientStatus, DeactivationResponse, DownloadToken,
    Entitlement, EntitlementReason, EntitlementStatus, HealthResponse, HeartbeatResponse, License,
    LicenseResponse, LicenseStatus, LicenseStatusDetails, MachineFile, MachineFilePayload,
    MachineFileVerificationResult, OfflineEntitlement, OfflineTokenPayload, OfflineTokenResponse,
    OfflineTokenSignature, Product, Release, ReleaseList, RestoreResult, SigningKeyResponse,
    TrustedLicenseSource, ValidationResult, ValidationWarning,
};

/// SDK version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// SDK name (used in telemetry)
pub const SDK_NAME: &str = "rust";
