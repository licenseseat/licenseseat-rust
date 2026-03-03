//! # LicenseSeat Rust SDK
//!
//! Official Rust SDK for [LicenseSeat](https://licenseseat.com) - the simple, secure
//! licensing platform for apps, games, and plugins.
//!
//! ## Features
//!
//! - **License Lifecycle** - Activate, validate, and deactivate licenses
//! - **Offline Validation** - Ed25519 cryptographic verification (optional feature)
//! - **Automatic Re-validation** - Background validation with configurable intervals
//! - **Heartbeat** - Periodic health-check pings for real-time seat tracking
//! - **Entitlement Management** - Fine-grained feature access control
//! - **Device Telemetry** - Auto-collected device metadata for analytics
//! - **Network Resilience** - Automatic retry with exponential backoff
//!
//! ## Quick Start
//!
//! ```rust,no_run
//! use licenseseat::{LicenseSeat, Config};
//!
//! #[tokio::main]
//! async fn main() -> Result<(), licenseseat::Error> {
//!     // Create SDK instance
//!     let sdk = LicenseSeat::new(Config {
//!         api_key: "your-api-key".into(),
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
//! - `default` - Uses rustls for TLS
//! - `native-tls` - Use system TLS instead of rustls
//! - `offline` - Enable Ed25519 offline validation (adds crypto dependencies)

#![warn(missing_docs)]
#![warn(rustdoc::missing_crate_level_docs)]

mod cache;
mod client;
mod config;
mod error;
mod events;
mod models;
mod telemetry;

#[cfg(feature = "offline")]
mod offline;

pub use client::{ActivationOptions, LicenseSeat};
pub use config::{Config, OfflineFallbackMode};
pub use error::{Error, Result};
pub use events::{Event, EventKind};
pub use models::{
    ActivationResponse, DeactivationResponse, Entitlement, EntitlementReason, EntitlementStatus,
    HealthResponse, HeartbeatResponse, License, LicenseStatus, LicenseStatusDetails,
    ValidationResult,
};

/// SDK version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// SDK name (used in telemetry)
pub const SDK_NAME: &str = "rust";
