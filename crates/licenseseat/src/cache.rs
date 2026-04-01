//! License caching for persistent storage.
//!
//! This module provides a simple file-based cache for storing license data
//! between SDK sessions. The Tauri plugin will override this with
//! tauri-plugin-store for better cross-platform support.

use crate::error::{Error, Result};
use crate::models::{License, LicenseResponse, ValidationResult};
use std::path::PathBuf;

/// Cache for persisting license data.
#[derive(Debug)]
pub struct LicenseCache {
    prefix: String,
    cache_dir: Option<PathBuf>,
}

impl LicenseCache {
    /// Create a new cache with the given prefix.
    pub fn new(prefix: impl Into<String>, cache_dir: Option<PathBuf>) -> Self {
        let cache_dir = cache_dir.or_else(|| dirs::cache_dir().map(|d| d.join("licenseseat")));
        Self {
            prefix: prefix.into(),
            cache_dir,
        }
    }

    /// Get the path for a cache key.
    fn path(&self, key: &str) -> Option<PathBuf> {
        self.cache_dir
            .as_ref()
            .map(|d| d.join(format!("{}{}.json", self.prefix, key)))
    }

    /// Ensure the cache directory exists.
    fn ensure_dir(&self) -> Result<()> {
        if let Some(ref dir) = self.cache_dir {
            std::fs::create_dir_all(dir).map_err(|e| Error::Cache(e.to_string()))?;
        }
        Ok(())
    }

    /// Store a value in the cache.
    fn set<T: serde::Serialize>(&self, key: &str, value: &T) -> Result<()> {
        self.ensure_dir()?;
        if let Some(path) = self.path(key) {
            let json = serde_json::to_string_pretty(value)?;
            std::fs::write(&path, json).map_err(|e| Error::Cache(e.to_string()))?;
        }
        Ok(())
    }

    /// Get a value from the cache.
    fn get<T: serde::de::DeserializeOwned>(&self, key: &str) -> Option<T> {
        let path = self.path(key)?;
        let json = std::fs::read_to_string(&path).ok()?;
        serde_json::from_str(&json).ok()
    }

    // ========================================================================
    // License-specific methods
    // ========================================================================

    /// Store the current license.
    pub fn set_license(&self, license: &License) -> Result<()> {
        self.set("license", license)
    }

    /// Get the cached license.
    pub fn get_license(&self) -> Option<License> {
        self.get("license")
    }

    /// Get the cached device ID.
    pub fn get_device_id(&self) -> Option<String> {
        self.get_license().map(|l| l.device_id)
    }

    /// Preferred alias for the canonical fingerprint.
    pub fn get_fingerprint(&self) -> Option<String> {
        self.get_device_id()
    }

    /// Update the validation result on the cached license.
    pub fn update_validation(&self, result: &ValidationResult) -> Result<()> {
        if let Some(mut license) = self.get_license() {
            license.validation = Some(result.clone());
            license.last_validated = chrono::Utc::now();
            self.set_license(&license)?;
        }
        Ok(())
    }

    /// Store the last trusted license snapshot returned by the server.
    pub fn set_license_snapshot(&self, license: &LicenseResponse) -> Result<()> {
        self.set("license_snapshot", license)
    }

    /// Get the last trusted cached license snapshot.
    #[cfg(feature = "offline")]
    pub fn get_license_snapshot(&self) -> Option<LicenseResponse> {
        self.get("license_snapshot")
    }

    // ========================================================================
    // Offline token methods
    // ========================================================================

    /// Store the offline token.
    #[cfg(feature = "offline")]
    pub fn set_offline_token(&self, token: &crate::models::OfflineTokenResponse) -> Result<()> {
        self.set("offline_token", token)
    }

    /// Get the cached offline token.
    #[cfg(feature = "offline")]
    pub fn get_offline_token(&self) -> Option<crate::models::OfflineTokenResponse> {
        self.get("offline_token")
    }

    /// Store the machine file.
    #[cfg(feature = "offline")]
    pub fn set_machine_file(&self, machine_file: &crate::models::MachineFile) -> Result<()> {
        self.set("machine_file", machine_file)
    }

    /// Get the cached machine file.
    #[cfg(feature = "offline")]
    pub fn get_machine_file(&self) -> Option<crate::models::MachineFile> {
        self.get("machine_file")
    }

    // ========================================================================
    // Signing key cache
    // ========================================================================

    /// Store a signing key.
    #[cfg(feature = "offline")]
    pub fn set_signing_key(
        &self,
        key_id: &str,
        key: &crate::models::SigningKeyResponse,
    ) -> Result<()> {
        self.set(&format!("signing_key_{}", key_id), key)
    }

    /// Get a cached signing key.
    #[cfg(feature = "offline")]
    pub fn get_signing_key(&self, key_id: &str) -> Option<crate::models::SigningKeyResponse> {
        self.get(&format!("signing_key_{}", key_id))
    }

    // ========================================================================
    // Timestamps
    // ========================================================================

    /// Store the last seen timestamp (for clock tampering detection).
    pub fn set_last_seen_timestamp(&self, timestamp: i64) -> Result<()> {
        self.set("last_seen_ts", &timestamp)
    }

    /// Get the last seen timestamp.
    pub fn get_last_seen_timestamp(&self) -> Option<i64> {
        self.get("last_seen_ts")
    }

    // ========================================================================
    // Clear all
    // ========================================================================

    /// Clear all cached data.
    pub fn clear(&self) {
        let Some(dir) = &self.cache_dir else {
            return;
        };

        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };

        for entry in entries.flatten() {
            let path = entry.path();
            let matches_prefix = path
                .file_name()
                .and_then(|name| name.to_str())
                .map(|name| name.starts_with(&self.prefix))
                .unwrap_or(false);
            if matches_prefix {
                let _ = std::fs::remove_file(path);
            }
        }
    }
}
