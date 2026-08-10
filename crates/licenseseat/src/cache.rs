//! License caching for persistent storage.
//!
//! This module provides durable file-based storage for license identity and
//! signed offline artifacts between SDK sessions.

use crate::error::{Error, Result};
use crate::models::{License, LicenseIdentity, ValidationResult};
use sha2::{Digest, Sha256};
use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard};

const INSTALLATION_IDENTIFIER_KEY: &str = "installation_identifier";
const MAX_CACHE_FILE_BYTES: u64 = 4 * 1024 * 1024;
const LAST_SEEN_TIMESTAMP_KEY: &str = "last_seen_ts";
const LICENSE_STATE_KEYS: &[&str] = &[
    "license",
    "license_snapshot",
    "machine_file",
    "offline_token",
    LAST_SEEN_TIMESTAMP_KEY,
];
/// Keys that deliberately survive `clear()`/`reset()`.
///
/// The installation identifier survives so an upgrade or reset never consumes
/// an extra server seat. The clock-rollback watermark survives so a local
/// reset cannot be combined with a clock rollback to re-import previously
/// exported signed artifact files and extend an offline window; it is
/// re-anchored (and may move backward) only by an authoritative online
/// operation.
const CLEAR_SURVIVING_KEYS: &[&str] = &[INSTALLATION_IDENTIFIER_KEY, LAST_SEEN_TIMESTAMP_KEY];

/// Cache for persisting license data.
#[derive(Debug)]
pub struct LicenseCache {
    /// Opaque v2 namespace used for every newly-created cache file.
    prefix: String,
    /// Pre-hardening plaintext prefix used only for one-way migration and
    /// cleanup. New writes never use this value as a filename component.
    legacy_prefix: String,
    cache_dir: Option<PathBuf>,
    legacy_cache_dir: Option<PathBuf>,
    io_lock: Mutex<()>,
}

/// Holds both the in-process mutex and the advisory cross-process lock for one
/// cache transaction. Dropping the file handle releases the OS lock.
struct CacheIoGuard<'a> {
    _process_guard: MutexGuard<'a, ()>,
    #[cfg(any(unix, windows))]
    _lock_file: std::fs::File,
}

impl LicenseCache {
    /// Create a new cache with the given prefix.
    pub fn new(prefix: impl Into<String>, cache_dir: Option<PathBuf>) -> Self {
        let legacy_prefix = safe_prefix(&prefix.into());
        let namespace = Sha256::digest(legacy_prefix.as_bytes());
        let prefix = format!("v2_{}__", hex_bytes(&namespace));
        let (cache_dir, legacy_cache_dir) = match cache_dir {
            Some(cache_dir) => (Some(cache_dir), None),
            None => {
                let durable = dirs::data_local_dir()
                    .or_else(dirs::data_dir)
                    .map(|directory| directory.join("licenseseat"));
                let legacy = dirs::cache_dir()
                    .map(|directory| directory.join("licenseseat"))
                    .filter(|directory| Some(directory) != durable.as_ref());
                (durable, legacy)
            }
        };
        Self {
            prefix,
            legacy_prefix,
            cache_dir,
            legacy_cache_dir,
            io_lock: Mutex::new(()),
        }
    }

    /// Get the path for a cache key.
    fn path(&self, key: &str) -> Option<PathBuf> {
        self.path_in(self.cache_dir.as_deref(), key)
    }

    fn lock_path(&self) -> Option<PathBuf> {
        self.cache_dir
            .as_deref()
            .map(|directory| directory.join(format!("{}state.lock", self.prefix)))
    }

    fn path_in(&self, directory: Option<&Path>, key: &str) -> Option<PathBuf> {
        if !is_safe_cache_key(key) {
            return None;
        }
        directory.map(|directory| directory.join(format!("{}{}.json", self.prefix, key)))
    }

    fn legacy_path_in(&self, directory: Option<&Path>, key: &str) -> Option<PathBuf> {
        if !is_safe_cache_key(key) {
            return None;
        }
        directory.map(|directory| directory.join(format!("{}{}.json", self.legacy_prefix, key)))
    }

    /// Ensure the cache directory exists.
    fn ensure_dir(&self) -> Result<()> {
        if let Some(ref dir) = self.cache_dir {
            std::fs::create_dir_all(dir).map_err(|e| Error::Cache(e.to_string()))?;
            let metadata =
                std::fs::symlink_metadata(dir).map_err(|error| Error::Cache(error.to_string()))?;
            if metadata_is_link_or_reparse_point(&metadata) || !metadata.is_dir() {
                return Err(Error::Cache(
                    "cache directory must be a real directory, not a link or reparse point".into(),
                ));
            }
            restrict_directory_permissions(dir)?;
        } else {
            return Err(Error::Cache(
                "no durable application-data directory is available".into(),
            ));
        }
        Ok(())
    }

    fn lock_io(&self) -> Result<CacheIoGuard<'_>> {
        let process_guard = self
            .io_lock
            .lock()
            .map_err(|_| Error::Cache("cache lock poisoned".into()))?;
        self.ensure_dir()?;

        #[cfg(any(unix, windows))]
        {
            let lock_path = self
                .lock_path()
                .ok_or_else(|| Error::Cache("invalid cache lock path".into()))?;
            let lock_file = open_private_lock_file(&lock_path)?;
            fs4::FileExt::lock(&lock_file)
                .map_err(|error| Error::Cache(format!("failed to lock cached state: {error}")))?;
            Ok(CacheIoGuard {
                _process_guard: process_guard,
                _lock_file: lock_file,
            })
        }

        #[cfg(not(any(unix, windows)))]
        Ok(CacheIoGuard {
            _process_guard: process_guard,
        })
    }

    /// Store a value in the cache.
    fn set<T: serde::Serialize>(&self, key: &str, value: &T) -> Result<()> {
        let _guard = self.lock_io()?;
        self.set_unlocked(key, value)
    }

    fn set_unlocked<T: serde::Serialize>(&self, key: &str, value: &T) -> Result<()> {
        self.ensure_dir()?;
        if let Some(path) = self.path(key) {
            let json = serde_json::to_vec_pretty(value)?;
            if json.len() as u64 > MAX_CACHE_FILE_BYTES {
                return Err(Error::Cache(format!(
                    "serialized cache value exceeds the {MAX_CACHE_FILE_BYTES}-byte safety limit"
                )));
            }
            atomic_write_private(&path, &json)?;
        } else if self.cache_dir.is_some() {
            return Err(Error::Cache("invalid cache key".into()));
        }
        Ok(())
    }

    /// Get a value from the cache.
    fn get<T: serde::de::DeserializeOwned + serde::Serialize>(&self, key: &str) -> Option<T> {
        let _guard = self.lock_io().ok()?;
        self.get_unlocked(key)
    }

    fn get_strict<T: serde::de::DeserializeOwned + serde::Serialize>(
        &self,
        key: &str,
    ) -> Result<Option<T>> {
        let _guard = self.lock_io()?;
        self.get_unlocked_strict(key)
    }

    fn get_unlocked<T: serde::de::DeserializeOwned + serde::Serialize>(
        &self,
        key: &str,
    ) -> Option<T> {
        if let Some(directory) = self.cache_dir.as_deref() {
            match existing_real_directory(directory) {
                Ok(true) => {
                    let path = self.path_in(Some(directory), key)?;
                    match std::fs::symlink_metadata(&path) {
                        Ok(_) => return read_cache_value(&path),
                        Err(error) if error.kind() != std::io::ErrorKind::NotFound => return None,
                        Err(_) => {}
                    }
                }
                Ok(false) => {}
                Err(_) => return None,
            }
        }

        self.migrate_legacy_value_unlocked(key)
    }

    fn get_unlocked_strict<T: serde::de::DeserializeOwned + serde::Serialize>(
        &self,
        key: &str,
    ) -> Result<Option<T>> {
        if let Some(directory) = self.cache_dir.as_deref() {
            if existing_real_directory(directory)? {
                let path = self
                    .path_in(Some(directory), key)
                    .ok_or_else(|| Error::Cache("invalid cache key".into()))?;
                match std::fs::symlink_metadata(&path) {
                    Ok(_) => return read_cache_value_strict(&path).map(Some),
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                    Err(error) => return Err(Error::Cache(error.to_string())),
                }
            }
        }

        self.migrate_legacy_value_unlocked_strict(key)
    }

    fn migrate_legacy_value_unlocked<T: serde::de::DeserializeOwned + serde::Serialize>(
        &self,
        key: &str,
    ) -> Option<T> {
        for directory in [&self.cache_dir, &self.legacy_cache_dir]
            .into_iter()
            .flatten()
        {
            if !existing_real_directory(directory).ok()? {
                continue;
            }
            let path = self.legacy_path_in(Some(directory), key)?;
            match std::fs::symlink_metadata(&path) {
                Ok(_) => {
                    let value = read_cache_value(&path)?;
                    if self.set_unlocked(key, &value).is_ok() {
                        let _ = remove_cache_file(&path);
                        let _ = sync_parent_directory(directory);
                    }
                    return Some(value);
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(_) => return None,
            }
        }
        None
    }

    fn migrate_legacy_value_unlocked_strict<T: serde::de::DeserializeOwned + serde::Serialize>(
        &self,
        key: &str,
    ) -> Result<Option<T>> {
        for directory in [&self.cache_dir, &self.legacy_cache_dir]
            .into_iter()
            .flatten()
        {
            if !existing_real_directory(directory)? {
                continue;
            }
            let path = self
                .legacy_path_in(Some(directory), key)
                .ok_or_else(|| Error::Cache("invalid cache key".into()))?;
            match std::fs::symlink_metadata(&path) {
                Ok(_) => {
                    let value = read_cache_value_strict(&path)?;
                    self.set_unlocked(key, &value)?;
                    remove_cache_file(&path)?;
                    sync_parent_directory(directory)?;
                    return Ok(Some(value));
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(Error::Cache(error.to_string())),
            }
        }
        Ok(None)
    }

    fn remove_key_unlocked(&self, key: &str) -> Result<()> {
        for directory in [&self.cache_dir, &self.legacy_cache_dir]
            .into_iter()
            .flatten()
        {
            self.remove_key_in_directory_unlocked(directory, key)?;
        }
        Ok(())
    }

    fn remove_key_in_directory_unlocked(&self, directory: &Path, key: &str) -> Result<()> {
        if !existing_real_directory(directory)? {
            return Ok(());
        }
        let mut removed_any = false;
        for path in [
            self.path_in(Some(directory), key),
            self.legacy_path_in(Some(directory), key),
        ]
        .into_iter()
        .flatten()
        {
            let target_file_name = path
                .file_name()
                .and_then(|name| name.to_str())
                .ok_or_else(|| Error::Cache("invalid cache file name".into()))?;
            removed_any |= remove_cache_file(&path)?;
            removed_any |= remove_atomic_temporary_files_for_target(directory, target_file_name)?;
        }
        if removed_any {
            sync_parent_directory(directory)?;
        }
        Ok(())
    }

    fn clear_directory_unlocked(&self, directory: &Path) -> Result<()> {
        if !existing_real_directory(directory)? {
            return Ok(());
        }

        let mut removed_any = false;
        // Remove every grant/supporting artifact before deleting the license
        // record. When the record is a denial tombstone, this ordering ensures
        // a partial cleanup cannot expose an older signed artifact without the
        // stronger denial that blocks it. The clock-rollback watermark is
        // preserved exactly like the installation identifier (see
        // `CLEAR_SURVIVING_KEYS`); license and artifact grants die here, so
        // keeping the watermark costs nothing and closes the
        // "reset, roll the clock back, re-import artifact files" variant.
        for key in LICENSE_STATE_KEYS
            .iter()
            .copied()
            .filter(|key| *key != "license" && !CLEAR_SURVIVING_KEYS.contains(key))
        {
            for path in [
                self.path_in(Some(directory), key),
                self.legacy_path_in(Some(directory), key),
            ]
            .into_iter()
            .flatten()
            {
                removed_any |= remove_cache_file(&path)?;
            }
        }

        let signing_key_prefix = format!("{}signing_key_", self.prefix);
        let legacy_signing_key_prefix = format!("{}signing_key_", self.legacy_prefix);
        let entries =
            std::fs::read_dir(directory).map_err(|error| Error::Cache(error.to_string()))?;
        for entry in entries {
            let entry = entry.map_err(|error| Error::Cache(error.to_string()))?;
            let path = entry.path();
            let Some(file_name) = path.file_name().and_then(|name| name.to_str()) else {
                continue;
            };
            let is_our_signing_key = is_signing_key_file_name(file_name, &signing_key_prefix)
                || is_signing_key_file_name(file_name, &legacy_signing_key_prefix);
            let is_our_storage_probe = is_storage_probe_file_name(file_name, &self.prefix)
                || is_storage_probe_file_name(file_name, &self.legacy_prefix);
            let is_our_atomic_temporary =
                atomic_temporary_target_name(file_name).is_some_and(|target| {
                    is_owned_cache_target_name(target, &self.prefix, &signing_key_prefix)
                        || is_owned_cache_target_name(
                            target,
                            &self.legacy_prefix,
                            &legacy_signing_key_prefix,
                        )
                });
            if is_our_signing_key || is_our_storage_probe || is_our_atomic_temporary {
                removed_any |= remove_cache_file(&path)?;
            }
        }

        for path in [
            self.path_in(Some(directory), "license"),
            self.legacy_path_in(Some(directory), "license"),
        ]
        .into_iter()
        .flatten()
        {
            removed_any |= remove_cache_file(&path)?;
        }

        if removed_any {
            sync_parent_directory(directory)?;
        }
        Ok(())
    }

    /// Copy the typed trust state from a legacy product cache into this cache.
    pub(crate) fn migrate_from(&self, source: &Self) -> Result<()> {
        let Some(license) = source.get_license() else {
            return Ok(());
        };
        // Copy supporting records first and the license commit marker last. If
        // any earlier write fails, the next initialization can safely retry
        // instead of mistaking a partial migration for a completed one.
        #[cfg(feature = "offline")]
        {
            if let Some(token) = source.get_offline_token() {
                self.set_offline_token(&token)?;
            }
            if let Some(machine_file) = source.get_machine_file() {
                self.set_machine_file(&machine_file)?;
            }
        }
        if let Some(timestamp) = source.get_last_seen_timestamp() {
            self.set_last_seen_timestamp(timestamp)?;
        }
        self.set_license(&license)?;
        // Prevent a later deactivation/reset of the product-scoped cache from
        // resurrecting the pre-migration generic record on the next launch.
        source.clear()?;
        if source.get_license().is_some() {
            let _ = self.clear();
            return Err(Error::Cache(
                "legacy license state could not be removed after migration".into(),
            ));
        }
        Ok(())
    }

    pub(crate) fn product_scoped_prefix(product_slug: &str) -> String {
        let digest = Sha256::digest(product_slug.as_bytes());
        ["licenseseat_", &hex_bytes(&digest[..12]), "_"].concat()
    }

    pub(crate) fn normalized_prefix(prefix: &str) -> String {
        safe_prefix(prefix)
    }

    /// Fail fast if durable storage cannot be created and atomically written.
    ///
    /// This runs before any activation request so a host never consumes a seat
    /// and only then discovers that the resulting activation cannot be saved.
    pub(crate) fn initialize(&self) -> Result<()> {
        let _guard = self.lock_io()?;
        let probe_key = format!("storage_probe_{}", uuid::Uuid::new_v4().as_simple());
        let path = self
            .path(&probe_key)
            .ok_or_else(|| Error::Cache("invalid cache probe path".into()))?;
        atomic_write_private(&path, b"null")?;
        std::fs::remove_file(&path).map_err(|error| Error::Cache(error.to_string()))?;
        if let Some(parent) = path.parent() {
            sync_parent_directory(parent)?;
        }
        Ok(())
    }

    // ========================================================================
    // License-specific methods
    // ========================================================================

    /// Store the current license.
    pub fn set_license(&self, license: &License) -> Result<()> {
        self.set("license", license)
    }

    /// Commit a server-confirmed activation as one cross-process cache
    /// transaction.
    ///
    /// The license record is the durable commit marker and is written first.
    /// Supporting cleanup is deliberately best-effort after that point: stale
    /// offline artifacts are cryptographically identity-bound and cannot grant
    /// access for the replacement activation, while losing a newly consumed
    /// server seat because an obsolete artifact could not be deleted would be
    /// an avoidable availability failure. Cleanup failures are returned as
    /// diagnostic warnings for the caller to emit.
    pub(crate) fn commit_activation(
        &self,
        license: &License,
        observed_at: i64,
    ) -> Result<Vec<String>> {
        if observed_at <= 0 {
            return Err(Error::Cache("activation timestamp must be positive".into()));
        }

        let _guard = self.lock_io()?;
        self.set_unlocked("license", license)?;

        let mut warnings = Vec::new();
        // A committed activation is an authoritative online acceptance, so the
        // watermark is re-anchored (possibly lowered) to the observed commit
        // time rather than max()-advanced. See `anchor_last_seen_timestamp`.
        if let Err(error) = self.anchor_last_seen_timestamp_unlocked(observed_at) {
            warnings.push(format!(
                "activation was saved but the clock watermark could not be updated: {error}"
            ));
        }

        for key in ["offline_token", "machine_file", "license_snapshot"] {
            if let Err(error) = self.remove_key_unlocked(key) {
                warnings.push(format!(
                    "activation was saved but stale {key} state could not be removed: {error}"
                ));
            }
        }

        if let Some(legacy_directory) = self.legacy_cache_dir.as_deref() {
            if let Err(error) = self.clear_directory_unlocked(legacy_directory) {
                warnings.push(format!(
                    "activation was saved but legacy cached state could not be removed: {error}"
                ));
            }
        }

        Ok(warnings)
    }

    /// Get the cached license.
    pub fn get_license(&self) -> Option<License> {
        self.get("license")
    }

    /// Load startup license state without collapsing corruption, unsafe file
    /// substitution, or I/O failure into the same result as an absent license.
    pub(crate) fn get_license_for_initialization(&self) -> Result<Option<License>> {
        self.get_strict("license")
    }

    /// Return whether the exact cached activation is still current.
    #[cfg(feature = "offline")]
    pub fn matches_identity(&self, expected: &LicenseIdentity) -> bool {
        self.get_license()
            .is_some_and(|license| license.identity() == *expected)
    }

    /// Update validation state only when the exact initiating activation is
    /// still current.
    ///
    /// Offline verification updates the visible validation result but never
    /// advances `last_validated`, whose meaning is deliberately "last online".
    pub fn update_validation(
        &self,
        expected: &LicenseIdentity,
        result: &ValidationResult,
        observed_at: chrono::DateTime<chrono::Utc>,
    ) -> Result<bool> {
        let _guard = self.lock_io()?;
        if let Some(mut license) = self.get_unlocked::<License>("license") {
            if license.identity() != *expected {
                return Ok(false);
            }
            if result.valid && license.license_key == result.license.key {
                license.trusted_license = Some(result.license.clone());
            } else if !result.valid {
                license.trusted_license = None;
            }
            license.validation = Some(result.clone());
            if !result.offline {
                license.last_validated = observed_at;
            }
            self.set_unlocked("license", &license)?;
            return Ok(true);
        }
        Ok(false)
    }

    // Persist a fail-closed denial before destructive cleanup. If file
    // deletion is interrupted, a later process sees this stronger decision
    // before considering any older signed offline artifact.
    fn mark_invalid_unlocked(
        &self,
        expected: &LicenseIdentity,
        code: &str,
        message: &str,
        observed_at: chrono::DateTime<chrono::Utc>,
    ) -> Result<bool> {
        let Some(mut license) = self.get_unlocked::<License>("license") else {
            return Ok(false);
        };
        if license.identity() != *expected {
            return Ok(false);
        }
        let Some(mut license_response) = license.trusted_license.clone().or_else(|| {
            license
                .validation
                .as_ref()
                .map(|result| result.license.clone())
        }) else {
            return Err(Error::Cache(
                "cached license has no response metadata for a denial tombstone".into(),
            ));
        };
        license_response.status = "inactive".into();
        license_response.active_seats = 0;
        license_response.active_entitlements.clear();
        license.validation = Some(ValidationResult {
            object: "validation_result".into(),
            valid: false,
            code: Some(code.into()),
            message: Some(message.into()),
            warnings: None,
            license: license_response,
            activation: None,
            offline: false,
        });
        license.trusted_license = None;
        license.last_validated = observed_at;
        self.set_unlocked("license", &license)?;
        Ok(true)
    }

    /// Atomically invalidate and remove the exact cached activation while the
    /// cross-process state lock is held. A different replacement activation is
    /// left untouched.
    pub fn invalidate_and_clear(
        &self,
        expected: &LicenseIdentity,
        code: &str,
        message: &str,
        observed_at: chrono::DateTime<chrono::Utc>,
    ) -> Result<bool> {
        let _guard = self.lock_io()?;
        if self
            .get_unlocked::<License>("license")
            .is_none_or(|license| license.identity() != *expected)
        {
            return Ok(false);
        }

        let denial_error = self
            .mark_invalid_unlocked(expected, code, message, observed_at)
            .err();
        if let Err(clear_error) = self.clear_unlocked() {
            return Err(match denial_error {
                Some(denial_error) => Error::Cache(format!(
                    "failed to persist a denial ({denial_error}); cleanup also failed ({clear_error})"
                )),
                None => clear_error,
            });
        }
        Ok(true)
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
        self.set(&signing_key_cache_key(key_id), key)
    }

    /// Get a cached signing key.
    #[cfg(feature = "offline")]
    pub fn get_signing_key(&self, key_id: &str) -> Option<crate::models::SigningKeyResponse> {
        self.get(&signing_key_cache_key(key_id))
    }

    // ========================================================================
    // Timestamps
    // ========================================================================

    /// Advance the last seen timestamp (for clock tampering detection).
    ///
    /// This only ratchets upward. Offline verification must use this method so
    /// a rolled-back clock can never lower the watermark. Authoritative online
    /// successes use [`Self::anchor_last_seen_timestamp`] instead.
    pub fn set_last_seen_timestamp(&self, timestamp: i64) -> Result<()> {
        if timestamp <= 0 {
            return Err(Error::Cache("last-seen timestamp must be positive".into()));
        }
        let _guard = self.lock_io()?;
        self.set_last_seen_timestamp_unlocked(timestamp)
    }

    fn set_last_seen_timestamp_unlocked(&self, timestamp: i64) -> Result<()> {
        let existing = self
            .get_unlocked::<i64>(LAST_SEEN_TIMESTAMP_KEY)
            .unwrap_or_default();
        self.set_unlocked(LAST_SEEN_TIMESTAMP_KEY, &timestamp.max(existing))
    }

    /// Re-anchor the clock-rollback watermark to an authoritative observation.
    ///
    /// Unlike [`Self::set_last_seen_timestamp`], this may LOWER the stored
    /// value. It must only be called when the server has just accepted an
    /// authenticated request (activation commit, online validation success,
    /// heartbeat success): the server accepted the request as valid *now*, so
    /// the current local time is the best available trust anchor. Re-anchoring
    /// recovers installations whose watermark was poisoned by a transiently
    /// future-set clock, while rollback detection continues to protect the
    /// offline windows between authoritative contacts.
    pub fn anchor_last_seen_timestamp(&self, timestamp: i64) -> Result<()> {
        if timestamp <= 0 {
            return Err(Error::Cache("last-seen timestamp must be positive".into()));
        }
        let _guard = self.lock_io()?;
        self.anchor_last_seen_timestamp_unlocked(timestamp)
    }

    fn anchor_last_seen_timestamp_unlocked(&self, timestamp: i64) -> Result<()> {
        self.set_unlocked(LAST_SEEN_TIMESTAMP_KEY, &timestamp)?;
        // Writes only ever target the durable directory, so the anchor above
        // cannot lower a stale copy of the watermark left in the legacy cache
        // directory. Purge that slot here: the legacy read fallback in
        // `get_unlocked` copies legacy values back verbatim whenever the
        // durable file is missing, so a surviving legacy copy could otherwise
        // re-poison the watermark this authoritative anchor just repaired.
        if let Some(legacy_directory) = self.legacy_cache_dir.as_deref() {
            self.remove_key_in_directory_unlocked(legacy_directory, LAST_SEEN_TIMESTAMP_KEY)?;
        }
        Ok(())
    }

    /// Get the last seen timestamp.
    pub fn get_last_seen_timestamp(&self) -> Option<i64> {
        self.get(LAST_SEEN_TIMESTAMP_KEY)
    }

    // ========================================================================
    // Clear all
    // ========================================================================

    /// Return or create the stable, storage-scoped installation identifier.
    ///
    /// A legacy cached activation is adopted before generating a new random ID,
    /// preventing upgrades from consuming an additional seat.
    pub fn get_or_create_installation_identifier(
        &self,
        legacy_identifier: Option<&str>,
    ) -> Result<String> {
        let _guard = self.lock_io()?;

        if let Some(identifier) = self
            .get_unlocked::<String>(INSTALLATION_IDENTIFIER_KEY)
            .filter(|value| is_valid_installation_identifier(value))
        {
            return Ok(identifier);
        }

        let identifier = legacy_identifier
            .filter(|value| is_valid_installation_identifier(value))
            .map(ToString::to_string)
            .unwrap_or_else(|| format!("rust-{}", uuid::Uuid::new_v4().as_hyphenated()));
        self.set_unlocked(INSTALLATION_IDENTIFIER_KEY, &identifier)?;
        Ok(identifier)
    }

    /// Remove signed offline grants and unsigned diagnostic snapshots without
    /// deleting the active license record.
    pub fn clear_offline_assets(&self) -> Result<()> {
        let _guard = self.lock_io()?;
        for key in ["offline_token", "machine_file", "license_snapshot"] {
            self.remove_key_unlocked(key)?;
        }
        Ok(())
    }

    /// Clear license grants and derived artifacts while preserving the stable
    /// installation identifier and the clock-rollback watermark
    /// (`last_seen_ts`), which only authoritative online operations may
    /// re-anchor.
    pub fn clear(&self) -> Result<()> {
        let _guard = self.lock_io()?;
        self.clear_unlocked()
    }

    fn clear_unlocked(&self) -> Result<()> {
        // Clear a fallback directory before the authoritative current one. If
        // legacy cleanup fails, a current denial tombstone remains visible and
        // prevents legacy state from being resurrected on the next process.
        for directory in [&self.legacy_cache_dir, &self.cache_dir]
            .into_iter()
            .flatten()
        {
            self.clear_directory_unlocked(directory)?;
        }
        Ok(())
    }
}

fn remove_cache_file(path: &Path) -> Result<bool> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(Error::Cache(format!(
            "failed to remove cached state: {error}"
        ))),
    }
}

fn remove_atomic_temporary_files_for_target(
    directory: &Path,
    target_file_name: &str,
) -> Result<bool> {
    let entries = std::fs::read_dir(directory).map_err(|error| Error::Cache(error.to_string()))?;
    let mut removed_any = false;
    for entry in entries {
        let entry = entry.map_err(|error| Error::Cache(error.to_string()))?;
        let path = entry.path();
        if path
            .file_name()
            .and_then(|name| name.to_str())
            .and_then(atomic_temporary_target_name)
            == Some(target_file_name)
        {
            removed_any |= remove_cache_file(&path)?;
        }
    }
    Ok(removed_any)
}

fn atomic_temporary_target_name(file_name: &str) -> Option<&str> {
    let body = file_name.strip_prefix('.')?.strip_suffix(".tmp")?;
    let (target, nonce) = body.rsplit_once('.')?;
    (target.ends_with(".json") && is_random_suffix(nonce, 32)).then_some(target)
}

fn is_owned_cache_target_name(target: &str, prefix: &str, signing_key_prefix: &str) -> bool {
    LICENSE_STATE_KEYS
        .iter()
        .any(|key| target == format!("{prefix}{key}.json"))
        || target == format!("{prefix}{INSTALLATION_IDENTIFIER_KEY}.json")
        || is_signing_key_file_name(target, signing_key_prefix)
        || is_storage_probe_file_name(target, prefix)
}

fn is_signing_key_file_name(file_name: &str, signing_key_prefix: &str) -> bool {
    file_name
        .strip_prefix(signing_key_prefix)
        .and_then(|name| name.strip_suffix(".json"))
        .is_some_and(|digest| is_hex_with_length(digest, 64))
}

fn is_storage_probe_file_name(file_name: &str, prefix: &str) -> bool {
    file_name
        .strip_prefix(prefix)
        .and_then(|name| name.strip_prefix("storage_probe_"))
        .and_then(|name| name.strip_suffix(".json"))
        .is_some_and(|nonce| is_hex_with_length(nonce, 32))
}

fn is_hex_with_length(value: &str, length: usize) -> bool {
    value.len() == length && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn is_random_suffix(value: &str, length: usize) -> bool {
    value.len() == length && value.bytes().all(|byte| byte.is_ascii_alphanumeric())
}

fn existing_real_directory(path: &Path) -> Result<bool> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata_is_link_or_reparse_point(&metadata) || !metadata.is_dir() => {
            Err(Error::Cache(
                "cache directory must remain a real directory, not a link or reparse point".into(),
            ))
        }
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(Error::Cache(error.to_string())),
    }
}

fn read_cache_value<T: serde::de::DeserializeOwned>(path: &Path) -> Option<T> {
    let metadata = std::fs::symlink_metadata(path).ok()?;
    if metadata_is_link_or_reparse_point(&metadata)
        || !metadata.is_file()
        || metadata.len() > MAX_CACHE_FILE_BYTES
    {
        return None;
    }

    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        use windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT;
        options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    let file = options.open(path).ok()?;
    let opened_metadata = file.metadata().ok()?;
    if metadata_is_link_or_reparse_point(&opened_metadata)
        || !opened_metadata.is_file()
        || opened_metadata.len() > MAX_CACHE_FILE_BYTES
    {
        return None;
    }

    // A file can grow after metadata is read. `take` keeps the allocation and
    // read bounded even under a concurrent local writer.
    let mut json = Vec::with_capacity(opened_metadata.len() as usize);
    file.take(MAX_CACHE_FILE_BYTES + 1)
        .read_to_end(&mut json)
        .ok()?;
    if json.len() as u64 > MAX_CACHE_FILE_BYTES {
        return None;
    }
    crate::strict_json::from_slice(&json).ok()
}

fn read_cache_value_strict<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T> {
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|error| Error::Cache(format!("failed to inspect cached state: {error}")))?;
    if metadata_is_link_or_reparse_point(&metadata) || !metadata.is_file() {
        return Err(Error::Cache(
            "cache path must remain a real file, not a link or reparse point".into(),
        ));
    }
    if metadata.len() > MAX_CACHE_FILE_BYTES {
        return Err(Error::Cache(format!(
            "cached state exceeds the {MAX_CACHE_FILE_BYTES}-byte safety limit"
        )));
    }

    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        use windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT;
        options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    let file = options
        .open(path)
        .map_err(|error| Error::Cache(format!("failed to open cached state: {error}")))?;
    let opened_metadata = file
        .metadata()
        .map_err(|error| Error::Cache(format!("failed to inspect cached state: {error}")))?;
    if metadata_is_link_or_reparse_point(&opened_metadata)
        || !opened_metadata.is_file()
        || opened_metadata.len() > MAX_CACHE_FILE_BYTES
    {
        return Err(Error::Cache(
            "cached state is not a bounded real file".into(),
        ));
    }

    let mut json = Vec::with_capacity(opened_metadata.len() as usize);
    file.take(MAX_CACHE_FILE_BYTES + 1)
        .read_to_end(&mut json)
        .map_err(|error| Error::Cache(format!("failed to read cached state: {error}")))?;
    if json.len() as u64 > MAX_CACHE_FILE_BYTES {
        return Err(Error::Cache(format!(
            "cached state exceeds the {MAX_CACHE_FILE_BYTES}-byte safety limit"
        )));
    }
    crate::strict_json::from_slice(&json)
        .map_err(|error| Error::Cache(format!("cached state is corrupt: {error}")))
}

#[cfg(any(unix, windows))]
fn open_private_lock_file(path: &Path) -> Result<std::fs::File> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata_is_link_or_reparse_point(&metadata) || !metadata.is_file() => {
            return Err(Error::Cache(
                "cache lock path must be a real file, not a link or reparse point".into(),
            ));
        }
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(Error::Cache(error.to_string())),
    }

    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options
            .mode(0o600)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        use windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT;
        options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    let file = options
        .open(path)
        .map_err(|error| Error::Cache(format!("failed to open cache lock: {error}")))?;
    let metadata = file
        .metadata()
        .map_err(|error| Error::Cache(error.to_string()))?;
    if metadata_is_link_or_reparse_point(&metadata) || !metadata.is_file() {
        return Err(Error::Cache("cache lock path is not a real file".into()));
    }
    restrict_file_permissions(path)?;
    Ok(file)
}

fn metadata_is_link_or_reparse_point(metadata: &std::fs::Metadata) -> bool {
    if metadata.file_type().is_symlink() {
        return true;
    }

    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;

        metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
    }

    #[cfg(not(windows))]
    false
}

fn safe_prefix(prefix: &str) -> String {
    if !prefix.is_empty()
        && prefix.len() <= 128
        && prefix
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    {
        return prefix.to_string();
    }

    let digest = Sha256::digest(prefix.as_bytes());
    format!("licenseseat_{}_", hex_bytes(&digest[..12]))
}

fn is_safe_cache_key(key: &str) -> bool {
    !key.is_empty()
        && key.len() <= 128
        && key
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
}

#[cfg(feature = "offline")]
fn signing_key_cache_key(key_id: &str) -> String {
    let digest = Sha256::digest(key_id.as_bytes());
    format!("signing_key_{}", hex_bytes(&digest))
}

fn hex_bytes(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(encoded, "{byte:02x}");
    }
    encoded
}

/// An adopted or stored installation identifier must be non-empty, bounded,
/// control-free, and free of surrounding whitespace, but it is deliberately
/// not held to the 8-character floor applied to new `device_identifier`
/// configuration. A cached activation created before that floor existed (or
/// by another SDK without it) already consumed its server seat under the
/// short identifier; silently discarding it would generate a fresh random ID
/// and burn a second seat on the next activation.
fn is_valid_installation_identifier(value: &str) -> bool {
    let trimmed = value.trim();
    trimmed == value && (1..=255).contains(&value.len()) && !value.chars().any(char::is_control)
}

fn atomic_write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| Error::Cache("cache path has no parent".into()))?;
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| Error::Cache("cache path has an invalid file name".into()))?;
    let prefix = format!(".{file_name}.");
    let mut temporary = tempfile::Builder::new()
        .prefix(&prefix)
        .suffix(".tmp")
        .rand_bytes(32)
        .tempfile_in(parent)
        .map_err(|error| Error::Cache(error.to_string()))?;
    temporary
        .as_file_mut()
        .write_all(bytes)
        .and_then(|_| temporary.as_file().sync_all())
        .map_err(|error| Error::Cache(error.to_string()))?;

    // `NamedTempFile::persist` replaces atomically on supported platforms,
    // including MoveFileExW(REPLACE_EXISTING) on Windows. In particular, it
    // avoids a delete-then-rename gap that could lose the previous state.
    let persisted = temporary
        .persist(path)
        .map_err(|error| Error::Cache(error.error.to_string()))?;
    drop(persisted);
    restrict_file_permissions(path)?;
    sync_parent_directory(parent)
}

#[cfg(unix)]
fn restrict_directory_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
        .map_err(|error| Error::Cache(error.to_string()))
}

#[cfg(not(unix))]
fn restrict_directory_permissions(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(unix)]
fn restrict_file_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .map_err(|error| Error::Cache(error.to_string()))
}

#[cfg(not(unix))]
fn restrict_file_permissions(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(unix)]
fn sync_parent_directory(path: &Path) -> Result<()> {
    std::fs::File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| Error::Cache(error.to_string()))
}

#[cfg(not(unix))]
fn sync_parent_directory(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{License, LicenseResponse};
    use chrono::{TimeZone, Utc};

    fn sample_license(key: &str, fingerprint: &str, activation_id: &str) -> License {
        let timestamp = Utc
            .with_ymd_and_hms(2026, 1, 1, 0, 0, 0)
            .single()
            .expect("valid timestamp");
        License {
            license_key: key.into(),
            device_id: fingerprint.into(),
            activation_id: activation_id.into(),
            activated_at: timestamp,
            last_validated: timestamp,
            trusted_license: None,
            validation: None,
        }
    }

    fn sample_trusted_license(key: &str, fingerprint: &str, activation_id: &str) -> License {
        let mut license = sample_license(key, fingerprint, activation_id);
        license.trusted_license = Some(
            serde_json::from_value::<LicenseResponse>(serde_json::json!({
                "object": "license",
                "key": key,
                "status": "active",
                "starts_at": null,
                "expires_at": null,
                "mode": "hardware_locked",
                "plan_key": "pro",
                "seat_limit": 1,
                "active_seats": 1,
                "active_entitlements": [],
                "metadata": null,
                "product": { "slug": "test-product", "name": "Test Product" }
            }))
            .expect("trusted license fixture"),
        );
        license
    }

    #[test]
    fn unsafe_prefixes_and_signing_key_ids_never_become_paths() {
        let directory = tempfile::tempdir().expect("temp directory");
        let cache = LicenseCache::new("../../escape/", Some(directory.path().into()));
        cache
            .set_license(&sample_license("KEY", "fingerprint", "activation"))
            .expect("cache write");

        let entries = std::fs::read_dir(directory.path())
            .expect("cache directory")
            .map(|entry| {
                entry
                    .expect("directory entry")
                    .file_name()
                    .to_string_lossy()
                    .into_owned()
            })
            .collect::<Vec<_>>();
        assert_eq!(entries.len(), 2);
        assert!(entries.iter().all(|entry| entry.starts_with("v2_")));
        assert!(entries.iter().all(|entry| !entry.contains("escape")));
        assert!(
            entries
                .iter()
                .any(|entry| entry.ends_with("__license.json"))
        );
        assert!(entries.iter().any(|entry| entry.ends_with("__state.lock")));

        #[cfg(feature = "offline")]
        {
            let signing_key = crate::models::SigningKeyResponse {
                object: "signing_key".into(),
                key_id: "../../host-key".into(),
                algorithm: "Ed25519".into(),
                public_key: "key".into(),
                created_at: None,
                status: "active".into(),
            };
            cache
                .set_signing_key("../../host-key", &signing_key)
                .expect("signing key write");
            assert_eq!(
                cache
                    .get_signing_key("../../host-key")
                    .expect("signing key read")
                    .key_id,
                "../../host-key"
            );
        }
    }

    #[test]
    fn safe_caller_prefixes_are_not_disclosed_in_v2_filenames() {
        let directory = tempfile::tempdir().expect("temp directory");
        let cache = LicenseCache::new(
            "customer-product-confidential_",
            Some(directory.path().into()),
        );
        cache
            .set_license(&sample_license("KEY", "fingerprint", "activation"))
            .expect("cache write");

        let entries = std::fs::read_dir(directory.path())
            .expect("cache directory")
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .collect::<Vec<_>>();
        assert!(entries.iter().all(|entry| entry.starts_with("v2_")));
        assert!(
            entries
                .iter()
                .all(|entry| !entry.contains("customer") && !entry.contains("confidential"))
        );
    }

    #[test]
    fn duplicate_json_keys_are_never_accepted_from_cache() {
        let directory = tempfile::tempdir().expect("temp directory");
        let cache = LicenseCache::new("strict_json_", Some(directory.path().into()));
        cache.initialize().expect("cache initialization");
        let path = cache.path("ambiguous").expect("cache path");
        std::fs::write(&path, br#"{"decision":"deny","decision":"grant"}"#)
            .expect("ambiguous cache fixture");

        assert_eq!(cache.get::<serde_json::Value>("ambiguous"), None);
        assert!(cache.get_strict::<serde_json::Value>("ambiguous").is_err());
    }

    #[test]
    fn corrupt_current_state_never_resurrects_legacy_state() {
        let current = tempfile::tempdir().expect("current directory");
        let legacy = tempfile::tempdir().expect("legacy directory");
        let prefix = "migration_test_";
        let license = sample_license("LEGACY", "fingerprint", "activation");
        let legacy_path = legacy.path().join(format!("{prefix}license.json"));
        std::fs::write(&legacy_path, serde_json::to_vec(&license).unwrap()).expect("legacy write");

        let mut cache = LicenseCache::new(prefix, Some(current.path().into()));
        cache.legacy_cache_dir = Some(legacy.path().into());
        let current_path = cache.path("license").expect("current path");
        std::fs::write(&current_path, b"not-json").expect("corrupt current file");
        assert!(cache.get_license().is_none());

        std::fs::remove_file(&current_path).expect("remove corrupt file");
        assert_eq!(cache.get_license(), Some(license));
        assert!(
            current_path.exists(),
            "legacy value should migrate once absent"
        );
        assert!(!legacy_path.exists(), "migration must be one-way");
    }

    #[test]
    fn corrupt_current_license_entry_is_rejected_during_initialization() {
        let directory = tempfile::tempdir().expect("cache directory");
        let cache = LicenseCache::new("current_", Some(directory.path().into()));
        assert_eq!(
            cache
                .get_license_for_initialization()
                .expect("absent entry"),
            None
        );

        let path = cache.path("license").expect("current license path");
        std::fs::write(&path, b"not-json").expect("corrupt current state");
        assert!(cache.get_license_for_initialization().is_err());
        assert!(cache.get_license().is_none());

        std::fs::remove_file(&path).expect("remove corrupt file");
        std::fs::create_dir(&path).expect("substitute directory");
        assert!(cache.get_license_for_initialization().is_err());
    }

    #[test]
    fn legacy_cleanup_failure_retains_the_current_denial_tombstone() {
        let current = tempfile::tempdir().expect("current directory");
        let legacy = tempfile::tempdir().expect("legacy directory");
        let prefix = "denial_order_test_";
        let legacy_license =
            sample_trusted_license("LEGACY", "legacy-fingerprint", "legacy-activation");
        std::fs::write(
            legacy.path().join(format!("{prefix}license.json")),
            serde_json::to_vec(&legacy_license).unwrap(),
        )
        .expect("legacy state");

        let mut cache = LicenseCache::new(prefix, Some(current.path().into()));
        cache.legacy_cache_dir = Some(legacy.path().into());
        let active = sample_trusted_license("CURRENT", "fingerprint", "activation");
        let identity = active.identity();
        cache.set_license(&active).expect("current state");

        let blocked_legacy_path = legacy.path().join(format!("{prefix}license_snapshot.json"));
        std::fs::create_dir(&blocked_legacy_path).expect("blocked legacy cleanup path");
        assert!(
            cache
                .invalidate_and_clear(&identity, "revoked", "Revoked", Utc::now())
                .is_err()
        );

        let retained = cache
            .get_license()
            .expect("current denial must outrank legacy fallback");
        assert_eq!(retained.identity(), identity);
        assert!(retained.trusted_license.is_none());
        assert!(
            retained
                .validation
                .as_ref()
                .is_some_and(|validation| !validation.valid)
        );
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn cache_transactions_are_serialized_across_sdk_instances() {
        let directory = tempfile::tempdir().expect("cache directory");
        let first = LicenseCache::new("shared_", Some(directory.path().into()));
        let second = LicenseCache::new("shared_", Some(directory.path().into()));
        let first_transaction = first.lock_io().expect("first transaction lock");
        let (sender, receiver) = std::sync::mpsc::channel();

        let writer = std::thread::spawn(move || {
            let result = second.set_license(&sample_license(
                "SECOND",
                "second-fingerprint",
                "second-activation",
            ));
            sender.send(result).expect("report writer result");
        });

        assert!(
            receiver
                .recv_timeout(std::time::Duration::from_millis(100))
                .is_err(),
            "the second SDK instance must wait for the shared cache transaction"
        );
        drop(first_transaction);
        receiver
            .recv_timeout(std::time::Duration::from_secs(2))
            .expect("writer should resume after unlock")
            .expect("writer cache operation");
        writer.join().expect("writer thread");
    }

    #[test]
    fn clear_is_exact_and_preserves_installation_identity() {
        let directory = tempfile::tempdir().expect("temp directory");
        let first = LicenseCache::new("app", Some(directory.path().into()));
        let overlapping = LicenseCache::new("app2", Some(directory.path().into()));
        let first_identifier = first
            .get_or_create_installation_identifier(None)
            .expect("first identifier");
        first
            .set_license(&sample_license("FIRST", "first-device", "first-activation"))
            .expect("first license");
        overlapping
            .set_license(&sample_license(
                "SECOND",
                "second-device",
                "second-activation",
            ))
            .expect("second license");

        let nonce = "0".repeat(32);
        let digest = "a".repeat(64);
        let first_license_temporary = directory
            .path()
            .join(format!(".applicense.json.{nonce}.tmp"));
        let first_installation_temporary = directory
            .path()
            .join(format!(".appinstallation_identifier.json.{nonce}.tmp"));
        let first_signing_key_temporary = directory
            .path()
            .join(format!(".appsigning_key_{digest}.json.{nonce}.tmp"));
        let first_storage_probe = directory
            .path()
            .join(format!("appstorage_probe_{nonce}.json"));
        let overlapping_temporary = directory
            .path()
            .join(format!(".app2license.json.{nonce}.tmp"));
        for path in [
            &first_license_temporary,
            &first_installation_temporary,
            &first_signing_key_temporary,
            &first_storage_probe,
            &overlapping_temporary,
        ] {
            std::fs::write(path, b"private crash remnant").expect("write crash remnant");
        }

        first.clear().expect("clear first cache");

        assert!(first.get_license().is_none());
        assert!(!first_license_temporary.exists());
        assert!(!first_installation_temporary.exists());
        assert!(!first_signing_key_temporary.exists());
        assert!(!first_storage_probe.exists());
        assert!(overlapping_temporary.exists());
        assert_eq!(
            first
                .get_or_create_installation_identifier(None)
                .expect("preserved identifier"),
            first_identifier
        );
        assert_eq!(
            overlapping
                .get_license()
                .expect("overlapping cache survives")
                .license_key,
            "SECOND"
        );
    }

    #[test]
    fn activation_commit_survives_stale_artifact_cleanup_failure() {
        let directory = tempfile::tempdir().expect("temp directory");
        let prefix = "activation_commit_";
        let cache = LicenseCache::new(prefix, Some(directory.path().into()));
        let stale_machine_file = directory.path().join(format!("{prefix}machine_file.json"));
        std::fs::create_dir(&stale_machine_file).expect("blocked stale artifact path");

        let replacement = sample_license("NEW", "device", "new-activation");
        let warnings = cache
            .commit_activation(&replacement, 1_700_000_000)
            .expect("the durable license commit should succeed");

        assert_eq!(cache.get_license(), Some(replacement));
        assert_eq!(cache.get_last_seen_timestamp(), Some(1_700_000_000));
        assert!(
            warnings
                .iter()
                .any(|warning| warning.contains("stale machine_file")),
            "cleanup failure should remain observable: {warnings:?}"
        );
    }

    #[test]
    fn timestamp_watermark_is_monotonic() {
        let directory = tempfile::tempdir().expect("temp directory");
        let cache = LicenseCache::new("watermark_", Some(directory.path().into()));
        cache
            .set_last_seen_timestamp(200)
            .expect("initial timestamp");
        cache.set_last_seen_timestamp(100).expect("older timestamp");
        assert_eq!(cache.get_last_seen_timestamp(), Some(200));
        assert!(cache.set_last_seen_timestamp(0).is_err());
    }

    #[test]
    fn authoritative_anchor_may_lower_watermark() {
        let directory = tempfile::tempdir().expect("temp directory");
        let cache = LicenseCache::new("watermark_anchor_", Some(directory.path().into()));
        // A transiently future-set clock poisoned the ratcheting watermark.
        cache
            .set_last_seen_timestamp(4_102_444_800)
            .expect("poisoned future timestamp");
        cache
            .anchor_last_seen_timestamp(1_700_000_000)
            .expect("authoritative online re-anchor");
        assert_eq!(cache.get_last_seen_timestamp(), Some(1_700_000_000));
        assert!(cache.anchor_last_seen_timestamp(0).is_err());
        // The offline ratchet still refuses to move backward afterwards.
        cache.set_last_seen_timestamp(100).expect("older timestamp");
        assert_eq!(cache.get_last_seen_timestamp(), Some(1_700_000_000));
    }

    #[test]
    fn clear_preserves_clock_rollback_watermark() {
        let directory = tempfile::tempdir().expect("temp directory");
        let cache = LicenseCache::new("watermark_clear_", Some(directory.path().into()));
        let license = sample_license("KEY", "fingerprint", "activation");
        cache
            .commit_activation(&license, 1_700_000_000)
            .expect("activation commit");
        assert_eq!(cache.get_last_seen_timestamp(), Some(1_700_000_000));

        cache.clear().expect("clear");
        assert!(cache.get_license().is_none());
        assert_eq!(
            cache.get_last_seen_timestamp(),
            Some(1_700_000_000),
            "clear/reset must preserve the rollback watermark like the installation identifier"
        );

        cache
            .commit_activation(&license, 1_700_000_100)
            .expect("second activation commit");
        assert!(
            cache
                .invalidate_and_clear(
                    &license.identity(),
                    "locally_reset",
                    "License state was reset locally",
                    chrono::Utc::now(),
                )
                .expect("reset-style invalidate and clear")
        );
        assert!(cache.get_license().is_none());
        assert_eq!(
            cache.get_last_seen_timestamp(),
            Some(1_700_000_100),
            "the reset path must also preserve the rollback watermark"
        );
    }

    #[test]
    fn anchor_purges_the_stale_legacy_watermark_slot() {
        let current = tempfile::tempdir().expect("current directory");
        let legacy = tempfile::tempdir().expect("legacy directory");
        let prefix = "watermark_legacy_";
        std::fs::write(
            legacy.path().join(format!("{prefix}last_seen_ts.json")),
            b"4102444800",
        )
        .expect("poisoned legacy watermark");

        let mut cache = LicenseCache::new(prefix, Some(current.path().into()));
        cache.legacy_cache_dir = Some(legacy.path().into());
        cache
            .anchor_last_seen_timestamp(1_700_000_000)
            .expect("authoritative online re-anchor");
        assert_eq!(cache.get_last_seen_timestamp(), Some(1_700_000_000));
        assert!(
            !legacy
                .path()
                .join(format!("{prefix}last_seen_ts.json"))
                .exists(),
            "anchoring must purge the legacy watermark slot"
        );

        // Even if the durable copy is later lost, the legacy read fallback can
        // no longer resurrect the poisoned pre-anchor value.
        std::fs::remove_file(cache.path(LAST_SEEN_TIMESTAMP_KEY).unwrap())
            .expect("simulate loss of the durable copy");
        assert_eq!(cache.get_last_seen_timestamp(), None);
    }

    #[test]
    fn short_legacy_installation_identifier_is_adopted() {
        let directory = tempfile::tempdir().expect("temp directory");
        let cache = LicenseCache::new("short_adopt_", Some(directory.path().into()));
        assert_eq!(
            cache
                .get_or_create_installation_identifier(Some("dev-1"))
                .expect("adoption"),
            "dev-1",
            "an existing activation's short fingerprint must be adopted, not silently replaced"
        );
        assert_eq!(
            cache
                .get_or_create_installation_identifier(None)
                .expect("stored identifier"),
            "dev-1",
            "the adopted identifier must remain durable across reads"
        );

        // Malformed candidates are still rejected for adoption.
        let fresh = tempfile::tempdir().expect("temp directory");
        let fresh_cache = LicenseCache::new("short_adopt_fresh_", Some(fresh.path().into()));
        let generated = fresh_cache
            .get_or_create_installation_identifier(Some(" dev-1"))
            .expect("generated identifier");
        assert!(generated.starts_with("rust-"));
    }

    #[cfg(unix)]
    #[test]
    fn cache_uses_private_permissions_and_rejects_symlink_reads() {
        use std::os::unix::fs::{PermissionsExt, symlink};

        let directory = tempfile::tempdir().expect("temp directory");
        let cache = LicenseCache::new("private_", Some(directory.path().join("state")));
        let license = sample_license("KEY", "fingerprint", "activation");
        cache.set_license(&license).expect("cache write");
        let path = cache.path("license").expect("cache path");
        assert_eq!(
            std::fs::metadata(path.parent().unwrap())
                .expect("directory metadata")
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        assert_eq!(
            std::fs::metadata(&path)
                .expect("file metadata")
                .permissions()
                .mode()
                & 0o777,
            0o600
        );

        let target = directory.path().join("attacker-controlled.json");
        std::fs::write(&target, serde_json::to_vec(&license).unwrap()).expect("target write");
        std::fs::remove_file(&path).expect("remove cache file");
        symlink(&target, &path).expect("create symlink");
        assert!(cache.get_license().is_none());
    }

    #[test]
    fn oversized_cache_files_are_rejected() {
        let directory = tempfile::tempdir().expect("temp directory");
        let cache = LicenseCache::new("oversized_", Some(directory.path().into()));
        std::fs::create_dir_all(directory.path()).expect("cache directory");
        let path = cache.path("license").expect("cache path");
        let file = std::fs::File::create(path).expect("oversized file");
        file.set_len(MAX_CACHE_FILE_BYTES + 1)
            .expect("set oversized length");
        assert!(cache.get_license().is_none());
    }

    #[test]
    fn oversized_serialized_values_are_rejected_before_disk_commit() {
        let directory = tempfile::tempdir().expect("temp directory");
        let cache = LicenseCache::new("oversized_write_", Some(directory.path().into()));
        let oversized = "x".repeat(MAX_CACHE_FILE_BYTES as usize + 1);

        assert!(cache.set("oversized", &oversized).is_err());
        assert!(!cache.path("oversized").expect("cache path").exists());
    }

    #[test]
    fn default_prefix_is_deterministically_product_scoped() {
        let first = LicenseCache::product_scoped_prefix("clipbasket");
        assert_eq!(first, LicenseCache::product_scoped_prefix("clipbasket"));
        assert_ne!(first, LicenseCache::product_scoped_prefix("hustl"));
        assert!(first.starts_with("licenseseat_"));
        assert!(first.ends_with('_'));
    }
}
