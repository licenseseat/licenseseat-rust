//! License caching for persistent storage.
//!
//! Cache filenames are derived from cryptographic hashes rather than caller-
//! controlled prefixes or token-controlled key IDs. Writes use a same-directory
//! temporary file and atomic rename so partially written state is never trusted.

use crate::error::{Error, Result};
use crate::models::License;
use sha2::{Digest, Sha256};
use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

const MAX_CACHE_BYTES: u64 = 2 * 1024 * 1024;
static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

/// Cache for persisting license data.
#[derive(Debug)]
pub struct LicenseCache {
    namespace: String,
    legacy_prefix: Option<String>,
    cache_dir: Option<PathBuf>,
    legacy_cache_dir: Option<PathBuf>,
    manage_directory_permissions: bool,
}

impl LicenseCache {
    /// Create a new cache with the given prefix.
    pub fn new(prefix: impl Into<String>, cache_dir: Option<PathBuf>) -> Self {
        let prefix = prefix.into();
        let namespace = digest_hex(prefix.as_bytes());
        let legacy_prefix = is_safe_legacy_component(&prefix).then_some(prefix);
        let (cache_dir, legacy_cache_dir, manage_directory_permissions) = match cache_dir {
            Some(path) => (Some(path), None, false),
            None => (
                dirs::data_local_dir().map(|directory| directory.join("licenseseat")),
                dirs::cache_dir().map(|directory| directory.join("licenseseat")),
                true,
            ),
        };

        Self {
            namespace,
            legacy_prefix,
            cache_dir,
            legacy_cache_dir,
            manage_directory_permissions,
        }
    }

    fn path(&self, key: &str) -> Option<PathBuf> {
        let key_digest = digest_hex(key.as_bytes());
        self.cache_dir.as_ref().map(|directory| {
            directory.join(format!(
                "v2-{}-{}.json",
                &self.namespace[..32],
                &key_digest[..32]
            ))
        })
    }

    fn legacy_paths(&self, key: &str) -> Vec<PathBuf> {
        if !is_safe_legacy_component(key) {
            return Vec::new();
        }
        let Some(prefix) = &self.legacy_prefix else {
            return Vec::new();
        };
        let filename = format!("{prefix}{key}.json");
        [self.cache_dir.as_ref(), self.legacy_cache_dir.as_ref()]
            .into_iter()
            .flatten()
            .map(|directory| directory.join(&filename))
            .collect()
    }

    fn ensure_dir(&self) -> Result<()> {
        let Some(directory) = &self.cache_dir else {
            return Ok(());
        };
        let existed = match std::fs::symlink_metadata(directory) {
            Ok(_) => true,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
            Err(error) => return Err(cache_io_error(error)),
        };
        std::fs::create_dir_all(directory).map_err(cache_io_error)?;
        let metadata = std::fs::symlink_metadata(directory).map_err(cache_io_error)?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(Error::Cache(
                "cache directory is not a real directory".into(),
            ));
        }
        if self.manage_directory_permissions || !existed {
            set_directory_permissions(directory)?;
        }
        validate_directory_security(directory)?;
        Ok(())
    }

    fn set<T: serde::Serialize>(&self, key: &str, value: &T) -> Result<()> {
        self.ensure_dir()?;
        let Some(path) = self.path(key) else {
            return Ok(());
        };
        let json = serde_json::to_vec(value)?;
        if json.len() as u64 > MAX_CACHE_BYTES {
            return Err(Error::Cache(
                "cache value exceeds the supported size".into(),
            ));
        }
        atomic_write(&path, &json)
    }

    fn get<T: serde::de::DeserializeOwned + serde::Serialize>(&self, key: &str) -> Option<T> {
        if let Some(path) = self.path(key) {
            if let Some(value) = read_json_file(&path) {
                return Some(value);
            }
        }

        // One-way migration from the pre-hardening plaintext filename layout.
        for legacy_path in self.legacy_paths(key) {
            let Some(value) = read_json_file::<T>(&legacy_path) else {
                continue;
            };
            if self.set(key, &value).is_ok() {
                let _ = std::fs::remove_file(&legacy_path);
            }
            return Some(value);
        }
        None
    }

    pub fn set_license(&self, license: &License) -> Result<()> {
        self.set("license", license)
    }

    pub fn get_license(&self) -> Option<License> {
        self.get("license")
    }

    #[cfg(feature = "offline")]
    pub fn set_offline_token(&self, token: &crate::models::OfflineTokenResponse) -> Result<()> {
        self.set("offline_token", token)
    }

    #[cfg(feature = "offline")]
    pub fn get_offline_token(&self) -> Option<crate::models::OfflineTokenResponse> {
        self.get("offline_token")
    }

    #[cfg(feature = "offline")]
    pub fn set_machine_file(&self, machine_file: &crate::models::MachineFile) -> Result<()> {
        self.set("machine_file", machine_file)
    }

    #[cfg(feature = "offline")]
    pub fn get_machine_file(&self) -> Option<crate::models::MachineFile> {
        self.get("machine_file")
    }

    pub fn set_last_seen_timestamp(&self, timestamp: i64) -> Result<()> {
        if timestamp <= 0 {
            return Err(Error::Cache("invalid last-seen timestamp".into()));
        }
        self.set("last_seen_ts", &timestamp)
    }

    pub fn get_last_seen_timestamp(&self) -> Option<i64> {
        self.get("last_seen_ts")
    }

    pub fn clear(&self) {
        let Some(directory) = &self.cache_dir else {
            return;
        };
        let expected_prefix = format!("v2-{}-", &self.namespace[..32]);
        let Ok(entries) = std::fs::read_dir(directory) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let matches_namespace = path
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with(&expected_prefix) && name.ends_with(".json"));
            if matches_namespace && entry.file_type().is_ok_and(|kind| kind.is_file()) {
                let _ = std::fs::remove_file(path);
            }
        }
    }
}

fn digest_hex(value: &[u8]) -> String {
    Sha256::digest(value)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn is_safe_legacy_component(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

fn read_json_file<T: serde::de::DeserializeOwned>(path: &Path) -> Option<T> {
    let metadata = std::fs::symlink_metadata(path).ok()?;
    if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() > MAX_CACHE_BYTES
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
    if !opened_metadata.is_file() || opened_metadata.len() > MAX_CACHE_BYTES {
        return None;
    }
    let mut bytes = Vec::with_capacity(opened_metadata.len() as usize);
    file.take(MAX_CACHE_BYTES + 1)
        .read_to_end(&mut bytes)
        .ok()?;
    if bytes.len() as u64 > MAX_CACHE_BYTES {
        return None;
    }
    serde_json::from_slice(&bytes).ok()
}

fn atomic_write(path: &Path, bytes: &[u8]) -> Result<()> {
    let directory = path
        .parent()
        .ok_or_else(|| Error::Cache("cache path has no parent directory".into()))?;
    for _ in 0..16 {
        let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let temporary = directory.join(format!(
            ".licenseseat-{}-{sequence}.tmp",
            std::process::id()
        ));
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = match options.open(&temporary) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(cache_io_error(error)),
        };
        let result = (|| {
            file.write_all(bytes).map_err(cache_io_error)?;
            file.sync_all().map_err(cache_io_error)?;
            drop(file);
            replace_file(&temporary, path)?;
            set_file_permissions(path)?;
            sync_replaced_entry(path, directory)?;
            Ok(())
        })();
        if result.is_err() {
            let _ = std::fs::remove_file(&temporary);
        }
        return result;
    }
    Err(Error::Cache(
        "could not allocate an atomic cache file".into(),
    ))
}

#[cfg(not(windows))]
fn replace_file(source: &Path, destination: &Path) -> Result<()> {
    std::fs::rename(source, destination).map_err(cache_io_error)
}

#[cfg(windows)]
fn replace_file(source: &Path, destination: &Path) -> Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::{
        MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH, MoveFileExW,
    };

    let source = source
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let destination = destination
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();

    // SAFETY: both pointers reference owned, NUL-terminated UTF-16 buffers for
    // the duration of the call. MoveFileExW does not retain either pointer.
    let replaced = unsafe {
        MoveFileExW(
            source.as_ptr(),
            destination.as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    };
    if replaced == 0 {
        return Err(cache_io_error(std::io::Error::last_os_error()));
    }
    Ok(())
}

fn cache_io_error(error: std::io::Error) -> Error {
    Error::Cache(format!("cache I/O failure ({:?})", error.kind()))
}

#[cfg(unix)]
fn sync_replaced_entry(path: &Path, directory: &Path) -> Result<()> {
    use std::os::unix::fs::OpenOptionsExt;

    let mut file_options = OpenOptions::new();
    file_options
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    file_options
        .open(path)
        .and_then(|file| file.sync_all())
        .map_err(cache_io_error)?;

    let mut directory_options = OpenOptions::new();
    directory_options
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_DIRECTORY);
    directory_options
        .open(directory)
        .and_then(|directory| directory.sync_all())
        .map_err(cache_io_error)
}

#[cfg(not(unix))]
fn sync_replaced_entry(_path: &Path, _directory: &Path) -> Result<()> {
    Ok(())
}

#[cfg(unix)]
fn set_directory_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).map_err(cache_io_error)
}

#[cfg(unix)]
fn validate_directory_security(path: &Path) -> Result<()> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let metadata = std::fs::symlink_metadata(path).map_err(cache_io_error)?;
    // SAFETY: geteuid has no pointer arguments or caller-side preconditions.
    let effective_user_id = unsafe { libc::geteuid() };
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || metadata.uid() != effective_user_id
        || metadata.permissions().mode() & 0o022 != 0
    {
        return Err(Error::Cache(
            "cache directory permissions are unsafe".into(),
        ));
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_directory_security(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(not(unix))]
fn set_directory_permissions(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(unix)]
fn set_file_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).map_err(cache_io_error)
}

#[cfg(not(unix))]
fn set_file_permissions(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    static TEST_SEQUENCE: AtomicU64 = AtomicU64::new(0);

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new(label: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "licenseseat-{label}-{}-{}",
                std::process::id(),
                TEST_SEQUENCE.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir_all(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn caller_controlled_prefix_and_key_cannot_escape_storage_directory() {
        let directory = TestDirectory::new("path-confinement");
        let cache = LicenseCache::new("../../outside/\\..", Some(directory.0.clone()));

        cache
            .set("../../attacker-key", &json!({"safe": true}))
            .unwrap();
        let path = cache.path("../../attacker-key").unwrap();

        assert_eq!(path.parent(), Some(directory.0.as_path()));
        assert!(
            path.file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with("v2-")
        );
        assert_eq!(
            cache.get::<serde_json::Value>("../../attacker-key"),
            Some(json!({"safe": true}))
        );
    }

    #[test]
    fn oversized_cache_values_are_rejected() {
        let directory = TestDirectory::new("oversized");
        let cache = LicenseCache::new("test", Some(directory.0.clone()));
        let oversized = "x".repeat(MAX_CACHE_BYTES as usize);

        assert!(matches!(
            cache.set("value", &oversized),
            Err(Error::Cache(_))
        ));
        assert!(!cache.path("value").unwrap().exists());
    }

    #[test]
    fn atomic_overwrite_returns_only_the_latest_complete_value() {
        let directory = TestDirectory::new("atomic-overwrite");
        let cache = LicenseCache::new("test", Some(directory.0.clone()));

        cache.set("value", &json!({"version": 1})).unwrap();
        cache.set("value", &json!({"version": 2})).unwrap();

        assert_eq!(
            cache.get::<serde_json::Value>("value"),
            Some(json!({"version": 2}))
        );
        assert!(
            std::fs::read_dir(&directory.0)
                .unwrap()
                .flatten()
                .all(|entry| !entry.file_name().to_string_lossy().ends_with(".tmp"))
        );
    }

    #[test]
    fn clear_removes_only_the_selected_namespace() {
        let directory = TestDirectory::new("namespace-clear");
        let first = LicenseCache::new("first", Some(directory.0.clone()));
        let second = LicenseCache::new("second", Some(directory.0.clone()));
        first.set("value", &json!(1)).unwrap();
        second.set("value", &json!(2)).unwrap();

        first.clear();

        assert_eq!(first.get::<serde_json::Value>("value"), None);
        assert_eq!(second.get::<serde_json::Value>("value"), Some(json!(2)));
    }

    #[cfg(unix)]
    #[test]
    fn cache_reads_do_not_follow_symbolic_links() {
        use std::os::unix::fs::symlink;

        let directory = TestDirectory::new("symlink-read");
        let cache = LicenseCache::new("test", Some(directory.0.clone()));
        cache.ensure_dir().unwrap();
        let outside = directory.0.join("outside.json");
        std::fs::write(&outside, br#"{"forged":true}"#).unwrap();
        symlink(&outside, cache.path("value").unwrap()).unwrap();

        assert_eq!(cache.get::<serde_json::Value>("value"), None);
    }

    #[cfg(unix)]
    #[test]
    fn symbolic_link_storage_directory_is_rejected() {
        use std::os::unix::fs::symlink;

        let root = TestDirectory::new("symlink-directory");
        let target = root.0.join("target");
        let link = root.0.join("link");
        std::fs::create_dir(&target).unwrap();
        symlink(&target, &link).unwrap();
        let cache = LicenseCache::new("test", Some(link));

        assert!(matches!(
            cache.set("value", &json!(1)),
            Err(Error::Cache(_))
        ));
    }

    #[cfg(unix)]
    #[test]
    fn unsafe_custom_directory_permissions_are_rejected() {
        use std::os::unix::fs::PermissionsExt;

        let directory = TestDirectory::new("unsafe-directory-permissions");
        std::fs::set_permissions(&directory.0, std::fs::Permissions::from_mode(0o770)).unwrap();
        let cache = LicenseCache::new("test", Some(directory.0.clone()));

        assert!(matches!(
            cache.set("value", &json!(1)),
            Err(Error::Cache(_))
        ));
    }

    #[cfg(unix)]
    #[test]
    fn existing_custom_directory_permissions_are_not_rewritten() {
        use std::os::unix::fs::PermissionsExt;

        let directory = TestDirectory::new("preserve-directory-permissions");
        std::fs::set_permissions(&directory.0, std::fs::Permissions::from_mode(0o750)).unwrap();
        let cache = LicenseCache::new("test", Some(directory.0.clone()));

        cache.set("value", &json!(1)).unwrap();

        assert_eq!(
            std::fs::metadata(&directory.0)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o750
        );
    }

    #[cfg(unix)]
    #[test]
    fn cache_permissions_are_private() {
        use std::os::unix::fs::PermissionsExt;

        let root = TestDirectory::new("permissions");
        let directory = root.0.join("new-cache-directory");
        let cache = LicenseCache::new("test", Some(directory.clone()));
        cache.set("value", &json!(1)).unwrap();

        let directory_mode = std::fs::metadata(&directory).unwrap().permissions().mode() & 0o777;
        let file_mode = std::fs::metadata(cache.path("value").unwrap())
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(directory_mode, 0o700);
        assert_eq!(file_mode, 0o600);
    }
}
