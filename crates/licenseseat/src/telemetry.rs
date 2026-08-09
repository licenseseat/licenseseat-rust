//! Device telemetry collection for analytics.
//!
//! Collects non-personally identifiable device information for dashboard
//! analytics (DAU/MAU, version adoption, platform distribution).

use serde::Serialize;
use std::env;
#[cfg(target_os = "linux")]
use std::io::Read;
#[cfg(target_os = "linux")]
use std::path::Path;

#[cfg(target_os = "linux")]
const MAX_SYSTEM_FILE_BYTES: u64 = 64 * 1024;
const MAX_ENVIRONMENT_VALUE_BYTES: usize = 128;

/// Telemetry data collected from the device.
#[derive(Debug, Clone, Serialize)]
pub struct Telemetry {
    /// SDK name (always "rust").
    pub sdk_name: &'static str,
    /// SDK version.
    pub sdk_version: &'static str,
    /// Operating system name.
    pub os_name: String,
    /// Operating system version.
    pub os_version: String,
    /// Platform type ("native" for native apps, "web" for web apps).
    pub platform: &'static str,
    /// Device type ("desktop", "phone", "tablet", "tv", "watch").
    pub device_type: &'static str,
    /// CPU architecture.
    pub architecture: &'static str,
    /// Number of CPU cores.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cpu_cores: Option<usize>,
    /// System memory in GB.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memory_gb: Option<u64>,
    /// System locale.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub locale: Option<String>,
    /// Language code.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub language: Option<String>,
    /// Timezone.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timezone: Option<String>,
    /// App version (user-provided).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub app_version: Option<String>,
    /// App build (user-provided).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub app_build: Option<String>,
}

impl Telemetry {
    /// Collect telemetry from the current environment.
    pub fn collect(app_version: Option<String>, app_build: Option<String>) -> Self {
        Self {
            sdk_name: crate::SDK_NAME,
            sdk_version: crate::VERSION,
            os_name: os_name(),
            os_version: os_version(),
            platform: platform(),
            device_type: device_type(),
            architecture: architecture(),
            cpu_cores: num_cpus(),
            memory_gb: memory_gb(),
            locale: locale(),
            language: language(),
            timezone: timezone(),
            app_version,
            app_build,
        }
    }
}

/// Get the operating system name.
fn os_name() -> String {
    #[cfg(target_os = "macos")]
    return "macOS".to_string();
    #[cfg(target_os = "windows")]
    return "Windows".to_string();
    #[cfg(target_os = "linux")]
    return "Linux".to_string();
    #[cfg(target_os = "ios")]
    return "iOS".to_string();
    #[cfg(target_os = "android")]
    return "Android".to_string();
    #[cfg(not(any(
        target_os = "macos",
        target_os = "windows",
        target_os = "linux",
        target_os = "ios",
        target_os = "android"
    )))]
    return env::consts::OS.to_string();
}

/// Get the operating system version.
fn os_version() -> String {
    #[cfg(target_os = "linux")]
    {
        if let Some(content) = read_text_file_limited(Path::new("/etc/os-release")) {
            for line in content.lines() {
                if let Some(version) = line.strip_prefix("VERSION_ID=") {
                    let version = version
                        .trim_start_matches("VERSION_ID=")
                        .trim_matches('"')
                        .trim();
                    if let Some(version) = bounded_environment_text(version.to_string()) {
                        return version;
                    }
                }
            }
        }
    }

    "unknown".to_string()
}

/// Get the platform type.
/// Returns "native" for native apps (Tauri, Swift, etc.), "web" for web apps.
fn platform() -> &'static str {
    // Native SDK always returns "native"
    "native"
}

/// Get the device type.
/// Returns "desktop", "phone", "tablet", "tv", or "watch".
fn device_type() -> &'static str {
    #[cfg(target_os = "macos")]
    return "desktop";
    #[cfg(target_os = "windows")]
    return "desktop";
    #[cfg(target_os = "linux")]
    return "desktop";
    #[cfg(target_os = "ios")]
    {
        // iOS can be phone or tablet - check screen size or device model
        // For now, default to phone (most common)
        // TODO: Could use UIDevice.current.userInterfaceIdiom via FFI
        return "phone";
    }
    #[cfg(target_os = "android")]
    {
        // Android can be phone, tablet, tv, etc.
        // For now, default to phone (most common)
        // TODO: Could check screen density/size
        return "phone";
    }
    #[cfg(target_os = "tvos")]
    return "tv";
    #[cfg(target_os = "watchos")]
    return "watch";
    #[cfg(not(any(
        target_os = "macos",
        target_os = "windows",
        target_os = "linux",
        target_os = "ios",
        target_os = "android",
        target_os = "tvos",
        target_os = "watchos"
    )))]
    return "desktop";
}

/// Get the CPU architecture.
fn architecture() -> &'static str {
    env::consts::ARCH
}

/// Get the number of CPU cores.
fn num_cpus() -> Option<usize> {
    std::thread::available_parallelism().ok().map(|p| p.get())
}

/// Get system memory in GB.
fn memory_gb() -> Option<u64> {
    #[cfg(target_os = "linux")]
    {
        if let Some(content) = read_text_file_limited(Path::new("/proc/meminfo")) {
            for line in content.lines() {
                if line.starts_with("MemTotal:") {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() >= 2 {
                        if let Ok(kb) = parts[1].parse::<u64>() {
                            return Some(kb / (1024 * 1024)); // Convert kB to GB
                        }
                    }
                }
            }
        }
    }

    None
}

/// Get the system locale.
fn locale() -> Option<String> {
    env::var("LC_ALL")
        .ok()
        .and_then(bounded_environment_text)
        .or_else(|| env::var("LANG").ok().and_then(bounded_environment_text))
}

/// Get the language code from locale.
fn language() -> Option<String> {
    locale().and_then(|l| {
        l.split('_')
            .next()
            .map(|s| s.split('.').next().unwrap_or(s).to_string())
    })
}

/// Get the timezone.
fn timezone() -> Option<String> {
    env::var("TZ").ok().and_then(bounded_environment_text)
}

fn bounded_environment_text(value: String) -> Option<String> {
    let value = value.trim();
    (!value.is_empty()
        && value.len() <= MAX_ENVIRONMENT_VALUE_BYTES
        && !value.bytes().any(|byte| byte.is_ascii_control()))
    .then(|| value.to_string())
}

#[cfg(target_os = "linux")]
fn read_text_file_limited(path: &Path) -> Option<String> {
    let file = std::fs::File::open(path).ok()?;
    let metadata = file.metadata().ok()?;
    if !metadata.is_file() || metadata.len() > MAX_SYSTEM_FILE_BYTES {
        return None;
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take(MAX_SYSTEM_FILE_BYTES + 1)
        .read_to_end(&mut bytes)
        .ok()?;
    (bytes.len() as u64 <= MAX_SYSTEM_FILE_BYTES)
        .then(|| String::from_utf8(bytes).ok())
        .flatten()
}

/// Generate a stable device identifier.
///
/// This remains as a compatibility wrapper around the canonical fingerprint
/// generator now housed in `device.rs`.
#[allow(dead_code)]
pub fn generate_device_id() -> String {
    crate::device::generate_device_id()
}
