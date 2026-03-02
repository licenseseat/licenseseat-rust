//! Device telemetry collection for analytics.
//!
//! Collects non-personally identifiable device information for
//! dashboard analytics (DAU/MAU, version adoption, platform distribution).

use serde::Serialize;
use std::env;

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
    /// Platform type.
    pub platform: &'static str,
    /// CPU architecture.
    pub architecture: &'static str,
    /// Number of CPU cores.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cpu_cores: Option<usize>,
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
            architecture: architecture(),
            cpu_cores: num_cpus(),
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
    // This is a simplified version - in production you might use
    // platform-specific APIs to get the actual version
    env::consts::OS.to_string()
}

/// Get the platform type.
fn platform() -> &'static str {
    #[cfg(any(target_os = "ios", target_os = "android"))]
    return "mobile";
    #[cfg(not(any(target_os = "ios", target_os = "android")))]
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

/// Get the system locale.
fn locale() -> Option<String> {
    env::var("LANG").ok().or_else(|| env::var("LC_ALL").ok())
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
    env::var("TZ").ok()
}

/// Generate a stable device identifier.
pub fn generate_device_id() -> String {
    // Try to get machine UUID first
    if let Ok(id) = machine_uid::get() {
        return format!("rust_{}", &id[..16.min(id.len())]);
    }

    // Fallback: generate from hostname + username
    let hostname = hostname::get()
        .ok()
        .and_then(|h| h.into_string().ok())
        .unwrap_or_else(|| "unknown".to_string());

    let username = env::var("USER")
        .or_else(|_| env::var("USERNAME"))
        .unwrap_or_else(|_| "unknown".to_string());

    // Simple hash
    let combined = format!("{}:{}", hostname, username);
    let hash = simple_hash(&combined);
    format!("rust_{:016x}", hash)
}

/// Simple string hashing (not cryptographic, just for device ID).
fn simple_hash(s: &str) -> u64 {
    let mut hash: u64 = 5381;
    for byte in s.bytes() {
        hash = hash.wrapping_mul(33).wrapping_add(byte as u64);
    }
    hash
}
