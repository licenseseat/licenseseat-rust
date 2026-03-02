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
    #[cfg(target_os = "macos")]
    {
        // Try sw_vers to get macOS version
        if let Ok(output) = std::process::Command::new("sw_vers")
            .arg("-productVersion")
            .output()
        {
            if output.status.success() {
                if let Ok(version) = String::from_utf8(output.stdout) {
                    return version.trim().to_string();
                }
            }
        }
    }

    #[cfg(target_os = "windows")]
    {
        // Try ver command or registry
        if let Ok(output) = std::process::Command::new("cmd")
            .args(["/C", "ver"])
            .output()
        {
            if output.status.success() {
                if let Ok(version) = String::from_utf8(output.stdout) {
                    // Parse version from "Microsoft Windows [Version X.X.X]"
                    if let Some(start) = version.find('[') {
                        if let Some(end) = version.find(']') {
                            return version[start + 1..end]
                                .replace("Version ", "")
                                .trim()
                                .to_string();
                        }
                    }
                }
            }
        }
    }

    #[cfg(target_os = "linux")]
    {
        // Try /etc/os-release
        if let Ok(content) = std::fs::read_to_string("/etc/os-release") {
            for line in content.lines() {
                if line.starts_with("VERSION_ID=") {
                    return line
                        .trim_start_matches("VERSION_ID=")
                        .trim_matches('"')
                        .to_string();
                }
            }
        }
        // Fallback to uname -r
        if let Ok(output) = std::process::Command::new("uname").arg("-r").output() {
            if output.status.success() {
                if let Ok(version) = String::from_utf8(output.stdout) {
                    return version.trim().to_string();
                }
            }
        }
    }

    // Fallback
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
    #[cfg(target_os = "macos")]
    {
        // Use sysctl to get memory size
        if let Ok(output) = std::process::Command::new("sysctl")
            .args(["-n", "hw.memsize"])
            .output()
        {
            if output.status.success() {
                if let Ok(mem_str) = String::from_utf8(output.stdout) {
                    if let Ok(bytes) = mem_str.trim().parse::<u64>() {
                        return Some(bytes / (1024 * 1024 * 1024)); // Convert to GB
                    }
                }
            }
        }
    }

    #[cfg(target_os = "linux")]
    {
        // Read from /proc/meminfo
        if let Ok(content) = std::fs::read_to_string("/proc/meminfo") {
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

    #[cfg(target_os = "windows")]
    {
        // Use wmic to get memory
        if let Ok(output) = std::process::Command::new("wmic")
            .args(["ComputerSystem", "get", "TotalPhysicalMemory"])
            .output()
        {
            if output.status.success() {
                if let Ok(mem_str) = String::from_utf8(output.stdout) {
                    for line in mem_str.lines().skip(1) {
                        if let Ok(bytes) = line.trim().parse::<u64>() {
                            return Some(bytes / (1024 * 1024 * 1024));
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
