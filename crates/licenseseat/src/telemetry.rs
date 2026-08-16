//! Device telemetry collection for analytics.
//!
//! Collects platform, coarse hardware-capacity, locale/timezone, SDK, and
//! caller-provided app-version information for dashboard analytics. Hosts can
//! disable this through `Config::telemetry_enabled` and remain responsible for
//! describing the collection in their own privacy policy.

use serde::Serialize;
use std::env;
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "ios"))]
use std::io::Read;
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "ios"))]
use std::path::Path;

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "ios"))]
const MAX_SYSTEM_FILE_BYTES: u64 = 64 * 1024;
const MAX_ENVIRONMENT_VALUE_BYTES: usize = 128;
/// Upper bound for string-valued `sysctl` reads, which are short identifiers
/// such as `"15.5"`. Keeps a hostile or corrupt kernel value from allocating.
#[cfg(any(target_os = "macos", target_os = "ios"))]
const MAX_SYSCTL_STRING_BYTES: usize = 128;

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
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    {
        // `kern.osproductversion` is the user-facing product version ("15.5"),
        // available since macOS 10.13.4 / iOS 11.3. Deliberately not
        // `kern.osrelease`, which reports the Darwin kernel version ("24.5.0").
        if let Some(version) = sysctl_string("kern.osproductversion") {
            return version;
        }

        // Older systems (and any kernel that hides the sysctl) still ship the
        // product version in the system property list.
        if let Some(version) = system_version_plist_product_version() {
            return version;
        }
    }

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

    #[cfg(target_os = "windows")]
    {
        if let Some(version) = rtl_os_version() {
            return version;
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
        // `hw.machine` is the hardware model identifier ("iPhone16,2",
        // "iPad14,3"). Every iPad model identifier is prefixed "iPad", so the
        // prefix separates the tablet idiom from the phone idiom without
        // linking UIKit for `UIDevice.userInterfaceIdiom`. iPod touch and the
        // simulator both fall through to "phone", which matches their idiom.
        //
        // Compile-gated to iOS, so the host test suite never exercises this
        // branch; it is covered by the shared `sysctl_string` tests on macOS.
        return match sysctl_string("hw.machine") {
            Some(model) if model.starts_with("iPad") => "tablet",
            _ => "phone",
        };
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
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    {
        // `hw.memsize` is installed physical memory in bytes. Truncating
        // division by 1024^3 keeps the same rounding as the Linux
        // `/proc/meminfo` path below.
        if let Some(bytes) = sysctl_u64("hw.memsize") {
            return Some(bytes / (1024 * 1024 * 1024));
        }
    }

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

    #[cfg(target_os = "windows")]
    {
        // `ullTotalPhys` is installed physical memory in bytes. Truncating
        // division by 1024^3 keeps the same rounding as the macOS `hw.memsize`
        // and Linux `/proc/meminfo` paths above.
        if let Some(bytes) = total_physical_memory_bytes() {
            return Some(bytes / (1024 * 1024 * 1024));
        }
    }

    None
}

/// Read installed physical memory in bytes from `GlobalMemoryStatusEx`.
///
/// Returns `None` when the call fails or reports zero, so callers fall back to
/// omitting the field rather than publishing a bogus `0`.
#[cfg(target_os = "windows")]
fn total_physical_memory_bytes() -> Option<u64> {
    use windows_sys::Win32::System::SystemInformation::{GlobalMemoryStatusEx, MEMORYSTATUSEX};

    let mut status = MEMORYSTATUSEX {
        // The API rejects the call unless the caller states the struct size it
        // compiled against, which is how it version-checks the layout.
        dwLength: u32::try_from(std::mem::size_of::<MEMORYSTATUSEX>()).ok()?,
        ..Default::default()
    };

    // SAFETY: `status` is owned, fully initialized, correctly aligned storage of
    // exactly `size_of::<MEMORYSTATUSEX>()` bytes, and `dwLength` declares that
    // same size, so the kernel writes only within the struct. The pointer is
    // valid for the duration of the call and is not retained afterwards.
    let populated = unsafe { GlobalMemoryStatusEx(&raw mut status) };

    (populated != 0 && status.ullTotalPhys > 0).then_some(status.ullTotalPhys)
}

/// Read the OS version through `ntdll!RtlGetVersion`, formatted
/// "major.minor.build".
///
/// `RtlGetVersion` is used in preference to `GetVersionExW`, which is shimmed to
/// report 6.2 (Windows 8) for processes whose application manifest lacks a
/// `supportedOS` entry for the running release. `RtlGetVersion` is never shimmed,
/// so the reading is correct regardless of how the host application is
/// manifested — SDK consumers do not control that manifest.
#[cfg(target_os = "windows")]
fn rtl_os_version() -> Option<String> {
    use windows_sys::Wdk::System::SystemServices::RtlGetVersion;
    use windows_sys::Win32::System::SystemInformation::OSVERSIONINFOW;

    let mut info = OSVERSIONINFOW {
        dwOSVersionInfoSize: u32::try_from(std::mem::size_of::<OSVERSIONINFOW>()).ok()?,
        ..Default::default()
    };

    // SAFETY: `info` is owned, fully initialized, correctly aligned storage of
    // exactly `size_of::<OSVERSIONINFOW>()` bytes, and `dwOSVersionInfoSize`
    // declares that same size, so `ntdll` writes only within the struct. The
    // pointer is valid for the duration of the call and is not retained.
    let status = unsafe { RtlGetVersion(&raw mut info) };

    // `STATUS_SUCCESS` is 0; any negative `NTSTATUS` is a failure.
    if status != 0 {
        return None;
    }

    bounded_environment_text(format!(
        "{}.{}.{}",
        info.dwMajorVersion, info.dwMinorVersion, info.dwBuildNumber
    ))
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

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "ios"))]
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

/// Read a string-valued `sysctl` by name on Apple platforms.
///
/// Returns `None` when the name is unknown to the kernel, the value is empty,
/// or the value is larger than [`MAX_SYSCTL_STRING_BYTES`].
#[cfg(any(target_os = "macos", target_os = "ios"))]
fn sysctl_string(name: &str) -> Option<String> {
    let name = std::ffi::CString::new(name).ok()?;
    let mut len: libc::size_t = 0;

    // SAFETY: `name` is a valid NUL-terminated C string that outlives the call.
    // A null value pointer asks the kernel for the size only, which it writes
    // through `len`; no new value is written back (`newp` null, `newlen` 0).
    let probe = unsafe {
        libc::sysctlbyname(
            name.as_ptr(),
            std::ptr::null_mut(),
            &mut len,
            std::ptr::null_mut(),
            0,
        )
    };
    if probe != 0 || len == 0 || len > MAX_SYSCTL_STRING_BYTES {
        return None;
    }

    let mut buffer = vec![0u8; len];
    // SAFETY: as above, except the kernel now writes at most `len` bytes into
    // `buffer`, which owns exactly `len` initialized bytes. `len` is updated to
    // the number of bytes actually written; a value that grew between the two
    // calls fails with `ENOMEM` instead of overflowing the buffer.
    let read = unsafe {
        libc::sysctlbyname(
            name.as_ptr(),
            buffer.as_mut_ptr().cast::<libc::c_void>(),
            &mut len,
            std::ptr::null_mut(),
            0,
        )
    };
    if read != 0 || len == 0 || len > buffer.len() {
        return None;
    }

    buffer.truncate(len);
    // String sysctls are NUL-terminated; keep only the bytes before the first
    // terminator.
    let end = buffer
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(buffer.len());
    buffer.truncate(end);

    bounded_environment_text(String::from_utf8(buffer).ok()?)
}

/// Read a 64-bit integer `sysctl` by name on Apple platforms.
#[cfg(any(target_os = "macos", target_os = "ios"))]
fn sysctl_u64(name: &str) -> Option<u64> {
    let name = std::ffi::CString::new(name).ok()?;
    let mut value: u64 = 0;
    let mut len: libc::size_t = std::mem::size_of::<u64>();

    // SAFETY: `name` is a valid NUL-terminated C string, and the kernel writes
    // at most `len` bytes into `value`, which is exactly `size_of::<u64>()`
    // bytes of owned, initialized storage. Nothing is written back to the
    // kernel (`newp` null, `newlen` 0).
    let read = unsafe {
        libc::sysctlbyname(
            name.as_ptr(),
            (&raw mut value).cast::<libc::c_void>(),
            &mut len,
            std::ptr::null_mut(),
            0,
        )
    };

    (read == 0 && len == std::mem::size_of::<u64>()).then_some(value)
}

/// Parse `ProductVersion` out of the Apple system version property list.
///
/// Fallback for kernels without `kern.osproductversion` (macOS before 10.13.4).
#[cfg(any(target_os = "macos", target_os = "ios"))]
fn system_version_plist_product_version() -> Option<String> {
    let content = read_text_file_limited(Path::new(
        "/System/Library/CoreServices/SystemVersion.plist",
    ))?;
    let value = content
        .split_once("<key>ProductVersion</key>")?
        .1
        .split_once("<string>")?
        .1
        .split_once("</string>")?
        .0;

    bounded_environment_text(value.to_string())
}

/// Generate a stable device identifier.
///
/// This remains as a compatibility wrapper around the canonical fingerprint
/// generator now housed in `device.rs`.
#[allow(dead_code)]
pub fn generate_device_id() -> String {
    crate::device::generate_device_id()
}

#[cfg(all(test, target_os = "macos"))]
mod tests {
    use super::*;

    #[test]
    fn macos_os_version_reports_a_product_version() {
        let version = os_version();
        assert_ne!(
            version, "unknown",
            "macOS should resolve a product version through sysctl or SystemVersion.plist"
        );

        // Equivalent to matching `^\d+\.\d+`.
        let mut components = version.split('.');
        let major = components.next().unwrap_or_default();
        let minor = components.next().unwrap_or_default();

        assert!(
            !major.is_empty() && major.bytes().all(|byte| byte.is_ascii_digit()),
            "expected a numeric major version in {version:?}"
        );
        assert!(
            !minor.is_empty() && minor.bytes().all(|byte| byte.is_ascii_digit()),
            "expected a numeric minor version in {version:?}"
        );
        assert!(
            major.parse::<u32>().is_ok_and(|major| major > 0),
            "expected a non-zero macOS major version in {version:?}"
        );
    }

    #[test]
    fn macos_os_version_matches_the_product_version_sysctl() {
        // Guards against regressing to `kern.osrelease`, which reports the
        // Darwin kernel version rather than the user-facing product version.
        let expected = sysctl_string("kern.osproductversion")
            .expect("kern.osproductversion is available on macOS 10.13.4+");
        assert_eq!(os_version(), expected);
    }

    #[test]
    fn macos_system_version_plist_fallback_agrees_with_sysctl() {
        let plist = system_version_plist_product_version()
            .expect("SystemVersion.plist should expose ProductVersion");
        assert_eq!(
            Some(plist),
            sysctl_string("kern.osproductversion"),
            "plist fallback and sysctl should report the same product version"
        );
    }

    #[test]
    fn macos_memory_gb_is_reported() {
        let memory = memory_gb().expect("hw.memsize should report installed memory on macOS");
        assert!(memory > 0, "expected a positive GB reading, got {memory}");
    }

    #[test]
    fn macos_architecture_uses_canonical_vocabulary() {
        assert!(
            matches!(architecture(), "aarch64" | "x86_64"),
            "unexpected macOS architecture {:?}",
            architecture()
        );
    }
}

#[cfg(all(test, target_os = "windows"))]
mod windows_tests {
    use super::*;

    #[test]
    fn windows_os_version_reports_a_build_triple() {
        let version = os_version();
        assert_ne!(
            version, "unknown",
            "Windows should resolve a version through RtlGetVersion"
        );

        let components: Vec<&str> = version.split('.').collect();
        assert_eq!(
            components.len(),
            3,
            "expected a major.minor.build triple in {version:?}"
        );
        for component in &components {
            assert!(
                !component.is_empty() && component.bytes().all(|byte| byte.is_ascii_digit()),
                "expected numeric version components in {version:?}"
            );
        }

        // Every supported Windows release reports major >= 6 (Vista and later);
        // Windows 10 and 11 both report major 10 with a distinguishing build.
        assert!(
            components[0].parse::<u32>().is_ok_and(|major| major >= 6),
            "expected a supported Windows major version in {version:?}"
        );
        assert!(
            components[2].parse::<u32>().is_ok_and(|build| build > 0),
            "expected a non-zero build number in {version:?}"
        );
    }

    #[test]
    fn windows_os_version_is_not_shimmed_to_windows_8() {
        // `GetVersionExW` reports 6.2 for unmanifested processes. Test binaries
        // are unmanifested, so a 6.2 reading here would mean the shimmed API
        // leaked back in.
        let version = os_version();
        assert_ne!(
            version.split('.').take(2).collect::<Vec<_>>().join("."),
            "6.2",
            "RtlGetVersion should bypass the GetVersionExW manifest shim, got {version:?}"
        );
    }

    #[test]
    fn windows_memory_gb_is_reported() {
        let memory = memory_gb().expect("GlobalMemoryStatusEx should report installed memory");
        assert!(memory > 0, "expected a positive GB reading, got {memory}");
    }

    #[test]
    fn windows_memory_gb_truncates_like_the_unix_paths() {
        let bytes = total_physical_memory_bytes().expect("physical memory should be readable");
        assert_eq!(memory_gb(), Some(bytes / (1024 * 1024 * 1024)));
    }

    #[test]
    fn windows_device_type_is_desktop() {
        assert_eq!(device_type(), "desktop");
        assert_eq!(os_name(), "Windows");
    }
}
