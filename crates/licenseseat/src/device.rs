//! Device fingerprinting helpers.
//!
//! This module intentionally mirrors the C++ reference fingerprinting strategy
//! so mixed-SDK estates identify the same machine consistently by default.

use sha2::{Digest, Sha256};
use std::collections::HashMap;

/// Generate a stable device fingerprint.
pub fn generate_fingerprint() -> String {
    fingerprint_from_components(&collect_fingerprint_components())
}

/// Backward-compatible alias for the canonical fingerprint.
#[allow(dead_code)]
pub fn generate_device_id() -> String {
    generate_fingerprint()
}

/// Collect structured fingerprint components for diagnostics and server-side matching.
pub fn collect_fingerprint_components() -> HashMap<String, String> {
    let mut components = HashMap::new();
    components.insert("schema_version".into(), "1".into());
    components.insert("strategy".into(), "stable_exact".into());
    components.insert("platform".into(), get_platform_name());

    let hostname = get_hostname();
    if !hostname.is_empty() && hostname != "unknown" {
        components.insert("hostname".into(), hostname);
    }

    populate_platform_components(&mut components);

    if !components.contains_key("primary_signal") && components.contains_key("hostname") {
        components.insert("primary_signal".into(), "hostname".into());
    }

    components
}

/// Get the current platform name.
pub fn get_platform_name() -> String {
    #[cfg(target_os = "macos")]
    return "macos".to_string();
    #[cfg(target_os = "windows")]
    return "windows".to_string();
    #[cfg(target_os = "linux")]
    return "linux".to_string();
    #[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux")))]
    return "unknown".to_string();
}

/// Get a human-readable hostname.
pub fn get_hostname() -> String {
    hostname::get()
        .ok()
        .and_then(|hostname| hostname.into_string().ok())
        .unwrap_or_else(|| "unknown".to_string())
}

fn fingerprint_from_components(components: &HashMap<String, String>) -> String {
    let Some(raw_id) = select_raw_identifier(components) else {
        return "unknown-device".to_string();
    };

    let mut hasher = Sha256::new();
    hasher.update(raw_id.as_bytes());
    let digest = hasher.finalize();

    let mut fingerprint = String::with_capacity(32);
    for byte in digest.iter().take(16) {
        use std::fmt::Write as _;
        let _ = write!(fingerprint, "{byte:02x}");
    }

    fingerprint
}

fn select_raw_identifier(components: &HashMap<String, String>) -> Option<&str> {
    [
        "platform_uuid",
        "machine_id",
        "dbus_machine_id",
        "dmi_product_uuid",
        "machine_guid",
        "hostname",
    ]
    .into_iter()
    .find_map(|key| {
        components
            .get(key)
            .map(String::as_str)
            .filter(|value| !value.is_empty())
    })
}

#[cfg(target_os = "macos")]
fn populate_platform_components(components: &mut HashMap<String, String>) {
    if let Ok(platform_uuid) = machine_uid::get() {
        let trimmed = platform_uuid.trim();
        if !trimmed.is_empty() {
            components.insert("platform_uuid".into(), trimmed.to_string());
            components.insert("primary_signal".into(), "platform_uuid".into());
        }
    }
}

#[cfg(target_os = "linux")]
fn populate_platform_components(components: &mut HashMap<String, String>) {
    if let Some(machine_id) = read_trimmed_file("/etc/machine-id") {
        components.insert("machine_id".into(), machine_id.clone());
        components.insert("primary_signal".into(), "machine_id".into());

        if let Some(dbus_machine_id) =
            read_trimmed_file("/var/lib/dbus/machine-id").filter(|value| value != &machine_id)
        {
            components.insert("dbus_machine_id".into(), dbus_machine_id);
        }
    } else if let Some(dbus_machine_id) = read_trimmed_file("/var/lib/dbus/machine-id") {
        components.insert("dbus_machine_id".into(), dbus_machine_id);
        components.insert("primary_signal".into(), "dbus_machine_id".into());
    }

    if let Some(dmi_product_uuid) = read_trimmed_file("/sys/class/dmi/id/product_uuid") {
        components.insert("dmi_product_uuid".into(), dmi_product_uuid);
        if !components.contains_key("primary_signal") {
            components.insert("primary_signal".into(), "dmi_product_uuid".into());
        }
    }
}

#[cfg(target_os = "windows")]
fn populate_platform_components(components: &mut HashMap<String, String>) {
    if let Ok(machine_guid) = machine_uid::get() {
        let trimmed = machine_guid.trim();
        if !trimmed.is_empty() {
            components.insert("machine_guid".into(), trimmed.to_string());
            components.insert("primary_signal".into(), "machine_guid".into());
        }
    }
}

#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
fn populate_platform_components(_components: &mut HashMap<String, String>) {}

#[cfg(target_os = "linux")]
fn read_trimmed_file(path: &str) -> Option<String> {
    let value = std::fs::read_to_string(path).ok()?;
    let trimmed = value.trim();
    (!trimmed.is_empty()).then(|| trimmed.to_string())
}

#[cfg(test)]
mod tests {
    use super::{fingerprint_from_components, select_raw_identifier};
    use std::collections::HashMap;

    #[test]
    fn test_select_raw_identifier_matches_cpp_priority_order() {
        let mut components = HashMap::new();
        components.insert("hostname".into(), "studio-mac".into());
        components.insert("machine_id".into(), "machine-id".into());
        components.insert("platform_uuid".into(), "platform-uuid".into());

        assert_eq!(select_raw_identifier(&components), Some("platform-uuid"));
    }

    #[test]
    fn test_fingerprint_from_components_returns_cpp_style_hash() {
        let mut components = HashMap::new();
        components.insert("machine_id".into(), "machine-id-123".into());

        let fingerprint = fingerprint_from_components(&components);

        assert_eq!(fingerprint.len(), 32);
        assert!(fingerprint.chars().all(|ch| ch.is_ascii_hexdigit()));
    }

    #[test]
    fn test_fingerprint_from_components_falls_back_to_unknown_device() {
        let components = HashMap::new();

        assert_eq!(fingerprint_from_components(&components), "unknown-device");
    }
}
