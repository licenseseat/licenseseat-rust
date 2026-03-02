const COMMANDS: &[&str] = &[
    "activate",
    "validate",
    "deactivate",
    "heartbeat",
    "get_status",
    "check_entitlement",
    "has_entitlement",
    "get_license",
    "reset",
];

fn main() {
    tauri_plugin::Builder::new(COMMANDS).build();
}
