//! Pins the triplicated command registry.
//!
//! The renderer command surface is declared three times: the `COMMANDS` list
//! in `build.rs`, the default permission set in `permissions/default.toml`,
//! and the opt-in sets in `permissions/permission-sets.toml`. These files are
//! consumed by the Tauri build script rather than the compiler, so nothing
//! else fails when they drift apart. This test asserts that the default set
//! plus the four opt-in sets exactly partition the registered command list,
//! with `health` as the only designed overlap.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

fn manifest_path(relative: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(relative)
}

fn read_manifest_file(relative: &str) -> String {
    std::fs::read_to_string(manifest_path(relative))
        .unwrap_or_else(|error| panic!("failed to read {relative}: {error}"))
}

/// Extract every double-quoted string literal from `source`.
///
/// Both files under test are simple enough that neither contains escaped
/// quotes inside string literals.
fn quoted_strings(source: &str) -> Vec<String> {
    let mut values = Vec::new();
    let mut rest = source;
    while let Some(start) = rest.find('"') {
        let after = &rest[start + 1..];
        let Some(end) = after.find('"') else { break };
        values.push(after[..end].to_string());
        rest = &after[end + 1..];
    }
    values
}

fn build_rs_commands() -> BTreeSet<String> {
    let source = read_manifest_file("build.rs");
    let start = source
        .find("const COMMANDS")
        .expect("build.rs must declare COMMANDS");
    let end = source[start..]
        .find("];")
        .map(|offset| start + offset)
        .expect("the COMMANDS declaration must be terminated");
    let commands: BTreeSet<String> = quoted_strings(&source[start..end]).into_iter().collect();
    assert!(!commands.is_empty(), "build.rs listed no commands");
    commands
}

/// Map `allow-*` permission identifiers to their command names.
fn permission_commands(values: &[String]) -> BTreeSet<String> {
    values
        .iter()
        .filter_map(|value| value.strip_prefix("allow-"))
        .map(|name| name.replace('-', "_"))
        .collect()
}

fn default_set_commands() -> BTreeSet<String> {
    let source = read_manifest_file("permissions/default.toml");
    let commands = permission_commands(&quoted_strings(&source));
    assert!(
        !commands.is_empty(),
        "the default set grants no permissions"
    );
    commands
}

fn opt_in_sets() -> Vec<(String, BTreeSet<String>)> {
    let source = read_manifest_file("permissions/permission-sets.toml");
    let mut sets = Vec::new();
    for chunk in source.split("[[set]]").skip(1) {
        let identifier = chunk
            .lines()
            .find_map(|line| {
                line.trim().strip_prefix("identifier").map(|rest| {
                    rest.trim_start_matches([' ', '='])
                        .trim_matches('"')
                        .to_string()
                })
            })
            .expect("every [[set]] must declare an identifier");
        let commands = permission_commands(&quoted_strings(chunk));
        assert!(
            !commands.is_empty(),
            "permission set {identifier} grants no permissions"
        );
        sets.push((identifier, commands));
    }
    sets
}

#[test]
fn permission_sets_exactly_partition_the_command_registry() {
    let commands = build_rs_commands();
    let default_commands = default_set_commands();
    let opt_in = opt_in_sets();

    let opt_in_names: BTreeSet<&str> = opt_in.iter().map(|(name, _)| name.as_str()).collect();
    assert_eq!(
        opt_in_names,
        BTreeSet::from([
            "advanced-lifecycle",
            "diagnostics",
            "offline-management",
            "releases",
        ]),
        "the opt-in permission-set roster changed; update this partition test deliberately"
    );

    // Every granted permission must name a registered command.
    for command in &default_commands {
        assert!(
            commands.contains(command),
            "the default set grants unregistered command {command}"
        );
    }
    for (set, set_commands) in &opt_in {
        for command in set_commands {
            assert!(
                commands.contains(command),
                "set {set} grants unregistered command {command}"
            );
        }
    }

    // Opt-in sets must be pairwise disjoint.
    for (index, (first_name, first_commands)) in opt_in.iter().enumerate() {
        for (second_name, second_commands) in &opt_in[index + 1..] {
            let overlap: Vec<&String> = first_commands.intersection(second_commands).collect();
            assert!(
                overlap.is_empty(),
                "sets {first_name} and {second_name} both grant {overlap:?}"
            );
        }
    }

    // `health` is deliberately reachable from both the default surface and
    // the diagnostics set. Nothing else may appear in the default set and an
    // opt-in set at the same time.
    let opt_in_union: BTreeSet<String> = opt_in
        .iter()
        .flat_map(|(_, set_commands)| set_commands.iter().cloned())
        .collect();
    let default_overlap: BTreeSet<String> = default_commands
        .intersection(&opt_in_union)
        .cloned()
        .collect();
    assert_eq!(
        default_overlap,
        BTreeSet::from(["health".to_string()]),
        "unexpected overlap between the default set and the opt-in sets"
    );

    // Together, the default set and the opt-in sets must cover every
    // registered command and must not grant anything unregistered.
    let granted_union: BTreeSet<String> = default_commands.union(&opt_in_union).cloned().collect();
    assert_eq!(
        granted_union, commands,
        "the permission sets and the build.rs command registry diverged"
    );
}
