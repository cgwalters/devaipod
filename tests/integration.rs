//! Lightweight integration tests for devaipod
//!
//! These tests run as part of `cargo test` and don't require podman.
//! For comprehensive integration tests that test actual pod creation,
//! see the `crates/integration-tests` crate which uses linkme for test registration.
//!
//! Run with: cargo test

use std::process::{Command, Stdio};

/// Helper to run devaipod CLI commands
fn devaipod(args: &[&str]) -> std::io::Result<std::process::Output> {
    Command::new(env!("CARGO_BIN_EXE_devaipod"))
        .args(args)
        .stdin(Stdio::null())
        .output()
}

/// Test dry-run on this project
#[test]
fn test_dry_run_on_self() {
    // Run dry-run on this project - should succeed without starting anything
    let output = devaipod(&["up", ".", "--dry-run"]).expect("Failed to run devaipod up --dry-run");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        output.status.success(),
        "devaipod up --dry-run failed.\nstdout: {}\nstderr: {}",
        stdout,
        stderr
    );

    assert!(
        stdout.contains("Dry run") || stdout.contains("dry run"),
        "Expected dry-run message. stdout:\n{}",
        stdout
    );
}

/// Test help output
#[test]
fn test_help() {
    let output = devaipod(&["--help"]).expect("Failed to run devaipod --help");

    assert!(output.status.success());

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("up"), "Help should list 'up' command");
    assert!(stdout.contains("list"), "Help should list 'list' command");
    assert!(
        stdout.contains("delete"),
        "Help should list 'delete' command"
    );
}

/// Test up --help output
#[test]
fn test_up_help() {
    let output = devaipod(&["up", "--help"]).expect("Failed to run devaipod up --help");

    assert!(output.status.success());

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("--image"),
        "Help should list --image option"
    );
    assert!(
        stdout.contains("--dry-run"),
        "Help should list --dry-run option"
    );
}

/// Test completions generation
#[test]
fn test_completions() {
    let output = devaipod(&["completions", "bash"]).expect("Failed to run devaipod completions");

    assert!(output.status.success());

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("devaipod") || stdout.contains("complete"),
        "Should generate bash completions"
    );
}
