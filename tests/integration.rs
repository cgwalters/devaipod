//! Integration tests for devaipod
//!
//! These tests require:
//! - podman installed and running
//! - devpod installed and configured
//! - bubblewrap (bwrap) installed for sandbox tests
//!
//! Run with: cargo test -- --ignored
//! Run sandbox tests: cargo test test_sandbox
//!
//! ## End-to-End GitHub Integration Tests
//!
//! The `test_e2e_gh_*` tests require:
//! - A running devpod workspace with devaipod installed
//! - GitHub CLI (`gh`) authenticated
//! - Environment variable `DEVAIPOD_TEST_REPO` set to a repo you control (e.g., `cgwalters/playground`)
//!
//! Run with: `just test-e2e-gh` or `DEVAIPOD_TEST_REPO=owner/repo cargo test test_e2e_gh -- --ignored`

use std::io::Write;
use std::process::{Command, Stdio};

/// Helper to run devaipod CLI commands
fn devaipod(args: &[&str]) -> std::io::Result<std::process::Output> {
    Command::new(env!("CARGO_BIN_EXE_devaipod"))
        .args(args)
        .stdin(Stdio::null())
        .output()
}

/// Helper to check if devpod is installed
fn devpod_available() -> bool {
    Command::new("devpod")
        .arg("version")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Helper to check if podman is available
fn podman_available() -> bool {
    Command::new("podman")
        .arg("version")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Clean up a workspace, ignoring errors
fn cleanup_workspace(name: &str) {
    let _ = Command::new("devpod")
        .args(["delete", name, "--force"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
}

#[test]
#[ignore]
fn test_help() {
    let output = devaipod(&["--help"]).expect("Failed to run devaipod");
    assert!(output.status.success());

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("devaipod"));
    assert!(stdout.contains("up"));
    assert!(stdout.contains("list"));
}

#[test]
#[ignore]
fn test_list_workspaces() {
    if !devpod_available() {
        eprintln!("Skipping: devpod not available");
        return;
    }

    let output = devaipod(&["list"]).expect("Failed to run devaipod list");
    assert!(output.status.success());
}

#[test]
#[ignore]
fn test_list_workspaces_json() {
    if !devpod_available() {
        eprintln!("Skipping: devpod not available");
        return;
    }

    let output = devaipod(&["list", "--json"]).expect("Failed to run devaipod list --json");
    assert!(output.status.success());
}

#[test]
#[ignore]
fn test_up_and_delete_local_dir() {
    if !devpod_available() || !podman_available() {
        eprintln!("Skipping: devpod or podman not available");
        return;
    }

    let workspace_name = "devc-test";
    cleanup_workspace(workspace_name);

    let output = devaipod(&["up", ".", "--no-agent"]).expect("Failed to run devaipod up");

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        eprintln!("devaipod up failed: {}", stderr);
        cleanup_workspace(workspace_name);
        panic!("devaipod up failed");
    }

    let list_output = devaipod(&["list"]).expect("Failed to run devaipod list");
    assert!(list_output.status.success());

    let delete_output =
        devaipod(&["delete", workspace_name, "--force"]).expect("Failed to run devaipod delete");
    assert!(delete_output.status.success());
}

#[test]
#[ignore]
fn test_stop_nonexistent_workspace() {
    if !devpod_available() {
        eprintln!("Skipping: devpod not available");
        return;
    }

    let output =
        devaipod(&["stop", "nonexistent-workspace-12345"]).expect("Failed to run devaipod stop");
    assert!(!output.status.success());
}

#[test]
#[ignore]
fn test_delete_nonexistent_workspace() {
    if !devpod_available() {
        eprintln!("Skipping: devpod not available");
        return;
    }

    let output = devaipod(&["delete", "nonexistent-workspace-12345"])
        .expect("Failed to run devaipod delete");
    assert!(!output.status.success());
}

#[test]
#[ignore]
fn test_full_workflow() {
    if !devpod_available() || !podman_available() {
        eprintln!("Skipping: devpod or podman not available");
        return;
    }

    let workspace_name = "devc";
    cleanup_workspace(workspace_name);

    eprintln!("Creating workspace...");
    let output = devaipod(&["up", ".", "--no-agent"]).expect("Failed to run devaipod up");
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        eprintln!("devaipod up failed: {}", stderr);
        cleanup_workspace(workspace_name);
        panic!("devaipod up failed");
    }

    eprintln!("Listing workspaces...");
    let list_output = devaipod(&["list"]).expect("Failed to list");
    assert!(list_output.status.success());

    eprintln!("Testing SSH...");
    let ssh_output =
        devaipod(&["ssh", workspace_name, "--", "echo", "hello"]).expect("Failed to ssh");
    if ssh_output.status.success() {
        let stdout = String::from_utf8_lossy(&ssh_output.stdout);
        assert!(stdout.contains("hello"));
    }

    eprintln!("Stopping workspace...");
    let _ = devaipod(&["stop", workspace_name]);

    eprintln!("Deleting workspace...");
    let delete_output = devaipod(&["delete", workspace_name, "--force"]).expect("Failed to delete");
    assert!(delete_output.status.success());

    eprintln!("Full workflow test passed!");
}

// =============================================================================
// Sandbox tests - verify bwrap security constraints
// These tests run without devpod, directly testing the bwrap configuration
// =============================================================================

/// Helper to check if bwrap is available
fn bwrap_available() -> bool {
    Command::new("bwrap")
        .arg("--version")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Create a temporary directory for testing (unique per call)
fn create_temp_dir(name: &str) -> std::path::PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let id = COUNTER.fetch_add(1, Ordering::SeqCst);
    let dir = std::env::temp_dir().join(format!(
        "devaipod-test-{}-{}-{}",
        name,
        std::process::id(),
        id
    ));
    std::fs::create_dir_all(&dir).expect("Failed to create temp dir");
    dir
}

/// Create a mock agent script
fn create_mock_agent(dir: &std::path::Path, script: &str) -> std::path::PathBuf {
    let agent_path = dir.join("mock-agent");
    let mut file = std::fs::File::create(&agent_path).expect("Failed to create mock agent");
    file.write_all(format!("#!/bin/sh\n{}", script).as_bytes())
        .expect("Failed to write mock agent");

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&agent_path).unwrap().permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&agent_path, perms).unwrap();
    }

    agent_path
}

/// Build bwrap args matching what devaipod uses (minimal root)
fn build_test_bwrap_args(
    workspace_host: &str,
    workspace_sandbox: &str,
    home_sandbox: &str,
    agent_home_host: &str,
) -> Vec<String> {
    let mut args = vec![
        "bwrap".to_string(),
        "--ro-bind".to_string(),
        "/usr".to_string(),
        "/usr".to_string(),
        "--ro-bind".to_string(),
        "/etc".to_string(),
        "/etc".to_string(),
    ];

    // Handle /lib and /lib64 (may be symlinks on some systems)
    for lib in &["/lib", "/lib64"] {
        let path = std::path::Path::new(lib);
        if path.is_symlink() {
            if let Ok(target) = std::fs::read_link(path) {
                args.extend([
                    "--symlink".to_string(),
                    target.to_string_lossy().to_string(),
                    lib.to_string(),
                ]);
            }
        } else if path.exists() {
            args.extend(["--ro-bind".to_string(), lib.to_string(), lib.to_string()]);
        }
    }

    // Get parent of home_sandbox for --dir
    let home_parent = std::path::Path::new(home_sandbox)
        .parent()
        .unwrap_or(std::path::Path::new("/"))
        .to_string_lossy()
        .to_string();

    args.extend([
        "--symlink".to_string(),
        "/usr/bin".to_string(),
        "/bin".to_string(),
        "--symlink".to_string(),
        "/usr/sbin".to_string(),
        "/sbin".to_string(),
        "--dev".to_string(),
        "/dev".to_string(),
        "--proc".to_string(),
        "/proc".to_string(),
        "--tmpfs".to_string(),
        "/tmp".to_string(),
        "--tmpfs".to_string(),
        "/run".to_string(),
        "--dir".to_string(),
        "/workspaces".to_string(),
        "--bind".to_string(),
        workspace_host.to_string(),
        workspace_sandbox.to_string(),
        "--dir".to_string(),
        home_parent,
        "--bind".to_string(),
        agent_home_host.to_string(),
        home_sandbox.to_string(),
        "--unshare-pid".to_string(),
        "--die-with-parent".to_string(),
        "--setenv".to_string(),
        "PATH".to_string(),
        "/usr/local/bin:/usr/bin:/bin".to_string(),
        "--setenv".to_string(),
        "HOME".to_string(),
        home_sandbox.to_string(),
        "--chdir".to_string(),
        workspace_sandbox.to_string(),
        "--".to_string(),
    ]);

    args
}

/// Test that the sandbox can run basic commands
#[test]
fn test_sandbox_basic_execution() {
    if !bwrap_available() {
        eprintln!("Skipping: bwrap not available");
        return;
    }

    let workspace_host = create_temp_dir("workspace");
    let agent_home_host = create_temp_dir("agent-home");

    let mut args = build_test_bwrap_args(
        workspace_host.to_str().unwrap(),
        "/workspaces/test",
        "/home/testuser",
        agent_home_host.to_str().unwrap(),
    );
    args.extend(["sh".to_string(), "-c".to_string(), "echo hello".to_string()]);

    let output = Command::new(&args[0])
        .args(&args[1..])
        .output()
        .expect("Failed to run bwrap");

    let _ = std::fs::remove_dir_all(&workspace_host);
    let _ = std::fs::remove_dir_all(&agent_home_host);

    assert!(output.status.success(), "bwrap failed: {:?}", output);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("hello"),
        "Expected 'hello' in output: {}",
        stdout
    );
}

/// Test that /run is empty (no host sockets visible)
#[test]
fn test_sandbox_run_is_empty() {
    if !bwrap_available() {
        eprintln!("Skipping: bwrap not available");
        return;
    }

    let workspace_host = create_temp_dir("workspace");
    let agent_home_host = create_temp_dir("agent-home");

    let mut args = build_test_bwrap_args(
        workspace_host.to_str().unwrap(),
        "/workspaces/test",
        "/home/testuser",
        agent_home_host.to_str().unwrap(),
    );
    args.extend([
        "sh".to_string(),
        "-c".to_string(),
        "ls -la /run | wc -l".to_string(),
    ]);

    let output = Command::new(&args[0])
        .args(&args[1..])
        .output()
        .expect("Failed to run bwrap");

    let _ = std::fs::remove_dir_all(&workspace_host);
    let _ = std::fs::remove_dir_all(&agent_home_host);

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let line_count: i32 = stdout.trim().parse().unwrap_or(100);
    assert!(
        line_count <= 5,
        "/run should be nearly empty, got {} lines",
        line_count
    );
}

/// Test that agent home is visible at $HOME
#[test]
fn test_sandbox_home_is_isolated() {
    if !bwrap_available() {
        eprintln!("Skipping: bwrap not available");
        return;
    }

    let workspace_host = create_temp_dir("workspace");
    let agent_home_host = create_temp_dir("agent-home");

    // Create a marker file in agent_home
    std::fs::write(agent_home_host.join("agent-marker"), "agent").unwrap();

    let mut args = build_test_bwrap_args(
        workspace_host.to_str().unwrap(),
        "/workspaces/test",
        "/home/testuser",
        agent_home_host.to_str().unwrap(),
    );
    args.extend([
        "sh".to_string(),
        "-c".to_string(),
        "cat $HOME/agent-marker 2>/dev/null && echo FOUND || echo NOTFOUND".to_string(),
    ]);

    let output = Command::new(&args[0])
        .args(&args[1..])
        .output()
        .expect("Failed to run bwrap");

    let _ = std::fs::remove_dir_all(&workspace_host);
    let _ = std::fs::remove_dir_all(&agent_home_host);

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("agent") && stdout.contains("FOUND"),
        "Agent home should be visible at $HOME: {}",
        stdout
    );
}

/// Test that workspace is writable
#[test]
fn test_sandbox_workspace_writable() {
    if !bwrap_available() {
        eprintln!("Skipping: bwrap not available");
        return;
    }

    let workspace_host = create_temp_dir("workspace");
    let agent_home_host = create_temp_dir("agent-home");
    let workspace_sandbox = "/workspaces/test";

    let mut args = build_test_bwrap_args(
        workspace_host.to_str().unwrap(),
        workspace_sandbox,
        "/home/testuser",
        agent_home_host.to_str().unwrap(),
    );
    args.extend([
        "sh".to_string(),
        "-c".to_string(),
        format!(
            "echo test > {}/test-write && cat {}/test-write",
            workspace_sandbox, workspace_sandbox
        ),
    ]);

    let output = Command::new(&args[0])
        .args(&args[1..])
        .output()
        .expect("Failed to run bwrap");

    let _ = std::fs::remove_dir_all(&workspace_host);
    let _ = std::fs::remove_dir_all(&agent_home_host);

    assert!(
        output.status.success(),
        "Write to workspace failed: {:?}",
        output
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("test"),
        "Expected written content: {}",
        stdout
    );
}

/// Test that /usr is read-only
#[test]
fn test_sandbox_usr_readonly() {
    if !bwrap_available() {
        eprintln!("Skipping: bwrap not available");
        return;
    }

    let workspace_host = create_temp_dir("workspace");
    let agent_home_host = create_temp_dir("agent-home");

    let mut args = build_test_bwrap_args(
        workspace_host.to_str().unwrap(),
        "/workspaces/test",
        "/home/testuser",
        agent_home_host.to_str().unwrap(),
    );
    args.extend([
        "sh".to_string(),
        "-c".to_string(),
        "touch /usr/test-file 2>&1 && echo WRITABLE || echo READONLY".to_string(),
    ]);

    let output = Command::new(&args[0])
        .args(&args[1..])
        .output()
        .expect("Failed to run bwrap");

    let _ = std::fs::remove_dir_all(&workspace_host);
    let _ = std::fs::remove_dir_all(&agent_home_host);

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("READONLY"),
        "/usr should be read-only: {}",
        stdout
    );
}

/// Test that /var is not visible (not mounted)
#[test]
fn test_sandbox_var_not_mounted() {
    if !bwrap_available() {
        eprintln!("Skipping: bwrap not available");
        return;
    }

    let workspace_host = create_temp_dir("workspace");
    let agent_home_host = create_temp_dir("agent-home");

    let mut args = build_test_bwrap_args(
        workspace_host.to_str().unwrap(),
        "/workspaces/test",
        "/home/testuser",
        agent_home_host.to_str().unwrap(),
    );
    args.extend([
        "sh".to_string(),
        "-c".to_string(),
        "test -d /var && echo EXISTS || echo NOTFOUND".to_string(),
    ]);

    let output = Command::new(&args[0])
        .args(&args[1..])
        .output()
        .expect("Failed to run bwrap");

    let _ = std::fs::remove_dir_all(&workspace_host);
    let _ = std::fs::remove_dir_all(&agent_home_host);

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("NOTFOUND"),
        "/var should not be mounted: {}",
        stdout
    );
}

/// Test with a mock agent script that simulates opencode behavior
#[test]
fn test_sandbox_mock_agent() {
    if !bwrap_available() {
        eprintln!("Skipping: bwrap not available");
        return;
    }

    let workspace_host = create_temp_dir("workspace");
    let agent_home_host = create_temp_dir("agent-home");
    let workspace_sandbox = "/workspaces/test";

    // Create a mock agent that:
    // 1. Writes a file to workspace
    // 2. Checks that ~/.ssh doesn't exist (fresh home)
    // 3. Checks it can read /etc/passwd
    let mock_script = r#"
echo "Mock agent starting"
echo "test content" > test-output.txt
if [ -d "$HOME/.ssh" ]; then
    echo "ERROR: .ssh visible"
    exit 1
fi
if [ ! -f /etc/passwd ]; then
    echo "ERROR: /etc/passwd not readable"
    exit 1
fi
echo "Mock agent completed successfully"
cat test-output.txt
"#;

    let _agent_path = create_mock_agent(&workspace_host, mock_script);

    let mut args = build_test_bwrap_args(
        workspace_host.to_str().unwrap(),
        workspace_sandbox,
        "/home/testuser",
        agent_home_host.to_str().unwrap(),
    );
    args.push(format!("{}/mock-agent", workspace_sandbox));

    let output = Command::new(&args[0])
        .args(&args[1..])
        .output()
        .expect("Failed to run bwrap with mock agent");

    let _ = std::fs::remove_dir_all(&workspace_host);
    let _ = std::fs::remove_dir_all(&agent_home_host);

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        output.status.success(),
        "Mock agent failed.\nstdout: {}\nstderr: {}",
        stdout,
        stderr
    );
    assert!(
        stdout.contains("Mock agent completed successfully"),
        "Agent didn't complete: {}",
        stdout
    );
    assert!(
        stdout.contains("test content"),
        "Agent output missing: {}",
        stdout
    );
}
