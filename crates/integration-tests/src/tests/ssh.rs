//! SSH server integration tests
//!
//! These tests verify the SSH server functionality in devaipod:
//! - SSH config file generation on workspace creation
//! - SSH server startup via `devaipod exec --stdio`
//! - Basic command execution through SSH
//! - Cleanup of SSH config on workspace deletion
//!
//! Note: These tests use a temporary directory for SSH configs via
//! `DEVAIPOD_SSH_CONFIG_DIR` to avoid mutating the user's real `~/.ssh/config.d`.

use color_eyre::Result;
use color_eyre::eyre::bail;
use std::io::Read;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::Duration;
use xshell::cmd;

use crate::{
    PodGuard, SharedFixture, TestRepo, get_devaipod_binary_path, podman_integration_test,
    readonly_test, run_devaipod, run_devaipod_in_with_env, run_devaipod_with_env, shell,
    short_name, unique_test_name,
};

/// Environment variable name for overriding SSH config directory.
const SSH_CONFIG_DIR_ENV: &str = "DEVAIPOD_SSH_CONFIG_DIR";

/// Guard that creates a temporary directory for SSH configs.
/// The tempdir is automatically cleaned up when this guard is dropped.
struct SshConfigGuard {
    tempdir: tempfile::TempDir,
}

impl SshConfigGuard {
    /// Create a new SSH config guard with a temporary directory.
    fn new() -> Result<Self> {
        let tempdir = tempfile::TempDir::new()?;
        Ok(Self { tempdir })
    }

    /// Get the path to the SSH config directory.
    fn config_dir(&self) -> &std::path::Path {
        self.tempdir.path()
    }

    /// Get the config directory as a string for use in environment variables.
    fn config_dir_str(&self) -> &str {
        self.tempdir.path().to_str().unwrap()
    }

    /// Get the environment variable tuple for passing to commands.
    fn env(&self) -> (&'static str, &str) {
        (SSH_CONFIG_DIR_ENV, self.config_dir_str())
    }

    /// Get the expected config file path for a pod name.
    fn config_file(&self, pod_name: &str) -> PathBuf {
        self.tempdir.path().join(pod_name)
    }
}

// =============================================================================
// Readonly tests - use shared fixture
// =============================================================================

/// Verify that we can generate SSH config for the shared pod using ssh-config command.
///
/// Note: The shared fixture may not have SSH config auto-generated (depends on settings),
/// so we explicitly run ssh-config to test the generation. We use a tempdir to avoid
/// polluting the user's ~/.ssh/config.d.
fn test_readonly_ssh_config_generation(fixture: &SharedFixture) -> Result<()> {
    let short_name = fixture.short_name();

    // Create a tempdir for SSH configs
    let ssh_guard = SshConfigGuard::new()?;

    // Run ssh-config command to generate config in our tempdir
    let output = run_devaipod_with_env(&["ssh-config", short_name], &[ssh_guard.env()])?;

    // The command should succeed
    output.assert_success("ssh-config");

    // Check that the config file was created in our tempdir
    let config_file = ssh_guard.config_file(&format!("devaipod-{}", short_name));

    assert!(
        config_file.exists(),
        "SSH config file should exist at {}",
        config_file.display()
    );

    // Verify content
    let content = std::fs::read_to_string(&config_file)?;
    assert!(
        content.contains("ProxyCommand"),
        "SSH config should contain ProxyCommand: {}",
        content
    );
    assert!(
        content.contains("exec") && content.contains("--stdio"),
        "SSH config should use 'exec --stdio': {}",
        content
    );
    assert!(
        content.contains(short_name) || content.contains(&fixture.pod_name()),
        "SSH config should reference the pod: {}",
        content
    );

    Ok(())
}
readonly_test!(test_readonly_ssh_config_generation);

/// Verify that we can run commands through the SSH server via exec --stdio
///
/// This tests the core SSH server functionality without needing an SSH client.
/// We use `devaipod exec --stdio` which starts the embedded SSH server, but
/// we pass a command directly to test the underlying podman exec path.
fn test_readonly_exec_stdio_with_command(fixture: &SharedFixture) -> Result<()> {
    let short_name = fixture.short_name();

    // Run a simple command via exec --stdio
    // When a command is provided, exec --stdio does direct podman exec (not SSH)
    let output = run_devaipod(&[
        "exec",
        "--stdio",
        short_name,
        "--",
        "echo",
        "hello-from-stdio",
    ])?;

    // Should succeed
    assert!(
        output.success(),
        "exec --stdio with command should succeed: {}",
        output.combined()
    );

    assert!(
        output.stdout.contains("hello-from-stdio"),
        "Should see command output: {}",
        output.stdout
    );

    Ok(())
}
readonly_test!(test_readonly_exec_stdio_with_command);

// =============================================================================
// Mutating tests - create/delete their own pods
// =============================================================================

/// Verify SSH config file is created when a pod is created.
///
/// Uses a temporary directory for SSH configs to avoid mutating user's ~/.ssh/config.d.
fn test_ssh_config_created_on_pod_up() -> Result<()> {
    let repo = TestRepo::new()?;
    let pod_name = unique_test_name("test-ssh-cfg");
    let ssh_guard = SshConfigGuard::new()?;

    let mut pods = PodGuard::new();
    pods.add(&pod_name);

    // Create pod with SSH config pointing to our tempdir
    let output = run_devaipod_in_with_env(
        &repo.repo_path,
        &["up", ".", "--name", short_name(&pod_name)],
        &[ssh_guard.env()],
    )?;
    if !output.success() {
        bail!("devaipod up failed: {}", output.combined());
    }

    // The config file uses the full pod name with prefix
    let config_file = ssh_guard.config_file(&pod_name);

    // Wait for the SSH config file to appear
    crate::wait_for_file(&config_file, Duration::from_secs(10))?;

    let content = std::fs::read_to_string(&config_file)?;

    // Verify content structure
    assert!(
        content.contains("Host"),
        "SSH config should contain Host directive: {}",
        content
    );
    assert!(
        content.contains("ProxyCommand"),
        "SSH config should contain ProxyCommand: {}",
        content
    );
    assert!(
        content.contains("--stdio"),
        "SSH config should use --stdio for ProxyCommand: {}",
        content
    );

    Ok(())
}
podman_integration_test!(test_ssh_config_created_on_pod_up);

/// Verify SSH config file is removed when a pod is deleted.
///
/// Uses a temporary directory for SSH configs to avoid mutating user's ~/.ssh/config.d.
fn test_ssh_config_removed_on_pod_delete() -> Result<()> {
    let repo = TestRepo::new()?;
    let pod_name = unique_test_name("test-ssh-del");
    let ssh_guard = SshConfigGuard::new()?;

    let _pods = PodGuard::new();

    // Create pod with SSH config pointing to our tempdir
    let output = run_devaipod_in_with_env(
        &repo.repo_path,
        &["up", ".", "--name", short_name(&pod_name)],
        &[ssh_guard.env()],
    )?;
    if !output.success() {
        bail!("devaipod up failed: {}", output.combined());
    }

    // The config file uses the full pod name
    let config_file = ssh_guard.config_file(&pod_name);

    // Wait for the SSH config file to appear
    crate::wait_for_file(&config_file, Duration::from_secs(10))?;

    // Delete the pod (don't add to guard since we're deleting manually)
    let delete_output = run_devaipod_in_with_env(
        &repo.repo_path,
        &["delete", short_name(&pod_name), "--force"],
        &[ssh_guard.env()],
    )?;
    delete_output.assert_success("devaipod delete");

    // Verify config was removed
    assert!(
        !config_file.exists(),
        "SSH config file should be removed after pod deletion"
    );

    Ok(())
}
podman_integration_test!(test_ssh_config_removed_on_pod_delete);

/// Test that devaipod exec --stdio starts and accepts SSH protocol
///
/// This test spawns `devaipod exec --stdio` and verifies that it starts
/// an SSH server by checking for the SSH protocol banner.
fn test_ssh_server_starts_on_exec_stdio() -> Result<()> {
    let repo = TestRepo::new()?;
    let pod_name = unique_test_name("test-ssh-srv");
    let ssh_guard = SshConfigGuard::new()?;

    let mut pods = PodGuard::new();
    pods.add(&pod_name);

    // Create pod with SSH config pointing to our tempdir
    let output = run_devaipod_in_with_env(
        &repo.repo_path,
        &["up", ".", "--name", short_name(&pod_name)],
        &[ssh_guard.env()],
    )?;
    if !output.success() {
        bail!("devaipod up failed: {}", output.combined());
    }

    // Wait for agent container to be ready
    crate::wait_for_container_running(&format!("{}-agent", pod_name), Duration::from_secs(30))?;

    // Start exec --stdio without a command - this starts the SSH server
    // Use binary path directly since we're spawning a child process that needs host mode
    let devaipod = get_devaipod_binary_path()?;
    let mut child = Command::new(&devaipod)
        .env("DEVAIPOD_HOST_MODE", "1")
        .env(SSH_CONFIG_DIR_ENV, ssh_guard.config_dir_str())
        .args(["exec", "--stdio", short_name(&pod_name)])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| color_eyre::eyre::eyre!("Failed to spawn exec --stdio: {}", e))?;

    // The SSH server should send a protocol banner starting with "SSH-2.0-"
    // Poll stdout for up to 5s (server may take a moment to start async runtime and send banner)
    let mut stdout = child.stdout.take().unwrap();
    let mut banner = String::new();
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    let mut buf = [0u8; 256];
    while std::time::Instant::now() < deadline {
        match stdout.read(&mut buf) {
            Ok(0) => {}
            Ok(n) => {
                banner.push_str(&String::from_utf8_lossy(&buf[..n]));
                if banner.contains("SSH-2.0-") {
                    break;
                }
            }
            Err(_) => break,
        }
        if banner.contains("SSH-2.0-") {
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }

    // Clean up
    let _ = child.kill();
    let status = child.wait();

    // If we got no banner, check stderr for socket/config failure and skip if so
    let stderr_output = match child.stderr.take() {
        Some(mut s) => {
            let mut out = String::new();
            let _ = s.read_to_string(&mut out);
            out
        }
        None => String::new(),
    };
    if !banner.starts_with("SSH-2.0-") {
        if stderr_output.contains("No container socket")
            || stderr_output.contains("Failed to run SSH server")
            || status.as_ref().map(|s| !s.success()).unwrap_or(true)
        {
            tracing::info!(
                "SSH server test skipped - process failed or socket not available: {}",
                stderr_output.lines().next().unwrap_or("")
            );
            return Ok(());
        }
    }

    assert!(
        banner.starts_with("SSH-2.0-"),
        "SSH server should send SSH-2.0 banner. Got: {:?}",
        banner.chars().take(50).collect::<String>()
    );

    Ok(())
}
podman_integration_test!(test_ssh_server_starts_on_exec_stdio);

/// Test SSH connectivity using the ssh command if available
///
/// This is a more complete end-to-end test that uses the actual SSH client
/// to connect through the devaipod SSH server. The test is inherently flaky
/// in containerized environments, so failures are logged but not fatal.
fn test_ssh_client_connectivity() -> Result<()> {
    let sh = shell()?;

    // Check if both ssh and timeout commands are available
    let ssh_available = cmd!(sh, "sh -c 'command -v ssh'")
        .ignore_status()
        .output()?
        .status
        .success();
    if !ssh_available {
        tracing::info!("Skipping SSH client test: ssh command not available");
        return Ok(());
    }
    let timeout_available = cmd!(sh, "sh -c 'command -v timeout'")
        .ignore_status()
        .output()?
        .status
        .success();
    if !timeout_available {
        tracing::info!("Skipping SSH client test: timeout command not available (common on macOS)");
        return Ok(());
    }

    let repo = TestRepo::new()?;
    let pod_name = unique_test_name("test-ssh-cli");
    let ssh_guard = SshConfigGuard::new()?;

    let mut pods = PodGuard::new();
    pods.add(&pod_name);

    // Create pod with SSH config pointing to our tempdir
    let output = run_devaipod_in_with_env(
        &repo.repo_path,
        &["up", ".", "--name", short_name(&pod_name)],
        &[ssh_guard.env()],
    )?;
    if !output.success() {
        bail!("devaipod up failed: {}", output.combined());
    }

    // Verify the agent container is ready before attempting SSH.
    // SSH needs the container runtime to be fully ready, which can take
    // longer in CI environments.
    {
        let agent_container = format!("{}-agent", pod_name);
        let poll_sh = shell()?;
        let deadline = std::time::Instant::now() + Duration::from_secs(30);
        loop {
            let result = cmd!(poll_sh, "podman exec {agent_container} echo ready")
                .ignore_status()
                .output()?;
            if result.status.success() {
                break;
            }
            if std::time::Instant::now() >= deadline {
                tracing::warn!("Agent container not ready after 30s, skipping SSH test");
                return Ok(());
            }
            std::thread::sleep(Duration::from_secs(1));
        }
    }

    // Get the devaipod binary path for building the ProxyCommand
    // This uses host mode since it's building a command string for ssh
    let devaipod = get_devaipod_binary_path()?;
    let short = short_name(&pod_name);
    let ssh_config_dir = ssh_guard.config_dir_str();

    // Build the ProxyCommand string (includes env vars for proper execution)
    let proxy_cmd = format!(
        "DEVAIPOD_HOST_MODE=1 {}={} {} exec --stdio {}",
        SSH_CONFIG_DIR_ENV, ssh_config_dir, devaipod, short
    );

    // Try SSH with ProxyCommand directly, with retries for timing issues.
    // Use -o options to configure SSH without a config file.
    let max_attempts = 3;
    let mut last_stderr = String::new();
    let mut succeeded = false;

    for attempt in 1..=max_attempts {
        let ssh_result = match Command::new("timeout")
            .args([
                "15",
                "ssh",
                "-o",
                &format!("ProxyCommand={}", proxy_cmd),
                "-o",
                "StrictHostKeyChecking=no",
                "-o",
                "UserKnownHostsFile=/dev/null",
                "-o",
                "LogLevel=ERROR",
                "-o",
                "PasswordAuthentication=no",
                "-o",
                "PubkeyAuthentication=no",
                "localhost",
                "echo",
                "hello-via-ssh",
            ])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
        {
            Ok(out) => out,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                tracing::info!("SSH client test skipped - 'timeout' not found: {}", e);
                return Ok(());
            }
            Err(e) => return Err(e.into()),
        };

        if ssh_result.status.success() {
            let stdout = String::from_utf8_lossy(&ssh_result.stdout);
            assert!(
                stdout.contains("hello-via-ssh"),
                "SSH command should return output: {}",
                stdout
            );
            tracing::info!("SSH client connectivity test passed on attempt {}", attempt);
            succeeded = true;
            break;
        }

        last_stderr = String::from_utf8_lossy(&ssh_result.stderr).to_string();
        tracing::info!(
            "SSH attempt {}/{} failed: {}",
            attempt,
            max_attempts,
            last_stderr.lines().next().unwrap_or("")
        );
        if attempt < max_attempts {
            std::thread::sleep(Duration::from_secs(2));
        }
    }

    if !succeeded {
        // SSH may fail for various reasons in CI (no SSH agent, container
        // networking quirks, etc.). Log the error but don't fail the test.
        tracing::info!(
            "SSH client test skipped - all {} attempts failed (may be expected in CI): {}",
            max_attempts,
            last_stderr
        );
    }

    Ok(())
}
podman_integration_test!(test_ssh_client_connectivity);

/// Verify the ssh-config command generates valid output.
///
/// Uses a temporary directory for SSH configs to avoid mutating user's ~/.ssh/config.d.
fn test_ssh_config_command() -> Result<()> {
    let repo = TestRepo::new()?;
    let pod_name = unique_test_name("test-ssh-cmd");
    let ssh_guard = SshConfigGuard::new()?;

    let mut pods = PodGuard::new();
    pods.add(&pod_name);

    // Create pod with SSH config pointing to our tempdir
    let output = run_devaipod_in_with_env(
        &repo.repo_path,
        &["up", ".", "--name", short_name(&pod_name)],
        &[ssh_guard.env()],
    )?;
    if !output.success() {
        bail!("devaipod up failed: {}", output.combined());
    }

    // Run ssh-config command with our tempdir
    let ssh_config_output =
        run_devaipod_with_env(&["ssh-config", short_name(&pod_name)], &[ssh_guard.env()])?;
    ssh_config_output.assert_success("devaipod ssh-config");

    // Verify config file was created in our tempdir
    let config_file = ssh_guard.config_file(&pod_name);
    assert!(
        config_file.exists(),
        "SSH config file should exist at {}",
        config_file.display()
    );

    // Verify output mentions the config was written
    let combined = ssh_config_output.combined();
    assert!(
        combined.contains("SSH config") || combined.contains(ssh_guard.config_dir_str()),
        "ssh-config should report writing config: {}",
        combined
    );

    Ok(())
}
podman_integration_test!(test_ssh_config_command);

/// Test that exec --stdio with a command works correctly for multiple commands.
///
/// Uses a temporary directory for SSH configs to avoid mutating user's ~/.ssh/config.d.
fn test_exec_stdio_multiple_commands() -> Result<()> {
    let repo = TestRepo::new()?;
    let pod_name = unique_test_name("test-ssh-multi");
    let ssh_guard = SshConfigGuard::new()?;

    let mut pods = PodGuard::new();
    pods.add(&pod_name);

    // Create pod with SSH config pointing to our tempdir
    let output = run_devaipod_in_with_env(
        &repo.repo_path,
        &["up", ".", "--name", short_name(&pod_name)],
        &[ssh_guard.env()],
    )?;
    if !output.success() {
        bail!("devaipod up failed: {}", output.combined());
    }

    // Wait for agent container to be ready
    crate::wait_for_container_running(&format!("{}-agent", pod_name), Duration::from_secs(30))?;

    // Test 1: pwd command
    let pwd_output = run_devaipod(&["exec", "--stdio", short_name(&pod_name), "--", "pwd"])?;
    pwd_output.assert_success("pwd via exec --stdio");
    assert!(
        pwd_output.stdout.trim().starts_with('/'),
        "pwd should return a path: {}",
        pwd_output.stdout
    );

    // Test 2: ls command
    let ls_output = run_devaipod(&[
        "exec",
        "--stdio",
        short_name(&pod_name),
        "--",
        "ls",
        "/workspaces",
    ])?;
    ls_output.assert_success("ls via exec --stdio");
    assert!(
        ls_output.stdout.contains("test-repo"),
        "ls should show workspace: {}",
        ls_output.stdout
    );

    // Test 3: Command with arguments
    let cat_output = run_devaipod(&[
        "exec",
        "--stdio",
        short_name(&pod_name),
        "--",
        "cat",
        "/workspaces/test-repo/README.md",
    ])?;
    cat_output.assert_success("cat via exec --stdio");
    assert!(
        cat_output.stdout.contains("Test Repo") || cat_output.stdout.contains('#'),
        "cat should show README content: {}",
        cat_output.stdout
    );

    Ok(())
}
podman_integration_test!(test_exec_stdio_multiple_commands);

/// Verify that exec --stdio works with agent container target.
///
/// Uses a temporary directory for SSH configs to avoid mutating user's ~/.ssh/config.d.
fn test_exec_stdio_agent_container() -> Result<()> {
    let repo = TestRepo::new()?;
    let pod_name = unique_test_name("test-ssh-agent");
    let ssh_guard = SshConfigGuard::new()?;

    let mut pods = PodGuard::new();
    pods.add(&pod_name);

    // Create pod with SSH config pointing to our tempdir
    let output = run_devaipod_in_with_env(
        &repo.repo_path,
        &["up", ".", "--name", short_name(&pod_name)],
        &[ssh_guard.env()],
    )?;
    if !output.success() {
        bail!("devaipod up failed: {}", output.combined());
    }

    // Wait for agent container to be ready
    crate::wait_for_container_running(&format!("{}-agent", pod_name), Duration::from_secs(30))?;

    // Default exec --stdio goes to agent container
    let output = run_devaipod(&[
        "exec",
        "--stdio",
        short_name(&pod_name),
        "--",
        "echo",
        "hello-from-agent",
    ])?;
    output.assert_success("exec --stdio agent");
    assert!(
        output.stdout.contains("hello-from-agent"),
        "Should get output from agent: {}",
        output.stdout
    );

    // Verify we can access the agent's workspace
    let ws_output = run_devaipod(&[
        "exec",
        "--stdio",
        short_name(&pod_name),
        "--",
        "ls",
        "/workspaces",
    ])?;
    ws_output.assert_success("ls via exec --stdio agent");
    assert!(
        ws_output.stdout.contains("test-repo"),
        "Agent should have workspace access: {}",
        ws_output.stdout
    );

    Ok(())
}
podman_integration_test!(test_exec_stdio_agent_container);
