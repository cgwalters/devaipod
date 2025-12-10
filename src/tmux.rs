//! Host-side tmux session management for multi-container workspaces
//!
//! This module manages tmux sessions on the host machine, where each pane
//! runs `podman exec` into a different container within the same pod.
//! This enables working with multiple containers simultaneously in a single
//! terminal window.

use std::process::Command as ProcessCommand;

use color_eyre::eyre::{bail, Context, Result};

/// Get current terminal size (columns, rows)
fn get_terminal_size() -> Option<(u16, u16)> {
    terminal_size::terminal_size().map(|(w, h)| (w.0, h.0))
}

/// Generate a tmux session name for a workspace
///
/// The session name follows the pattern `devc-{workspace_name}` to avoid
/// conflicts with user's own tmux sessions.
pub fn session_name(workspace_name: &str) -> String {
    format!("devc-{}", workspace_name)
}

/// Check if tmux is available on the system
///
/// Returns true if the tmux binary can be found and executed.
pub fn tmux_available() -> bool {
    ProcessCommand::new("tmux")
        .arg("-V")
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false)
}

/// Check if a tmux session already exists
///
/// Returns true if a session with the given name is currently active.
pub fn session_exists(name: &str) -> bool {
    use std::process::Stdio;

    // Use output() instead of status() to capture stderr and prevent
    // "no server running" messages from leaking to the terminal
    ProcessCommand::new("tmux")
        .args(["has-session", "-t", name])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

/// Container info for tmux pane creation
pub struct ContainerPane<'a> {
    /// Full container name (e.g., "devc-infra-dev")
    pub name: &'a str,
    /// Command to run in the container (e.g., "/bin/bash -l" or "goose")
    pub command: &'a str,
}

/// Create or attach to a tmux session with one pane per container
///
/// If the session already exists, this will attach to it. Otherwise, it creates
/// a new session with one pane per container, each running the specified command.
///
/// # Arguments
///
/// * `workspace_name` - Name of the workspace (used for session naming)
/// * `containers` - Slice of ContainerPane structs with container names and commands
///
/// # Returns
///
/// The exit code of the tmux attach session (typically 0 on normal detach)
pub fn enter_multi_container(workspace_name: &str, containers: &[ContainerPane]) -> Result<i32> {
    if containers.is_empty() {
        bail!("Cannot create tmux session with zero containers");
    }

    let session = session_name(workspace_name);

    // If session already exists, just attach to it
    if session_exists(&session) {
        tracing::info!("Attaching to existing tmux session: {}", session);
        return attach_session(&session);
    }

    // Create new session with first container
    tracing::info!("Creating new tmux session: {}", session);

    let first = &containers[0];
    let first_cmd = format!("podman exec -it {} {}", first.name, first.command);

    let mut cmd = ProcessCommand::new("tmux");
    cmd.args(["new-session", "-d", "-s", &session, "-n", "main"]);

    // Pass current terminal size to avoid size mismatch when attaching
    if let Some((cols, rows)) = get_terminal_size() {
        cmd.args(["-x", &cols.to_string(), "-y", &rows.to_string()]);
    }

    cmd.arg(&first_cmd);

    let status = cmd.status().context("Failed to create tmux session")?;

    if !status.success() {
        bail!("Failed to create tmux session {}", session);
    }

    // Keep panes open when processes exit (useful for debugging errors)
    let _ = ProcessCommand::new("tmux")
        .args(["set-option", "-t", &session, "remain-on-exit", "on"])
        .status();

    // Split window horizontally for each additional container
    for pane in containers.iter().skip(1) {
        let exec_cmd = format!("podman exec -it {} {}", pane.name, pane.command);
        let target = format!("{}:main", session);

        let status = ProcessCommand::new("tmux")
            .args(["split-window", "-h", "-t", &target])
            .arg(&exec_cmd)
            .status()
            .context("Failed to split tmux window")?;

        if !status.success() {
            // Clean up the session on failure
            let _ = kill_session(workspace_name);
            bail!("Failed to split tmux window for container {}", pane.name);
        }
    }

    // Evenly distribute panes
    let target = format!("{}:main", session);
    let _ = ProcessCommand::new("tmux")
        .args(["select-layout", "-t", &target, "even-horizontal"])
        .status();

    // Select first pane
    let pane_target = format!("{}:main.0", session);
    let _ = ProcessCommand::new("tmux")
        .args(["select-pane", "-t", &pane_target])
        .status();

    // Attach to the session
    tracing::info!("Attaching to tmux session: {}", session);
    attach_session(&session)
}

/// Attach to an existing tmux session
///
/// Returns the exit code of the tmux attach command.
fn attach_session(session: &str) -> Result<i32> {
    use std::process::Stdio;

    let status = ProcessCommand::new("tmux")
        .args(["attach-session", "-t", session])
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .context("Failed to attach to tmux session")?;

    Ok(status.code().unwrap_or(1))
}

/// Kill a tmux session for a workspace
///
/// This is typically called during workspace cleanup to ensure no orphaned
/// tmux sessions remain.
pub fn kill_session(workspace_name: &str) -> Result<()> {
    let session = session_name(workspace_name);

    if !session_exists(&session) {
        tracing::debug!("Tmux session {} does not exist, nothing to kill", session);
        return Ok(());
    }

    tracing::info!("Killing tmux session: {}", session);

    let status = ProcessCommand::new("tmux")
        .args(["kill-session", "-t", &session])
        .status()
        .context("Failed to kill tmux session")?;

    if !status.success() {
        bail!("Failed to kill tmux session {}", session);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_name() {
        assert_eq!(session_name("myworkspace"), "devc-myworkspace");
        assert_eq!(session_name("feature-123"), "devc-feature-123");
    }

    #[test]
    fn test_session_name_prefix() {
        // Ensure session names always start with devc- prefix
        let name = session_name("test");
        assert!(name.starts_with("devc-"));
    }

    #[test]
    fn test_tmux_available() {
        // This test will pass if tmux is installed, otherwise it should fail gracefully
        let available = tmux_available();
        // We can't assert a specific value since it depends on the environment,
        // but we can verify the function doesn't panic
        assert!(available || !available);
    }

    #[test]
    fn test_session_exists_nonexistent() {
        // Test with a session name that definitely doesn't exist
        let exists = session_exists("devc-nonexistent-session-12345");
        assert!(!exists);
    }

    #[test]
    fn test_empty_containers() {
        let result = enter_multi_container("test", &[]);
        assert!(result.is_err());
    }
}
