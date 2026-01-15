//! State management for the devaipod upcall system.
//!
//! This module tracks which GitHub repos and PRs the agent is allowed to write to.
//! The state is persisted as JSON and can be modified via JSON-RPC upcalls from the
//! sandboxed agent.
//!
//! State is stored in:
//! - `$XDG_RUNTIME_DIR/devaipod/<workspace>/` (preferred, per-session)
//! - `$HOME/.local/state/devaipod/<workspace>/` (fallback, persistent)

use std::collections::HashSet;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use color_eyre::eyre::{bail, Context, Result};
use serde::{Deserialize, Serialize};

/// Legacy path to the state file (for backwards compatibility)
pub const STATE_FILE_PATH: &str = "/run/devaipod/state.json";

/// Get the runtime directory for devaipod state.
///
/// Uses XDG_RUNTIME_DIR if available (typically /run/user/UID),
/// falls back to $HOME/.local/state/devaipod/.
///
/// Returns the base directory (not workspace-specific).
pub fn get_runtime_dir() -> PathBuf {
    if let Ok(xdg_runtime) = std::env::var("XDG_RUNTIME_DIR") {
        PathBuf::from(xdg_runtime).join("devaipod")
    } else {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
        PathBuf::from(home).join(".local/state/devaipod")
    }
}

/// Get the workspace-specific state directory.
///
/// Creates the directory if it doesn't exist.
pub fn get_workspace_state_dir(workspace: &str) -> Result<PathBuf> {
    let dir = get_runtime_dir().join(workspace);
    fs::create_dir_all(&dir).with_context(|| {
        format!(
            "Failed to create workspace state directory: {}",
            dir.display()
        )
    })?;
    Ok(dir)
}

/// Get the socket path for a workspace.
pub fn get_socket_path(workspace: &str) -> Result<PathBuf> {
    Ok(get_workspace_state_dir(workspace)?.join("socket"))
}

/// Get the PID file path for the upcall listener daemon.
pub fn get_pid_path(workspace: &str) -> Result<PathBuf> {
    Ok(get_workspace_state_dir(workspace)?.join("listener.pid"))
}

/// Get the state file path for a workspace.
#[allow(dead_code)]
pub fn get_state_path(workspace: &str) -> Result<PathBuf> {
    Ok(get_workspace_state_dir(workspace)?.join("state.json"))
}

/// Check if a process with the given PID is still running.
fn is_process_alive(pid: u32) -> bool {
    // Check if /proc/<pid> exists - this is the standard Linux way
    Path::new(&format!("/proc/{}", pid)).exists()
}

/// Result of checking for an existing listener daemon.
#[derive(Debug)]
pub enum ListenerStatus {
    /// No listener is running (no PID file or stale PID)
    NotRunning,
    /// A listener is running with this PID and socket path
    Running { pid: u32, socket_path: PathBuf },
}

/// Check if a listener daemon is already running for this workspace.
///
/// Returns the PID and socket path if running, or NotRunning if not.
/// Cleans up stale PID files automatically.
pub fn check_listener_status(workspace: &str) -> Result<ListenerStatus> {
    let pid_path = get_pid_path(workspace)?;

    if !pid_path.exists() {
        return Ok(ListenerStatus::NotRunning);
    }

    // Read the PID file
    let pid_contents = match fs::read_to_string(&pid_path) {
        Ok(c) => c,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Ok(ListenerStatus::NotRunning);
        }
        Err(e) => {
            return Err(e)
                .with_context(|| format!("Failed to read PID file: {}", pid_path.display()));
        }
    };

    let pid: u32 = match pid_contents.trim().parse() {
        Ok(p) => p,
        Err(_) => {
            // Invalid PID file, clean it up
            tracing::warn!(
                "Invalid PID file contents, removing: {}",
                pid_path.display()
            );
            let _ = fs::remove_file(&pid_path);
            return Ok(ListenerStatus::NotRunning);
        }
    };

    // Check if the process is still alive
    if is_process_alive(pid) {
        let socket_path = get_socket_path(workspace)?;
        if socket_path.exists() {
            return Ok(ListenerStatus::Running { pid, socket_path });
        } else {
            // Process is running but socket doesn't exist - something is wrong
            // This could happen if the socket was manually deleted. We'll consider
            // the listener as not properly running and let the caller decide.
            tracing::warn!(
                "Listener process {} is running but socket doesn't exist at {}",
                pid,
                socket_path.display()
            );
            // Don't try to kill - just report as not running so a new one starts
            let _ = fs::remove_file(&pid_path);
            return Ok(ListenerStatus::NotRunning);
        }
    }

    // Process is dead, clean up stale PID file and socket
    tracing::debug!(
        "Cleaning up stale listener files for workspace: {}",
        workspace
    );
    let _ = fs::remove_file(&pid_path);
    let socket_path = get_socket_path(workspace)?;
    let _ = fs::remove_file(&socket_path);

    Ok(ListenerStatus::NotRunning)
}

/// Write the current process's PID to the PID file.
pub fn write_pid_file(workspace: &str) -> Result<()> {
    let pid_path = get_pid_path(workspace)?;
    let pid = std::process::id();

    fs::write(&pid_path, format!("{}", pid))
        .with_context(|| format!("Failed to write PID file: {}", pid_path.display()))?;

    tracing::debug!("Wrote PID {} to {}", pid, pid_path.display());
    Ok(())
}

/// Remove the PID file for a workspace.
pub fn remove_pid_file(workspace: &str) -> Result<()> {
    let pid_path = get_pid_path(workspace)?;
    if pid_path.exists() {
        fs::remove_file(&pid_path)
            .with_context(|| format!("Failed to remove PID file: {}", pid_path.display()))?;
    }
    Ok(())
}

/// State tracking allowed repositories and PRs for the agent.
#[derive(Debug, Default, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct State {
    /// Repositories the agent is allowed to write to (format: "owner/repo")
    pub allowed_repos: HashSet<String>,
    /// PRs the agent has created (URLs) - automatically allowed for updates
    pub allowed_prs: HashSet<String>,
}

/// Load state from the state file.
///
/// Returns the default (empty) state if the file doesn't exist.
pub fn load_state() -> Result<State> {
    let path = Path::new(STATE_FILE_PATH);

    if !path.exists() {
        return Ok(State::default());
    }

    let contents = fs::read_to_string(path)
        .with_context(|| format!("Failed to read state file: {}", path.display()))?;

    serde_json::from_str(&contents)
        .with_context(|| format!("Failed to parse state file: {}", path.display()))
}

/// Save state to the state file atomically.
///
/// Writes to a temporary file first, then renames to ensure atomic updates.
pub fn save_state(state: &State) -> Result<()> {
    let path = Path::new(STATE_FILE_PATH);

    // Ensure parent directory exists
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("Failed to create state directory: {}", parent.display()))?;
    }

    // Write to temporary file first
    let tmp_path = format!("{}.tmp.{}", STATE_FILE_PATH, std::process::id());
    let contents = serde_json::to_string_pretty(state).context("Failed to serialize state")?;

    {
        let mut file = fs::File::create(&tmp_path)
            .with_context(|| format!("Failed to create temp state file: {}", tmp_path))?;
        file.write_all(contents.as_bytes())
            .with_context(|| format!("Failed to write temp state file: {}", tmp_path))?;
        file.sync_all()
            .with_context(|| format!("Failed to sync temp state file: {}", tmp_path))?;
    }

    // Atomic rename
    fs::rename(&tmp_path, path).with_context(|| {
        format!(
            "Failed to rename temp state file {} to {}",
            tmp_path,
            path.display()
        )
    })?;

    Ok(())
}

/// Validate repository format ("owner/repo").
fn validate_repo_format(repo: &str) -> Result<()> {
    let parts: Vec<&str> = repo.split('/').collect();

    if parts.len() != 2 {
        bail!(
            "Invalid repository format: '{}'. Expected 'owner/repo'",
            repo
        );
    }

    let owner = parts[0];
    let repo_name = parts[1];

    if owner.is_empty() || repo_name.is_empty() {
        bail!(
            "Invalid repository format: '{}'. Owner and repo name cannot be empty",
            repo
        );
    }

    // Basic validation: no special characters that would be invalid
    for part in &[owner, repo_name] {
        if part.contains(|c: char| c.is_whitespace() || c == '/' || c == '\\') {
            bail!(
                "Invalid repository format: '{}'. Contains invalid characters",
                repo
            );
        }
    }

    Ok(())
}

/// Validate GitHub PR URL format.
///
/// Expected format: `https://github.com/owner/repo/pull/123`
fn validate_pr_url_format(pr_url: &str) -> Result<()> {
    let parsed = url::Url::parse(pr_url).context("Invalid URL")?;

    if parsed.scheme() != "https" {
        bail!("PR URL must use https scheme: {}", pr_url);
    }

    if parsed.host_str() != Some("github.com") {
        bail!("PR URL must be on github.com: {}", pr_url);
    }

    let path_segments: Vec<&str> = parsed
        .path_segments()
        .map(|s| s.collect())
        .unwrap_or_default();

    // Expected: owner/repo/pull/123
    if path_segments.len() != 4 {
        bail!(
            "Invalid GitHub PR URL format: '{}'. Expected: https://github.com/owner/repo/pull/123",
            pr_url
        );
    }

    if path_segments[2] != "pull" {
        bail!(
            "Invalid GitHub PR URL format: '{}'. Expected 'pull' in path, got '{}'",
            pr_url,
            path_segments[2]
        );
    }

    // Validate PR number is numeric
    let _pr_number: u64 = path_segments[3]
        .parse()
        .with_context(|| format!("Invalid PR number in URL: {}", pr_url))?;

    Ok(())
}

/// Add a repository to the allowed list.
///
/// Validates the format is "owner/repo" before adding.
pub fn add_repo(repo: &str) -> Result<()> {
    validate_repo_format(repo)?;

    let mut state = load_state()?;
    state.allowed_repos.insert(repo.to_string());
    save_state(&state)?;

    tracing::info!("Added repository to allowed list: {}", repo);
    Ok(())
}

/// Remove a repository from the allowed list.
pub fn remove_repo(repo: &str) -> Result<()> {
    let mut state = load_state()?;
    state.allowed_repos.remove(repo);
    save_state(&state)?;

    tracing::info!("Removed repository from allowed list: {}", repo);
    Ok(())
}

/// Add a PR URL to the allowed list.
///
/// Validates the URL format before adding.
pub fn add_pr(pr_url: &str) -> Result<()> {
    validate_pr_url_format(pr_url)?;

    let mut state = load_state()?;
    state.allowed_prs.insert(pr_url.to_string());
    save_state(&state)?;

    tracing::info!("Added PR to allowed list: {}", pr_url);
    Ok(())
}

/// Check if a repository is in the allowed list.
/// Used by gh-restricted upcall binary.
#[allow(dead_code)]
pub fn is_repo_allowed(repo: &str) -> bool {
    load_state()
        .map(|state| state.allowed_repos.contains(repo))
        .unwrap_or(false)
}

/// Check if a PR URL is in the allowed list.
/// Used by gh-restricted upcall binary.
#[allow(dead_code)]
pub fn is_pr_allowed(pr_url: &str) -> bool {
    load_state()
        .map(|state| state.allowed_prs.contains(pr_url))
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_repo_format_valid() {
        assert!(validate_repo_format("owner/repo").is_ok());
        assert!(validate_repo_format("my-org/my-repo").is_ok());
        assert!(validate_repo_format("user123/project_name").is_ok());
    }

    #[test]
    fn test_validate_repo_format_invalid() {
        assert!(validate_repo_format("").is_err());
        assert!(validate_repo_format("noslash").is_err());
        assert!(validate_repo_format("too/many/slashes").is_err());
        assert!(validate_repo_format("/repo").is_err());
        assert!(validate_repo_format("owner/").is_err());
        assert!(validate_repo_format("has spaces/repo").is_err());
    }

    #[test]
    fn test_validate_pr_url_format_valid() {
        assert!(validate_pr_url_format("https://github.com/owner/repo/pull/123").is_ok());
        assert!(validate_pr_url_format("https://github.com/my-org/my-repo/pull/1").is_ok());
        assert!(validate_pr_url_format("https://github.com/user/project/pull/999999").is_ok());
    }

    #[test]
    fn test_validate_pr_url_format_invalid() {
        // Wrong scheme
        assert!(validate_pr_url_format("http://github.com/owner/repo/pull/123").is_err());
        // Wrong host
        assert!(validate_pr_url_format("https://gitlab.com/owner/repo/pull/123").is_err());
        // Wrong path (issues instead of pull)
        assert!(validate_pr_url_format("https://github.com/owner/repo/issues/123").is_err());
        // Missing PR number
        assert!(validate_pr_url_format("https://github.com/owner/repo/pull").is_err());
        // Invalid PR number
        assert!(validate_pr_url_format("https://github.com/owner/repo/pull/abc").is_err());
        // Too many path segments
        assert!(validate_pr_url_format("https://github.com/owner/repo/pull/123/files").is_err());
    }

    #[test]
    fn test_state_serialization() {
        let mut state = State::default();
        state.allowed_repos.insert("owner/repo".to_string());
        state
            .allowed_prs
            .insert("https://github.com/owner/repo/pull/123".to_string());

        let json = serde_json::to_string(&state).unwrap();
        let deserialized: State = serde_json::from_str(&json).unwrap();

        assert_eq!(state, deserialized);
    }

    #[test]
    fn test_state_default_is_empty() {
        let state = State::default();
        assert!(state.allowed_repos.is_empty());
        assert!(state.allowed_prs.is_empty());
    }

    #[test]
    fn test_get_runtime_dir_with_xdg() {
        // Test with XDG_RUNTIME_DIR set
        std::env::set_var("XDG_RUNTIME_DIR", "/run/user/1000");
        let dir = get_runtime_dir();
        assert_eq!(dir, PathBuf::from("/run/user/1000/devaipod"));
        std::env::remove_var("XDG_RUNTIME_DIR");
    }

    #[test]
    fn test_get_runtime_dir_fallback() {
        // Test fallback to $HOME/.local/state/devaipod
        std::env::remove_var("XDG_RUNTIME_DIR");
        let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
        let dir = get_runtime_dir();
        assert_eq!(
            dir,
            PathBuf::from(format!("{}/.local/state/devaipod", home))
        );
    }

    #[test]
    fn test_is_process_alive() {
        // Current process should be alive
        let pid = std::process::id();
        assert!(is_process_alive(pid));

        // Non-existent PID should not be alive (use a very high PID that's unlikely to exist)
        assert!(!is_process_alive(u32::MAX));
    }

    #[test]
    fn test_listener_status_not_running_no_pid_file() {
        // Create a temp directory to use as runtime dir
        let temp_dir = tempfile::tempdir().unwrap();
        std::env::set_var("XDG_RUNTIME_DIR", temp_dir.path());

        let status = check_listener_status("test-workspace").unwrap();
        assert!(matches!(status, ListenerStatus::NotRunning));

        std::env::remove_var("XDG_RUNTIME_DIR");
    }

    #[test]
    fn test_write_and_check_pid_file() {
        // Create a temp directory to use as runtime dir
        let temp_dir = tempfile::tempdir().unwrap();
        std::env::set_var("XDG_RUNTIME_DIR", temp_dir.path());

        // Write PID file
        write_pid_file("test-workspace-2").unwrap();

        // Check that we detect ourselves as running
        let socket_path = get_socket_path("test-workspace-2").unwrap();
        // Create a dummy socket file so the check passes
        std::fs::write(&socket_path, "").unwrap();

        let status = check_listener_status("test-workspace-2").unwrap();
        match status {
            ListenerStatus::Running { pid, .. } => {
                assert_eq!(pid, std::process::id());
            }
            ListenerStatus::NotRunning => panic!("Expected Running status"),
        }

        // Clean up
        remove_pid_file("test-workspace-2").unwrap();
        std::env::remove_var("XDG_RUNTIME_DIR");
    }
}
