//! Agent workspace directory helpers
//!
//! Manages the on-disk directories used for agent workspaces. Each pod gets
//! a dedicated directory that is bind-mounted into the agent container.
//!
//! There are two path spaces:
//! - **Container-side**: where the devaipod controlplane sees the directory
//!   (e.g. `/var/lib/devaipod-workspaces/<pod>/` when containerized)
//! - **Host-side**: the actual host filesystem path passed as `-v` source
//!   to podman (e.g. `~/.local/share/devaipod/workspaces/<pod>/`)
//!
//! These differ because devaipod itself runs in a container with the host
//! workdir bind-mounted at a fixed path. The host-side path is needed for
//! creating sibling containers via the host's podman daemon.
//!
//! Each workspace directory contains a `.devaipod/state.json` file that
//! records metadata (source, task, timestamps). This file is the durable
//! anchor — it survives pod stop/start/delete cycles and makes workspaces
//! discoverable by scanning the filesystem.

use std::path::{Path, PathBuf};

use color_eyre::eyre::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::podman;

/// Container-side mount point for the workspaces base directory.
///
/// When running containerized, the host's workdir is mounted here.
const CONTAINER_WORKDIR_BASE: &str = "/var/lib/devaipod-workspaces";

/// Get the container-side base path for agent workspaces.
///
/// When running containerized, this is `/var/lib/devaipod-workspaces/`.
/// When running on the host, this falls back to the same path as
/// [`podman::get_host_workdir_path()`].
pub fn agent_workdir_base() -> Result<PathBuf> {
    let container_path = PathBuf::from(CONTAINER_WORKDIR_BASE);
    if container_path.exists() {
        return Ok(container_path);
    }
    // Not containerized (or mount not present) -- use the host path
    podman::get_host_workdir_path()
}

/// Get the container-side path for a specific pod's agent workspace.
pub fn agent_dir_container_path(pod_name: &str) -> Result<PathBuf> {
    Ok(agent_workdir_base()?.join(pod_name))
}

/// Get the host-side path for a specific pod's agent workspace.
///
/// This is what gets passed as the `-v` source to podman when creating
/// agent containers. The host podman daemon resolves paths on the host
/// filesystem, so this must be the real host path.
pub fn agent_dir_host_path(pod_name: &str) -> Result<PathBuf> {
    let base = podman::get_host_workdir_path()?;
    Ok(base.join(pod_name))
}

/// Create the agent directory on disk. Returns the container-side path.
pub fn create_agent_dir(pod_name: &str) -> Result<PathBuf> {
    let path = agent_dir_container_path(pod_name)?;
    std::fs::create_dir_all(&path)
        .with_context(|| format!("Failed to create agent directory {}", path.display()))?;
    Ok(path)
}

/// Remove the agent directory on disk.
pub fn remove_agent_dir(pod_name: &str) -> Result<()> {
    let path = agent_dir_container_path(pod_name)?;
    if path.exists() {
        std::fs::remove_dir_all(&path)
            .with_context(|| format!("Failed to remove agent directory {}", path.display()))?;
    }
    Ok(())
}

// ── Git repo discovery ───────────────────────────────────────────────

/// Find all git repositories inside a directory.
///
/// Checks `dir` itself first, then scans one level of subdirectories.
/// Returns `(repo_name, repo_path)` pairs sorted by name.
pub fn find_git_repos_in_dir(dir: &Path) -> Vec<(String, PathBuf)> {
    if dir.join(".git").exists() {
        let name = dir
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("workspace")
            .to_string();
        return vec![(name, dir.to_path_buf())];
    }
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return vec![],
    };
    let mut repos: Vec<(String, PathBuf)> = entries
        .flatten()
        .filter(|e| {
            let p = e.path();
            p.is_dir() && p.join(".git").exists()
        })
        .map(|e| {
            let name = e.file_name().to_str().unwrap_or("unknown").to_string();
            (name, e.path())
        })
        .collect();
    repos.sort_by(|a, b| a.0.cmp(&b.0));
    repos
}

// ── Workspace state file ─────────────────────────────────────────────

/// Subdirectory inside each workspace for devaipod metadata.
const DEVAIPOD_META_DIR: &str = ".devaipod";

/// Filename for the workspace state file.
const STATE_FILENAME: &str = "state.json";

/// Persistent workspace metadata, stored at `<workspace>/.devaipod/state.json`.
///
/// This is the durable record of a workspace. It survives pod stop/start/delete
/// cycles and is the primary data source for workspace listing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkspaceState {
    /// Pod name (e.g. `devaipod-myproject-abc123`).
    pub pod_name: String,

    /// Source identifier: local path, remote URL, or PR reference.
    /// Examples: `/home/user/src/myproject`, `https://github.com/org/repo`,
    /// `https://github.com/org/repo/pull/42`.
    pub source: String,

    /// Host-side paths of read-only source directories mounted into the pod.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub source_dirs: Vec<PathBuf>,

    /// RFC 3339 timestamp when the workspace was created.
    pub created: String,

    /// RFC 3339 timestamp of last known agent activity.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_active: Option<String>,

    /// Initial task description, if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub task: Option<String>,

    /// Human-readable title (may be updated by the agent).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,

    /// Completion status: `"active"` or `"done"`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub completion_status: Option<String>,

    /// SHA of the last harvested HEAD commit per repo, if any.
    #[serde(default, skip_serializing_if = "std::collections::HashMap::is_empty")]
    pub last_harvested: std::collections::HashMap<String, String>,
}

impl WorkspaceState {
    /// Path to the state file within a workspace directory.
    #[allow(dead_code)] // Used by tests
    pub fn state_path(workspace_dir: &Path) -> PathBuf {
        workspace_dir.join(DEVAIPOD_META_DIR).join(STATE_FILENAME)
    }

    /// Write this state to `<workspace_dir>/.devaipod/state.json`.
    ///
    /// Creates the `.devaipod/` subdirectory if needed. Uses atomic
    /// write-to-temp + rename.
    pub fn save(&self, workspace_dir: &Path) -> Result<()> {
        let meta_dir = workspace_dir.join(DEVAIPOD_META_DIR);
        std::fs::create_dir_all(&meta_dir).with_context(|| {
            format!("Failed to create metadata directory {}", meta_dir.display())
        })?;

        let state_path = meta_dir.join(STATE_FILENAME);
        let tmp_path = meta_dir.join("state.json.tmp");
        let data =
            serde_json::to_string_pretty(self).context("Failed to serialize workspace state")?;
        std::fs::write(&tmp_path, &data).with_context(|| {
            format!("Failed to write workspace state to {}", tmp_path.display())
        })?;
        std::fs::rename(&tmp_path, &state_path).with_context(|| {
            format!(
                "Failed to rename workspace state {} -> {}",
                tmp_path.display(),
                state_path.display()
            )
        })?;

        tracing::debug!("Wrote workspace state to {}", state_path.display());
        Ok(())
    }

    /// Load workspace state from `<workspace_dir>/.devaipod/state.json`.
    ///
    /// Returns `None` if the file doesn't exist (legacy workspace without
    /// state). Returns an error only on parse failures.
    pub fn load(workspace_dir: &Path) -> Result<Option<Self>> {
        let state_path = Self::state_path(workspace_dir);
        match std::fs::read_to_string(&state_path) {
            Ok(data) => {
                let state: Self = serde_json::from_str(&data).with_context(|| {
                    format!(
                        "Failed to parse workspace state at {}",
                        state_path.display()
                    )
                })?;
                Ok(Some(state))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e).with_context(|| {
                format!("Failed to read workspace state at {}", state_path.display())
            }),
        }
    }
}

/// Scan the workspaces base directory and load state for each workspace.
///
/// Returns `(pod_name, workspace_dir, state)` triples. Workspaces without
/// a state file are included with `state = None` (legacy or orphaned dirs).
pub fn list_workspaces() -> Result<Vec<(String, PathBuf, Option<WorkspaceState>)>> {
    let base = agent_workdir_base()?;
    if !base.exists() {
        return Ok(Vec::new());
    }

    let mut results = Vec::new();
    let entries = std::fs::read_dir(&base)
        .with_context(|| format!("Failed to read workspaces directory {}", base.display()))?;

    for entry in entries {
        let entry = entry?;
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        let dir_name = match entry.file_name().to_str() {
            Some(n) => n.to_string(),
            None => continue,
        };

        let state = match WorkspaceState::load(&path) {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!("Failed to load workspace state for {}: {e:#}", dir_name);
                None
            }
        };

        results.push((dir_name, path, state));
    }

    // Sort by created timestamp (newest first), falling back to dir name.
    results.sort_by(|a, b| {
        let ts_a = a.2.as_ref().map(|s| s.created.as_str()).unwrap_or("");
        let ts_b = b.2.as_ref().map(|s| s.created.as_str()).unwrap_or("");
        ts_b.cmp(ts_a)
    });

    Ok(results)
}

// ── Recent sources ───────────────────────────────────────────────────

const RECENT_SOURCES_FILENAME: &str = "recent-sources.json";
const MAX_RECENT_SOURCES: usize = 50;

/// A recently-used source for the launcher's "recents" list.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecentSource {
    /// Source identifier (local path or remote URL).
    pub source: String,
    /// RFC 3339 timestamp of last use.
    pub last_used: String,
}

/// Path to the recent-sources.json file (sibling of the workspaces dir).
fn recent_sources_path() -> Result<PathBuf> {
    let base = agent_workdir_base()?;
    // Place alongside the workspaces dir, e.g. /var/lib/devaipod-workspaces/../recent-sources.json
    // falls back to the workspaces dir itself if there's no parent.
    let parent = base.parent().unwrap_or(&base);
    Ok(parent.join(RECENT_SOURCES_FILENAME))
}

/// Load the recent sources list from disk. Returns empty vec on missing/corrupt file.
pub fn load_recent_sources() -> Vec<RecentSource> {
    let path = match recent_sources_path() {
        Ok(p) => p,
        Err(e) => {
            tracing::debug!("Cannot resolve recent sources path: {e:#}");
            return Vec::new();
        }
    };
    match std::fs::read_to_string(&path) {
        Ok(data) => serde_json::from_str(&data).unwrap_or_else(|e| {
            tracing::debug!("Failed to parse recent sources at {}: {e}", path.display());
            Vec::new()
        }),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
        Err(e) => {
            tracing::debug!("Failed to read recent sources at {}: {e}", path.display());
            Vec::new()
        }
    }
}

/// Record a source as recently used. Updates the timestamp if already present,
/// otherwise appends. Caps at [`MAX_RECENT_SOURCES`] entries.
///
/// Best-effort: logs warnings on failure.
pub fn record_recent_source(source: &str) {
    let path = match recent_sources_path() {
        Ok(p) => p,
        Err(e) => {
            tracing::debug!("Cannot resolve recent sources path: {e:#}");
            return;
        }
    };

    let mut sources = load_recent_sources();
    let now = chrono::Utc::now().to_rfc3339();

    // Update existing or insert new
    if let Some(existing) = sources.iter_mut().find(|s| s.source == source) {
        existing.last_used = now;
    } else {
        sources.push(RecentSource {
            source: source.to_string(),
            last_used: now,
        });
    }

    // Sort by last_used descending and cap
    sources.sort_by(|a, b| b.last_used.cmp(&a.last_used));
    sources.truncate(MAX_RECENT_SOURCES);

    // Write atomically
    match serde_json::to_string_pretty(&sources) {
        Ok(data) => {
            let tmp = path.with_extension("json.tmp");
            if let Err(e) = std::fs::write(&tmp, &data) {
                tracing::warn!("Failed to write recent sources to {}: {e}", tmp.display());
                return;
            }
            if let Err(e) = std::fs::rename(&tmp, &path) {
                tracing::warn!("Failed to rename recent sources: {e}");
            }
        }
        Err(e) => {
            tracing::warn!("Failed to serialize recent sources: {e}");
        }
    }
}

// ── Shared harvest logic ─────────────────────────────────────────────

/// Result of harvesting commits from one agent repo into a target repo.
#[derive(Debug)]
pub struct HarvestRepoResult {
    pub remote_name: String,
    pub branches: Vec<String>,
}

/// Build the podman CLI argument list (binary + `--url` flag) matching how
/// the rest of devaipod invokes podman.
///
/// Returns a `Vec<String>` like `["podman", "--url", "unix:///path/to/sock"]`
/// or just `["podman"]` when no socket is discovered. The caller can join
/// these into a shell command string for use in `ext::` URLs.
fn podman_cli_prefix() -> Vec<String> {
    let mut args = vec!["podman".to_string()];
    if let Ok(socket_path) = podman::get_container_socket() {
        args.push("--url".to_string());
        args.push(format!("unix://{}", socket_path.display()));
    }
    args
}

/// Check whether a container is currently running.
///
/// Uses `podman inspect` to query the container's running state. Returns
/// `false` when the container doesn't exist or isn't running.
pub fn is_container_running(container_name: &str) -> bool {
    let mut cmd_args = podman_cli_prefix();
    cmd_args.extend([
        "inspect".to_string(),
        "--format".to_string(),
        "{{.State.Running}}".to_string(),
        container_name.to_string(),
    ]);

    let output = std::process::Command::new(&cmd_args[0])
        .args(&cmd_args[1..])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .output();

    match output {
        Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout).trim() == "true",
        _ => false,
    }
}

/// Harvest commits from an agent repo via `ext::` git transport.
///
/// Instead of pointing git at a host-side filesystem path (which breaks
/// for workspace-v2 repos that use container-internal alternates), this
/// tunnels git-upload-pack through `podman exec` into the running agent
/// container where the alternates resolve correctly.
///
/// `container_name` is the full podman container name (e.g.
/// `devaipod-myproject-abc-agent`).
///
/// `workspace_path` is the repo path *inside* the container (e.g.
/// `/workspaces/myproject`).
pub fn harvest_one_repo_via_exec(
    target_repo: &Path,
    container_name: &str,
    workspace_path: &str,
    remote_name: &str,
) -> Result<HarvestRepoResult> {
    let prefix = podman_cli_prefix();
    let ext_url = format!(
        "ext::{} exec -i {} git-upload-pack {}",
        prefix.join(" "),
        shell_quote(container_name),
        shell_quote(workspace_path),
    );

    tracing::debug!("Using ext:: exec transport: {}", ext_url);
    harvest_via_ext_url(target_repo, &ext_url, remote_name)
}

/// Harvest commits by spawning a transient container that mounts the
/// workspace volume + host-side workspace directory.
///
/// This works even when the agent container is stopped. The transient
/// container mounts the workspace volume at `/mnt/main-workspace` (matching
/// the alternates path) and the host-side workspace-v2 directory at
/// `/workspaces`, so all git objects resolve correctly.
///
/// `pod_name` is the pod name (e.g. `devaipod-myproject-abc`).
/// `workspace_path` is the repo path inside the container (e.g.
/// `/workspaces/myproject`).
/// `image` is a container image with git installed.
pub fn harvest_one_repo_via_transient(
    target_repo: &Path,
    pod_name: &str,
    workspace_path: &str,
    remote_name: &str,
    image: &str,
) -> Result<HarvestRepoResult> {
    // The workspace volume follows the naming convention {pod_name}-workspace.
    let volume_name = format!("{pod_name}-workspace");
    // The host-side workspace-v2 directory
    let host_ws_dir = agent_dir_host_path(pod_name)?;

    let prefix = podman_cli_prefix();
    let ext_url = format!(
        "ext::{} run --rm --privileged -i \
         -v {volume}:/mnt/main-workspace:ro \
         -v {host_dir}:/workspaces:ro \
         {image} \
         git-upload-pack {ws_path}",
        prefix.join(" "),
        volume = shell_quote(&volume_name),
        host_dir = shell_quote(&host_ws_dir.to_string_lossy()),
        image = shell_quote(image),
        ws_path = shell_quote(workspace_path),
    );

    tracing::debug!("Using ext:: transient container transport: {}", ext_url);
    harvest_via_ext_url(target_repo, &ext_url, remote_name)
}

/// Shared logic: set up a git remote with an `ext::` URL, fetch, and list branches.
fn harvest_via_ext_url(
    target_repo: &Path,
    ext_url: &str,
    remote_name: &str,
) -> Result<HarvestRepoResult> {
    use color_eyre::eyre::bail;

    // Add or update the remote
    let add_result = std::process::Command::new("git")
        .arg("-C")
        .arg(target_repo)
        .args(["remote", "add", remote_name, ext_url])
        .stderr(std::process::Stdio::piped())
        .output()
        .context("Failed to run git remote add")?;

    if !add_result.status.success() {
        let stderr = String::from_utf8_lossy(&add_result.stderr);
        if stderr.contains("already exists") {
            let set_result = std::process::Command::new("git")
                .arg("-C")
                .arg(target_repo)
                .args(["remote", "set-url", remote_name, ext_url])
                .output()
                .context("Failed to run git remote set-url")?;
            if !set_result.status.success() {
                let stderr = String::from_utf8_lossy(&set_result.stderr);
                tracing::warn!(
                    "Failed to update remote '{}' URL: {}",
                    remote_name,
                    stderr.trim()
                );
            }
        } else {
            bail!("Failed to add remote '{}': {}", remote_name, stderr.trim());
        }
    }

    // Fetch with protocol.ext.allow=always so git permits the ext:: URL.
    let fetch_output = std::process::Command::new("git")
        .arg("-C")
        .arg(target_repo)
        .args(["-c", "protocol.ext.allow=always"])
        .args(["fetch", remote_name])
        .stderr(std::process::Stdio::piped())
        .output()
        .context("Failed to run git fetch via ext:: transport")?;

    // A failed exit code with only "unable to normalize alternate" warnings
    // is treated as success — these warnings are benign and expected with
    // workspace-v2 repos that use container-internal alternate paths.
    let stderr = String::from_utf8_lossy(&fetch_output.stderr);
    let real_errors: Vec<&str> = stderr
        .lines()
        .filter(|l| !l.contains("unable to normalize alternate"))
        .filter(|l| !l.trim().is_empty())
        .collect();

    if !fetch_output.status.success() && !real_errors.is_empty() {
        bail!(
            "Failed to fetch from '{}' via ext:: transport: {}",
            remote_name,
            real_errors.join("\n")
        );
    }

    // List branches
    let branch_output = std::process::Command::new("git")
        .arg("-C")
        .arg(target_repo)
        .args(["branch", "-r", "--list", &format!("{remote_name}/*")])
        .output()
        .context("Failed to list remote branches")?;

    let branches: Vec<String> = if branch_output.status.success() {
        String::from_utf8_lossy(&branch_output.stdout)
            .lines()
            .map(|l| l.trim().to_string())
            .filter(|l| !l.is_empty())
            .collect()
    } else {
        vec![]
    };

    Ok(HarvestRepoResult {
        remote_name: remote_name.to_string(),
        branches,
    })
}

/// Shell-quote a string for safe embedding in an ext:: URL.
///
/// Quote a value for embedding in a git `ext::` URL.
///
/// Git's ext:: transport splits the URL on whitespace and passes each
/// token as an argv element — it does NOT invoke a shell. So we only
/// need to avoid whitespace and ensure no token splitting. Single-quote
/// wrapping would cause literal quote characters to reach the command.
fn shell_quote(s: &str) -> String {
    // Characters safe in ext:: URL tokens (no shell involved).
    if s.chars()
        .all(|c| c.is_alphanumeric() || matches!(c, '-' | '_' | '.' | '/' | ':' | '@'))
    {
        return s.to_string();
    }
    // If we somehow have whitespace or exotic chars, this is an error
    // condition for ext:: URLs. Log and return as-is — the fetch will
    // fail with a clear error rather than silently mangling the value.
    tracing::warn!("ext:: URL token contains unusual characters: {s:?}");
    s.to_string()
}

/// Add or update a git remote in `target_repo` pointing at `agent_repo`,
/// then fetch from it. Returns the list of fetched branches.
///
/// This is the simple path for repos with self-contained objects (no
/// container-internal alternates). For workspace-v2 repos, prefer
/// [`harvest_one_repo_via_exec`] or [`harvest_one_repo_via_transient`].
#[cfg(test)]
pub fn harvest_one_repo(
    target_repo: &Path,
    agent_repo: &Path,
    remote_name: &str,
) -> Result<HarvestRepoResult> {
    use color_eyre::eyre::bail;

    let agent_repo_str = agent_repo.to_str().ok_or_else(|| {
        color_eyre::eyre::eyre!(
            "Agent repo path is not valid UTF-8: {}",
            agent_repo.display()
        )
    })?;

    // Add or update the remote
    let add_result = std::process::Command::new("git")
        .arg("-C")
        .arg(target_repo)
        .args(["remote", "add", remote_name, agent_repo_str])
        .stderr(std::process::Stdio::piped())
        .output()
        .context("Failed to run git remote add")?;

    if !add_result.status.success() {
        let stderr = String::from_utf8_lossy(&add_result.stderr);
        if stderr.contains("already exists") {
            let set_result = std::process::Command::new("git")
                .arg("-C")
                .arg(target_repo)
                .args(["remote", "set-url", remote_name, agent_repo_str])
                .output()
                .context("Failed to run git remote set-url")?;
            if !set_result.status.success() {
                let stderr = String::from_utf8_lossy(&set_result.stderr);
                tracing::warn!(
                    "Failed to update remote '{}' URL: {}",
                    remote_name,
                    stderr.trim()
                );
            }
        } else {
            bail!("Failed to add remote '{}': {}", remote_name, stderr.trim());
        }
    }

    // Fetch
    let fetch_output = std::process::Command::new("git")
        .arg("-C")
        .arg(target_repo)
        .args(["fetch", remote_name])
        .stderr(std::process::Stdio::piped())
        .output()
        .context("Failed to run git fetch")?;

    // Filter alternates warnings
    let stderr = String::from_utf8_lossy(&fetch_output.stderr);
    let real_errors: Vec<&str> = stderr
        .lines()
        .filter(|l| !l.contains("unable to normalize alternate"))
        .filter(|l| !l.trim().is_empty())
        .collect();

    if !fetch_output.status.success() && !real_errors.is_empty() {
        bail!(
            "Failed to fetch from '{}': {}",
            remote_name,
            real_errors.join("\n")
        );
    }

    // List branches
    let branch_output = std::process::Command::new("git")
        .arg("-C")
        .arg(target_repo)
        .args(["branch", "-r", "--list", &format!("{remote_name}/*")])
        .output()
        .context("Failed to list remote branches")?;

    let branches: Vec<String> = if branch_output.status.success() {
        String::from_utf8_lossy(&branch_output.stdout)
            .lines()
            .map(|l| l.trim().to_string())
            .filter(|l| !l.is_empty())
            .collect()
    } else {
        vec![]
    };

    Ok(HarvestRepoResult {
        remote_name: remote_name.to_string(),
        branches,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_agent_dir_container_path_appends_pod_name() {
        // On the host test runner, /var/lib/devaipod-workspaces won't exist,
        // so agent_dir_container_path falls back to the host workdir path.
        // Either way, the result must end with the pod name.
        let path = agent_dir_container_path("devaipod-test-pod").unwrap();
        assert!(
            path.ends_with("devaipod-test-pod"),
            "Expected path to end with pod name, got: {}",
            path.display()
        );
    }

    #[test]
    fn test_agent_dir_host_path_appends_pod_name() {
        let path = agent_dir_host_path("devaipod-myproject-abc123").unwrap();
        assert!(
            path.ends_with("devaipod-myproject-abc123"),
            "Expected path to end with pod name, got: {}",
            path.display()
        );
    }

    #[test]
    fn test_agent_dir_host_path_is_absolute() {
        let path = agent_dir_host_path("devaipod-test").unwrap();
        assert!(
            path.is_absolute(),
            "Expected absolute path, got: {}",
            path.display()
        );
    }

    #[test]
    fn test_agent_workdir_base_returns_absolute_path() {
        let base = agent_workdir_base().unwrap();
        assert!(
            base.is_absolute(),
            "Expected absolute path, got: {}",
            base.display()
        );
    }

    #[test]
    fn test_create_and_remove_agent_dir() {
        let temp = tempfile::tempdir().unwrap();
        let pod_name = "devaipod-test-create-remove";

        // Create a directory under the temp dir to test create/remove.
        // We test the underlying logic directly since we can't safely
        // manipulate env vars in a multi-threaded test runner.
        let dir = temp.path().join(pod_name);
        std::fs::create_dir_all(&dir).unwrap();
        assert!(dir.exists());

        std::fs::remove_dir_all(&dir).unwrap();
        assert!(!dir.exists());
    }

    #[test]
    fn test_workspace_state_roundtrip() {
        let temp = tempfile::tempdir().unwrap();
        let ws_dir = temp.path().join("devaipod-test-ws");
        std::fs::create_dir_all(&ws_dir).unwrap();

        let state = WorkspaceState {
            pod_name: "devaipod-test-ws".into(),
            source: "/home/user/src/myproject".into(),
            source_dirs: vec![PathBuf::from("/home/user/src/docs")],
            created: "2026-04-04T12:00:00Z".into(),
            last_active: None,
            task: Some("fix the auth bug".into()),
            title: None,
            completion_status: None,
            last_harvested: std::collections::HashMap::new(),
        };

        state.save(&ws_dir).unwrap();

        // Verify file exists at expected path
        let state_path = WorkspaceState::state_path(&ws_dir);
        assert!(state_path.exists(), "state.json should exist");

        // Load and verify roundtrip
        let loaded = WorkspaceState::load(&ws_dir).unwrap().unwrap();
        assert_eq!(loaded.pod_name, "devaipod-test-ws");
        assert_eq!(loaded.source, "/home/user/src/myproject");
        assert_eq!(
            loaded.source_dirs,
            vec![PathBuf::from("/home/user/src/docs")]
        );
        assert_eq!(loaded.task.as_deref(), Some("fix the auth bug"));
        assert!(loaded.title.is_none());
        assert!(loaded.completion_status.is_none());
    }

    #[test]
    fn test_workspace_state_load_missing() {
        let temp = tempfile::tempdir().unwrap();
        let ws_dir = temp.path().join("devaipod-no-state");
        std::fs::create_dir_all(&ws_dir).unwrap();

        // No state file → returns None
        let loaded = WorkspaceState::load(&ws_dir).unwrap();
        assert!(loaded.is_none());
    }

    #[test]
    fn test_workspace_state_optional_fields_omitted() {
        let temp = tempfile::tempdir().unwrap();
        let ws_dir = temp.path().join("devaipod-minimal");
        std::fs::create_dir_all(&ws_dir).unwrap();

        let state = WorkspaceState {
            pod_name: "devaipod-minimal".into(),
            source: "https://github.com/org/repo".into(),
            source_dirs: vec![],
            created: "2026-04-04T12:00:00Z".into(),
            last_active: None,
            task: None,
            title: None,
            completion_status: None,
            last_harvested: std::collections::HashMap::new(),
        };

        state.save(&ws_dir).unwrap();

        // Verify optional fields are omitted from JSON (not null)
        let raw = std::fs::read_to_string(WorkspaceState::state_path(&ws_dir)).unwrap();
        assert!(
            !raw.contains("last_active"),
            "omitted fields should not appear in JSON"
        );
        assert!(
            !raw.contains("task"),
            "omitted fields should not appear in JSON"
        );
        assert!(
            !raw.contains("source_dirs"),
            "empty source_dirs should be omitted"
        );
        assert!(
            !raw.contains("last_harvested"),
            "empty last_harvested should be omitted"
        );
    }

    #[test]
    fn test_list_workspaces_with_mixed_dirs() {
        let temp = tempfile::tempdir().unwrap();

        // Create a workspace with state
        let ws1 = temp.path().join("devaipod-project-a");
        std::fs::create_dir_all(&ws1).unwrap();
        let state1 = WorkspaceState {
            pod_name: "devaipod-project-a".into(),
            source: "/home/user/src/a".into(),
            source_dirs: vec![],
            created: "2026-04-04T12:00:00Z".into(),
            last_active: None,
            task: Some("task a".into()),
            title: None,
            completion_status: None,
            last_harvested: std::collections::HashMap::new(),
        };
        state1.save(&ws1).unwrap();

        // Create a workspace without state (legacy)
        let ws2 = temp.path().join("devaipod-project-b");
        std::fs::create_dir_all(&ws2).unwrap();

        // Create a regular file (should be skipped)
        std::fs::write(temp.path().join("not-a-dir.txt"), "hi").unwrap();

        // We can't easily test list_workspaces() directly because it uses
        // agent_workdir_base() which depends on env vars. Test the underlying
        // scan logic instead.
        let mut results = Vec::new();
        for entry in std::fs::read_dir(temp.path()).unwrap() {
            let entry = entry.unwrap();
            let path = entry.path();
            if !path.is_dir() {
                continue;
            }
            let name = entry.file_name().to_str().unwrap().to_string();
            let state = WorkspaceState::load(&path).unwrap();
            results.push((name, path, state));
        }

        assert_eq!(results.len(), 2);
        let with_state = results
            .iter()
            .find(|(n, _, _)| n == "devaipod-project-a")
            .unwrap();
        assert!(with_state.2.is_some());
        assert_eq!(
            with_state.2.as_ref().unwrap().task.as_deref(),
            Some("task a")
        );

        let without_state = results
            .iter()
            .find(|(n, _, _)| n == "devaipod-project-b")
            .unwrap();
        assert!(without_state.2.is_none());
    }

    #[test]
    fn test_recent_source_roundtrip() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join(RECENT_SOURCES_FILENAME);

        // Write directly (bypassing record_recent_source which uses env-dependent paths)
        let sources = vec![
            RecentSource {
                source: "/home/user/src/a".into(),
                last_used: "2026-04-04T14:00:00Z".into(),
            },
            RecentSource {
                source: "https://github.com/org/repo".into(),
                last_used: "2026-04-03T09:00:00Z".into(),
            },
        ];

        let data = serde_json::to_string_pretty(&sources).unwrap();
        std::fs::write(&path, &data).unwrap();

        let loaded: Vec<RecentSource> =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(loaded.len(), 2);
        assert_eq!(loaded[0].source, "/home/user/src/a");
        assert_eq!(loaded[1].source, "https://github.com/org/repo");
    }

    #[test]
    fn test_workspace_state_with_harvest_info() {
        let temp = tempfile::tempdir().unwrap();
        let ws_dir = temp.path().join("devaipod-test-harvest");
        std::fs::create_dir_all(&ws_dir).unwrap();

        let mut state = WorkspaceState {
            pod_name: "devaipod-test-harvest".into(),
            source: "/home/user/src/project".into(),
            source_dirs: vec![],
            created: "2026-04-04T12:00:00Z".into(),
            last_active: None,
            task: None,
            title: None,
            completion_status: None,
            last_harvested: std::collections::HashMap::new(),
        };

        state
            .last_harvested
            .insert("project".into(), "abc123".into());
        state.save(&ws_dir).unwrap();

        let loaded = WorkspaceState::load(&ws_dir).unwrap().unwrap();
        assert_eq!(loaded.last_harvested.get("project").unwrap(), "abc123");

        // Verify it appears in the JSON when non-empty
        let raw = std::fs::read_to_string(WorkspaceState::state_path(&ws_dir)).unwrap();
        assert!(
            raw.contains("last_harvested"),
            "non-empty last_harvested should appear in JSON"
        );
    }

    #[test]
    fn test_recent_source_truncation() {
        // Verify that MAX_RECENT_SOURCES caps the list
        let mut sources: Vec<RecentSource> = (0..60)
            .map(|i| RecentSource {
                source: format!("/home/user/src/project-{i}"),
                last_used: format!("2026-04-{:02}T12:00:00Z", (i % 28) + 1),
            })
            .collect();

        sources.sort_by(|a, b| b.last_used.cmp(&a.last_used));
        sources.truncate(MAX_RECENT_SOURCES);

        assert_eq!(sources.len(), MAX_RECENT_SOURCES);
    }

    #[test]
    fn test_find_git_repos_in_dir_multiple() {
        let temp = tempfile::tempdir().unwrap();

        // Create two "repos" (directories with .git)
        let repo_a = temp.path().join("alpha");
        std::fs::create_dir_all(repo_a.join(".git")).unwrap();
        let repo_b = temp.path().join("beta");
        std::fs::create_dir_all(repo_b.join(".git")).unwrap();
        // Create a non-repo directory
        std::fs::create_dir_all(temp.path().join("not-a-repo")).unwrap();

        let repos = find_git_repos_in_dir(temp.path());
        assert_eq!(repos.len(), 2);
        // Should be sorted by name
        assert_eq!(repos[0].0, "alpha");
        assert_eq!(repos[1].0, "beta");
        assert!(repos[0].1.ends_with("alpha"));
        assert!(repos[1].1.ends_with("beta"));
    }

    #[test]
    fn test_find_git_repos_in_dir_single() {
        let temp = tempfile::tempdir().unwrap();
        // Dir itself is a repo
        std::fs::create_dir_all(temp.path().join(".git")).unwrap();

        let repos = find_git_repos_in_dir(temp.path());
        assert_eq!(repos.len(), 1);
        assert_eq!(repos[0].1, temp.path());
    }

    #[test]
    fn test_find_git_repos_in_dir_empty() {
        let temp = tempfile::tempdir().unwrap();
        let repos = find_git_repos_in_dir(temp.path());
        assert!(repos.is_empty());
    }

    #[test]
    fn test_harvest_one_repo_roundtrip() {
        // Create a "source" repo with one commit
        let temp = tempfile::tempdir().unwrap();
        let source = temp.path().join("source");
        std::fs::create_dir_all(&source).unwrap();
        let init = |dir: &std::path::Path, args: &[&str]| {
            std::process::Command::new("git")
                .arg("-C")
                .arg(dir)
                .args(args)
                .output()
                .expect("git command failed");
        };
        init(&source, &["init", "-b", "main"]);
        init(&source, &["config", "user.email", "test@test.com"]);
        init(&source, &["config", "user.name", "Test"]);
        std::fs::write(source.join("README.md"), "hello").unwrap();
        init(&source, &["add", "."]);
        init(&source, &["commit", "-m", "initial"]);

        // Create an "agent" repo that is a clone of source with an extra commit
        let agent = temp.path().join("agent");
        std::process::Command::new("git")
            .args(["clone", source.to_str().unwrap(), agent.to_str().unwrap()])
            .output()
            .unwrap();
        std::fs::write(agent.join("agent.txt"), "agent work").unwrap();
        init(&agent, &["add", "."]);
        init(&agent, &["commit", "-m", "agent commit"]);

        // Harvest agent commits into source
        let result = harvest_one_repo(&source, &agent, "devaipod/test").unwrap();
        assert_eq!(result.remote_name, "devaipod/test");
        assert!(
            !result.branches.is_empty(),
            "Expected at least one branch after harvest"
        );
        assert!(
            result.branches.iter().any(|b| b.contains("main")),
            "Expected a main branch in {:?}",
            result.branches
        );

        // Harvest again (remote already exists) should succeed
        let result2 = harvest_one_repo(&source, &agent, "devaipod/test").unwrap();
        assert!(!result2.branches.is_empty());
    }
}
