//! Advisor data types, pod/workspace introspection, and draft proposal management.
//!
//! The advisor is a special devaipod pod that observes the user's development
//! environment and suggests agent pods to launch. This module provides:
//!
//! - Pod introspection (list, status, logs) via podman CLI
//! - Workspace introspection (state, git branches, diffs) via direct filesystem access
//! - Draft proposal storage (`DraftStore`) for human-approved pod launches
//!
//! The MCP server that exposes these as tools lives in `mcp.rs` and is mounted
//! on the control plane web server at `/api/devaipod/mcp`.

use std::path::Path;

use color_eyre::eyre::{Context, Result};
use serde::{Deserialize, Serialize};

/// Default path for draft proposals storage
pub const DRAFTS_PATH: &str = "/var/lib/devaipod-drafts.json";

/// Priority level for a draft proposal
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Priority {
    High,
    Medium,
    Low,
}

/// Status of a draft proposal
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ProposalStatus {
    /// Waiting for human review
    #[default]
    Pending,
    /// Approved by human, pod launch pending or in progress
    Approved,
    /// Dismissed by human
    Dismissed,
    /// Expired (source issue closed, etc.)
    Expired,
}

/// A draft proposal for launching an agent pod
///
/// Created by the advisor agent when it identifies work that could be
/// delegated to a new agent pod. Each proposal captures enough context
/// for a human to make an informed approve/dismiss decision.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DraftProposal {
    /// Unique identifier (hex-encoded timestamp)
    pub id: String,
    /// Human-readable summary
    pub title: String,
    /// Target repository (e.g. "myorg/backend")
    pub repo: String,
    /// Task description for the agent
    pub task: String,
    /// Why the advisor thinks this is worth doing
    pub rationale: String,
    /// Priority level
    pub priority: Priority,
    /// What triggered this proposal (e.g. "github:myorg/backend#142")
    pub source: Option<String>,
    /// Rough sizing estimate (e.g. "small", "medium", "large")
    pub estimated_scope: Option<String>,
    /// Current status
    #[serde(default)]
    pub status: ProposalStatus,
    /// When the proposal was created (RFC 3339)
    pub created_at: String,
}

/// Collection of draft proposals, persisted as a JSON file
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DraftStore {
    pub proposals: Vec<DraftProposal>,
}

impl DraftStore {
    /// Load from a JSON file, returning an empty store if the file doesn't exist
    pub fn load(path: &Path) -> Result<Self> {
        if !path.exists() {
            return Ok(Self::default());
        }
        let data = std::fs::read_to_string(path)
            .with_context(|| format!("Reading draft store from {}", path.display()))?;
        serde_json::from_str(&data)
            .with_context(|| format!("Parsing draft store from {}", path.display()))
    }

    /// Save to a JSON file (creates parent directories if needed)
    pub fn save(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("Creating directory {}", parent.display()))?;
        }
        let data = serde_json::to_string_pretty(self).context("Serializing draft store")?;
        std::fs::write(path, data)
            .with_context(|| format!("Writing draft store to {}", path.display()))
    }

    /// Add a new proposal, returning its generated ID.
    ///
    /// Automatically sets the `id` and `created_at` fields.
    pub fn add(&mut self, mut proposal: DraftProposal) -> String {
        let id = generate_proposal_id();
        proposal.id = id.clone();
        if proposal.created_at.is_empty() {
            proposal.created_at = rfc3339_now();
        }
        self.proposals.push(proposal);
        id
    }

    /// List proposals, optionally filtered by status
    pub fn list(&self, status: Option<&ProposalStatus>) -> Vec<&DraftProposal> {
        match status {
            Some(s) => self.proposals.iter().filter(|p| &p.status == s).collect(),
            None => self.proposals.iter().collect(),
        }
    }

    /// Update a proposal's status by ID, returning the updated proposal if found
    pub fn update_status(&mut self, id: &str, status: ProposalStatus) -> Option<&DraftProposal> {
        if let Some(proposal) = self.proposals.iter_mut().find(|p| p.id == id) {
            proposal.status = status;
            // Re-borrow as immutable
            self.proposals.iter().find(|p| p.id == id)
        } else {
            None
        }
    }
}

/// Generate a unique proposal ID from the current timestamp.
///
/// Uses the same approach as `unique_suffix()` in main.rs: lower bits of
/// the unix timestamp XOR'd with nanoseconds for short, reasonably unique IDs.
fn generate_proposal_id() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let val = (now.as_secs() & 0xFFFFFF) ^ ((now.subsec_nanos() as u64) & 0xFFFF);
    format!("{val:x}")
}

/// Generate an RFC 3339 timestamp for the current time (UTC).
fn rfc3339_now() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let secs = now.as_secs();
    // Simple UTC timestamp without external crate
    let days = secs / 86400;
    let time_of_day = secs % 86400;
    let hours = time_of_day / 3600;
    let minutes = (time_of_day % 3600) / 60;
    let seconds = time_of_day % 60;

    // Days since 1970-01-01 to Y-M-D (civil calendar algorithm)
    let (y, m, d) = days_to_ymd(days);
    format!("{y:04}-{m:02}-{d:02}T{hours:02}:{minutes:02}:{seconds:02}Z")
}

/// Convert days since Unix epoch to (year, month, day).
///
/// Uses the civil calendar algorithm from Howard Hinnant.
fn days_to_ymd(days: u64) -> (i64, u32, u32) {
    let z = days as i64 + 719468;
    let era = z.div_euclid(146097);
    let doe = z.rem_euclid(146097) as u32;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

// ---------------------------------------------------------------------------
// Pod introspection — shell out to podman CLI
// ---------------------------------------------------------------------------

use crate::{INSTANCE_LABEL_KEY, get_instance_id};

/// List all devaipod pods with basic status info.
///
/// Runs `podman pod ps --filter name=devaipod-* --format json` and returns
/// the parsed JSON array. Each element contains fields like `Name`, `Status`,
/// `Created`, etc. as defined by podman's JSON output.
///
/// When `DEVAIPOD_INSTANCE` is set, results are narrowed to pods carrying
/// the matching label. When unset, no instance filtering is performed here
/// because the advisor runs inside an isolated container environment where
/// cross-instance contamination doesn't occur (unlike the host-side CLI/TUI).
pub fn list_pods() -> Result<Vec<serde_json::Value>> {
    let instance_id = get_instance_id();

    let mut args = vec![
        "pod".to_string(),
        "ps".to_string(),
        "--filter".to_string(),
        "name=devaipod-*".to_string(),
    ];
    if let Some(ref id) = instance_id {
        args.push("--filter".to_string());
        args.push(format!("label={INSTANCE_LABEL_KEY}={id}"));
    }
    args.push("--format".to_string());
    args.push("json".to_string());

    let output = std::process::Command::new("podman")
        .args(&args)
        .output()
        .context("Failed to run podman pod ps")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        color_eyre::eyre::bail!("podman pod ps failed: {}", stderr.trim());
    }

    let pods: Vec<serde_json::Value> =
        serde_json::from_slice(&output.stdout).context("Parsing podman pod ps output")?;

    Ok(pods)
}

/// Get detailed status for a specific pod.
///
/// Runs `podman pod inspect <pod_name>` and returns the full JSON object
/// with container details, network config, etc.
pub fn pod_status(pod_name: &str) -> Result<serde_json::Value> {
    let output = std::process::Command::new("podman")
        .args(["pod", "inspect", pod_name])
        .output()
        .with_context(|| format!("Failed to run podman pod inspect {pod_name}"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        color_eyre::eyre::bail!("podman pod inspect {pod_name} failed: {}", stderr.trim());
    }

    serde_json::from_slice(&output.stdout)
        .with_context(|| format!("Parsing podman pod inspect output for {pod_name}"))
}

/// Get recent logs from a pod's agent container.
///
/// Runs `podman logs --tail <lines> <pod_name>-agent` and returns the
/// combined stdout/stderr output as a string.
pub fn pod_logs(pod_name: &str, lines: Option<u32>) -> Result<String> {
    let container_name = format!("{pod_name}-agent");
    let tail = lines.unwrap_or(100).to_string();

    let output = std::process::Command::new("podman")
        .args(["logs", "--tail", &tail, &container_name])
        .output()
        .with_context(|| format!("Failed to run podman logs for {container_name}"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        color_eyre::eyre::bail!("podman logs {container_name} failed: {}", stderr.trim());
    }

    // podman logs writes to both stdout and stderr; combine them
    let mut combined = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr);
    if !stderr.is_empty() {
        if !combined.is_empty() {
            combined.push('\n');
        }
        combined.push_str(&stderr);
    }
    Ok(combined)
}

// ---------------------------------------------------------------------------
// Workspace introspection — direct filesystem access (control plane side)
// ---------------------------------------------------------------------------

use crate::agent_dir;

/// Summary of a devaipod workspace, suitable for the advisor.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkspaceSummary {
    /// Workspace (pod) name, e.g. "my-feature"
    pub name: String,
    /// Source repository URL or path
    pub source: Option<String>,
    /// Task description given at creation
    pub task: Option<String>,
    /// Agent-reported title
    pub title: Option<String>,
    /// Completion status: "active", "done", etc.
    pub completion_status: Option<String>,
    /// RFC 3339 creation timestamp
    pub created: Option<String>,
    /// RFC 3339 last-active timestamp
    pub last_active: Option<String>,
    /// Git repos found in the workspace, with branch and ahead-count info
    pub repos: Vec<WorkspaceRepo>,
}

/// A git repo inside a workspace, with branch info.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkspaceRepo {
    /// Repo directory name
    pub name: String,
    /// Current branch
    pub branch: Option<String>,
    /// Number of commits ahead of the default upstream branch
    pub commits_ahead: Option<u32>,
    /// Short hash of HEAD
    pub head_sha: Option<String>,
}

/// List all workspaces with their state and per-repo git info.
///
/// This runs on the control plane and has direct filesystem access to
/// workspace directories at `~/.local/share/devaipod/workspaces/`.
pub fn list_workspace_summaries() -> Result<Vec<WorkspaceSummary>> {
    let workspaces = agent_dir::list_workspaces()?;
    let mut summaries = Vec::new();

    for (name, path, state) in workspaces {
        let repos = agent_dir::find_git_repos_in_dir(&path);
        let repo_summaries: Vec<WorkspaceRepo> = repos
            .iter()
            .map(|(repo_name, repo_path)| {
                let branch = git_current_branch(repo_path);
                let head_sha = git_short_head(repo_path);
                let commits_ahead = branch
                    .as_ref()
                    .and_then(|_| git_commits_ahead_of_default(repo_path));
                WorkspaceRepo {
                    name: repo_name.clone(),
                    branch,
                    commits_ahead,
                    head_sha,
                }
            })
            .collect();

        summaries.push(WorkspaceSummary {
            name,
            source: state.as_ref().map(|s| s.source.clone()),
            task: state.as_ref().and_then(|s| s.task.clone()),
            title: state.as_ref().and_then(|s| s.title.clone()),
            completion_status: state.as_ref().and_then(|s| s.completion_status.clone()),
            created: state.as_ref().map(|s| s.created.clone()),
            last_active: state.as_ref().and_then(|s| s.last_active.clone()),
            repos: repo_summaries,
        });
    }

    Ok(summaries)
}

/// Get the diff for a specific workspace (all repos combined).
pub fn workspace_diff(workspace_name: &str) -> Result<String> {
    // Validate workspace name to prevent path traversal
    if workspace_name.contains('/')
        || workspace_name.contains('\\')
        || workspace_name.contains("..")
        || workspace_name.is_empty()
    {
        color_eyre::eyre::bail!("Invalid workspace name: {}", workspace_name);
    }
    let base = agent_dir::agent_workdir_base()?;
    let ws_dir = base.join(workspace_name);
    if !ws_dir.exists() {
        color_eyre::eyre::bail!("Workspace '{}' not found", workspace_name);
    }

    let repos = agent_dir::find_git_repos_in_dir(&ws_dir);
    if repos.is_empty() {
        return Ok("No git repos found in workspace.".to_string());
    }

    let mut combined = String::new();
    for (repo_name, repo_path) in &repos {
        // Diff against the default upstream branch, or just show uncommitted changes
        let diff = git_diff_from_default(repo_path);
        if !diff.is_empty() {
            if !combined.is_empty() {
                combined.push_str("\n\n");
            }
            combined.push_str(&format!("=== {} ===\n{}", repo_name, diff));
        }
    }

    if combined.is_empty() {
        Ok("No changes detected.".to_string())
    } else {
        Ok(combined)
    }
}

// ---------------------------------------------------------------------------
// Git helpers (direct filesystem, no podman)
// ---------------------------------------------------------------------------

/// Get the current branch name for a git repo.
fn git_current_branch(repo_path: &std::path::Path) -> Option<String> {
    let output = std::process::Command::new("git")
        .args(["rev-parse", "--abbrev-ref", "HEAD"])
        .current_dir(repo_path)
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let branch = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if branch.is_empty() || branch == "HEAD" {
        None
    } else {
        Some(branch)
    }
}

/// Get the short HEAD SHA for a git repo.
fn git_short_head(repo_path: &std::path::Path) -> Option<String> {
    let output = std::process::Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .current_dir(repo_path)
        .output()
        .ok()?;
    if output.status.success() {
        let sha = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if sha.is_empty() { None } else { Some(sha) }
    } else {
        None
    }
}

/// Count commits ahead of the default upstream branch.
///
/// Tries `origin/main`, then `origin/master`, then gives up.
fn git_commits_ahead_of_default(repo_path: &std::path::Path) -> Option<u32> {
    for upstream in &["origin/main", "origin/master"] {
        let output = std::process::Command::new("git")
            .args(["rev-list", "--count", &format!("{upstream}..HEAD")])
            .current_dir(repo_path)
            .stderr(std::process::Stdio::null())
            .output()
            .ok()?;
        if output.status.success() {
            let count_str = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if let Ok(n) = count_str.parse::<u32>() {
                return Some(n);
            }
        }
    }
    None
}

/// Get the diff of agent changes vs the default upstream branch.
///
/// Shows all commits from the agent's branch that aren't in origin/main (or
/// origin/master). Falls back to `git diff HEAD` for uncommitted changes.
fn git_diff_from_default(repo_path: &std::path::Path) -> String {
    // Try each upstream ref. An empty diff from a successful command means
    // "no changes" (branch matches upstream) — return that rather than
    // falling through to the next ref.
    for upstream in &["origin/main", "origin/master"] {
        let output = std::process::Command::new("git")
            .args(["diff", upstream])
            .current_dir(repo_path)
            .stderr(std::process::Stdio::null())
            .output();
        if let Ok(o) = output {
            if o.status.success() {
                return String::from_utf8_lossy(&o.stdout).to_string();
            }
        }
    }
    // Fallback: show uncommitted changes
    let output = std::process::Command::new("git")
        .args(["diff", "HEAD"])
        .current_dir(repo_path)
        .output();
    match output {
        Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout).to_string(),
        _ => String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn test_draft_store_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("drafts.json");

        let mut store = DraftStore::default();
        let id = store.add(DraftProposal {
            id: String::new(), // will be replaced by add()
            title: "Fix CI flake".into(),
            repo: "myorg/backend".into(),
            task: "Investigate and fix the flaky test in ci.yml".into(),
            rationale: "CI has been red for 3 days".into(),
            priority: Priority::High,
            source: Some("github:myorg/backend#142".into()),
            estimated_scope: Some("small".into()),
            status: ProposalStatus::default(),
            created_at: "2025-01-15T10:00:00Z".into(),
        });

        assert!(!id.is_empty());
        assert_eq!(store.proposals.len(), 1);
        assert_eq!(store.proposals[0].id, id);

        store.save(&path).unwrap();

        let loaded = DraftStore::load(&path).unwrap();
        assert_eq!(loaded.proposals.len(), 1);
        assert_eq!(loaded.proposals[0].title, "Fix CI flake");
        assert_eq!(loaded.proposals[0].priority, Priority::High);
    }

    #[test]
    fn test_draft_store_load_missing_file() {
        let store = DraftStore::load(Path::new("/nonexistent/drafts.json")).unwrap();
        assert!(store.proposals.is_empty());
    }

    #[test]
    fn test_draft_store_filter_by_status() {
        let mut store = DraftStore::default();
        store.add(DraftProposal {
            id: String::new(),
            title: "Task A".into(),
            repo: "org/a".into(),
            task: "Do A".into(),
            rationale: "Because".into(),
            priority: Priority::Low,
            source: None,
            estimated_scope: None,
            status: ProposalStatus::Pending,
            created_at: "2025-01-01T00:00:00Z".into(),
        });
        store.add(DraftProposal {
            id: String::new(),
            title: "Task B".into(),
            repo: "org/b".into(),
            task: "Do B".into(),
            rationale: "Because".into(),
            priority: Priority::Medium,
            source: None,
            estimated_scope: None,
            status: ProposalStatus::Approved,
            created_at: "2025-01-02T00:00:00Z".into(),
        });

        // Note: add() overwrites the status field only if already set,
        // but the status we set in the struct is preserved since add()
        // only replaces the id field.
        // However, add() sets the id, not the status. Let's fix status
        // on the second proposal manually for this test.
        store.proposals[1].status = ProposalStatus::Approved;

        let pending = store.list(Some(&ProposalStatus::Pending));
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].title, "Task A");

        let all = store.list(None);
        assert_eq!(all.len(), 2);
    }

    #[test]
    fn test_update_status() {
        let mut store = DraftStore::default();
        let id = store.add(DraftProposal {
            id: String::new(),
            title: "Test".into(),
            repo: "org/repo".into(),
            task: "Do it".into(),
            rationale: "Why not".into(),
            priority: Priority::Medium,
            source: None,
            estimated_scope: None,
            status: ProposalStatus::Pending,
            created_at: "2025-01-01T00:00:00Z".into(),
        });

        let updated = store.update_status(&id, ProposalStatus::Approved);
        assert!(updated.is_some());
        assert_eq!(updated.unwrap().status, ProposalStatus::Approved);

        let missing = store.update_status("nonexistent", ProposalStatus::Dismissed);
        assert!(missing.is_none());
    }

    #[test]
    fn test_draft_store_corrupt_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bad.json");
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(b"not json").unwrap();

        let result = DraftStore::load(&path);
        assert!(result.is_err());
    }

    #[test]
    fn test_proposal_id_is_nonempty() {
        let id = generate_proposal_id();
        assert!(!id.is_empty());
        // Should be valid hex
        assert!(id.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_serde_priority_roundtrip() {
        let json = serde_json::to_string(&Priority::High).unwrap();
        assert_eq!(json, "\"high\"");
        let parsed: Priority = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, Priority::High);
    }

    #[test]
    fn test_serde_status_default() {
        #[derive(Deserialize)]
        struct Wrapper {
            #[serde(default)]
            status: ProposalStatus,
        }
        let w: Wrapper = serde_json::from_str("{}").unwrap();
        assert_eq!(w.status, ProposalStatus::Pending);
    }

    #[test]
    fn test_workspace_summary_serialization() {
        let summary = WorkspaceSummary {
            name: "devaipod-my-feature".into(),
            source: Some("https://github.com/org/repo".into()),
            task: Some("fix the login bug".into()),
            title: Some("Login Fix".into()),
            completion_status: Some("active".into()),
            created: Some("2026-04-04T12:00:00Z".into()),
            last_active: Some("2026-04-05T08:30:00Z".into()),
            repos: vec![WorkspaceRepo {
                name: "repo".into(),
                branch: Some("fix-login".into()),
                commits_ahead: Some(3),
                head_sha: Some("abc1234".into()),
            }],
        };

        let json = serde_json::to_string_pretty(&summary).unwrap();
        let parsed: WorkspaceSummary = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.name, "devaipod-my-feature");
        assert_eq!(
            parsed.source.as_deref(),
            Some("https://github.com/org/repo")
        );
        assert_eq!(parsed.task.as_deref(), Some("fix the login bug"));
        assert_eq!(parsed.title.as_deref(), Some("Login Fix"));
        assert_eq!(parsed.completion_status.as_deref(), Some("active"));
        assert_eq!(parsed.repos.len(), 1);
        assert_eq!(parsed.repos[0].name, "repo");
        assert_eq!(parsed.repos[0].branch.as_deref(), Some("fix-login"));
        assert_eq!(parsed.repos[0].commits_ahead, Some(3));
        assert_eq!(parsed.repos[0].head_sha.as_deref(), Some("abc1234"));

        // Also test with all-None optional fields
        let minimal = WorkspaceSummary {
            name: "devaipod-bare".into(),
            source: None,
            task: None,
            title: None,
            completion_status: None,
            created: None,
            last_active: None,
            repos: vec![],
        };
        let json2 = serde_json::to_string(&minimal).unwrap();
        let parsed2: WorkspaceSummary = serde_json::from_str(&json2).unwrap();
        assert_eq!(parsed2.name, "devaipod-bare");
        assert!(parsed2.source.is_none());
        assert!(parsed2.repos.is_empty());
    }

    /// Helper to run a git command in a directory, panicking on failure.
    fn run_git(dir: &std::path::Path, args: &[&str]) {
        let output = std::process::Command::new("git")
            .current_dir(dir)
            .args(args)
            .output()
            .expect("failed to execute git");
        assert!(
            output.status.success(),
            "git {:?} failed: {}",
            args,
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[test]
    fn test_git_helpers_on_real_repo() {
        let temp = tempfile::tempdir().unwrap();
        let repo = temp.path().join("test-repo");
        std::fs::create_dir_all(&repo).unwrap();

        // Initialize a repo with a commit on "main"
        run_git(&repo, &["init", "-b", "main"]);
        run_git(&repo, &["config", "user.email", "test@test.com"]);
        run_git(&repo, &["config", "user.name", "Test"]);
        std::fs::write(repo.join("file.txt"), "hello").unwrap();
        run_git(&repo, &["add", "."]);
        run_git(&repo, &["commit", "-m", "initial commit"]);

        // git_current_branch should return "main"
        let branch = git_current_branch(&repo);
        assert_eq!(branch.as_deref(), Some("main"));

        // git_short_head should return a non-empty hex string
        let sha = git_short_head(&repo);
        assert!(sha.is_some(), "expected a short SHA");
        let sha_val = sha.unwrap();
        assert!(!sha_val.is_empty());
        assert!(
            sha_val.chars().all(|c| c.is_ascii_hexdigit()),
            "expected hex SHA, got: {sha_val}"
        );

        // No remote, so commits_ahead_of_default should return None
        let ahead = git_commits_ahead_of_default(&repo);
        assert!(
            ahead.is_none(),
            "expected None without a remote, got: {ahead:?}"
        );

        // Now create a bare "origin" and push, then add a local commit
        let origin = temp.path().join("origin.git");
        std::fs::create_dir_all(&origin).unwrap();
        run_git(&origin, &["init", "--bare", "-b", "main"]);
        run_git(
            &repo,
            &["remote", "add", "origin", origin.to_str().unwrap()],
        );
        run_git(&repo, &["push", "-u", "origin", "main"]);

        // After push, should be 0 ahead
        let ahead = git_commits_ahead_of_default(&repo);
        assert_eq!(ahead, Some(0));

        // Add a local commit, should be 1 ahead
        std::fs::write(repo.join("new.txt"), "new content").unwrap();
        run_git(&repo, &["add", "."]);
        run_git(&repo, &["commit", "-m", "second commit"]);

        let ahead = git_commits_ahead_of_default(&repo);
        assert_eq!(ahead, Some(1));
    }

    #[test]
    fn test_workspace_diff_nonexistent() {
        // workspace_diff checks agent_dir::agent_workdir_base() then looks
        // for a subdirectory matching the workspace name. Using a name that
        // won't exist should produce an error.
        let result = workspace_diff("this-workspace-definitely-does-not-exist-zzzzzz");
        assert!(result.is_err(), "expected error for nonexistent workspace");
        let msg = format!("{}", result.unwrap_err());
        assert!(
            msg.contains("not found") || msg.contains("No such file"),
            "unexpected error message: {msg}"
        );
    }

    #[test]
    fn test_workspace_diff_path_traversal() {
        // Ensure path traversal attempts are rejected
        let traversal_inputs = &["../etc", "foo/bar", "..\\windows", "..", ""];
        for input in traversal_inputs {
            let result = workspace_diff(input);
            assert!(result.is_err(), "expected error for input '{input}'");
            let msg = format!("{}", result.unwrap_err());
            assert!(
                msg.contains("Invalid workspace name"),
                "expected 'Invalid workspace name' for '{input}', got: {msg}"
            );
        }
    }

    #[test]
    fn test_rfc3339_now() {
        let ts = rfc3339_now();
        // Should be a valid RFC 3339 timestamp like "2025-01-15T10:00:00Z"
        assert!(
            ts.ends_with('Z'),
            "expected UTC timestamp ending in Z: {ts}"
        );
        assert_eq!(ts.len(), 20, "expected 20 chars: {ts}");
        assert_eq!(&ts[4..5], "-", "expected dash at pos 4: {ts}");
        assert_eq!(&ts[7..8], "-", "expected dash at pos 7: {ts}");
        assert_eq!(&ts[10..11], "T", "expected T at pos 10: {ts}");
        // Year should be reasonable (2024-2099)
        let year: i64 = ts[0..4].parse().unwrap();
        assert!(year >= 2024 && year <= 2099, "unexpected year: {year}");
    }

    #[test]
    fn test_days_to_ymd_epoch() {
        // Unix epoch: 1970-01-01
        let (y, m, d) = days_to_ymd(0);
        assert_eq!((y, m, d), (1970, 1, 1));
    }

    #[test]
    fn test_days_to_ymd_known_date() {
        // 2025-01-15 is 20103 days after epoch
        // (verified: date -d '2025-01-15' +%s => 1736899200 / 86400 = 20103)
        let (y, m, d) = days_to_ymd(20103);
        assert_eq!((y, m, d), (2025, 1, 15));
    }

    #[test]
    fn test_add_sets_created_at() {
        let mut store = DraftStore::default();
        let id = store.add(DraftProposal {
            id: String::new(),
            title: "Test".into(),
            repo: "org/repo".into(),
            task: "Do it".into(),
            rationale: "Why not".into(),
            priority: Priority::Medium,
            source: None,
            estimated_scope: None,
            status: ProposalStatus::Pending,
            created_at: String::new(), // should be auto-set
        });

        let proposal = store.proposals.iter().find(|p| p.id == id).unwrap();
        assert!(
            !proposal.created_at.is_empty(),
            "created_at should be auto-set"
        );
        assert!(
            proposal.created_at.ends_with('Z'),
            "expected UTC timestamp: {}",
            proposal.created_at
        );
    }

    #[test]
    fn test_git_diff_from_default() {
        let temp = tempfile::tempdir().unwrap();
        let repo = temp.path().join("diff-repo");
        std::fs::create_dir_all(&repo).unwrap();

        // Set up repo with initial commit on "main"
        run_git(&repo, &["init", "-b", "main"]);
        run_git(&repo, &["config", "user.email", "test@test.com"]);
        run_git(&repo, &["config", "user.name", "Test"]);
        std::fs::write(repo.join("base.txt"), "base content").unwrap();
        run_git(&repo, &["add", "."]);
        run_git(&repo, &["commit", "-m", "initial"]);

        // Set up a bare origin and push to create origin/main
        let origin = temp.path().join("origin.git");
        std::fs::create_dir_all(&origin).unwrap();
        run_git(&origin, &["init", "--bare", "-b", "main"]);
        run_git(
            &repo,
            &["remote", "add", "origin", origin.to_str().unwrap()],
        );
        run_git(&repo, &["push", "-u", "origin", "main"]);

        // Now make a local change: add a new file and commit
        std::fs::write(repo.join("feature.txt"), "new feature").unwrap();
        run_git(&repo, &["add", "."]);
        run_git(&repo, &["commit", "-m", "add feature"]);

        let diff = git_diff_from_default(&repo);
        assert!(
            diff.contains("feature.txt"),
            "diff should reference the changed file, got: {diff}"
        );
        assert!(
            diff.contains("new feature"),
            "diff should include the added content"
        );
    }

    #[test]
    fn test_git_diff_from_default_master_fallback() {
        let temp = tempfile::tempdir().unwrap();
        let repo = temp.path().join("master-repo");
        std::fs::create_dir_all(&repo).unwrap();

        // Use "master" as the default branch — no "main" anywhere
        run_git(&repo, &["init", "-b", "master"]);
        run_git(&repo, &["config", "user.email", "test@test.com"]);
        run_git(&repo, &["config", "user.name", "Test"]);
        std::fs::write(repo.join("old.txt"), "old content").unwrap();
        run_git(&repo, &["add", "."]);
        run_git(&repo, &["commit", "-m", "initial on master"]);

        // Set up bare origin with "master" branch
        let origin = temp.path().join("origin.git");
        std::fs::create_dir_all(&origin).unwrap();
        run_git(&origin, &["init", "--bare", "-b", "master"]);
        run_git(
            &repo,
            &["remote", "add", "origin", origin.to_str().unwrap()],
        );
        run_git(&repo, &["push", "-u", "origin", "master"]);

        // Create a local change
        std::fs::write(repo.join("update.txt"), "updated stuff").unwrap();
        run_git(&repo, &["add", "."]);
        run_git(&repo, &["commit", "-m", "add update"]);

        let diff = git_diff_from_default(&repo);
        assert!(
            diff.contains("update.txt"),
            "master fallback diff should reference the changed file, got: {diff}"
        );
        assert!(
            diff.contains("updated stuff"),
            "master fallback diff should include the content"
        );
    }
}
