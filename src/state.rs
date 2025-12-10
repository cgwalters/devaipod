//! State management for the devaipod upcall system.
//!
//! This module tracks which GitHub repos and PRs the agent is allowed to write to.
//! The state is persisted as JSON to a tmpfs file and can be modified via JSON-RPC
//! upcalls from the sandboxed agent.

use std::collections::HashSet;
use std::fs;
use std::io::Write;
use std::path::Path;

use color_eyre::eyre::{bail, Context, Result};
use serde::{Deserialize, Serialize};

/// Path to the state file (tmpfs inside the container)
pub const STATE_FILE_PATH: &str = "/run/devaipod/state.json";

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
}
