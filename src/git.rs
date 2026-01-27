//! Git repository detection and operations
//!
//! This module provides utilities for detecting git repository state and
//! cloning repositories into containers.
//!
//! ## TODO: Git mirror support
//!
//! For faster cloning in environments with many workspaces, we should support
//! local git mirrors/caches. This would allow:
//! - Cloning from a local mirror instead of remote for frequently-used repos
//! - Using `--reference` to share object storage between clones
//! - Automatic mirror population/updates
//!
//! See: git clone --reference, git clone --dissociate

use std::path::Path;
use std::process::Command;

use color_eyre::eyre::{bail, Context, Result};

/// Information about a git repository's state
#[derive(Debug, Clone)]
pub struct GitRepoInfo {
    /// Local path to the repository (for local clone support)
    pub local_path: std::path::PathBuf,
    /// Remote URL (None if no remote configured)
    pub remote_url: Option<String>,
    /// Current commit SHA (full 40-character hash)
    pub commit_sha: String,
    /// Current branch name (None if detached HEAD)
    #[allow(dead_code)] // Useful for future features like branch-based workspace naming
    pub branch: Option<String>,
    /// Whether the working tree has uncommitted changes
    pub is_dirty: bool,
    /// List of uncommitted file paths (for warning messages)
    pub dirty_files: Vec<String>,
}

/// Information about a remote git repository (URL only, no local clone)
#[derive(Debug, Clone)]
pub struct RemoteRepoInfo {
    /// Remote URL to clone from
    pub remote_url: String,
    /// Default branch name (e.g., "main", "master")
    pub default_branch: String,
    /// Repository name (extracted from URL)
    pub repo_name: String,
}

/// Detect git repository information from a local path
///
/// Returns information about the git repository at the given path,
/// including remote URL, current commit, branch, and dirty state.
///
/// # Errors
///
/// Returns an error if:
/// - The path is not a git repository
/// - Git commands fail to execute
pub fn detect_git_info(project_path: &Path) -> Result<GitRepoInfo> {
    // Check if it's a git repo
    let git_dir = project_path.join(".git");
    if !git_dir.exists() {
        bail!(
            "Not a git repository: {}\n\
             devaipod requires a git repository to clone into containers.\n\
             Initialize with: git init && git remote add origin <url>",
            project_path.display()
        );
    }

    // Get remote URL (try 'origin' first, then any remote)
    let remote_url =
        get_remote_url(project_path, "origin").or_else(|| get_first_remote_url(project_path));

    // Get current commit SHA
    let commit_output = Command::new("git")
        .args(["rev-parse", "HEAD"])
        .current_dir(project_path)
        .output()
        .context("Failed to run git rev-parse HEAD")?;

    if !commit_output.status.success() {
        bail!("Failed to get current commit. Is this a git repository with at least one commit?");
    }

    let commit_sha = String::from_utf8_lossy(&commit_output.stdout)
        .trim()
        .to_string();

    // Get current branch (returns None for detached HEAD)
    let branch = get_current_branch(project_path);

    // Check for uncommitted changes
    let status_output = Command::new("git")
        .args(["status", "--porcelain"])
        .current_dir(project_path)
        .output()
        .context("Failed to check git status")?;

    let status_str = String::from_utf8_lossy(&status_output.stdout);
    let dirty_files: Vec<String> = status_str
        .lines()
        .filter(|l| !l.is_empty())
        .map(|l| {
            // Status format: "XY filename" where XY is 2 chars
            if l.len() > 3 {
                l[3..].to_string()
            } else {
                l.to_string()
            }
        })
        .collect();

    let is_dirty = !dirty_files.is_empty();

    Ok(GitRepoInfo {
        local_path: project_path.to_path_buf(),
        remote_url,
        commit_sha,
        branch,
        is_dirty,
        dirty_files,
    })
}

/// Get the URL for a specific remote
fn get_remote_url(project_path: &Path, remote_name: &str) -> Option<String> {
    let output = Command::new("git")
        .args(["remote", "get-url", remote_name])
        .current_dir(project_path)
        .output()
        .ok()?;

    if output.status.success() {
        let url = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if !url.is_empty() {
            return Some(url);
        }
    }
    None
}

/// Get the URL for the first available remote
fn get_first_remote_url(project_path: &Path) -> Option<String> {
    let output = Command::new("git")
        .args(["remote"])
        .current_dir(project_path)
        .output()
        .ok()?;

    if output.status.success() {
        let remotes = String::from_utf8_lossy(&output.stdout);
        if let Some(first_remote) = remotes.lines().next() {
            return get_remote_url(project_path, first_remote);
        }
    }
    None
}

/// Get the current branch name
fn get_current_branch(project_path: &Path) -> Option<String> {
    let output = Command::new("git")
        .args(["symbolic-ref", "--short", "HEAD"])
        .current_dir(project_path)
        .output()
        .ok()?;

    if output.status.success() {
        let branch = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if !branch.is_empty() {
            return Some(branch);
        }
    }
    None
}

/// Generate a shell script to clone and checkout a repository from remote
///
/// Note: For local repos, prefer `clone_from_local_script` which clones from
/// the mounted local .git directory, allowing work with unpushed commits.
///
/// The script will:
/// 1. Clone the repository to the workspace folder
/// 2. Checkout the specific commit
/// 3. Optionally checkout a branch if tracking
#[allow(dead_code)] // Used in tests; may be useful for direct remote clone in future
pub fn clone_script(git_info: &GitRepoInfo, workspace_folder: &str) -> Result<String> {
    let remote_url = git_info.remote_url.as_ref().ok_or_else(|| {
        color_eyre::eyre::eyre!(
            "No git remote configured.\n\
             devaipod requires a git remote to clone into containers.\n\
             Configure with: git remote add origin <url>"
        )
    })?;

    let script = format!(
        r#"
set -e
echo "Cloning repository..."
mkdir -p "$(dirname "{workspace}")"

# Full clone to ensure all history is available for git operations
git clone "{url}" "{workspace}" 2>&1

cd "{workspace}"

# Checkout the exact commit
git checkout "{commit}" 2>&1

echo "Repository cloned successfully at commit {short_commit}"
"#,
        url = remote_url,
        workspace = workspace_folder,
        commit = git_info.commit_sha,
        short_commit = &git_info.commit_sha[..git_info.commit_sha.len().min(8)],
    );

    Ok(script)
}

/// Generate a shell script to clone from a local git repository
///
/// This is used when running `devaipod up .` to clone from the local repo
/// instead of the remote. This allows working with unpushed commits.
///
/// The script expects the host's .git directory to be mounted at /mnt/host-git
///
/// The script will:
/// 1. Clone from the mounted local .git directory
/// 2. Checkout the specific commit
/// 3. Set up the remote URL for push/pull operations
/// 4. Chown the workspace to the target user (since we clone as root)
///
/// `target_user` is the user who will own the workspace (from devcontainer remoteUser/containerUser)
pub fn clone_from_local_script(
    git_info: &GitRepoInfo,
    workspace_folder: &str,
    target_user: Option<&str>,
) -> String {
    // We'll set up the remote after cloning if available
    let setup_remote = if let Some(ref url) = git_info.remote_url {
        format!(
            r#"
# Set up origin remote for push/pull
git remote set-url origin "{url}" 2>/dev/null || git remote add origin "{url}"
"#,
            url = url
        )
    } else {
        String::new()
    };

    format!(
        r#"
set -e
echo "Cloning from local repository..."
mkdir -p "$(dirname "{workspace}")"

# Clone from the mounted local .git directory
# Use --no-hardlinks since we're cloning from a bind mount
git clone --no-hardlinks /mnt/host-git "{workspace}" 2>&1

cd "{workspace}"

# Checkout the exact commit
git checkout "{commit}" 2>&1
{setup_remote}
{chown_cmd}
echo "Repository cloned successfully at commit {short_commit}"
"#,
        workspace = workspace_folder,
        commit = git_info.commit_sha,
        short_commit = &git_info.commit_sha[..git_info.commit_sha.len().min(8)],
        setup_remote = setup_remote,
        chown_cmd = target_user
            .map(|u| format!(
                "# Set ownership to target user\nchown -R {u}:{u} \"{workspace_folder}\""
            ))
            .unwrap_or_default(),
    )
}

/// Generate a shell script to clone from a PR/MR
///
/// The script will:
/// 1. Clone the PR's head repository
/// 2. Checkout the specific commit
/// 3. Add the upstream repository as a remote
pub fn clone_pr_script(pr_info: &crate::forge::PullRequestInfo, workspace_folder: &str) -> String {
    format!(
        r#"
set -e
echo "Cloning PR #{number}: {title}"
mkdir -p "$(dirname "{workspace}")"

# Full clone of PR head (fork) repository for complete git history
git clone --branch "{branch}" "{head_url}" "{workspace}" 2>&1

cd "{workspace}"

# Checkout the exact commit
git checkout "{commit}" 2>&1

# Add upstream as a remote for reference
git remote add upstream "{upstream_url}" 2>/dev/null || true

echo "PR #{number} cloned successfully at commit {short_commit}"
"#,
        number = pr_info.pr_ref.number,
        title = pr_info.title.replace('"', r#"\""#),
        workspace = workspace_folder,
        head_url = pr_info.head_clone_url,
        branch = pr_info.head_ref,
        commit = pr_info.head_sha,
        short_commit = &pr_info.head_sha[..pr_info.head_sha.len().min(8)],
        upstream_url = pr_info.pr_ref.upstream_url(),
    )
}

/// Generate a shell script to clone from a remote git URL
///
/// The script will:
/// 1. Clone the repository's default branch
/// 2. Chown to the target user if specified
pub fn clone_remote_script(
    remote_info: &RemoteRepoInfo,
    workspace_folder: &str,
    target_user: Option<&str>,
) -> String {
    format!(
        r#"
set -e
echo "Cloning repository from {url}..."
mkdir -p "$(dirname "{workspace}")"

# Full clone for complete git history
git clone --branch "{branch}" "{url}" "{workspace}" 2>&1

cd "{workspace}"
{chown_cmd}
echo "Repository cloned successfully"
"#,
        url = remote_info.remote_url,
        workspace = workspace_folder,
        branch = remote_info.default_branch,
        chown_cmd = target_user
            .map(|u| format!(
                "# Set ownership to target user\nchown -R {u}:{u} \"{workspace_folder}\""
            ))
            .unwrap_or_default(),
    )
}

/// Extract repository name from a git URL
///
/// Handles both HTTPS and SSH formats:
/// - https://github.com/owner/repo.git -> repo
/// - git@github.com:owner/repo.git -> repo
pub fn extract_repo_name(url: &str) -> Option<String> {
    // Handle SSH format: git@github.com:owner/repo.git
    if url.starts_with("git@") {
        let path = url.rsplit(':').next()?;
        let repo = path.rsplit('/').next()?;
        return Some(repo.trim_end_matches(".git").to_string());
    }

    // Handle HTTPS format: https://github.com/owner/repo.git
    if let Ok(parsed) = url::Url::parse(url) {
        let path = parsed
            .path()
            .trim_start_matches('/')
            .trim_end_matches(".git");
        let repo = path.rsplit('/').next()?;
        return Some(repo.to_string());
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn test_detect_git_info_not_a_repo() {
        let temp = TempDir::new().unwrap();
        let result = detect_git_info(temp.path());
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Not a git repository"));
    }

    #[test]
    fn test_detect_git_info_empty_repo() {
        let temp = TempDir::new().unwrap();

        // Initialize git repo
        Command::new("git")
            .args(["init"])
            .current_dir(temp.path())
            .output()
            .unwrap();

        // Configure git user for this repo
        Command::new("git")
            .args(["config", "user.email", "test@test.com"])
            .current_dir(temp.path())
            .output()
            .unwrap();
        Command::new("git")
            .args(["config", "user.name", "Test"])
            .current_dir(temp.path())
            .output()
            .unwrap();

        // No commits yet - should fail
        let result = detect_git_info(temp.path());
        assert!(result.is_err());
    }

    #[test]
    fn test_detect_git_info_with_commit() {
        let temp = TempDir::new().unwrap();

        // Initialize and make a commit
        Command::new("git")
            .args(["init"])
            .current_dir(temp.path())
            .output()
            .unwrap();

        Command::new("git")
            .args(["config", "user.email", "test@test.com"])
            .current_dir(temp.path())
            .output()
            .unwrap();
        Command::new("git")
            .args(["config", "user.name", "Test"])
            .current_dir(temp.path())
            .output()
            .unwrap();

        fs::write(temp.path().join("test.txt"), "hello").unwrap();

        Command::new("git")
            .args(["add", "."])
            .current_dir(temp.path())
            .output()
            .unwrap();

        Command::new("git")
            .args(["commit", "-m", "initial"])
            .current_dir(temp.path())
            .output()
            .unwrap();

        let info = detect_git_info(temp.path()).unwrap();

        assert!(info.remote_url.is_none()); // No remote configured
        assert_eq!(info.commit_sha.len(), 40); // Full SHA
        assert!(!info.is_dirty);
        assert!(info.dirty_files.is_empty());
    }

    #[test]
    fn test_detect_git_info_dirty() {
        let temp = TempDir::new().unwrap();

        // Initialize and make a commit
        Command::new("git")
            .args(["init"])
            .current_dir(temp.path())
            .output()
            .unwrap();

        Command::new("git")
            .args(["config", "user.email", "test@test.com"])
            .current_dir(temp.path())
            .output()
            .unwrap();
        Command::new("git")
            .args(["config", "user.name", "Test"])
            .current_dir(temp.path())
            .output()
            .unwrap();

        fs::write(temp.path().join("test.txt"), "hello").unwrap();

        Command::new("git")
            .args(["add", "."])
            .current_dir(temp.path())
            .output()
            .unwrap();

        Command::new("git")
            .args(["commit", "-m", "initial"])
            .current_dir(temp.path())
            .output()
            .unwrap();

        // Make a dirty change
        fs::write(temp.path().join("dirty.txt"), "uncommitted").unwrap();

        let info = detect_git_info(temp.path()).unwrap();

        assert!(info.is_dirty);
        assert!(!info.dirty_files.is_empty());
    }

    #[test]
    fn test_clone_script_no_remote() {
        let info = GitRepoInfo {
            local_path: std::path::PathBuf::from("/tmp/test"),
            remote_url: None,
            commit_sha: "abc123".to_string(),
            branch: None,
            is_dirty: false,
            dirty_files: vec![],
        };

        let result = clone_script(&info, "/workspaces/test");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("No git remote"));
    }

    #[test]
    fn test_clone_script_with_remote() {
        let info = GitRepoInfo {
            local_path: std::path::PathBuf::from("/tmp/test"),
            remote_url: Some("https://github.com/test/repo.git".to_string()),
            commit_sha: "abc123def456".to_string(),
            branch: Some("main".to_string()),
            is_dirty: false,
            dirty_files: vec![],
        };

        let script = clone_script(&info, "/workspaces/test").unwrap();

        assert!(script.contains("git clone"));
        assert!(script.contains("https://github.com/test/repo.git"));
        assert!(script.contains("/workspaces/test"));
        assert!(script.contains("abc123def456"));
    }

    #[test]
    fn test_clone_from_local_script() {
        let info = GitRepoInfo {
            local_path: std::path::PathBuf::from("/home/user/project"),
            remote_url: Some("https://github.com/test/repo.git".to_string()),
            commit_sha: "abc123def456".to_string(),
            branch: Some("feature".to_string()),
            is_dirty: false,
            dirty_files: vec![],
        };

        let script = clone_from_local_script(&info, "/workspaces/test", Some("devenv"));

        assert!(script.contains("git clone"));
        assert!(script.contains("/mnt/host-git"));
        assert!(script.contains("/workspaces/test"));
        assert!(script.contains("abc123def456"));
        assert!(script.contains("origin"));
        assert!(script.contains("chown -R devenv:devenv"));
    }

    #[test]
    fn test_clone_from_local_script_no_user() {
        let info = GitRepoInfo {
            local_path: std::path::PathBuf::from("/home/user/project"),
            remote_url: Some("https://github.com/test/repo.git".to_string()),
            commit_sha: "abc123def456".to_string(),
            branch: Some("feature".to_string()),
            is_dirty: false,
            dirty_files: vec![],
        };

        let script = clone_from_local_script(&info, "/workspaces/test", None);

        assert!(script.contains("git clone"));
        assert!(!script.contains("chown"));
    }

    #[test]
    fn test_extract_repo_name_https() {
        assert_eq!(
            extract_repo_name("https://github.com/owner/repo.git"),
            Some("repo".to_string())
        );
        assert_eq!(
            extract_repo_name("https://github.com/owner/repo"),
            Some("repo".to_string())
        );
        assert_eq!(
            extract_repo_name("https://gitlab.com/group/subgroup/project.git"),
            Some("project".to_string())
        );
    }

    #[test]
    fn test_extract_repo_name_ssh() {
        assert_eq!(
            extract_repo_name("git@github.com:owner/repo.git"),
            Some("repo".to_string())
        );
        assert_eq!(
            extract_repo_name("git@gitlab.com:group/project.git"),
            Some("project".to_string())
        );
    }

    #[test]
    fn test_clone_remote_script() {
        let info = RemoteRepoInfo {
            remote_url: "https://github.com/owner/repo.git".to_string(),
            default_branch: "main".to_string(),
            repo_name: "repo".to_string(),
        };

        let script = clone_remote_script(&info, "/workspaces/repo", Some("devenv"));

        assert!(script.contains("git clone"));
        assert!(script.contains("https://github.com/owner/repo.git"));
        assert!(script.contains("/workspaces/repo"));
        assert!(script.contains("--branch \"main\""));
        assert!(script.contains("chown -R devenv:devenv"));
    }
}
