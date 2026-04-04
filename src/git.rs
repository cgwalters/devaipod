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

use color_eyre::eyre::{Context, Result, bail};
use std::path::Path;
use std::process::Command;

// Git remote name constants
// These names are used consistently across workspace and worker pods.

/// The main upstream repository (where PRs merge to, the source of truth)
pub const REMOTE_ORIGIN: &str = "origin";

/// The user's fork (present when working on a PR from a fork, or when the
/// authenticated user has a fork of the upstream repository)
pub const REMOTE_FORK: &str = "fork";

// Cross-container remotes for collaboration:

/// In workspace container: points to agent's workspace git.
/// Currently unused since agent pods no longer have a workspace container,
/// but retained for future standalone devcontainer mode.
#[allow(dead_code)]
pub const REMOTE_AGENT: &str = "agent";

/// In agent container: points to human's workspace git
pub const REMOTE_WORKSPACE: &str = "workspace";

/// In task owner (agent) container: points to worker's workspace git
pub const REMOTE_WORKER: &str = "worker";

/// In worker container: points to task owner's workspace git
pub const REMOTE_OWNER: &str = "owner";

/// Generate a branch name for an agent workspace.
///
/// Uses the `devaipod/` namespace so agent branches are easily
/// identifiable via `git branch --list 'devaipod/*'` after
/// `devaipod fetch`.
pub fn agent_branch_name(slug: &str) -> String {
    format!("devaipod/{}", slug)
}

/// Get a GitHub token from the environment (checks GH_TOKEN and GITHUB_TOKEN)
pub fn get_github_token() -> Option<String> {
    std::env::var("GH_TOKEN")
        .or_else(|_| std::env::var("GITHUB_TOKEN"))
        .ok()
}

/// Get a GitHub token, checking environment variables first, then podman secrets.
///
/// Checks in order:
/// 1. `GH_TOKEN` environment variable
/// 2. `GITHUB_TOKEN` environment variable
/// 3. Podman secret configured in `[trusted]` section for `GH_TOKEN`
///
/// Returns `None` if no token is available.
pub fn get_github_token_with_secret(config: &crate::config::Config) -> Option<String> {
    // First check environment variables
    if let Some(token) = get_github_token() {
        return Some(token);
    }

    // Then check for a GH_TOKEN secret in the trusted config
    for (env_var, secret_name) in config.trusted_env.secret_mounts() {
        if (env_var == "GH_TOKEN" || env_var == "GITHUB_TOKEN")
            && let Some(token) = read_podman_secret(&secret_name)
        {
            return Some(token);
        }
    }

    None
}

/// Read a podman secret value by name.
///
/// Returns `None` if the secret doesn't exist or can't be read.
fn read_podman_secret(secret_name: &str) -> Option<String> {
    let output = Command::new("podman")
        .args(["secret", "inspect", "--showsecret", secret_name])
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    // Parse JSON output: [{"SecretData": "token_value\n", ...}]
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).ok()?;
    let secret_data = json
        .as_array()?
        .first()?
        .get("SecretData")?
        .as_str()?
        .trim();

    if secret_data.is_empty() {
        None
    } else {
        Some(secret_data.to_string())
    }
}

/// Convert a GitHub HTTPS URL to an authenticated URL using a token.
///
/// Takes `https://github.com/owner/repo.git` and returns
/// `https://x-access-token:TOKEN@github.com/owner/repo.git`
///
/// For non-GitHub URLs or SSH URLs, returns the original URL unchanged.
pub fn authenticated_clone_url(url: &str, token: Option<&str>) -> String {
    let Some(token) = token else {
        return url.to_string();
    };

    // Only modify HTTPS GitHub URLs
    if !url.starts_with("https://github.com/") {
        return url.to_string();
    }

    // Insert the token as x-access-token
    url.replacen(
        "https://github.com/",
        &format!("https://x-access-token:{token}@github.com/"),
        1,
    )
}

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
    pub branch: Option<String>,
    /// Whether the working tree has uncommitted changes
    pub is_dirty: bool,
    /// List of uncommitted file paths (for warning messages)
    pub dirty_files: Vec<String>,
    /// URL of the authenticated user's fork, if detected
    pub fork_url: Option<String>,
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
    /// URL of the authenticated user's fork, if detected
    pub fork_url: Option<String>,
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
        get_remote_url(project_path, REMOTE_ORIGIN).or_else(|| get_first_remote_url(project_path));

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
        fork_url: None,
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

/// Generate the git checkout command, preferring branch checkout over detached HEAD.
///
/// When a branch name is available, uses `git checkout -B <branch> <sha>` to create
/// (or reset) a local branch at the given commit. This avoids detached HEAD state,
/// which is confusing for agents and users working in the container.
///
/// When `slug` is provided, uses `devaipod/<slug>` as the branch name (for agent
/// workspaces). This makes agent branches discoverable via
/// `git branch --list 'devaipod/*'` after `devaipod fetch`.
///
/// When no branch is known and no slug is provided, creates a `devaipod-work`
/// branch rather than leaving HEAD detached, since detached HEAD confuses
/// agents that need to commit.
fn checkout_cmd(commit: &str, branch: Option<&str>, slug: Option<&str>) -> String {
    let branch_name = if let Some(slug) = slug {
        agent_branch_name(slug)
    } else {
        branch.unwrap_or("devaipod-work").to_string()
    };
    format!(r#"git checkout -B "{branch_name}" "{commit}" 2>&1"#)
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

    let checkout = checkout_cmd(&git_info.commit_sha, git_info.branch.as_deref(), None);

    let script = format!(
        r#"
set -e
echo "Cloning repository..."
mkdir -p "$(dirname "{workspace}")"

# Full clone to ensure all history is available for git operations
git clone "{url}" "{workspace}" 2>&1

cd "{workspace}"

# Checkout the exact commit (on a branch when possible to avoid detached HEAD)
{checkout}

echo "Repository cloned successfully at commit {short_commit}"
"#,
        url = remote_url,
        workspace = workspace_folder,
        checkout = checkout,
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
git remote set-url {REMOTE_ORIGIN} "{url}" 2>/dev/null || git remote add {REMOTE_ORIGIN} "{url}"
"#,
            url = url,
            REMOTE_ORIGIN = REMOTE_ORIGIN
        )
    } else {
        String::new()
    };

    // Add fork remote if the user has a fork of this repo
    let fork_remote_setup = if let Some(ref fork_url) = git_info.fork_url {
        format!(
            r#"
# Add '{REMOTE_FORK}' remote pointing to user's fork
git remote add {REMOTE_FORK} "{fork_url}" 2>/dev/null || git remote set-url {REMOTE_FORK} "{fork_url}"
"#,
            REMOTE_FORK = REMOTE_FORK,
            fork_url = fork_url
        )
    } else {
        String::new()
    };

    let checkout = checkout_cmd(&git_info.commit_sha, git_info.branch.as_deref(), None);

    format!(
        r#"
set -e
echo "Cloning from local repository..."
mkdir -p "$(dirname "{workspace}")"

# Mark the host-mounted git directory as safe (different ownership in container)
git config --global --add safe.directory /mnt/host-git

# Clone from the mounted local .git directory
# Use --no-hardlinks since we're cloning from a bind mount
git clone --no-hardlinks /mnt/host-git "{workspace}" 2>&1

cd "{workspace}"

# Checkout the exact commit (on a branch when possible to avoid detached HEAD)
{checkout}
{setup_remote}
{fork_remote_setup}{chown_cmd}
echo "Repository cloned successfully at commit {short_commit}"
"#,
        workspace = workspace_folder,
        checkout = checkout,
        short_commit = &git_info.commit_sha[..git_info.commit_sha.len().min(8)],
        setup_remote = setup_remote,
        fork_remote_setup = fork_remote_setup,
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
/// 1. Clone the PR's head repository (the fork, using authenticated URL if token provided)
/// 2. Checkout the specific commit
/// 3. Set up remotes:
///    - `origin` points to the upstream repo (where the PR will merge to)
///    - `fork` points to the PR author's fork (only if PR is from a fork)
///
/// `gh_token` is an optional GitHub token for cloning private repositories.
pub fn clone_pr_script(
    pr_info: &crate::forge::PullRequestInfo,
    workspace_folder: &str,
    gh_token: Option<&str>,
) -> String {
    // Use authenticated URL for cloning if token is provided
    let clone_url = authenticated_clone_url(&pr_info.head_clone_url, gh_token);
    let upstream_url = pr_info.pr_ref.upstream_url();
    // The fork URL without embedded token (for storing in .git/config)
    let fork_url = &pr_info.head_clone_url;

    // Only add fork remote if PR is actually from a fork (different repo)
    let is_from_fork = fork_url != &upstream_url;
    let fork_remote_setup = if is_from_fork {
        format!(
            r#"
# Add '{REMOTE_FORK}' remote pointing to PR author's fork
git remote add {REMOTE_FORK} "{fork_url}" 2>/dev/null || git remote set-url {REMOTE_FORK} "{fork_url}"
"#,
            REMOTE_FORK = REMOTE_FORK,
            fork_url = fork_url
        )
    } else {
        // PR is from a branch in the same repo, no fork remote needed
        String::new()
    };

    let checkout = checkout_cmd(&pr_info.head_sha, Some(&pr_info.head_ref), None);

    format!(
        r#"
set -e
echo "Cloning PR #{number}: {title}"
mkdir -p "$(dirname "{workspace}")"

# Full clone of PR head repository for complete git history
git clone --branch "{branch}" "{clone_url}" "{workspace}" 2>&1

cd "{workspace}"

# Checkout the exact commit (on the PR branch to avoid detached HEAD)
{checkout}

# Set 'origin' to point to the upstream repo (where PR merges to)
git remote set-url {REMOTE_ORIGIN} "{upstream_url}"
{fork_remote_setup}
echo "PR #{number} cloned successfully at commit {short_commit}"
"#,
        number = pr_info.pr_ref.number,
        title = pr_info.title.replace('"', r#"\""#),
        workspace = workspace_folder,
        clone_url = clone_url,
        branch = pr_info.head_ref,
        checkout = checkout,
        short_commit = &pr_info.head_sha[..pr_info.head_sha.len().min(8)],
        upstream_url = upstream_url,
        fork_remote_setup = fork_remote_setup,
        REMOTE_ORIGIN = REMOTE_ORIGIN,
    )
}

/// Generate a shell script to clone from a remote git URL
///
/// The script will:
/// 1. Clone the repository's default branch (using authenticated URL if token provided)
/// 2. Reset the remote URL to the original (unauthenticated) URL
/// 3. Chown to the target user if specified
///
/// `gh_token` is an optional GitHub token for cloning private repositories.
pub fn clone_remote_script(
    remote_info: &RemoteRepoInfo,
    workspace_folder: &str,
    target_user: Option<&str>,
    gh_token: Option<&str>,
) -> String {
    // Use authenticated URL for cloning if token is provided
    let clone_url = authenticated_clone_url(&remote_info.remote_url, gh_token);

    // After cloning, reset the remote to the original URL (without token)
    // so the token isn't stored in .git/config
    let reset_remote = if gh_token.is_some() {
        format!(
            "\n# Reset remote URL to remove embedded token\ngit remote set-url {REMOTE_ORIGIN} \"{url}\"\n",
            REMOTE_ORIGIN = REMOTE_ORIGIN,
            url = remote_info.remote_url
        )
    } else {
        String::new()
    };

    // Add fork remote if the user has a fork of this repo
    let fork_remote_setup = if let Some(ref fork_url) = remote_info.fork_url {
        format!(
            r#"
# Add '{REMOTE_FORK}' remote pointing to user's fork
git remote add {REMOTE_FORK} "{fork_url}" 2>/dev/null || git remote set-url {REMOTE_FORK} "{fork_url}"
"#,
            REMOTE_FORK = REMOTE_FORK,
            fork_url = fork_url
        )
    } else {
        String::new()
    };

    format!(
        r#"
set -e
echo "Cloning repository from {display_url}..."
mkdir -p "$(dirname "{workspace}")"

# Full clone for complete git history
git clone --branch "{branch}" "{clone_url}" "{workspace}" 2>&1

cd "{workspace}"
{reset_remote}{fork_remote_setup}{chown_cmd}
echo "Repository cloned successfully"
"#,
        display_url = remote_info.remote_url, // Don't log the token
        clone_url = clone_url,
        workspace = workspace_folder,
        branch = remote_info.default_branch,
        reset_remote = reset_remote,
        fork_remote_setup = fork_remote_setup,
        chown_cmd = target_user
            .map(|u| format!(
                "# Set ownership to target user\nchown -R {u}:{u} \"{workspace_folder}\""
            ))
            .unwrap_or_default(),
    )
}

/// Generate a shell script to clone or update dotfiles in a volume
///
/// The script will:
/// 1. If the target directory already exists with a git repo, update it
/// 2. Otherwise, clone the dotfiles repository fresh
/// 3. Print the git SHA for logging
/// 4. Reset the remote URL to remove any embedded token
///
/// Returns (script, commit_sha_will_be_echoed_with_prefix)
/// The caller should look for lines starting with "DOTFILES_SHA:" to extract the SHA.
///
/// `gh_token` is an optional GitHub token for cloning private repositories.
pub fn clone_dotfiles_script(
    dotfiles_url: &str,
    target_dir: &str,
    gh_token: Option<&str>,
) -> String {
    // Use authenticated URL for cloning if token is provided
    let clone_url = authenticated_clone_url(dotfiles_url, gh_token);

    // After cloning/updating, reset the remote to the original URL (without token)
    let reset_remote = if gh_token.is_some() {
        format!("git remote set-url origin \"{}\"", dotfiles_url)
    } else {
        String::new()
    };

    format!(
        r#"
set -e
if [ -d "{target_dir}/.git" ]; then
    echo "Dotfiles already cloned, updating from {display_url}..."
    cd "{target_dir}"
    # Set authenticated URL for fetch if token provided
    git remote set-url origin "{clone_url}"
    git fetch --depth 1 origin
    git reset --hard origin/HEAD
    {reset_remote}
else
    echo "Cloning dotfiles from {display_url}..."
    rm -rf "{target_dir}"
    git clone --depth 1 "{clone_url}" "{target_dir}"
    cd "{target_dir}"
    {reset_remote}
fi
DOTFILES_SHA=$(git rev-parse HEAD)
echo "DOTFILES_SHA:$DOTFILES_SHA"
echo "Dotfiles ready"
"#,
        display_url = dotfiles_url, // Don't log the token
        clone_url = clone_url,
        target_dir = target_dir,
        reset_remote = reset_remote,
    )
}

/// Generate a shell script to clone a git repo for the agent using --reference
/// to share objects with the main workspace clone.
///
/// This enables efficient disk usage by sharing git objects between the main
/// workspace and the agent's isolated workspace. The agent gets its own working
/// tree but shares the object database with the reference repository.
///
/// The script will:
/// 1. Clone from the local reference repository (fast, no network access needed)
/// 2. Set up the same remote URL as the main workspace
/// 3. Checkout the same commit as the main workspace
/// 4. Optionally chown to target user
///
/// Parameters:
/// - `workspace_folder`: Target path for the clone (e.g., "/workspaces/project")
/// - `reference_git_path`: Path to the reference .git directory (e.g., "/mnt/main-workspace")
/// - `git_info`: Git repository info from the main workspace
/// - `target_user`: Optional user to chown the workspace to
pub fn clone_agent_workspace_script(
    workspace_folder: &str,
    reference_git_path: &str,
    git_info: &GitRepoInfo,
    target_user: Option<&str>,
    slug: Option<&str>,
) -> String {
    // Clone from the local reference repository's .git directory using --shared.
    // This is much faster than cloning from remote since all objects are local.
    // --shared creates an alternates file to share objects with the reference repo,
    // avoiding object duplication and saving disk space.
    let clone_source = format!(
        r#"# Clone from local reference workspace with shared objects
git clone --shared "{reference}/.git" "{workspace}" 2>&1"#,
        reference = reference_git_path,
        workspace = workspace_folder,
    );

    // Set up remote if we have a URL
    let setup_remote = if let Some(ref url) = git_info.remote_url {
        format!(
            r#"
# Ensure origin remote is set correctly
git remote set-url origin "{url}" 2>/dev/null || git remote add origin "{url}"
"#,
            url = url
        )
    } else {
        String::new()
    };

    let checkout = checkout_cmd(&git_info.commit_sha, git_info.branch.as_deref(), slug);

    format!(
        r#"
set -e
echo "Cloning agent workspace with reference to main workspace..."
mkdir -p "$(dirname "{workspace}")"

# Mark the reference git directory as safe (different ownership in container)
git config --global --add safe.directory "{reference}/.git"
git config --global --add safe.directory "{reference}"

{clone_source}

cd "{workspace}"

# Checkout the exact commit from the main workspace (on a branch when possible to avoid detached HEAD)
{checkout}
{setup_remote}
{chown_cmd}
echo "Agent workspace cloned successfully at commit {short_commit}"
"#,
        workspace = workspace_folder,
        reference = reference_git_path,
        clone_source = clone_source,
        checkout = checkout,
        setup_remote = setup_remote,
        short_commit = &git_info.commit_sha[..git_info.commit_sha.len().min(8)],
        chown_cmd = target_user
            .map(|u| format!(
                "# Set ownership to target user\nchown -R {u}:{u} \"{workspace_folder}\""
            ))
            .unwrap_or_default(),
    )
}

/// Generate script to clone the worker workspace from the task owner's workspace
///
/// The worker gets its own isolated git clone. We use `--shared` for fast initial
/// cloning, then immediately dissociate (repack and remove alternates) to make the
/// clone self-contained. This is necessary because:
///
/// 1. The alternates file would point to `/mnt/owner-workspace/...` paths
/// 2. When the task owner fetches from the worker (mounted at `/mnt/worker-workspace`),
///    git tries to follow the alternates, but those paths don't exist in the owner's
///    container (it has `/mnt/main-workspace`, not `/mnt/owner-workspace`)
///
/// The script:
/// 1. Clones from the task owner's workspace using --shared (fast, no network)
/// 2. Dissociates: repacks all objects locally and removes the alternates file
/// 3. Sets up an `owner` remote pointing to the task owner's workspace
/// 4. Checkouts the same commit as the task owner
/// 5. Optionally chowns to target user
///
/// Parameters:
/// - `workspace_folder`: Target path for the clone (e.g., "/workspaces/project")
/// - `reference_git_path`: Path to the task owner's workspace (e.g., "/mnt/owner-workspace/project")
/// - `git_info`: Git repository info from the task owner's workspace
/// - `target_user`: Optional user to chown the workspace to
pub fn clone_worker_workspace_script(
    workspace_folder: &str,
    reference_git_path: &str,
    git_info: &GitRepoInfo,
    target_user: Option<&str>,
) -> String {
    // Clone from the task owner's workspace using --shared for speed,
    // then dissociate to make the clone self-contained.
    let clone_source = format!(
        r#"# Clone from task owner workspace with shared objects (for speed)
git clone --shared "{reference}/.git" "{workspace}" 2>&1

cd "{workspace}"

# Dissociate: repack all objects locally and remove alternates file
# This makes the clone self-contained, which is necessary because the alternates
# path (/mnt/owner-workspace/...) won't exist when others fetch from this repo
git repack -a -d
rm -f .git/objects/info/alternates"#,
        reference = reference_git_path,
        workspace = workspace_folder,
    );

    // Set up remotes: origin for upstream, owner for task owner's workspace
    let setup_remotes = if let Some(ref url) = git_info.remote_url {
        format!(
            r#"
# Ensure origin remote is set correctly
git remote set-url {REMOTE_ORIGIN} "{url}" 2>/dev/null || git remote add {REMOTE_ORIGIN} "{url}"

# Add '{REMOTE_OWNER}' remote pointing to task owner's workspace for fetching their commits
git remote add {REMOTE_OWNER} "{reference}/.git" 2>/dev/null || git remote set-url {REMOTE_OWNER} "{reference}/.git"
"#,
            url = url,
            reference = reference_git_path,
            REMOTE_ORIGIN = REMOTE_ORIGIN,
            REMOTE_OWNER = REMOTE_OWNER,
        )
    } else {
        // Even without origin URL, add the owner remote
        format!(
            r#"
# Add '{REMOTE_OWNER}' remote pointing to task owner's workspace for fetching their commits
git remote add {REMOTE_OWNER} "{reference}/.git" 2>/dev/null || git remote set-url {REMOTE_OWNER} "{reference}/.git"
"#,
            reference = reference_git_path,
            REMOTE_OWNER = REMOTE_OWNER,
        )
    };

    let checkout = checkout_cmd(&git_info.commit_sha, git_info.branch.as_deref(), None);

    format!(
        r#"
set -e
echo "Cloning worker workspace from task owner workspace..."
mkdir -p "$(dirname "{workspace}")"

# Mark the reference git directories as safe (different ownership in container)
git config --global --add safe.directory "{reference}/.git"
git config --global --add safe.directory "{reference}"

{clone_source}

# Checkout the exact commit from the task owner's workspace (on a branch when possible to avoid detached HEAD)
{checkout}
{setup_remotes}
{chown_cmd}
echo "Worker workspace cloned successfully at commit {short_commit}"
"#,
        workspace = workspace_folder,
        reference = reference_git_path,
        clone_source = clone_source,
        checkout = checkout,
        setup_remotes = setup_remotes,
        short_commit = &git_info.commit_sha[..git_info.commit_sha.len().min(8)],
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
        let repo = path
            .trim_end_matches('/')
            .rsplit('/')
            .next()?
            .trim_end_matches(".git");
        if repo.is_empty() {
            return None;
        }
        return Some(repo.to_string());
    }

    // Handle HTTPS format: https://github.com/owner/repo.git
    if let Ok(parsed) = url::Url::parse(url) {
        let path = parsed
            .path()
            .trim_start_matches('/')
            .trim_end_matches('/')
            .trim_end_matches(".git");
        let repo = path.rsplit('/').next()?;
        if repo.is_empty() {
            return None;
        }
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
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Not a git repository")
        );
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
            fork_url: None,
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
            fork_url: None,
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
            fork_url: None,
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
            fork_url: None,
        };

        let script = clone_from_local_script(&info, "/workspaces/test", None);

        assert!(script.contains("git clone"));
        assert!(!script.contains("chown"));
    }

    #[test]
    fn test_extract_repo_name() {
        let cases = [
            // HTTPS URLs
            ("https://github.com/owner/repo.git", Some("repo")),
            ("https://github.com/owner/repo", Some("repo")),
            (
                "https://gitlab.com/group/subgroup/project.git",
                Some("project"),
            ),
            // Trailing slashes
            ("https://github.com/owner/repo/", Some("repo")),
            ("https://github.com/bootc-dev/bootc/", Some("bootc")),
            // SSH URLs
            ("git@github.com:owner/repo.git", Some("repo")),
            ("git@gitlab.com:group/project.git", Some("project")),
            ("git@github.com:owner/repo", Some("repo")),
            ("git@github.com:owner/repo/", Some("repo")),
            ("git@github.com:owner/repo.git/", Some("repo")),
            // Invalid/edge cases
            ("https://github.com/", None),
            ("not-a-url", None),
        ];
        for (url, expected) in cases {
            assert_eq!(
                extract_repo_name(url),
                expected.map(String::from),
                "failed for URL: {url}"
            );
        }
    }

    #[test]
    fn test_clone_remote_script() {
        let info = RemoteRepoInfo {
            remote_url: "https://github.com/owner/repo.git".to_string(),
            default_branch: "main".to_string(),
            repo_name: "repo".to_string(),
            fork_url: None,
        };

        let script = clone_remote_script(&info, "/workspaces/repo", Some("devenv"), None);

        assert!(script.contains("git clone"));
        assert!(script.contains("https://github.com/owner/repo.git"));
        assert!(script.contains("/workspaces/repo"));
        assert!(script.contains("--branch \"main\""));
        assert!(script.contains("chown -R devenv:devenv"));
    }

    #[test]
    fn test_clone_remote_script_with_token() {
        let info = RemoteRepoInfo {
            remote_url: "https://github.com/owner/repo.git".to_string(),
            default_branch: "main".to_string(),
            repo_name: "repo".to_string(),
            fork_url: None,
        };

        let script = clone_remote_script(&info, "/workspaces/repo", None, Some("ghp_secret123"));

        // Should use authenticated URL in clone command
        assert!(script.contains("x-access-token:ghp_secret123@github.com"));
        // Should reset remote to original URL after clone
        assert!(script.contains("git remote set-url origin"));
        assert!(script.contains("https://github.com/owner/repo.git"));
        // Display message should NOT contain the token
        assert!(script.contains("Cloning repository from https://github.com/owner/repo.git"));
    }

    #[test]
    fn test_clone_remote_script_with_fork() {
        let info = RemoteRepoInfo {
            remote_url: "https://github.com/upstream/repo.git".to_string(),
            default_branch: "main".to_string(),
            repo_name: "repo".to_string(),
            fork_url: Some("https://github.com/myuser/repo.git".to_string()),
        };

        let script = clone_remote_script(&info, "/workspaces/repo", None, None);

        // Should add the fork remote
        assert!(
            script.contains("git remote add fork"),
            "should add fork remote"
        );
        assert!(
            script.contains("https://github.com/myuser/repo.git"),
            "should use the fork URL"
        );
    }

    #[test]
    fn test_clone_remote_script_without_fork() {
        let info = RemoteRepoInfo {
            remote_url: "https://github.com/owner/repo.git".to_string(),
            default_branch: "main".to_string(),
            repo_name: "repo".to_string(),
            fork_url: None,
        };

        let script = clone_remote_script(&info, "/workspaces/repo", None, None);

        // Should NOT add a fork remote
        assert!(
            !script.contains("git remote add fork"),
            "should not add fork remote when no fork detected"
        );
    }

    #[test]
    fn test_clone_from_local_script_with_fork() {
        let info = GitRepoInfo {
            local_path: std::path::PathBuf::from("/home/user/project"),
            remote_url: Some("https://github.com/upstream/repo.git".to_string()),
            commit_sha: "abc123def456".to_string(),
            branch: Some("main".to_string()),
            is_dirty: false,
            dirty_files: vec![],
            fork_url: Some("https://github.com/myuser/repo.git".to_string()),
        };

        let script = clone_from_local_script(&info, "/workspaces/test", None);

        assert!(
            script.contains("git remote add fork"),
            "should add fork remote"
        );
        assert!(
            script.contains("https://github.com/myuser/repo.git"),
            "should use the fork URL"
        );
    }

    #[test]
    fn test_authenticated_clone_url() {
        // GitHub HTTPS URL should be modified
        assert_eq!(
            authenticated_clone_url("https://github.com/owner/repo.git", Some("token123")),
            "https://x-access-token:token123@github.com/owner/repo.git"
        );

        // Non-GitHub URL should be unchanged
        assert_eq!(
            authenticated_clone_url("https://gitlab.com/owner/repo.git", Some("token123")),
            "https://gitlab.com/owner/repo.git"
        );

        // No token should return original URL
        assert_eq!(
            authenticated_clone_url("https://github.com/owner/repo.git", None),
            "https://github.com/owner/repo.git"
        );
    }

    #[test]
    fn test_clone_dotfiles_script() {
        let script = clone_dotfiles_script(
            "https://github.com/user/dotfiles.git",
            "/home/agent/.dotfiles",
            None,
        );

        // Should handle both fresh clone and update cases
        assert!(script.contains("if [ -d \"/home/agent/.dotfiles/.git\" ]"));
        assert!(script.contains("git clone"));
        assert!(script.contains("git fetch --depth 1"));
        assert!(script.contains("https://github.com/user/dotfiles.git"));
        assert!(script.contains("/home/agent/.dotfiles"));
        assert!(script.contains("DOTFILES_SHA:"));
        // No token means no x-access-token in URL
        assert!(!script.contains("x-access-token"));
    }

    #[test]
    fn test_clone_dotfiles_script_with_token() {
        let script = clone_dotfiles_script(
            "https://github.com/user/dotfiles.git",
            "/home/agent/.dotfiles",
            Some("ghp_secret123"),
        );

        // Should use authenticated URL in clone command
        assert!(script.contains("x-access-token:ghp_secret123@github.com"));
        // Should reset remote to original URL after clone (both in update and clone paths)
        assert!(script.contains("git remote set-url origin"));
        assert!(script.contains("https://github.com/user/dotfiles.git"));
        // Display messages should NOT contain the token
        assert!(script.contains("Cloning dotfiles from https://github.com/user/dotfiles.git"));
        assert!(script.contains(
            "Dotfiles already cloned, updating from https://github.com/user/dotfiles.git"
        ));
        // Should output SHA with prefix for parsing
        assert!(script.contains("DOTFILES_SHA:$DOTFILES_SHA"));
    }

    #[test]
    fn test_clone_agent_workspace_script_with_remote() {
        let info = GitRepoInfo {
            local_path: std::path::PathBuf::from("/home/user/project"),
            remote_url: Some("https://github.com/owner/repo.git".to_string()),
            commit_sha: "abc123def456789".to_string(),
            branch: Some("main".to_string()),
            is_dirty: false,
            dirty_files: vec![],
            fork_url: None,
        };

        let script = clone_agent_workspace_script(
            "/workspaces/project",
            "/mnt/main-workspace",
            &info,
            Some("devenv"),
            Some("my-workspace"),
        );

        // Should clone from local reference with shared objects
        assert!(
            script.contains("--shared"),
            "should use --shared to share objects via alternates"
        );
        // Should reference the main workspace
        assert!(
            script.contains("/mnt/main-workspace/.git"),
            "should reference main workspace .git"
        );
        // Should set up remote URL after cloning (not clone from remote)
        assert!(
            script.contains("https://github.com/owner/repo.git"),
            "should configure remote URL"
        );
        // Should checkout the exact commit
        assert!(
            script.contains("abc123def456789"),
            "should checkout the commit"
        );
        // Should use devaipod/<slug> branch naming
        assert!(
            script.contains("devaipod/my-workspace"),
            "should use devaipod/<slug> branch naming"
        );
        // Should set up origin remote
        assert!(
            script.contains("git remote set-url origin")
                || script.contains("git remote add origin"),
            "should configure origin remote"
        );
        // Should chown to target user
        assert!(
            script.contains("chown -R devenv:devenv"),
            "should chown to target user"
        );
        // Should mark directories as safe
        assert!(
            script.contains("safe.directory"),
            "should mark directories as safe"
        );
    }

    #[test]
    fn test_clone_agent_workspace_script_no_remote() {
        let info = GitRepoInfo {
            local_path: std::path::PathBuf::from("/home/user/project"),
            remote_url: None,
            commit_sha: "abc123def456789".to_string(),
            branch: None,
            is_dirty: false,
            dirty_files: vec![],
            fork_url: None,
        };

        let script = clone_agent_workspace_script(
            "/workspaces/project",
            "/mnt/main-workspace",
            &info,
            None,
            Some("test-pod"),
        );

        // Should clone directly from reference with shared objects
        assert!(
            script.contains("clone --shared \"/mnt/main-workspace/.git\""),
            "should clone from reference .git directory with shared objects"
        );
        // Should checkout the exact commit
        assert!(
            script.contains("abc123def456789"),
            "should checkout the commit"
        );
        // Should use devaipod/<slug> branch naming even without source branch
        assert!(
            script.contains("devaipod/test-pod"),
            "should use devaipod/<slug> branch naming"
        );
        // Should NOT have chown (no target user)
        assert!(
            !script.contains("chown"),
            "should not chown without target user"
        );
    }

    #[test]
    fn test_clone_agent_workspace_script_no_user() {
        let info = GitRepoInfo {
            local_path: std::path::PathBuf::from("/home/user/project"),
            remote_url: Some("https://github.com/owner/repo.git".to_string()),
            commit_sha: "abc123def456789".to_string(),
            branch: Some("feature".to_string()),
            is_dirty: false,
            dirty_files: vec![],
            fork_url: None,
        };

        let script = clone_agent_workspace_script(
            "/workspaces/project",
            "/mnt/main-workspace",
            &info,
            None, // No target user
            Some("feat-ws"),
        );

        // Should still clone from local reference with shared objects
        assert!(script.contains("--shared"));
        // Should use devaipod/<slug> branch naming
        assert!(
            script.contains("devaipod/feat-ws"),
            "should use devaipod/<slug> branch naming"
        );
        // Should NOT have chown
        assert!(
            !script.contains("chown"),
            "should not chown without target user"
        );
    }

    #[test]
    fn test_clone_worker_workspace_script_with_remote() {
        let info = GitRepoInfo {
            local_path: std::path::PathBuf::from("/home/user/project"),
            remote_url: Some("https://github.com/owner/repo.git".to_string()),
            commit_sha: "abc123def456789".to_string(),
            branch: Some("main".to_string()),
            is_dirty: false,
            dirty_files: vec![],
            fork_url: None,
        };

        let script = clone_worker_workspace_script(
            "/workspaces/project",
            "/mnt/owner-workspace/project",
            &info,
            Some("devenv"),
        );

        // Should clone from task owner's workspace with shared objects (for speed)
        assert!(
            script.contains("--shared"),
            "should use --shared for initial clone speed"
        );
        // Should reference the task owner's workspace
        assert!(
            script.contains("/mnt/owner-workspace/project/.git"),
            "should reference owner workspace .git"
        );
        // Should dissociate: repack and remove alternates
        assert!(
            script.contains("git repack -a -d"),
            "should repack to copy objects locally"
        );
        assert!(
            script.contains("rm -f .git/objects/info/alternates"),
            "should remove alternates file to make clone self-contained"
        );
        // Should set up origin remote URL
        assert!(
            script.contains("https://github.com/owner/repo.git"),
            "should configure origin remote URL"
        );
        // Should set up 'owner' remote pointing to task owner's workspace
        assert!(
            script.contains("git remote add owner") || script.contains("git remote set-url owner"),
            "should configure owner remote"
        );
        // Should checkout the exact commit
        assert!(
            script.contains("abc123def456789"),
            "should checkout the commit"
        );
        // Should chown to target user
        assert!(
            script.contains("chown -R devenv:devenv"),
            "should chown to target user"
        );
        // Should mark directories as safe
        assert!(
            script.contains("safe.directory"),
            "should mark directories as safe"
        );
    }

    #[test]
    fn test_clone_worker_workspace_script_no_remote() {
        let info = GitRepoInfo {
            local_path: std::path::PathBuf::from("/home/user/project"),
            remote_url: None,
            commit_sha: "abc123def".to_string(),
            branch: None,
            is_dirty: false,
            dirty_files: vec![],
            fork_url: None,
        };

        let script = clone_worker_workspace_script(
            "/workspaces/project",
            "/mnt/owner-workspace/project",
            &info,
            None,
        );

        // Should still clone from task owner's workspace with shared objects (for speed)
        assert!(script.contains("--shared"));
        // Should dissociate to make clone self-contained
        assert!(
            script.contains("git repack -a -d"),
            "should repack to copy objects locally"
        );
        assert!(
            script.contains("rm -f .git/objects/info/alternates"),
            "should remove alternates file"
        );
        // Should still set up 'owner' remote even without origin URL
        assert!(
            script.contains("git remote add owner") || script.contains("git remote set-url owner"),
            "should configure owner remote even without origin"
        );
        // Should NOT have chown without target user
        assert!(
            !script.contains("chown"),
            "should not chown without target user"
        );
    }

    #[test]
    fn test_agent_branch_name() {
        assert_eq!(agent_branch_name("fix-auth"), "devaipod/fix-auth");
        assert_eq!(
            agent_branch_name("add-metrics-abc123"),
            "devaipod/add-metrics-abc123"
        );
    }
}
