//! Workspace management for devc
//!
//! Handles creating isolated workspaces using podman volumes:
//! - Remote git repositories: cloned directly into a volume
//! - Local git repositories with --worktree: uses git clone --reference for efficiency
//! - All storage is in podman volumes for isolation and portability

use std::path::{Path, PathBuf};
use std::process::Command as ProcessCommand;

use color_eyre::eyre::{bail, Context, ContextCompat, Result};
use url::Url;

/// Generate a random suffix for unique workspace names (4 lowercase alphanumeric chars)
fn generate_suffix() -> String {
    use rand::distr::{Alphanumeric, SampleString};
    Alphanumeric
        .sample_string(&mut rand::rng(), 4)
        .to_lowercase()
}

/// Generate a unique workspace name by appending a random suffix
fn unique_workspace_name(base: &str) -> String {
    format!("{}-{}", base, generate_suffix())
}

/// Source type for workspace creation
#[derive(Debug, Clone)]
pub enum WorkspaceSource {
    /// Remote git repository URL
    RemoteUrl(String),
    /// Local git repository path (will use --reference clone)
    LocalGitRepo(PathBuf),
    /// Local directory (not a git repo)
    LocalDirectory(PathBuf),
}

/// Storage configuration for a workspace
#[derive(Debug, Clone)]
pub enum StorageMode {
    /// Use a podman volume (default, isolated)
    Volume {
        /// Volume name
        name: String,
    },
    /// Use a bind mount to host path (legacy/debugging)
    BindMount {
        /// Host path to mount
        host_path: PathBuf,
    },
}

/// Workspace metadata
#[derive(Debug)]
pub struct Workspace {
    /// Path inside container where workspace is mounted
    #[allow(dead_code)]
    pub container_path: PathBuf,
    /// Storage configuration
    pub storage: StorageMode,
    /// Source of the workspace
    #[allow(dead_code)]
    pub source: WorkspaceSource,
    /// Name of the workspace
    pub name: String,
    /// Git reference repo (for --reference clones)
    #[allow(dead_code)]
    pub reference_repo: Option<PathBuf>,
}

/// Parse a source string into a WorkspaceSource
///
/// Determines if the source is:
/// 1. A URL (http://, https://, git://, ssh://, or git@)
/// 2. A local path (absolute or relative)
pub fn parse_source(source: &str) -> Result<WorkspaceSource> {
    // Check if it looks like a URL
    if source.starts_with("http://")
        || source.starts_with("https://")
        || source.starts_with("git://")
        || source.starts_with("ssh://")
        || source.starts_with("git@")
    {
        // Validate URL format for http(s) URLs
        if source.starts_with("http://") || source.starts_with("https://") {
            Url::parse(source).context("Invalid URL format")?;
        }
        return Ok(WorkspaceSource::RemoteUrl(source.to_string()));
    }

    // Treat as local path
    let path = PathBuf::from(source);
    let abs_path = if path.is_absolute() {
        path
    } else {
        std::env::current_dir()
            .context("Failed to get current directory")?
            .join(&path)
    };

    if !abs_path.exists() {
        bail!("Path does not exist: {}", abs_path.display());
    }

    // Check if it's a git repository
    if is_git_repo(&abs_path)? {
        Ok(WorkspaceSource::LocalGitRepo(abs_path))
    } else {
        Ok(WorkspaceSource::LocalDirectory(abs_path))
    }
}

/// Check if a path is a git repository
fn is_git_repo(path: &Path) -> Result<bool> {
    let output = ProcessCommand::new("git")
        .args(["-C", &path.to_string_lossy(), "rev-parse", "--git-dir"])
        .output()
        .context("Failed to run git")?;

    Ok(output.status.success())
}

/// Extract a repository name from a URL
///
/// Examples:
/// - https://github.com/bootc-dev/bootc -> bootc
/// - https://github.com/user/repo.git -> repo
pub fn extract_repo_name(url: &str) -> Result<String> {
    // Handle git@github.com:user/repo.git format
    if let Some(path_part) = url.strip_prefix("git@") {
        if let Some((_host, path)) = path_part.split_once(':') {
            let name = path
                .trim_end_matches(".git")
                .split('/')
                .last()
                .context("Invalid git URL format")?;
            return Ok(name.to_string());
        }
    }

    // Parse as URL
    let parsed = Url::parse(url).context("Invalid URL format")?;
    let path = parsed.path();
    let name = path
        .trim_end_matches(".git")
        .split('/')
        .last()
        .context("Could not extract repository name from URL")?;

    if name.is_empty() {
        bail!("Could not determine repository name from URL: {}", url);
    }

    Ok(name.to_string())
}

/// Generate a volume name for a workspace
pub fn volume_name(workspace_name: &str) -> String {
    format!("devc-{}", workspace_name)
}

/// Check if a podman volume exists
pub fn volume_exists(name: &str) -> Result<bool> {
    let output = ProcessCommand::new("podman")
        .args(["volume", "exists", name])
        .output()
        .context("Failed to check volume")?;
    Ok(output.status.success())
}

/// Metadata for volume creation
pub struct VolumeMetadata<'a> {
    /// Source URL or path that was cloned
    pub source_url: Option<&'a str>,
    /// Git branch/ref if applicable
    pub git_ref: Option<&'a str>,
    /// Workspace description
    pub description: Option<&'a str>,
}

/// Create a podman volume with labels
pub fn create_volume(name: &str, metadata: Option<&VolumeMetadata>) -> Result<()> {
    use crate::consts::{LABEL_KEY_DESCRIPTION, LABEL_KEY_REF, LABEL_KEY_SOURCE, LABEL_MARKER};

    tracing::info!("Creating volume: {}", name);
    let mut cmd = ProcessCommand::new("podman");
    cmd.args(["volume", "create"]);

    // Always add our marker label
    cmd.args(["--label", LABEL_MARKER]);

    // Add metadata labels if provided
    if let Some(meta) = metadata {
        if let Some(url) = meta.source_url {
            cmd.args(["--label", &format!("{}={}", LABEL_KEY_SOURCE, url)]);
        }
        if let Some(git_ref) = meta.git_ref {
            cmd.args(["--label", &format!("{}={}", LABEL_KEY_REF, git_ref)]);
        }
        if let Some(desc) = meta.description {
            cmd.args(["--label", &format!("{}={}", LABEL_KEY_DESCRIPTION, desc)]);
        }
    }

    cmd.arg(name);

    let status = cmd.status().context("Failed to create volume")?;

    if !status.success() {
        bail!("Failed to create volume {}", name);
    }
    Ok(())
}

/// Clone a git repository into a volume
///
/// Uses a temporary container to perform the clone operation.
/// If reference_repo is provided, uses --reference for efficiency.
pub fn clone_into_volume(
    volume_name: &str,
    url: &str,
    branch: Option<&str>,
    reference_repo: Option<&Path>,
) -> Result<()> {
    tracing::info!("Cloning {} into volume {}", url, volume_name);

    // Build the git clone command
    let mut clone_cmd = String::from("git clone --progress");

    if let Some(branch) = branch {
        clone_cmd.push_str(&format!(" --branch {}", branch));
    }

    if let Some(ref_repo) = reference_repo {
        // Use --reference to share objects with local repo
        // Also use --dissociate to copy objects so volume is self-contained
        clone_cmd.push_str(&format!(" --reference {} --dissociate", ref_repo.display()));
    }

    clone_cmd.push_str(&format!(" {} /workspace", url));

    // Run git clone in a temporary container with the volume mounted
    let mut cmd = ProcessCommand::new("podman");
    cmd.args(["run", "--rm"]);

    // Mount the volume
    cmd.args(["-v", &format!("{}:/workspace:Z", volume_name)]);

    // If using --reference, we need to bind mount the reference repo too
    if let Some(ref_repo) = reference_repo {
        cmd.args([
            "-v",
            &format!("{}:{}:ro,z", ref_repo.display(), ref_repo.display()),
        ]);
    }

    // Use alpine/git but override the entrypoint to run our command with sh
    cmd.args(["--entrypoint", "/bin/sh"]);
    cmd.args(["docker.io/alpine/git:latest", "-c", &clone_cmd]);

    tracing::debug!("Running: {:?}", cmd);

    let output = cmd
        .output()
        .context("Failed to run git clone in container")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("Failed to clone repository: {}", stderr);
    }

    tracing::info!("Repository cloned successfully into volume");
    Ok(())
}

/// Create a workspace from a source
///
/// The name parameter is optional. If not provided:
/// - For URLs: extracted from the repository name
/// - For local paths: uses the directory name
///
/// All workspaces use podman volumes for storage. For local git repos,
/// `git clone --reference` is used to efficiently share objects.
pub fn create_workspace(
    source: &WorkspaceSource,
    name: Option<&str>,
    base_ref: Option<&str>,
    description: Option<&str>,
) -> Result<Workspace> {
    match source {
        WorkspaceSource::RemoteUrl(url) => {
            // If name is explicitly provided, use it as-is (fail if exists)
            // Otherwise, generate a unique name with random suffix
            let workspace_name = if let Some(n) = name {
                let vol_name = volume_name(n);
                if volume_exists(&vol_name)? {
                    bail!(
                        "Workspace volume already exists: {}. Use a different name or remove with `podman volume rm {}`",
                        vol_name,
                        vol_name
                    );
                }
                n.to_string()
            } else {
                let base = extract_repo_name(url).unwrap_or_else(|_| "workspace".to_string());
                unique_workspace_name(&base)
            };

            let vol_name = volume_name(&workspace_name);

            let metadata = VolumeMetadata {
                source_url: Some(url),
                git_ref: base_ref,
                description,
            };
            create_volume(&vol_name, Some(&metadata))?;
            clone_into_volume(&vol_name, url, base_ref, None)?;

            Ok(Workspace {
                container_path: PathBuf::from("/projects"),
                storage: StorageMode::Volume { name: vol_name },
                source: source.clone(),
                name: workspace_name,
                reference_repo: None,
            })
        }

        WorkspaceSource::LocalGitRepo(repo_path) => {
            // For local git repos, we clone with --reference to share objects
            let repo_name_str = repo_path
                .file_name()
                .context("Could not determine repository name")?
                .to_string_lossy();

            // If name is explicitly provided, use it as-is (fail if exists)
            // Otherwise, generate a unique name with random suffix
            let workspace_name = if let Some(n) = name {
                let vol_name = volume_name(n);
                if volume_exists(&vol_name)? {
                    bail!(
                        "Workspace volume already exists: {}. Use a different name or remove with `podman volume rm {}`",
                        vol_name,
                        vol_name
                    );
                }
                n.to_string()
            } else {
                unique_workspace_name(&repo_name_str)
            };

            let vol_name = volume_name(&workspace_name);

            // Get the remote URL from the local repo to clone from
            let remote_url = get_git_remote_url(repo_path)?;

            let metadata = VolumeMetadata {
                source_url: Some(&remote_url),
                git_ref: base_ref,
                description,
            };
            create_volume(&vol_name, Some(&metadata))?;
            clone_into_volume(&vol_name, &remote_url, base_ref, Some(repo_path))?;

            Ok(Workspace {
                container_path: PathBuf::from("/projects"),
                storage: StorageMode::Volume { name: vol_name },
                source: source.clone(),
                name: workspace_name,
                reference_repo: Some(repo_path.clone()),
            })
        }

        WorkspaceSource::LocalDirectory(dir_path) => {
            // For non-git directories, copy contents into volume
            // If name is explicitly provided, use it as-is (fail if exists)
            // Otherwise, generate a unique name with random suffix
            let workspace_name = if let Some(n) = name {
                let vol_name = volume_name(n);
                if volume_exists(&vol_name)? {
                    bail!(
                        "Workspace volume already exists: {}. Use a different name or remove with `podman volume rm {}`",
                        vol_name,
                        vol_name
                    );
                }
                n.to_string()
            } else {
                let base = dir_path
                    .file_name()
                    .map(|s| s.to_string_lossy().to_string())
                    .unwrap_or_else(|| "workspace".to_string());
                unique_workspace_name(&base)
            };

            let vol_name = volume_name(&workspace_name);

            // For local directories, store the source path
            let source_path = dir_path.to_string_lossy();
            let metadata = VolumeMetadata {
                source_url: Some(&source_path),
                git_ref: None,
                description,
            };
            create_volume(&vol_name, Some(&metadata))?;
            copy_into_volume(&vol_name, dir_path)?;

            Ok(Workspace {
                container_path: PathBuf::from("/projects"),
                storage: StorageMode::Volume { name: vol_name },
                source: source.clone(),
                name: workspace_name,
                reference_repo: None,
            })
        }
    }
}

/// Get the remote origin URL from a git repository
fn get_git_remote_url(repo_path: &Path) -> Result<String> {
    let output = ProcessCommand::new("git")
        .args([
            "-C",
            &repo_path.to_string_lossy(),
            "remote",
            "get-url",
            "origin",
        ])
        .output()
        .context("Failed to get git remote URL")?;

    if !output.status.success() {
        bail!("Repository has no 'origin' remote configured");
    }

    let url = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if url.is_empty() {
        bail!("Repository has no 'origin' remote URL");
    }

    Ok(url)
}

/// Copy a directory's contents into a volume
fn copy_into_volume(volume_name: &str, source_path: &Path) -> Result<()> {
    tracing::info!(
        "Copying {} into volume {}",
        source_path.display(),
        volume_name
    );

    let status = ProcessCommand::new("podman")
        .args(["run", "--rm"])
        .args(["-v", &format!("{}:/workspace:Z", volume_name)])
        .args(["-v", &format!("{}:/source:ro,z", source_path.display())])
        .args([
            "docker.io/library/alpine:latest",
            "sh",
            "-c",
            "cp -a /source/. /workspace/",
        ])
        .status()
        .context("Failed to copy into volume")?;

    if !status.success() {
        bail!("Failed to copy directory into volume");
    }

    tracing::info!("Directory copied successfully into volume");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_repo_name() {
        assert_eq!(
            extract_repo_name("https://github.com/bootc-dev/bootc").unwrap(),
            "bootc"
        );
        assert_eq!(
            extract_repo_name("https://github.com/user/repo.git").unwrap(),
            "repo"
        );
        assert_eq!(
            extract_repo_name("git@github.com:user/repo.git").unwrap(),
            "repo"
        );
    }

    #[test]
    fn test_parse_source_url() {
        let source = parse_source("https://github.com/bootc-dev/bootc").unwrap();
        match source {
            WorkspaceSource::RemoteUrl(url) => {
                assert_eq!(url, "https://github.com/bootc-dev/bootc");
            }
            _ => panic!("Expected RemoteUrl"),
        }
    }

    #[test]
    fn test_parse_source_git_ssh() {
        let source = parse_source("git@github.com:user/repo.git").unwrap();
        match source {
            WorkspaceSource::RemoteUrl(url) => {
                assert_eq!(url, "git@github.com:user/repo.git");
            }
            _ => panic!("Expected RemoteUrl"),
        }
    }
}
