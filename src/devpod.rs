//! DevPod integration
//!
//! Wraps the DevPod CLI to manage workspaces.

use std::process::Command;

use color_eyre::eyre::{bail, Context, Result};

/// Run `devpod up` to create/start a workspace
///
/// Returns the workspace name on success.
///
/// # Arguments
/// * `source` - Git URL or local path
/// * `provider` - Optional provider override
/// * `ide` - Optional IDE (defaults to "none")
/// * `secrets` - Environment variables to inject via `--workspace-env`
pub fn up(
    source: &str,
    provider: Option<&str>,
    ide: Option<&str>,
    secrets: &[(String, String)],
) -> Result<String> {
    let mut cmd = Command::new("devpod");
    cmd.arg("up");
    cmd.arg(source);

    // Default to no IDE (we manage our own agent)
    let ide = ide.unwrap_or("none");
    cmd.args(["--ide", ide]);

    if let Some(provider) = provider {
        cmd.args(["--provider", provider]);
    }

    // Inject secrets as workspace environment variables
    for (name, value) in secrets {
        cmd.args(["--workspace-env", &format!("{}={}", name, value)]);
    }

    tracing::info!("Running: devpod up {} --ide {}", source, ide);
    if !secrets.is_empty() {
        tracing::info!("Injecting {} secret(s) via --workspace-env", secrets.len());
    }

    let status = cmd
        .status()
        .context("Failed to run devpod up. Is devpod installed?")?;

    if !status.success() {
        bail!("devpod up failed");
    }

    // Derive workspace name from source
    let workspace_name = derive_workspace_name(source);
    tracing::info!("Workspace '{}' is ready", workspace_name);

    Ok(workspace_name)
}

/// Run `devpod ssh` to connect to a workspace
pub fn ssh(workspace: &str, command: &[String]) -> Result<()> {
    let mut cmd = Command::new("devpod");
    cmd.arg("ssh");
    cmd.arg(workspace);

    if !command.is_empty() {
        cmd.arg("--");
        cmd.args(command);
    }

    let status = cmd.status().context("Failed to run devpod ssh")?;

    if !status.success() {
        bail!("devpod ssh failed");
    }

    Ok(())
}

/// Run `devpod list` to show workspaces
pub fn list(json: bool) -> Result<()> {
    let mut cmd = Command::new("devpod");
    cmd.arg("list");

    if json {
        cmd.arg("--output=json");
    }

    let status = cmd.status().context("Failed to run devpod list")?;

    if !status.success() {
        bail!("devpod list failed");
    }

    Ok(())
}

/// Run `devpod stop` to stop a workspace
pub fn stop(workspace: &str) -> Result<()> {
    tracing::info!("Stopping workspace '{}'", workspace);

    let status = Command::new("devpod")
        .args(["stop", workspace])
        .status()
        .context("Failed to run devpod stop")?;

    if !status.success() {
        bail!("devpod stop failed");
    }

    Ok(())
}

/// Run `devpod delete` to delete a workspace
pub fn delete(workspace: &str, force: bool) -> Result<()> {
    tracing::info!("Deleting workspace '{}'", workspace);

    let mut cmd = Command::new("devpod");
    cmd.args(["delete", workspace]);

    if force {
        cmd.arg("--force");
    }

    let status = cmd.status().context("Failed to run devpod delete")?;

    if !status.success() {
        bail!("devpod delete failed");
    }

    Ok(())
}

/// Get workspace status
/// Reserved for future use (workspace status checking before operations).
#[allow(dead_code)]
pub fn status(workspace: &str) -> Result<WorkspaceStatus> {
    let output = Command::new("devpod")
        .args(["status", workspace, "--output=json"])
        .output()
        .context("Failed to run devpod status")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        if stderr.contains("does not exist") {
            return Ok(WorkspaceStatus::NotFound);
        }
        bail!("devpod status failed: {}", stderr);
    }

    let stdout = String::from_utf8_lossy(&output.stdout);

    // Parse JSON output
    if let Ok(json) = serde_json::from_str::<serde_json::Value>(&stdout) {
        if let Some(state) = json.get("state").and_then(|s| s.as_str()) {
            return Ok(match state {
                "Running" => WorkspaceStatus::Running,
                "Stopped" => WorkspaceStatus::Stopped,
                "Busy" => WorkspaceStatus::Busy,
                _ => WorkspaceStatus::Unknown,
            });
        }
    }

    Ok(WorkspaceStatus::Unknown)
}

/// Workspace status
/// Reserved for future use (workspace status checking).
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(dead_code)]
pub enum WorkspaceStatus {
    Running,
    Stopped,
    Busy,
    NotFound,
    Unknown,
}

/// Derive workspace name from source URL or path
pub fn derive_workspace_name(source: &str) -> String {
    // Handle URLs
    if source.starts_with("http://") || source.starts_with("https://") || source.starts_with("git@")
    {
        if let Ok(url) = url::Url::parse(source) {
            if let Some(path) = url.path_segments() {
                let segments: Vec<&str> = path.collect();
                if let Some(last) = segments.last() {
                    return last.trim_end_matches(".git").to_string();
                }
            }
        }
        // Fallback for git@ URLs
        if let Some(repo) = source.rsplit('/').next() {
            return repo.trim_end_matches(".git").to_string();
        }
    }

    // Handle local paths
    if source == "." {
        if let Ok(cwd) = std::env::current_dir() {
            if let Some(name) = cwd.file_name() {
                return name.to_string_lossy().to_string();
            }
        }
        return "workspace".to_string();
    }

    // Use the last path component
    std::path::Path::new(source)
        .file_name()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| "workspace".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derive_workspace_name_from_github_url() {
        assert_eq!(
            derive_workspace_name("https://github.com/user/myrepo"),
            "myrepo"
        );
        assert_eq!(
            derive_workspace_name("https://github.com/user/myrepo.git"),
            "myrepo"
        );
    }

    #[test]
    fn test_derive_workspace_name_from_path() {
        assert_eq!(derive_workspace_name("/path/to/myproject"), "myproject");
    }

    #[test]
    fn test_derive_workspace_name_from_dot() {
        // This will depend on the current directory, so just check it doesn't panic
        let name = derive_workspace_name(".");
        assert!(!name.is_empty());
    }
}
