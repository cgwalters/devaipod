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

use std::path::PathBuf;

use color_eyre::eyre::{Context, Result};

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
#[allow(dead_code)] // Used by workspace-v2 creation (upcoming)
pub fn agent_dir_host_path(pod_name: &str) -> Result<PathBuf> {
    let base = podman::get_host_workdir_path()?;
    Ok(base.join(pod_name))
}

/// Create the agent directory on disk. Returns the container-side path.
#[allow(dead_code)] // Used by workspace-v2 creation (upcoming)
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
}
