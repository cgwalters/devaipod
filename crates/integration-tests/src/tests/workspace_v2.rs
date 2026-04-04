//! Workspace v2 tests: agent workspace bind mounts
//!
//! These tests verify that workspace-v2 correctly uses host bind mounts
//! (rather than named volumes) for agent workspaces from local repos.

use color_eyre::Result;
use color_eyre::eyre::bail;
use std::process::Command;
use std::time::Duration;

use crate::{
    PodGuard, TestRepo, podman_integration_test, run_devaipod_in, short_name, unique_test_name,
};

/// Verify that the agent container's /workspaces is a bind mount, not a volume.
///
/// With workspace-v2, local repos use a host directory bind mount instead of a
/// named podman volume. This test inspects the agent container's mount
/// configuration to confirm the mount type is "bind".
fn test_agent_workspace_is_bind_mount() -> Result<()> {
    let repo = TestRepo::new()?;
    let pod_name = unique_test_name("test-ws-bind");

    let mut pods = PodGuard::new();
    pods.add(&pod_name);

    // Create pod
    let output = run_devaipod_in(
        &repo.repo_path,
        &["up", ".", "--name", short_name(&pod_name)],
    )?;
    if !output.success() {
        bail!("devaipod up failed: {}", output.combined());
    }

    let agent_container = format!("{}-agent", pod_name);

    // Wait for agent container to be running
    crate::wait_for_container_running(&agent_container, Duration::from_secs(30))?;

    // Inspect the agent container's mounts as JSON and find /workspaces
    let inspect_output = Command::new("podman")
        .args(["inspect", "--format", "{{json .Mounts}}", &agent_container])
        .output()
        .map_err(|e| color_eyre::eyre::eyre!("Failed to run podman inspect: {}", e))?;
    if !inspect_output.status.success() {
        let stderr = String::from_utf8_lossy(&inspect_output.stderr);
        bail!("podman inspect failed: {}", stderr.trim());
    }

    let mounts_json = String::from_utf8_lossy(&inspect_output.stdout)
        .trim()
        .to_string();
    let mounts: serde_json::Value = serde_json::from_str(&mounts_json).map_err(|e| {
        color_eyre::eyre::eyre!("Failed to parse mounts JSON: {}: {}", e, mounts_json,)
    })?;

    let mounts_array = mounts
        .as_array()
        .ok_or_else(|| color_eyre::eyre::eyre!("Expected mounts to be an array"))?;

    // Find the /workspaces mount
    let workspaces_mount = mounts_array
        .iter()
        .find(|m| m.get("Destination").and_then(|d| d.as_str()) == Some("/workspaces"))
        .ok_or_else(|| {
            color_eyre::eyre::eyre!(
                "No /workspaces mount found in agent container mounts: {}",
                mounts_json,
            )
        })?;

    let mount_type = workspaces_mount
        .get("Type")
        .and_then(|t| t.as_str())
        .unwrap_or("<missing>");

    assert_eq!(
        mount_type,
        "bind",
        "Agent /workspaces should be a bind mount (workspace-v2), got Type={:?}.\nFull mount: {}",
        mount_type,
        serde_json::to_string_pretty(workspaces_mount).unwrap_or_default(),
    );

    Ok(())
}
podman_integration_test!(test_agent_workspace_is_bind_mount);
