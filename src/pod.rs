//! Podman pod lifecycle management
//!
//! This module provides functions for managing podman pods, which allow
//! grouping multiple containers together with shared network and IPC namespaces.

use std::process::Command as ProcessCommand;

use color_eyre::eyre::{bail, Context, Result};
use serde::Deserialize;

/// Generate a pod name for a workspace
pub fn pod_name(workspace_name: &str) -> String {
    format!("devc-{}", workspace_name)
}

/// Generate a container name within a pod
pub fn container_name(workspace_name: &str, component_name: &str) -> String {
    format!("devc-{}-{}", workspace_name, component_name)
}

/// Create a podman pod with labels and hostname
pub fn create_pod(name: &str, hostname: &str, labels: &[(&str, &str)]) -> Result<()> {
    tracing::info!("Creating pod: {}", name);

    let mut cmd = ProcessCommand::new("podman");
    cmd.args(["pod", "create", "--name", name]);

    // Set hostname for the pod (shared by all containers)
    cmd.args(["--hostname", hostname]);

    // Add marker label and caller-provided labels
    cmd.args(["--label", crate::consts::LABEL_MARKER]);
    for (key, value) in labels {
        cmd.args(["--label", &format!("{}={}", key, value)]);
    }

    tracing::debug!("Running: {:?}", cmd);

    let output = cmd.output().context("Failed to run podman pod create")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("Failed to create pod {}: {}", name, stderr);
    }

    let pod_id = String::from_utf8_lossy(&output.stdout).trim().to_string();
    tracing::info!("Pod created: {} ({})", name, pod_id);

    Ok(())
}

/// Check if a pod exists
pub fn pod_exists(name: &str) -> Result<bool> {
    let status = ProcessCommand::new("podman")
        .args(["pod", "exists", name])
        .status()
        .context("Failed to run podman pod exists")?;

    Ok(status.success())
}

/// Start an existing pod
pub fn start_pod(name: &str) -> Result<()> {
    tracing::info!("Starting pod: {}", name);

    let status = ProcessCommand::new("podman")
        .args(["pod", "start", name])
        .status()
        .context("Failed to run podman pod start")?;

    if !status.success() {
        bail!("Failed to start pod {}", name);
    }

    tracing::info!("Pod started: {}", name);
    Ok(())
}

/// Stop a pod
#[allow(dead_code)]
pub fn stop_pod(name: &str) -> Result<()> {
    tracing::info!("Stopping pod: {}", name);

    let status = ProcessCommand::new("podman")
        .args(["pod", "stop", name])
        .status()
        .context("Failed to run podman pod stop")?;

    if !status.success() {
        bail!("Failed to stop pod {}", name);
    }

    tracing::info!("Pod stopped: {}", name);
    Ok(())
}

/// Remove a pod and all its containers
pub fn remove_pod(name: &str) -> Result<()> {
    let status = ProcessCommand::new("podman")
        .args(["pod", "rm", "-f", name])
        .status()
        .context("Failed to run podman pod rm")?;

    if !status.success() {
        bail!("Failed to remove pod {}", name);
    }

    tracing::info!("Pod removed: {}", name);
    Ok(())
}

/// Podman pod status from JSON output
#[derive(Debug, Deserialize)]
struct PodmanPod {
    #[serde(rename = "Name")]
    #[allow(dead_code)]
    name: String,
    #[serde(rename = "Status")]
    status: String,
}

/// Check if pod is running
pub fn pod_is_running(name: &str) -> Result<bool> {
    let output = ProcessCommand::new("podman")
        .args([
            "pod",
            "ps",
            "--filter",
            &format!("name=^{}$", name),
            "--format",
            "json",
        ])
        .output()
        .context("Failed to run podman pod ps")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("Failed to query pod status: {}", stderr);
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let pods: Vec<PodmanPod> = serde_json::from_str(&stdout).unwrap_or_default();

    if let Some(pod) = pods.first() {
        // Pod status is "Running" when running, "Exited" when stopped, etc.
        Ok(pod.status == "Running")
    } else {
        // Pod doesn't exist
        Ok(false)
    }
}

/// Podman container info from JSON output
#[derive(Debug, Deserialize)]
struct PodmanContainer {
    #[serde(rename = "Names")]
    names: Vec<String>,
}

/// List container names in a pod
pub fn list_pod_containers(pod_name: &str) -> Result<Vec<String>> {
    let output = ProcessCommand::new("podman")
        .args([
            "ps",
            "-a",
            "--pod",
            "--filter",
            &format!("pod={}", pod_name),
            "--format",
            "json",
        ])
        .output()
        .context("Failed to run podman ps")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("Failed to list pod containers: {}", stderr);
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let containers: Vec<PodmanContainer> = serde_json::from_str(&stdout).unwrap_or_default();

    let mut names = Vec::new();
    for container in containers {
        if let Some(name) = container.names.first() {
            // Skip the pod infra container (which has the same name as the pod with a suffix)
            if !name.ends_with("-infra") {
                names.push(name.clone());
            }
        }
    }

    Ok(names)
}

/// Execute a command in a container by its full name
pub fn exec_in_container(container_name: &str, command: &[&str], interactive: bool) -> Result<i32> {
    use std::process::Stdio;

    let mut cmd = ProcessCommand::new("podman");
    cmd.arg("exec");

    if interactive {
        cmd.args(["-it"]);
    }

    cmd.arg(container_name);
    cmd.args(command);

    if interactive {
        cmd.stdin(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit());
    }

    let status = cmd.status().context("Failed to exec in container")?;
    Ok(status.code().unwrap_or(1))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pod_name() {
        assert_eq!(pod_name("myworkspace"), "devc-myworkspace");
        assert_eq!(pod_name("feature-123"), "devc-feature-123");
    }

    #[test]
    fn test_container_name() {
        assert_eq!(container_name("myworkspace", "dev"), "devc-myworkspace-dev");
        assert_eq!(
            container_name("feature-123", "runtime"),
            "devc-feature-123-runtime"
        );
    }

    #[test]
    fn test_pod_name_consistency() {
        // Ensure pod names match the expected pattern
        let workspace = "test-ws";
        let pod = pod_name(workspace);
        assert!(pod.starts_with("devc-"));
        assert!(pod.contains(workspace));
    }

    #[test]
    fn test_container_name_includes_workspace_and_component() {
        let workspace = "workspace";
        let component = "component";
        let name = container_name(workspace, component);

        assert!(name.starts_with("devc-"));
        assert!(name.contains(workspace));
        assert!(name.contains(component));
    }
}
