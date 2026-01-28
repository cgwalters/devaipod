//! Container/pod tests that require podman
//!
//! These tests verify that devaipod correctly creates and manages pods.

use color_eyre::eyre::bail;
use color_eyre::Result;
use xshell::cmd;

use crate::{podman_integration_test, run_devaipod_in, shell, PodGuard, TestRepo};

fn test_pod_creation_and_deletion() -> Result<()> {
    let repo = TestRepo::new()?;
    let pod_name = "test-repo"; // derived from directory name

    let mut pods = PodGuard::new();
    pods.add(pod_name);

    // Create pod
    let output = run_devaipod_in(&repo.repo_path, &["up", "."])?;
    if !output.success() {
        bail!("devaipod up failed: {}", output.combined());
    }

    let sh = shell()?;

    // Verify pod was created
    let pod_exists = cmd!(sh, "podman pod exists {pod_name}")
        .ignore_status()
        .output()?;
    assert!(
        pod_exists.status.success(),
        "Pod {} should exist after 'devaipod up'",
        pod_name
    );

    // Verify containers are running
    let format_names = "{{.Names}}";
    let ps_output = cmd!(
        sh,
        "podman ps --filter pod={pod_name} --format {format_names}"
    )
    .read()?;
    assert!(
        ps_output.contains("workspace"),
        "Pod should have workspace container: {}",
        ps_output
    );
    assert!(
        ps_output.contains("agent"),
        "Pod should have agent container: {}",
        ps_output
    );

    // Test devaipod list shows the pod
    let list_output = run_devaipod_in(&repo.repo_path, &["list"])?;
    list_output.assert_success("devaipod list");
    assert!(
        list_output.stdout.contains(pod_name),
        "devaipod list should show pod {}: {}",
        pod_name,
        list_output.stdout
    );

    // Test devaipod status
    let status_output = run_devaipod_in(&repo.repo_path, &["status", pod_name])?;
    status_output.assert_success("devaipod status");

    // Delete pod
    let delete_output = run_devaipod_in(&repo.repo_path, &["delete", pod_name, "--force"])?;
    delete_output.assert_success("devaipod delete");

    // Verify pod is gone
    let pod_exists_after = cmd!(sh, "podman pod exists {pod_name}")
        .ignore_status()
        .output()?;
    assert!(
        !pod_exists_after.status.success(),
        "Pod {} should not exist after 'devaipod delete'",
        pod_name
    );

    Ok(())
}
podman_integration_test!(test_pod_creation_and_deletion);

fn test_workspace_container_has_repo() -> Result<()> {
    let repo = TestRepo::new()?;
    let pod_name = "test-repo";
    let workspace_container = format!("{}-workspace", pod_name);

    let mut pods = PodGuard::new();
    pods.add(pod_name);

    // Create pod
    let output = run_devaipod_in(&repo.repo_path, &["up", "."])?;
    if !output.success() {
        bail!("devaipod up failed: {}", output.combined());
    }

    // Give containers a moment to start
    std::thread::sleep(std::time::Duration::from_secs(2));

    let sh = shell()?;

    // Verify workspace container has the repository cloned
    let ls_output = cmd!(
        sh,
        "podman exec {workspace_container} ls /workspaces/test-repo"
    )
    .read()?;
    assert!(
        ls_output.contains("README.md"),
        "Workspace should have README.md: {}",
        ls_output
    );

    Ok(())
}
podman_integration_test!(test_workspace_container_has_repo);

fn test_stop_and_start_pod() -> Result<()> {
    let repo = TestRepo::new()?;
    let pod_name = "test-repo";

    let mut pods = PodGuard::new();
    pods.add(pod_name);

    // Create pod
    let output = run_devaipod_in(&repo.repo_path, &["up", "."])?;
    if !output.success() {
        bail!("devaipod up failed: {}", output.combined());
    }

    // Stop pod
    let stop_output = run_devaipod_in(&repo.repo_path, &["stop", pod_name])?;
    stop_output.assert_success("devaipod stop");

    let sh = shell()?;

    // Verify pod is stopped (containers should not be running)
    let ps_output = cmd!(sh, "podman ps -q --filter pod={pod_name}").read()?;
    assert!(
        ps_output.trim().is_empty(),
        "No containers should be running after stop: {}",
        ps_output
    );

    // Start pod again via 'up'
    let start_output = run_devaipod_in(&repo.repo_path, &["up", "."])?;
    start_output.assert_success("devaipod up (restart)");

    // Verify pod is running again
    let ps_output2 = cmd!(sh, "podman ps -q --filter pod={pod_name}").read()?;
    assert!(
        !ps_output2.trim().is_empty(),
        "Containers should be running after restart"
    );

    Ok(())
}
podman_integration_test!(test_stop_and_start_pod);

fn test_image_override_creates_pod() -> Result<()> {
    // Create a repo without devcontainer.json
    let repo = TestRepo::new_minimal()?;
    let pod_name = "minimal-repo";

    let mut pods = PodGuard::new();
    pods.add(pod_name);

    // Create pod with image override
    let output = run_devaipod_in(
        &repo.repo_path,
        &["up", ".", "--image", "docker.io/library/alpine:latest"],
    )?;
    if !output.success() {
        bail!("devaipod up --image failed: {}", output.combined());
    }

    let sh = shell()?;

    // Verify pod was created
    let pod_exists = cmd!(sh, "podman pod exists {pod_name}")
        .ignore_status()
        .output()?;
    assert!(
        pod_exists.status.success(),
        "Pod {} should exist after 'devaipod up --image'",
        pod_name
    );

    // Verify workspace container is running
    let format_names = "{{.Names}}";
    let ps_output = cmd!(
        sh,
        "podman ps --filter pod={pod_name} --format {format_names}"
    )
    .read()?;
    assert!(
        ps_output.contains("workspace"),
        "Pod should have workspace container: {}",
        ps_output
    );

    Ok(())
}
podman_integration_test!(test_image_override_creates_pod);

fn test_logs_command() -> Result<()> {
    let repo = TestRepo::new()?;
    let pod_name = "test-repo";

    let mut pods = PodGuard::new();
    pods.add(pod_name);

    // Create pod
    let output = run_devaipod_in(&repo.repo_path, &["up", "."])?;
    if !output.success() {
        bail!("devaipod up failed: {}", output.combined());
    }

    // Give containers a moment to produce logs
    std::thread::sleep(std::time::Duration::from_secs(2));

    // Get logs (should not error even if empty)
    let logs_output = run_devaipod_in(&repo.repo_path, &["logs", pod_name])?;
    // Logs command should succeed even if there are no logs yet
    logs_output.assert_success("devaipod logs");

    Ok(())
}
podman_integration_test!(test_logs_command);

fn test_ssh_runs_command() -> Result<()> {
    let repo = TestRepo::new()?;
    let pod_name = "test-repo";

    let mut pods = PodGuard::new();
    pods.add(pod_name);

    // Create pod
    let output = run_devaipod_in(&repo.repo_path, &["up", "."])?;
    if !output.success() {
        bail!("devaipod up failed: {}", output.combined());
    }

    // Give containers a moment to start
    std::thread::sleep(std::time::Duration::from_secs(2));

    // Run a command via ssh
    let ssh_output = run_devaipod_in(&repo.repo_path, &["ssh", pod_name, "--", "echo", "hello"])?;
    ssh_output.assert_success("devaipod ssh echo");
    assert!(
        ssh_output.stdout.contains("hello"),
        "ssh should run command and return output: {}",
        ssh_output.combined()
    );

    // Verify we can see the workspace
    let ls_output = run_devaipod_in(
        &repo.repo_path,
        &["ssh", pod_name, "--", "ls", "/workspaces"],
    )?;
    ls_output.assert_success("devaipod ssh ls");
    assert!(
        ls_output.stdout.contains("test-repo"),
        "Should see workspace directory: {}",
        ls_output.stdout
    );

    Ok(())
}
podman_integration_test!(test_ssh_runs_command);

fn test_ssh_nonexistent_pod_fails() -> Result<()> {
    // SSH to a pod that doesn't exist should fail gracefully
    let output = run_devaipod_in(
        std::path::Path::new("."),
        &["ssh", "nonexistent-pod-12345", "--", "echo", "hi"],
    )?;
    assert!(!output.success(), "ssh to nonexistent pod should fail");

    Ok(())
}
podman_integration_test!(test_ssh_nonexistent_pod_fails);
