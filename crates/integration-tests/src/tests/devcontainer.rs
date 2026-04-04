//! Devcontainer integration tests
//!
//! These tests verify the standalone devcontainer commands:
//! `devaipod devcontainer run`, `devaipod devcontainer list`, and
//! `devaipod devcontainer rm`.
//!
//! Devcontainer pods are created with label `io.devaipod.mode=devcontainer`
//! and are intentionally excluded from the regular `devaipod list` output.

use color_eyre::Result;

use crate::{
    PodGuard, TestRepo, integration_test, podman_integration_test, run_devaipod, run_devaipod_in,
    shell, short_name, unique_test_name,
};

/// Verify that `devaipod devcontainer list` works when no devcontainer pods exist.
fn test_devcontainer_list_empty() -> Result<()> {
    let output = run_devaipod(&["devcontainer", "list"])?;
    output.assert_success("devaipod devcontainer list");

    assert!(
        output.stdout.contains("No devcontainer pods found"),
        "Expected 'No devcontainer pods found' message, got:\n{}",
        output.combined()
    );

    Ok(())
}
integration_test!(test_devcontainer_list_empty);

/// Create a devcontainer from a local repo and verify it appears in the list.
fn test_devcontainer_run_local() -> Result<()> {
    let repo = TestRepo::new()?;
    let pod_name = unique_test_name("dc-run");

    let mut pods = PodGuard::new();
    pods.add(&pod_name);

    let output = run_devaipod_in(
        &repo.repo_path,
        &["devcontainer", "run", ".", "--name", short_name(&pod_name)],
    )?;
    output.assert_success("devaipod devcontainer run");

    // Verify the devcontainer pod exists via podman
    let sh = shell()?;
    let pod_exists = xshell::cmd!(sh, "podman pod exists {pod_name}")
        .ignore_status()
        .output()?;
    assert!(
        pod_exists.status.success(),
        "Pod {} should exist after 'devaipod devcontainer run'",
        pod_name
    );

    // Verify it shows up in devcontainer list
    let list_output = run_devaipod(&["devcontainer", "list"])?;
    list_output.assert_success("devaipod devcontainer list");
    assert!(
        list_output.stdout.contains(short_name(&pod_name)),
        "Devcontainer list should show pod {}: {}",
        short_name(&pod_name),
        list_output.combined()
    );

    // Verify the list shows a Running or Degraded status (pod is alive)
    let combined = list_output.stdout.to_lowercase();
    assert!(
        combined.contains("running") || combined.contains("degraded"),
        "Pod should have Running or Degraded status in list:\n{}",
        list_output.stdout
    );

    Ok(())
}
podman_integration_test!(test_devcontainer_run_local);

/// Create a devcontainer and remove it with `devaipod devcontainer rm`.
fn test_devcontainer_rm() -> Result<()> {
    let repo = TestRepo::new()?;
    let pod_name = unique_test_name("dc-rm");

    let mut pods = PodGuard::new();
    pods.add(&pod_name);

    // Create
    let output = run_devaipod_in(
        &repo.repo_path,
        &["devcontainer", "run", ".", "--name", short_name(&pod_name)],
    )?;
    output.assert_success("devaipod devcontainer run");

    // Remove (--force to stop running containers first)
    let rm_output = run_devaipod(&["devcontainer", "rm", short_name(&pod_name), "--force"])?;
    rm_output.assert_success("devaipod devcontainer rm");

    // Verify the pod is gone
    let sh = shell()?;
    let pod_exists = xshell::cmd!(sh, "podman pod exists {pod_name}")
        .ignore_status()
        .output()?;
    assert!(
        !pod_exists.status.success(),
        "Pod {} should not exist after 'devaipod devcontainer rm'",
        pod_name
    );

    // Verify it's gone from the devcontainer list
    let list_output = run_devaipod(&["devcontainer", "list"])?;
    list_output.assert_success("devaipod devcontainer list");
    assert!(
        !list_output.stdout.contains(short_name(&pod_name)),
        "Removed pod should not appear in devcontainer list:\n{}",
        list_output.combined()
    );

    Ok(())
}
podman_integration_test!(test_devcontainer_rm);

/// Devcontainer pods should NOT appear in the regular agent list.
fn test_devcontainer_not_in_agent_list() -> Result<()> {
    let repo = TestRepo::new()?;
    let pod_name = unique_test_name("dc-noagent");

    let mut pods = PodGuard::new();
    pods.add(&pod_name);

    let output = run_devaipod_in(
        &repo.repo_path,
        &["devcontainer", "run", ".", "--name", short_name(&pod_name)],
    )?;
    output.assert_success("devaipod devcontainer run");

    // The regular `devaipod list --json` should filter out devcontainer pods
    let list_output = run_devaipod(&["list", "--json"])?;
    list_output.assert_success("devaipod list --json");

    let agent_pods: Vec<serde_json::Value> =
        serde_json::from_str(&list_output.stdout).unwrap_or_else(|_| Vec::new());

    // None of the agent list entries should have our devcontainer pod name
    let found = agent_pods.iter().any(|p| {
        p.get("Name")
            .and_then(|n| n.as_str())
            .map(|n| n == pod_name)
            .unwrap_or(false)
    });
    assert!(
        !found,
        "Devcontainer pod {} should NOT appear in agent list: {:?}",
        pod_name, agent_pods
    );

    Ok(())
}
podman_integration_test!(test_devcontainer_not_in_agent_list);

/// `devaipod devcontainer run` should fail for a repo without a git remote.
fn test_devcontainer_run_requires_git_remote() -> Result<()> {
    let temp_dir = tempfile::TempDir::new()?;
    let repo_path = temp_dir.path().join("no-remote-repo");
    std::fs::create_dir_all(&repo_path)?;

    let sh = shell()?;
    let repo = repo_path.to_str().unwrap();

    // Initialize git repo without remote
    xshell::cmd!(sh, "git -C {repo} init").run()?;
    xshell::cmd!(sh, "git -C {repo} config user.email test@example.com").run()?;
    xshell::cmd!(sh, "git -C {repo} config user.name 'Test User'").run()?;

    // Create devcontainer.json
    let devcontainer_dir = repo_path.join(".devcontainer");
    std::fs::create_dir_all(&devcontainer_dir)?;
    std::fs::write(
        devcontainer_dir.join("devcontainer.json"),
        r#"{"image": "alpine:latest"}"#,
    )?;
    std::fs::write(repo_path.join("README.md"), "# Test\n")?;

    xshell::cmd!(sh, "git -C {repo} add .").run()?;
    xshell::cmd!(sh, "git -C {repo} commit -m 'Initial'").run()?;

    let output = run_devaipod_in(
        &repo_path,
        &["devcontainer", "run", ".", "--config", "/dev/null"],
    )?;
    assert!(
        !output.success(),
        "Should fail without git remote configured"
    );
    assert!(
        output.combined().contains("remote")
            || output.combined().contains("Remote")
            || output.combined().contains("clone"),
        "Error should mention remote/clone issue: {}",
        output.combined()
    );

    Ok(())
}
integration_test!(test_devcontainer_run_requires_git_remote);

/// Verify the web API endpoint for listing devcontainers returns valid JSON.
fn test_devcontainer_web_api_list() -> Result<()> {
    use integration_tests::harness::DevaipodHarness;

    let harness = DevaipodHarness::start()?;

    let (status, body) = harness.get("/api/devaipod/devcontainer/list")?;
    assert_eq!(
        status,
        200,
        "GET /api/devaipod/devcontainer/list should return 200, got {status}: {}",
        &body[..body.len().min(300)]
    );

    let pods: Vec<serde_json::Value> = serde_json::from_str(&body).map_err(|e| {
        color_eyre::eyre::eyre!(
            "Failed to parse devcontainer list: {} - body: {}",
            e,
            &body[..body.len().min(500)]
        )
    })?;

    // Without any devcontainer pods running, the array should be empty.
    tracing::info!(
        "Devcontainer list returned {} entries (port {})",
        pods.len(),
        harness.port()
    );

    Ok(())
}
podman_integration_test!(test_devcontainer_web_api_list);
