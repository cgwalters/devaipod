//! Integration tests for multi-agent orchestration
//!
//! These tests verify the orchestration configuration parsing and pod creation
//! with worker containers.
//!
//! Note: Config parsing tests use TOML directly since the integration test crate
//! doesn't have access to the main devaipod library internals. Full config parsing
//! is tested via unit tests in src/config.rs.

use color_eyre::Result;
use xshell::cmd;

use crate::{
    PodGuard, TestRepo, integration_test, podman_integration_test, run_devaipod_in, shell,
    short_name, unique_test_name,
};

// =============================================================================
// Configuration parsing tests (no containers needed)
// =============================================================================

/// Verify orchestration config structure is valid TOML
///
/// This test validates that the expected orchestration config formats parse
/// as valid TOML. Full semantic parsing is tested in src/config.rs unit tests.
fn test_orchestration_config_parsing() -> Result<()> {
    // Test that orchestration config parses as valid TOML
    let toml_content = r#"
[orchestration]
enabled = true
worker-timeout = "45m"

[orchestration.worker]
gator = "inherit"
"#;

    let value: toml::Value = toml::from_str(toml_content)?;

    // Verify the structure
    let orch = value.get("orchestration").expect("orchestration section");
    assert_eq!(
        orch.get("enabled").and_then(|v| v.as_bool()),
        Some(true),
        "enabled should be true"
    );
    assert_eq!(
        orch.get("worker-timeout").and_then(|v| v.as_str()),
        Some("45m"),
        "worker-timeout should be 45m"
    );

    let worker = orch.get("worker").expect("worker section");
    assert_eq!(
        worker.get("gator").and_then(|v| v.as_str()),
        Some("inherit"),
        "gator should be inherit"
    );

    Ok(())
}
integration_test!(test_orchestration_config_parsing);

/// Verify that empty config doesn't include orchestration by default
fn test_orchestration_disabled_by_default() -> Result<()> {
    // Empty config should have no orchestration section
    let toml_content = "";
    let value: toml::Value = toml::from_str(toml_content)?;

    // Empty TOML parses as an empty table
    assert!(
        value.get("orchestration").is_none(),
        "Empty config should not have orchestration section"
    );

    // Config with other sections but no orchestration
    let toml_content = r#"
[env]
allowlist = ["PATH"]
"#;
    let value: toml::Value = toml::from_str(toml_content)?;
    assert!(
        value.get("orchestration").is_none(),
        "Config without orchestration section should not have one"
    );

    Ok(())
}
integration_test!(test_orchestration_disabled_by_default);

/// Verify all three gator modes are valid TOML values
fn test_worker_gator_mode_parsing() -> Result<()> {
    // Test readonly mode
    let toml_content = r#"
[orchestration.worker]
gator = "readonly"
"#;
    let value: toml::Value = toml::from_str(toml_content)?;
    let gator = value
        .get("orchestration")
        .and_then(|o| o.get("worker"))
        .and_then(|w| w.get("gator"))
        .and_then(|g| g.as_str());
    assert_eq!(gator, Some("readonly"), "Should parse readonly mode");

    // Test inherit mode
    let toml_content = r#"
[orchestration.worker]
gator = "inherit"
"#;
    let value: toml::Value = toml::from_str(toml_content)?;
    let gator = value
        .get("orchestration")
        .and_then(|o| o.get("worker"))
        .and_then(|w| w.get("gator"))
        .and_then(|g| g.as_str());
    assert_eq!(gator, Some("inherit"), "Should parse inherit mode");

    // Test none mode
    let toml_content = r#"
[orchestration.worker]
gator = "none"
"#;
    let value: toml::Value = toml::from_str(toml_content)?;
    let gator = value
        .get("orchestration")
        .and_then(|o| o.get("worker"))
        .and_then(|w| w.get("gator"))
        .and_then(|g| g.as_str());
    assert_eq!(gator, Some("none"), "Should parse none mode");

    Ok(())
}
integration_test!(test_worker_gator_mode_parsing);

/// Verify worker container naming convention
///
/// Worker container should be named `<pod>-worker` following the existing
/// pattern of `<pod>-workspace`, `<pod>-agent`, `<pod>-gator`.
fn test_worker_container_naming() -> Result<()> {
    // This tests the naming convention pattern
    let pod_name = "devaipod-test-orch";
    let expected_worker_name = format!("{}-worker", pod_name);

    assert_eq!(
        expected_worker_name, "devaipod-test-orch-worker",
        "Worker container should follow naming convention"
    );

    // Verify naming patterns are consistent
    let workspace_name = format!("{}-workspace", pod_name);
    let agent_name = format!("{}-agent", pod_name);
    let gator_name = format!("{}-gator", pod_name);

    assert!(
        workspace_name.ends_with("-workspace"),
        "Workspace should end with -workspace"
    );
    assert!(
        agent_name.ends_with("-agent"),
        "Agent should end with -agent"
    );
    assert!(
        gator_name.ends_with("-gator"),
        "Gator should end with -gator"
    );
    assert!(
        expected_worker_name.ends_with("-worker"),
        "Worker should end with -worker"
    );

    Ok(())
}
integration_test!(test_worker_container_naming);

// =============================================================================
// Container tests (require podman)
// =============================================================================

/// Verify that pods do NOT have a worker container by default (orchestration is opt-in)
fn test_pod_no_worker_by_default() -> Result<()> {
    let repo = TestRepo::new()?;
    let pod_name = unique_test_name("test-no-orch");

    let mut pods = PodGuard::new();
    pods.add(&pod_name);

    // Create pod - orchestration is disabled by default
    let output = run_devaipod_in(
        &repo.repo_path,
        &["up", ".", "--name", short_name(&pod_name)],
    )?;

    if !output.success() {
        color_eyre::eyre::bail!("devaipod up failed: {}", output.combined());
    }

    let sh = shell()?;

    // Verify pod was created
    let pod_exists = cmd!(sh, "podman pod exists {pod_name}")
        .ignore_status()
        .output()?;
    assert!(pod_exists.status.success(), "Pod {} should exist", pod_name);

    // List containers in the pod
    let format_names = "{{.Names}}";
    let ps_output = cmd!(
        sh,
        "podman ps --filter pod={pod_name} --format {format_names}"
    )
    .read()?;

    // Orchestration is disabled by default, so no worker container.
    // workspace-v2: agent pods no longer have a separate workspace
    // container — the agent workspace uses a host bind mount.
    assert!(
        ps_output.contains("agent"),
        "Pod should have agent container: {}",
        ps_output
    );
    assert!(
        ps_output.contains("api"),
        "Pod should have api container: {}",
        ps_output
    );
    assert!(
        !ps_output.contains("worker"),
        "Pod should NOT have worker container by default: {}",
        ps_output
    );

    Ok(())
}
podman_integration_test!(test_pod_no_worker_by_default);
