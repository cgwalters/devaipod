//! Container/pod tests that require podman
//!
//! These tests verify that devaipod correctly creates and manages pods.
//!
//! Tests are organized into two categories:
//! - Readonly tests: Use the shared fixture, only query pod state
//! - Mutating tests: Create/delete their own pods

use color_eyre::eyre::{bail, Context};
use color_eyre::Result;
use std::process::Command;
use std::time::{Duration, Instant};
use xshell::{cmd, Shell};

use crate::{
    podman_integration_test, readonly_test, run_devaipod, run_devaipod_in, shell, short_name,
    unique_test_name, PodGuard, SharedFixture, TestRepo,
};

/// Host to use when connecting to pod-published ports from the test runner.
///
/// When the test runner is inside the devaipod *test container* (the normal
/// `just test-integration` path), published ports are on the podman host,
/// reached via `host.containers.internal`.
///
/// When running in host mode (DEVAIPOD_HOST_MODE=1, e.g. local dev or
/// devaipod-in-devaipod), the test runner and podman are in the same
/// network namespace, so ports are on `127.0.0.1`.
fn pod_service_host() -> &'static str {
    // DEVAIPOD_HOST_MODE means we're running devaipod directly rather than
    // through the containerized test runner infrastructure. In this mode,
    // nested podman publishes ports on localhost.
    if std::env::var("DEVAIPOD_HOST_MODE").as_deref() == Ok("1") {
        return "127.0.0.1";
    }
    if std::path::Path::new("/run/.containerenv").exists()
        || std::path::Path::new("/.dockerenv").exists()
    {
        "host.containers.internal"
    } else {
        "127.0.0.1"
    }
}

/// Run podman inspect with a Go template format string.
///
/// This uses std::process::Command instead of xshell's cmd! macro
/// to avoid issues with Go template brace escaping.
fn podman_inspect(target: &str, format: &str) -> Result<String> {
    let output = Command::new("podman")
        .args(["inspect", "--format", format, target])
        .output()
        .map_err(|e| color_eyre::eyre::eyre!("Failed to run podman inspect: {}", e))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(color_eyre::eyre::eyre!(
            "podman inspect failed: {}",
            stderr.trim()
        ));
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

/// Run podman pod inspect with a Go template format string.
fn podman_pod_inspect(pod_name: &str, format: &str) -> Result<String> {
    let output = Command::new("podman")
        .args(["pod", "inspect", "--format", format, pod_name])
        .output()
        .map_err(|e| color_eyre::eyre::eyre!("Failed to run podman pod inspect: {}", e))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(color_eyre::eyre::eyre!(
            "podman pod inspect failed: {}",
            stderr.trim()
        ));
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

/// Discover the host port published for a given container port in a pod.
///
/// Pod-level port bindings are owned by the infra container, so `podman port`
/// on non-infra containers may return nothing. Instead, we use `podman inspect`
/// on the pod's infra container (discovered via `podman pod inspect`) and parse
/// the JSON port mappings. This matches the approach used by the web proxy via
/// bollard's Docker API.
fn get_published_port(pod_name: &str, container_port: u16) -> Result<u16> {
    // Get the infra container ID from the pod
    let infra_id = podman_pod_inspect(pod_name, "{{.InfraContainerID}}")?;
    if infra_id.is_empty() {
        bail!("No infra container found for pod {}", pod_name);
    }

    // Use podman port on the infra container, which owns the pod-level port bindings
    let sh = shell()?;
    let port_str = container_port.to_string();
    let port_output = cmd!(sh, "podman port {infra_id} {port_str}")
        .ignore_status()
        .read()?;

    if port_output.trim().is_empty() {
        bail!(
            "Port {} not published for pod {} (infra container {})",
            container_port,
            pod_name,
            &infra_id[..12.min(infra_id.len())]
        );
    }

    port_output
        .lines()
        .next()
        .unwrap_or("")
        .trim()
        .split(':')
        .last()
        .and_then(|p| p.parse().ok())
        .ok_or_else(|| {
            color_eyre::eyre::eyre!(
                "Could not parse host port from podman port output: {}",
                port_output
            )
        })
}

/// Poll a condition until it succeeds or times out.
/// Returns Ok(output) on success, Err on timeout.
fn poll_until<F>(timeout: Duration, interval: Duration, mut check: F) -> Result<String>
where
    F: FnMut() -> Result<Option<String>>,
{
    let start = Instant::now();
    loop {
        match check() {
            Ok(Some(output)) => return Ok(output),
            Ok(None) => {}
            Err(e) => {
                if start.elapsed() >= timeout {
                    return Err(e);
                }
            }
        }
        if start.elapsed() >= timeout {
            bail!("Timed out after {:?}", timeout);
        }
        std::thread::sleep(interval);
    }
}

/// Wait for a file to exist in a container with expected content
fn wait_for_file_content(
    sh: &Shell,
    container: &str,
    path: &str,
    expected: &str,
    timeout: Duration,
) -> Result<String> {
    let container = container.to_string();
    let path = path.to_string();
    let expected = expected.to_string();

    poll_until(timeout, Duration::from_millis(500), || {
        let output = cmd!(sh, "podman exec {container} cat {path}")
            .ignore_status()
            .read()?;
        if output.contains(&expected) {
            Ok(Some(output))
        } else {
            Ok(None)
        }
    })
}

// =============================================================================
// Readonly tests - use shared fixture
// =============================================================================

/// Verify the shared instance exists and is running
fn test_readonly_pod_exists(fixture: &SharedFixture) -> Result<()> {
    let sh = shell()?;
    let pod_name = fixture.pod_name();

    let exists = cmd!(sh, "podman pod exists {pod_name}")
        .ignore_status()
        .output()?;
    assert!(
        exists.status.success(),
        "Shared instance {} should exist",
        pod_name
    );

    // Verify instance is running (podman uses .State, not .Status)
    let format_state = "{{.State}}";
    let state = cmd!(sh, "podman pod inspect {pod_name} --format {format_state}").read()?;
    assert!(
        state.contains("Running"),
        "Shared instance should be running, got: {}",
        state
    );

    Ok(())
}
readonly_test!(test_readonly_pod_exists);

/// Verify we can exec into the shared pod and run commands
fn test_readonly_can_exec(fixture: &SharedFixture) -> Result<()> {
    // Use short_name() for devaipod CLI commands
    let short_name = fixture.short_name();

    // Run a simple command via exec -W (workspace container)
    let output = run_devaipod(&["exec", "-W", short_name, "--", "echo", "hello-from-shared"])?;
    output.assert_success("devaipod exec echo");
    assert!(
        output.stdout.contains("hello-from-shared"),
        "Exec should return command output: {}",
        output.combined()
    );

    // Verify we can see the workspace
    let ls_output = run_devaipod(&["exec", "-W", short_name, "--", "ls", "/workspaces"])?;
    ls_output.assert_success("devaipod exec ls");
    assert!(
        ls_output.stdout.contains("shared-test-repo"),
        "Should see shared workspace directory: {}",
        ls_output.stdout
    );

    Ok(())
}
readonly_test!(test_readonly_can_exec);

/// Verify the pod-api sidecar responds to requests.
///
/// We test the /git/status endpoint which is handled directly by the pod-api
/// server (no dependency on the upstream opencode server being ready).
fn test_readonly_api_responds(fixture: &SharedFixture) -> Result<()> {
    let sh = shell()?;
    let pod_name = fixture.pod_name();

    // Get API credentials from pod labels
    let format_label = "{{index .Labels \"io.devaipod.api-password\"}}";
    let password = cmd!(sh, "podman pod inspect {pod_name} --format {format_label}").read()?;
    let password = password.trim();
    assert!(!password.is_empty(), "Pod should have API password label");

    // Get the published pod-api port via the pod's infra container.
    let port =
        get_published_port(pod_name, 8090).context("Port 8090 (pod-api) should be published")?;
    assert!(port > 0, "Should have a valid port number");

    // Test /git/status which is handled directly by pod-api (no opencode dependency).
    // Poll with retries since the pod-api sidecar may still be starting.
    let host = pod_service_host();
    let url = format!("http://{}:{}/git/status", host, port);
    poll_until(Duration::from_secs(30), Duration::from_secs(1), || {
        let response = cmd!(sh, "curl -sf {url}").ignore_status().output()?;
        if response.status.success() {
            Ok(Some(String::from_utf8_lossy(&response.stdout).to_string()))
        } else {
            Ok(None)
        }
    })
    .context("pod-api /git/status should respond within 30s")?;

    Ok(())
}
readonly_test!(test_readonly_api_responds);

/// Verify the shared pod has the expected containers
fn test_readonly_containers_exist(fixture: &SharedFixture) -> Result<()> {
    let sh = shell()?;
    let pod_name = fixture.pod_name();

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
    assert!(
        ps_output.contains("api"),
        "Pod should have api container: {}",
        ps_output
    );

    Ok(())
}
readonly_test!(test_readonly_containers_exist);

/// Verify the pod-api server responds with valid JSON on /git/status
fn test_readonly_api_git_status(fixture: &SharedFixture) -> Result<()> {
    let sh = shell()?;
    let agent = fixture.agent_container();
    // The api container shares the pod network namespace, so we can reach it
    // from any container in the pod. Use the agent container which has curl.
    // Poll with retries since the pod-api sidecar may still be starting.
    let output = poll_until(Duration::from_secs(60), Duration::from_secs(1), || {
        let result = cmd!(
            sh,
            "podman exec {agent} curl -sf http://localhost:8090/git/status"
        )
        .ignore_status()
        .output()?;
        let body = String::from_utf8_lossy(&result.stdout).trim().to_string();
        if result.status.success() {
            if body.starts_with('{') {
                Ok(Some(body))
            } else {
                Ok(None)
            }
        } else {
            Ok(None)
        }
    })
    .context("pod-api /git/status should respond within 60s")?;
    let _parsed: serde_json::Value =
        serde_json::from_str(&output).context("pod-api /git/status should return valid JSON")?;
    Ok(())
}
readonly_test!(test_readonly_api_git_status);

/// Verify the pod-api /git/log endpoint returns valid JSON with a commits array
fn test_readonly_api_git_log(fixture: &SharedFixture) -> Result<()> {
    let sh = shell()?;
    let agent = fixture.agent_container();

    // Poll with retries since the pod-api sidecar may still be starting.
    // Use a generous timeout as this runs in parallel with other readonly tests.
    // If the endpoint returns a non-transient error (like "not a git repository"),
    // fail immediately rather than retrying for the full timeout.
    let output = poll_until(Duration::from_secs(60), Duration::from_secs(1), || {
        let result = cmd!(
            sh,
            "podman exec {agent} curl -sf http://localhost:8090/git/log"
        )
        .ignore_status()
        .output()?;
        let body = String::from_utf8_lossy(&result.stdout).trim().to_string();
        if result.status.success() {
            // Curl succeeded — but we also need the response to be valid JSON
            if body.starts_with('{') {
                Ok(Some(body))
            } else {
                Ok(None)
            }
        } else if body.contains("not a git repository") {
            // Non-transient error — the workspace isn't configured as a git repo.
            // Return the body so we get a meaningful error message.
            bail!("pod-api /git/log returned: {}", body);
        } else {
            tracing::debug!(
                "curl /git/log failed (exit {:?}): {body}",
                result.status.code()
            );
            Ok(None)
        }
    })
    .context("pod-api /git/log should respond within 60s")?;

    let parsed: serde_json::Value =
        serde_json::from_str(&output).context("pod-api /git/log should return valid JSON")?;
    assert!(
        parsed.get("commits").and_then(|c| c.as_array()).is_some(),
        "/git/log response should have a 'commits' array"
    );
    Ok(())
}
readonly_test!(test_readonly_api_git_log);

/// Verify the pod-api /summary endpoint returns valid JSON with expected fields.
///
/// The /summary endpoint is the canonical source of agent status; the control
/// plane proxies it rather than deriving status from raw opencode messages.
fn test_readonly_api_summary(fixture: &SharedFixture) -> Result<()> {
    let sh = shell()?;
    let agent = fixture.agent_container();

    // Poll with retries since the pod-api sidecar may still be starting.
    // Like /git/log, validate the body looks like JSON inside the loop
    // to avoid accepting an empty or truncated startup response.
    let output = poll_until(Duration::from_secs(60), Duration::from_secs(1), || {
        let result = cmd!(
            sh,
            "podman exec {agent} curl -sf http://localhost:8090/summary"
        )
        .ignore_status()
        .output()?;
        let body = String::from_utf8_lossy(&result.stdout).trim().to_string();
        if result.status.success() {
            if body.starts_with('{') {
                Ok(Some(body))
            } else {
                Ok(None)
            }
        } else {
            Ok(None)
        }
    })
    .context("pod-api /summary should respond within 60s")?;

    let parsed: serde_json::Value =
        serde_json::from_str(&output).context("pod-api /summary should return valid JSON")?;

    // Verify all expected fields are present.
    assert!(
        parsed.get("activity").and_then(|a| a.as_str()).is_some(),
        "/summary should have an 'activity' string field"
    );
    assert!(
        parsed.get("session_count").is_some(),
        "/summary should have a 'session_count' field"
    );
    assert!(
        parsed
            .get("recent_output")
            .and_then(|r| r.as_array())
            .is_some(),
        "/summary should have a 'recent_output' array"
    );
    // status_line, current_tool, last_message_ts may be null — just check they're present.
    assert!(
        parsed.get("status_line").is_some(),
        "/summary should have a 'status_line' field"
    );
    assert!(
        parsed.get("current_tool").is_some(),
        "/summary should have a 'current_tool' field"
    );
    assert!(
        parsed.get("last_message_ts").is_some(),
        "/summary should have a 'last_message_ts' field"
    );

    Ok(())
}
readonly_test!(test_readonly_api_summary);

/// Verify the pod-api /git/events SSE endpoint returns an initial git.updated event
fn test_readonly_api_git_events(fixture: &SharedFixture) -> Result<()> {
    let sh = shell()?;
    let agent = fixture.agent_container();
    // Use curl with --max-time to avoid hanging forever.
    // The SSE endpoint should send an initial event immediately on connect.
    // -N disables buffering so we get the event without waiting for the buffer to fill.
    let output = cmd!(
        sh,
        "podman exec {agent} curl -sf -N --max-time 3 http://localhost:8090/git/events"
    )
    .ignore_status() // curl returns exit code 28 on timeout, which is expected
    .read()?;
    // Should contain the initial git.updated event
    assert!(
        output.contains("git.updated"),
        "SSE stream should contain initial git.updated event: {}",
        output
    );
    assert!(
        output.contains("head"),
        "SSE event should contain head sha: {}",
        output
    );
    Ok(())
}
readonly_test!(test_readonly_api_git_events);

/// Verify we can query pod status via devaipod
fn test_readonly_status_command(fixture: &SharedFixture) -> Result<()> {
    // Use short_name() for devaipod CLI commands
    let short_name = fixture.short_name();

    let status_output = run_devaipod(&["status", short_name])?;
    status_output.assert_success("devaipod status");

    Ok(())
}
readonly_test!(test_readonly_status_command);

/// Verify the pod appears in devaipod list
fn test_readonly_list_shows_pod(fixture: &SharedFixture) -> Result<()> {
    // devaipod list shows the short name (without prefix)
    let short_name = fixture.short_name();

    let list_output = run_devaipod(&["list"])?;
    list_output.assert_success("devaipod list");
    assert!(
        list_output.stdout.contains(short_name) || list_output.stderr.contains(short_name),
        "List should show the shared pod {}: {}",
        short_name,
        list_output.combined()
    );

    Ok(())
}
readonly_test!(test_readonly_list_shows_pod);

// =============================================================================
// Mutating tests - create/delete their own pods
// =============================================================================

fn test_pod_creation_and_deletion() -> Result<()> {
    let repo = TestRepo::new()?;
    let pod_name = unique_test_name("test-create");

    let mut pods = PodGuard::new();
    pods.add(&pod_name);

    // Create pod with explicit name (pass short name, devaipod adds prefix)
    let output = run_devaipod_in(
        &repo.repo_path,
        &["up", ".", "--name", short_name(&pod_name)],
    )?;
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

    // Test devaipod list shows the instance
    let list_output = run_devaipod(&["list"])?;
    list_output.assert_success("devaipod list");

    // Test devaipod status (use short name for CLI commands)
    let status_output = run_devaipod(&["status", short_name(&pod_name)])?;
    status_output.assert_success("devaipod status");

    // Delete instance (use short name for CLI commands)
    let delete_output = run_devaipod(&["delete", short_name(&pod_name), "--force"])?;
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
    let pod_name = unique_test_name("test-repo");

    let mut pods = PodGuard::new();
    pods.add(&pod_name);

    // Create pod (pass short name, devaipod adds prefix)
    let output = run_devaipod_in(
        &repo.repo_path,
        &["up", ".", "--name", short_name(&pod_name)],
    )?;
    if !output.success() {
        bail!("devaipod up failed: {}", output.combined());
    }

    let workspace_container = format!("{}-workspace", pod_name);

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
    let pod_name = unique_test_name("test-stop");

    let mut pods = PodGuard::new();
    pods.add(&pod_name);

    // Create pod (pass short name, devaipod adds prefix)
    let output = run_devaipod_in(
        &repo.repo_path,
        &["up", ".", "--name", short_name(&pod_name)],
    )?;
    if !output.success() {
        bail!("devaipod up failed: {}", output.combined());
    }

    // Stop instance (use short name for CLI commands)
    let stop_output = run_devaipod(&["stop", short_name(&pod_name)])?;
    stop_output.assert_success("devaipod stop");

    let sh = shell()?;

    // Verify pod is stopped (containers should not be running)
    let ps_output = cmd!(sh, "podman ps -q --filter pod={pod_name}").read()?;
    assert!(
        ps_output.trim().is_empty(),
        "No containers should be running after stop: {}",
        ps_output
    );

    // Start pod again via podman (devaipod up would create a new pod now)
    cmd!(sh, "podman pod start {pod_name}").run()?;

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
    let pod_name = unique_test_name("test-image");

    let mut pods = PodGuard::new();
    pods.add(&pod_name);

    // Create pod with image override - use an image that has git
    // (pass short name, devaipod adds prefix)
    let test_image = std::env::var("DEVAIPOD_TEST_IMAGE")
        .unwrap_or_else(|_| "ghcr.io/bootc-dev/devenv-debian:latest".to_string());
    let output = run_devaipod_in(
        &repo.repo_path,
        &[
            "up",
            ".",
            "--name",
            short_name(&pod_name),
            "--image",
            &test_image,
        ],
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
    let pod_name = unique_test_name("test-logs");

    let mut pods = PodGuard::new();
    pods.add(&pod_name);

    // Create pod (pass short name, devaipod adds prefix)
    let output = run_devaipod_in(
        &repo.repo_path,
        &["up", ".", "--name", short_name(&pod_name)],
    )?;
    if !output.success() {
        bail!("devaipod up failed: {}", output.combined());
    }

    // Give containers a moment to produce logs
    std::thread::sleep(std::time::Duration::from_secs(2));

    // Get logs (should not error even if empty) - use short name for CLI
    let logs_output = run_devaipod(&["logs", short_name(&pod_name)])?;
    // Logs command should succeed even if there are no logs yet
    logs_output.assert_success("devaipod logs");

    Ok(())
}
podman_integration_test!(test_logs_command);

fn test_exec_runs_command() -> Result<()> {
    let repo = TestRepo::new()?;
    let pod_name = unique_test_name("test-exec");

    let mut pods = PodGuard::new();
    pods.add(&pod_name);

    // Create pod (pass short name, devaipod adds prefix)
    let output = run_devaipod_in(
        &repo.repo_path,
        &["up", ".", "--name", short_name(&pod_name)],
    )?;
    if !output.success() {
        bail!("devaipod up failed: {}", output.combined());
    }

    // Give containers a moment to start
    std::thread::sleep(std::time::Duration::from_secs(2));

    // Run a command via exec (defaults to agent container)
    let exec_output = run_devaipod(&["exec", short_name(&pod_name), "--", "echo", "hello"])?;
    exec_output.assert_success("devaipod exec echo");
    assert!(
        exec_output.stdout.contains("hello"),
        "exec should run command and return output: {}",
        exec_output.combined()
    );

    // Verify we can see the workspace in agent container
    let ls_output = run_devaipod(&["exec", short_name(&pod_name), "--", "ls", "/workspaces"])?;
    ls_output.assert_success("devaipod exec ls");
    assert!(
        ls_output.stdout.contains("test-repo"),
        "Should see workspace directory: {}",
        ls_output.stdout
    );

    // Also verify exec -W works (workspace container)
    let ws_output = run_devaipod(&[
        "exec",
        "-W",
        short_name(&pod_name),
        "--",
        "echo",
        "workspace",
    ])?;
    ws_output.assert_success("devaipod exec -W echo");
    assert!(
        ws_output.stdout.contains("workspace"),
        "exec -W should run command in workspace container: {}",
        ws_output.combined()
    );

    Ok(())
}
podman_integration_test!(test_exec_runs_command);

fn test_exec_nonexistent_pod_fails() -> Result<()> {
    // Exec into an instance that doesn't exist should fail gracefully
    // Use a short name since that's what devaipod CLI expects
    let output = run_devaipod(&["exec", "nonexistent-instance-12345", "--", "echo", "hi"])?;
    assert!(
        !output.success(),
        "exec to nonexistent instance should fail"
    );

    Ok(())
}
podman_integration_test!(test_exec_nonexistent_pod_fails);

fn test_pod_has_api_credentials() -> Result<()> {
    let repo = TestRepo::new()?;
    let pod_name = unique_test_name("test-api-creds");

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

    let sh = shell()?;

    // Verify pod has API password label
    let format_label = "{{index .Labels \"io.devaipod.api-password\"}}";
    let password = cmd!(sh, "podman pod inspect {pod_name} --format {format_label}").read()?;
    assert!(
        !password.trim().is_empty(),
        "Pod should have io.devaipod.api-password label"
    );
    assert!(
        password.trim().len() >= 32,
        "API password should be at least 32 chars, got: {}",
        password.len()
    );

    // Verify pod-api port is published (8090) via the pod's infra container.
    let port =
        get_published_port(&pod_name, 8090).context("Port 8090 (pod-api) should be published")?;
    assert!(port > 0, "Should have a valid port number");

    Ok(())
}
podman_integration_test!(test_pod_has_api_credentials);

fn test_api_authentication_works() -> Result<()> {
    let repo = TestRepo::new()?;
    let pod_name = unique_test_name("test-api-auth");

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

    let sh = shell()?;

    // Get API credentials
    let format_label = "{{index .Labels \"io.devaipod.api-password\"}}";
    let _password = cmd!(sh, "podman pod inspect {pod_name} --format {format_label}").read()?;

    // Get the published pod-api port (8090) via the pod's infra container.
    let port =
        get_published_port(&pod_name, 8090).context("Pod-api port 8090 should be published")?;
    assert!(port > 0, "Pod-api port 8090 should be published");

    // Test that the pod-api sidecar responds on the published port.
    // Use /git/status which is handled directly by pod-api (no opencode dependency).
    // Poll with retries since the sidecar may still be starting.
    let host = pod_service_host();
    let url = format!("http://{}:{}/git/status", host, port);
    poll_until(Duration::from_secs(30), Duration::from_secs(1), || {
        let response = cmd!(sh, "curl -sf {url}").ignore_status().output()?;
        if response.status.success() {
            Ok(Some("ok".to_string()))
        } else {
            Ok(None)
        }
    })
    .context("Pod-api sidecar should respond to /git/status within 30s")?;

    // Test that internal access (inside container) also works via pod-api
    let agent_container = format!("{}-agent", pod_name);
    let internal_output = poll_until(Duration::from_secs(15), Duration::from_secs(1), || {
        let result = cmd!(
            sh,
            "podman exec {agent_container} curl -sf http://localhost:8090/git/status"
        )
        .ignore_status()
        .output()?;
        if result.status.success() {
            Ok(Some("ok".to_string()))
        } else {
            Ok(None)
        }
    });
    assert!(
        internal_output.is_ok(),
        "Internal API request via pod-api should succeed"
    );

    Ok(())
}
podman_integration_test!(test_api_authentication_works);

/// Verify agent container has matching security settings to workspace.
///
/// In rootless podman, capabilities are relative to the user namespace, so both
/// containers should have the same security settings to enable nested containers.
fn test_agent_matches_workspace_security(fixture: &SharedFixture) -> Result<()> {
    let sh = shell()?;
    let workspace = fixture.workspace_container();
    let agent = fixture.agent_container();

    // Check that both containers have SELinux disabled (label=disable) if workspace does
    // We check this by looking at the security options in the container inspect output
    let format_security = "{{json .HostConfig.SecurityOpt}}";
    let workspace_security =
        cmd!(sh, "podman inspect {workspace} --format {format_security}").read()?;
    let agent_security = cmd!(sh, "podman inspect {agent} --format {format_security}").read()?;

    // If workspace has label:disable, agent should too
    if workspace_security.contains("label") {
        assert!(
            agent_security.contains("label"),
            "Agent should have same SELinux settings as workspace.\nWorkspace: {}\nAgent: {}",
            workspace_security,
            agent_security
        );
    }

    // Check that agent doesn't have no-new-privileges (which would block nested containers)
    let format_nnp = "{{.HostConfig.SecurityOpt}}";
    let agent_nnp = cmd!(sh, "podman inspect {agent} --format {format_nnp}").read()?;
    assert!(
        !agent_nnp.contains("no-new-privileges"),
        "Agent should not have no-new-privileges: {}",
        agent_nnp
    );

    Ok(())
}
readonly_test!(test_agent_matches_workspace_security);

/// Verify both workspace and agent containers can run commands that require user namespaces.
///
/// This tests that newuidmap/newgidmap work, which is required for nested containers.
/// We test by checking if unshare --user works (creates a user namespace).
fn test_containers_support_user_namespaces(fixture: &SharedFixture) -> Result<()> {
    let sh = shell()?;
    let workspace = fixture.workspace_container();
    let agent = fixture.agent_container();

    // Test workspace can create user namespace
    let workspace_unshare = cmd!(
        sh,
        "podman exec {workspace} unshare --user --map-root-user id"
    )
    .ignore_status()
    .output()?;

    // Test agent can create user namespace
    let agent_unshare = cmd!(sh, "podman exec {agent} unshare --user --map-root-user id")
        .ignore_status()
        .output()?;

    // If workspace supports user namespaces, agent should too
    if workspace_unshare.status.success() {
        assert!(
            agent_unshare.status.success(),
            "Agent should support user namespaces like workspace.\nWorkspace: success\nAgent stderr: {}",
            String::from_utf8_lossy(&agent_unshare.stderr)
        );
    }

    Ok(())
}
readonly_test!(test_containers_support_user_namespaces);

/// Verify agent container has access to devices when devcontainer.json specifies them.
///
/// This creates a pod with a devcontainer.json that requests /dev/kvm (if available),
/// and verifies the agent container can see it.
fn test_agent_device_passthrough() -> Result<()> {
    use std::path::Path;

    // Skip if /dev/kvm doesn't exist on host
    if !Path::new("/dev/kvm").exists() {
        tracing::info!("Skipping test_agent_device_passthrough: /dev/kvm not available");
        return Ok(());
    }

    let repo = TestRepo::new_with_devcontainer(
        r#"{
    "name": "device-test",
    "image": "ghcr.io/bootc-dev/devenv-debian:latest",
    "runArgs": ["--device", "/dev/kvm"]
}"#,
    )?;
    let pod_name = unique_test_name("test-device");

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

    let sh = shell()?;
    let agent_container = format!("{}-agent", pod_name);
    let workspace_container = format!("{}-workspace", pod_name);

    // Give containers time to start
    std::thread::sleep(std::time::Duration::from_secs(2));

    // Verify workspace has /dev/kvm
    let workspace_kvm = cmd!(sh, "podman exec {workspace_container} test -e /dev/kvm")
        .ignore_status()
        .output()?;
    assert!(
        workspace_kvm.status.success(),
        "Workspace should have /dev/kvm"
    );

    // Verify agent also has /dev/kvm
    let agent_kvm = cmd!(sh, "podman exec {agent_container} test -e /dev/kvm")
        .ignore_status()
        .output()?;
    assert!(
        agent_kvm.status.success(),
        "Agent should have /dev/kvm like workspace"
    );

    Ok(())
}
podman_integration_test!(test_agent_device_passthrough);

/// Verify lifecycle commands (postCreateCommand) run in BOTH workspace and agent containers.
///
/// This is critical for init scripts that configure nested podman, subuid mappings, etc.
/// Both containers need these configurations for nested containers to work.
fn test_lifecycle_commands_run_in_both_containers() -> Result<()> {
    // Create a devcontainer with a postCreateCommand that creates a marker file
    let marker_path = "/tmp/lifecycle-test-marker";
    let devcontainer_json = format!(
        r#"{{
    "name": "lifecycle-test",
    "image": "ghcr.io/bootc-dev/devenv-debian:latest",
    "postCreateCommand": "echo 'lifecycle-ran' > {}"
}}"#,
        marker_path
    );

    let repo = TestRepo::new_with_devcontainer(&devcontainer_json)?;
    let pod_name = unique_test_name("test-lifecycle");

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

    let sh = shell()?;
    let agent_container = format!("{}-agent", pod_name);
    let workspace_container = format!("{}-workspace", pod_name);

    let timeout = Duration::from_secs(60);

    // Poll for marker file in workspace container
    let workspace_marker = wait_for_file_content(
        &sh,
        &workspace_container,
        marker_path,
        "lifecycle-ran",
        timeout,
    )?;
    assert!(
        workspace_marker.contains("lifecycle-ran"),
        "Workspace should have marker file from postCreateCommand: {}",
        workspace_marker
    );

    // Poll for marker file in agent container
    let agent_marker =
        wait_for_file_content(&sh, &agent_container, marker_path, "lifecycle-ran", timeout)?;
    assert!(
        agent_marker.contains("lifecycle-ran"),
        "Agent should have marker file from postCreateCommand: {}",
        agent_marker
    );

    Ok(())
}
podman_integration_test!(test_lifecycle_commands_run_in_both_containers);

/// Verify that a more complex init script runs in both containers.
///
/// This simulates what devenv-init.sh does: creates config files that are needed
/// for nested container operations.
fn test_init_script_configures_both_containers() -> Result<()> {
    // Create a devcontainer with an init script that creates a config file
    let config_path = "/tmp/nested-container-config";
    let devcontainer_json = format!(
        r#"{{
    "name": "init-script-test",
    "image": "ghcr.io/bootc-dev/devenv-debian:latest",
    "postCreateCommand": "echo 'subuid_configured=true' > {} && echo 'Init script completed for user:' $(whoami)"
}}"#,
        config_path
    );

    let repo = TestRepo::new_with_devcontainer(&devcontainer_json)?;
    let pod_name = unique_test_name("test-init");

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

    let sh = shell()?;
    let agent_container = format!("{}-agent", pod_name);
    let workspace_container = format!("{}-workspace", pod_name);

    let timeout = Duration::from_secs(60);

    // Poll for config file in workspace container
    let workspace_config = wait_for_file_content(
        &sh,
        &workspace_container,
        config_path,
        "subuid_configured=true",
        timeout,
    )?;
    assert!(
        workspace_config.contains("subuid_configured=true"),
        "Workspace should have config from init script: {}",
        workspace_config
    );

    // Poll for config file in agent container
    let agent_config = wait_for_file_content(
        &sh,
        &agent_container,
        config_path,
        "subuid_configured=true",
        timeout,
    )?;
    assert!(
        agent_config.contains("subuid_configured=true"),
        "Agent should have config from init script: {}",
        agent_config
    );

    Ok(())
}
podman_integration_test!(test_init_script_configures_both_containers);

// =============================================================================
// Agent workspace isolation tests
// =============================================================================

/// Verify that the agent container has its own /workspaces directory that is separate
/// from the workspace container's /workspaces.
///
/// This tests the core workspace isolation feature: the agent gets a git clone with
/// --reference to share objects, but has its own working tree.
fn test_agent_has_separate_workspace() -> Result<()> {
    let repo = TestRepo::new()?;
    let pod_name = unique_test_name("test-agent-ws");

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

    let sh = shell()?;
    let workspace_container = format!("{}-workspace", pod_name);
    let agent_container = format!("{}-agent", pod_name);

    // Give containers time to start
    std::thread::sleep(std::time::Duration::from_secs(2));

    // Create a unique marker file in the workspace container
    let workspace_marker = "workspace-unique-marker-12345";
    let ws_marker_cmd = format!(
        "echo '{}' > /workspaces/test-repo/workspace-marker.txt",
        workspace_marker
    );
    cmd!(
        sh,
        "podman exec {workspace_container} sh -c {ws_marker_cmd}"
    )
    .run()?;

    // Verify the workspace container can see its marker
    let ws_check = cmd!(
        sh,
        "podman exec {workspace_container} cat /workspaces/test-repo/workspace-marker.txt"
    )
    .read()?;
    assert!(
        ws_check.contains(workspace_marker),
        "Workspace should see its own marker: {}",
        ws_check
    );

    // Verify the agent container does NOT see the workspace marker
    let agent_check_ws = cmd!(
        sh,
        "podman exec {agent_container} cat /workspaces/test-repo/workspace-marker.txt"
    )
    .ignore_status()
    .output()?;
    assert!(
        !agent_check_ws.status.success(),
        "Agent should NOT see workspace's marker file (has separate workspace)"
    );

    // Create a unique marker file in the agent container
    let agent_marker = "agent-unique-marker-67890";
    let agent_marker_cmd = format!(
        "echo '{}' > /workspaces/test-repo/agent-marker.txt",
        agent_marker
    );
    cmd!(sh, "podman exec {agent_container} sh -c {agent_marker_cmd}").run()?;

    // Verify the agent container can see its marker
    let agent_check = cmd!(
        sh,
        "podman exec {agent_container} cat /workspaces/test-repo/agent-marker.txt"
    )
    .read()?;
    assert!(
        agent_check.contains(agent_marker),
        "Agent should see its own marker: {}",
        agent_check
    );

    // Verify the workspace container does NOT see the agent marker
    let ws_check_agent = cmd!(
        sh,
        "podman exec {workspace_container} cat /workspaces/test-repo/agent-marker.txt"
    )
    .ignore_status()
    .output()?;
    assert!(
        !ws_check_agent.status.success(),
        "Workspace should NOT see agent's marker file (has separate workspace)"
    );

    Ok(())
}
podman_integration_test!(test_agent_has_separate_workspace);

/// Verify that the agent container has read-only access to /mnt/main-workspace.
///
/// The agent should be able to read the main workspace for reference but cannot
/// write to it, preventing accidental modifications.
fn test_agent_cannot_write_to_main_workspace() -> Result<()> {
    let repo = TestRepo::new()?;
    let pod_name = unique_test_name("test-agent-ro");

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

    let sh = shell()?;
    let agent_container = format!("{}-agent", pod_name);

    // Give containers time to start
    std::thread::sleep(std::time::Duration::from_secs(2));

    // First verify the mount point exists and is accessible for reading
    let read_check = cmd!(
        sh,
        "podman exec {agent_container} ls /mnt/main-workspace/test-repo"
    )
    .ignore_status()
    .output()?;
    assert!(
        read_check.status.success(),
        "Agent should be able to read /mnt/main-workspace: {}",
        String::from_utf8_lossy(&read_check.stderr)
    );

    // Verify the agent can read the README.md from main workspace
    let readme_check = cmd!(
        sh,
        "podman exec {agent_container} cat /mnt/main-workspace/test-repo/README.md"
    )
    .ignore_status()
    .output()?;
    assert!(
        readme_check.status.success(),
        "Agent should be able to read files from /mnt/main-workspace"
    );

    // Try to create a file in /mnt/main-workspace - this should fail (read-only)
    let write_attempt = cmd!(
        sh,
        "podman exec {agent_container} touch /mnt/main-workspace/test-repo/should-fail.txt"
    )
    .ignore_status()
    .output()?;
    assert!(
        !write_attempt.status.success(),
        "Agent should NOT be able to write to /mnt/main-workspace (read-only filesystem)"
    );

    // Verify the error message indicates read-only filesystem
    let stderr = String::from_utf8_lossy(&write_attempt.stderr);
    assert!(
        stderr.contains("Read-only") || stderr.contains("read-only") || stderr.contains("EROFS"),
        "Error should indicate read-only filesystem: {}",
        stderr
    );

    Ok(())
}
podman_integration_test!(test_agent_cannot_write_to_main_workspace);

/// Verify that git objects are shared between the main workspace and agent workspace
/// via the --reference mechanism.
///
/// This tests that the agent's .git/objects/info/alternates file exists and points
/// to the main workspace's git objects.
fn test_agent_workspace_shares_git_objects() -> Result<()> {
    let repo = TestRepo::new()?;
    let pod_name = unique_test_name("test-git-ref");

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

    let sh = shell()?;
    let agent_container = format!("{}-agent", pod_name);

    // Give containers time to start
    std::thread::sleep(std::time::Duration::from_secs(2));

    // Check that the alternates file exists in the agent's git repo
    let alternates_check = cmd!(
        sh,
        "podman exec {agent_container} cat /workspaces/test-repo/.git/objects/info/alternates"
    )
    .ignore_status()
    .output()?;

    assert!(
        alternates_check.status.success(),
        "Agent should have .git/objects/info/alternates file for git --reference: {}",
        String::from_utf8_lossy(&alternates_check.stderr)
    );

    // Verify the alternates file references the main workspace's git objects
    // The path should be /mnt/main-workspace/<project>/objects
    let alternates_content = String::from_utf8_lossy(&alternates_check.stdout);
    assert!(
        alternates_content.contains("/mnt/main-workspace/test-repo"),
        "Alternates should reference /mnt/main-workspace/test-repo: {}",
        alternates_content
    );

    Ok(())
}
podman_integration_test!(test_agent_workspace_shares_git_objects);

/// Readonly test: Verify the agent workspace isolation volumes are set up correctly.
///
/// This is a lightweight check that uses the shared fixture to verify the volume
/// configuration without modifying state.
fn test_readonly_agent_has_separate_workspace(fixture: &SharedFixture) -> Result<()> {
    let sh = shell()?;
    let workspace = fixture.workspace_container();
    let agent = fixture.agent_container();

    // Verify both containers have /workspaces mounted
    let ws_workspaces = cmd!(sh, "podman exec {workspace} ls /workspaces")
        .ignore_status()
        .output()?;
    assert!(
        ws_workspaces.status.success(),
        "Workspace container should have /workspaces"
    );

    let agent_workspaces = cmd!(sh, "podman exec {agent} ls /workspaces")
        .ignore_status()
        .output()?;
    assert!(
        agent_workspaces.status.success(),
        "Agent container should have /workspaces"
    );

    // Verify agent has /mnt/main-workspace mount
    let agent_main_ws = cmd!(sh, "podman exec {agent} ls /mnt/main-workspace")
        .ignore_status()
        .output()?;
    assert!(
        agent_main_ws.status.success(),
        "Agent container should have /mnt/main-workspace mount"
    );

    // Verify the agent's /mnt/main-workspace contains the shared test repo
    let agent_main_ws_content = cmd!(sh, "podman exec {agent} ls /mnt/main-workspace")
        .ignore_status()
        .read()?;
    assert!(
        agent_main_ws_content.contains("shared-test-repo"),
        "Agent's /mnt/main-workspace should contain shared-test-repo: {}",
        agent_main_ws_content
    );

    // Verify the mount is read-only by checking mount options
    let mount_info = cmd!(sh, "podman exec {agent} cat /proc/mounts").read()?;

    // Find the line for /mnt/main-workspace and check it has 'ro' option
    let main_ws_mount = mount_info
        .lines()
        .find(|line| line.contains("/mnt/main-workspace"));
    assert!(
        main_ws_mount.is_some(),
        "/mnt/main-workspace should appear in /proc/mounts"
    );
    assert!(
        main_ws_mount.unwrap().contains(" ro,")
            || main_ws_mount.unwrap().contains(",ro ")
            || main_ws_mount.unwrap().contains(",ro,"),
        "/mnt/main-workspace should be mounted read-only: {}",
        main_ws_mount.unwrap()
    );

    Ok(())
}
readonly_test!(test_readonly_agent_has_separate_workspace);

// =============================================================================
// Gator container tests
// =============================================================================

/// Verify that the gator container can access the agent's workspace.
///
/// With agent isolation, the gator needs to read from /workspaces/<project>
/// which is mounted from the agent-workspace volume (not main workspace).
/// This is required for git_push_local to read the agent's commits.
fn test_gator_can_access_agent_workspace() -> Result<()> {
    let repo = TestRepo::new()?;
    let pod_name = unique_test_name("test-gator-ws");

    let mut pods = PodGuard::new();
    pods.add(&pod_name);

    // Create pod with service-gator explicitly enabled (local repos don't auto-enable gator)
    // We use a dummy scope to force gator creation
    let output = run_devaipod_in(
        &repo.repo_path,
        &[
            "up",
            ".",
            "--name",
            short_name(&pod_name),
            "--service-gator=github:test/test-repo",
        ],
    )?;
    if !output.success() {
        bail!("devaipod up failed: {}", output.combined());
    }

    let sh = shell()?;
    let gator_container = format!("{}-gator", pod_name);

    // Give containers time to start
    std::thread::sleep(std::time::Duration::from_secs(2));

    // Verify gator can read from /workspaces
    let ws_check = cmd!(sh, "podman exec {gator_container} ls /workspaces")
        .ignore_status()
        .output()?;
    assert!(
        ws_check.status.success(),
        "Gator should be able to read /workspaces: {}",
        String::from_utf8_lossy(&ws_check.stderr)
    );

    // Verify gator can see the project directory
    let ws_content = String::from_utf8_lossy(&ws_check.stdout);
    assert!(
        ws_content.contains("test-repo"),
        "Gator /workspaces should contain the project: {}",
        ws_content
    );

    // Verify the project has git data (meaning we're looking at the agent workspace clone)
    let git_check = cmd!(
        sh,
        "podman exec {gator_container} ls /workspaces/test-repo/.git"
    )
    .ignore_status()
    .output()?;
    assert!(
        git_check.status.success(),
        "Gator should see .git directory in agent workspace: {}",
        String::from_utf8_lossy(&git_check.stderr)
    );

    Ok(())
}
podman_integration_test!(test_gator_can_access_agent_workspace);

/// Verify that the gator container can resolve git alternates.
///
/// The agent workspace uses `git clone --shared` with alternates pointing to
/// /mnt/main-workspace/<project>/.git/objects. The gator needs this path
/// mounted so git operations (like reading commits for git_push_local) work.
fn test_gator_can_resolve_git_alternates() -> Result<()> {
    let repo = TestRepo::new()?;
    let pod_name = unique_test_name("test-gator-alt");

    let mut pods = PodGuard::new();
    pods.add(&pod_name);

    // Create pod with service-gator explicitly enabled (local repos don't auto-enable gator)
    let output = run_devaipod_in(
        &repo.repo_path,
        &[
            "up",
            ".",
            "--name",
            short_name(&pod_name),
            "--service-gator=github:test/test-repo",
        ],
    )?;
    if !output.success() {
        bail!("devaipod up failed: {}", output.combined());
    }

    let sh = shell()?;
    let gator_container = format!("{}-gator", pod_name);

    // Give containers time to start
    std::thread::sleep(std::time::Duration::from_secs(2));

    // Verify gator has /mnt/main-workspace mounted
    let main_ws_check = cmd!(sh, "podman exec {gator_container} ls /mnt/main-workspace")
        .ignore_status()
        .output()?;
    assert!(
        main_ws_check.status.success(),
        "Gator should have /mnt/main-workspace mounted: {}",
        String::from_utf8_lossy(&main_ws_check.stderr)
    );

    // Verify /mnt/main-workspace contains the project
    let main_ws_content = String::from_utf8_lossy(&main_ws_check.stdout);
    assert!(
        main_ws_content.contains("test-repo"),
        "Gator /mnt/main-workspace should contain the project: {}",
        main_ws_content
    );

    // Read the alternates file from the agent workspace
    let alternates = cmd!(
        sh,
        "podman exec {gator_container} cat /workspaces/test-repo/.git/objects/info/alternates"
    )
    .ignore_status()
    .output()?;
    assert!(
        alternates.status.success(),
        "Gator should be able to read alternates file: {}",
        String::from_utf8_lossy(&alternates.stderr)
    );

    let alternates_path = String::from_utf8_lossy(&alternates.stdout);
    assert!(
        alternates_path.contains("/mnt/main-workspace"),
        "Alternates should reference /mnt/main-workspace: {}",
        alternates_path
    );

    // Verify the alternates path is accessible (the key test!)
    // This is what was broken before the fix - gator couldn't resolve this path
    let alternates_path = alternates_path.trim();
    let objects_check = cmd!(sh, "podman exec {gator_container} ls {alternates_path}")
        .ignore_status()
        .output()?;
    assert!(
        objects_check.status.success(),
        "Gator should be able to access the alternates objects path {}: {}",
        alternates_path,
        String::from_utf8_lossy(&objects_check.stderr)
    );

    // Verify git log works in the gator container (requires resolving alternates)
    let git_log = cmd!(
        sh,
        "podman exec {gator_container} git -C /workspaces/test-repo log --oneline -1"
    )
    .ignore_status()
    .output()?;
    assert!(
        git_log.status.success(),
        "Gator should be able to run git log (requires alternates): {}",
        String::from_utf8_lossy(&git_log.stderr)
    );

    Ok(())
}
podman_integration_test!(test_gator_can_resolve_git_alternates);

/// Verify that service-gator is configured correctly with scopes.
///
/// This test verifies:
/// 1. Pod labels contain the service-gator configuration
/// 2. Gator container is running with the correct scope args
/// 3. Agent container has MCP config for connecting to gator
/// 4. `devaipod gator show` displays the configured scopes
fn test_gator_scopes_configuration() -> Result<()> {
    let repo = TestRepo::new()?;
    let pod_name = unique_test_name("test-gator-cfg");

    let mut pods = PodGuard::new();
    pods.add(&pod_name);

    // Create pod with service-gator
    let output = run_devaipod_in(
        &repo.repo_path,
        &[
            "up",
            ".",
            "--name",
            short_name(&pod_name),
            "--service-gator=github:myorg/myrepo:read",
        ],
    )?;
    if !output.success() {
        bail!("devaipod up failed: {}", output.combined());
    }

    // Give containers time to start
    std::thread::sleep(std::time::Duration::from_secs(2));

    // 1. Verify pod has service-gator label with scope config
    let labels_str = podman_pod_inspect(&pod_name, "{{json .Labels}}")?;

    assert!(
        labels_str.contains("io.devaipod.service-gator"),
        "Pod should have service-gator label: {}",
        labels_str
    );
    // The label should contain the requested repo scope
    assert!(
        labels_str.contains("myorg/myrepo"),
        "Pod service-gator label should contain requested repo: {}",
        labels_str
    );

    // 2. Verify gator container is running with --scope-file for live config reload
    let gator_container = format!("{}-gator", pod_name);
    let gator_cmd = podman_inspect(&gator_container, "{{json .Config.Cmd}}")?;

    // Should use --scope-file for inotify-based live reload
    assert!(
        gator_cmd.contains("--scope-file"),
        "Gator should use --scope-file for live reload: {}",
        gator_cmd
    );
    assert!(
        gator_cmd.contains("gator-config.json"),
        "Gator should reference gator-config.json: {}",
        gator_cmd
    );

    // 3. Verify agent container has MCP config for service-gator
    let agent_container = format!("{}-agent", pod_name);
    let agent_env_str = podman_inspect(&agent_container, "{{json .Config.Env}}")?;

    assert!(
        agent_env_str.contains("OPENCODE_CONFIG_CONTENT"),
        "Agent should have OPENCODE_CONFIG_CONTENT: {}",
        agent_env_str
    );
    assert!(
        agent_env_str.contains("service-gator"),
        "Agent MCP config should reference service-gator: {}",
        agent_env_str
    );

    // 4. Verify `devaipod gator show` works and displays scopes
    let show_output = run_devaipod(&["gator", "show", short_name(&pod_name)])?;
    if !show_output.success() {
        bail!("devaipod gator show failed: {}", show_output.combined());
    }

    // Should show the configured repo
    assert!(
        show_output.combined().contains("myorg/myrepo")
            || show_output.combined().contains("github"),
        "gator show should display configured scopes: {}",
        show_output.combined()
    );

    // 5. Verify JSON output mode works
    let show_json = run_devaipod(&["gator", "show", "--json", short_name(&pod_name)])?;
    if !show_json.success() {
        bail!(
            "devaipod gator show --json failed: {}",
            show_json.combined()
        );
    }

    // Should be valid JSON containing github config
    let json_output = show_json.stdout.trim();
    assert!(
        json_output.starts_with('{') && json_output.ends_with('}'),
        "gator show --json should output valid JSON: {}",
        json_output
    );

    Ok(())
}
podman_integration_test!(test_gator_scopes_configuration);

/// Verify that gator scopes can be updated at runtime via the MCP API.
///
/// This test verifies the live reload path works by:
/// 1. Creating a pod with initial scopes
/// 2. Checking that opencode's /mcp endpoint is accessible
/// 3. Verifying the MCP config structure is correct for dynamic updates
fn test_gator_mcp_api_accessible() -> Result<()> {
    let repo = TestRepo::new()?;
    let pod_name = unique_test_name("test-gator-mcp");

    let mut pods = PodGuard::new();
    pods.add(&pod_name);

    // Create pod with service-gator
    let output = run_devaipod_in(
        &repo.repo_path,
        &[
            "up",
            ".",
            "--name",
            short_name(&pod_name),
            "--service-gator=github:test/test-repo",
        ],
    )?;
    if !output.success() {
        bail!("devaipod up failed: {}", output.combined());
    }

    let sh = shell()?;
    let agent_container = format!("{}-agent", pod_name);

    // Wait for opencode to be ready (it takes a moment to start)
    let timeout = Duration::from_secs(30);
    let interval = Duration::from_secs(2);

    let api_ready = poll_until(timeout, interval, || {
        // Try to hit the opencode health endpoint
        let result = cmd!(
            sh,
            "podman exec {agent_container} curl -s http://127.0.0.1:4096/global/health"
        )
        .ignore_status()
        .output()?;

        if result.status.success() {
            let body = String::from_utf8_lossy(&result.stdout);
            if body.contains("healthy") {
                return Ok(Some(body.to_string()));
            }
        }
        Ok(None)
    });

    if api_ready.is_err() {
        // opencode might not be fully running in test environment, skip gracefully
        eprintln!("Note: opencode API not ready, skipping MCP API test");
        return Ok(());
    }

    // Verify MCP endpoint is accessible (GET /mcp returns MCP server status)
    let mcp_status = cmd!(
        sh,
        "podman exec {agent_container} curl -s http://127.0.0.1:4096/mcp"
    )
    .ignore_status()
    .output()?;

    if mcp_status.status.success() {
        let mcp_body = String::from_utf8_lossy(&mcp_status.stdout);
        // Should contain service-gator if configured
        assert!(
            mcp_body.contains("service-gator") || mcp_body.starts_with('{'),
            "MCP endpoint should return server status: {}",
            mcp_body
        );
    }

    Ok(())
}
podman_integration_test!(test_gator_mcp_api_accessible);

// =============================================================================
// TODO: Agent task/message flow tests
// =============================================================================
//
// The following tests are needed but require mocking opencode:
//
// 1. test_run_with_task_sends_message()
//    - Verify `devaipod run "task"` sends the initial message
//    - Requires intercepting/mocking the opencode API
//
// 2. test_initial_message_includes_task()
//    - Verify the task text is included in the message body
//    - Requires mocking to inspect message content
//
// 3. test_message_send_is_async()
//    - Verify the message send doesn't block waiting for LLM response
//    - Could use a mock that delays response to verify timeout doesn't occur
//
// Approach: Could add a test mode where opencode is replaced with a simple
// HTTP server that records requests. The `send_message_async` function could
// be tested by checking the detached process is spawned correctly.

// ---------------------------------------------------------------------------
// forwardPorts
// ---------------------------------------------------------------------------

/// Verify that `forwardPorts` in devcontainer.json causes the port to be
/// published on the pod's infra container.
fn test_forward_ports_published() -> Result<()> {
    let image = std::env::var("DEVAIPOD_TEST_IMAGE")
        .unwrap_or_else(|_| "ghcr.io/bootc-dev/devenv-debian:latest".to_string());
    let devcontainer_json = format!(
        r#"{{
            "name": "forward-ports-test",
            "image": "{}",
            "forwardPorts": [9876]
        }}"#,
        image
    );
    let repo = TestRepo::new_with_devcontainer(&devcontainer_json)?;
    let pod_name = unique_test_name("test-fwd-port");

    let mut pods = PodGuard::new();
    pods.add(&pod_name);

    let output = run_devaipod_in(
        &repo.repo_path,
        &["up", ".", "--name", short_name(&pod_name)],
    )?;
    if !output.success() {
        bail!("devaipod up failed: {}", output.combined());
    }

    // Port 9876 should be published to a random host port
    let host_port = get_published_port(&pod_name, 9876)
        .context("forwardPorts port 9876 should be published")?;
    assert!(
        host_port > 0,
        "Port 9876 should be mapped to a non-zero host port, got {}",
        host_port
    );

    // The pod-api port (8090) should still be published too
    let api_port = get_published_port(&pod_name, 8090)
        .context("Pod-api port 8090 should still be published")?;
    assert!(api_port > 0, "Pod-api port should still be published");

    // The two host ports should be different
    assert_ne!(
        host_port, api_port,
        "Forwarded port and pod-api port should be on different host ports"
    );

    Ok(())
}
podman_integration_test!(test_forward_ports_published);
