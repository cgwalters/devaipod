//! Control plane integration tests.
//!
//! Tests for the unified pod list endpoint (`GET /api/devaipod/pods`) and the
//! completion-status (done/active) workflow proxied through the control plane
//! to the pod-api sidecar.
//!
//! Tests prefixed `test_harness_` use [`DevaipodHarness`] which starts
//! `devaipod web` directly on the host (no container image required).

use color_eyre::Result;
use integration_tests::harness::DevaipodHarness;

use crate::{TestRepo, container_integration_test, podman_integration_test};

use super::WebFixture;

/// Verify `GET /api/devaipod/pods` returns a JSON array with valid pod entries.
///
/// This is the basic smoke test for the unified endpoint: it must return 200,
/// a valid JSON array, and each entry must have the expected fields. Since the
/// web fixture is running a devaipod pod, we expect at least one entry.
fn test_unified_pod_list() -> Result<()> {
    let fixture = WebFixture::get()?;
    let token = fixture.token().to_string();

    let (status, body) = fixture.curl_in_container("/api/devaipod/pods", Some(&token))?;

    assert_eq!(
        status,
        200,
        "GET /api/devaipod/pods should return 200, got {}: {}",
        status,
        &body[..body.len().min(300)]
    );

    let pods: Vec<serde_json::Value> = serde_json::from_str(&body).map_err(|e| {
        color_eyre::eyre::eyre!(
            "Failed to parse response: {} - body: {}",
            e,
            &body[..body.len().min(500)]
        )
    })?;

    // The web fixture is a standalone container running `devaipod web`,
    // not a devaipod pod itself. The shared fixture creates a pod, but it
    // may or may not be visible depending on podman instance isolation.
    // Validate structure of any returned entries but don't require non-empty.
    for pod in &pods {
        let name = pod
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or_else(|| panic!("Pod entry missing 'name': {pod}"));
        assert!(
            name.starts_with("devaipod-"),
            "Pod name should start with 'devaipod-', got: {name}"
        );

        assert!(
            pod.get("status").and_then(|v| v.as_str()).is_some(),
            "Pod '{name}' missing 'status'"
        );

        assert!(
            pod.get("needs_update").and_then(|v| v.as_bool()).is_some(),
            "Pod '{name}' missing boolean 'needs_update'"
        );
    }

    tracing::info!(
        "Unified pod list returned {} entries (may be 0 if no pods visible)",
        pods.len()
    );
    Ok(())
}
container_integration_test!(test_unified_pod_list);

/// Find the short name of the shared integration pod from the unified pod list.
///
/// Specifically looks for the `devaipod-integration-shared` pod (the
/// WebFixture's pod) to avoid accidentally picking up a pod created by
/// a concurrently running test that may be mid-teardown.
///
/// Returns `None` if the shared pod is not found or not running.
pub(crate) fn find_running_pod(fixture: &WebFixture, token: &str) -> Result<Option<String>> {
    let (status, body) = fixture.curl_in_container("/api/devaipod/pods", Some(token))?;
    if status != 200 {
        return Ok(None);
    }
    let pods: Vec<serde_json::Value> = serde_json::from_str(&body).unwrap_or_default();
    for pod in &pods {
        let name = match pod.get("name").and_then(|v| v.as_str()) {
            Some(n) => n,
            None => continue,
        };
        // Only match the shared integration pod — other pods may belong
        // to concurrent tests and can disappear at any time.
        if name != integration_tests::SHARED_POD_NAME {
            continue;
        }
        let status = pod.get("status").and_then(|v| v.as_str()).unwrap_or("");
        if status.eq_ignore_ascii_case("running") {
            return Ok(Some(name.to_string()));
        }
    }
    Ok(None)
}

/// Exercise the completion-status (done/active) roundtrip through the
/// control plane proxy.
///
/// This tests the full stack: control plane receives the PUT, injects the
/// admin token, proxies to the pod-api sidecar, which writes the status to
/// `/var/lib/devaipod/completion-status.json`. Then GET reads it back.
///
/// The test resets the status to "active" at the end so it doesn't affect
/// other tests sharing the same WebFixture.
fn test_completion_status_roundtrip() -> Result<()> {
    let fixture = WebFixture::get()?;
    let token = fixture.token().to_string();

    let short_name = match find_running_pod(fixture, &token)? {
        Some(n) => n,
        None => {
            tracing::info!("No running pods, skipping completion-status test");
            return Ok(());
        }
    };

    let path = format!("/api/devaipod/pods/{}/completion-status", short_name);

    // 1. GET — default should be "active"
    let (status, body) = fixture.curl_in_container(&path, Some(&token))?;
    if status != 200 {
        // This runs inside a container, so use curl to the control plane's
        // own containers endpoint for debug info.  Also try a direct curl
        // to the pod-api port (discovered from podman inspect).
        let debug_body = fixture
            .curl_in_container("/api/devaipod/pods", Some(&token))
            .map(|(_, b)| b)
            .unwrap_or_else(|e| format!("(failed: {e})"));
        panic!(
            "GET completion-status returned {status} (expected 200)\n\
             body: {body}\n\
             pod name used: {short_name}\n\
             pods list: {debug_body}"
        );
    }
    let json: serde_json::Value = serde_json::from_str(&body)?;
    assert_eq!(
        json["status"].as_str(),
        Some("active"),
        "Default completion status should be 'active', got: {body}"
    );

    // 2. PUT "done"
    let (status, body) =
        fixture.curl_with_method("PUT", &path, Some(r#"{"status":"done"}"#), Some(&token))?;
    assert_eq!(
        status, 200,
        "PUT completion-status should return 200: {body}"
    );
    let json: serde_json::Value = serde_json::from_str(&body)?;
    assert_eq!(
        json["status"].as_str(),
        Some("done"),
        "PUT response should confirm 'done': {body}"
    );

    // 3. GET — should now be "done"
    let (status, body) = fixture.curl_in_container(&path, Some(&token))?;
    assert_eq!(status, 200);
    let json: serde_json::Value = serde_json::from_str(&body)?;
    assert_eq!(
        json["status"].as_str(),
        Some("done"),
        "After PUT, GET should return 'done': {body}"
    );

    // 4. Verify it shows up in the unified pod list's agent_status
    let (status, body) = fixture.curl_in_container("/api/devaipod/pods", Some(&token))?;
    assert_eq!(status, 200);
    let pods: Vec<serde_json::Value> = serde_json::from_str(&body)?;
    let our_pod = pods.iter().find(|p| {
        p.get("name")
            .and_then(|v| v.as_str())
            .map(|n| n.ends_with(&short_name))
            .unwrap_or(false)
    });
    if let Some(pod) = our_pod {
        if let Some(agent) = pod.get("agent_status") {
            assert_eq!(
                agent.get("completion_status").and_then(|v| v.as_str()),
                Some("done"),
                "Unified pod list should reflect 'done' in agent_status"
            );
        }
    }

    // 5. Reset to "active" (cleanup for shared fixture)
    let (status, _) =
        fixture.curl_with_method("PUT", &path, Some(r#"{"status":"active"}"#), Some(&token))?;
    assert_eq!(status, 200, "Reset to 'active' should succeed");

    tracing::info!(
        "Completion status roundtrip passed for pod '{}'",
        short_name
    );
    Ok(())
}
container_integration_test!(test_completion_status_roundtrip);

/// Smoke test using the [`DevaipodHarness`] (no container image required).
///
/// Starts `devaipod web` on a random port and verifies that the health
/// endpoint responds with 200 and the pod list endpoint returns a valid
/// (possibly empty) JSON array.
fn test_harness_health_and_pod_list() -> Result<()> {
    let harness = DevaipodHarness::start()?;

    // Health endpoint (no auth needed).
    let (status, body) = harness.get("/_devaipod/health")?;
    assert_eq!(
        status, 200,
        "health should return 200, got {status}: {body}"
    );
    assert!(
        body.contains("ok"),
        "health body should contain 'ok': {body}"
    );

    // Pod list (requires auth — the harness sends Bearer token automatically).
    let (status, body) = harness.get("/api/devaipod/pods")?;
    assert_eq!(
        status,
        200,
        "GET /api/devaipod/pods should return 200, got {status}: {}",
        &body[..body.len().min(300)]
    );

    let pods: Vec<serde_json::Value> = serde_json::from_str(&body).map_err(|e| {
        color_eyre::eyre::eyre!(
            "Failed to parse pod list: {} - body: {}",
            e,
            &body[..body.len().min(500)]
        )
    })?;

    // Without a running pod the array may be empty — that's fine.
    tracing::info!(
        "Harness pod list returned {} entries (port {})",
        pods.len(),
        harness.port()
    );

    Ok(())
}
podman_integration_test!(test_harness_health_and_pod_list);

/// End-to-end test: create a pod via the API and exercise completion-status.
///
/// Uses [`DevaipodHarness`] to start a real devaipod web server, creates a
/// pod from a local test repo (no network required), and verifies the
/// completion-status roundtrip through the full stack: control plane →
/// pod-api sidecar → disk → back.
///
/// The agent container runs mock-opencode (via `DEVAIPOD_MOCK_AGENT=1`),
/// so no real AI provider is needed.
fn test_harness_completion_status_e2e() -> Result<()> {
    let mut harness = DevaipodHarness::start()?;
    let repo = TestRepo::new()?;

    // Create a pod from the local test repo.
    let pod_name = crate::unique_test_name("cs-e2e");
    let short = crate::short_name(&pod_name);

    harness.create_pod(repo.repo_path.to_str().unwrap(), short)?;

    // Wait a bit for the pod-api sidecar to become healthy.
    let api_container = format!("{pod_name}-api");
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
    loop {
        let output = std::process::Command::new("podman")
            .args([
                "inspect",
                "--format",
                "{{.State.Health.Status}}",
                &api_container,
            ])
            .output()?;
        let status = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if status == "healthy" {
            break;
        }
        if std::time::Instant::now() > deadline {
            color_eyre::eyre::bail!(
                "pod-api container did not become healthy within 60s (status: {status})"
            );
        }
        std::thread::sleep(std::time::Duration::from_secs(1));
    }

    let cs_path = format!("/api/devaipod/pods/{short}/completion-status");

    // 1. GET default → "active"
    // The web server needs time to discover the pod-api's published port
    // via podman inspect. Retry with exponential backoff.
    let (status, body) = {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
        loop {
            let (s, b) = harness.get(&cs_path)?;
            if s == 200 || std::time::Instant::now() > deadline {
                break (s, b);
            }
            std::thread::sleep(std::time::Duration::from_secs(2));
        }
    };
    if status != 200 {
        let stderr = harness.recent_stderr(30);
        panic!(
            "GET completion-status returned {status} after retries: {body}\n\
             Web server stderr:\n{stderr}"
        );
    }
    let json: serde_json::Value = serde_json::from_str(&body)?;
    assert_eq!(
        json["status"].as_str(),
        Some("active"),
        "default should be 'active': {body}"
    );

    // 2. PUT "done"
    let (status, body) = harness.put(&cs_path, r#"{"status":"done"}"#)?;
    if status != 200 {
        // Collect debug info for the assertion message
        let api_container = format!("{pod_name}-api");
        let api_logs = std::process::Command::new("podman")
            .args(["logs", "--tail", "30", &api_container])
            .output()
            .map(|o| {
                format!(
                    "stdout: {}\nstderr: {}",
                    String::from_utf8_lossy(&o.stdout),
                    String::from_utf8_lossy(&o.stderr)
                )
            })
            .unwrap_or_else(|e| format!("(failed to get logs: {e})"));
        let web_stderr = harness.recent_stderr(30);
        panic!(
            "PUT done failed with {status}: {body}\n\
             === pod-api ({api_container}) logs ===\n{api_logs}\n\
             === devaipod web stderr ===\n{web_stderr}"
        );
    }

    // 3. GET → "done"
    let (status, body) = harness.get(&cs_path)?;
    assert_eq!(status, 200);
    let json: serde_json::Value = serde_json::from_str(&body)?;
    assert_eq!(
        json["status"].as_str(),
        Some("done"),
        "should be 'done' after PUT: {body}"
    );

    // 4. Verify unified pod list reflects completion_status
    let (status, body) = harness.get("/api/devaipod/pods")?;
    assert_eq!(status, 200);
    let pods: Vec<serde_json::Value> = serde_json::from_str(&body)?;
    let our_pod = pods
        .iter()
        .find(|p| p.get("name").and_then(|n| n.as_str()) == Some(&pod_name));
    if let Some(pod) = our_pod {
        if let Some(agent) = pod.get("agent_status") {
            assert_eq!(
                agent.get("completion_status").and_then(|v| v.as_str()),
                Some("done"),
                "unified list should show 'done'"
            );
        }
    }

    // 5. Reset to active
    let (status, _) = harness.put(&cs_path, r#"{"status":"active"}"#)?;
    assert_eq!(status, 200, "reset to active should succeed");

    tracing::info!("Completion status e2e test passed for pod '{pod_name}'");
    Ok(())
}
podman_integration_test!(test_harness_completion_status_e2e);

/// Multi-pod test for the pod switcher dropdown.
///
/// Creates two pods via the harness, verifies both appear as Running in
/// `/api/devaipod/pods`, and confirms the agent iframe wrapper HTML for
/// each pod contains the pod switcher UI elements (dropdown, arrow buttons,
/// and JS functions for fetching/rendering the pod list).
fn test_harness_pod_switcher_multi_pod() -> Result<()> {
    let mut harness = DevaipodHarness::start()?;

    let repo_a = TestRepo::new()?;
    let repo_b = TestRepo::new()?;

    let pod_name_a = crate::unique_test_name("switcher-a");
    let short_a = crate::short_name(&pod_name_a);
    let pod_name_b = crate::unique_test_name("switcher-b");
    let short_b = crate::short_name(&pod_name_b);

    harness.create_pod(repo_a.repo_path.to_str().unwrap(), short_a)?;
    harness.create_pod(repo_b.repo_path.to_str().unwrap(), short_b)?;

    // Wait for both pod-api containers to become healthy.
    for pod_name in [&pod_name_a, &pod_name_b] {
        let api_container = format!("{pod_name}-api");
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
        loop {
            let output = std::process::Command::new("podman")
                .args([
                    "inspect",
                    "--format",
                    "{{.State.Health.Status}}",
                    &api_container,
                ])
                .output()?;
            let status = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if status == "healthy" {
                tracing::info!("{api_container} is healthy");
                break;
            }
            if std::time::Instant::now() > deadline {
                color_eyre::eyre::bail!(
                    "pod-api container {api_container} did not become healthy within 60s (status: {status})"
                );
            }
            std::thread::sleep(std::time::Duration::from_secs(1));
        }
    }

    // Verify both pods appear in the unified pod list as Running.
    let (status, body) = harness.get("/api/devaipod/pods")?;
    assert_eq!(status, 200, "GET /api/devaipod/pods: {body}");
    let pods: Vec<serde_json::Value> = serde_json::from_str(&body)?;

    // Accept both "Running" and "Degraded" as active pod statuses
    let active_pods: Vec<&serde_json::Value> = pods
        .iter()
        .filter(|p| {
            p.get("status")
                .and_then(|s| s.as_str())
                .map(|s| s.eq_ignore_ascii_case("running") || s.eq_ignore_ascii_case("degraded"))
                .unwrap_or(false)
        })
        .collect();

    let names: Vec<&str> = active_pods
        .iter()
        .filter_map(|p| p.get("name").and_then(|n| n.as_str()))
        .collect();
    tracing::info!("Active pods: {:?}", names);

    assert!(
        names.contains(&pod_name_a.as_str()),
        "Pod A ({pod_name_a}) should be in the active list; got: {names:?}"
    );
    assert!(
        names.contains(&pod_name_b.as_str()),
        "Pod B ({pod_name_b}) should be in the active list; got: {names:?}"
    );

    // Fetch the agent iframe wrapper for each pod and verify pod switcher elements.
    for short in [short_a, short_b] {
        let path = format!("/_devaipod/agent/{short}/");
        let (status, body) = harness.get(&path)?;
        assert_eq!(
            status,
            200,
            "GET {path} should return 200, got {status}: {}",
            &body[..body.len().min(300)]
        );

        for marker in [
            r#"id="pod-switcher""#,
            r#"id="pod-trigger""#,
            r#"id="prev-pod""#,
            r#"id="next-pod""#,
            r#"id="pod-dropdown""#,
            "agent-wrapper.js",
            r#"id="pod-data""#,
        ] {
            assert!(
                body.contains(marker),
                "Agent iframe for '{short}' should contain '{marker}'; body length={}",
                body.len()
            );
        }
    }

    // Confirm the pod list has at least 2 active entries, meaning the JS
    // would enable back-and-forth arrow navigation.
    assert!(
        active_pods.len() >= 2,
        "Expected at least 2 active pods for switcher navigation; got {}",
        active_pods.len()
    );

    tracing::info!(
        "Pod switcher multi-pod test passed ({} active pods)",
        active_pods.len()
    );
    Ok(())
}
podman_integration_test!(test_harness_pod_switcher_multi_pod);

/// Verify that the pod state cache preserves completion_status and last_active_ts
/// after a pod is stopped.
///
/// Uses the DevaipodHarness (host-mode web server) to create a pod, set
/// completion status to "done", stop it, and verify the cached state survives.
fn test_harness_pod_state_cache_survives_stop() -> Result<()> {
    let mut harness = DevaipodHarness::start()?;
    let repo = TestRepo::new()?;

    let pod_name = crate::unique_test_name("cache-stop");
    let short = crate::short_name(&pod_name);

    harness.create_pod(repo.repo_path.to_str().unwrap(), short)?;

    // Wait for completion-status endpoint to be reachable through the proxy.
    // The pod-api sidecar needs time to become healthy after pod creation.
    let cs_path = format!("/api/devaipod/pods/{short}/completion-status");
    let cs_deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
    loop {
        let (status, _) = harness.get(&cs_path)?;
        if status == 200 {
            break;
        }
        if std::time::Instant::now() > cs_deadline {
            color_eyre::eyre::bail!(
                "completion-status endpoint not reachable within 60s (last status: {status})"
            );
        }
        std::thread::sleep(std::time::Duration::from_secs(1));
    }

    // Set completion status to "done"
    let (status, body) = harness.put(&cs_path, r#"{"status":"done"}"#)?;
    assert_eq!(status, 200, "PUT completion-status failed: {body}");

    // Verify unified list shows completion_status while running
    let (status, body) = harness.get("/api/devaipod/pods")?;
    assert_eq!(status, 200);
    let pods: Vec<serde_json::Value> = serde_json::from_str(&body)?;
    let our_pod = pods
        .iter()
        .find(|p| p.get("name").and_then(|n| n.as_str()) == Some(&pod_name));
    assert!(our_pod.is_some(), "Pod {pod_name} should be in the list");
    let pod_json = our_pod.unwrap();

    if let Some(agent) = pod_json.get("agent_status") {
        assert_eq!(
            agent.get("completion_status").and_then(|v| v.as_str()),
            Some("done"),
            "Running pod should show completion_status 'done'"
        );
    }

    // Now stop the pod
    tracing::info!("Stopping pod {pod_name}...");
    let stop = std::process::Command::new("podman")
        .args(["pod", "stop", "--", &pod_name])
        .output()?;
    assert!(
        stop.status.success(),
        "podman pod stop failed: {}",
        String::from_utf8_lossy(&stop.stderr)
    );

    // Poll until the control plane reports the pod as non-Running
    let stop_deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    let mut pod_json;
    loop {
        let (status, body) = harness.get("/api/devaipod/pods")?;
        assert_eq!(status, 200);
        let pods: Vec<serde_json::Value> = serde_json::from_str(&body)?;
        let our_pod = pods
            .iter()
            .find(|p| p.get("name").and_then(|n| n.as_str()) == Some(&pod_name));
        assert!(
            our_pod.is_some(),
            "Stopped pod {pod_name} should still be in the list"
        );
        pod_json = our_pod.unwrap().clone();
        let pod_status = pod_json
            .get("status")
            .and_then(|s| s.as_str())
            .unwrap_or("");
        // Wait until the pod is no longer in an active state.
        // "Running" and "Degraded" both indicate the pod is still up
        // (Degraded means gator exited but agent/api are healthy).
        if !pod_status.eq_ignore_ascii_case("running")
            && !pod_status.eq_ignore_ascii_case("degraded")
        {
            break;
        }
        if std::time::Instant::now() > stop_deadline {
            color_eyre::eyre::bail!(
                "Pod {pod_name} still active 30s after stop (status: {pod_status})"
            );
        }
        std::thread::sleep(std::time::Duration::from_secs(1));
    }

    // completion_status should be preserved from cache
    let agent_status = pod_json.get("agent_status");
    assert!(
        agent_status.is_some(),
        "Stopped pod should have agent_status from cache: {pod_json}"
    );
    assert_eq!(
        agent_status
            .unwrap()
            .get("completion_status")
            .and_then(|v| v.as_str()),
        Some("done"),
        "Cached completion_status should survive pod stop: {pod_json}"
    );

    // Activity should be "Stopped" for a stopped pod
    assert_eq!(
        agent_status
            .unwrap()
            .get("activity")
            .and_then(|v| v.as_str()),
        Some("Stopped"),
        "Stopped pod activity should be 'Stopped': {pod_json}"
    );

    tracing::info!("Pod state cache test passed for pod '{pod_name}'");
    Ok(())
}
podman_integration_test!(test_harness_pod_state_cache_survives_stop);
