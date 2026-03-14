//! Integration tests for the pod-api sidecar
//!
//! These tests start a mock opencode server and a real `devaipod pod-api`
//! process, then exercise the HTTP API via actual TCP connections. No
//! podman or containers required — just two localhost processes.

use color_eyre::eyre::Context;
use color_eyre::Result;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use crate::{get_devaipod_binary_path, integration_test};

/// Canned opencode session list (one root session, one child).
const MOCK_SESSIONS: &str = r#"[
  {
    "id": "ses_root_001",
    "slug": "test-session",
    "projectID": "proj_001",
    "directory": "/workspaces/test",
    "title": "Test session",
    "version": "1.0.0",
    "time": {"created": 1700000000000, "updated": 1700000100000}
  },
  {
    "id": "ses_child_001",
    "slug": "child-session",
    "projectID": "proj_001",
    "directory": "/workspaces/test",
    "parentID": "ses_root_001",
    "title": "Sub-agent session",
    "version": "1.0.0",
    "time": {"created": 1700000050000, "updated": 1700000090000}
  }
]"#;

/// Canned messages for the root session — assistant is still working
/// (no completed time), has a running tool, and some text output.
const MOCK_MESSAGES_WORKING: &str = r#"[
  {
    "info": {
      "role": "user",
      "time": {"created": 1700000000000}
    },
    "parts": [{"type": "text", "text": "Fix the bug in main.rs"}]
  },
  {
    "info": {
      "role": "assistant",
      "time": {"created": 1700000001000}
    },
    "parts": [
      {"type": "text", "text": "I'll fix the bug in main.rs by updating the error handling."},
      {"type": "tool", "name": "edit", "state": {"status": "running"}}
    ]
  }
]"#;

/// Canned messages for idle state — assistant finished with "stop".
const MOCK_MESSAGES_IDLE: &str = r#"[
  {
    "info": {
      "role": "assistant",
      "time": {"created": 1700000001000, "completed": 1700000002000},
      "finish": "stop"
    },
    "parts": [
      {"type": "text", "text": "Done! The bug is fixed."}
    ]
  }
]"#;

/// Start a mock opencode HTTP server on a random port.
///
/// Returns (port, join_handle). The server handles:
/// - GET /session → returns `sessions_json`
/// - GET /session/{id}/message → returns `messages_json`
/// - Everything else → 404
///
/// The server runs in a background thread and stops when the returned
/// handle is dropped (it checks a shutdown flag).
fn start_mock_opencode(
    sessions_json: &str,
    messages_json: &str,
) -> Result<(u16, std::thread::JoinHandle<()>)> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let port = listener.local_addr()?.port();

    let sessions = sessions_json.to_string();
    let messages = messages_json.to_string();

    let handle = std::thread::spawn(move || {
        // Accept connections until the listener is dropped (which happens
        // when the test ends). Set a short timeout so we don't block forever.
        listener
            .set_nonblocking(false)
            .expect("set_nonblocking failed");
        let _ = listener.set_nonblocking(false).and_then(|_| {
            // Use SO_REUSEADDR timeout trick: set a deadline so accept
            // doesn't block forever after test ends
            Ok(())
        });

        for stream in listener.incoming() {
            let mut stream = match stream {
                Ok(s) => s,
                Err(_) => break,
            };

            // Read the request (we only need the first line for routing)
            let mut reader = BufReader::new(stream.try_clone().expect("clone"));
            let mut request_line = String::new();
            if reader.read_line(&mut request_line).is_err() {
                continue;
            }

            // Consume remaining headers (read until empty line)
            loop {
                let mut line = String::new();
                match reader.read_line(&mut line) {
                    Ok(0) => break,
                    Ok(_) if line.trim().is_empty() => break,
                    Ok(_) => continue,
                    Err(_) => break,
                }
            }

            // Route the request
            let (status, body) =
                if request_line.starts_with("GET /session/") && request_line.contains("/message") {
                    ("200 OK", messages.as_str())
                } else if request_line.starts_with("GET /session") {
                    ("200 OK", sessions.as_str())
                } else {
                    ("404 Not Found", "{\"error\": \"not found\"}")
                };

            let response = format!(
                "HTTP/1.1 {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                status,
                body.len(),
                body
            );

            let _ = stream.write_all(response.as_bytes());
            let _ = stream.flush();
        }
    });

    Ok((port, handle))
}

/// Wait for a TCP port to become reachable, with timeout.
fn wait_for_port(port: u16, timeout: Duration) -> Result<()> {
    let start = Instant::now();
    loop {
        if std::net::TcpStream::connect_timeout(
            &std::net::SocketAddr::from(([127, 0, 0, 1], port)),
            Duration::from_millis(100),
        )
        .is_ok()
        {
            return Ok(());
        }
        if start.elapsed() > timeout {
            color_eyre::eyre::bail!(
                "port {} did not become reachable within {:?}",
                port,
                timeout
            );
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// Find a free TCP port.
fn free_port() -> Result<u16> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    Ok(listener.local_addr()?.port())
}

/// Initialize a minimal git repo in the given directory with one commit.
///
/// Creates a README.md, sets user config, and makes an initial commit.
fn init_git_repo(dir: &std::path::Path) -> Result<()> {
    std::fs::create_dir_all(dir)?;
    let _ = Command::new("git").args(["init"]).current_dir(dir).output();
    let _ = Command::new("git")
        .args(["config", "user.email", "test@test.com"])
        .current_dir(dir)
        .output();
    let _ = Command::new("git")
        .args(["config", "user.name", "Test"])
        .current_dir(dir)
        .output();
    let readme = dir.join("README.md");
    if !readme.exists() {
        std::fs::write(&readme, "# test\n")?;
    }
    let _ = Command::new("git")
        .args(["add", "."])
        .current_dir(dir)
        .output();
    let _ = Command::new("git")
        .args(["commit", "-m", "init"])
        .current_dir(dir)
        .output();
    Ok(())
}

/// Start the pod-api binary on a given port, pointing at a mock opencode.
///
/// Returns the child process. Caller is responsible for killing it.
fn start_pod_api(pod_api_port: u16, opencode_port: u16) -> Result<std::process::Child> {
    let workspace = std::env::temp_dir().join("devaipod-integration-test-workspace");
    init_git_repo(&workspace)?;

    let state_dir = workspace.join(".devaipod-state");
    std::fs::create_dir_all(&state_dir)?;

    let binary = get_devaipod_binary_path()?;
    let child = Command::new(&binary)
        .args([
            "pod-api",
            "--port",
            &pod_api_port.to_string(),
            "--workspace",
            workspace.to_str().unwrap(),
            "--opencode-port",
            &opencode_port.to_string(),
            "--opencode-password",
            "",
        ])
        .env("DEVAIPOD_STATE_DIR", &state_dir)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("Failed to start {binary} pod-api"))?;

    Ok(child)
}

/// Start pod-api with a specific workspace directory and optional main workspace.
///
/// Returns the child process. Caller must keep `workspace` and `main_workspace`
/// directories alive (e.g. via `tempfile::TempDir`).
fn start_pod_api_in(
    pod_api_port: u16,
    opencode_port: u16,
    workspace: &std::path::Path,
    main_workspace: Option<&std::path::Path>,
) -> Result<std::process::Child> {
    let state_dir = workspace.join(".devaipod-state");
    std::fs::create_dir_all(&state_dir)?;

    let binary = get_devaipod_binary_path()?;
    let mut args = vec![
        "pod-api".to_string(),
        "--port".to_string(),
        pod_api_port.to_string(),
        "--workspace".to_string(),
        workspace.to_str().unwrap().to_string(),
        "--opencode-port".to_string(),
        opencode_port.to_string(),
        "--opencode-password".to_string(),
        String::new(),
    ];
    if let Some(mw) = main_workspace {
        args.push("--main-workspace".to_string());
        args.push(mw.to_str().unwrap().to_string());
    }

    let child = Command::new(&binary)
        .args(&args)
        .env("DEVAIPOD_STATE_DIR", &state_dir)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("Failed to start {binary} pod-api"))?;

    Ok(child)
}

/// Simple HTTP POST that sends a JSON body and returns the response.
fn http_post(url: &str, body: &str) -> Result<(u16, String)> {
    let url_without_scheme = url.strip_prefix("http://").unwrap_or(url);
    let (host_port, path) = url_without_scheme
        .split_once('/')
        .unwrap_or((url_without_scheme, ""));

    let mut stream = std::net::TcpStream::connect(host_port)
        .with_context(|| format!("connect to {host_port}"))?;
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;

    let request = format!(
        "POST /{path} HTTP/1.1\r\nHost: {host_port}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(request.as_bytes())?;
    stream.flush()?;

    let mut response = String::new();
    stream.read_to_string(&mut response)?;

    let status_line = response.lines().next().unwrap_or("");
    let status_code: u16 = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);

    let body = response
        .split_once("\r\n\r\n")
        .map(|(_, b)| b.to_string())
        .unwrap_or_default();

    Ok((status_code, body))
}

/// Simple HTTP GET that returns the response body as a string.
fn http_get(url: &str) -> Result<(u16, String)> {
    // Minimal HTTP/1.1 client using std::net
    let url_without_scheme = url.strip_prefix("http://").unwrap_or(url);
    let (host_port, path) = url_without_scheme
        .split_once('/')
        .unwrap_or((url_without_scheme, ""));

    let mut stream = std::net::TcpStream::connect(host_port)
        .with_context(|| format!("connect to {host_port}"))?;
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;

    let request = format!("GET /{path} HTTP/1.1\r\nHost: {host_port}\r\nConnection: close\r\n\r\n");
    stream.write_all(request.as_bytes())?;
    stream.flush()?;

    let mut response = String::new();
    stream.read_to_string(&mut response)?;

    // Parse status code from first line
    let status_line = response.lines().next().unwrap_or("");
    let status_code: u16 = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);

    // Extract body (after \r\n\r\n)
    let body = response
        .split_once("\r\n\r\n")
        .map(|(_, b)| b.to_string())
        .unwrap_or_default();

    Ok((status_code, body))
}

/// Guard that kills a child process on drop.
struct ProcessGuard(Option<std::process::Child>);

impl ProcessGuard {
    fn new(child: std::process::Child) -> Self {
        Self(Some(child))
    }
}

impl Drop for ProcessGuard {
    fn drop(&mut self) {
        if let Some(ref mut child) = self.0 {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// GET /summary with a working agent returns correct activity and fields.
fn test_pod_api_summary_working() -> Result<()> {
    let (mock_port, _mock_handle) = start_mock_opencode(MOCK_SESSIONS, MOCK_MESSAGES_WORKING)?;
    let api_port = free_port()?;
    let child = start_pod_api(api_port, mock_port)?;
    let _guard = ProcessGuard::new(child);

    wait_for_port(api_port, Duration::from_secs(30)).context("pod-api should start within 30s")?;

    let (status, body) = http_get(&format!("http://127.0.0.1:{api_port}/summary"))?;
    assert_eq!(status, 200, "GET /summary should return 200");

    let json: serde_json::Value =
        serde_json::from_str(&body).context("response should be valid JSON")?;

    // Verify all fields exist
    assert_eq!(
        json["activity"].as_str(),
        Some("Working"),
        "agent with no completed time and running tool should be Working"
    );
    assert_eq!(
        json["session_count"].as_u64(),
        Some(2),
        "should count both sessions"
    );
    assert!(
        json["recent_output"].as_array().is_some(),
        "should have recent_output array"
    );
    assert_eq!(
        json["current_tool"].as_str(),
        Some("edit"),
        "should report the running tool"
    );
    assert!(
        json["status_line"].as_str().is_some(),
        "should have a status_line"
    );
    assert!(
        json["last_message_ts"].as_i64().is_some(),
        "should have last_message_ts"
    );

    Ok(())
}
integration_test!(test_pod_api_summary_working);

/// GET /summary with an idle agent returns Idle activity.
fn test_pod_api_summary_idle() -> Result<()> {
    let (mock_port, _mock_handle) = start_mock_opencode(MOCK_SESSIONS, MOCK_MESSAGES_IDLE)?;
    let api_port = free_port()?;
    let child = start_pod_api(api_port, mock_port)?;
    let _guard = ProcessGuard::new(child);

    wait_for_port(api_port, Duration::from_secs(30))?;

    let (status, body) = http_get(&format!("http://127.0.0.1:{api_port}/summary"))?;
    assert_eq!(status, 200);

    let json: serde_json::Value = serde_json::from_str(&body)?;
    assert_eq!(
        json["activity"].as_str(),
        Some("Idle"),
        "agent with completed time and stop finish should be Idle"
    );
    assert!(
        json["current_tool"].is_null(),
        "idle agent should have no current_tool"
    );

    Ok(())
}
integration_test!(test_pod_api_summary_idle);

/// GET /summary with no sessions returns Idle with zero sessions.
fn test_pod_api_summary_no_sessions() -> Result<()> {
    let (mock_port, _mock_handle) = start_mock_opencode("[]", "[]")?;
    let api_port = free_port()?;
    let child = start_pod_api(api_port, mock_port)?;
    let _guard = ProcessGuard::new(child);

    wait_for_port(api_port, Duration::from_secs(30))?;

    let (status, body) = http_get(&format!("http://127.0.0.1:{api_port}/summary"))?;
    assert_eq!(status, 200);

    let json: serde_json::Value = serde_json::from_str(&body)?;
    assert_eq!(json["activity"].as_str(), Some("Idle"));
    assert_eq!(json["session_count"].as_u64(), Some(0));
    assert_eq!(
        json["status_line"].as_str(),
        Some("Waiting for input..."),
        "no-session state should say waiting"
    );

    Ok(())
}
integration_test!(test_pod_api_summary_no_sessions);

/// GET /summary with unreachable opencode returns Unknown.
fn test_pod_api_summary_opencode_unreachable() -> Result<()> {
    // Point at a port where nothing is listening
    let dead_port = free_port()?;
    let api_port = free_port()?;
    let child = start_pod_api(api_port, dead_port)?;
    let _guard = ProcessGuard::new(child);

    wait_for_port(api_port, Duration::from_secs(30))?;

    let (status, body) = http_get(&format!("http://127.0.0.1:{api_port}/summary"))?;
    assert_eq!(status, 200, "should still return 200, not an error");

    let json: serde_json::Value = serde_json::from_str(&body)?;
    assert_eq!(
        json["activity"].as_str(),
        Some("Unknown"),
        "unreachable opencode should yield Unknown"
    );
    assert_eq!(json["session_count"].as_u64(), Some(0));

    Ok(())
}
integration_test!(test_pod_api_summary_opencode_unreachable);

/// The /summary response is wire-compatible with the control plane's
/// AgentStatusResponse (all fields deserialize into the expected types).
fn test_pod_api_summary_wire_compatibility() -> Result<()> {
    // This struct mirrors web.rs AgentStatusResponse exactly.
    #[derive(Debug, serde::Deserialize)]
    #[allow(dead_code)]
    struct AgentStatusResponse {
        activity: String,
        status_line: Option<String>,
        current_tool: Option<String>,
        recent_output: Vec<String>,
        last_message_ts: Option<i64>,
        session_count: usize,
    }

    let (mock_port, _mock_handle) = start_mock_opencode(MOCK_SESSIONS, MOCK_MESSAGES_WORKING)?;
    let api_port = free_port()?;
    let child = start_pod_api(api_port, mock_port)?;
    let _guard = ProcessGuard::new(child);

    wait_for_port(api_port, Duration::from_secs(30))?;

    let (_, body) = http_get(&format!("http://127.0.0.1:{api_port}/summary"))?;

    let _parsed: AgentStatusResponse = serde_json::from_str(&body).context(
        "pod-api /summary response must deserialize as AgentStatusResponse (control plane type)",
    )?;

    Ok(())
}
integration_test!(test_pod_api_summary_wire_compatibility);

// ---------------------------------------------------------------------------
// Git endpoint tests
// ---------------------------------------------------------------------------

/// GET /git/status includes a `branch` field along with `files` and `exit_code`.
fn test_pod_api_git_status_has_branch() -> Result<()> {
    let (mock_port, _mock_handle) = start_mock_opencode(MOCK_SESSIONS, MOCK_MESSAGES_IDLE)?;
    let api_port = free_port()?;
    let child = start_pod_api(api_port, mock_port)?;
    let _guard = ProcessGuard::new(child);

    wait_for_port(api_port, Duration::from_secs(30))?;

    let (status, body) = http_get(&format!("http://127.0.0.1:{api_port}/git/status"))?;
    assert_eq!(status, 200, "GET /git/status should return 200");

    let json: serde_json::Value =
        serde_json::from_str(&body).context("response should be valid JSON")?;

    // The workspace has a single commit, so branch should be "main" or "master"
    let branch = json["branch"]
        .as_str()
        .expect("branch should be a string (not detached HEAD)");
    assert!(
        branch == "main" || branch == "master",
        "branch should be 'main' or 'master', got '{branch}'"
    );

    assert!(
        json["files"].as_array().is_some(),
        "response should have files array"
    );
    assert!(
        json["exit_code"].is_number(),
        "response should have exit_code"
    );

    Ok(())
}
integration_test!(test_pod_api_git_status_has_branch);

/// GET /git/log returns structured commits with expected fields.
fn test_pod_api_git_log() -> Result<()> {
    let (mock_port, _mock_handle) = start_mock_opencode(MOCK_SESSIONS, MOCK_MESSAGES_IDLE)?;
    let api_port = free_port()?;
    let child = start_pod_api(api_port, mock_port)?;
    let _guard = ProcessGuard::new(child);

    wait_for_port(api_port, Duration::from_secs(30))?;

    let (status, body) = http_get(&format!("http://127.0.0.1:{api_port}/git/log"))?;
    assert_eq!(status, 200, "GET /git/log should return 200");

    let json: serde_json::Value =
        serde_json::from_str(&body).context("response should be valid JSON")?;

    let commits = json["commits"]
        .as_array()
        .expect("response should have commits array");
    assert!(
        !commits.is_empty(),
        "should have at least 1 commit (the init commit)"
    );

    let first = &commits[0];
    assert!(first["sha"].as_str().is_some(), "commit should have sha");
    assert!(
        first["short_sha"].as_str().is_some(),
        "commit should have short_sha"
    );
    assert!(
        first["message"].as_str().is_some(),
        "commit should have message"
    );
    assert!(
        first["author"].as_str().is_some(),
        "commit should have author"
    );

    Ok(())
}
integration_test!(test_pod_api_git_log);

/// GET /git/diff-range returns per-file diffs between two commits.
fn test_pod_api_git_diff_range() -> Result<()> {
    let (mock_port, _mock_handle) = start_mock_opencode(MOCK_SESSIONS, MOCK_MESSAGES_IDLE)?;

    // Create a workspace with two commits so we have a range to diff.
    let tmp = tempfile::TempDir::new()?;
    let workspace = tmp.path().join("diff-range-ws");
    init_git_repo(&workspace)?;

    // Make a second commit that adds a file.
    std::fs::write(workspace.join("new-file.txt"), "hello\n")?;
    let _ = Command::new("git")
        .args(["add", "new-file.txt"])
        .current_dir(&workspace)
        .output();
    let _ = Command::new("git")
        .args(["commit", "-m", "add new-file"])
        .current_dir(&workspace)
        .output();

    let api_port = free_port()?;
    let child = start_pod_api_in(api_port, mock_port, &workspace, None)?;
    let _guard = ProcessGuard::new(child);

    wait_for_port(api_port, Duration::from_secs(30))?;

    // Get the two commit SHAs via /git/log
    let (status, body) = http_get(&format!("http://127.0.0.1:{api_port}/git/log"))?;
    assert_eq!(status, 200);
    let log_json: serde_json::Value = serde_json::from_str(&body)?;
    let commits = log_json["commits"].as_array().expect("should have commits");
    assert!(
        commits.len() >= 2,
        "expected at least 2 commits, got {}",
        commits.len()
    );

    // git log returns newest first, so commits[0] is HEAD, commits[1] is the init.
    let head_sha = commits[0]["sha"].as_str().unwrap();
    let base_sha = commits[1]["sha"].as_str().unwrap();

    let (status, body) = http_get(&format!(
        "http://127.0.0.1:{api_port}/git/diff-range?base={base_sha}&head={head_sha}"
    ))?;
    assert_eq!(status, 200, "GET /git/diff-range should return 200");

    let json: serde_json::Value = serde_json::from_str(&body)?;
    let files = json["files"]
        .as_array()
        .expect("response should have files array");
    assert!(!files.is_empty(), "should have at least 1 changed file");

    let file = &files[0];
    assert!(
        file["file"].as_str().is_some(),
        "file entry should have 'file'"
    );
    assert!(
        file["before"].is_string(),
        "file entry should have 'before'"
    );
    assert!(file["after"].is_string(), "file entry should have 'after'");
    assert!(
        file["status"].as_str().is_some(),
        "file entry should have 'status'"
    );
    assert!(
        file["additions"].is_number(),
        "file entry should have 'additions'"
    );
    assert!(
        file["deletions"].is_number(),
        "file entry should have 'deletions'"
    );

    Ok(())
}
integration_test!(test_pod_api_git_diff_range);

/// POST /git/fetch-agent returns failure when --main-workspace is not set.
fn test_pod_api_fetch_agent_no_main_workspace() -> Result<()> {
    let (mock_port, _mock_handle) = start_mock_opencode(MOCK_SESSIONS, MOCK_MESSAGES_IDLE)?;
    let api_port = free_port()?;
    let child = start_pod_api(api_port, mock_port)?;
    let _guard = ProcessGuard::new(child);

    wait_for_port(api_port, Duration::from_secs(30))?;

    let (status, body) = http_post(
        &format!("http://127.0.0.1:{api_port}/git/fetch-agent"),
        "{}",
    )?;
    assert_eq!(status, 200, "POST /git/fetch-agent should return 200");

    let json: serde_json::Value = serde_json::from_str(&body)?;
    assert_eq!(
        json["success"].as_bool(),
        Some(false),
        "should report failure"
    );
    let message = json["message"].as_str().unwrap_or("");
    assert!(
        message.contains("Main workspace not configured"),
        "message should mention main workspace not configured, got: {message}"
    );

    Ok(())
}
integration_test!(test_pod_api_fetch_agent_no_main_workspace);

/// POST /git/push returns failure when --main-workspace is not set.
fn test_pod_api_push_no_main_workspace() -> Result<()> {
    let (mock_port, _mock_handle) = start_mock_opencode(MOCK_SESSIONS, MOCK_MESSAGES_IDLE)?;
    let api_port = free_port()?;
    let child = start_pod_api(api_port, mock_port)?;
    let _guard = ProcessGuard::new(child);

    wait_for_port(api_port, Duration::from_secs(30))?;

    let (status, body) = http_post(
        &format!("http://127.0.0.1:{api_port}/git/push"),
        r#"{"branch": "test"}"#,
    )?;
    assert_eq!(status, 200, "POST /git/push should return 200");

    let json: serde_json::Value = serde_json::from_str(&body)?;
    assert_eq!(
        json["success"].as_bool(),
        Some(false),
        "should report failure"
    );
    let message = json["message"].as_str().unwrap_or("");
    assert!(
        message.contains("Main workspace not configured"),
        "message should mention main workspace not configured, got: {message}"
    );

    Ok(())
}
integration_test!(test_pod_api_push_no_main_workspace);

/// POST /git/create-branch returns failure when --main-workspace is not set.
fn test_pod_api_create_branch_no_main_workspace() -> Result<()> {
    let (mock_port, _mock_handle) = start_mock_opencode(MOCK_SESSIONS, MOCK_MESSAGES_IDLE)?;
    let api_port = free_port()?;
    let child = start_pod_api(api_port, mock_port)?;
    let _guard = ProcessGuard::new(child);

    wait_for_port(api_port, Duration::from_secs(30))?;

    let (status, body) = http_post(
        &format!("http://127.0.0.1:{api_port}/git/create-branch"),
        r#"{"branch": "test"}"#,
    )?;
    assert_eq!(status, 200, "POST /git/create-branch should return 200");

    let json: serde_json::Value = serde_json::from_str(&body)?;
    assert_eq!(
        json["success"].as_bool(),
        Some(false),
        "should report failure"
    );
    let message = json["message"].as_str().unwrap_or("");
    assert!(
        message.contains("Main workspace not configured"),
        "message should mention main workspace not configured, got: {message}"
    );

    Ok(())
}
integration_test!(test_pod_api_create_branch_no_main_workspace);

/// POST /git/create-branch rejects invalid ref names with 400.
fn test_pod_api_create_branch_invalid_ref() -> Result<()> {
    let (mock_port, _mock_handle) = start_mock_opencode(MOCK_SESSIONS, MOCK_MESSAGES_IDLE)?;
    let api_port = free_port()?;
    let child = start_pod_api(api_port, mock_port)?;
    let _guard = ProcessGuard::new(child);

    wait_for_port(api_port, Duration::from_secs(30))?;

    let (status, _body) = http_post(
        &format!("http://127.0.0.1:{api_port}/git/create-branch"),
        r#"{"branch": "bad..ref"}"#,
    )?;
    assert_eq!(
        status, 400,
        "POST /git/create-branch with invalid ref should return 400"
    );

    Ok(())
}
integration_test!(test_pod_api_create_branch_invalid_ref);

/// POST /git/fetch-agent succeeds when --main-workspace is set, and the
/// fetched commits appear in the main workspace.
fn test_pod_api_fetch_agent_with_main_workspace() -> Result<()> {
    let (mock_port, _mock_handle) = start_mock_opencode(MOCK_SESSIONS, MOCK_MESSAGES_IDLE)?;

    // Create the agent workspace with two commits.
    let tmp = tempfile::TempDir::new()?;
    let agent_ws = tmp.path().join("agent-ws");
    init_git_repo(&agent_ws)?;
    std::fs::write(agent_ws.join("agent-change.txt"), "from agent\n")?;
    let _ = Command::new("git")
        .args(["add", "agent-change.txt"])
        .current_dir(&agent_ws)
        .output();
    let _ = Command::new("git")
        .args(["commit", "-m", "agent commit"])
        .current_dir(&agent_ws)
        .output();

    // Record the agent HEAD sha for later verification.
    let agent_head = Command::new("git")
        .args(["rev-parse", "HEAD"])
        .current_dir(&agent_ws)
        .output()?;
    let agent_head_sha = String::from_utf8_lossy(&agent_head.stdout)
        .trim()
        .to_string();

    // Create the main workspace with its own initial commit.
    let main_ws = tmp.path().join("main-ws");
    init_git_repo(&main_ws)?;

    let api_port = free_port()?;
    let child = start_pod_api_in(api_port, mock_port, &agent_ws, Some(&main_ws))?;
    let _guard = ProcessGuard::new(child);

    wait_for_port(api_port, Duration::from_secs(30))?;

    // Fetch agent commits into the main workspace.
    let (status, body) = http_post(
        &format!("http://127.0.0.1:{api_port}/git/fetch-agent"),
        "{}",
    )?;
    assert_eq!(status, 200, "POST /git/fetch-agent should return 200");

    let json: serde_json::Value = serde_json::from_str(&body)?;
    assert_eq!(
        json["success"].as_bool(),
        Some(true),
        "fetch-agent should succeed when main-workspace is configured"
    );

    // Verify the agent's commit is now reachable in the main workspace.
    let log_output = Command::new("git")
        .args(["log", "--all", "--format=%H"])
        .current_dir(&main_ws)
        .output()?;
    let all_shas = String::from_utf8_lossy(&log_output.stdout);
    assert!(
        all_shas.contains(&agent_head_sha),
        "agent HEAD ({agent_head_sha}) should appear in main workspace's git log --all"
    );

    Ok(())
}
integration_test!(test_pod_api_fetch_agent_with_main_workspace);
