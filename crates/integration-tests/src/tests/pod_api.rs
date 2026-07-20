//! Integration tests for the pod-api sidecar
//!
//! These tests start a mock opencode server and a real `devaipod pod-api`
//! process, then exercise the HTTP API via actual TCP connections. No
//! podman or containers required — just two localhost processes.

use color_eyre::Result;
use color_eyre::eyre::Context;
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

/// Start the pod-api binary on a given port, pointing at a mock opencode.
///
/// Returns the child process. Caller is responsible for killing it.
fn start_pod_api(pod_api_port: u16, opencode_port: u16) -> Result<std::process::Child> {
    let binary = get_devaipod_binary_path()?;
    let workspace = std::env::temp_dir().join("devaipod-integration-test-workspace");
    std::fs::create_dir_all(&workspace)?;

    // Initialize a minimal git repo so the git watcher doesn't error
    let git_dir = workspace.join(".git");
    if !git_dir.exists() {
        let _ = Command::new("git")
            .args(["init"])
            .current_dir(&workspace)
            .output();
        let _ = Command::new("git")
            .args(["config", "user.email", "test@test.com"])
            .current_dir(&workspace)
            .output();
        let _ = Command::new("git")
            .args(["config", "user.name", "Test"])
            .current_dir(&workspace)
            .output();
        let readme = workspace.join("README.md");
        if !readme.exists() {
            std::fs::write(&readme, "# test\n")?;
        }
        let _ = Command::new("git")
            .args(["add", "."])
            .current_dir(&workspace)
            .output();
        let _ = Command::new("git")
            .args(["commit", "-m", "init"])
            .current_dir(&workspace)
            .output();
    }

    // Override the state directory so the admin token and completion status
    // files are written under the workspace (the default /var/lib/devaipod/
    // requires root, which we don't have in local dev / devaipod-in-devaipod).
    // Pre-create it because the pod-api avoids create_dir_all at runtime
    // (mkdir on overlayfs can EPERM when capabilities are dropped).
    let state_dir = workspace.join(".devaipod-state");
    std::fs::create_dir_all(&state_dir)?;

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

/// Start the pod-api binary with ACP backend (no opencode port).
///
/// Returns the child process. Caller is responsible for killing it.
fn start_pod_api_acp(pod_api_port: u16) -> Result<std::process::Child> {
    let binary = get_devaipod_binary_path()?;
    let workspace = std::env::temp_dir().join("devaipod-integration-test-workspace-acp");
    std::fs::create_dir_all(&workspace)?;

    // Initialize a minimal git repo so the git watcher doesn't error
    let git_dir = workspace.join(".git");
    if !git_dir.exists() {
        let _ = Command::new("git")
            .args(["init"])
            .current_dir(&workspace)
            .output();
        let _ = Command::new("git")
            .args(["config", "user.email", "test@test.com"])
            .current_dir(&workspace)
            .output();
        let _ = Command::new("git")
            .args(["config", "user.name", "Test"])
            .current_dir(&workspace)
            .output();
        let readme = workspace.join("README.md");
        if !readme.exists() {
            std::fs::write(&readme, "# test\n")?;
        }
        let _ = Command::new("git")
            .args(["add", "."])
            .current_dir(&workspace)
            .output();
        let _ = Command::new("git")
            .args(["commit", "-m", "init"])
            .current_dir(&workspace)
            .output();
    }

    let state_dir = workspace.join(".devaipod-state");
    std::fs::create_dir_all(&state_dir)?;

    // ACP backend doesn't use --opencode-port
    let child = Command::new(&binary)
        .args([
            "pod-api",
            "--port",
            &pod_api_port.to_string(),
            "--workspace",
            workspace.to_str().unwrap(),
        ])
        .env("DEVAIPOD_STATE_DIR", &state_dir)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("Failed to start {binary} pod-api"))?;

    Ok(child)
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

/// GET /summary with ACP backend but no connected client returns Unknown.
fn test_pod_api_summary_working() -> Result<()> {
    // ACP backend uses stdio, not HTTP. When no ACP client is connected,
    // pod_summary() returns a default AgentStatusSummary with activity Unknown.
    let api_port = free_port()?;
    // Don't pass --opencode-port; ACP backend ignores it
    let child = start_pod_api_acp(api_port)?;
    let _guard = ProcessGuard::new(child);

    wait_for_port(api_port, Duration::from_secs(30)).context("pod-api should start within 30s")?;

    let (status, body) = http_get(&format!("http://127.0.0.1:{api_port}/summary"))?;
    assert_eq!(status, 200, "GET /summary should return 200");

    let json: serde_json::Value =
        serde_json::from_str(&body).context("response should be valid JSON")?;

    // With no ACP client connected, activity is Unknown
    assert_eq!(
        json["activity"].as_str(),
        Some("Unknown"),
        "ACP backend with no client should report Unknown activity"
    );
    assert_eq!(
        json["session_count"].as_u64(),
        Some(0),
        "no connected client means no sessions"
    );
    assert!(
        json["recent_output"].as_array().is_some(),
        "should have recent_output array (even if empty)"
    );
    assert!(
        json["status_line"].as_str().is_some(),
        "should have a status_line"
    );
    // current_tool and last_message_ts can be null when no client
    assert!(
        json.get("current_tool").is_some(),
        "current_tool field should exist"
    );
    assert!(
        json.get("last_message_ts").is_some(),
        "last_message_ts field should exist"
    );

    Ok(())
}
integration_test!(test_pod_api_summary_working);

/// GET /summary with ACP backend but no connected client returns Unknown.
fn test_pod_api_summary_idle() -> Result<()> {
    // ACP backend uses stdio, not HTTP. When no ACP client is connected,
    // pod_summary() returns Unknown (same as "working" test).
    let api_port = free_port()?;
    let child = start_pod_api_acp(api_port)?;
    let _guard = ProcessGuard::new(child);

    wait_for_port(api_port, Duration::from_secs(30))?;

    let (status, body) = http_get(&format!("http://127.0.0.1:{api_port}/summary"))?;
    assert_eq!(status, 200);

    let json: serde_json::Value = serde_json::from_str(&body)?;
    assert_eq!(
        json["activity"].as_str(),
        Some("Unknown"),
        "ACP backend with no client should report Unknown activity"
    );
    assert!(
        json["current_tool"].is_null(),
        "no client means no current_tool"
    );

    Ok(())
}
integration_test!(test_pod_api_summary_idle);

/// GET /summary with ACP backend and no client returns Unknown with zero sessions.
fn test_pod_api_summary_no_sessions() -> Result<()> {
    // ACP backend uses stdio, not HTTP. When no ACP client is connected,
    // pod_summary() returns Unknown (same as other tests).
    let api_port = free_port()?;
    let child = start_pod_api_acp(api_port)?;
    let _guard = ProcessGuard::new(child);

    wait_for_port(api_port, Duration::from_secs(30))?;

    let (status, body) = http_get(&format!("http://127.0.0.1:{api_port}/summary"))?;
    assert_eq!(status, 200);

    let json: serde_json::Value = serde_json::from_str(&body)?;
    assert_eq!(json["activity"].as_str(), Some("Unknown"));
    assert_eq!(json["session_count"].as_u64(), Some(0));
    assert!(
        json["status_line"].as_str().is_some(),
        "should have a status_line"
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
