//! Integration test harness that spawns a real devaipod web server.
//!
//! The harness starts `devaipod web` on a random port, captures the
//! authentication token from stdout, and provides HTTP client methods
//! for tests to interact with the control plane API.
//!
//! On drop the harness kills the web server process and removes any
//! pods that were registered via [`DevaipodHarness::track_pod`].

use color_eyre::Result;
use color_eyre::eyre::{Context, ContextCompat, bail};
use std::io::{Read, Write};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

/// A running devaipod web server for integration testing.
///
/// Starts `devaipod web` on a random port and provides HTTP client methods
/// to interact with the control plane API. The token is captured from the
/// server's stdout output.
///
/// Cleaned up automatically on drop (kills the web server process and
/// removes any pods created during the test).
pub struct DevaipodHarness {
    /// The web server process
    child: Option<Child>,
    /// Port the web server is listening on
    port: u16,
    /// Authentication token for API access
    token: String,
    /// Pod names created during this test (for cleanup)
    pods: Vec<String>,
    /// Background thread draining stdout (kept alive to avoid SIGPIPE)
    _stdout_drainer: Option<std::thread::JoinHandle<()>>,
    /// Background thread draining stderr into a shared buffer
    _stderr_drainer: Option<std::thread::JoinHandle<()>>,
    /// Recent stderr lines from the web server (ring buffer)
    stderr_lines: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
}

impl DevaipodHarness {
    /// Start a new devaipod web server on a random port.
    ///
    /// Spawns `devaipod web --port <port>` with the standard integration test
    /// environment variables (`DEVAIPOD_INSTANCE`, `DEVAIPOD_HOST_MODE`).
    /// Blocks until the token is captured from stdout and the health endpoint
    /// responds with 200.
    pub fn start() -> Result<Self> {
        let port = find_free_port()?;
        let binary = std::env::var("DEVAIPOD_PATH").unwrap_or_else(|_| "devaipod".to_string());

        let mut cmd = Command::new(&binary);
        cmd.args(["web", "--port", &port.to_string()])
            .env("DEVAIPOD_INSTANCE", crate::INTEGRATION_TEST_INSTANCE)
            .env("DEVAIPOD_HOST_MODE", "1")
            // When the web server spawns `devaipod run` to create pods, this
            // env var propagates to the child process, which passes it into
            // the agent container so it runs mock-opencode instead of the
            // real opencode server.
            .env("DEVAIPOD_MOCK_AGENT", "1")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        // Propagate DEVAIPOD_CONTAINER_IMAGE so `detect_self_image()` in the
        // web server uses the locally-built image instead of the published one.
        if let Ok(img) = std::env::var("DEVAIPOD_CONTAINER_IMAGE") {
            cmd.env("DEVAIPOD_CONTAINER_IMAGE", img);
        }
        let mut child = cmd
            .spawn()
            .with_context(|| format!("Failed to start devaipod web on port {port}"))?;

        // Read the token from stdout in a background thread.
        // The web server prints "Web UI: http://...?token=TOKEN" to stdout
        // early in startup, then keeps running. We use a channel to receive
        // the token as soon as the line is found.
        let stdout = child.stdout.take().context("No stdout from child")?;
        let (tx, rx) = mpsc::channel::<String>();

        let drainer = std::thread::spawn(move || {
            use std::io::{BufRead, BufReader};
            let reader = BufReader::new(stdout);
            for line in reader.lines() {
                let line = match line {
                    Ok(l) => l,
                    Err(_) => break,
                };
                if let Some(token) = extract_token_from_line(&line) {
                    // Ignore send error: receiver may have been dropped if
                    // start() timed out or failed.
                    let _ = tx.send(token);
                }
                // Keep draining to avoid blocking the child on a full pipe.
            }
        });

        // Drain stderr into a shared ring buffer so tests can inspect it
        // on failure.  Also prevents deadlock from a full pipe buffer.
        let stderr_lines = std::sync::Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
        let stderr = child.stderr.take().context("No stderr from child")?;
        let stderr_lines_clone = stderr_lines.clone();
        let stderr_drainer = std::thread::spawn(move || {
            use std::io::{BufRead, BufReader};
            let reader = BufReader::new(stderr);
            for line in reader.lines() {
                let line = match line {
                    Ok(l) => l,
                    Err(_) => break,
                };
                let mut buf = stderr_lines_clone.lock().unwrap();
                buf.push(line);
                // Keep only the last 200 lines
                if buf.len() > 200 {
                    let drain = buf.len() - 200;
                    buf.drain(..drain);
                }
            }
        });

        let token = rx
            .recv_timeout(Duration::from_secs(30))
            .map_err(|_| color_eyre::eyre::eyre!("Timeout waiting for token in devaipod output"))?;

        // Wait for the health endpoint to respond.
        wait_for_health(port, Duration::from_secs(30))?;

        Ok(DevaipodHarness {
            child: Some(child),
            port,
            token,
            pods: Vec::new(),
            _stdout_drainer: Some(drainer),
            _stderr_drainer: Some(stderr_drainer),
            stderr_lines,
        })
    }

    /// HTTP GET request to the control plane API.
    ///
    /// Sends a GET with `Authorization: Bearer <token>` and returns
    /// `(status_code, body)`.
    pub fn get(&self, path: &str) -> Result<(u16, String)> {
        http_request("GET", self.port, path, &self.token, None)
    }

    /// HTTP PUT request with a JSON body.
    pub fn put(&self, path: &str, json_body: &str) -> Result<(u16, String)> {
        http_request("PUT", self.port, path, &self.token, Some(json_body))
    }

    /// HTTP POST request with a JSON body.
    pub fn post(&self, path: &str, json_body: &str) -> Result<(u16, String)> {
        http_request("POST", self.port, path, &self.token, Some(json_body))
    }

    /// Register a pod name for cleanup on drop.
    pub fn track_pod(&mut self, name: &str) {
        self.pods.push(name.to_string());
    }

    /// Get the port the web server is listening on.
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Get the auth token.
    pub fn token(&self) -> &str {
        &self.token
    }

    /// Return the last `n` lines from the web server's stderr.
    pub fn recent_stderr(&self, n: usize) -> String {
        let buf = self.stderr_lines.lock().unwrap();
        let start = buf.len().saturating_sub(n);
        buf[start..].join("\n")
    }

    /// Create a pod from a local repo path and wait for it to appear in the
    /// pod list as "Running".
    ///
    /// Sends `POST /api/devaipod/run` with the given source path and pod name,
    /// then polls the unified pod list until the pod shows up with a Running
    /// status or the timeout expires.
    ///
    /// The pod is automatically registered for cleanup on drop.
    pub fn create_pod(&mut self, source: &str, pod_name: &str) -> Result<()> {
        let body = serde_json::json!({
            "source": source,
            "name": pod_name,
        });

        let (status, resp) = self.post("/api/devaipod/run", &body.to_string())?;
        if status != 200 {
            bail!("POST /api/devaipod/run returned {status}: {resp}");
        }

        // Track for cleanup immediately (even if pod creation fails, the
        // name may have been partially created).
        let full_name = if pod_name.starts_with("devaipod-") {
            pod_name.to_string()
        } else {
            format!("devaipod-{pod_name}")
        };
        self.track_pod(&full_name);

        // Poll the unified pod list until the pod appears and is Running,
        // or the API container is healthy. Pod creation is async (the web
        // server spawns `devaipod run` in the background), so we need to
        // wait for it to complete.
        let deadline = Instant::now() + Duration::from_secs(120);
        loop {
            if Instant::now() > deadline {
                bail!("Pod '{full_name}' did not become Running within 120s");
            }

            if let Ok((200, body)) = self.get("/api/devaipod/pods")
                && let Ok(pods) = serde_json::from_str::<Vec<serde_json::Value>>(&body)
                && let Some(pod) = pods.iter().find(|p| {
                    p.get("name")
                        .and_then(|n| n.as_str())
                        .map(|n| n == full_name)
                        .unwrap_or(false)
                })
            {
                let status = pod.get("status").and_then(|s| s.as_str()).unwrap_or("");
                // Accept both "Running" and "Degraded" — the latter happens when
                // the service-gator container exits (expected for test repos with
                // fake remote URLs), but the agent and api containers are healthy.
                if status.eq_ignore_ascii_case("running") || status.eq_ignore_ascii_case("degraded")
                {
                    tracing::info!("Pod '{full_name}' is {status}");
                    return Ok(());
                }
            }

            #[allow(clippy::disallowed_methods)] // Intentional: poll interval
            std::thread::sleep(Duration::from_secs(2));
        }
    }
}

impl Drop for DevaipodHarness {
    fn drop(&mut self) {
        // Clean up tracked pods and their volumes.
        // Compute workspace base dir for host-side cleanup
        let ws_base = std::env::var("DEVAIPOD_HOST_WORKDIR")
            .map(std::path::PathBuf::from)
            .or_else(|_| {
                std::env::var("HOME")
                    .map(|h| std::path::PathBuf::from(h).join(".local/share/devaipod/workspaces"))
            })
            .ok();

        for pod in &self.pods {
            let _ = Command::new("podman")
                .args(["pod", "rm", "-f", pod])
                .output();
            for suffix in crate::POD_VOLUME_SUFFIXES {
                let vol = format!("{pod}{suffix}");
                let _ = Command::new("podman")
                    .args(["volume", "rm", "-f", &vol])
                    .output();
            }
            // Remove host-side workspace directory.
            // Use `podman unshare` because files are owned by container subuids.
            if let Some(ref base) = ws_base {
                let ws_dir = base.join(pod);
                if ws_dir.exists() {
                    let _ = Command::new("podman")
                        .args(["unshare", "rm", "-rf"])
                        .arg(&ws_dir)
                        .output();
                }
            }
        }

        // Kill the web server.
        if let Some(ref mut child) = self.child {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Find a free TCP port by binding to port 0.
fn find_free_port() -> Result<u16> {
    let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
    Ok(listener.local_addr()?.port())
}

/// Extract the authentication token from a stdout line.
///
/// Recognises two formats emitted by `devaipod web`:
/// - `Web UI: http://...?token=TOKEN`           (main.rs)
/// - `Control plane URL: http://...?token=TOKEN` (web.rs)
fn extract_token_from_line(line: &str) -> Option<String> {
    let idx = line.find("token=")?;
    let rest = &line[idx + 6..];
    // Token ends at whitespace, quote, or end-of-string.
    let end = rest
        .find(|c: char| c.is_whitespace() || c == '"' || c == '\'')
        .unwrap_or(rest.len());
    let token = &rest[..end];
    if token.is_empty() {
        None
    } else {
        Some(token.to_string())
    }
}

/// Poll `/_devaipod/health` until it returns 200 or timeout expires.
fn wait_for_health(port: u16, timeout: Duration) -> Result<()> {
    let start = Instant::now();
    while start.elapsed() < timeout {
        if let Ok((status, _)) = http_request_raw("GET", port, "/_devaipod/health", None, None)
            && status == 200
        {
            return Ok(());
        }
        #[allow(clippy::disallowed_methods)] // Intentional: poll interval
        std::thread::sleep(Duration::from_millis(200));
    }
    bail!(
        "Health endpoint on port {} did not respond within {:?}",
        port,
        timeout
    );
}

/// Minimal HTTP/1.1 client over raw TCP (no external crate needed).
///
/// Optionally attaches `Authorization: Bearer` and a JSON body.
fn http_request(
    method: &str,
    port: u16,
    path: &str,
    token: &str,
    body: Option<&str>,
) -> Result<(u16, String)> {
    http_request_raw(method, port, path, Some(token), body)
}

/// Low-level HTTP/1.1 request. `token` and `body` are both optional.
fn http_request_raw(
    method: &str,
    port: u16,
    path: &str,
    token: Option<&str>,
    body: Option<&str>,
) -> Result<(u16, String)> {
    let host_port = format!("127.0.0.1:{}", port);
    let mut stream = std::net::TcpStream::connect(&host_port)
        .with_context(|| format!("connect to {host_port}"))?;
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;

    let content_length = body.map(|b| b.len()).unwrap_or(0);

    let mut request =
        format!("{method} {path} HTTP/1.1\r\nHost: {host_port}\r\nConnection: close\r\n");
    if let Some(token) = token {
        request.push_str(&format!("Authorization: Bearer {token}\r\n"));
    }
    if body.is_some() {
        request.push_str("Content-Type: application/json\r\n");
        request.push_str(&format!("Content-Length: {content_length}\r\n"));
    }
    request.push_str("\r\n");
    if let Some(body) = body {
        request.push_str(body);
    }

    stream.write_all(request.as_bytes())?;
    stream.flush()?;

    let mut response = String::new();
    stream.read_to_string(&mut response)?;

    // Parse status code from the first line.
    let status_line = response.lines().next().unwrap_or("");
    let status_code: u16 = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);

    // Extract body after the header/body separator.
    let resp_body = response
        .split_once("\r\n\r\n")
        .map(|(_, b)| b.to_string())
        .unwrap_or_default();

    Ok((status_code, resp_body))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_token_from_line() {
        let line = "Web UI: http://localhost:8080/?token=abc123def456";
        assert_eq!(
            extract_token_from_line(line),
            Some("abc123def456".to_string())
        );

        let line2 = "Control plane URL: http://127.0.0.1:9999/_devaipod/login?token=xyz789";
        assert_eq!(extract_token_from_line(line2), Some("xyz789".to_string()));

        assert_eq!(extract_token_from_line("no token here"), None);
        assert_eq!(extract_token_from_line("token="), None);
    }
}
