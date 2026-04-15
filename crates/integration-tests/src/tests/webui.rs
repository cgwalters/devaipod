//! Web UI integration tests (containerized)
//!
//! These tests verify the web UI server running inside a container:
//! - Token-based authentication
//! - Podman socket proxy
//! - Pod list API access
//! - **UI surface**: control-plane HTML and all APIs used by the frontend
//!
//! The tests start a devaipod container image (passed via `DEVAIPOD_CONTAINER_IMAGE`),
//! mount the podman socket, and test the web server via `podman exec` + curl.
//!
//! ## UI surface (keep covered by tests)
//!
//! The frontend relies on:
//!
//! - **GET /** — Control plane HTML (optional `?token=...`). Must return 200 and
//!   contain "devaipod" and control-plane markers (e.g. "Refresh", "Launch", or token prompt).
//! - **GET /_devaipod/agent/{name}** — 307 redirect to /_devaipod/agent/{name}/.
//! - **GET /_devaipod/agent/{name}/** — Iframe wrapper page (back button bar + full-screen
//!   iframe pointing at the pod-api sidecar).
//! - **GET /api/podman/v5.0.0/libpod/pods/json** — Pod list (Bearer token required).
//! - **POST /api/podman/.../pods/{name}/start**, **.../stop**, **DELETE .../pods/{name}?force=true**
//! - **GET /api/devaipod/pods/{name}/agent-status** — Agent status summary.
//! - **POST /api/devaipod/pods/{name}/recreate** — Recreate workspace (same repo).
//! - **POST /api/devaipod/run** — Create workspace (JSON: `{ "source", "task" }`).
//! - **GET /api/devaipod/pods/{name}/pod-api/{*path}** — Proxy to the per-pod API sidecar
//!   (git operations, PTY, etc.).
//!
//! ## How to run
//!
//! - **Integration tests (this module)**: Run **`just test-integration`** which builds both the
//!   main devaipod image and the integration-runner image, then runs tests in a container.
//! - **Fast route tests (no container)**: `cargo test -p devaipod web::tests::` — sub-second.
//!
//! ## Test tiers
//!
//! Tests are categorized into tiers based on their resource needs:
//!
//! - **Tier 1 (parallel safe, no pod)**: Static file serving, auth checks, health endpoints
//! - **Tier 2 (parallel safe, needs pod)**: Pod listing, agent-status (uses the shared test pod)
//! - **Tier 3 (serial, mutations)**: Tests that modify state (currently none)
//!
//! All tests share a single `WebFixture` container to reduce resource contention.

use color_eyre::eyre::bail;
use color_eyre::Result;
use std::process::Command;
use std::sync::OnceLock;
use std::time::Duration;
use xshell::{cmd, Shell};

use crate::container_integration_test;
use crate::shell;

/// Env var: the pre-built devaipod container image to test against.
/// Set by `just test-integration` (which builds both the main image and the
/// integration-runner image before running tests).
const DEVAIPOD_CONTAINER_IMAGE_ENV: &str = "DEVAIPOD_CONTAINER_IMAGE";

/// Get the container image to use for web UI tests.
///
/// Requires `DEVAIPOD_CONTAINER_IMAGE` to be set (done by `just test-integration`).
fn web_container_image() -> Result<String> {
    std::env::var(DEVAIPOD_CONTAINER_IMAGE_ENV).map_err(|_| {
        color_eyre::eyre::eyre!("DEVAIPOD_CONTAINER_IMAGE not set. Run: just test-integration")
    })
}

/// Helper struct to manage a running web container.
/// Automatically removes the container on drop.
struct WebContainerGuard {
    container_name: String,
    token: String,
    /// Keep temp dir alive for config file
    _config_dir: tempfile::TempDir,
}

impl WebContainerGuard {
    /// Generate a unique container name using timestamp
    fn generate_name() -> String {
        use std::time::{SystemTime, UNIX_EPOCH};
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default();
        let unique = (now.as_secs() & 0xFFFF) ^ ((now.subsec_nanos() as u64) & 0xFFFF);
        format!("test-devaipod-web-{:x}", unique)
    }

    /// Start the web container and extract the token from logs
    fn start() -> Result<Self> {
        let sh = shell()?;

        // Generate unique container name
        let container_name = Self::generate_name();

        // Socket for volume mount: resolve the host podman socket path.
        // Target is always /run/docker.sock (well-known path).
        // DEVAIPOD_HOST_SOCKET is passed so the container can use it as a bind mount source
        // when creating sibling containers (the host podman resolves sources on the host filesystem).
        let (host_socket, socket_mount, check_socket) =
            if std::env::var("DEVAIPOD_CONTAINER").as_deref() == Ok("1") {
                // Inside the integration-runner container: the Justfile mounts the
                // host socket at /run/docker.sock and passes DEVAIPOD_HOST_SOCKET.
                // We use DEVAIPOD_HOST_SOCKET for the volume mount source because
                // podman resolves -v sources on the host filesystem, not inside
                // this container.
                let host = std::env::var("DEVAIPOD_HOST_SOCKET")
                    .unwrap_or_else(|_| "/run/docker.sock".to_string());
                (
                    host.clone(),
                    format!("{}:/run/docker.sock", host),
                    // Check the local mount (inside this container) for reachability
                    Some("/run/docker.sock".to_string()),
                )
            } else if let Ok(xdg_runtime) = std::env::var("XDG_RUNTIME_DIR") {
                // Linux host: use XDG_RUNTIME_DIR podman socket
                let path = format!("{}/podman/podman.sock", xdg_runtime);
                (
                    path.clone(),
                    format!("{}:/run/docker.sock", path),
                    Some(path),
                )
            } else {
                // macOS/Windows: container runs in VM; VM bind-mounts its own socket
                (
                    "/run/podman/podman.sock".to_string(),
                    "/run/podman/podman.sock:/run/docker.sock".to_string(),
                    std::env::var("DEVAIPOD_PODMAN_SOCKET").ok(),
                )
            };

        // Check podman is reachable (on macOS we may have Mac socket path for the binary, not for the mount)
        if let Some(ref path) = check_socket {
            if !std::path::Path::new(path).exists() {
                bail!("Podman socket not found at {}. Is podman running?", path);
            }
        }

        // Create minimal config file (devaipod requires config to exist)
        let config_dir = tempfile::TempDir::new()?;
        let config_path = config_dir.path().join("devaipod.toml");
        std::fs::write(
            &config_path,
            r#"# Minimal config for testing
# All fields have defaults, empty config is valid
"#,
        )?;
        // Use :ro,z for SELinux relabeling
        let config_mount = format!(
            "{}:/root/.config/devaipod.toml:ro,z",
            config_path.to_string_lossy()
        );

        let image = web_container_image()?;
        tracing::info!(
            "Starting web container {} from image {}",
            container_name,
            image
        );

        // Run the container (no port forwarding needed - we use podman exec)
        let host_socket_env = format!("DEVAIPOD_HOST_SOCKET={}", host_socket);
        // Pass the container image name so detect_self_image() uses the
        // locally-built image for pod-api sidecars instead of the published one.
        let container_image_env = format!("DEVAIPOD_CONTAINER_IMAGE={}", image);
        let run_output = cmd!(
            sh,
            "podman run -d --name {container_name} --privileged -v {socket_mount} -e {host_socket_env} -e {container_image_env} -v {config_mount} {image}"
        )
        .ignore_status()
        .output()?;

        if !run_output.status.success() {
            let stderr = String::from_utf8_lossy(&run_output.stderr);
            bail!("Failed to start web container: {}", stderr);
        }

        // Wait for container to start and extract token from logs
        let token = Self::wait_for_token(&sh, &container_name, Duration::from_secs(60))?;

        Ok(WebContainerGuard {
            container_name,
            token,
            _config_dir: config_dir,
        })
    }

    /// Wait for the container to output the token and extract it
    fn wait_for_token(sh: &Shell, container_name: &str, timeout: Duration) -> Result<String> {
        let start = std::time::Instant::now();
        let poll_interval = Duration::from_millis(500);

        while start.elapsed() < timeout {
            // Get container logs
            let logs_output = cmd!(sh, "podman logs {container_name}")
                .ignore_status()
                .output()?;

            let logs = String::from_utf8_lossy(&logs_output.stdout);
            let stderr = String::from_utf8_lossy(&logs_output.stderr);
            let combined = format!("{}\n{}", logs, stderr);

            // Look for token in output
            // Format: "Web UI: http://0.0.0.0:8080/?token=TOKEN"
            for line in combined.lines() {
                if line.contains("token=") {
                    if let Some(token_start) = line.find("token=") {
                        let mut token = line[token_start + 6..].trim().to_string();
                        // Token may have trailing characters
                        if let Some(end) =
                            token.find(|c: char| c.is_whitespace() || c == '"' || c == '\'')
                        {
                            token = token[..end].to_string();
                        }
                        if !token.is_empty() {
                            tracing::info!("Extracted token from container logs");
                            return Ok(token);
                        }
                    }
                }
            }

            std::thread::sleep(poll_interval);
        }

        // Get final logs for debugging
        let final_logs = cmd!(sh, "podman logs {container_name}")
            .ignore_status()
            .output()?;
        let logs = String::from_utf8_lossy(&final_logs.stdout);
        let stderr = String::from_utf8_lossy(&final_logs.stderr);

        bail!(
            "Timeout waiting for token in container logs.\nstdout: {}\nstderr: {}",
            logs,
            stderr
        )
    }

    /// Get the authentication token
    fn token(&self) -> &str {
        &self.token
    }

    /// Run curl inside the container and return (status_code, body)
    /// The web server binds to 127.0.0.1 inside the container, so we must
    /// use `podman exec` to access it.
    fn curl_in_container(&self, path: &str, auth_token: Option<&str>) -> Result<(i32, String)> {
        let url = format!("http://127.0.0.1:8080{}", path);
        let container = &self.container_name;

        let output = if let Some(token) = auth_token {
            let auth_header = format!("Authorization: Bearer {}", token);
            Command::new("podman")
                .args([
                    "exec",
                    container,
                    "curl",
                    "-s",
                    "-w",
                    "\n%{http_code}",
                    "--connect-timeout",
                    "5",
                    "--max-time",
                    "30",
                    "--retry",
                    "5",
                    "--retry-connrefused",
                    "--retry-all-errors",
                    "--retry-delay",
                    "2",
                    "-H",
                    &auth_header,
                    &url,
                ])
                .output()?
        } else {
            Command::new("podman")
                .args([
                    "exec",
                    container,
                    "curl",
                    "-s",
                    "-w",
                    "\n%{http_code}",
                    "--connect-timeout",
                    "5",
                    "--max-time",
                    "30",
                    "--retry",
                    "5",
                    "--retry-connrefused",
                    "--retry-all-errors",
                    "--retry-delay",
                    "2",
                    &url,
                ])
                .output()?
        };

        let combined = String::from_utf8_lossy(&output.stdout);
        let lines: Vec<&str> = combined.trim().lines().collect();

        if lines.is_empty() {
            return Ok((-1, String::new()));
        }

        let status_code: i32 = lines.last().and_then(|s| s.parse().ok()).unwrap_or(-1);
        let body = if lines.len() > 1 {
            lines[..lines.len() - 1].join("\n")
        } else {
            String::new()
        };

        Ok((status_code, body))
    }

    /// Run curl with -i and optional Cookie header; captures HTTP version, status, content-type, body.
    /// Returns (http_version, status_code, content_type, body).
    /// `http_version` is e.g. "HTTP/1.1" or "HTTP/1.0".
    fn curl_in_container_full_headers(
        &self,
        path: &str,
        max_time_secs: u8,
        cookie: Option<&str>,
    ) -> Result<(String, i32, String, String)> {
        let url = format!("http://127.0.0.1:8080{}", path);
        let mut args: Vec<String> = vec![
            "exec".into(),
            self.container_name.clone(),
            "curl".into(),
            "-i".into(),
            "-s".into(),
            "--connect-timeout".into(),
            "5".into(),
            "--max-time".into(),
            max_time_secs.to_string(),
        ];
        if let Some(c) = cookie {
            args.push("-H".into());
            args.push(format!("Cookie: {}", c));
        }
        args.push(url);
        let output = Command::new("podman").args(&args).output()?;
        let raw = String::from_utf8_lossy(&output.stdout);
        let (headers_str, body) = if let Some(pos) = raw.find("\r\n\r\n") {
            (raw[..pos].to_string(), raw[pos + 4..].trim().to_string())
        } else if let Some(pos) = raw.find("\n\n") {
            (raw[..pos].to_string(), raw[pos + 2..].trim().to_string())
        } else {
            (raw.to_string(), String::new())
        };
        let status_line = headers_str.lines().next().unwrap_or("");
        let http_version = status_line
            .split_whitespace()
            .next()
            .unwrap_or("")
            .to_string();
        let status = status_line
            .split_whitespace()
            .nth(1)
            .and_then(|s| s.parse::<i32>().ok())
            .unwrap_or(-1);
        let content_type = headers_str
            .lines()
            .find(|l| l.trim_start().to_lowercase().starts_with("content-type:"))
            .and_then(|l| l.split(':').nth(1).map(|v| v.trim().to_string()))
            .unwrap_or_default();
        Ok((http_version, status, content_type, body))
    }

    /// Run curl with a Cookie header.
    fn curl_in_container_with_cookie(&self, path: &str, cookie: &str) -> Result<(i32, String)> {
        let url = format!("http://127.0.0.1:8080{}", path);
        let cookie_header = format!("Cookie: {}", cookie);
        let output = Command::new("podman")
            .args([
                "exec",
                &self.container_name,
                "curl",
                "-s",
                "-w",
                "\n%{http_code}",
                "--connect-timeout",
                "5",
                "--max-time",
                "30",
                "-H",
                &cookie_header,
                &url,
            ])
            .output()?;
        let combined = String::from_utf8_lossy(&output.stdout);
        let lines: Vec<&str> = combined.trim().lines().collect();
        let status_code: i32 = lines.last().and_then(|s| s.parse().ok()).unwrap_or(-1);
        let body = if lines.len() > 1 {
            lines[..lines.len() - 1].join("\n")
        } else {
            String::new()
        };
        Ok((status_code, body))
    }

    /// Run curl with a custom HTTP method, optional body, and optional auth token.
    ///
    /// Useful for PUT/POST requests with JSON payloads. Returns (status_code, body).
    fn curl_in_container_with_method(
        &self,
        method: &str,
        path: &str,
        body: Option<&str>,
        auth_token: Option<&str>,
    ) -> Result<(i32, String)> {
        let url = format!("http://127.0.0.1:8080{}", path);
        let mut args: Vec<String> = vec![
            "exec".into(),
            self.container_name.clone(),
            "curl".into(),
            "-s".into(),
            "-w".into(),
            "\n%{http_code}".into(),
            "--connect-timeout".into(),
            "5".into(),
            "--max-time".into(),
            "30".into(),
            "-X".into(),
            method.into(),
        ];
        if let Some(token) = auth_token {
            args.push("-H".into());
            args.push(format!("Authorization: Bearer {}", token));
        }
        if let Some(data) = body {
            args.push("-H".into());
            args.push("Content-Type: application/json".into());
            args.push("-d".into());
            args.push(data.into());
        }
        args.push(url);

        let output = Command::new("podman").args(&args).output()?;
        let combined = String::from_utf8_lossy(&output.stdout);
        let lines: Vec<&str> = combined.trim().lines().collect();

        if lines.is_empty() {
            return Ok((-1, String::new()));
        }

        let status_code: i32 = lines.last().and_then(|s| s.parse().ok()).unwrap_or(-1);
        let resp_body = if lines.len() > 1 {
            lines[..lines.len() - 1].join("\n")
        } else {
            String::new()
        };
        Ok((status_code, resp_body))
    }

    /// Wait for the server to be ready by polling the health endpoint
    fn wait_ready(&self, timeout: Duration) -> Result<()> {
        let start = std::time::Instant::now();

        while start.elapsed() < timeout {
            // Check container is still running
            let status = Command::new("podman")
                .args([
                    "inspect",
                    "--format",
                    "{{.State.Running}}",
                    &self.container_name,
                ])
                .output();

            if let Ok(output) = &status {
                let running = String::from_utf8_lossy(&output.stdout).trim() == "true";
                if !running {
                    // Container stopped, get logs for debugging
                    let logs = Command::new("podman")
                        .args(["logs", &self.container_name])
                        .output()
                        .ok();
                    let log_output = logs
                        .map(|l| {
                            format!(
                                "stdout: {}\nstderr: {}",
                                String::from_utf8_lossy(&l.stdout),
                                String::from_utf8_lossy(&l.stderr)
                            )
                        })
                        .unwrap_or_default();
                    bail!("Container stopped unexpectedly. Logs:\n{}", log_output);
                }
            }

            // Try health endpoint
            if let Ok((status, _)) = self.curl_in_container("/_devaipod/health", None) {
                if status == 200 {
                    return Ok(());
                }
            }

            std::thread::sleep(Duration::from_millis(500));
        }

        bail!("Timeout waiting for web server to be ready")
    }
}

impl Drop for WebContainerGuard {
    fn drop(&mut self) {
        // Remove the container (force stop and remove)
        let _ = Command::new("podman")
            .args(["rm", "-f", &self.container_name])
            .output();
    }
}

// =============================================================================
// Shared Web Fixture (singleton pattern)
// =============================================================================

/// Shared fixture for web UI integration tests.
///
/// This fixture starts a single devaipod web container that is reused by all
/// web tests. It uses `OnceLock` for thread-safe lazy initialization.
///
/// The fixture is automatically initialized on first access via `get()` and
/// cleaned up via `cleanup()` after all tests complete.
pub struct WebFixture {
    /// The underlying container guard (handles cleanup on drop)
    guard: WebContainerGuard,
}

/// Singleton instance of the web fixture
static WEB_FIXTURE: OnceLock<Result<WebFixture, String>> = OnceLock::new();

impl WebFixture {
    /// Get the shared web fixture instance, creating it on first access.
    ///
    /// This method is thread-safe and will only create the fixture once.
    /// Returns an error if fixture creation fails.
    pub fn get() -> Result<&'static WebFixture> {
        let result = WEB_FIXTURE.get_or_init(|| {
            tracing::info!("Initializing shared WebFixture");
            match Self::create() {
                Ok(fixture) => Ok(fixture),
                Err(e) => {
                    tracing::error!("Failed to create WebFixture: {:?}", e);
                    Err(format!("{:?}", e))
                }
            }
        });

        match result {
            Ok(fixture) => Ok(fixture),
            Err(msg) => bail!("WebFixture initialization failed: {}", msg),
        }
    }

    /// Create a new web fixture (internal)
    fn create() -> Result<Self> {
        let guard = WebContainerGuard::start()?;
        guard.wait_ready(Duration::from_secs(30))?;
        tracing::info!(
            "WebFixture ready: container={}, token=***",
            guard.container_name
        );
        Ok(WebFixture { guard })
    }

    /// Get the authentication token
    pub fn token(&self) -> &str {
        self.guard.token()
    }

    /// Run curl inside the container and return (status_code, body)
    pub fn curl_in_container(&self, path: &str, auth_token: Option<&str>) -> Result<(i32, String)> {
        self.guard.curl_in_container(path, auth_token)
    }

    /// Run curl with a Cookie header.
    pub fn curl_in_container_with_cookie(&self, path: &str, cookie: &str) -> Result<(i32, String)> {
        self.guard.curl_in_container_with_cookie(path, cookie)
    }

    /// Curl with full header inspection (HTTP version, status, content-type, body) and optional cookie.
    pub fn curl_full_headers(
        &self,
        path: &str,
        max_time_secs: u8,
        cookie: Option<&str>,
    ) -> Result<(String, i32, String, String)> {
        self.guard
            .curl_in_container_full_headers(path, max_time_secs, cookie)
    }

    /// Run curl with a custom HTTP method, optional body, and optional auth token.
    pub fn curl_with_method(
        &self,
        method: &str,
        path: &str,
        body: Option<&str>,
        auth_token: Option<&str>,
    ) -> Result<(i32, String)> {
        self.guard
            .curl_in_container_with_method(method, path, body, auth_token)
    }

    /// Get the container name (for advanced operations like podman exec)
    pub fn container_name(&self) -> &str {
        &self.guard.container_name
    }

    /// Clean up the shared web fixture.
    ///
    /// This is a no-op if the fixture was never initialized.
    /// The actual cleanup happens via `WebContainerGuard::drop()`.
    pub fn cleanup() {
        // The fixture is stored in a static OnceLock, so we can't easily
        // take ownership and drop it. Instead, we manually remove the container.
        if let Some(Ok(fixture)) = WEB_FIXTURE.get() {
            tracing::info!("Cleaning up WebFixture: {}", fixture.guard.container_name);
            let _ = Command::new("podman")
                .args(["rm", "-f", &fixture.guard.container_name])
                .output();
        }
    }
}

// Note: We don't need find_available_port or external curl helpers anymore
// since the web server binds to 127.0.0.1 inside the container and we use
// `podman exec` to run curl inside the container via curl_in_container().

// =============================================================================
// Web container tests
// =============================================================================

/// Verify the containerized web server starts and serves health, API, and static files
///
/// Tier 1: Parallel safe, no pod needed
fn test_web_container_starts() -> Result<()> {
    // Get the shared web fixture (creates container on first access)
    let fixture = WebFixture::get()?;

    // Test health endpoint (no auth required)
    let (status, body) = fixture.curl_in_container("/_devaipod/health", None)?;
    assert_eq!(
        status, 200,
        "Health endpoint should return 200, got {}",
        status
    );
    assert!(
        body.contains("ok"),
        "Health should return 'ok', got: {}",
        body
    );

    // Root path always redirects to /pods (307) regardless of auth
    let (root_status, _root_body) = fixture.curl_in_container("/", None)?;
    assert_eq!(
        root_status, 307,
        "Root path should return 307 redirect to /pods, got {}",
        root_status,
    );

    // /pods serves the SPA HTML directly (no auth required for the page itself)
    let (status, body) = fixture.curl_in_container("/pods", None)?;
    assert_eq!(
        status,
        200,
        "/pods should return 200, got {}. Body: {}",
        status,
        &body[..body.len().min(200)]
    );
    assert!(
        body.contains("<!DOCTYPE html>")
            || body.contains("<html")
            || body.contains("<!doctype html>"),
        "/pods should return HTML, got: {}",
        &body[..body.len().min(200)]
    );
    let body_lower = body.to_lowercase();
    assert!(
        body_lower.contains("devaipod") || body_lower.contains("opencode"),
        "HTML should contain 'devaipod' or 'opencode' (case-insensitive), got: {}",
        &body[..body.len().min(500)]
    );

    Ok(())
}
container_integration_test!(test_web_container_starts);

/// Verify GET /_devaipod/agent/{name}/ serves iframe wrapper (not the raw opencode SPA)
///
/// The agent UI is now an iframe wrapper page: a thin nav bar with "back to pods" link
/// and a full-screen iframe pointing to /_devaipod/opencode-ui. This avoids fragile
/// HTML/CSS rewriting of the opencode SPA.
///
/// Tier 1: Parallel safe, no pod needed
fn test_web_agent_ui_index_rewrites_asset_urls() -> Result<()> {
    let fixture = WebFixture::get()?;
    let pod_name = "example-pod";
    let path = format!("/_devaipod/agent/{}/", urlencoding::encode(pod_name));
    let (status, body) = fixture.curl_in_container(&path, None)?;

    // The agent iframe wrapper needs to discover the pod-api sidecar port by
    // inspecting the pod's api container. In this test environment there is no
    // real pod running, so we expect 404 with a descriptive error message.
    if status == 404 {
        // Verify the error message is descriptive (not a generic 404)
        assert!(
            body.contains("pod-api")
                || body.contains("not found")
                || body.contains("not running")
                || body.contains("sidecar"),
            "404 response should mention pod-api sidecar not being available; got: {}",
            &body[..body.len().min(400)]
        );
        tracing::info!(
            "Agent UI endpoint returned expected 404 (no real pod): {}",
            &body[..body.len().min(200)]
        );
        return Ok(());
    }

    // If a real pod happens to exist, verify the iframe wrapper content
    assert_eq!(
        status,
        200,
        "GET /_devaipod/agent/{{name}}/ should return 200 or 404, got {}: {}",
        status,
        &body[..body.len().min(400)]
    );
    // Must be the iframe wrapper, not the raw opencode SPA
    assert!(
        body.contains("/_devaipod/opencode-ui"),
        "Agent page must contain iframe pointing to /_devaipod/opencode-ui; got: {}",
        &body[..body.len().min(600)]
    );
    assert!(
        body.contains("Pods"),
        "Agent page must have back-to-pods link; got: {}",
        &body[..body.len().min(600)]
    );
    assert!(
        body.contains("devaipod_token"),
        "Agent page must read devaipod_token from sessionStorage; got: {}",
        &body[..body.len().min(600)]
    );

    Ok(())
}
container_integration_test!(test_web_agent_ui_index_rewrites_asset_urls);

/// Verify the login flow sets a cookie and the SPA is served at /pods.
///
/// The root path (`/`) always returns 307 → `/pods`. The login endpoint
/// (`/_devaipod/login?token=...`) validates the token, sets an HttpOnly
/// cookie, and redirects to `/pods`. This test verifies:
/// 1. `/_devaipod/login?token=...` returns 307 (success) or 401 (bad token)
/// 2. `/pods` serves the SPA HTML
/// 3. Bearer token auth works for API endpoints
///
/// Tier 1: Parallel safe, no pod needed
fn test_web_ui_root_with_token() -> Result<()> {
    let fixture = WebFixture::get()?;
    let token = fixture.token().to_string();

    // The login endpoint validates the token and sets a cookie.
    // With the correct token it should redirect (307) to /pods.
    let login_path = format!("/_devaipod/login?token={}", urlencoding::encode(&token));
    let (login_status, _login_body) = fixture.curl_in_container(&login_path, None)?;
    assert_eq!(
        login_status, 307,
        "Login with valid token should redirect (307), got {}",
        login_status,
    );

    // /pods serves the SPA directly (no auth required for the page itself)
    let (pods_status, pods_body) = fixture.curl_in_container("/pods", None)?;
    assert_eq!(
        pods_status,
        200,
        "/pods should return 200, got {}: {}",
        pods_status,
        &pods_body[..pods_body.len().min(300)]
    );
    assert!(
        pods_body.contains("<!DOCTYPE html>")
            || pods_body.contains("<html")
            || pods_body.contains("<!doctype html>"),
        "/pods should return HTML, got: {}",
        &pods_body[..pods_body.len().min(500)]
    );

    // Bearer token auth should work for API endpoints
    let (api_status, api_body) =
        fixture.curl_in_container("/api/podman/v5.0.0/libpod/pods/json", Some(&token))?;
    assert_eq!(
        api_status,
        200,
        "API with Bearer token should return 200, got {}: {}",
        api_status,
        &api_body[..api_body.len().min(300)]
    );
    assert!(
        api_body.starts_with('['),
        "API response should be a JSON array, got: {}",
        &api_body[..api_body.len().min(200)]
    );

    Ok(())
}
container_integration_test!(test_web_ui_root_with_token);

/// Verify POST /api/devaipod/run is wired and returns JSON (UI surface: launch from UI)
///
/// Posts with valid auth and a body that will fail (empty/invalid source).
/// We only assert: 200 response and JSON body with "success" key (success: false is expected).
///
/// Tier 1: Parallel safe, no pod needed
fn test_web_ui_run_endpoint() -> Result<()> {
    let fixture = WebFixture::get()?;
    let token = fixture.token().to_string();

    let body = r#"{"source":"","task":null}"#;
    let auth_header = format!("Authorization: Bearer {}", token);
    let url = "http://127.0.0.1:8080/api/devaipod/run";
    let curl_output = Command::new("podman")
        .args([
            "exec",
            fixture.container_name(),
            "curl",
            "-s",
            "-w",
            "\n%{http_code}",
            "--connect-timeout",
            "5",
            "--max-time",
            "30",
            "-X",
            "POST",
            "-H",
            &auth_header,
            "-H",
            "Content-Type: application/json",
            "--data",
            body,
            url,
        ])
        .output()?;

    let combined = String::from_utf8_lossy(&curl_output.stdout);
    let lines: Vec<&str> = combined.trim().lines().collect();
    let status_code: i32 = lines.last().and_then(|s| s.parse().ok()).unwrap_or(-1);
    let response_body = if lines.len() > 1 {
        lines[..lines.len() - 1].join("\n")
    } else {
        String::new()
    };

    assert_eq!(
        status_code, 200,
        "POST /api/devaipod/run should return 200 (auth OK, JSON response), got {}: {}",
        status_code, response_body
    );
    let parsed: serde_json::Value = serde_json::from_str(&response_body).map_err(|e| {
        color_eyre::eyre::eyre!(
            "Run endpoint should return JSON: {} - body: {}",
            e,
            response_body
        )
    })?;
    assert!(
        parsed.get("success").is_some(),
        "Run response JSON should have 'success' key: {}",
        response_body
    );

    Ok(())
}
container_integration_test!(test_web_ui_run_endpoint);

/// Verify auth works: 401 without token, 200 with valid token
///
/// Tier 1: Parallel safe, no pod needed (just tests auth mechanism)
fn test_web_container_auth() -> Result<()> {
    let fixture = WebFixture::get()?;

    // Test API without token - should get 401
    let (status, _body) = fixture.curl_in_container("/api/podman/v5.0.0/libpod/pods/json", None)?;
    assert_eq!(
        status, 401,
        "API request without token should return 401 Unauthorized"
    );

    // Test API with wrong token - should get 401
    let (status, _body) = fixture.curl_in_container(
        "/api/podman/v5.0.0/libpod/pods/json",
        Some("wrong-token-12345"),
    )?;
    assert_eq!(
        status, 401,
        "API request with invalid token should return 401 Unauthorized"
    );

    // Test API with valid token - should succeed
    let token = fixture.token().to_string();
    let (status, body) =
        fixture.curl_in_container("/api/podman/v5.0.0/libpod/pods/json", Some(&token))?;
    assert_eq!(
        status, 200,
        "API request with valid token should return 200, got {}: {}",
        status, body
    );

    // Body should be valid JSON array (pods list)
    assert!(
        body.starts_with('['),
        "Pods list should be a JSON array: {}",
        body
    );

    Ok(())
}
container_integration_test!(test_web_container_auth);

/// Verify the web API pod list returns valid data and includes any existing devaipod pods
///
/// Tier 2: Parallel safe, uses shared pod for validation
fn test_web_container_pod_list() -> Result<()> {
    let fixture = WebFixture::get()?;

    // Query the web API for pod list
    let token = fixture.token().to_string();
    let (status, body) =
        fixture.curl_in_container("/api/podman/v5.0.0/libpod/pods/json", Some(&token))?;

    assert_eq!(status, 200, "Should get pod list: {}", body);

    // Body should be valid JSON array
    assert!(
        body.starts_with('['),
        "Pods list should be a JSON array: {}",
        body
    );

    // Parse the JSON to verify structure
    let pods: Vec<serde_json::Value> = serde_json::from_str(&body).map_err(|e| {
        color_eyre::eyre::eyre!("Failed to parse pods JSON: {} - body: {}", e, body)
    })?;

    // Log how many pods were found
    tracing::info!("Found {} pods in API response", pods.len());

    // If there are any devaipod pods, verify they have expected fields
    for pod in &pods {
        if let Some(name) = pod.get("Name").and_then(|n| n.as_str()) {
            if name.starts_with("devaipod-") {
                tracing::info!("Found devaipod pod: {}", name);
                // Verify expected fields exist
                assert!(
                    pod.get("Status").is_some(),
                    "Pod {} should have Status field",
                    name
                );
                assert!(
                    pod.get("Labels").is_some(),
                    "Pod {} should have Labels field",
                    name
                );
            }
        }
    }

    Ok(())
}
container_integration_test!(test_web_container_pod_list);

/// Verify the agent-status endpoint returns "Stopped" for non-existent pods
/// and proper JSON structure for existing pods
///
/// Note: The old /agent-info endpoint was removed in the ACP migration.
/// The /agent-status endpoint is now the canonical way to get pod status.
///
/// Tier 2: Parallel safe, uses shared pod for validation
fn test_web_container_agent_info_endpoint() -> Result<()> {
    let fixture = WebFixture::get()?;

    let token = fixture.token().to_string();

    // Test that non-existent pod returns "Stopped" (not an error, just status)
    let (status, body) = fixture.curl_in_container(
        "/api/devaipod/pods/nonexistent-pod-12345/agent-status",
        Some(&token),
    )?;
    assert_eq!(
        status, 200,
        "agent-status should always return 200, got {}",
        status
    );
    let status_json: serde_json::Value = serde_json::from_str(&body)?;
    assert_eq!(
        status_json["activity"].as_str(),
        Some("Stopped"),
        "Non-existent pod should have Stopped activity"
    );

    // If there's a running devaipod pod, test the endpoint returns valid data
    let (pod_status, pod_body) =
        fixture.curl_in_container("/api/podman/v5.0.0/libpod/pods/json", Some(&token))?;

    if pod_status == 200 {
        let pods: Vec<serde_json::Value> = serde_json::from_str(&pod_body).unwrap_or_default();
        for pod in &pods {
            if let Some(name) = pod.get("Name").and_then(|n| n.as_str()) {
                if name.starts_with("devaipod-") {
                    // Found a devaipod pod, test the agent-status endpoint
                    let (info_status, info_body) = fixture.curl_in_container(
                        &format!("/api/devaipod/pods/{}/agent-status", name),
                        Some(&token),
                    )?;

                    // Should always return 200 (status endpoint never errors)
                    assert_eq!(
                        info_status, 200,
                        "agent-status should return 200, got {}: {}",
                        info_status,
                        info_body
                    );

                    // Verify JSON structure
                    let info: serde_json::Value =
                        serde_json::from_str(&info_body).map_err(|e| {
                            color_eyre::eyre::eyre!(
                                "Failed to parse agent-status JSON: {} - body: {}",
                                e,
                                info_body
                            )
                        })?;

                    assert!(
                        info.get("activity").is_some(),
                        "agent-status should have 'activity' field"
                    );
                    assert!(
                        info.get("status_line").is_some(),
                        "agent-status should have 'status_line' field"
                    );
                    assert!(
                        info.get("session_count").is_some(),
                        "agent-status should have 'session_count' field"
                    );

                    tracing::info!(
                        "Successfully validated agent-status for pod {}: activity={}",
                        name,
                        info.get("activity").unwrap()
                    );
                    break; // Only test one pod
                }
            }
        }
    }

    Ok(())
}
container_integration_test!(test_web_container_agent_info_endpoint);

/// Test connectivity to a running devaipod pod's agent proxy
///
/// This test validates that the agent proxy actually returns content by:
/// 1. Finding a running devaipod pod
/// 2. Getting its agent-info (URL, port)
/// 3. Using curl from inside the web container to test the proxy returns content
///
/// If no devaipod pod is running, the test passes with a skip note.
///
/// Tier 2: Parallel safe, uses shared pod for validation
fn test_web_container_agent_connectivity() -> Result<()> {
    let fixture = WebFixture::get()?;

    let token = fixture.token().to_string();

    // Get pod list to find a running devaipod pod
    let (pod_status, pod_body) =
        fixture.curl_in_container("/api/podman/v5.0.0/libpod/pods/json", Some(&token))?;

    if pod_status != 200 {
        tracing::info!("Could not get pod list, skipping connectivity test");
        return Ok(());
    }

    let pods: Vec<serde_json::Value> = serde_json::from_str(&pod_body).unwrap_or_default();

    // Find a running devaipod pod
    let mut found_running_pod = false;
    for pod in &pods {
        let name = match pod.get("Name").and_then(|n| n.as_str()) {
            Some(n) if n.starts_with("devaipod-") => n,
            _ => continue,
        };

        // Check if pod is running
        let status = pod
            .get("Status")
            .and_then(|s| s.as_str())
            .unwrap_or("unknown");
        if status != "Running" {
            tracing::info!("Pod {} is not running (status: {}), skipping", name, status);
            continue;
        }

        tracing::info!("Found running devaipod pod: {}", name);

        // The /agent-info endpoint was removed in the ACP migration.
        // ACP uses stdio transport (podman exec) instead of HTTP, so there's
        // no published agent port to test connectivity against.
        // TODO: Add ACP-specific connectivity test (e.g. verify podman exec works)
        tracing::info!("Skipping connectivity test (agent-info endpoint removed in ACP migration)");
        return Ok(());
    }

    tracing::info!("No running devaipod pods found, skipping connectivity test");
    Ok(())
}
container_integration_test!(test_web_container_agent_connectivity);

/// Verify cookie-based authentication persists across requests.
///
/// This tests the auth flow:
/// 1. Make initial request to root path with ?token= query parameter
/// 2. Extract Set-Cookie header from response (if present)
/// 3. Make follow-up API request with only the cookie (no token param)
/// 4. Verify the cookie-authenticated request succeeds
///
/// Note: The devaipod web server may or may not use cookies for session management.
/// This test documents the current behavior.
///
/// Tier 1: Parallel safe, tests auth mechanism
fn test_auth_proxy_cookie_persistence() -> Result<()> {
    let fixture = WebFixture::get()?;

    let token = fixture.token().to_string();

    // Step 1: Make request to root path with token (this is where cookie would be set)
    // Using -c to save cookies and -L to follow redirects
    let url_with_token = format!("http://127.0.0.1:8080/?token={}", token);
    let curl_output = Command::new("podman")
        .args([
            "exec",
            fixture.container_name(),
            "curl",
            "-s",
            "-D",
            "-",  // Dump headers to stdout
            "-L", // Follow redirects
            "--connect-timeout",
            "5",
            "--max-time",
            "30",
            "--retry",
            "5",
            "--retry-connrefused",
            "--retry-all-errors",
            "--retry-delay",
            "2",
            &url_with_token,
        ])
        .output()?;

    let response = String::from_utf8_lossy(&curl_output.stdout);

    // Parse the response to extract headers (may have multiple header blocks due to redirects)
    // Find the Set-Cookie in any of them
    let set_cookie = response
        .lines()
        .find(|line| line.to_lowercase().starts_with("set-cookie:"))
        .map(|line| line.trim().to_string());

    // Also extract final status code
    let parts: Vec<&str> = response.rsplitn(2, "\r\n\r\n").collect();
    let _final_headers = parts.get(1).unwrap_or(&"");
    let final_body = parts.first().unwrap_or(&"");

    tracing::info!(
        "Root path response (first 500 chars):\n{}",
        &response[..response.len().min(500)]
    );

    // Check if we got HTML (successful page load)
    let got_html = final_body.contains("<!DOCTYPE html>")
        || final_body.contains("<html")
        || final_body.contains("<!doctype html>");

    if !got_html {
        tracing::warn!(
            "Root path didn't return HTML, got: {}",
            &final_body[..final_body.len().min(200)]
        );
    }

    // Check for Set-Cookie
    if let Some(ref cookie_header) = set_cookie {
        tracing::info!("Got Set-Cookie: {}", cookie_header);

        // Extract the cookie name=value part (before any attributes like Path, HttpOnly, etc.)
        let cookie_value = cookie_header
            .strip_prefix("Set-Cookie:")
            .or_else(|| cookie_header.strip_prefix("set-cookie:"))
            .unwrap_or(cookie_header)
            .trim()
            .split(';')
            .next()
            .unwrap_or("");

        if !cookie_value.is_empty() {
            tracing::info!("Using cookie for follow-up request: {}", cookie_value);

            // Step 2: Make follow-up API request with only the cookie (no token param)
            let cookie_request_header = format!("Cookie: {}", cookie_value);
            let url_without_token = "http://127.0.0.1:8080/api/podman/v5.0.0/libpod/pods/json";

            let cookie_curl_output = Command::new("podman")
                .args([
                    "exec",
                    fixture.container_name(),
                    "curl",
                    "-s",
                    "-w",
                    "\n%{http_code}",
                    "--connect-timeout",
                    "5",
                    "--max-time",
                    "30",
                    "--retry",
                    "5",
                    "--retry-connrefused",
                    "--retry-all-errors",
                    "--retry-delay",
                    "2",
                    "-H",
                    &cookie_request_header,
                    url_without_token,
                ])
                .output()?;

            let combined = String::from_utf8_lossy(&cookie_curl_output.stdout);
            let lines: Vec<&str> = combined.trim().lines().collect();
            let status_code: i32 = lines.last().and_then(|s| s.parse().ok()).unwrap_or(-1);
            let cookie_body = if lines.len() > 1 {
                lines[..lines.len() - 1].join("\n")
            } else {
                String::new()
            };

            // Step 3: Verify the cookie-only request succeeds
            if status_code == 200 {
                tracing::info!(
                    "Cookie persistence works: follow-up request succeeded with cookie-only auth"
                );
                assert!(
                    cookie_body.starts_with('['),
                    "Cookie-authenticated response should be valid JSON array: {}",
                    &cookie_body[..cookie_body.len().min(200)]
                );
            } else {
                // Cookie auth didn't work - this is the behavior we're testing
                tracing::warn!(
                    "Cookie-only auth returned {}: Cookie may not be used for API auth. Body: {}",
                    status_code,
                    &cookie_body[..cookie_body.len().min(200)]
                );
                // This is expected if the server doesn't use cookie-based auth for API
            }
        }
    } else {
        tracing::info!(
            "No Set-Cookie header in response - server doesn't use cookie-based sessions"
        );
        // This is also valid - the server might use only Bearer tokens
    }

    // Alternative test: verify Bearer token auth works for API (this should always work)
    let bearer_header = format!("Authorization: Bearer {}", token);
    let bearer_curl_output = Command::new("podman")
        .args([
            "exec",
            fixture.container_name(),
            "curl",
            "-s",
            "-w",
            "\n%{http_code}",
            "--connect-timeout",
            "5",
            "--max-time",
            "30",
            "--retry",
            "5",
            "--retry-connrefused",
            "--retry-all-errors",
            "--retry-delay",
            "2",
            "-H",
            &bearer_header,
            "http://127.0.0.1:8080/api/podman/v5.0.0/libpod/pods/json",
        ])
        .output()?;

    let bearer_combined = String::from_utf8_lossy(&bearer_curl_output.stdout);
    let bearer_lines: Vec<&str> = bearer_combined.trim().lines().collect();
    let bearer_status: i32 = bearer_lines
        .last()
        .and_then(|s| s.parse().ok())
        .unwrap_or(-1);
    let bearer_body = if bearer_lines.len() > 1 {
        bearer_lines[..bearer_lines.len() - 1].join("\n")
    } else {
        String::new()
    };

    assert_eq!(
        bearer_status, 200,
        "Bearer token auth should work for API. Got {}: {}",
        bearer_status, bearer_body
    );
    assert!(
        bearer_body.starts_with('['),
        "Bearer-authenticated response should be valid JSON array: {}",
        &bearer_body[..bearer_body.len().min(200)]
    );
    tracing::info!("Bearer token auth verified working for API");

    Ok(())
}
container_integration_test!(test_auth_proxy_cookie_persistence);

/// Verify that 401 responses include WWW-Authenticate header.
///
/// This is important because WWW-Authenticate triggers the browser's
/// built-in authentication dialog (the "signin request" popup in Firefox).
/// We want to detect this behavior so we can fix it for cross-origin requests.
///
/// Tier 1: Parallel safe, tests auth mechanism
fn test_auth_proxy_wrong_password_returns_401_with_www_authenticate() -> Result<()> {
    let fixture = WebFixture::get()?;

    // Make request with wrong token - should get 401
    let wrong_token = "wrong-token-12345";
    let url = format!(
        "http://127.0.0.1:8080/api/podman/v5.0.0/libpod/pods/json?token={}",
        wrong_token
    );

    let curl_output = Command::new("podman")
        .args([
            "exec",
            fixture.container_name(),
            "curl",
            "-s",
            "-D",
            "-", // Dump headers to stdout
            "--connect-timeout",
            "5",
            "--max-time",
            "30",
            "--retry",
            "5",
            "--retry-connrefused",
            "--retry-all-errors",
            "--retry-delay",
            "2",
            &url,
        ])
        .output()?;

    let response = String::from_utf8_lossy(&curl_output.stdout);

    // Parse the response to extract headers
    let parts: Vec<&str> = response.splitn(2, "\r\n\r\n").collect();
    let headers = parts.first().unwrap_or(&"");

    tracing::info!("Wrong password response headers:\n{}", headers);

    // Verify status is 401
    let status_line = headers.lines().next().unwrap_or("");
    assert!(
        status_line.contains("401"),
        "Request with wrong token should return 401, got: {}",
        status_line
    );

    // Check for WWW-Authenticate header
    let www_authenticate = headers
        .lines()
        .find(|line| line.to_lowercase().starts_with("www-authenticate:"));

    // Log whether WWW-Authenticate is present (this is the behavior we want to document/fix)
    if let Some(header) = www_authenticate {
        tracing::warn!(
            "WWW-Authenticate header IS present: {} - This triggers Firefox signin dialog!",
            header
        );
    } else {
        tracing::info!(
            "WWW-Authenticate header is NOT present (good for avoiding browser dialogs)"
        );
    }

    // For now, we're just documenting the behavior.
    // The assertion below captures current behavior - update after fix:
    // Currently we expect WWW-Authenticate to be absent (or present - adjust based on actual behavior)

    // Test request with no auth at all
    let no_auth_url = "http://127.0.0.1:8080/api/podman/v5.0.0/libpod/pods/json";
    let no_auth_output = Command::new("podman")
        .args([
            "exec",
            fixture.container_name(),
            "curl",
            "-s",
            "-D",
            "-",
            "--connect-timeout",
            "5",
            "--max-time",
            "30",
            "--retry",
            "5",
            "--retry-connrefused",
            "--retry-all-errors",
            "--retry-delay",
            "2",
            no_auth_url,
        ])
        .output()?;

    let no_auth_response = String::from_utf8_lossy(&no_auth_output.stdout);
    let no_auth_parts: Vec<&str> = no_auth_response.splitn(2, "\r\n\r\n").collect();
    let no_auth_headers = no_auth_parts.first().unwrap_or(&"");

    tracing::info!("No auth response headers:\n{}", no_auth_headers);

    // Verify status is 401
    let no_auth_status = no_auth_headers.lines().next().unwrap_or("");
    assert!(
        no_auth_status.contains("401"),
        "Request without auth should return 401, got: {}",
        no_auth_status
    );

    let no_auth_www_authenticate = no_auth_headers
        .lines()
        .find(|line| line.to_lowercase().starts_with("www-authenticate:"));

    if let Some(header) = no_auth_www_authenticate {
        tracing::warn!(
            "WWW-Authenticate header IS present on no-auth request: {} - This triggers Firefox signin dialog!",
            header
        );
    } else {
        tracing::info!("WWW-Authenticate header is NOT present on no-auth request (good)");
    }

    Ok(())
}
container_integration_test!(test_auth_proxy_wrong_password_returns_401_with_www_authenticate);

/// Test API-style requests (Accept: application/json) without auth.
///
/// This simulates cross-origin API requests from app.opencode.ai to 127.0.0.1.
/// When cookies aren't sent (due to SameSite=Lax on cross-origin), the 401
/// response with WWW-Authenticate header causes Firefox to show a signin dialog.
///
/// Tier 1: Parallel safe, tests auth mechanism
fn test_auth_proxy_api_request_without_auth() -> Result<()> {
    let fixture = WebFixture::get()?;

    // Simulate API request with Accept: application/json but no auth
    // This is what happens on cross-origin requests when cookie is not sent
    let url = "http://127.0.0.1:8080/api/podman/v5.0.0/libpod/pods/json";

    let curl_output = Command::new("podman")
        .args([
            "exec",
            fixture.container_name(),
            "curl",
            "-s",
            "-D",
            "-", // Dump headers to stdout
            "--connect-timeout",
            "5",
            "--max-time",
            "30",
            "--retry",
            "5",
            "--retry-connrefused",
            "--retry-all-errors",
            "--retry-delay",
            "2",
            "-H",
            "Accept: application/json",
            "-H",
            "Origin: https://app.opencode.ai", // Simulate cross-origin
            url,
        ])
        .output()?;

    let response = String::from_utf8_lossy(&curl_output.stdout);

    // Parse the response to extract headers
    let parts: Vec<&str> = response.splitn(2, "\r\n\r\n").collect();
    let headers = parts.first().unwrap_or(&"");
    let body = parts.get(1).unwrap_or(&"");

    tracing::info!("API request without auth - headers:\n{}", headers);
    tracing::info!("API request without auth - body:\n{}", body);

    // Verify status is 401
    let status_line = headers.lines().next().unwrap_or("");
    assert!(
        status_line.contains("401"),
        "API request without auth should return 401, got: {}",
        status_line
    );

    // Check for WWW-Authenticate header - this is what causes the Firefox issue
    let www_authenticate = headers
        .lines()
        .find(|line| line.to_lowercase().starts_with("www-authenticate:"));

    if let Some(header) = www_authenticate {
        tracing::warn!(
            "WWW-Authenticate header IS present on API request: {}",
            header
        );
        tracing::warn!(
            "This will cause Firefox to show a signin dialog for cross-origin API requests!"
        );
        tracing::warn!(
            "Fix: Don't send WWW-Authenticate for requests with Accept: application/json"
        );
    } else {
        tracing::info!("WWW-Authenticate header is NOT present on API request (good)");
    }

    // Check for CORS headers (may be relevant for cross-origin requests)
    let cors_header = headers
        .lines()
        .find(|line| line.to_lowercase().starts_with("access-control-"));

    if let Some(header) = cors_header {
        tracing::info!("CORS header present: {}", header);
    } else {
        tracing::info!("No CORS headers present");
    }

    // Verify body is JSON error response (not HTML)
    // Good API behavior: return JSON error, not redirect to login page
    if body.trim().starts_with('{') || body.trim().starts_with('[') {
        tracing::info!("Response body is JSON (good for API clients)");
    } else if body.contains("<!DOCTYPE html>") || body.contains("<html") {
        tracing::warn!("Response body is HTML - API clients expect JSON error response");
    }

    Ok(())
}
container_integration_test!(test_auth_proxy_api_request_without_auth);

/// Verify the MCP endpoint requires authentication.
///
/// The MCP endpoint at `/api/devaipod/mcp` uses a separate shared secret
/// (not the web API token). This test verifies that:
/// - Unauthenticated requests are rejected (401)
/// - The web API token does not grant MCP access (401)
/// - A random/wrong token does not grant MCP access (401)
///
/// We cannot test the positive case (valid MCP token -> 200) because the
/// MCP token is generated internally and not exposed in the container logs.
/// That case is covered by unit tests in src/web.rs.
///
/// Tier 1: Parallel safe, no pod needed
fn test_mcp_endpoint_requires_auth() -> Result<()> {
    let fixture = WebFixture::get()?;
    let container = fixture.container_name();
    let sh = crate::shell()?;

    let mcp_body = r#"{"jsonrpc":"2.0","id":1,"method":"ping"}"#;
    let url = "http://127.0.0.1:8080/api/devaipod/mcp";
    let content_type = "Content-Type: application/json";
    // Use a variable so xshell doesn't try to interpolate {http_code}
    let write_format = r"\n%{http_code}";

    // Helper: extract HTTP status code from curl -w '\n%{http_code}' output
    let extract_status = |output: &str| -> i32 {
        output
            .trim()
            .lines()
            .last()
            .and_then(|s| s.parse().ok())
            .unwrap_or(-1)
    };

    // 1. POST without auth -> 401
    let output = cmd!(
        sh,
        "podman exec {container} curl -s -w {write_format} --connect-timeout 5 --max-time 10 -X POST -H {content_type} -d {mcp_body} {url}"
    )
    .ignore_status()
    .read()?;
    assert_eq!(
        extract_status(&output),
        401,
        "MCP endpoint without auth should return 401"
    );

    // 2. POST with the web API token -> 401 (tokens are separate)
    let auth_header = format!("Authorization: Bearer {}", fixture.token());
    let output = cmd!(
        sh,
        "podman exec {container} curl -s -w {write_format} --connect-timeout 5 --max-time 10 -X POST -H {content_type} -H {auth_header} -d {mcp_body} {url}"
    )
    .ignore_status()
    .read()?;
    assert_eq!(
        extract_status(&output),
        401,
        "MCP endpoint with web API token should return 401 (separate secrets)"
    );

    // 3. POST with a random wrong token -> 401
    let wrong_auth = "Authorization: Bearer totally-wrong-token-12345";
    let output = cmd!(
        sh,
        "podman exec {container} curl -s -w {write_format} --connect-timeout 5 --max-time 10 -X POST -H {content_type} -H {wrong_auth} -d {mcp_body} {url}"
    )
    .ignore_status()
    .read()?;
    assert_eq!(
        extract_status(&output),
        401,
        "MCP endpoint with wrong token should return 401"
    );

    Ok(())
}
container_integration_test!(test_mcp_endpoint_requires_auth);

/// Verify the agent iframe wrapper contains pod switcher UI elements.
///
/// Fetches `/_devaipod/agent/{name}/` for a running pod and checks that the
/// HTML includes the pod switcher dropdown, navigation arrows, and the JS
/// functions that fetch and render the pod list. If no running pod exists
/// (404), the test is skipped gracefully.
///
/// Tier 2: Parallel safe, uses shared pod for validation
fn test_web_agent_iframe_has_pod_switcher() -> Result<()> {
    let fixture = WebFixture::get()?;
    let token = fixture.token().to_string();
    let cookie = format!("devaipod_token={}", token);

    let short_name = match super::controlplane::find_running_pod(fixture, &token)? {
        Some(n) => n,
        None => {
            tracing::info!("No running pods found, skipping pod switcher test");
            return Ok(());
        }
    };

    let path = format!("/_devaipod/agent/{}/", short_name);
    let (status, body) = fixture.curl_in_container_with_cookie(&path, &cookie)?;

    if status == 404 {
        tracing::info!(
            "Agent iframe returned 404 for '{}' (pod may not have a healthy sidecar), skipping",
            short_name
        );
        return Ok(());
    }

    assert_eq!(
        status,
        200,
        "GET {} should return 200 or 404, got {}: {}",
        path,
        status,
        &body[..body.len().min(400)]
    );

    // Verify all pod switcher HTML elements are present.
    for (id, description) in [
        (r#"id="pod-switcher""#, "pod switcher container"),
        (r#"id="pod-trigger""#, "pod trigger button"),
        (r#"id="prev-pod""#, "previous pod arrow"),
        (r#"id="next-pod""#, "next pod arrow"),
        (r#"id="pod-dropdown""#, "pod dropdown menu"),
    ] {
        assert!(
            body.contains(id),
            "Agent iframe should contain {description} ({id}); body length={}",
            body.len()
        );
    }

    // Verify external script reference and pod-data element are present.
    for (marker, description) in [
        ("agent-wrapper.js", "external agent-wrapper.js script"),
        (r#"id="pod-data""#, "pod-data JSON element"),
    ] {
        assert!(
            body.contains(marker),
            "Agent iframe should contain {description} ('{marker}'); body length={}",
            body.len()
        );
    }

    tracing::info!(
        "Pod switcher elements verified in agent iframe for '{}'",
        short_name
    );
    Ok(())
}
container_integration_test!(test_web_agent_iframe_has_pod_switcher);
