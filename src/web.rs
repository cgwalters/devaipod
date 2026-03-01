//! Web server for devaipod control plane
//!
//! This module provides:
//! - Token-based authentication for API access
//! - Podman socket proxy at `/api/podman/*`
//! - Agent view at `/_devaipod/agent/{name}/` (iframe wrapper pointing at pod-api sidecar)
//! - Workspace recreate at `POST /api/devaipod/pods/{name}/recreate`
//! - Opencode-info and agent-status endpoints for the pods page
//! - Static file serving for web UI

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use axum::{
    body::Body,
    extract::{Path, Query, Request, State},
    http::{header, HeaderMap, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use base64::prelude::*;
use color_eyre::eyre::{Context, Result};
use hyper_util::rt::TokioIo;
use serde::{Deserialize, Serialize};
use tokio::net::UnixStream;
use tower::ServiceExt;
use tower_http::cors::{Any, CorsLayer};
use tower_http::services::ServeDir;

use crate::advisor;
use crate::podman::{get_container_socket, host_for_pod_services};

/// Path to the token file when using podman/Kubernetes secrets (highest priority).
const TOKEN_SECRET_PATH: &str = "/run/secrets/devaipod-web-token";

/// Default directory for persistent state when using the devaipod-state volume.
/// Override with DEVAIPOD_STATE_DIR. Token is stored at {state_dir}/web-token.
const DEFAULT_STATE_DIR: &str = "/var/lib/devaipod";

/// Filename for the web auth token inside the state directory.
const STATE_TOKEN_FILENAME: &str = "web-token";

fn state_token_path() -> std::path::PathBuf {
    let dir = std::env::var("DEVAIPOD_STATE_DIR").unwrap_or_else(|_| DEFAULT_STATE_DIR.to_string());
    std::path::PathBuf::from(dir).join(STATE_TOKEN_FILENAME)
}

const DEVAIPOD_AUTH_COOKIE: &str = "DEVAIPOD_AUTH";

/// Extract a raw cookie value by name from the request headers.
fn cookie_value(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(header::COOKIE)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| {
            let prefix = format!("{name}=");
            s.split(';').find_map(|pair| {
                let pair = pair.trim();
                pair.starts_with(&prefix)
                    .then(|| pair[prefix.len()..].to_string())
            })
        })
}

/// Normalize pod name: ensure it has the "devaipod-" prefix.
fn normalize_pod_name(name: &str) -> String {
    if name.starts_with("devaipod-") {
        name.to_string()
    } else {
        format!("devaipod-{name}")
    }
}

/// Generate a cryptographically secure random token
///
/// Returns 32 random bytes encoded as URL-safe base64 (no padding).
/// This provides 256 bits of entropy, suitable for authentication tokens.
pub fn generate_token() -> String {
    use rand::Rng;
    let mut rng = rand::rng();
    let bytes: [u8; 32] = rng.random();
    BASE64_URL_SAFE_NO_PAD.encode(bytes)
}

/// Load token from secrets file, state volume, or generate a new one
///
/// Priority: (1) `/run/secrets/devaipod-web-token` (podman secret / Kubernetes),
/// (2) state dir `DEVAIPOD_STATE_DIR/web-token` (default `/var/lib/devaipod/web-token` when
/// the devaipod-state volume is mounted). If a new token is generated and the state dir exists,
/// it is written there so it persists across restarts.
pub fn load_or_generate_token() -> String {
    // 1. Podman/Kubernetes secret (highest priority)
    if let Ok(token) = std::fs::read_to_string(TOKEN_SECRET_PATH) {
        let trimmed = token.trim();
        if !trimmed.is_empty() {
            tracing::debug!("Loaded token from {}", TOKEN_SECRET_PATH);
            return trimmed.to_string();
        }
    }

    // 2. State volume path (devaipod-state mounted at DEVAIPOD_STATE_DIR)
    let state_path = state_token_path();
    if let Ok(token) = std::fs::read_to_string(&state_path) {
        let trimmed = token.trim();
        if !trimmed.is_empty() {
            tracing::debug!("Loaded token from {}", state_path.display());
            return trimmed.to_string();
        }
    }

    // 3. Generate and persist to state dir if it exists
    let token = generate_token();
    if let Some(parent) = state_path.parent() {
        if parent.exists() {
            if let Err(e) = std::fs::write(&state_path, &token) {
                tracing::warn!("Could not persist token to {}: {}", state_path.display(), e);
            } else {
                tracing::debug!("Generated and saved token to {}", state_path.display());
            }
        }
    } else {
        tracing::debug!("Generated new authentication token");
    }
    token
}

/// State of a background launch spawned by the web UI.
///
/// Completed launches are removed from the map immediately (the pod becomes
/// visible via normal podman polling). Failed launches stay until dismissed.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "state")]
enum LaunchState {
    /// Subprocess is still running.
    #[serde(rename = "launching")]
    Launching,
    /// Subprocess failed with an error message.
    #[serde(rename = "failed")]
    Failed { error: String },
}

/// In-flight launches tracked by the web server, keyed by pod name.
type LaunchMap = Arc<tokio::sync::Mutex<HashMap<String, LaunchState>>>;

/// Shared state for the web server
#[derive(Clone)]
pub(crate) struct AppState {
    /// Authentication token for API access
    token: String,
    /// Path to the podman/docker socket (None if not available at startup)
    socket_path: Option<PathBuf>,
    /// Background launch states so the UI can track in-flight launches.
    launches: LaunchMap,
    /// Image ID (digest) of the running control plane container.
    /// Used to detect pods whose API sidecar is running an older image.
    self_image_id: Option<String>,
}

/// Query parameters for token authentication
#[derive(Debug, Deserialize)]
struct TokenQuery {
    token: Option<String>,
}

/// Authentication middleware
///
/// Validates requests by checking (in order):
/// 1. `DEVAIPOD_AUTH` cookie (set by the login endpoint)
/// 2. `Authorization: Bearer ...` header
/// 3. `?token=...` query parameter
///
/// Returns 401 Unauthorized if none is present or valid.
async fn auth_middleware(
    State(state): State<Arc<AppState>>,
    Query(query): Query<TokenQuery>,
    headers: HeaderMap,
    request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    // Check auth cookie (primary method — set by /_devaipod/login)
    if let Some(token) = cookie_value(&headers, DEVAIPOD_AUTH_COOKIE) {
        if token == state.token {
            return Ok(next.run(request).await);
        }
    }

    // Check Authorization header
    if let Some(auth_header) = headers.get(header::AUTHORIZATION) {
        if let Ok(auth_str) = auth_header.to_str() {
            if let Some(token) = auth_str.strip_prefix("Bearer ") {
                if token == state.token {
                    return Ok(next.run(request).await);
                }
            }
        }
    }

    // Check query parameter (legacy / one-off use)
    if let Some(ref token) = query.token {
        if token == &state.token {
            return Ok(next.run(request).await);
        }
    }

    Err(StatusCode::UNAUTHORIZED)
}

/// Proxy handler for podman socket
///
/// Forwards all requests under `/api/podman/*` to the podman unix socket.
/// The path after `/api/podman` is used as the request path to podman.
///
/// Example: `GET /api/podman/v1.0.0/containers/json` ->
///          `GET /v1.0.0/containers/json` on the socket
async fn podman_proxy(
    State(state): State<Arc<AppState>>,
    Path(path): Path<String>,
    request: Request,
) -> Result<Response, StatusCode> {
    // Get socket path, trying to discover it if not known at startup
    let socket_path = match &state.socket_path {
        Some(p) => p.clone(),
        None => {
            // Try to find socket now (it might have become available)
            get_container_socket().map_err(|e| {
                tracing::error!("No podman socket available: {}", e);
                StatusCode::SERVICE_UNAVAILABLE
            })?
        }
    };

    // Connect to the unix socket
    let stream = UnixStream::connect(&socket_path).await.map_err(|e| {
        tracing::error!("Failed to connect to podman socket: {}", e);
        StatusCode::BAD_GATEWAY
    })?;

    let io = TokioIo::new(stream);

    // Create HTTP client over unix socket
    let (mut sender, conn) = hyper::client::conn::http1::handshake(io)
        .await
        .map_err(|e| {
            tracing::error!("Handshake with podman socket failed: {}", e);
            StatusCode::BAD_GATEWAY
        })?;

    // Spawn connection handler
    tokio::spawn(async move {
        if let Err(e) = conn.await {
            tracing::error!("Connection to podman socket failed: {}", e);
        }
    });

    // Build the request to send to podman
    let (parts, body) = request.into_parts();

    // Reconstruct the URI with the path after /api/podman
    let uri = format!("/{}", path);

    let mut builder = hyper::Request::builder()
        .method(parts.method)
        .uri(&uri)
        // Podman expects a Host header even over unix socket
        .header(header::HOST, "localhost");

    // Copy headers (except Host which we set above)
    for (key, value) in parts.headers.iter() {
        if key != header::HOST {
            builder = builder.header(key, value);
        }
    }

    let proxy_request = builder.body(body).map_err(|e| {
        tracing::error!("Failed to build proxy request: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    // Send request and get response
    let response = sender.send_request(proxy_request).await.map_err(|e| {
        tracing::error!("Failed to send request to podman: {}", e);
        StatusCode::BAD_GATEWAY
    })?;

    // Convert the response
    let (parts, body) = response.into_parts();
    let body = Body::new(body);

    Ok(Response::from_parts(parts, body))
}

/// Response for opencode info endpoint
#[derive(Debug, Serialize)]
struct OpencodeInfoResponse {
    /// URL to access the opencode web UI directly
    url: String,
    /// Published port on localhost
    port: u16,
    /// Whether the pod is accessible
    accessible: bool,
    /// Most recent session info (if any sessions exist)
    #[serde(skip_serializing_if = "Option::is_none")]
    latest_session: Option<LatestSessionInfo>,
}

/// Info about the most recent session, used by the control plane to navigate
/// directly to it (avoiding the empty new-session view).
#[derive(Debug, Serialize)]
struct LatestSessionInfo {
    id: String,
    directory: String,
}

/// JSON body for API errors (e.g. 404) so the frontend can show a clear message
#[derive(Debug, Serialize)]
struct ApiErrorBody {
    error: String,
}

/// Path to vendored opencode web UI
const OPENCODE_UI_PATH: &str = "/usr/share/devaipod/opencode";

/// Path to mdbook documentation output
const DOCS_PATH: &str = "/usr/share/devaipod/docs";

/// Get opencode connection info for a pod
///
/// Returns the direct URL to access the opencode web UI.
/// On 404 returns JSON body so the frontend can show "Pod or agent not found".
async fn opencode_info(
    Path(name): Path<String>,
) -> Result<Json<OpencodeInfoResponse>, (StatusCode, Json<ApiErrorBody>)> {
    let pod_name = normalize_pod_name(&name);

    let port = get_pod_api_port(&pod_name).await.map_err(|code| {
        let msg = if code == StatusCode::NOT_FOUND {
            "Pod or agent not found (pod-api sidecar may not be running or port not published)"
                .to_string()
        } else {
            code.to_string()
        };
        (code, Json(ApiErrorBody { error: msg }))
    })?;

    // Build URL for the opencode web UI (via pod-api sidecar)
    let url = format!("http://localhost:{}/", port);

    // Fetch the most recent session via the pod-api sidecar (which proxies to
    // the opencode server internally and handles auth).
    let latest_session = fetch_latest_session(port).await;

    Ok(Json(OpencodeInfoResponse {
        url,
        port,
        accessible: true,
        latest_session,
    }))
}

/// Fetch the most recent session via the pod-api sidecar.
///
/// Calls GET /session on the pod-api sidecar, which proxies to the opencode
/// server internally (with auth). Returns the session with the most recent
/// `time.updated` timestamp. Returns None on any error (non-fatal: the
/// control plane just won't deep-link into a session).
async fn fetch_latest_session(pod_api_port: u16) -> Option<LatestSessionInfo> {
    let host = host_for_pod_services();

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .ok()?;

    let resp = client
        .get(format!("http://{}:{}/session", host, pod_api_port))
        .send()
        .await
        .ok()?;

    if !resp.status().is_success() {
        return None;
    }

    let sessions: Vec<serde_json::Value> = resp.json().await.ok()?;

    // Find the session with the most recent updated time
    sessions
        .iter()
        .filter_map(|s| {
            let id = s.get("id")?.as_str()?;
            let dir = s.get("directory")?.as_str()?;
            let updated = s.get("time")?.get("updated")?.as_u64()?;
            Some((id, dir, updated))
        })
        .max_by_key(|&(_, _, updated)| updated)
        .map(|(id, dir, _)| LatestSessionInfo {
            id: id.to_string(),
            directory: dir.to_string(),
        })
}

/// Get the published host port for the pod-api sidecar container.
///
/// The pod-api container listens on `POD_API_PORT` (8090) inside the pod.
/// Since we publish that port when creating the pod, we can discover the
/// host-mapped port by inspecting the infra container's port bindings —
/// the same way we discover the opencode port.
async fn get_pod_api_port(pod_name: &str) -> Result<u16, StatusCode> {
    use bollard::Docker;

    let socket_path = get_container_socket().map_err(|e| {
        tracing::error!("Failed to get container socket: {}", e);
        StatusCode::SERVICE_UNAVAILABLE
    })?;

    let docker = Docker::connect_with_unix(
        &format!("unix://{}", socket_path.display()),
        120,
        bollard::API_DEFAULT_VERSION,
    )
    .map_err(|e| {
        tracing::error!("Failed to connect to container socket: {}", e);
        StatusCode::SERVICE_UNAVAILABLE
    })?;

    // Inspect the agent container to find the published port mapping.
    // All containers in the pod share the same network namespace, so port
    // bindings appear on any container.
    let info = docker
        .inspect_container(&format!("{pod_name}-agent"), None)
        .await
        .map_err(|e| {
            tracing::error!("Failed to inspect agent container for {pod_name}: {e}");
            StatusCode::NOT_FOUND
        })?;

    let ports = info
        .network_settings
        .as_ref()
        .and_then(|ns| ns.ports.as_ref())
        .ok_or_else(|| {
            tracing::error!("No port mappings found for {pod_name}");
            StatusCode::NOT_FOUND
        })?;

    let api_port = crate::pod::POD_API_PORT;
    let port_key = format!("{api_port}/tcp");
    let bindings = ports
        .get(&port_key)
        .and_then(|b| b.as_ref())
        .ok_or_else(|| {
            tracing::error!("Port {api_port} not published for {pod_name}");
            StatusCode::NOT_FOUND
        })?;

    bindings
        .first()
        .and_then(|b| b.host_port.as_ref())
        .and_then(|p| p.parse::<u16>().ok())
        .ok_or_else(|| {
            tracing::error!("Could not parse host port for pod-api of {pod_name}");
            StatusCode::NOT_FOUND
        })
}

/// Low-level HTTP proxy: connect to `host:port`, forward `request`,
/// and return the response with the HTTP version normalized to 1.1.
///
/// Supports HTTP Upgrade (WebSocket): when the request contains an `Upgrade` header,
/// the proxy negotiates the upgrade with upstream and then bidirectionally copies
/// raw bytes between the client and upstream connections.
async fn proxy_to_upstream(
    host: &str,
    port: u16,
    path: String,
    request: Request,
) -> Result<Response, StatusCode> {
    let stream = tokio::net::TcpStream::connect(format!("{}:{}", host, port))
        .await
        .map_err(|e| {
            tracing::error!("Failed to connect to upstream at {}:{}: {}", host, port, e);
            StatusCode::BAD_GATEWAY
        })?;

    let io = TokioIo::new(stream);

    let is_upgrade = request.headers().get(header::UPGRADE).is_some();

    let (mut sender, conn) = hyper::client::conn::http1::handshake(io)
        .await
        .map_err(|e| {
            tracing::error!("Handshake with upstream failed: {}", e);
            StatusCode::BAD_GATEWAY
        })?;

    if is_upgrade {
        tokio::spawn(async move {
            if let Err(e) = conn.with_upgrades().await {
                tracing::debug!("Upgrade connection closed: {}", e);
            }
        });
    } else {
        tokio::spawn(async move {
            if let Err(e) = conn.await {
                tracing::error!("Connection to upstream failed: {}", e);
            }
        });
    }

    let mut uri = if path.is_empty() || path == "/" {
        "/".to_string()
    } else if path.starts_with('/') {
        path
    } else {
        format!("/{}", path)
    };

    if let Some(query) = request.uri().query() {
        uri.push('?');
        uri.push_str(query);
    }

    let (parts, body) = request.into_parts();

    let mut builder = hyper::Request::builder()
        .method(parts.method.clone())
        .uri(&uri)
        .header(header::HOST, format!("{}:{}", host, port));

    for (key, value) in parts.headers.iter() {
        if key != header::HOST {
            builder = builder.header(key, value);
        }
    }

    let proxy_request = builder.body(body).map_err(|e| {
        tracing::error!("Failed to build proxy request: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let upstream_response = sender.send_request(proxy_request).await.map_err(|e| {
        tracing::error!("Failed to send request to upstream: {}", e);
        StatusCode::BAD_GATEWAY
    })?;

    if is_upgrade && upstream_response.status() == StatusCode::SWITCHING_PROTOCOLS {
        let mut response_builder = Response::builder().status(StatusCode::SWITCHING_PROTOCOLS);
        for (key, value) in upstream_response.headers() {
            response_builder = response_builder.header(key, value);
        }

        let inbound_request = Request::from_parts(parts, Body::empty());

        tokio::spawn(async move {
            let client_upgraded = hyper::upgrade::on(inbound_request).await;
            let upstream_upgraded = hyper::upgrade::on(upstream_response).await;

            match (client_upgraded, upstream_upgraded) {
                (Ok(client), Ok(upstream)) => {
                    let mut client_io = TokioIo::new(client);
                    let mut upstream_io = TokioIo::new(upstream);
                    if let Err(e) =
                        tokio::io::copy_bidirectional(&mut client_io, &mut upstream_io).await
                    {
                        tracing::debug!("WebSocket proxy connection closed: {}", e);
                    }
                }
                (Err(e), _) => tracing::error!("Client upgrade failed: {}", e),
                (_, Err(e)) => tracing::error!("Upstream upgrade failed: {}", e),
            }
        });

        return response_builder.body(Body::empty()).map_err(|e| {
            tracing::error!("Failed to build upgrade response: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        });
    }

    let (mut parts, body) = upstream_response.into_parts();
    parts.version = hyper::Version::HTTP_11;
    let body = Body::new(body);

    Ok(Response::from_parts(parts, body))
}

/// Catch-all proxy handler for the per-pod API sidecar.
///
/// Routes `/api/devaipod/pods/{name}/pod-api/{*path}` to the pod-api container
/// at `http://{host}:{published_port}/{path}`.
async fn pod_api_proxy(
    Path((name, path)): Path<(String, String)>,
    request: Request,
) -> Result<Response, StatusCode> {
    let pod_name = normalize_pod_name(&name);

    let port = get_pod_api_port(&pod_name).await.map_err(|code| {
        if code == StatusCode::NOT_FOUND {
            StatusCode::SERVICE_UNAVAILABLE
        } else {
            code
        }
    })?;

    let host = host_for_pod_services();

    tracing::debug!(
        "Proxying to pod-api for pod {} on {}:{}, path: {}",
        pod_name,
        host,
        port,
        path
    );

    proxy_to_upstream(&host, port, path, request).await
}

/// Helper: proxy a request to a pod's pod-api sidecar at the given path.
async fn proxy_to_pod_api(
    name: &str,
    upstream_path: String,
    request: Request,
) -> Result<Response, StatusCode> {
    let pod_name = normalize_pod_name(name);
    let port = get_pod_api_port(&pod_name).await.map_err(|code| {
        if code == StatusCode::NOT_FOUND {
            StatusCode::SERVICE_UNAVAILABLE
        } else {
            code
        }
    })?;
    let host = host_for_pod_services();
    proxy_to_upstream(&host, port, upstream_path, request).await
}

/// Proxy PTY root requests (`GET /pty`, `POST /pty`) to the pod-api sidecar.
async fn pty_pod_api_proxy_root(
    Path(name): Path<String>,
    request: Request,
) -> Result<Response, StatusCode> {
    proxy_to_pod_api(&name, "pty".to_string(), request).await
}

/// Proxy PTY sub-path requests (`GET/PUT/DELETE /pty/{id}`, `GET /pty/{id}/connect`)
/// to the pod-api sidecar.
async fn pty_pod_api_proxy(
    Path((name, rest)): Path<(String, String)>,
    request: Request,
) -> Result<Response, StatusCode> {
    proxy_to_pod_api(&name, format!("pty/{rest}"), request).await
}

/// Middleware that logs every HTTP request and response (method, URI, status, duration, content-type).
/// Query parameters are stripped to avoid leaking tokens into logs.
async fn request_trace(request: Request, next: Next) -> Response {
    let method = request.method().clone();
    let path = request.uri().path().to_owned();
    let start = std::time::Instant::now();
    let response = next.run(request).await;
    let latency = start.elapsed();
    let ct = response
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("-");
    tracing::info!(
        %method,
        path = %path,
        status = %response.status(),
        content_type = ct,
        version = ?response.version(),
        latency_ms = latency.as_millis(),
    );
    response
}

/// Frontend error report sent by the injected console.error interceptor.
#[derive(Deserialize)]
struct FrontendErrorReport {
    message: String,
    #[serde(default)]
    url: String,
    #[serde(default)]
    stack: String,
    #[serde(default)]
    context: String,
}

/// Receives frontend error reports POSTed by the injected console.error interceptor.
/// Logs them server-side so they appear in `RUST_LOG=devaipod=debug` output alongside
/// request traces, making it possible to correlate client and server events.
async fn frontend_error_report(Json(report): Json<FrontendErrorReport>) -> StatusCode {
    tracing::warn!(
        url = %report.url,
        context = %report.context,
        stack = %report.stack,
        "[frontend] {}",
        report.message,
    );
    StatusCode::NO_CONTENT
}

/// Fallback handler: serve static files from the vendored opencode UI directory
/// (for /assets/*, favicon.ico, etc.) or the SPA index.html for client-side
/// routing (e.g. /pods, /some-dir/session/123).
///
/// The pod-api sidecar now handles the opencode UI and API proxy directly,
/// so this fallback no longer does cookie-based routing or opencode proxying.
async fn static_or_spa_fallback(request: Request) -> Response {
    let path = request.uri().path();
    let trimmed_path = path.trim_start_matches('/');

    // Check if path looks like a static file (has a file extension).
    let has_ext = trimmed_path
        .rsplit_once('/')
        .map_or(trimmed_path, |(_dir, file)| file)
        .contains('.');

    if has_ext {
        let opencode_req = Request::builder()
            .uri(request.uri().clone())
            .body(Body::empty())
            .unwrap();
        let resp = ServeDir::new(OPENCODE_UI_PATH)
            .oneshot(opencode_req)
            .await
            .unwrap()
            .into_response();
        if resp.status() != StatusCode::NOT_FOUND {
            return resp;
        }
    }

    // For any non-file path, serve the SPA index.html for client-side routing.
    match serve_opencode_index().await {
        Ok(resp) => resp,
        Err(status) => Response::builder()
            .status(status)
            .body(Body::empty())
            .unwrap(),
    }
}

/// Wrapper HTML page that embeds the pod-api sidecar's opencode UI in a full-screen
/// iframe with a thin navigation bar. The `base_url` points at the pod-api sidecar's
/// published port (e.g. `http://localhost:54321/` or
/// `http://localhost:54321/{base64dir}/session/{id}`). The iframe loads the SPA
/// directly from the sidecar, which also proxies opencode API calls.
fn agent_iframe_wrapper(name: &str, base_url: &str) -> String {
    let escaped_name = name
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;");
    let escaped_url = base_url.replace('&', "&amp;").replace('"', "&quot;");
    format!(
        r#"<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>devaipod - {escaped_name}</title>
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
html,body{{height:100%;overflow:hidden;background:#1c1717}}
#dbar{{height:44px;display:flex;align-items:center;padding:0 12px;
  background:#1c1717;border-bottom:1px solid rgba(255,255,255,0.12)}}
#dbar a{{color:#e8e2e2;text-decoration:none;font-size:14px;font-weight:500;
  font-family:Inter,system-ui,sans-serif;
  padding:6px 14px;border-radius:6px;
  background:rgba(255,255,255,0.08);border:1px solid rgba(255,255,255,0.15);
  transition:background 0.15s,border-color 0.15s}}
#dbar a:hover{{background:rgba(255,255,255,0.14);border-color:rgba(255,255,255,0.25)}}
iframe{{width:100%;height:calc(100% - 44px);border:none}}
</style></head><body>
<div id="dbar"><a href="/pods">&#8592; Pods</a></div>
<iframe id="oc" src="{escaped_url}" allow="clipboard-read; clipboard-write"></iframe>
</body></html>"#
    )
}

/// Redirect /_devaipod/agent/{name} to /_devaipod/agent/{name}/ (URL consistency).
///
/// Query parameters (e.g. `?dir=...&session=...`) are preserved across the redirect
/// so the trailing-slash handler can read them for pod-api URL construction.
async fn agent_wrapper(Path(name): Path<String>, request: Request) -> Result<Response, StatusCode> {
    let mut location = format!("/_devaipod/agent/{}/", urlencoding::encode(&name));
    if let Some(query) = request.uri().query() {
        location.push('?');
        location.push_str(query);
    }
    Ok(Response::builder()
        .status(StatusCode::TEMPORARY_REDIRECT)
        .header(header::LOCATION, location)
        .body(Body::empty())
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?)
}

/// Query parameters for the agent UI page.
///
/// The `openPod` frontend function navigates to
/// `/_devaipod/agent/{name}/?dir=BASE64&session=ID` so the server can construct the
/// full pod-api URL with the session deep-link path.
#[derive(Debug, Deserialize)]
struct AgentQuery {
    /// Base64-encoded working directory for the session.
    dir: Option<String>,
    /// Session ID to deep-link into.
    session: Option<String>,
}

/// Serve the iframe wrapper page for a specific agent.
///
/// Discovers the pod-api sidecar's published port and constructs an iframe src
/// pointing directly at it (optionally including a session deep-link path).
/// Returns 503 if the pod-api container is not running or its port cannot be
/// discovered.
async fn agent_ui_root(
    Path(name): Path<String>,
    Query(query): Query<AgentQuery>,
) -> Result<Response, (StatusCode, String)> {
    let pod_name = normalize_pod_name(&name);

    let port = get_pod_api_port(&pod_name).await.map_err(|code| {
        let msg = format!(
            "Could not discover pod-api port for {pod_name}: \
             the pod-api sidecar may not be running"
        );
        tracing::error!("{msg}");
        (code, msg)
    })?;

    // The iframe URL is rendered in the user's browser on the host, so we must
    // use localhost — not host.containers.internal (which is only resolvable
    // inside containers).  Published ports are bound to 0.0.0.0 on the host.
    let host = "localhost";

    // Build the base URL, optionally including the session deep-link path.
    let base_url = match (query.dir.as_deref(), query.session.as_deref()) {
        (Some(dir), Some(session)) => {
            format!("http://{host}:{port}/{dir}/session/{session}")
        }
        _ => format!("http://{host}:{port}/"),
    };

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "text/html; charset=utf-8")
        .header(header::CACHE_CONTROL, "no-cache")
        .body(Body::from(agent_iframe_wrapper(&name, &base_url)))
        .unwrap())
}

/// Serve the opencode SPA's index.html.
/// The SPA handles devaipod-specific behavior (error reporting, SSE
/// suppression) unconditionally since this is a devaipod-specific fork.
async fn serve_opencode_index() -> Result<Response, StatusCode> {
    let ui_path = std::path::Path::new(OPENCODE_UI_PATH).join("index.html");
    let content = tokio::fs::read(&ui_path).await.map_err(|e| {
        tracing::error!("Failed to read opencode index.html: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;
    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "text/html; charset=utf-8")
        .header(header::CACHE_CONTROL, "no-cache")
        .body(Body::from(content))
        .unwrap())
}

/// Redirect `/docs` to `/docs/` for consistency.
async fn redirect_to_docs() -> Response {
    Response::builder()
        .status(StatusCode::TEMPORARY_REDIRECT)
        .header(header::LOCATION, "/docs/")
        .body(Body::empty())
        .unwrap()
}

/// Serve the mdbook index at `/docs/`.
async fn serve_docs_index() -> Result<Response, StatusCode> {
    let index_path = std::path::Path::new(DOCS_PATH).join("index.html");
    let content = tokio::fs::read(&index_path).await.map_err(|e| {
        tracing::error!("Failed to read docs index.html: {}", e);
        StatusCode::NOT_FOUND
    })?;
    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "text/html; charset=utf-8")
        .body(Body::from(content))
        .unwrap())
}

/// Serve static files from the mdbook output at `/docs/{path}`.
async fn serve_docs_file(Path(path): Path<String>) -> Result<Response, StatusCode> {
    let uri = format!("/{}", path.trim_start_matches('/'));
    let request = Request::builder()
        .uri(&uri)
        .body(Body::empty())
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    let resp = ServeDir::new(DOCS_PATH)
        .oneshot(request)
        .await
        .unwrap()
        .into_response();
    if resp.status() == StatusCode::NOT_FOUND {
        return Err(StatusCode::NOT_FOUND);
    }
    Ok(resp)
}

/// Redirect `/` to `/pods`.
async fn redirect_to_pods() -> Response {
    Response::builder()
        .status(StatusCode::TEMPORARY_REDIRECT)
        .header(header::LOCATION, "/pods")
        .body(Body::empty())
        .unwrap()
}

/// Login endpoint: validates the token and sets an HttpOnly auth cookie.
/// This is the initial entry point — the startup URL points here.
async fn login(State(state): State<Arc<AppState>>, Query(query): Query<TokenQuery>) -> Response {
    let valid = query.token.as_ref().is_some_and(|t| t == &state.token);
    if !valid {
        return Response::builder()
            .status(StatusCode::UNAUTHORIZED)
            .header(header::CONTENT_TYPE, "text/plain")
            .body(Body::from("Invalid or missing token"))
            .unwrap();
    }
    let cookie = format!(
        "{}={}; HttpOnly; SameSite=Lax; Path=/; Max-Age=86400",
        DEVAIPOD_AUTH_COOKIE, state.token
    );
    Response::builder()
        .status(StatusCode::TEMPORARY_REDIRECT)
        .header(header::LOCATION, "/pods")
        .header(header::SET_COOKIE, cookie)
        .body(Body::empty())
        .unwrap()
}

/// Serve the opencode SPA for top-level pages (e.g. /pods).
/// The SPA handles client-side routing internally.
async fn serve_spa_page() -> Result<Response, StatusCode> {
    serve_opencode_index().await
}

/// Serve /assets/* from the vendored opencode UI directory.
///
/// All `/assets/*` requests come from the opencode SPA, so we always
/// serve from `OPENCODE_UI_PATH`.
async fn serve_root_assets(Path(path): Path<String>) -> Result<Response, StatusCode> {
    let file_path = if path.is_empty() {
        "assets".to_string()
    } else {
        format!("assets/{}", path)
    };
    let uri = format!("/{}", file_path.trim_start_matches('/'));
    let request = Request::builder()
        .uri(&uri)
        .body(Body::empty())
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    Ok(ServeDir::new(OPENCODE_UI_PATH)
        .oneshot(request)
        .await
        .unwrap()
        .into_response())
}

/// Request body for run endpoint
#[derive(Debug, Deserialize)]
struct RunRequest {
    source: Option<String>,
    task: Option<String>,
    name: Option<String>,
    /// Override the container image (skip devcontainer.json build)
    image: Option<String>,
    /// Service-gator scopes (e.g. "github:org/repo", "github:org/*:write")
    #[serde(default)]
    service_gator_scopes: Vec<String>,
    /// Custom service-gator container image
    service_gator_image: Option<String>,
    /// Suppress default write service-gator scopes
    #[serde(default)]
    service_gator_ro: bool,
    /// Additional MCP servers to attach (name=url format)
    #[serde(default)]
    mcp_servers: Vec<String>,
    /// Inline devcontainer JSON that replaces the repo's devcontainer.json
    devcontainer_json: Option<String>,
}

/// Response for run endpoint
#[derive(Debug, Serialize)]
struct RunResponse {
    /// Whether the operation succeeded
    success: bool,
    /// The workspace name (short name without devaipod- prefix)
    workspace: String,
    /// Status message
    message: String,
    /// Launch status for async launches ("launching", "completed", "failed")
    #[serde(skip_serializing_if = "Option::is_none")]
    status: Option<String>,
    /// Full pod name (with devaipod- prefix)
    #[serde(skip_serializing_if = "Option::is_none")]
    pod_name: Option<String>,
}

/// Compute a pod name for a web-initiated launch.
///
/// Uses the same sanitization and unique-suffix logic as `main.rs::make_pod_name`
/// so the name we return to the UI matches what `devaipod run --name` will create.
fn compute_pod_name(req: &RunRequest) -> String {
    if let Some(ref name) = req.name {
        // If the user gave an explicit name, normalize it.
        normalize_pod_name(name)
    } else {
        // Derive from source URL: strip scheme, take last path component as project name.
        let project = req
            .source
            .as_deref()
            .and_then(|s| s.rsplit('/').next())
            .map(|s| s.trim_end_matches(".git"))
            .filter(|s| !s.is_empty())
            .unwrap_or("workspace");
        crate::make_pod_name(project)
    }
}

/// Run a new devaipod workspace (non-blocking)
///
/// Computes the pod name up-front, spawns `devaipod run` in the background,
/// and returns immediately with `{"status":"launching", "pod_name":"..."}`.
/// The frontend polls `/api/devaipod/launches` to detect failures.
async fn run_workspace(
    State(state): State<Arc<AppState>>,
    Json(req): Json<RunRequest>,
) -> Result<Json<RunResponse>, StatusCode> {
    let pod_name = compute_pod_name(&req);
    let short_name = pod_name
        .strip_prefix("devaipod-")
        .unwrap_or(&pod_name)
        .to_string();

    let mut cmd = tokio::process::Command::new("devaipod");
    cmd.arg("run");

    // Add source if provided
    if let Some(ref source) = req.source {
        cmd.arg(source);
    }

    // Add task if provided (as positional argument after source)
    if let Some(ref task) = req.task {
        cmd.arg(task);
    }

    // Always pass --name so the pod name matches what we told the UI.
    cmd.args(["--name", &pod_name]);

    if let Some(ref image) = req.image {
        cmd.args(["--image", image]);
    }

    for scope in &req.service_gator_scopes {
        cmd.args(["--service-gator", scope]);
    }

    if let Some(ref gator_image) = req.service_gator_image {
        cmd.args(["--service-gator-image", gator_image]);
    }

    if req.service_gator_ro {
        cmd.arg("--service-gator-ro");
    }

    for mcp in &req.mcp_servers {
        cmd.args(["--mcp", mcp]);
    }

    if let Some(ref json) = req.devcontainer_json {
        cmd.args(["--devcontainer-json", json]);
    }

    // Prevent stdin reads from blocking the server process
    cmd.stdin(std::process::Stdio::null());

    tracing::info!("Running devaipod (async): {:?}", cmd);

    // Guard against duplicate launches (e.g. double-submit)
    {
        let mut launches = state.launches.lock().await;
        if launches.contains_key(&pod_name) {
            tracing::warn!("Duplicate launch rejected for {}", pod_name);
            return Err(StatusCode::CONFLICT);
        }
        launches.insert(pod_name.clone(), LaunchState::Launching);
    }

    // Spawn the subprocess in the background.
    let launches = state.launches.clone();
    let pod_name_bg = pod_name.clone();
    tokio::spawn(async move {
        let result = cmd.output().await;
        let mut map = launches.lock().await;
        match result {
            Ok(output) if output.status.success() => {
                tracing::info!("devaipod run completed for {}", pod_name_bg);
                // Remove completed entries immediately; the pod is now visible
                // in podman and the UI will pick it up via normal polling.
                map.remove(&pod_name_bg);
            }
            Ok(output) => {
                let stderr = String::from_utf8_lossy(&output.stderr);
                let msg = stderr.trim().to_string();
                tracing::error!("devaipod run failed for {}: {}", pod_name_bg, msg);
                map.insert(
                    pod_name_bg.clone(),
                    LaunchState::Failed {
                        error: if msg.is_empty() {
                            format!("Process exited with {}", output.status)
                        } else {
                            msg
                        },
                    },
                );
            }
            Err(e) => {
                tracing::error!("Failed to execute devaipod run for {}: {}", pod_name_bg, e);
                map.insert(
                    pod_name_bg.clone(),
                    LaunchState::Failed {
                        error: format!("Failed to execute: {}", e),
                    },
                );
            }
        }
    });

    Ok(Json(RunResponse {
        success: true,
        workspace: short_name,
        message: "Launching workspace in background".to_string(),
        status: Some("launching".to_string()),
        pod_name: Some(pod_name),
    }))
}

/// Return current launch states.
///
/// The UI polls this to discover failures (and to show "launching" indicators
/// before the pod appears in podman). Completed entries are removed eagerly
/// in the spawn callback above; failed entries are kept until the UI
/// acknowledges them via DELETE.
async fn list_launches(State(state): State<Arc<AppState>>) -> Json<HashMap<String, LaunchState>> {
    let map = state.launches.lock().await;
    Json(map.clone())
}

/// Dismiss (remove) a launch entry so it stops showing in the UI.
async fn dismiss_launch(
    State(state): State<Arc<AppState>>,
    Path(pod_name): Path<String>,
) -> StatusCode {
    let mut map = state.launches.lock().await;
    map.remove(&pod_name);
    StatusCode::NO_CONTENT
}

/// Request body for advisor launch endpoint
#[derive(Debug, Deserialize)]
struct AdvisorLaunchRequest {
    /// Optional task for the advisor (e.g. "check my GitHub issues")
    task: Option<String>,
}

/// Launch or check the advisor pod
///
/// If the advisor pod already exists and is running, returns its status.
/// If it doesn't exist, creates it with the appropriate image and MCP config.
async fn launch_advisor(
    Json(req): Json<AdvisorLaunchRequest>,
) -> Result<Json<RunResponse>, StatusCode> {
    // Check if advisor pod already exists
    let check = std::process::Command::new("podman")
        .args([
            "pod",
            "inspect",
            "devaipod-advisor",
            "--format",
            "{{.State}}",
        ])
        .output();

    if let Ok(output) = check {
        if output.status.success() {
            let state = String::from_utf8_lossy(&output.stdout)
                .trim()
                .to_lowercase();
            if state == "running" {
                // Advisor already running — if task provided, send it
                if let Some(ref task) = req.task {
                    let mut cmd = tokio::process::Command::new("devaipod");
                    cmd.args(["opencode", "advisor", "send", task]);
                    let _ = cmd.output().await;
                }
                return Ok(Json(RunResponse {
                    success: true,
                    workspace: "advisor".to_string(),
                    message: "Advisor is already running".to_string(),
                    status: None,
                    pod_name: None,
                }));
            } else {
                // Advisor exists but stopped — start it
                let start = tokio::process::Command::new("podman")
                    .args(["pod", "start", "devaipod-advisor"])
                    .output()
                    .await;
                if let Ok(o) = start {
                    if o.status.success() {
                        return Ok(Json(RunResponse {
                            success: true,
                            workspace: "advisor".to_string(),
                            message: "Advisor pod started".to_string(),
                            status: None,
                            pod_name: None,
                        }));
                    }
                }
            }
        }
    }

    // Advisor doesn't exist — create it via `devaipod advisor`.
    // This reuses the CLI command which handles dotfiles fallback,
    // image selection, and MCP setup internally. We pass --no-attach
    // (via an env var) so it doesn't block trying to attach.
    let mut cmd = tokio::process::Command::new("devaipod");
    cmd.arg("advisor");
    // Prevent the advisor command from trying to attach to the pod
    // (which would block the web handler indefinitely). Setting
    // DEVAIPOD_NO_ATTACH=1 is checked by cmd_advisor.
    cmd.env("DEVAIPOD_NO_ATTACH", "1");
    if let Some(ref task) = req.task {
        cmd.arg(task);
    }

    tracing::info!("Launching advisor: {:?}", cmd);

    let output = cmd.output().await.map_err(|e| {
        tracing::error!("Failed to launch advisor: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        tracing::error!("Advisor launch failed: {}", stderr);
        return Ok(Json(RunResponse {
            success: false,
            workspace: String::new(),
            message: format!("Failed to launch advisor: {}", stderr.trim()),
            status: None,
            pod_name: None,
        }));
    }

    Ok(Json(RunResponse {
        success: true,
        workspace: "advisor".to_string(),
        message: "Advisor pod created".to_string(),
        status: None,
        pod_name: None,
    }))
}

/// Advisor status response
#[derive(Debug, Serialize)]
struct AdvisorStatusResponse {
    /// Whether the advisor pod exists
    exists: bool,
    /// Pod state: "running", "stopped", or "not_found"
    state: String,
}

async fn advisor_status() -> Result<Json<AdvisorStatusResponse>, StatusCode> {
    let check = std::process::Command::new("podman")
        .args([
            "pod",
            "inspect",
            "devaipod-advisor",
            "--format",
            "{{.State}}",
        ])
        .output();

    match check {
        Ok(output) if output.status.success() => {
            let state = String::from_utf8_lossy(&output.stdout)
                .trim()
                .to_lowercase();
            Ok(Json(AdvisorStatusResponse {
                exists: true,
                state,
            }))
        }
        _ => Ok(Json(AdvisorStatusResponse {
            exists: false,
            state: "not_found".to_string(),
        })),
    }
}

/// List draft proposals from the advisor
///
/// Reads the draft store JSON file and returns all proposals as a JSON array.
/// Returns an empty array if the file doesn't exist or can't be parsed.
async fn list_proposals_api() -> Json<serde_json::Value> {
    let proposals = tokio::task::spawn_blocking(|| {
        advisor::DraftStore::load(std::path::Path::new(advisor::DRAFTS_PATH))
            .map(|s| s.proposals)
            .unwrap_or_default()
    })
    .await
    .unwrap_or_default();

    Json(serde_json::to_value(&proposals).unwrap_or_default())
}

/// Dismiss a draft proposal by ID
///
/// Updates the proposal's status to Dismissed and persists the change.
async fn dismiss_proposal(Path(id): Path<String>) -> Result<Json<serde_json::Value>, StatusCode> {
    tokio::task::spawn_blocking(move || {
        let path = std::path::Path::new(advisor::DRAFTS_PATH);
        let mut store = advisor::DraftStore::load(path).map_err(|_| StatusCode::NOT_FOUND)?;
        store
            .update_status(&id, advisor::ProposalStatus::Dismissed)
            .ok_or(StatusCode::NOT_FOUND)?;
        store
            .save(path)
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        Ok::<_, StatusCode>(())
    })
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)??;

    Ok(Json(serde_json::json!({"success": true})))
}

/// Recreate a workspace (delete and recreate with same repo)
///
/// Runs `devaipod rebuild <pod_name>`. Requires pod to have
/// io.devaipod.repo label.
async fn recreate_workspace(
    Path(name): Path<String>,
) -> Result<Json<RunResponse>, (StatusCode, Json<ApiErrorBody>)> {
    let pod_name = normalize_pod_name(&name);

    tracing::info!("Recreating workspace: {}", pod_name);

    let output = tokio::process::Command::new("devaipod")
        .arg("rebuild")
        .arg(&pod_name)
        .output()
        .await
        .map_err(|e| {
            tracing::error!("Failed to execute devaipod rebuild: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiErrorBody {
                    error: format!("Failed to run rebuild: {}", e),
                }),
            )
        })?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        tracing::error!("devaipod rebuild failed: {}", stderr);
        let msg = stderr.trim();
        let status =
            if msg.contains("no repository label") || msg.contains("Cannot determine source") {
                StatusCode::BAD_REQUEST
            } else if msg.contains("not found") {
                StatusCode::NOT_FOUND
            } else {
                StatusCode::INTERNAL_SERVER_ERROR
            };
        return Err((
            status,
            Json(ApiErrorBody {
                error: msg.to_string(),
            }),
        ));
    }

    let short_name = pod_name.strip_prefix("devaipod-").unwrap_or(&pod_name);
    Ok(Json(RunResponse {
        success: true,
        workspace: short_name.to_string(),
        message: format!("Workspace '{}' recreated successfully", short_name),
        status: None,
        pod_name: None,
    }))
}

/// Pod enrichment response: extra metadata computed server-side.
///
/// Currently reports whether each pod's API sidecar is running an older
/// image than the control plane, so the UI can show "update available".
#[derive(Debug, Serialize)]
struct PodEnrichment {
    needs_update: bool,
}

/// Return enrichment data for all devaipod pods.
///
/// Compares the image ID of each pod's `-api` sidecar container against
/// the control plane's own image ID. If they differ the pod needs a
/// recreate to pick up the new image.
async fn pod_enrichment(
    State(state): State<Arc<AppState>>,
) -> Json<HashMap<String, PodEnrichment>> {
    let mut result = HashMap::new();

    let self_image_id = match &state.self_image_id {
        Some(id) => id,
        None => return Json(result), // Not in container, can't compare
    };

    let socket_path = match &state.socket_path {
        Some(p) => p.clone(),
        None => match get_container_socket() {
            Ok(p) => p,
            Err(_) => return Json(result),
        },
    };

    let docker = match bollard::Docker::connect_with_unix(
        &format!("unix://{}", socket_path.display()),
        120,
        bollard::API_DEFAULT_VERSION,
    ) {
        Ok(d) => d,
        Err(_) => return Json(result),
    };

    // List all containers whose name starts with "devaipod-" and ends with "-api"
    let mut filters = HashMap::new();
    filters.insert("name", vec!["devaipod-*-api"]);
    let options = bollard::container::ListContainersOptions {
        all: true,
        filters,
        ..Default::default()
    };

    let containers = match docker.list_containers(Some(options)).await {
        Ok(c) => c,
        Err(_) => return Json(result),
    };

    for container in containers {
        let names = match &container.names {
            Some(n) => n,
            None => continue,
        };
        // Container names are prefixed with "/"
        let api_name = match names.iter().find(|n| n.ends_with("-api")) {
            Some(n) => n.trim_start_matches('/').to_string(),
            None => continue,
        };
        // Derive pod name: "devaipod-foo-abc123-api" -> "devaipod-foo-abc123"
        let pod_name = match api_name.strip_suffix("-api") {
            Some(p) => p.to_string(),
            None => continue,
        };

        let needs_update = container
            .image_id
            .as_ref()
            .map(|id| id != self_image_id)
            .unwrap_or(false);

        result.insert(pod_name, PodEnrichment { needs_update });
    }

    Json(result)
}

/// Extract workspace name from devaipod run output
///
/// Looks for the short workspace name (without devaipod- prefix) in the output.
/// Currently unused (run_workspace computes the name upfront) but kept for
/// potential use by other callers.
#[allow(dead_code)]
fn extract_workspace_name(output: &str) -> Option<String> {
    // Look for patterns like "devaipod-foo-abc123" or just the workspace name in output
    for line in output.lines() {
        // Check if line contains a pod name
        if let Some(start) = line.find("devaipod-") {
            // Extract the full pod name
            let rest = &line[start..];
            // Pod names are alphanumeric with hyphens, terminated by whitespace or quote
            let end = rest
                .find(|c: char| !c.is_alphanumeric() && c != '-')
                .unwrap_or(rest.len());
            let pod_name = &rest[..end];
            // Strip the prefix and return
            return Some(
                pod_name
                    .strip_prefix("devaipod-")
                    .unwrap_or(pod_name)
                    .to_string(),
            );
        }
    }
    None
}

/// Response for agent status endpoint.
///
/// This is now a thin wrapper: the actual status derivation lives in pod-api's
/// `/summary` endpoint. The control plane just proxies it.
#[derive(Debug, Serialize, Deserialize)]
struct AgentStatusResponse {
    activity: String,
    status_line: Option<String>,
    current_tool: Option<String>,
    recent_output: Vec<String>,
    last_message_ts: Option<i64>,
    session_count: usize,
}

impl AgentStatusResponse {
    /// Construct a response for a given activity with all other fields empty.
    fn with_activity(activity: &str) -> Self {
        Self {
            activity: activity.to_string(),
            status_line: None,
            current_tool: None,
            recent_output: vec![],
            last_message_ts: None,
            session_count: 0,
        }
    }
}

/// Get agent status for a pod (thin proxy to pod-api `/summary`).
///
/// Delegates to the pod-api sidecar's `/summary` endpoint, which is the
/// source of truth for agent status. See `docs/todo/pod-api-driver.md`.
async fn agent_status(Path(name): Path<String>) -> Json<AgentStatusResponse> {
    let pod_name = normalize_pod_name(&name);

    let port = match get_pod_api_port(&pod_name).await {
        Ok(p) => p,
        Err(_) => return Json(AgentStatusResponse::with_activity("Stopped")),
    };

    let host = host_for_pod_services();

    let client = match reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
    {
        Ok(c) => c,
        Err(_) => return Json(AgentStatusResponse::with_activity("Unknown")),
    };

    // Proxy to pod-api's /summary endpoint.
    match client
        .get(format!("http://{}:{}/summary", host, port))
        .send()
        .await
    {
        Ok(resp) if resp.status().is_success() => match resp.json::<AgentStatusResponse>().await {
            Ok(summary) => Json(summary),
            Err(_) => Json(AgentStatusResponse::with_activity("Unknown")),
        },
        _ => Json(AgentStatusResponse::with_activity("Unknown")),
    }
}

// Git endpoints (git_status, git_diff, git_commits, git_log, git_diff_range,
// git_fetch_agent, git_push) and exec_in_container have been removed.
// The pod-api sidecar now handles all git operations directly, and the frontend
// routes git requests through the pod-api proxy.

/// Run the web server
///
/// Starts an HTTP server on the specified port with:
/// - Token-based authentication on `/api/*` routes
/// - Podman socket proxy at `/api/podman/*`
/// - Pod-api proxy for git and PTY access
/// - Static file serving from `dist/` directory
///
/// # Arguments
///
/// * `port` - TCP port to bind to (on 127.0.0.1 only)
/// * `token` - Authentication token for API access
///
/// # Errors
///
/// Returns an error if the server fails to bind to the port.
/// Podman socket availability is checked lazily when proxying requests.

/// Build the web app router for a given token and socket path.
///
/// Exposed for tests so we can hit the router with in-process requests (fast)
/// without starting a server or container.
pub(crate) fn build_app(
    token: String,
    socket_path: Option<PathBuf>,
    self_image_id: Option<String>,
) -> Router {
    let state = Arc::new(AppState {
        token: token.clone(),
        socket_path,
        launches: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
        self_image_id,
    });

    // Build the API router with authentication
    let api_router = Router::new()
        .route(
            "/podman/{*path}",
            get(podman_proxy)
                .post(podman_proxy)
                .put(podman_proxy)
                .delete(podman_proxy),
        )
        .route("/devaipod/pods/{name}/opencode-info", get(opencode_info))
        .route("/devaipod/pods/{name}/agent-status", get(agent_status))
        .route(
            "/devaipod/pods/{name}/pod-api/{*path}",
            get(pod_api_proxy)
                .post(pod_api_proxy)
                .put(pod_api_proxy)
                .delete(pod_api_proxy),
        )
        .route("/devaipod/run", post(run_workspace))
        .route("/devaipod/launches", get(list_launches))
        .route(
            "/devaipod/launches/{pod_name}",
            axum::routing::delete(dismiss_launch),
        )
        .route("/devaipod/advisor/launch", post(launch_advisor))
        .route("/devaipod/advisor/status", get(advisor_status))
        .route("/devaipod/proposals", get(list_proposals_api))
        .route("/devaipod/proposals/{id}/dismiss", post(dismiss_proposal))
        .route("/devaipod/pods/{name}/recreate", post(recreate_workspace))
        .route("/devaipod/pods/enrichment", get(pod_enrichment))
        // PTY: proxy to the pod-api sidecar (direct PTY, no exec overhead)
        .route(
            "/devaipod/pods/{name}/pty",
            get(pty_pod_api_proxy_root).post(pty_pod_api_proxy_root),
        )
        .route(
            "/devaipod/pods/{name}/pty/{*rest}",
            get(pty_pod_api_proxy)
                .put(pty_pod_api_proxy)
                .delete(pty_pod_api_proxy),
        )
        .layer(middleware::from_fn_with_state(
            state.clone(),
            auth_middleware,
        ))
        .with_state(state.clone());

    // CORS: allow webviews and cross-origin requests (e.g. IDE embedding control plane at 127.0.0.1:8080)
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    Router::new()
        .route("/_devaipod/health", get(|| async { "ok" }))
        .route("/_devaipod/login", get(login))
        .route("/_devaipod/frontend-error", post(frontend_error_report))
        // MCP endpoint for advisor tools — outside auth since the advisor
        // pod connects without a bearer token. Only exposes pod metadata
        // and a local draft-proposals JSON file.
        // TODO: add lightweight auth (e.g. shared secret) for production use
        .route("/api/devaipod/mcp", post(crate::mcp::handle_mcp))
        .nest("/api", api_router)
        .route("/", get(redirect_to_pods))
        .route("/pods", get(serve_spa_page))
        .route("/_devaipod/agent/{name}", get(agent_wrapper))
        .route("/_devaipod/agent/{name}/", get(agent_ui_root))
        // Serve mdbook documentation at /docs/
        .route("/docs", get(redirect_to_docs))
        .route("/docs/", get(serve_docs_index))
        .route("/docs/{*path}", get(serve_docs_file))
        // /assets/*: serve from vendored opencode UI
        .route("/assets", get(serve_root_assets))
        .route("/assets/{*path}", get(serve_root_assets))
        // Catch-all fallback: serve static files or the SPA index.html for client-side routing.
        .fallback(static_or_spa_fallback)
        .layer(middleware::from_fn(request_trace))
        .layer(cors)
        .with_state(state)
}

pub async fn run_web_server(port: u16, token: String) -> Result<()> {
    // Try to get the podman socket path, but don't fail if not found
    // (allows server to start for static file serving even without podman)
    let socket_path = get_container_socket().ok();

    if socket_path.is_none() {
        tracing::warn!(
            "No podman socket found. Podman API proxy will return 503 until socket is available."
        );
    }

    // Detect our own image ID so we can tell the UI which pods need updates
    let self_image_id = crate::pod::detect_self_image_id().await;
    if let Some(ref id) = self_image_id {
        tracing::info!("Control plane image ID: {}", id);
    }

    let app = build_app(token.clone(), socket_path, self_image_id);

    // Bind to [::] which accepts both IPv4 and IPv6 connections via dual-stack
    // (the Linux default).  Browsers typically try IPv6 first when resolving
    // "localhost", so binding IPv4-only would cause connection resets.
    let addr = format!("[::]:{}", port);
    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .with_context(|| format!("Failed to bind to {}", addr))?;

    // Print startup message with URL including token
    let url = format!("http://127.0.0.1:{}/_devaipod/login?token={}", port, token);
    tracing::info!("Web server started at {}", url);
    println!("Control plane URL: {}", url);

    // Run the server with graceful shutdown on SIGTERM/SIGINT.
    // This is critical because devaipod runs as PID 1 in the container,
    // and the kernel silently drops signals with SIG_DFL disposition for
    // PID 1 (the SIGNAL_UNKILLABLE protection).  Without an explicit
    // handler, `podman stop` would wait the full timeout before SIGKILL.
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .context("Web server error")?;

    tracing::info!("Web server shut down gracefully");
    Ok(())
}

/// Wait for a SIGTERM or SIGINT signal (whichever arrives first).
pub async fn shutdown_signal() {
    let sigterm = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install SIGTERM handler")
            .recv()
            .await;
    };
    let sigint = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install SIGINT handler");
    };
    tokio::select! {
        _ = sigterm => tracing::info!("Received SIGTERM, shutting down"),
        _ = sigint => tracing::info!("Received SIGINT, shutting down"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::to_bytes;
    use axum::http::Request;
    use tower::util::ServiceExt;

    /// Fast in-process test: GET /_devaipod/agent/{name} must return 307 redirect
    /// to /_devaipod/agent/{name}/ and preserve query parameters.
    #[tokio::test]
    async fn test_agent_redirect() {
        let app = build_app("test-token".into(), None, None);

        // Without query params
        let req = Request::builder()
            .uri("/_devaipod/agent/test-pod")
            .body(Body::empty())
            .expect("request");
        let res = app.oneshot(req).await.expect("oneshot");
        let status = res.status();
        let headers = res.headers().clone();
        let _body = to_bytes(res.into_body(), usize::MAX).await.expect("body");

        assert_eq!(
            status.as_u16(),
            307,
            "GET /_devaipod/agent/test-pod must return 307 redirect; got {}",
            status
        );
        let location = headers
            .get(header::LOCATION)
            .and_then(|v| v.to_str().ok())
            .expect("Location header must be set");
        assert_eq!(
            location, "/_devaipod/agent/test-pod/",
            "Location must redirect to trailing-slash path"
        );
        assert!(
            headers.get(header::SET_COOKIE).is_none(),
            "Redirect must not set cookies (cookie routing no longer used)"
        );

        // With query params
        let app2 = build_app("test-token".into(), None, None);
        let req = Request::builder()
            .uri("/_devaipod/agent/test-pod?dir=abc&session=s1")
            .body(Body::empty())
            .expect("request");
        let res = app2.oneshot(req).await.expect("oneshot");
        let location = res
            .headers()
            .get(header::LOCATION)
            .and_then(|v| v.to_str().ok())
            .expect("Location header must be set");
        assert_eq!(
            location, "/_devaipod/agent/test-pod/?dir=abc&session=s1",
            "Redirect must preserve query parameters"
        );
    }

    /// Test the iframe wrapper HTML generation.
    #[test]
    fn test_agent_iframe_wrapper() {
        let html = agent_iframe_wrapper("test-pod", "http://localhost:12345/");
        assert!(html.contains("test-pod"), "wrapper must include pod name");
        assert!(
            html.contains("http://localhost:12345/"),
            "wrapper must contain iframe src pointing at pod-api base_url"
        );
        assert!(html.contains("Pods"), "wrapper must have back-to-pods link");
        assert!(html.contains("/pods"), "back link must point to /pods");

        // With session deep-link
        let html = agent_iframe_wrapper("test-pod", "http://localhost:12345/abc123/session/s1");
        assert!(
            html.contains("http://localhost:12345/abc123/session/s1"),
            "wrapper must include session deep-link in iframe src"
        );

        // HTML-escaping
        let html = agent_iframe_wrapper("<script>alert(1)</script>", "http://localhost:1/");
        assert!(
            !html.contains("<script>alert"),
            "pod name must be HTML-escaped"
        );
        assert!(
            html.contains("&lt;script&gt;"),
            "angle brackets must be escaped"
        );
    }

    #[test]
    fn test_generate_token() {
        let token1 = generate_token();
        let token2 = generate_token();

        // Tokens should be different
        assert_ne!(token1, token2);

        // Tokens should be 43 characters (32 bytes base64url encoded without padding)
        assert_eq!(token1.len(), 43);
        assert_eq!(token2.len(), 43);

        // Tokens should be valid base64url
        assert!(BASE64_URL_SAFE_NO_PAD.decode(&token1).is_ok());
        assert!(BASE64_URL_SAFE_NO_PAD.decode(&token2).is_ok());
    }

    #[test]
    fn test_load_or_generate_token_generates_when_no_file() {
        // When the secrets file doesn't exist, a token should be generated
        let token = load_or_generate_token();
        assert_eq!(token.len(), 43);
    }

    /// Verify proxy_to_upstream upgrades HTTP/1.0 responses to HTTP/1.1.
    ///
    /// Browsers require HTTP/1.1 for SSE (chunked transfer encoding). This test
    /// starts a mock HTTP/1.0 server, proxies through proxy_to_upstream, and
    /// asserts the response version is upgraded.
    #[tokio::test]
    async fn test_proxy_upgrades_http10_to_http11() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let port = listener.local_addr().unwrap().port();

        // Mock server: accept one connection, read the request, reply with HTTP/1.0
        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.expect("accept");
            let mut buf = vec![0u8; 4096];
            let n = sock.read(&mut buf).await.expect("read");
            assert!(n > 0, "should receive request bytes");

            let response = b"HTTP/1.0 200 OK\r\n\
                content-type: text/event-stream\r\n\
                cache-control: no-cache\r\n\
                connection: keep-alive\r\n\
                \r\n\
                : mock-keepalive\n\n";
            sock.write_all(response).await.expect("write");
            drop(sock);
        });

        let request = Request::builder()
            .uri("/global/event")
            .body(Body::empty())
            .expect("request");

        let response = proxy_to_upstream("127.0.0.1", port, "global/event".into(), request)
            .await
            .expect("proxy_to_upstream should succeed");

        assert_eq!(
            response.version(),
            hyper::Version::HTTP_11,
            "proxy must upgrade HTTP/1.0 response to HTTP/1.1"
        );
        assert_eq!(response.status(), StatusCode::OK);

        let ct = response
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        assert!(
            ct.contains("text/event-stream"),
            "Content-Type must be preserved; got: {ct}"
        );
    }

    /// Verify proxy_to_upstream also upgrades non-SSE HTTP/1.0 responses.
    #[tokio::test]
    async fn test_proxy_upgrades_http10_json_response() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let port = listener.local_addr().unwrap().port();

        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.expect("accept");
            let mut buf = vec![0u8; 4096];
            let _ = sock.read(&mut buf).await.expect("read");
            let body = r#"{"ok":true}"#;
            let response = format!(
                "HTTP/1.0 200 OK\r\n\
                 content-type: application/json\r\n\
                 content-length: {}\r\n\
                 \r\n\
                 {}",
                body.len(),
                body
            );
            sock.write_all(response.as_bytes()).await.expect("write");
            drop(sock);
        });

        let request = Request::builder()
            .uri("/session")
            .body(Body::empty())
            .expect("request");

        let response = proxy_to_upstream("127.0.0.1", port, "session".into(), request)
            .await
            .expect("proxy should succeed");

        assert_eq!(
            response.version(),
            hyper::Version::HTTP_11,
            "JSON response must also be upgraded to HTTP/1.1"
        );
        assert_eq!(response.status(), StatusCode::OK);

        let body = to_bytes(response.into_body(), 1024)
            .await
            .expect("read body");
        assert!(
            String::from_utf8_lossy(&body).contains("ok"),
            "body must be forwarded"
        );
    }

    /// Verify proxy_to_upstream preserves query string (required for /file?path=..., /find/file?path=..., etc.).
    #[tokio::test]
    async fn test_proxy_preserves_query_string() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::sync::oneshot;

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let port = listener.local_addr().unwrap().port();
        let (tx, rx) = oneshot::channel::<String>();

        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.expect("accept");
            let mut buf = vec![0u8; 4096];
            let n = sock.read(&mut buf).await.expect("read");
            let request = String::from_utf8_lossy(&buf[..n]);
            let first_line = request.lines().next().unwrap_or("").to_string();
            let _ = tx.send(first_line);
            let response = "HTTP/1.1 200 OK\r\ncontent-length: 0\r\n\r\n";
            sock.write_all(response.as_bytes()).await.expect("write");
            drop(sock);
        });

        let request = Request::builder()
            .uri("/file?path=src/main.rs")
            .body(Body::empty())
            .expect("request");

        let _ = proxy_to_upstream("127.0.0.1", port, "file".into(), request)
            .await
            .expect("proxy should succeed");

        let request_line = rx.await.expect("mock should send request line");
        assert!(
            request_line.contains("path="),
            "proxy must forward query string; request line: {}",
            request_line
        );
        assert!(
            request_line.contains("src"),
            "proxy must preserve path param value; request line: {}",
            request_line
        );
    }
}
