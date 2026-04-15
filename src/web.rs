//! Web server for devaipod control plane
//!
//! This module provides:
//! - Token-based authentication for API access
//! - Podman socket proxy at `/api/podman/*`
//! - Agent view at `/_devaipod/agent/{name}/` (iframe wrapper pointing at pod-api sidecar)
//! - Workspace recreate at `POST /api/devaipod/pods/{name}/recreate`
//! - Opencode-info and agent-status endpoints for the pods page
//! - Static file serving for web UI

use std::collections::{BTreeMap, HashMap};
use std::path::PathBuf;
use std::sync::Arc;

use axum::{
    Json, Router,
    body::Body,
    extract::{Path, Query, Request, State},
    http::{HeaderMap, StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use base64::prelude::*;
use color_eyre::eyre::{Context, Result};
use futures_util::StreamExt;
use hyper_util::rt::TokioIo;
use serde::{Deserialize, Serialize};
use tokio::net::UnixStream;
use tower::ServiceExt;
use tower_http::compression::CompressionLayer;
use tower_http::cors::{Any, CorsLayer};
use tower_http::services::ServeDir;

use crate::advisor;
use crate::config::SourceAccess;
use crate::podman::{get_container_socket, host_for_pod_services};

/// Path to the token file when using podman/Kubernetes secrets (highest priority).
const TOKEN_SECRET_PATH: &str = "/run/secrets/devaipod-web-token";

/// Default directory for persistent state when using the devaipod-state volume.
/// Override with DEVAIPOD_STATE_DIR. Token is stored at {state_dir}/web-token.
const DEFAULT_STATE_DIR: &str = "/var/lib/devaipod";

/// Filename for the web auth token inside the state directory.
const STATE_TOKEN_FILENAME: &str = "web-token";

/// Path to the MCP token file when using podman/Kubernetes secrets.
const MCP_TOKEN_SECRET_PATH: &str = "/run/secrets/devaipod-mcp-token";

/// Filename for the MCP auth token inside the state directory.
const MCP_STATE_TOKEN_FILENAME: &str = "mcp-token";

/// Filename for the pod state cache inside the state directory.
const POD_STATE_CACHE_FILENAME: &str = "pod-state-cache.json";

fn state_dir_path() -> std::path::PathBuf {
    let dir = std::env::var("DEVAIPOD_STATE_DIR").unwrap_or_else(|_| DEFAULT_STATE_DIR.to_string());
    std::path::PathBuf::from(dir)
}

fn state_token_path() -> std::path::PathBuf {
    state_dir_path().join(STATE_TOKEN_FILENAME)
}

/// Get the path to the current devaipod binary for spawning subcommands.
///
/// Uses `current_exe()` so subcommand spawning works both in-container
/// (where `devaipod` is on PATH) and in host/test mode (where it may be
/// at an arbitrary path like `target/debug/devaipod`).
fn self_exe() -> String {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.to_str().map(|s| s.to_string()))
        .unwrap_or_else(|| "devaipod-server".to_string())
}

fn mcp_state_token_path() -> std::path::PathBuf {
    state_dir_path().join(MCP_STATE_TOKEN_FILENAME)
}

fn pod_state_cache_path() -> std::path::PathBuf {
    state_dir_path().join(POD_STATE_CACHE_FILENAME)
}

/// Cached pod state persisted to disk so that metadata survives pod stops.
///
/// Populated from running pods' agent status responses and used as fallback
/// when pods are stopped and the pod-api sidecar is unreachable.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
struct CachedPodState {
    /// Last time the agent was active (from last_message_ts, unix ms).
    #[serde(skip_serializing_if = "Option::is_none")]
    last_active_ts: Option<i64>,
    /// Completion status: "active" or "done".
    #[serde(skip_serializing_if = "Option::is_none")]
    completion_status: Option<String>,
    /// Human-readable session title.
    #[serde(skip_serializing_if = "Option::is_none")]
    title: Option<String>,
    /// Last known agent activity: "Working", "Idle", "Stopped".
    #[serde(skip_serializing_if = "Option::is_none")]
    activity: Option<String>,
}

type PodStateCache = Arc<tokio::sync::RwLock<HashMap<String, CachedPodState>>>;

/// Load the pod state cache from disk. Returns an empty map if the file
/// doesn't exist or is corrupt.
fn load_pod_state_cache() -> HashMap<String, CachedPodState> {
    let path = pod_state_cache_path();
    match std::fs::read_to_string(&path) {
        Ok(data) => match serde_json::from_str(&data) {
            Ok(map) => {
                tracing::debug!("Loaded pod state cache from {}", path.display());
                map
            }
            Err(e) => {
                tracing::debug!(
                    "Failed to parse pod state cache at {}: {e}; starting fresh",
                    path.display()
                );
                HashMap::new()
            }
        },
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => HashMap::new(),
        Err(e) => {
            tracing::debug!(
                "Failed to read pod state cache at {}: {e}; starting fresh",
                path.display()
            );
            HashMap::new()
        }
    }
}

/// Persist the pod state cache to disk asynchronously.
///
/// Uses write-to-temp + rename for atomicity.
async fn save_pod_state_cache(cache: &PodStateCache) {
    let path = pod_state_cache_path();
    let data = {
        let map = cache.read().await;
        match serde_json::to_string_pretty(&*map) {
            Ok(d) => d,
            Err(e) => {
                tracing::warn!("Failed to serialize pod state cache: {e}");
                return;
            }
        }
    };
    let Some(parent) = path.parent() else {
        return;
    };
    if !parent.exists() {
        tracing::debug!(
            "Pod state cache directory {} does not exist; skipping save",
            parent.display()
        );
        return;
    }
    let tmp = path.with_extension("json.tmp");
    if let Err(e) = tokio::fs::write(&tmp, &data).await {
        tracing::warn!("Failed to write pod state cache to {}: {e}", tmp.display());
        return;
    }
    if let Err(e) = tokio::fs::rename(&tmp, &path).await {
        tracing::warn!(
            "Failed to rename pod state cache {} -> {}: {e}",
            tmp.display(),
            path.display()
        );
    }
}

/// Base name for the auth cookie. The actual cookie name includes the port
/// to avoid collisions when running multiple instances on the same host
/// (e.g. `DEVAIPOD_AUTH_8080`).  HTTP cookies have no port attribute, so
/// embedding the port in the name is the standard workaround.
const DEVAIPOD_AUTH_COOKIE_BASE: &str = "DEVAIPOD_AUTH";

/// Cookie Max-Age: 1 week (604800 seconds).
const COOKIE_MAX_AGE_SECS: u32 = 604_800;

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

/// Strip the `devaipod-` prefix from a pod name to get the short workspace name.
fn strip_pod_prefix(name: &str) -> &str {
    name.strip_prefix("devaipod-").unwrap_or(name)
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

/// Load MCP token from secrets file, state volume, or generate a new one
///
/// Same priority as `load_or_generate_token` but uses MCP-specific paths.
/// The MCP token is separate from the web API token and is only given to
/// the advisor pod for authenticating MCP requests.
pub fn load_or_generate_mcp_token() -> String {
    // 1. Podman/Kubernetes secret (highest priority)
    if let Ok(token) = std::fs::read_to_string(MCP_TOKEN_SECRET_PATH) {
        let trimmed = token.trim();
        if !trimmed.is_empty() {
            tracing::debug!("Loaded MCP token from {}", MCP_TOKEN_SECRET_PATH);
            return trimmed.to_string();
        }
    }

    // 2. State volume path
    let state_path = mcp_state_token_path();
    if let Ok(token) = std::fs::read_to_string(&state_path) {
        let trimmed = token.trim();
        if !trimmed.is_empty() {
            tracing::debug!("Loaded MCP token from {}", state_path.display());
            return trimmed.to_string();
        }
    }

    // 3. Generate and persist to state dir if it exists
    let token = generate_token();
    if let Some(parent) = state_path.parent() {
        if parent.exists() {
            if let Err(e) = std::fs::write(&state_path, &token) {
                tracing::warn!(
                    "Could not persist MCP token to {}: {}",
                    state_path.display(),
                    e
                );
            } else {
                tracing::debug!("Generated and saved MCP token to {}", state_path.display());
            }
        }
    } else {
        tracing::debug!("Generated new MCP authentication token");
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

/// Cached pod list without agent status (which is fetched on-demand).
///
/// The event watcher maintains this cache so that `list_pods_unified` does not
/// need to hit the podman socket on every poll request.
type PodCache = Arc<tokio::sync::RwLock<Vec<CachedPodInfo>>>;

/// Pod metadata cached by the event watcher.
///
/// Contains everything from `UnifiedPodInfo` except `agent_status`, which is
/// fetched on-demand from each pod's pod-api sidecar.
#[derive(Debug, Clone, Serialize)]
struct CachedPodInfo {
    name: String,
    status: String,
    created: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    labels: Option<HashMap<String, String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    containers: Option<Vec<UnifiedContainerInfo>>,
    needs_update: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    diagnostics: Option<PodDiagnostics>,
}

/// Shared state for the web server
#[derive(Clone)]
pub(crate) struct AppState {
    /// Authentication token for API access
    token: String,
    /// Authentication token for MCP endpoint (separate from web API token)
    mcp_token: String,
    /// Path to the podman/docker socket (None if not available at startup)
    socket_path: Option<PathBuf>,
    /// Background launch states so the UI can track in-flight launches.
    launches: LaunchMap,
    /// Image ID (digest) of the running control plane container.
    /// Used to detect pods whose API sidecar is running an older image.
    self_image_id: Option<String>,
    /// Cached pod list maintained by the background event watcher.
    pod_cache: PodCache,
    /// Port-scoped auth cookie name (e.g. `DEVAIPOD_AUTH_8080`).
    auth_cookie_name: String,
    /// Cached pod state (activity, completion, title, last_active_ts) persisted
    /// to disk so that metadata survives pod stops.
    pod_state_cache: PodStateCache,
}

impl AppState {
    /// Format a Set-Cookie header value for the auth cookie.
    fn auth_cookie_header(&self) -> String {
        format!(
            "{}={}; HttpOnly; SameSite=Lax; Path=/; Max-Age={}",
            self.auth_cookie_name, self.token, COOKIE_MAX_AGE_SECS
        )
    }
}

/// Query parameters for token authentication
#[derive(Debug, Deserialize)]
struct TokenQuery {
    token: Option<String>,
}

/// Authentication middleware
///
/// Validates requests by checking (in order):
/// 1. Port-scoped `DEVAIPOD_AUTH_<port>` cookie (set by the login endpoint)
/// 2. `Authorization: Bearer ...` header
/// 3. `?token=...` query parameter
///
/// When cookie-based auth succeeds, the cookie is re-issued with a fresh
/// `Max-Age` so the expiry slides forward on every request. This keeps the
/// session alive as long as the browser is actively using the UI.
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
    if let Some(token) = cookie_value(&headers, &state.auth_cookie_name)
        && token == state.token
    {
        let mut response = next.run(request).await;
        // Refresh the cookie expiry on every authenticated request.
        // Use `append` (not `insert`) to preserve any Set-Cookie headers
        // from proxied upstream responses.
        response.headers_mut().append(
            header::SET_COOKIE,
            state.auth_cookie_header().parse().unwrap(),
        );
        return Ok(response);
    }

    // Check Authorization header
    if let Some(auth_header) = headers.get(header::AUTHORIZATION)
        && let Ok(auth_str) = auth_header.to_str()
        && let Some(token) = auth_str.strip_prefix("Bearer ")
        && token == state.token
    {
        return Ok(next.run(request).await);
    }

    // Check query parameter (legacy / one-off use)
    if let Some(ref token) = query.token
        && token == &state.token
    {
        return Ok(next.run(request).await);
    }

    Err(StatusCode::UNAUTHORIZED)
}

/// Authentication middleware for the MCP endpoint
///
/// Validates requests by checking the `Authorization: Bearer <mcp_token>` header.
/// Only Bearer authentication is supported (no cookies, no query params).
/// Returns 401 Unauthorized if missing or invalid.
async fn mcp_auth_middleware(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    if let Some(auth_header) = headers.get(header::AUTHORIZATION)
        && let Ok(auth_str) = auth_header.to_str()
        && let Some(token) = auth_str.strip_prefix("Bearer ")
        && token == state.mcp_token
    {
        return Ok(next.run(request).await);
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

/// Agent wrapper JS, embedded at compile time.
const AGENT_WRAPPER_JS: &str = include_str!("static/agent-wrapper.js");

/// Path to mdbook documentation output
const DOCS_PATH: &str = "/usr/share/devaipod/docs";

/// Get opencode connection info for a pod
///
/// Returns the direct URL to access the opencode web UI.
/// On 404 returns JSON body so the frontend can show "Pod or agent not found".
async fn opencode_info(
    headers: HeaderMap,
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

    // Build URL for the opencode web UI (via pod-api sidecar).
    // Use the request's Host header so the URL works for remote access too
    // (e.g. when the control plane is accessed via http://xenon:8080/).
    // Respect X-Forwarded-Proto so HTTPS reverse proxies produce https:// URLs.
    let host = extract_request_host(&headers);
    let scheme = extract_request_scheme(&headers);
    let url = format!("{}://{}:{}/", scheme, host, port);

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

    // Find the root session (not a subagent) with the most recent updated time.
    // Subagent sessions have a non-null parentID and should never be navigated
    // to directly — the chat UI is intended for the parent session.
    sessions
        .iter()
        .filter(|s| crate::session_is_root(s))
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

/// Extract the hostname from the incoming request for use in browser-facing URLs.
///
/// Checks `X-Forwarded-Host` first (for reverse proxy setups), then falls back
/// to the standard `Host` header.  The port portion is stripped since callers
/// combine the hostname with a specific pod-api port.  Returns `"localhost"` if
/// no header is present (e.g. HTTP/1.0 without Host).
fn extract_request_host(headers: &HeaderMap) -> &str {
    headers
        .get("x-forwarded-host")
        .or_else(|| headers.get(header::HOST))
        .and_then(|v| v.to_str().ok())
        .map(|h| {
            // Strip the port suffix (e.g. "xenon:8080" -> "xenon").
            // Be careful with IPv6 literals like "[::1]:8080".
            if h.starts_with('[') {
                // IPv6 literal: find the closing ']' then strip :port after it
                h.find(']').map(|i| &h[..=i]).unwrap_or(h)
            } else {
                h.split(':').next().unwrap_or(h)
            }
        })
        .unwrap_or("localhost")
}

/// Extract the URL scheme from the incoming request for browser-facing URLs.
///
/// Checks `X-Forwarded-Proto` (set by reverse proxies that terminate TLS),
/// falling back to `"http"`.  The pod-api sidecars always speak plain HTTP,
/// but when a reverse proxy forwards the published ports over HTTPS the
/// browser needs `https://` URLs to avoid mixed-content issues.
fn extract_request_scheme(headers: &HeaderMap) -> &str {
    headers
        .get("x-forwarded-proto")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("http")
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

/// Inspect a pod's agent container once and extract both the pod-api host port
/// and all forwarded ports, avoiding redundant Docker connections and
/// `inspect_container` calls.
///
/// Returns `(Option<pod_api_host_port>, Vec<ForwardedPort>)`.
async fn inspect_pod_ports(
    docker: &bollard::Docker,
    pod_name: &str,
) -> (Option<u16>, Vec<ForwardedPort>) {
    let info = match docker
        .inspect_container(&format!("{pod_name}-agent"), None)
        .await
    {
        Ok(i) => i,
        Err(e) => {
            tracing::debug!("Failed to inspect agent container for {pod_name}: {e}");
            return (None, vec![]);
        }
    };

    let ports = match info
        .network_settings
        .as_ref()
        .and_then(|ns| ns.ports.as_ref())
    {
        Some(p) => p,
        None => return (None, vec![]),
    };

    let api_port = crate::pod::POD_API_PORT;
    let port_key = format!("{api_port}/tcp");

    // Extract the pod-api host port
    let pod_api_host_port = ports
        .get(&port_key)
        .and_then(|b| b.as_ref())
        .and_then(|bindings| bindings.first())
        .and_then(|b| b.host_port.as_ref())
        .and_then(|p| p.parse::<u16>().ok());

    // Extract all forwarded ports (excluding pod-api infrastructure port)
    let mut forwarded = Vec::new();
    for (container_port_key, bindings) in ports {
        let container_port: u16 = match container_port_key
            .split('/')
            .next()
            .and_then(|p| p.parse().ok())
        {
            Some(p) => p,
            None => continue,
        };

        if container_port == api_port {
            continue;
        }

        if let Some(bindings) = bindings {
            for binding in bindings {
                if let Some(host_port) = binding
                    .host_port
                    .as_ref()
                    .and_then(|p| p.parse::<u16>().ok())
                {
                    forwarded.push(ForwardedPort {
                        container_port,
                        host_port,
                    });
                }
            }
        }
    }

    (pod_api_host_port, forwarded)
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
///
/// Pod-specific data is passed to the JS via a `<script id="pod-data" type="application/json">`
/// element, and the logic lives in `src/static/agent-wrapper.js` (served at
/// `/_devaipod/static/agent-wrapper.js`).
fn agent_iframe_wrapper(name: &str, base_url: &str) -> String {
    let escaped_name = name
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;");
    let escaped_url = base_url.replace('&', "&amp;").replace('"', "&quot;");
    // URL-encode the name for API calls (the raw name, not the HTML-escaped one)
    let url_name = urlencoding::encode(name);
    // Pod-specific data as JSON for the external JS to read.
    // Escape `</` to `<\/` to prevent a `</script>` sequence inside the
    // JSON from prematurely closing the script tag.
    let pod_data_json = serde_json::json!({
        "urlName": &*url_name,
        "fullName": normalize_pod_name(name)
    })
    .to_string()
    .replace("</", r"<\/");
    format!(
        r#"<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>devaipod - {escaped_name}</title>
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
html,body{{height:100%;overflow:hidden;background:#1c1717}}
#dbar{{height:44px;display:flex;align-items:center;padding:0 12px;gap:8px;
  background:#1c1717;border-bottom:1px solid rgba(255,255,255,0.12)}}
#dbar a,#dbar button{{color:#e8e2e2;text-decoration:none;font-size:14px;font-weight:500;
  font-family:Inter,system-ui,sans-serif;
  padding:6px 14px;border-radius:6px;cursor:pointer;
  background:rgba(255,255,255,0.08);border:1px solid rgba(255,255,255,0.15);
  transition:background 0.15s,border-color 0.15s}}
#dbar a:hover,#dbar button:hover{{background:rgba(255,255,255,0.14);border-color:rgba(255,255,255,0.25)}}
#dbar button.done{{background:rgba(34,197,94,0.15);border-color:rgba(34,197,94,0.4);color:#86efac}}
#dbar button.done:hover{{background:rgba(34,197,94,0.25);border-color:rgba(34,197,94,0.6)}}
#dbar .spacer{{flex:1}}
iframe{{width:100%;height:calc(100% - 44px);border:none}}

/* Pod switcher */
.pod-switcher{{display:flex;align-items:center;gap:2px;position:relative}}
.pod-switcher .nav-arrow{{padding:6px 8px;font-size:16px;min-width:30px;text-align:center;
  font-family:Inter,system-ui,sans-serif}}
.pod-switcher .nav-arrow:disabled{{opacity:0.3;cursor:default;pointer-events:none}}
.pod-trigger{{position:relative;min-width:140px;text-align:left;padding-right:28px !important}}
.pod-trigger::after{{content:"\25BE";position:absolute;right:10px;top:50%;transform:translateY(-50%);
  font-size:11px;opacity:0.6}}
.pod-dropdown{{display:none;position:absolute;top:100%;right:0;margin-top:4px;
  min-width:280px;max-height:360px;overflow-y:auto;
  background:#2a2323;border:1px solid rgba(255,255,255,0.15);border-radius:8px;
  box-shadow:0 8px 24px rgba(0,0,0,0.5);z-index:100;padding:4px}}
.pod-dropdown.open{{display:block}}
.pod-item{{display:flex;align-items:center;gap:8px;padding:8px 12px;border-radius:6px;
  cursor:pointer;font-size:13px;font-family:Inter,system-ui,sans-serif;
  color:#e8e2e2;border:none;background:none;width:100%;text-align:left;
  transition:background 0.12s}}
.pod-item:hover{{background:rgba(255,255,255,0.08)}}
.pod-item.current{{background:rgba(255,255,255,0.06);font-weight:600}}
.pod-item .dot{{width:8px;height:8px;border-radius:50%;flex-shrink:0}}
.pod-item .dot.running{{background:#22c55e}}
.pod-item .dot.working{{background:#22c55e;animation:pulse-dot 1.5s ease-in-out infinite}}
.pod-item .dot.idle{{background:#3b82f6}}
.pod-item .dot.stopped{{background:#888}}
.pod-item .dot.done{{background:#a78bfa}}
.pod-item .pod-name{{flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}}
.pod-item .pod-status{{font-size:11px;opacity:0.55;white-space:nowrap}}
@keyframes pulse-dot{{0%,100%{{opacity:1}}50%{{opacity:0.4}}}}
</style></head><body>
<div id="dbar">
  <a href="/pods">&#8592; Pods</a>
  <button id="done-btn" title="Mark this pod as done">Loading...</button>
  <span class="spacer"></span>
  <div class="pod-switcher" id="pod-switcher">
    <button class="nav-arrow" id="prev-pod" title="Previous pod" disabled>&#8592;</button>
    <button class="pod-trigger" id="pod-trigger" title="Switch pod">{escaped_name}</button>
    <button class="nav-arrow" id="next-pod" title="Next pod" disabled>&#8594;</button>
    <div class="pod-dropdown" id="pod-dropdown"></div>
  </div>
</div>
<iframe id="oc" src="{escaped_url}" allow="clipboard-read; clipboard-write"></iframe>
<script id="pod-data" type="application/json">{pod_data_json}</script>
<script src="/_devaipod/static/agent-wrapper.js"></script>
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
    Response::builder()
        .status(StatusCode::TEMPORARY_REDIRECT)
        .header(header::LOCATION, location)
        .body(Body::empty())
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
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
    headers: HeaderMap,
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

    // The iframe URL is rendered in the user's browser, so we use the hostname
    // from the incoming request.  This way remote access (e.g. http://xenon:8080/)
    // produces an iframe pointing at http://xenon:{port}/ instead of localhost.
    // Published ports are bound to 0.0.0.0 on the host so they are reachable
    // from any interface.
    // Respect X-Forwarded-Proto so HTTPS reverse proxies produce https:// URLs.
    let host = extract_request_host(&headers);
    let scheme = extract_request_scheme(&headers);

    // Build the base URL, optionally including the session deep-link path.
    let base_url = match (query.dir.as_deref(), query.session.as_deref()) {
        (Some(dir), Some(session)) => {
            format!("{scheme}://{host}:{port}/{dir}/session/{session}")
        }
        _ => format!("{scheme}://{host}:{port}/"),
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

/// Serve the agent wrapper JS (embedded at compile time).
async fn serve_agent_wrapper_js() -> Response {
    Response::builder()
        .status(StatusCode::OK)
        .header(
            header::CONTENT_TYPE,
            "application/javascript; charset=utf-8",
        )
        .header(header::CACHE_CONTROL, "public, max-age=3600")
        .body(Body::from(AGENT_WRAPPER_JS))
        .unwrap()
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
    Response::builder()
        .status(StatusCode::TEMPORARY_REDIRECT)
        .header(header::LOCATION, "/pods")
        .header(header::SET_COOKIE, state.auth_cookie_header())
        .body(Body::empty())
        .unwrap()
}

/// No-op handler for token refresh.
///
/// The actual cookie renewal happens in `auth_middleware`, which re-issues
/// the cookie on every authenticated request. This endpoint exists solely
/// so the frontend has a dedicated URL to call on a periodic timer (every
/// 4 hours) to ensure the cookie doesn't expire during long idle periods.
async fn token_refresh() -> StatusCode {
    StatusCode::NO_CONTENT
}

/// Serve the opencode SPA for top-level pages (e.g. /pods).
/// The SPA handles client-side routing internally.
async fn serve_spa_page() -> Result<Response, StatusCode> {
    serve_opencode_index().await
}

/// Serve /assets/* from the vendored opencode UI directory.
///
/// All `/assets/*` requests come from the opencode SPA, so we always
/// serve from `OPENCODE_UI_PATH`. Vite produces content-hashed filenames
/// (e.g. `index-abc123.js`) so these files are immutable — we set
/// aggressive cache headers to avoid re-downloading on every page load.
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
    let mut resp = ServeDir::new(OPENCODE_UI_PATH)
        .oneshot(request)
        .await
        .unwrap()
        .into_response();
    if resp.status().is_success() {
        resp.headers_mut().insert(
            header::CACHE_CONTROL,
            "public, max-age=31536000, immutable".parse().unwrap(),
        );
    }
    Ok(resp)
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
    /// Use the devcontainer.json from dotfiles instead of the project's
    #[serde(default)]
    use_default_devcontainer: bool,
    /// Human-readable title for the workspace session
    title: Option<String>,
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
            .unwrap_or("scratch");
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
    let short_name = strip_pod_prefix(&pod_name).to_string();

    let mut cmd = tokio::process::Command::new(self_exe());
    cmd.arg("run");

    // Add source if provided
    if let Some(ref source) = req.source {
        cmd.arg(source);
    }

    // Add task if provided (use -c flag so it works with or without source)
    if let Some(ref task) = req.task {
        cmd.args(["-c", task]);
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

    if req.use_default_devcontainer {
        cmd.arg("--use-default-devcontainer");
    }

    if let Some(ref title) = req.title {
        cmd.args(["--title", title]);
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
    let advisor_name = crate::advisor_pod_name();
    let check = std::process::Command::new("podman")
        .args(["pod", "inspect", &advisor_name, "--format", "{{.State}}"])
        .output();

    if let Ok(output) = check
        && output.status.success()
    {
        let state = String::from_utf8_lossy(&output.stdout)
            .trim()
            .to_lowercase();
        if state == "running" {
            // Advisor already running — if task provided, send it
            if let Some(ref task) = req.task {
                let mut cmd = tokio::process::Command::new(self_exe());
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
                .args(["pod", "start", &advisor_name])
                .output()
                .await;
            if let Ok(o) = start
                && o.status.success()
            {
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

    // Advisor doesn't exist — create it via `devaipod advisor`.
    // This reuses the CLI command which handles dotfiles fallback,
    // image selection, and MCP setup internally. We pass --no-attach
    // (via an env var) so it doesn't block trying to attach.
    let mut cmd = tokio::process::Command::new(self_exe());
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
    let advisor_name = crate::advisor_pod_name();
    let check = std::process::Command::new("podman")
        .args(["pod", "inspect", &advisor_name, "--format", "{{.State}}"])
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

    let output = tokio::process::Command::new(self_exe())
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

    let short_name = strip_pod_prefix(&pod_name);
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

// =============================================================================
// Unified pod list endpoint (pods + agent status + enrichment in one response)
// =============================================================================

/// A single pod entry in the unified list response.
///
/// Merges podman pod metadata, agent status from the pod-api sidecar, and
/// enrichment data (needs_update) into one object. This eliminates the
/// multi-step fetch that caused UI layout shift.
#[derive(Debug, Serialize)]
struct UnifiedPodInfo {
    /// Pod name (e.g. "devaipod-myproject-abc123")
    name: String,
    /// Pod status from podman (e.g. "Running", "Exited")
    status: String,
    /// Creation timestamp
    created: String,
    /// Pod labels
    #[serde(skip_serializing_if = "Option::is_none")]
    labels: Option<HashMap<String, String>>,
    /// Container info (names + status)
    #[serde(skip_serializing_if = "Option::is_none")]
    containers: Option<Vec<UnifiedContainerInfo>>,
    /// Agent status from pod-api sidecar (None if pod is not running or unreachable)
    #[serde(skip_serializing_if = "Option::is_none")]
    agent_status: Option<AgentStatusResponse>,
    /// Last time the agent was active (unix timestamp in milliseconds).
    /// Available for both running pods (live) and stopped pods (from cache).
    #[serde(skip_serializing_if = "Option::is_none")]
    last_active_ts: Option<i64>,
    /// Whether the pod's sidecar image is outdated
    needs_update: bool,
    /// Diagnostic info for degraded pods (e.g. agent binary not found)
    #[serde(skip_serializing_if = "Option::is_none")]
    diagnostics: Option<PodDiagnostics>,
    /// Forwarded ports from devcontainer.json `forwardPorts`
    #[serde(skip_serializing_if = "Vec::is_empty")]
    forwarded_ports: Vec<ForwardedPort>,
}

/// A single forwarded port mapping (container port → host port).
#[derive(Debug, Clone, Serialize)]
struct ForwardedPort {
    container_port: u16,
    host_port: u16,
}

#[derive(Debug, Clone, Serialize)]
struct UnifiedContainerInfo {
    #[serde(rename = "Names")]
    names: String,
    #[serde(rename = "Status")]
    status: String,
    #[serde(rename = "ExitCode", skip_serializing_if = "Option::is_none")]
    exit_code: Option<i64>,
}

/// Diagnostic information for degraded or failed pods.
///
/// Populated when the backend detects a known failure mode (e.g. missing agent
/// binary, exit code 42).  The frontend renders this as an actionable banner.
#[derive(Debug, Clone, Serialize)]
struct PodDiagnostics {
    /// Machine-readable error code (e.g. "agent-binary-not-found")
    code: String,
    /// Human-readable message
    message: String,
    /// Suggested recovery action
    #[serde(skip_serializing_if = "Option::is_none")]
    suggestion: Option<String>,
}

/// Raw pod JSON from the podman REST API (`/v5.0.0/libpod/pods/json`).
///
/// Only the fields the unified endpoint needs are deserialized.
#[derive(Debug, Deserialize)]
struct PodmanPodJson {
    #[serde(rename = "Name")]
    name: String,
    #[serde(rename = "Status")]
    status: Option<String>,
    #[serde(rename = "Created")]
    created: Option<String>,
    #[serde(rename = "Labels")]
    labels: Option<HashMap<String, String>>,
    #[serde(rename = "Containers")]
    containers: Option<Vec<PodmanContainerJson>>,
}

#[derive(Debug, Deserialize)]
struct PodmanContainerJson {
    #[serde(rename = "Names")]
    names: Option<String>,
    #[serde(rename = "Status")]
    status: Option<String>,
}

/// Fetch the pod list from the podman unix socket.
async fn fetch_podman_pods(socket_path: &std::path::Path) -> Vec<PodmanPodJson> {
    let stream = match UnixStream::connect(socket_path).await {
        Ok(s) => s,
        Err(e) => {
            tracing::error!("Failed to connect to podman socket: {e}");
            return vec![];
        }
    };

    let io = TokioIo::new(stream);
    let (mut sender, conn) = match hyper::client::conn::http1::handshake(io).await {
        Ok(pair) => pair,
        Err(e) => {
            tracing::error!("Handshake with podman socket failed: {e}");
            return vec![];
        }
    };

    tokio::spawn(async move {
        if let Err(e) = conn.await {
            tracing::error!("Podman socket connection error: {e}");
        }
    });

    let request = match hyper::Request::builder()
        .uri("/v5.0.0/libpod/pods/json")
        .header(header::HOST, "localhost")
        .body(Body::empty())
    {
        Ok(r) => r,
        Err(e) => {
            tracing::error!("Failed to build podman request: {e}");
            return vec![];
        }
    };

    let response = match sender.send_request(request).await {
        Ok(r) => r,
        Err(e) => {
            tracing::error!("Failed to send request to podman: {e}");
            return vec![];
        }
    };

    if !response.status().is_success() {
        tracing::error!("Podman pods/json returned {}", response.status());
        return vec![];
    }

    let body = match axum::body::to_bytes(Body::new(response.into_body()), 4 * 1024 * 1024).await {
        Ok(b) => b,
        Err(e) => {
            tracing::error!("Failed to read podman response: {e}");
            return vec![];
        }
    };

    match serde_json::from_slice::<Vec<PodmanPodJson>>(&body) {
        Ok(pods) => pods,
        Err(e) => {
            tracing::error!("Failed to parse podman pods JSON: {e}");
            vec![]
        }
    }
}

/// `GET /api/devaipod/pods` -- unified pod list with agent status and enrichment.
///
/// Reads the cached pod list (maintained by the background event watcher) and
/// concurrently fetches agent status from each running pod's pod-api sidecar.
/// The cache is populated at startup and updated whenever podman container
/// events fire, so this handler never hits the podman socket directly.
///
/// For running pods, the pod state cache is updated with fresh data from the
/// agent status response. For stopped pods, cached state is used to populate
/// `agent_status` and `last_active_ts` so that titles, completion status, and
/// frecency timestamps survive across pod stops.
async fn list_pods_unified(State(state): State<Arc<AppState>>) -> Json<Vec<UnifiedPodInfo>> {
    let cached_pods = state.pod_cache.read().await.clone();

    if cached_pods.is_empty() {
        return Json(vec![]);
    }

    let has_running = cached_pods
        .iter()
        .any(|p| p.status.eq_ignore_ascii_case("running"));

    // Create a single shared Docker connection for all pod inspections,
    // rather than one per pod (which was the previous behaviour).
    let docker = if has_running {
        let socket_path = get_container_socket().ok();
        socket_path.and_then(|sp| {
            bollard::Docker::connect_with_unix(
                &format!("unix://{}", sp.display()),
                120,
                bollard::API_DEFAULT_VERSION,
            )
            .ok()
        })
    } else {
        None
    };
    let docker = docker.map(Arc::new);

    // Concurrently fetch agent status for running pods
    let host = host_for_pod_services();
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .unwrap_or_else(|_| reqwest::Client::new());

    let mut tasks = Vec::with_capacity(cached_pods.len());

    for pod in cached_pods {
        // Skip devcontainer pods (they have their own management path)
        if pod
            .labels
            .as_ref()
            .and_then(|l| l.get("io.devaipod.mode"))
            .map(|m| m == "devcontainer")
            .unwrap_or(false)
        {
            continue;
        }

        let is_running = pod.status.eq_ignore_ascii_case("running");
        let host = host.clone();
        let client = client.clone();
        let pod_name = pod.name.clone();
        let docker = docker.clone();

        let task = tokio::spawn(async move {
            let (agent_status, forwarded_ports) = if is_running {
                if let Some(ref docker) = docker {
                    // Single inspect_container call to get both the pod-api
                    // port and forwarded ports, avoiding redundant work.
                    let (api_port, ports) = inspect_pod_ports(docker, &pod_name).await;
                    let status = match api_port {
                        Some(port) => fetch_agent_status_with_port(&client, &host, port).await,
                        None => None,
                    };
                    (status, ports)
                } else {
                    (None, vec![])
                }
            } else {
                (None, vec![])
            };

            (pod, agent_status, forwarded_ports)
        });

        tasks.push(task);
    }

    let mut result = Vec::with_capacity(tasks.len());
    let mut cache_changed = false;
    let mut newly_done_pods: Vec<String> = Vec::new();

    {
        let mut psc = state.pod_state_cache.write().await;

        for task in tasks {
            let Ok((pod, agent_status, forwarded_ports)) = task.await else {
                continue;
            };

            let is_running = pod.status.eq_ignore_ascii_case("running");
            let (final_agent_status, last_active_ts) = if is_running {
                if let Some(status) = agent_status {
                    // Update the cache with fresh data from the running pod
                    let ts = status.last_message_ts;
                    let new_cached = CachedPodState {
                        last_active_ts: ts,
                        completion_status: status.completion_status.clone(),
                        title: status.title.clone(),
                        activity: Some(status.activity.clone()),
                    };
                    let old = psc.insert(pod.name.clone(), new_cached.clone());
                    if old.as_ref() != Some(&new_cached) {
                        cache_changed = true;
                    }
                    // Detect completion_status transition to "done"
                    let was_done =
                        old.as_ref().and_then(|o| o.completion_status.as_deref()) == Some("done");
                    let is_done = new_cached.completion_status.as_deref() == Some("done");
                    if is_done && !was_done {
                        newly_done_pods.push(pod.name.clone());
                    }
                    (Some(status), ts)
                } else {
                    // Running but pod-api unreachable; use cached last_active_ts
                    let ts = psc.get(&pod.name).and_then(|c| c.last_active_ts);
                    (agent_status, ts)
                }
            } else {
                // Stopped pod: construct synthetic agent_status from cache
                match psc.get(&pod.name) {
                    Some(cached) => {
                        let synthetic = AgentStatusResponse {
                            // Always report "Stopped" for non-running pods,
                            // regardless of what was cached.
                            activity: "Stopped".to_string(),
                            status_line: None,
                            current_tool: None,
                            recent_output: vec![],
                            last_message_ts: cached.last_active_ts,
                            session_count: 0,
                            completion_status: cached.completion_status.clone(),
                            title: cached.title.clone(),
                        };
                        (Some(synthetic), cached.last_active_ts)
                    }
                    None => (None, None),
                }
            };

            result.push(UnifiedPodInfo {
                name: pod.name,
                status: pod.status,
                created: pod.created,
                labels: pod.labels,
                containers: pod.containers,
                agent_status: final_agent_status,
                last_active_ts,
                needs_update: pod.needs_update,
                diagnostics: pod.diagnostics,
                forwarded_ports,
            });
        }
    }

    // Persist the cache in the background if anything changed
    if cache_changed {
        let cache = state.pod_state_cache.clone();
        tokio::spawn(async move {
            save_pod_state_cache(&cache).await;
        });
    }

    // Auto-harvest: when a pod transitions to "done", fetch its commits
    // into the source repo in the background. Each pod is harvested at most
    // once per completion (we only fire when the cached status changes).
    //
    // TODO: Add periodic harvest while agents are still active. Track a
    // `last_harvest_check: HashMap<String, Instant>` in AppState and, on
    // each poll cycle, harvest from pods whose status is "active", whose
    // source is a local path, and where >5 minutes have elapsed since the
    // last harvest. This would surface incremental progress before the
    // agent marks itself done.
    for pod_name in newly_done_pods {
        tokio::task::spawn_blocking(move || match harvest_agent_commits(&pod_name) {
            Ok(result) => {
                for repo in &result.repos {
                    tracing::info!(
                        "Auto-harvested {} branch(es) from {} into {}",
                        repo.branches.len(),
                        repo.repo_name,
                        repo.target_repo
                    );
                }
            }
            Err((_, msg)) => {
                tracing::debug!("Auto-harvest skipped for {pod_name}: {msg}");
            }
        });
    }

    Json(result)
}

/// Fetch agent status given an already-known pod-api host port.
async fn fetch_agent_status_with_port(
    client: &reqwest::Client,
    host: &str,
    port: u16,
) -> Option<AgentStatusResponse> {
    let resp = client
        .get(format!("http://{}:{}/summary", host, port))
        .send()
        .await
        .ok()?;
    if !resp.status().is_success() {
        return None;
    }
    resp.json::<AgentStatusResponse>().await.ok()
}

/// Build a map of pod_name -> needs_update by comparing api container image IDs.
async fn compute_enrichment_map(
    docker: &bollard::Docker,
    self_image_id: Option<&str>,
) -> HashMap<String, bool> {
    let mut result = HashMap::new();

    let self_image_id = match self_image_id {
        Some(id) => id,
        None => return result,
    };

    let mut filters = HashMap::new();
    filters.insert("name", vec!["devaipod-*-api"]);
    let options = bollard::container::ListContainersOptions {
        all: true,
        filters,
        ..Default::default()
    };

    let containers = match docker.list_containers(Some(options)).await {
        Ok(c) => c,
        Err(_) => return result,
    };

    for container in containers {
        let names = match &container.names {
            Some(n) => n,
            None => continue,
        };
        let api_name = match names.iter().find(|n| n.ends_with("-api")) {
            Some(n) => n.trim_start_matches('/').to_string(),
            None => continue,
        };
        let pod_name = match api_name.strip_suffix("-api") {
            Some(p) => p.to_string(),
            None => continue,
        };
        let needs_update = container
            .image_id
            .as_ref()
            .map(|id| id != self_image_id)
            .unwrap_or(false);
        result.insert(pod_name, needs_update);
    }

    result
}

/// Refresh the pod cache: fetch pods from podman + enrichment, store the result.
///
/// This is called once at startup and again whenever a relevant podman event
/// fires. It replaces the entire cache atomically. Also prunes stale entries
/// from the pod state cache (pods that no longer exist).
async fn refresh_pod_cache(
    socket_path: &std::path::Path,
    self_image_id: Option<&str>,
    cache: &PodCache,
    pod_state_cache: Option<&PodStateCache>,
) {
    // Single Docker connection shared by enrichment map and exit-code inspection.
    let docker = bollard::Docker::connect_with_unix(
        &format!("unix://{}", socket_path.display()),
        120,
        bollard::API_DEFAULT_VERSION,
    )
    .ok();

    let enrichment_future = async {
        match &docker {
            Some(d) => compute_enrichment_map(d, self_image_id).await,
            None => HashMap::new(),
        }
    };

    let (all_pods, enrichment_map) =
        tokio::join!(fetch_podman_pods(socket_path), enrichment_future);

    let mut pods: Vec<CachedPodInfo> = all_pods
        .into_iter()
        .filter(|p| p.name.starts_with("devaipod-"))
        .filter(|p| {
            // Filter by DEVAIPOD_INSTANCE if set
            match crate::get_instance_id() {
                Some(ref instance_id) => {
                    // When instance is set, only show pods with matching label
                    p.labels
                        .as_ref()
                        .and_then(|l| l.get(crate::INSTANCE_LABEL_KEY))
                        == Some(instance_id)
                }
                None => {
                    // When no instance is set (production), exclude pods that carry
                    // any instance label (they belong to test/isolated instances)
                    p.labels
                        .as_ref()
                        .and_then(|l| l.get(crate::INSTANCE_LABEL_KEY))
                        .is_none()
                }
            }
        })
        .map(|pod| {
            let needs_update = enrichment_map.get(&pod.name).copied().unwrap_or(false);
            let containers = pod.containers.as_ref().map(|cs| {
                cs.iter()
                    .map(|c| UnifiedContainerInfo {
                        names: c.names.clone().unwrap_or_default(),
                        status: c.status.clone().unwrap_or_default(),
                        exit_code: None, // Populated below for exited containers
                    })
                    .collect()
            });
            CachedPodInfo {
                name: pod.name,
                status: pod.status.unwrap_or_else(|| "Unknown".to_string()),
                created: pod.created.unwrap_or_default(),
                labels: pod.labels,
                containers,
                needs_update,
                diagnostics: None, // Populated below for degraded pods
            }
        })
        .collect();

    // Inspect exited agent containers to detect known failure modes.
    // Only bother for non-running pods to avoid unnecessary API calls.
    if let Some(ref docker) = docker {
        for pod in pods.iter_mut() {
            let dominated_by_exit = pod.status.eq_ignore_ascii_case("degraded")
                || pod.status.eq_ignore_ascii_case("exited");
            if !dominated_by_exit {
                continue;
            }
            let agent_name = format!("{}-agent", pod.name);
            if let Ok(info) = docker.inspect_container(&agent_name, None).await
                && let Some(state) = &info.state
                && let Some(exit_code) = state.exit_code
            {
                // Update the agent container's exit_code in the cached containers
                if let Some(ref mut containers) = pod.containers {
                    for c in containers.iter_mut() {
                        if c.names == agent_name {
                            c.exit_code = Some(exit_code);
                        }
                    }
                }
                // Exit code 42 = agent binary not found (devaipod-specific)
                if exit_code == 42 {
                    pod.diagnostics = Some(PodDiagnostics {
                        code: "agent-binary-not-found".to_string(),
                        message: "Agent binary not found in container image".to_string(),
                        suggestion: Some(
                            "Recreate this workspace with the 'Use dotfiles \
                             devcontainer' option enabled, or specify a container \
                             image that includes the agent binary"
                                .to_string(),
                        ),
                    });
                }
            }
        }
    }

    // Sort: advisor first, then running pods, then by creation date descending
    let advisor_name = crate::advisor_pod_name();
    pods.sort_by(|a, b| {
        let a_advisor = u8::from(a.name == advisor_name);
        let b_advisor = u8::from(b.name == advisor_name);
        if b_advisor != a_advisor {
            return b_advisor.cmp(&a_advisor);
        }
        let a_running = u8::from(a.status.eq_ignore_ascii_case("running"));
        let b_running = u8::from(b.status.eq_ignore_ascii_case("running"));
        if b_running != a_running {
            return b_running.cmp(&a_running);
        }
        b.created.cmp(&a.created)
    });

    let pod_names: std::collections::HashSet<String> =
        pods.iter().map(|p| p.name.clone()).collect();
    let count = pods.len();
    *cache.write().await = pods;
    tracing::debug!("Pod cache refreshed: {} pods", count);

    // Prune pod state cache entries for pods that no longer exist
    if let Some(psc) = pod_state_cache {
        let mut psc_guard = psc.write().await;
        let before = psc_guard.len();
        psc_guard.retain(|name, _| pod_names.contains(name));
        let pruned = before - psc_guard.len();
        drop(psc_guard);
        if pruned > 0 {
            tracing::debug!("Pruned {} stale pod state cache entries", pruned);
            save_pod_state_cache(psc).await;
        }
    }
}

/// Spawn a background task that watches podman events and refreshes the pod cache.
///
/// The watcher subscribes to container events (start, stop, die, create, remove)
/// via bollard's streaming events API. On any relevant event it triggers a full
/// cache refresh (rather than incremental updates, which would be fragile).
///
/// If the event stream disconnects, the watcher reconnects after a short delay.
fn spawn_pod_event_watcher(
    socket_path: PathBuf,
    self_image_id: Option<String>,
    cache: PodCache,
    pod_state_cache: PodStateCache,
) {
    tokio::spawn(async move {
        loop {
            let docker = match bollard::Docker::connect_with_unix(
                &format!("unix://{}", socket_path.display()),
                120,
                bollard::API_DEFAULT_VERSION,
            ) {
                Ok(d) => d,
                Err(e) => {
                    tracing::warn!("Event watcher: failed to connect to podman: {e}");
                    tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                    continue;
                }
            };

            // Filter to container events only. Podman does not expose a
            // separate "pod" event type through the Docker-compat API, but
            // container lifecycle events (start/stop/die/remove) cover all the
            // state transitions we care about.
            let mut filters = HashMap::new();
            filters.insert("type".to_string(), vec!["container".to_string()]);
            let options = bollard::system::EventsOptions {
                since: None,
                until: None,
                filters,
            };

            let mut stream = docker.events(Some(options));

            tracing::info!("Event watcher: subscribed to podman container events");

            // Debounce: when many events arrive in quick succession (e.g. pod
            // start fires events for every container), we wait briefly before
            // refreshing so we only do one fetch per burst.
            let debounce = std::time::Duration::from_millis(500);
            let mut pending_refresh = false;
            let sleep = tokio::time::sleep(debounce);
            tokio::pin!(sleep);

            loop {
                tokio::select! {
                    event = stream.next() => {
                        match event {
                            Some(Ok(msg)) => {
                                // Only refresh on events related to devaipod containers.
                                let dominated = if let Some(ref actor) = msg.actor {
                                    actor.attributes.as_ref().is_some_and(|attrs| {
                                        attrs
                                            .get("name")
                                            .is_some_and(|n| n.starts_with("devaipod-"))
                                    })
                                } else {
                                    false
                                };

                                if dominated {
                                    let action = msg.action.as_deref().unwrap_or("?");
                                    tracing::debug!("Event watcher: devaipod event action={action}");
                                    pending_refresh = true;
                                    // Reset the debounce timer
                                    sleep.as_mut().reset(tokio::time::Instant::now() + debounce);
                                }
                            }
                            Some(Err(e)) => {
                                tracing::warn!("Event watcher: stream error: {e}");
                                break;
                            }
                            None => {
                                tracing::warn!("Event watcher: stream ended");
                                break;
                            }
                        }
                    }
                    _ = &mut sleep, if pending_refresh => {
                        pending_refresh = false;
                        refresh_pod_cache(
                            &socket_path,
                            self_image_id.as_deref(),
                            &cache,
                            Some(&pod_state_cache),
                        ).await;
                    }
                }
            }

            // Stream disconnected; reconnect after a short delay.
            tracing::info!("Event watcher: reconnecting in 5s");
            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
        }
    });
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
            return Some(strip_pod_prefix(pod_name).to_string());
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
    /// Pod completion status: "active" or "done".
    #[serde(default)]
    completion_status: Option<String>,
    /// Human-readable session title (from pod-api state).
    #[serde(default)]
    title: Option<String>,
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
            completion_status: None,
            title: None,
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
    let url = format!("http://{}:{}/summary", host, port);
    match client.get(&url).send().await {
        Ok(resp) if resp.status().is_success() => {
            // Read the raw body first so we can log it on deserialization failure
            let body = match resp.text().await {
                Ok(b) => b,
                Err(e) => {
                    tracing::warn!(pod = %pod_name, "Failed to read /summary body: {e}");
                    return Json(AgentStatusResponse::with_activity("Unknown"));
                }
            };
            match serde_json::from_str::<AgentStatusResponse>(&body) {
                Ok(summary) => {
                    tracing::debug!(
                        pod = %pod_name,
                        activity = %summary.activity,
                        completion_status = ?summary.completion_status,
                        "agent-status from pod-api"
                    );
                    Json(summary)
                }
                Err(e) => {
                    tracing::warn!(
                        pod = %pod_name,
                        "Failed to parse /summary response: {e}; body: {body}"
                    );
                    Json(AgentStatusResponse::with_activity("Unknown"))
                }
            }
        }
        Ok(resp) => {
            tracing::debug!(pod = %pod_name, status = %resp.status(), "Non-success from pod-api /summary");
            Json(AgentStatusResponse::with_activity("Unknown"))
        }
        Err(e) => {
            tracing::debug!(pod = %pod_name, "Failed to reach pod-api /summary: {e}");
            Json(AgentStatusResponse::with_activity("Unknown"))
        }
    }
}

// Git endpoints (git_status, git_diff, git_commits, git_log, git_diff_range,
// git_fetch_agent, git_push) and exec_in_container have been removed.
// The pod-api sidecar now handles all git operations directly, and the frontend
// routes git requests through the pod-api proxy.

// =============================================================================
// Agent diff endpoint — shows changes the agent made vs the starting point
// =============================================================================

/// Query parameters for the agent diff endpoint.
#[derive(Debug, Deserialize)]
struct DiffQueryParams {
    /// If true, return `--stat` output instead of full diff.
    stat: Option<bool>,
}

/// A single commit summary in the diff response.
#[derive(Debug, Serialize)]
struct CommitSummary {
    sha: String,
    message: String,
    author: String,
    timestamp: String,
}

/// Response for `GET /api/devaipod/pods/{name}/diff`.
#[derive(Debug, Serialize)]
struct AgentDiffResponse {
    /// The branch the agent is on.
    branch: String,
    /// Number of commits ahead of the starting point.
    commit_count: usize,
    /// Commit summaries (newest first).
    commits: Vec<CommitSummary>,
    /// The diff output (full diff or stat).
    diff: String,
    /// Whether this is a stat-only response.
    is_stat: bool,
}

/// Per-repo diff data for multi-repo workspaces.
#[derive(Debug, Serialize)]
struct RepoDiffResponse {
    /// Repository name (directory name, e.g. "devaipod" or "service-gator")
    repo_name: String,
    /// The diff data for this repo
    #[serde(flatten)]
    diff: AgentDiffResponse,
}

/// Response for multi-repo diff endpoint.
#[derive(Debug, Serialize)]
struct MultiRepoDiffResponse {
    /// Diff data for each git repo in the workspace
    repos: Vec<RepoDiffResponse>,
}

/// Convenience wrapper: find a single git repo inside `dir`.
///
/// Returns the first repo found by [`crate::agent_dir::find_git_repos_in_dir`],
/// or `None` if no repos exist.
fn find_git_repo_in_dir(dir: &std::path::Path) -> Option<std::path::PathBuf> {
    crate::agent_dir::find_git_repos_in_dir(dir)
        .into_iter()
        .next()
        .map(|(_, p)| p)
}

/// Run a git command in `repo` and return stdout, or `None` on failure
/// or empty output.
fn run_git(repo: &std::path::Path, args: &[&str]) -> Option<String> {
    let output = std::process::Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(args)
        .output()
        .ok()?;
    if output.status.success() {
        let s = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if s.is_empty() { None } else { Some(s) }
    } else {
        None
    }
}

/// Resolve the base ref to diff against. Tries `origin/HEAD`, then
/// `origin/main`, `origin/master`, then the first `origin/*` branch.
fn resolve_origin_ref(repo: &std::path::Path) -> Option<String> {
    // Try origin/HEAD (symbolic)
    if run_git(repo, &["rev-parse", "--verify", "origin/HEAD"]).is_some() {
        return Some("origin/HEAD".to_string());
    }
    for branch in ["main", "master"] {
        let refname = format!("origin/{branch}");
        if run_git(repo, &["rev-parse", "--verify", &refname]).is_some() {
            return Some(refname);
        }
    }
    // Fall back to the first origin/* branch
    let branches = run_git(repo, &["branch", "-r", "--list", "origin/*"])?;
    branches
        .lines()
        .map(|l| l.trim())
        .find(|l| !l.is_empty() && !l.contains("->"))
        .map(|s| s.to_string())
}

/// Parse null-byte delimited git log output into commit summaries.
fn parse_commit_log(log_output: &str) -> Vec<CommitSummary> {
    if log_output.is_empty() {
        return vec![];
    }
    log_output
        .lines()
        .filter_map(|line| {
            let fields: Vec<&str> = line.split('\0').collect();
            if fields.len() >= 4 {
                Some(CommitSummary {
                    sha: fields[0].to_string(),
                    message: fields[1].to_string(),
                    author: fields[2].to_string(),
                    timestamp: fields[3].to_string(),
                })
            } else {
                None
            }
        })
        .collect()
}

/// Build an `AgentDiffResponse` from a locally accessible git repo.
fn diff_from_local_repo(
    repo_path: &std::path::Path,
    use_stat: bool,
) -> Result<AgentDiffResponse, (StatusCode, String)> {
    let branch = run_git(repo_path, &["symbolic-ref", "--short", "HEAD"])
        .unwrap_or_else(|| "HEAD".to_string());

    let origin_ref = match resolve_origin_ref(repo_path) {
        Some(r) => r,
        None => {
            return Ok(AgentDiffResponse {
                branch,
                commit_count: 0,
                commits: vec![],
                diff: String::new(),
                is_stat: use_stat,
            });
        }
    };

    let range = format!("{origin_ref}..HEAD");
    let commit_count: usize = run_git(repo_path, &["rev-list", "--count", &range])
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);

    let format_str = "%H%x00%s%x00%an%x00%aI";
    let log_output = run_git(
        repo_path,
        &["log", &format!("--format={format_str}"), &range],
    )
    .unwrap_or_default();
    let commits = parse_commit_log(&log_output);

    let diff = if use_stat {
        run_git(repo_path, &["diff", "--stat", &range])
    } else {
        run_git(repo_path, &["diff", &range])
    }
    .unwrap_or_default();

    Ok(AgentDiffResponse {
        branch,
        commit_count,
        commits,
        diff,
        is_stat: use_stat,
    })
}

/// `GET /api/devaipod/pods/{name}/diff`
///
/// Returns the agent's git diff compared to the origin ref, plus commit
/// metadata. Reads the agent's git repo from the host filesystem.
async fn agent_diff(
    Path(name): Path<String>,
    Query(params): Query<DiffQueryParams>,
) -> Result<Json<AgentDiffResponse>, (StatusCode, Json<ApiErrorBody>)> {
    let pod_name = normalize_pod_name(&name);
    let use_stat = params.stat.unwrap_or(false);

    // All git operations are blocking I/O; run on the blocking pool.
    let result =
        tokio::task::spawn_blocking(move || -> Result<AgentDiffResponse, (StatusCode, String)> {
            let agent_dir = crate::agent_dir::agent_dir_container_path(&pod_name).map_err(|e| {
                (
                    StatusCode::NOT_FOUND,
                    format!("Failed to resolve agent directory for pod '{pod_name}': {e}"),
                )
            })?;
            let repo_path = find_git_repo_in_dir(&agent_dir).ok_or_else(|| {
                (
                    StatusCode::NOT_FOUND,
                    format!(
                        "No git workspace found in agent directory '{}'",
                        agent_dir.display()
                    ),
                )
            })?;
            diff_from_local_repo(&repo_path, use_stat)
        })
        .await
        .map_err(|e| {
            tracing::error!("spawn_blocking panicked: {e}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiErrorBody {
                    error: "Internal error".to_string(),
                }),
            )
        })?;

    result
        .map(Json)
        .map_err(|(code, msg)| (code, Json(ApiErrorBody { error: msg })))
}

/// `GET /api/devaipod/pods/{name}/diffs`
///
/// Returns diffs for ALL git repos in the agent's workspace. For single-repo
/// workspaces this returns a single entry; for multi-repo workspaces (created
/// with `--source-dir`) each repo gets its own entry.
async fn agent_diffs(
    Path(name): Path<String>,
    Query(params): Query<DiffQueryParams>,
) -> Result<Json<MultiRepoDiffResponse>, (StatusCode, Json<ApiErrorBody>)> {
    let pod_name = normalize_pod_name(&name);
    let use_stat = params.stat.unwrap_or(false);

    let result = tokio::task::spawn_blocking(
        move || -> Result<MultiRepoDiffResponse, (StatusCode, String)> {
            let agent_dir = crate::agent_dir::agent_dir_container_path(&pod_name).map_err(|e| {
                (
                    StatusCode::NOT_FOUND,
                    format!("Failed to resolve agent directory for pod '{pod_name}': {e}"),
                )
            })?;
            let repos = crate::agent_dir::find_git_repos_in_dir(&agent_dir);
            if repos.is_empty() {
                return Err((
                    StatusCode::NOT_FOUND,
                    format!(
                        "No git repos found in agent directory '{}'",
                        agent_dir.display()
                    ),
                ));
            }
            let mut repo_diffs = Vec::new();
            for (repo_name, repo_path) in repos {
                match diff_from_local_repo(&repo_path, use_stat) {
                    Ok(diff) => repo_diffs.push(RepoDiffResponse { repo_name, diff }),
                    Err((code, msg)) => {
                        tracing::warn!(
                            "Failed to get diff for repo {}: {} {}",
                            repo_name,
                            code,
                            msg
                        );
                        // Skip repos that fail (e.g., no commits yet)
                    }
                }
            }
            Ok(MultiRepoDiffResponse { repos: repo_diffs })
        },
    )
    .await
    .map_err(|e| {
        tracing::error!("spawn_blocking panicked: {e}");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ApiErrorBody {
                error: "Internal error".to_string(),
            }),
        )
    })?;

    result
        .map(Json)
        .map_err(|(code, msg)| (code, Json(ApiErrorBody { error: msg })))
}

// =============================================================================
// Review endpoint — send diff feedback to the agent
// =============================================================================

/// A single inline comment on a file/line in the diff.
#[derive(Debug, Deserialize)]
struct ReviewComment {
    /// File path the comment refers to.
    file: String,
    /// Optional line number in the diff.
    line: Option<usize>,
    /// The review comment body.
    body: String,
}

/// Request body for `POST /api/devaipod/pods/{name}/review`.
#[derive(Debug, Deserialize)]
struct ReviewRequest {
    /// Overall review message (e.g. "Please fix the error handling").
    #[serde(default)]
    message: Option<String>,
    /// Inline comments on specific files/lines.
    #[serde(default)]
    comments: Vec<ReviewComment>,
}

/// Response for the review endpoint.
#[derive(Debug, Serialize)]
struct ReviewResponse {
    success: bool,
    message: String,
}

/// Format review comments into a structured message the agent can act on.
fn format_review_message(req: &ReviewRequest) -> String {
    let mut parts = Vec::new();

    parts.push("## Code Review Feedback\n".to_string());
    parts.push(
        "The following review comments have been left on your changes. \
         Please address each one and commit the fixes.\n"
            .to_string(),
    );

    if let Some(ref msg) = req.message {
        parts.push(format!("### Overall\n\n{msg}\n"));
    }

    if !req.comments.is_empty() {
        parts.push("### Inline Comments\n".to_string());
        for (i, comment) in req.comments.iter().enumerate() {
            let location = match comment.line {
                Some(line) => format!("`{}:{}`", comment.file, line),
                None => format!("`{}`", comment.file),
            };
            parts.push(format!("{}. **{}**: {}\n", i + 1, location, comment.body));
        }
    }

    parts.join("\n")
}

/// `POST /api/devaipod/pods/{name}/review`
///
/// Sends code review feedback to a running agent. Formats the review
/// comments into a structured message, sends it to the agent's opencode
/// session via the pod-api proxy, and resets completion_status to "active"
/// so the agent resumes work.
async fn submit_review(
    Path(name): Path<String>,
    Json(req): Json<ReviewRequest>,
) -> Result<Json<ReviewResponse>, (StatusCode, Json<ApiErrorBody>)> {
    let pod_name = normalize_pod_name(&name);

    // Validate: must have at least a message or comments.
    if req.message.is_none() && req.comments.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ApiErrorBody {
                error: "Review must contain a message or at least one comment".to_string(),
            }),
        ));
    }

    let review_text = format_review_message(&req);

    // Get the pod-api port and admin token.
    let port = get_pod_api_port(&pod_name).await.map_err(|code| {
        (
            code,
            Json(ApiErrorBody {
                error: format!("Pod '{pod_name}' not reachable"),
            }),
        )
    })?;
    let admin_token = get_pod_api_admin_token(&pod_name).await.map_err(|code| {
        (
            code,
            Json(ApiErrorBody {
                error: "Failed to get pod admin token".to_string(),
            }),
        )
    })?;
    let host = host_for_pod_services();

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiErrorBody {
                    error: "HTTP client error".to_string(),
                }),
            )
        })?;

    // Find the root session ID by listing sessions.
    let sessions_resp = client
        .get(format!("http://{host}:{port}/session"))
        .send()
        .await
        .map_err(|e| {
            tracing::error!("Failed to list sessions for {pod_name}: {e}");
            (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(ApiErrorBody {
                    error: "Failed to reach agent".to_string(),
                }),
            )
        })?;

    let sessions: Vec<serde_json::Value> = sessions_resp.json().await.map_err(|e| {
        tracing::error!("Failed to parse sessions for {pod_name}: {e}");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ApiErrorBody {
                error: "Failed to parse agent sessions".to_string(),
            }),
        )
    })?;

    let session_id = sessions
        .iter()
        .find(|s| crate::session_is_root(s))
        .and_then(|s| s.get("id"))
        .and_then(|id| id.as_str())
        .ok_or_else(|| {
            (
                StatusCode::NOT_FOUND,
                Json(ApiErrorBody {
                    error: "No active agent session found".to_string(),
                }),
            )
        })?
        .to_string();

    // Send the review as a message using the async prompt endpoint
    // (fire-and-forget so we don't block on the LLM response).
    let message_body = serde_json::json!({
        "parts": [{"type": "text", "text": review_text}]
    });

    let send_resp = client
        .post(format!(
            "http://{host}:{port}/session/{session_id}/prompt_async"
        ))
        .json(&message_body)
        .send()
        .await
        .map_err(|e| {
            tracing::error!("Failed to send review to {pod_name}: {e}");
            (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(ApiErrorBody {
                    error: "Failed to send review to agent".to_string(),
                }),
            )
        })?;

    if !send_resp.status().is_success() {
        let status = send_resp.status();
        let body = send_resp.text().await.unwrap_or_default();
        tracing::error!("Agent rejected review message ({}): {}", status, body);
        return Err((
            StatusCode::BAD_GATEWAY,
            Json(ApiErrorBody {
                error: format!("Agent rejected review message: {status}"),
            }),
        ));
    }

    // Reset completion_status to Active so the agent shows as working again.
    let reset_body = serde_json::json!({"status": "active"});
    let reset_resp = client
        .put(format!("http://{host}:{port}/completion-status"))
        .header("Content-Type", "application/json")
        .header("Authorization", format!("Bearer {admin_token}"))
        .json(&reset_body)
        .send()
        .await;

    match reset_resp {
        Ok(r) if r.status().is_success() => {
            tracing::info!("Reset completion status to active for {pod_name}");
        }
        Ok(r) => {
            tracing::warn!(
                "Failed to reset completion status for {pod_name}: {}",
                r.status()
            );
        }
        Err(e) => {
            tracing::warn!("Failed to reset completion status for {pod_name}: {e}");
        }
    }

    let comment_count = req.comments.len();
    let summary = if comment_count > 0 {
        format!("Sent review with {comment_count} inline comment(s) to agent")
    } else {
        "Sent review feedback to agent".to_string()
    };

    Ok(Json(ReviewResponse {
        success: true,
        message: summary,
    }))
}

// =============================================================================
// Service-gator scope management (proxy to pod-api)
// =============================================================================

/// Proxy GET /gator-scopes to the pod-api sidecar's `/gator/scopes`.
///
/// Read-only — no admin auth required.
async fn get_gator_scopes(
    Path(name): Path<String>,
    request: Request,
) -> Result<Response, StatusCode> {
    proxy_to_pod_api(&name, "gator/scopes".to_string(), request).await
}

/// Proxy PUT /gator-scopes to the pod-api sidecar's `/gator/scopes`.
///
/// Retrieves the pod-api admin token via `podman exec` and injects it as
/// `Authorization: Bearer`. Pod-api requires this for write operations,
/// preventing the agent from self-escalating its scopes.
async fn update_gator_scopes(
    Path(name): Path<String>,
    request: Request,
) -> Result<Response, StatusCode> {
    let pod_name = normalize_pod_name(&name);

    // Retrieve the admin token from the pod-api container's state file
    let admin_token = get_pod_api_admin_token(&pod_name).await?;

    // Resolve pod-api port
    let port = get_pod_api_port(&pod_name).await.map_err(|code| {
        if code == StatusCode::NOT_FOUND {
            StatusCode::SERVICE_UNAVAILABLE
        } else {
            code
        }
    })?;
    let host = host_for_pod_services();

    // Rebuild the request with the admin token as Authorization: Bearer.
    // Replace the user's web-token Authorization with the pod-api admin token.
    let (parts, body) = request.into_parts();
    let mut builder = hyper::Request::builder()
        .method(parts.method.clone())
        .uri("/gator/scopes")
        .header(header::HOST, format!("{}:{}", host, port))
        .header(header::AUTHORIZATION, format!("Bearer {}", admin_token));
    for (key, value) in parts.headers.iter() {
        if key != header::HOST && key != header::AUTHORIZATION {
            builder = builder.header(key, value);
        }
    }
    let proxy_req = builder
        .body(body)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    proxy_to_upstream(&host, port, "gator/scopes".to_string(), proxy_req).await
}

/// Retrieve the pod-api admin token by execing into the pod-api container.
///
/// The pod-api generates its own token at startup and persists it to a state
/// file. The control plane reads it via `podman exec`, which establishes the
/// trust model: ability to exec into the container implies admin access.
async fn get_pod_api_admin_token(pod_name: &str) -> Result<String, StatusCode> {
    let api_container = format!("{pod_name}-api");

    let output = tokio::process::Command::new("podman")
        .args([
            "exec",
            &api_container,
            "cat",
            crate::pod_api::ADMIN_TOKEN_PATH,
        ])
        .output()
        .await
        .map_err(|e| {
            tracing::error!("Failed to exec into {api_container}: {e}");
            StatusCode::SERVICE_UNAVAILABLE
        })?;

    if !output.status.success() {
        tracing::error!(
            "Failed to read admin token from {api_container}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        return Err(StatusCode::SERVICE_UNAVAILABLE);
    }

    let token = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if token.is_empty() {
        tracing::error!("Empty admin token from {api_container}");
        return Err(StatusCode::SERVICE_UNAVAILABLE);
    }

    Ok(token)
}

/// Public wrapper for get_pod_api_port (used by CLI commands).
pub async fn get_pod_api_port_pub(pod_name: &str) -> Result<u16, StatusCode> {
    get_pod_api_port(pod_name).await
}

/// Public wrapper for get_pod_api_admin_token (used by CLI commands).
pub async fn get_pod_api_admin_token_pub(pod_name: &str) -> Result<String, StatusCode> {
    get_pod_api_admin_token(pod_name).await
}

/// Proxy GET /completion-status to the pod-api sidecar.
async fn get_pod_completion_status(
    Path(name): Path<String>,
    request: Request,
) -> Result<Response, StatusCode> {
    proxy_to_pod_api(&name, "completion-status".to_string(), request).await
}

/// Proxy PUT /completion-status to the pod-api sidecar (with admin token injection).
async fn update_pod_completion_status(
    Path(name): Path<String>,
    request: Request,
) -> Result<Response, StatusCode> {
    let pod_name = normalize_pod_name(&name);
    let admin_token = get_pod_api_admin_token(&pod_name).await?;
    let port = get_pod_api_port(&pod_name).await.map_err(|code| {
        if code == StatusCode::NOT_FOUND {
            StatusCode::SERVICE_UNAVAILABLE
        } else {
            code
        }
    })?;
    let host = host_for_pod_services();

    let (parts, body) = request.into_parts();
    let mut builder = hyper::Request::builder()
        .method(parts.method.clone())
        .uri("/completion-status")
        .header(header::HOST, format!("{}:{}", host, port))
        .header(header::AUTHORIZATION, format!("Bearer {}", admin_token));
    for (key, value) in parts.headers.iter() {
        if key != header::HOST && key != header::AUTHORIZATION {
            builder = builder.header(key, value);
        }
    }
    let proxy_req = builder
        .body(body)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    proxy_to_upstream(&host, port, "completion-status".to_string(), proxy_req).await
}

/// Response for the prune endpoint.
#[derive(Debug, Serialize)]
struct PruneResponse {
    /// Number of pods deleted.
    deleted: usize,
    /// Names of pods that were deleted.
    pod_names: Vec<String>,
    /// Any errors encountered (pod name -> error message).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    errors: Vec<String>,
}

/// Delete all pods marked as "done".
///
/// Iterates over all devaipod pods, checks their completion status via the
/// pod-api sidecar, and deletes those marked as "done".
async fn prune_done_pods() -> Result<Json<PruneResponse>, StatusCode> {
    use bollard::Docker;

    let socket_path = get_container_socket().map_err(|e| {
        tracing::error!("No container socket: {}", e);
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

    // List all devaipod pods
    let mut filters = std::collections::HashMap::new();
    filters.insert("name", vec!["devaipod-*-agent"]);
    let options = bollard::container::ListContainersOptions {
        all: true,
        filters,
        ..Default::default()
    };
    let containers = docker.list_containers(Some(options)).await.map_err(|e| {
        tracing::error!("Failed to list containers: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    // Collect unique pod names
    let mut pod_names: Vec<String> = Vec::new();
    for container in &containers {
        if let Some(names) = &container.names {
            for name in names {
                let name = name.trim_start_matches('/');
                if let Some(pod_name) = name.strip_suffix("-agent")
                    && pod_name.starts_with("devaipod-")
                    && !pod_names.contains(&pod_name.to_string())
                {
                    pod_names.push(pod_name.to_string());
                }
            }
        }
    }

    let host = host_for_pod_services();
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let mut deleted = Vec::new();
    let mut errors = Vec::new();

    for pod_name in &pod_names {
        // Check completion status via pod-api sidecar
        let port = match get_pod_api_port(pod_name).await {
            Ok(p) => p,
            Err(_) => continue, // Skip pods without pod-api
        };

        let resp = match client
            .get(format!("http://{}:{}/completion-status", host, port))
            .send()
            .await
        {
            Ok(r) if r.status().is_success() => r,
            _ => continue,
        };

        #[derive(Deserialize)]
        struct StatusResp {
            status: String,
        }
        let status: StatusResp = match resp.json().await {
            Ok(s) => s,
            Err(_) => continue,
        };

        if status.status != "done" {
            continue;
        }

        // Delete the pod
        tracing::info!("Pruning done pod: {}", pod_name);
        let output = tokio::process::Command::new("podman")
            .args(["pod", "rm", "-f", pod_name])
            .output()
            .await;

        match output {
            Ok(o) if o.status.success() => {
                deleted.push(pod_name.clone());
            }
            Ok(o) => {
                let stderr = String::from_utf8_lossy(&o.stderr);
                errors.push(format!("{}: {}", pod_name, stderr.trim()));
            }
            Err(e) => {
                errors.push(format!("{}: {}", pod_name, e));
            }
        }
    }

    Ok(Json(PruneResponse {
        deleted: deleted.len(),
        pod_names: deleted,
        errors,
    }))
}

// ── Workspace-centric endpoints ──────────────────────────────────────

/// A workspace entry in the workspace list response.
///
/// Merges on-disk workspace state with podman pod status.
#[derive(Debug, Serialize)]
struct WorkspaceInfo {
    /// Directory name (doubles as pod name for host-dir workspaces).
    name: String,
    /// Source identifier (local path or remote URL).
    source: String,
    /// RFC 3339 creation timestamp.
    created: String,
    /// RFC 3339 timestamp of last known activity.
    #[serde(skip_serializing_if = "Option::is_none")]
    last_active: Option<String>,
    /// Task description.
    #[serde(skip_serializing_if = "Option::is_none")]
    task: Option<String>,
    /// Human-readable title.
    #[serde(skip_serializing_if = "Option::is_none")]
    title: Option<String>,
    /// Completion status: "active" or "done".
    #[serde(skip_serializing_if = "Option::is_none")]
    completion_status: Option<String>,
    /// Whether a matching podman pod is currently running.
    pod_running: bool,
    /// Podman pod status string (e.g. "Running", "Exited"), if a pod exists.
    #[serde(skip_serializing_if = "Option::is_none")]
    pod_status: Option<String>,
}

/// `GET /api/devaipod/workspaces` — list all workspaces (running + stopped).
///
/// Scans the workspaces base directory for state files and cross-references
/// with the cached podman pod list to determine which workspaces have
/// running pods.
async fn list_workspaces_api(
    State(state): State<Arc<AppState>>,
) -> Result<axum::Json<Vec<WorkspaceInfo>>, StatusCode> {
    let workspaces = crate::agent_dir::list_workspaces().map_err(|e| {
        tracing::warn!("Failed to list workspaces: {e:#}");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    // Build a set of running pod names from the cache for fast lookup.
    let pod_cache = state.pod_cache.read().await;
    let pod_status_map: HashMap<&str, &str> = pod_cache
        .iter()
        .map(|p| (p.name.as_str(), p.status.as_str()))
        .collect();

    let mut results: Vec<WorkspaceInfo> = workspaces
        .into_iter()
        .map(|(dir_name, _path, state)| {
            let pod_status = pod_status_map.get(dir_name.as_str()).copied();
            let pod_running = pod_status
                .map(|s| s.eq_ignore_ascii_case("running"))
                .unwrap_or(false);

            match state {
                Some(ws) => WorkspaceInfo {
                    name: ws.pod_name,
                    source: ws.source,
                    created: ws.created,
                    last_active: ws.last_active,
                    task: ws.task,
                    title: ws.title,
                    completion_status: ws.completion_status,
                    pod_running,
                    pod_status: pod_status.map(|s| s.to_string()),
                },
                None => WorkspaceInfo {
                    name: dir_name.clone(),
                    source: String::new(),
                    created: String::new(),
                    last_active: None,
                    task: None,
                    title: None,
                    completion_status: None,
                    pod_running,
                    pod_status: pod_status.map(|s| s.to_string()),
                },
            }
        })
        .collect();

    // Sort: running first, then by created descending.
    results.sort_by(|a, b| {
        b.pod_running
            .cmp(&a.pod_running)
            .then_with(|| b.created.cmp(&a.created))
    });

    Ok(axum::Json(results))
}

/// `GET /api/devaipod/recent-sources` — list recently-used sources for the launcher.
async fn list_recent_sources() -> axum::Json<Vec<crate::agent_dir::RecentSource>> {
    axum::Json(crate::agent_dir::load_recent_sources())
}

// ── Devcontainer endpoints ───────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct DevcontainerRunRequest {
    source: Option<String>,
    name: Option<String>,
    image: Option<String>,
    devcontainer_json: Option<String>,
    #[serde(default)]
    use_default_devcontainer: bool,
}

fn compute_devcontainer_pod_name(req: &DevcontainerRunRequest) -> String {
    if let Some(ref name) = req.name {
        normalize_pod_name(name)
    } else {
        let project = req
            .source
            .as_deref()
            .and_then(|s| s.rsplit('/').next())
            .map(|s| s.trim_end_matches(".git"))
            .filter(|s| !s.is_empty())
            .unwrap_or("devcontainer");
        crate::make_pod_name(project)
    }
}

async fn run_devcontainer(
    State(state): State<Arc<AppState>>,
    Json(req): Json<DevcontainerRunRequest>,
) -> Result<Json<RunResponse>, StatusCode> {
    let pod_name = compute_devcontainer_pod_name(&req);
    let short_name = strip_pod_prefix(&pod_name).to_string();

    let mut cmd = tokio::process::Command::new(self_exe());
    cmd.args(["devcontainer", "run"]);

    if let Some(ref source) = req.source {
        cmd.arg(source);
    }

    cmd.args(["--name", &pod_name]);

    if let Some(ref image) = req.image {
        cmd.args(["--image", image]);
    }

    if let Some(ref json) = req.devcontainer_json {
        cmd.args(["--devcontainer-json", json]);
    }

    if req.use_default_devcontainer {
        cmd.arg("--use-default-devcontainer");
    }

    cmd.stdin(std::process::Stdio::null());

    tracing::info!("Running devcontainer (async): {:?}", cmd);

    {
        let mut launches = state.launches.lock().await;
        if launches.contains_key(&pod_name) {
            tracing::warn!("Duplicate devcontainer launch rejected for {}", pod_name);
            return Err(StatusCode::CONFLICT);
        }
        launches.insert(pod_name.clone(), LaunchState::Launching);
    }

    let launches = state.launches.clone();
    let pod_name_bg = pod_name.clone();
    tokio::spawn(async move {
        let result = cmd.output().await;
        let mut map = launches.lock().await;
        match result {
            Ok(output) if output.status.success() => {
                tracing::info!("devcontainer run completed for {}", pod_name_bg);
                map.remove(&pod_name_bg);
            }
            Ok(output) => {
                let stderr = String::from_utf8_lossy(&output.stderr);
                let msg = stderr.trim().to_string();
                tracing::error!("devcontainer run failed for {}: {}", pod_name_bg, msg);
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
                tracing::error!(
                    "Failed to execute devcontainer run for {}: {}",
                    pod_name_bg,
                    e
                );
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
        message: "Launching devcontainer in background".to_string(),
        status: Some("launching".to_string()),
        pod_name: Some(pod_name),
    }))
}

#[derive(Debug, Serialize)]
struct DevcontainerPodInfo {
    name: String,
    status: String,
    created: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    labels: Option<HashMap<String, String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    containers: Option<Vec<UnifiedContainerInfo>>,
}

async fn list_devcontainers(State(state): State<Arc<AppState>>) -> Json<Vec<DevcontainerPodInfo>> {
    let cached_pods = state.pod_cache.read().await;

    let result: Vec<DevcontainerPodInfo> = cached_pods
        .iter()
        .filter(|p| {
            p.labels
                .as_ref()
                .and_then(|l| l.get("io.devaipod.mode"))
                .map(|m| m == "devcontainer")
                .unwrap_or(false)
        })
        .map(|p| DevcontainerPodInfo {
            name: p.name.clone(),
            status: p.status.clone(),
            created: p.created.clone(),
            labels: p.labels.clone(),
            containers: p.containers.clone(),
        })
        .collect();

    Json(result)
}

async fn delete_devcontainer(Path(name): Path<String>) -> Result<StatusCode, StatusCode> {
    let pod_name = normalize_pod_name(&name);

    tracing::info!("Deleting devcontainer pod: {}", pod_name);

    let output = tokio::process::Command::new("podman")
        .args(["pod", "rm", "-f", &pod_name])
        .output()
        .await
        .map_err(|e| {
            tracing::error!("Failed to execute podman pod rm: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        tracing::error!("podman pod rm failed for {}: {}", pod_name, stderr.trim());
        return Err(StatusCode::INTERNAL_SERVER_ERROR);
    }

    Ok(StatusCode::NO_CONTENT)
}

// ── Control plane overview endpoint ───────────────────────────────────

/// Top-level response for the control plane overview.
#[derive(Debug, Serialize)]
struct ControlPlaneResponse {
    repos: Vec<RepoGroup>,
}

/// Pods grouped by repository.
#[derive(Debug, Serialize)]
struct RepoGroup {
    /// Repository identifier (e.g. "cgwalters/devaipod").
    repo: String,
    /// Number of running, non-done agents in this repo.
    active_count: usize,
    /// Agent pods for this repo.
    agents: Vec<ControlPlaneAgent>,
    /// Devcontainer pods for this repo.
    devcontainers: Vec<ControlPlaneDevcontainer>,
}

/// An agent pod in the control plane overview.
#[derive(Debug, Serialize)]
struct ControlPlaneAgent {
    /// Full pod name.
    name: String,
    /// Short name (without `devaipod-` prefix).
    short_name: String,
    /// Pod status ("Running", "Stopped", etc.).
    status: String,
    /// Task description from labels.
    #[serde(skip_serializing_if = "Option::is_none")]
    task: Option<String>,
    /// Title (from agent status or labels).
    #[serde(skip_serializing_if = "Option::is_none")]
    title: Option<String>,
    /// Completion status ("active", "done").
    #[serde(skip_serializing_if = "Option::is_none")]
    completion_status: Option<String>,
    /// Last active timestamp (RFC 3339 from pod state cache).
    #[serde(skip_serializing_if = "Option::is_none")]
    last_active: Option<String>,
    /// Whether the pod is currently running.
    is_running: bool,
    /// Created timestamp.
    created: String,
}

/// A devcontainer pod in the control plane overview.
#[derive(Debug, Serialize)]
struct ControlPlaneDevcontainer {
    name: String,
    short_name: String,
    status: String,
    created: String,
    is_running: bool,
}

/// `GET /api/devaipod/control-plane` — pods grouped by git repository.
///
/// Reads the cached pod list and pod state cache to produce a view of all
/// pods organised by their `io.devaipod.repo` label. No new data sources
/// are consulted; this is purely a grouping/projection of existing data.
async fn control_plane(State(state): State<Arc<AppState>>) -> Json<ControlPlaneResponse> {
    let cached_pods = state.pod_cache.read().await;
    let pod_state_cache = state.pod_state_cache.read().await;

    let mut repo_map: BTreeMap<String, RepoGroup> = BTreeMap::new();

    for pod in cached_pods.iter() {
        let labels = pod.labels.as_ref();
        let mode = labels
            .and_then(|l| l.get("io.devaipod.mode"))
            .map(|s| s.as_str());
        let repo = labels
            .and_then(|l| l.get("io.devaipod.repo"))
            .cloned()
            .unwrap_or_else(|| "unknown".to_string());

        let is_running = pod.status.eq_ignore_ascii_case("running");
        let short_name = strip_pod_prefix(&pod.name).to_string();

        let group = repo_map.entry(repo.clone()).or_insert_with(|| RepoGroup {
            repo: repo.clone(),
            active_count: 0,
            agents: Vec::new(),
            devcontainers: Vec::new(),
        });

        match mode {
            Some("devcontainer") => {
                group.devcontainers.push(ControlPlaneDevcontainer {
                    name: pod.name.clone(),
                    short_name,
                    status: pod.status.clone(),
                    created: pod.created.clone(),
                    is_running,
                });
            }
            _ => {
                // Agent pod (mode "up", "run", or absent)
                let cached_state = pod_state_cache.get(&pod.name);

                let task = labels.and_then(|l| l.get("io.devaipod.task")).cloned();
                let title = cached_state
                    .and_then(|s| s.title.clone())
                    .or_else(|| labels.and_then(|l| l.get("io.devaipod.title")).cloned());
                let completion_status = cached_state.and_then(|s| s.completion_status.clone());
                let last_active = cached_state.and_then(|s| s.last_active_ts).map(|ts| {
                    chrono::DateTime::from_timestamp_millis(ts)
                        .map(|dt| dt.to_rfc3339())
                        .unwrap_or_else(|| ts.to_string())
                });

                let is_done = completion_status.as_deref() == Some("done");
                if is_running && !is_done {
                    group.active_count += 1;
                }

                group.agents.push(ControlPlaneAgent {
                    name: pod.name.clone(),
                    short_name,
                    status: pod.status.clone(),
                    task,
                    title,
                    completion_status,
                    last_active,
                    is_running,
                    created: pod.created.clone(),
                });
            }
        }
    }

    // Sort: repos with active agents first, then alphabetically.
    let mut repos: Vec<RepoGroup> = repo_map.into_values().collect();
    repos.sort_by(|a, b| {
        b.active_count
            .cmp(&a.active_count)
            .then_with(|| a.repo.cmp(&b.repo))
    });

    Json(ControlPlaneResponse { repos })
}

// =============================================================================
// Harvest endpoint — fetch agent commits into the source repo
// =============================================================================

/// A single repo that was harvested.
#[derive(Debug, Serialize)]
struct HarvestedRepo {
    repo_name: String,
    target_repo: String,
    remote_name: String,
    branches: Vec<String>,
}

/// Result of a harvest operation.
#[derive(Debug, Serialize)]
struct HarvestResult {
    repos: Vec<HarvestedRepo>,
}

/// Harvest agent commits by fetching them into the source repo.
///
/// Reads the workspace state to find the source repo path, then adds/updates
/// a git remote named `devaipod/<short_name>` in the source repo and runs
/// `git fetch` to bring agent branches into the user's repo.
fn harvest_agent_commits(pod_name: &str) -> Result<HarvestResult, (StatusCode, String)> {
    let agent_dir = crate::agent_dir::agent_dir_container_path(pod_name)
        .map_err(|e| (StatusCode::NOT_FOUND, format!("Agent dir not found: {e}")))?;

    // Load workspace state to find source path
    let state = crate::agent_dir::WorkspaceState::load(&agent_dir)
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to load workspace state: {e}"),
            )
        })?
        .ok_or_else(|| {
            (
                StatusCode::NOT_FOUND,
                "No workspace state file found".to_string(),
            )
        })?;

    // Only harvest when source is a local path (not a URL)
    let source_path = PathBuf::from(&state.source);
    if !source_path.exists() || !source_path.join(".git").exists() {
        return Err((
            StatusCode::BAD_REQUEST,
            format!(
                "Source '{}' is not a local git repo (remote sources can't be auto-harvested)",
                state.source
            ),
        ));
    }

    // Find agent git repos
    let repos = crate::agent_dir::find_git_repos_in_dir(&agent_dir);
    if repos.is_empty() {
        return Err((
            StatusCode::NOT_FOUND,
            "No git repos in agent workspace".to_string(),
        ));
    }

    let short_name = strip_pod_prefix(pod_name);
    let mut harvested = Vec::new();

    // Check once whether the agent container is running (avoid per-repo overhead).
    let agent_container = format!("{pod_name}-agent");
    let container_running = crate::agent_dir::is_container_running(&agent_container);

    for (repo_name, repo_path) in &repos {
        // Check if HEAD has advanced since last harvest
        let current_head = run_git(repo_path, &["rev-parse", "HEAD"]);
        if let Some(ref head) = current_head
            && let Some(last) = state.last_harvested.get(repo_name)
            && last == head
        {
            tracing::debug!("Skipping harvest for {repo_name}: HEAD unchanged at {head}");
            continue;
        }

        // Determine which source repo to fetch into.
        // For single-repo: use state.source directly.
        // For multi-repo: try to find a matching source_dirs entry.
        let target_repo = if repos.len() == 1 {
            source_path.clone()
        } else {
            state
                .source_dirs
                .iter()
                .find(|d| {
                    d.file_name()
                        .and_then(|n| n.to_str())
                        .is_some_and(|n| n == repo_name)
                })
                .cloned()
                .unwrap_or_else(|| source_path.clone())
        };

        if !target_repo.join(".git").exists() {
            tracing::debug!(
                "Skipping harvest for {repo_name}: target {:?} is not a git repo",
                target_repo
            );
            continue;
        }

        let remote_name = if repos.len() == 1 {
            format!("devaipod/{short_name}")
        } else {
            format!("devaipod/{short_name}/{repo_name}")
        };

        // Use ext:: transport to handle workspace-v2 repos with container-
        // internal alternates. When the agent is running, use podman exec;
        // otherwise spawn a transient container mounting the workspace volume.
        let workspace_path = format!("/workspaces/{repo_name}");
        let harvest_result = if container_running {
            crate::agent_dir::harvest_one_repo_via_exec(
                &target_repo,
                &agent_container,
                &workspace_path,
                &remote_name,
            )
        } else {
            let image = crate::pod::detect_self_image();
            crate::agent_dir::harvest_one_repo_via_transient(
                &target_repo,
                pod_name,
                &workspace_path,
                &remote_name,
                &image,
            )
        };

        match harvest_result {
            Ok(result) => {
                harvested.push(HarvestedRepo {
                    repo_name: repo_name.to_string(),
                    target_repo: target_repo.display().to_string(),
                    remote_name: result.remote_name,
                    branches: result.branches,
                });
            }
            Err(e) => {
                tracing::warn!(
                    "Failed to harvest {repo_name} into {}: {e}",
                    target_repo.display(),
                );
            }
        }
    }

    // Update workspace state with the harvested HEAD SHAs
    if !harvested.is_empty()
        && let Ok(Some(mut ws_state)) = crate::agent_dir::WorkspaceState::load(&agent_dir)
    {
        for repo in &harvested {
            // Read HEAD from the agent repo
            for (name, agent_path) in &repos {
                if name == &repo.repo_name
                    && let Some(sha) = run_git(agent_path, &["rev-parse", "HEAD"])
                {
                    ws_state.last_harvested.insert(repo.repo_name.clone(), sha);
                }
            }
        }
        if let Err(e) = ws_state.save(&agent_dir) {
            tracing::warn!("Failed to update workspace state after harvest: {e}");
        }
    }

    Ok(HarvestResult { repos: harvested })
}

/// `POST /api/devaipod/pods/{name}/fetch`
///
/// Harvest agent commits by fetching them into the source repo.
async fn harvest_commits(
    Path(name): Path<String>,
) -> Result<Json<HarvestResult>, (StatusCode, Json<ApiErrorBody>)> {
    let pod_name = normalize_pod_name(&name);

    let result = tokio::task::spawn_blocking(move || harvest_agent_commits(&pod_name))
        .await
        .map_err(|e| {
            tracing::error!("spawn_blocking panicked: {e}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiErrorBody {
                    error: "Internal error".to_string(),
                }),
            )
        })?;

    result
        .map(Json)
        .map_err(|(code, msg)| (code, Json(ApiErrorBody { error: msg })))
}

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
#[cfg(test)]
pub(crate) fn build_app(
    token: String,
    mcp_token: String,
    socket_path: Option<PathBuf>,
    self_image_id: Option<String>,
) -> Router {
    let pod_cache: PodCache = Arc::new(tokio::sync::RwLock::new(Vec::new()));
    let pod_state_cache: PodStateCache = Arc::new(tokio::sync::RwLock::new(HashMap::new()));
    // Default to port 8080 when not specified (unit tests, etc.)
    build_app_with_cache(
        token,
        mcp_token,
        socket_path,
        self_image_id,
        pod_cache,
        pod_state_cache,
        8080,
    )
}

/// Build the web app router with a pre-existing pod cache.
///
/// This variant is used by `run_web_server` so the cache can be shared with
/// the background event watcher.
fn build_app_with_cache(
    token: String,
    mcp_token: String,
    socket_path: Option<PathBuf>,
    self_image_id: Option<String>,
    pod_cache: PodCache,
    pod_state_cache: PodStateCache,
    port: u16,
) -> Router {
    let state = Arc::new(AppState {
        token: token.clone(),
        mcp_token,
        socket_path,
        launches: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
        self_image_id,
        pod_cache,
        pod_state_cache,
        auth_cookie_name: format!("{}_{}", DEVAIPOD_AUTH_COOKIE_BASE, port),
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
        .route(
            "/devaipod/pods/{name}/gator-scopes",
            get(get_gator_scopes).put(update_gator_scopes),
        )
        .route(
            "/devaipod/pods/{name}/completion-status",
            get(get_pod_completion_status).put(update_pod_completion_status),
        )
        .route("/devaipod/pods/{name}/diff", get(agent_diff))
        .route("/devaipod/pods/{name}/diffs", get(agent_diffs))
        .route("/devaipod/pods/{name}/review", post(submit_review))
        // Harvest agent commits into the source repo
        .route("/devaipod/pods/{name}/fetch", post(harvest_commits))
        // Lightweight endpoint for frontend cookie refresh (every 4h).
        // The auth_middleware already re-issues the cookie on every
        // authenticated request, so this handler is a no-op — its only
        // purpose is to give the frontend a dedicated URL to hit.
        .route("/devaipod/token-refresh", post(token_refresh))
        .route("/devaipod/prune", post(prune_done_pods))
        .route("/devaipod/pods/enrichment", get(pod_enrichment))
        // Unified pod list: pods + agent status + enrichment in one response
        .route("/devaipod/pods", get(list_pods_unified))
        // Control plane overview: pods grouped by repository
        .route("/devaipod/control-plane", get(control_plane))
        // Workspace-centric endpoints
        .route("/devaipod/workspaces", get(list_workspaces_api))
        .route("/devaipod/recent-sources", get(list_recent_sources))
        // Devcontainer endpoints
        .route("/devaipod/devcontainer/run", post(run_devcontainer))
        .route("/devaipod/devcontainer/list", get(list_devcontainers))
        .route(
            "/devaipod/devcontainer/{name}",
            axum::routing::delete(delete_devcontainer),
        )
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
        // MCP endpoint for advisor tools — requires a separate MCP token
        // (shared secret given only to the advisor pod). This prevents other
        // pods from reaching the MCP endpoint via host.containers.internal.
        .nest(
            "/api/devaipod",
            Router::new()
                .route("/mcp", post(crate::mcp::handle_mcp))
                .layer(middleware::from_fn_with_state(
                    state.clone(),
                    mcp_auth_middleware,
                ))
                .with_state(state.clone()),
        )
        .nest("/api", api_router)
        .route("/", get(redirect_to_pods))
        .route("/pods", get(serve_spa_page))
        .route("/_devaipod/agent/{name}", get(agent_wrapper))
        .route("/_devaipod/agent/{name}/", get(agent_ui_root))
        .route(
            "/_devaipod/static/agent-wrapper.js",
            get(serve_agent_wrapper_js),
        )
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
        .layer(CompressionLayer::new())
        .with_state(state)
}

/// Check if this process is a launcher container and, if so, create the real
/// server container with source bind mounts and exit.
///
/// The launcher pattern works as follows:
/// 1. The Justfile creates a `$NAME-launcher` container with the config file mounted
/// 2. This function reads `~/.config/devaipod.toml`, resolves `[sources]`
/// 3. It inspects its own container to copy mounts/env/network settings
/// 4. It creates the real `$NAME` container with additional `-v` mounts for sources
/// 5. The launcher exits; the real server container runs `devaipod web`
///
/// If `DEVAIPOD_CONTAINER_NAME` is not set or the container name does not end
/// with `-launcher`, this is a no-op and the current process continues as the
/// server. The server container is always created (even with zero sources).
fn maybe_launch_server_with_sources() -> Result<()> {
    // Step (a): only act when running as a launcher container
    let container_name = match std::env::var("DEVAIPOD_CONTAINER_NAME") {
        Ok(name) => name,
        Err(_) => return Ok(()), // not in launcher pattern
    };

    // Must end with -launcher to be a launcher
    let server_name = match container_name.strip_suffix("-launcher") {
        Some(name) => name.to_string(),
        None => return Ok(()), // already the server container
    };

    // Step (b): load config and resolve sources (may be empty)
    let config = crate::config::load_config(None)?;
    let sources = config.resolve_sources();

    tracing::info!(
        "Launcher: creating server container '{}' with {} source mount(s)",
        server_name,
        sources.len()
    );

    // Step (c): inspect our own container to get image, mounts, env, etc.
    let socket_path = get_container_socket()?;
    let inspect_output = std::process::Command::new("podman")
        .args([
            "--url",
            &format!("unix://{}", socket_path.display()),
            "inspect",
            &container_name,
        ])
        .output()
        .context("Failed to run podman inspect on launcher container")?;

    if !inspect_output.status.success() {
        let stderr = String::from_utf8_lossy(&inspect_output.stderr);
        color_eyre::eyre::bail!(
            "podman inspect {} failed: {}",
            container_name,
            stderr.trim()
        );
    }

    let inspect_json: serde_json::Value =
        serde_json::from_slice(&inspect_output.stdout).context("Failed to parse podman inspect")?;

    // podman inspect returns an array; take the first element
    let info = inspect_json
        .as_array()
        .and_then(|a| a.first())
        .unwrap_or(&inspect_json);

    // Extract image
    let image = info
        .pointer("/ImageName")
        .or_else(|| info.pointer("/Image"))
        .and_then(|v| v.as_str())
        .unwrap_or("localhost/devaipod:latest")
        .to_string();

    // Extract existing mounts (bind mounts and volumes)
    let mut existing_mounts: Vec<String> = Vec::new();
    if let Some(mounts) = info.pointer("/Mounts").and_then(|v| v.as_array()) {
        for mount in mounts {
            let source = mount.get("Source").and_then(|v| v.as_str()).unwrap_or("");
            let destination = mount
                .get("Destination")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if source.is_empty() || destination.is_empty() {
                continue;
            }
            let options = mount.get("Options").and_then(|v| v.as_array());
            let is_ro = options
                .map(|opts| opts.iter().any(|o| o.as_str() == Some("ro")))
                .unwrap_or(false);
            let mount_type = mount.get("Type").and_then(|v| v.as_str()).unwrap_or("");
            // For named volumes, use the volume name as source
            let source_str = if mount_type == "volume" {
                mount.get("Name").and_then(|v| v.as_str()).unwrap_or(source)
            } else {
                source
            };
            if is_ro {
                existing_mounts.push(format!("{}:{}:ro", source_str, destination));
            } else {
                existing_mounts.push(format!("{}:{}", source_str, destination));
            }
        }
    }

    // Extract existing environment variables
    let mut existing_env: Vec<String> = Vec::new();
    if let Some(env_arr) = info.pointer("/Config/Env").and_then(|v| v.as_array()) {
        for env_val in env_arr {
            if let Some(env_str) = env_val.as_str() {
                // Skip internal vars that we'll set ourselves
                if env_str.starts_with("DEVAIPOD_CONTAINER_NAME=") {
                    continue;
                }
                existing_env.push(env_str.to_string());
            }
        }
    }

    // Check if privileged
    let is_privileged = info
        .pointer("/HostConfig/Privileged")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    // Get host port from env var
    let host_port = std::env::var("DEVAIPOD_HOST_PORT").unwrap_or_else(|_| "8080".to_string());

    // Step (d) + (e): build the podman run command for the server container
    let mut cmd = std::process::Command::new("podman");
    cmd.args([
        "--url",
        &format!("unix://{}", socket_path.display()),
        "run",
        "-d",
        "--name",
        &server_name,
        "--replace",
    ]);

    if is_privileged {
        cmd.arg("--privileged");
    }

    // Re-add existing mounts
    for mount in &existing_mounts {
        cmd.args(["-v", mount]);
    }

    // Re-add existing env vars
    for env_str in &existing_env {
        cmd.args(["-e", env_str]);
    }

    // Set the server container name
    cmd.args(["-e", &format!("DEVAIPOD_CONTAINER_NAME={}", server_name)]);

    // Publish the host port
    cmd.args(["-p", &format!("{}:8080", host_port)]);

    // Check for --add-host from extra hosts
    if let Some(extra_hosts) = info
        .pointer("/HostConfig/ExtraHosts")
        .and_then(|v| v.as_array())
    {
        for host in extra_hosts {
            if let Some(h) = host.as_str() {
                cmd.args(["--add-host", h]);
            }
        }
    }

    // Step (e): add source bind mounts
    for source in &sources {
        let mount_target = format!("/mnt/{}", source.name);
        let mount_str = match source.access {
            SourceAccess::Readonly => format!("{}:{}:ro", source.path.display(), mount_target),
            SourceAccess::Controlplane | SourceAccess::Agent => {
                format!("{}:{}", source.path.display(), mount_target)
            }
        };
        tracing::info!(
            "Source mount: {} -> {} ({:?})",
            source.path.display(),
            mount_target,
            source.access
        );
        cmd.args(["-v", &mount_str]);
    }

    // Step (e2): add generic bind mounts
    for bind in config.resolve_binds() {
        let arg = bind.to_podman_arg();
        tracing::info!("Bind mount: {}", arg);
        cmd.args(["-v", &arg]);
    }

    // Image and command
    cmd.arg(&image);
    cmd.args(["devaipod-server", "web", "--port", "8080"]);

    tracing::info!("Creating server container: {:?}", cmd);

    // Step (f): run the command
    let output = cmd.output().context("Failed to create server container")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        color_eyre::eyre::bail!("Failed to create server container: {}", stderr.trim());
    }

    tracing::info!(
        "Server container '{}' created successfully, launcher exiting",
        server_name
    );
    std::process::exit(0);
}

pub async fn run_web_server(port: u16, token: String, mcp_token: String) -> Result<()> {
    // Check if we should act as a launcher (inspect config, create server container with
    // source mounts, then exit). This is a no-op if DEVAIPOD_CONTAINER_NAME is not set
    // or if no [sources] are configured.
    maybe_launch_server_with_sources()?;

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

    // Create a shared pod cache and populate it before the server starts
    // accepting requests. The same Arc is given to both the router and the
    // background event watcher.
    let pod_cache: PodCache = Arc::new(tokio::sync::RwLock::new(Vec::new()));
    let pod_state_cache: PodStateCache = Arc::new(tokio::sync::RwLock::new(load_pod_state_cache()));

    if let Some(ref sp) = socket_path {
        refresh_pod_cache(
            sp,
            self_image_id.as_deref(),
            &pod_cache,
            Some(&pod_state_cache),
        )
        .await;
        tracing::info!("Initial pod cache populated");

        spawn_pod_event_watcher(
            sp.clone(),
            self_image_id.clone(),
            pod_cache.clone(),
            pod_state_cache.clone(),
        );
    }

    let app = build_app_with_cache(
        token.clone(),
        mcp_token,
        socket_path,
        self_image_id,
        pod_cache,
        pod_state_cache,
        port,
    );

    // Bind to [::] which accepts both IPv4 and IPv6 connections via dual-stack
    // (the Linux default).  Browsers typically try IPv6 first when resolving
    // "localhost", so binding IPv4-only would cause connection resets.
    let addr = format!("[::]:{}", port);
    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .with_context(|| format!("Failed to bind to {}", addr))?;

    // Print startup message with URL including token.
    // Use DEVAIPOD_HOST_PORT if set (the host-mapped port may differ from the
    // internal listen port when running inside a container, e.g. -p 8081:8080).
    let display_port = std::env::var("DEVAIPOD_HOST_PORT")
        .ok()
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(port);
    let url = format!(
        "http://127.0.0.1:{}/_devaipod/login?token={}",
        display_port, token
    );
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
        let app = build_app("test-token".into(), "test-mcp-token".into(), None, None);

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
        let app2 = build_app("test-token".into(), "test-mcp-token".into(), None, None);
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

        // Must include pod-data JSON element and external JS reference
        assert!(
            html.contains(r#"<script id="pod-data" type="application/json">"#),
            "wrapper must include pod-data JSON element"
        );
        assert!(
            html.contains(r#""urlName":"test-pod""#),
            "pod-data must contain urlName"
        );
        assert!(
            html.contains(r#""fullName":"devaipod-test-pod""#),
            "pod-data must contain fullName with devaipod- prefix"
        );
        assert!(
            html.contains(r#"src="/_devaipod/static/agent-wrapper.js""#),
            "wrapper must reference external agent-wrapper.js"
        );

        // Must NOT contain inline JS logic (the old toggleDone, fetchPodList, etc.)
        assert!(
            !html.contains("function fetchPodList"),
            "wrapper must not contain inline JS logic"
        );

        // With session deep-link
        let html = agent_iframe_wrapper("test-pod", "http://localhost:12345/abc123/session/s1");
        assert!(
            html.contains("http://localhost:12345/abc123/session/s1"),
            "wrapper must include session deep-link in iframe src"
        );

        // HTML-escaping: the title and button text must use HTML entities
        let html = agent_iframe_wrapper("<script>alert(1)</script>", "http://localhost:1/");
        assert!(
            html.contains("&lt;script&gt;"),
            "angle brackets in pod name must be HTML-escaped in visible elements"
        );
        // The JSON data block must not contain a literal "</script>" which would
        // prematurely close the script tag. We escape it to "<\/script>".
        assert!(
            !html.contains(r#"</script><script>"#),
            "JSON data must not contain literal </script> that closes the tag early"
        );
    }

    #[test]
    fn test_agent_wrapper_json_valid() {
        // Verify the embedded pod-data JSON is actually parseable.
        // This catches brace-escaping bugs (e.g. doubled {{ from format!()).
        for name in ["test-pod", "my-project-abc123", "devaipod-already-prefixed"] {
            let html = agent_iframe_wrapper(name, "http://localhost:1234/");
            let json_start = html
                .find(r#"<script id="pod-data" type="application/json">"#)
                .expect("must have pod-data script tag");
            let json_start = json_start + r#"<script id="pod-data" type="application/json">"#.len();
            let json_end = html[json_start..]
                .find("</script>")
                .expect("must have closing script tag");
            let json_str = &html[json_start..json_start + json_end];
            let parsed: serde_json::Value = serde_json::from_str(json_str).unwrap_or_else(|e| {
                panic!("pod-data JSON must be valid for name={name:?}: {e}\n  got: {json_str:?}")
            });
            assert!(parsed.get("urlName").is_some(), "must have urlName");
            assert!(parsed.get("fullName").is_some(), "must have fullName");
            let full = parsed["fullName"].as_str().unwrap();
            assert!(
                full.starts_with("devaipod-"),
                "fullName must have devaipod- prefix, got {full:?}"
            );
            assert!(
                !full.starts_with("devaipod-devaipod-"),
                "fullName must not have double prefix, got {full:?}"
            );
        }
    }

    #[test]
    fn test_agent_wrapper_js_syntax() {
        // Basic static check: the embedded JS file should be valid enough
        // that it doesn't have obvious syntax issues (unmatched braces,
        // template interpolation artifacts like {{ or }}).
        let js = AGENT_WRAPPER_JS;
        assert!(!js.is_empty(), "agent-wrapper.js must not be empty");
        assert!(
            !js.contains("{{"),
            "JS must not contain {{ (format!() artifact)"
        );
        assert!(
            !js.contains("}}"),
            "JS must not contain }} (format!() artifact)"
        );
        // Verify key functions exist
        for func in [
            "fetchPodList",
            "navigateToPod",
            "renderDropdown",
            "updateArrows",
            "fetchTitle",
            "fetchStatus",
            "toggleDone",
        ] {
            assert!(
                js.contains(func),
                "agent-wrapper.js must contain function {func}"
            );
        }
        // Verify it reads from pod-data
        assert!(
            js.contains("pod-data"),
            "JS must reference the pod-data element"
        );
    }

    #[test]
    fn test_extract_request_host() {
        // No headers → fallback to localhost
        let headers = HeaderMap::new();
        assert_eq!(extract_request_host(&headers), "localhost");

        // hostname:port → strip port
        let mut headers = HeaderMap::new();
        headers.insert(header::HOST, "xenon:8080".parse().unwrap());
        assert_eq!(extract_request_host(&headers), "xenon");

        // hostname without port
        let mut headers = HeaderMap::new();
        headers.insert(header::HOST, "xenon".parse().unwrap());
        assert_eq!(extract_request_host(&headers), "xenon");

        // IPv4 address
        let mut headers = HeaderMap::new();
        headers.insert(header::HOST, "192.168.1.5:8080".parse().unwrap());
        assert_eq!(extract_request_host(&headers), "192.168.1.5");

        // IPv6 literal with port
        let mut headers = HeaderMap::new();
        headers.insert(header::HOST, "[::1]:8080".parse().unwrap());
        assert_eq!(extract_request_host(&headers), "[::1]");

        // IPv6 literal without port
        let mut headers = HeaderMap::new();
        headers.insert(header::HOST, "[::1]".parse().unwrap());
        assert_eq!(extract_request_host(&headers), "[::1]");

        // X-Forwarded-Host takes priority over Host
        let mut headers = HeaderMap::new();
        headers.insert(header::HOST, "internal:8080".parse().unwrap());
        headers.insert("x-forwarded-host", "proxy.example.com:443".parse().unwrap());
        assert_eq!(extract_request_host(&headers), "proxy.example.com");
    }

    #[test]
    fn test_extract_request_scheme() {
        // No headers → default to http
        let headers = HeaderMap::new();
        assert_eq!(extract_request_scheme(&headers), "http");

        // X-Forwarded-Proto: https
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-proto", "https".parse().unwrap());
        assert_eq!(extract_request_scheme(&headers), "https");

        // X-Forwarded-Proto: http (explicit)
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-proto", "http".parse().unwrap());
        assert_eq!(extract_request_scheme(&headers), "http");
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

    /// MCP endpoint must return 401 without any authorization header.
    #[tokio::test]
    async fn test_mcp_endpoint_requires_auth() {
        let app = build_app("test-token".into(), "test-mcp-token".into(), None, None);

        let body = serde_json::to_string(&serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "ping"
        }))
        .unwrap();

        let req = Request::builder()
            .method("POST")
            .uri("/api/devaipod/mcp")
            .header("content-type", "application/json")
            .body(Body::from(body))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::UNAUTHORIZED,
            "MCP endpoint must return 401 without auth header"
        );
    }

    /// MCP endpoint must reject a wrong Bearer token.
    #[tokio::test]
    async fn test_mcp_endpoint_rejects_wrong_token() {
        let app = build_app("test-token".into(), "test-mcp-token".into(), None, None);

        let body = serde_json::to_string(&serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "ping"
        }))
        .unwrap();

        let req = Request::builder()
            .method("POST")
            .uri("/api/devaipod/mcp")
            .header("content-type", "application/json")
            .header("Authorization", "Bearer wrong-token")
            .body(Body::from(body))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::UNAUTHORIZED,
            "MCP endpoint must reject wrong Bearer token"
        );
    }

    /// MCP endpoint must reject the web API token — they are separate.
    #[tokio::test]
    async fn test_mcp_endpoint_rejects_web_token() {
        let app = build_app("test-token".into(), "test-mcp-token".into(), None, None);

        let body = serde_json::to_string(&serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "ping"
        }))
        .unwrap();

        let req = Request::builder()
            .method("POST")
            .uri("/api/devaipod/mcp")
            .header("content-type", "application/json")
            .header("Authorization", "Bearer test-token")
            .body(Body::from(body))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::UNAUTHORIZED,
            "Web API token must NOT grant access to MCP endpoint"
        );
    }

    /// MCP endpoint must accept the correct MCP token.
    #[tokio::test]
    async fn test_mcp_endpoint_accepts_valid_mcp_token() {
        let app = build_app("test-token".into(), "test-mcp-token".into(), None, None);

        let body = serde_json::to_string(&serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "ping"
        }))
        .unwrap();

        let req = Request::builder()
            .method("POST")
            .uri("/api/devaipod/mcp")
            .header("content-type", "application/json")
            .header("Authorization", "Bearer test-mcp-token")
            .body(Body::from(body))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "MCP endpoint must accept valid MCP token"
        );

        let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["result"], serde_json::json!({}));
    }

    /// MCP token must NOT grant access to regular API endpoints.
    #[tokio::test]
    async fn test_mcp_token_does_not_grant_api_access() {
        let app = build_app("test-token".into(), "test-mcp-token".into(), None, None);

        let req = Request::builder()
            .uri("/api/devaipod/advisor/status")
            .header("Authorization", "Bearer test-mcp-token")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::UNAUTHORIZED,
            "MCP token must NOT grant access to regular API endpoints"
        );
    }

    // =========================================================================
    // Gator-scopes endpoint tests (auth/routing layer)
    // =========================================================================

    /// GET /api/devaipod/pods/{name}/gator-scopes must require authentication.
    #[tokio::test]
    async fn test_gator_scopes_get_requires_auth() {
        let app = build_app("test-token".into(), "mcp".into(), None, None);

        let req = Request::builder()
            .uri("/api/devaipod/pods/test-pod/gator-scopes")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::UNAUTHORIZED,
            "GET gator-scopes must return 401 without auth"
        );
    }

    /// PUT /api/devaipod/pods/{name}/gator-scopes must require authentication.
    #[tokio::test]
    async fn test_gator_scopes_put_requires_auth() {
        let app = build_app("test-token".into(), "mcp".into(), None, None);

        let body = serde_json::to_string(&serde_json::json!({
            "scopes": { "gh": { "read": true } }
        }))
        .unwrap();

        let req = Request::builder()
            .method("PUT")
            .uri("/api/devaipod/pods/test-pod/gator-scopes")
            .header("content-type", "application/json")
            .body(Body::from(body))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::UNAUTHORIZED,
            "PUT gator-scopes must return 401 without auth"
        );
    }

    /// GET gator-scopes with valid auth should not return 401.
    #[tokio::test]
    async fn test_gator_scopes_get_with_auth() {
        let app = build_app("test-token".into(), "mcp".into(), None, None);

        let req = Request::builder()
            .uri("/api/devaipod/pods/test-pod/gator-scopes")
            .header("Authorization", "Bearer test-token")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_ne!(
            resp.status(),
            StatusCode::UNAUTHORIZED,
            "GET gator-scopes must not return 401 with valid auth"
        );
    }

    /// PUT gator-scopes with valid auth should not return 401.
    #[tokio::test]
    async fn test_gator_scopes_put_with_auth_and_valid_body() {
        let app = build_app("test-token".into(), "mcp".into(), None, None);

        let body = serde_json::to_string(&serde_json::json!({
            "scopes": {
                "gh": {
                    "read": true,
                    "repos": {
                        "myorg/myrepo": {
                            "read": true,
                            "create-draft": true,
                            "push-new-branch": true
                        }
                    }
                }
            }
        }))
        .unwrap();

        let req = Request::builder()
            .method("PUT")
            .uri("/api/devaipod/pods/test-pod/gator-scopes")
            .header("content-type", "application/json")
            .header("Authorization", "Bearer test-token")
            .body(Body::from(body))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_ne!(
            resp.status(),
            StatusCode::UNAUTHORIZED,
            "PUT gator-scopes must not return 401 with valid auth"
        );
    }

    /// MCP token must not grant access to gator-scopes endpoints.
    #[tokio::test]
    async fn test_gator_scopes_rejects_mcp_token() {
        let app = build_app("test-token".into(), "test-mcp-token".into(), None, None);

        let req = Request::builder()
            .uri("/api/devaipod/pods/test-pod/gator-scopes")
            .header("Authorization", "Bearer test-mcp-token")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::UNAUTHORIZED,
            "MCP token must not grant access to gator-scopes"
        );
    }

    #[test]
    fn test_cached_pod_state_roundtrip() {
        let state = CachedPodState {
            last_active_ts: Some(1700000000000),
            completion_status: Some("done".to_string()),
            title: Some("Fix the widget".to_string()),
            activity: Some("Idle".to_string()),
        };

        let json = serde_json::to_string(&state).unwrap();
        let deserialized: CachedPodState = serde_json::from_str(&json).unwrap();
        assert_eq!(state, deserialized);
    }

    #[test]
    fn test_cached_pod_state_empty_fields() {
        let state = CachedPodState::default();
        let json = serde_json::to_string(&state).unwrap();
        // All fields have skip_serializing_if, so default should produce "{}"
        assert_eq!(json, "{}");
        let deserialized: CachedPodState = serde_json::from_str(&json).unwrap();
        assert_eq!(state, deserialized);
    }

    #[test]
    fn test_cached_pod_state_partial_fields() {
        // Only some fields set — mirrors a pod that has a title but no
        // last_message_ts yet.
        let state = CachedPodState {
            title: Some("My task".to_string()),
            ..Default::default()
        };
        let json = serde_json::to_string(&state).unwrap();
        let deserialized: CachedPodState = serde_json::from_str(&json).unwrap();
        assert_eq!(state, deserialized);
        assert!(deserialized.last_active_ts.is_none());
        assert!(deserialized.completion_status.is_none());
    }

    #[test]
    fn test_pod_state_cache_map_roundtrip() {
        let mut map = HashMap::new();
        map.insert(
            "devaipod-foo-abc123".to_string(),
            CachedPodState {
                last_active_ts: Some(1700000000000),
                completion_status: Some("active".to_string()),
                title: Some("Working on foo".to_string()),
                activity: Some("Working".to_string()),
            },
        );
        map.insert(
            "devaipod-bar-def456".to_string(),
            CachedPodState {
                last_active_ts: Some(1699999000000),
                completion_status: Some("done".to_string()),
                title: None,
                activity: Some("Stopped".to_string()),
            },
        );

        let json = serde_json::to_string(&map).unwrap();
        let deserialized: HashMap<String, CachedPodState> = serde_json::from_str(&json).unwrap();
        assert_eq!(map, deserialized);
    }

    #[test]
    fn test_pod_state_cache_corrupt_json() {
        // Corrupt JSON should deserialize to nothing (load function returns
        // empty map). Test the pattern used in load_pod_state_cache.
        let corrupt = "not valid json {{{";
        let result: Result<HashMap<String, CachedPodState>, _> = serde_json::from_str(corrupt);
        assert!(result.is_err());
    }

    /// Control plane endpoint must require authentication.
    #[tokio::test]
    async fn test_control_plane_requires_auth() {
        let app = build_app("test-token".into(), "mcp".into(), None, None);

        let req = Request::builder()
            .uri("/api/devaipod/control-plane")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::UNAUTHORIZED,
            "control-plane must return 401 without auth"
        );
    }

    /// Control plane endpoint returns empty repos for an empty pod cache.
    #[tokio::test]
    async fn test_control_plane_empty_cache() {
        let app = build_app("test-token".into(), "mcp".into(), None, None);

        let req = Request::builder()
            .uri("/api/devaipod/control-plane")
            .header("Authorization", "Bearer test-token")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["repos"], serde_json::json!([]),);
    }

    /// Control plane groups pods by repo label.
    #[tokio::test]
    async fn test_control_plane_groups_by_repo() {
        let pod_cache: PodCache = Arc::new(tokio::sync::RwLock::new(vec![
            CachedPodInfo {
                name: "devaipod-foo-abc".to_string(),
                status: "Running".to_string(),
                created: "2025-01-01T00:00:00Z".to_string(),
                labels: Some(HashMap::from([
                    ("io.devaipod.repo".into(), "owner/repo-a".into()),
                    ("io.devaipod.task".into(), "Fix the bug".into()),
                ])),
                containers: None,
                needs_update: false,
                diagnostics: None,
            },
            CachedPodInfo {
                name: "devaipod-bar-def".to_string(),
                status: "Exited".to_string(),
                created: "2025-01-02T00:00:00Z".to_string(),
                labels: Some(HashMap::from([(
                    "io.devaipod.repo".into(),
                    "owner/repo-a".into(),
                )])),
                containers: None,
                needs_update: false,
                diagnostics: None,
            },
            CachedPodInfo {
                name: "devaipod-baz-ghi".to_string(),
                status: "Running".to_string(),
                created: "2025-01-03T00:00:00Z".to_string(),
                labels: Some(HashMap::from([
                    ("io.devaipod.repo".into(), "owner/repo-b".into()),
                    ("io.devaipod.mode".into(), "devcontainer".into()),
                ])),
                containers: None,
                needs_update: false,
                diagnostics: None,
            },
            CachedPodInfo {
                name: "devaipod-unlabeled-xyz".to_string(),
                status: "Running".to_string(),
                created: "2025-01-04T00:00:00Z".to_string(),
                labels: None,
                containers: None,
                needs_update: false,
                diagnostics: None,
            },
        ]));
        let pod_state_cache: PodStateCache = Arc::new(tokio::sync::RwLock::new(HashMap::new()));

        let app = build_app_with_cache(
            "test-token".into(),
            "mcp".into(),
            None,
            None,
            pod_cache,
            pod_state_cache,
            8080,
        );

        let req = Request::builder()
            .uri("/api/devaipod/control-plane")
            .header("Authorization", "Bearer test-token")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let repos = json["repos"].as_array().unwrap();

        // Three groups: owner/repo-a, owner/repo-b, unknown
        assert_eq!(repos.len(), 3, "expected 3 repo groups: {json:#}");

        // Repos with active agents first: owner/repo-a (1 running), unknown (1 running),
        // then owner/repo-b (0 agents, only devcontainer — active_count=0).
        // Among groups with active_count=1, alphabetical order applies.
        let repo_names: Vec<&str> = repos.iter().map(|r| r["repo"].as_str().unwrap()).collect();
        assert_eq!(repo_names, &["owner/repo-a", "unknown", "owner/repo-b"]);

        // repo-a should have 1 active, 2 agents, 0 devcontainers
        let repo_a = &repos[0];
        assert_eq!(repo_a["active_count"], 1);
        assert_eq!(repo_a["agents"].as_array().unwrap().len(), 2);
        assert_eq!(repo_a["devcontainers"].as_array().unwrap().len(), 0);
        // First agent should have the task label
        let agent0 = &repo_a["agents"][0];
        assert_eq!(agent0["task"], "Fix the bug");
        assert_eq!(agent0["short_name"], "foo-abc");
        assert!(agent0["is_running"].as_bool().unwrap());

        // repo-b should have 0 agents, 1 devcontainer
        let repo_b = &repos[2];
        assert_eq!(repo_b["active_count"], 0);
        assert_eq!(repo_b["agents"].as_array().unwrap().len(), 0);
        assert_eq!(repo_b["devcontainers"].as_array().unwrap().len(), 1);
        let dc0 = &repo_b["devcontainers"][0];
        assert_eq!(dc0["short_name"], "baz-ghi");
        assert!(dc0["is_running"].as_bool().unwrap());

        // "unknown" should have 1 active, 1 agent
        let unknown = &repos[1];
        assert_eq!(unknown["repo"], "unknown");
        assert_eq!(unknown["active_count"], 1);
        assert_eq!(unknown["agents"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn test_pod_state_cache_ignores_unknown_fields() {
        // Forward-compatible: extra fields in the JSON should be ignored
        let json = r#"{"devaipod-x":{"last_active_ts":42,"unknown_field":"ok"}}"#;
        let map: HashMap<String, CachedPodState> = serde_json::from_str(json).unwrap();
        assert_eq!(map["devaipod-x"].last_active_ts, Some(42));
    }

    #[test]
    fn test_run_request_deserializes_title() {
        let json = r#"{"source":"https://github.com/org/repo","task":"fix bug","title":"Fix the login bug"}"#;
        let req: RunRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.title.as_deref(), Some("Fix the login bug"));
        assert_eq!(req.source.as_deref(), Some("https://github.com/org/repo"));
        assert_eq!(req.task.as_deref(), Some("fix bug"));
    }

    #[test]
    fn test_run_request_title_is_optional() {
        let json = r#"{"source":"https://github.com/org/repo"}"#;
        let req: RunRequest = serde_json::from_str(json).unwrap();
        assert!(req.title.is_none());
    }

    #[test]
    fn test_parse_commit_log_normal() {
        let input = "abc123\0Fix the bug\0Alice\02026-01-01T00:00:00Z\n\
                      def456\0Add feature\0Bob\02026-01-02T00:00:00Z";
        let commits = super::parse_commit_log(input);
        assert_eq!(commits.len(), 2);
        assert_eq!(commits[0].sha, "abc123");
        assert_eq!(commits[0].message, "Fix the bug");
        assert_eq!(commits[0].author, "Alice");
        assert_eq!(commits[1].sha, "def456");
        assert_eq!(commits[1].author, "Bob");
    }

    #[test]
    fn test_parse_commit_log_empty() {
        assert!(super::parse_commit_log("").is_empty());
    }

    #[test]
    fn test_parse_commit_log_malformed_lines_skipped() {
        let input = "abc123\0Fix\n\
                      bad-line-no-nulls\n\
                      def456\0Add\0Bob\02026-01-01T00:00:00Z";
        let commits = super::parse_commit_log(input);
        // Only the last line has 4 fields
        assert_eq!(commits.len(), 1);
        assert_eq!(commits[0].sha, "def456");
    }

    #[test]
    fn test_format_review_message_with_comments() {
        let req = super::ReviewRequest {
            message: Some("Please fix the tests".to_string()),
            comments: vec![
                super::ReviewComment {
                    file: "src/main.rs".to_string(),
                    line: Some(42),
                    body: "This is wrong".to_string(),
                },
                super::ReviewComment {
                    file: "src/lib.rs".to_string(),
                    line: None,
                    body: "Missing docs".to_string(),
                },
            ],
        };
        let msg = super::format_review_message(&req);
        assert!(msg.contains("Code Review Feedback"));
        assert!(msg.contains("Please fix the tests"));
        assert!(msg.contains("`src/main.rs:42`"));
        assert!(msg.contains("`src/lib.rs`"));
        assert!(msg.contains("This is wrong"));
        assert!(msg.contains("Missing docs"));
    }

    #[test]
    fn test_format_review_message_no_comments() {
        let req = super::ReviewRequest {
            message: Some("Looks good overall".to_string()),
            comments: vec![],
        };
        let msg = super::format_review_message(&req);
        assert!(msg.contains("Looks good overall"));
        assert!(!msg.contains("Inline Comments"));
    }

    #[test]
    fn test_harvest_result_serialization() {
        let result = HarvestResult {
            repos: vec![HarvestedRepo {
                repo_name: "devaipod".to_string(),
                target_repo: "/home/user/src/devaipod".to_string(),
                remote_name: "devaipod/my-workspace".to_string(),
                branches: vec!["devaipod/my-workspace/devaipod/fix-auth".to_string()],
            }],
        };
        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("devaipod"));
        assert!(json.contains("fix-auth"));

        // Verify field names
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert!(parsed["repos"][0]["repo_name"].is_string());
        assert!(parsed["repos"][0]["target_repo"].is_string());
        assert!(parsed["repos"][0]["remote_name"].is_string());
        assert!(parsed["repos"][0]["branches"].is_array());
    }

    #[test]
    fn test_harvest_result_empty() {
        let result = HarvestResult { repos: vec![] };
        let json = serde_json::to_string(&result).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["repos"].as_array().unwrap().len(), 0);
    }
}
