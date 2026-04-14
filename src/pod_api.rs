//! Per-pod HTTP API server (sidecar container mode).
//!
//! Runs inside a sidecar container that mounts the workspace volumes directly,
//! replacing the current approach of exec'ing into containers for git/PTY
//! operations. All git commands run as direct `tokio::process::Command` calls
//! against the local filesystem, eliminating the ~200-500ms per-exec overhead.

use std::collections::{HashMap, VecDeque};
use std::convert::Infallible;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Path, Query, Request, State};
use axum::http::{StatusCode, header};
use axum::response::IntoResponse;
use axum::response::sse::{Event, Sse};
use axum::routing::{get, post};
use axum::{Json, Router};
use bollard::Docker;
use bollard::exec::{CreateExecOptions, ResizeExecOptions, StartExecResults};
use color_eyre::eyre::{Context, Result};
use futures_util::{SinkExt, Stream, StreamExt};
use serde::{Deserialize, Serialize};
use tokio::io::AsyncWriteExt;
use tokio::process::Command;
use tokio::sync::{Mutex, RwLock, broadcast};
use tower_http::compression::CompressionLayer;

use crate::acp_client::{AcpClient, AcpEvent};

// ---------------------------------------------------------------------------
// Shared state
// ---------------------------------------------------------------------------

/// Default directory for pod-api state (admin token, completion status, etc.).
///
/// In containers this is `/var/lib/devaipod/`; tests can override it via
/// the `DEVAIPOD_STATE_DIR` environment variable.
const DEFAULT_STATE_DIR: &str = "/var/lib/devaipod";

/// Path where pod-api persists its admin token.
/// The control plane retrieves this via `podman exec <container> cat <path>`.
pub(crate) const ADMIN_TOKEN_PATH: &str = "/var/lib/devaipod/pod-api-token";

/// Resolve the pod-api state directory.
///
/// Returns the value of `DEVAIPOD_STATE_DIR` if set, otherwise
/// [`DEFAULT_STATE_DIR`].  The caller is responsible for ensuring the
/// directory exists (it is pre-created in the container image).
fn state_dir() -> PathBuf {
    let dir = std::env::var("DEVAIPOD_STATE_DIR").unwrap_or_else(|_| DEFAULT_STATE_DIR.to_string());
    PathBuf::from(dir)
}

/// Server state shared across all handlers.
#[derive(Clone)]
struct AppState {
    /// Path to the workspace root (default `/workspaces`).
    workspace: Arc<PathBuf>,
    /// Broadcast sender for git filesystem change events.
    git_events_tx: broadcast::Sender<GitEvent>,
    /// PTY session manager.
    pty_sessions: PtySessionManager,
    /// Name of the workspace container to exec into for PTY sessions.
    workspace_container: String,
    /// Name of the agent container to exec into for agent PTY sessions.
    agent_container: String,
    /// Admin token for authenticating control plane requests (e.g. gator scope updates).
    /// Only the control plane knows this token; the agent does not.
    admin_token: String,
    /// ACP event broadcast channel for WebSocket clients.
    acp_event_tx: broadcast::Sender<AcpEvent>,
    /// ACP client for communicating with the agent (created lazily).
    acp_client: Arc<Mutex<Option<AcpClient>>>,
    /// Cached Initialized event so late-connecting WebSocket clients
    /// receive agent info (name, version, capabilities).
    initialized_event: Arc<Mutex<Option<AcpEvent>>>,
}

// ---------------------------------------------------------------------------
// Response / request types (independent of web.rs)
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
struct GitStatusResponse {
    exit_code: i32,
    output: String,
    files: Vec<GitStatusFile>,
}

#[derive(Debug, Serialize)]
struct GitStatusFile {
    status: String,
    path: String,
}

#[derive(Debug, Serialize)]
struct GitDiffResponse {
    exit_code: i32,
    diff: String,
}

#[derive(Debug, Serialize)]
struct GitCommitsResponse {
    exit_code: i32,
    commits: Vec<GitCommit>,
}

#[derive(Debug, Serialize)]
struct GitCommit {
    hash: String,
    message: String,
}

#[derive(Debug, Deserialize)]
struct GitLogQuery {
    base: Option<String>,
    head: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct GitLogEntry {
    sha: String,
    short_sha: String,
    message: String,
    author: String,
    author_email: String,
    timestamp: String,
    parents: Vec<String>,
}

#[derive(Debug, Serialize)]
struct GitLogResponse {
    commits: Vec<GitLogEntry>,
}

#[derive(Debug, Deserialize)]
struct GitDiffRangeQuery {
    base: String,
    head: String,
}

#[derive(Debug, Serialize)]
struct FileDiff {
    file: String,
    before: String,
    after: String,
    additions: u32,
    deletions: u32,
    status: &'static str,
}

#[derive(Debug, Serialize)]
struct GitDiffRangeResponse {
    files: Vec<FileDiff>,
}

#[derive(Debug, Serialize)]
struct GitFetchResponse {
    success: bool,
    message: String,
}

#[derive(Debug, Deserialize)]
struct GitPushRequest {
    branch: String,
}

#[derive(Debug, Serialize)]
struct GitPushResponse {
    success: bool,
    message: String,
}

// ---------------------------------------------------------------------------
// Git filesystem watcher (SSE event source)
// ---------------------------------------------------------------------------

/// Event emitted when the git state changes on disk.
#[derive(Clone, Debug, Serialize)]
struct GitEvent {
    head: String,
    timestamp: String,
}

/// Reads the current HEAD sha from the workspace. Returns an empty string on
/// failure (e.g. bare init with no commits yet).
async fn read_head_sha(workspace: &PathBuf) -> String {
    match run_git(workspace, &["rev-parse", "HEAD"]).await {
        Ok((0, stdout, _)) => String::from_utf8_lossy(&stdout).trim().to_string(),
        _ => String::new(),
    }
}

/// Background watcher that monitors `.git/` for ref changes and broadcasts
/// `GitEvent`s to all SSE subscribers.
///
/// The `RecommendedWatcher` is kept alive inside the spawned task — dropping it
/// would stop inotify watches.
struct GitWatcher;

impl GitWatcher {
    /// Spawn the background watcher task. Returns the broadcast sender that SSE
    /// handlers subscribe to.
    fn spawn(workspace: Arc<PathBuf>) -> broadcast::Sender<GitEvent> {
        let (tx, _) = broadcast::channel::<GitEvent>(64);
        let tx_clone = tx.clone();

        tokio::spawn(async move {
            if let Err(e) = Self::run(workspace, tx_clone).await {
                tracing::error!("GitWatcher exited with error: {e}");
            }
        });

        tx
    }

    async fn run(workspace: Arc<PathBuf>, tx: broadcast::Sender<GitEvent>) -> Result<()> {
        use notify::{RecursiveMode, Watcher};

        let (fs_tx, mut fs_rx) = tokio::sync::mpsc::channel::<()>(128);

        // The watcher must live as long as we want events, so we bind it here
        // and keep it alive for the lifetime of this task.
        let mut watcher = notify::recommended_watcher(move |res: notify::Result<notify::Event>| {
            match res {
                Ok(_) => {
                    // Non-blocking send; if the channel is full we just skip
                    // (the debounce will catch the next one).
                    let _ = fs_tx.try_send(());
                }
                Err(e) => tracing::warn!("filesystem watch error: {e}"),
            }
        })
        .context("Failed to create filesystem watcher")?;

        let git_dir = workspace.join(".git");

        // Watch .git/refs/ recursively (branch updates, remote refs, tags).
        let refs_dir = git_dir.join("refs");
        if refs_dir.is_dir() {
            watcher
                .watch(&refs_dir, RecursiveMode::Recursive)
                .with_context(|| format!("Failed to watch {}", refs_dir.display()))?;
        }

        // Watch .git/HEAD (branch switches).
        let head_file = git_dir.join("HEAD");
        if head_file.exists() {
            watcher
                .watch(&head_file, RecursiveMode::NonRecursive)
                .with_context(|| format!("Failed to watch {}", head_file.display()))?;
        }

        // Watch .git/FETCH_HEAD if it exists (created on first fetch).
        let fetch_head = git_dir.join("FETCH_HEAD");
        if fetch_head.exists()
            && let Err(e) = watcher.watch(&fetch_head, RecursiveMode::NonRecursive)
        {
            tracing::debug!("FETCH_HEAD watch skipped (non-critical): {e}");
        }

        tracing::info!("GitWatcher started for {}", workspace.display());

        // Debounced event loop: collect events for 200ms, then emit one
        // GitEvent with the current HEAD.
        loop {
            // Wait for at least one filesystem notification.
            if fs_rx.recv().await.is_none() {
                // Channel closed — watcher was dropped.
                break;
            }

            // Debounce: drain any further events that arrive within 200ms.
            tokio::time::sleep(Duration::from_millis(200)).await;
            while fs_rx.try_recv().is_ok() {}

            let head = read_head_sha(&workspace).await;
            let event = GitEvent {
                head,
                timestamp: chrono::Utc::now().to_rfc3339(),
            };

            // Ignore send errors (no active receivers is fine).
            let _ = tx.send(event);
        }

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// SSE handler
// ---------------------------------------------------------------------------

/// `GET /git/events` — Server-Sent Events stream of git state changes.
///
/// Sends an initial event with the current HEAD sha, then pushes `git.updated`
/// events whenever the filesystem watcher detects ref changes. A keepalive
/// comment is sent every 30 seconds to prevent proxy timeouts.
async fn git_events_sse(
    State(state): State<AppState>,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    let workspace = state.workspace.clone();
    let mut rx = state.git_events_tx.subscribe();

    let stream = async_stream::stream! {
        // Send initial HEAD so the client has a baseline.
        let head = read_head_sha(&workspace).await;
        let initial = GitEvent {
            head,
            timestamp: chrono::Utc::now().to_rfc3339(),
        };
        if let Ok(data) = serde_json::to_string(&initial) {
            yield Ok(Event::default().event("git.updated").data(data));
        }

        // Stream subsequent events from the broadcast channel.
        loop {
            match rx.recv().await {
                Ok(event) => {
                    if let Ok(data) = serde_json::to_string(&event) {
                        yield Ok(Event::default().event("git.updated").data(data));
                    }
                }
                Err(broadcast::error::RecvError::Lagged(n)) => {
                    tracing::debug!("SSE client lagged, skipped {n} events");
                    // Continue — the next event will have the latest HEAD anyway.
                }
                Err(broadcast::error::RecvError::Closed) => {
                    break;
                }
            }
        }
    };

    Sse::new(stream).keep_alive(
        axum::response::sse::KeepAlive::new()
            .interval(Duration::from_secs(30))
            .text("keepalive"),
    )
}

// ---------------------------------------------------------------------------
// Validation helpers
// ---------------------------------------------------------------------------

/// Validate that a string looks like a safe git ref (no shell metacharacters).
fn is_valid_git_ref(s: &str) -> bool {
    !s.is_empty()
        && !s.contains("..")
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '/' | '.' | '_' | '~' | '^'))
}

/// Maximum number of files allowed in a diff-range response.
const DIFF_RANGE_MAX_FILES: usize = 100;

// ---------------------------------------------------------------------------
// Git command helpers
// ---------------------------------------------------------------------------

/// Run a git command in the workspace directory and return (exit_code, stdout, stderr).
async fn run_git(workspace: &PathBuf, args: &[&str]) -> Result<(i32, Vec<u8>, Vec<u8>)> {
    let output = Command::new("git")
        // The workspace is bind-mounted into the container and may be owned by a
        // different UID than the pod-api process. Tell git to trust it regardless;
        // we're inside a container where the mount was deliberate.
        .args(["-c", "safe.directory=*"])
        .args(args)
        .current_dir(workspace)
        .output()
        .await
        .with_context(|| format!("Failed to spawn git {}", args.first().unwrap_or(&"")))?;

    let exit_code = output.status.code().unwrap_or(-1);
    Ok((exit_code, output.stdout, output.stderr))
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// `GET /git/status` — `git status --porcelain`
async fn git_status(State(state): State<AppState>) -> Result<Json<GitStatusResponse>, StatusCode> {
    let (exit_code, stdout, _stderr) = run_git(&state.workspace, &["status", "--porcelain"])
        .await
        .map_err(|e| {
            tracing::error!("git status failed: {e}");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    let output = String::from_utf8_lossy(&stdout).to_string();

    let files: Vec<GitStatusFile> = output
        .lines()
        .filter(|line| !line.is_empty())
        .map(|line| {
            let status = line.chars().take(2).collect::<String>().trim().to_string();
            let path = line.chars().skip(3).collect::<String>();
            GitStatusFile { status, path }
        })
        .collect();

    Ok(Json(GitStatusResponse {
        exit_code,
        output,
        files,
    }))
}

/// `GET /git/diff` — `git diff HEAD`
async fn git_diff(State(state): State<AppState>) -> Result<Json<GitDiffResponse>, StatusCode> {
    let (exit_code, stdout, _stderr) =
        run_git(&state.workspace, &["diff", "HEAD"])
            .await
            .map_err(|e| {
                tracing::error!("git diff failed: {e}");
                StatusCode::INTERNAL_SERVER_ERROR
            })?;

    let diff = String::from_utf8_lossy(&stdout).to_string();

    Ok(Json(GitDiffResponse { exit_code, diff }))
}

/// `GET /git/commits` — `git log --oneline -20`
async fn git_commits(
    State(state): State<AppState>,
) -> Result<Json<GitCommitsResponse>, StatusCode> {
    let (exit_code, stdout, _stderr) = run_git(&state.workspace, &["log", "--oneline", "-20"])
        .await
        .map_err(|e| {
            tracing::error!("git log failed: {e}");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    let output = String::from_utf8_lossy(&stdout);

    let commits: Vec<GitCommit> = output
        .lines()
        .filter(|line| !line.is_empty())
        .filter_map(|line| {
            let mut parts = line.splitn(2, ' ');
            let hash = parts.next()?.to_string();
            let message = parts.next().unwrap_or("").to_string();
            Some(GitCommit { hash, message })
        })
        .collect();

    Ok(Json(GitCommitsResponse { exit_code, commits }))
}

/// `GET /git/log` — structured git log with optional range filtering.
///
/// When no `base`/`head` are provided, shows recent commits from HEAD.
/// The pod-api mounts the agent's workspace directly, so HEAD reflects
/// the agent's latest work. Returns an empty list if the ref doesn't exist.
async fn git_log(
    State(state): State<AppState>,
    Query(params): Query<GitLogQuery>,
) -> Result<Json<GitLogResponse>, (StatusCode, String)> {
    if let Some(ref base) = params.base
        && !is_valid_git_ref(base)
    {
        return Err((
            StatusCode::BAD_REQUEST,
            format!("Invalid git ref for 'base': {base}"),
        ));
    }
    if let Some(ref head) = params.head
        && !is_valid_git_ref(head)
    {
        return Err((
            StatusCode::BAD_REQUEST,
            format!("Invalid git ref for 'head': {head}"),
        ));
    }

    // Build the format arg and range specification.
    let format_arg = "--format=%H%x00%h%x00%s%n%b%x00%an%x00%ae%x00%aI%x00%P%x1e".to_string();
    let range_arg: String;

    let mut args: Vec<&str> = vec!["log", &format_arg];

    match (&params.base, &params.head) {
        (Some(base), Some(head)) => {
            range_arg = format!("{base}..{head}");
            args.push(&range_arg);
            args.push("-500");
        }
        (None, Some(head)) => {
            args.push(head.as_str());
            args.push("-50");
        }
        (Some(_), None) => {
            return Err((
                StatusCode::BAD_REQUEST,
                "'base' requires 'head' to also be specified".to_string(),
            ));
        }
        // Default: show recent commits on current branch.
        // The pod-api container mounts the agent's workspace directly,
        // so HEAD is already the agent's latest commit.
        (None, None) => {
            args.push("HEAD");
            args.push("-50");
        }
    }

    let (exit_code, stdout, stderr) = run_git(&state.workspace, &args).await.map_err(|e| {
        tracing::error!("git log failed: {e}");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to run git log: {e}"),
        )
    })?;

    if exit_code != 0 {
        let stderr_text = String::from_utf8_lossy(&stderr);
        // Unknown ref → empty list rather than 500.
        if stderr_text.contains("unknown revision") || stderr_text.contains("bad default revision")
        {
            return Ok(Json(GitLogResponse {
                commits: Vec::new(),
            }));
        }
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("git log failed: {stderr_text}"),
        ));
    }

    let output = String::from_utf8_lossy(&stdout);

    if output.trim().is_empty() {
        return Ok(Json(GitLogResponse {
            commits: Vec::new(),
        }));
    }

    let commits: Vec<GitLogEntry> = output
        .split('\x1e')
        .filter(|record| !record.trim().is_empty())
        .filter_map(|record| {
            let fields: Vec<&str> = record.trim().splitn(7, '\0').collect();
            if fields.len() < 7 {
                tracing::warn!(
                    "Skipping malformed git log record ({} fields): {:?}",
                    fields.len(),
                    record
                );
                return None;
            }
            Some(GitLogEntry {
                sha: fields[0].to_string(),
                short_sha: fields[1].to_string(),
                message: fields[2].trim().to_string(),
                author: fields[3].to_string(),
                author_email: fields[4].to_string(),
                timestamp: fields[5].to_string(),
                parents: fields[6]
                    .split_whitespace()
                    .filter(|s| !s.is_empty())
                    .map(|s| s.to_string())
                    .collect(),
            })
        })
        .collect();

    Ok(Json(GitLogResponse { commits }))
}

/// `GET /git/diff-range?base=X&head=Y` — structured per-file diffs.
///
/// Returns before/after file content, addition/deletion counts, and change
/// status for each file changed between `base` and `head`. File content is
/// fetched concurrently via `git show ref:path`.
async fn git_diff_range(
    State(state): State<AppState>,
    Query(params): Query<GitDiffRangeQuery>,
) -> Result<Json<GitDiffRangeResponse>, (StatusCode, String)> {
    if !is_valid_git_ref(&params.base) {
        return Err((
            StatusCode::BAD_REQUEST,
            format!("Invalid git ref for 'base': {}", params.base),
        ));
    }
    if !is_valid_git_ref(&params.head) {
        return Err((
            StatusCode::BAD_REQUEST,
            format!("Invalid git ref for 'head': {}", params.head),
        ));
    }

    // Get name-status and numstat in parallel.
    let ws = &state.workspace;
    let ns_args = [
        "diff",
        "--name-status",
        "--no-renames",
        &params.base,
        &params.head,
    ];
    let num_args = [
        "diff",
        "--numstat",
        "--no-renames",
        &params.base,
        &params.head,
    ];
    let (ns_result, num_result) = tokio::join!(run_git(ws, &ns_args), run_git(ws, &num_args),);

    let (ns_exit, ns_stdout, ns_stderr) = ns_result.map_err(|e| {
        tracing::error!("git diff --name-status failed: {e}");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to run git diff --name-status: {e}"),
        )
    })?;

    if ns_exit != 0 {
        let stderr_text = String::from_utf8_lossy(&ns_stderr);
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("git diff --name-status failed: {stderr_text}"),
        ));
    }

    let (num_exit, num_stdout, num_stderr) = num_result.map_err(|e| {
        tracing::error!("git diff --numstat failed: {e}");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to run git diff --numstat: {e}"),
        )
    })?;

    if num_exit != 0 {
        let stderr_text = String::from_utf8_lossy(&num_stderr);
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("git diff --numstat failed: {stderr_text}"),
        ));
    }

    let ns_output = String::from_utf8_lossy(&ns_stdout);
    let num_output = String::from_utf8_lossy(&num_stdout);

    if ns_output.trim().is_empty() {
        return Ok(Json(GitDiffRangeResponse { files: Vec::new() }));
    }

    // Parse --name-status
    let mut file_statuses: Vec<(String, &'static str)> = Vec::new();
    for line in ns_output.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let mut parts = line.splitn(2, '\t');
        let status_char = parts.next().unwrap_or("").trim();
        let file_path = match parts.next() {
            Some(p) => p.trim(),
            None => continue,
        };
        let status: &'static str = match status_char {
            "A" => "added",
            "D" => "deleted",
            _ => "modified",
        };
        file_statuses.push((file_path.to_string(), status));
    }

    if file_statuses.len() > DIFF_RANGE_MAX_FILES {
        return Err((
            StatusCode::UNPROCESSABLE_ENTITY,
            format!(
                "Too many changed files ({}, max {DIFF_RANGE_MAX_FILES})",
                file_statuses.len(),
            ),
        ));
    }

    // Parse --numstat
    let mut numstat_map: HashMap<String, (u32, u32)> = HashMap::new();
    for line in num_output.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let fields: Vec<&str> = line.splitn(3, '\t').collect();
        if fields.len() < 3 {
            continue;
        }
        let adds = fields[0].parse::<u32>().unwrap_or(0);
        let dels = fields[1].parse::<u32>().unwrap_or(0);
        numstat_map.insert(fields[2].trim().to_string(), (adds, dels));
    }

    // Fetch before/after content concurrently using `git show ref:path`.
    // Since we're running direct commands (no exec overhead), we can spawn
    // one task per file and it's still fast.
    let base_files: Vec<&str> = file_statuses
        .iter()
        .filter(|(_, status)| *status != "added")
        .map(|(path, _)| path.as_str())
        .collect();
    let head_files: Vec<&str> = file_statuses
        .iter()
        .filter(|(_, status)| *status != "deleted")
        .map(|(path, _)| path.as_str())
        .collect();

    let (base_contents, head_contents) = tokio::join!(
        fetch_file_contents(ws, &params.base, &base_files),
        fetch_file_contents(ws, &params.head, &head_files),
    );

    let mut files = Vec::with_capacity(file_statuses.len());
    for (file_path, status) in &file_statuses {
        let (adds, dels) = numstat_map
            .get(file_path.as_str())
            .copied()
            .unwrap_or((0, 0));
        files.push(FileDiff {
            file: file_path.clone(),
            before: base_contents
                .get(file_path.as_str())
                .cloned()
                .unwrap_or_default(),
            after: head_contents
                .get(file_path.as_str())
                .cloned()
                .unwrap_or_default(),
            additions: adds,
            deletions: dels,
            status,
        });
    }

    Ok(Json(GitDiffRangeResponse { files }))
}

/// Fetch the content of multiple files at a given git ref, concurrently.
///
/// Returns a map from file path to content. Missing files map to empty strings.
#[allow(clippy::ptr_arg)] // PathBuf needed: spawned tasks clone it, &Path would require 'static
async fn fetch_file_contents(
    workspace: &PathBuf,
    git_ref: &str,
    files: &[&str],
) -> HashMap<String, String> {
    if files.is_empty() {
        return HashMap::new();
    }

    let mut tasks = Vec::with_capacity(files.len());
    for &file in files {
        let ws = workspace.clone();
        let ref_path = format!("{git_ref}:{file}");
        let file_owned = file.to_string();
        tasks.push(tokio::spawn(async move {
            let output = Command::new("git")
                .args(["show", &ref_path])
                .current_dir(&ws)
                .output()
                .await;
            let content = match output {
                Ok(o) if o.status.success() => String::from_utf8(o.stdout)
                    .unwrap_or_else(|e| String::from_utf8_lossy(&e.into_bytes()).into_owned()),
                _ => String::new(),
            };
            (file_owned, content)
        }));
    }

    let mut map = HashMap::with_capacity(tasks.len());
    for task in tasks {
        if let Ok((path, content)) = task.await {
            map.insert(path, content);
        }
    }
    map
}

/// `POST /git/fetch-agent` — `git fetch agent`
async fn git_fetch_agent(
    State(state): State<AppState>,
) -> Result<Json<GitFetchResponse>, (StatusCode, String)> {
    let (exit_code, _stdout, stderr) = run_git(&state.workspace, &["fetch", "agent"])
        .await
        .map_err(|e| {
            tracing::error!("git fetch agent failed: {e}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to run git fetch agent: {e}"),
            )
        })?;

    if exit_code != 0 {
        let stderr_text = String::from_utf8_lossy(&stderr);
        return Ok(Json(GitFetchResponse {
            success: false,
            message: format!("git fetch agent failed: {stderr_text}"),
        }));
    }

    Ok(Json(GitFetchResponse {
        success: true,
        message: "Fetched latest agent commits".to_string(),
    }))
}

/// `POST /git/push` — `git push origin <branch>`
async fn git_push(
    State(state): State<AppState>,
    Json(body): Json<GitPushRequest>,
) -> Result<Json<GitPushResponse>, (StatusCode, String)> {
    if !is_valid_git_ref(&body.branch) {
        return Err((
            StatusCode::BAD_REQUEST,
            format!("Invalid branch name: {}", body.branch),
        ));
    }

    let (exit_code, _stdout, stderr) = run_git(&state.workspace, &["push", "origin", &body.branch])
        .await
        .map_err(|e| {
            tracing::error!("git push failed: {e}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to run git push: {e}"),
            )
        })?;

    if exit_code != 0 {
        let stderr_text = String::from_utf8_lossy(&stderr);
        return Ok(Json(GitPushResponse {
            success: false,
            message: format!("git push failed: {stderr_text}"),
        }));
    }

    Ok(Json(GitPushResponse {
        success: true,
        message: format!("Pushed branch '{}' to origin", body.branch),
    }))
}

// ---------------------------------------------------------------------------
// PTY data structures and session management
// ---------------------------------------------------------------------------

/// Maximum size of the output ring buffer per session (2 MB).
const MAX_RING_BUFFER_BYTES: usize = 2 * 1024 * 1024;

/// Capacity of the broadcast channel per session.
const BROADCAST_CAPACITY: usize = 256;

/// How long to keep exited sessions before cleanup (5 minutes).
const EXITED_SESSION_TTL: Duration = Duration::from_secs(5 * 60);

/// PTY session info returned by most endpoints.
#[derive(Debug, Serialize, Clone)]
struct PtyInfo {
    id: String,
    title: String,
    command: String,
    args: Vec<String>,
    cwd: String,
    status: String,
    pid: Option<u64>,
    /// Which container this PTY session is running in (`"agent"` or `"workspace"`).
    container: String,
}

/// Request body for `POST /pty`.
#[derive(Debug, Deserialize)]
struct PtyCreateInput {
    command: Option<String>,
    args: Option<Vec<String>>,
    cwd: Option<String>,
    title: Option<String>,
    env: Option<HashMap<String, String>>,
    /// Target container: `"agent"` or `"workspace"`. Defaults to `"agent"`.
    container: Option<String>,
}

/// Request body for `PUT /pty/{pty_id}`.
#[derive(Debug, Deserialize)]
struct PtyUpdateInput {
    title: Option<String>,
    size: Option<PtySize>,
}

/// Terminal dimensions.
#[derive(Debug, Deserialize)]
struct PtySize {
    rows: u16,
    cols: u16,
}

/// Query parameters for the WebSocket connect endpoint.
#[derive(Debug, Deserialize)]
struct ConnectQuery {
    cursor: Option<u64>,
}

/// Mutable output state for a single PTY session, behind its own lock so that
/// the output reader task does not require a write lock on the global sessions map.
struct SessionOutput {
    /// Ring buffer of output bytes (VecDeque for O(1) front drain).
    ring_buffer: VecDeque<u8>,
    /// Total bytes written since session start (monotonically increasing cursor).
    cursor: u64,
    /// Session status: "running" or "exited".
    status: String,
    /// When the session exited (for cleanup TTL). `None` while running.
    exited_at: Option<std::time::Instant>,
}

/// Internal state for a single PTY session.
struct PtySession {
    /// Metadata returned via the REST API.
    info: PtyInfo,
    /// The bollard exec ID for resize operations.
    exec_id: String,
    /// Per-session mutable output state (ring buffer, cursor, status).
    output: Arc<tokio::sync::Mutex<SessionOutput>>,
    /// Broadcast channel sender for streaming output to WebSocket clients.
    output_tx: broadcast::Sender<(Vec<u8>, u64)>,
    /// Sender half of the channel used to forward WebSocket input to PTY stdin.
    /// `None` once the child process has exited or stdin is closed.
    stdin_tx: Option<tokio::sync::mpsc::Sender<Vec<u8>>>,
}

impl PtySession {
    /// Return a snapshot of the session info with the current status.
    async fn info(&self) -> PtyInfo {
        let output = self.output.lock().await;
        let mut info = self.info.clone();
        info.status = output.status.clone();
        info
    }
}

/// Manages PTY sessions. Internally wraps an `Arc` so it is cheap to clone.
#[derive(Clone)]
struct PtySessionManager {
    sessions: Arc<RwLock<HashMap<String, PtySession>>>,
}

impl PtySessionManager {
    fn new() -> Self {
        Self {
            sessions: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

/// Generate a short random session ID like `pty_a1b2c3d4e5f6`.
fn generate_pty_id() -> String {
    use rand::Rng;
    let mut rng = rand::rng();
    let suffix: u64 = rng.random::<u64>() & 0xFFFF_FFFF_FFFF;
    format!("pty_{suffix:x}")
}

/// Remove sessions that have been in "exited" state for longer than `EXITED_SESSION_TTL`.
async fn cleanup_stale_pty_sessions(sessions: &mut HashMap<String, PtySession>) {
    let now = std::time::Instant::now();
    let mut to_remove = Vec::new();
    for (id, session) in sessions.iter() {
        let output = session.output.lock().await;
        if let Some(exited_at) = output.exited_at
            && now.duration_since(exited_at) > EXITED_SESSION_TTL
        {
            to_remove.push(id.clone());
        }
    }
    for id in &to_remove {
        sessions.remove(id);
    }
    if !to_remove.is_empty() {
        tracing::info!("Cleaned up {} stale exited PTY sessions", to_remove.len());
    }
}

// ---------------------------------------------------------------------------
// Docker/Podman connection helper
// ---------------------------------------------------------------------------

/// Connect to the container runtime socket (podman or docker).
fn connect_docker() -> std::result::Result<Docker, StatusCode> {
    let socket_path = crate::podman::get_container_socket().map_err(|e| {
        tracing::error!("No container socket: {}", e);
        StatusCode::SERVICE_UNAVAILABLE
    })?;
    Docker::connect_with_unix(
        &format!("unix://{}", socket_path.display()),
        120,
        bollard::API_DEFAULT_VERSION,
    )
    .map_err(|e| {
        tracing::error!("Failed to connect to container socket: {}", e);
        StatusCode::SERVICE_UNAVAILABLE
    })
}

// ---------------------------------------------------------------------------
// PTY handlers
// ---------------------------------------------------------------------------

/// `GET /pty` — list all sessions.
async fn pty_list(State(state): State<AppState>) -> Json<Vec<PtyInfo>> {
    let sessions = state.pty_sessions.sessions.read().await;
    let mut infos = Vec::with_capacity(sessions.len());
    for s in sessions.values() {
        infos.push(s.info().await);
    }
    Json(infos)
}

/// `POST /pty` — create a new PTY session via bollard exec into a container.
///
/// The `container` field in the request body selects the target: `"workspace"` for
/// the workspace container, anything else (including absent) defaults to the agent
/// container. This means a minimal SDK (which cannot add extra fields) naturally
/// targets the agent container, while the workspace terminal frontend explicitly
/// passes `"workspace"`.
async fn pty_create(
    State(state): State<AppState>,
    Json(input): Json<PtyCreateInput>,
) -> Result<(StatusCode, Json<PtyInfo>), (StatusCode, String)> {
    let command = input.command.unwrap_or_else(|| "/bin/bash".to_string());
    let args = input.args.unwrap_or_default();
    let cwd = input
        .cwd
        .unwrap_or_else(|| state.workspace.to_string_lossy().into_owned());
    let title = input.title.unwrap_or_else(|| {
        let full = format!("{} {}", command, args.join(" "));
        full.trim().to_string()
    });
    let env = input.env.unwrap_or_default();

    // Resolve which container to exec into.
    let is_workspace = input.container.as_deref().is_some_and(|c| c == "workspace");
    let (target_container, container_label) = if is_workspace {
        (&state.workspace_container, "workspace")
    } else {
        (&state.agent_container, "agent")
    };

    if target_container.is_empty() {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            format!("No {container_label} container configured (--{container_label}-container)"),
        ));
    }

    let docker = connect_docker()
        .map_err(|sc| (sc, "Failed to connect to container runtime".to_string()))?;

    // Build the command vector for exec.
    let mut cmd: Vec<String> = vec![command.clone()];
    cmd.extend(args.clone());

    // Build environment variables list.
    let mut env_vec: Vec<String> = vec![
        "TERM=xterm-256color".to_string(),
        "COLORTERM=truecolor".to_string(),
    ];
    for (k, v) in &env {
        env_vec.push(format!("{k}={v}"));
    }

    let exec = docker
        .create_exec(
            target_container,
            CreateExecOptions {
                cmd: Some(cmd),
                attach_stdin: Some(true),
                attach_stdout: Some(true),
                attach_stderr: Some(true),
                tty: Some(true),
                working_dir: Some(cwd.clone()),
                env: Some(env_vec),
                ..Default::default()
            },
        )
        .await
        .map_err(|e| {
            tracing::error!("Failed to create exec: {e}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to create exec: {e}"),
            )
        })?;

    let exec_id = exec.id.clone();

    let start_result = docker
        .start_exec(
            &exec.id,
            Some(bollard::exec::StartExecOptions {
                detach: false,
                tty: true,
                ..Default::default()
            }),
        )
        .await
        .map_err(|e| {
            tracing::error!("Failed to start exec: {e}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to start exec: {e}"),
            )
        })?;

    let session_id = generate_pty_id();
    let (output_tx, _) = broadcast::channel::<(Vec<u8>, u64)>(BROADCAST_CAPACITY);
    let (stdin_tx, mut stdin_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(64);

    let info = PtyInfo {
        id: session_id.clone(),
        title,
        command,
        args,
        cwd,
        status: "running".to_string(),
        pid: None,
        container: container_label.to_string(),
    };

    let session_output = Arc::new(tokio::sync::Mutex::new(SessionOutput {
        ring_buffer: VecDeque::new(),
        cursor: 0,
        status: "running".to_string(),
        exited_at: None,
    }));

    let session = PtySession {
        info: info.clone(),
        exec_id: exec_id.clone(),
        output: session_output.clone(),
        output_tx: output_tx.clone(),
        stdin_tx: Some(stdin_tx),
    };

    {
        let mut sessions = state.pty_sessions.sessions.write().await;
        cleanup_stale_pty_sessions(&mut sessions).await;
        sessions.insert(session_id.clone(), session);
    }

    match start_result {
        StartExecResults::Attached {
            mut output,
            mut input,
        } => {
            // Spawn stdin writer: forward bytes from the mpsc channel to exec stdin.
            tokio::spawn(async move {
                while let Some(data) = stdin_rx.recv().await {
                    if input.write_all(&data).await.is_err() {
                        break;
                    }
                }
            });

            // Spawn output reader: read from exec output and distribute to ring buffer + broadcast.
            let sid = session_id.clone();
            let tx = output_tx;
            let so = session_output;
            tokio::spawn(async move {
                while let Some(chunk) = output.next().await {
                    let bytes = match &chunk {
                        Ok(bollard::container::LogOutput::StdOut { message }) => message.to_vec(),
                        Ok(bollard::container::LogOutput::StdErr { message }) => message.to_vec(),
                        Ok(bollard::container::LogOutput::Console { message }) => message.to_vec(),
                        Ok(_) => continue,
                        Err(e) => {
                            tracing::debug!("Exec output stream ended for {sid}: {e}");
                            break;
                        }
                    };
                    if bytes.is_empty() {
                        continue;
                    }

                    let mut out = so.lock().await;
                    out.ring_buffer.extend(bytes.iter());
                    out.cursor += bytes.len() as u64;

                    if out.ring_buffer.len() > MAX_RING_BUFFER_BYTES {
                        let overflow = out.ring_buffer.len() - MAX_RING_BUFFER_BYTES;
                        out.ring_buffer.drain(..overflow);
                    }

                    let _ = tx.send((bytes, out.cursor));
                }

                let mut out = so.lock().await;
                out.status = "exited".to_string();
                out.exited_at = Some(std::time::Instant::now());
                tracing::info!("PTY session {sid} exited");
            });
        }
        StartExecResults::Detached => {
            // Remove the session we just inserted — detached exec is unusable for PTY.
            let mut sessions = state.pty_sessions.sessions.write().await;
            sessions.remove(&session_id);
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                "Exec started in detached mode unexpectedly".to_string(),
            ));
        }
    }

    Ok((StatusCode::CREATED, Json(info)))
}

/// `GET /pty/{pty_id}` — get session info.
async fn pty_get(
    Path(pty_id): Path<String>,
    State(state): State<AppState>,
) -> Result<Json<PtyInfo>, StatusCode> {
    let sessions = state.pty_sessions.sessions.read().await;
    let session = sessions.get(&pty_id).ok_or(StatusCode::NOT_FOUND)?;
    Ok(Json(session.info().await))
}

/// `PUT /pty/{pty_id}` — update session (resize and/or rename).
async fn pty_update(
    Path(pty_id): Path<String>,
    State(state): State<AppState>,
    Json(input): Json<PtyUpdateInput>,
) -> Result<Json<PtyInfo>, (StatusCode, String)> {
    // Read the exec_id under a read lock (no need to hold a write lock for resize).
    let exec_id = {
        let sessions = state.pty_sessions.sessions.read().await;
        let session = sessions
            .get(&pty_id)
            .ok_or((StatusCode::NOT_FOUND, "Session not found".to_string()))?;
        session.exec_id.clone()
    };

    // Perform the resize outside the lock — it's an async network call.
    if let Some(size) = &input.size {
        let docker = connect_docker()
            .map_err(|sc| (sc, "Failed to connect to container runtime".to_string()))?;
        docker
            .resize_exec(
                &exec_id,
                ResizeExecOptions {
                    height: size.rows,
                    width: size.cols,
                },
            )
            .await
            .map_err(|e| {
                tracing::error!("Failed to resize exec {pty_id}: {e}");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("Failed to resize: {e}"),
                )
            })?;
    }

    // Update title under write lock.
    if let Some(title) = input.title {
        let mut sessions = state.pty_sessions.sessions.write().await;
        if let Some(session) = sessions.get_mut(&pty_id) {
            session.info.title = title;
        }
    }

    // Return current info.
    let sessions = state.pty_sessions.sessions.read().await;
    let session = sessions
        .get(&pty_id)
        .ok_or((StatusCode::NOT_FOUND, "Session not found".to_string()))?;
    Ok(Json(session.info().await))
}

/// `DELETE /pty/{pty_id}` — remove session and clean up.
///
/// Dropping the session closes the broadcast channel and stdin sender, which
/// shuts down the background tasks. The exec process will be cleaned up by
/// the container runtime.
async fn pty_delete(
    Path(pty_id): Path<String>,
    State(state): State<AppState>,
) -> Result<StatusCode, StatusCode> {
    let mut sessions = state.pty_sessions.sessions.write().await;
    let _session = sessions.remove(&pty_id).ok_or(StatusCode::NOT_FOUND)?;
    tracing::info!("Deleted PTY session {pty_id}");
    Ok(StatusCode::NO_CONTENT)
}

/// `GET /pty/{pty_id}/connect` — WebSocket upgrade.
async fn pty_connect(
    Path(pty_id): Path<String>,
    Query(query): Query<ConnectQuery>,
    State(state): State<AppState>,
    ws: WebSocketUpgrade,
) -> Result<impl IntoResponse, StatusCode> {
    let sessions = state.pty_sessions.sessions.read().await;
    let session = sessions.get(&pty_id).ok_or(StatusCode::NOT_FOUND)?;

    let replay_cursor = query.cursor.unwrap_or(0);
    let output_rx = session.output_tx.subscribe();
    let stdin_tx = session.stdin_tx.clone();

    // Compute replay bytes under the per-session output lock.
    let out = session.output.lock().await;
    let current_cursor = out.cursor;
    let replay_bytes = if replay_cursor < current_cursor {
        let buffer_start_cursor = current_cursor - out.ring_buffer.len() as u64;
        let effective_start = replay_cursor.max(buffer_start_cursor);
        let offset = (effective_start - buffer_start_cursor) as usize;
        let (front, back) = out.ring_buffer.as_slices();
        let mut replay = Vec::with_capacity(out.ring_buffer.len() - offset);
        if offset < front.len() {
            replay.extend_from_slice(&front[offset..]);
            replay.extend_from_slice(back);
        } else {
            replay.extend_from_slice(&back[offset - front.len()..]);
        }
        Some(replay)
    } else {
        None
    };
    drop(out);
    drop(sessions);

    let pty_id_owned = pty_id.clone();
    Ok(ws.on_upgrade(move |socket| {
        handle_ws(
            socket,
            pty_id_owned,
            replay_bytes,
            current_cursor,
            output_rx,
            stdin_tx,
        )
    }))
}

/// Handle an upgraded WebSocket connection for a PTY session.
async fn handle_ws(
    socket: WebSocket,
    pty_id: String,
    replay_bytes: Option<Vec<u8>>,
    mut cursor: u64,
    mut output_rx: broadcast::Receiver<(Vec<u8>, u64)>,
    stdin_tx: Option<tokio::sync::mpsc::Sender<Vec<u8>>>,
) {
    let (mut ws_tx, mut ws_rx) = socket.split();

    // Send initial meta frame: [0x00] + JSON {"cursor": <u64>}
    let meta = serde_json::json!({"cursor": cursor});
    let mut meta_bytes = vec![0x00u8];
    meta_bytes.extend_from_slice(meta.to_string().as_bytes());
    if ws_tx
        .send(Message::Binary(meta_bytes.into()))
        .await
        .is_err()
    {
        return;
    }

    // Replay buffered output from the requested cursor.
    if let Some(replay) = replay_bytes
        && !replay.is_empty()
        && ws_tx
            .send(Message::Text(
                String::from_utf8_lossy(&replay).into_owned().into(),
            ))
            .await
            .is_err()
    {
        return;
    }

    // Bridge: PTY output → WebSocket, WebSocket input → PTY stdin.
    loop {
        tokio::select! {
            result = output_rx.recv() => {
                match result {
                    Ok((data, new_cursor)) => {
                        cursor = new_cursor;
                        if ws_tx.send(Message::Text(
                            String::from_utf8_lossy(&data).into_owned().into()
                        )).await.is_err() {
                            break;
                        }
                        // Send updated meta frame.
                        let meta = serde_json::json!({"cursor": cursor});
                        let mut meta_bytes = vec![0x00u8];
                        meta_bytes.extend_from_slice(meta.to_string().as_bytes());
                        if ws_tx.send(Message::Binary(meta_bytes.into())).await.is_err() {
                            break;
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(n)) => {
                        tracing::debug!("WebSocket client for {pty_id} lagged {n} messages");
                    }
                    Err(broadcast::error::RecvError::Closed) => {
                        break;
                    }
                }
            }
            msg = ws_rx.next() => {
                match msg {
                    Some(Ok(Message::Text(text))) => {
                        if let Some(ref tx) = stdin_tx {
                            let _ = tx.send(text.as_bytes().to_vec()).await;
                        }
                    }
                    Some(Ok(Message::Binary(data))) => {
                        if let Some(ref tx) = stdin_tx {
                            let _ = tx.send(data.to_vec()).await;
                        }
                    }
                    Some(Ok(Message::Close(_))) | None => break,
                    Some(Err(e)) => {
                        tracing::debug!("WebSocket error for {pty_id}: {e}");
                        break;
                    }
                    _ => {}
                }
            }
        }
    }

    tracing::debug!("WebSocket client disconnected from {pty_id}");
}

// ---------------------------------------------------------------------------
// GET /summary — pre-computed pod status for the control plane
// ---------------------------------------------------------------------------

/// Response for the `/summary` endpoint.
///
/// The control plane polls this instead of fetching raw agent sessions
/// and deriving status itself. This makes pod-api the source of truth for
/// pod/agent status (see `docs/todo/pod-api-driver.md`, Phase 2).
#[derive(Debug, Serialize)]
struct PodSummaryResponse {
    /// High-level activity: "Working", "Idle", "Stopped", "Unknown".
    activity: String,
    /// One-line description of what the agent is doing.
    status_line: Option<String>,
    /// Currently executing tool (if any).
    current_tool: Option<String>,
    /// Last few lines of agent output for quick preview.
    recent_output: Vec<String>,
    /// Epoch millis of the most recent message.
    last_message_ts: Option<i64>,
    /// Total number of agent sessions in this pod.
    session_count: usize,
    /// Pod completion status: "active" or "done".
    completion_status: CompletionStatus,
    /// Human-readable session title.
    title: Option<String>,
}

/// `GET /summary` — return pre-computed agent status.
///
/// Queries the ACP client for current session state and derives a structured
/// status summary. Handles auto-completion detection. The control plane proxies
/// this directly instead of reimplementing the derivation logic.
async fn pod_summary(State(state): State<AppState>) -> Json<PodSummaryResponse> {
    let title = {
        let path = title_path();
        tokio::fs::read_to_string(&path)
            .await
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
    };

    // Query ACP client status. If the client is not connected, report idle.
    let status = {
        let guard = state.acp_client.lock().await;
        match guard.as_ref() {
            Some(client) => {
                let session_id = client.current_session_id().await;
                let is_working = client.is_working();
                crate::agent::AgentStatusSummary {
                    activity: if session_id.is_none() {
                        crate::agent::AgentActivity::Unknown
                    } else if is_working {
                        crate::agent::AgentActivity::Working
                    } else {
                        crate::agent::AgentActivity::Idle
                    },
                    status_line: session_id.as_ref().map(|sid| format!("Session: {}", sid)),
                    current_tool: None,
                    recent_output: vec![],
                    last_message_ts: None,
                    session_count: if session_id.is_some() { 1 } else { 0 },
                }
            }
            None => crate::agent::AgentStatusSummary {
                activity: crate::agent::AgentActivity::Unknown,
                status_line: Some("ACP client not connected".to_string()),
                current_tool: None,
                recent_output: vec![],
                last_message_ts: None,
                session_count: 0,
            },
        }
    };

    let activity = status.activity.as_str().to_string();

    let (mut completion_status, changed_at) = read_completion_status(&state.workspace).await;

    // Auto-detect completion: when the agent is idle after doing work,
    // automatically transition to Done. This avoids requiring the user
    // to manually click "Done" or run `devaipod done`.
    //
    // Grace period: skip auto-completion if the status was recently set
    // to Active (e.g. after a review submission). This prevents the race
    // where the agent hasn't started processing a new message yet but
    // the poll sees the old "Idle" state.
    let in_grace_period = if completion_status == CompletionStatus::Active {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        changed_at.is_some_and(|t| (now - t) < AUTO_COMPLETION_GRACE_SECS)
    } else {
        false
    };

    if activity == "Idle"
        && completion_status == CompletionStatus::Active
        && status.session_count > 0
        && !in_grace_period
    {
        if let Err(e) = write_completion_status(&state.workspace, CompletionStatus::Done).await {
            tracing::warn!("Failed to auto-set completion status: {e}");
        } else {
            tracing::info!("Auto-detected agent completion (idle after work)");
            completion_status = CompletionStatus::Done;
        }
    }

    Json(PodSummaryResponse {
        activity,
        status_line: status.status_line,
        current_tool: status.current_tool,
        recent_output: status.recent_output,
        last_message_ts: status.last_message_ts,
        session_count: status.session_count,
        completion_status,
        title,
    })
}

// ---------------------------------------------------------------------------
// ACP client spawning
// ---------------------------------------------------------------------------

/// Ensure the ACP client is spawned and initialized. Returns a reference to the client.
///
/// If the client doesn't exist yet, this function:
/// 1. Loads the agent profile configuration
/// 2. Builds a podman exec command to run the agent in the agent container
/// 3. Spawns the ACP client with the wrapped command
/// 4. Initializes the ACP connection
async fn ensure_acp_client(state: &AppState) -> color_eyre::Result<()> {
    // Check if a live client exists (quick lock).
    // If the agent process has exited, clear the stale client so we
    // respawn it below.
    {
        let mut guard = state.acp_client.lock().await;
        if let Some(client) = guard.as_ref() {
            if client.is_alive().await {
                return Ok(());
            }
            tracing::info!("ACP agent process exited, clearing stale client");
            *guard = None;
        }
    }

    tracing::info!(
        "Spawning ACP client for agent container: {}",
        state.agent_container
    );

    // Load agent profile from config
    let config = crate::config::load_config(None).unwrap_or_else(|e| {
        tracing::warn!("Failed to load config, using defaults: {}", e);
        crate::config::Config::default()
    });

    // Get podman path first (needed for probing)
    let podman_path = std::env::var("PODMAN_PATH").unwrap_or_else(|_| "podman".to_string());

    // Try each candidate profile in priority order, probing the container
    // for the binary. Use the first one that's available.
    let candidates = config.agent.candidates();
    let mut selected: Option<(String, crate::config::AgentProfile)> = None;

    for (name, profile) in &candidates {
        if profile.command.is_empty() {
            continue;
        }
        let binary = &profile.command[0];
        // Check if binary exists in the agent container
        let probe = tokio::process::Command::new(&podman_path)
            .args([
                "exec",
                &state.agent_container,
                "sh",
                "-c",
                &format!("command -v {}", binary),
            ])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .await;
        if probe.map(|s| s.success()).unwrap_or(false) {
            tracing::info!(
                "Selected agent profile '{}' (binary '{}' found)",
                name,
                binary
            );
            selected = Some((name.to_string(), (*profile).clone()));
            break;
        } else {
            tracing::debug!("Agent binary '{}' not found for profile '{}'", binary, name);
        }
    }

    let (profile_name, profile) = match selected {
        Some((name, p)) => (name, p),
        None => {
            // No binary found — fall back to hardcoded opencode and let it fail
            // with a clear error when the exec happens.
            tracing::warn!("No agent binary found in container, falling back to opencode");
            (
                "opencode".to_string(),
                crate::config::AgentProfile {
                    command: vec!["opencode".to_string(), "acp".to_string()],
                    env: HashMap::new(),
                },
            )
        }
    };

    tracing::info!("Using agent profile: {}", profile_name);

    // Build podman exec command:
    // podman exec -i <agent_container> <agent_command...>
    let mut podman_command = vec![podman_path, "exec".to_string(), "-i".to_string()];

    // Add environment variables as -e flags
    for (key, value) in &profile.env {
        podman_command.push("-e".to_string());
        podman_command.push(format!("{}={}", key, value));
    }

    // Add container name
    podman_command.push(state.agent_container.clone());

    // Add agent command. In mock mode, use the mock ACP agent script
    // installed by the agent container startup script.
    if std::env::var("DEVAIPOD_MOCK_AGENT").is_ok() {
        podman_command.push("/home/devenv/.local/bin/mock-acp-agent".to_string());
    } else {
        podman_command.extend(profile.command.clone());
    }

    tracing::debug!("Spawning ACP client with command: {:?}", podman_command);

    // Spawn the ACP client (outside the lock)
    let cwd = state.workspace.to_string_lossy().to_string();
    let client = AcpClient::spawn(
        podman_command,
        std::collections::HashMap::new(), // env vars are passed via -e flags to podman exec
        &cwd,
        state.acp_event_tx.clone(),
    )?;

    // Initialize the ACP connection (outside the lock)
    match client.initialize().await {
        Ok(resp) => {
            tracing::info!("ACP client initialized successfully");
            // Cache the Initialized event so late-connecting WebSocket clients
            // receive agent info (name, version, capabilities).
            // Always use the config profile name for consistency across agents.
            let acp_info = resp.get("agentInfo");
            let event = AcpEvent::Initialized {
                agent_info: Some(serde_json::json!({
                    "name": profile_name,
                    "version": acp_info
                        .and_then(|i| i.get("version"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("unknown"),
                })),
                capabilities: resp.get("agentCapabilities").cloned(),
            };
            *state.initialized_event.lock().await = Some(event);
        }
        Err(e) => {
            tracing::error!("Failed to initialize ACP client: {}", e);
            return Err(color_eyre::eyre::eyre!("ACP initialization failed: {}", e));
        }
    }

    // Insert under lock
    {
        let mut guard = state.acp_client.lock().await;
        // TOCTOU: Two concurrent calls could both spawn. That's acceptable
        // (one wins, the other's client gets dropped).
        *guard = Some(client);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// WebSocket command types for ACP interaction
// ---------------------------------------------------------------------------

/// Commands sent from the frontend to pod-api via WebSocket.
#[derive(Debug, Deserialize)]
#[serde(tag = "type")]
enum WsCommand {
    /// Send a prompt to the agent.
    #[serde(rename = "send_prompt")]
    Prompt {
        /// Session to send the prompt to.
        #[serde(alias = "session_id", rename = "sessionId")]
        session_id: String,
        /// The prompt content blocks (ACP format).
        prompt: Vec<serde_json::Value>,
    },
    /// Cancel an in-progress prompt.
    #[serde(rename = "cancel")]
    Cancel {
        /// Session to cancel.
        #[serde(alias = "session_id", rename = "sessionId")]
        session_id: String,
    },
    /// Approve a permission request.
    #[serde(rename = "permission_response")]
    Approve {
        /// The JSON-RPC request id from the permission request.
        #[serde(alias = "request_id", rename = "requestId")]
        request_id: i64,
        /// The selected permission option (e.g. "allow_once").
        #[serde(alias = "option_id", rename = "optionId")]
        option_id: String,
    },
    /// Create a new session.
    #[serde(rename = "new_session")]
    NewSession,
    /// List all sessions.
    #[serde(rename = "list_sessions")]
    ListSessions,
    /// Load a specific session by ID.
    #[serde(rename = "load_session")]
    LoadSession {
        /// The session ID to load.
        #[serde(alias = "session_id", rename = "sessionId")]
        session_id: String,
    },
}

/// Handle a WebSocket command from the frontend.
async fn handle_ws_command(text: &str, state: &AppState) {
    let cmd: WsCommand = match serde_json::from_str(text) {
        Ok(c) => c,
        Err(e) => {
            tracing::debug!(
                "Failed to parse WebSocket command: {}: {}",
                e,
                &text[..text.len().min(200)]
            );
            return;
        }
    };

    // Ensure the ACP client is spawned before handling commands
    if let Err(e) = ensure_acp_client(state).await {
        tracing::error!("Failed to spawn ACP client: {}", e);
        let _ = state.acp_event_tx.send(AcpEvent::Error {
            message: format!("Failed to start agent: {}", e),
        });
        return;
    }

    // Clone the client and drop the lock before async I/O operations.
    // Holding the lock across async calls can cause deadlocks if other tasks
    // need to acquire it.
    let client = {
        let guard = state.acp_client.lock().await;
        match guard.as_ref() {
            Some(c) => c.clone(),
            None => {
                tracing::warn!("Received WebSocket command but no ACP client is connected");
                return;
            }
        }
    };
    // Lock is dropped here.

    match cmd {
        WsCommand::Prompt { session_id, prompt } => {
            let session_id = session_id.clone();
            // Extract text from ACP content blocks
            let text: String = prompt
                .iter()
                .filter_map(|block| {
                    if block.get("type")?.as_str()? == "text" {
                        block.get("text")?.as_str().map(String::from)
                    } else {
                        None
                    }
                })
                .collect::<Vec<_>>()
                .join("\n");
            if let Err(e) = client.prompt(&session_id, &text).await {
                tracing::error!("Failed to send prompt: {}", e);
                let _ = state.acp_event_tx.send(AcpEvent::Error {
                    message: format!("Prompt failed: {}", e),
                });
            } else {
                // New work started — reset completion status so the pod
                // shows as active (not done) while the agent processes.
                if let Err(e) =
                    write_completion_status(&state.workspace, CompletionStatus::Active).await
                {
                    tracing::warn!("Failed to reset completion status: {e}");
                }
            }
        }
        WsCommand::Cancel { session_id } => {
            if let Err(e) = client.cancel(&session_id).await {
                tracing::error!("Failed to cancel: {}", e);
            }
        }
        WsCommand::Approve {
            request_id,
            option_id,
        } => {
            client.respond_permission(request_id, &option_id).await;
        }
        WsCommand::NewSession => {
            let cwd = state.workspace.to_string_lossy().to_string();
            match client.new_session(&cwd).await {
                Ok(sid) => {
                    // SessionCreated is already broadcast by AcpClient::new_session().
                    tracing::info!("Created new ACP session: {}", sid);
                }
                Err(e) => {
                    tracing::error!("Failed to create session: {}", e);
                    let _ = state.acp_event_tx.send(AcpEvent::Error {
                        message: format!("Failed to create session: {}", e),
                    });
                }
            }
        }
        WsCommand::ListSessions => match client.list_sessions().await {
            Ok(sessions) => {
                let _ = state.acp_event_tx.send(AcpEvent::SessionList { sessions });
            }
            Err(e) => {
                tracing::error!("Failed to list sessions: {}", e);
                let _ = state.acp_event_tx.send(AcpEvent::Error {
                    message: format!("Failed to list sessions: {}", e),
                });
            }
        },
        WsCommand::LoadSession { session_id } => {
            let cwd = state.workspace.to_string_lossy().to_string();
            if let Err(e) = client.load_session(&session_id, &cwd).await {
                tracing::error!("Failed to load session: {}", e);
                let _ = state.acp_event_tx.send(AcpEvent::Error {
                    message: format!("Failed to load session: {}", e),
                });
            }
        }
    }
}

// ---------------------------------------------------------------------------
// GET/PUT /gator/scopes — service-gator scope management
// ---------------------------------------------------------------------------

/// Response for the gator scopes endpoint.
#[derive(Debug, Serialize, Deserialize)]
struct GatorScopesResponse {
    /// Whether service-gator is enabled for this pod.
    enabled: bool,
    /// Current scope configuration (absent if gator not enabled).
    #[serde(skip_serializing_if = "Option::is_none")]
    scopes: Option<crate::service_gator::JwtScopeConfig>,
}

/// Request body for PUT /gator/scopes.
#[derive(Debug, Deserialize)]
struct GatorScopesUpdateRequest {
    scopes: crate::service_gator::JwtScopeConfig,
}

/// Completion status for the pod (active vs done).
///
/// Persisted to `.devaipod/completion-status.json` in the workspace volume.
/// The control plane reads this via GET /completion-status and writes via
/// PUT /completion-status (requires admin token).
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
enum CompletionStatus {
    /// Pod is actively being worked on (default)
    #[default]
    Active,
    /// Work is done; pod can be cleaned up
    Done,
}

/// On-disk format for the completion status file.
#[derive(Debug, Serialize, Deserialize)]
struct CompletionStatusFile {
    status: CompletionStatus,
    /// Unix timestamp (seconds) of the last status change. Used to suppress
    /// auto-completion for a grace period after the status is reset to Active
    /// (e.g. after a review submission), preventing the auto-completion
    /// from immediately re-triggering before the agent processes new input.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    changed_at: Option<i64>,
}

/// Duration (in seconds) after a status change to Active during which
/// auto-completion is suppressed. This prevents the race where a review
/// resets status to Active but the agent hasn't started processing the
/// review message yet, so the next /summary poll would see "Idle" and
/// immediately re-set Done.
const AUTO_COMPLETION_GRACE_SECS: i64 = 5;

/// Response for GET /completion-status.
#[derive(Debug, Serialize)]
struct CompletionStatusResponse {
    status: CompletionStatus,
}

/// Request body for PUT /completion-status.
#[derive(Debug, Deserialize)]
struct CompletionStatusUpdateRequest {
    status: CompletionStatus,
}

/// Response for GET /title.
#[derive(Debug, Serialize)]
struct TitleResponse {
    title: Option<String>,
}

/// Request body for PUT /title.
#[derive(Debug, Deserialize)]
struct TitleUpdateRequest {
    title: String,
}

/// Resolve the gator config file path from the workspace root.
fn gator_config_path(workspace: &std::path::Path) -> PathBuf {
    workspace.join(crate::service_gator::GATOR_CONFIG_PATH)
}

/// Resolve the completion status file path.
///
/// Stored under the pod-api state directory (default `/var/lib/devaipod/`)
/// rather than in the workspace directory because the pod-api container
/// drops all capabilities (including `DAC_OVERRIDE`), so it cannot write
/// to workspace directories owned by a different UID. The state directory
/// is on the container's own overlay filesystem and is always writable.
///
/// Override via `DEVAIPOD_STATE_DIR` for testing outside of containers.
fn completion_status_path(_workspace: &std::path::Path) -> PathBuf {
    state_dir().join("completion-status.json")
}

/// Resolve the title file path.
fn title_path() -> PathBuf {
    state_dir().join("title.txt")
}

/// Read the current completion status and change timestamp from disk.
async fn read_completion_status(workspace: &std::path::Path) -> (CompletionStatus, Option<i64>) {
    let path = completion_status_path(workspace);
    match tokio::fs::read_to_string(&path).await {
        Ok(content) => serde_json::from_str::<CompletionStatusFile>(&content)
            .map(|f| (f.status, f.changed_at))
            .unwrap_or_default(),
        Err(_) => Default::default(),
    }
}

/// Write the completion status to disk atomically (write-to-temp then rename).
/// Records the current timestamp so auto-completion can be suppressed
/// during the grace period after a reset to Active.
async fn write_completion_status(
    workspace: &std::path::Path,
    status: CompletionStatus,
) -> Result<(), String> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    let file = CompletionStatusFile {
        status,
        changed_at: Some(now),
    };
    let json = serde_json::to_string_pretty(&file).map_err(|e| format!("serialize: {e}"))?;
    let path = completion_status_path(workspace);
    let temp_path = path.with_extension("json.tmp");
    tokio::fs::write(&temp_path, &json)
        .await
        .map_err(|e| format!("write {temp_path:?}: {e}"))?;
    tokio::fs::rename(&temp_path, &path)
        .await
        .map_err(|e| format!("rename {temp_path:?} -> {path:?}: {e}"))
}

/// `GET /gator/scopes` — read current service-gator scopes.
///
/// Reads the config file directly from the workspace volume. Returns
/// `enabled: false` if the file doesn't exist (gator not configured).
async fn get_gator_scopes(State(state): State<AppState>) -> Json<GatorScopesResponse> {
    let config_path = gator_config_path(&state.workspace);

    let content = match tokio::fs::read_to_string(&config_path).await {
        Ok(c) => c,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Json(GatorScopesResponse {
                enabled: false,
                scopes: None,
            });
        }
        Err(e) => {
            tracing::warn!(
                "Failed to read gator config at {}: {}",
                config_path.display(),
                e
            );
            return Json(GatorScopesResponse {
                enabled: false,
                scopes: None,
            });
        }
    };

    match serde_json::from_str::<crate::service_gator::GatorConfigFile>(&content) {
        Ok(config) => Json(GatorScopesResponse {
            enabled: true,
            scopes: Some(config.scopes),
        }),
        Err(e) => {
            tracing::error!("Failed to parse gator config JSON: {}", e);
            Json(GatorScopesResponse {
                enabled: false,
                scopes: None,
            })
        }
    }
}

/// `PUT /gator/scopes` — update service-gator scopes.
///
/// Requires `Authorization: Bearer <admin_token>`. This token is known only
/// to the control plane (passed via `--admin-token` at startup). The agent
/// does not receive it, preventing self-escalation of scopes.
///
/// Writes the updated config file to the workspace volume. Gator watches
/// this file via inotify and reloads automatically — no restart needed.
async fn update_gator_scopes(
    State(state): State<AppState>,
    request: Request,
) -> Result<Json<GatorScopesResponse>, StatusCode> {
    // Require admin token — the agent does not have this secret
    if !state.admin_token.is_empty() {
        let provided = request
            .headers()
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "));
        if provided != Some(&state.admin_token) {
            tracing::warn!("Rejected gator scope update: invalid or missing admin token");
            return Err(StatusCode::FORBIDDEN);
        }
    }

    // Parse body manually since we consumed the request for header inspection
    let body = axum::body::to_bytes(request.into_body(), 64 * 1024)
        .await
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    let req: GatorScopesUpdateRequest =
        serde_json::from_slice(&body).map_err(|_| StatusCode::UNPROCESSABLE_ENTITY)?;
    let config_path = gator_config_path(&state.workspace);

    let config = crate::service_gator::GatorConfigFile::new(req.scopes.clone());
    let config_json = serde_json::to_string_pretty(&config).map_err(|e| {
        tracing::error!("Failed to serialize gator config: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    // Ensure parent directory exists
    if let Some(parent) = config_path.parent() {
        tokio::fs::create_dir_all(parent).await.map_err(|e| {
            tracing::error!("Failed to create gator config dir: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;
    }

    // Atomic write: write to a temp file in the same directory, then rename.
    // This prevents gator's inotify watcher from seeing a partial file.
    let temp_path = config_path.with_extension("json.tmp");
    tokio::fs::write(&temp_path, &config_json)
        .await
        .map_err(|e| {
            tracing::error!("Failed to write gator config temp file: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;
    tokio::fs::rename(&temp_path, &config_path)
        .await
        .map_err(|e| {
            tracing::error!("Failed to rename gator config: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    tracing::info!("Updated gator scopes (auto-reload via inotify)");

    Ok(Json(GatorScopesResponse {
        enabled: true,
        scopes: Some(req.scopes),
    }))
}

// ---------------------------------------------------------------------------
// Completion status endpoints
// ---------------------------------------------------------------------------

/// `GET /completion-status` — read current pod completion status.
async fn get_completion_status(State(state): State<AppState>) -> Json<CompletionStatusResponse> {
    let (status, _changed_at) = read_completion_status(&state.workspace).await;
    Json(CompletionStatusResponse { status })
}

/// `PUT /completion-status` — update pod completion status.
///
/// Requires `Authorization: Bearer <admin_token>` (same as gator scope updates).
async fn update_completion_status(
    State(state): State<AppState>,
    request: Request,
) -> Result<Json<CompletionStatusResponse>, StatusCode> {
    // Require admin token
    if !state.admin_token.is_empty() {
        let provided = request
            .headers()
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "));
        if provided != Some(&state.admin_token) {
            tracing::warn!("Rejected completion status update: invalid or missing admin token");
            return Err(StatusCode::FORBIDDEN);
        }
    }

    let body = axum::body::to_bytes(request.into_body(), 64 * 1024)
        .await
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    let req: CompletionStatusUpdateRequest =
        serde_json::from_slice(&body).map_err(|_| StatusCode::UNPROCESSABLE_ENTITY)?;

    write_completion_status(&state.workspace, req.status.clone())
        .await
        .map_err(|e| {
            tracing::error!("Failed to update completion status: {e}");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    tracing::info!("Updated completion status to {:?}", req.status);

    Ok(Json(CompletionStatusResponse { status: req.status }))
}

// ---------------------------------------------------------------------------
// Title endpoints
// ---------------------------------------------------------------------------

/// `GET /title` — read the current session title.
async fn get_title() -> Json<TitleResponse> {
    let path = title_path();
    let title = tokio::fs::read_to_string(&path)
        .await
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    Json(TitleResponse { title })
}

/// `PUT /title` — update the session title.
///
/// Does NOT require admin token — the title is user-editable metadata,
/// not a security-sensitive setting.
async fn update_title(
    Json(req): Json<TitleUpdateRequest>,
) -> Result<Json<TitleResponse>, StatusCode> {
    let path = title_path();
    let temp_path = path.with_extension("txt.tmp");
    tokio::fs::write(&temp_path, req.title.trim())
        .await
        .map_err(|e| {
            tracing::error!("Failed to write title to {:?}: {}", temp_path, e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;
    tokio::fs::rename(&temp_path, &path).await.map_err(|e| {
        tracing::error!("Failed to rename {:?} -> {:?}: {}", temp_path, path, e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;
    let title = Some(req.title.trim().to_string()).filter(|s| !s.is_empty());
    tracing::info!("Updated session title to {:?}", title);
    Ok(Json(TitleResponse { title }))
}

// ---------------------------------------------------------------------------
// Server entrypoint
// ---------------------------------------------------------------------------

/// CLI arguments for the `pod-api` subcommand.
#[derive(Debug, clap::Args)]
pub(crate) struct PodApiArgs {
    /// Port to listen on
    #[arg(long, default_value = "8090")]
    port: u16,
    /// Path to the workspace directory
    #[arg(long, default_value = "/workspaces")]
    workspace: PathBuf,
    /// Name of the workspace container to exec into for PTY sessions.
    #[arg(long)]
    workspace_container: Option<String>,
    /// Name of the agent container to exec into for agent PTY sessions.
    #[arg(long)]
    agent_container: Option<String>,
    /// Password for authenticating to the opencode server (Basic auth).
    /// Legacy: unused with ACP transport, but accepted for CLI compatibility.
    #[arg(long, default_value = "")]
    #[allow(dead_code)]
    opencode_password: String,
    /// Port of the opencode server to connect to.
    /// Legacy: unused with ACP transport, but accepted for CLI compatibility.
    #[arg(long, default_value_t = 4096)]
    #[allow(dead_code)]
    opencode_port: u16,
}

/// Liveness/readiness probe for container healthchecks.
async fn healthz() -> &'static str {
    "ok"
}

// ---------------------------------------------------------------------------
// WebSocket endpoint for ACP event streaming
// ---------------------------------------------------------------------------

/// `GET /ws/events` — WebSocket endpoint for streaming ACP agent events.
///
/// Streams ACP events (session updates, permission requests, etc.) to
/// the frontend. Also accepts commands from the frontend (prompts,
/// approvals, etc.) as JSON text frames.
async fn ws_agent_events(ws: WebSocketUpgrade, State(state): State<AppState>) -> impl IntoResponse {
    ws.on_upgrade(move |socket| handle_agent_events_ws(socket, state))
}

/// Handle an upgraded WebSocket connection for ACP agent events.
///
/// Bidirectional: forwards ACP events to the client, and processes
/// commands (prompt, cancel, approve) from the client.
async fn handle_agent_events_ws(mut socket: WebSocket, state: AppState) {
    let mut rx = state.acp_event_tx.subscribe();

    // Send an initial keepalive so the client knows the connection is live.
    let _ = socket
        .send(Message::Text(
            serde_json::to_string(&AcpEvent::Keepalive).unwrap().into(),
        ))
        .await;

    // Send cached Initialized event so the frontend has agent info
    // (name, version, capabilities) even if it connected after init.
    {
        let init_event = state.initialized_event.lock().await;
        if let Some(event) = init_event.as_ref() {
            let json = serde_json::to_string(event).unwrap();
            let _ = socket.send(Message::Text(json.into())).await;
        }
    }

    // Send session list inline (not spawned) so the frontend reliably
    // receives it before any other events. The frontend then calls
    // session/load which replays the full conversation history.
    {
        if let Err(e) = ensure_acp_client(&state).await {
            tracing::error!("Failed to spawn ACP client for session list: {}", e);
        } else {
            let client = {
                let guard = state.acp_client.lock().await;
                guard.as_ref().map(|c| c.clone())
            };
            if let Some(client) = client {
                match client.list_sessions().await {
                    Ok(sessions) => {
                        let json =
                            serde_json::to_string(&AcpEvent::SessionList { sessions }).unwrap();
                        let _ = socket.send(Message::Text(json.into())).await;
                    }
                    Err(e) => {
                        tracing::error!("Failed to list sessions on connect: {}", e);
                    }
                }
            }
        }
    }

    let mut keepalive_interval = tokio::time::interval(Duration::from_secs(30));

    loop {
        tokio::select! {
            // Forward ACP events to WebSocket.
            event = rx.recv() => {
                match event {
                    Ok(event) => {
                        let json = serde_json::to_string(&event).unwrap();
                        if socket.send(Message::Text(json.into())).await.is_err() {
                            break;
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(broadcast::error::RecvError::Closed) => break,
                }
            }
            // Handle incoming WebSocket messages (prompts, approvals).
            msg = socket.recv() => {
                match msg {
                    Some(Ok(Message::Text(text))) => {
                        handle_ws_command(&text, &state).await;
                    }
                    Some(Ok(Message::Close(_))) | None => break,
                    _ => {}
                }
            }
            // Periodic keepalive.
            _ = keepalive_interval.tick() => {
                let ping = serde_json::to_string(&AcpEvent::Keepalive).unwrap();
                if socket.send(Message::Text(ping.into())).await.is_err() {
                    break;
                }
            }
        }
    }
}

/// `GET /api/devaipod/agent-profiles` — return available agent profiles.
///
/// Returns the agent profiles from the user's config file (if any),
/// plus the default "opencode" profile as a fallback.
async fn get_agent_profiles() -> Json<serde_json::Value> {
    let config = crate::config::load_config(None).ok();
    let mut profiles = serde_json::Map::new();

    // Always include the default profile.
    profiles.insert(
        "opencode".to_string(),
        serde_json::json!({
            "command": ["opencode", "acp"],
            "env": {},
            "is_default": true
        }),
    );

    // Merge user-configured profiles.
    if let Some(ref config) = config {
        let agent_config = &config.agent;
        for (name, profile) in &agent_config.profiles {
            profiles.insert(
                name.clone(),
                serde_json::json!({
                    "command": profile.command,
                    "env": profile.env,
                    "is_default": agent_config.default.iter().any(|s| s == name)
                }),
            );
        }
    }

    Json(serde_json::Value::Object(profiles))
}

/// Build the axum router (public for testing).
fn build_router(state: AppState) -> Router {
    Router::new()
        // Health endpoint for container healthchecks
        .route("/healthz", get(healthz))
        // Pod summary: pre-computed agent status for the control plane
        .route("/summary", get(pod_summary))
        // Git endpoints
        .route("/git/status", get(git_status))
        .route("/git/diff", get(git_diff))
        .route("/git/commits", get(git_commits))
        .route("/git/log", get(git_log))
        .route("/git/diff-range", get(git_diff_range))
        .route("/git/events", get(git_events_sse))
        .route("/git/fetch-agent", post(git_fetch_agent))
        .route("/git/push", post(git_push))
        // Gator scope management
        .route(
            "/gator/scopes",
            get(get_gator_scopes).put(update_gator_scopes),
        )
        // Completion status
        .route(
            "/completion-status",
            get(get_completion_status).put(update_completion_status),
        )
        // Session title
        .route("/title", get(get_title).put(update_title))
        // Agent event stream (ACP over WebSocket)
        .route("/ws/events", get(ws_agent_events))
        // Agent profile listing
        .route("/api/devaipod/agent-profiles", get(get_agent_profiles))
        // PTY endpoints
        .route("/pty", get(pty_list).post(pty_create))
        .route(
            "/pty/{pty_id}",
            get(pty_get).put(pty_update).delete(pty_delete),
        )
        .route("/pty/{pty_id}/connect", get(pty_connect))
        .layer(CompressionLayer::new())
        .with_state(state)
}

/// Generate or load the admin token and persist it to disk.
///
/// The token is a 128-bit random hex string. On first startup it is generated
/// and written to `ADMIN_TOKEN_PATH`. On subsequent starts (container restart)
/// the existing token is reused so the control plane doesn't need to re-fetch.
///
/// The control plane retrieves the token via:
///   `podman exec <pod-api-container> cat /var/lib/devaipod/pod-api-token`
///
/// The agent container cannot exec into pod-api, so it cannot read this token.
fn load_or_generate_admin_token() -> Result<String> {
    use std::io::Read;

    // Allow override via env var for testing outside of containers.
    // Falls back to DEVAIPOD_STATE_DIR/pod-api-token if set, otherwise
    // the hardcoded ADMIN_TOKEN_PATH.
    let resolved_path;
    let env_path = std::env::var("DEVAIPOD_ADMIN_TOKEN_PATH").ok();
    let path = if let Some(ref p) = env_path {
        std::path::Path::new(p.as_str())
    } else if std::env::var("DEVAIPOD_STATE_DIR").is_ok() {
        resolved_path = state_dir().join("pod-api-token");
        resolved_path.as_path()
    } else {
        std::path::Path::new(ADMIN_TOKEN_PATH)
    };

    // Try to read existing token
    if let Ok(mut file) = std::fs::File::open(path) {
        let mut token = String::new();
        file.read_to_string(&mut token)?;
        let token = token.trim().to_string();
        if !token.is_empty() {
            tracing::debug!("Loaded admin token from {}", path.display());
            return Ok(token);
        }
    }

    // Generate new token
    use rand::Rng;
    let mut rng = rand::rng();
    let bytes: [u8; 16] = rng.random();
    let token: String = bytes.iter().map(|b| format!("{:02x}", b)).collect();

    // Persist it.
    // The state directory (/var/lib/devaipod/) is pre-created in the
    // container image.  We avoid create_dir_all here because mkdir on
    // an existing overlayfs directory can return EPERM when all Linux
    // capabilities are dropped (the pod-api runs with drop_all_caps).
    std::fs::write(path, &token)?;
    tracing::info!("Generated admin token at {}", path.display());

    Ok(token)
}

// ---------------------------------------------------------------------------
// Auto-start: read initial task from file, create session, send message
// ---------------------------------------------------------------------------

/// Path (relative to the workspace parent) where the initial task message is
/// written by `write_task()` during pod creation. The pod-api reads this file,
/// sends it to the agent, and marks it consumed so it doesn't repeat on restart.
const INITIAL_TASK_RELATIVE: &str = ".devaipod/initial-task.md";

/// Sentinel file written to the pod-api state dir after the initial task has
/// been sent. Prevents re-sending on container restart.
const INITIAL_TASK_DONE_FILE: &str = "initial-task-done";

/// Resolve the initial task file path from the workspace path.
///
/// The file is stored at `<workspace>/.devaipod/initial-task.md`, alongside
/// other pod metadata like the gator config.
fn initial_task_path(workspace: &std::path::Path) -> PathBuf {
    workspace.join(INITIAL_TASK_RELATIVE)
}

/// Check whether the initial task has already been consumed.
///
/// The marker lives alongside the task file in the workspace directory
/// (a persistent bind mount), not in the container overlay. This
/// survives pod-api container restarts.
fn initial_task_already_done(workspace: &std::path::Path) -> bool {
    workspace
        .join(".devaipod")
        .join(INITIAL_TASK_DONE_FILE)
        .exists()
}

/// Mark the initial task as consumed so it isn't re-sent on restart.
async fn mark_initial_task_done(workspace: &std::path::Path) {
    let path = workspace.join(".devaipod").join(INITIAL_TASK_DONE_FILE);
    if let Err(e) = tokio::fs::write(&path, "done").await {
        tracing::warn!("Failed to write initial-task-done marker: {e}");
    }
}

/// Background task: if an initial task file exists and no session has been
/// started yet, wait for the ACP client to be available, create a session,
/// and send the task as the first prompt.
async fn maybe_auto_start_session(state: AppState) -> Result<()> {
    tracing::info!("Checking for initial task to auto-start...");

    // Already consumed (e.g. container restarted after initial send).
    if initial_task_already_done(&state.workspace) {
        tracing::info!("Initial task already sent (done marker exists), skipping auto-start");
        return Ok(());
    }

    // The initial task file is written by finalize_pod() AFTER the pod
    // containers are already running, so it may not exist yet. Poll for
    // up to 120s — this covers the time for dotfiles install, config
    // writing, etc.
    let task_path = initial_task_path(&state.workspace);
    tracing::info!("Waiting for initial task at: {}", task_path.display());
    let mut task_content = None;
    for attempt in 1..=60 {
        match tokio::fs::read_to_string(&task_path).await {
            Ok(content) if !content.trim().is_empty() => {
                task_content = Some(content);
                break;
            }
            Ok(_) | Err(_) => {
                if attempt == 60 {
                    tracing::info!("No initial task file appeared after 120s, skipping auto-start");
                    return Ok(());
                }
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
        }
    }
    let task_content = task_content.unwrap();

    tracing::info!("Found initial task file, spawning ACP client...");

    // Ensure the ACP client is spawned and ready
    if let Err(e) = ensure_acp_client(&state).await {
        tracing::warn!("Failed to spawn ACP client for auto-start: {:#}", e);
        return Ok(());
    }

    // Create a session and send the initial prompt via ACP.
    let client_guard = state.acp_client.lock().await;
    let Some(client) = client_guard.as_ref() else {
        tracing::warn!("ACP client disappeared, giving up on auto-start");
        return Ok(());
    };

    let cwd = state.workspace.to_string_lossy().to_string();
    let session_id = client
        .new_session(&cwd)
        .await
        .map_err(|e| color_eyre::eyre::eyre!("Failed to create ACP session: {}", e))?;

    tracing::info!("Created ACP session {session_id}, sending initial task...");

    client
        .prompt(&session_id, &task_content)
        .await
        .map_err(|e| color_eyre::eyre::eyre!("Failed to send initial prompt: {}", e))?;

    tracing::info!("Initial task sent to ACP session {session_id}");
    // Set Active with a timestamp so the grace period protects against
    // premature Done if the agent responds very quickly.
    if let Err(e) = write_completion_status(&state.workspace, CompletionStatus::Active).await {
        tracing::warn!("Failed to set completion status for auto-start: {e}");
    }
    mark_initial_task_done(&state.workspace).await;

    Ok(())
}

/// Run the pod-api HTTP server.
pub(crate) async fn run(args: PodApiArgs) -> Result<()> {
    let workspace = Arc::new(args.workspace.clone());
    let git_events_tx = GitWatcher::spawn(Arc::clone(&workspace));
    let admin_token = load_or_generate_admin_token().context("Failed to initialize admin token")?;

    // ACP event broadcast channel for WebSocket clients.
    let (acp_event_tx, _) = broadcast::channel::<AcpEvent>(256);

    // The ACP client is created lazily when the agent container starts
    // (the pod-api sidecar starts before the agent).
    let state = AppState {
        workspace,
        git_events_tx,
        pty_sessions: PtySessionManager::new(),
        workspace_container: args.workspace_container.unwrap_or_default(),
        agent_container: args.agent_container.unwrap_or_default(),
        admin_token,
        acp_event_tx,
        acp_client: Arc::new(Mutex::new(None)),
        initialized_event: Arc::new(Mutex::new(None)),
    };

    // Spawn background auto-start task: reads the initial task file (if present)
    // and sends the initial prompt via ACP once the client is available.
    let auto_start_state = state.clone();
    tokio::spawn(async move {
        if let Err(e) = maybe_auto_start_session(auto_start_state).await {
            tracing::warn!("Auto-start session failed: {:#}", e);
        }
    });

    let app = build_router(state);

    let addr = std::net::SocketAddr::from(([0, 0, 0, 0], args.port));
    tracing::info!(
        "pod-api listening on {addr} (workspace: {})",
        args.workspace.display()
    );

    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .with_context(|| format!("Failed to bind to {addr}"))?;

    // Handle SIGTERM/SIGINT for graceful shutdown (same PID 1 reasoning
    // as the control-plane web server — see web.rs).
    axum::serve(listener, app)
        .with_graceful_shutdown(crate::web::shutdown_signal())
        .await
        .context("pod-api server error")?;

    tracing::info!("pod-api shut down gracefully");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;

    // -----------------------------------------------------------------------
    // Gator scopes endpoint tests (in-process HTTP with temp workspace)
    // -----------------------------------------------------------------------

    use axum::body::to_bytes;
    use axum::http::Request as HttpRequest;
    use tower::util::ServiceExt;

    const TEST_ADMIN_TOKEN: &str = "test-admin-token-secret";

    /// Build a test router backed by a real temp directory.
    fn test_app(workspace: &std::path::Path) -> Router {
        let (git_tx, _rx) = broadcast::channel(16);
        let (acp_tx, _) = broadcast::channel(16);
        let state = AppState {
            workspace: Arc::new(workspace.to_path_buf()),
            git_events_tx: git_tx,
            pty_sessions: PtySessionManager::new(),
            workspace_container: String::new(),
            agent_container: String::new(),
            admin_token: TEST_ADMIN_TOKEN.to_string(),
            acp_event_tx: acp_tx,
            acp_client: Arc::new(Mutex::new(None)),
            initialized_event: Arc::new(Mutex::new(None)),
        };
        build_router(state)
    }

    // -----------------------------------------------------------------------
    // /summary endpoint tests
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_summary_with_no_acp_client() {
        let tmp = tempfile::tempdir().unwrap();
        let app = test_app(tmp.path());

        let req = HttpRequest::builder()
            .uri("/summary")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

        // Without an ACP client, the summary should report Unknown status.
        assert_eq!(json["activity"], "Unknown");
        assert_eq!(json["status_line"], "ACP client not connected");
        assert!(json["current_tool"].is_null());
        assert_eq!(json["session_count"], 0);
    }

    // -----------------------------------------------------------------------
    // /ws/events WebSocket endpoint test
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_ws_events_route_exists() {
        // Verify /ws/events returns a WebSocket upgrade response (426)
        // when called without the proper upgrade headers. This confirms
        // the route is registered and the handler expects a WebSocket.
        let tmp = tempfile::tempdir().unwrap();
        let app = test_app(tmp.path());

        let req = HttpRequest::builder()
            .uri("/ws/events")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        // Without Upgrade headers, axum's WebSocketUpgrade extractor rejects
        // the request. The exact status depends on axum version but is not 404.
        assert_ne!(
            resp.status(),
            StatusCode::NOT_FOUND,
            "/ws/events route must exist"
        );
    }

    #[tokio::test]
    async fn test_ws_events_rejects_non_upgrade() {
        // A plain GET to /ws/events without WebSocket upgrade headers should
        // be rejected (not 404) — axum returns 400 or similar when the
        // WebSocketUpgrade extractor cannot extract from a non-upgrade request.
        let tmp = tempfile::tempdir().unwrap();
        let app = test_app(tmp.path());

        let req = HttpRequest::builder()
            .uri("/ws/events")
            .header("Connection", "Upgrade")
            .header("Upgrade", "websocket")
            // Missing required Sec-WebSocket-Key/Version → extractor fails
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        // Without the full WS handshake headers the request is rejected,
        // but the route itself exists (not 404). This confirms the route
        // is registered and wired to the ws_agent_events handler.
        assert_ne!(
            resp.status(),
            StatusCode::NOT_FOUND,
            "/ws/events route must exist even if upgrade fails"
        );
    }

    // -----------------------------------------------------------------------
    // handle_ws_command routing tests
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_ws_command_deserialization_send_prompt() {
        let json =
            r#"{"type":"send_prompt","sessionId":"s1","prompt":[{"type":"text","text":"hello"}]}"#;
        let cmd: WsCommand = serde_json::from_str(json).unwrap();
        match cmd {
            WsCommand::Prompt { session_id, prompt } => {
                assert_eq!(session_id, "s1");
                assert_eq!(prompt.len(), 1);
            }
            _ => panic!("expected Prompt variant"),
        }
    }

    #[tokio::test]
    async fn test_ws_command_deserialization_cancel() {
        let json = r#"{"type":"cancel","sessionId":"s1"}"#;
        let cmd: WsCommand = serde_json::from_str(json).unwrap();
        match cmd {
            WsCommand::Cancel { session_id } => {
                assert_eq!(session_id, "s1");
            }
            _ => panic!("expected Cancel variant"),
        }
    }

    #[tokio::test]
    async fn test_ws_command_deserialization_permission_response() {
        let json = r#"{"type":"permission_response","requestId":42,"optionId":"allow_once"}"#;
        let cmd: WsCommand = serde_json::from_str(json).unwrap();
        match cmd {
            WsCommand::Approve {
                request_id,
                option_id,
            } => {
                assert_eq!(request_id, 42);
                assert_eq!(option_id, "allow_once");
            }
            _ => panic!("expected Approve variant"),
        }
    }

    #[tokio::test]
    async fn test_ws_command_deserialization_new_session() {
        let json = r#"{"type":"new_session"}"#;
        let cmd: WsCommand = serde_json::from_str(json).unwrap();
        assert!(matches!(cmd, WsCommand::NewSession));
    }

    #[tokio::test]
    async fn test_ws_command_deserialization_list_sessions() {
        let json = r#"{"type":"list_sessions"}"#;
        let cmd: WsCommand = serde_json::from_str(json).unwrap();
        assert!(matches!(cmd, WsCommand::ListSessions));
    }

    #[tokio::test]
    async fn test_ws_command_deserialization_load_session() {
        let json = r#"{"type":"load_session","sessionId":"s2"}"#;
        let cmd: WsCommand = serde_json::from_str(json).unwrap();
        match cmd {
            WsCommand::LoadSession { session_id } => {
                assert_eq!(session_id, "s2");
            }
            _ => panic!("expected LoadSession variant"),
        }
    }

    #[tokio::test]
    async fn test_handle_ws_command_no_client() {
        // Verify that handle_ws_command logs a warning and returns cleanly
        // when no ACP client exists, without crashing.
        let tmp = tempfile::tempdir().unwrap();
        let (git_tx, _) = broadcast::channel(16);
        let (acp_tx, _) = broadcast::channel(16);
        let state = AppState {
            workspace: Arc::new(tmp.path().to_path_buf()),
            git_events_tx: git_tx,
            pty_sessions: PtySessionManager::new(),
            workspace_container: String::new(),
            agent_container: String::new(),
            admin_token: TEST_ADMIN_TOKEN.to_string(),
            acp_event_tx: acp_tx,
            acp_client: Arc::new(Mutex::new(None)),
            initialized_event: Arc::new(Mutex::new(None)),
        };

        // This should not panic or crash — just log a warning.
        let json = r#"{"type":"new_session"}"#;
        handle_ws_command(json, &state).await;
    }

    // -----------------------------------------------------------------------
    // Gator scopes endpoint tests
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_gator_scopes_get_not_configured() {
        let tmp = tempfile::tempdir().unwrap();
        let app = test_app(tmp.path());

        let req = HttpRequest::builder()
            .uri("/gator/scopes")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["enabled"], false);
        assert!(json.get("scopes").is_none());
    }

    #[tokio::test]
    async fn test_gator_scopes_get_with_config() {
        let tmp = tempfile::tempdir().unwrap();
        let config_dir = tmp.path().join(".devaipod");
        std::fs::create_dir_all(&config_dir).unwrap();

        let config = serde_json::json!({
            "scopes": {
                "gh": {
                    "read": true,
                    "repos": {
                        "myorg/myrepo": { "read": true, "create-draft": true }
                    }
                }
            }
        });
        std::fs::write(
            config_dir.join("gator-config.json"),
            serde_json::to_string_pretty(&config).unwrap(),
        )
        .unwrap();

        let app = test_app(tmp.path());

        let req = HttpRequest::builder()
            .uri("/gator/scopes")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["enabled"], true);
        assert!(json["scopes"]["gh"]["read"].as_bool().unwrap());
        assert!(
            json["scopes"]["gh"]["repos"]["myorg/myrepo"]["create-draft"]
                .as_bool()
                .unwrap()
        );
    }

    #[tokio::test]
    async fn test_gator_scopes_put_requires_admin_token() {
        let tmp = tempfile::tempdir().unwrap();
        let app = test_app(tmp.path());

        let body = serde_json::to_string(&serde_json::json!({
            "scopes": { "gh": { "read": true } }
        }))
        .unwrap();

        // No Authorization header → 403
        let req = HttpRequest::builder()
            .method("PUT")
            .uri("/gator/scopes")
            .header("content-type", "application/json")
            .body(Body::from(body.clone()))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::FORBIDDEN,
            "PUT without admin token must be rejected"
        );

        // Wrong Bearer token → 403
        let app = test_app(tmp.path());
        let req = HttpRequest::builder()
            .method("PUT")
            .uri("/gator/scopes")
            .header("content-type", "application/json")
            .header("Authorization", "Bearer wrong-token")
            .body(Body::from(body))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::FORBIDDEN,
            "PUT with wrong admin token must be rejected"
        );
    }

    #[tokio::test]
    async fn test_gator_scopes_put_creates_config() {
        let tmp = tempfile::tempdir().unwrap();
        let app = test_app(tmp.path());

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

        let req = HttpRequest::builder()
            .method("PUT")
            .uri("/gator/scopes")
            .header("content-type", "application/json")
            .header("Authorization", format!("Bearer {}", TEST_ADMIN_TOKEN))
            .body(Body::from(body))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["enabled"], true);
        assert!(
            json["scopes"]["gh"]["repos"]["myorg/myrepo"]["create-draft"]
                .as_bool()
                .unwrap()
        );

        // Verify the file was actually written
        let config_path = tmp.path().join(".devaipod/gator-config.json");
        assert!(config_path.exists(), "config file must be created on disk");
        let written: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&config_path).unwrap()).unwrap();
        assert!(written["scopes"]["gh"]["read"].as_bool().unwrap());
    }

    #[tokio::test]
    async fn test_gator_scopes_get_malformed_config() {
        let tmp = tempfile::tempdir().unwrap();
        let config_dir = tmp.path().join(".devaipod");
        std::fs::create_dir_all(&config_dir).unwrap();
        std::fs::write(config_dir.join("gator-config.json"), "not valid json {{{").unwrap();

        let app = test_app(tmp.path());

        let req = HttpRequest::builder()
            .uri("/gator/scopes")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            json["enabled"], false,
            "Malformed config should report enabled:false"
        );
    }

    #[tokio::test]
    async fn test_gator_scopes_put_rejects_invalid_json() {
        let tmp = tempfile::tempdir().unwrap();
        let app = test_app(tmp.path());

        let req = HttpRequest::builder()
            .method("PUT")
            .uri("/gator/scopes")
            .header("content-type", "application/json")
            .header("Authorization", format!("Bearer {}", TEST_ADMIN_TOKEN))
            .body(Body::from("not valid json"))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert!(
            resp.status().is_client_error(),
            "Invalid JSON must produce 4xx, got {}",
            resp.status()
        );
    }

    #[tokio::test]
    async fn test_gator_scopes_put_rejects_wrong_structure() {
        let tmp = tempfile::tempdir().unwrap();
        let app = test_app(tmp.path());

        let body = serde_json::to_string(&serde_json::json!({
            "wrong_field": "value"
        }))
        .unwrap();

        let req = HttpRequest::builder()
            .method("PUT")
            .uri("/gator/scopes")
            .header("content-type", "application/json")
            .header("Authorization", format!("Bearer {}", TEST_ADMIN_TOKEN))
            .body(Body::from(body))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert!(
            resp.status().is_client_error(),
            "Missing 'scopes' field must produce 4xx, got {}",
            resp.status()
        );
    }

    #[tokio::test]
    async fn test_gator_scopes_roundtrip() {
        let tmp = tempfile::tempdir().unwrap();

        // PUT scopes
        let app = test_app(tmp.path());
        let body = serde_json::to_string(&serde_json::json!({
            "scopes": {
                "gh": {
                    "repos": {
                        "owner/repo": { "read": true, "pending-review": true }
                    }
                }
            }
        }))
        .unwrap();

        let req = HttpRequest::builder()
            .method("PUT")
            .uri("/gator/scopes")
            .header("content-type", "application/json")
            .header("Authorization", format!("Bearer {}", TEST_ADMIN_TOKEN))
            .body(Body::from(body))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        // GET scopes back (fresh router, same temp dir)
        let app = test_app(tmp.path());
        let req = HttpRequest::builder()
            .uri("/gator/scopes")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["enabled"], true);
        assert!(
            json["scopes"]["gh"]["repos"]["owner/repo"]["pending-review"]
                .as_bool()
                .unwrap()
        );
    }

    // -----------------------------------------------------------------------
    // Agent profiles endpoint tests
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_agent_profiles_returns_default() {
        let tmp = tempfile::tempdir().unwrap();
        let app = test_app(tmp.path());

        let req = HttpRequest::builder()
            .uri("/api/devaipod/agent-profiles")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

        // Should always have the default "opencode" profile.
        assert!(
            json.get("opencode").is_some(),
            "default opencode profile must exist"
        );
        let opencode = &json["opencode"];
        assert_eq!(opencode["command"], serde_json::json!(["opencode", "acp"]));
        assert_eq!(opencode["is_default"], true);
    }

    // -----------------------------------------------------------------------
    // ACP WebSocket command parsing tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_ws_command_deserialization() {
        // Frontend sends camelCase with content blocks
        let json =
            r#"{"type":"send_prompt","sessionId":"s1","prompt":[{"type":"text","text":"hello"}]}"#;
        let cmd: WsCommand = serde_json::from_str(json).unwrap();
        assert!(matches!(cmd, WsCommand::Prompt { .. }));

        let json = r#"{"type":"cancel","sessionId":"s1"}"#;
        let cmd: WsCommand = serde_json::from_str(json).unwrap();
        assert!(matches!(cmd, WsCommand::Cancel { .. }));

        let json = r#"{"type":"permission_response","requestId":42,"optionId":"allow_once"}"#;
        let cmd: WsCommand = serde_json::from_str(json).unwrap();
        assert!(matches!(cmd, WsCommand::Approve { .. }));

        let json = r#"{"type":"new_session"}"#;
        let cmd: WsCommand = serde_json::from_str(json).unwrap();
        assert!(matches!(cmd, WsCommand::NewSession));

        let json = r#"{"type":"list_sessions"}"#;
        let cmd: WsCommand = serde_json::from_str(json).unwrap();
        assert!(matches!(cmd, WsCommand::ListSessions));

        let json = r#"{"type":"load_session","sessionId":"s1"}"#;
        let cmd: WsCommand = serde_json::from_str(json).unwrap();
        match cmd {
            WsCommand::LoadSession { session_id } => assert_eq!(session_id, "s1"),
            _ => panic!("Expected LoadSession variant"),
        }
    }
}
