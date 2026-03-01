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

use axum::body::Body;
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Path, Query, Request, State};
use axum::http::{header, StatusCode};
use axum::response::sse::{Event, Sse};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::prelude::*;
use bollard::exec::{CreateExecOptions, ResizeExecOptions, StartExecResults};
use bollard::Docker;
use color_eyre::eyre::{Context, Result};
use futures_util::{SinkExt, Stream, StreamExt};
use hyper_util::rt::TokioIo;
use serde::{Deserialize, Serialize};
use tokio::io::AsyncWriteExt;
use tokio::process::Command;
use tokio::sync::{broadcast, RwLock};
use tower::ServiceExt;
use tower_http::services::{ServeDir, ServeFile};

// ---------------------------------------------------------------------------
// Shared state
// ---------------------------------------------------------------------------

/// Path to the vendored opencode UI files.
const OPENCODE_UI_PATH: &str = "/usr/share/devaipod/opencode";

/// The opencode server listens on this port inside the pod.
const OPENCODE_UPSTREAM_PORT: u16 = 4096;

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
    /// Password for authenticating to the opencode server (Basic auth).
    opencode_password: String,
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
        if fetch_head.exists() {
            if let Err(e) = watcher.watch(&fetch_head, RecursiveMode::NonRecursive) {
                tracing::debug!("FETCH_HEAD watch skipped (non-critical): {e}");
            }
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
    if let Some(ref base) = params.base {
        if !is_valid_git_ref(base) {
            return Err((
                StatusCode::BAD_REQUEST,
                format!("Invalid git ref for 'base': {base}"),
            ));
        }
    }
    if let Some(ref head) = params.head {
        if !is_valid_git_ref(head) {
            return Err((
                StatusCode::BAD_REQUEST,
                format!("Invalid git ref for 'head': {head}"),
            ));
        }
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
        if let Some(exited_at) = output.exited_at {
            if now.duration_since(exited_at) > EXITED_SESSION_TTL {
                to_remove.push(id.clone());
            }
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
/// container. This means the opencode SDK (which cannot add extra fields) naturally
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
    if let Some(replay) = replay_bytes {
        if !replay.is_empty()
            && ws_tx
                .send(Message::Text(
                    String::from_utf8_lossy(&replay).into_owned().into(),
                ))
                .await
                .is_err()
        {
            return;
        }
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
/// The control plane polls this instead of fetching raw opencode sessions
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
    /// Total number of opencode sessions in this pod.
    session_count: usize,
}

/// Maximum number of output lines to return in the summary.
const SUMMARY_MAX_LINES: usize = 3;

/// `GET /summary` — return pre-computed agent status.
///
/// Queries the opencode server at `127.0.0.1:4096` (same pod network namespace),
/// finds the root session, fetches recent messages, and derives a structured
/// status summary. The control plane can proxy this directly instead of
/// reimplementing the derivation logic.
async fn pod_summary(State(state): State<AppState>) -> Json<PodSummaryResponse> {
    let unknown = PodSummaryResponse {
        activity: "Unknown".to_string(),
        status_line: None,
        current_tool: None,
        recent_output: vec![],
        last_message_ts: None,
        session_count: 0,
    };

    let client = match reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
    {
        Ok(c) => c,
        Err(_) => return Json(unknown),
    };

    let credentials = BASE64_STANDARD.encode(format!("opencode:{}", state.opencode_password));
    let auth_value = format!("Basic {}", credentials);

    // Fetch sessions from the local opencode server.
    let sessions_resp = match client
        .get(format!(
            "http://127.0.0.1:{}/session",
            OPENCODE_UPSTREAM_PORT
        ))
        .header(header::AUTHORIZATION, &auth_value)
        .send()
        .await
    {
        Ok(r) if r.status().is_success() => r,
        _ => return Json(unknown),
    };

    let sessions: Vec<serde_json::Value> = match sessions_resp.json().await {
        Ok(s) => s,
        Err(_) => return Json(unknown),
    };

    let session_count = sessions.len();

    if sessions.is_empty() {
        return Json(PodSummaryResponse {
            activity: "Idle".to_string(),
            status_line: Some("Waiting for input...".to_string()),
            current_tool: None,
            recent_output: vec![],
            last_message_ts: None,
            session_count: 0,
        });
    }

    // Find the root session (no parentID or null parentID).
    let root_session = sessions.iter().find(|s| {
        s.get("parentID").is_none() || s.get("parentID").map(|p| p.is_null()).unwrap_or(false)
    });

    let session_id = match root_session
        .and_then(|s| s.get("id"))
        .and_then(|id| id.as_str())
    {
        Some(id) => id.to_string(),
        None => return Json(unknown),
    };

    // Fetch recent messages for the root session.
    let messages_resp = match client
        .get(format!(
            "http://127.0.0.1:{}/session/{}/message?limit=5",
            OPENCODE_UPSTREAM_PORT, session_id
        ))
        .header(header::AUTHORIZATION, &auth_value)
        .send()
        .await
    {
        Ok(r) if r.status().is_success() => r,
        _ => return Json(unknown),
    };

    let messages: Vec<serde_json::Value> = match messages_resp.json().await {
        Ok(m) => m,
        Err(_) => return Json(unknown),
    };

    let (activity, status_line, current_tool, recent_output, last_message_ts) =
        derive_agent_status_from_messages(&messages);

    Json(PodSummaryResponse {
        activity,
        status_line,
        current_tool,
        recent_output,
        last_message_ts,
        session_count,
    })
}

/// Derive agent status fields from opencode session messages.
///
/// This is the canonical implementation; the control plane proxies to `/summary`
/// rather than reimplementing this logic. See `docs/todo/pod-api-driver.md`.
fn derive_agent_status_from_messages(
    messages: &[serde_json::Value],
) -> (
    String,         // activity
    Option<String>, // status_line
    Option<String>, // current_tool
    Vec<String>,    // recent_output
    Option<i64>,    // last_message_ts
) {
    if messages.is_empty() {
        return ("Unknown".to_string(), None, None, vec![], None);
    }

    // Find the last assistant message.
    let last_assistant = messages.iter().rev().find(|msg| {
        msg.get("info")
            .and_then(|i| i.get("role"))
            .and_then(|r| r.as_str())
            == Some("assistant")
    });

    let Some(last_assistant) = last_assistant else {
        return ("Unknown".to_string(), None, None, vec![], None);
    };

    let info = match last_assistant.get("info") {
        Some(i) => i,
        None => return ("Unknown".to_string(), None, None, vec![], None),
    };

    let parts = last_assistant
        .get("parts")
        .and_then(|p| p.as_array())
        .map(|arr| arr.as_slice())
        .unwrap_or(&[]);

    // Extract recent output from parts.
    let recent_output = {
        let mut lines = Vec::new();
        for part in parts {
            let part_type = part.get("type").and_then(|t| t.as_str()).unwrap_or("");
            match part_type {
                "text" => {
                    if let Some(text) = part.get("text").and_then(|t| t.as_str()) {
                        for line in text.lines().rev().take(SUMMARY_MAX_LINES) {
                            let truncated = if line.chars().count() > 80 {
                                let s: String = line.chars().take(77).collect();
                                format!("{s}...")
                            } else {
                                line.to_string()
                            };
                            if !truncated.trim().is_empty() {
                                lines.push(truncated);
                            }
                            if lines.len() >= SUMMARY_MAX_LINES {
                                break;
                            }
                        }
                    }
                }
                "tool" => {
                    if let Some(tool_name) = part.get("name").and_then(|n| n.as_str()) {
                        let status = part
                            .get("state")
                            .and_then(|s| s.get("status"))
                            .and_then(|s| s.as_str())
                            .unwrap_or("running");
                        lines.push(format!("\u{2192} {tool_name}: {status}"));
                    }
                }
                _ => {}
            }
            if lines.len() >= SUMMARY_MAX_LINES {
                break;
            }
        }
        lines.reverse();
        lines
    };

    // Extract current tool (first incomplete tool).
    let current_tool = parts.iter().find_map(|part| {
        if part.get("type").and_then(|t| t.as_str()) == Some("tool") {
            let status = part
                .get("state")
                .and_then(|s| s.get("status"))
                .and_then(|s| s.as_str());
            if status != Some("completed") && status != Some("error") {
                return part.get("name").and_then(|n| n.as_str()).map(String::from);
            }
        }
        None
    });

    // Build status line from first text part.
    let status_line = parts.iter().find_map(|part| {
        if part.get("type").and_then(|t| t.as_str()) == Some("text") {
            part.get("text").and_then(|t| t.as_str()).map(|text| {
                let first_line = text.lines().next().unwrap_or("");
                if first_line.chars().count() > 60 {
                    let s: String = first_line.chars().take(57).collect();
                    format!("{s}...")
                } else {
                    first_line.to_string()
                }
            })
        } else {
            None
        }
    });

    // Determine activity.
    let activity = if info.get("time").and_then(|t| t.get("completed")).is_none() {
        "Working"
    } else {
        let has_incomplete_tool = parts.iter().any(|part| {
            if part.get("type").and_then(|t| t.as_str()) == Some("tool") {
                let status = part
                    .get("state")
                    .and_then(|s| s.get("status"))
                    .and_then(|s| s.as_str());
                status != Some("completed") && status != Some("error")
            } else {
                false
            }
        });

        if has_incomplete_tool {
            "Working"
        } else {
            let finish = info.get("finish").and_then(|f| f.as_str()).unwrap_or("");
            if finish == "tool-calls" {
                "Working"
            } else {
                "Idle"
            }
        }
    };

    // Extract the most recent message timestamp.
    let last_message_ts = messages
        .iter()
        .filter_map(|msg| {
            msg.get("info").and_then(|info| {
                info.get("time").and_then(|time| {
                    time.get("completed")
                        .or_else(|| time.get("created"))
                        .and_then(|t| t.as_i64())
                })
            })
        })
        .max();

    (
        activity.to_string(),
        status_line,
        current_tool,
        recent_output,
        last_message_ts,
    )
}

// ---------------------------------------------------------------------------
// Opencode proxy and static file serving
// ---------------------------------------------------------------------------

/// Whether a path is an SSE event-stream endpoint.
fn is_event_stream_path(path: &str) -> bool {
    path == "event" || path.starts_with("event/") || path == "global" || path.starts_with("global/")
}

/// Return a long-lived SSE stream that sends periodic keepalive comments.
/// Prevents the opencode SDK from error-looping when the upstream isn't ready.
fn sse_keepalive_stream(comment: &str) -> Body {
    let initial = format!(": {comment}\n\n");
    let (tx, rx) = tokio::sync::mpsc::channel::<std::result::Result<String, std::io::Error>>(2);
    tokio::spawn(async move {
        if tx.send(Ok(initial)).await.is_err() {
            return;
        }
        let mut interval = tokio::time::interval(Duration::from_secs(30));
        loop {
            interval.tick().await;
            if tx.send(Ok(": keepalive\n\n".to_string())).await.is_err() {
                return;
            }
        }
    });
    Body::from_stream(tokio_stream::wrappers::ReceiverStream::new(rx))
}

/// Build a 200 OK SSE keepalive response.
fn sse_keepalive_response(comment: &str) -> std::result::Result<Response, StatusCode> {
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "text/event-stream")
        .header(header::CACHE_CONTROL, "no-cache")
        .body(sse_keepalive_stream(comment))
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
}

/// Whether a path's last segment contains a dot (i.e. looks like a static file).
fn has_file_extension(path: &str) -> bool {
    path.rsplit_once('/')
        .map_or(path, |(_dir, file)| file)
        .contains('.')
}

/// Whether a path (with leading `/` stripped) is an opencode REST/SSE API endpoint
/// that should be proxied to the upstream opencode server rather than served as
/// an SPA navigation route.
///
/// The list is derived from the opencode SDK's generated route table
/// (`sdk.gen.ts`). Everything that is *not* in this list and does not have a
/// file extension is treated as an SPA navigation path and served our vendored
/// `index.html`.
fn is_opencode_api_path(path: &str) -> bool {
    // All known opencode API top-level path segments. A request matches if the
    // trimmed path equals one of these exactly (e.g. `session`) *or* starts
    // with one followed by `/` (e.g. `session/abc123/message`).
    const API_SEGMENTS: &[&str] = &[
        "session",
        "global",
        "event",
        "auth",
        "project",
        "config",
        "experimental",
        "permission",
        "question",
        "provider",
        "find",
        "file",
        "mcp",
        "tui",
        "instance",
        "path",
        "vcs",
        "command",
        "log",
        "agent",
        "skill",
        "lsp",
        "formatter",
    ];

    // Extract the first path segment for matching.
    let first_segment = path.split('/').next().unwrap_or("");
    API_SEGMENTS.contains(&first_segment)
}

/// Proxy an HTTP request to the opencode server at localhost:4096.
///
/// Supports regular requests, SSE streaming, and HTTP Upgrade (WebSocket).
/// If the upstream is unreachable and the path is an event-stream endpoint,
/// returns an SSE keepalive stream instead of an error.
async fn proxy_to_opencode(
    path: &str,
    password: &str,
    request: Request,
) -> std::result::Result<Response, StatusCode> {
    let host = "127.0.0.1";
    let port = OPENCODE_UPSTREAM_PORT;

    // Connect to the opencode server.
    // For SSE/event paths, return a keepalive stream immediately if unreachable.
    // For regular API paths, retry a few times so the SPA doesn't see errors
    // while opencode is still starting up after a rebuild.
    let stream = if is_event_stream_path(path) {
        match tokio::net::TcpStream::connect(format!("{}:{}", host, port)).await {
            Ok(s) => s,
            Err(e) => {
                tracing::debug!("Cannot connect to opencode at {}:{}: {}", host, port, e);
                return sse_keepalive_response("opencode not ready");
            }
        }
    } else {
        const MAX_RETRIES: u32 = 3;
        const RETRY_DELAY: Duration = Duration::from_secs(1);
        let mut last_err = None;
        let mut connected = None;
        for attempt in 0..MAX_RETRIES {
            match tokio::net::TcpStream::connect(format!("{}:{}", host, port)).await {
                Ok(s) => {
                    connected = Some(s);
                    break;
                }
                Err(e) => {
                    tracing::debug!(
                        "Cannot connect to opencode at {}:{} (attempt {}/{}): {}",
                        host,
                        port,
                        attempt + 1,
                        MAX_RETRIES,
                        e
                    );
                    last_err = Some(e);
                    if attempt + 1 < MAX_RETRIES {
                        tokio::time::sleep(RETRY_DELAY).await;
                    }
                }
            }
        }
        match connected {
            Some(s) => s,
            None => {
                tracing::warn!(
                    "opencode at {}:{} unreachable after {} attempts: {}",
                    host,
                    port,
                    MAX_RETRIES,
                    last_err.unwrap()
                );
                return Err(StatusCode::BAD_GATEWAY);
            }
        }
    };

    let io = TokioIo::new(stream);
    let is_upgrade = request.headers().get(header::UPGRADE).is_some();

    let (mut sender, conn) = hyper::client::conn::http1::handshake(io)
        .await
        .map_err(|e| {
            tracing::error!("Handshake with opencode server failed: {}", e);
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
                tracing::error!("Connection to opencode server failed: {}", e);
            }
        });
    }

    // Build the upstream URI, preserving query string
    let mut uri = if path.is_empty() || path == "/" {
        "/".to_string()
    } else if path.starts_with('/') {
        path.to_string()
    } else {
        format!("/{}", path)
    };
    if let Some(query) = request.uri().query() {
        uri.push('?');
        uri.push_str(query);
    }

    let (parts, body) = request.into_parts();

    // Add Basic auth header
    let credentials = BASE64_STANDARD.encode(format!("opencode:{}", password));
    let mut builder = hyper::Request::builder()
        .method(parts.method.clone())
        .uri(&uri)
        .header(header::HOST, format!("{}:{}", host, port))
        .header(header::AUTHORIZATION, format!("Basic {}", credentials));

    // Copy headers (except Host and Authorization which we set)
    for (key, value) in parts.headers.iter() {
        if key != header::HOST && key != header::AUTHORIZATION {
            builder = builder.header(key, value);
        }
    }

    let proxy_request = builder.body(body).map_err(|e| {
        tracing::error!("Failed to build opencode proxy request: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let upstream_response = sender.send_request(proxy_request).await.map_err(|e| {
        tracing::error!("Failed to send request to opencode: {}", e);
        StatusCode::BAD_GATEWAY
    })?;

    // Handle HTTP Upgrade (WebSocket) responses
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
                (Err(e), _) => {
                    tracing::error!("Client upgrade failed: {}", e);
                }
                (_, Err(e)) => {
                    tracing::error!("Upstream upgrade failed: {}", e);
                }
            }
        });

        return response_builder.body(Body::empty()).map_err(|e| {
            tracing::error!("Failed to build upgrade response: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        });
    }

    // Normal response: normalize HTTP version for SSE/chunked support
    let (mut resp_parts, body) = upstream_response.into_parts();
    resp_parts.version = hyper::Version::HTTP_11;
    let body = Body::new(body);

    Ok(Response::from_parts(resp_parts, body))
}

/// Fallback handler: serves static files from the vendored UI or proxies to opencode.
///
/// Priority:
/// 1. If the path has a file extension → try serving from the vendored UI directory,
///    then fall through to the opencode proxy if the file isn't found locally.
/// 2. If the path is a known opencode API route → proxy to localhost:4096.
/// 3. Everything else (SPA navigation like `/`, `/:dir`, `/:dir/session/:id`) →
///    serve our vendored `index.html` directly so that the opencode server's own
///    index.html is never exposed to the browser.
async fn fallback_handler(State(state): State<AppState>, request: Request) -> Response {
    let path = request.uri().path().to_string();
    let trimmed = path.trim_start_matches('/');

    // 1. Static files: serve from the vendored UI directory first.
    if has_file_extension(trimmed) {
        let file_req = Request::builder()
            .uri(request.uri().clone())
            .body(Body::empty())
            .unwrap();
        let resp = ServeDir::new(OPENCODE_UI_PATH)
            .oneshot(file_req)
            .await
            .unwrap()
            .into_response();
        if resp.status() != StatusCode::NOT_FOUND {
            return resp;
        }
        // File not found in UI dir — fall through to proxy (opencode may serve it)
    }

    // 2. Opencode API paths: proxy to the upstream opencode server.
    if has_file_extension(trimmed) || is_opencode_api_path(trimmed) {
        return match proxy_to_opencode(trimmed, &state.opencode_password, request).await {
            Ok(resp) => resp,
            Err(status) => status.into_response(),
        };
    }

    // 3. SPA fallback: serve our vendored index.html for all navigation routes.
    let index_html = format!("{}/index.html", OPENCODE_UI_PATH);
    let serve_dir = ServeDir::new(OPENCODE_UI_PATH).fallback(ServeFile::new(&index_html));
    let fallback_req = Request::builder().uri("/").body(Body::empty()).unwrap();
    serve_dir
        .oneshot(fallback_req)
        .await
        .unwrap()
        .into_response()
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
    #[arg(long, default_value = "")]
    opencode_password: String,
}

/// Build the axum router (public for testing).
fn build_router(state: AppState) -> Router {
    Router::new()
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
        // PTY endpoints
        .route("/pty", get(pty_list).post(pty_create))
        .route(
            "/pty/{pty_id}",
            get(pty_get).put(pty_update).delete(pty_delete),
        )
        .route("/pty/{pty_id}/connect", get(pty_connect))
        // Fallback: static UI files and opencode API proxy
        .fallback(fallback_handler)
        .with_state(state)
}

/// Run the pod-api HTTP server.
pub(crate) async fn run(args: PodApiArgs) -> Result<()> {
    let workspace = Arc::new(args.workspace.clone());
    let git_events_tx = GitWatcher::spawn(Arc::clone(&workspace));

    let state = AppState {
        workspace,
        git_events_tx,
        pty_sessions: PtySessionManager::new(),
        workspace_container: args.workspace_container.unwrap_or_default(),
        agent_container: args.agent_container.unwrap_or_default(),
        opencode_password: args.opencode_password,
    };

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

    #[test]
    fn test_has_file_extension() {
        assert!(has_file_extension("index.html"));
        assert!(has_file_extension("assets/main.js"));
        assert!(has_file_extension("deep/path/style.css"));
        assert!(!has_file_extension(""));
        assert!(!has_file_extension("session"));
        assert!(!has_file_extension("mydir/session/abc123"));
        assert!(!has_file_extension("global/health"));
    }

    #[test]
    fn test_is_opencode_api_path_bare_segments() {
        // All known API segments should match when used alone
        for path in [
            "session",
            "global",
            "event",
            "auth",
            "project",
            "config",
            "experimental",
            "permission",
            "question",
            "provider",
            "find",
            "file",
            "mcp",
            "tui",
            "instance",
            "path",
            "vcs",
            "command",
            "log",
            "agent",
            "skill",
            "lsp",
            "formatter",
        ] {
            assert!(is_opencode_api_path(path), "expected API path: {path}");
        }
    }

    #[test]
    fn test_is_opencode_api_path_with_subpaths() {
        assert!(is_opencode_api_path("session/abc123"));
        assert!(is_opencode_api_path("session/abc123/message"));
        assert!(is_opencode_api_path(
            "session/abc123/message/msg456/part/p789"
        ));
        assert!(is_opencode_api_path("global/health"));
        assert!(is_opencode_api_path("global/config"));
        assert!(is_opencode_api_path("global/event"));
        assert!(is_opencode_api_path("auth/github"));
        assert!(is_opencode_api_path("project/current"));
        assert!(is_opencode_api_path("config/providers"));
        assert!(is_opencode_api_path("experimental/tool"));
        assert!(is_opencode_api_path("permission/req123/reply"));
        assert!(is_opencode_api_path("question/req456/reply"));
        assert!(is_opencode_api_path("provider/openai/oauth/authorize"));
        assert!(is_opencode_api_path("find/file"));
        assert!(is_opencode_api_path("file/content"));
        assert!(is_opencode_api_path("mcp/myserver/connect"));
        assert!(is_opencode_api_path("tui/submit-prompt"));
        assert!(is_opencode_api_path("instance/dispose"));
        assert!(is_opencode_api_path("event/something"));
    }

    #[test]
    fn test_is_opencode_api_path_rejects_spa_navigation() {
        // Root path (trimmed to empty string)
        assert!(!is_opencode_api_path(""));
        // /:dir style SPA routes — arbitrary workspace directory names
        assert!(!is_opencode_api_path("myproject"));
        assert!(!is_opencode_api_path("some-workspace"));
        assert!(!is_opencode_api_path("my-repo/session/abc123"));
        // Random unknown paths should not be treated as API
        assert!(!is_opencode_api_path("unknown"));
        assert!(!is_opencode_api_path("foo/bar"));
    }

    #[test]
    fn test_is_event_stream_path() {
        assert!(is_event_stream_path("event"));
        assert!(is_event_stream_path("event/something"));
        assert!(is_event_stream_path("global"));
        assert!(is_event_stream_path("global/event"));
        assert!(!is_event_stream_path("session"));
        assert!(!is_event_stream_path(""));
        assert!(!is_event_stream_path("config"));
    }
}
