//! TUI (Text User Interface) for devaipod
//!
//! Provides a real-time dashboard for managing devaipod instances using async Rust
//! with ratatui for rendering. Data is fetched from the local web REST API
//! (`/api/devaipod/pods`) rather than accessing the container runtime directly.

use std::collections::HashMap;
use std::io::{self, IsTerminal, Stdout};
use std::time::Duration;

use color_eyre::eyre::{Context, Result};
use crossterm::event::{
    Event, EventStream, KeyCode, KeyEventKind, KeyModifiers, KeyboardEnhancementFlags,
    PopKeyboardEnhancementFlags, PushKeyboardEnhancementFlags,
};
use crossterm::execute;
use crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
    supports_keyboard_enhancement,
};
use futures_util::StreamExt;
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style, Stylize};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, Paragraph, TableState, Wrap};
use tokio::time::interval;

/// Prefix for all devaipod pod names
const POD_NAME_PREFIX: &str = "devaipod-";

/// Default state directory (matches web server's default).
const DEFAULT_STATE_DIR: &str = "/var/lib/devaipod";

/// Default web API port.
const DEFAULT_WEB_PORT: u16 = 8080;

/// Response shape for the unified pod list endpoint (`GET /api/devaipod/pods`).
#[derive(Debug, serde::Deserialize)]
struct ApiPodInfo {
    name: String,
    status: String,
    created: String,
    #[serde(default)]
    labels: Option<HashMap<String, String>>,
    #[serde(default)]
    containers: Option<Vec<ApiContainerInfo>>,
    #[serde(default)]
    agent_status: Option<ApiAgentStatus>,
    #[serde(default)]
    last_active_ts: Option<i64>,
}

/// Container entry inside the API response.
#[derive(Debug, serde::Deserialize)]
struct ApiContainerInfo {
    #[serde(rename = "Names")]
    names: String,
    #[serde(rename = "Status")]
    status: String,
}

/// Agent status from the pod-api sidecar, nested inside `ApiPodInfo`.
#[derive(Debug, serde::Deserialize)]
struct ApiAgentStatus {
    activity: String,
    #[serde(default)]
    status_line: Option<String>,
    #[serde(default)]
    current_tool: Option<String>,
    #[serde(default)]
    recent_output: Vec<String>,
    #[serde(default)]
    last_message_ts: Option<i64>,
    #[serde(default)]
    title: Option<String>,
}

/// Read the web auth token from the state directory.
pub(crate) fn read_api_token() -> Result<String> {
    let state_dir =
        std::env::var("DEVAIPOD_STATE_DIR").unwrap_or_else(|_| DEFAULT_STATE_DIR.to_string());
    let token_path = std::path::PathBuf::from(state_dir).join("web-token");
    std::fs::read_to_string(&token_path)
        .map(|t| t.trim().to_string())
        .with_context(|| format!("Failed to read API token from {}", token_path.display()))
}

/// Determine the web API port from environment or default.
pub(crate) fn api_port() -> u16 {
    std::env::var("DEVAIPOD_WEB_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(DEFAULT_WEB_PORT)
}

/// Agent activity state (idle, working, etc.)
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum AgentActivity {
    /// Agent is running but waiting for input
    Idle,
    /// Agent is actively processing a task
    Working,
    /// Agent container is not running
    #[default]
    Stopped,
    /// Could not determine agent state (API error, etc.)
    Unknown,
}

/// Rich agent state including activity and recent output
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct AgentState {
    /// Current activity level
    pub activity: AgentActivity,
    /// Recent output lines from the agent (last 3-4 lines)
    pub recent_output: Vec<String>,
    /// Current tool being used (if any)
    pub current_tool: Option<String>,
    /// Brief summary of what agent is doing
    pub status_line: Option<String>,
    /// Timestamp of the most recent message (Unix milliseconds)
    pub last_message_ts: Option<i64>,
}

/// Git repository state
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct GitState {
    /// Current branch name
    pub branch: Option<String>,
    /// Whether there are uncommitted changes
    pub dirty: bool,
    /// Number of commits ahead of remote
    pub ahead: u32,
    /// Number of commits behind remote
    pub behind: u32,
    /// Short summary (e.g., "main ✓" or "feature-x *+2-1")
    pub summary: String,
}

impl GitState {
    /// Create a summary string for display
    #[allow(dead_code)]
    fn compute_summary(&mut self) {
        let branch = self.branch.as_deref().unwrap_or("detached");
        let dirty_indicator = if self.dirty { "*" } else { "" };

        let ahead_behind = match (self.ahead, self.behind) {
            (0, 0) => String::new(),
            (a, 0) => format!(" ↑{}", a),
            (0, b) => format!(" ↓{}", b),
            (a, b) => format!(" ↑{}↓{}", a, b),
        };

        self.summary = format!("{}{}{}", branch, dirty_indicator, ahead_behind);
    }
}

/// Information about a devaipod instance gathered from bollard
#[derive(Debug, Clone)]
pub struct InstanceInfo {
    /// Short name (without devaipod- prefix)
    pub name: String,
    /// Full pod name (used by subprocess commands via name, kept for completeness)
    #[allow(dead_code)]
    pub full_name: String,
    /// Pod status (Running, Exited, Degraded)
    pub status: String,
    /// Repository URL from labels
    pub repo: Option<String>,
    /// Current task description from labels
    pub task: Option<String>,
    /// Human-readable session title (from pod-api or labels)
    pub title: Option<String>,
    /// Mode (up, run, etc.)
    pub mode: Option<String>,
    /// Whether the agent is healthy
    pub agent_healthy: Option<bool>,
    /// Created timestamp (formatted for display)
    pub created: Option<String>,
    /// Raw creation timestamp (Unix seconds) for sorting
    #[allow(dead_code)]
    pub created_ts: Option<i64>,
    /// Git repository state (fetched async)
    pub git_state: Option<GitState>,
    /// Workspace directory path inside container
    #[allow(dead_code)]
    pub workspace_path: Option<String>,
    /// Last time git state was refreshed for this instance (for rate-limiting)
    #[allow(dead_code)]
    pub last_git_refresh: Option<std::time::Instant>,
    /// Agent activity state (fetched async)
    pub agent_state: AgentState,
    /// Last time agent state was refreshed for this instance
    #[allow(dead_code)]
    pub last_agent_refresh: Option<std::time::Instant>,
    /// API password for the agent backend (from pod labels)
    #[allow(dead_code)]
    pub api_password: Option<String>,
    /// Published host port for the agent API
    #[allow(dead_code)]
    pub api_port: Option<u16>,
    /// Whether service-gator container is running
    pub gator_healthy: Option<bool>,
    /// Service-gator scopes (from pod labels)
    pub gator_scopes: Option<String>,
    /// Most recent activity timestamp (Unix milliseconds) for sorting by "last active"
    /// Derived from agent state (last message time) or falls back to created_ts
    pub last_activity_ts: Option<i64>,
    /// Whether worker container exists and is running
    pub worker_healthy: Option<bool>,
    /// Names of containers that are not running (for degraded status display)
    pub degraded_containers: Vec<String>,
}

/// Mode of the TUI (normal browsing vs delete selection)
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum TuiMode {
    /// Normal browsing mode
    #[default]
    Normal,
    /// Delete selection mode - allows selecting multiple instances
    DeleteSelect,
    /// Confirming deletion of selected instances
    DeleteConfirm,
    /// Launch dialog - input URLs and task
    Launch,
    /// Container access menu - select which container/shell to access
    ContainerMenu,
    /// Editing the filter text
    Filter,
}

/// Menu item in the container access menu
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContainerMenuItem {
    /// Attach to orchestrator agent (default attach)
    OrchestratorAgent,
    /// Attach to worker agent
    WorkerAgent,
    /// Exec shell into worker container
    WorkerShell,
    /// Exec shell into workspace container
    WorkspaceShell,
}

impl ContainerMenuItem {
    /// Get display label for menu item
    fn label(&self) -> &'static str {
        match self {
            ContainerMenuItem::OrchestratorAgent => "1. Orchestrator Agent",
            ContainerMenuItem::WorkerAgent => "2. Worker Agent",
            ContainerMenuItem::WorkerShell => "3. Worker Shell",
            ContainerMenuItem::WorkspaceShell => "4. Workspace Shell",
        }
    }

    /// Get description for menu item
    fn description(&self) -> &'static str {
        match self {
            ContainerMenuItem::OrchestratorAgent => "attach to task owner agent",
            ContainerMenuItem::WorkerAgent => "attach to worker agent",
            ContainerMenuItem::WorkerShell => "bash shell in worker container",
            ContainerMenuItem::WorkspaceShell => "bash shell in workspace container",
        }
    }

    /// All menu items in order
    fn all() -> &'static [ContainerMenuItem] {
        &[
            ContainerMenuItem::OrchestratorAgent,
            ContainerMenuItem::WorkerAgent,
            ContainerMenuItem::WorkerShell,
            ContainerMenuItem::WorkspaceShell,
        ]
    }

    /// Whether this menu item requires the worker container to be available
    fn requires_worker(&self) -> bool {
        matches!(
            self,
            ContainerMenuItem::WorkerAgent | ContainerMenuItem::WorkerShell
        )
    }
}

/// Which field is active in the launch dialog
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum LaunchField {
    #[default]
    Urls,
    Task,
    Submit,
}

/// State for the launch dialog
#[derive(Debug, Clone, Default)]
pub struct LaunchInput {
    /// URLs (one per line)
    pub urls: String,
    /// Task to run
    pub task: String,
    /// Which field is currently active
    pub active_field: LaunchField,
}

/// Action to perform after exiting TUI
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// Just quit, no further action
    Quit,
    /// Attach to the specified instance (opens tmux with agent + shell)
    Attach(String),
    /// Trigger a refresh
    Refresh,
    /// Delete selected instances
    Delete(Vec<String>),
    /// Toggle start/stop for an instance
    ToggleStartStop(String),
    /// Exec into agent container
    ExecAgent(String),
    /// Exec into workspace container
    ExecWorkspace(String),
    /// Attach to worker agent
    AttachWorker(String),
    /// Exec into worker container
    ExecWorker(String),
    /// Launch new instances with URLs and a task
    Launch { urls: Vec<String>, task: String },
    /// Launch/attach the advisor
    Advisor,
    /// Open the review TUI for the specified instance
    Review(String),
    /// Rebuild (recreate) the selected instance
    Rebuild(String),
}

/// Application state for the TUI
pub struct App {
    /// Reusable HTTP client for API requests
    http_client: reqwest::Client,
    /// Auth token for the web API
    api_token: String,
    /// Web API port
    api_port: u16,
    /// List of instances
    instances: Vec<InstanceInfo>,
    /// Table selection state
    table_state: TableState,
    /// Last refresh time
    last_refresh: std::time::Instant,
    /// Status message
    status_message: Option<String>,
    /// Current TUI mode (normal, delete select, etc.)
    mode: TuiMode,
    /// Instances selected for deletion (by name)
    selected_for_delete: std::collections::HashSet<String>,
    /// Launch dialog input state
    launch_input: LaunchInput,
    /// Selected item in container menu (0-3)
    container_menu_selection: usize,
    /// Text filter applied to instance list (matches name, repo, task)
    filter_text: String,
    /// Whether we're in a git repo (used for launch dialog defaults)
    in_git_repo: bool,
    /// All instances before filtering (so filter edits don't lose data)
    all_instances: Vec<InstanceInfo>,
    /// Whether to show inactive (stopped/exited) pods
    show_inactive: bool,
}

impl App {
    /// Create a new App instance.
    ///
    /// When `show_all` is false and CWD is inside a git repo, instances are
    /// filtered to only those whose repo label matches the current repo.
    pub async fn new(show_all: bool) -> Result<Self> {
        let token = read_api_token()?;
        let port = api_port();
        let http_client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .context("Failed to create HTTP client")?;

        // Initialize default filter from CWD repo
        let in_git_repo = crate::repo_root_path().is_ok();
        let default_filter = if !show_all && in_git_repo {
            crate::repo_root_path()
                .ok()
                .and_then(|root| crate::extract_repo_suffix(&root.to_string_lossy()))
                .and_then(|s| {
                    // Use org/repo portion after the host
                    s.split_once('/').map(|(_, rest)| rest.to_string())
                })
                .unwrap_or_default()
        } else {
            String::new()
        };

        let mut app = Self {
            http_client,
            api_token: token,
            api_port: port,
            instances: Vec::new(),
            table_state: TableState::default(),
            last_refresh: std::time::Instant::now(),
            status_message: None,
            mode: TuiMode::Normal,
            selected_for_delete: std::collections::HashSet::new(),
            launch_input: LaunchInput {
                urls: if in_git_repo {
                    ".".to_string()
                } else {
                    String::new()
                },
                ..LaunchInput::default()
            },
            container_menu_selection: 0,
            filter_text: default_filter,
            in_git_repo,
            all_instances: Vec::new(),
            show_inactive: false,
        };

        // Initial data fetch
        app.refresh_from_api().await?;

        Ok(app)
    }

    /// Refresh the list of instances from the web REST API.
    async fn refresh_from_api(&mut self) -> Result<()> {
        let url = format!("http://127.0.0.1:{}/api/devaipod/pods", self.api_port);
        let resp = self
            .http_client
            .get(&url)
            .header("Authorization", format!("Bearer {}", self.api_token))
            .send()
            .await
            .context("Failed to reach web API")?;

        if !resp.status().is_success() {
            color_eyre::eyre::bail!("API returned {}", resp.status());
        }

        let pods: Vec<ApiPodInfo> = resp.json().await.context("Failed to parse API response")?;

        let mut instances: Vec<InstanceInfo> = pods
            .into_iter()
            .map(|api| {
                let labels = api.labels.as_ref();

                let short_name = api
                    .name
                    .strip_prefix(POD_NAME_PREFIX)
                    .unwrap_or(&api.name)
                    .to_string();

                let repo = labels.and_then(|l| l.get("io.devaipod.repo")).cloned();
                let task = labels.and_then(|l| l.get("io.devaipod.task")).cloned();
                let mode = labels.and_then(|l| l.get("io.devaipod.mode")).cloned();

                // Title: prefer agent_status title, fall back to label
                let title = api
                    .agent_status
                    .as_ref()
                    .and_then(|s| s.title.clone())
                    .or_else(|| labels.and_then(|l| l.get("io.devaipod.title")).cloned());

                let is_running = api.status.eq_ignore_ascii_case("running");

                // Agent health: running status + agent_status present
                let agent_healthy = if is_running {
                    Some(api.agent_status.is_some())
                } else {
                    Some(false)
                };

                // Map agent_status to AgentState
                let agent_state = match &api.agent_status {
                    Some(status) => {
                        let activity = match status.activity.as_str() {
                            "Working" => AgentActivity::Working,
                            "Idle" => AgentActivity::Idle,
                            "Stopped" => AgentActivity::Stopped,
                            _ => AgentActivity::Unknown,
                        };
                        AgentState {
                            activity,
                            recent_output: status.recent_output.clone(),
                            current_tool: status.current_tool.clone(),
                            status_line: status.status_line.clone(),
                            last_message_ts: status.last_message_ts,
                        }
                    }
                    None => AgentState {
                        activity: if is_running {
                            AgentActivity::Unknown
                        } else {
                            AgentActivity::Stopped
                        },
                        ..Default::default()
                    },
                };

                // Gator health: check containers list for a container with
                // "-gator" in name that has "Up" in status
                let gator_healthy = api.containers.as_ref().map(|cs| {
                    cs.iter()
                        .any(|c| c.names.contains("-gator") && c.status.contains("Up"))
                });

                let gator_scopes = labels
                    .and_then(|l| l.get("io.devaipod.service-gator"))
                    .cloned();

                // Worker health
                let worker_healthy = api.containers.as_ref().map(|cs| {
                    cs.iter()
                        .any(|c| c.names.contains("-worker") && c.status.contains("Up"))
                });

                // Degraded containers: those without "Up" in status
                let degraded_containers: Vec<String> = api
                    .containers
                    .as_ref()
                    .map(|cs| {
                        cs.iter()
                            .filter(|c| !c.status.contains("Up") && !c.names.contains("-infra"))
                            .map(|c| {
                                c.names
                                    .strip_prefix(&format!("{}-", api.name))
                                    .unwrap_or(&c.names)
                                    .to_string()
                            })
                            .collect()
                    })
                    .unwrap_or_default();

                InstanceInfo {
                    name: short_name,
                    full_name: api.name,
                    status: api.status,
                    repo,
                    task,
                    title,
                    mode,
                    agent_healthy,
                    created: Some(api.created),
                    created_ts: None,
                    git_state: None,
                    workspace_path: None,
                    last_git_refresh: None,
                    agent_state,
                    last_agent_refresh: None,
                    api_password: None,
                    api_port: None,
                    gator_healthy,
                    gator_scopes,
                    last_activity_ts: api.last_active_ts,
                    worker_healthy,
                    degraded_containers,
                }
            })
            .collect();

        // Sort by last activity time (most recently active first)
        instances.sort_by(|a, b| match (b.last_activity_ts, a.last_activity_ts) {
            (Some(b_ts), Some(a_ts)) => b_ts.cmp(&a_ts).then_with(|| a.name.cmp(&b.name)),
            (Some(_), None) => std::cmp::Ordering::Less,
            (None, Some(_)) => std::cmp::Ordering::Greater,
            (None, None) => a.name.cmp(&b.name),
        });

        self.all_instances = instances;
        self.apply_filter();
        self.last_refresh = std::time::Instant::now();

        // Ensure selection is valid and within bounds
        if let Some(selected) = self.table_state.selected() {
            if selected >= self.instances.len() {
                self.table_state.select(if self.instances.is_empty() {
                    None
                } else {
                    Some(self.instances.len() - 1)
                });
            }
        } else if !self.instances.is_empty() {
            self.table_state.select(Some(0));
        }

        Ok(())
    }

    /// Apply the current filter_text and inactive filter to all_instances.
    fn apply_filter(&mut self) {
        let candidates: Box<dyn Iterator<Item = &InstanceInfo>> = if self.filter_text.is_empty() {
            Box::new(self.all_instances.iter())
        } else {
            let filter = self.filter_text.to_lowercase();
            Box::new(self.all_instances.iter().filter(move |inst| {
                inst.name.to_lowercase().contains(&filter)
                    || inst
                        .repo
                        .as_deref()
                        .is_some_and(|r| r.to_lowercase().contains(&filter))
                    || inst
                        .task
                        .as_deref()
                        .is_some_and(|t| t.to_lowercase().contains(&filter))
            }))
        };

        self.instances = candidates
            .filter(|inst| {
                if self.show_inactive {
                    true
                } else {
                    let s = inst.status.to_lowercase();
                    s != "stopped" && s != "exited"
                }
            })
            .cloned()
            .collect();
        // Keep selection in bounds
        if let Some(selected) = self.table_state.selected() {
            if selected >= self.instances.len() {
                self.table_state.select(if self.instances.is_empty() {
                    None
                } else {
                    Some(self.instances.len() - 1)
                });
            }
        } else if !self.instances.is_empty() {
            self.table_state.select(Some(0));
        }
    }

    /// Move selection up
    pub fn previous(&mut self) {
        if self.instances.is_empty() {
            return;
        }
        let i = match self.table_state.selected() {
            Some(i) => {
                if i == 0 {
                    self.instances.len() - 1
                } else {
                    i - 1
                }
            }
            None => 0,
        };
        self.table_state.select(Some(i));
    }

    /// Move selection down
    pub fn next(&mut self) {
        if self.instances.is_empty() {
            return;
        }
        let i = match self.table_state.selected() {
            Some(i) => {
                if i >= self.instances.len() - 1 {
                    0
                } else {
                    i + 1
                }
            }
            None => 0,
        };
        self.table_state.select(Some(i));
    }

    /// Get the currently selected instance
    pub fn selected_instance(&self) -> Option<&InstanceInfo> {
        self.table_state
            .selected()
            .and_then(|i| self.instances.get(i))
    }
}

/// Truncate a string to a maximum number of characters, adding "..." if truncated.
///
/// This correctly handles multi-byte UTF-8 characters by counting characters,
/// not bytes.
#[cfg(test)]
fn truncate_with_ellipsis(s: &str, max_chars: usize) -> String {
    if s.chars().count() <= max_chars {
        s.to_string()
    } else {
        let truncated: String = s.chars().take(max_chars.saturating_sub(3)).collect();
        format!("{truncated}...")
    }
}

/// Setup terminal for TUI mode with optional keyboard enhancement.
/// Returns whether keyboard enhancement was enabled (for cleanup).
fn setup_terminal() -> Result<(Terminal<CrosstermBackend<Stdout>>, bool)> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();

    // Enable keyboard enhancement if supported (for Ctrl+Enter to work correctly)
    let keyboard_enhancement_enabled = if supports_keyboard_enhancement().unwrap_or(false) {
        execute!(
            stdout,
            PushKeyboardEnhancementFlags(KeyboardEnhancementFlags::DISAMBIGUATE_ESCAPE_CODES)
        )
        .is_ok()
    } else {
        false
    };

    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let terminal = Terminal::new(backend)?;
    Ok((terminal, keyboard_enhancement_enabled))
}

/// Restore terminal from TUI mode.
fn restore_terminal(
    terminal: &mut Terminal<CrosstermBackend<Stdout>>,
    keyboard_enhancement_enabled: bool,
) -> Result<()> {
    disable_raw_mode()?;
    if keyboard_enhancement_enabled {
        let _ = execute!(terminal.backend_mut(), PopKeyboardEnhancementFlags);
    }
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;
    Ok(())
}

/// Run the TUI application
pub async fn run(show_all: bool) -> Result<()> {
    // Check if we're running in a terminal
    if !std::io::stdout().is_terminal() {
        color_eyre::eyre::bail!(
            "TUI requires a terminal. Use 'devaipod list' for non-interactive output."
        );
    }

    let (mut terminal, keyboard_enhancement) = setup_terminal()?;

    // Create app and run
    let app = App::new(show_all).await?;
    let result = run_app(&mut terminal, app).await;

    // Restore terminal
    restore_terminal(&mut terminal, keyboard_enhancement)?;

    result
}

/// Result from the standalone launch prompt
pub struct LaunchPromptResult {
    /// The source URL
    pub url: String,
    /// The task to run
    pub task: String,
}

/// State for the standalone launch prompt
struct LaunchPromptApp {
    /// Current input state
    input: LaunchInput,
    /// Status message
    status_message: Option<String>,
}

impl LaunchPromptApp {
    fn new(url: &str, task: &str) -> Self {
        Self {
            input: LaunchInput {
                urls: url.to_string(),
                task: task.to_string(),
                active_field: if url.is_empty() {
                    LaunchField::Urls
                } else {
                    LaunchField::Task
                },
            },
            status_message: None,
        }
    }
}

/// Run a standalone launch prompt for the `run` command.
///
/// This provides a simple editable dialog for URL and task input,
/// similar to the launch dialog in the full TUI.
///
/// Returns `Ok(Some(result))` if the user submitted, `Ok(None)` if cancelled.
pub async fn prompt_launch_input(url: &str, task: &str) -> Result<Option<LaunchPromptResult>> {
    // Check if we're running in a terminal
    if !std::io::stdout().is_terminal() {
        color_eyre::eyre::bail!("Interactive prompt requires a terminal");
    }

    let (mut terminal, keyboard_enhancement) = setup_terminal()?;

    // Run the prompt
    let result = run_launch_prompt(&mut terminal, url, task).await;

    // Restore terminal
    restore_terminal(&mut terminal, keyboard_enhancement)?;

    result
}

/// Main loop for the standalone launch prompt
async fn run_launch_prompt(
    terminal: &mut Terminal<CrosstermBackend<Stdout>>,
    url: &str,
    task: &str,
) -> Result<Option<LaunchPromptResult>> {
    let mut app = LaunchPromptApp::new(url, task);
    let mut event_stream = EventStream::new();

    loop {
        // Draw the UI
        terminal.draw(|f| render_launch_prompt(f, &app))?;

        // Wait for event
        if let Some(Ok(Event::Key(key))) = event_stream.next().await {
            if key.kind != KeyEventKind::Press {
                continue;
            }

            match key.code {
                KeyCode::Esc => {
                    // Cancel
                    return Ok(None);
                }
                KeyCode::Tab => {
                    // Cycle forward through fields
                    app.input.active_field = match app.input.active_field {
                        LaunchField::Urls => LaunchField::Task,
                        LaunchField::Task => LaunchField::Submit,
                        LaunchField::Submit => LaunchField::Urls,
                    };
                }
                KeyCode::BackTab => {
                    // Cycle backward through fields
                    app.input.active_field = match app.input.active_field {
                        LaunchField::Urls => LaunchField::Submit,
                        LaunchField::Task => LaunchField::Urls,
                        LaunchField::Submit => LaunchField::Task,
                    };
                }
                KeyCode::Enter if key.modifiers.contains(KeyModifiers::CONTROL) => {
                    // Ctrl+Enter: Submit from any field
                    let url = app.input.urls.trim().to_string();
                    let task = app.input.task.trim().to_string();

                    if url.is_empty() {
                        app.status_message = Some("Enter a URL".to_string());
                    } else if task.is_empty() {
                        app.status_message = Some("Enter a task".to_string());
                    } else {
                        return Ok(Some(LaunchPromptResult { url, task }));
                    }
                }
                KeyCode::Enter => {
                    // Regular Enter: add newline to text fields, or submit if on button
                    match app.input.active_field {
                        LaunchField::Urls => {
                            app.input.urls.push('\n');
                        }
                        LaunchField::Task => {
                            app.input.task.push('\n');
                        }
                        LaunchField::Submit => {
                            // Submit button pressed
                            let url = app.input.urls.trim().to_string();
                            let task = app.input.task.trim().to_string();

                            if url.is_empty() {
                                app.status_message = Some("Enter a URL".to_string());
                                app.input.active_field = LaunchField::Urls;
                            } else if task.is_empty() {
                                app.status_message = Some("Enter a task".to_string());
                                app.input.active_field = LaunchField::Task;
                            } else {
                                return Ok(Some(LaunchPromptResult { url, task }));
                            }
                        }
                    }
                }
                KeyCode::Backspace => {
                    // Delete character from active field (no-op for Submit button)
                    match app.input.active_field {
                        LaunchField::Urls => {
                            app.input.urls.pop();
                        }
                        LaunchField::Task => {
                            app.input.task.pop();
                        }
                        LaunchField::Submit => {}
                    }
                }
                KeyCode::Char(c) => {
                    // Add character to active field (no-op for Submit button)
                    match app.input.active_field {
                        LaunchField::Urls => {
                            app.input.urls.push(c);
                        }
                        LaunchField::Task => {
                            app.input.task.push(c);
                        }
                        LaunchField::Submit => {}
                    }
                }
                _ => {}
            }
        }
    }
}

/// Render the standalone launch prompt
fn render_launch_prompt(frame: &mut ratatui::Frame, app: &LaunchPromptApp) {
    let area = frame.area();

    // Clear the entire screen
    frame.render_widget(Clear, area);

    // Calculate dialog size - centered, fixed width
    let popup_width = (area.width * 70 / 100).max(60).min(area.width - 4);
    let popup_height = 20u16.min(area.height - 2);
    let popup_x = (area.width.saturating_sub(popup_width)) / 2;
    let popup_y = (area.height.saturating_sub(popup_height)) / 2;
    let popup_area = Rect::new(popup_x, popup_y, popup_width, popup_height);

    // Split popup into title, URL field, Task field, submit button, and footer
    let chunks = Layout::vertical([
        Constraint::Length(3), // Title
        Constraint::Length(4), // URL field (single URL for run)
        Constraint::Min(5),    // Task field (expandable)
        Constraint::Length(3), // Submit button
        Constraint::Length(3), // Footer
    ])
    .split(popup_area);

    // Title bar
    let title = Paragraph::new(" Launch New Instance ")
        .style(Style::default().fg(Color::Cyan).bold())
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Cyan)),
        );
    frame.render_widget(title, chunks[0]);

    // Helper to add cursor character to text when field is active
    let add_cursor = |text: &str, is_active: bool| -> String {
        if is_active {
            format!("{}▌", text)
        } else {
            text.to_string()
        }
    };

    // URL field
    let url_is_active = app.input.active_field == LaunchField::Urls;
    let url_border_style = if url_is_active {
        Style::default().fg(Color::Yellow)
    } else {
        Style::default().fg(Color::DarkGray)
    };
    let (url_content, url_style) = if app.input.urls.is_empty() {
        if url_is_active {
            ("▌".to_string(), Style::default().fg(Color::Yellow))
        } else {
            (
                "Enter git URL or path...".to_string(),
                Style::default().fg(Color::DarkGray),
            )
        }
    } else {
        (
            add_cursor(&app.input.urls, url_is_active),
            Style::default().fg(Color::Yellow),
        )
    };

    let url_paragraph = Paragraph::new(url_content)
        .style(url_style)
        .wrap(Wrap { trim: false })
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(url_border_style)
                .title(" Source "),
        );
    frame.render_widget(url_paragraph, chunks[1]);

    // Task field
    let task_is_active = app.input.active_field == LaunchField::Task;
    let task_border_style = if task_is_active {
        Style::default().fg(Color::Yellow)
    } else {
        Style::default().fg(Color::DarkGray)
    };
    let (task_content, task_style) = if app.input.task.is_empty() {
        if task_is_active {
            ("▌".to_string(), Style::default().fg(Color::Yellow))
        } else {
            (
                "Enter task for the AI agent...".to_string(),
                Style::default().fg(Color::DarkGray),
            )
        }
    } else {
        (
            add_cursor(&app.input.task, task_is_active),
            Style::default().fg(Color::Yellow),
        )
    };

    // Calculate scroll offset for Task field
    let task_inner_height = chunks[2].height.saturating_sub(2) as usize;
    let task_content_lines = task_content.lines().count();
    let task_scroll = task_content_lines.saturating_sub(task_inner_height) as u16;

    let task_paragraph = Paragraph::new(task_content)
        .style(task_style)
        .wrap(Wrap { trim: false })
        .scroll((task_scroll, 0))
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(task_border_style)
                .title(" Task "),
        );
    frame.render_widget(task_paragraph, chunks[2]);

    // Submit button
    let submit_is_active = app.input.active_field == LaunchField::Submit;
    let (submit_text, submit_style) = if submit_is_active {
        (
            "[ Launch ]",
            Style::default().fg(Color::Black).bg(Color::Green).bold(),
        )
    } else {
        ("[ Launch ]", Style::default().fg(Color::Green).bold())
    };

    let submit_button = Paragraph::new(submit_text)
        .style(submit_style)
        .alignment(ratatui::layout::Alignment::Center)
        .block(Block::default().borders(Borders::ALL));
    frame.render_widget(submit_button, chunks[3]);

    // Footer with help text
    let footer_text = if let Some(ref msg) = app.status_message {
        format!(" {} ", msg)
    } else {
        " Tab: Switch field │ Esc: Cancel".to_string()
    };

    let footer_style = if app.status_message.is_some() {
        Style::default().fg(Color::Yellow)
    } else {
        Style::default().fg(Color::DarkGray)
    };

    let footer = Paragraph::new(footer_text)
        .style(footer_style)
        .block(Block::default().borders(Borders::ALL));
    frame.render_widget(footer, chunks[4]);
}

/// Main event loop
async fn run_app(terminal: &mut Terminal<CrosstermBackend<Stdout>>, mut app: App) -> Result<()> {
    // Refresh every 5 seconds, matching the web frontend's POD_POLL_MS
    let mut refresh_interval = interval(Duration::from_secs(5));

    let mut event_stream = EventStream::new();

    loop {
        terminal.draw(|f| ui(f, &mut app))?;

        tokio::select! {
            _ = refresh_interval.tick() => {
                if let Err(e) = app.refresh_from_api().await {
                    app.status_message = Some(format!("Refresh error: {}", e));
                }
            }
            maybe_event = event_stream.next() => {
                if let Some(Ok(event)) = maybe_event
                    && let Some(action) = handle_event(&mut app, event) {
                        match action {
                            Action::Quit => return Ok(()),
                            Action::Refresh => {
                                app.status_message = Some("Refreshing...".to_string());
                                match app.refresh_from_api().await {
                                    Err(e) => {
                                        app.status_message = Some(format!("Refresh error: {}", e));
                                    }
                                    Ok(()) => {
                                        app.status_message = Some("Refreshed".to_string());
                                    }
                                }
                            }
                            Action::Attach(name) => {
                                run_subprocess(terminal, &["attach", "--", &name]).await?;
                                refresh_interval.reset();
                                let _ = app.refresh_from_api().await;
                            }
                            Action::Delete(names) => {
                                let count = names.len();
                                app.status_message = Some(format!(
                                    "Deleting {} instance{}...",
                                    count,
                                    if count == 1 { "" } else { "s" }
                                ));
                                terminal.draw(|f| ui(f, &mut app))?;

                                let mut errors = Vec::new();
                                for name in &names {
                                    if let Err(e) = run_subprocess_silent(&["delete", "--force", "--", name]).await {
                                        errors.push(format!("{}: {}", name, e));
                                    }
                                }

                                refresh_interval.reset();
                                let _ = app.refresh_from_api().await;

                                if errors.is_empty() {
                                    app.status_message = Some(format!(
                                        "Deleted {} instance{}",
                                        count,
                                        if count == 1 { "" } else { "s" }
                                    ));
                                } else {
                                    app.status_message = Some(format!("Errors: {}", errors.join(", ")));
                                }
                            }
                            Action::ToggleStartStop(name) => {
                                let is_running = app
                                    .instances
                                    .iter()
                                    .find(|i| i.name == name)
                                    .is_some_and(|i| i.status == "Running");

                                if is_running {
                                    app.status_message = Some(format!("Stopping {}...", name));
                                    terminal.draw(|f| ui(f, &mut app))?;
                                    match run_subprocess_silent(&["stop", "--", &name]).await {
                                        Ok(()) => {
                                            app.status_message = Some(format!("Stopped {}", name));
                                        }
                                        Err(e) => {
                                            app.status_message =
                                                Some(format!("Failed to stop {}: {}", name, e));
                                        }
                                    }
                                } else {
                                    app.status_message = Some(format!("Starting {}...", name));
                                    terminal.draw(|f| ui(f, &mut app))?;
                                    match run_subprocess_silent(&["start", "--", &name]).await {
                                        Ok(()) => {
                                            app.status_message = Some(format!("Started {}", name));
                                        }
                                        Err(e) => {
                                            app.status_message =
                                                Some(format!("Failed to start {}: {}", name, e));
                                        }
                                    }
                                }

                                refresh_interval.reset();
                                let _ = app.refresh_from_api().await;
                            }
                            Action::ExecAgent(name) => {
                                run_subprocess(terminal, &["exec", "--", &name]).await?;
                                refresh_interval.reset();
                                let _ = app.refresh_from_api().await;
                            }
                            Action::ExecWorkspace(name) => {
                                run_subprocess(terminal, &["exec", "-W", "--", &name]).await?;
                                refresh_interval.reset();
                                let _ = app.refresh_from_api().await;
                            }
                            Action::AttachWorker(name) => {
                                run_subprocess(terminal, &["attach", "--worker", "--", &name]).await?;
                                refresh_interval.reset();
                                let _ = app.refresh_from_api().await;
                            }
                            Action::ExecWorker(name) => {
                                run_subprocess(terminal, &["exec", "--worker", "--", &name]).await?;
                                refresh_interval.reset();
                                let _ = app.refresh_from_api().await;
                            }
                            Action::Launch { urls, task } => {
                                if urls.is_empty() {
                                    // Scratch workspace — no source URL
                                    app.status_message =
                                        Some("Launching scratch workspace...".to_string());
                                    terminal.draw(|f| ui(f, &mut app))?;

                                    if let Err(e) =
                                        run_subprocess_silent(&["run", "-c", &task]).await
                                    {
                                        app.status_message =
                                            Some(format!("Error: {}", e));
                                    } else {
                                        app.status_message =
                                            Some("Launched scratch workspace".to_string());
                                    }
                                } else {
                                    let count = urls.len();
                                    app.status_message = Some(format!(
                                        "Launching {} instance{}...",
                                        count,
                                        if count == 1 { "" } else { "s" }
                                    ));
                                    terminal.draw(|f| ui(f, &mut app))?;

                                    let mut errors = Vec::new();
                                    for url in &urls {
                                        if let Err(e) =
                                            run_subprocess_silent(&["run", url, "-c", &task]).await
                                        {
                                            errors.push(format!("{}: {}", url, e));
                                        }
                                    }

                                    if errors.is_empty() {
                                        app.status_message = Some(format!(
                                            "Launched {} instance{}",
                                            count,
                                            if count == 1 { "" } else { "s" }
                                        ));
                                    } else {
                                        app.status_message =
                                            Some(format!("Errors: {}", errors.join(", ")));
                                    }
                                }

                                refresh_interval.reset();
                                let _ = app.refresh_from_api().await;
                            }
                            Action::Advisor => {
                                run_subprocess(terminal, &["advisor"]).await?;
                                refresh_interval.reset();
                                let _ = app.refresh_from_api().await;
                            }
                            Action::Review(name) => {
                                run_subprocess(terminal, &["review", &name]).await?;
                                refresh_interval.reset();
                                let _ = app.refresh_from_api().await;
                            }
                            Action::Rebuild(name) => {
                                app.status_message =
                                    Some(format!("Rebuilding {}...", name));
                                terminal.draw(|f| ui(f, &mut app))?;
                                match run_subprocess_silent(&["rebuild", "--", &name])
                                    .await
                                {
                                    Ok(()) => {
                                        app.status_message =
                                            Some(format!("Rebuilt {}", name));
                                    }
                                    Err(e) => {
                                        app.status_message = Some(format!(
                                            "Failed to rebuild {}: {}",
                                            name, e
                                        ));
                                    }
                                }
                                refresh_interval.reset();
                                let _ = app.refresh_from_api().await;
                            }
                        }
                    }
            }
        }
    }
}

/// Handle a terminal event, returning an action if the TUI should exit
fn handle_event(app: &mut App, event: Event) -> Option<Action> {
    match event {
        Event::Key(key) if key.kind == KeyEventKind::Press => match app.mode {
            TuiMode::Normal => handle_normal_mode(app, key.code),
            TuiMode::DeleteSelect => handle_delete_select_mode(app, key.code),
            TuiMode::DeleteConfirm => handle_delete_confirm_mode(app, key.code),
            TuiMode::Launch => handle_launch_mode(app, key),
            TuiMode::ContainerMenu => handle_container_menu_mode(app, key.code),
            TuiMode::Filter => handle_filter_mode(app, key.code),
        },
        _ => None,
    }
}

/// Handle key events in normal mode
fn handle_normal_mode(app: &mut App, code: KeyCode) -> Option<Action> {
    match code {
        KeyCode::Char('q') | KeyCode::Esc => Some(Action::Quit),
        KeyCode::Char('j') | KeyCode::Down => {
            app.next();
            None
        }
        KeyCode::Char('k') | KeyCode::Up => {
            app.previous();
            None
        }
        KeyCode::Char('r') => Some(Action::Refresh),
        KeyCode::Enter | KeyCode::Char('a') => {
            if let Some(instance) = app.selected_instance() {
                Some(Action::Attach(instance.name.clone()))
            } else {
                app.status_message = Some("No instance selected".to_string());
                None
            }
        }
        KeyCode::Char('d') => {
            // Enter delete select mode
            app.mode = TuiMode::DeleteSelect;
            app.selected_for_delete.clear();
            app.status_message =
                Some("Delete mode: Space to select, Enter to confirm, Esc to cancel".to_string());
            None
        }
        KeyCode::Char('e') => {
            // Exec into agent container
            if let Some(instance) = app.selected_instance() {
                if instance.status == "Running" {
                    Some(Action::ExecAgent(instance.name.clone()))
                } else {
                    app.status_message = Some("Instance is not running".to_string());
                    None
                }
            } else {
                app.status_message = Some("No instance selected".to_string());
                None
            }
        }
        KeyCode::Char('E') => {
            // Exec into workspace container
            if let Some(instance) = app.selected_instance() {
                if instance.status == "Running" {
                    Some(Action::ExecWorkspace(instance.name.clone()))
                } else {
                    app.status_message = Some("Instance is not running".to_string());
                    None
                }
            } else {
                app.status_message = Some("No instance selected".to_string());
                None
            }
        }
        KeyCode::Char('S') => {
            // Toggle start/stop for the selected instance
            if let Some(instance) = app.selected_instance() {
                Some(Action::ToggleStartStop(instance.name.clone()))
            } else {
                app.status_message = Some("No instance selected".to_string());
                None
            }
        }
        KeyCode::Char('L') => {
            // Enter launch mode, pre-filling source with "." when in a git repo
            app.mode = TuiMode::Launch;
            app.launch_input = LaunchInput {
                urls: if app.in_git_repo {
                    ".".to_string()
                } else {
                    String::new()
                },
                ..LaunchInput::default()
            };
            app.status_message = None;
            None
        }
        KeyCode::Char('A') => {
            // Launch/attach the advisor
            Some(Action::Advisor)
        }
        KeyCode::Char('R') => {
            // Open review TUI for selected instance
            if let Some(instance) = app.selected_instance() {
                Some(Action::Review(instance.name.clone()))
            } else {
                app.status_message = Some("No instance selected".to_string());
                None
            }
        }
        KeyCode::Char('B') => {
            // Rebuild (recreate) selected instance
            if let Some(instance) = app.selected_instance() {
                Some(Action::Rebuild(instance.name.clone()))
            } else {
                app.status_message = Some("No instance selected".to_string());
                None
            }
        }
        KeyCode::Right | KeyCode::Char('l') => {
            // Open container access menu
            if let Some(instance) = app.selected_instance() {
                if instance.status == "Running" {
                    app.mode = TuiMode::ContainerMenu;
                    app.container_menu_selection = 0;
                    app.status_message = None;
                } else {
                    app.status_message = Some("Instance is not running".to_string());
                }
            } else {
                app.status_message = Some("No instance selected".to_string());
            }
            None
        }
        KeyCode::Char('i') => {
            // Toggle inactive pod visibility
            app.show_inactive = !app.show_inactive;
            app.apply_filter();
            app.status_message = Some(if app.show_inactive {
                "Showing all pods (including inactive)".to_string()
            } else {
                "Hiding inactive pods".to_string()
            });
            None
        }
        KeyCode::Char('/') => {
            // Enter filter mode
            app.mode = TuiMode::Filter;
            app.status_message = None;
            None
        }
        _ => None,
    }
}

/// Handle key events in filter mode
fn handle_filter_mode(app: &mut App, code: KeyCode) -> Option<Action> {
    match code {
        KeyCode::Esc => {
            app.mode = TuiMode::Normal;
            None
        }
        KeyCode::Enter => {
            app.mode = TuiMode::Normal;
            None
        }
        KeyCode::Backspace => {
            app.filter_text.pop();
            app.apply_filter();
            None
        }
        KeyCode::Char(c) => {
            app.filter_text.push(c);
            app.apply_filter();
            None
        }
        _ => None,
    }
}

/// Handle key events in container menu mode
fn handle_container_menu_mode(app: &mut App, code: KeyCode) -> Option<Action> {
    let menu_items = ContainerMenuItem::all();
    let max_idx = menu_items.len().saturating_sub(1);

    match code {
        KeyCode::Esc | KeyCode::Left | KeyCode::Char('q') | KeyCode::Char('h') => {
            // Close menu, return to normal mode
            app.mode = TuiMode::Normal;
            app.status_message = None;
            None
        }
        KeyCode::Char('j') | KeyCode::Down => {
            // Move down in menu
            if app.container_menu_selection < max_idx {
                app.container_menu_selection += 1;
            }
            None
        }
        KeyCode::Char('k') | KeyCode::Up => {
            // Move up in menu
            if app.container_menu_selection > 0 {
                app.container_menu_selection -= 1;
            }
            None
        }
        KeyCode::Char('1') => {
            app.container_menu_selection = 0;
            select_container_menu_item(app)
        }
        KeyCode::Char('2') => {
            app.container_menu_selection = 1;
            select_container_menu_item(app)
        }
        KeyCode::Char('3') => {
            app.container_menu_selection = 2;
            select_container_menu_item(app)
        }
        KeyCode::Char('4') => {
            app.container_menu_selection = 3;
            select_container_menu_item(app)
        }
        KeyCode::Enter => select_container_menu_item(app),
        _ => None,
    }
}

/// Execute the selected container menu item
fn select_container_menu_item(app: &mut App) -> Option<Action> {
    let menu_items = ContainerMenuItem::all();
    let selected_item = menu_items.get(app.container_menu_selection)?;
    let instance = app.selected_instance()?;
    let name = instance.name.clone();
    let worker_available = instance.worker_healthy == Some(true);

    // Check if worker is available for worker-related actions
    if selected_item.requires_worker() && !worker_available {
        app.status_message = Some("Worker container not available".to_string());
        return None;
    }

    app.mode = TuiMode::Normal;

    match selected_item {
        ContainerMenuItem::OrchestratorAgent => Some(Action::Attach(name)),
        ContainerMenuItem::WorkerAgent => Some(Action::AttachWorker(name)),
        ContainerMenuItem::WorkerShell => Some(Action::ExecWorker(name)),
        ContainerMenuItem::WorkspaceShell => Some(Action::ExecWorkspace(name)),
    }
}

/// Handle key events in delete select mode
fn handle_delete_select_mode(app: &mut App, code: KeyCode) -> Option<Action> {
    match code {
        KeyCode::Esc | KeyCode::Char('q') => {
            // Cancel delete mode
            app.mode = TuiMode::Normal;
            app.selected_for_delete.clear();
            app.status_message = None;
            None
        }
        KeyCode::Char('j') | KeyCode::Down => {
            app.next();
            None
        }
        KeyCode::Char('k') | KeyCode::Up => {
            app.previous();
            None
        }
        KeyCode::Char(' ') => {
            // Toggle selection of current instance
            if let Some(instance) = app.selected_instance() {
                let name = instance.name.clone();
                if app.selected_for_delete.contains(&name) {
                    app.selected_for_delete.remove(&name);
                } else {
                    app.selected_for_delete.insert(name);
                }
                let count = app.selected_for_delete.len();
                app.status_message = Some(format!(
                    "Delete mode: {} selected. Space to toggle, Enter to confirm, Esc to cancel",
                    count
                ));
            }
            None
        }
        KeyCode::Enter => {
            if app.selected_for_delete.is_empty() {
                app.status_message = Some("No instances selected for deletion".to_string());
                None
            } else {
                // Enter confirmation mode
                app.mode = TuiMode::DeleteConfirm;
                let count = app.selected_for_delete.len();
                app.status_message = Some(format!(
                    "Delete {} instance{}? y to confirm, n/Esc to cancel",
                    count,
                    if count == 1 { "" } else { "s" }
                ));
                None
            }
        }
        _ => None,
    }
}

/// Handle key events in delete confirm mode
fn handle_delete_confirm_mode(app: &mut App, code: KeyCode) -> Option<Action> {
    match code {
        KeyCode::Char('y') | KeyCode::Char('Y') => {
            // Confirm deletion
            let names: Vec<String> = app.selected_for_delete.drain().collect();
            app.mode = TuiMode::Normal;
            Some(Action::Delete(names))
        }
        KeyCode::Char('n') | KeyCode::Char('N') | KeyCode::Esc => {
            // Cancel - go back to delete select mode
            app.mode = TuiMode::DeleteSelect;
            let count = app.selected_for_delete.len();
            app.status_message = Some(format!(
                "Delete mode: {} selected. Space to toggle, Enter to confirm, Esc to cancel",
                count
            ));
            None
        }
        _ => None,
    }
}

/// Try to submit the launch dialog, returning an action if successful
fn try_submit_launch(app: &mut App) -> Option<Action> {
    let urls: Vec<String> = app
        .launch_input
        .urls
        .lines()
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .map(String::from)
        .collect();

    let task = app.launch_input.task.trim().to_string();

    if task.is_empty() {
        app.status_message = Some("Enter a task".to_string());
        app.launch_input.active_field = LaunchField::Task;
        None
    } else {
        // URLs are optional — an empty list creates a scratch workspace
        app.mode = TuiMode::Normal;
        app.launch_input = LaunchInput::default();
        Some(Action::Launch { urls, task })
    }
}

/// Handle key events in launch mode (URL + task input dialog)
fn handle_launch_mode(app: &mut App, key: crossterm::event::KeyEvent) -> Option<Action> {
    match key.code {
        KeyCode::Esc => {
            // Cancel launch mode
            app.mode = TuiMode::Normal;
            app.launch_input = LaunchInput::default();
            app.status_message = None;
            None
        }
        KeyCode::Tab => {
            // Cycle forward through fields
            app.launch_input.active_field = match app.launch_input.active_field {
                LaunchField::Urls => LaunchField::Task,
                LaunchField::Task => LaunchField::Submit,
                LaunchField::Submit => LaunchField::Urls,
            };
            None
        }
        KeyCode::BackTab => {
            // Cycle backward through fields
            app.launch_input.active_field = match app.launch_input.active_field {
                LaunchField::Urls => LaunchField::Submit,
                LaunchField::Task => LaunchField::Urls,
                LaunchField::Submit => LaunchField::Task,
            };
            None
        }
        KeyCode::Enter if key.modifiers.contains(KeyModifiers::CONTROL) => {
            // Ctrl+Enter: Submit from any field
            try_submit_launch(app)
        }
        KeyCode::Enter => {
            // Regular Enter: add newline to text fields, or submit if on button
            match app.launch_input.active_field {
                LaunchField::Urls => {
                    app.launch_input.urls.push('\n');
                    None
                }
                LaunchField::Task => {
                    app.launch_input.task.push('\n');
                    None
                }
                LaunchField::Submit => {
                    // Submit button pressed
                    try_submit_launch(app)
                }
            }
        }
        KeyCode::Backspace => {
            // Delete character from active field (no-op for Submit button)
            match app.launch_input.active_field {
                LaunchField::Urls => {
                    app.launch_input.urls.pop();
                }
                LaunchField::Task => {
                    app.launch_input.task.pop();
                }
                LaunchField::Submit => {}
            }
            None
        }
        KeyCode::Char(c) => {
            // Add character to active field (no-op for Submit button)
            match app.launch_input.active_field {
                LaunchField::Urls => {
                    app.launch_input.urls.push(c);
                }
                LaunchField::Task => {
                    app.launch_input.task.push(c);
                }
                LaunchField::Submit => {}
            }
            None
        }
        _ => None,
    }
}

/// Run a subprocess with terminal properly suspended, then resume TUI
async fn run_subprocess(
    terminal: &mut Terminal<CrosstermBackend<Stdout>>,
    args: &[&str],
) -> Result<()> {
    use std::process::Stdio;
    use tokio::process::Command;

    // Restore terminal for the subprocess
    disable_raw_mode()?;
    execute!(io::stdout(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;

    // Get the path to ourselves
    let exe = std::env::current_exe().context("Failed to get current executable")?;

    // Spawn subprocess and wait
    let status = Command::new(&exe)
        .args(args)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .await
        .context("Failed to run subprocess")?;

    if !status.success() {
        tracing::warn!("Subprocess exited with status: {:?}", status.code());
    }

    // Restore TUI terminal state
    enable_raw_mode()?;
    execute!(io::stdout(), EnterAlternateScreen)?;
    terminal.hide_cursor()?;
    terminal.clear()?;

    Ok(())
}

/// Run a subprocess silently (no terminal restore needed), capturing stderr for errors
async fn run_subprocess_silent(args: &[&str]) -> Result<()> {
    use std::process::Stdio;
    use tokio::process::Command;

    let exe = std::env::current_exe().context("Failed to get current executable")?;

    let output = Command::new(&exe)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .output()
        .await
        .context("Failed to run subprocess")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let msg = stderr.trim();
        if msg.is_empty() {
            color_eyre::eyre::bail!("exit code {:?}", output.status.code());
        } else {
            color_eyre::eyre::bail!("{}", msg);
        }
    }

    Ok(())
}

/// Render the UI
fn ui(frame: &mut ratatui::Frame, app: &mut App) {
    let area = frame.area();

    // Layout: header, main table, footer
    let chunks = Layout::vertical([
        Constraint::Length(3), // Header
        Constraint::Min(5),    // Table
        Constraint::Length(3), // Footer
    ])
    .split(area);

    // Header
    let mut header_spans = vec![
        Span::styled(" devaipod ", Style::default().fg(Color::Cyan).bold()),
        Span::raw("│ "),
        Span::styled(
            format!("{} instances", app.instances.len()),
            Style::default().fg(Color::Green),
        ),
    ];
    if !app.filter_text.is_empty() {
        header_spans.push(Span::raw(" │ /"));
        header_spans.push(Span::styled(
            app.filter_text.clone(),
            Style::default().fg(Color::Magenta),
        ));
        if app.mode == TuiMode::Filter {
            header_spans.push(Span::styled("█", Style::default().fg(Color::Magenta)));
        }
    } else if app.mode == TuiMode::Filter {
        header_spans.push(Span::raw(" │ /"));
        header_spans.push(Span::styled("█", Style::default().fg(Color::Magenta)));
    }
    header_spans.push(Span::raw(" │ Last refresh: "));
    header_spans.push(Span::styled(
        format!("{}s ago", app.last_refresh.elapsed().as_secs()),
        Style::default().fg(Color::Yellow),
    ));
    let header = Paragraph::new(Line::from(header_spans))
        .block(Block::default().borders(Borders::ALL).title(" Dashboard "));
    frame.render_widget(header, chunks[0]);

    // Instance table
    render_table(frame, app, chunks[1]);

    // Footer with help and status
    let status = app
        .status_message
        .as_deref()
        .map(|s| format!(" │ {}", s))
        .unwrap_or_default();

    // Footer with help and status (mode-dependent)
    let (help_base, footer_style) = match app.mode {
        TuiMode::Normal => (
            " q: Quit │ j/k: Nav │ /: Filter │ i: Inactive │ a: Attach │ →: Menu │ e: Exec │ S: Stop │ B: Rebuild │ d: Del │ L: Launch │ A: Advisor │ r: Refresh",
            Style::default().fg(Color::DarkGray),
        ),
        TuiMode::DeleteSelect => (
            " Esc: Cancel │ j/k: Navigate │ Space: Toggle selection │ Enter: Confirm delete",
            Style::default().fg(Color::Yellow),
        ),
        TuiMode::DeleteConfirm => (
            " y: Confirm delete │ n/Esc: Cancel",
            Style::default().fg(Color::Red),
        ),
        TuiMode::Launch => (
            " Tab: Switch field │ Esc: Cancel",
            Style::default().fg(Color::Cyan),
        ),
        TuiMode::ContainerMenu => (
            " j/k: Navigate │ 1-4: Quick select │ Enter: Confirm │ Esc/←: Cancel",
            Style::default().fg(Color::Cyan),
        ),
        TuiMode::Filter => (
            " Type to filter │ Enter: Apply │ Esc: Cancel",
            Style::default().fg(Color::Magenta),
        ),
    };
    let help_text = format!("{}{}", help_base, status);
    let footer = Paragraph::new(help_text)
        .style(footer_style)
        .block(Block::default().borders(Borders::ALL));
    frame.render_widget(footer, chunks[2]);

    // Render popups for dialog modes
    match app.mode {
        TuiMode::Launch => render_launch_dialog(frame, app, area),
        TuiMode::ContainerMenu => render_container_menu(frame, app, area),
        _ => {}
    }
}

/// Render the launch dialog popup
fn render_launch_dialog(frame: &mut ratatui::Frame, app: &App, area: Rect) {
    // Calculate URLs field height: 2 lines minimum, expand based on content
    // +2 for borders
    let urls_line_count = app.launch_input.urls.lines().count().max(1);
    let urls_height = (urls_line_count as u16 + 2).clamp(4, 12); // min 4 (2 lines + borders), max 12

    // Task field: 5 lines minimum, expand based on content
    // +2 for borders
    let task_line_count = app.launch_input.task.lines().count().max(1);
    let task_height = (task_line_count as u16 + 2).clamp(7, 12); // min 7 (5 lines + borders), max 12

    // Total popup height: title (3) + urls + task + submit button (3)
    let popup_height = (3 + urls_height + task_height + 3).min(area.height - 4);
    let popup_width = (area.width * 60 / 100).max(50).min(area.width - 4);
    let popup_x = (area.width.saturating_sub(popup_width)) / 2;
    let popup_y = (area.height.saturating_sub(popup_height)) / 2;
    let popup_area = Rect::new(popup_x, popup_y, popup_width, popup_height);

    // Clear the area behind the popup
    frame.render_widget(Clear, popup_area);

    // Split popup into title, URLs field, Task field, Submit button
    let inner_chunks = Layout::vertical([
        Constraint::Length(3),           // Title
        Constraint::Length(urls_height), // URLs (dynamic height)
        Constraint::Length(task_height), // Task
        Constraint::Length(3),           // Submit button
    ])
    .split(popup_area);

    // Title bar
    let title = Paragraph::new(" Launch New Instances ")
        .style(Style::default().fg(Color::Cyan).bold())
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Cyan)),
        );
    frame.render_widget(title, inner_chunks[0]);

    // Helper to add cursor character to text when field is active
    let add_cursor = |text: &str, is_active: bool| -> String {
        if is_active {
            format!("{}▌", text)
        } else {
            text.to_string()
        }
    };

    // URLs field
    let urls_is_active = app.launch_input.active_field == LaunchField::Urls;
    let urls_border_style = if urls_is_active {
        Style::default().fg(Color::Yellow)
    } else {
        Style::default().fg(Color::DarkGray)
    };
    let (urls_content, urls_style) = if app.launch_input.urls.is_empty() {
        if urls_is_active {
            ("▌".to_string(), Style::default().fg(Color::Yellow))
        } else {
            (
                "Enter git URLs (one per line)...".to_string(),
                Style::default().fg(Color::DarkGray),
            )
        }
    } else {
        (
            add_cursor(&app.launch_input.urls, urls_is_active),
            Style::default().fg(Color::Yellow),
        )
    };

    // Calculate scroll offset for URLs field (show last lines if content exceeds height)
    let urls_inner_height = inner_chunks[1].height.saturating_sub(2) as usize; // -2 for borders
    let urls_line_count = urls_content.lines().count();
    let urls_scroll = urls_line_count.saturating_sub(urls_inner_height) as u16;

    let urls_paragraph = Paragraph::new(urls_content)
        .style(urls_style)
        .wrap(Wrap { trim: false })
        .scroll((urls_scroll, 0))
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(urls_border_style)
                .title(" URLs "),
        );
    frame.render_widget(urls_paragraph, inner_chunks[1]);

    // Task field
    let task_is_active = app.launch_input.active_field == LaunchField::Task;
    let task_border_style = if task_is_active {
        Style::default().fg(Color::Yellow)
    } else {
        Style::default().fg(Color::DarkGray)
    };
    let (task_content, task_style) = if app.launch_input.task.is_empty() {
        if task_is_active {
            ("▌".to_string(), Style::default().fg(Color::Yellow))
        } else {
            (
                "Enter task to run...".to_string(),
                Style::default().fg(Color::DarkGray),
            )
        }
    } else {
        (
            add_cursor(&app.launch_input.task, task_is_active),
            Style::default().fg(Color::Yellow),
        )
    };

    // Calculate scroll offset for Task field
    let task_inner_height = inner_chunks[2].height.saturating_sub(2) as usize;
    let task_content_lines = task_content.lines().count();
    let task_scroll = task_content_lines.saturating_sub(task_inner_height) as u16;

    let task_paragraph = Paragraph::new(task_content)
        .style(task_style)
        .wrap(Wrap { trim: false })
        .scroll((task_scroll, 0))
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(task_border_style)
                .title(" Task "),
        );
    frame.render_widget(task_paragraph, inner_chunks[2]);

    // Submit button
    let submit_is_active = app.launch_input.active_field == LaunchField::Submit;
    let (submit_text, submit_style) = if submit_is_active {
        (
            "[ Launch ]",
            Style::default().fg(Color::Black).bg(Color::Green).bold(),
        )
    } else {
        ("[ Launch ]", Style::default().fg(Color::Green).bold())
    };

    let submit_button = Paragraph::new(submit_text)
        .style(submit_style)
        .alignment(ratatui::layout::Alignment::Center)
        .block(Block::default().borders(Borders::ALL));
    frame.render_widget(submit_button, inner_chunks[3]);
}

/// Render the container access menu popup
fn render_container_menu(frame: &mut ratatui::Frame, app: &App, area: Rect) {
    let menu_items = ContainerMenuItem::all();

    // Get selected instance info
    let instance = app.selected_instance();
    let instance_name = instance.map(|i| i.name.as_str()).unwrap_or("?");
    let worker_available = instance
        .map(|i| i.worker_healthy == Some(true))
        .unwrap_or(false);

    // Popup dimensions: title + menu items (1 line each) + borders
    let popup_height = (menu_items.len() as u16 + 4).min(area.height - 4); // +2 title, +2 borders
    let popup_width = 55u16.min(area.width - 4);
    let popup_x = (area.width.saturating_sub(popup_width)) / 2;
    let popup_y = (area.height.saturating_sub(popup_height)) / 2;
    let popup_area = Rect::new(popup_x, popup_y, popup_width, popup_height);

    // Clear the area behind the popup
    frame.render_widget(Clear, popup_area);

    // Build menu content
    let mut lines: Vec<Line<'static>> = Vec::new();

    for (idx, item) in menu_items.iter().enumerate() {
        let is_selected = idx == app.container_menu_selection;
        let is_disabled = item.requires_worker() && !worker_available;

        let (prefix, label_style, desc_style) = if is_disabled {
            // Disabled items are grayed out
            (
                "  ",
                Style::default().fg(Color::DarkGray),
                Style::default().fg(Color::DarkGray),
            )
        } else if is_selected {
            (
                "▶ ",
                Style::default().fg(Color::Cyan).bold(),
                Style::default().fg(Color::DarkGray),
            )
        } else {
            (
                "  ",
                Style::default().fg(Color::White),
                Style::default().fg(Color::DarkGray),
            )
        };

        let description = if is_disabled {
            "(no worker)"
        } else {
            item.description()
        };

        lines.push(Line::from(vec![
            Span::styled(prefix.to_string(), label_style),
            Span::styled(item.label().to_string(), label_style),
            Span::raw("  "),
            Span::styled(description.to_string(), desc_style),
        ]));
    }

    let menu = Paragraph::new(lines).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Cyan))
            .title(format!(" {} ", instance_name)),
    );
    frame.render_widget(menu, popup_area);
}

/// Height of each instance card (lines)
const CARD_HEIGHT: u16 = 5;

/// Render a single instance as a card
fn render_instance_card(
    instance: &InstanceInfo,
    is_selected: bool,
    is_marked_for_delete: bool,
    in_delete_mode: bool,
    width: u16,
) -> Vec<Line<'static>> {
    let mut lines: Vec<Line<'static>> = Vec::new();

    // Line 1: Name and metadata bar
    let (health_label, status_style) = match instance.status.as_str() {
        "Running" => ("Healthy".to_string(), Style::default().fg(Color::Green)),
        "Exited" => ("Stopped".to_string(), Style::default().fg(Color::Red)),
        "Degraded" => {
            let reason = if instance.degraded_containers.is_empty() {
                "Degraded".to_string()
            } else {
                format!("Degraded: {} down", instance.degraded_containers.join(", "))
            };
            (reason, Style::default().fg(Color::Yellow))
        }
        _ => (instance.status.clone(), Style::default()),
    };

    let mode = instance.mode.clone().unwrap_or_else(|| "-".to_string());
    let mode_style = match mode.as_str() {
        "run" => Style::default().fg(Color::Magenta).bold(),
        "up" => Style::default().fg(Color::Blue),
        _ => Style::default().fg(Color::DarkGray),
    };

    // Git state
    let git_text = match &instance.git_state {
        Some(state) => state.summary.clone(),
        None if instance.status == "Running" => "...".to_string(),
        None => "-".to_string(),
    };
    let git_style = match &instance.git_state {
        Some(state) if state.dirty => Style::default().fg(Color::Yellow),
        Some(state) if state.ahead > 0 || state.behind > 0 => Style::default().fg(Color::Cyan),
        Some(_) => Style::default().fg(Color::Green),
        None => Style::default().fg(Color::DarkGray),
    };

    // Selection indicator for delete mode: arrow shows cursor, checkbox shows marked for deletion
    let prefix: Span<'static> = if in_delete_mode {
        let arrow = if is_selected { "▶ " } else { "  " };
        let checkbox = if is_marked_for_delete { "[x]" } else { "[ ]" };
        let style = if is_selected {
            // Selected row: cyan for visibility (red if also marked)
            if is_marked_for_delete {
                Style::default().fg(Color::Red).bold()
            } else {
                Style::default().fg(Color::Cyan).bold()
            }
        } else if is_marked_for_delete {
            Style::default().fg(Color::Red).bold()
        } else {
            Style::default().fg(Color::DarkGray)
        };
        Span::styled(format!("{arrow}{checkbox} "), style)
    } else if is_selected {
        Span::styled("▶ ".to_string(), Style::default().fg(Color::Cyan).bold())
    } else {
        Span::raw("  ".to_string())
    };

    // Truncate repo
    let repo = instance
        .repo
        .as_deref()
        .map(|r| {
            r.strip_prefix("https://")
                .or_else(|| r.strip_prefix("git@"))
                .unwrap_or(r)
                .to_string()
        })
        .unwrap_or_else(|| "-".to_string());

    // Created timestamp (short format)
    let created = instance.created.as_deref().unwrap_or("-").to_string();

    let display_name = if let Some(ref title) = instance.title {
        format!("{} \u{2014} {}", instance.name, title)
    } else {
        instance.name.clone()
    };

    lines.push(Line::from(vec![
        prefix,
        Span::styled(
            display_name,
            Style::default().bold().fg(if is_selected {
                Color::White
            } else {
                Color::Reset
            }),
        ),
        Span::raw(" │ ".to_string()),
        Span::styled(health_label, status_style),
        Span::raw(" │ ".to_string()),
        Span::styled(mode, mode_style),
        Span::raw(" │ ".to_string()),
        Span::styled(git_text, git_style),
        Span::raw(" │ ".to_string()),
        Span::styled(created, Style::default().fg(Color::DarkGray)),
    ]));

    // Line 2-4: Agent output (varies by mode)
    let is_run_mode = instance.mode.as_deref() == Some("run");
    let show_active_output =
        is_run_mode && matches!(instance.agent_state.activity, AgentActivity::Working);

    // Activity indicator
    let (activity_icon, activity_style): (String, Style) = match instance.agent_state.activity {
        AgentActivity::Working => ("●".to_string(), Style::default().fg(Color::Green)),
        AgentActivity::Idle => ("○".to_string(), Style::default().fg(Color::Blue)),
        AgentActivity::Stopped => ("◌".to_string(), Style::default().fg(Color::DarkGray)),
        AgentActivity::Unknown => {
            if instance.status == "Running" && instance.agent_healthy == Some(true) {
                ("…".to_string(), Style::default().fg(Color::DarkGray))
            } else {
                ("◌".to_string(), Style::default().fg(Color::DarkGray))
            }
        }
    };

    let activity_label: String = match instance.agent_state.activity {
        AgentActivity::Working => "working".to_string(),
        AgentActivity::Idle => "idle".to_string(),
        AgentActivity::Stopped => "stopped".to_string(),
        AgentActivity::Unknown => {
            if instance.status == "Running" {
                "loading".to_string()
            } else {
                "stopped".to_string()
            }
        }
    };

    // Line 2: Agent activity status - prefer task description, then agent status
    let status_line = instance
        .agent_state
        .status_line
        .clone()
        .or_else(|| instance.task.clone())
        .unwrap_or_else(|| {
            if is_run_mode {
                match instance.agent_state.activity {
                    AgentActivity::Working => "Processing...".to_string(),
                    AgentActivity::Idle => "Waiting for next task".to_string(),
                    AgentActivity::Stopped => "Agent stopped".to_string(),
                    AgentActivity::Unknown => String::new(),
                }
            } else {
                // 'up' mode - show as available for attach
                "Ready for attach".to_string()
            }
        });

    // Truncate status line to available width
    let max_status_len = width.saturating_sub(20) as usize;
    let truncated_status = if status_line.len() > max_status_len && max_status_len > 3 {
        format!("{}...", &status_line[..max_status_len.saturating_sub(3)])
    } else {
        status_line
    };

    lines.push(Line::from(vec![
        Span::raw("  ".to_string()),
        Span::styled(activity_icon, activity_style),
        Span::raw(" ".to_string()),
        Span::styled(activity_label, activity_style),
        Span::raw(": ".to_string()),
        Span::styled(truncated_status, Style::default().fg(Color::White)),
    ]));

    // Line 3: Repo + service indicators (gator, worker)
    let gator_indicator = match instance.gator_healthy {
        Some(true) => "🔐".to_string(),
        Some(false) => "⚠".to_string(),
        None => String::new(),
    };

    // Worker indicator: W for running worker, shows orchestration is available
    let worker_indicator = match instance.worker_healthy {
        Some(true) => "W".to_string(),
        Some(false) => "w".to_string(), // lowercase = not running
        None => String::new(),
    };
    let gator_scopes_short = instance
        .gator_scopes
        .as_ref()
        .map(|s| {
            // Parse scopes like "--gh-repo user/repo:read" -> "gh:user/repo"
            s.split_whitespace()
                .filter_map(|part| {
                    if part.starts_with("--gh-repo") || part.starts_with("--github-repo") {
                        None // skip the flag itself
                    } else if part.contains(':') {
                        // This is a repo:perms spec
                        let repo_part = part.split(':').next().unwrap_or(part);
                        Some(format!("gh:{}", repo_part))
                    } else {
                        None
                    }
                })
                .collect::<Vec<_>>()
                .join(" ")
        })
        .filter(|s| !s.is_empty());

    if !repo.is_empty() && repo != "-" {
        let mut spans = vec![
            Span::raw("    ".to_string()),
            Span::styled(repo, Style::default().fg(Color::DarkGray)),
        ];
        if !gator_indicator.is_empty() {
            spans.push(Span::raw(" ".to_string()));
            spans.push(Span::styled(
                gator_indicator,
                if instance.gator_healthy == Some(true) {
                    Style::default().fg(Color::Green)
                } else {
                    Style::default().fg(Color::Yellow)
                },
            ));
            if let Some(ref scopes) = gator_scopes_short {
                spans.push(Span::raw(" ".to_string()));
                spans.push(Span::styled(
                    scopes.clone(),
                    Style::default().fg(Color::Cyan),
                ));
            }
        }
        // Add worker indicator if worker container exists
        if !worker_indicator.is_empty() {
            spans.push(Span::raw(" ".to_string()));
            spans.push(Span::styled(
                format!("[{}]", worker_indicator),
                if instance.worker_healthy == Some(true) {
                    Style::default().fg(Color::Magenta)
                } else {
                    Style::default().fg(Color::DarkGray)
                },
            ));
        }
        lines.push(Line::from(spans));
    }

    // Lines 4-5: Recent output or tool info (only for active run mode)
    if show_active_output && !instance.agent_state.recent_output.is_empty() {
        for output_line in instance.agent_state.recent_output.iter().take(2) {
            let max_len = width.saturating_sub(6) as usize;
            let truncated = if output_line.len() > max_len && max_len > 3 {
                format!("{}...", &output_line[..max_len.saturating_sub(3)])
            } else {
                output_line.clone()
            };
            lines.push(Line::from(vec![
                Span::raw("    ".to_string()),
                Span::styled(truncated, Style::default().fg(Color::DarkGray)),
            ]));
        }
    } else if let Some(ref tool) = instance.agent_state.current_tool {
        lines.push(Line::from(vec![
            Span::raw("    ".to_string()),
            Span::styled("→ ".to_string(), Style::default().fg(Color::Yellow)),
            Span::styled(tool.clone(), Style::default().fg(Color::Yellow)),
        ]));
    }

    // Pad to consistent height
    while lines.len() < CARD_HEIGHT as usize {
        lines.push(Line::from(String::new()));
    }

    lines
}

/// Render instances as cards grouped by repository
fn render_table(frame: &mut ratatui::Frame, app: &mut App, area: Rect) {
    let in_delete_mode = matches!(app.mode, TuiMode::DeleteSelect | TuiMode::DeleteConfirm);
    let selected_idx = app.table_state.selected();
    let selected_for_delete = &app.selected_for_delete;

    // Group instances by repo, preserving instance order within each group
    let mut repo_order: Vec<String> = Vec::new();
    let mut groups: std::collections::HashMap<String, Vec<usize>> =
        std::collections::HashMap::new();
    for (idx, inst) in app.instances.iter().enumerate() {
        let key = inst.repo.clone().unwrap_or_default();
        if !groups.contains_key(&key) {
            repo_order.push(key.clone());
        }
        groups.entry(key).or_default().push(idx);
    }
    let multiple_repos = repo_order.len() > 1 || repo_order.first().is_some_and(|k| !k.is_empty());

    // Build lines with repo group headers and instance cards.
    // Track which line range corresponds to the selected card for scrolling.
    let mut all_lines: Vec<Line> = Vec::new();
    let mut selected_line_start: usize = 0;
    let mut card_count: usize = 0;

    for (group_idx, repo_key) in repo_order.iter().enumerate() {
        let indices = &groups[repo_key];

        // Repo header line
        if multiple_repos {
            if group_idx > 0 {
                all_lines.push(Line::from(""));
            }
            let active = indices
                .iter()
                .filter(|&&i| app.instances[i].status.to_lowercase() == "running")
                .count();
            let label = if repo_key.is_empty() {
                "(no repo)".to_string()
            } else {
                repo_key.clone()
            };
            let header = if active > 0 {
                format!(" {} ({} active)", label, active)
            } else {
                format!(" {}", label)
            };
            all_lines.push(Line::from(Span::styled(
                header,
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            )));
        }

        for &idx in indices {
            let instance = &app.instances[idx];
            let is_selected = selected_idx == Some(idx);
            let is_marked = selected_for_delete.contains(&instance.name);

            // Record start line for scroll calculation
            if is_selected {
                selected_line_start = all_lines.len();
            }

            // Separator before card (thin line between cards within a group)
            if card_count > 0 {
                all_lines.push(Line::from(Span::styled(
                    "─".repeat(area.width.saturating_sub(2) as usize),
                    Style::default().fg(Color::DarkGray),
                )));
            }

            let card_lines =
                render_instance_card(instance, is_selected, is_marked, in_delete_mode, area.width);
            all_lines.extend(card_lines);
            card_count += 1;
        }
    }

    // Calculate scroll offset to keep selected item visible
    let visible_height = area.height.saturating_sub(2) as usize;
    let scroll_offset = if selected_line_start >= visible_height {
        selected_line_start.saturating_sub(visible_height / 2)
    } else {
        0
    };

    let visible_lines: Vec<Line> = all_lines.into_iter().skip(scroll_offset).collect();

    let inactive_indicator = if app.show_inactive {
        " [+inactive]"
    } else {
        ""
    };
    let title = format!(" Instances{} ", inactive_indicator);
    let paragraph =
        Paragraph::new(visible_lines).block(Block::default().borders(Borders::ALL).title(title));

    frame.render_widget(paragraph, area);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crossterm::event::{KeyEvent, KeyEventState, KeyModifiers};

    #[test]
    fn test_truncate_with_ellipsis_short_string() {
        assert_eq!(truncate_with_ellipsis("hello", 10), "hello");
        assert_eq!(truncate_with_ellipsis("", 10), "");
    }

    #[test]
    fn test_truncate_with_ellipsis_exact_length() {
        assert_eq!(truncate_with_ellipsis("1234567890", 10), "1234567890");
    }

    #[test]
    fn test_truncate_with_ellipsis_long_string() {
        assert_eq!(
            truncate_with_ellipsis("12345678901234567890", 10),
            "1234567..."
        );
    }

    #[test]
    fn test_truncate_with_ellipsis_unicode() {
        // Em-dash is 3 bytes but 1 character
        let s = "Clean across the board — clippy, fmt, tests pass";
        let result = truncate_with_ellipsis(s, 30);
        assert_eq!(result.chars().count(), 30);
        assert!(result.ends_with("..."));
        // Verify we didn't panic on the multi-byte character
        assert!(result.contains("—") || result.ends_with("..."));
    }

    #[test]
    fn test_truncate_with_ellipsis_unicode_at_boundary() {
        // String where truncation point lands right at/near a multi-byte char
        let s = "Test string—with em-dash";
        let result = truncate_with_ellipsis(s, 15);
        assert_eq!(result.chars().count(), 15);
        assert!(result.ends_with("..."));
    }

    #[test]
    fn test_truncate_with_ellipsis_emoji() {
        let s = "Hello 🎉 world with emoji";
        let result = truncate_with_ellipsis(s, 10);
        assert_eq!(result.chars().count(), 10);
        assert!(result.ends_with("..."));
    }

    /// Create a test app for UI testing (no Docker connection needed)
    fn create_test_app_for_ui() -> TestApp {
        TestApp {
            instances: Vec::new(),
            table_state: TableState::default(),
            last_refresh: std::time::Instant::now(),
            status_message: None,
        }
    }

    /// Minimal app struct for testing without Docker
    struct TestApp {
        instances: Vec<InstanceInfo>,
        table_state: TableState,
        #[allow(dead_code)]
        last_refresh: std::time::Instant,
        status_message: Option<String>,
    }

    impl TestApp {
        fn next(&mut self) {
            if self.instances.is_empty() {
                return;
            }
            let i = match self.table_state.selected() {
                Some(i) => {
                    if i >= self.instances.len() - 1 {
                        0
                    } else {
                        i + 1
                    }
                }
                None => 0,
            };
            self.table_state.select(Some(i));
        }

        fn previous(&mut self) {
            if self.instances.is_empty() {
                return;
            }
            let i = match self.table_state.selected() {
                Some(i) => {
                    if i == 0 {
                        self.instances.len() - 1
                    } else {
                        i - 1
                    }
                }
                None => 0,
            };
            self.table_state.select(Some(i));
        }

        fn selected_instance(&self) -> Option<&InstanceInfo> {
            self.table_state
                .selected()
                .and_then(|i| self.instances.get(i))
        }
    }

    /// Create a key event for testing
    fn key_event(code: KeyCode) -> Event {
        Event::Key(KeyEvent {
            code,
            modifiers: KeyModifiers::empty(),
            kind: KeyEventKind::Press,
            state: KeyEventState::NONE,
        })
    }

    /// Handle event for TestApp (mirrors real handle_event)
    fn handle_test_event(app: &mut TestApp, event: Event) -> Option<Action> {
        match event {
            Event::Key(key) if key.kind == KeyEventKind::Press => match key.code {
                KeyCode::Char('q') | KeyCode::Esc => Some(Action::Quit),
                KeyCode::Char('j') | KeyCode::Down => {
                    app.next();
                    None
                }
                KeyCode::Char('k') | KeyCode::Up => {
                    app.previous();
                    None
                }
                KeyCode::Enter | KeyCode::Char('a') => {
                    if let Some(instance) = app.selected_instance() {
                        Some(Action::Attach(instance.name.clone()))
                    } else {
                        app.status_message = Some("No instance selected".to_string());
                        None
                    }
                }
                _ => None,
            },
            _ => None,
        }
    }

    /// Create sample instances for testing
    fn sample_instances() -> Vec<InstanceInfo> {
        vec![
            InstanceInfo {
                name: "myproject-abc123".to_string(),
                full_name: "devaipod-myproject-abc123".to_string(),
                status: "Running".to_string(),
                repo: Some("github.com/user/myproject".to_string()),
                task: Some("Implement new feature".to_string()),
                title: None,
                mode: Some("up".to_string()),
                agent_healthy: Some(true),
                created: Some("2024-01-15 10:30".to_string()),
                created_ts: Some(1705315800), // 2024-01-15 10:30
                git_state: Some(GitState {
                    branch: Some("main".to_string()),
                    dirty: false,
                    ahead: 0,
                    behind: 0,
                    summary: "main".to_string(),
                }),
                workspace_path: Some("/workspaces/myproject".to_string()),
                last_git_refresh: None,
                agent_state: AgentState {
                    activity: AgentActivity::Working,
                    status_line: Some("Processing request...".to_string()),
                    ..Default::default()
                },
                last_agent_refresh: None,
                api_password: None,
                api_port: None,
                gator_healthy: Some(true),
                gator_scopes: Some("--gh-repo user/myproject:read".to_string()),
                last_activity_ts: Some(1705315800000), // 2024-01-15 10:30 in millis
                worker_healthy: Some(true),
                degraded_containers: vec![],
            },
            InstanceInfo {
                name: "otherrepo-def456".to_string(),
                full_name: "devaipod-otherrepo-def456".to_string(),
                status: "Exited".to_string(),
                repo: Some("github.com/org/otherrepo".to_string()),
                task: None,
                title: None,
                mode: Some("run".to_string()),
                agent_healthy: Some(false),
                created: Some("2024-01-14 14:00".to_string()),
                created_ts: Some(1705240800), // 2024-01-14 14:00
                git_state: None,
                workspace_path: Some("/workspaces/otherrepo".to_string()),
                last_git_refresh: None,
                agent_state: AgentState {
                    activity: AgentActivity::Stopped,
                    ..Default::default()
                },
                last_agent_refresh: None,
                api_password: None,
                api_port: None,
                gator_healthy: Some(false),
                gator_scopes: None,
                last_activity_ts: Some(1705240800000), // 2024-01-14 14:00 in millis
                worker_healthy: Some(false),
                degraded_containers: vec![],
            },
            InstanceInfo {
                name: "degraded-pod".to_string(),
                full_name: "devaipod-degraded-pod".to_string(),
                status: "Degraded".to_string(),
                repo: None,
                task: Some("Fix bug in authentication".to_string()),
                title: None,
                mode: None,
                agent_healthy: None,
                created: None,
                created_ts: None,
                git_state: Some(GitState {
                    branch: Some("feature-x".to_string()),
                    dirty: true,
                    ahead: 2,
                    behind: 1,
                    summary: "feature-x* ↑2↓1".to_string(),
                }),
                workspace_path: None,
                last_git_refresh: None,
                agent_state: AgentState {
                    activity: AgentActivity::Idle,
                    ..Default::default()
                },
                last_agent_refresh: None,
                api_password: None,
                api_port: None,
                gator_healthy: None,
                gator_scopes: Some("--gh-repo org/repo:read,write".to_string()),
                last_activity_ts: None,
                worker_healthy: None,
                degraded_containers: vec!["agent".to_string()],
            },
        ]
    }

    #[test]
    fn test_navigation_next() {
        let mut app = create_test_app_for_ui();
        app.instances = sample_instances();
        app.table_state.select(Some(0));

        app.next();
        assert_eq!(app.table_state.selected(), Some(1));

        app.next();
        assert_eq!(app.table_state.selected(), Some(2));

        // Wrap around
        app.next();
        assert_eq!(app.table_state.selected(), Some(0));
    }

    #[test]
    fn test_navigation_previous() {
        let mut app = create_test_app_for_ui();
        app.instances = sample_instances();
        app.table_state.select(Some(0));

        // Wrap around to end
        app.previous();
        assert_eq!(app.table_state.selected(), Some(2));

        app.previous();
        assert_eq!(app.table_state.selected(), Some(1));
    }

    #[test]
    fn test_navigation_empty_list() {
        let mut app = create_test_app_for_ui();
        app.instances = vec![];

        app.next();
        assert_eq!(app.table_state.selected(), None);

        app.previous();
        assert_eq!(app.table_state.selected(), None);
    }

    #[test]
    fn test_handle_event_quit() {
        let mut app = create_test_app_for_ui();

        let action = handle_test_event(&mut app, key_event(KeyCode::Char('q')));
        assert_eq!(action, Some(Action::Quit));

        let action = handle_test_event(&mut app, key_event(KeyCode::Esc));
        assert_eq!(action, Some(Action::Quit));
    }

    #[test]
    fn test_handle_event_navigation() {
        let mut app = create_test_app_for_ui();
        app.instances = sample_instances();
        app.table_state.select(Some(0));

        let action = handle_test_event(&mut app, key_event(KeyCode::Char('j')));
        assert_eq!(action, None);
        assert_eq!(app.table_state.selected(), Some(1));

        let action = handle_test_event(&mut app, key_event(KeyCode::Char('k')));
        assert_eq!(action, None);
        assert_eq!(app.table_state.selected(), Some(0));
    }

    #[test]
    fn test_handle_event_attach() {
        let mut app = create_test_app_for_ui();
        app.instances = sample_instances();
        app.table_state.select(Some(0));

        let action = handle_test_event(&mut app, key_event(KeyCode::Enter));
        assert_eq!(action, Some(Action::Attach("myproject-abc123".to_string())));
    }

    #[test]
    fn test_handle_event_no_selection() {
        let mut app = create_test_app_for_ui();
        app.instances = sample_instances();
        // No selection

        let action = handle_test_event(&mut app, key_event(KeyCode::Enter));
        assert_eq!(action, None);
        assert!(app.status_message.is_some());
    }

    #[test]
    fn test_selected_instance() {
        let mut app = create_test_app_for_ui();
        app.instances = sample_instances();

        assert!(app.selected_instance().is_none());

        app.table_state.select(Some(1));
        let selected = app.selected_instance().unwrap();
        assert_eq!(selected.name, "otherrepo-def456");
    }
}
