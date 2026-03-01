//! TUI (Text User Interface) for devaipod
//!
//! Provides a real-time dashboard for managing devaipod instances using async Rust
//! with ratatui for rendering and bollard for container API access.

use std::collections::HashMap;
use std::io::{self, IsTerminal, Stdout};
use std::time::Duration;

use tokio::sync::mpsc;

use bollard::container::ListContainersOptions;
use bollard::models::ContainerSummary;
use bollard::Docker;
use color_eyre::eyre::{Context, Result};
use crossterm::event::{
    Event, EventStream, KeyCode, KeyEventKind, KeyModifiers, KeyboardEnhancementFlags,
    PopKeyboardEnhancementFlags, PushKeyboardEnhancementFlags,
};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, supports_keyboard_enhancement, EnterAlternateScreen,
    LeaveAlternateScreen,
};
use futures_util::StreamExt;
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Style, Stylize};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, Paragraph, TableState, Wrap};
use ratatui::Terminal;
use tokio::time::interval;

/// State file name for persistent TUI/instance state
const STATE_FILE_NAME: &str = "state.json";

/// Cache for TUI state, versioned for compatibility
#[derive(serde::Serialize, serde::Deserialize)]
struct TuiStateCache {
    /// Application version for compatibility check
    version: String,
    /// Cached state per instance (keyed by instance name)
    instances: HashMap<String, CachedInstanceState>,
}

/// Cached state for a single instance
#[derive(serde::Serialize, serde::Deserialize)]
struct CachedInstanceState {
    /// Cached git repository state
    git_state: Option<GitState>,
    /// Cached agent activity state
    agent_state: Option<AgentState>,
    /// Unix timestamp when this cache entry was last updated
    updated_at: i64,
}

/// Get the persistent state file path.
///
/// Uses XDG_DATA_HOME (typically ~/.local/share), falling back to ~/.local/share.
/// Creates the directory if it doesn't exist.
fn state_file_path() -> std::path::PathBuf {
    let data_dir = std::env::var("XDG_DATA_HOME")
        .map(std::path::PathBuf::from)
        .or_else(|_| {
            std::env::var("HOME").map(|h| std::path::PathBuf::from(h).join(".local/share"))
        })
        .unwrap_or_else(|_| std::path::PathBuf::from("/tmp"))
        .join("devaipod");

    // Ensure directory exists
    let _ = std::fs::create_dir_all(&data_dir);

    data_dir.join(STATE_FILE_NAME)
}

/// Load the TUI state from disk.
/// Returns None if state doesn't exist, is corrupt, or has a version mismatch.
fn load_state() -> Option<TuiStateCache> {
    let path = state_file_path();

    let contents = std::fs::read_to_string(&path).ok()?;
    let cache: TuiStateCache = serde_json::from_str(&contents).ok()?;

    // Version mismatch - ignore cache
    if cache.version != env!("CARGO_PKG_VERSION") {
        return None;
    }

    Some(cache)
}

/// Save the TUI state to disk.
/// Silently ignores any errors (state persistence is best-effort).
fn save_state(state: &TuiStateCache) {
    let path = state_file_path();

    // Write atomically via temp file
    let tmp_path = path.with_extension("tmp");
    if let Ok(contents) = serde_json::to_string_pretty(state) {
        if std::fs::write(&tmp_path, contents).is_ok() {
            let _ = std::fs::rename(&tmp_path, &path);
        }
    }
}

/// Build a cache from current instance state
fn build_cache(instances: &[InstanceInfo]) -> TuiStateCache {
    let now = chrono::Utc::now().timestamp();
    let entries: HashMap<String, CachedInstanceState> = instances
        .iter()
        .filter_map(|i| {
            // Only cache instances that have some fetched state
            if i.git_state.is_some() || i.agent_state.activity != AgentActivity::default() {
                Some((
                    i.name.clone(),
                    CachedInstanceState {
                        git_state: i.git_state.clone(),
                        agent_state: Some(i.agent_state.clone()),
                        updated_at: now,
                    },
                ))
            } else {
                None
            }
        })
        .collect();

    TuiStateCache {
        version: env!("CARGO_PKG_VERSION").to_string(),
        instances: entries,
    }
}

/// Prefix for all devaipod pod names
const POD_NAME_PREFIX: &str = "devaipod-";

use crate::{get_instance_id, INSTANCE_LABEL_KEY};

/// Check whether a container's labels match the current instance filter.
fn labels_match_instance(labels: Option<&HashMap<String, String>>) -> bool {
    let instance_id = get_instance_id();
    let pod_instance = labels
        .and_then(|l| l.get(INSTANCE_LABEL_KEY))
        .map(|s| s.as_str());

    match (instance_id.as_deref(), pod_instance) {
        (Some(want), Some(have)) => want == have,
        (Some(_), None) => false,
        (None, Some(_)) => false,
        (None, None) => true,
    }
}

/// Minimum interval between git state refreshes for a single instance.
/// Prevents excessive git command execution when multiple refresh triggers occur.
const GIT_REFRESH_RATE_LIMIT: Duration = Duration::from_secs(10);

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
    /// Full pod name
    pub full_name: String,
    /// Pod status (Running, Exited, Degraded)
    pub status: String,
    /// Repository URL from labels
    pub repo: Option<String>,
    /// Current task description from labels
    pub task: Option<String>,
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
    pub workspace_path: Option<String>,
    /// Last time git state was refreshed for this instance (for rate-limiting)
    pub last_git_refresh: Option<std::time::Instant>,
    /// Agent activity state (fetched async)
    pub agent_state: AgentState,
    /// Last time agent state was refreshed for this instance
    pub last_agent_refresh: Option<std::time::Instant>,
    /// API password for the opencode server (from pod labels)
    pub api_password: Option<String>,
    /// Published host port for the opencode API
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
            ContainerMenuItem::OrchestratorAgent => "opencode attach to task owner",
            ContainerMenuItem::WorkerAgent => "opencode attach to worker",
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
}

/// Application state for the TUI
pub struct App {
    /// Docker/Podman client
    docker: Docker,
    /// List of instances
    instances: Vec<InstanceInfo>,
    /// Table selection state
    table_state: TableState,
    /// Last refresh time
    last_refresh: std::time::Instant,
    /// Status message
    status_message: Option<String>,
    /// Cached TUI state (loaded on startup, updated on refreshes)
    cache: Option<TuiStateCache>,
    /// Current TUI mode (normal, delete select, etc.)
    mode: TuiMode,
    /// Instances selected for deletion (by name)
    selected_for_delete: std::collections::HashSet<String>,
    /// Launch dialog input state
    launch_input: LaunchInput,
    /// Selected item in container menu (0-3)
    container_menu_selection: usize,
}

impl App {
    /// Create a new App instance
    pub async fn new() -> Result<Self> {
        // Connect to container socket - we expect to run inside a container
        // with the host's podman/docker socket mounted at one of these paths
        let docker = crate::podman::connect_to_container_socket()
            .context("Failed to connect to podman/docker socket")?;

        // Load cached state for instant display
        let cache = load_state();

        let mut app = Self {
            docker,
            instances: Vec::new(),
            table_state: TableState::default(),
            last_refresh: std::time::Instant::now(),
            status_message: None,
            cache,
            mode: TuiMode::Normal,
            selected_for_delete: std::collections::HashSet::new(),
            launch_input: LaunchInput::default(),
            container_menu_selection: 0,
        };

        // Initial data fetch
        app.refresh_instances().await?;

        Ok(app)
    }

    /// Refresh the list of instances from podman
    pub async fn refresh_instances(&mut self) -> Result<()> {
        // Preserve git state and rate-limit timestamps from existing instances
        let old_git_data: HashMap<String, (Option<GitState>, Option<std::time::Instant>)> = self
            .instances
            .iter()
            .map(|i| (i.name.clone(), (i.git_state.clone(), i.last_git_refresh)))
            .collect();

        // Preserve agent state and rate-limit timestamps
        let old_agent_data: HashMap<String, (AgentState, Option<std::time::Instant>)> = self
            .instances
            .iter()
            .map(|i| {
                (
                    i.name.clone(),
                    (i.agent_state.clone(), i.last_agent_refresh),
                )
            })
            .collect();

        let filter = format!("{}*", POD_NAME_PREFIX);
        let mut filters = HashMap::new();
        filters.insert("name", vec![filter.as_str()]);

        let options = ListContainersOptions {
            all: true,
            filters,
            ..Default::default()
        };

        let containers = self
            .docker
            .list_containers(Some(options))
            .await
            .context("Failed to list containers")?;

        // Group containers by pod (using the pod label or name prefix)
        let mut pod_containers: HashMap<String, Vec<ContainerSummary>> = HashMap::new();

        for container in containers {
            // Extract pod name from container name
            // Container names look like: /devaipod-foo-workspace, /devaipod-foo-agent
            if let Some(names) = &container.names {
                for name in names {
                    let name = name.trim_start_matches('/');
                    if name.starts_with(POD_NAME_PREFIX) {
                        // Extract the pod name (everything before -workspace, -agent, -infra)
                        let pod_name = extract_pod_name(name);
                        pod_containers
                            .entry(pod_name.to_string())
                            .or_default()
                            .push(container.clone());
                        break;
                    }
                }
            }
        }

        // Build instance info from grouped containers
        let mut instances: Vec<InstanceInfo> = Vec::new();

        for (full_name, containers) in pod_containers {
            // Skip if this doesn't have a workspace container (e.g., orphaned gator containers)
            if !is_valid_instance(&containers) {
                continue;
            }

            let short_name = full_name
                .strip_prefix(POD_NAME_PREFIX)
                .unwrap_or(&full_name)
                .to_string();

            // Find the workspace container to extract labels
            let workspace = containers.iter().find(|c| {
                c.names
                    .as_ref()
                    .is_some_and(|n| n.iter().any(|name| name.ends_with("-workspace")))
            });

            // Extract labels from workspace container
            let labels = workspace.and_then(|w| w.labels.as_ref());

            // Filter by instance: skip pods that don't belong to this instance
            if !labels_match_instance(labels) {
                continue;
            }

            let repo = labels.and_then(|l| l.get("io.devaipod.repo")).cloned();
            let task = labels.and_then(|l| l.get("io.devaipod.task")).cloned();
            let mode = labels.and_then(|l| l.get("io.devaipod.mode")).cloned();

            // Determine overall status
            let running_count = containers
                .iter()
                .filter(|c| c.state.as_deref() == Some("running"))
                .count();
            let total = containers.len();

            let status = if running_count == total && total > 0 {
                "Running".to_string()
            } else if running_count == 0 {
                "Exited".to_string()
            } else {
                "Degraded".to_string()
            };

            // Check agent health (simplified - just check if agent container is running)
            let agent_healthy = containers.iter().any(|c| {
                c.names
                    .as_ref()
                    .is_some_and(|n| n.iter().any(|name| name.contains("-agent")))
                    && c.state.as_deref() == Some("running")
            });

            // Get created time from workspace container
            let created_ts = workspace.and_then(|w| w.created);
            let created = created_ts.map(|ts| {
                chrono::DateTime::from_timestamp(ts, 0)
                    .map(|dt| dt.format("%Y-%m-%d %H:%M").to_string())
                    .unwrap_or_else(|| "-".to_string())
            });

            // Extract workspace path from labels
            let workspace_path = labels.and_then(|l| l.get("io.devaipod.workspace")).cloned();

            // Restore git state and rate-limit timestamp from previous instance data
            // Fall back to cache if no in-memory state exists
            let (git_state, last_git_refresh) = old_git_data
                .get(&short_name)
                .cloned()
                .or_else(|| {
                    // Try loading from cache
                    self.cache
                        .as_ref()
                        .and_then(|c| c.instances.get(&short_name))
                        .map(|cached| (cached.git_state.clone(), None))
                })
                .unwrap_or((None, None));

            // Restore agent state and rate-limit timestamp from previous instance data
            // Default to Stopped if agent is not running, otherwise preserve or set Unknown
            // Fall back to cache if no in-memory state exists
            let (agent_state, last_agent_refresh) = if agent_healthy {
                old_agent_data
                    .get(&short_name)
                    .cloned()
                    .or_else(|| {
                        // Try loading from cache
                        self.cache
                            .as_ref()
                            .and_then(|c| c.instances.get(&short_name))
                            .and_then(|cached| cached.agent_state.clone().map(|s| (s, None)))
                    })
                    .unwrap_or((
                        AgentState {
                            activity: AgentActivity::Unknown,
                            ..Default::default()
                        },
                        None,
                    ))
            } else {
                (
                    AgentState {
                        activity: AgentActivity::Stopped,
                        ..Default::default()
                    },
                    None,
                )
            };

            // Extract API password from labels (stored on workspace container)
            let api_password = labels
                .and_then(|l| l.get("io.devaipod.api-password"))
                .cloned();

            // Get published port from agent container's port mappings
            let agent_container = containers.iter().find(|c| {
                c.names
                    .as_ref()
                    .is_some_and(|n| n.iter().any(|name| name.ends_with("-agent")))
            });
            let api_port = agent_container.and_then(|c| {
                c.ports.as_ref().and_then(|ports| {
                    ports.iter().find_map(|p| {
                        // Looking for the opencode port which is published to host
                        if p.private_port == crate::pod::OPENCODE_PORT {
                            p.public_port
                        } else {
                            None
                        }
                    })
                })
            });

            // Check service-gator health
            let gator_healthy = containers.iter().any(|c| {
                c.names.as_ref().is_some_and(|n| {
                    n.iter()
                        .any(|name| name.ends_with("-gator") || name.ends_with("-service-gator"))
                }) && c.state.as_deref() == Some("running")
            });

            // Get service-gator scopes from labels
            let gator_scopes = labels
                .and_then(|l| l.get("io.devaipod.service-gator"))
                .cloned();

            // Check worker container health (if orchestration is enabled)
            let worker_healthy = containers.iter().any(|c| {
                c.names
                    .as_ref()
                    .is_some_and(|n| n.iter().any(|name| name.ends_with("-worker")))
                    && c.state.as_deref() == Some("running")
            });

            // Collect names of non-running containers (for degraded status display)
            let degraded_containers: Vec<String> = containers
                .iter()
                .filter(|c| {
                    c.state.as_deref() != Some("running")
                        && !c
                            .names
                            .as_ref()
                            .is_some_and(|n| n.iter().any(|name| name.ends_with("-infra")))
                })
                .filter_map(|c| {
                    c.names.as_ref().and_then(|n| {
                        n.first().map(|name| {
                            let name = name.trim_start_matches('/');
                            name.strip_prefix(&format!("{}-", full_name))
                                .unwrap_or(name)
                                .to_string()
                        })
                    })
                })
                .collect();

            // Initialize last_activity_ts from agent state if available, otherwise from created_ts
            let last_activity_ts = agent_state
                .last_message_ts
                .or(created_ts.map(|ts| ts * 1000)); // Convert created_ts (seconds) to milliseconds

            instances.push(InstanceInfo {
                name: short_name,
                full_name,
                status,
                repo,
                task,
                mode,
                agent_healthy: Some(agent_healthy),
                created,
                created_ts,
                git_state,
                workspace_path,
                last_git_refresh,
                agent_state,
                last_agent_refresh,
                api_password,
                api_port,
                gator_healthy: Some(gator_healthy),
                gator_scopes,
                last_activity_ts,
                worker_healthy: Some(worker_healthy),
                degraded_containers,
            });
        }

        // Sort by last activity time (most recently active first), with fallback to name for ties
        instances.sort_by(|a, b| match (b.last_activity_ts, a.last_activity_ts) {
            (Some(b_ts), Some(a_ts)) => b_ts.cmp(&a_ts).then_with(|| a.name.cmp(&b.name)),
            (Some(_), None) => std::cmp::Ordering::Less,
            (None, Some(_)) => std::cmp::Ordering::Greater,
            (None, None) => a.name.cmp(&b.name),
        });

        self.instances = instances;
        self.last_refresh = std::time::Instant::now();

        // NOTE: Git state is fetched separately via refresh_git_states_background()
        // to avoid blocking the initial display

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

    /// Update and persist the cache with current instance state
    fn update_cache(&mut self) {
        let new_cache = build_cache(&self.instances);
        save_state(&new_cache);
        self.cache = Some(new_cache);
    }
}

/// Fetch git state from a container by exec'ing git commands
async fn fetch_git_state(
    docker: &Docker,
    container_name: &str,
    workspace_path: &str,
) -> Option<GitState> {
    use bollard::exec::{CreateExecOptions, StartExecResults};
    use futures_util::TryStreamExt;

    // Helper to run a git command and get stdout
    async fn git_exec(
        docker: &Docker,
        container: &str,
        workdir: &str,
        args: &[&str],
    ) -> Option<String> {
        let mut cmd = vec!["git", "-C", workdir];
        cmd.extend(args);

        let exec = docker
            .create_exec(
                container,
                CreateExecOptions {
                    attach_stdout: Some(true),
                    attach_stderr: Some(true),
                    cmd: Some(cmd.iter().map(|s| s.to_string()).collect()),
                    ..Default::default()
                },
            )
            .await
            .ok()?;

        let output = docker.start_exec(&exec.id, None).await.ok()?;

        if let StartExecResults::Attached { mut output, .. } = output {
            let mut stdout = String::new();
            while let Ok(Some(msg)) = output.try_next().await {
                stdout.push_str(&msg.to_string());
            }
            Some(stdout.trim().to_string())
        } else {
            None
        }
    }

    // Find the actual repo directory
    // First, try to find directories in /workspaces
    let repo_dir = {
        // List directories in /workspaces
        let ls_exec = docker
            .create_exec(
                container_name,
                CreateExecOptions {
                    attach_stdout: Some(true),
                    cmd: Some(vec![
                        "ls".to_string(),
                        "-1".to_string(),
                        "/workspaces".to_string(),
                    ]),
                    ..Default::default()
                },
            )
            .await
            .ok();

        let dirs: Vec<String> = if let Some(exec) = ls_exec {
            if let Ok(StartExecResults::Attached { mut output, .. }) =
                docker.start_exec(&exec.id, None).await
            {
                let mut stdout = String::new();
                while let Ok(Some(msg)) = output.try_next().await {
                    stdout.push_str(&msg.to_string());
                }
                stdout
                    .lines()
                    .filter(|s| !s.is_empty())
                    .map(|s| s.to_string())
                    .collect()
            } else {
                vec![]
            }
        } else {
            vec![]
        };

        // Use the first directory found, or fall back to workspace_path
        if let Some(first_dir) = dirs.first() {
            format!("/workspaces/{}", first_dir)
        } else if workspace_path != "/workspaces" {
            workspace_path.to_string()
        } else {
            return None; // No workspace found
        }
    };

    // Get current branch
    let branch = git_exec(
        docker,
        container_name,
        &repo_dir,
        &["rev-parse", "--abbrev-ref", "HEAD"],
    )
    .await
    .filter(|s| !s.is_empty() && s != "HEAD");

    // Check for uncommitted changes (dirty state)
    let status_output = git_exec(
        docker,
        container_name,
        &repo_dir,
        &["status", "--porcelain"],
    )
    .await;
    let dirty = status_output.as_ref().is_some_and(|s| !s.is_empty());

    // Get ahead/behind counts - use tracking branch or fall back to origin/main
    let (ahead, behind) = if let Some(ref branch_name) = branch {
        // Use @{upstream} which git resolves to the tracking branch, or try origin/main
        let rev_list = git_exec(
            docker,
            container_name,
            &repo_dir,
            &["rev-list", "--left-right", "--count", "HEAD...@{upstream}"],
        )
        .await
        .filter(|s| !s.contains("fatal") && !s.contains("error"));

        // Fall back to origin/main if no upstream configured
        let counts = if rev_list.is_some() {
            rev_list
        } else {
            git_exec(
                docker,
                container_name,
                &repo_dir,
                &[
                    "rev-list",
                    "--left-right",
                    "--count",
                    &format!("{}...origin/main", branch_name),
                ],
            )
            .await
            .filter(|s| !s.contains("fatal") && !s.contains("error"))
        };

        if let Some(counts) = counts {
            let parts: Vec<&str> = counts.split_whitespace().collect();
            if parts.len() == 2 {
                let a = parts[0].parse().unwrap_or(0);
                let b = parts[1].parse().unwrap_or(0);
                (a, b)
            } else {
                (0, 0)
            }
        } else {
            (0, 0)
        }
    } else {
        (0, 0)
    };

    let mut state = GitState {
        branch,
        dirty,
        ahead,
        behind,
        summary: String::new(),
    };
    state.compute_summary();

    Some(state)
}

/// Minimum interval between agent state refreshes for a single instance.
const AGENT_REFRESH_RATE_LIMIT: Duration = Duration::from_secs(3);

/// Maximum number of output lines to keep per instance
const MAX_OUTPUT_LINES: usize = 3;

/// Extract text content from message parts, truncating long lines
fn extract_text_from_parts(parts: &[serde_json::Value], max_lines: usize) -> Vec<String> {
    let mut lines = Vec::new();

    for part in parts {
        let part_type = part.get("type").and_then(|t| t.as_str()).unwrap_or("");

        match part_type {
            "text" => {
                if let Some(text) = part.get("text").and_then(|t| t.as_str()) {
                    // Take last few lines of text, truncate each line
                    for line in text.lines().rev().take(max_lines) {
                        let truncated = if line.len() > 80 {
                            format!("{}...", &line[..77])
                        } else {
                            line.to_string()
                        };
                        if !truncated.trim().is_empty() {
                            lines.push(truncated);
                        }
                        if lines.len() >= max_lines {
                            break;
                        }
                    }
                }
            }
            "tool" => {
                // Extract tool name and status
                if let Some(tool_name) = part.get("name").and_then(|n| n.as_str()) {
                    let status = part
                        .get("state")
                        .and_then(|s| s.get("status"))
                        .and_then(|s| s.as_str())
                        .unwrap_or("running");
                    lines.push(format!("→ {}: {}", tool_name, status));
                }
            }
            _ => {}
        }

        if lines.len() >= max_lines {
            break;
        }
    }

    lines.reverse(); // Put in chronological order
    lines
}

/// Derive agent status (busy/idle) from session messages.
///
/// This mirrors the logic from workspace_monitor.py's derive_status_from_messages().
/// We check the last assistant message for:
/// - time.completed: if absent, agent is still processing
/// - finish: if "tool-calls", agent will continue (but may be between calls)
/// - parts with type="tool" and state.status != "completed": tool in progress
fn derive_agent_state_from_messages(messages: &[serde_json::Value]) -> AgentState {
    if messages.is_empty() {
        return AgentState {
            activity: AgentActivity::Unknown,
            ..Default::default()
        };
    }

    // Find the last assistant message
    let last_assistant = messages.iter().rev().find(|msg| {
        msg.get("info")
            .and_then(|i| i.get("role"))
            .and_then(|r| r.as_str())
            == Some("assistant")
    });

    let Some(last_assistant) = last_assistant else {
        return AgentState {
            activity: AgentActivity::Unknown,
            ..Default::default()
        };
    };

    let info = match last_assistant.get("info") {
        Some(i) => i,
        None => {
            return AgentState {
                activity: AgentActivity::Unknown,
                ..Default::default()
            }
        }
    };

    // Extract recent output from parts
    let parts = last_assistant
        .get("parts")
        .and_then(|p| p.as_array())
        .map(|arr| arr.as_slice())
        .unwrap_or(&[]);
    let recent_output = extract_text_from_parts(parts, MAX_OUTPUT_LINES);

    // Extract current tool if any is running
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

    // Build status line from first text part
    let status_line = parts.iter().find_map(|part| {
        if part.get("type").and_then(|t| t.as_str()) == Some("text") {
            part.get("text").and_then(|t| t.as_str()).map(|text| {
                let first_line = text.lines().next().unwrap_or("");
                truncate_with_ellipsis(first_line, 60)
            })
        } else {
            None
        }
    });

    // Determine activity level
    let activity = if info.get("time").and_then(|t| t.get("completed")).is_none() {
        AgentActivity::Working
    } else {
        // Check if there are any incomplete tool calls
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
            AgentActivity::Working
        } else {
            let finish = info.get("finish").and_then(|f| f.as_str()).unwrap_or("");
            if finish == "tool-calls" {
                AgentActivity::Working
            } else {
                AgentActivity::Idle
            }
        }
    };

    // Extract the most recent message timestamp from all messages
    // We look for the latest time.completed or time.created across all messages
    let last_message_ts = messages
        .iter()
        .filter_map(|msg| {
            msg.get("info").and_then(|info| {
                info.get("time").and_then(|time| {
                    // Prefer completed time, fall back to created time
                    time.get("completed")
                        .or_else(|| time.get("created"))
                        .and_then(|t| t.as_i64())
                })
            })
        })
        .max();

    AgentState {
        activity,
        recent_output,
        current_tool,
        status_line,
        last_message_ts,
    }
}

/// Fetch agent state by querying the opencode API
async fn fetch_agent_state(api_port: u16, api_password: &str) -> AgentState {
    let unknown = AgentState {
        activity: AgentActivity::Unknown,
        ..Default::default()
    };

    // Build HTTP client with timeout
    let client = match reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
    {
        Ok(c) => c,
        Err(_) => return unknown,
    };

    let base_url = format!("http://127.0.0.1:{}", api_port);

    // First, get the list of sessions
    let sessions_url = format!("{}/session", base_url);
    let sessions_resp = match client
        .get(&sessions_url)
        .basic_auth("opencode", Some(api_password))
        .send()
        .await
    {
        Ok(r) if r.status().is_success() => r,
        _ => return unknown,
    };

    let sessions: Vec<serde_json::Value> = match sessions_resp.json().await {
        Ok(s) => s,
        Err(_) => return unknown,
    };

    if sessions.is_empty() {
        // No sessions yet - agent is idle/waiting for input
        return AgentState {
            activity: AgentActivity::Idle,
            status_line: Some("Waiting for input...".to_string()),
            ..Default::default()
        };
    }

    // Find the root session (no parent)
    let root_session = sessions.iter().find(|s| {
        s.get("parentID").is_none() || s.get("parentID").map(|p| p.is_null()).unwrap_or(false)
    });

    let Some(root_session) = root_session else {
        return unknown;
    };

    let session_id = match root_session.get("id").and_then(|id| id.as_str()) {
        Some(id) => id,
        None => return unknown,
    };

    // Fetch recent messages from the session (more messages for richer output)
    let messages_url = format!("{}/session/{}/message?limit=5", base_url, session_id);
    let messages_resp = match client
        .get(&messages_url)
        .basic_auth("opencode", Some(api_password))
        .send()
        .await
    {
        Ok(r) if r.status().is_success() => r,
        _ => return unknown,
    };

    let messages: Vec<serde_json::Value> = match messages_resp.json().await {
        Ok(m) => m,
        Err(_) => return unknown,
    };

    derive_agent_state_from_messages(&messages)
}

/// Truncate a string to a maximum number of characters, adding "..." if truncated.
///
/// This correctly handles multi-byte UTF-8 characters by counting characters,
/// not bytes.
fn truncate_with_ellipsis(s: &str, max_chars: usize) -> String {
    if s.chars().count() <= max_chars {
        s.to_string()
    } else {
        let truncated: String = s.chars().take(max_chars.saturating_sub(3)).collect();
        format!("{truncated}...")
    }
}

/// Extract the pod name from a container name
/// e.g., "devaipod-foo-workspace" -> "devaipod-foo"
fn extract_pod_name(container_name: &str) -> &str {
    // Order matters - check longer suffixes first
    for suffix in &[
        "-service-gator",
        "-workspace",
        "-worker",
        "-agent",
        "-infra",
        "-gator",
        "-proxy",
    ] {
        if let Some(prefix) = container_name.strip_suffix(suffix) {
            return prefix;
        }
    }
    container_name
}

/// Check if this is a valid devaipod instance (has workspace container)
fn is_valid_instance(containers: &[ContainerSummary]) -> bool {
    containers.iter().any(|c| {
        c.names
            .as_ref()
            .is_some_and(|n| n.iter().any(|name| name.ends_with("-workspace")))
    })
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
pub async fn run() -> Result<()> {
    // Check if we're running in a terminal
    if !std::io::stdout().is_terminal() {
        color_eyre::eyre::bail!(
            "TUI requires a terminal. Use 'devaipod list' for non-interactive output."
        );
    }

    let (mut terminal, keyboard_enhancement) = setup_terminal()?;

    // Create app and run
    let app = App::new().await?;
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

/// Message for git state updates from background task
struct GitStateUpdate {
    instance_name: String,
    git_state: Option<GitState>,
}

/// Spawn background tasks to fetch git state for all running instances.
/// Rate-limited per instance: only spawns a refresh if >GIT_REFRESH_RATE_LIMIT
/// has passed since the last successful refresh for that instance.
fn spawn_git_refresh(
    docker: &Docker,
    instances: &[InstanceInfo],
    tx: mpsc::Sender<GitStateUpdate>,
) {
    let now = std::time::Instant::now();

    for instance in instances {
        if instance.status != "Running" {
            continue;
        }

        // Rate-limit: skip if we refreshed this instance recently
        if let Some(last_refresh) = instance.last_git_refresh {
            if now.duration_since(last_refresh) < GIT_REFRESH_RATE_LIMIT {
                continue;
            }
        }

        let docker = docker.clone();
        let tx = tx.clone();
        let instance_name = instance.name.clone();
        let full_name = instance.full_name.clone();
        let workspace_path = instance
            .workspace_path
            .clone()
            .unwrap_or_else(|| "/workspaces".to_string());

        tokio::spawn(async move {
            let container_name = format!("{}-workspace", full_name);
            let git_state = fetch_git_state(&docker, &container_name, &workspace_path).await;
            let _ = tx
                .send(GitStateUpdate {
                    instance_name,
                    git_state,
                })
                .await;
        });
    }
}

/// Message for agent state updates from background task
struct AgentStateUpdate {
    instance_name: String,
    agent_state: AgentState,
}

/// Spawn background tasks to fetch agent state for all running instances.
/// Rate-limited per instance: only spawns a refresh if >AGENT_REFRESH_RATE_LIMIT
/// has passed since the last successful refresh for that instance.
fn spawn_agent_refresh(instances: &[InstanceInfo], tx: mpsc::Sender<AgentStateUpdate>) {
    let now = std::time::Instant::now();

    for instance in instances {
        // Only fetch for running instances with valid API credentials
        if instance.status != "Running" {
            continue;
        }

        // Skip if agent is not healthy (not running)
        if instance.agent_healthy != Some(true) {
            continue;
        }

        // Need both port and password to query the API
        let (Some(api_port), Some(ref api_password)) = (instance.api_port, &instance.api_password)
        else {
            continue;
        };

        // Rate-limit: skip if we refreshed this instance recently
        if let Some(last_refresh) = instance.last_agent_refresh {
            if now.duration_since(last_refresh) < AGENT_REFRESH_RATE_LIMIT {
                continue;
            }
        }

        let tx = tx.clone();
        let instance_name = instance.name.clone();
        let api_password = api_password.clone();

        tokio::spawn(async move {
            let agent_state = fetch_agent_state(api_port, &api_password).await;
            let _ = tx
                .send(AgentStateUpdate {
                    instance_name,
                    agent_state,
                })
                .await;
        });
    }
}

/// Main event loop
async fn run_app(terminal: &mut Terminal<CrosstermBackend<Stdout>>, mut app: App) -> Result<()> {
    let mut refresh_interval = interval(Duration::from_secs(10));

    // Channel for receiving git state updates from background tasks
    let (git_tx, mut git_rx) = mpsc::channel::<GitStateUpdate>(32);

    // Channel for receiving agent state updates from background tasks
    let (agent_tx, mut agent_rx) = mpsc::channel::<AgentStateUpdate>(32);

    // Spawn initial git state fetch
    spawn_git_refresh(&app.docker, &app.instances, git_tx.clone());

    // Spawn initial agent state fetch
    spawn_agent_refresh(&app.instances, agent_tx.clone());

    // Use async event stream instead of blocking poll
    let mut event_stream = EventStream::new();

    // Agent state refresh runs more frequently than git state
    let mut agent_refresh_interval = interval(Duration::from_secs(3));

    loop {
        // Draw the UI
        terminal.draw(|f| ui(f, &mut app))?;

        // Handle events with proper async - no blocking!
        tokio::select! {
            // Receive git state updates from background
            Some(update) = git_rx.recv() => {
                if let Some(instance) = app.instances.iter_mut().find(|i| i.name == update.instance_name) {
                    instance.git_state = update.git_state;
                    // Update timestamp to enforce rate-limiting on subsequent refresh attempts
                    instance.last_git_refresh = Some(std::time::Instant::now());
                }
                // Persist updated state to cache
                app.update_cache();
            }
            // Receive agent state updates from background
            Some(update) = agent_rx.recv() => {
                if let Some(instance) = app.instances.iter_mut().find(|i| i.name == update.instance_name) {
                    // Update last_activity_ts from agent's last message timestamp
                    if let Some(ts) = update.agent_state.last_message_ts {
                        instance.last_activity_ts = Some(ts);
                    }
                    instance.agent_state = update.agent_state;
                    // Update timestamp to enforce rate-limiting on subsequent refresh attempts
                    instance.last_agent_refresh = Some(std::time::Instant::now());
                }
                // Persist updated state to cache
                app.update_cache();
                // Note: We intentionally don't re-sort here. Re-sorting on every agent
                // update would cause items to jump around constantly as agents work,
                // which is jarring UX. The periodic full refresh handles re-sorting.
            }
            // Periodic agent state refresh (more frequent)
            _ = agent_refresh_interval.tick() => {
                spawn_agent_refresh(&app.instances, agent_tx.clone());
            }
            _ = refresh_interval.tick() => {
                if let Err(e) = app.refresh_instances().await {
                    app.status_message = Some(format!("Refresh error: {}", e));
                } else {
                    // Spawn background git refresh after instance refresh
                    spawn_git_refresh(&app.docker, &app.instances, git_tx.clone());
                    // Also refresh agent state
                    spawn_agent_refresh(&app.instances, agent_tx.clone());
                }
            }
            // Async event stream - truly non-blocking
            maybe_event = event_stream.next() => {
                if let Some(Ok(event)) = maybe_event {
                    if let Some(action) = handle_event(&mut app, event) {
                        match action {
                            Action::Quit => return Ok(()),
                            Action::Refresh => {
                                app.status_message = Some("Refreshing...".to_string());
                                if let Err(e) = app.refresh_instances().await {
                                    app.status_message = Some(format!("Refresh error: {}", e));
                                } else {
                                    spawn_git_refresh(&app.docker, &app.instances, git_tx.clone());
                                    spawn_agent_refresh(&app.instances, agent_tx.clone());
                                    app.status_message = Some("Refreshed".to_string());
                                }
                            }
                            Action::Attach(name) => {
                                // Run attach in subprocess (opens tmux with agent + shell)
                                // Use -- to prevent names starting with - being parsed as options
                                run_subprocess(terminal, &["attach", "--", &name]).await?;
                                // Reset intervals to prevent accumulated ticks from firing
                                refresh_interval.reset();
                                agent_refresh_interval.reset();
                                // Refresh after returning from subprocess
                                let _ = app.refresh_instances().await;
                                spawn_git_refresh(&app.docker, &app.instances, git_tx.clone());
                                spawn_agent_refresh(&app.instances, agent_tx.clone());
                            }
                            Action::Delete(names) => {
                                // Delete instances synchronously for now
                                let count = names.len();
                                app.status_message = Some(format!(
                                    "Deleting {} instance{}...",
                                    count,
                                    if count == 1 { "" } else { "s" }
                                ));
                                terminal.draw(|f| ui(f, &mut app))?;

                                let mut errors = Vec::new();
                                for name in &names {
                                    // Use -- to prevent names starting with - being parsed as options
                                    if let Err(e) = run_subprocess_silent(&["delete", "--force", "--", name]).await {
                                        errors.push(format!("{}: {}", name, e));
                                    }
                                }

                                // Reset intervals to prevent accumulated ticks from firing
                                refresh_interval.reset();
                                agent_refresh_interval.reset();
                                // Refresh after deletions
                                let _ = app.refresh_instances().await;
                                spawn_git_refresh(&app.docker, &app.instances, git_tx.clone());
                                spawn_agent_refresh(&app.instances, agent_tx.clone());

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
                                // Check instance status to determine whether to start or stop
                                let is_running = app
                                    .instances
                                    .iter()
                                    .find(|i| i.name == name)
                                    .is_some_and(|i| i.status == "Running");

                                if is_running {
                                    app.status_message = Some(format!("Stopping {}...", name));
                                    terminal.draw(|f| ui(f, &mut app))?;

                                    // Use -- to prevent names starting with - being parsed as options
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

                                    // Use -- to prevent names starting with - being parsed as options
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

                                // Reset intervals to prevent accumulated ticks from firing
                                refresh_interval.reset();
                                agent_refresh_interval.reset();
                                // Refresh after start/stop
                                let _ = app.refresh_instances().await;
                                spawn_git_refresh(&app.docker, &app.instances, git_tx.clone());
                                spawn_agent_refresh(&app.instances, agent_tx.clone());
                            }
                            Action::ExecAgent(name) => {
                                // Exec into agent container
                                // Use -- to prevent names starting with - being parsed as options
                                run_subprocess(terminal, &["exec", "--", &name]).await?;
                                // Reset intervals to prevent accumulated ticks from firing
                                refresh_interval.reset();
                                agent_refresh_interval.reset();
                                // Refresh after returning from subprocess
                                let _ = app.refresh_instances().await;
                                spawn_git_refresh(&app.docker, &app.instances, git_tx.clone());
                                spawn_agent_refresh(&app.instances, agent_tx.clone());
                            }
                            Action::ExecWorkspace(name) => {
                                // Exec into workspace container
                                // Use -- to prevent names starting with - being parsed as options
                                run_subprocess(terminal, &["exec", "-W", "--", &name]).await?;
                                // Reset intervals to prevent accumulated ticks from firing
                                refresh_interval.reset();
                                agent_refresh_interval.reset();
                                // Refresh after returning from subprocess
                                let _ = app.refresh_instances().await;
                                spawn_git_refresh(&app.docker, &app.instances, git_tx.clone());
                                spawn_agent_refresh(&app.instances, agent_tx.clone());
                            }
                            Action::AttachWorker(name) => {
                                // Attach to worker agent
                                // Use -- to prevent names starting with - being parsed as options
                                run_subprocess(terminal, &["attach", "--worker", "--", &name]).await?;
                                // Reset intervals to prevent accumulated ticks from firing
                                refresh_interval.reset();
                                agent_refresh_interval.reset();
                                // Refresh after returning from subprocess
                                let _ = app.refresh_instances().await;
                                spawn_git_refresh(&app.docker, &app.instances, git_tx.clone());
                                spawn_agent_refresh(&app.instances, agent_tx.clone());
                            }
                            Action::ExecWorker(name) => {
                                // Exec into worker container
                                // Use -- to prevent names starting with - being parsed as options
                                run_subprocess(terminal, &["exec", "--worker", "--", &name]).await?;
                                // Reset intervals to prevent accumulated ticks from firing
                                refresh_interval.reset();
                                agent_refresh_interval.reset();
                                // Refresh after returning from subprocess
                                let _ = app.refresh_instances().await;
                                spawn_git_refresh(&app.docker, &app.instances, git_tx.clone());
                                spawn_agent_refresh(&app.instances, agent_tx.clone());
                            }
                            Action::Launch { urls, task } => {
                                // Launch instances for each URL in parallel
                                let count = urls.len();
                                app.status_message = Some(format!(
                                    "Launching {} instance{}...",
                                    count,
                                    if count == 1 { "" } else { "s" }
                                ));
                                terminal.draw(|f| ui(f, &mut app))?;

                                let mut errors = Vec::new();
                                for url in &urls {
                                    if let Err(e) = run_subprocess_silent(&["run", url, "-c", &task]).await {
                                        errors.push(format!("{}: {}", url, e));
                                    }
                                }

                                // Reset intervals to prevent accumulated ticks from firing
                                refresh_interval.reset();
                                agent_refresh_interval.reset();
                                // Refresh after launches
                                let _ = app.refresh_instances().await;
                                spawn_git_refresh(&app.docker, &app.instances, git_tx.clone());
                                spawn_agent_refresh(&app.instances, agent_tx.clone());

                                if errors.is_empty() {
                                    app.status_message = Some(format!(
                                        "Launched {} instance{}",
                                        count,
                                        if count == 1 { "" } else { "s" }
                                    ));
                                } else {
                                    app.status_message = Some(format!("Errors: {}", errors.join(", ")));
                                }
                            }
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
            // Enter launch mode
            app.mode = TuiMode::Launch;
            app.launch_input = LaunchInput::default();
            app.status_message = None;
            None
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

    if urls.is_empty() {
        app.status_message = Some("Enter at least one URL".to_string());
        app.launch_input.active_field = LaunchField::Urls;
        None
    } else if task.is_empty() {
        app.status_message = Some("Enter a task".to_string());
        app.launch_input.active_field = LaunchField::Task;
        None
    } else {
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
    let header = Paragraph::new(Line::from(vec![
        Span::styled(" devaipod ", Style::default().fg(Color::Cyan).bold()),
        Span::raw("│ "),
        Span::styled(
            format!("{} instances", app.instances.len()),
            Style::default().fg(Color::Green),
        ),
        Span::raw(" │ Last refresh: "),
        Span::styled(
            format!("{}s ago", app.last_refresh.elapsed().as_secs()),
            Style::default().fg(Color::Yellow),
        ),
    ]))
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
            " q: Quit │ j/k: Nav │ a/Enter: Attach │ →/l: Menu │ e: Exec │ S: Start/Stop │ d: Del │ L: Launch │ r: Refresh",
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

    lines.push(Line::from(vec![
        prefix,
        Span::styled(
            instance.name.clone(),
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

/// Render instances as cards (multi-line per instance)
fn render_table(frame: &mut ratatui::Frame, app: &mut App, area: Rect) {
    let in_delete_mode = matches!(app.mode, TuiMode::DeleteSelect | TuiMode::DeleteConfirm);
    let selected_idx = app.table_state.selected();
    let selected_for_delete = &app.selected_for_delete;

    // Build card content for all instances
    let mut all_lines: Vec<Line> = Vec::new();

    for (idx, instance) in app.instances.iter().enumerate() {
        let is_selected = selected_idx == Some(idx);
        let is_marked = selected_for_delete.contains(&instance.name);

        let card_lines =
            render_instance_card(instance, is_selected, is_marked, in_delete_mode, area.width);

        // Add separator before card (except first)
        if idx > 0 {
            all_lines.push(Line::from(Span::styled(
                "─".repeat(area.width.saturating_sub(2) as usize),
                Style::default().fg(Color::DarkGray),
            )));
        }

        all_lines.extend(card_lines);
    }

    // Calculate scroll offset to keep selected item visible
    let visible_height = area.height.saturating_sub(2) as usize; // Account for borders
    let lines_per_card = CARD_HEIGHT as usize + 1; // +1 for separator
    let selected_card_start = selected_idx.unwrap_or(0) * lines_per_card;

    // Simple scroll: show from selected card if it would be off-screen
    let scroll_offset = if selected_card_start >= visible_height {
        selected_card_start.saturating_sub(visible_height / 2)
    } else {
        0
    };

    // Apply scroll offset
    let visible_lines: Vec<Line> = all_lines.into_iter().skip(scroll_offset).collect();

    let paragraph = Paragraph::new(visible_lines)
        .block(Block::default().borders(Borders::ALL).title(" Instances "));

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
    fn test_extract_pod_name() {
        assert_eq!(extract_pod_name("devaipod-foo-workspace"), "devaipod-foo");
        assert_eq!(extract_pod_name("devaipod-foo-agent"), "devaipod-foo");
        assert_eq!(
            extract_pod_name("devaipod-foo-bar-workspace"),
            "devaipod-foo-bar"
        );
        assert_eq!(
            extract_pod_name("devaipod-foo-service-gator"),
            "devaipod-foo"
        );
        assert_eq!(extract_pod_name("unknown-container"), "unknown-container");
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

    #[test]
    fn test_derive_agent_state_empty_messages() {
        let messages: Vec<serde_json::Value> = vec![];
        let state = derive_agent_state_from_messages(&messages);
        assert_eq!(state.activity, AgentActivity::Unknown);
    }

    #[test]
    fn test_derive_agent_state_no_assistant_message() {
        let messages = vec![serde_json::json!({
            "info": {"role": "user"},
            "parts": [{"type": "text", "text": "Hello"}]
        })];
        let state = derive_agent_state_from_messages(&messages);
        assert_eq!(state.activity, AgentActivity::Unknown);
    }

    #[test]
    fn test_derive_agent_state_working_no_completed_time() {
        // Message without completed time indicates agent is still working
        let messages = vec![serde_json::json!({
            "info": {
                "role": "assistant",
                "time": {"created": 1234567890}
            },
            "parts": [{"type": "text", "text": "Working on it..."}]
        })];
        let state = derive_agent_state_from_messages(&messages);
        assert_eq!(state.activity, AgentActivity::Working);
        assert!(state.status_line.is_some());
    }

    #[test]
    fn test_derive_agent_state_idle_with_stop_finish() {
        // Completed message with finish=stop indicates idle
        let messages = vec![serde_json::json!({
            "info": {
                "role": "assistant",
                "time": {"created": 1234567890, "completed": 1234567891},
                "finish": "stop"
            },
            "parts": [{"type": "text", "text": "Done!"}]
        })];
        let state = derive_agent_state_from_messages(&messages);
        assert_eq!(state.activity, AgentActivity::Idle);
    }

    #[test]
    fn test_derive_agent_state_working_with_tool_calls_finish() {
        // Completed message with finish=tool-calls indicates still working
        let messages = vec![serde_json::json!({
            "info": {
                "role": "assistant",
                "time": {"created": 1234567890, "completed": 1234567891},
                "finish": "tool-calls"
            },
            "parts": [{"type": "text", "text": "Making tool call..."}]
        })];
        let state = derive_agent_state_from_messages(&messages);
        assert_eq!(state.activity, AgentActivity::Working);
    }

    #[test]
    fn test_derive_agent_state_working_with_incomplete_tool() {
        // Message with tool part that's not completed
        let messages = vec![serde_json::json!({
            "info": {
                "role": "assistant",
                "time": {"created": 1234567890, "completed": 1234567891}
            },
            "parts": [
                {"type": "text", "text": "Running a tool..."},
                {"type": "tool", "name": "bash", "state": {"status": "running"}}
            ]
        })];
        let state = derive_agent_state_from_messages(&messages);
        assert_eq!(state.activity, AgentActivity::Working);
        assert_eq!(state.current_tool, Some("bash".to_string()));
    }

    #[test]
    fn test_derive_agent_state_idle_with_completed_tool() {
        // Message with completed tool part
        let messages = vec![serde_json::json!({
            "info": {
                "role": "assistant",
                "time": {"created": 1234567890, "completed": 1234567891}
            },
            "parts": [
                {"type": "text", "text": "Tool result..."},
                {"type": "tool", "state": {"status": "completed"}}
            ]
        })];
        let state = derive_agent_state_from_messages(&messages);
        assert_eq!(state.activity, AgentActivity::Idle);
    }

    #[test]
    fn test_extract_text_from_parts() {
        let parts = vec![
            serde_json::json!({"type": "text", "text": "Hello world\nSecond line"}),
            serde_json::json!({"type": "tool", "name": "bash", "state": {"status": "running"}}),
        ];
        let lines = extract_text_from_parts(&parts, 3);
        assert!(!lines.is_empty());
    }
}
