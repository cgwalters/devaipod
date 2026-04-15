//! devaipod - Sandboxed AI coding agents in reproducible dev environments
//!
//! This tool uses DevPod for container provisioning and adds AI agent sandboxing.

#![forbid(unsafe_code)]

use std::io::IsTerminal;
use std::path::{Path, PathBuf};
use std::process::Command as ProcessCommand;

use clap::{Args, CommandFactory, Parser};
use color_eyre::eyre::{Context, Result, bail};

mod acp_client;
mod advisor;
mod agent;
mod agent_acp;
mod agent_dir;
mod config;
mod devcontainer;
mod forge;
mod git;
#[allow(dead_code)] // Preparatory infrastructure for GPU passthrough
mod gpu;
mod init;
mod mcp;
mod pod;
mod pod_api;
mod podman;
mod prompt;
mod review_tui;
mod secrets;
mod service_gator;
mod ssh_server;
mod tui;
mod web;

/// Returns `true` if the session JSON object represents a root session
/// (i.e. not a subagent session). Subagent sessions have a non-null `parentID`.
pub(crate) fn session_is_root(s: &serde_json::Value) -> bool {
    matches!(s.get("parentID"), None | Some(serde_json::Value::Null))
}

/// Prefix for all devaipod pod names
const POD_NAME_PREFIX: &str = "devaipod-";

/// Environment variable name for the instance identifier.
///
/// When set, this value is stored as a label (`io.devaipod.instance`) on every
/// pod created by this process, and all listing/filtering operations will only
/// show pods whose label matches. This allows multiple independent devaipod
/// sessions (e.g. integration tests vs. interactive use) to coexist without
/// interfering with each other.
pub(crate) const DEVAIPOD_INSTANCE_ENV: &str = "DEVAIPOD_INSTANCE";

/// Pod/container label key used to record the instance identifier.
pub(crate) const INSTANCE_LABEL_KEY: &str = "io.devaipod.instance";

/// Return the current instance identifier, if any.
pub(crate) fn get_instance_id() -> Option<String> {
    std::env::var(DEVAIPOD_INSTANCE_ENV)
        .ok()
        .filter(|s| !s.is_empty())
}

/// Normalize a workspace name to a full pod name by adding the prefix
///
/// The user-facing "short name" is what's shown by `devaipod list` and suggested
/// after `devaipod up` (the pod name with the prefix stripped). This function
/// adds the prefix to convert back to the full pod name, but is idempotent -
/// if the name already has the prefix, it won't be added again.
fn normalize_pod_name(name: &str) -> String {
    if name.starts_with(POD_NAME_PREFIX) {
        // The input already has the prefix. It might be the full pod name
        // (e.g. "devaipod-myproject-abc"), or it might be a stripped display
        // name for a project whose name itself starts with "devaipod"
        // (e.g. "devaipod-abc" from pod "devaipod-devaipod-abc").
        // Try the name as-is first; if the pod doesn't exist, try adding
        // the prefix again.
        if !pod_exists(name).unwrap_or(true) {
            let with_prefix = format!("{}{}", POD_NAME_PREFIX, name);
            if pod_exists(&with_prefix).unwrap_or(false) {
                return with_prefix;
            }
        }
        name.to_string()
    } else {
        format!("{}{}", POD_NAME_PREFIX, name)
    }
}

/// Strip the prefix from a pod name for display
fn strip_pod_prefix(name: &str) -> &str {
    name.strip_prefix(POD_NAME_PREFIX).unwrap_or(name)
}

/// Target container for the attach command.
///
/// Devaipod pods contain multiple containers with different roles. This enum
/// specifies which container to attach to when using `devaipod attach`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AttachTarget {
    /// The workspace container where the user's development environment runs.
    /// Use `-W` flag to attach to this container for direct access to your
    /// development environment without AI interaction.
    Workspace,
    /// The task owner agent container. This is the primary AI agent that
    /// orchestrates work and delegates to the worker. This is the default target.
    Agent,
    /// The worker container where the worker agent runs. The worker receives
    /// delegated tasks from the task owner and makes commits for review.
    Worker,
}

/// Get the container name for a given pod and attach target.
///
/// Returns the full container name that can be used with `podman exec`.
fn get_attach_container_name(pod_name: &str, target: AttachTarget) -> String {
    match target {
        AttachTarget::Workspace => format!("{}-workspace", pod_name),
        AttachTarget::Agent => format!("{}-agent", pod_name),
        AttachTarget::Worker => format!("{}-worker", pod_name),
    }
}

/// Resolve a workspace name, handling the --latest flag
///
/// If a workspace name is provided, normalizes it. If --latest is set (or no
/// workspace is given and `latest` is true — the default for diff/fetch/etc.),
/// first tries to scope to workspaces for the current git repo. When multiple
/// workspaces exist for the same repo, shows an interactive chooser on TTYs or
/// picks the most recent one on non-TTYs.
fn resolve_workspace(workspace: Option<&str>, latest: bool) -> Result<String> {
    match (workspace, latest) {
        (Some(name), false) => Ok(normalize_pod_name(name)),
        (None, true) | (Some(_), true) => {
            // If we're inside a git repo, try to scope to workspaces for it
            if let Ok(repo_root) = repo_root_path() {
                let workspaces = find_workspaces_for_repo(&repo_root);
                match workspaces.len() {
                    0 => {
                        // No workspaces for this repo; fall through to global latest
                    }
                    1 => {
                        let ws = &workspaces[0];
                        tracing::info!("Using workspace for this repo: {}", ws.short_name);
                        return Ok(ws.pod_name.clone());
                    }
                    _ => {
                        return resolve_workspace_interactive(&workspaces);
                    }
                }
            }

            // Fall back to globally latest workspace
            let pod_name = get_latest_workspace()?;
            tracing::info!("Using latest workspace: {}", strip_pod_prefix(&pod_name));
            Ok(pod_name)
        }
        (None, false) => {
            bail!(
                "No workspace specified. Use a workspace name or --latest (-l) for the most recent."
            );
        }
    }
}

/// Present an interactive chooser when multiple workspaces match the current repo.
///
/// On non-TTY stdin (e.g. piped), automatically picks the most recent workspace
/// and prints a hint about specifying a name explicitly.
fn resolve_workspace_interactive(workspaces: &[RepoWorkspaceInfo]) -> Result<String> {
    // Build display labels for each workspace
    let labels: Vec<String> = workspaces
        .iter()
        .map(|ws| {
            let commits = if ws.commit_count == 1 {
                "1 commit".to_string()
            } else {
                format!("{} commits", ws.commit_count)
            };
            let task = ws
                .task_summary
                .as_deref()
                .map(|t| format!("  \"{}\"", t))
                .unwrap_or_default();
            format!(
                "{:<10} {:<12} {:<14}{}",
                ws.short_name, commits, ws.age_display, task
            )
        })
        .collect();

    if !std::io::stdin().is_terminal() {
        // Non-interactive: pick the first (most recent, since list_workspaces
        // sorts newest-first) and print a hint.
        let ws = &workspaces[0];
        let commits = if ws.commit_count == 1 {
            "1 commit".to_string()
        } else {
            format!("{} commits", ws.commit_count)
        };
        eprintln!(
            "Using most recent workspace: {} ({}, {})",
            ws.short_name, commits, ws.age_display
        );
        eprintln!(
            "Tip: specify a workspace name to choose: devaipod diff {}",
            if workspaces.len() > 1 {
                &workspaces[1].short_name
            } else {
                &ws.short_name
            }
        );
        return Ok(ws.pod_name.clone());
    }

    let selection = dialoguer::Select::new()
        .with_prompt("Multiple agents have worked on this repo. Select one")
        .items(&labels)
        .default(0)
        .interact()
        .context("Failed to show workspace chooser")?;

    Ok(workspaces[selection].pod_name.clone())
}

/// Get the most recently created devaipod workspace
fn get_latest_workspace() -> Result<String> {
    let name_filter = format!("name={}*", POD_NAME_PREFIX);
    let mut args = vec!["pod", "ps", "--filter", &name_filter];

    // Narrow results by instance label when set
    let label_filter;
    if let Some(instance_id) = get_instance_id() {
        label_filter = format!("label={INSTANCE_LABEL_KEY}={instance_id}");
        args.extend(["--filter", &label_filter]);
    }
    args.push("--format=json");

    let output = podman_command()
        .args(&args)
        .output()
        .context("Failed to run podman pod ps")?;

    if !output.status.success() {
        bail!("Failed to list workspaces");
    }

    let pods: Vec<serde_json::Value> =
        serde_json::from_slice(&output.stdout).context("Failed to parse pod list")?;

    // When no instance is set, filter out pods that carry an instance label
    let pods: Vec<&serde_json::Value> = if get_instance_id().is_none() {
        pods.iter()
            .filter(|pod| {
                let name = pod.get("Name").and_then(|v| v.as_str()).unwrap_or("");
                let labels = get_pod_labels(name);
                pod_labels_match_instance(labels.as_ref())
            })
            .collect()
    } else {
        pods.iter().collect()
    };

    if pods.is_empty() {
        bail!("No devaipod workspaces found. Create one with 'devaipod up' or 'devaipod run'.");
    }

    // Pods are returned in creation order (newest last), so take the last one
    // Actually podman returns them in reverse order (newest first), so take first
    let latest = pods
        .first()
        .and_then(|p| p.get("Name"))
        .and_then(|n| n.as_str())
        .ok_or_else(|| color_eyre::eyre::eyre!("Failed to get workspace name"))?;

    Ok(latest.to_string())
}

/// If `source` matches a configured source shorthand (e.g. `src:github/org/repo`),
/// resolve it to a full container path. Otherwise return the source unchanged.
fn maybe_resolve_shorthand(source: Option<&str>, config: &config::Config) -> Option<String> {
    source.map(|s| {
        if let Some(resolved) = config::resolve_source_shorthand(s, config) {
            let resolved_str = resolved.to_string_lossy().to_string();
            tracing::info!("Resolved source shorthand '{}' -> {}", s, resolved_str);
            resolved_str
        } else {
            s.to_string()
        }
    })
}

/// Resolve the source for a workspace, using journal or dotfiles as fallback
///
/// If source is provided, returns it. Otherwise, falls back to the journal
/// repo (if configured), then the dotfiles URL, or returns an error.
fn resolve_source<'a>(source: Option<&'a str>, config: &'a config::Config) -> Option<&'a str> {
    if let Some(s) = source {
        return Some(s);
    }

    // If CWD is inside a git repo, default to "." (the current repo)
    if repo_root_path().is_ok() {
        tracing::info!("No source specified, using current git repo");
        return Some(".");
    }

    // Fall back to journal repo if configured
    if let Some(ref repo) = config.journal.repo {
        tracing::info!("No source specified, using journal repo: {}", repo);
        return Some(repo.as_str());
    }

    if let Some(ref dotfiles) = config.dotfiles {
        return Some(dotfiles.url.as_str());
    }

    None
}

/// Sanitize a name for use in pod names (alphanumeric and hyphens only)
///
/// Also strips leading hyphens to avoid generating names that look like
/// command-line options (e.g., `-foo` would break `devaipod attach -foo`).
pub(crate) fn sanitize_name(name: &str) -> String {
    name.chars()
        .map(|c| {
            if c.is_alphanumeric() || c == '-' {
                c
            } else {
                '-'
            }
        })
        .collect::<String>()
        .trim_start_matches('-')
        .to_string()
}

/// Generate a short unique suffix for pod names
pub(crate) fn unique_suffix() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    // Use lower 24 bits of timestamp in seconds + some randomness from nanos
    // This gives us a short but reasonably unique suffix
    let val = (now.as_secs() & 0xFFFFFF) ^ ((now.subsec_nanos() as u64) & 0xFFFF);
    format!("{:x}", val)
}

/// Create a pod name from a project name
///
/// Always generates a unique name to avoid conflicts with existing pods.
pub(crate) fn make_pod_name(project_name: &str) -> String {
    format!(
        "{}{}-{}",
        POD_NAME_PREFIX,
        sanitize_name(project_name),
        unique_suffix()
    )
}

/// Create a pod name for a PR
///
/// Always generates a unique name to avoid conflicts with existing pods.
fn make_pr_pod_name(repo: &str, pr_number: u64) -> String {
    format!(
        "{}{}-pr{}-{}",
        POD_NAME_PREFIX,
        sanitize_name(repo),
        pr_number,
        unique_suffix()
    )
}

// =============================================================================
// Host CLI - commands that run on the host machine (outside devcontainer)
// =============================================================================

#[derive(Debug, Parser)]
#[command(name = "devaipod-server")]
#[command(about = "Sandboxed AI coding agents in reproducible dev environments")]
#[command(after_help = "\
QUICK START:
  devaipod run <url> 'fix the bug'            Create workspace and start agent
  devaipod attach -l                          Attach to most recent workspace

WORKSPACE LIFECYCLE:
  up, run                                     Create workspaces
  list, tui, status                           View workspaces
  start, stop, delete                         Manage lifecycle
  done, prune, cleanup                        Mark complete and clean up
  rebuild, title                              Reconfigure workspaces

AGENT INTERACTION:
  attach, exec                                Connect to workspace
  logs, debug                                 Inspect workspace
  advisor                                     Launch advisor agent

GIT & CODE REVIEW:
  fetch, diff, review                         Review agent changes
  apply, push, pr                             Integrate agent work

ADVANCED (use '<command> --help' for details):
  opencode, gator, controlplane (cp)          Programmatic / service APIs
  web, ssh-config, completions, init          Infrastructure & setup

DOCS: https://github.com/cgwalters/devaipod")]
struct HostCli {
    /// Path to config file (default: ~/.config/devaipod.toml)
    #[arg(long, global = true, value_name = "PATH")]
    config: Option<PathBuf>,

    /// Enable verbose output (debug logging)
    #[arg(short, long, global = true)]
    verbose: bool,

    /// Quiet mode (only show warnings and errors)
    #[arg(short, long, global = true)]
    quiet: bool,

    /// Allow running on the host instead of inside the devaipod container
    ///
    /// By default, devaipod requires running inside the official devaipod container
    /// for proper isolation. Use this flag (or set DEVAIPOD_HOST_MODE=1) to run
    /// directly on the host system.
    #[arg(long, global = true)]
    host: bool,

    #[command(subcommand)]
    command: HostCommand,
}

/// Mode of workspace creation (run vs up)
#[derive(Debug, Clone, Copy, Default)]
enum WorkspaceMode {
    /// Created with 'devaipod up' - interactive/manual control
    #[default]
    Up,
    /// Created with 'devaipod run' - automated task execution
    Run,
}

impl WorkspaceMode {
    fn as_str(&self) -> &'static str {
        match self {
            WorkspaceMode::Up => "up",
            WorkspaceMode::Run => "run",
        }
    }
}

/// Common CLI options for workspace creation commands
#[derive(Debug, Args)]
struct UpOptions {
    /// Task description for the AI agent (also stored as workspace description)
    #[arg(value_name = "TASK")]
    task: Option<String>,
    /// Human-readable title for this session (e.g. "refactoring auth")
    #[arg(long, value_name = "TITLE")]
    title: Option<String>,
    /// Store task description but don't send it to the agent as a prompt
    #[arg(short = 'n', long)]
    no_prompt: bool,
    /// Generate configuration files but don't start containers
    #[arg(long)]
    dry_run: bool,
    /// Exec into agent container after starting
    #[arg(short = 'S', long = "exec")]
    exec_after: bool,
    /// Internal: mode of workspace creation (not exposed as CLI arg)
    #[arg(skip)]
    mode: WorkspaceMode,
    /// Use a specific container image instead of building from devcontainer.json
    ///
    /// This allows working with git repositories that have no devcontainer.json.
    /// The image must already exist locally or be pullable.
    #[arg(long, value_name = "IMAGE")]
    image: Option<String>,
    /// Explicit pod name (default: derived from source with unique suffix)
    ///
    /// Use this for predictable pod names, e.g. in CI/CD or testing.
    /// The devaipod- prefix will be added automatically if not present.
    #[arg(long, value_name = "NAME")]
    name: Option<String>,
    /// Configure service-gator scopes for AI agent access to external services.
    ///
    /// Format: service:scope where service is github, gitlab, jira, etc.
    /// Can be specified multiple times.
    ///
    /// Examples:
    ///   --service-gator=github:readonly-all       # Read-only access to all GitHub repos
    ///   --service-gator=github:myorg/myrepo       # Read access to specific repo
    ///   --service-gator=github:myorg/*            # Read access to all repos in org
    ///   --service-gator=github:myorg/repo:write   # Write access to specific repo
    #[arg(long = "service-gator", value_name = "SCOPE")]
    service_gator_scopes: Vec<String>,
    /// Use a specific image for the service-gator container.
    ///
    /// This allows testing locally-built service-gator images instead of
    /// pulling from ghcr.io/cgwalters/service-gator:latest.
    ///
    /// Example:
    ///   --service-gator-image localhost/service-gator:dev
    #[arg(long, value_name = "IMAGE")]
    service_gator_image: Option<String>,
    /// Additional MCP servers to attach to the agent (name=url format)
    ///
    /// Can be specified multiple times. These are added to any servers
    /// configured in the [mcp] section of the config file.
    ///
    /// Example: --mcp advisor=http://localhost:8766/mcp
    #[arg(long = "mcp", value_name = "NAME=URL")]
    mcp_servers: Vec<String>,
    /// Use this devcontainer JSON instead of the repo's devcontainer.json
    ///
    /// Accepts a full devcontainer.json as an inline JSONC string. This completely
    /// replaces any devcontainer.json found in the repository.
    ///
    /// Example: --devcontainer-json '{"image": "debian", "capAdd": ["SYS_ADMIN"]}'
    #[arg(long, value_name = "JSON")]
    devcontainer_json: Option<String>,
    /// Use the devcontainer.json from your dotfiles repo instead of the project's.
    ///
    /// When set, any devcontainer.json in the target repository is ignored and the
    /// one from the dotfiles repository (configured in [dotfiles] in devaipod.toml)
    /// is used instead. This is useful for ensuring your personal environment
    /// settings (nested containers, lifecycle commands, etc.) always apply.
    #[arg(long)]
    use_default_devcontainer: bool,
    /// Additional source directories to mount read-only in the agent container.
    ///
    /// Each directory is bind-mounted at /mnt/source/<dirname>/ (read-only).
    /// Can be specified multiple times.
    /// If the directory is a git repository, it will be automatically cloned
    /// into the agent workspace for convenience.
    ///
    /// Examples:
    ///   --source-dir ~/src/api --source-dir ~/docs
    ///   --source-dir .   # Current directory as read-only source
    #[arg(long = "source-dir", value_name = "DIR")]
    source_dirs: Vec<PathBuf>,
}

/// Internal options for workspace creation (like `podman create` vs `podman run`)
///
/// This struct captures all the options needed to create a workspace pod without
/// starting it or performing post-setup actions like SSH. It's used by the common
/// `create_workspace` function that both `up` and `run` commands call.
#[derive(Debug, Clone)]
struct CreateOptions {
    /// Task description for the AI agent
    task: Option<String>,
    /// Human-readable title for this session
    title: Option<String>,
    /// Use a specific container image instead of building from devcontainer.json
    image: Option<String>,
    /// Explicit pod name (default: derived from source with unique suffix)
    name: Option<String>,
    /// Service-gator scopes for AI agent access to external services
    service_gator_scopes: Vec<String>,
    /// Custom service-gator container image
    service_gator_image: Option<String>,
    /// Mode of workspace creation (up vs run)
    mode: WorkspaceMode,
    /// Make service-gator read-only (no push, no draft PRs)
    service_gator_ro: bool,
    /// Additional MCP servers (name=url format)
    mcp_servers: Vec<String>,
    /// Inline devcontainer JSON that replaces the repo's devcontainer.json
    devcontainer_json: Option<String>,
    /// Use the devcontainer.json from dotfiles instead of the project's
    use_default_devcontainer: bool,
    /// Additional source directories to mount read-only
    source_dirs: Vec<PathBuf>,
}

impl CreateOptions {
    /// Build CreateOptions from UpOptions
    fn from_up_options(opts: &UpOptions) -> Self {
        Self {
            task: opts.task.clone(),
            title: opts.title.clone(),
            image: opts.image.clone(),
            name: opts.name.clone(),
            service_gator_scopes: opts.service_gator_scopes.clone(),
            service_gator_image: opts.service_gator_image.clone(),
            mode: opts.mode,
            // UpOptions doesn't have service_gator_ro, it's only for `run`
            service_gator_ro: false,
            mcp_servers: opts.mcp_servers.clone(),
            devcontainer_json: opts.devcontainer_json.clone(),
            use_default_devcontainer: opts.use_default_devcontainer,
            source_dirs: opts.source_dirs.clone(),
        }
    }
}

/// Create an [`AgentBackend`] from the resolved agent name and optional profile.
///
/// If a profile is provided, uses AcpBackend with the profile's command.
/// Otherwise, uses ACP backend with default command `["opencode", "acp"]`.
///
/// The `agent_config` parameter is used to extract candidate binaries for
/// auto-detection in the startup script.
fn create_agent_backend(
    _name: &str,
    profile: Option<&crate::config::AgentProfile>,
    agent_config: &crate::config::AgentConfig,
) -> color_eyre::Result<Box<dyn crate::agent::AgentBackend>> {
    let candidate_binaries: Vec<String> = agent_config
        .candidate_binaries()
        .into_iter()
        .map(|s| s.to_string())
        .collect();

    if let Some(profile) = profile {
        return Ok(Box::new(crate::agent_acp::AcpBackend::new_with_candidates(
            profile.command.clone(),
            candidate_binaries,
        )));
    }

    // No profile — use ACP backend with default opencode command
    Ok(Box::new(crate::agent_acp::AcpBackend::new_with_candidates(
        vec!["opencode".to_string(), "acp".to_string()],
        if candidate_binaries.is_empty() {
            vec!["opencode".to_string()]
        } else {
            candidate_binaries
        },
    )))
}

#[derive(Debug, Parser)]
enum HostCommand {
    /// Create/start a workspace with AI agent
    ///
    /// Creates a podman pod with workspace and agent containers. The agent runs
    /// opencode in server mode and can be given tasks to work on.
    ///
    /// For remote URLs (GitHub repos/PRs), service-gator is automatically enabled
    /// with read + draft PR permissions for that repository.
    ///
    /// If no source is specified, falls back to the journal repo (if configured),
    /// then the dotfiles repository from config.
    ///
    /// Examples:
    ///   devaipod up                                        # Use journal/dotfiles repo
    ///   devaipod up .                                      # Local repo
    ///   devaipod up . -S                                   # Local repo, SSH in after
    ///   devaipod up https://github.com/user/repo           # Remote repo
    ///   devaipod up https://github.com/user/repo/pull/123  # PR
    ///   devaipod up . 'fix the bug'                        # With task for agent
    ///   devaipod up . --service-gator=github:myorg/*       # Custom permissions
    Up {
        /// Source: local path, git URL, or PR URL (default: journal or dotfiles repo from config)
        source: Option<String>,
        #[command(flatten)]
        opts: UpOptions,
    },

    /// Attach to the AI agent in a workspace
    ///
    /// Opens a tmux session with two panes:
    /// - Left pane: AI agent (opencode attach)
    /// - Right pane: Shell for manual work
    ///
    /// By default, attaches to the agent container where the AI runs. Use -W to
    /// attach to the workspace container for direct access to your development
    /// environment without AI interaction.
    ///
    /// This is the primary way to interact with a workspace. Use tmux keys
    /// (Ctrl-b + arrow keys) to switch panes, or Ctrl-b d to detach.
    ///
    /// Examples:
    ///   devaipod attach myworkspace              # Attach to agent (default)
    ///   devaipod attach -l                       # Attach to most recent workspace
    ///   devaipod attach myworkspace -W           # Attach to workspace container
    ///   devaipod attach myworkspace --worker     # Attach to worker agent
    ///   devaipod attach myworkspace -s abc123    # Connect to specific session
    Attach {
        /// Workspace name (devaipod- prefix optional)
        #[arg(allow_hyphen_values = true)]
        workspace: Option<String>,
        /// Attach to the most recently created workspace
        #[arg(short = 'l', long)]
        latest: bool,
        /// Session ID to attach to (default: auto-detect existing session)
        #[arg(short, long)]
        session: Option<String>,
        /// Attach to the workspace container instead of the agent
        ///
        /// By default, devaipod attach connects to the task owner agent.
        /// Use this flag to access the workspace container for direct access
        /// to your development environment without AI interaction.
        #[arg(short = 'W', long)]
        workspace_mode: bool,
        /// Attach to the worker agent instead of the task owner
        ///
        /// Use this flag to connect to the worker agent that receives delegated
        /// tasks from the task owner.
        #[arg(long)]
        worker: bool,
    },
    /// Execute a shell in a container
    ///
    /// Opens an interactive shell in the task owner agent container by default.
    /// Use -W for workspace or --worker for worker agent.
    ///
    /// Examples:
    ///   devaipod exec myworkspace           # Shell in task owner agent (default)
    ///   devaipod exec myworkspace -W        # Shell in workspace container
    ///   devaipod exec myworkspace --worker  # Shell in worker agent
    ///   devaipod exec myworkspace -- ls -la # Run a specific command
    Exec {
        /// Workspace name (devaipod- prefix optional)
        #[arg(allow_hyphen_values = true)]
        workspace: String,
        /// Exec into the workspace container instead of the agent
        ///
        /// By default, devaipod exec enters the task owner agent container.
        /// Use this flag to access the workspace container for manual
        /// development work or to review/pull agent changes.
        #[arg(short = 'W', long = "workspace")]
        workspace_mode: bool,
        /// Exec into the worker agent instead of the task owner
        ///
        /// Use this flag to access the worker agent's container that receives
        /// delegated tasks from the task owner.
        #[arg(long)]
        worker: bool,
        /// Stdio mode: pipe stdin/stdout for ProxyCommand use (VSCode/Zed remote dev)
        #[arg(long, hide = true)]
        stdio: bool,
        /// Command to run (default: bash)
        #[arg(trailing_var_arg = true)]
        command: Vec<String>,
    },
    /// Generate SSH config entry for a workspace
    ///
    /// Outputs an SSH config block that can be added to ~/.ssh/config.
    /// This enables VSCode/Zed Remote SSH to connect via ProxyCommand.
    ///
    /// Example:
    ///   devaipod ssh-config my-repo >> ~/.ssh/config
    #[command(hide = true)]
    SshConfig {
        /// Workspace name (devaipod- prefix optional)
        #[arg(allow_hyphen_values = true)]
        workspace: String,
        /// User to connect as (default: current user)
        #[arg(long)]
        user: Option<String>,
    },
    /// Clean up stale resources
    ///
    /// Runs various cleanup tasks:
    /// - Removes orphaned SSH config entries for deleted pods
    /// - (Future: other cleanup tasks)
    ///
    /// This is run automatically on `devaipod delete`, but can be run
    /// manually to clean up after crashes or external pod deletions.
    #[command(hide = true)]
    Cleanup {
        /// Dry run - show what would be cleaned without doing it
        #[arg(long, short = 'n')]
        dry_run: bool,
    },
    /// List workspaces
    ///
    /// When run from a git repository, only workspaces for the current repo
    /// are shown. Use -A to show all workspaces. Inactive (stopped/exited)
    /// pods are hidden by default; use --inactive to include them.
    List {
        /// Output in JSON format
        #[arg(long)]
        json: bool,
        /// Show all workspaces (default: filter to current repo)
        #[arg(short = 'A', long)]
        all: bool,
        /// Include inactive (stopped/exited) workspaces
        #[arg(long)]
        inactive: bool,
    },
    /// Interactive TUI dashboard
    ///
    /// Opens a terminal UI for managing devaipod instances. Shows real-time
    /// status of all instances with agent health, tasks, and repository info.
    ///
    /// When run from a git repository, only workspaces for the current repo
    /// are shown. Use -A to show all workspaces.
    ///
    /// Instances are grouped by repository. Inactive (stopped/exited) pods
    /// are hidden by default; press 'i' to toggle.
    ///
    /// Keybindings:
    ///   j/k or arrows: Navigate
    ///   i: Toggle inactive pods
    ///   r: Refresh
    ///   q: Quit
    Tui {
        /// Show all workspaces (default: filter to current repo)
        #[arg(short = 'A', long)]
        all: bool,
    },
    /// Start a stopped workspace
    ///
    /// Starts a previously stopped pod (restarts all containers).
    /// Use 'devaipod list' to see available workspaces.
    Start {
        /// Workspace name (devaipod- prefix optional)
        #[arg(allow_hyphen_values = true)]
        workspace: String,
    },
    /// Stop a workspace
    Stop {
        /// Workspace name (devaipod- prefix optional)
        #[arg(allow_hyphen_values = true)]
        workspace: String,
    },
    /// Delete a workspace
    Delete {
        /// Workspace name (devaipod- prefix optional)
        #[arg(allow_hyphen_values = true)]
        workspace: String,
        /// Force deletion (stop running containers first)
        #[arg(short, long)]
        force: bool,
    },
    /// Mark a workspace as done
    ///
    /// Labels a workspace as completed. Done workspaces can be cleaned up
    /// in bulk with 'devaipod prune'.
    ///
    /// Examples:
    ///   devaipod done myworkspace
    ///   devaipod done myworkspace --undo    # Mark as incomplete again
    Done {
        /// Workspace name (devaipod- prefix optional)
        #[arg(allow_hyphen_values = true)]
        workspace: String,
        /// Mark as incomplete (undo a previous done)
        #[arg(long)]
        undo: bool,
    },
    /// Remove all workspaces marked as done
    ///
    /// Deletes all pods that have been marked as "done" with 'devaipod done'.
    /// This is a bulk cleanup operation.
    ///
    /// Examples:
    ///   devaipod prune
    Prune,
    /// Rebuild a workspace with a new image
    ///
    /// Recreates the containers with a new or updated image while preserving
    /// the workspace volume (your code and changes). This is useful when:
    /// - The devcontainer.json has changed
    /// - You want to use a newer version of the dev image
    /// - You need to apply configuration changes
    ///
    /// By default, runs postStartCommand after rebuild. Use --run-create to also
    /// run onCreateCommand and postCreateCommand.
    ///
    /// Examples:
    ///   devaipod rebuild my-workspace
    ///   devaipod rebuild my-workspace --image ghcr.io/org/devenv:latest
    Rebuild {
        /// Workspace name (devaipod- prefix optional)
        #[arg(allow_hyphen_values = true)]
        workspace: String,
        /// Use a specific container image instead of rebuilding from devcontainer.json
        #[arg(long, value_name = "IMAGE")]
        image: Option<String>,
        /// Also run onCreateCommand and postCreateCommand (default: only postStartCommand)
        #[arg(long)]
        run_create: bool,
    },
    /// View container logs
    Logs {
        /// Workspace name (devaipod- prefix optional)
        #[arg(allow_hyphen_values = true)]
        workspace: String,
        /// Which container to show logs for (workspace, agent, gator, proxy)
        #[arg(short, long, default_value = "agent")]
        container: String,
        /// Follow log output
        #[arg(short, long)]
        follow: bool,
        /// Number of lines to show from the end
        #[arg(short = 'n', long)]
        tail: Option<u32>,
    },
    /// Show status of agent workspaces, branches, and PRs
    ///
    /// When run from a git repository with no arguments, displays a
    /// comprehensive overview of all agent work related to the current
    /// repository: workspace status, harvested branches, push status,
    /// and associated pull requests.
    ///
    /// When a workspace name is given, displays detailed pod status
    /// including container states, agent health, and exposed ports.
    ///
    /// Examples:
    ///   devaipod status                          # Repo overview (from a git repo)
    ///   devaipod status myworkspace              # Pod-level status
    Status {
        /// Workspace name (devaipod- prefix optional). Omit for repo overview.
        #[arg(allow_hyphen_values = true)]
        workspace: Option<String>,
        /// Output in JSON format
        #[arg(long)]
        json: bool,
        /// Show all workspaces (default: filter to current repo)
        #[arg(short = 'A', long)]
        all: bool,
    },
    /// Debug and diagnose a workspace
    ///
    /// Collects diagnostic information to help troubleshoot issues with
    /// the pod, service-gator, MCP connectivity, and agent health.
    ///
    /// Examples:
    ///   devaipod debug my-workspace
    ///   devaipod debug my-workspace --json
    Debug {
        /// Workspace name (devaipod- prefix optional)
        #[arg(allow_hyphen_values = true)]
        workspace: String,
        /// Output in JSON format for scripting
        #[arg(long)]
        json: bool,
    },
    /// Run an agent on a repository with a task
    ///
    /// Creates a workspace and starts the agent with a task. Returns immediately
    /// after setup (async by default). Use 'devaipod attach <workspace>' to monitor
    /// the agent's progress.
    ///
    /// For issue URLs, the source repo is extracted and the default task is
    /// "Fix <issue_url>". If no task is provided and stdin is a TTY, prompts
    /// interactively with the default pre-filled.
    ///
    /// If no source is specified, falls back to the journal repo (if configured),
    /// then the dotfiles repository from config.
    ///
    /// Examples:
    ///   devaipod run                                         # Use journal/dotfiles repo
    ///   devaipod run https://github.com/org/repo
    ///   devaipod run https://github.com/org/repo 'fix typos in README.md'
    ///   devaipod run https://github.com/org/repo/issues/123  # Default: "Fix <url>"
    ///   devaipod run . 'add unit tests for the parser module'
    Run {
        /// Source: local path, git URL, issue URL, or PR URL (default: journal or dotfiles repo from config)
        source: Option<String>,
        /// Task description for the AI agent
        #[arg(value_name = "TASK")]
        task: Option<String>,
        /// Task for the agent (alternative to positional argument)
        #[arg(short = 'c', long = "command", value_name = "TASK")]
        command: Option<String>,
        /// Attach to the agent after starting
        #[arg(short = 'A', long = "attach")]
        attach: bool,
        /// Use a specific container image instead of building from devcontainer.json
        #[arg(long, value_name = "IMAGE")]
        image: Option<String>,
        /// Explicit pod name (default: derived from source with unique suffix)
        #[arg(long, value_name = "NAME")]
        name: Option<String>,
        /// Configure service-gator scopes for AI agent access to external services
        #[arg(long = "service-gator", value_name = "SCOPE")]
        service_gator_scopes: Vec<String>,
        /// Use a specific image for the service-gator container
        #[arg(long, value_name = "IMAGE")]
        service_gator_image: Option<String>,
        /// Suppress any default write service-gator scopes provided to the agent
        ///
        /// When set, the agent will only have read access to repositories -
        /// no push-new-branch or create-draft permissions will be granted.
        #[arg(short = 'R', long = "service-gator-ro")]
        service_gator_ro: bool,
        /// Additional MCP servers to attach to the agent (name=url format)
        ///
        /// Can be specified multiple times. These are added to any servers
        /// configured in the [mcp] section of the config file.
        ///
        /// Example: --mcp advisor=http://localhost:8766/mcp
        #[arg(long = "mcp", value_name = "NAME=URL")]
        mcp_servers: Vec<String>,
        /// Use this devcontainer JSON instead of the repo's devcontainer.json
        ///
        /// Accepts a full devcontainer.json as an inline JSONC string. This completely
        /// replaces any devcontainer.json found in the repository.
        ///
        /// Example: --devcontainer-json '{"image": "debian", "capAdd": ["SYS_ADMIN"]}'
        #[arg(long, value_name = "JSON")]
        devcontainer_json: Option<String>,
        /// Use the devcontainer.json from your dotfiles repo instead of the project's
        #[arg(long)]
        use_default_devcontainer: bool,
        /// Human-readable title for this session (e.g. "refactoring auth")
        #[arg(long, value_name = "TITLE")]
        title: Option<String>,
        /// Additional source directories to mount read-only in the agent container
        #[arg(long = "source-dir", value_name = "DIR")]
        source_dirs: Vec<PathBuf>,
    },
    /// Generate shell completions
    ///
    /// Outputs shell completion scripts to stdout for various shells.
    ///
    /// Examples:
    ///   devaipod completions bash > ~/.local/share/bash-completion/completions/devaipod
    ///   devaipod completions zsh > ~/.zfunc/_devaipod
    ///   devaipod completions fish > ~/.config/fish/completions/devaipod.fish
    #[command(hide = true)]
    Completions {
        /// Shell to generate completions for
        #[arg(value_enum)]
        shell: clap_complete::Shell,
    },
    /// Initialize devaipod configuration
    ///
    /// Interactive setup wizard for first-time users. Configures:
    /// - Dotfiles/homegit repository
    /// - Forge tokens (GitHub, GitLab, Forgejo) via podman secrets
    /// - OpenCode configuration recommendations
    ///
    /// Examples:
    ///   devaipod init
    ///   devaipod init --config ~/.config/devaipod-test.toml
    Init {
        /// Path to write config file (default: ~/.config/devaipod.toml)
        #[arg(long, value_name = "PATH")]
        config: Option<PathBuf>,
    },
    /// Interact with the opencode agent programmatically
    ///
    /// Provides CLI access to the opencode server API for scripting and automation.
    /// Commands are executed by connecting to the agent container's API.
    ///
    /// Examples:
    ///   devaipod opencode myworkspace mcp list          # List MCP servers
    ///   devaipod opencode myworkspace mcp tools         # List available tools
    ///   devaipod opencode myworkspace session list      # List sessions
    ///   devaipod opencode myworkspace send "fix bug"    # Send message to agent
    #[command(hide = true)]
    Opencode {
        /// Workspace name (devaipod- prefix optional)
        #[arg(allow_hyphen_values = true)]
        workspace: String,
        #[command(subcommand)]
        action: OpencodeAction,
    },
    /// Control plane for managing and reviewing agent workspaces
    ///
    /// Provides a unified view of all running devaipod pods with the ability to:
    /// - Monitor pod status and agent health
    /// - Review git commits before they're pushed
    /// - Accept, reject, or comment on agent changes
    ///
    /// By default, launches an interactive TUI. Use --serve for HTTP API mode.
    ///
    /// Examples:
    ///   devaipod controlplane              # Launch TUI
    ///   devaipod controlplane --serve      # Start HTTP server
    ///   devaipod controlplane --list       # One-shot: list pods and exit
    #[command(alias = "cp")]
    Controlplane {
        /// Start as HTTP server instead of TUI
        #[arg(long)]
        serve: bool,
        /// Port for HTTP server (default: 8080)
        #[arg(long, default_value = "8080")]
        port: u16,
        /// One-shot: list all pods and exit
        #[arg(long)]
        list: bool,
        /// Output in JSON format (for --list)
        #[arg(long)]
        json: bool,
    },
    /// Start the web UI server
    ///
    /// Launches a web server that provides a browser-based UI for managing
    /// devaipod workspaces. The server proxies podman API calls and provides
    /// git operations endpoints.
    ///
    /// A random auth token is generated at startup (or loaded from a podman
    /// secret). The full URL with token is printed to stdout.
    ///
    /// Examples:
    ///   devaipod web                    # Start on default port 8080
    ///   devaipod web --port 3000        # Start on port 3000
    #[command(hide = true)]
    Web {
        /// Port to bind the web server
        #[arg(long, default_value = "8080")]
        port: u16,
        /// Open browser automatically after starting
        #[arg(long)]
        open: bool,
    },

    /// Run the per-pod API server (sidecar container mode)
    ///
    /// Starts an HTTP server that provides git and PTY endpoints by operating
    /// directly on the mounted workspace volume. Designed to run as a sidecar
    /// container within a devaipod pod, replacing exec-based git operations.
    ///
    /// Examples:
    ///   devaipod pod-api                              # Default port 8090, workspace /workspaces
    ///   devaipod pod-api --port 9000                  # Custom port
    ///   devaipod pod-api --workspace /home/user/repo  # Custom workspace path
    #[command(hide = true)]
    PodApi(pod_api::PodApiArgs),

    /// Manage service-gator scopes for a workspace
    ///
    /// Service-gator provides scope-restricted access to external services
    /// (GitHub, GitLab, JIRA) for AI agents. This command allows editing
    /// the scopes for a running workspace.
    ///
    /// Examples:
    ///   devaipod gator edit my-workspace      # Edit scopes in $EDITOR
    ///   devaipod gator show my-workspace      # Show current scopes
    #[command(alias = "service-gator")]
    Gator {
        #[command(subcommand)]
        action: GatorAction,
    },

    /// Launch or interact with the advisor agent
    ///
    /// The advisor is a special agent that observes running pods and external
    /// services, then suggests actions for the human to approve. It runs in
    /// a pod named 'devaipod-advisor' using devaipod's own container image.
    ///
    /// If no advisor pod exists, this command helps launch one. If one is
    /// already running, it attaches to it.
    ///
    /// Examples:
    ///   devaipod advisor                              # Launch or attach
    ///   devaipod advisor 'check my github issues'     # Launch with task
    ///   devaipod advisor --status                     # Show advisor status
    ///   devaipod advisor --proposals                  # List draft proposals
    Advisor {
        /// Task for the advisor (e.g. "look at my assigned GitHub issues")
        task: Option<String>,
        /// Show advisor status and exit
        #[arg(long)]
        status: bool,
        /// List current draft proposals
        #[arg(long)]
        proposals: bool,
        /// Override the advisor pod name (default: advisor → devaipod-advisor)
        #[arg(long)]
        name: Option<String>,
        /// Additional source directories to mount read-only in the advisor pod.
        ///
        /// The advisor can browse these to understand project structure,
        /// check git status, and correlate across repos — without being
        /// able to modify anything.
        ///
        /// Example: --source-dir ~/src
        #[arg(long = "source-dir", value_name = "DIR")]
        source_dirs: Vec<PathBuf>,
    },

    /// Fetch agent commits into the current git repo
    ///
    /// Adds a git remote pointing at the agent's workspace directory and fetches
    /// all refs. This lets you review agent commits from your source repository
    /// using standard git tools (git log, git diff, etc.).
    ///
    /// When run from a git repo without a workspace name, fetches from all
    /// workspaces for the current repo. Use -A to fetch all regardless.
    ///
    /// Examples:
    ///   devaipod fetch                           # Fetch all workspaces for this repo
    ///   devaipod fetch myworkspace               # Fetch from named workspace
    ///   devaipod fetch -A                        # Fetch all workspaces (all repos)
    Fetch {
        /// Workspace name (uses latest if omitted)
        workspace: Option<String>,
        /// Fetch from all workspaces for the current repo
        #[arg(short = 'A', long)]
        all: bool,
    },

    /// Show diff of agent changes relative to current branch
    ///
    /// Fetches agent commits (if not already fetched) and shows the diff between
    /// your current branch and the agent's main branch. Uses three-dot diff
    /// (HEAD...remote/main) to show only what the agent changed.
    ///
    /// Examples:
    ///   devaipod diff                            # Diff against latest workspace
    ///   devaipod diff myworkspace                # Diff against named workspace
    ///   devaipod diff --stat                     # Show diffstat instead of full diff
    Diff {
        /// Workspace name (uses latest if omitted)
        workspace: Option<String>,
        /// Show stat instead of full diff
        #[arg(long)]
        stat: bool,
    },

    /// Interactive review of agent changes
    ///
    /// Opens a TUI showing the agent's commits and diff. Navigate the diff,
    /// add inline comments, and submit them back to the agent as review
    /// feedback. The agent receives the comments and iterates on its work.
    ///
    /// Examples:
    ///   devaipod review                            # Review latest workspace
    ///   devaipod review myworkspace                # Review named workspace
    Review {
        /// Workspace name (uses latest if omitted)
        workspace: Option<String>,
    },

    /// Apply agent changes to the current branch
    ///
    /// Fetches the latest agent commits and merges them into your current
    /// branch. Equivalent to `devaipod fetch` followed by `git merge`.
    ///
    /// Must be run from your source repository.
    ///
    /// Examples:
    ///   devaipod apply                          # Apply from latest workspace
    ///   devaipod apply myworkspace              # Apply from named workspace
    ///   devaipod apply --cherry-pick myws       # Cherry-pick instead of merge
    Apply {
        /// Workspace name (uses latest if omitted)
        workspace: Option<String>,
        /// Cherry-pick instead of merge (for individual commits)
        #[arg(long)]
        cherry_pick: bool,
    },

    /// Push agent branch to origin
    ///
    /// Pushes the most recently harvested branch from the named (or latest)
    /// workspace to the remote origin. Equivalent to running `devaipod fetch`
    /// then `git push origin <ref>:<branch>`.
    ///
    /// Must be run from your source repository.
    ///
    /// Examples:
    ///   devaipod push                            # Push latest workspace's branch
    ///   devaipod push myworkspace                # Push specific workspace
    Push {
        /// Workspace name (uses latest if omitted)
        workspace: Option<String>,
    },

    /// Create a pull request from agent work
    ///
    /// Pushes the agent branch and creates a PR using `gh pr create`.
    /// Requires the `gh` CLI to be installed and authenticated.
    ///
    /// Must be run from your source repository.
    ///
    /// Examples:
    ///   devaipod pr                              # PR from latest workspace
    ///   devaipod pr myworkspace                  # PR from specific workspace
    ///   devaipod pr --draft myworkspace          # Create as draft PR
    Pr {
        /// Workspace name (uses latest if omitted)
        workspace: Option<String>,
        /// Create as draft PR
        #[arg(long)]
        draft: bool,
        /// PR title (auto-generated from commits if omitted)
        #[arg(long)]
        title: Option<String>,
    },

    /// Get or set the session title for a pod
    ///
    /// The title is human-readable metadata for the session, separate from
    /// the auto-generated pod name and from the agent task.
    ///
    /// Examples:
    ///   devaipod title myworkspace                    # Show current title
    ///   devaipod title myworkspace "refactoring auth"  # Set title
    Title {
        /// Workspace name (devaipod- prefix optional)
        #[arg(allow_hyphen_values = true)]
        name: String,
        /// New title (omit to show current title)
        title: Option<String>,
    },

    /// Manage standalone devcontainers (human dev environment, no AI agent)
    ///
    /// Creates and manages devcontainer pods with a workspace container
    /// and API sidecar, but no AI agent or service-gator.
    ///
    /// Examples:
    ///   devaipod devcontainer run .                              # Local repo
    ///   devaipod devcontainer run https://github.com/user/repo   # Remote repo
    ///   devaipod devcontainer list                               # List devcontainers
    ///   devaipod devcontainer rm my-workspace                    # Remove a devcontainer
    #[command(alias = "dc")]
    Devcontainer {
        #[command(subcommand)]
        action: DevcontainerAction,
    },

    /// Internal helper commands (not for direct user use)
    ///
    /// These commands are used internally for remote development integration.
    /// They can run in any context (host or container).
    #[command(hide = true)]
    Helper {
        #[command(subcommand)]
        action: HelperCommand,
    },

    /// Internal plumbing commands used by the control plane
    #[command(hide = true)]
    Internals {
        #[command(subcommand)]
        action: InternalsCommand,
    },
}

/// Actions for interacting with the opencode agent
#[derive(Debug, Parser)]
enum OpencodeAction {
    /// MCP server operations
    Mcp {
        #[command(subcommand)]
        action: McpAction,
    },
    /// Session operations
    Session {
        #[command(subcommand)]
        action: SessionAction,
    },
    /// Send a message to the agent
    ///
    /// Creates a new session (or uses existing) and sends the message.
    /// Waits for and prints the response.
    Send {
        /// Message to send to the agent
        message: String,
        /// Session ID to use (creates new if not specified)
        #[arg(short, long)]
        session: Option<String>,
        /// Output raw JSON response
        #[arg(long)]
        json: bool,
    },
    /// Show agent status and health
    Status {
        /// Output in JSON format
        #[arg(long)]
        json: bool,
    },
}

/// MCP-related actions
#[derive(Debug, Parser)]
enum McpAction {
    /// List MCP servers and their connection status
    List {
        /// Output in JSON format
        #[arg(long)]
        json: bool,
    },
    /// List available tools from MCP servers
    Tools {
        /// Filter by server name
        #[arg(short, long)]
        server: Option<String>,
        /// Output in JSON format
        #[arg(long)]
        json: bool,
    },
}

/// Session-related actions
#[derive(Debug, Parser)]
enum SessionAction {
    /// List all sessions
    List {
        /// Output in JSON format
        #[arg(long)]
        json: bool,
    },
    /// Show session details
    Show {
        /// Session ID
        id: String,
        /// Output in JSON format
        #[arg(long)]
        json: bool,
    },
}

/// Service-gator management actions
#[derive(Debug, Parser)]
enum GatorAction {
    /// Edit service-gator scopes for a running workspace
    ///
    /// Opens $EDITOR with the current scope configuration in TOML format.
    /// After saving, mints a new JWT token with the updated scopes.
    ///
    /// Examples:
    ///   devaipod gator edit my-workspace
    ///   EDITOR=vim devaipod gator edit my-workspace
    Edit {
        /// Workspace name (devaipod- prefix optional)
        #[arg(allow_hyphen_values = true)]
        workspace: String,
    },
    /// Show current service-gator scopes
    Show {
        /// Workspace name (devaipod- prefix optional)
        #[arg(allow_hyphen_values = true)]
        workspace: String,
        /// Output in JSON format
        #[arg(long)]
        json: bool,
    },
    /// Add a scope to a running workspace (applies immediately)
    ///
    /// Uses the same format as --service-gator flag.
    ///
    /// Examples:
    ///   devaipod gator add my-workspace github:owner/repo
    ///   devaipod gator add my-workspace github:owner/repo:push
    ///   devaipod gator add my-workspace github:owner/*:read
    Add {
        /// Workspace name (devaipod- prefix optional)
        #[arg(allow_hyphen_values = true)]
        workspace: String,
        /// Scope to add (format: github:owner/repo[:permissions])
        #[arg(required = true)]
        scopes: Vec<String>,
    },
}

/// Devcontainer management actions
#[derive(Debug, Parser)]
enum DevcontainerAction {
    /// Create a standalone devcontainer (no AI agent)
    ///
    /// Creates a pod with a workspace container and API sidecar.
    /// The workspace gets trusted credentials, devcontainer lifecycle
    /// commands, dotfiles, and SSH access.
    ///
    /// Examples:
    ///   devaipod devcontainer run .
    ///   devaipod devcontainer run https://github.com/user/repo
    ///   devaipod devcontainer run . --image mcr.microsoft.com/devcontainers/rust:1
    Run {
        /// Source: local path or git URL
        source: Option<String>,
        /// Use a specific container image instead of building from devcontainer.json
        #[arg(long, value_name = "IMAGE")]
        image: Option<String>,
        /// Explicit pod name (default: derived from source with unique suffix)
        #[arg(long, value_name = "NAME")]
        name: Option<String>,
        /// Use this devcontainer JSON instead of the repo's devcontainer.json
        #[arg(long, value_name = "JSON")]
        devcontainer_json: Option<String>,
        /// Use the devcontainer.json from your dotfiles repo instead of the project's
        #[arg(long)]
        use_default_devcontainer: bool,
    },
    /// List running devcontainer pods
    ///
    /// Shows only devcontainer pods (not agent pods).
    List {
        /// Output in JSON format
        #[arg(long)]
        json: bool,
    },
    /// Remove a devcontainer pod and its volumes
    ///
    /// Examples:
    ///   devaipod devcontainer rm my-workspace
    ///   devaipod devcontainer rm my-workspace --force
    Rm {
        /// Workspace name (devaipod- prefix optional)
        #[arg(allow_hyphen_values = true)]
        name: String,
        /// Force deletion (stop running containers first)
        #[arg(short, long)]
        force: bool,
    },
}

// =============================================================================
// Container CLI - commands that run inside a devcontainer
// =============================================================================

#[derive(Debug, Parser)]
#[command(name = "devaipod-server")]
#[command(about = "Sandboxed AI coding agents (container mode)", long_about = None)]
struct ContainerCli {
    /// Path to config file (default: ~/.config/devaipod.toml)
    #[arg(long, global = true, value_name = "PATH")]
    config: Option<PathBuf>,

    #[command(subcommand)]
    command: ContainerCommand,
}

#[derive(Debug, Parser)]
enum ContainerCommand {
    /// Configure the container environment for nested containers
    ///
    /// Sets up containers.conf, subuid/subgid, and starts the podman service.
    /// This command is idempotent and should be run at container startup.
    /// Typically called from postStartCommand in devcontainer.json.
    ConfigureEnv,

    /// Internal helper commands for container operations
    #[command(subcommand)]
    Helper(HelperCommand),
}

/// Helper commands that run inside containers (not for direct user use)
#[derive(Debug, Parser)]
enum HelperCommand {
    /// Run SSH server for remote development (VSCode/Zed integration)
    ///
    /// This starts an embedded SSH server that speaks the SSH protocol over
    /// stdin/stdout. Used as a ProxyCommand target for editor remote development.
    SshServer {
        /// Run over stdin/stdout instead of a TCP port (for ProxyCommand use)
        #[arg(long, default_value = "true")]
        stdio: bool,
    },
}

/// Internal plumbing commands used by the control plane.
///
/// These are not user-facing; they exist so the control plane can run
/// our own binary inside an init container to extract data from volumes.
#[derive(Debug, Parser)]
enum InternalsCommand {
    /// Read devcontainer.json and git state from a workspace directory.
    ///
    /// Outputs a JSON object with `devcontainer_json` (nullable string)
    /// and `default_branch` (string) on stdout.
    OutputDevcontainerState {
        /// Path to the project root (e.g. /workspaces/myrepo)
        path: std::path::PathBuf,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    // Only emit ANSI color codes when stderr is a real terminal.
    // When captured by the web handler or piped, raw escape sequences
    // are noise.
    color_eyre::config::HookBuilder::default()
        .theme(if std::io::IsTerminal::is_terminal(&std::io::stderr()) {
            color_eyre::config::Theme::dark()
        } else {
            color_eyre::config::Theme::new()
        })
        .install()?;

    // Detect context BEFORE parsing args - this determines which CLI we use
    if is_inside_devcontainer() {
        // Container mode - use default log level
        init_tracing(false, false);
        let cli = ContainerCli::parse();
        run_container(cli)
    } else {
        // Host mode - parse CLI first to check for --verbose flag
        let cli = HostCli::parse();
        init_tracing(cli.verbose, cli.quiet);
        run_host(cli).await
    }
}

/// Initialize tracing with the appropriate log level
fn init_tracing(verbose: bool, quiet: bool) {
    let format = tracing_subscriber::fmt::format()
        .without_time()
        .with_target(false)
        .compact();

    let default_level = if verbose {
        "debug"
    } else if quiet {
        "warn"
    } else {
        "info"
    };

    tracing_subscriber::fmt()
        .event_format(format)
        .with_writer(std::io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(default_level)),
        )
        .init();
}

/// Commands that don't require a config file to exist
fn command_requires_config(cmd: &HostCommand) -> bool {
    !matches!(
        cmd,
        HostCommand::Init { .. }
            | HostCommand::Completions { .. }
            | HostCommand::PodApi(_)
            | HostCommand::Internals { .. }
            | HostCommand::Fetch { .. }
            | HostCommand::Diff { .. }
            | HostCommand::Review { .. }
            | HostCommand::Apply { .. }
            | HostCommand::Push { .. }
            | HostCommand::Pr { .. }
            | HostCommand::Status {
                workspace: None,
                ..
            }
    )
}

/// Commands that are allowed to run on the host without the devaipod container
fn command_allowed_on_host(cmd: &HostCommand) -> bool {
    matches!(
        cmd,
        HostCommand::Init { .. }
            | HostCommand::Completions { .. }
            | HostCommand::PodApi(_)
            | HostCommand::Internals { .. }
            | HostCommand::Fetch { .. }
            | HostCommand::Diff { .. }
            | HostCommand::Review { .. }
            | HostCommand::Apply { .. }
            | HostCommand::Push { .. }
            | HostCommand::Pr { .. }
            | HostCommand::Status {
                workspace: None,
                ..
            }
    )
}

async fn run_host(cli: HostCli) -> Result<()> {
    // Check if we're running inside the devaipod container (unless --host or exempt command)
    if !is_inside_devaipod_container()
        && !cli.host
        && !is_host_mode_env()
        && !command_allowed_on_host(&cli.command)
    {
        eprintln!("Error: this is the server binary, which runs inside the devaipod container.");
        eprintln!();
        eprintln!("Install the host CLI shim instead:");
        eprintln!("  cargo install --git https://github.com/cgwalters/devaipod devaipod-host");
        eprintln!("  # or from a local checkout:");
        eprintln!("  just install-host-shim");
        eprintln!();
        eprintln!("Then use:");
        eprintln!("  devaipod server start   # start the server container");
        eprintln!("  devaipod list            # commands are proxied into the container");
        eprintln!();
        eprintln!("To bypass this check and run the server binary directly:");
        eprintln!("  devaipod --host <command>");
        eprintln!("  DEVAIPOD_HOST_MODE=1 devaipod <command>");
        std::process::exit(1);
    }

    // Check if config file is required and exists
    if command_requires_config(&cli.command) {
        let config_path = cli
            .config
            .as_ref()
            .cloned()
            .unwrap_or_else(config::config_path);
        if !config_path.exists() {
            eprintln!("No configuration file found at {}", config_path.display());
            eprintln!();
            eprintln!("devaipod requires a configuration file to run.");
            eprintln!("Run 'devaipod init' to create one interactively.");
            eprintln!();
            eprintln!(
                "For more information, see: https://github.com/cgwalters/devaipod#configuration"
            );
            std::process::exit(1);
        }
    }

    let config = config::load_config(cli.config.as_deref())?;

    match cli.command {
        HostCommand::Up { source, opts } => {
            let source = resolve_source(source.as_deref(), &config);
            let source = maybe_resolve_shorthand(source, &config);
            cmd_up(&config, source.as_deref(), opts).await
        }

        HostCommand::Attach {
            workspace,
            latest,
            session,
            workspace_mode,
            worker,
        } => {
            if !std::io::stdin().is_terminal() {
                bail!(
                    "attach requires an interactive terminal. For non-interactive use, consider using the OpenCode API directly."
                );
            }
            let pod_name = resolve_workspace(workspace.as_deref(), latest)?;
            let target = if worker {
                AttachTarget::Worker
            } else if workspace_mode {
                tracing::warn!(
                    "Agent pods no longer have a workspace container; -W targets a container that may not exist"
                );
                AttachTarget::Workspace
            } else {
                AttachTarget::Agent
            };
            cmd_attach(&pod_name, session.as_deref(), target).await
        }
        HostCommand::Exec {
            workspace,
            workspace_mode,
            worker,
            stdio,
            command,
        } => {
            let target = if worker {
                AttachTarget::Worker
            } else if workspace_mode {
                tracing::warn!(
                    "Agent pods no longer have a workspace container; -W targets a container that may not exist"
                );
                AttachTarget::Workspace
            } else {
                AttachTarget::Agent
            };
            cmd_exec(&normalize_pod_name(&workspace), target, stdio, &command).await
        }
        HostCommand::SshConfig { workspace, user } => {
            cmd_ssh_config(&normalize_pod_name(&workspace), user.as_deref())
        }
        HostCommand::Cleanup { dry_run } => cmd_cleanup(dry_run),
        HostCommand::List {
            json,
            all,
            inactive,
        } => cmd_list(json, all, inactive),
        HostCommand::Tui { all } => tui::run(all).await,
        HostCommand::Start { workspace } => cmd_start(&normalize_pod_name(&workspace)),
        HostCommand::Stop { workspace } => cmd_stop(&normalize_pod_name(&workspace)),
        HostCommand::Delete { workspace, force } => {
            cmd_delete(&normalize_pod_name(&workspace), force)
        }
        HostCommand::Done { workspace, undo } => {
            cmd_done(&normalize_pod_name(&workspace), undo).await
        }
        HostCommand::Prune => cmd_prune().await,
        HostCommand::Rebuild {
            workspace,
            image,
            run_create,
        } => {
            cmd_rebuild(
                &config,
                &normalize_pod_name(&workspace),
                image.as_deref(),
                run_create,
            )
            .await
        }
        HostCommand::Logs {
            workspace,
            container,
            follow,
            tail,
        } => cmd_logs(&normalize_pod_name(&workspace), &container, follow, tail),
        HostCommand::Status {
            workspace: Some(workspace),
            json,
            ..
        } => cmd_status(&normalize_pod_name(&workspace), json),
        HostCommand::Status {
            workspace: None,
            all: true,
            ..
        } => cmd_list(false, true, true),
        HostCommand::Status {
            workspace: None,
            all: false,
            ..
        } => cmd_repo_status(),
        HostCommand::Debug { workspace, json } => cmd_debug(&normalize_pod_name(&workspace), json),
        HostCommand::Run {
            source,
            task,
            command,
            attach,
            image,
            name,
            service_gator_scopes,
            service_gator_image,
            service_gator_ro,
            mcp_servers,
            devcontainer_json,
            use_default_devcontainer,
            title,
            source_dirs,
        } => {
            let source = resolve_source(source.as_deref(), &config);
            let source = maybe_resolve_shorthand(source, &config);
            let source = source.as_deref();

            // Merge task sources: positional arg takes precedence, then -c/--command
            let explicit_task = task.or(command);

            // If no source and no explicit task, error out early with guidance
            if source.is_none() && explicit_task.is_none() {
                bail!(
                    "No source specified. Either provide a git URL, or use -c to specify a task for a scratch workspace.\n\
                     You can also configure a fallback in your config:\n\n\
                     [journal]\n\
                     repo = \"~/src/journal\"\n\n\
                     [dotfiles]\n\
                     url = \"https://github.com/youruser/dotfiles\""
                );
            }

            // Expand issue/PR shorthands like "#123" or "issues/123" to full
            // forge URLs using the current repo's origin remote.
            let source = match source {
                Some(ref s) => {
                    let trimmed = s.trim();
                    let issue_number = if let Some(n) = trimmed.strip_prefix('#') {
                        n.parse::<u64>().ok()
                    } else if let Some(n) = trimmed.strip_prefix("issues/") {
                        n.parse::<u64>().ok()
                    } else {
                        None
                    };
                    if let Some(num) = issue_number {
                        // Get the origin URL for the current repo
                        let origin = ProcessCommand::new("git")
                            .args(["remote", "get-url", "origin"])
                            .output()
                            .ok()
                            .filter(|o| o.status.success())
                            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string());
                        if let Some(origin_url) = origin {
                            let base = normalize_source(&origin_url, &config.git.extra_hosts);
                            let expanded = format!("{}/issues/{}", base.trim_end_matches('/'), num);
                            tracing::info!("Expanded '{}' to {}", trimmed, expanded);
                            Some(expanded)
                        } else {
                            bail!(
                                "Cannot expand '{}': not in a git repo with an 'origin' remote",
                                trimmed
                            );
                        }
                    } else {
                        source.as_ref().map(|s| s.to_string())
                    }
                }
                None => None,
            };

            // Check if source is an issue or PR URL - if so, set default task
            // Format: "<url> - work on" so human can easily edit the action
            let (effective_source, default_task) = match source.as_deref() {
                Some(source) => {
                    if let Some(issue_ref) = forge::parse_issue_url(source) {
                        let issue_url = issue_ref.issue_url();
                        let repo_url = issue_ref.repo_url();
                        tracing::info!("Issue URL detected: {}", issue_ref.short_display());
                        (Some(repo_url), Some(format!("{} - work on", issue_url)))
                    } else if let Some(pr_ref) = forge::parse_pr_url(source) {
                        let pr_url = pr_ref.pr_url();
                        tracing::info!("PR URL detected: {}", pr_ref.short_display());
                        (
                            Some(source.to_string()),
                            Some(format!("{} - work on", pr_url)),
                        )
                    } else {
                        (Some(source.to_string()), None)
                    }
                }
                None => (None, None),
            };

            // Determine final source and task: explicit task, or prompt interactively
            let (effective_source, effective_task) = match explicit_task {
                Some(t) => (effective_source, Some(t)),
                None if effective_source.is_some() && std::io::stdin().is_terminal() => {
                    // Use TUI-style editable prompt for both source and task
                    // (only when we have a source to show)
                    match tui::prompt_launch_input(
                        effective_source.as_deref().unwrap(),
                        default_task.as_deref().unwrap_or(""),
                    )
                    .await?
                    {
                        Some(result) => (Some(result.url), Some(result.task)),
                        None => {
                            // User cancelled with Esc
                            std::process::exit(130)
                        }
                    }
                }
                // Non-interactive: try to read from stdin (for piped input), fall back to default_task
                None if effective_source.is_some() => {
                    use std::io::BufRead;
                    let stdin = std::io::stdin();
                    let mut line = String::new();
                    match stdin.lock().read_line(&mut line) {
                        Ok(0) => (effective_source, default_task), // EOF, no input
                        Ok(_) => {
                            let trimmed = line.trim();
                            if trimmed.is_empty() {
                                (effective_source, default_task)
                            } else {
                                (effective_source, Some(trimmed.to_string()))
                            }
                        }
                        Err(_) => (effective_source, default_task), // Read error, use default
                    }
                }
                // No source and explicit_task was None — we already bailed above
                None => (effective_source, None),
            };

            let pod_name = cmd_run(
                &config,
                effective_source.as_deref(),
                effective_task.as_deref(),
                image.as_deref(),
                name.as_deref(),
                &service_gator_scopes,
                service_gator_image.as_deref(),
                service_gator_ro,
                &mcp_servers,
                devcontainer_json.as_deref(),
                use_default_devcontainer,
                title.as_deref(),
                &source_dirs,
            )
            .await?;

            if attach {
                cmd_attach(&pod_name, None, AttachTarget::Agent).await?;
            }
            Ok(())
        }
        HostCommand::Completions { shell } => cmd_completions(shell),
        HostCommand::Init { config } => init::cmd_init(config.as_deref()),
        HostCommand::Opencode { workspace, action } => {
            cmd_opencode(&normalize_pod_name(&workspace), action).await
        }
        HostCommand::Controlplane {
            serve,
            port,
            list,
            json,
        } => cmd_controlplane(serve, port, list, json).await,
        HostCommand::Gator { action } => cmd_gator(action).await,
        HostCommand::Web { port, open } => {
            let token = crate::web::load_or_generate_token();
            let mcp_token = crate::web::load_or_generate_mcp_token();
            let url = format!("http://localhost:{}/?token={}", port, token);

            println!("devaipod v{}", env!("CARGO_PKG_VERSION"));
            println!("Web UI: {}", url);
            println!();

            if open {
                // Try to open browser
                #[cfg(target_os = "linux")]
                let _ = std::process::Command::new("xdg-open").arg(&url).spawn();
                #[cfg(target_os = "macos")]
                let _ = std::process::Command::new("open").arg(&url).spawn();
            }

            crate::web::run_web_server(port, token, mcp_token).await
        }
        HostCommand::Fetch { workspace, all } => {
            if all || (workspace.is_none() && repo_root_path().is_ok()) {
                // Fetch all workspaces for the current repo
                let repo_root = repo_root_path()?;
                let workspaces = find_workspaces_for_repo(&repo_root);
                if workspaces.is_empty() {
                    println!("No workspaces found for this repo.");
                    println!("Use 'devaipod up .' to create one.");
                } else {
                    let mut errors = 0;
                    for ws in &workspaces {
                        match cmd_fetch(&ws.pod_name) {
                            Ok(_) => {}
                            Err(e) => {
                                eprintln!("Error fetching {}: {:#}", ws.short_name, e);
                                errors += 1;
                            }
                        }
                    }
                    if errors > 0 {
                        bail!("{} workspace(s) failed to fetch", errors);
                    }
                }
                Ok(())
            } else {
                let pod_name = resolve_workspace(workspace.as_deref(), workspace.is_none())?;
                cmd_fetch(&pod_name).map(|_| ())
            }
        }
        HostCommand::Diff {
            workspace, stat, ..
        } => {
            let pod_name = resolve_workspace(workspace.as_deref(), workspace.is_none())?;
            cmd_diff(&pod_name, stat)
        }
        HostCommand::Review { workspace } => {
            let pod_name = resolve_workspace(workspace.as_deref(), workspace.is_none())?;
            crate::review_tui::run(&pod_name).await
        }
        HostCommand::Apply {
            workspace,
            cherry_pick,
        } => {
            let pod_name = resolve_workspace(workspace.as_deref(), workspace.is_none())?;
            cmd_apply(&pod_name, cherry_pick)
        }
        HostCommand::Push { workspace } => {
            let pod_name = resolve_workspace(workspace.as_deref(), workspace.is_none())?;
            cmd_push(&pod_name)
        }
        HostCommand::Pr {
            workspace,
            draft,
            title,
        } => {
            let pod_name = resolve_workspace(workspace.as_deref(), workspace.is_none())?;
            cmd_pr(&pod_name, draft, title.as_deref())
        }
        HostCommand::Title { name, title } => {
            cmd_title(&normalize_pod_name(&name), title.as_deref()).await
        }
        HostCommand::PodApi(args) => crate::pod_api::run(args).await,
        HostCommand::Advisor {
            task,
            status,
            proposals,
            name,
            source_dirs,
        } => {
            cmd_advisor(
                &config,
                task.as_deref(),
                status,
                proposals,
                name.as_deref(),
                &source_dirs,
            )
            .await
        }
        HostCommand::Devcontainer { action } => cmd_devcontainer(&config, action).await,
        HostCommand::Helper { action } => run_helper_async(action).await,
        HostCommand::Internals { action } => run_internals(action),
    }
}

/// Dispatch devcontainer subcommands
async fn cmd_devcontainer(config: &config::Config, action: DevcontainerAction) -> Result<()> {
    match action {
        DevcontainerAction::Run {
            source,
            image,
            name,
            devcontainer_json,
            use_default_devcontainer,
        } => {
            let source = resolve_source(source.as_deref(), config);
            match source {
                Some(source) => {
                    cmd_devcontainer_run(
                        config,
                        source,
                        image.as_deref(),
                        name.as_deref(),
                        devcontainer_json.as_deref(),
                        use_default_devcontainer,
                    )
                    .await
                }
                None => {
                    bail!(
                        "No source specified for devcontainer.\n\
                         Either provide a source argument, or configure a fallback in your config."
                    );
                }
            }
        }
        DevcontainerAction::List { json } => cmd_devcontainer_list(json),
        DevcontainerAction::Rm { name, force } => cmd_delete(&normalize_pod_name(&name), force),
    }
}

/// Create a standalone devcontainer pod
async fn cmd_devcontainer_run(
    config: &config::Config,
    source: &str,
    image: Option<&str>,
    explicit_name: Option<&str>,
    devcontainer_json: Option<&str>,
    use_default_devcontainer: bool,
) -> Result<()> {
    let source = normalize_source(source, &config.git.extra_hosts);
    let source = source.as_ref();

    // Build CreateOptions-like state for devcontainer config resolution
    let create_opts = CreateOptions {
        task: None,
        title: None,
        image: image.map(|s| s.to_string()),
        name: explicit_name.map(|s| s.to_string()),
        service_gator_scopes: vec![],
        service_gator_image: None,
        mode: WorkspaceMode::Up, // doesn't matter, we use our own label
        service_gator_ro: false,
        mcp_servers: vec![],
        devcontainer_json: devcontainer_json.map(|s| s.to_string()),
        use_default_devcontainer,
        source_dirs: vec![],
    };

    // Resolve the source (local vs remote)
    let result = if source.starts_with("http://")
        || source.starts_with("https://")
        || source.starts_with("git@")
    {
        cmd_devcontainer_run_remote(config, source, &create_opts).await?
    } else {
        cmd_devcontainer_run_local(config, source, &create_opts).await?
    };

    // Auto-create SSH config entry
    if config.ssh.auto_config
        && let Some(config_path) = write_ssh_config_devcontainer(&result.pod_name)
    {
        tracing::info!("Created SSH config: {}", config_path.display());
        if !is_using_container_ssh_export() && !ssh_config_has_include() {
            tracing::warn!(
                "Add 'Include ~/.ssh/config.d/*' to the top of ~/.ssh/config for SSH integration"
            );
        }
    }

    let short_name = strip_pod_prefix(&result.pod_name);
    tracing::info!("Devcontainer ready ({})", short_name);
    tracing::info!("  SSH: ssh {}.devaipod", result.pod_name);
    tracing::info!("  Shell: devaipod exec {} -W", short_name);

    Ok(())
}

/// Create a devcontainer from a local path
async fn cmd_devcontainer_run_local(
    config: &config::Config,
    source: &str,
    opts: &CreateOptions,
) -> Result<CreateResult> {
    let source_path = std::path::Path::new(source).canonicalize().ok();
    let project_path = match source_path {
        Some(ref p) => p,
        None => bail!("Path '{}' does not exist or is not accessible.", source),
    };

    let git_info =
        git::detect_git_info(project_path).context("Failed to detect git repository info")?;

    if git_info.remote_url.is_none() {
        bail!(
            "No git remote configured for {}.\n\
             devaipod clones the repository into containers and requires a git remote.\n\
             Configure with: git remote add origin <url>",
            project_path.display()
        );
    }

    let (devcontainer_config, effective_image) = resolve_devcontainer_config(
        config,
        project_path,
        opts,
        &project_path.display().to_string(),
    )
    .await?;

    let project_name = project_path
        .file_name()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| "project".to_string());
    let pod_name = if let Some(ref name) = opts.name {
        normalize_pod_name(name)
    } else {
        make_pod_name(&project_name)
    };

    let podman = podman::PodmanService::spawn()
        .await
        .context("Failed to start podman service")?;

    let ws_source = pod::WorkspaceSource::LocalRepo(git_info);

    let mut extra_labels = vec![("io.devaipod.mode".to_string(), "devcontainer".to_string())];
    if let Some(instance_id) = get_instance_id() {
        extra_labels.push((INSTANCE_LABEL_KEY.to_string(), instance_id));
    }

    let devaipod_pod = pod::DevaipodPod::create_devcontainer(
        &podman,
        project_path,
        &devcontainer_config,
        &pod_name,
        config,
        &ws_source,
        &extra_labels,
        effective_image.as_deref(),
    )
    .await
    .context("Failed to create devcontainer pod")?;

    finalize_devcontainer_pod(&podman, &devaipod_pod, &devcontainer_config, config).await?;

    drop(podman);
    Ok(CreateResult { pod_name })
}

/// Create a devcontainer from a remote URL
async fn cmd_devcontainer_run_remote(
    config: &config::Config,
    remote_url: &str,
    opts: &CreateOptions,
) -> Result<CreateResult> {
    tracing::info!("Setting up {}...", remote_url);

    let repo_name = git::extract_repo_name(remote_url).unwrap_or_else(|| "project".to_string());

    let temp_dir = tempfile::tempdir().context("Failed to create temp directory")?;
    let temp_path = temp_dir.path();

    let gh_token = git::get_github_token_with_secret(config);
    let clone_url = git::authenticated_clone_url(remote_url, gh_token.as_deref());

    let clone_output = tokio::process::Command::new("git")
        .args([
            "clone",
            "--depth",
            "1",
            &clone_url,
            temp_path.to_str().unwrap(),
        ])
        .output()
        .await
        .context("Failed to clone repository")?;

    if !clone_output.status.success() {
        let stderr = String::from_utf8_lossy(&clone_output.stderr);
        bail!("Failed to clone repository: {}", stderr);
    }

    let branch_output = tokio::process::Command::new("git")
        .args(["rev-parse", "--abbrev-ref", "HEAD"])
        .current_dir(temp_path)
        .output()
        .await
        .context("Failed to get default branch")?;

    let default_branch = if branch_output.status.success() {
        String::from_utf8_lossy(&branch_output.stdout)
            .trim()
            .to_string()
    } else {
        "main".to_string()
    };

    let (devcontainer_config, effective_image) =
        resolve_devcontainer_config(config, temp_path, opts, remote_url).await?;

    let pod_name = if let Some(ref name) = opts.name {
        normalize_pod_name(name)
    } else {
        make_pod_name(&repo_name)
    };

    let podman = podman::PodmanService::spawn()
        .await
        .context("Failed to start podman service")?;

    let remote_info = git::RemoteRepoInfo {
        remote_url: remote_url.to_string(),
        default_branch,
        repo_name,
        fork_url: None,
    };
    let ws_source = pod::WorkspaceSource::RemoteRepo(remote_info);

    let mut extra_labels = vec![("io.devaipod.mode".to_string(), "devcontainer".to_string())];
    if let Some(instance_id) = get_instance_id() {
        extra_labels.push((INSTANCE_LABEL_KEY.to_string(), instance_id));
    }

    let devaipod_pod = pod::DevaipodPod::create_devcontainer(
        &podman,
        temp_path,
        &devcontainer_config,
        &pod_name,
        config,
        &ws_source,
        &extra_labels,
        effective_image.as_deref(),
    )
    .await
    .context("Failed to create devcontainer pod")?;

    finalize_devcontainer_pod(&podman, &devaipod_pod, &devcontainer_config, config).await?;

    drop(podman);
    Ok(CreateResult { pod_name })
}

/// Post-creation steps for devcontainer pods
async fn finalize_devcontainer_pod(
    podman: &podman::PodmanService,
    devaipod_pod: &pod::DevaipodPod,
    devcontainer_config: &devcontainer::DevcontainerConfig,
    config: &config::Config,
) -> Result<()> {
    devaipod_pod
        .start(podman)
        .await
        .context("Failed to start pod")?;

    // Copy bind_home files into workspace container
    devaipod_pod
        .copy_bind_home_files_workspace(
            podman,
            &devaipod_pod.workspace_bind_home,
            &devaipod_pod.container_home,
            devcontainer_config.effective_user(),
        )
        .await
        .context("Failed to copy bind_home files")?;

    // Install dotfiles in workspace container
    if let Some(ref dotfiles) = config.dotfiles {
        devaipod_pod
            .install_dotfiles_workspace(podman, dotfiles, devcontainer_config.effective_user())
            .await
            .context("Failed to install dotfiles")?;
    }

    // Run lifecycle commands in workspace container
    devaipod_pod
        .run_lifecycle_commands_workspace(podman, devcontainer_config)
        .await
        .context("Failed to run lifecycle commands")?;

    Ok(())
}

/// Write SSH config for a devcontainer pod
///
/// The SSH ProxyCommand uses `-W` to target the workspace container.
fn write_ssh_config_devcontainer(pod_name: &str) -> Option<std::path::PathBuf> {
    let username = std::env::var("USER").unwrap_or_else(|_| "user".to_string());

    let devaipod_cmd = if is_using_container_ssh_export() {
        "podman exec -i devaipod devaipod-server".to_string()
    } else {
        std::env::current_exe()
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_else(|_| "devaipod-server".to_string())
    };

    let config_content = format!(
        r#"# Generated by devaipod devcontainer
Host {pod}.devaipod
    ProxyCommand {devaipod} exec -W --stdio {pod}
    User {user}
    StrictHostKeyChecking no
    UserKnownHostsFile /dev/null
    LogLevel ERROR
"#,
        pod = pod_name,
        devaipod = devaipod_cmd,
        user = username,
    );

    let config_dir = get_ssh_config_dir().ok()?;
    std::fs::create_dir_all(&config_dir).ok()?;

    use cap_std_ext::cap_primitives::fs::PermissionsExt;
    use cap_std_ext::cap_std;
    use cap_std_ext::dirext::CapStdExtDirExt;

    let dir = cap_std::fs::Dir::open_ambient_dir(&config_dir, cap_std::ambient_authority()).ok()?;
    let config_path = get_ssh_config_path(pod_name).ok()?;
    let filename = config_path.file_name()?;

    dir.atomic_write_with_perms(
        filename,
        config_content.as_bytes(),
        cap_std::fs::Permissions::from_mode(0o600),
    )
    .ok()?;

    Some(config_path)
}

/// List devcontainer pods (those with io.devaipod.mode=devcontainer)
fn cmd_devcontainer_list(json_output: bool) -> Result<()> {
    let name_filter = format!("name={}*", POD_NAME_PREFIX);
    let mut args = vec!["pod", "ps", "--filter", &name_filter];

    let label_filter;
    if let Some(instance_id) = get_instance_id() {
        label_filter = format!("label={INSTANCE_LABEL_KEY}={instance_id}");
        args.extend(["--filter", &label_filter]);
    }
    args.push("--format=json");

    let output = podman_command()
        .args(&args)
        .output()
        .context("Failed to run podman pod ps")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("podman pod ps failed: {}", stderr.trim());
    }

    let pods: Vec<serde_json::Value> =
        serde_json::from_slice(&output.stdout).unwrap_or_else(|_| Vec::new());

    // Filter to only devcontainer pods
    let mut devcontainer_pods = Vec::new();
    for pod in &pods {
        let full_name = pod.get("Name").and_then(|v| v.as_str()).unwrap_or("");
        let labels = get_pod_labels(full_name);
        if !pod_labels_match_instance(labels.as_ref()) {
            continue;
        }
        let mode = labels
            .as_ref()
            .and_then(|l| l.get("io.devaipod.mode"))
            .and_then(|v| v.as_str());
        if mode != Some("devcontainer") {
            continue;
        }
        devcontainer_pods.push((pod, labels));
    }

    if json_output {
        let enriched: Vec<serde_json::Value> = devcontainer_pods
            .iter()
            .map(|(pod, labels)| {
                let mut enriched = (*pod).clone();
                if let Some(labels) = labels {
                    enriched["Labels"] = labels.clone();
                }
                enriched
            })
            .collect();
        println!("{}", serde_json::to_string_pretty(&enriched)?);
        return Ok(());
    }

    if devcontainer_pods.is_empty() {
        println!("No devcontainer pods found.");
        println!("Use 'devaipod devcontainer run <path>' to create one.");
        return Ok(());
    }

    // Calculate column widths
    let name_width = devcontainer_pods
        .iter()
        .filter_map(|(pod, _)| pod.get("Name").and_then(|v| v.as_str()))
        .map(|n| strip_pod_prefix(n).len())
        .max()
        .unwrap_or(4)
        .max(4);

    let repo_width = devcontainer_pods
        .iter()
        .filter_map(|(_, labels)| {
            labels
                .as_ref()
                .and_then(|l| l.get("io.devaipod.repo"))
                .and_then(|v| v.as_str())
        })
        .map(|s| s.len())
        .max()
        .unwrap_or(4)
        .max(4);

    let has_repo = devcontainer_pods.iter().any(|(_, labels)| {
        labels
            .as_ref()
            .and_then(|l| l.get("io.devaipod.repo"))
            .is_some()
    });

    if has_repo {
        println!(
            "{:<name_width$}  {:<10}  {:<repo_width$}  CREATED",
            "NAME",
            "STATUS",
            "REPO",
            name_width = name_width,
            repo_width = repo_width
        );
    } else {
        println!(
            "{:<name_width$}  {:<10}  CREATED",
            "NAME",
            "STATUS",
            name_width = name_width
        );
    }

    for (pod, labels) in &devcontainer_pods {
        let full_name = pod.get("Name").and_then(|v| v.as_str()).unwrap_or("-");
        let name = strip_pod_prefix(full_name);
        let status = pod.get("Status").and_then(|v| v.as_str()).unwrap_or("-");
        let created = pod.get("Created").and_then(|v| v.as_str()).unwrap_or("-");
        let created_display = format_created_time(created);

        let base_status = match status.to_lowercase().as_str() {
            "running" => "Running",
            "stopped" => "Stopped",
            "exited" => "Exited",
            "degraded" => "Degraded",
            _ => status,
        };

        if has_repo {
            let repo = labels
                .as_ref()
                .and_then(|l| l.get("io.devaipod.repo"))
                .and_then(|v| v.as_str())
                .unwrap_or("-");
            println!(
                "{:<name_width$}  {:<10}  {:<repo_width$}  {}",
                name,
                base_status,
                repo,
                created_display,
                name_width = name_width,
                repo_width = repo_width
            );
        } else {
            println!(
                "{:<name_width$}  {:<10}  {}",
                name,
                base_status,
                created_display,
                name_width = name_width
            );
        }
    }

    Ok(())
}

fn run_container(cli: ContainerCli) -> Result<()> {
    match cli.command {
        ContainerCommand::ConfigureEnv => {
            let _config = config::load_config(cli.config.as_deref())?;
            cmd_configure_env()
        }
        ContainerCommand::Helper(helper) => run_helper(helper),
    }
}

/// Run helper commands
async fn run_helper_async(cmd: HelperCommand) -> Result<()> {
    match cmd {
        HelperCommand::SshServer { stdio: _ } => {
            // The SSH server now runs on the host (not in the container).
            // This command is kept for backwards compatibility but is no longer used.
            bail!(
                "ssh-server helper is deprecated. The SSH server now runs on the host. \
                 Use 'devaipod exec --stdio <workspace>' instead."
            )
        }
    }
}

/// Wrapper for sync context (container mode)
fn run_helper(cmd: HelperCommand) -> Result<()> {
    tokio::runtime::Runtime::new()
        .context("Failed to create tokio runtime")?
        .block_on(run_helper_async(cmd))
}

fn run_internals(cmd: InternalsCommand) -> Result<()> {
    match cmd {
        InternalsCommand::OutputDevcontainerState { path } => {
            let info = devcontainer::read_workspace_state(&path);
            serde_json::to_writer(std::io::stdout(), &info)
                .context("Failed to write workspace info JSON")?;
            Ok(())
        }
    }
}

/// Which lifecycle commands to run
#[derive(Clone, Copy)]
enum LifecycleMode {
    /// Run all commands (onCreateCommand, postCreateCommand, postStartCommand)
    Full,
    /// Skip onCreateCommand (for rebuild when workspace already exists)
    Rebuild,
}

/// Common post-creation steps for all up commands
///
/// After creating a pod with DevaipodPod::create(), this function handles:
/// - Starting the pod
/// - Copying bind_home files
/// - Installing dotfiles
/// - Running lifecycle commands
/// - Printing success message
async fn finalize_pod(
    podman: &podman::PodmanService,
    devaipod_pod: &pod::DevaipodPod,
    devcontainer_config: &devcontainer::DevcontainerConfig,
    config: &config::Config,
) -> Result<()> {
    finalize_pod_with_mode(
        podman,
        devaipod_pod,
        devcontainer_config,
        config,
        LifecycleMode::Full,
    )
    .await
}

/// Common post-creation steps with configurable lifecycle mode
async fn finalize_pod_with_mode(
    podman: &podman::PodmanService,
    devaipod_pod: &pod::DevaipodPod,
    devcontainer_config: &devcontainer::DevcontainerConfig,
    config: &config::Config,
    lifecycle_mode: LifecycleMode,
) -> Result<()> {
    // Start the pod
    devaipod_pod
        .start(podman)
        .await
        .context("Failed to start pod")?;

    // Copy bind_home files into containers
    tracing::debug!("Copying bind_home files...");
    devaipod_pod
        .copy_bind_home_files(
            podman,
            &devaipod_pod.workspace_bind_home,
            &devaipod_pod.agent_bind_home,
            &devaipod_pod.container_home,
            devcontainer_config.effective_user(),
        )
        .await
        .context("Failed to copy bind_home files")?;

    // Install dotfiles before lifecycle commands
    if let Some(ref dotfiles) = config.dotfiles {
        devaipod_pod
            .install_dotfiles(podman, dotfiles, devcontainer_config.effective_user())
            .await
            .context("Failed to install dotfiles")?;
        devaipod_pod
            .install_dotfiles_agent(podman, dotfiles)
            .await
            .context("Failed to install dotfiles in agent")?;
    }

    // Write task to agent container AFTER dotfiles (so we don't get overwritten)
    if let Some(ref task) = devaipod_pod.task {
        devaipod_pod
            .write_task(podman, task, devaipod_pod.enable_gator)
            .await
            .context("Failed to write task to agent")?;
    }

    // Signal that agent setup is complete - this unblocks opencode serve
    // which is waiting for the state file
    devaipod_pod
        .signal_agent_ready(podman, config.dotfiles.as_ref())
        .await
        .context("Failed to signal agent ready")?;

    // Run lifecycle commands based on mode
    match lifecycle_mode {
        LifecycleMode::Full => {
            tracing::debug!("Running lifecycle commands...");
            devaipod_pod
                .run_lifecycle_commands(podman, devcontainer_config)
                .await
                .context("Failed to run lifecycle commands")?;
        }
        LifecycleMode::Rebuild => {
            tracing::debug!("Running rebuild lifecycle commands (postCreate + postStart)...");
            devaipod_pod
                .run_rebuild_lifecycle_commands(podman, devcontainer_config)
                .await
                .context("Failed to run lifecycle commands")?;
        }
    }

    // Set up git remotes for bidirectional collaboration
    // - 'agent' remote in workspace container (human can fetch agent's commits)
    // - 'workspace' remote in agent container (agent can fetch human's changes)
    devaipod_pod
        .setup_git_remotes(podman)
        .await
        .context("Failed to set up git remotes")?;

    // Success message
    let short_name = strip_pod_prefix(&devaipod_pod.pod_name);
    tracing::info!("Pod ready ({})", short_name);
    tracing::info!("  Attach to agent: devaipod attach {short_name}");

    Ok(())
}

// =============================================================================
// Workspace Creation (shared by up and run commands)
// =============================================================================

/// Result of creating a workspace
struct CreateResult {
    /// The pod name that was created
    pod_name: String,
}

/// Known git hosting providers whose bare hostnames should get `https://` prepended.
const KNOWN_GIT_HOSTS: &[&str] = &[
    "github.com",
    "gitlab.com",
    "codeberg.org",
    "bitbucket.org",
    "sr.ht",
    "gitea.com",
];

/// Normalize source string so that git URLs are correctly dispatched to clone
/// rather than treated as a local path.
///
/// Handles:
/// - Typos: `https;//` → `https://`
/// - Bare hostnames: `github.com/owner/repo` → `https://github.com/owner/repo`
/// - SSH URLs: `git@github.com:owner/repo.git` → `https://github.com/owner/repo`
///
/// `extra_hosts` allows user-configured hostnames (from `[git] extra_hosts`)
/// to be recognized alongside the built-in list.
fn normalize_source<'s>(source: &'s str, extra_hosts: &[String]) -> std::borrow::Cow<'s, str> {
    // Fix semicolon typos in scheme
    if let Some(rest) = source.strip_prefix("https;//") {
        return std::borrow::Cow::Owned(format!("https://{rest}"));
    }
    if let Some(rest) = source.strip_prefix("http;//") {
        return std::borrow::Cow::Owned(format!("http://{rest}"));
    }

    // Convert SSH URLs (git@host:owner/repo.git) to HTTPS
    if let Some(rest) = source.strip_prefix("git@") {
        // git@github.com:owner/repo.git -> github.com/owner/repo
        if let Some((host, path)) = rest.split_once(':') {
            let path = path.trim_end_matches(".git");
            return std::borrow::Cow::Owned(format!("https://{host}/{path}"));
        }
    }

    // Prepend https:// for bare known-host URLs (e.g. github.com/owner/repo)
    if !source.contains("://") {
        let is_known = KNOWN_GIT_HOSTS.iter().any(|h| source.starts_with(h))
            || extra_hosts.iter().any(|h| source.starts_with(h.as_str()));
        if is_known {
            return std::borrow::Cow::Owned(format!("https://{source}"));
        }
    }

    std::borrow::Cow::Borrowed(source)
}

/// Create a copy of the config with CLI --mcp servers merged in
///
/// Since `Config` doesn't implement `Clone`, we reload the config from disk
/// and merge the CLI servers into the `[mcp]` section. This is only called
/// when `--mcp` flags are present, so the reload cost is negligible.
fn merge_cli_mcp_into_config(
    _original: &config::Config,
    cli_servers: &[String],
) -> Result<config::Config> {
    // Reload config from default path (same path the original was loaded from)
    let mut config = config::load_config(None)?;
    config
        .mcp
        .merge_cli_servers(cli_servers)
        .context("Failed to parse --mcp arguments")?;
    Ok(config)
}

/// Create a workspace from a source (local path, remote URL, or PR)
///
/// Canonicalize a list of `--source-dir` paths, warning and skipping any that
/// don't resolve (e.g. non-existent directories).
fn canonicalize_source_dirs(dirs: &[PathBuf]) -> Vec<PathBuf> {
    dirs.iter()
        .filter_map(|d| match d.canonicalize() {
            Ok(p) => Some(p),
            Err(e) => {
                tracing::warn!("Skipping --source-dir {}: {}", d.display(), e);
                None
            }
        })
        .collect()
}

/// Write the workspace state file for a host-dir workspace.
///
/// Best-effort: logs a warning on failure rather than propagating errors,
/// since the pod is already created and running at this point.
fn write_workspace_state(
    pod_name: &str,
    source: String,
    source_dirs: &[PathBuf],
    task: Option<&str>,
    title: Option<&str>,
) {
    let ws_dir = match agent_dir::agent_dir_container_path(pod_name) {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!("Cannot resolve workspace dir for state file: {e:#}");
            return;
        }
    };
    if !ws_dir.exists() {
        // Not a host-dir workspace (remote/PR with volumes) — skip.
        return;
    }

    let state = agent_dir::WorkspaceState {
        pod_name: pod_name.to_string(),
        source,
        source_dirs: source_dirs.to_vec(),
        created: chrono::Utc::now().to_rfc3339(),
        last_active: None,
        task: task.map(|s| s.to_string()),
        title: title.map(|s| s.to_string()),
        completion_status: None,
        last_harvested: std::collections::HashMap::new(),
    };

    if let Err(e) = state.save(&ws_dir) {
        tracing::warn!("Failed to write workspace state for {pod_name}: {e:#}");
    }

    // Record in recent sources for the launcher
    agent_dir::record_recent_source(&state.source);
}

/// This is the inner "create" operation that handles all the common pod setup
/// logic without any SSH or other post-setup behavior. Both `cmd_up` and `cmd_run`
/// use this function internally.
///
/// Like `podman create` vs `podman run`, this function just creates and starts
/// the pod but doesn't perform any interactive operations afterward.
async fn create_workspace(
    config: &config::Config,
    source: Option<&str>,
    opts: &CreateOptions,
) -> Result<CreateResult> {
    // Merge CLI --mcp servers into config if any were provided.
    // We need to create a modified config since Config doesn't derive Clone.
    // Instead, we merge into a local McpServersConfig and swap it in via
    // a helper that takes the effective config.
    let effective_config;
    let config = if !opts.mcp_servers.is_empty() {
        effective_config = merge_cli_mcp_into_config(config, &opts.mcp_servers)?;
        &effective_config
    } else {
        config
    };

    // Dispatch based on source type
    let result = if let Some(source) = source {
        let source = normalize_source(source, &config.git.extra_hosts);
        let source = source.as_ref();

        // Try to resolve remote URLs to local source directories.
        // Users are expected to maintain pristine local clones; devaipod
        // works with those instead of cloning remotely.
        let source: std::borrow::Cow<'_, str> = if source.starts_with("https://")
            || source.starts_with("http://")
            || source.starts_with("git@")
        {
            if let Some(local_path) = resolve_url_to_local_source(source, config) {
                tracing::info!(
                    "Resolved {} to local source: {}",
                    source,
                    local_path.display()
                );
                std::borrow::Cow::Owned(local_path.to_string_lossy().to_string())
            } else {
                let suffix = extract_repo_suffix(source).unwrap_or_else(|| source.to_string());
                // Trim to host/org/repo for display
                let display_suffix: String = {
                    let parts: Vec<&str> = suffix.splitn(4, '/').collect();
                    if parts.len() >= 3 {
                        format!("{}/{}/{}", parts[0], parts[1], parts[2])
                    } else {
                        suffix.clone()
                    }
                };
                let sources_list: Vec<String> = config
                    .resolve_sources()
                    .iter()
                    .map(|s| format!("  {} = {}", s.name, s.path.display()))
                    .collect();
                let sources_display = if sources_list.is_empty() {
                    "  (none configured)".to_string()
                } else {
                    sources_list.join("\n")
                };
                // Suggest a TLD-less clone path
                let clone_suggestion = {
                    let parts: Vec<&str> = display_suffix.splitn(2, '/').collect();
                    if parts.len() == 2 {
                        let host = parts[0];
                        let short_host = host.split('.').next().unwrap_or(host);
                        format!("{}/{}", short_host, parts[1])
                    } else {
                        display_suffix.clone()
                    }
                };
                bail!(
                    "Repository '{}' not found in your source directories.\n\
                         Clone it first:\n\
                         \n  git clone {} ~/src/{}\n\
                         \n\
                         Configured sources:\n{}",
                    display_suffix,
                    source,
                    clone_suggestion,
                    sources_display,
                );
            }
        } else {
            std::borrow::Cow::Borrowed(source)
        };
        let source: &str = &source;

        if forge::parse_pr_url(source).is_some()
            || source.starts_with("http://")
            || source.starts_with("https://")
            || source.starts_with("git@")
        {
            bail!(
                "Internal error: URL '{}' should have been resolved to a local path",
                source
            );
        }

        create_workspace_from_local(config, source, opts).await?
    } else {
        create_workspace_without_source(config, opts).await?
    };

    // Auto-create SSH config entry if enabled (default: true)
    if config.ssh.auto_config
        && let Some(config_path) = write_ssh_config(&result.pod_name)
    {
        tracing::info!("Created SSH config: {}", config_path.display());
        // Warn if Include directive is missing (skip in container mode where
        // the config is exported via /run/devaipod-ssh bind mount)
        if !is_using_container_ssh_export() && !ssh_config_has_include() {
            tracing::warn!(
                "Add 'Include ~/.ssh/config.d/*' to the top of ~/.ssh/config for SSH integration"
            );
        }
    }

    Ok(result)
}

/// Resolve the devcontainer configuration for a project.
///
/// Searches in priority order:
/// 1. Inline JSON override (--devcontainer-json)
/// 2. devcontainer.json in the project source
/// 3. devcontainer.json from the dotfiles repository (cloned to a temp dir)
/// 4. --image override with default DevcontainerConfig
/// 5. default-image from config with default DevcontainerConfig
///
/// The dotfiles fallback (step 3) allows users to define a default devcontainer
/// configuration in their dotfiles repo that applies to projects without their
/// own devcontainer.json. This is the natural place for user-level defaults
/// like nested container support, default extensions, or lifecycle commands.
async fn resolve_devcontainer_config(
    config: &config::Config,
    project_path: &Path,
    opts: &CreateOptions,
    source_description: &str,
) -> Result<(devcontainer::DevcontainerConfig, Option<String>)> {
    // 1. Inline JSON override takes highest priority
    if let Some(ref json) = opts.devcontainer_json {
        tracing::info!("Using inline devcontainer JSON override");
        return Ok((
            devcontainer::parse_jsonc(json).context("Failed to parse --devcontainer-json")?,
            opts.image.clone(),
        ));
    }

    // 2. Check the project source (unless user requested the dotfiles devcontainer)
    if !opts.use_default_devcontainer
        && let Some(ref path) = devcontainer::try_find_devcontainer_json(project_path)
    {
        return Ok((devcontainer::load(path)?, opts.image.clone()));
    }

    // 3. Check the dotfiles repository for a devcontainer.json
    if let Some(ref dotfiles) = config.dotfiles {
        let gh_token = git::get_github_token_with_secret(config);
        match clone_dotfiles_for_devcontainer(&dotfiles.url, gh_token.as_deref()).await {
            Ok(Some((dotfiles_config, _temp_dir))) => {
                tracing::info!("Using devcontainer.json from dotfiles ({})", dotfiles.url);
                // If the dotfiles devcontainer specifies an image, use it;
                // otherwise fall through to image override / default-image.
                let effective_image = opts.image.clone().or_else(|| {
                    dotfiles_config
                        .image
                        .clone()
                        .or_else(|| config.default_image.clone())
                });
                return Ok((dotfiles_config, effective_image));
            }
            Ok(None) => {
                tracing::debug!("No devcontainer.json found in dotfiles repo");
            }
            Err(e) => {
                tracing::debug!("Failed to check dotfiles for devcontainer.json: {:#}", e);
            }
        }
    }

    // 4. Image override
    if opts.image.is_some() {
        tracing::info!(
            "No devcontainer.json found in {}, using defaults with --image override",
            source_description
        );
        return Ok((
            devcontainer::DevcontainerConfig::default(),
            opts.image.clone(),
        ));
    }

    // 5. Default image from config
    if let Some(ref default_image) = config.default_image {
        tracing::info!(
            "No devcontainer.json found in {}, using default-image from config: {}",
            source_description,
            default_image
        );
        return Ok((
            devcontainer::DevcontainerConfig::default(),
            Some(default_image.clone()),
        ));
    }

    bail!(
        "No devcontainer.json found in {}.\n\
         Either add a devcontainer.json, use --image, or set default-image in config.",
        source_description
    );
}

/// Clone the dotfiles repo to a temp directory and look for a devcontainer.json.
///
/// Returns `Ok(Some((config, temp_dir)))` if found, `Ok(None)` if the dotfiles
/// repo has no devcontainer.json. The `TempDir` is returned so the caller keeps
/// it alive for as long as the config may reference relative paths (e.g. Dockerfile builds).
async fn clone_dotfiles_for_devcontainer(
    dotfiles_url: &str,
    gh_token: Option<&str>,
) -> Result<Option<(devcontainer::DevcontainerConfig, tempfile::TempDir)>> {
    let temp_dir = tempfile::tempdir().context("Failed to create temp directory for dotfiles")?;
    let clone_url = git::authenticated_clone_url(dotfiles_url, gh_token);

    let output = tokio::process::Command::new("git")
        .args([
            "clone",
            "--depth",
            "1",
            "--filter=blob:none",
            &clone_url,
            temp_dir.path().to_str().unwrap(),
        ])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .output()
        .await
        .context("Failed to clone dotfiles repo")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("Failed to clone dotfiles repo: {}", stderr.trim());
    }

    match devcontainer::try_find_devcontainer_json(temp_dir.path()) {
        Some(path) => {
            let config = devcontainer::load(&path)?;
            Ok(Some((config, temp_dir)))
        }
        None => Ok(None),
    }
}

/// Create a workspace from a local git repository
async fn create_workspace_from_local(
    config: &config::Config,
    source: &str,
    opts: &CreateOptions,
) -> Result<CreateResult> {
    let source_path = std::path::Path::new(source).canonicalize().ok();

    // Local path is required for non-remote sources
    let project_path = match source_path {
        Some(ref p) => p,
        None => {
            if source.contains("github.com")
                || source.contains("gitlab.com")
                || source.contains("http")
            {
                bail!(
                    "Source looks like a git URL but was not recognized (e.g. use https:// not https;//).\n\
                     Got: '{}'",
                    source
                );
            }
            bail!("Path '{}' does not exist or is not accessible.", source);
        }
    };

    // Detect git repository info for cloning into containers
    let mut git_info =
        git::detect_git_info(project_path).context("Failed to detect git repository info")?;

    // Require a remote URL for cloning
    if git_info.remote_url.is_none() {
        bail!(
            "No git remote configured for {}.\n\
             devaipod clones the repository into containers and requires a git remote.\n\
             Configure with: git remote add origin <url>",
            project_path.display()
        );
    }

    // Warn about dirty working tree
    if git_info.is_dirty {
        eprintln!(
            "\n\u{26a0}\u{fe0f}  Warning: Uncommitted changes detected ({} file(s)):",
            git_info.dirty_files.len()
        );
        for file in git_info.dirty_files.iter().take(5) {
            eprintln!("     {}", file);
        }
        if git_info.dirty_files.len() > 5 {
            eprintln!("     ... and {} more", git_info.dirty_files.len() - 5);
        }
        eprintln!();
        eprintln!(
            "   The AI agent will work on commit {} and won't see uncommitted changes.",
            &git_info.commit_sha[..8]
        );
        eprintln!("   Consider committing or stashing your changes first.\n");
    }

    // Detect if the user has a fork of the repository and add it as a remote
    if let Some(ref remote_url) = git_info.remote_url
        && let Some(repo_ref) = forge::parse_repo_url(remote_url)
        && repo_ref.forge_type == forge::ForgeType::GitHub
        && let Some(fork_info) = forge::fetch_github_user_fork(&repo_ref, Some(config)).await
    {
        git_info.fork_url = Some(fork_info.clone_url);
    }

    let (devcontainer_config, effective_image) = resolve_devcontainer_config(
        config,
        project_path,
        opts,
        &project_path.display().to_string(),
    )
    .await?;

    // Derive project/pod name from path
    let project_name = project_path
        .file_name()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| "project".to_string());

    // Use explicit name if provided, otherwise generate a unique name
    let pod_name = if let Some(ref name) = opts.name {
        normalize_pod_name(name)
    } else {
        make_pod_name(&project_name)
    };

    // Check for API keys and warn if none are configured (helps first-run experience)
    check_api_keys_configured();

    // Parse CLI service-gator scopes and merge with file config
    // For local repos with a remote URL, auto-enable service-gator with read + draft access
    // (same behavior as remote URL path in create_workspace_from_remote)
    let service_gator_config = if !opts.service_gator_scopes.is_empty() {
        let cli_scopes = service_gator::parse_scopes(&opts.service_gator_scopes)
            .context("Failed to parse --service-gator scopes")?;
        service_gator::merge_configs(&config.service_gator, &cli_scopes)
    } else if let Some(ref remote_url) = git_info.remote_url {
        // Auto-configure: read + optionally create-draft for the target repo based on remote URL
        if let Some(repo_ref) = forge::parse_repo_url(remote_url) {
            let mut sg_config = config.service_gator.clone();
            let owner_repo = repo_ref.owner_repo();

            match repo_ref.forge_type {
                forge::ForgeType::GitHub => {
                    // If --service-gator-ro is set, only grant read access
                    let (create_draft, push_new_branch) = if opts.service_gator_ro {
                        (false, false)
                    } else {
                        (true, true)
                    };
                    sg_config.gh.repos.insert(
                        owner_repo.clone(),
                        config::GhRepoPermission {
                            read: true,
                            create_draft,
                            pending_review: false,
                            push_new_branch,
                            write: false,
                        },
                    );
                    if opts.service_gator_ro {
                        tracing::debug!(
                            "Auto-enabled service-gator for {} (read-only)",
                            owner_repo
                        );
                    } else {
                        tracing::debug!(
                            "Auto-enabled service-gator for {} (read + push-new-branch + draft PRs)",
                            owner_repo
                        );
                    }
                }
                forge::ForgeType::GitLab | forge::ForgeType::Forgejo | forge::ForgeType::Gitea => {
                    // TODO: Add GitLab/Forgejo/Gitea support to service-gator config
                    tracing::debug!(
                        "Auto service-gator not yet supported for {} ({})",
                        repo_ref.forge_type,
                        owner_repo
                    );
                }
            }
            sg_config
        } else {
            config.service_gator.clone()
        }
    } else {
        config.service_gator.clone()
    };

    // Check if gator should be enabled (from merged config)
    let enable_gator = service_gator_config.is_enabled();

    // Start podman service
    tracing::debug!("Starting podman service...");
    let podman = podman::PodmanService::spawn()
        .await
        .context("Failed to start podman service")?;

    // Create the pod with all containers
    tracing::debug!("Creating pod '{}'...", pod_name);
    let source = pod::WorkspaceSource::LocalRepo(git_info);

    // Build extra labels for task description, mode, and instance
    let mut extra_labels = Vec::new();
    extra_labels.push((
        "io.devaipod.mode".to_string(),
        opts.mode.as_str().to_string(),
    ));
    if let Some(ref task_desc) = opts.task {
        extra_labels.push(("io.devaipod.task".to_string(), task_desc.clone()));
    }
    if let Some(ref title) = opts.title {
        extra_labels.push(("io.devaipod.title".to_string(), title.clone()));
    }
    if let Some(instance_id) = get_instance_id() {
        extra_labels.push((INSTANCE_LABEL_KEY.to_string(), instance_id));
    }

    let source_dirs = canonicalize_source_dirs(&opts.source_dirs);

    // Create agent backend
    let (agent_name, agent_profile) = config.agent.resolve_profile(None);
    let backend = create_agent_backend(&agent_name, agent_profile, &config.agent)?;

    let devaipod_pod = pod::DevaipodPod::create(
        &podman,
        project_path,
        &devcontainer_config,
        &pod_name,
        enable_gator,
        config,
        &source,
        &extra_labels,
        Some(&service_gator_config),
        effective_image.as_deref(),
        opts.service_gator_image.as_deref(),
        opts.task.as_deref(),
        config.orchestration.is_enabled(),
        config.orchestration.worker.gator.clone(),
        &source_dirs,
        backend.as_ref(),
    )
    .await
    .context("Failed to create devaipod pod")?;

    finalize_pod(&podman, &devaipod_pod, &devcontainer_config, config).await?;

    // Write workspace state file for host-dir workspaces
    write_workspace_state(
        &pod_name,
        project_path.display().to_string(),
        &source_dirs,
        opts.task.as_deref(),
        opts.title.as_deref(),
    );

    drop(podman);

    Ok(CreateResult { pod_name })
}

/// Create a scratch workspace without a git repo source.
///
/// The devcontainer image is resolved from fallback sources (dotfiles repo
/// devcontainer.json, --image flag, or default-image in config). The workspace
/// gets an empty directory instead of a git clone.
async fn create_workspace_without_source(
    config: &config::Config,
    opts: &CreateOptions,
) -> Result<CreateResult> {
    tracing::info!("Creating scratch workspace (no source repo)...");

    // Resolve devcontainer config without a project path — this will use
    // fallback sources (dotfiles repo, --image, or default-image config)
    let temp_dir = tempfile::tempdir().context("Failed to create temp directory")?;
    let (devcontainer_config, effective_image) =
        resolve_devcontainer_config(config, temp_dir.path(), opts, "scratch workspace").await?;

    let pod_name = if let Some(ref name) = opts.name {
        normalize_pod_name(name)
    } else {
        make_pod_name("scratch")
    };

    check_api_keys_configured();

    // Use base service-gator config (no repo-specific scopes)
    let service_gator_config = if !opts.service_gator_scopes.is_empty() {
        let cli_scopes = service_gator::parse_scopes(&opts.service_gator_scopes)
            .context("Failed to parse --service-gator scopes")?;
        service_gator::merge_configs(&config.service_gator, &cli_scopes)
    } else {
        config.service_gator.clone()
    };

    let enable_gator = service_gator_config.is_enabled();

    let podman = podman::PodmanService::spawn()
        .await
        .context("Failed to start podman service")?;

    let source = pod::WorkspaceSource::Scratch;

    let mut extra_labels = Vec::new();
    extra_labels.push((
        "io.devaipod.mode".to_string(),
        opts.mode.as_str().to_string(),
    ));
    if let Some(ref task_desc) = opts.task {
        extra_labels.push(("io.devaipod.task".to_string(), task_desc.clone()));
    }
    if let Some(ref title) = opts.title {
        extra_labels.push(("io.devaipod.title".to_string(), title.clone()));
    }
    if let Some(instance_id) = get_instance_id() {
        extra_labels.push((INSTANCE_LABEL_KEY.to_string(), instance_id));
    }

    let source_dirs = canonicalize_source_dirs(&opts.source_dirs);

    // Create agent backend
    let (agent_name, agent_profile) = config.agent.resolve_profile(None);
    let backend = create_agent_backend(&agent_name, agent_profile, &config.agent)?;

    let devaipod_pod = pod::DevaipodPod::create(
        &podman,
        temp_dir.path(),
        &devcontainer_config,
        &pod_name,
        enable_gator,
        config,
        &source,
        &extra_labels,
        Some(&service_gator_config),
        effective_image.as_deref(),
        opts.service_gator_image.as_deref(),
        opts.task.as_deref(),
        config.orchestration.is_enabled(),
        config.orchestration.worker.gator.clone(),
        &source_dirs,
        backend.as_ref(),
    )
    .await
    .context("Failed to create scratch workspace pod")?;

    finalize_pod(&podman, &devaipod_pod, &devcontainer_config, config).await?;

    write_workspace_state(
        &pod_name,
        "scratch".to_string(),
        &source_dirs,
        opts.task.as_deref(),
        opts.title.as_deref(),
    );

    drop(podman);
    Ok(CreateResult { pod_name })
}

/// Create a workspace from a remote git URL
#[allow(dead_code)] // Retained for possible future use; URLs now resolve to local paths
async fn create_workspace_from_remote(
    config: &config::Config,
    remote_url: &str,
    opts: &CreateOptions,
) -> Result<CreateResult> {
    tracing::info!("Setting up {}...", remote_url);

    // Extract repo name from URL for naming
    let repo_name = git::extract_repo_name(remote_url).unwrap_or_else(|| "project".to_string());

    // Clone the repository to a temp directory to read devcontainer.json and get default branch
    let temp_dir = tempfile::tempdir().context("Failed to create temp directory")?;
    let temp_path = temp_dir.path();

    tracing::debug!("Cloning repository to read devcontainer.json...");

    // Use authenticated URL if GH_TOKEN is available (for private repos)
    let gh_token = git::get_github_token_with_secret(config);
    let clone_url = git::authenticated_clone_url(remote_url, gh_token.as_deref());

    // Clone the repository (shallow clone for speed)
    let clone_output = tokio::process::Command::new("git")
        .args([
            "clone",
            "--depth",
            "1",
            &clone_url,
            temp_path.to_str().unwrap(),
        ])
        .output()
        .await
        .context("Failed to clone repository")?;

    if !clone_output.status.success() {
        let stderr = String::from_utf8_lossy(&clone_output.stderr);
        bail!("Failed to clone repository: {}", stderr);
    }

    // Get the default branch name
    let branch_output = tokio::process::Command::new("git")
        .args(["rev-parse", "--abbrev-ref", "HEAD"])
        .current_dir(temp_path)
        .output()
        .await
        .context("Failed to get default branch")?;

    let default_branch = if branch_output.status.success() {
        String::from_utf8_lossy(&branch_output.stdout)
            .trim()
            .to_string()
    } else {
        "main".to_string() // Fallback
    };

    let (devcontainer_config, effective_image) =
        resolve_devcontainer_config(config, temp_path, opts, remote_url).await?;

    // Use explicit name if provided, otherwise generate a unique name
    let pod_name = if let Some(ref name) = opts.name {
        normalize_pod_name(name)
    } else {
        make_pod_name(&repo_name)
    };

    // For remote URLs, auto-enable service-gator with readonly + draft PR access
    // to the target repository (unless user provided explicit scopes)
    let service_gator_config = if !opts.service_gator_scopes.is_empty() {
        let cli_scopes = service_gator::parse_scopes(&opts.service_gator_scopes)
            .context("Failed to parse --service-gator scopes")?;
        service_gator::merge_configs(&config.service_gator, &cli_scopes)
    } else if let Some(repo_ref) = forge::parse_repo_url(remote_url) {
        // Auto-configure: read + optionally create-draft for the target repo
        let mut sg_config = config.service_gator.clone();
        let owner_repo = repo_ref.owner_repo();

        match repo_ref.forge_type {
            forge::ForgeType::GitHub => {
                // If --service-gator-ro is set, only grant read access
                let (create_draft, push_new_branch) = if opts.service_gator_ro {
                    (false, false)
                } else {
                    (true, true)
                };
                sg_config.gh.repos.insert(
                    owner_repo.clone(),
                    config::GhRepoPermission {
                        read: true,
                        create_draft,
                        pending_review: false,
                        push_new_branch,
                        write: false,
                    },
                );
                if opts.service_gator_ro {
                    tracing::debug!("Auto-enabled service-gator for {} (read-only)", owner_repo);
                } else {
                    tracing::debug!(
                        "Auto-enabled service-gator for {} (read + push-new-branch + draft PRs)",
                        owner_repo
                    );
                }
            }
            forge::ForgeType::GitLab | forge::ForgeType::Forgejo | forge::ForgeType::Gitea => {
                // TODO: Add GitLab/Forgejo/Gitea support to service-gator config
                tracing::debug!(
                    "Auto service-gator not yet supported for {} ({})",
                    repo_ref.forge_type,
                    owner_repo
                );
            }
        }
        sg_config
    } else {
        config.service_gator.clone()
    };

    // Start podman service
    let podman = podman::PodmanService::spawn()
        .await
        .context("Failed to start podman service")?;

    let enable_gator = service_gator_config.is_enabled();

    // Detect if the user has a fork of the repository
    let fork_url = if let Some(repo_ref) = forge::parse_repo_url(remote_url) {
        if repo_ref.forge_type == forge::ForgeType::GitHub {
            forge::fetch_github_user_fork(&repo_ref, Some(config))
                .await
                .map(|info| info.clone_url)
        } else {
            None
        }
    } else {
        None
    };

    // Create source from remote repo info
    let remote_info = git::RemoteRepoInfo {
        remote_url: remote_url.to_string(),
        default_branch: default_branch.clone(),
        repo_name: repo_name.clone(),
        fork_url,
    };
    let source = pod::WorkspaceSource::RemoteRepo(remote_info);

    // Build extra labels for task description, mode, and instance
    let mut extra_labels = Vec::new();
    extra_labels.push((
        "io.devaipod.mode".to_string(),
        opts.mode.as_str().to_string(),
    ));
    if let Some(ref task_desc) = opts.task {
        extra_labels.push(("io.devaipod.task".to_string(), task_desc.clone()));
    }
    if let Some(ref title) = opts.title {
        extra_labels.push(("io.devaipod.title".to_string(), title.clone()));
    }
    if let Some(instance_id) = get_instance_id() {
        extra_labels.push((INSTANCE_LABEL_KEY.to_string(), instance_id));
    }

    let source_dirs = canonicalize_source_dirs(&opts.source_dirs);

    // Create agent backend
    let (agent_name, agent_profile) = config.agent.resolve_profile(None);
    let backend = create_agent_backend(&agent_name, agent_profile, &config.agent)?;

    // Create the pod
    tracing::debug!("Creating pod '{}'...", pod_name);
    let devaipod_pod = pod::DevaipodPod::create(
        &podman,
        temp_path,
        &devcontainer_config,
        &pod_name,
        enable_gator,
        config,
        &source,
        &extra_labels,
        Some(&service_gator_config),
        effective_image.as_deref(),
        opts.service_gator_image.as_deref(),
        opts.task.as_deref(),
        config.orchestration.is_enabled(),
        config.orchestration.worker.gator.clone(),
        &source_dirs,
        backend.as_ref(),
    )
    .await
    .context("Failed to create devaipod pod")?;

    finalize_pod(&podman, &devaipod_pod, &devcontainer_config, config).await?;

    // Write workspace state file (best-effort; remote workspaces may not
    // have a host-dir yet, in which case this is a no-op).
    write_workspace_state(
        &pod_name,
        remote_url.to_string(),
        &source_dirs,
        opts.task.as_deref(),
        opts.title.as_deref(),
    );

    drop(podman);

    Ok(CreateResult { pod_name })
}

/// Create a workspace from a PR/MR URL
#[allow(dead_code)] // Retained for possible future use; URLs now resolve to local paths
async fn create_workspace_from_pr(
    config: &config::Config,
    pr_ref: forge::PullRequestRef,
    opts: &CreateOptions,
) -> Result<CreateResult> {
    tracing::info!(
        "Setting up PR #{} ({}/{})...",
        pr_ref.number,
        pr_ref.owner,
        pr_ref.repo
    );

    // Fetch PR metadata (pass config for GH_TOKEN from podman secrets)
    let pr_info = forge::fetch_pr_info(&pr_ref, Some(config))
        .await
        .context("Failed to fetch PR information")?;

    tracing::debug!("PR: {}", pr_info.title);
    tracing::debug!("Head: {} @ {}", pr_info.head_ref, &pr_info.head_sha[..8]);

    // Clone PR head to get the devcontainer.json from the PR
    let temp_dir = tempfile::tempdir().context("Failed to create temp directory")?;
    let temp_path = temp_dir.path();

    tracing::debug!("Cloning PR head to read devcontainer.json...");

    // Use authenticated URL if GH_TOKEN is available (for private repos)
    let gh_token = git::get_github_token_with_secret(config);
    let clone_url = git::authenticated_clone_url(&pr_info.head_clone_url, gh_token.as_deref());

    // Clone from the PR's head repository and checkout the specific commit
    let clone_output = tokio::process::Command::new("git")
        .args([
            "clone",
            "--depth",
            "1",
            "--branch",
            &pr_info.head_ref,
            &clone_url,
            temp_path.to_str().unwrap(),
        ])
        .output()
        .await
        .context("Failed to clone PR head repository")?;

    if !clone_output.status.success() {
        let stderr = String::from_utf8_lossy(&clone_output.stderr);
        bail!("Failed to clone PR head repository: {}", stderr);
    }

    let pr_description = format!("{}#{}", pr_ref.repo, pr_ref.number);
    let (devcontainer_config, effective_image) =
        resolve_devcontainer_config(config, temp_path, opts, &pr_description).await?;

    // Use explicit name if provided, otherwise generate a unique name
    let pod_name = if let Some(ref name) = opts.name {
        normalize_pod_name(name)
    } else {
        make_pr_pod_name(&pr_ref.repo, pr_ref.number)
    };

    // Start podman service
    let podman = podman::PodmanService::spawn()
        .await
        .context("Failed to start podman service")?;

    // Auto-enable service-gator for PR workflows based on forge type
    // PRs are the primary use case for service-gator (reviewing, pushing, etc.)
    let service_gator_config = if !opts.service_gator_scopes.is_empty() {
        let cli_scopes = service_gator::parse_scopes(&opts.service_gator_scopes)
            .context("Failed to parse --service-gator scopes")?;
        service_gator::merge_configs(&config.service_gator, &cli_scopes)
    } else {
        // Auto-configure: read + optionally create-draft for the PR's repo
        let mut sg_config = config.service_gator.clone();
        let owner_repo = format!("{}/{}", pr_ref.owner, pr_ref.repo);

        match pr_ref.forge_type {
            forge::ForgeType::GitHub => {
                // If --service-gator-ro is set, only grant read access
                let (create_draft, push_new_branch) = if opts.service_gator_ro {
                    (false, false)
                } else {
                    (true, true)
                };
                sg_config.gh.repos.insert(
                    owner_repo.clone(),
                    config::GhRepoPermission {
                        read: true,
                        create_draft,
                        pending_review: false,
                        push_new_branch,
                        write: false,
                    },
                );
                if opts.service_gator_ro {
                    tracing::debug!("Auto-enabled service-gator for {} (read-only)", owner_repo);
                } else {
                    tracing::debug!(
                        "Auto-enabled service-gator for {} (read + push-new-branch + draft PRs)",
                        owner_repo
                    );
                }
            }
            forge::ForgeType::GitLab | forge::ForgeType::Forgejo | forge::ForgeType::Gitea => {
                // TODO: Add GitLab/Forgejo/Gitea support to service-gator config
                tracing::debug!(
                    "Auto service-gator not yet supported for {} ({})",
                    pr_ref.forge_type,
                    owner_repo
                );
            }
        }
        sg_config
    };

    let enable_gator = service_gator_config.is_enabled();

    // Create source from PR info
    let source = pod::WorkspaceSource::PullRequest(pr_info);

    // Build extra labels for task description, mode, and instance
    let mut extra_labels = Vec::new();
    extra_labels.push((
        "io.devaipod.mode".to_string(),
        opts.mode.as_str().to_string(),
    ));
    if let Some(ref task_desc) = opts.task {
        extra_labels.push(("io.devaipod.task".to_string(), task_desc.clone()));
    }
    if let Some(ref title) = opts.title {
        extra_labels.push(("io.devaipod.title".to_string(), title.clone()));
    }
    if let Some(instance_id) = get_instance_id() {
        extra_labels.push((INSTANCE_LABEL_KEY.to_string(), instance_id));
    }

    let source_dirs = canonicalize_source_dirs(&opts.source_dirs);

    // Create agent backend
    let (agent_name, agent_profile) = config.agent.resolve_profile(None);
    let backend = create_agent_backend(&agent_name, agent_profile, &config.agent)?;

    // Create the pod
    tracing::debug!("Creating pod '{}'...", pod_name);
    let devaipod_pod = pod::DevaipodPod::create(
        &podman,
        temp_path, // Use temp path for image building context
        &devcontainer_config,
        &pod_name,
        enable_gator,
        config,
        &source,
        &extra_labels,
        Some(&service_gator_config),
        effective_image.as_deref(),
        opts.service_gator_image.as_deref(),
        opts.task.as_deref(),
        config.orchestration.is_enabled(),
        config.orchestration.worker.gator.clone(),
        &source_dirs,
        backend.as_ref(),
    )
    .await
    .context("Failed to create devaipod pod")?;

    finalize_pod(&podman, &devaipod_pod, &devcontainer_config, config).await?;

    // Write workspace state file for PR workspaces (best-effort).
    write_workspace_state(
        &pod_name,
        pr_ref.pr_url(),
        &source_dirs,
        opts.task.as_deref(),
        opts.title.as_deref(),
    );

    drop(podman);

    Ok(CreateResult { pod_name })
}

// =============================================================================
// Command Implementations
// =============================================================================

/// Create/start a workspace with AI agent
///
/// This is a thin wrapper around `create_workspace` that handles:
/// - Dry-run mode (prints what would be created)
/// - Optional exec into the agent container after creation
///
/// Uses podman-native multi-container setup with a pod containing:
/// - agent: Container running opencode serve
/// - api: Pod-api sidecar for git/PTY endpoints
/// - gator (optional): Service-gator MCP server container
async fn cmd_up(config: &config::Config, source: Option<&str>, opts: UpOptions) -> Result<()> {
    // Handle dry-run mode
    if opts.dry_run {
        return cmd_dry_run(config, source, &opts).await;
    }

    // Create the workspace using the common create function
    let create_opts = CreateOptions::from_up_options(&opts);
    let result = create_workspace(config, source, &create_opts).await?;

    // Optionally exec into the agent container - go directly to bash
    if opts.exec_after {
        return cmd_exec(
            &result.pod_name,
            AttachTarget::Agent,
            false,
            &["bash".to_string()],
        )
        .await;
    }

    Ok(())
}

/// Run an agent on a repository with a task
///
/// This is a thin wrapper around `create_workspace` that:
/// - Sets mode to Run (for tracking)
/// - Does not attach by default (async execution)
///
/// It creates a workspace and starts the agent with the task, then returns
/// immediately. Use `devaipod attach <workspace>` to monitor the agent's progress.
///
/// Returns the pod name for optional follow-up operations (e.g., attach).
#[allow(clippy::too_many_arguments)]
async fn cmd_run(
    config: &config::Config,
    source: Option<&str>,
    command: Option<&str>,
    image: Option<&str>,
    explicit_name: Option<&str>,
    service_gator_scopes: &[String],
    service_gator_image: Option<&str>,
    service_gator_ro: bool,
    mcp_servers: &[String],
    devcontainer_json: Option<&str>,
    use_default_devcontainer: bool,
    title: Option<&str>,
    source_dirs: &[PathBuf],
) -> Result<String> {
    // Build CreateOptions with mode=Run
    let create_opts = CreateOptions {
        task: command.map(|s| s.to_string()),
        title: title.map(|s| s.to_string()),
        image: image.map(|s| s.to_string()),
        name: explicit_name.map(|s| s.to_string()),
        service_gator_scopes: service_gator_scopes.to_vec(),
        service_gator_image: service_gator_image.map(|s| s.to_string()),
        mode: WorkspaceMode::Run,
        service_gator_ro,
        mcp_servers: mcp_servers.to_vec(),
        devcontainer_json: devcontainer_json.map(|s| s.to_string()),
        use_default_devcontainer,
        source_dirs: source_dirs.to_vec(),
    };

    // Create the workspace - no SSH by default (async execution)
    let result = create_workspace(config, source, &create_opts).await?;

    // The initial task message is now sent by the pod-api sidecar, which reads
    // the task file written during workspace creation and sends it to opencode
    // once the server is reachable. This makes startup self-contained — the CLI
    // doesn't need to poll the agent for health.
    if command.is_some() {
        let short = strip_pod_prefix(&result.pod_name);
        println!(
            "Workspace created. Agent will start working shortly.\n\
             Attach with: devaipod attach {}",
            short
        );
    }

    Ok(result.pod_name)
}

/// Wait for the agent to be healthy and send an initial message to start working
///
/// This is called after workspace creation when a task was provided.
/// The task content is sent directly in the initial message to ensure the agent
/// receives it even if opencode started before the config file was written.
///
/// When orchestration is enabled, includes mandatory orchestration instructions
/// directly in the message to ensure the agent follows the delegation workflow.
fn start_agent_task(pod_name: &str, task: &str, enable_orchestration: bool) -> Result<()> {
    tracing::info!("Waiting for agent to be ready...");

    // Wait for the agent to be healthy (up to 60 seconds)
    let max_attempts = 30;
    let poll_interval = std::time::Duration::from_secs(2);

    for attempt in 1..=max_attempts {
        match check_agent_health(pod_name) {
            Some(true) => {
                tracing::debug!("Agent healthy after {} attempts", attempt);
                break;
            }
            Some(false) => {
                if attempt == max_attempts {
                    bail!(
                        "Agent did not become healthy after {} seconds. Check logs with: devaipod logs {}",
                        max_attempts * 2,
                        strip_pod_prefix(pod_name)
                    );
                }
                std::thread::sleep(poll_interval);
            }
            None => {
                // Container may not be running yet
                if attempt == max_attempts {
                    bail!(
                        "Could not check agent health. Is the pod running? Check with: devaipod list"
                    );
                }
                std::thread::sleep(poll_interval);
            }
        }
    }

    // Send the initial message with the task directly included.
    // We include the full task in the message because opencode may have started
    // before the config file (with instructions path) was written.
    tracing::info!("Starting agent on task...");

    // Include orchestration instructions directly in the user message when enabled,
    // to ensure they have high priority.
    let orchestration_section = if enable_orchestration {
        format!(
            r#"

---

{}

---

"#,
            prompt::orchestration_instructions()
        )
    } else {
        String::new()
    };

    let initial_message = format!(
        r#"# Your Task

{task}{orchestration_section}
Please start working on this task now. Make commits with clear messages as you work."#,
        task = task,
        orchestration_section = orchestration_section
    );

    // Create session and send message, retrying a few times since the
    // opencode API may not be fully ready even after the health check passes.
    let short = strip_pod_prefix(pod_name);
    let mut last_err = None;
    for attempt in 1..=5 {
        match send_initial_message(pod_name, &initial_message) {
            Ok(_) => {
                println!(
                    "Agent started on task. Attach with: devaipod attach {}",
                    short
                );
                return Ok(());
            }
            Err(e) => {
                tracing::debug!("send_initial_message attempt {}/5 failed: {}", attempt, e);
                last_err = Some(e);
                if attempt < 5 {
                    std::thread::sleep(std::time::Duration::from_secs(2));
                }
            }
        }
    }
    // All retries failed — report loudly
    let e = last_err.unwrap();
    eprintln!(
        "Warning: failed to send initial message to agent: {:#}\n\
         The workspace was created but the agent may be idle.\n\
         To start manually: devaipod opencode {} send 'Start working on your task'",
        e, short
    );
    Ok(())
}

/// Send an initial message to the agent to start working
///
/// Creates a new session and sends the message asynchronously (without waiting
/// for the LLM response). This returns immediately after the request is sent.
fn send_initial_message(pod_name: &str, message: &str) -> Result<()> {
    // Create a new session (this is fast, we can wait for it)
    let session = opencode_api_post(pod_name, "/session", "{}")?;
    let session_id = session
        .get("id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| color_eyre::eyre::eyre!("Failed to get session ID from response"))?;

    // Build message payload
    let payload = serde_json::json!({
        "parts": [{"type": "text", "text": message}]
    });

    // Fire off the message request asynchronously - don't wait for LLM response.
    // The opencode /message endpoint blocks until the LLM finishes, which can take
    // minutes. We spawn the curl process and don't wait for it.
    send_message_async(pod_name, session_id, &payload.to_string())?;

    tracing::debug!("Sent initial message to session {}", session_id);
    Ok(())
}

/// Send a message to opencode asynchronously (fire-and-forget)
///
/// Spawns a curl process in the background and returns immediately.
/// Used for starting agent tasks where we don't need to wait for the response.
fn send_message_async(pod_name: &str, session_id: &str, payload: &str) -> Result<()> {
    let agent_container = format!("{}-agent", pod_name);
    let url = format!(
        "http://localhost:{}/session/{}/message",
        pod::OPENCODE_PORT,
        session_id
    );

    // Use spawn() instead of output() to not wait for the curl process.
    // The curl command runs in the container background.
    // Suppress stdout to avoid printing the exec session ID.
    podman_command()
        .args([
            "exec",
            "-d", // detached mode - run in background
            &agent_container,
            "curl",
            "-sf",
            "-X",
            "POST",
            "-H",
            "Content-Type: application/json",
            "-d",
            payload,
            &url,
        ])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .context("Failed to spawn curl process for async message")?;

    Ok(())
}

/// Handle dry-run mode for the up command
///
/// Prints what would be created without actually creating anything.
async fn cmd_dry_run(
    config: &config::Config,
    source: Option<&str>,
    opts: &UpOptions,
) -> Result<()> {
    let source = match source {
        Some(s) => s,
        None => {
            let pod_name = if let Some(ref name) = opts.name {
                normalize_pod_name(name)
            } else {
                make_pod_name("scratch")
            };
            tracing::info!("Dry run mode - would create scratch pod '{}'", pod_name);
            tracing::info!("  source: (none — scratch workspace)");
            if let Some(ref img) = opts.image {
                tracing::info!("  image: {}", img);
            }
            if let Some(ref task) = opts.task {
                tracing::info!("  Task: {}", task);
            }
            return Ok(());
        }
    };
    // Dispatch based on source type for dry-run info
    if let Some(pr_ref) = forge::parse_pr_url(source) {
        // PR dry-run
        let pr_info = forge::fetch_pr_info(&pr_ref, Some(config))
            .await
            .context("Failed to fetch PR information")?;

        let pod_name = if let Some(ref name) = opts.name {
            normalize_pod_name(name)
        } else {
            make_pr_pod_name(&pr_ref.repo, pr_ref.number)
        };

        tracing::info!("Dry run mode - would create pod '{}'", pod_name);
        tracing::info!("  PR: {}", pr_info.pr_ref.short_display());
        tracing::info!("  Head: {} @ {}", pr_info.head_ref, &pr_info.head_sha[..8]);
        tracing::info!("  Clone URL: {}", pr_info.head_clone_url);
        if opts.image.is_some() {
            tracing::info!("  devcontainer: (none, using image override)");
        }
    } else if source.starts_with("http://")
        || source.starts_with("https://")
        || source.starts_with("git@")
    {
        // Remote URL dry-run
        let repo_name = git::extract_repo_name(source).unwrap_or_else(|| "project".to_string());
        let pod_name = if let Some(ref name) = opts.name {
            normalize_pod_name(name)
        } else {
            make_pod_name(&repo_name)
        };

        // Parse service-gator config for dry-run info
        let service_gator_config = if !opts.service_gator_scopes.is_empty() {
            let cli_scopes = service_gator::parse_scopes(&opts.service_gator_scopes)
                .context("Failed to parse --service-gator scopes")?;
            service_gator::merge_configs(&config.service_gator, &cli_scopes)
        } else {
            config.service_gator.clone()
        };

        tracing::info!("Dry run mode - would create pod '{}'", pod_name);
        tracing::info!("  Remote URL: {}", source);
        if opts.image.is_none() {
            tracing::info!("  (would clone to read devcontainer.json)");
        } else {
            tracing::info!("  devcontainer: (none, using image override)");
        }
        tracing::info!("  gator enabled: {}", service_gator_config.is_enabled());
        if let Some(ref img) = opts.service_gator_image {
            tracing::info!("  gator image: {}", img);
        }
        if let Some(ref task) = opts.task {
            tracing::info!("  Task: {}", task);
        }
    } else {
        // Local path dry-run
        let source_path = std::path::Path::new(source).canonicalize().ok();
        let project_path = match source_path {
            Some(ref p) => p,
            None => {
                bail!("Path '{}' does not exist or is not accessible.", source);
            }
        };

        let project_name = project_path
            .file_name()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_else(|| "project".to_string());

        let pod_name = if let Some(ref name) = opts.name {
            normalize_pod_name(name)
        } else {
            make_pod_name(&project_name)
        };

        // Parse service-gator config for dry-run info
        let service_gator_config = if !opts.service_gator_scopes.is_empty() {
            let cli_scopes = service_gator::parse_scopes(&opts.service_gator_scopes)
                .context("Failed to parse --service-gator scopes")?;
            service_gator::merge_configs(&config.service_gator, &cli_scopes)
        } else {
            config.service_gator.clone()
        };

        let devcontainer_json_path = devcontainer::try_find_devcontainer_json(project_path);

        tracing::info!("Dry run: would create pod '{}'", pod_name);
        tracing::info!("  project: {}", project_path.display());
        if let Some(ref path) = devcontainer_json_path {
            tracing::info!("  devcontainer: {}", path.display());
        } else {
            tracing::info!("  devcontainer: (none, using image override)");
        }
        tracing::info!("  gator enabled: {}", service_gator_config.is_enabled());
        if let Some(ref img) = opts.service_gator_image {
            tracing::info!("  gator image: {}", img);
        }
    }

    Ok(())
}

// =============================================================================
// Fetch / Diff Commands
// =============================================================================

/// Find ALL git repos inside an agent's host-side workspace directory.
///
/// Resolves the pod's workspace directory and delegates to the shared
/// [`agent_dir::find_git_repos_in_dir`]. Returns an error if the directory
/// doesn't exist or contains no git repos.
fn find_all_agent_git_repos(pod_name: &str) -> Result<Vec<(String, PathBuf)>> {
    let base = agent_dir::agent_workdir_base()?;
    let pod_dir = base.join(pod_name);

    if !pod_dir.exists() {
        let pod_exists = podman_command()
            .args(["pod", "exists", pod_name])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if pod_exists {
            bail!(
                "Workspace '{}' has no host directory (possibly a legacy volume-based workspace). \
                 Try recreating it with `devaipod delete` then `devaipod up`.",
                strip_pod_prefix(pod_name)
            );
        } else {
            bail!(
                "Workspace '{}' not found. Run `devaipod list` to see available workspaces.",
                strip_pod_prefix(pod_name)
            );
        }
    }

    let repos = agent_dir::find_git_repos_in_dir(&pod_dir);

    if repos.is_empty() {
        bail!(
            "No git repository found in agent workspace at {}. \
             The agent may not have cloned the repo yet.",
            pod_dir.display()
        );
    }

    Ok(repos)
}

/// Check whether the given path is a git repository.
fn is_git_repo(path: &Path) -> bool {
    ProcessCommand::new("git")
        .arg("-C")
        .arg(path)
        .args(["rev-parse", "--git-dir"])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

/// Resolve the local git repo that corresponds to a workspace.
///
/// Tries in order:
/// 1. CWD, if it is a git repo whose source matches the workspace
/// 2. Auto-detected from source mounts (e.g. `/mnt/src/github/org/repo`)
/// 3. Error with a helpful message
fn resolve_target_repo(pod_name: &str) -> Result<PathBuf> {
    let base = agent_dir::agent_workdir_base()?;
    let pod_dir = base.join(pod_name);
    let state = agent_dir::WorkspaceState::load(&pod_dir)?;

    let cwd = std::env::current_dir().context("Failed to get current directory")?;

    // If CWD is a git repo that matches the workspace source, use it.
    if is_git_repo(&cwd) {
        if let Some(ref state) = state {
            if source_matches_repo(&state.source, &state.source_dirs, &cwd) {
                return Ok(cwd);
            }
        } else {
            // No workspace state — can't validate, use CWD as before.
            return Ok(cwd);
        }
    }

    // CWD doesn't match. Try to find the repo from source mounts.
    let state = state.as_ref();
    let source = state.map(|s| s.source.as_str()).unwrap_or("");
    if let Some(suffix) = extract_repo_suffix(source) {
        // The suffix is like "github.com/org/repo". Build candidate paths:
        // 1. As-is: /mnt/src/github.com/org/repo
        // 2. Strip TLD from host: /mnt/src/github/org/repo (common convention)
        let mut suffixes = vec![suffix.clone()];
        if let Some(pos) = suffix.find('/') {
            let host_part = &suffix[..pos];
            if let Some(stripped) = host_part.split('.').next() {
                let alt = format!("{}{}", stripped, &suffix[pos..]);
                if alt != suffix {
                    suffixes.push(alt);
                }
            }
        }

        let config = config::load_config(None)?;
        for resolved in config.resolve_sources() {
            // Inside the container, sources are mounted at /mnt/<name>
            let mount_point = PathBuf::from(format!("/mnt/{}", resolved.name));
            for s in &suffixes {
                let candidate = mount_point.join(s);
                if candidate.exists() && is_git_repo(&candidate) {
                    tracing::info!(
                        "Auto-resolved repo for workspace '{}' at {}",
                        strip_pod_prefix(pod_name),
                        candidate.display()
                    );
                    return Ok(candidate);
                }
            }
        }
    }

    // Nothing worked — produce a helpful error.
    if is_git_repo(&cwd) {
        bail!(
            "Current directory ({}) does not match workspace '{}' (source: {}). \
             Run this from the repo that the workspace was created for.",
            cwd.display(),
            strip_pod_prefix(pod_name),
            source,
        );
    } else {
        bail!(
            "Not inside a git repo, and could not auto-detect the local repo \
             for workspace '{}' (source: {}). \
             Run this from the repo that the workspace was created for.",
            strip_pod_prefix(pod_name),
            source,
        );
    }
}

/// Fetch agent commits into the matching local git repo.
///
/// Discovers all git repos in the agent's workspace and fetches each one.
/// For single-repo workspaces the remote is named `devaipod/<workspace>`;
/// for multi-repo workspaces each remote is `devaipod/<workspace>/<repo>`.
///
/// The target local repo is resolved from the workspace state — if CWD
/// matches the workspace source it is used directly; otherwise the correct
/// repo is auto-detected from configured source mounts.
///
/// When the agent container is running, uses `ext::` git transport to tunnel
/// git-upload-pack through `podman exec`. This avoids the broken-alternates
/// problem with workspace-v2 repos whose git alternates point to
/// container-internal paths that don't exist on the host.
///
/// Falls back to direct filesystem access when the container is not running
/// (works for self-contained repos without alternates).
///
/// Returns the path to the local repo where branches were fetched.
fn cmd_fetch(pod_name: &str) -> Result<PathBuf> {
    let target_repo = resolve_target_repo(pod_name)?;

    let repos = find_all_agent_git_repos(pod_name)?;
    let short_name = strip_pod_prefix(pod_name);

    // Check if the agent container is running for ext:: transport
    let agent_container = get_attach_container_name(pod_name, AttachTarget::Agent);
    let container_running = agent_dir::is_container_running(&agent_container);

    if container_running {
        tracing::debug!(
            "Agent container '{}' is running, using ext:: transport",
            agent_container
        );
    } else {
        tracing::debug!(
            "Agent container '{}' is not running, using direct filesystem access",
            agent_container
        );
    }

    for (repo_name, _agent_repo) in &repos {
        let remote_name = if repos.len() == 1 {
            format!("devaipod/{}", short_name)
        } else {
            format!("devaipod/{}/{}", short_name, repo_name)
        };

        // Record pre-fetch HEAD so we can detect changes
        let pre_fetch_ref = resolve_remote_default_ref_in(&remote_name, &target_repo)
            .ok()
            .flatten();
        let pre_fetch_sha = pre_fetch_ref.as_ref().and_then(|r| {
            ProcessCommand::new("git")
                .arg("-C")
                .arg(&target_repo)
                .args(["rev-parse", r])
                .output()
                .ok()
                .filter(|o| o.status.success())
                .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        });

        let workspace_path = format!("/workspaces/{}", repo_name);
        let _result = if container_running {
            // Use ext:: transport through podman exec into the running agent
            tracing::info!(
                "Fetching from agent container: {}:{}",
                agent_container,
                workspace_path
            );
            agent_dir::harvest_one_repo_via_exec(
                &target_repo,
                &agent_container,
                &workspace_path,
                &remote_name,
            )?
        } else {
            // Agent is stopped — spawn a transient container that mounts the
            // workspace volume + host-side workspace dir so alternates resolve.
            let image = pod::detect_self_image();
            tracing::info!(
                "Agent not running; fetching via transient container for {}",
                pod_name
            );
            agent_dir::harvest_one_repo_via_transient(
                &target_repo,
                pod_name,
                &workspace_path,
                &remote_name,
                &image,
            )?
        };

        // Detect what changed and show a useful summary
        let post_fetch_ref = resolve_remote_default_ref_in(&remote_name, &target_repo)
            .ok()
            .flatten();

        let Some(ref full_ref) = post_fetch_ref else {
            println!("No branches found for remote '{}'.", remote_name);
            continue;
        };

        let post_fetch_sha = ProcessCommand::new("git")
            .arg("-C")
            .arg(&target_repo)
            .args(["rev-parse", full_ref])
            .output()
            .ok()
            .filter(|o| o.status.success())
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string());

        let is_new = pre_fetch_sha.is_none();
        let changed = is_new || pre_fetch_sha.as_ref() != post_fetch_sha.as_ref();

        println!();
        if !changed {
            println!("Already up to date ({}).", short_name);
        } else {
            // Count new commits
            let new_commits = if is_new {
                // First fetch — count all commits on the agent branch
                ProcessCommand::new("git")
                    .arg("-C")
                    .arg(&target_repo)
                    .args(["rev-list", "--count", full_ref])
                    .output()
                    .ok()
                    .filter(|o| o.status.success())
                    .and_then(|o| {
                        String::from_utf8_lossy(&o.stdout)
                            .trim()
                            .parse::<usize>()
                            .ok()
                    })
            } else {
                // Subsequent fetch — count commits between old and new HEAD
                let range = format!(
                    "{}..{}",
                    pre_fetch_sha.as_deref().unwrap_or(""),
                    post_fetch_sha.as_deref().unwrap_or("")
                );
                ProcessCommand::new("git")
                    .arg("-C")
                    .arg(&target_repo)
                    .args(["rev-list", "--count", &range])
                    .output()
                    .ok()
                    .filter(|o| o.status.success())
                    .and_then(|o| {
                        String::from_utf8_lossy(&o.stdout)
                            .trim()
                            .parse::<usize>()
                            .ok()
                    })
            };

            if let Some(n) = new_commits {
                if is_new {
                    println!("Fetched {} commit(s) from {}.", n, short_name);
                } else {
                    println!("Fetched {} new commit(s) from {}.", n, short_name);
                }
            } else {
                println!("Fetched new commits from {}.", short_name);
            }

            // Show diffstat (agent changes vs merge-base with current branch)
            let merge_base = ProcessCommand::new("git")
                .arg("-C")
                .arg(&target_repo)
                .args(["merge-base", "HEAD", full_ref])
                .output()
                .ok()
                .filter(|o| o.status.success())
                .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string());

            if let Some(base) = merge_base {
                let stat = ProcessCommand::new("git")
                    .arg("-C")
                    .arg(&target_repo)
                    .args(["diff", "--stat", &format!("{}..{}", base, full_ref)])
                    .output()
                    .ok()
                    .filter(|o| o.status.success())
                    .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string());

                if let Some(ref s) = stat {
                    if !s.is_empty() {
                        println!();
                        println!("{}", s);
                    }
                }
            }
        }

        // Always show the commands for further inspection
        println!();
        println!("  git log {}", full_ref);
        println!("  git diff HEAD...{}", full_ref);
        if repos.len() == 1 {
            println!("  devaipod diff {}", short_name);
        }
    }

    Ok(target_repo)
}

/// Resolve the default branch for a remote, returning the fully-qualified
/// `refs/remotes/...` path to avoid ambiguity.
///
/// Tries in order: the remote's symbolic HEAD, then `main`, then `master`,
/// then falls back to the first available branch. Returns `None` if the remote
/// has no branches.
///
/// Returns a fully-qualified ref like `refs/remotes/devaipod/ws/main` that
/// git will resolve unambiguously even when the remote name contains slashes.
/// Resolve the default branch for a remote in the given repo, returning the
/// fully-qualified `refs/remotes/...` path to avoid ambiguity.
fn resolve_remote_default_ref_in(remote_name: &str, repo: &Path) -> Result<Option<String>> {
    // Try the remote's symbolic HEAD (set by `git clone` or `git remote set-head`)
    let head_ref = format!("refs/remotes/{}/HEAD", remote_name);
    let head_output = ProcessCommand::new("git")
        .arg("-C")
        .arg(repo)
        .args(["symbolic-ref", &head_ref])
        .output()
        .ok();
    if let Some(output) = head_output.filter(|o| o.status.success()) {
        let target = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if !target.is_empty() {
            return Ok(Some(target));
        }
    }

    // Try well-known branch names
    for branch in ["main", "master"] {
        let ref_name = format!("refs/remotes/{}/{}", remote_name, branch);
        let verify = ProcessCommand::new("git")
            .arg("-C")
            .arg(repo)
            .args(["rev-parse", "--verify", &ref_name])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
        if verify.is_ok_and(|s| s.success()) {
            return Ok(Some(ref_name));
        }
    }

    // Fall back to the first available branch (skip HEAD symref)
    let branch_output = ProcessCommand::new("git")
        .arg("-C")
        .arg(repo)
        .args([
            "for-each-ref",
            "--format=%(refname)",
            &format!("refs/remotes/{}/", remote_name),
        ])
        .output()
        .context("Failed to list remote refs")?;

    if branch_output.status.success() {
        let refs = String::from_utf8_lossy(&branch_output.stdout);
        if let Some(first) = refs
            .lines()
            .map(|l| l.trim())
            .find(|l| !l.is_empty() && !l.ends_with("/HEAD"))
        {
            return Ok(Some(first.to_string()));
        }
    }

    Ok(None)
}

/// Show diff of agent changes relative to current branch
fn cmd_diff(pod_name: &str, stat: bool) -> Result<()> {
    // Fetch first — resolve_target_repo validates CWD / auto-detects the repo
    let target_repo = cmd_fetch(pod_name)?;

    let short_name = strip_pod_prefix(pod_name);
    let remote_name = format!("devaipod/{}", short_name);

    // Find the remote's default branch using fully-qualified refs to avoid
    // ambiguity (remote names with slashes can confuse git's ref resolution).
    let remote_ref = resolve_remote_default_ref_in(&remote_name, &target_repo)?;
    let Some(remote_ref) = remote_ref else {
        println!("No changes from agent yet.");
        return Ok(());
    };

    // Check if there are any commits beyond the merge base
    let merge_base = ProcessCommand::new("git")
        .arg("-C")
        .arg(&target_repo)
        .args(["merge-base", "HEAD", &remote_ref])
        .output()
        .context("Failed to find merge base")?;

    if merge_base.status.success() {
        let base_sha = String::from_utf8_lossy(&merge_base.stdout)
            .trim()
            .to_string();
        let remote_sha_output = ProcessCommand::new("git")
            .arg("-C")
            .arg(&target_repo)
            .args(["rev-parse", &remote_ref])
            .output()
            .context("Failed to get remote HEAD")?;

        if remote_sha_output.status.success() {
            let remote_sha = String::from_utf8_lossy(&remote_sha_output.stdout)
                .trim()
                .to_string();
            if base_sha == remote_sha {
                println!("No changes from agent yet.");
                return Ok(());
            }
        }
    }

    // Run the diff
    let mut diff_args = vec![
        "-C".to_string(),
        target_repo.to_string_lossy().to_string(),
        "diff".to_string(),
    ];
    if stat {
        diff_args.push("--stat".to_string());
    }
    diff_args.push(format!("HEAD...{}", remote_ref));

    let status = ProcessCommand::new("git")
        .args(&diff_args)
        .status()
        .context("Failed to run git diff")?;

    if !status.success() {
        bail!("git diff failed");
    }

    Ok(())
}

/// Apply agent changes to the current branch.
///
/// Fetches the latest commits (like `cmd_fetch`), then merges or cherry-picks
/// the agent's branch into the current branch.
fn cmd_apply(pod_name: &str, cherry_pick: bool) -> Result<()> {
    // Fetch first to ensure we have the latest
    let target_repo = cmd_fetch(pod_name)?;

    let short_name = strip_pod_prefix(pod_name);
    let remote_name = format!("devaipod/{}", short_name);

    let ref_name = resolve_remote_default_ref_in(&remote_name, &target_repo)?.ok_or_else(|| {
        color_eyre::eyre::eyre!(
            "No branches found for remote '{}'. The agent may not have made any commits.",
            remote_name
        )
    })?;

    // Count how many commits the agent is ahead
    let ahead_output = ProcessCommand::new("git")
        .arg("-C")
        .arg(&target_repo)
        .args(["rev-list", "--count", &format!("HEAD..{}", ref_name)])
        .output()
        .context("Failed to count commits")?;

    let count: usize = String::from_utf8_lossy(&ahead_output.stdout)
        .trim()
        .parse()
        .unwrap_or(0);

    if count == 0 {
        println!("Already up to date with {}.", ref_name);
        return Ok(());
    }

    println!("Applying {} commit(s) from {}...", count, ref_name);

    if cherry_pick {
        let list_output = ProcessCommand::new("git")
            .arg("-C")
            .arg(&target_repo)
            .args(["rev-list", "--reverse", &format!("HEAD..{}", ref_name)])
            .output()
            .context("Failed to list commits")?;

        let sha_strings: Vec<String> = String::from_utf8_lossy(&list_output.stdout)
            .lines()
            .filter(|l| !l.is_empty())
            .map(|s| s.to_string())
            .collect();

        for sha in &sha_strings {
            let result = ProcessCommand::new("git")
                .arg("-C")
                .arg(&target_repo)
                .args(["cherry-pick", sha])
                .status()
                .context("Failed to run git cherry-pick")?;

            if !result.success() {
                eprintln!();
                eprintln!(
                    "Cherry-pick of {} failed. Resolve conflicts, then run:",
                    sha
                );
                eprintln!("  git cherry-pick --continue");
                return Ok(());
            }
        }
        println!("Applied {} commit(s) via cherry-pick.", sha_strings.len());
    } else {
        let result = ProcessCommand::new("git")
            .arg("-C")
            .arg(&target_repo)
            .args([
                "merge",
                "--no-ff",
                &ref_name,
                "-m",
                &format!("Merge agent work from {}", short_name),
            ])
            .status()
            .context("Failed to run git merge")?;

        if !result.success() {
            eprintln!();
            eprintln!("Merge conflicts detected. Resolve them, then run:");
            eprintln!("  git merge --continue");
            return Ok(());
        }
        println!("Merged {} commit(s) from {}.", count, ref_name);
    }

    Ok(())
}

// =============================================================================
// Repo-level commands: status, push, pr
// =============================================================================

/// Show a comprehensive overview of agent work for the current repo.
///
/// Displays workspace status, harvested branches, push status, and PRs.
fn cmd_repo_status() -> Result<()> {
    let cwd = std::env::current_dir().context("Failed to get current directory")?;
    if !is_git_repo(&cwd) {
        bail!("Not a git repo. Run this from your source repository.");
    }

    let repo_name = detect_repo_name().unwrap_or_else(|_| "(unknown)".to_string());
    let repo_root = repo_root_path()?;
    let current_branch = current_branch_name().unwrap_or_else(|_| "(detached)".to_string());

    println!("Repo: {} ({})", repo_name, repo_root.display());
    println!("Branch: {}", current_branch);
    println!();

    // 1. Find agent workspaces for this repo
    let workspaces = find_workspaces_for_repo(&repo_root);
    if !workspaces.is_empty() {
        println!("Agent workspaces:");
        for ws in &workspaces {
            // Derive a display status: use completion_status if set,
            // otherwise check if the pod is actually running.
            let display_status = ws.completion_status.clone().unwrap_or_else(|| {
                let pod_status = podman_command()
                    .args(["pod", "inspect", "--format", "{{.State}}", &ws.pod_name])
                    .output()
                    .ok()
                    .filter(|o| o.status.success())
                    .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string());
                match pod_status.as_deref() {
                    Some("Running") => "running".to_string(),
                    Some("Exited") | Some("Stopped") => "exited".to_string(),
                    Some("Created") => "created".to_string(),
                    _ => "pending".to_string(),
                }
            });
            let status_icon = match display_status.as_str() {
                "done" => "\u{25c9}",    // ◉
                "active" => "\u{25cf}",  // ●
                "running" => "\u{25cf}", // ●
                _ => "\u{25cb}",         // ○
            };
            let commit_info = if ws.commit_count > 0 {
                format!("{} commits", ws.commit_count)
            } else {
                "\u{2014}".to_string() // —
            };
            let task = ws
                .task_summary
                .as_deref()
                .map(|t| format!("  \"{}\"", t))
                .unwrap_or_default();
            println!(
                "  {} {:<30} {:<8} {:<12} {}{}",
                status_icon, ws.short_name, display_status, commit_info, ws.age_display, task,
            );
        }
        println!();
    }

    // 2. Show harvested branches (devaipod/* remotes)
    let branches = find_devaipod_branches();
    if !branches.is_empty() {
        // Try to get PR info via gh CLI (best effort, single call for all branches)
        let prs = list_prs_for_repo();

        println!("Harvested branches:");
        for branch in &branches {
            println!("  {}", branch.ref_name);
            if branch.ahead > 0 {
                println!(
                    "    {} commit{} ahead of {}",
                    branch.ahead,
                    if branch.ahead == 1 { "" } else { "s" },
                    branch.base_branch,
                );
            }
            match &branch.push_status {
                RepoPushStatus::NotPushed => println!("    Not pushed"),
                RepoPushStatus::Pushed(remote_ref) => {
                    println!("    Pushed to {}", remote_ref)
                }
            }
            if let Some(pr) = match_pr(&branch.ref_name, &prs) {
                println!(
                    "    PR #{}: \"{}\" ({})",
                    pr.number,
                    pr.title,
                    pr.state_display()
                );
            }
            println!();
        }
    } else if workspaces.is_empty() {
        println!("No agent workspaces or harvested branches found for this repo.");
        println!("Run `devaipod up . \"your task\"` to launch an agent.");
    }

    Ok(())
}

/// Push agent branch to origin.
fn cmd_push(pod_name: &str) -> Result<()> {
    // Ensure we have the latest
    let target_repo = cmd_fetch(pod_name)?;

    let short_name = strip_pod_prefix(pod_name);
    let remote_name = format!("devaipod/{}", short_name);

    let full_ref = resolve_remote_default_ref_in(&remote_name, &target_repo)?.ok_or_else(|| {
        color_eyre::eyre::eyre!(
            "No branches found for remote '{}'. The agent may not have made any commits.",
            remote_name
        )
    })?;

    // Extract the branch name from the full ref for the push target.
    // e.g., "refs/remotes/devaipod/ws/devaipod/fix-auth" → "devaipod/fix-auth"
    let push_branch = full_ref
        .strip_prefix(&format!("refs/remotes/{}/", remote_name))
        .unwrap_or(&full_ref);

    println!("Pushing {} to origin/{}...", full_ref, push_branch);

    let result = ProcessCommand::new("git")
        .arg("-C")
        .arg(&target_repo)
        .args([
            "push",
            "origin",
            &format!("{}:refs/heads/{}", full_ref, push_branch),
        ])
        .status()
        .context("Failed to run git push")?;

    if !result.success() {
        bail!("Push failed. Check your permissions and try again.");
    }

    println!("Pushed to origin/{}", push_branch);
    Ok(())
}

/// Create a pull request from agent work.
///
/// Pushes the branch first, then runs `gh pr create`.
fn cmd_pr(pod_name: &str, draft: bool, title: Option<&str>) -> Result<()> {
    // Push first (handles repo resolution + fetch)
    cmd_push(pod_name)?;

    // Re-resolve the target repo for git log / gh pr commands
    let target_repo = resolve_target_repo(pod_name)?;
    let short_name = strip_pod_prefix(pod_name);
    let remote_name = format!("devaipod/{}", short_name);

    let full_ref = resolve_remote_default_ref_in(&remote_name, &target_repo)?.ok_or_else(|| {
        color_eyre::eyre::eyre!(
            "No branches found for remote '{}'. The agent may not have made any commits.",
            remote_name
        )
    })?;

    let push_branch = full_ref
        .strip_prefix(&format!("refs/remotes/{}/", remote_name))
        .unwrap_or(&full_ref);

    // Auto-generate title from commit log if not provided
    let pr_title = if let Some(t) = title {
        t.to_string()
    } else {
        let log_output = ProcessCommand::new("git")
            .arg("-C")
            .arg(&target_repo)
            .args(["log", "--format=%s", "-1", &full_ref])
            .output()
            .context("Failed to get commit message for PR title")?;
        String::from_utf8_lossy(&log_output.stdout)
            .trim()
            .to_string()
    };

    let mut gh_args = vec![
        "pr".to_string(),
        "create".to_string(),
        "--head".to_string(),
        push_branch.to_string(),
        "--title".to_string(),
        pr_title,
    ];

    if draft {
        gh_args.push("--draft".to_string());
    }

    // Fill the body with the commit log
    let body_output = ProcessCommand::new("git")
        .arg("-C")
        .arg(&target_repo)
        .args(["log", "--format=- %s", &format!("HEAD..{}", full_ref)])
        .output()
        .ok();

    let body = body_output
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_default();

    if !body.is_empty() {
        gh_args.push("--body".to_string());
        gh_args.push(body);
    }

    println!("Creating pull request...");

    let result = ProcessCommand::new("gh")
        .args(&gh_args)
        .status()
        .context("Failed to run `gh pr create`. Is the GitHub CLI installed and authenticated?")?;

    if !result.success() {
        bail!("gh pr create failed. Check the output above for details.");
    }

    Ok(())
}

// ── Repo-status helpers ──────────────────────────────────────────────

/// Extract org/repo from the origin remote URL.
fn detect_repo_name() -> Result<String> {
    let output = ProcessCommand::new("git")
        .args(["remote", "get-url", "origin"])
        .output()
        .context("Failed to get origin URL")?;
    if !output.status.success() {
        bail!("No 'origin' remote configured");
    }
    let url = String::from_utf8_lossy(&output.stdout).trim().to_string();
    // Handle https://github.com/org/repo.git and git@github.com:org/repo.git
    let path = url.strip_suffix(".git").unwrap_or(&url);
    // Try to find a hosting provider hostname
    for sep in ["github.com", "gitlab.com", "codeberg.org", "bitbucket.org"] {
        if let Some(idx) = path.find(sep) {
            let after = &path[idx + sep.len()..];
            let clean = after.trim_start_matches('/').trim_start_matches(':');
            return Ok(clean.to_string());
        }
    }
    Ok(url)
}

/// Get the current branch name.
fn current_branch_name() -> Result<String> {
    let output = ProcessCommand::new("git")
        .args(["symbolic-ref", "--short", "HEAD"])
        .output()
        .context("Failed to get current branch")?;
    if !output.status.success() {
        bail!("HEAD is detached");
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

/// Get the repo root path.
pub(crate) fn repo_root_path() -> Result<PathBuf> {
    let output = ProcessCommand::new("git")
        .args(["rev-parse", "--show-toplevel"])
        .output()
        .context("Failed to get repo root")?;
    if !output.status.success() {
        bail!("Not inside a git working tree");
    }
    Ok(PathBuf::from(
        String::from_utf8_lossy(&output.stdout).trim(),
    ))
}

/// Summary of a workspace relevant to the current repo.
struct RepoWorkspaceInfo {
    /// Full pod name (e.g. `devaipod-myproject-abc123`).
    pod_name: String,
    short_name: String,
    completion_status: Option<String>,
    commit_count: usize,
    age_display: String,
    /// Truncated task description for display in choosers.
    task_summary: Option<String>,
}

/// Try to resolve a remote git URL to a local source directory path.
///
/// Searches configured `[sources]` for a directory matching the URL's
/// forge suffix (e.g. `github.com/org/repo` → `~/src/github/org/repo`).
/// Tries both the full suffix (`github.com/org/repo`) and a TLD-less
/// variant (`github/org/repo`).
fn resolve_url_to_local_source(url: &str, config: &config::Config) -> Option<PathBuf> {
    let suffix = extract_repo_suffix(url)?;
    // Trim to host/org/repo (drop extra path like /pull/123 or /issues/42)
    let parts: Vec<&str> = suffix.splitn(4, '/').collect();
    let suffix = if parts.len() >= 3 {
        format!("{}/{}/{}", parts[0], parts[1], parts[2])
    } else {
        return None; // Need at least host/org/repo
    };

    // Build candidate suffixes: canonical (github.com/org/repo) and
    // TLD-less (github/org/repo)
    let mut suffixes = vec![suffix.clone()];
    if let Some(pos) = suffix.find('/') {
        let host_part = &suffix[..pos];
        if let Some(stripped) = host_part.split('.').next() {
            let alt = format!("{}{}", stripped, &suffix[pos..]);
            if alt != suffix {
                suffixes.push(alt);
            }
        }
    }

    for resolved in config.resolve_sources() {
        // Check both the host-expanded path and the container mount point
        // (/mnt/<name>). When running inside the container, the host path
        // won't exist on disk but the mount point will.
        let candidates_bases = [
            resolved.path.clone(),
            PathBuf::from(format!("/mnt/{}", resolved.name)),
        ];
        for base in &candidates_bases {
            for s in &suffixes {
                let candidate = base.join(s);
                if candidate.join(".git").exists() || candidate.join(".git").is_file() {
                    return Some(candidate);
                }
            }
        }
    }
    None
}

/// Extract a forge-style repo suffix from a path or URL.
///
/// Given a path like `/var/home/ai/src/github/org/repo` or a URL like
/// `https://github.com/org/repo`, extracts the trailing `github.com/org/repo`
/// (or equivalent for other forges). Returns `None` if no forge host is found.
pub(crate) fn extract_repo_suffix(s: &str) -> Option<String> {
    // Strip common URL parts first
    let s = s.strip_suffix(".git").unwrap_or(s).trim_end_matches('/');
    let hosts = [
        "github.com",
        "gitlab.com",
        "codeberg.org",
        "bitbucket.org",
        "sr.ht",
        "gitea.com",
    ];
    for host in &hosts {
        // Match the host appearing as a path component (preceded by `/` or start)
        // or as a URL authority (preceded by `://` or `@`).
        if let Some(idx) = s.find(host) {
            // Grab "host/org/repo" from the match position onward
            let suffix = &s[idx..];
            return Some(suffix.to_string());
        }
    }
    // Also match TLD-less host names as path components (e.g. `/github/org/repo`
    // from container bind-mount paths like `/mnt/src/github/org/repo`).
    // Normalize to the canonical `host.tld/org/repo` form.
    let tld_less = [
        ("github", "github.com"),
        ("gitlab", "gitlab.com"),
        ("codeberg", "codeberg.org"),
        ("bitbucket", "bitbucket.org"),
        ("gitea", "gitea.com"),
    ];
    for (short, canonical) in &tld_less {
        // Must appear as a path component: preceded by `/` and followed by `/`
        let pattern = format!("/{short}/");
        if let Some(idx) = s.find(&pattern) {
            let rest = &s[idx + 1 + short.len()..]; // skip "/<short>"
            return Some(format!("{canonical}{rest}"));
        }
    }
    None
}

/// Check whether a workspace's source matches the given repo root.
///
/// Handles the container-vs-host path mismatch (e.g. `/mnt/src/github/org/repo`
/// vs `/var/home/ai/src/github/org/repo`) and URL sources by comparing the
/// forge-qualified repo suffix when direct path comparison fails.
fn source_matches_repo(source: &str, source_dirs: &[PathBuf], repo_root: &Path) -> bool {
    let repo_str = repo_root.to_string_lossy();

    // Direct path match
    if source == repo_str || source_dirs.iter().any(|d| d.to_string_lossy() == repo_str) {
        return true;
    }

    // Fall back to forge-suffix comparison
    let repo_suffix = extract_repo_suffix(&repo_str);
    if let Some(ref rs) = repo_suffix {
        if let Some(ref ss) = extract_repo_suffix(source)
            && rs == ss
        {
            return true;
        }

        // Also check source_dirs suffixes
        for d in source_dirs {
            let ds = d.to_string_lossy();
            if let Some(ref ds_suffix) = extract_repo_suffix(&ds)
                && rs == ds_suffix
            {
                return true;
            }
        }
    }

    false
}

/// Scan the workspaces directory for workspaces whose source matches this repo.
fn find_workspaces_for_repo(repo_root: &Path) -> Vec<RepoWorkspaceInfo> {
    let workspaces = match agent_dir::list_workspaces() {
        Ok(w) => w,
        Err(e) => {
            tracing::debug!("Failed to list workspaces: {e:#}");
            return Vec::new();
        }
    };

    let mut results = Vec::new();
    for (_dir_name, ws_dir, state) in &workspaces {
        let Some(state) = state else { continue };

        if !source_matches_repo(&state.source, &state.source_dirs, repo_root) {
            continue;
        }

        let short_name = strip_pod_prefix(&state.pod_name).to_string();

        // Count commits in agent workspace
        let repos = agent_dir::find_git_repos_in_dir(ws_dir);
        let commit_count: usize = repos
            .iter()
            .filter_map(|(_, rp)| {
                let output = ProcessCommand::new("git")
                    .arg("-C")
                    .arg(rp)
                    .args(["rev-list", "--count", "HEAD", "--not", "--remotes=origin"])
                    .output()
                    .ok()?;
                if output.status.success() {
                    String::from_utf8_lossy(&output.stdout)
                        .trim()
                        .parse::<usize>()
                        .ok()
                } else {
                    None
                }
            })
            .sum();

        // Format age from created timestamp
        let age_display = format_relative_time(&state.created);

        // Truncate task to ~60 chars for display
        let task_summary = state.task.as_ref().map(|t| {
            let trimmed = t.trim();
            if trimmed.len() > 60 {
                format!("{}...", &trimmed[..57])
            } else {
                trimmed.to_string()
            }
        });

        results.push(RepoWorkspaceInfo {
            pod_name: state.pod_name.clone(),
            short_name,
            completion_status: state.completion_status.clone(),
            commit_count,
            age_display,
            task_summary,
        });
    }
    results
}

/// Format an RFC 3339 timestamp as a human-readable relative time.
fn format_relative_time(rfc3339: &str) -> String {
    let Ok(ts) = chrono::DateTime::parse_from_rfc3339(rfc3339) else {
        return rfc3339.to_string();
    };
    let now = chrono::Utc::now();
    let elapsed = now.signed_duration_since(ts);

    if elapsed.num_seconds() < 60 {
        "just now".to_string()
    } else if elapsed.num_minutes() < 60 {
        let m = elapsed.num_minutes();
        format!("{m} min ago")
    } else if elapsed.num_hours() < 24 {
        let h = elapsed.num_hours();
        format!("{h} hour{} ago", if h == 1 { "" } else { "s" })
    } else {
        let d = elapsed.num_days();
        if d == 1 {
            "yesterday".to_string()
        } else {
            format!("{d} days ago")
        }
    }
}

/// Information about a harvested devaipod branch.
struct RepoBranchInfo {
    ref_name: String,
    ahead: usize,
    base_branch: String,
    push_status: RepoPushStatus,
}

enum RepoPushStatus {
    NotPushed,
    Pushed(String),
}

/// PR metadata from `gh pr list`.
#[derive(Debug, Clone)]
struct RepoPrInfo {
    number: u64,
    title: String,
    state: String,
    draft: bool,
    head_ref_name: String,
}

impl RepoPrInfo {
    fn state_display(&self) -> String {
        if self.draft {
            "draft".to_string()
        } else {
            self.state.to_lowercase()
        }
    }
}

/// List all `devaipod/*` remote-tracking branches in the current repo.
fn find_devaipod_branches() -> Vec<RepoBranchInfo> {
    let output = match ProcessCommand::new("git")
        .args(["branch", "-r", "--list", "devaipod/*"])
        .output()
    {
        Ok(o) if o.status.success() => o,
        _ => return Vec::new(),
    };

    let branches_str = String::from_utf8_lossy(&output.stdout);
    let branch_refs: Vec<String> = branches_str
        .lines()
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty() && !l.contains("->"))
        .collect();

    if branch_refs.is_empty() {
        return Vec::new();
    }

    let base_branch = detect_default_branch();

    branch_refs
        .into_iter()
        .map(|ref_name| {
            let range = format!("{}..{}", base_branch, ref_name);
            let ahead: usize = ProcessCommand::new("git")
                .args(["rev-list", "--count", &range])
                .output()
                .ok()
                .filter(|o| o.status.success())
                .and_then(|o| String::from_utf8_lossy(&o.stdout).trim().parse().ok())
                .unwrap_or(0);

            let push_status = check_push_status(&ref_name);

            RepoBranchInfo {
                ref_name,
                ahead,
                base_branch: base_branch.clone(),
                push_status,
            }
        })
        .collect()
}

/// Detect whether the repo uses `main` or `master` as default branch.
fn detect_default_branch() -> String {
    for branch in ["main", "master"] {
        let result = ProcessCommand::new("git")
            .args(["rev-parse", "--verify", branch])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
        if result.is_ok_and(|s| s.success()) {
            return branch.to_string();
        }
    }
    "HEAD".to_string()
}

/// Check if a devaipod remote-tracking branch has a corresponding `origin/` ref.
fn check_push_status(devaipod_ref: &str) -> RepoPushStatus {
    // devaipod_ref looks like "devaipod/<workspace>/<branch>"
    // We check if origin has a matching ref.
    let parts: Vec<&str> = devaipod_ref.splitn(3, '/').collect();
    if parts.len() >= 3 {
        // Try origin/<workspace>/<branch>
        let full_branch = format!("{}/{}", parts[1], parts[2]);
        let origin_ref = format!("origin/{}", full_branch);
        let result = ProcessCommand::new("git")
            .args(["rev-parse", "--verify", &origin_ref])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
        if result.is_ok_and(|s| s.success()) {
            return RepoPushStatus::Pushed(origin_ref);
        }
        // Try just origin/<branch> (the branch part only)
        let simple_ref = format!("origin/{}", parts[2]);
        let result = ProcessCommand::new("git")
            .args(["rev-parse", "--verify", &simple_ref])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
        if result.is_ok_and(|s| s.success()) {
            return RepoPushStatus::Pushed(simple_ref);
        }
    }
    RepoPushStatus::NotPushed
}

/// List open PRs for the current repo via `gh pr list` (best effort).
fn list_prs_for_repo() -> Vec<RepoPrInfo> {
    let output = ProcessCommand::new("gh")
        .args([
            "pr",
            "list",
            "--json",
            "number,title,state,headRefName,isDraft",
            "--limit",
            "50",
        ])
        .output();

    let output = match output {
        Ok(o) if o.status.success() => o,
        _ => return Vec::new(),
    };

    let json_str = String::from_utf8_lossy(&output.stdout);

    #[derive(serde::Deserialize)]
    struct GhPr {
        number: u64,
        title: String,
        state: String,
        #[serde(rename = "headRefName")]
        head_ref_name: String,
        #[serde(rename = "isDraft")]
        is_draft: bool,
    }

    match serde_json::from_str::<Vec<GhPr>>(&json_str) {
        Ok(prs) => prs
            .into_iter()
            .map(|p| RepoPrInfo {
                number: p.number,
                title: p.title,
                state: p.state,
                draft: p.is_draft,
                head_ref_name: p.head_ref_name,
            })
            .collect(),
        Err(_) => Vec::new(),
    }
}

/// Match a devaipod remote ref to a PR by branch name.
fn match_pr<'a>(ref_name: &str, prs: &'a [RepoPrInfo]) -> Option<&'a RepoPrInfo> {
    let parts: Vec<&str> = ref_name.splitn(3, '/').collect();
    if parts.len() >= 3 {
        let branch_suffix = parts[2]; // e.g., "devaipod/fix-auth" or "main"
        for pr in prs {
            if pr.head_ref_name == branch_suffix
                || pr.head_ref_name.ends_with(branch_suffix)
                || branch_suffix.ends_with(&pr.head_ref_name)
            {
                return Some(pr);
            }
        }
    }
    None
}

/// Get or set the session title for a pod
async fn cmd_title(pod_name: &str, new_title: Option<&str>) -> Result<()> {
    let short = strip_pod_prefix(pod_name);

    // Try to reach the pod-api sidecar
    let port = crate::web::get_pod_api_port_pub(pod_name).await;

    match new_title {
        Some(title) => {
            // Set title via pod-api
            let port = port.map_err(|_| {
                color_eyre::eyre::eyre!("Could not find pod-api port. Is the pod running?")
            })?;

            let host = crate::podman::host_for_pod_services();
            let client = reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(5))
                .build()
                .context("Failed to create HTTP client")?;

            let resp = client
                .put(format!("http://{host}:{port}/title"))
                .header("Content-Type", "application/json")
                .body(serde_json::json!({"title": title}).to_string())
                .send()
                .await
                .context("Failed to update title")?;

            if !resp.status().is_success() {
                bail!("Failed to update title: HTTP {}", resp.status());
            }

            tracing::info!("Set title for '{short}': {title}");
        }
        None => {
            // Get title — try pod-api first, fall back to label
            if let Ok(port) = port {
                let host = crate::podman::host_for_pod_services();
                let client = reqwest::Client::builder()
                    .timeout(std::time::Duration::from_secs(5))
                    .build()
                    .context("Failed to create HTTP client")?;

                let resp = client
                    .get(format!("http://{host}:{port}/title"))
                    .send()
                    .await;

                if let Ok(resp) = resp
                    && resp.status().is_success()
                {
                    #[derive(serde::Deserialize)]
                    struct TitleResp {
                        title: Option<String>,
                    }
                    if let Ok(t) = resp.json::<TitleResp>().await {
                        match t.title {
                            Some(title) => println!("{title}"),
                            None => println!("(no title set)"),
                        }
                        return Ok(());
                    }
                }
            }

            // Fall back to pod label
            let labels = get_pod_labels(pod_name);
            let title = labels
                .as_ref()
                .and_then(|l| l.get("io.devaipod.title"))
                .and_then(|v| v.as_str());

            match title {
                Some(t) => println!("{}", t),
                None => println!("(no title set)"),
            }
        }
    }

    Ok(())
}

/// Mark a workspace as done (or undo)
async fn cmd_done(pod_name: &str, undo: bool) -> Result<()> {
    let podman = podman::PodmanService::spawn()
        .await
        .context("Failed to start podman service")?;

    // Verify pod exists
    let _labels = podman
        .get_pod_labels(pod_name)
        .await
        .with_context(|| format!("Pod not found: {}", pod_name))?;

    // Get pod-api port and admin token
    let port = crate::web::get_pod_api_port_pub(pod_name)
        .await
        .map_err(|_| color_eyre::eyre::eyre!("Could not find pod-api port. Is the pod running?"))?;
    let admin_token = crate::web::get_pod_api_admin_token_pub(pod_name)
        .await
        .map_err(|_| {
            color_eyre::eyre::eyre!("Could not get admin token. Is the pod-api container running?")
        })?;

    let host = crate::podman::host_for_pod_services();
    let status = if undo { "active" } else { "done" };

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .context("Failed to create HTTP client")?;

    let resp = client
        .put(format!("http://{}:{}/completion-status", host, port))
        .header("Content-Type", "application/json")
        .header("Authorization", format!("Bearer {}", admin_token))
        .body(format!(r#"{{"status":"{}"}}"#, status))
        .send()
        .await
        .context("Failed to update completion status")?;

    if !resp.status().is_success() {
        bail!("Failed to update completion status: HTTP {}", resp.status());
    }

    let short = strip_pod_prefix(pod_name);
    if undo {
        tracing::info!("Marked '{}' as incomplete", short);
    } else {
        tracing::info!("Marked '{}' as done", short);
    }

    Ok(())
}

/// Remove all workspaces marked as done
async fn cmd_prune() -> Result<()> {
    // We need to iterate all devaipod pods, check their completion status, and delete "done" ones
    let _podman = podman::PodmanService::spawn()
        .await
        .context("Failed to start podman service")?;

    // List all devaipod pods
    let name_filter = format!("name={}*", POD_NAME_PREFIX);
    let output = podman_command()
        .args(["pod", "ps", "--filter", &name_filter, "--format=json"])
        .output()
        .context("Failed to list pods")?;

    if !output.status.success() {
        bail!("Failed to list pods");
    }

    let pods: Vec<serde_json::Value> =
        serde_json::from_slice(&output.stdout).context("Failed to parse pod list")?;

    if pods.is_empty() {
        tracing::info!("No devaipod pods found");
        return Ok(());
    }

    let host = crate::podman::host_for_pod_services();
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .context("Failed to create HTTP client")?;

    let mut deleted = 0;

    for pod in &pods {
        let pod_name = match pod.get("Name").and_then(|v| v.as_str()) {
            Some(n) => n,
            None => continue,
        };

        if !pod_name.starts_with(POD_NAME_PREFIX) {
            continue;
        }

        // Check completion status via pod-api sidecar
        let port = match crate::web::get_pod_api_port_pub(pod_name).await {
            Ok(p) => p,
            Err(_) => continue,
        };

        let resp = match client
            .get(format!("http://{}:{}/completion-status", host, port))
            .send()
            .await
        {
            Ok(r) if r.status().is_success() => r,
            _ => continue,
        };

        #[derive(serde::Deserialize)]
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

        let short = strip_pod_prefix(pod_name);
        tracing::info!("Pruning done pod: {}", short);

        // Force-delete the pod
        let del_output = podman_command()
            .args(["pod", "rm", "-f", pod_name])
            .output();

        match del_output {
            Ok(o) if o.status.success() => {
                deleted += 1;
            }
            Ok(o) => {
                let stderr = String::from_utf8_lossy(&o.stderr);
                tracing::warn!("Failed to delete {}: {}", short, stderr.trim());
            }
            Err(e) => {
                tracing::warn!("Failed to delete {}: {}", short, e);
            }
        }
    }

    if deleted == 0 {
        tracing::info!("No done pods to prune");
    } else {
        tracing::info!("Pruned {} done pod(s)", deleted);
    }

    Ok(())
}

/// Control plane for managing and reviewing agent workspaces
///
/// Provides a unified view of all running devaipod pods with the ability to
/// monitor status, review git commits, and accept/reject changes.
async fn cmd_controlplane(serve: bool, _port: u16, list: bool, json: bool) -> Result<()> {
    if list {
        // One-shot mode: list pods and exit
        // Reuse the existing list logic (show all, since controlplane is global)
        return cmd_list(json, true, true);
    }

    if serve {
        // HTTP server mode (future: axum server)
        eprintln!("Control plane HTTP server mode is not yet implemented.");
        eprintln!();
        eprintln!("This feature is planned for a future release. See:");
        eprintln!(
            "  https://github.com/cgwalters/devaipod/blob/main/docs/todo/opencode-web-enhancements.md"
        );
        eprintln!();
        eprintln!(
            "For now, use 'devaipod web' or 'devaipod list' and 'devaipod attach' to manage pods."
        );
        std::process::exit(1);
    }

    // TUI mode (future: ratatui TUI)
    eprintln!("Control plane TUI mode is not yet implemented.");
    eprintln!();
    eprintln!("This feature is planned for a future release. See:");
    eprintln!(
        "  https://github.com/cgwalters/devaipod/blob/main/docs/todo/opencode-web-enhancements.md"
    );
    eprintln!();
    eprintln!("For now, use these commands to manage pods:");
    eprintln!("  devaipod list              # List all workspaces");
    eprintln!("  devaipod attach <name>     # Attach to agent");
    eprintln!("  devaipod logs <name> -f    # Follow agent logs");
    eprintln!("  devaipod status <name>     # Detailed pod status");
    eprintln!();
    eprintln!("The control plane will provide:");
    eprintln!("  - Unified view of all running pods");
    eprintln!("  - Git commit review before pushing");
    eprintln!("  - Accept/reject/comment on agent changes");
    eprintln!();

    // For now, fall back to list as a useful default
    tracing::info!("Falling back to pod list:");
    cmd_list(json, true, true)
}

/// Manage service-gator scopes for a workspace
async fn cmd_gator(action: GatorAction) -> Result<()> {
    // Extract workspace name from the action
    let workspace = match &action {
        GatorAction::Edit { workspace } => workspace,
        GatorAction::Show { workspace, .. } => workspace,
        GatorAction::Add { workspace, .. } => workspace,
    };
    let pod_name = normalize_pod_name(workspace);

    let podman = podman::PodmanService::spawn()
        .await
        .context("Failed to start podman service")?;

    // Verify the pod exists and get labels (for backwards compat)
    let labels = podman
        .get_pod_labels(&pod_name)
        .await
        .with_context(|| format!("Pod not found: {}", pod_name))?;

    // Read gator config from the workspace volume.
    // The config may be at /workspaces/.devaipod/gator-config.json (older pods)
    // or /workspaces/<project>/.devaipod/gator-config.json (workspace-v2).
    // Search for it under /workspaces so we handle both layouts.
    let agent_container = format!("{}-agent", pod_name);
    let config_path = {
        let find_result = podman
            .exec_output(
                &agent_container,
                &[
                    "find",
                    "/workspaces",
                    "-maxdepth",
                    "3",
                    "-name",
                    "gator-config.json",
                    "-path",
                    "*/.devaipod/*",
                    "-print",
                    "-quit",
                ],
            )
            .await;
        if let Ok((0, stdout, _)) = find_result {
            let path = String::from_utf8_lossy(&stdout).trim().to_string();
            if !path.is_empty() {
                path
            } else {
                String::new()
            }
        } else {
            String::new()
        }
    };
    let config_content = if !config_path.is_empty() {
        podman
            .copy_from_container(&agent_container, &config_path)
            .await
            .ok()
            .flatten()
    } else {
        None
    };

    // Try to parse from volume file first, fall back to pod labels for backwards compat
    let gator_config: Option<service_gator::GatorConfigFile> = if let Some(content) = config_content
    {
        serde_json::from_str(&content).ok()
    } else {
        // Backwards compat: read scopes from pod labels (pre-volume pods)
        let scopes_json = labels.get(pod::GATOR_SCOPES_LABEL);
        scopes_json.and_then(|s| {
            let scopes: service_gator::JwtScopeConfig = serde_json::from_str(s).ok()?;
            Some(service_gator::GatorConfigFile::new(scopes))
        })
    };

    if gator_config.is_none() {
        eprintln!("Service-gator is not enabled for this workspace.");
        eprintln!();
        eprintln!("To enable service-gator, recreate the workspace with --service-gator flag:");
        eprintln!("  devaipod up <source> --service-gator=github:owner/repo");
        std::process::exit(1);
    }

    let gator_config = gator_config.unwrap();

    match action {
        GatorAction::Show { json, .. } => {
            if json {
                let scopes_json = serde_json::to_string(&gator_config.scopes)
                    .unwrap_or_else(|_| "{}".to_string());
                println!("{}", scopes_json);
            } else {
                println!("Service-gator scopes for {}:", strip_pod_prefix(&pod_name));
                println!();
                let toml_str = toml::to_string_pretty(&gator_config.scopes)
                    .unwrap_or_else(|_| "(failed to format)".to_string());
                if toml_str.trim().is_empty() {
                    println!("  (no scopes configured)");
                } else {
                    println!("{}", toml_str);
                }
            }
        }
        GatorAction::Edit { workspace: _ } => {
            // Convert current scopes to TOML for editing
            let toml_content = toml::to_string_pretty(&gator_config.scopes)
                .context("Failed to serialize scopes to TOML")?;

            // Create a temp file with the current scopes
            let temp_dir = tempfile::tempdir().context("Failed to create temp directory")?;
            let temp_file = temp_dir.path().join("scopes.toml");
            std::fs::write(
                &temp_file,
                format!(
                    "# Service-gator scopes for {}\n\
                 # Edit and save to update the scopes.\n\
                 # See: https://github.com/cgwalters/service-gator#configuration-examples\n\n\
                 {}",
                    strip_pod_prefix(&pod_name),
                    toml_content
                ),
            )
            .context("Failed to write temp file")?;

            // Get the editor
            let editor = std::env::var("EDITOR").unwrap_or_else(|_| "vi".to_string());

            // Open the editor
            tracing::info!("Opening {} in {}...", temp_file.display(), editor);
            let status = std::process::Command::new(&editor)
                .arg(&temp_file)
                .status()
                .with_context(|| format!("Failed to run editor: {}", editor))?;

            if !status.success() {
                eprintln!("Editor exited with non-zero status, aborting.");
                std::process::exit(1);
            }

            // Read the edited file
            let edited_content =
                std::fs::read_to_string(&temp_file).context("Failed to read edited file")?;

            // Parse the edited TOML
            let new_scopes: service_gator::JwtScopeConfig = toml::from_str(&edited_content)
                .context("Failed to parse edited TOML. Check for syntax errors.")?;

            // Update the gator config file in the volume
            // Gator watches this file via inotify and will reload automatically
            let mut updated_config = gator_config.clone();
            updated_config.update_scopes(new_scopes.clone());
            let updated_config_json = serde_json::to_string_pretty(&updated_config)
                .context("Failed to serialize updated config")?;

            // Write updated config to a temp file and copy to container
            let temp_dir2 = tempfile::tempdir().context("Failed to create temp directory")?;
            let config_temp = temp_dir2.path().join("gator-config.json");
            std::fs::write(&config_temp, &updated_config_json)?;

            podman
                .copy_to_container(&agent_container, &config_temp, &config_path, None)
                .await
                .context("Failed to save updated gator config")?;

            // No restart needed - gator watches the config file via inotify
            // and will automatically reload the new scopes
            println!("Scopes updated!");
            println!();
            println!("New scopes:");
            println!("{}", toml::to_string_pretty(&new_scopes)?);
            println!();
            println!("Gator will automatically reload these scopes (no restart needed).");
        }
        GatorAction::Add { scopes, .. } => {
            // Parse the new scopes from CLI
            let new_config =
                service_gator::parse_scopes(&scopes).context("Failed to parse scope arguments")?;

            // Convert new CLI scopes to JWT format
            let new_jwt_scopes = service_gator::config_to_jwt_scopes(&new_config);

            // Merge: new repos are added to existing
            let mut merged = gator_config.scopes.clone();
            for (pattern, perm) in new_jwt_scopes.gh.repos {
                merged.gh.repos.insert(pattern, perm);
            }
            if new_jwt_scopes.gh.read {
                merged.gh.read = true;
            }

            // Update the gator config file in the volume
            // Gator watches this file via inotify and will reload automatically
            let mut updated_config = gator_config.clone();
            updated_config.update_scopes(merged.clone());
            let updated_config_json = serde_json::to_string_pretty(&updated_config)
                .context("Failed to serialize updated config")?;

            // Write updated config to a temp file and copy to container
            let temp_dir = tempfile::tempdir().context("Failed to create temp directory")?;
            let config_temp = temp_dir.path().join("gator-config.json");
            std::fs::write(&config_temp, &updated_config_json)?;

            podman
                .copy_to_container(&agent_container, &config_temp, &config_path, None)
                .await
                .context("Failed to save updated gator config")?;

            // No restart needed - gator watches the config file via inotify
            // and will automatically reload the new scopes
            println!("Scopes added!");
            println!();
            println!("Active scopes:");
            println!("{}", toml::to_string_pretty(&merged)?);
            println!();
            println!("Gator will automatically reload these scopes (no restart needed).");
        }
    }

    Ok(())
}

// =============================================================================
// Advisor Command
// =============================================================================

/// State of the advisor pod
enum AdvisorPodState {
    Running,
    Stopped,
    NotFound,
}

/// Check whether the advisor pod exists and its state
fn check_advisor_pod_state(pod_name: &str) -> AdvisorPodState {
    let output = podman_command()
        .args(["pod", "inspect", pod_name, "--format", "{{.State}}"])
        .output();
    match output {
        Ok(o) if o.status.success() => {
            let state = String::from_utf8_lossy(&o.stdout).trim().to_lowercase();
            if state == "running" {
                AdvisorPodState::Running
            } else {
                AdvisorPodState::Stopped
            }
        }
        _ => AdvisorPodState::NotFound,
    }
}

/// Handle the advisor command
///
/// Checks if a devaipod-advisor pod exists:
/// - If running: attach to it (or send task if provided)
/// - If stopped: start it and attach
/// - If not found: create it
async fn cmd_advisor(
    config: &config::Config,
    task: Option<&str>,
    show_status: bool,
    show_proposals: bool,
    name_override: Option<&str>,
    source_dirs: &[PathBuf],
) -> Result<()> {
    let advisor_pod = match name_override {
        Some(n) => normalize_pod_name(n),
        None => advisor_pod_name(),
    };

    let existing = check_advisor_pod_state(&advisor_pod);

    if show_status {
        return cmd_advisor_status(&advisor_pod, &existing);
    }

    if show_proposals {
        return cmd_advisor_proposals(&advisor_pod);
    }

    // When called from the web handler, DEVAIPOD_NO_ATTACH is set to
    // prevent blocking on cmd_attach (which would hang the HTTP request).
    let no_attach = std::env::var("DEVAIPOD_NO_ATTACH").is_ok();

    match existing {
        AdvisorPodState::Running => {
            if let Some(task) = task {
                eprintln!("Advisor is running. Sending task...");
                start_agent_task(&advisor_pod, task, false)?;
            } else {
                eprintln!("Advisor is running.");
            }
            if no_attach {
                return Ok(());
            }
            cmd_attach(&advisor_pod, None, AttachTarget::Agent).await
        }
        AdvisorPodState::Stopped => {
            eprintln!("Starting stopped advisor pod...");
            cmd_start(&advisor_pod)?;
            if let Some(task) = task {
                start_agent_task(&advisor_pod, task, false)?;
            }
            if no_attach {
                return Ok(());
            }
            cmd_attach(&advisor_pod, None, AttachTarget::Agent).await
        }
        AdvisorPodState::NotFound => {
            eprintln!("No advisor pod found. Creating one...");
            create_advisor_pod(config, task, source_dirs).await?;
            if no_attach {
                return Ok(());
            }
            cmd_attach(&advisor_pod, None, AttachTarget::Agent).await
        }
    }
}

/// Default system prompt for the advisor agent.
///
/// This prompt instructs the advisor to use its MCP tools to survey the
/// current state and proactively suggest agent pods to launch.
const ADVISOR_SYSTEM_PROMPT: &str = "\
You are the devaipod advisor agent. Your job is to observe the user's development \
environment and suggest useful agent pods to launch. You have two sets of tools:

- **devaipod MCP tools** for pod/workspace introspection: `list_pods`, `list_workspaces`, \
  `workspace_diff`, `pod_status`, `pod_logs`, `propose_agent`, `list_proposals`
- **service-gator MCP tools** for GitHub access: use these to search for PRs where \
  you are requested as a reviewer, list notifications, browse issues, etc.

Start by surveying the current state:

1. Use service-gator to find open PRs where the user is requested as a reviewer. \
   For each non-draft PR, consider proposing an agent pod to review it.
2. Use `list_workspaces` to see what agent pods are already running or completed, \
   what repos they're working on, and their completion status.
3. Use service-gator to check GitHub notifications for new issues, mentions, or \
   CI failures that might warrant an agent.
4. Use `list_pods` to check pod health. Look for stuck or unhealthy pods.

Based on what you find, use `propose_agent` to create draft proposals for new \
agent pods. Each proposal should have:
- A clear title describing the work
- The target repo (e.g. 'owner/repo')
- A detailed task description the agent can act on
- Your rationale for why this is worth doing
- A priority level (high/medium/low)
- The source that triggered it (e.g. 'github:owner/repo#123')

Focus on actionable items: PRs waiting for review, issues with clear reproduction \
steps, dependency updates, CI failures. Skip anything that's already being worked \
on by an existing agent pod.

If source directories are mounted at /mnt/source/, browse them to understand \
project structure and cross-repo dependencies. This helps you write better task \
descriptions.

After your initial survey, summarize what you found and what you proposed.";

/// Detect the host-mapped port for the control plane's web server.
///
/// The web server inside the container always listens on 8080, but when the
/// advisor connects from another container via `host.containers.internal`, it
/// needs the host-mapped port (e.g. 8081 for a `test-devaipod` instance).
///
/// Checks `DEVAIPOD_HOST_PORT` env var first, then falls back to inspecting
/// our own container's port mappings via `podman port`.
fn detect_own_host_port() -> u16 {
    if let Ok(port) = std::env::var("DEVAIPOD_HOST_PORT")
        && let Ok(p) = port.parse::<u16>()
    {
        return p;
    }
    let container_name =
        std::env::var(DEVAIPOD_INSTANCE_ENV).unwrap_or_else(|_| "devaipod".to_string());
    if let Ok(output) = std::process::Command::new("podman")
        .args(["port", &container_name, "8080/tcp"])
        .output()
        && output.status.success()
    {
        let s = String::from_utf8_lossy(&output.stdout);
        // Output format: "0.0.0.0:8081" or ":::8081"
        if let Some(port_str) = s.trim().rsplit(':').next()
            && let Ok(p) = port_str.parse::<u16>()
        {
            return p;
        }
    }
    8080
}

/// Return the advisor pod name.
///
/// Always `devaipod-advisor` — instance isolation is handled by the
/// `io.devaipod.instance` label, not the pod name. All pods share the
/// `devaipod-` prefix regardless of instance.
pub(crate) fn advisor_pod_name() -> String {
    "devaipod-advisor".to_string()
}

/// Create the advisor pod using cmd_run with advisor-specific settings.
///
/// The advisor doesn't work on a specific repo — it's a meta-agent that
/// observes other pods and suggests actions. It uses the dotfiles repo as
/// the workspace source if configured, otherwise creates a scratch workspace.
/// The image is overridden to use our own container which has opencode
/// installed.
async fn create_advisor_pod(
    config: &config::Config,
    task: Option<&str>,
    source_dirs: &[PathBuf],
) -> Result<()> {
    let default_task = task.unwrap_or(ADVISOR_SYSTEM_PROMPT);

    // The MCP server runs as a route on the devaipod web server.
    // The advisor agent reaches it via host.containers.internal:<host_port>.
    // The host port may differ from the internal 8080 in multi-instance
    // setups (e.g. test-devaipod maps 8081:8080).
    let host_port = detect_own_host_port();
    let mcp_url = format!(
        "http://{}:{}/api/devaipod/mcp",
        crate::podman::host_for_pod_services(),
        host_port
    );

    // Load the MCP token so the advisor can authenticate to the MCP endpoint.
    // This is a separate shared secret scoped to MCP, not the web API token.
    let mcp_token = crate::web::load_or_generate_mcp_token();

    // The advisor is a scratch-like workspace — it doesn't need a specific
    // git repo. Use the dotfiles repo if configured, otherwise None (scratch).
    let source = resolve_source(None, config);

    // Build a modified config that includes the MCP server entry with the
    // Authorization header. We reload the config and insert the entry
    // directly so it flows through the normal config -> pod.rs pipeline
    // (which now supports headers on McpServerEntry).
    let mut advisor_config = config::load_config(None)?;
    let mut headers = std::collections::HashMap::new();
    headers.insert("Authorization".to_string(), format!("Bearer {}", mcp_token));
    advisor_config.mcp.servers.insert(
        "devaipod".to_string(),
        config::McpServerEntry {
            url: mcp_url,
            enabled: true,
            headers,
        },
    );

    // The advisor needs service-gator for GitHub access (checking PRs,
    // notifications, issues, etc.). Ensure at least global read access
    // is enabled so the gator sidecar is always created.
    if !advisor_config.service_gator.is_enabled() {
        advisor_config.service_gator.gh.read = true;
    }

    let pod_name = cmd_run(
        &advisor_config,
        source,
        Some(default_task),
        None,            // Use user's default devcontainer image, not the devaipod image
        Some("advisor"), // Becomes devaipod-advisor via normalize_pod_name
        &[],             // service-gator scopes from config
        None,
        true,                                   // read-only service-gator
        &[],   // no CLI mcp_servers — entry is already in the config
        None,  // no devcontainer override
        false, // don't override project devcontainer
        None,  // no title for advisor
        &canonicalize_source_dirs(source_dirs), // read-only source dirs
    )
    .await?;

    eprintln!("Created advisor pod: {}", strip_pod_prefix(&pod_name));
    Ok(())
}

/// Show the advisor pod status
fn cmd_advisor_status(pod_name: &str, state: &AdvisorPodState) -> Result<()> {
    match state {
        AdvisorPodState::Running => {
            eprintln!("Advisor pod: running");
            if let Some(healthy) = check_agent_health(pod_name) {
                eprintln!(
                    "Agent health: {}",
                    if healthy { "healthy" } else { "unhealthy" }
                );
            }
        }
        AdvisorPodState::Stopped => eprintln!("Advisor pod: stopped"),
        AdvisorPodState::NotFound => eprintln!("Advisor pod: not found"),
    }
    Ok(())
}

/// List current draft proposals from the advisor pod
fn cmd_advisor_proposals(pod_name: &str) -> Result<()> {
    let agent_container = get_attach_container_name(pod_name, AttachTarget::Agent);
    let output = ProcessCommand::new("podman")
        .args(["exec", &agent_container, "cat", advisor::DRAFTS_PATH])
        .output();

    match output {
        Ok(o) if o.status.success() => {
            let store: advisor::DraftStore =
                serde_json::from_slice(&o.stdout).context("Failed to parse proposals")?;
            if store.proposals.is_empty() {
                eprintln!("No proposals.");
            } else {
                for p in &store.proposals {
                    eprintln!(
                        "[{:?}] {} - {} ({:?})",
                        p.priority, p.title, p.repo, p.status
                    );
                }
            }
        }
        _ => eprintln!("No proposals (advisor may not be running or no proposals yet)."),
    }
    Ok(())
}

/// Check if any API keys are configured for the AI agent and warn if not
///
/// This helps users on first run understand that they need to configure
/// API keys for the agent to function properly. Only warns if no config
/// file exists - if the user has a config file, we assume they've set
/// things up properly (e.g. via secrets, env vars in config, etc).
fn check_api_keys_configured() {
    // If a config file exists, assume the user has configured things properly
    if config::config_path().exists() {
        return;
    }

    // Check for DEVAIPOD_AGENT_* env vars (legacy mechanism)
    let agent_env_vars = config::collect_agent_env_vars();

    if agent_env_vars.is_empty() {
        eprintln!();
        eprintln!("Warning: No devaipod configuration found.");
        eprintln!("   Run 'devaipod init' to create a config file.");
        eprintln!("   See: https://opencode.ai/docs/providers/");
        eprintln!();
    }
}

/// Build a std::process::Command for running podman CLI.
///
/// Uses the container socket path from podman module.
fn podman_command() -> ProcessCommand {
    let mut cmd = ProcessCommand::new("podman");
    if let Ok(socket_path) = podman::get_container_socket() {
        cmd.args(["--url", &format!("unix://{}", socket_path.display())]);
    }
    cmd
}

/// Attach to a devaipod workspace
///
/// Behavior depends on the target:
/// - **Agent (default)**: Runs `opencode attach` to connect to the AI agent's session
/// - **Workspace (-W flag)**: Opens tmux with opencode-connect + shell panes
///
/// The agent container runs `opencode serve`, so we connect directly to it.
/// The workspace container is the human's development environment with tmux.
async fn cmd_attach(pod_name: &str, session: Option<&str>, target: AttachTarget) -> Result<()> {
    let container = get_attach_container_name(pod_name, target);

    match target {
        AttachTarget::Agent => {
            // Agent container: connect directly to opencode serve
            tracing::info!("Attaching to agent in '{}'...", strip_pod_prefix(pod_name));

            // If no session specified, try to auto-detect an existing session
            // This enables seamless handoff from `devaipod run "task"` to interactive mode
            let effective_session = match session {
                Some(sid) => Some(sid.to_string()),
                None => detect_active_session(pod_name, None),
            };

            if let Some(ref sid) = effective_session {
                tracing::info!("Continuing session: {}", sid);
            }

            // Build the opencode attach command
            // The agent runs opencode serve on localhost:4096
            let mut attach_args = vec![
                "opencode".to_string(),
                "attach".to_string(),
                "http://localhost:4096".to_string(),
            ];
            if let Some(sid) = effective_session {
                attach_args.push("-s".to_string());
                attach_args.push(sid);
            }

            let mut cmd = podman_command();
            cmd.args(["exec", "-it", &container]);
            cmd.args(&attach_args);

            let status = cmd.status().context("Failed to run podman exec")?;

            if !status.success() {
                bail!(
                    "Failed to attach to agent in '{}' (exit code {:?}). \
                     The container may not exist or is not running. \
                     Run 'devaipod list' to see available pods.",
                    pod_name,
                    status.code()
                );
            }
        }
        AttachTarget::Workspace => {
            // Workspace container: tmux session with opencode-connect + shell
            let tmux_session = strip_pod_prefix(pod_name).replace(['.', ':'], "-");

            tracing::info!(
                "Attaching to workspace '{}' with tmux...",
                strip_pod_prefix(pod_name)
            );

            // Build the opencode-connect command with optional session
            let agent_cmd = match session {
                Some(sid) => format!("opencode-connect -s {}", sid),
                None => "opencode-connect".to_string(),
            };

            // Script to run inside the workspace container:
            // 1. Kill any existing tmux session (ensures fresh state)
            // 2. Create new session with two panes (agent left, shell right)
            // 3. Attach to the session
            let tmux_script = format!(
                r#"
# Kill any existing session to ensure fresh state
tmux kill-session -t {session} 2>/dev/null || true
# Create new session with agent in left pane
tmux new-session -d -s {session} '{agent_cmd}'
# Split horizontally and start shell in right pane
tmux split-window -h -t {session} 'bash'
# Focus left pane (agent)
tmux select-pane -t {session}:0.0
# Attach to the session
exec tmux attach -t {session}
"#,
                session = tmux_session,
                agent_cmd = agent_cmd,
            );

            let mut cmd = podman_command();
            cmd.args(["exec", "-it", &container, "bash", "-c", &tmux_script]);

            let status = cmd.status().context("Failed to run podman exec")?;

            if !status.success() {
                bail!(
                    "Failed to attach to workspace '{}' (exit code {:?}). \
                     The container may not exist or is not running. \
                     Run 'devaipod list' to see available pods.",
                    pod_name,
                    status.code()
                );
            }
        }
        AttachTarget::Worker => {
            // Worker container: connect to worker's opencode serve
            tracing::info!("Attaching to worker in '{}'...", strip_pod_prefix(pod_name));

            // Worker uses WORKER_OPENCODE_PORT (4098) to avoid conflict with agent's OPENCODE_PORT (4096)
            let worker_port = pod::WORKER_OPENCODE_PORT;

            // If no session specified, try to auto-detect an existing session
            let effective_session = match session {
                Some(sid) => Some(sid.to_string()),
                None => detect_active_session(pod_name, Some(worker_port)),
            };

            if let Some(ref sid) = effective_session {
                tracing::info!("Continuing session: {}", sid);
            }

            // Build the opencode attach command for the worker
            let mut attach_args = vec![
                "opencode".to_string(),
                "attach".to_string(),
                format!("http://localhost:{}", worker_port),
            ];
            if let Some(sid) = effective_session {
                attach_args.push("-s".to_string());
                attach_args.push(sid);
            }

            let mut cmd = podman_command();
            cmd.args(["exec", "-it", &container]);
            cmd.args(&attach_args);

            let status = cmd.status().context("Failed to run podman exec")?;

            if !status.success() {
                bail!(
                    "Failed to attach to worker in '{}' (exit code {:?}). \
                     The worker container may not exist (is orchestration enabled?) or is not running. \
                     Run 'devaipod list' to see available pods.",
                    pod_name,
                    status.code()
                );
            }
        }
    }

    Ok(())
}

/// Exec into a container using podman exec
async fn cmd_exec(
    pod_name: &str,
    target: AttachTarget,
    stdio: bool,
    command: &[String],
) -> Result<()> {
    let container = get_attach_container_name(pod_name, target);

    if stdio {
        // Stdio mode: run the embedded SSH server on the host
        // The SSH server speaks real SSH protocol over stdin/stdout and
        // translates SSH requests into podman exec commands
        if command.is_empty() {
            // Run the SSH server - this runs on the host and uses podman exec
            ssh_server::run_stdio_for_container(&container).await?;
        } else {
            // Direct command execution via podman exec
            let mut cmd = podman_command();
            cmd.args(["exec", "-i", &container]);
            cmd.args(command);

            let status = cmd.status().context("Failed to run podman exec")?;

            if !status.success() {
                bail!(
                    "podman exec failed for container '{}' (exit code {:?}). \
                     The container may not exist or is not running. \
                     Run 'devaipod list' to see available pods.",
                    container,
                    status.code()
                );
            }
        }
    } else {
        // Interactive mode with TTY
        let target_name = match target {
            AttachTarget::Agent => "agent",
            AttachTarget::Workspace => "workspace",
            AttachTarget::Worker => "worker",
        };
        tracing::info!(
            "Exec into {} container '{}'...",
            target_name,
            strip_pod_prefix(pod_name)
        );

        let mut cmd = podman_command();
        cmd.args(["exec", "-it", &container]);

        if command.is_empty() {
            cmd.arg("bash");
        } else {
            cmd.args(command);
        }

        let status = cmd.status().context("Failed to run podman exec")?;

        if !status.success() {
            bail!(
                "podman exec failed for container '{}' (exit code {:?}). \
                 The container may not exist or is not running. \
                 Run 'devaipod list' to see available pods.",
                container,
                status.code()
            );
        }
    }

    Ok(())
}

/// Well-known path for SSH config export in container mode.
/// If this directory exists, SSH configs are written here instead of ~/.ssh/config.d
const CONTAINER_SSH_CONFIG_DIR: &str = "/run/devaipod-ssh";

/// Check if we're using the container SSH export directory.
fn is_using_container_ssh_export() -> bool {
    PathBuf::from(CONTAINER_SSH_CONFIG_DIR).exists()
}

/// Environment variable to override the SSH config directory.
/// Primarily used for testing to avoid mutating the user's real ~/.ssh/config.d.
const SSH_CONFIG_DIR_ENV: &str = "DEVAIPOD_SSH_CONFIG_DIR";

/// Get the SSH config directory path.
///
/// Priority:
/// 1. `DEVAIPOD_SSH_CONFIG_DIR` environment variable (for testing)
/// 2. Container mode export directory `/run/devaipod-ssh` (if it exists)
/// 3. Default `~/.ssh/config.d`
fn get_ssh_config_dir() -> Result<PathBuf> {
    // Check for explicit override (mainly for testing)
    if let Ok(dir) = std::env::var(SSH_CONFIG_DIR_ENV) {
        return Ok(PathBuf::from(dir));
    }

    // Check for container mode export directory
    if is_using_container_ssh_export() {
        return Ok(PathBuf::from(CONTAINER_SSH_CONFIG_DIR));
    }

    // Default to ~/.ssh/config.d
    let home = std::env::var("HOME").context("HOME environment variable not set")?;
    Ok(PathBuf::from(home).join(".ssh").join("config.d"))
}

/// Get the SSH config file path for a workspace
///
/// The config file is named after the short workspace name (without prefix)
fn get_ssh_config_path(pod_name: &str) -> Result<PathBuf> {
    let short_name = strip_pod_prefix(pod_name);
    Ok(get_ssh_config_dir()?.join(format!("{}{}", POD_NAME_PREFIX, short_name)))
}

/// Check if ~/.ssh/config has Include directive for config.d
fn ssh_config_has_include() -> bool {
    let home = match std::env::var("HOME") {
        Ok(h) => h,
        Err(_) => return false,
    };
    let ssh_config = PathBuf::from(home).join(".ssh").join("config");

    if !ssh_config.exists() {
        return false;
    }

    let content = match std::fs::read_to_string(&ssh_config) {
        Ok(c) => c,
        Err(_) => return false,
    };

    // Check for Include directive that covers config.d/*
    // Common patterns: "Include config.d/*", "Include ~/.ssh/config.d/*"
    for line in content.lines() {
        let line = line.trim();
        if line.starts_with("Include") {
            let rest = line.strip_prefix("Include").unwrap_or("").trim();
            if rest.contains("config.d/*") || rest.contains("config.d/") {
                return true;
            }
        }
    }

    false
}

/// Remove SSH config file for a workspace
fn remove_ssh_config(workspace: &str) -> Result<()> {
    let config_path = get_ssh_config_path(workspace)?;
    if config_path.exists() {
        std::fs::remove_file(&config_path)
            .with_context(|| format!("Failed to remove {}", config_path.display()))?;
        tracing::info!("Removed SSH config: {}", config_path.display());
    }
    Ok(())
}

/// Run cleanup tasks
///
/// Currently includes:
/// - Garbage collect orphaned SSH config entries
/// - (Future: other cleanup tasks)
fn cmd_cleanup(dry_run: bool) -> Result<()> {
    println!("Running cleanup tasks...\n");

    // SSH config garbage collection
    println!("=== SSH Config Cleanup ===");
    gc_ssh_configs(dry_run)?;

    // Future cleanup tasks would go here
    // println!("\n=== Other Cleanup ===");
    // ...

    Ok(())
}

/// Garbage collect orphaned SSH config entries
///
/// 1. List all devaipod pods
/// 2. List all SSH config files in ~/.ssh/config.d/
/// 3. Find configs that don't have a corresponding pod
/// 4. Delete orphaned configs (with re-verification to avoid races)
fn gc_ssh_configs(dry_run: bool) -> Result<()> {
    // Step 1: Get list of all existing pod names
    let existing_pods = get_pod_names()?;
    let existing_pods_set: std::collections::HashSet<_> = existing_pods.iter().collect();

    // Step 2: List all SSH config files
    let config_dir = get_ssh_config_dir()?;
    if !config_dir.exists() {
        println!("No SSH config directory found at {}", config_dir.display());
        return Ok(());
    }

    let entries = std::fs::read_dir(&config_dir)
        .with_context(|| format!("Failed to read {}", config_dir.display()))?;

    let mut orphaned = Vec::new();
    for entry in entries {
        let entry = entry?;
        let filename = entry.file_name();
        let filename_str = filename.to_string_lossy();

        // Only consider files with our prefix
        if !filename_str.starts_with(POD_NAME_PREFIX) {
            continue;
        }

        // Extract pod name from filename (filename IS the pod name)
        let pod_name = filename_str.to_string();

        // Check if this pod exists
        if !existing_pods_set.contains(&pod_name) {
            orphaned.push((entry.path(), pod_name));
        }
    }

    if orphaned.is_empty() {
        println!("No orphaned SSH config entries found.");
        return Ok(());
    }

    println!(
        "Found {} orphaned SSH config {}:",
        orphaned.len(),
        if orphaned.len() == 1 {
            "entry"
        } else {
            "entries"
        }
    );

    for (path, pod_name) in &orphaned {
        println!("  {} (pod: {})", path.display(), pod_name);
    }

    if dry_run {
        println!("\nDry run - no files deleted. Run without -n to delete.");
        return Ok(());
    }

    // Step 4: Delete orphaned configs with re-verification
    let mut deleted = 0;
    for (path, pod_name) in orphaned {
        // Re-verify pod doesn't exist (avoid race with concurrent `devaipod up`)
        if pod_exists(&pod_name)? {
            println!("Skipping {} - pod appeared since check", path.display());
            continue;
        }

        match std::fs::remove_file(&path) {
            Ok(()) => {
                println!("Deleted: {}", path.display());
                deleted += 1;
            }
            Err(e) => {
                eprintln!("Failed to delete {}: {}", path.display(), e);
            }
        }
    }

    println!("\nDeleted {} orphaned SSH config file(s).", deleted);
    Ok(())
}

/// Get list of all devaipod pod names
fn get_pod_names() -> Result<Vec<String>> {
    let filter = format!("name={}*", POD_NAME_PREFIX);
    let output = podman_command()
        .args(["pod", "ps", "--filter", &filter, "--format={{.Name}}"])
        .output()
        .context("Failed to run podman pod ps")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("podman pod ps failed: {}", stderr.trim());
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    Ok(stdout.lines().map(|s| s.to_string()).collect())
}

/// Check if a specific pod exists
fn pod_exists(pod_name: &str) -> Result<bool> {
    let output = podman_command()
        .args(["pod", "exists", pod_name])
        .output()
        .context("Failed to run podman pod exists")?;

    Ok(output.status.success())
}

/// Quietly garbage collect orphaned SSH configs
///
/// This is called automatically after `devaipod delete` to clean up stragglers.
/// Returns the number of configs deleted.
fn gc_ssh_configs_quiet() -> Result<usize> {
    // Get list of existing pods
    let existing_pods = get_pod_names()?;
    let existing_pods_set: std::collections::HashSet<_> = existing_pods.iter().collect();

    let config_dir = get_ssh_config_dir()?;
    if !config_dir.exists() {
        return Ok(0);
    }

    let entries = std::fs::read_dir(&config_dir)?;

    let mut deleted = 0;
    for entry in entries.flatten() {
        let filename = entry.file_name();
        let filename_str = filename.to_string_lossy();

        if !filename_str.starts_with(POD_NAME_PREFIX) {
            continue;
        }

        let pod_name = filename_str.to_string();

        // Check if pod exists
        if existing_pods_set.contains(&pod_name) {
            continue;
        }

        // Re-verify before deleting (race protection)
        if pod_exists(&pod_name).unwrap_or(true) {
            continue;
        }

        if std::fs::remove_file(entry.path()).is_ok() {
            tracing::debug!("GC: removed orphaned SSH config {}", entry.path().display());
            deleted += 1;
        }
    }

    Ok(deleted)
}

/// Write SSH config entry for a workspace (internal helper)
///
/// Returns the path to the created config file, or None if an error occurred.
/// This is a best-effort operation - errors are logged but don't fail the caller.
fn write_ssh_config(pod_name: &str) -> Option<std::path::PathBuf> {
    let username = std::env::var("USER").unwrap_or_else(|_| "user".to_string());

    match write_ssh_config_with_user(pod_name, &username) {
        Ok(path) => Some(path),
        Err(e) => {
            tracing::warn!("Failed to write SSH config: {}", e);
            None
        }
    }
}

/// Generate SSH config entry for a workspace (CLI command)
fn cmd_ssh_config(pod_name: &str, user: Option<&str>) -> Result<()> {
    // For the CLI command, we support --user override
    let username = user
        .map(|s| s.to_string())
        .or_else(|| std::env::var("USER").ok())
        .unwrap_or_else(|| "user".to_string());

    let config_path = write_ssh_config_with_user(pod_name, &username)?;

    println!("Added SSH config to {}", config_path.display());

    // Check if Include directive exists in ~/.ssh/config
    // Skip in container mode where configs are exported via bind mount
    if !is_using_container_ssh_export() && !ssh_config_has_include() {
        println!();
        println!("Add this line to the TOP of ~/.ssh/config:");
        println!("Include ~/.ssh/config.d/*");
    }

    Ok(())
}

/// Write SSH config with explicit username (used by CLI command)
///
/// Creates SSH config entries for the pod's containers:
/// - `<pod>.devaipod` - agent container (default target)
/// - `<pod>-worker.devaipod` - worker container
fn write_ssh_config_with_user(pod_name: &str, username: &str) -> Result<std::path::PathBuf> {
    use cap_std_ext::cap_primitives::fs::PermissionsExt;
    use cap_std_ext::cap_std;
    use cap_std_ext::dirext::CapStdExtDirExt;

    // Build the ProxyCommand.
    // The devaipod binary path - either from container or local install
    let devaipod_cmd = if is_using_container_ssh_export() {
        // Container mode: use podman exec to run devaipod inside the container.
        // Note: This has a known limitation with SSH protocol over nested podman exec.
        // For full SSH support, install devaipod on the host or use `podman exec -it` directly.
        "podman exec -i devaipod devaipod-server".to_string()
    } else {
        // Non-container mode: use the local binary path
        std::env::current_exe()
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_else(|_| "devaipod-server".to_string())
    };

    // Create SSH config content:
    // - default: agent container (no flag)
    // - worker: --worker flag
    let config_content = format!(
        r#"# Generated by devaipod
# Agent container (default target)
Host {pod}.devaipod
    ProxyCommand {devaipod} exec --stdio {pod}
    User {user}
    StrictHostKeyChecking no
    UserKnownHostsFile /dev/null
    LogLevel ERROR

# Worker container
Host {pod}-worker.devaipod
    ProxyCommand {devaipod} exec --worker --stdio {pod}
    User {user}
    StrictHostKeyChecking no
    UserKnownHostsFile /dev/null
    LogLevel ERROR
"#,
        pod = pod_name,
        devaipod = devaipod_cmd,
        user = username,
    );

    // Ensure ~/.ssh/config.d directory exists
    let config_dir = get_ssh_config_dir()?;
    std::fs::create_dir_all(&config_dir)
        .with_context(|| format!("Failed to create {}", config_dir.display()))?;

    // Open the directory for atomic writes
    let dir = cap_std::fs::Dir::open_ambient_dir(&config_dir, cap_std::ambient_authority())
        .with_context(|| format!("Failed to open {}", config_dir.display()))?;

    let config_path = get_ssh_config_path(pod_name)?;
    let filename = config_path
        .file_name()
        .ok_or_else(|| color_eyre::eyre::eyre!("Invalid SSH config path"))?;

    // Write atomically with proper permissions (0600) - SSH requires restrictive perms
    dir.atomic_write_with_perms(
        filename,
        config_content.as_bytes(),
        cap_std::fs::Permissions::from_mode(0o600),
    )
    .with_context(|| format!("Failed to write {}", config_path.display()))?;

    Ok(config_path)
}

/// Check whether a pod's labels match the current instance filter.
///
/// When `DEVAIPOD_INSTANCE` is set, only pods carrying a matching
/// `io.devaipod.instance` label are included. When the env var is unset,
/// pods that carry *any* instance label are excluded so that test/CI pods
/// don't clutter the main view.
fn pod_labels_match_instance(labels: Option<&serde_json::Value>) -> bool {
    let instance_id = get_instance_id();
    let pod_instance = labels
        .and_then(|l| l.get(INSTANCE_LABEL_KEY))
        .and_then(|v| v.as_str());

    match (instance_id.as_deref(), pod_instance) {
        // Both set – must match
        (Some(want), Some(have)) => want == have,
        // We want an instance but pod doesn't have one
        (Some(_), None) => false,
        // We don't want an instance but pod has one – hide it
        (None, Some(_)) => false,
        // Neither set – show it
        (None, None) => true,
    }
}

/// List devaipod pods using podman pod ps.
///
/// When `show_all` is false and CWD is inside a git repo, only pods whose
/// `io.devaipod.repo` label matches the current repo are displayed.
/// Inactive (stopped/exited) pods are hidden unless `show_inactive` is true.
fn cmd_list(json_output: bool, show_all: bool, show_inactive: bool) -> Result<()> {
    let name_filter = format!("name={}*", POD_NAME_PREFIX);
    let mut args = vec!["pod", "ps", "--filter", &name_filter];

    // When an instance is set, use podman's label filter for efficiency
    let label_filter;
    if let Some(instance_id) = get_instance_id() {
        label_filter = format!("label={INSTANCE_LABEL_KEY}={instance_id}");
        args.extend(["--filter", &label_filter]);
    }
    args.push("--format=json");

    let output = podman_command()
        .args(&args)
        .output()
        .context("Failed to run podman pod ps")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stderr = stderr.trim();
        if stderr.is_empty() {
            bail!(
                "podman pod ps failed with exit code {:?}",
                output.status.code()
            );
        } else {
            bail!("podman pod ps failed: {}", stderr);
        }
    }

    let pods: Vec<serde_json::Value> =
        serde_json::from_slice(&output.stdout).unwrap_or_else(|_| Vec::new());

    // Compute repo filter suffix once (used by both JSON and tabular paths).
    let repo_filter_suffix: Option<String> = if !show_all {
        let cwd = std::env::current_dir().ok();
        let in_git = cwd.as_deref().is_some_and(is_git_repo);
        if in_git {
            repo_root_path()
                .ok()
                .and_then(|root| extract_repo_suffix(&root.to_string_lossy()))
        } else {
            None
        }
    } else {
        None
    };

    if json_output {
        // For JSON output, enrich with labels from pod inspect and filter by instance
        let mut enriched_pods = Vec::new();
        for pod in &pods {
            let mut enriched = pod.clone();
            if let Some(name) = pod.get("Name").and_then(|v| v.as_str()) {
                let labels = get_pod_labels(name);
                if !pod_labels_match_instance(labels.as_ref()) {
                    continue;
                }
                // Skip devcontainer pods (they have their own list command)
                if labels
                    .as_ref()
                    .and_then(|l| l.get("io.devaipod.mode"))
                    .and_then(|v| v.as_str())
                    == Some("devcontainer")
                {
                    continue;
                }
                // Apply repo filter
                if let Some(ref filter) = repo_filter_suffix {
                    let repo_label = labels
                        .as_ref()
                        .and_then(|l| l.get("io.devaipod.repo"))
                        .and_then(|v| v.as_str())
                        .and_then(extract_repo_suffix);
                    if repo_label.as_ref() != Some(filter) {
                        continue;
                    }
                }
                if let Some(labels) = labels {
                    enriched["Labels"] = labels;
                }
            }
            enriched_pods.push(enriched);
        }
        println!("{}", serde_json::to_string_pretty(&enriched_pods)?);
        return Ok(());
    }

    if pods.is_empty() {
        println!("No devaipod workspaces found.");
        println!("Use 'devaipod up <path>' to create one.");
        return Ok(());
    }

    // Collect pod info with labels
    struct PodInfo {
        name: String,
        status: String,
        containers: usize,
        created: String,
        repo: Option<String>,
        pr: Option<String>,
        task: Option<String>,
        mode: Option<String>,
        #[allow(dead_code)] // Populated from labels but not yet shown in tabular output
        title: Option<String>,
        agent_status: Option<bool>,
    }

    let mut pod_infos: Vec<PodInfo> = Vec::new();
    for pod in &pods {
        let full_name = pod.get("Name").and_then(|v| v.as_str()).unwrap_or("-");
        let name = strip_pod_prefix(full_name).to_string();
        let status = pod
            .get("Status")
            .and_then(|v| v.as_str())
            .unwrap_or("-")
            .to_string();
        let containers = pod
            .get("Containers")
            .and_then(|v| v.as_array())
            .map(|a| a.len())
            .unwrap_or(0);
        let created = pod
            .get("Created")
            .and_then(|v| v.as_str())
            .unwrap_or("-")
            .to_string();

        // Get labels from pod inspect (use full name for podman commands)
        // and filter by instance + skip devcontainer pods (they have their own list command)
        let labels = get_pod_labels(full_name);
        if !pod_labels_match_instance(labels.as_ref()) {
            continue;
        }
        if labels
            .as_ref()
            .and_then(|l| l.get("io.devaipod.mode"))
            .and_then(|v| v.as_str())
            == Some("devcontainer")
        {
            continue;
        }
        let (repo, pr, task, mode, title) = if let Some(labels) = labels {
            let repo = labels
                .get("io.devaipod.repo")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            let pr = labels
                .get("io.devaipod.pr")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            let task = labels
                .get("io.devaipod.task")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            let mode = labels
                .get("io.devaipod.mode")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            let title = labels
                .get("io.devaipod.title")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            (repo, pr, task, mode, title)
        } else {
            (None, None, None, None, None)
        };

        // Check agent status for running pods
        let agent_status = if status.to_lowercase() == "running" {
            check_agent_health(full_name)
        } else {
            None
        };

        pod_infos.push(PodInfo {
            name,
            status,
            containers,
            created,
            repo,
            pr,
            task,
            mode,
            title,
            agent_status,
        });
    }

    // Filter by current repo when not showing all
    let repo_filter_name = if let Some(ref s) = repo_filter_suffix {
        let before = pod_infos.len();
        pod_infos.retain(|p| p.repo.as_deref().and_then(extract_repo_suffix).as_ref() == Some(s));
        let filtered = before - pod_infos.len();
        tracing::debug!("Filtered {filtered} pods not matching repo suffix {s}");
        // Use detect_repo_name for the header, falling back to the directory name
        let name = detect_repo_name().unwrap_or_else(|_| {
            repo_root_path()
                .ok()
                .and_then(|r| r.file_name().map(|f| f.to_string_lossy().into_owned()))
                .unwrap_or_default()
        });
        Some(name)
    } else {
        None
    };

    // Hide inactive (stopped/exited) pods unless --inactive is passed
    let hidden_inactive = if !show_inactive {
        let before = pod_infos.len();
        pod_infos.retain(|p| {
            let s = p.status.to_lowercase();
            s != "stopped" && s != "exited"
        });
        before - pod_infos.len()
    } else {
        0
    };

    // Print repo filter header
    if let Some(ref name) = repo_filter_name {
        println!("Workspaces for {}:", name);
        println!();
    }

    if pod_infos.is_empty() {
        if repo_filter_name.is_some() {
            if hidden_inactive > 0 {
                println!(
                    "No active workspaces for this repo ({hidden_inactive} inactive hidden, use --inactive to show)."
                );
            } else {
                println!("No workspaces found for this repo.");
                println!("Use 'devaipod up .' to create one, or -A to show all.");
            }
        } else if hidden_inactive > 0 {
            println!(
                "No active workspaces ({hidden_inactive} inactive hidden, use --inactive to show)."
            );
        } else {
            println!("No devaipod workspaces found.");
            println!("Use 'devaipod up <path>' to create one.");
        }
        return Ok(());
    }

    // Group pods by repo for display
    let mut repo_groups: std::collections::BTreeMap<String, Vec<&PodInfo>> =
        std::collections::BTreeMap::new();
    for info in &pod_infos {
        let key = info.repo.clone().unwrap_or_else(|| "(no repo)".to_string());
        repo_groups.entry(key).or_default().push(info);
    }

    // Calculate column widths across all pods
    let name_width = pod_infos
        .iter()
        .map(|p| p.name.len())
        .max()
        .unwrap_or(4)
        .max(4);

    let has_task_info = pod_infos.iter().any(|p| p.task.is_some());
    let multiple_repos = repo_groups.len() > 1;

    // Print grouped output
    for (group_idx, (repo, group)) in repo_groups.iter().enumerate() {
        // Repo header
        if multiple_repos {
            if group_idx > 0 {
                println!();
            }
            let active = group
                .iter()
                .filter(|p| p.status.to_lowercase() == "running")
                .count();
            if active > 0 {
                println!("{repo}  ({active} active)");
            } else {
                println!("{repo}");
            }
        }

        // Column header (only print once when single repo)
        if group_idx == 0 || multiple_repos {
            if multiple_repos {
                // Indented under repo header
                if has_task_info {
                    println!(
                        "  {:<name_width$}  {:<18}  {:<4}  {:<25}  CREATED",
                        "NAME",
                        "STATUS",
                        "MODE",
                        "TASK",
                        name_width = name_width
                    );
                } else {
                    println!(
                        "  {:<name_width$}  {:<18}  CREATED",
                        "NAME",
                        "STATUS",
                        name_width = name_width
                    );
                }
            } else if has_task_info {
                println!(
                    "{:<name_width$}  {:<18}  {:<4}  {:<25}  CREATED",
                    "NAME",
                    "STATUS",
                    "MODE",
                    "TASK",
                    name_width = name_width
                );
            } else {
                println!(
                    "{:<name_width$}  {:<18}  CREATED",
                    "NAME",
                    "STATUS",
                    name_width = name_width
                );
            }
        }

        for info in group {
            let created_display = format_created_time(&info.created);
            let indent = if multiple_repos { "  " } else { "" };

            // Build status display with agent status suffix for running pods
            let base_status = match info.status.to_lowercase().as_str() {
                "running" => "Running",
                "stopped" => "Stopped",
                "exited" => "Exited",
                "degraded" => "Degraded",
                _ => &info.status,
            };

            let status_display = if info.status.to_lowercase() == "running" {
                match info.agent_status {
                    Some(true) => format!("{} [agent:ok]", base_status),
                    Some(false) => format!("{} [agent:--]", base_status),
                    None => base_status.to_string(),
                }
            } else {
                base_status.to_string()
            };

            let mode_display = info.mode.as_deref().unwrap_or("-");

            let task_display = info
                .task
                .as_ref()
                .map(|t| {
                    if t.len() > 25 {
                        format!("{}...", &t[..22])
                    } else {
                        t.clone()
                    }
                })
                .unwrap_or_else(|| "-".to_string());

            if has_task_info {
                println!(
                    "{indent}{:<name_width$}  {:<18}  {:<4}  {:<25}  {}",
                    info.name,
                    status_display,
                    mode_display,
                    task_display,
                    created_display,
                    name_width = name_width
                );
            } else {
                println!(
                    "{indent}{:<name_width$}  {:<18}  {}",
                    info.name,
                    status_display,
                    created_display,
                    name_width = name_width
                );
            }
        }
    }

    // Footer hints
    let mut hints = Vec::new();
    if repo_filter_name.is_some() {
        hints.push("-A to show all workspaces");
    }
    if hidden_inactive > 0 {
        hints.push("--inactive to include stopped pods");
    }
    if !hints.is_empty() {
        println!();
        println!("(use {})", hints.join(", "));
    }

    if pod_infos.is_empty() {
        if repo_filter_name.is_some() {
            println!("No workspaces found for this repo.");
            println!("Use 'devaipod up .' to create one, or -A to show all.");
        } else {
            println!("No devaipod workspaces found.");
            println!("Use 'devaipod up <path>' to create one.");
        }
        return Ok(());
    }

    // Calculate column widths
    let name_width = pod_infos
        .iter()
        .map(|p| p.name.len())
        .max()
        .unwrap_or(4)
        .max(4);
    let repo_width = pod_infos
        .iter()
        .filter_map(|p| p.repo.as_ref())
        .map(|s| s.len())
        .max()
        .unwrap_or(0)
        .max(4);

    // Check if any pods have repo/PR/task info
    let has_repo_info = pod_infos.iter().any(|p| p.repo.is_some());
    let has_task_info = pod_infos.iter().any(|p| p.task.is_some());

    // Print header - include MODE column when there are task-based workspaces
    if has_repo_info {
        if has_task_info {
            println!(
                "{:<name_width$}  {:<18}  {:<4}  {:<repo_width$}  {:<6}  {:<25}  CREATED",
                "NAME",
                "STATUS",
                "MODE",
                "REPO",
                "PR",
                "TASK",
                name_width = name_width,
                repo_width = repo_width
            );
        } else {
            println!(
                "{:<name_width$}  {:<18}  {:<repo_width$}  {:<6}  CREATED",
                "NAME",
                "STATUS",
                "REPO",
                "PR",
                name_width = name_width,
                repo_width = repo_width
            );
        }
    } else if has_task_info {
        println!(
            "{:<name_width$}  {:<18}  {:<4}  {:<25}  CREATED",
            "NAME",
            "STATUS",
            "MODE",
            "TASK",
            name_width = name_width
        );
    } else {
        println!(
            "{:<name_width$}  {:<18}  {:<12}  CREATED",
            "NAME",
            "STATUS",
            "CONTAINERS",
            name_width = name_width
        );
    }

    // Print pods
    for info in &pod_infos {
        let created_display = format_created_time(&info.created);

        // Build status display with agent status suffix for running pods
        let base_status = match info.status.to_lowercase().as_str() {
            "running" => "Running",
            "stopped" => "Stopped",
            "exited" => "Exited",
            "degraded" => "Degraded",
            _ => &info.status,
        };

        // For running pods, append agent status
        let status_display = if info.status.to_lowercase() == "running" {
            match info.agent_status {
                Some(true) => format!("{} [agent:ok]", base_status),
                Some(false) => format!("{} [agent:--]", base_status),
                None => base_status.to_string(),
            }
        } else {
            base_status.to_string()
        };

        // Show mode (run/up) if available
        let mode_display = info.mode.as_deref().unwrap_or("-");

        // Truncate task to 25 chars for display (shortened to make room for mode)
        let task_display = info
            .task
            .as_ref()
            .map(|t| {
                if t.len() > 25 {
                    format!("{}...", &t[..22])
                } else {
                    t.clone()
                }
            })
            .unwrap_or_else(|| "-".to_string());

        if has_repo_info {
            let repo_display = info.repo.as_deref().unwrap_or("-");
            let pr_display = info
                .pr
                .as_ref()
                .map(|n| format!("#{}", n))
                .unwrap_or_else(|| "-".to_string());

            if has_task_info {
                println!(
                    "{:<name_width$}  {:<18}  {:<4}  {:<repo_width$}  {:<6}  {:<25}  {}",
                    info.name,
                    status_display,
                    mode_display,
                    repo_display,
                    pr_display,
                    task_display,
                    created_display,
                    name_width = name_width,
                    repo_width = repo_width
                );
            } else {
                println!(
                    "{:<name_width$}  {:<18}  {:<repo_width$}  {:<6}  {}",
                    info.name,
                    status_display,
                    repo_display,
                    pr_display,
                    created_display,
                    name_width = name_width,
                    repo_width = repo_width
                );
            }
        } else if has_task_info {
            println!(
                "{:<name_width$}  {:<18}  {:<4}  {:<25}  {}",
                info.name,
                status_display,
                mode_display,
                task_display,
                created_display,
                name_width = name_width
            );
        } else {
            println!(
                "{:<name_width$}  {:<18}  {:<12}  {}",
                info.name,
                status_display,
                format!(
                    "{} container{}",
                    info.containers,
                    if info.containers == 1 { "" } else { "s" }
                ),
                created_display,
                name_width = name_width
            );
        }
    }

    if repo_filter_name.is_some() {
        println!();
        println!("(use -A to show all workspaces)");
    }

    Ok(())
}

/// Get labels for a pod using podman pod inspect
fn get_pod_labels(pod_name: &str) -> Option<serde_json::Value> {
    let output = podman_command()
        .args([
            "pod",
            "inspect",
            "--format",
            "{{json .Labels}}",
            "--",
            pod_name,
        ])
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    let json_str = String::from_utf8_lossy(&output.stdout);
    serde_json::from_str(json_str.trim()).ok()
}

/// Format a timestamp to a more readable format
fn format_created_time(timestamp: &str) -> String {
    // Podman returns timestamps like "2025-01-26T10:30:00.000000000Z"
    // Try to parse and show a relative or short format
    if timestamp.len() >= 10 {
        // Just show the date portion for simplicity
        timestamp[..10].to_string()
    } else {
        timestamp.to_string()
    }
}

/// Start a stopped pod using podman pod start
fn cmd_start(pod_name: &str) -> Result<()> {
    tracing::info!("Starting pod '{}'...", pod_name);

    let output = podman_command()
        .args(["pod", "start", "--", pod_name])
        .output()
        .context("Failed to run podman pod start")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stderr = stderr.trim();
        // Ignore "already running" type errors
        if !stderr.contains("already running") && !stderr.contains("no such pod") {
            if stderr.is_empty() {
                bail!(
                    "podman pod start failed with exit code {:?}",
                    output.status.code()
                );
            } else {
                bail!("podman pod start failed: {}", stderr);
            }
        }
    }

    tracing::info!("Pod '{}' started", pod_name);
    Ok(())
}

/// Stop a pod using podman pod stop
fn cmd_stop(pod_name: &str) -> Result<()> {
    tracing::info!("Stopping pod '{}'...", pod_name);

    let output = podman_command()
        .args(["pod", "stop", "--", pod_name])
        .output()
        .context("Failed to run podman pod stop")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stderr = stderr.trim();
        // Ignore "not running" errors
        if !stderr.contains("not running") && !stderr.contains("no such pod") {
            if stderr.is_empty() {
                bail!(
                    "podman pod stop failed with exit code {:?}",
                    output.status.code()
                );
            } else {
                bail!("podman pod stop failed: {}", stderr);
            }
        }
    }

    tracing::info!("Pod '{}' stopped", pod_name);
    Ok(())
}

/// Delete a pod using podman pod rm
fn cmd_delete(pod_name: &str, force: bool) -> Result<()> {
    tracing::info!("Deleting pod '{}'...", pod_name);

    // Stop the pod first (graceful shutdown)
    // This gives containers time to handle SIGTERM before we remove them
    let stop_output = podman_command()
        .args(["pod", "stop", "--", pod_name])
        .output()
        .context("Failed to run podman pod stop")?;

    if !stop_output.status.success() {
        // Pod might already be stopped, or might not exist - continue with rm
        tracing::debug!(
            "Pod stop returned non-zero (may already be stopped): {}",
            String::from_utf8_lossy(&stop_output.stderr).trim()
        );
    }

    let mut cmd = podman_command();
    cmd.args(["pod", "rm"]);

    if force {
        cmd.arg("--force");
    }

    cmd.args(["--", pod_name]);

    let output = cmd.output().context("Failed to run podman pod rm")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stderr = stderr.trim();
        if stderr.is_empty() {
            bail!(
                "podman pod rm failed with exit code {:?}",
                output.status.code()
            );
        } else {
            bail!("podman pod rm failed: {}", stderr);
        }
    }

    tracing::info!("Pod '{}' deleted", pod_name);

    // Clean up all devaipod volumes
    for suffix in [
        "-workspace",
        "-agent-home",
        "-agent-workspace",
        "-worker-home",
        "-worker-workspace",
    ] {
        let volume = format!("{pod_name}{suffix}");
        let output = podman_command()
            .args(["volume", "rm", "--force", "--", &volume])
            .output()
            .context("Failed to run podman volume rm")?;

        if output.status.success() {
            tracing::debug!("Removed volume '{}'", volume);
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            if !stderr.contains("no such volume") {
                tracing::warn!("Failed to remove volume '{}': {}", volume, stderr.trim());
            }
        }
    }

    // Clean up agent directory if it exists
    if let Err(e) = crate::agent_dir::remove_agent_dir(pod_name) {
        tracing::warn!("Failed to remove agent directory for {pod_name}: {e}");
    }

    // Clean up SSH config file if it exists
    if let Err(e) = remove_ssh_config(pod_name) {
        tracing::warn!("Failed to remove SSH config: {}", e);
    }

    // Run GC to clean up any other orphaned SSH configs
    if let Err(e) = gc_ssh_configs_quiet() {
        tracing::debug!("SSH config GC: {}", e);
    }

    Ok(())
}

/// Rebuild a workspace with a new image while preserving the workspace volume
///
/// This stops and removes the containers but keeps the volumes intact,
/// then recreates the containers with the new/updated image.
/// Check if a devcontainer config exists in a repo directory.
///
/// Handles PermissionDenied (container subuid ownership) gracefully.
fn check_devcontainer_exists(repo_dir: &std::path::Path) -> bool {
    let dc_dir = repo_dir.join(".devcontainer");
    let dc_file = repo_dir.join("devcontainer.json");
    match std::fs::metadata(&dc_dir) {
        Ok(m) if m.is_dir() => return true,
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => return true,
        _ => {}
    }
    match std::fs::metadata(&dc_file) {
        Ok(m) if m.is_file() => return true,
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => return true,
        _ => {}
    }
    false
}

async fn cmd_rebuild(
    config: &config::Config,
    pod_name: &str,
    image_override: Option<&str>,
    run_create: bool,
) -> Result<()> {
    tracing::info!("Rebuilding workspace '{}'...", strip_pod_prefix(pod_name));

    // Get pod labels to find the repo URL
    let labels = get_pod_labels(pod_name)
        .ok_or_else(|| color_eyre::eyre::eyre!("Pod '{}' not found", pod_name))?;

    // Check workspace state file first — it knows the original source type
    let ws_state = agent_dir::WorkspaceState::load(
        &agent_dir::agent_dir_host_path(pod_name).unwrap_or_default(),
    )
    .ok()
    .flatten();

    let repo_url = labels
        .get("io.devaipod.repo")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    // Convert repo label back to URL (github.com/owner/repo -> https://github.com/owner/repo)
    let remote_url = if repo_url.is_empty() {
        // No repo label — check workspace state for the source
        ws_state
            .as_ref()
            .map(|s| s.source.clone())
            .unwrap_or_default()
    } else {
        format!("https://{}", repo_url)
    };
    tracing::debug!("Repository: {}", remote_url);

    // Get task label if present (to preserve it)
    let task = labels
        .get("io.devaipod.task")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    // Start podman service early — we need it to read config from the
    // workspace volume before tearing down the pod.
    let podman = podman::PodmanService::spawn()
        .await
        .context("Failed to start podman service")?;

    // Read devcontainer.json from the agent workspace.
    //
    // workspace-v2: the agent workspace is a host bind mount, so we can
    // read directly from the filesystem instead of running an init container.
    // This correctly picks up modifications the agent made inside the workspace.
    // Fall back to the workspace volume for older (pre-v2) pods.
    let repo_name = git::extract_repo_name(&remote_url).unwrap_or_else(|| "workspace".to_string());
    let self_image = pod::detect_self_image();

    let workspace_dir = format!("/workspaces/{}", repo_name);

    // Try reading from agent workspace host directory first (workspace-v2).
    // Use agent_dir_container_path for existence checks (visible from our
    // process), but agent_dir_host_path for the podman bind mount source
    // (podman resolves paths on the host).
    let (exit_code, raw_output) = {
        let agent_ws_container = agent_dir::agent_dir_container_path(pod_name)?;
        let agent_repo_dir = agent_ws_container.join(&repo_name);
        let has_devcontainer = check_devcontainer_exists(&agent_repo_dir);
        if has_devcontainer {
            let agent_ws_host = agent_dir::agent_dir_host_path(pod_name)?;
            tracing::info!(
                "Reading devcontainer configuration from agent workspace at {}...",
                agent_ws_host.display()
            );
            let host_path = agent_ws_host.display().to_string();
            podman
                .run_init_container_with_output(
                    &self_image,
                    &host_path,
                    "/workspaces",
                    &[
                        "devaipod-server",
                        "internals",
                        "output-devcontainer-state",
                        &workspace_dir,
                    ],
                    &[],
                )
                .await
                .context("Failed to read config from agent workspace")?
        } else {
            // Fall back to workspace volume (pre-v2 or devcontainer
            // was never in the agent workspace)
            let volume_name = format!("{}-workspace", pod_name);
            tracing::info!("Reading devcontainer configuration from workspace volume...");
            podman
                .run_init_container_with_output(
                    &self_image,
                    &volume_name,
                    "/workspaces",
                    &[
                        "devaipod-server",
                        "internals",
                        "output-devcontainer-state",
                        &workspace_dir,
                    ],
                    &[],
                )
                .await
                .context("Failed to read config from workspace volume")?
        }
    };

    if exit_code != 0 {
        tracing::warn!(
            "Init container exited with code {} while reading workspace config",
            exit_code
        );
    }

    let ws_info: devcontainer::WorkspaceInfo = serde_json::from_str(&raw_output)
        .context("Failed to parse workspace info JSON from init container")?;
    let default_branch = ws_info.default_branch;

    // Write the devcontainer.json to a tempdir so DevaipodPod::create can
    // use find_devcontainer_json() for image resolution (Dockerfile builds).
    let temp_dir = tempfile::tempdir().context("Failed to create temp directory")?;
    let temp_path = temp_dir.path();

    let (devcontainer_config, dotfiles_image) =
        if let Some(ref dc_content) = ws_info.devcontainer_json {
            let dc_dir = temp_path.join(".devcontainer");
            std::fs::create_dir_all(&dc_dir)?;
            std::fs::write(dc_dir.join("devcontainer.json"), dc_content)?;
            (devcontainer::load(&dc_dir.join("devcontainer.json"))?, None)
        } else if let Some(ref dotfiles) = config.dotfiles {
            // Try dotfiles repo as fallback
            let gh_token = git::get_github_token_with_secret(config);
            match clone_dotfiles_for_devcontainer(&dotfiles.url, gh_token.as_deref()).await {
                Ok(Some((dc_config, _temp_dir))) => {
                    tracing::info!("Using devcontainer.json from dotfiles ({})", dotfiles.url);
                    let img = dc_config.image.clone();
                    (dc_config, img)
                }
                _ => (devcontainer::DevcontainerConfig::default(), None),
            }
        } else if image_override.is_some() {
            tracing::info!("No devcontainer.json found, using defaults with image override");
            (devcontainer::DevcontainerConfig::default(), None)
        } else if let Some(ref default_image) = config.default_image {
            tracing::info!(
                "No devcontainer.json found, using default-image from config: {}",
                default_image
            );
            (devcontainer::DevcontainerConfig::default(), None)
        } else {
            bail!(
                "No devcontainer.json found in workspace.\n\
             Use --image to specify a container image or set default-image in config."
            );
        };

    // Detect if the user has a fork of the repository
    let fork_url = if let Some(repo_ref) = forge::parse_repo_url(&remote_url) {
        if repo_ref.forge_type == forge::ForgeType::GitHub {
            forge::fetch_github_user_fork(&repo_ref, Some(config))
                .await
                .map(|info| info.clone_url)
        } else {
            None
        }
    } else {
        None
    };

    // Determine workspace source: local path or remote URL.
    // The workspace state file records the original source string, which is
    // a local path for `devaipod up .` and a URL for remote repos.
    let source = if std::path::Path::new(&remote_url).exists() {
        // Local repository — detect git info from the path
        let git_info = git::detect_git_info(std::path::Path::new(&remote_url))?;
        pod::WorkspaceSource::LocalRepo(git_info)
    } else if !remote_url.is_empty() {
        let remote_info = git::RemoteRepoInfo {
            remote_url: remote_url.clone(),
            default_branch,
            repo_name,
            fork_url,
        };
        pod::WorkspaceSource::RemoteRepo(remote_info)
    } else if ws_state.as_ref().is_some_and(|s| s.source == "scratch") {
        pod::WorkspaceSource::Scratch
    } else {
        bail!(
            "Cannot determine source for rebuild. Pod '{}' has no repo label and no workspace state.",
            pod_name
        );
    };

    // Now stop and remove the pod (volumes are preserved)
    tracing::info!("Stopping containers...");
    let stop_output = podman_command()
        .args(["pod", "stop", "--", pod_name])
        .output()
        .context("Failed to stop pod")?;

    if !stop_output.status.success() {
        tracing::debug!(
            "Pod stop returned non-zero (may already be stopped): {}",
            String::from_utf8_lossy(&stop_output.stderr).trim()
        );
    }

    tracing::info!("Removing containers (keeping volumes)...");
    let rm_output = podman_command()
        .args(["pod", "rm", "--force", "--", pod_name])
        .output()
        .context("Failed to remove pod")?;

    if !rm_output.status.success() {
        let stderr = String::from_utf8_lossy(&rm_output.stderr);
        bail!("Failed to remove pod: {}", stderr.trim());
    }

    let enable_gator = config.service_gator.is_enabled();

    // Build extra labels (including instance tag if set)
    let mut extra_labels = Vec::new();
    if let Some(ref task_desc) = task {
        extra_labels.push(("io.devaipod.task".to_string(), task_desc.clone()));
    }
    if let Some(instance_id) = get_instance_id() {
        extra_labels.push((INSTANCE_LABEL_KEY.to_string(), instance_id));
    }

    // Recreate the pod - volumes already exist so they'll be reused
    // Note: We don't pass the task for rebuilds - the agent home volume persists
    // and contains the original task file, so it will be picked up on restart.
    tracing::info!("Recreating containers with new image...");

    // Use image_override if provided, then dotfiles image, then default_image from config
    let effective_image_override: Option<String> = image_override
        .map(|s| s.to_string())
        .or(dotfiles_image)
        .or_else(|| config.default_image.clone());

    // Create agent backend
    let (agent_name, agent_profile) = config.agent.resolve_profile(None);
    let backend = create_agent_backend(&agent_name, agent_profile, &config.agent)?;

    let devaipod_pod = pod::DevaipodPod::create(
        &podman,
        temp_path,
        &devcontainer_config,
        pod_name,
        enable_gator,
        config,
        &source,
        &extra_labels,
        None,
        effective_image_override.as_deref(),
        None, // gator_image_override not yet supported for rebuild
        None, // task - agent home volume persists with original task
        config.orchestration.is_enabled(),
        config.orchestration.worker.gator.clone(),
        &[],  // source_dirs: not supported for rebuild yet
        backend.as_ref(),
    )
    .await
    .context("Failed to recreate pod")?;

    let lifecycle_mode = if run_create {
        LifecycleMode::Full
    } else {
        LifecycleMode::Rebuild
    };

    finalize_pod_with_mode(
        &podman,
        &devaipod_pod,
        &devcontainer_config,
        config,
        lifecycle_mode,
    )
    .await?;

    tracing::info!(
        "Workspace '{}' rebuilt successfully",
        strip_pod_prefix(pod_name)
    );

    Ok(())
}

/// View container logs
fn cmd_logs(pod_name: &str, container: &str, follow: bool, tail: Option<u32>) -> Result<()> {
    let container_name = format!("{}-{}", pod_name, container);

    let mut cmd = podman_command();
    cmd.arg("logs");

    if follow {
        cmd.arg("-f");
    }

    // Convert tail to string outside of the conditional to ensure it lives long enough
    let tail_str;
    if let Some(n) = tail {
        tail_str = n.to_string();
        cmd.args(["--tail", &tail_str]);
    }

    cmd.arg(&container_name);

    let status = cmd.status().context("Failed to get container logs")?;

    if !status.success() {
        bail!(
            "Container '{}' not found or not running. Use 'devaipod list' to see pods.",
            container_name
        );
    }

    Ok(())
}

/// Show detailed status of a pod
fn cmd_status(pod_name: &str, json_output: bool) -> Result<()> {
    // Get pod info using podman pod inspect
    let pod_output = podman_command()
        .args(["pod", "inspect", "--", pod_name])
        .output()
        .context("Failed to run podman pod inspect")?;

    if !pod_output.status.success() {
        let stderr = String::from_utf8_lossy(&pod_output.stderr);
        if stderr.contains("no such pod") || stderr.contains("not found") {
            bail!(
                "Pod '{}' not found. Use 'devaipod list' to see available pods.",
                pod_name
            );
        }
        bail!("podman pod inspect failed: {}", stderr.trim());
    }

    let pod_json_array: serde_json::Value =
        serde_json::from_slice(&pod_output.stdout).context("Failed to parse pod inspect output")?;

    // podman pod inspect returns an array, get the first element
    let pod_json = pod_json_array
        .as_array()
        .and_then(|arr| arr.first())
        .cloned()
        .unwrap_or(pod_json_array);

    // Get container list using podman container ls
    let containers_output = podman_command()
        .args([
            "container",
            "ls",
            "--all",
            "--filter",
            &format!("pod={}", pod_name),
            "--format",
            "json",
        ])
        .output()
        .context("Failed to run podman container ls")?;

    let containers_json: serde_json::Value = if containers_output.status.success() {
        serde_json::from_slice(&containers_output.stdout).unwrap_or(serde_json::json!([]))
    } else {
        serde_json::json!([])
    };

    // Check agent health if pod is running
    let pod_state = pod_json
        .get("State")
        .and_then(|s| s.as_str())
        .unwrap_or("Unknown");

    let agent_health = if pod_state == "Running" {
        check_agent_health(pod_name)
    } else {
        None
    };

    // Get ports from pod
    let ports = extract_pod_ports(&pod_json);

    // Extract service-gator config from pod labels
    let gator_config = extract_service_gator_label(&pod_json);

    if json_output {
        // Build JSON output
        let status = serde_json::json!({
            "pod": {
                "name": pod_name,
                "state": pod_state,
                "id": pod_json.get("Id").and_then(|v| v.as_str()).unwrap_or(""),
            },
            "containers": containers_json,
            "agent_health": agent_health,
            "ports": ports,
            "service_gator": gator_config,
        });
        println!("{}", serde_json::to_string_pretty(&status)?);
    } else {
        // Human-readable output
        println!("Pod: {}", pod_name);
        println!("Status: {}", format_pod_state(pod_state));
        if let Some(id) = pod_json.get("Id").and_then(|v| v.as_str()) {
            // Show short ID
            println!("ID: {}", &id[..12.min(id.len())]);
        }
        println!();

        // Containers section
        println!("Containers:");
        if let Some(containers) = containers_json.as_array() {
            if containers.is_empty() {
                println!("  (none)");
            } else {
                for container in containers {
                    let name = container
                        .get("Names")
                        .and_then(|n| n.as_array())
                        .and_then(|a| a.first())
                        .and_then(|v| v.as_str())
                        .unwrap_or("unknown");
                    let state = container
                        .get("State")
                        .and_then(|s| s.as_str())
                        .unwrap_or("unknown");
                    let image = container
                        .get("Image")
                        .and_then(|s| s.as_str())
                        .unwrap_or("unknown");
                    // Truncate image name for display
                    let image_display = if image.len() > 40 {
                        format!("{}...", &image[..37])
                    } else {
                        image.to_string()
                    };
                    println!(
                        "  {} - {} ({})",
                        name,
                        format_container_state(state),
                        image_display
                    );
                }
            }
        }
        println!();

        // Agent health section
        println!("Agent Health:");
        match agent_health {
            Some(true) => println!("  Healthy (responding at localhost:{})", pod::OPENCODE_PORT),
            Some(false) => println!("  Unhealthy (not responding)"),
            None => println!("  Unknown (pod not running)"),
        }
        println!();

        // Ports section
        println!("Exposed Ports:");
        if ports.is_empty() {
            println!("  (none)");
        } else {
            for port in &ports {
                println!("  {}", port);
            }
        }
        println!();

        // Service-gator section
        println!("Service-Gator:");
        if let Some(ref config) = gator_config {
            println!("  {}", config);
        } else {
            println!("  (not configured)");
        }
    }

    Ok(())
}

/// Debug and diagnose a workspace
///
/// Collects diagnostic information about the pod, gator, and agent.
fn cmd_debug(pod_name: &str, json_output: bool) -> Result<()> {
    use serde_json::json;

    // Get pod info
    let pod_output = podman_command()
        .args(["pod", "inspect", "--", pod_name])
        .output()
        .context("Failed to run podman pod inspect")?;

    if !pod_output.status.success() {
        let stderr = String::from_utf8_lossy(&pod_output.stderr);
        if stderr.contains("no such pod") || stderr.contains("not found") {
            bail!(
                "Pod '{}' not found. Use 'devaipod list' to see available pods.",
                pod_name
            );
        }
        bail!("podman pod inspect failed: {}", stderr.trim());
    }

    let pod_json_array: serde_json::Value =
        serde_json::from_slice(&pod_output.stdout).context("Failed to parse pod inspect output")?;
    let pod_json = pod_json_array
        .as_array()
        .and_then(|arr| arr.first())
        .cloned()
        .unwrap_or(pod_json_array);

    let pod_state = pod_json
        .get("State")
        .and_then(|s| s.as_str())
        .unwrap_or("Unknown");

    // Extract project name from labels
    let project_name = pod_json
        .get("Labels")
        .and_then(|l| l.get("io.devaipod.repo"))
        .and_then(|v| v.as_str())
        .map(|s| s.rsplit('/').next().unwrap_or(s))
        .unwrap_or("unknown");

    // Check gator container
    let gator_container = format!("{}-gator", pod_name);
    let gator_info = collect_gator_debug(&gator_container, project_name);

    // Check agent container
    let agent_info = collect_agent_debug(pod_name);

    // Check MCP connectivity
    let mcp_info = collect_mcp_debug(pod_name);

    if json_output {
        let debug_info = json!({
            "pod": {
                "name": pod_name,
                "state": pod_state,
                "project": project_name,
            },
            "gator": gator_info,
            "agent": agent_info,
            "mcp": mcp_info,
        });
        println!("{}", serde_json::to_string_pretty(&debug_info)?);
    } else {
        println!("=== Pod Debug: {} ===\n", pod_name);
        println!("State: {}", format_pod_state(pod_state));
        println!("Project: {}", project_name);
        println!();

        // Gator section
        println!("--- Gator Container ---");
        if let Some(info) = &gator_info {
            println!(
                "  Present: {}",
                if info
                    .get("present")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false)
                {
                    "yes"
                } else {
                    "no"
                }
            );
            if let Some(version) = info.get("version").and_then(|v| v.as_str()) {
                println!("  Version: {}", version);
            }
            if let Some(mount_type) = info.get("mount_type").and_then(|v| v.as_str()) {
                let readonly = info
                    .get("mount_readonly")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
                println!(
                    "  Workspace mount: {} ({})",
                    mount_type,
                    if readonly { "read-only" } else { "read-write" }
                );
            }
            if let Some(git_ok) = info.get("git_accessible").and_then(|v| v.as_bool()) {
                println!(
                    "  Git accessible: {}",
                    if git_ok { "yes" } else { "NO - check mount!" }
                );
            }
        } else {
            println!("  (not present or error inspecting)");
        }
        println!();

        // Agent section
        println!("--- Agent Container ---");
        if let Some(info) = &agent_info {
            if let Some(healthy) = info.get("healthy").and_then(|v| v.as_bool()) {
                println!(
                    "  Health: {}",
                    if healthy { "healthy" } else { "NOT responding" }
                );
            }
            if let Some(mcp_config) = info.get("mcp_configured").and_then(|v| v.as_bool()) {
                println!(
                    "  MCP configured: {}",
                    if mcp_config { "yes" } else { "no" }
                );
            }
        } else {
            println!("  (error checking agent)");
        }
        println!();

        // MCP section
        println!("--- MCP Connectivity ---");
        if let Some(info) = &mcp_info {
            if let Some(reachable) = info.get("gator_reachable").and_then(|v| v.as_bool()) {
                println!(
                    "  Gator reachable from agent: {}",
                    if reachable { "yes" } else { "NO" }
                );
            }
        } else {
            println!("  (unable to check)");
        }
    }

    Ok(())
}

/// Collect debug info for the gator container
fn collect_gator_debug(gator_container: &str, project_name: &str) -> Option<serde_json::Value> {
    use serde_json::json;

    // Check if container exists
    let inspect_output = podman_command()
        .args(["inspect", gator_container])
        .output()
        .ok()?;

    if !inspect_output.status.success() {
        return Some(json!({ "present": false }));
    }

    let container_json: serde_json::Value = serde_json::from_slice(&inspect_output.stdout).ok()?;
    let container = container_json.as_array()?.first()?;

    // Get version
    let version_output = podman_command()
        .args(["exec", gator_container, "service-gator", "--version"])
        .output()
        .ok();
    let version = version_output
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string());

    // Get mount info
    let mounts = container.get("Mounts")?.as_array()?;
    let workspace_mount = mounts.iter().find(|m| {
        m.get("Destination")
            .and_then(|d| d.as_str())
            .map(|d| d.starts_with("/workspaces"))
            .unwrap_or(false)
    });

    let (mount_type, mount_readonly) = workspace_mount
        .map(|m| {
            let t = m.get("Type").and_then(|v| v.as_str()).unwrap_or("unknown");
            let rw = m.get("RW").and_then(|v| v.as_bool()).unwrap_or(true);
            (t.to_string(), !rw)
        })
        .unwrap_or(("none".to_string(), false));

    // Check if .git is accessible
    let git_path = format!("/workspaces/{}/.git", project_name);
    let git_check = podman_command()
        .args(["exec", gator_container, "test", "-d", &git_path])
        .status()
        .ok();
    let git_accessible = git_check.map(|s| s.success()).unwrap_or(false);

    Some(json!({
        "present": true,
        "version": version,
        "mount_type": mount_type,
        "mount_readonly": mount_readonly,
        "git_accessible": git_accessible,
    }))
}

/// Collect debug info for the agent container
fn collect_agent_debug(pod_name: &str) -> Option<serde_json::Value> {
    use serde_json::json;

    let agent_container = format!("{}-agent", pod_name);

    // Check health
    let healthy = check_agent_health(pod_name);

    // Check if MCP is configured (look at OPENCODE_CONFIG_CONTENT env)
    let env_check = podman_command()
        .args([
            "exec",
            &agent_container,
            "/bin/sh",
            "-c",
            "echo $OPENCODE_CONFIG_CONTENT",
        ])
        .output()
        .ok();
    let mcp_configured = env_check
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).contains("service-gator"))
        .unwrap_or(false);

    Some(json!({
        "healthy": healthy,
        "mcp_configured": mcp_configured,
    }))
}

/// Collect MCP connectivity info
fn collect_mcp_debug(pod_name: &str) -> Option<serde_json::Value> {
    use serde_json::json;

    let agent_container = format!("{}-agent", pod_name);

    // Test if gator port is reachable from agent
    let port_check = format!("nc -z localhost {} 2>/dev/null", pod::GATOR_PORT);
    let gator_reachable = podman_command()
        .args(["exec", &agent_container, "/bin/sh", "-c", &port_check])
        .status()
        .ok()
        .map(|s| s.success())
        .unwrap_or(false);

    Some(json!({
        "gator_reachable": gator_reachable,
    }))
}

/// Interact with the opencode agent programmatically
async fn cmd_opencode(pod_name: &str, action: OpencodeAction) -> Result<()> {
    // Verify pod exists and is running
    // Check if the agent is healthy first
    if check_agent_health(pod_name) != Some(true) {
        bail!(
            "Agent is not responding in pod '{}'. Is the pod running?",
            pod_name
        );
    }

    match action {
        OpencodeAction::Mcp { action } => cmd_opencode_mcp(pod_name, action),
        OpencodeAction::Session { action } => cmd_opencode_session(pod_name, action),
        OpencodeAction::Send {
            message,
            session,
            json,
        } => cmd_opencode_send(pod_name, &message, session.as_deref(), json),
        OpencodeAction::Status { json } => cmd_opencode_status(pod_name, json),
    }
}

/// Detect an existing active session to continue
///
/// This enables seamless handoff from autonomous mode (`devaipod run "task"`)
/// to interactive mode (`devaipod attach`). We look for root sessions (those
/// without a parent) and return the oldest one, which is typically the main
/// task session.
///
/// If `port` is provided, queries that specific port; otherwise uses the default
/// coordinator agent port.
///
/// Returns None if no session is found or if there's an error (fail-open).
fn detect_active_session(pod_name: &str, port: Option<u16>) -> Option<String> {
    // Try to get sessions from the API
    let sessions = match opencode_api_get_port(pod_name, "/session", port) {
        Ok(s) => s,
        Err(_) => return None,
    };

    let sessions = sessions.as_array()?;
    if sessions.is_empty() {
        return None;
    }

    // Find root sessions (those without a parentID)
    // These are the main task sessions, not subagent sessions
    let mut root_sessions: Vec<_> = sessions.iter().filter(|s| session_is_root(s)).collect();

    if root_sessions.is_empty() {
        // No root sessions, just use the first session
        return sessions.first()?.get("id")?.as_str().map(|s| s.to_string());
    }

    // Sort by creation time (oldest first) - we want the original task session
    root_sessions.sort_by(|a, b| {
        let time_a = a
            .get("time")
            .and_then(|t| t.get("created"))
            .and_then(|c| c.as_i64())
            .unwrap_or(0);
        let time_b = b
            .get("time")
            .and_then(|t| t.get("created"))
            .and_then(|c| c.as_i64())
            .unwrap_or(0);
        time_a.cmp(&time_b)
    });

    root_sessions
        .first()
        .and_then(|s| s.get("id"))
        .and_then(|id| id.as_str())
        .map(|s| s.to_string())
}

/// Execute a curl command in the workspace container and return the output
/// (Legacy approach for pods without published API)
fn opencode_api_get(pod_name: &str, path: &str) -> Result<serde_json::Value> {
    opencode_api_get_port(pod_name, path, None)
}

/// Execute a curl command in the agent container with a specific port
fn opencode_api_get_port(
    pod_name: &str,
    path: &str,
    port: Option<u16>,
) -> Result<serde_json::Value> {
    let agent_container = format!("{}-agent", pod_name);
    let port = port.unwrap_or(pod::OPENCODE_PORT);
    let url = format!("http://localhost:{}{}", port, path);

    let output = podman_command()
        .args(["exec", &agent_container, "curl", "-sf", &url])
        .output()
        .context("Failed to execute curl in agent container")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("API request to {} failed: {}", path, stderr.trim());
    }

    serde_json::from_slice(&output.stdout)
        .with_context(|| format!("Failed to parse JSON response from {}", path))
}

/// Execute a POST request to the opencode API
fn opencode_api_post(pod_name: &str, path: &str, body: &str) -> Result<serde_json::Value> {
    let agent_container = format!("{}-agent", pod_name);
    let url = format!("http://localhost:{}{}", pod::OPENCODE_PORT, path);

    let output = podman_command()
        .args([
            "exec",
            &agent_container,
            "curl",
            "-sf",
            "-X",
            "POST",
            "-H",
            "Content-Type: application/json",
            "-d",
            body,
            &url,
        ])
        .output()
        .context("Failed to execute curl in agent container")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("API POST to {} failed: {}", path, stderr.trim());
    }

    serde_json::from_slice(&output.stdout)
        .with_context(|| format!("Failed to parse JSON response from {}", path))
}

/// Handle MCP subcommands
fn cmd_opencode_mcp(pod_name: &str, action: McpAction) -> Result<()> {
    match action {
        McpAction::List { json } => {
            let mcp_status = opencode_api_get(pod_name, "/mcp")?;

            if json {
                println!("{}", serde_json::to_string_pretty(&mcp_status)?);
            } else {
                println!("MCP Servers:");
                if let Some(obj) = mcp_status.as_object() {
                    if obj.is_empty() {
                        println!("  (none configured)");
                    } else {
                        for (name, info) in obj {
                            let status = info
                                .get("status")
                                .and_then(|s| s.as_str())
                                .unwrap_or("unknown");
                            let icon = if status == "connected" { "✓" } else { "✗" };
                            println!("  {} {} ({})", icon, name, status);
                        }
                    }
                }
            }
            Ok(())
        }
        McpAction::Tools { server, json } => {
            let tools = opencode_api_get(pod_name, "/experimental/tool/ids")?;

            if json {
                println!("{}", serde_json::to_string_pretty(&tools)?);
            } else {
                println!("Available Tools:");
                if let Some(arr) = tools.as_array() {
                    let filtered: Vec<_> = arr
                        .iter()
                        .filter_map(|t| t.as_str())
                        .filter(|t| server.as_ref().map(|s| t.starts_with(s)).unwrap_or(true))
                        .collect();

                    if filtered.is_empty() {
                        println!("  (none)");
                    } else {
                        for tool in filtered {
                            println!("  {}", tool);
                        }
                    }
                }
            }
            Ok(())
        }
    }
}

/// Handle session subcommands
fn cmd_opencode_session(pod_name: &str, action: SessionAction) -> Result<()> {
    match action {
        SessionAction::List { json } => {
            let sessions = opencode_api_get(pod_name, "/session")?;

            if json {
                println!("{}", serde_json::to_string_pretty(&sessions)?);
            } else {
                println!("Sessions:");
                if let Some(arr) = sessions.as_array() {
                    // Only show root sessions (not subagent sessions).
                    let root_sessions: Vec<_> = arr.iter().filter(|s| session_is_root(s)).collect();
                    if root_sessions.is_empty() {
                        println!("  (none)");
                    } else {
                        for session in &root_sessions {
                            let id = session.get("id").and_then(|v| v.as_str()).unwrap_or("?");
                            let title = session
                                .get("title")
                                .and_then(|v| v.as_str())
                                .unwrap_or("Untitled");
                            // Truncate long titles
                            let title_display = if title.len() > 50 {
                                format!("{}...", &title[..47])
                            } else {
                                title.to_string()
                            };
                            println!("  {} - {}", &id[..12.min(id.len())], title_display);
                        }
                    }
                }
            }
            Ok(())
        }
        SessionAction::Show { id, json } => {
            let session = opencode_api_get(pod_name, &format!("/session/{}", id))?;

            if json {
                println!("{}", serde_json::to_string_pretty(&session)?);
            } else {
                println!("Session: {}", id);
                if let Some(title) = session.get("title").and_then(|v| v.as_str()) {
                    println!("Title: {}", title);
                }
                if let Some(dir) = session.get("directory").and_then(|v| v.as_str()) {
                    println!("Directory: {}", dir);
                }
            }
            Ok(())
        }
    }
}

/// Send a message to the agent
fn cmd_opencode_send(
    pod_name: &str,
    message: &str,
    session_id: Option<&str>,
    json_output: bool,
) -> Result<()> {
    // Create or use existing session
    let session_id = match session_id {
        Some(id) => id.to_string(),
        None => {
            // Create a new session
            let session = opencode_api_post(pod_name, "/session", "{}")?;
            session
                .get("id")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string())
                .ok_or_else(|| color_eyre::eyre::eyre!("Failed to get session ID from response"))?
        }
    };

    // Build message payload
    let payload = serde_json::json!({
        "parts": [{"type": "text", "text": message}]
    });

    // Send message
    let response = opencode_api_post(
        pod_name,
        &format!("/session/{}/message", session_id),
        &payload.to_string(),
    )?;

    if json_output {
        println!("{}", serde_json::to_string_pretty(&response)?);
    } else {
        // Extract and print the text response
        if let Some(parts) = response.get("parts").and_then(|p| p.as_array()) {
            for part in parts {
                if let Some("text") = part.get("type").and_then(|t| t.as_str())
                    && let Some(text) = part.get("text").and_then(|t| t.as_str())
                {
                    println!("{}", text);
                }
            }
        }
        // Show session ID for follow-up
        eprintln!("\n(session: {})", session_id);
    }

    Ok(())
}

/// Show agent status
fn cmd_opencode_status(pod_name: &str, json_output: bool) -> Result<()> {
    let health = opencode_api_get(pod_name, "/global/health")?;
    let mcp = opencode_api_get(pod_name, "/mcp")?;
    let sessions = opencode_api_get(pod_name, "/session")?;

    if json_output {
        let status = serde_json::json!({
            "health": health,
            "mcp": mcp,
            "session_count": sessions.as_array().map(|a| a.len()).unwrap_or(0),
        });
        println!("{}", serde_json::to_string_pretty(&status)?);
    } else {
        println!("Agent Status:");
        if let Some(version) = health.get("version").and_then(|v| v.as_str()) {
            println!("  Version: {}", version);
        }
        println!("  Health: OK");

        println!("\nMCP Servers:");
        if let Some(obj) = mcp.as_object() {
            if obj.is_empty() {
                println!("  (none)");
            } else {
                for (name, info) in obj {
                    let status = info
                        .get("status")
                        .and_then(|s| s.as_str())
                        .unwrap_or("unknown");
                    println!("  {} - {}", name, status);
                }
            }
        }

        let session_count = sessions.as_array().map(|a| a.len()).unwrap_or(0);
        println!("\nSessions: {}", session_count);
    }

    Ok(())
}

/// Check if the agent is listening on its port
fn check_agent_health(pod_name: &str) -> Option<bool> {
    let api_container = format!("{}-api", pod_name);

    // Check the pod-api sidecar's health endpoint. With ACP, the agent
    // communicates via stdio (no HTTP port), so we check the sidecar
    // that manages the agent lifecycle.
    let result = podman_command()
        .args([
            "exec",
            &api_container,
            "curl",
            "-sf",
            &format!("http://localhost:{}/healthz", pod::POD_API_PORT),
        ])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();

    match result {
        Ok(status) => Some(status.success()),
        Err(_) => None,
    }
}

/// Extract service-gator config from pod labels
fn extract_service_gator_label(pod_json: &serde_json::Value) -> Option<String> {
    pod_json
        .get("Labels")
        .and_then(|labels| labels.get("io.devaipod.service-gator"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
}

/// Extract exposed ports from pod inspect JSON
fn extract_pod_ports(pod_json: &serde_json::Value) -> Vec<String> {
    let mut ports = Vec::new();

    // Ports are typically in InfraConfig.PortBindings
    if let Some(infra) = pod_json.get("InfraConfig")
        && let Some(bindings) = infra.get("PortBindings")
        && let Some(obj) = bindings.as_object()
    {
        for (container_port, host_bindings) in obj {
            if let Some(arr) = host_bindings.as_array() {
                for binding in arr {
                    let host_ip = binding
                        .get("HostIp")
                        .and_then(|v| v.as_str())
                        .unwrap_or("0.0.0.0");
                    let host_port = binding
                        .get("HostPort")
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    if !host_port.is_empty() {
                        ports.push(format!("{}:{} -> {}", host_ip, host_port, container_port));
                    }
                }
            }
        }
    }

    ports
}

/// Format pod state for display
fn format_pod_state(state: &str) -> &str {
    match state {
        "Running" => "Running",
        "Stopped" => "Stopped",
        "Exited" => "Exited",
        "Created" => "Created",
        "Paused" => "Paused",
        "Degraded" => "Degraded",
        _ => state,
    }
}

/// Format container state for display
fn format_container_state(state: &str) -> &str {
    match state.to_lowercase().as_str() {
        "running" => "running",
        "exited" => "exited",
        "created" => "created",
        "paused" => "paused",
        "dead" => "dead",
        "removing" => "removing",
        _ => state,
    }
}

/// Generate shell completions
fn cmd_completions(shell: clap_complete::Shell) -> Result<()> {
    let mut cmd = HostCli::command();
    clap_complete::generate(shell, &mut cmd, "devaipod-server", &mut std::io::stdout());
    Ok(())
}

/// Check if we're running inside a devpod devcontainer
///
/// DevPod sets `DEVPOD=true` in devcontainers it creates.
/// This distinguishes devaipod devcontainers from other container
/// environments like toolbox containers.
fn is_inside_devcontainer() -> bool {
    std::env::var("DEVPOD")
        .map(|v| v == "true")
        .unwrap_or(false)
}

/// Check if we're running inside the official devaipod container
///
/// The devaipod container sets `DEVAIPOD_CONTAINER=1` to indicate
/// that we're running in the expected environment.
fn is_inside_devaipod_container() -> bool {
    std::env::var("DEVAIPOD_CONTAINER")
        .map(|v| v == "1")
        .unwrap_or(false)
}

/// Check if host mode is enabled via environment variable
fn is_host_mode_env() -> bool {
    std::env::var("DEVAIPOD_HOST_MODE")
        .map(|v| v == "1")
        .unwrap_or(false)
}

/// Standard path for the podman socket (started by devaipod-init.sh)
const PODMAN_SOCKET: &str = "/run/podman/podman.sock";

/// Configure the container environment for nested containers.
///
/// This command is idempotent and should be run at container startup.
/// It configures:
/// - /etc/containers/containers.conf with nested-friendly defaults
/// - /etc/subuid and /etc/subgid for nested user namespaces
/// - Starts the podman service at /run/podman/podman.sock
/// - Sets up /etc/profile.d/podman-remote.sh for CONTAINER_HOST
fn cmd_configure_env() -> Result<()> {
    // Must run as root
    if !rustix::process::geteuid().is_root() {
        bail!("configure-env must be run as root (use sudo)");
    }

    configure_containers_conf()?;
    configure_subuid()?;
    configure_podman_service()?;
    configure_profile()?;

    tracing::info!("Container environment configured successfully");
    Ok(())
}

/// Configure /etc/containers/containers.conf for nested containers
fn configure_containers_conf() -> Result<()> {
    let conf_dir = Path::new("/etc/containers");
    let conf_path = conf_dir.join("containers.conf");

    // Create directory if needed
    std::fs::create_dir_all(conf_dir).context("Failed to create /etc/containers")?;

    // Build the TOML configuration as a string (easier to include comments)
    let config_str = r#"[containers]
# Disable cgroups - nested cgroups don't work in user namespaces
cgroups = "disabled"
# Use host network - avoids network namespace issues
netns = "host"
# Use cgroupfs manager (systemd not available in containers)
cgroup_manager = "cgroupfs"
# Allow ping without special capabilities
default_sysctls = ["net.ipv4.ping_group_range=0 0"]

[engine]
cgroup_manager = "cgroupfs"
"#;

    // Check if already configured correctly
    if conf_path.exists() {
        let existing = std::fs::read_to_string(&conf_path).unwrap_or_default();
        if existing == config_str {
            tracing::debug!("containers.conf already configured");
            return Ok(());
        }
    }

    let full_config = format!(
        "# Generated by devaipod configure-env\n\
         # Optimized for nested container environments\n\n\
         {config_str}"
    );
    std::fs::write(&conf_path, &full_config).context("Failed to write containers.conf")?;

    tracing::info!("Configured {}", conf_path.display());
    Ok(())
}

/// Configure /etc/subuid and /etc/subgid for nested user namespaces
fn configure_subuid() -> Result<()> {
    // Find the container user
    let user = ["vscode", "devenv", "codespace"]
        .iter()
        .find(|u| {
            ProcessCommand::new("id")
                .arg(u)
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status()
                .map(|s| s.success())
                .unwrap_or(false)
        })
        .copied();

    let Some(user) = user else {
        tracing::debug!("No standard container user found, skipping subuid configuration");
        return Ok(());
    };

    // Parse /proc/self/uid_map to find max UID in this namespace
    let uid_map = std::fs::read_to_string("/proc/self/uid_map").unwrap_or_default();
    let max_uid: u64 = uid_map
        .lines()
        .filter_map(|line| {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 3 {
                let inside: u64 = parts[0].parse().ok()?;
                let count: u64 = parts[2].parse().ok()?;
                Some(inside + count)
            } else {
                None
            }
        })
        .max()
        .unwrap_or(0);

    // If we have full UID range, default config should work
    if max_uid > 100000 {
        tracing::debug!(
            "Full UID range available (max={}), using default subuid",
            max_uid
        );
        return Ok(());
    }

    // Check if current subuid config already works
    let current_subuid = std::fs::read_to_string("/etc/subuid").unwrap_or_default();
    if let Some(line) = current_subuid
        .lines()
        .find(|l| l.starts_with(&format!("{}:", user)))
        && let Some(start_str) = line.split(':').nth(1)
        && let Ok(start) = start_str.parse::<u64>()
        && start > 0
        && start < max_uid
    {
        tracing::debug!("subuid already configured correctly for {}", user);
        return Ok(());
    }

    // Reconfigure for constrained namespace
    let subuid_start: u64 = 10000;
    let subuid_count = max_uid.saturating_sub(subuid_start);

    if subuid_count < 1000 {
        tracing::warn!(
            "Limited UID range (max={}), nested podman may not work",
            max_uid
        );
        return Ok(());
    }

    let subuid_entry = format!("{}:{}:{}\n", user, subuid_start, subuid_count);

    std::fs::write("/etc/subuid", &subuid_entry).context("Failed to write /etc/subuid")?;
    std::fs::write("/etc/subgid", &subuid_entry).context("Failed to write /etc/subgid")?;

    tracing::info!(
        "Configured subuid/subgid: {}:{}:{}",
        user,
        subuid_start,
        subuid_count
    );

    // Reset podman storage if it exists (may have wrong mappings)
    let user_home = std::env::var("HOME").unwrap_or_else(|_| format!("/home/{}", user));
    let storage_path = PathBuf::from(&user_home).join(".local/share/containers/storage");
    if storage_path.exists() {
        tracing::info!("Resetting podman storage for new UID mappings");
        let _ = std::fs::remove_dir_all(&storage_path);
    }

    Ok(())
}

/// Start the podman service
fn configure_podman_service() -> Result<()> {
    let socket_path = Path::new(PODMAN_SOCKET);
    let socket_dir = socket_path.parent().unwrap();

    // Check if podman is available
    if !ProcessCommand::new("podman")
        .arg("--version")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
    {
        tracing::debug!("podman not found, skipping service setup");
        return Ok(());
    }

    // Check if already running
    if socket_path.exists() {
        // Try to connect to verify it's working
        if ProcessCommand::new("podman")
            .args(["--remote", "info"])
            .env(
                "CONTAINER_HOST",
                format!("unix://{}", socket_path.display()),
            )
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
        {
            tracing::debug!("Podman service already running");
            return Ok(());
        }
        // Socket exists but not working, remove it
        let _ = std::fs::remove_file(socket_path);
    }

    // Create socket directory
    std::fs::create_dir_all(socket_dir).context("Failed to create /run/podman")?;

    // Start podman service in background.
    // Use pre_exec to set PR_SET_PDEATHSIG so the child dies with us.
    let mut cmd = ProcessCommand::new("podman");
    cmd.args(["system", "service", "--time=0"])
        .arg(format!("unix://{}", socket_path.display()))
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());

    // Lifecycle-bind the child to this process: if we exit, the kernel
    // sends SIGTERM to the podman service. No orphans, no timeouts.
    #[cfg(target_os = "linux")]
    {
        use cap_std_ext::cmdext::CapStdExtCommandExt;
        cmd.lifecycle_bind_to_parent_thread();
    }

    cmd.spawn().context("Failed to start podman service")?;

    // Wait for socket to appear and chmod it
    for _ in 0..50 {
        if socket_path.exists() {
            // Make socket world-accessible
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(0o666);
            std::fs::set_permissions(socket_path, perms)?;
            tracing::info!("Podman service started at {}", socket_path.display());
            return Ok(());
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }

    bail!("Podman service did not start in time")
}

/// Configure /etc/profile.d/podman-remote.sh
fn configure_profile() -> Result<()> {
    let profile_path = Path::new("/etc/profile.d/devaipod-podman.sh");

    let content = r#"# Generated by devaipod configure-env
# Use rootful podman service (safe in rootless devcontainer)
if [ -S /run/podman/podman.sock ]; then
    export CONTAINER_HOST="unix:///run/podman/podman.sock"
fi
"#;

    // Check if already configured
    if profile_path.exists() {
        let existing = std::fs::read_to_string(profile_path).unwrap_or_default();
        if existing == content {
            tracing::debug!("Profile already configured");
            return Ok(());
        }
    }

    std::fs::write(profile_path, content).context("Failed to write profile.d script")?;
    tracing::info!("Configured {}", profile_path.display());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn test_host_cli_has_expected_commands() {
        // Verify HostCli has the expected host-only commands
        let cmd = HostCli::command();
        let subcommands: Vec<_> = cmd.get_subcommands().map(|c| c.get_name()).collect();

        assert!(subcommands.contains(&"up"), "Missing 'up' command");
        assert!(subcommands.contains(&"run"), "Missing 'run' command");
        assert!(subcommands.contains(&"exec"), "Missing 'exec' command");
        assert!(
            subcommands.contains(&"ssh-config"),
            "Missing 'ssh-config' command"
        );
        assert!(subcommands.contains(&"list"), "Missing 'list' command");
        assert!(subcommands.contains(&"stop"), "Missing 'stop' command");
        assert!(subcommands.contains(&"delete"), "Missing 'delete' command");
        assert!(subcommands.contains(&"logs"), "Missing 'logs' command");
        assert!(subcommands.contains(&"status"), "Missing 'status' command");
        assert!(subcommands.contains(&"fetch"), "Missing 'fetch' command");
        assert!(subcommands.contains(&"diff"), "Missing 'diff' command");
        assert!(
            subcommands.contains(&"completions"),
            "Missing 'completions' command"
        );
    }

    #[test]
    fn test_container_cli_has_expected_commands() {
        // Verify ContainerCli has the expected container-only commands
        let cmd = ContainerCli::command();
        let subcommands: Vec<_> = cmd.get_subcommands().map(|c| c.get_name()).collect();

        assert!(
            subcommands.contains(&"configure-env"),
            "Missing 'configure-env' command"
        );

        // Should NOT have host-only commands
        assert!(
            !subcommands.contains(&"up"),
            "'up' should not be in container CLI"
        );
    }

    #[test]
    fn test_is_inside_devcontainer_detection() {
        // This tests the detection function - result depends on runtime environment
        // Just verify it runs without panicking
        let _inside = is_inside_devcontainer();
    }

    #[test]
    fn test_get_attach_container_name_workspace() {
        let pod_name = "devaipod-myproject";
        let result = get_attach_container_name(pod_name, AttachTarget::Workspace);
        assert_eq!(result, "devaipod-myproject-workspace");
    }

    #[test]
    fn test_get_attach_container_name_agent() {
        let pod_name = "devaipod-myproject";
        let result = get_attach_container_name(pod_name, AttachTarget::Agent);
        assert_eq!(result, "devaipod-myproject-agent");
    }

    #[test]
    fn test_get_attach_container_name_with_special_chars() {
        // Pod names may contain dots and colons which get sanitized elsewhere,
        // but the container name function should handle them transparently
        let pod_name = "devaipod-my.project";
        assert_eq!(
            get_attach_container_name(pod_name, AttachTarget::Workspace),
            "devaipod-my.project-workspace"
        );
        assert_eq!(
            get_attach_container_name(pod_name, AttachTarget::Agent),
            "devaipod-my.project-agent"
        );
    }

    #[test]
    fn test_attach_target_equality() {
        // Verify that AttachTarget derives PartialEq correctly
        assert_eq!(AttachTarget::Workspace, AttachTarget::Workspace);
        assert_eq!(AttachTarget::Agent, AttachTarget::Agent);
        assert_ne!(AttachTarget::Workspace, AttachTarget::Agent);
    }

    #[test]
    fn test_normalize_pod_name_adds_prefix() {
        // Short name without prefix gets prefixed
        assert_eq!(normalize_pod_name("myproject"), "devaipod-myproject");
        assert_eq!(
            normalize_pod_name("playground-89e601"),
            "devaipod-playground-89e601"
        );
    }

    #[test]
    fn test_normalize_pod_name_idempotent() {
        // Name already with prefix should not be double-prefixed
        assert_eq!(
            normalize_pod_name("devaipod-myproject"),
            "devaipod-myproject"
        );
        assert_eq!(
            normalize_pod_name("devaipod-playground-89e601"),
            "devaipod-playground-89e601"
        );
    }

    #[test]
    fn test_normalize_pod_name_roundtrip() {
        // strip_pod_prefix and normalize_pod_name should roundtrip
        let short_name = "myproject";
        let full_name = normalize_pod_name(short_name);
        assert_eq!(strip_pod_prefix(&full_name), short_name);

        // Normalizing the full name again should be idempotent
        assert_eq!(normalize_pod_name(&full_name), full_name);
    }

    #[test]
    fn test_normalize_does_not_roundtrip_for_devaipod_project() {
        // When the project name itself is "devaipod", make_pod_name produces
        // "devaipod-devaipod-XXXX". Stripping the prefix yields "devaipod-XXXX"
        // which already starts with "devaipod-", so normalize_pod_name returns
        // it unchanged instead of re-adding the prefix.
        //
        // resolve_workspace() compensates for this by checking pod existence
        // and trying the double-prefix when the first lookup fails.
        let full_name = "devaipod-devaipod-a47a13";
        let stripped = strip_pod_prefix(full_name);
        assert_eq!(stripped, "devaipod-a47a13");
        // normalize does NOT recover the original:
        assert_eq!(normalize_pod_name(stripped), "devaipod-a47a13");
        assert_ne!(normalize_pod_name(stripped), full_name);
        // But passing the full name through normalize is fine (idempotent):
        assert_eq!(normalize_pod_name(full_name), full_name);
    }

    #[test]
    fn test_strip_pod_prefix() {
        assert_eq!(strip_pod_prefix("devaipod-myproject"), "myproject");
        assert_eq!(
            strip_pod_prefix("devaipod-playground-89e601"),
            "playground-89e601"
        );
        // Names without prefix are returned as-is
        assert_eq!(strip_pod_prefix("myproject"), "myproject");
    }

    #[test]
    fn test_sanitize_name_strips_leading_hyphens() {
        // Names starting with special chars that become hyphens should have them stripped
        assert_eq!(sanitize_name("-foo"), "foo");
        assert_eq!(sanitize_name("--bar"), "bar");
        assert_eq!(sanitize_name("---baz"), "baz");
        assert_eq!(sanitize_name(".dotfile"), "dotfile");
        assert_eq!(sanitize_name("_underscore"), "underscore");
        // Normal names are unchanged
        assert_eq!(sanitize_name("myproject"), "myproject");
        // Hyphens in the middle are preserved
        assert_eq!(sanitize_name("my-project"), "my-project");
        // Leading hyphens stripped, middle hyphens preserved
        assert_eq!(sanitize_name("-my-project"), "my-project");
        assert_eq!(sanitize_name("--my-project"), "my-project");
    }

    #[test]
    fn test_normalize_source_bare_github_url() {
        let no_extra: &[String] = &[];
        assert_eq!(
            normalize_source("github.com/owner/repo", no_extra).as_ref(),
            "https://github.com/owner/repo"
        );
        assert_eq!(
            normalize_source("gitlab.com/group/project", no_extra).as_ref(),
            "https://gitlab.com/group/project"
        );
        assert_eq!(
            normalize_source("codeberg.org/user/repo", no_extra).as_ref(),
            "https://codeberg.org/user/repo"
        );
    }

    #[test]
    fn test_normalize_source_ssh_url() {
        let no_extra: &[String] = &[];
        assert_eq!(
            normalize_source("git@github.com:owner/repo.git", no_extra).as_ref(),
            "https://github.com/owner/repo"
        );
        assert_eq!(
            normalize_source("git@gitlab.com:group/project.git", no_extra).as_ref(),
            "https://gitlab.com/group/project"
        );
        // Without .git suffix
        assert_eq!(
            normalize_source("git@github.com:owner/repo", no_extra).as_ref(),
            "https://github.com/owner/repo"
        );
    }

    #[test]
    fn test_normalize_source_already_valid() {
        let no_extra: &[String] = &[];
        // Already-valid URLs should pass through unchanged
        assert_eq!(
            normalize_source("https://github.com/owner/repo", no_extra).as_ref(),
            "https://github.com/owner/repo"
        );
        assert_eq!(
            normalize_source("http://example.com/repo", no_extra).as_ref(),
            "http://example.com/repo"
        );
        // Local paths should not be modified
        assert_eq!(
            normalize_source("/tmp/myrepo", no_extra).as_ref(),
            "/tmp/myrepo"
        );
        assert_eq!(normalize_source("./myrepo", no_extra).as_ref(), "./myrepo");
    }

    #[test]
    fn test_normalize_source_typo_fix() {
        let no_extra: &[String] = &[];
        assert_eq!(
            normalize_source("https;//github.com/owner/repo", no_extra).as_ref(),
            "https://github.com/owner/repo"
        );
    }

    #[test]
    fn test_normalize_source_extra_hosts() {
        let extra = vec![
            "forgejo.example.com".to_string(),
            "gitea.corp.internal".to_string(),
        ];
        assert_eq!(
            normalize_source("forgejo.example.com/user/repo", &extra).as_ref(),
            "https://forgejo.example.com/user/repo"
        );
        assert_eq!(
            normalize_source("gitea.corp.internal/team/project", &extra).as_ref(),
            "https://gitea.corp.internal/team/project"
        );
        // Unknown hosts still pass through
        assert_eq!(
            normalize_source("unknown.host/foo", &extra).as_ref(),
            "unknown.host/foo"
        );
        // Built-in hosts still work alongside extra hosts
        assert_eq!(
            normalize_source("github.com/owner/repo", &extra).as_ref(),
            "https://github.com/owner/repo"
        );
    }

    /// Data-driven edge-case tests for normalize_source.
    ///
    /// Each entry is (input, extra_hosts, expected_output).
    #[test]
    fn test_normalize_source_edge_cases() {
        let no_extra: &[String] = &[];
        let cases: &[(&str, &[String], &str)] = &[
            // SSH URL for an unknown host (git@ is a clear signal)
            (
                "git@gitea.private.corp:team/project.git",
                no_extra,
                "https://gitea.private.corp/team/project",
            ),
            // SSH URL without .git suffix on unknown host
            (
                "git@my.internal:org/repo",
                no_extra,
                "https://my.internal/org/repo",
            ),
            // Bare hostname with port (not a known host, passes through)
            (
                "gitea.local:3000/owner/repo",
                no_extra,
                "gitea.local:3000/owner/repo",
            ),
            // Empty extra_hosts behaves like no extra hosts
            ("unknown.host/foo", no_extra, "unknown.host/foo"),
            // http;// typo fix (not just https)
            (
                "http;//example.com/repo",
                no_extra,
                "http://example.com/repo",
            ),
            // Bare known host with no path (e.g. just "github.com")
            ("github.com", no_extra, "https://github.com"),
            // sr.ht style URL with tilde user
            ("sr.ht/~user/repo", no_extra, "https://sr.ht/~user/repo"),
            // bitbucket bare URL
            (
                "bitbucket.org/team/project",
                no_extra,
                "https://bitbucket.org/team/project",
            ),
            // gitea.com bare URL
            (
                "gitea.com/owner/repo",
                no_extra,
                "https://gitea.com/owner/repo",
            ),
            // Relative path (.) should not be modified
            (".", no_extra, "."),
            // Plain word (not a host) should not be modified
            ("myproject", no_extra, "myproject"),
        ];

        for (input, extra, expected) in cases {
            assert_eq!(
                normalize_source(input, extra).as_ref(),
                *expected,
                "normalize_source({:?}, ...) failed",
                input,
            );
        }
    }

    /// Verify that extra_hosts from config are used in bare-host matching.
    #[test]
    fn test_normalize_source_extra_hosts_with_port() {
        // A host with a port in extra_hosts should match bare URLs that
        // start with that host:port prefix.
        let extra = vec!["gitea.local:3000".to_string()];
        assert_eq!(
            normalize_source("gitea.local:3000/owner/repo", &extra).as_ref(),
            "https://gitea.local:3000/owner/repo",
        );
        // Without the extra_hosts entry, it passes through unchanged
        let no_extra: &[String] = &[];
        assert_eq!(
            normalize_source("gitea.local:3000/owner/repo", no_extra).as_ref(),
            "gitea.local:3000/owner/repo",
        );
    }

    #[test]
    fn test_extract_repo_suffix() {
        // Host path
        assert_eq!(
            extract_repo_suffix("/var/home/ai/src/github.com/org/repo"),
            Some("github.com/org/repo".to_string()),
        );
        // Container-internal path (different prefix, same suffix)
        assert_eq!(
            extract_repo_suffix("/mnt/src/github.com/org/repo"),
            Some("github.com/org/repo".to_string()),
        );
        // HTTPS URL
        assert_eq!(
            extract_repo_suffix("https://github.com/org/repo"),
            Some("github.com/org/repo".to_string()),
        );
        // HTTPS URL with .git suffix
        assert_eq!(
            extract_repo_suffix("https://github.com/org/repo.git"),
            Some("github.com/org/repo".to_string()),
        );
        // GitLab
        assert_eq!(
            extract_repo_suffix("/home/user/src/gitlab.com/group/project"),
            Some("gitlab.com/group/project".to_string()),
        );
        // No forge host => None
        assert_eq!(extract_repo_suffix("/tmp/myrepo"), None);
        // Path with TLD-less host name (common convention: ~/src/github/org/repo)
        assert_eq!(
            extract_repo_suffix("/home/user/github/org/repo"),
            Some("github.com/org/repo".to_string()),
        );
        // Container path with TLD-less host
        assert_eq!(
            extract_repo_suffix("/mnt/src/github/org/repo"),
            Some("github.com/org/repo".to_string()),
        );
        // GitLab without TLD
        assert_eq!(
            extract_repo_suffix("/home/user/gitlab/group/project"),
            Some("gitlab.com/group/project".to_string()),
        );
        // No forge host => None
        assert_eq!(extract_repo_suffix("/tmp/myrepo"), None);
    }

    #[test]
    fn test_source_matches_repo_direct_path() {
        let repo = Path::new("/var/home/ai/src/myproject");
        assert!(source_matches_repo("/var/home/ai/src/myproject", &[], repo));
        assert!(!source_matches_repo("/var/home/ai/src/other", &[], repo));
    }

    #[test]
    fn test_source_matches_repo_via_source_dirs() {
        let repo = Path::new("/var/home/ai/src/myproject");
        assert!(source_matches_repo(
            "https://github.com/unrelated/url",
            &[PathBuf::from("/var/home/ai/src/myproject")],
            repo
        ));
    }

    #[test]
    fn test_source_matches_repo_cross_path_via_suffix() {
        // Container path vs host path — different prefixes but same forge suffix
        let repo = Path::new("/var/home/ai/src/github.com/org/repo");
        assert!(source_matches_repo(
            "/mnt/src/github.com/org/repo",
            &[],
            repo
        ));
    }

    #[test]
    fn test_source_matches_repo_url_vs_path() {
        // URL source vs local path with forge suffix
        let repo = Path::new("/home/user/src/github.com/org/repo");
        assert!(source_matches_repo(
            "https://github.com/org/repo",
            &[],
            repo
        ));
        assert!(source_matches_repo(
            "https://github.com/org/repo.git",
            &[],
            repo
        ));
    }

    #[test]
    fn test_source_matches_repo_no_forge_no_match() {
        // When neither side has a forge host, only direct match works
        let repo = Path::new("/tmp/myproject");
        assert!(!source_matches_repo("/other/myproject", &[], repo));
    }

    #[test]
    fn test_create_agent_backend_any_name_returns_acp() {
        // All agents use ACP now — name is informational
        let agent_config = crate::config::AgentConfig::default();
        let backend = create_agent_backend("anything", None, &agent_config).unwrap();
        assert_eq!(backend.name(), "acp");
    }

    #[test]
    fn test_create_agent_backend_with_profile() {
        let mut env = std::collections::HashMap::new();
        env.insert("FOO".to_string(), "bar".to_string());
        let profile = crate::config::AgentProfile {
            command: vec!["goose".to_string(), "acp".to_string()],
            env,
        };
        let agent_config = crate::config::AgentConfig::default();
        let backend = create_agent_backend("goose", Some(&profile), &agent_config).unwrap();
        assert_eq!(backend.name(), "acp");
    }
}
