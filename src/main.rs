//! devaipod - Sandboxed AI coding agents in reproducible dev environments
//!
//! This tool uses DevPod for container provisioning and adds AI agent sandboxing.

use std::path::{Path, PathBuf};
use std::process::Command as ProcessCommand;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;

use clap::Parser;
use color_eyre::eyre::{bail, Context, Result};

mod config;
mod devpod;
mod secrets;
mod state;
mod upcall;

// =============================================================================
// Host CLI - commands that run on the host machine (outside devcontainer)
// =============================================================================

#[derive(Debug, Parser)]
#[command(name = "devaipod")]
#[command(about = "Sandboxed AI coding agents in reproducible dev environments", long_about = None)]
struct HostCli {
    /// Path to config file (default: ~/.config/devaipod.toml)
    #[arg(long, global = true, value_name = "PATH")]
    config: Option<PathBuf>,

    #[command(subcommand)]
    command: HostCommand,
}

#[derive(Debug, Parser)]
enum HostCommand {
    /// Create/start a workspace with AI agent
    ///
    /// Creates a DevPod workspace and optionally starts an AI agent inside.
    ///
    /// Examples:
    ///   devaipod up .
    ///   devaipod up https://github.com/user/repo
    ///   devaipod up https://github.com/user/repo --agent goose
    Up {
        /// Source: local path or git URL
        source: String,
        /// AI agent to run: goose, claude, opencode (default: from config or goose)
        #[arg(long, value_name = "AGENT")]
        agent: Option<String>,
        /// Don't start AI agent automatically
        #[arg(long)]
        no_agent: bool,
        /// DevPod provider to use (default: docker)
        #[arg(long, value_name = "PROVIDER")]
        provider: Option<String>,
        /// DevPod IDE to open (default: none)
        #[arg(long, value_name = "IDE")]
        ide: Option<String>,
    },
    /// Run an AI agent with a task
    ///
    /// Starts a DevPod workspace and runs an AI agent with the given task.
    /// The task can reference GitHub issues which will be fetched for context.
    ///
    /// Examples:
    ///   devaipod run "find typos in the docs"
    ///   devaipod run --git . "fix the bug in main.rs"
    ///   devaipod run --issue https://github.com/org/repo/issues/123
    ///   devaipod run "fix https://github.com/org/repo/issues/123"
    Run {
        /// Task description for the AI agent (optional if --issue is provided)
        task: Option<String>,
        /// Git source: local path or URL (default: current directory)
        #[arg(long, value_name = "SOURCE")]
        git: Option<String>,
        /// GitHub issue URL to work on (fetches issue context automatically)
        #[arg(long, value_name = "URL")]
        issue: Option<String>,
        /// AI agent to run: opencode, goose, claude (default: opencode)
        #[arg(long, value_name = "AGENT")]
        agent: Option<String>,
        /// Repositories the agent is allowed to write to (format: owner/repo)
        #[arg(long = "repo", value_name = "REPO")]
        repos: Vec<String>,
    },
    /// Attach to running AI agent (tmux session)
    Attach {
        /// Workspace name
        workspace: String,
    },
    /// SSH into a workspace
    Ssh {
        /// Workspace name
        workspace: String,
        /// Command to run (optional)
        #[arg(trailing_var_arg = true)]
        command: Vec<String>,
    },
    /// List workspaces
    List {
        /// Output in JSON format
        #[arg(long)]
        json: bool,
    },
    /// Stop a workspace
    Stop {
        /// Workspace name
        workspace: String,
    },
    /// Delete a workspace
    Delete {
        /// Workspace name
        workspace: String,
        /// Skip confirmation
        #[arg(long)]
        force: bool,
    },
}

// =============================================================================
// Container CLI - commands that run inside a devcontainer
// =============================================================================

#[derive(Debug, Parser)]
#[command(name = "devaipod")]
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
    /// Create/attach to a tmux session with AI agent
    ///
    /// Creates or attaches to a tmux session with two panes: one running
    /// the AI agent in a bwrap sandbox, and one with a shell.
    Tmux {
        /// AI agent to run: goose, claude, opencode (default: opencode)
        #[arg(long, value_name = "AGENT")]
        agent: Option<String>,
    },
    /// Get a shell inside the bwrap sandbox
    ///
    /// For debugging or manual work inside the sandbox environment.
    Enter,
    /// Internal: Run an agent with task (called by 'run' command via devpod ssh)
    ///
    /// Starts the upcall listener, runs the agent in a bwrap sandbox, and cleans up.
    #[command(hide = true)]
    InternalRunAgent {
        /// AI agent to run
        #[arg(long)]
        agent: String,
        /// Task for the agent
        #[arg(long)]
        task: String,
        /// Repositories the agent is allowed to write to (format: owner/repo)
        #[arg(long = "repo")]
        repos: Vec<String>,
    },
    /// Perform an upcall from inside the sandbox
    ///
    /// Upcalls allow the sandboxed agent to request controlled operations
    /// that require access outside the sandbox (like creating a GitHub PR).
    #[command(subcommand)]
    Upcall(UpcallCommand),
}

#[derive(Debug, Parser)]
enum UpcallCommand {
    /// Execute an allowlisted binary via upcall RPC
    ///
    /// Runs a binary from /usr/lib/devaipod/upcalls/ with the given arguments.
    /// This allows sandboxed agents to perform controlled operations.
    ///
    /// Examples:
    ///   devaipod upcall exec gh-restricted pr create --draft --title "Fix"
    Exec {
        /// Binary name (must be in /usr/lib/devaipod/upcalls/)
        binary: String,
        /// Arguments to pass to the binary
        #[arg(trailing_var_arg = true)]
        args: Vec<String>,
    },
    /// Show the current state (allowed repos and PRs)
    ///
    /// Displays the list of repositories the agent can write to and
    /// the PRs that have been created by the agent.
    State,
    /// Add a repository to the allowed list
    ///
    /// Allows the agent to create draft PRs in this repository.
    ///
    /// Examples:
    ///   devaipod upcall add-repo containers/composefs
    ///   devaipod upcall add-repo containers/bootc
    AddRepo {
        /// Repository in "owner/repo" format
        repo: String,
    },
    /// Remove a repository from the allowed list
    RemoveRepo {
        /// Repository in "owner/repo" format
        repo: String,
    },
}

fn main() -> Result<()> {
    color_eyre::install()?;
    let format = tracing_subscriber::fmt::format()
        .without_time()
        .with_target(false)
        .compact();
    tracing_subscriber::fmt()
        .event_format(format)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    // Detect context BEFORE parsing args - this determines which CLI we use
    if is_inside_devcontainer() {
        let cli = ContainerCli::parse();
        run_container(cli)
    } else {
        let cli = HostCli::parse();
        run_host(cli)
    }
}

fn run_host(cli: HostCli) -> Result<()> {
    let config = config::load_config(cli.config.as_deref())?;

    match cli.command {
        HostCommand::Up {
            source,
            agent,
            no_agent,
            provider,
            ide,
        } => cmd_up(
            &config,
            &source,
            agent.as_deref(),
            no_agent,
            provider.as_deref(),
            ide.as_deref(),
        ),
        HostCommand::Run {
            task,
            git,
            issue,
            agent,
            repos,
        } => cmd_run(
            &config,
            task.as_deref(),
            git.as_deref(),
            issue.as_deref(),
            agent.as_deref(),
            &repos,
        ),
        HostCommand::Attach { workspace } => cmd_attach(&workspace),
        HostCommand::Ssh { workspace, command } => cmd_ssh(&workspace, &command),
        HostCommand::List { json } => cmd_list(json),
        HostCommand::Stop { workspace } => cmd_stop(&workspace),
        HostCommand::Delete { workspace, force } => cmd_delete(&workspace, force),
    }
}

fn run_container(cli: ContainerCli) -> Result<()> {
    let config = config::load_config(cli.config.as_deref())?;

    match cli.command {
        ContainerCommand::Tmux { agent } => cmd_tmux(&config, agent.as_deref()),
        ContainerCommand::Enter => cmd_enter(),
        ContainerCommand::InternalRunAgent { agent, task, repos } => {
            cmd_internal_run_agent(&agent, &task, &repos)
        }
        ContainerCommand::Upcall(upcall_cmd) => cmd_upcall(upcall_cmd),
    }
}

/// Create/start a workspace with AI agent
fn cmd_up(
    config: &config::Config,
    source: &str,
    agent: Option<&str>,
    no_agent: bool,
    provider: Option<&str>,
    ide: Option<&str>,
) -> Result<()> {
    // Resolve the source path to an absolute path
    let source_path = if source.starts_with("http://")
        || source.starts_with("https://")
        || source.starts_with("git@")
    {
        // For remote URLs, we can't load secrets from devcontainer.json
        // since we don't have the repo locally yet
        tracing::debug!("Remote source detected, skipping devcontainer secrets");
        std::path::PathBuf::from(source)
    } else {
        // Resolve local path to absolute
        std::path::Path::new(source)
            .canonicalize()
            .unwrap_or_else(|_| std::path::PathBuf::from(source))
    };

    // Load secrets from devcontainer.json (fetched from podman secrets)
    let secrets = if source_path.is_dir() {
        secrets::load_secrets_from_devcontainer(&source_path)?
    } else {
        Vec::new()
    };

    // Run devpod up, passing secrets via --workspace-env
    let workspace_name = devpod::up(source, provider, ide, &secrets)?;

    if !no_agent {
        let agent_name = agent
            .map(|s| s.to_string())
            .or_else(|| config.agent.default_agent.clone())
            .unwrap_or_else(|| "goose".to_string());

        tracing::info!("Starting {} agent in tmux session...", agent_name);
        start_agent_in_tmux(&workspace_name, &agent_name)?;
        tracing::info!(
            "Agent started. Use 'devaipod attach {}' to connect.",
            workspace_name
        );
    }

    Ok(())
}

/// Run an AI agent with a task
fn cmd_run(
    config: &config::Config,
    task: Option<&str>,
    git: Option<&str>,
    issue: Option<&str>,
    agent: Option<&str>,
    repos: &[String],
) -> Result<()> {
    // Determine source - either from --git, or inferred from issue URL, or default to current directory
    let source = if let Some(git_source) = git {
        git_source.to_string()
    } else if let Some(issue_url) = issue {
        // Try to infer repo URL from issue URL
        if let Ok((owner, repo, _)) = parse_github_issue_url(issue_url) {
            format!("https://github.com/{}/{}", owner, repo)
        } else {
            ".".to_string()
        }
    } else {
        ".".to_string()
    };

    // Build the task from either --issue or positional task argument
    let base_task = if let Some(issue_url) = issue {
        // Parse issue and create task from it
        if let Ok((owner, repo, issue_number)) = parse_github_issue_url(issue_url) {
            tracing::info!(
                "Fetching GitHub issue #{} from {}/{}...",
                issue_number,
                owner,
                repo
            );
            if let Ok(issue_data) = fetch_github_issue(&owner, &repo, issue_number) {
                let comments = fetch_github_comments(&issue_data.comments_url).unwrap_or_default();
                let context =
                    format_issue_context(&owner, &repo, issue_number, &issue_data, &comments);

                // If there's also a task, combine them; otherwise create a task from the issue
                if let Some(task_text) = task {
                    format!("{}\n\n{}", task_text, context)
                } else {
                    format!("Fix the following GitHub issue:\n\n{}", context)
                }
            } else {
                task.map(|t| t.to_string())
                    .unwrap_or_else(|| format!("Fix GitHub issue: {}", issue_url))
            }
        } else {
            bail!("Invalid GitHub issue URL: {}", issue_url);
        }
    } else if let Some(task_text) = task {
        // Check if task contains a GitHub issue URL and extract context
        if let Some(issue_context) = extract_github_issue_context(task_text) {
            format!("{}\n\n{}", task_text, issue_context)
        } else {
            task_text.to_string()
        }
    } else {
        bail!("Either a task or --issue must be provided");
    };

    tracing::info!("Task: {}", base_task.lines().next().unwrap_or(&base_task));
    tracing::info!("Source: {}", source);

    // Resolve source path
    let source_path = if source.starts_with("http://")
        || source.starts_with("https://")
        || source.starts_with("git@")
    {
        std::path::PathBuf::from(&source)
    } else {
        std::path::Path::new(&source)
            .canonicalize()
            .unwrap_or_else(|_| std::path::PathBuf::from(&source))
    };

    // Load secrets from devcontainer.json (fetched from podman secrets)
    let secrets = if source_path.is_dir() {
        secrets::load_secrets_from_devcontainer(&source_path)?
    } else {
        Vec::new()
    };

    // Start workspace, passing secrets via --workspace-env
    let workspace_name = devpod::up(&source, None, None, &secrets)?;

    // Determine agent
    let agent_name = agent
        .map(|s| s.to_string())
        .or_else(|| config.agent.default_agent.clone())
        .unwrap_or_else(|| "opencode".to_string());

    tracing::info!("Running {} agent...", agent_name);

    // Run the agent with the task
    run_agent_with_task(&workspace_name, &agent_name, &base_task, repos)?;

    Ok(())
}

/// Extract GitHub issue context from task text if it contains issue URLs
fn extract_github_issue_context(task: &str) -> Option<String> {
    // Simple regex-like search for GitHub issue URLs
    let url_start = task.find("https://github.com/")?;
    let url_part = &task[url_start..];
    let url_end = url_part
        .find(|c: char| c.is_whitespace())
        .unwrap_or(url_part.len());
    let url = &url_part[..url_end];

    // Try to parse as issue URL
    if let Ok((owner, repo, issue_number)) = parse_github_issue_url(url) {
        tracing::info!(
            "Fetching GitHub issue #{} from {}/{}...",
            issue_number,
            owner,
            repo
        );
        if let Ok(issue) = fetch_github_issue(&owner, &repo, issue_number) {
            // Fetch comments if there's a comments URL
            let comments = fetch_github_comments(&issue.comments_url).unwrap_or_default();
            return Some(format_issue_context(
                &owner,
                &repo,
                issue_number,
                &issue,
                &comments,
            ));
        }
    }
    None
}

/// Get the real home directory, defaulting to /home/user if not set
fn get_real_home_dir() -> String {
    std::env::var("HOME").unwrap_or_else(|_| "/home/user".to_string())
}

/// Get the agent's isolated home directory ($HOME/ai)
/// Returns (real_home, agent_home) - agent_home is created if it doesn't exist.
fn get_agent_home_dir() -> Result<(String, String)> {
    let real_home = get_real_home_dir();
    let agent_home = format!("{}/ai", real_home);

    // Create the directory if it doesn't exist
    std::fs::create_dir_all(&agent_home)
        .with_context(|| format!("Failed to create agent home directory: {}", agent_home))?;

    Ok((real_home, agent_home))
}

/// Handle for a running upcall listener thread
struct UpcallListenerHandle {
    #[allow(dead_code)]
    thread: thread::JoinHandle<()>,
    shutdown: Arc<AtomicBool>,
    socket_path: std::path::PathBuf,
    workspace: String,
}

impl Drop for UpcallListenerHandle {
    fn drop(&mut self) {
        // Signal the listener to shut down
        self.shutdown.store(true, Ordering::SeqCst);
        // Connect to the socket to unblock the listener's accept() call
        let _ = std::os::unix::net::UnixStream::connect(&self.socket_path);
        // Clean up the socket file and PID file
        let _ = std::fs::remove_file(&self.socket_path);
        let _ = state::remove_pid_file(&self.workspace);
        tracing::debug!("Upcall listener shutdown signaled");
    }
}

/// Result of ensuring a listener is available for a workspace.
enum ListenerResult {
    /// Started a new listener (caller owns it)
    Started(UpcallListenerHandle, PathBuf),
    /// An existing listener is running (caller should just use the socket)
    Existing(PathBuf),
}

/// Ensure an upcall listener is available for the workspace.
///
/// If a listener is already running (based on PID file check), returns
/// the existing socket path. Otherwise, starts a new listener.
fn ensure_upcall_listener(workspace: &str) -> Result<ListenerResult> {
    // Check if a listener is already running
    match state::check_listener_status(workspace)? {
        state::ListenerStatus::Running { socket_path, pid } => {
            tracing::info!(
                "Upcall listener already running (pid {}) at {:?}",
                pid,
                socket_path
            );
            return Ok(ListenerResult::Existing(socket_path));
        }
        state::ListenerStatus::NotRunning => {
            tracing::debug!("No existing listener, starting new one");
        }
    }

    // Start a new listener
    let socket_path = upcall::get_host_socket_path(workspace)?;

    // Create the socket directory
    if let Some(parent) = socket_path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("Failed to create upcall socket directory: {:?}", parent))?;
    }

    // Remove existing socket if present (stale from previous run)
    let _ = std::fs::remove_file(&socket_path);

    // Create the listener before spawning the thread so we can catch bind errors
    let listener = std::os::unix::net::UnixListener::bind(&socket_path)
        .with_context(|| format!("Failed to bind upcall socket at {:?}", socket_path))?;

    // Set non-blocking so we can check for shutdown
    listener.set_nonblocking(true)?;

    // Write PID file so other processes know we're running
    state::write_pid_file(workspace)?;

    tracing::info!("Starting upcall listener at {:?}", socket_path);

    let workspace_owned = workspace.to_string();
    let shutdown = Arc::new(AtomicBool::new(false));
    let shutdown_clone = shutdown.clone();

    let thread = thread::spawn(move || {
        while !shutdown_clone.load(Ordering::SeqCst) {
            match listener.accept() {
                Ok((stream, _)) => {
                    // Set blocking mode for the stream
                    let _ = stream.set_nonblocking(false);
                    if let Err(e) = upcall::handle_connection(stream, &workspace_owned) {
                        tracing::error!("Error handling upcall: {}", e);
                    }
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    // No connection pending, sleep briefly and check shutdown
                    thread::sleep(std::time::Duration::from_millis(100));
                }
                Err(e) => {
                    if !shutdown_clone.load(Ordering::SeqCst) {
                        tracing::error!("Error accepting upcall connection: {}", e);
                    }
                    break;
                }
            }
        }
        tracing::debug!("Upcall listener thread exiting");
    });

    Ok(ListenerResult::Started(
        UpcallListenerHandle {
            thread,
            shutdown,
            socket_path: socket_path.clone(),
            workspace: workspace.to_string(),
        },
        socket_path,
    ))
}

/// Build a bwrap command to sandbox the agent
fn build_bwrap_command(
    workspace_path: &str,
    real_home: &str,
    agent_home: &str,
    agent: &str,
    task: &str,
    agent_env_vars: &[(String, String)],
    socket_path: &Path,
    podman_socket: Option<&Path>,
) -> String {
    // Escape task for shell - replace single quotes with escaped version
    let escaped_task = task.replace('\'', "'\\''");

    // Build the inner agent command
    let agent_inner_cmd = format!("{} run '{}'", agent, escaped_task);

    // Build bwrap command with a minimal root filesystem.
    // Instead of bind-mounting / and trying to hide things, we explicitly
    // add only what's needed. This is safer and easier to reason about.
    //
    // TODO: Network isolation - restrict to LLM API endpoints only
    // Currently allows full network access since hosted LLMs require it.
    // Options: HTTPS proxy with allowlist, iptables in network namespace,
    // or DNS-based filtering.
    let mut bwrap_args = vec![
        "bwrap".to_string(),
        // Start with nothing, build up a minimal root
        //
        // System directories (read-only)
        "--ro-bind".to_string(),
        "/usr".to_string(),
        "/usr".to_string(),
        "--ro-bind".to_string(),
        "/etc".to_string(),
        "/etc".to_string(),
        "--ro-bind".to_string(),
        "/lib".to_string(),
        "/lib".to_string(),
        "--ro-bind".to_string(),
        "/lib64".to_string(),
        "/lib64".to_string(),
        // Symlink /bin and /sbin to /usr/bin and /usr/sbin (standard on modern distros)
        "--symlink".to_string(),
        "/usr/bin".to_string(),
        "/bin".to_string(),
        "--symlink".to_string(),
        "/usr/sbin".to_string(),
        "/sbin".to_string(),
        // Device and proc filesystems
        // Bind mount /dev and /proc from host (--dev/--proc require CAP_SYS_ADMIN which nested containers lack)
        "--dev-bind".to_string(),
        "/dev".to_string(),
        "/dev".to_string(),
        "--ro-bind".to_string(),
        "/proc".to_string(),
        "/proc".to_string(),
        // Temporary filesystems (fresh, empty)
        "--tmpfs".to_string(),
        "/tmp".to_string(),
        "--tmpfs".to_string(),
        "/run".to_string(),
        // Upcall socket (bind-mounted from host for agent-to-host RPC)
        "--ro-bind".to_string(),
        socket_path.display().to_string(),
        upcall::UPCALL_SOCKET_PATH.to_string(),
        // Writable workspace
        "--bind".to_string(),
        workspace_path.to_string(),
        workspace_path.to_string(),
        // Agent's isolated home directory
        "--bind".to_string(),
        agent_home.to_string(),
        real_home.to_string(),
        // Create /workspaces parent if workspace is under it
        "--dir".to_string(),
        "/workspaces".to_string(),
        // Process isolation
        "--unshare-pid".to_string(),
        "--die-with-parent".to_string(),
    ];

    // Bind-mount gcloud config read-only for Vertex AI ADC if it exists
    let gcloud_config = format!("{}/.config/gcloud", real_home);
    if Path::new(&gcloud_config).exists() {
        bwrap_args.extend([
            "--ro-bind".to_string(),
            gcloud_config,
            format!("{}/.config/gcloud", real_home),
        ]);
    }

    // Bind-mount sandboxed podman socket if available
    if let Some(podman_sock) = podman_socket {
        bwrap_args.extend([
            "--dir".to_string(),
            "/run/podman".to_string(),
            "--ro-bind".to_string(),
            podman_sock.display().to_string(),
            "/run/podman/podman.sock".to_string(),
        ]);
    }

    // Set environment variables
    bwrap_args.extend([
        "--setenv".to_string(),
        "PATH".to_string(),
        "/usr/local/bin:/usr/bin:/bin".to_string(),
        "--setenv".to_string(),
        "HOME".to_string(),
        real_home.to_string(),
        "--setenv".to_string(),
        "USER".to_string(),
        std::env::var("USER").unwrap_or_else(|_| "user".to_string()),
    ]);

    // Set CONTAINER_HOST if podman socket is available
    if podman_socket.is_some() {
        bwrap_args.extend([
            "--setenv".to_string(),
            "CONTAINER_HOST".to_string(),
            "unix:///run/podman/podman.sock".to_string(),
        ]);
    }

    // Forward only DEVAIPOD_AGENT_* prefixed environment variables (with prefix stripped)
    // This is the security boundary - only these env vars are visible to the agent
    for (key, val) in agent_env_vars {
        bwrap_args.push("--setenv".to_string());
        bwrap_args.push(key.to_string());
        bwrap_args.push(val.to_string());
    }

    // Change to workspace directory
    bwrap_args.push("--chdir".to_string());
    bwrap_args.push(workspace_path.to_string());

    // Add the shell command to run
    bwrap_args.push("--".to_string());
    bwrap_args.push("/bin/sh".to_string());
    bwrap_args.push("-c".to_string());
    bwrap_args.push(agent_inner_cmd);

    // Join all args with proper shell quoting
    bwrap_args
        .iter()
        .map(|arg| {
            if arg.contains(' ') || arg.contains('\'') || arg.contains('"') {
                format!("'{}'", arg.replace('\'', "'\\''"))
            } else {
                arg.clone()
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// Run AI agent with a specific task
fn run_agent_with_task(workspace: &str, agent: &str, task: &str, repos: &[String]) -> Result<()> {
    tracing::info!("Running {} agent in workspace: {}", agent, workspace);

    // Escape arguments for shell
    let escaped_agent = agent.replace('\'', "'\\''");
    let escaped_task = task.replace('\'', "'\\''");

    // Build repo arguments
    let repo_args: String = repos
        .iter()
        .map(|r| format!(" --repo '{}'", r.replace('\'', "'\\''")))
        .collect();

    // Build the command to run inside the devcontainer
    // This uses the internal-run-agent command which handles:
    // 1. Starting the upcall listener
    // 2. Running the agent in a bwrap sandbox
    // 3. Cleaning up when done
    //
    // We source ~/.bashrc first to ensure environment variables (like GH_TOKEN)
    // from dotfiles are available for upcall commands.
    let internal_cmd = format!(
        "source ~/.bashrc 2>/dev/null; devaipod internal-run-agent --agent '{}' --task '{}'{}",
        escaped_agent, escaped_task, repo_args
    );

    tracing::debug!("Running via devpod ssh: {}", internal_cmd);

    let status = ProcessCommand::new("devpod")
        .args(["ssh", workspace, "--command", &internal_cmd])
        .status()
        .context("Failed to run agent")?;

    if !status.success() {
        bail!("Agent exited with error");
    }

    Ok(())
}

/// Attach to running AI agent
fn cmd_attach(workspace: &str) -> Result<()> {
    tracing::info!("Attaching to agent in {}...", workspace);

    let status = ProcessCommand::new("devpod")
        .args([
            "ssh",
            workspace,
            "--",
            "tmux",
            "attach-session",
            "-t",
            "agent",
        ])
        .status()
        .context("Failed to run devpod ssh")?;

    if !status.success() {
        tracing::warn!("No agent session found. Starting shell...");
        devpod::ssh(workspace, &[])?;
    }

    Ok(())
}

/// SSH into workspace
fn cmd_ssh(workspace: &str, command: &[String]) -> Result<()> {
    devpod::ssh(workspace, command)
}

/// List workspaces
fn cmd_list(json: bool) -> Result<()> {
    devpod::list(json)
}

/// Stop workspace
fn cmd_stop(workspace: &str) -> Result<()> {
    devpod::stop(workspace)
}

/// Delete workspace
fn cmd_delete(workspace: &str, force: bool) -> Result<()> {
    devpod::delete(workspace, force)
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

/// Get the workspace path inside the devcontainer
fn get_workspace_path() -> Result<String> {
    // Inside a devcontainer, the workspace is typically at /workspaces/<name>
    // We can detect it by looking at /workspaces or using PWD
    let cwd = std::env::current_dir().context("Failed to get current directory")?;
    let cwd_str = cwd.to_string_lossy();

    // If we're already in /workspaces/*, use that
    if cwd_str.starts_with("/workspaces/") {
        // Extract the workspace root (first component under /workspaces)
        let parts: Vec<&str> = cwd_str.split('/').collect();
        if parts.len() >= 3 {
            return Ok(format!("/workspaces/{}", parts[2]));
        }
    }

    // Otherwise, try to find any workspace directory
    let workspaces_dir = std::path::Path::new("/workspaces");
    if workspaces_dir.is_dir() {
        for entry in std::fs::read_dir(workspaces_dir)? {
            let entry = entry?;
            if entry.path().is_dir() {
                return Ok(entry.path().to_string_lossy().to_string());
            }
        }
    }

    bail!("Could not determine workspace path. Are you inside a devcontainer?")
}

/// Standard path for the podman socket (started by devaipod-init.sh)
const PODMAN_SOCKET: &str = "/run/podman/podman.sock";

/// Check if the podman socket is available.
///
/// The podman service should be started by the container init script
/// (devaipod-init.sh). This runs `sudo podman system service` which is
/// safe because in a rootless devcontainer, "root" is actually an
/// unprivileged UID on the real host.
fn get_podman_socket() -> Option<PathBuf> {
    let socket_path = Path::new(PODMAN_SOCKET);
    if socket_path.exists() {
        tracing::debug!("Found podman socket at {:?}", socket_path);
        Some(socket_path.to_path_buf())
    } else {
        tracing::debug!("Podman socket not found at {:?}", socket_path);
        None
    }
}

/// Build bwrap command arguments for a shell (without running an agent command)
fn build_bwrap_shell_args(
    workspace_path: &str,
    real_home: &str,
    agent_home: &str,
    agent_env_vars: &[(String, String)],
    socket_path: &Path,
    podman_socket: Option<&Path>,
) -> Vec<String> {
    // Build a minimal root filesystem - only bind what's explicitly needed
    let mut bwrap_args = vec![
        "bwrap".to_string(),
        // System directories (read-only)
        "--ro-bind".to_string(),
        "/usr".to_string(),
        "/usr".to_string(),
        "--ro-bind".to_string(),
        "/etc".to_string(),
        "/etc".to_string(),
        "--ro-bind".to_string(),
        "/lib".to_string(),
        "/lib".to_string(),
        "--ro-bind".to_string(),
        "/lib64".to_string(),
        "/lib64".to_string(),
        // Symlink /bin and /sbin to /usr/bin and /usr/sbin
        "--symlink".to_string(),
        "/usr/bin".to_string(),
        "/bin".to_string(),
        "--symlink".to_string(),
        "/usr/sbin".to_string(),
        "/sbin".to_string(),
        // Bind mount /dev from host (--dev requires CAP_SYS_ADMIN which nested containers lack)
        "--dev-bind".to_string(),
        "/dev".to_string(),
        "/dev".to_string(),
        "--ro-bind".to_string(),
        "/proc".to_string(),
        "/proc".to_string(),
        // Temporary filesystems (fresh, empty)
        "--tmpfs".to_string(),
        "/tmp".to_string(),
        "--tmpfs".to_string(),
        "/run".to_string(),
        // Upcall socket (bind-mounted from host for agent-to-host RPC)
        "--ro-bind".to_string(),
        socket_path.display().to_string(),
        upcall::UPCALL_SOCKET_PATH.to_string(),
        // Writable workspace
        "--bind".to_string(),
        workspace_path.to_string(),
        workspace_path.to_string(),
        // Agent's isolated home directory
        "--bind".to_string(),
        agent_home.to_string(),
        real_home.to_string(),
        // Create /workspaces parent if workspace is under it
        "--dir".to_string(),
        "/workspaces".to_string(),
        // Process isolation
        "--unshare-pid".to_string(),
        "--die-with-parent".to_string(),
        // Set environment variables
        "--setenv".to_string(),
        "PATH".to_string(),
        "/usr/local/bin:/usr/bin:/bin".to_string(),
        "--setenv".to_string(),
        "HOME".to_string(),
        real_home.to_string(),
        "--setenv".to_string(),
        "USER".to_string(),
        std::env::var("USER").unwrap_or_else(|_| "user".to_string()),
    ];

    // Bind-mount gcloud config read-only for Vertex AI ADC if it exists
    let gcloud_config = format!("{}/.config/gcloud", real_home);
    if Path::new(&gcloud_config).exists() {
        bwrap_args.extend([
            "--ro-bind".to_string(),
            gcloud_config,
            format!("{}/.config/gcloud", real_home),
        ]);
    }

    // Bind-mount sandboxed podman socket if available
    // This allows the AI agent to use podman for container operations.
    // The podman service itself runs in a separate bwrap sandbox as root,
    // but since we're in a rootless container, "root" is unprivileged on the host.
    if let Some(podman_sock) = podman_socket {
        bwrap_args.extend([
            "--dir".to_string(),
            "/run/podman".to_string(),
            "--ro-bind".to_string(),
            podman_sock.display().to_string(),
            "/run/podman/podman.sock".to_string(),
            "--setenv".to_string(),
            "CONTAINER_HOST".to_string(),
            "unix:///run/podman/podman.sock".to_string(),
        ]);
    }

    // Forward only DEVAIPOD_AGENT_* prefixed environment variables (with prefix stripped)
    // This is the security boundary - only these env vars are visible to the agent
    for (key, val) in agent_env_vars {
        bwrap_args.push("--setenv".to_string());
        bwrap_args.push(key.to_string());
        bwrap_args.push(val.to_string());
    }

    // Change to workspace directory
    bwrap_args.push("--chdir".to_string());
    bwrap_args.push(workspace_path.to_string());

    bwrap_args
}

/// Create/attach to tmux session with AI agent (inside devcontainer)
fn cmd_tmux(config: &config::Config, agent: Option<&str>) -> Result<()> {
    let workspace_path = get_workspace_path()?;
    // Extract workspace name from path (e.g., "/workspaces/myrepo" -> "myrepo")
    let workspace_name = Path::new(&workspace_path)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("workspace");

    let agent_name = agent
        .map(|s| s.to_string())
        .or_else(|| config.agent.default_agent.clone())
        .unwrap_or_else(|| "opencode".to_string());

    let session_name = "devaipod";

    // Ensure an upcall listener is running for this workspace.
    // If one already exists (from a previous devaipod tmux invocation that's still running),
    // we reuse it. Otherwise, we start a new one.
    // The listener allows the sandboxed agent to perform controlled operations
    // like creating PRs or pushing branches via RPC to this process.
    let (maybe_listener, socket_path) = match ensure_upcall_listener(workspace_name)? {
        ListenerResult::Started(handle, path) => (Some(handle), path),
        ListenerResult::Existing(path) => (None, path),
    };
    tracing::debug!(
        "Upcall listener ready for workspace: {} (socket: {:?})",
        workspace_name,
        socket_path
    );

    // Check if session already exists
    let session_exists = ProcessCommand::new("tmux")
        .args(["has-session", "-t", session_name])
        .status()
        .map(|s| s.success())
        .unwrap_or(false);

    if session_exists {
        tracing::info!("Attaching to existing '{}' session...", session_name);
        let status = ProcessCommand::new("tmux")
            .args(["attach-session", "-t", session_name])
            .status()
            .context("Failed to attach to tmux session")?;

        // Keep the listener alive until we're done (if we started one)
        drop(maybe_listener);

        if !status.success() {
            bail!("Failed to attach to tmux session");
        }
    } else {
        tracing::info!(
            "Creating '{}' session with {} agent...",
            session_name,
            agent_name
        );

        // Build the bwrap command for the agent
        let (real_home, agent_home) = get_agent_home_dir()?;
        let agent_env_vars = config::collect_agent_env_vars();

        // Check for podman socket (started by devaipod-init.sh)
        let podman_socket = get_podman_socket();

        let mut bwrap_args = build_bwrap_shell_args(
            &workspace_path,
            &real_home,
            &agent_home,
            &agent_env_vars,
            &socket_path,
            podman_socket.as_deref(),
        );
        bwrap_args.push("--".to_string());
        bwrap_args.push(agent_name.clone());

        let bwrap_cmd = bwrap_args
            .iter()
            .map(|arg| {
                if arg.contains(' ') || arg.contains('\'') || arg.contains('"') {
                    format!("'{}'", arg.replace('\'', "'\\''"))
                } else {
                    arg.clone()
                }
            })
            .collect::<Vec<_>>()
            .join(" ");

        // Create new tmux session with agent in first pane
        let status = ProcessCommand::new("tmux")
            .args([
                "new-session",
                "-d",
                "-s",
                session_name,
                "-c",
                &workspace_path,
                "/bin/sh",
                "-c",
                &bwrap_cmd,
            ])
            .status()
            .context("Failed to create tmux session")?;

        if !status.success() {
            bail!("Failed to create tmux session");
        }

        // Split window and create a shell pane
        let status = ProcessCommand::new("tmux")
            .args([
                "split-window",
                "-t",
                session_name,
                "-h",
                "-c",
                &workspace_path,
            ])
            .status()
            .context("Failed to split tmux window")?;

        if !status.success() {
            tracing::warn!("Failed to create shell pane");
        }

        // Select the first pane (agent pane)
        let _ = ProcessCommand::new("tmux")
            .args(["select-pane", "-t", &format!("{}:0.0", session_name)])
            .status();

        // Attach to the session
        let status = ProcessCommand::new("tmux")
            .args(["attach-session", "-t", session_name])
            .status()
            .context("Failed to attach to tmux session")?;

        if !status.success() {
            bail!("Failed to attach to tmux session");
        }
    }

    Ok(())
}

/// Get a shell inside the bwrap sandbox (inside devcontainer)
fn cmd_enter() -> Result<()> {
    let workspace_path = get_workspace_path()?;
    // Extract workspace name from path (e.g., "/workspaces/myrepo" -> "myrepo")
    let workspace_name = Path::new(&workspace_path)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("workspace");

    tracing::info!("Entering bwrap sandbox (workspace: {})...", workspace_path);

    // Ensure an upcall listener is running. If one already exists (e.g., from
    // a running `devaipod tmux` session), we reuse it.
    let (maybe_listener, socket_path) = match ensure_upcall_listener(workspace_name)? {
        ListenerResult::Started(handle, path) => (Some(handle), path),
        ListenerResult::Existing(path) => (None, path),
    };
    tracing::debug!(
        "Upcall listener ready for workspace: {} (socket: {:?})",
        workspace_name,
        socket_path
    );
    // Suppress unused warning - we need to keep the listener alive
    let _ = &maybe_listener;

    // Build bwrap args for a shell
    let (real_home, agent_home) = get_agent_home_dir()?;
    let agent_env_vars = config::collect_agent_env_vars();

    // Check for podman socket (started by devaipod-init.sh)
    let podman_socket = get_podman_socket();

    let mut bwrap_args = build_bwrap_shell_args(
        &workspace_path,
        &real_home,
        &agent_home,
        &agent_env_vars,
        &socket_path,
        podman_socket.as_deref(),
    );
    bwrap_args.push("--".to_string());
    bwrap_args.push("/bin/bash".to_string());

    let status = ProcessCommand::new(&bwrap_args[0])
        .args(&bwrap_args[1..])
        .status()
        .context("Failed to enter bwrap sandbox")?;

    if !status.success() {
        bail!("bwrap shell exited with error");
    }

    Ok(())
}

/// Internal command: Run an agent with task inside devcontainer
/// This is called via `devpod ssh` from the host's `run` command.
fn cmd_internal_run_agent(agent: &str, task: &str, repos: &[String]) -> Result<()> {
    let workspace_path = get_workspace_path()?;
    // Extract workspace name from path (e.g., "/workspaces/myrepo" -> "myrepo")
    let workspace_name = Path::new(&workspace_path)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("workspace");

    tracing::info!(
        "Running {} agent in bwrap sandbox (workspace: {})",
        agent,
        workspace_path
    );

    // Initialize state with allowed repos before starting the upcall listener
    if !repos.is_empty() {
        tracing::info!("Initializing state with {} allowed repos", repos.len());
        for repo in repos {
            state::add_repo(repo)?;
        }
    }

    // Ensure an upcall listener is running. If one already exists, we reuse it.
    let (maybe_listener, socket_path) = match ensure_upcall_listener(workspace_name)? {
        ListenerResult::Started(handle, path) => (Some(handle), path),
        ListenerResult::Existing(path) => (None, path),
    };
    tracing::debug!(
        "Upcall listener ready for workspace: {} (socket: {:?})",
        workspace_name,
        socket_path
    );
    // Suppress unused warning - we need to keep the listener alive
    let _ = &maybe_listener;

    // Collect DEVAIPOD_AGENT_* prefixed env vars to forward into sandbox
    let agent_env_vars = config::collect_agent_env_vars();
    if agent_env_vars.is_empty() {
        tracing::warn!(
            "No DEVAIPOD_AGENT_* env vars found. The agent won't have any API keys. \
             Set e.g. DEVAIPOD_AGENT_ANTHROPIC_API_KEY to forward ANTHROPIC_API_KEY to the agent."
        );
    } else {
        tracing::debug!(
            "Forwarding {} env vars to sandbox: {:?}",
            agent_env_vars.len(),
            agent_env_vars.iter().map(|(k, _)| k).collect::<Vec<_>>()
        );
    }

    // Build and run the bwrap command
    let (real_home, agent_home) = get_agent_home_dir()?;

    // Check for podman socket (started by devaipod-init.sh)
    let podman_socket = get_podman_socket();

    let agent_cmd = build_bwrap_command(
        &workspace_path,
        &real_home,
        &agent_home,
        agent,
        task,
        &agent_env_vars,
        &socket_path,
        podman_socket.as_deref(),
    );

    tracing::debug!("Agent command: {}", agent_cmd);

    // Execute the bwrap command directly
    let status = ProcessCommand::new("/bin/sh")
        .args(["-c", &agent_cmd])
        .status()
        .context("Failed to run agent in bwrap sandbox")?;

    if !status.success() {
        bail!("Agent exited with error");
    }

    Ok(())
}

/// Execute an upcall command from inside the sandbox
fn cmd_upcall(cmd: UpcallCommand) -> Result<()> {
    match cmd {
        UpcallCommand::Exec { binary, args } => {
            // Convert Vec<String> to Vec<&str> for the API
            let args_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
            let (exit_code, output) = upcall::exec_command(&binary, &args_refs)?;

            // Print the combined output
            if !output.is_empty() {
                print!("{}", output);
            }

            if exit_code != 0 {
                std::process::exit(exit_code);
            }

            Ok(())
        }
        UpcallCommand::State => {
            let current_state = state::load_state()?;
            println!("Allowed repositories:");
            if current_state.allowed_repos.is_empty() {
                println!("  (none)");
            } else {
                for repo in &current_state.allowed_repos {
                    println!("  {}", repo);
                }
            }
            println!();
            println!("Allowed PRs (created by agent):");
            if current_state.allowed_prs.is_empty() {
                println!("  (none)");
            } else {
                for pr in &current_state.allowed_prs {
                    println!("  {}", pr);
                }
            }
            Ok(())
        }
        UpcallCommand::AddRepo { repo } => {
            state::add_repo(&repo)?;
            println!("Added repository: {}", repo);
            Ok(())
        }
        UpcallCommand::RemoveRepo { repo } => {
            state::remove_repo(&repo)?;
            println!("Removed repository: {}", repo);
            Ok(())
        }
    }
}

/// Start AI agent in a tmux session inside the workspace
fn start_agent_in_tmux(workspace: &str, agent: &str) -> Result<()> {
    let status = ProcessCommand::new("devpod")
        .args([
            "ssh",
            workspace,
            "--",
            "tmux",
            "new-session",
            "-d",
            "-s",
            "agent",
            agent,
        ])
        .status()
        .context("Failed to start agent in tmux")?;

    if !status.success() {
        bail!("Failed to start agent in tmux session");
    }

    Ok(())
}

/// Parse GitHub issue URL: https://github.com/owner/repo/issues/123
fn parse_github_issue_url(url: &str) -> Result<(String, String, u64)> {
    let parsed = url::Url::parse(url).context("Invalid URL")?;

    if parsed.host_str() != Some("github.com") {
        bail!("Not a GitHub URL: {}", url);
    }

    let path_segments: Vec<&str> = parsed
        .path_segments()
        .map(|s| s.collect())
        .unwrap_or_default();

    if path_segments.len() != 4 || path_segments[2] != "issues" {
        bail!(
            "Invalid GitHub issue URL format. Expected: https://github.com/owner/repo/issues/123"
        );
    }

    let owner = path_segments[0].to_string();
    let repo = path_segments[1].to_string();
    let issue_number: u64 = path_segments[3].parse().context("Invalid issue number")?;

    Ok((owner, repo, issue_number))
}

/// GitHub issue data
#[derive(Debug)]
struct GitHubIssue {
    title: String,
    body: String,
    labels: Vec<String>,
    state: String,
    comments_url: String,
}

/// Fetch GitHub issue details (title, body, labels)
fn fetch_github_issue(owner: &str, repo: &str, issue_number: u64) -> Result<GitHubIssue> {
    let url = format!(
        "https://api.github.com/repos/{}/{}/issues/{}",
        owner, repo, issue_number
    );

    let output = ProcessCommand::new("curl")
        .args([
            "-s",
            "-H",
            "Accept: application/vnd.github+json",
            "-H",
            "User-Agent: devaipod/0.1.0",
            &url,
        ])
        .output()
        .context("Failed to run curl")?;

    if !output.status.success() {
        bail!("Failed to fetch issue from GitHub API");
    }

    let json: serde_json::Value =
        serde_json::from_slice(&output.stdout).context("Failed to parse GitHub API response")?;

    // Check for API error
    if let Some(message) = json.get("message").and_then(|m| m.as_str()) {
        bail!("GitHub API error: {}", message);
    }

    let title = json
        .get("title")
        .and_then(|t| t.as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| color_eyre::eyre::eyre!("No title in GitHub API response"))?;

    let body = json
        .get("body")
        .and_then(|b| b.as_str())
        .unwrap_or("")
        .to_string();

    let state = json
        .get("state")
        .and_then(|s| s.as_str())
        .unwrap_or("unknown")
        .to_string();

    let labels: Vec<String> = json
        .get("labels")
        .and_then(|l| l.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|l| l.get("name").and_then(|n| n.as_str()))
                .map(|s| s.to_string())
                .collect()
        })
        .unwrap_or_default();

    let comments_url = json
        .get("comments_url")
        .and_then(|u| u.as_str())
        .unwrap_or("")
        .to_string();

    Ok(GitHubIssue {
        title,
        body,
        labels,
        state,
        comments_url,
    })
}

/// Fetch GitHub issue comments
fn fetch_github_comments(comments_url: &str) -> Result<Vec<String>> {
    if comments_url.is_empty() {
        return Ok(vec![]);
    }

    let output = ProcessCommand::new("curl")
        .args([
            "-s",
            "-H",
            "Accept: application/vnd.github+json",
            "-H",
            "User-Agent: devaipod/0.1.0",
            comments_url,
        ])
        .output()
        .context("Failed to run curl")?;

    if !output.status.success() {
        return Ok(vec![]);
    }

    let json: serde_json::Value =
        serde_json::from_slice(&output.stdout).unwrap_or(serde_json::Value::Array(vec![]));

    let comments: Vec<String> = json
        .as_array()
        .map(|arr| {
            arr.iter()
                .filter_map(|c| {
                    let author = c
                        .get("user")
                        .and_then(|u| u.get("login"))
                        .and_then(|l| l.as_str())
                        .unwrap_or("unknown");
                    let body = c.get("body").and_then(|b| b.as_str()).unwrap_or("");
                    if body.is_empty() {
                        None
                    } else {
                        Some(format!("@{}: {}", author, body))
                    }
                })
                .collect()
        })
        .unwrap_or_default();

    Ok(comments)
}

/// Format GitHub issue as context for the AI agent
fn format_issue_context(
    owner: &str,
    repo: &str,
    issue_number: u64,
    issue: &GitHubIssue,
    comments: &[String],
) -> String {
    let mut context = format!(
        "## GitHub Issue #{} ({}/{})\n\n**Title:** {}\n**State:** {}\n",
        issue_number, owner, repo, issue.title, issue.state
    );

    if !issue.labels.is_empty() {
        context.push_str(&format!("**Labels:** {}\n", issue.labels.join(", ")));
    }

    if !issue.body.is_empty() {
        context.push_str(&format!("\n### Description\n\n{}\n", issue.body));
    }

    if !comments.is_empty() {
        context.push_str("\n### Comments\n\n");
        for comment in comments.iter().take(10) {
            // Limit to 10 most recent comments
            context.push_str(&format!("{}\n\n---\n\n", comment));
        }
    }

    context
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
        assert!(subcommands.contains(&"attach"), "Missing 'attach' command");
        assert!(subcommands.contains(&"ssh"), "Missing 'ssh' command");
        assert!(subcommands.contains(&"list"), "Missing 'list' command");
        assert!(subcommands.contains(&"stop"), "Missing 'stop' command");
        assert!(subcommands.contains(&"delete"), "Missing 'delete' command");

        // Should NOT have container-only commands
        assert!(
            !subcommands.contains(&"tmux"),
            "'tmux' should not be in host CLI"
        );
        assert!(
            !subcommands.contains(&"enter"),
            "'enter' should not be in host CLI"
        );
    }

    #[test]
    fn test_container_cli_has_expected_commands() {
        // Verify ContainerCli has the expected container-only commands
        let cmd = ContainerCli::command();
        let subcommands: Vec<_> = cmd.get_subcommands().map(|c| c.get_name()).collect();

        assert!(subcommands.contains(&"tmux"), "Missing 'tmux' command");
        assert!(subcommands.contains(&"enter"), "Missing 'enter' command");
        assert!(subcommands.contains(&"upcall"), "Missing 'upcall' command");

        // Should NOT have host-only commands
        assert!(
            !subcommands.contains(&"up"),
            "'up' should not be in container CLI"
        );
        assert!(
            !subcommands.contains(&"run"),
            "'run' should not be in container CLI"
        );
        assert!(
            !subcommands.contains(&"attach"),
            "'attach' should not be in container CLI"
        );
    }

    #[test]
    fn test_is_inside_devcontainer_detection() {
        // This tests the detection function - result depends on runtime environment
        // Just verify it runs without panicking
        let _inside = is_inside_devcontainer();
    }
}
