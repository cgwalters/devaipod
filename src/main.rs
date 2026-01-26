//! devaipod - Sandboxed AI coding agents in reproducible dev environments
//!
//! This tool uses DevPod for container provisioning and adds AI agent sandboxing.

#![forbid(unsafe_code)]

use std::path::{Path, PathBuf};
use std::process::Command as ProcessCommand;

use clap::Parser;
use color_eyre::eyre::{bail, Context, Result};

mod compose;
mod config;
mod devcontainer;
mod devpod;
mod pod;
mod podman;
mod secrets;
mod service_gator;

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
        /// Generate configuration files but don't start containers
        #[arg(long)]
        dry_run: bool,
        /// Enable agent sidecar container (experimental)
        #[arg(long)]
        agent_sidecar: bool,
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
    /// Configure the container environment for nested containers
    ///
    /// Sets up containers.conf, subuid/subgid, and starts the podman service.
    /// This command is idempotent and should be run at container startup.
    /// Typically called from postStartCommand in devcontainer.json.
    ConfigureEnv,
    /// Internal: Run an agent with task (called by 'run' command via devpod ssh)
    ///
    /// Runs the agent in a bwrap sandbox.
    #[command(hide = true)]
    InternalRunAgent {
        /// AI agent to run
        #[arg(long)]
        agent: String,
        /// Task for the agent
        #[arg(long)]
        task: String,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
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
        run_host(cli).await
    }
}

async fn run_host(cli: HostCli) -> Result<()> {
    let config = config::load_config(cli.config.as_deref())?;

    match cli.command {
        HostCommand::Up {
            source,
            agent,
            no_agent,
            provider,
            ide,
            dry_run,
            agent_sidecar,
        } => {
            cmd_up(
                &config,
                &source,
                agent.as_deref(),
                no_agent,
                provider.as_deref(),
                ide.as_deref(),
                dry_run,
                agent_sidecar,
            )
            .await
        }
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
        ContainerCommand::ConfigureEnv => cmd_configure_env(),
        ContainerCommand::InternalRunAgent { agent, task } => {
            cmd_internal_run_agent(&config, &agent, &task)
        }
    }
}

/// Create/start a workspace with AI agent
///
/// Uses podman-native multi-container setup with a pod containing:
/// - workspace: The user's development environment
/// - agent: Container running opencode serve with restricted security
/// - gator (optional): Service-gator MCP server container
async fn cmd_up(
    config: &config::Config,
    source: &str,
    _agent: Option<&str>,
    _no_agent: bool,
    _provider: Option<&str>,
    _ide: Option<&str>,
    dry_run: bool,
    _agent_sidecar: bool,
) -> Result<()> {
    // Resolve local paths
    let source_path = if source.starts_with("http://")
        || source.starts_with("https://")
        || source.starts_with("git@")
    {
        None
    } else {
        std::path::Path::new(source).canonicalize().ok()
    };

    // Podman-native path requires a local path (can't modify remote repos)
    let project_path = match source_path {
        Some(ref p) => p,
        None => {
            bail!(
                "Podman-native mode requires a local path, not a remote URL. \
                 Clone the repository first and use the local path."
            );
        }
    };

    // Find and load devcontainer.json
    let devcontainer_json_path = devcontainer::find_devcontainer_json(project_path)?;
    let devcontainer_config = devcontainer::load(&devcontainer_json_path)?;

    // Derive project/pod name from path
    let project_name = project_path
        .file_name()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| "project".to_string());

    // Use a sanitized pod name (replace problematic characters)
    let pod_name = format!(
        "devaipod-{}",
        project_name
            .chars()
            .map(|c| if c.is_alphanumeric() || c == '-' { c } else { '-' })
            .collect::<String>()
    );

    if dry_run {
        tracing::info!("Dry run: would create pod '{}'", pod_name);
        tracing::info!("  project: {}", project_path.display());
        tracing::info!("  devcontainer: {}", devcontainer_json_path.display());
        tracing::info!(
            "  gator enabled: {}",
            config.service_gator.is_enabled()
        );
        return Ok(());
    }

    // Start podman service
    tracing::info!("Starting podman service...");
    let podman = podman::PodmanService::spawn()
        .await
        .context("Failed to start podman service")?;

    // Check if gator should be enabled
    let enable_gator = config.service_gator.is_enabled();

    // Create the pod with all containers
    tracing::info!("Creating pod '{}'...", pod_name);
    let devaipod_pod = pod::DevaipodPod::create(
        &podman,
        project_path,
        &devcontainer_config,
        &pod_name,
        enable_gator,
    )
    .await
    .context("Failed to create devaipod pod")?;

    // Start the pod
    tracing::info!("Starting pod...");
    devaipod_pod
        .start(&podman)
        .await
        .context("Failed to start pod")?;

    // Run lifecycle commands (onCreateCommand, postCreateCommand, postStartCommand)
    tracing::info!("Running lifecycle commands...");
    devaipod_pod
        .run_lifecycle_commands(&podman, &devcontainer_config)
        .await
        .context("Failed to run lifecycle commands")?;

    // Success! Print connection info
    tracing::info!("Pod '{}' started successfully.", pod_name);
    tracing::info!("  • Workspace container: {}", devaipod_pod.workspace_container);
    tracing::info!("  • Agent container: {}", devaipod_pod.agent_container);
    if let Some(ref gator) = devaipod_pod.gator_container {
        tracing::info!("  • Gator container: {}", gator);
    }
    tracing::info!(
        "  • Agent server: http://localhost:{}",
        pod::OPENCODE_PORT
    );
    tracing::info!(
        "  • SSH into workspace: podman exec -it {} bash",
        devaipod_pod.workspace_container
    );

    // Keep podman service running - when we drop it, the service will stop
    // For now, we just exit after starting. The pod will keep running.
    // In the future, we could wait for a signal or provide a shell.
    tracing::info!("Pod is running. Use 'podman pod stop {}' to stop.", pod_name);

    // Drop podman service - this will kill the service process
    // but the pod/containers will continue running since podman doesn't
    // require the service to be running for containers to run.
    drop(podman);

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
        .unwrap_or_else(|| config::DEFAULT_AGENT.to_string());

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

/// Build a bwrap command to sandbox the agent
fn build_bwrap_command(
    workspace_path: &str,
    real_home: &str,
    agent_home: &str,
    agent: &str,
    task: &str,
    agent_env_vars: &[(String, String)],
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
/// The podman service should be started by `devaipod configure-env`.
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
    {
        if let Some(start_str) = line.split(':').nth(1) {
            if let Ok(start) = start_str.parse::<u64>() {
                if start > 0 && start < max_uid {
                    tracing::debug!("subuid already configured correctly for {}", user);
                    return Ok(());
                }
            }
        }
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
    if ProcessCommand::new("podman")
        .arg("--version")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
        == false
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

    // Start podman service in background
    ProcessCommand::new("podman")
        .args(["system", "service", "--time=0"])
        .arg(format!("unix://{}", socket_path.display()))
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .context("Failed to start podman service")?;

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

/// Build bwrap command arguments for a shell (without running an agent command)
fn build_bwrap_shell_args(
    workspace_path: &str,
    real_home: &str,
    agent_home: &str,
    agent_env_vars: &[(String, String)],
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

    let agent_name = agent
        .map(|s| s.to_string())
        .or_else(|| config.agent.default_agent.clone())
        .unwrap_or_else(|| config::DEFAULT_AGENT.to_string());

    let session_name = "devaipod";

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

        // Start service-gator if configured
        if config.service_gator.is_enabled() {
            if let Err(e) = service_gator::start_server(&config.service_gator) {
                tracing::warn!("Failed to start service-gator: {}", e);
            } else {
                // Configure opencode to use service-gator MCP
                if let Err(e) =
                    service_gator::configure_opencode(&agent_home, &config.service_gator)
                {
                    tracing::warn!("Failed to configure opencode for service-gator: {}", e);
                }
            }
        }
        let agent_env_vars = config::collect_agent_env_vars();

        // Check for podman socket (started by devaipod-init.sh)
        let podman_socket = get_podman_socket();

        let mut bwrap_args = build_bwrap_shell_args(
            &workspace_path,
            &real_home,
            &agent_home,
            &agent_env_vars,
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

    tracing::info!("Entering bwrap sandbox (workspace: {})...", workspace_path);

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
fn cmd_internal_run_agent(config: &config::Config, agent: &str, task: &str) -> Result<()> {
    let workspace_path = get_workspace_path()?;

    tracing::info!(
        "Running {} agent in bwrap sandbox (workspace: {})",
        agent,
        workspace_path
    );

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

    // Start service-gator if configured
    if config.service_gator.is_enabled() {
        if let Err(e) = service_gator::start_server(&config.service_gator) {
            tracing::warn!("Failed to start service-gator: {}", e);
        } else {
            // Configure opencode to use service-gator MCP
            if let Err(e) = service_gator::configure_opencode(&agent_home, &config.service_gator) {
                tracing::warn!("Failed to configure opencode for service-gator: {}", e);
            }
        }
    }

    // Check for podman socket (started by devaipod-init.sh)
    let podman_socket = get_podman_socket();

    let agent_cmd = build_bwrap_command(
        &workspace_path,
        &real_home,
        &agent_home,
        agent,
        task,
        &agent_env_vars,
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
            &format!("User-Agent: devaipod/{}", env!("CARGO_PKG_VERSION")),
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
            &format!("User-Agent: devaipod/{}", env!("CARGO_PKG_VERSION")),
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
