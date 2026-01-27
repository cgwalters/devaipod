//! devaipod - Sandboxed AI coding agents in reproducible dev environments
//!
//! This tool uses DevPod for container provisioning and adds AI agent sandboxing.

#![forbid(unsafe_code)]

use std::path::{Path, PathBuf};
use std::process::Command as ProcessCommand;

use clap::{CommandFactory, Parser};
use color_eyre::eyre::{bail, Context, Result};

mod compose;
mod config;
mod devcontainer;
mod devpod;
mod forge;
mod git;
#[allow(dead_code)] // Preparatory infrastructure for GPU passthrough
mod gpu;
mod pod;
mod podman;
mod proxy;
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

    /// Enable verbose output (debug logging)
    #[arg(short, long, global = true)]
    verbose: bool,

    /// Quiet mode (only show warnings and errors)
    #[arg(short, long, global = true)]
    quiet: bool,

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
    ///   devaipod up . --service-gator=github:readonly-all
    ///   devaipod up . --service-gator=github:myorg/myrepo
    Up {
        /// Source: local path, git URL, or PR URL
        source: String,
        /// Task description for the AI agent (also stored as workspace description)
        #[arg(value_name = "TASK")]
        task: Option<String>,
        /// AI agent to run: goose, claude, opencode (default: from config or goose)
        #[arg(long, value_name = "AGENT")]
        agent: Option<String>,
        /// Don't start AI agent automatically
        #[arg(long)]
        no_agent: bool,
        /// Store task description but don't send it to the agent as a prompt
        #[arg(short = 'n', long)]
        no_prompt: bool,
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
        /// SSH into workspace after starting
        #[arg(short = 'S', long)]
        ssh: bool,
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
        /// Stdio mode: pipe stdin/stdout for ProxyCommand use (VSCode/Zed remote dev)
        #[arg(long)]
        stdio: bool,
        /// Command to run (optional)
        #[arg(trailing_var_arg = true)]
        command: Vec<String>,
    },
    /// Generate SSH config entry for a workspace
    ///
    /// Outputs an SSH config block that can be added to ~/.ssh/config.
    /// This enables VSCode/Zed Remote SSH to connect via ProxyCommand.
    ///
    /// Example:
    ///   devaipod ssh-config my-pod >> ~/.ssh/config
    SshConfig {
        /// Workspace name (pod name without devaipod- prefix)
        workspace: String,
        /// User to connect as (default: current user)
        #[arg(long)]
        user: Option<String>,
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
        /// Force deletion (stop running containers first)
        #[arg(short, long)]
        force: bool,
    },
    /// View container logs
    Logs {
        /// Workspace/pod name
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
    /// Show detailed status of a pod
    ///
    /// Displays pod status, container states, agent health, and exposed ports.
    Status {
        /// Workspace/pod name
        workspace: String,
        /// Output in JSON format
        #[arg(long)]
        json: bool,
    },
    /// Generate shell completions
    ///
    /// Outputs shell completion scripts to stdout for various shells.
    ///
    /// Examples:
    ///   devaipod completions bash > ~/.local/share/bash-completion/completions/devaipod
    ///   devaipod completions zsh > ~/.zfunc/_devaipod
    ///   devaipod completions fish > ~/.config/fish/completions/devaipod.fish
    Completions {
        /// Shell to generate completions for
        #[arg(value_enum)]
        shell: clap_complete::Shell,
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
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(default_level)),
        )
        .init();
}

async fn run_host(cli: HostCli) -> Result<()> {
    let config = config::load_config(cli.config.as_deref())?;

    match cli.command {
        HostCommand::Up {
            source,
            task,
            agent,
            no_agent,
            no_prompt,
            provider,
            ide,
            dry_run,
            agent_sidecar,
            ssh,
            service_gator_scopes,
        } => {
            cmd_up(
                &config,
                &source,
                task.as_deref(),
                no_prompt,
                agent.as_deref(),
                no_agent,
                provider.as_deref(),
                ide.as_deref(),
                dry_run,
                agent_sidecar,
                ssh,
                &service_gator_scopes,
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
        HostCommand::Ssh {
            workspace,
            stdio,
            command,
        } => cmd_ssh(&workspace, stdio, &command),
        HostCommand::SshConfig { workspace, user } => cmd_ssh_config(&workspace, user.as_deref()),
        HostCommand::List { json } => cmd_list(json),
        HostCommand::Stop { workspace } => cmd_stop(&workspace),
        HostCommand::Delete { workspace, force } => cmd_delete(&workspace, force),
        HostCommand::Logs {
            workspace,
            container,
            follow,
            tail,
        } => cmd_logs(&workspace, &container, follow, tail),
        HostCommand::Status { workspace, json } => cmd_status(&workspace, json),
        HostCommand::Completions { shell } => cmd_completions(shell),
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
    task: Option<&str>,
    no_prompt: bool,
    _agent: Option<&str>,
    _no_agent: bool,
    _provider: Option<&str>,
    _ide: Option<&str>,
    dry_run: bool,
    _agent_sidecar: bool,
    ssh: bool,
    service_gator_scopes: &[String],
) -> Result<()> {
    // Check if source is a PR/MR URL
    if let Some(pr_ref) = forge::parse_pr_url(source) {
        return cmd_up_pr(config, pr_ref, task, no_prompt, dry_run, ssh).await;
    }

    // Resolve local paths - if it looks like a URL, treat it as remote
    let is_remote_url = source.starts_with("http://")
        || source.starts_with("https://")
        || source.starts_with("git@");

    if is_remote_url {
        return cmd_up_remote(
            config,
            source,
            task,
            no_prompt,
            dry_run,
            ssh,
            service_gator_scopes,
        )
        .await;
    }

    let source_path = std::path::Path::new(source).canonicalize().ok();

    // Local path is required for non-remote sources
    let project_path = match source_path {
        Some(ref p) => p,
        None => {
            bail!(
                "Path '{}' does not exist or is not accessible.",
                source
            );
        }
    };

    // Detect git repository info for cloning into containers
    let git_info = git::detect_git_info(project_path)
        .context("Failed to detect git repository info")?;

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
            "\n⚠️  Warning: Uncommitted changes detected ({} file(s)):",
            git_info.dirty_files.len()
        );
        for file in git_info.dirty_files.iter().take(5) {
            eprintln!("     {}", file);
        }
        if git_info.dirty_files.len() > 5 {
            eprintln!("     ... and {} more", git_info.dirty_files.len() - 5);
        }
        eprintln!();
        eprintln!("   The AI agent will work on commit {} and won't see uncommitted changes.", &git_info.commit_sha[..8]);
        eprintln!("   Consider committing or stashing your changes first.\n");
    }

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
            .map(|c| if c.is_alphanumeric() || c == '-' {
                c
            } else {
                '-'
            })
            .collect::<String>()
    );

    // Check for API keys and warn if none are configured (helps first-run experience)
    check_api_keys_configured();

    if dry_run {
        tracing::info!("Dry run: would create pod '{}'", pod_name);
        tracing::info!("  project: {}", project_path.display());
        tracing::info!("  devcontainer: {}", devcontainer_json_path.display());
        tracing::info!("  gator enabled: {}", config.service_gator.is_enabled());
        return Ok(());
    }

    // Start podman service
    tracing::debug!("Starting podman service...");
    let podman = podman::PodmanService::spawn()
        .await
        .context("Failed to start podman service")?;

    // Check if pod already exists
    if let Some(status) = podman
        .get_pod_status(&pod_name)
        .await
        .context("Failed to check pod status")?
    {
        if status.is_running() {
            tracing::info!("Pod '{}' already running", pod_name);
            return Ok(());
        } else {
            // Pod exists but is stopped - start it
            tracing::debug!("Pod '{}' exists but is stopped, starting...", pod_name);
            podman
                .start_pod(&pod_name)
                .await
                .context("Failed to start existing pod")?;
            tracing::info!("Pod '{}' started", pod_name);
            return Ok(());
        }
    }

    // Parse CLI service-gator scopes and merge with file config
    let service_gator_config = if !service_gator_scopes.is_empty() {
        let cli_scopes = service_gator::parse_scopes(service_gator_scopes)
            .context("Failed to parse --service-gator scopes")?;
        service_gator::merge_configs(&config.service_gator, &cli_scopes)
    } else {
        config.service_gator.clone()
    };

    // Check if gator should be enabled (from merged config)
    let enable_gator = service_gator_config.is_enabled();
    // Check if network isolation should be enabled
    let enable_network_isolation = config.network_isolation.enabled;

    // Create the pod with all containers
    tracing::debug!("Creating pod '{}'...", pod_name);
    let source = pod::WorkspaceSource::LocalRepo(git_info);

    // Build extra labels for task description
    let mut extra_labels = Vec::new();
    if let Some(task_desc) = task {
        extra_labels.push(("io.devaipod.task".to_string(), task_desc.to_string()));
    }

    let devaipod_pod = pod::DevaipodPod::create(
        &podman,
        project_path,
        &devcontainer_config,
        &pod_name,
        enable_gator,
        enable_network_isolation,
        config,
        &source,
        &extra_labels,
        Some(&service_gator_config),
    )
    .await
    .context("Failed to create devaipod pod")?;

    // Start the pod
    devaipod_pod
        .start(&podman)
        .await
        .context("Failed to start pod")?;

    // Wait for the agent to be ready before proceeding
    devaipod_pod
        .wait_for_agent_ready(&podman, 60, 500)
        .await
        .context("Agent container failed to start")?;

    // Copy bind_home files into containers (using podman cp instead of bind mounts
    // to avoid permission issues with rootless podman)
    tracing::debug!("Copying bind_home files...");
    devaipod_pod
        .copy_bind_home_files(
            &podman,
            &devaipod_pod.workspace_bind_home,
            &devaipod_pod.agent_bind_home,
            &devaipod_pod.container_home,
            devcontainer_config.effective_user(),
        )
        .await
        .context("Failed to copy bind_home files")?;

    // Configure opencode in agent container to use service-gator MCP
    if enable_gator {
        devaipod_pod
            .configure_agent_opencode(&podman, &service_gator_config)
            .await
            .context("Failed to configure agent opencode")?;
    }

    // Configure nested podman support (adjusts subuid/subgid for container's UID namespace)
    devaipod_pod
        .configure_nested_podman(&podman)
        .await
        .context("Failed to configure nested podman")?;

    // Install dotfiles BEFORE lifecycle commands so bashrc, gitconfig, etc. are available
    if let Some(ref dotfiles) = config.dotfiles {
        devaipod_pod
            .install_dotfiles(&podman, dotfiles, devcontainer_config.effective_user())
            .await
            .context("Failed to install dotfiles")?;
        // Also install in agent container so .gitconfig is available for git operations
        devaipod_pod
            .install_dotfiles_agent(&podman, dotfiles)
            .await
            .context("Failed to install dotfiles in agent")?;
    }

    // Run lifecycle commands (onCreateCommand, postCreateCommand, postStartCommand)
    tracing::debug!("Running lifecycle commands...");
    devaipod_pod
        .run_lifecycle_commands(&podman, &devcontainer_config)
        .await
        .context("Failed to run lifecycle commands")?;

    // Success! Print connection info
    tracing::info!("Pod '{}' ready", pod_name);
    tracing::info!("  Agent: http://localhost:{}", pod::OPENCODE_PORT);
    tracing::info!(
        "  SSH: podman exec -it {} bash",
        devaipod_pod.workspace_container
    );

    // Send task to agent if provided and not --no-prompt
    if let Some(task_desc) = task {
        if !no_prompt {
            tracing::debug!("Sending task to agent...");
            send_task_to_agent(task_desc).await?;
        }
    }

    // Drop podman service - this will kill the service process
    // but the pod/containers will continue running since podman doesn't
    // require the service to be running for containers to run.
    drop(podman);

    // SSH into workspace if requested
    if ssh {
        return cmd_ssh(&pod_name, false, &[]);
    }

    Ok(())
}

/// Start a development environment from a PR/MR URL
async fn cmd_up_pr(
    config: &config::Config,
    pr_ref: forge::PullRequestRef,
    task: Option<&str>,
    no_prompt: bool,
    dry_run: bool,
    ssh: bool,
) -> Result<()> {
    tracing::info!(
        "Setting up PR #{} ({}/{})...",
        pr_ref.number,
        pr_ref.owner,
        pr_ref.repo
    );

    // Fetch PR metadata
    let pr_info = forge::fetch_pr_info(&pr_ref)
        .await
        .context("Failed to fetch PR information")?;

    tracing::debug!("PR: {}", pr_info.title);
    tracing::debug!("Head: {} @ {}", pr_info.head_ref, &pr_info.head_sha[..8]);

    // For PRs, we clone from the PR head to get the devcontainer.json from the PR
    // (not from upstream main, which may not have the devcontainer.json yet)
    let temp_dir = tempfile::tempdir().context("Failed to create temp directory")?;
    let temp_path = temp_dir.path();

    tracing::debug!("Cloning PR head to read devcontainer.json...");

    // Clone from the PR's head repository and checkout the specific commit
    let clone_output = tokio::process::Command::new("git")
        .args([
            "clone",
            "--depth",
            "1",
            "--branch",
            &pr_info.head_ref,
            &pr_info.head_clone_url,
            temp_path.to_str().unwrap(),
        ])
        .output()
        .await
        .context("Failed to clone PR head repository")?;

    if !clone_output.status.success() {
        let stderr = String::from_utf8_lossy(&clone_output.stderr);
        bail!("Failed to clone PR head repository: {}", stderr);
    }

    // Find and load devcontainer.json from the cloned repo
    let devcontainer_json_path = devcontainer::find_devcontainer_json(temp_path)?;
    let devcontainer_config = devcontainer::load(&devcontainer_json_path)?;

    // Derive pod name from repo and PR number
    let pod_name = format!(
        "devaipod-{}-pr{}",
        pr_ref.repo.chars()
            .map(|c| if c.is_alphanumeric() || c == '-' { c } else { '-' })
            .collect::<String>(),
        pr_ref.number
    );

    if dry_run {
        tracing::info!("Dry run mode - would create pod '{}'", pod_name);
        tracing::info!("  PR: {}", pr_info.pr_ref.short_display());
        tracing::info!("  Head: {} @ {}", pr_info.head_ref, &pr_info.head_sha[..8]);
        tracing::info!("  Clone URL: {}", pr_info.head_clone_url);
        return Ok(());
    }

    // Start podman service
    let podman = podman::PodmanService::spawn()
        .await
        .context("Failed to start podman service")?;

    // Check if pod already exists
    if let Some(status) = podman.get_pod_status(&pod_name).await? {
        tracing::info!(
            "Pod '{}' already exists (status: {:?}). Use 'devaipod delete {}' to remove it first.",
            pod_name,
            status,
            pod_name
        );
        return Ok(());
    }

    // Check for gator and network isolation settings
    let enable_gator = config.service_gator.is_enabled();
    let enable_network_isolation = config.network_isolation.enabled;

    // Create source from PR info
    let source = pod::WorkspaceSource::PullRequest(pr_info);

    // Build extra labels for task description
    let mut extra_labels = Vec::new();
    if let Some(task_desc) = task {
        extra_labels.push(("io.devaipod.task".to_string(), task_desc.to_string()));
    }

    // Create the pod
    // Note: For PR workflows, we use the file-based service_gator config (no CLI override yet)
    tracing::debug!("Creating pod '{}'...", pod_name);
    let devaipod_pod = pod::DevaipodPod::create(
        &podman,
        temp_path, // Use temp path for image building context
        &devcontainer_config,
        &pod_name,
        enable_gator,
        enable_network_isolation,
        config,
        &source,
        &extra_labels,
        None, // Use config.service_gator for PR workflows
    )
    .await
    .context("Failed to create devaipod pod")?;

    // Start the pod
    devaipod_pod
        .start(&podman)
        .await
        .context("Failed to start pod")?;

    // Wait for the agent to be ready
    devaipod_pod
        .wait_for_agent_ready(&podman, 120, 500)
        .await
        .context("Agent container failed to start")?;

    // Copy bind_home files
    tracing::debug!("Copying bind_home files...");
    devaipod_pod
        .copy_bind_home_files(
            &podman,
            &devaipod_pod.workspace_bind_home,
            &devaipod_pod.agent_bind_home,
            &devaipod_pod.container_home,
            devcontainer_config.effective_user(),
        )
        .await
        .context("Failed to copy bind_home files")?;

    // Configure nested podman
    devaipod_pod
        .configure_nested_podman(&podman)
        .await
        .context("Failed to configure nested podman")?;

    // Install dotfiles
    if let Some(ref dotfiles) = config.dotfiles {
        devaipod_pod
            .install_dotfiles(&podman, dotfiles, devcontainer_config.effective_user())
            .await
            .context("Failed to install dotfiles")?;
        // Also install in agent container so .gitconfig is available for git operations
        devaipod_pod
            .install_dotfiles_agent(&podman, dotfiles)
            .await
            .context("Failed to install dotfiles in agent")?;
    }

    // Run lifecycle commands
    tracing::debug!("Running lifecycle commands...");
    devaipod_pod
        .run_lifecycle_commands(&podman, &devcontainer_config)
        .await
        .context("Failed to run lifecycle commands")?;

    // Success!
    tracing::info!("Pod '{}' ready", pod_name);
    tracing::info!("  Agent: http://localhost:{}", pod::OPENCODE_PORT);
    tracing::info!(
        "  SSH: podman exec -it {} bash",
        devaipod_pod.workspace_container
    );

    // Send task to agent if provided and not --no-prompt
    if let Some(task_desc) = task {
        if !no_prompt {
            tracing::debug!("Sending task to agent...");
            send_task_to_agent(task_desc).await?;
        }
    }

    drop(podman);

    // SSH into workspace if requested
    if ssh {
        return cmd_ssh(&pod_name, false, &[]);
    }

    Ok(())
}

/// Start a development environment from a remote git URL
async fn cmd_up_remote(
    config: &config::Config,
    remote_url: &str,
    task: Option<&str>,
    no_prompt: bool,
    dry_run: bool,
    ssh: bool,
    service_gator_scopes: &[String],
) -> Result<()> {
    tracing::info!("Setting up {}...", remote_url);

    // Extract repo name from URL for naming
    let repo_name = git::extract_repo_name(remote_url)
        .unwrap_or_else(|| "project".to_string());

    // Clone the repository to a temp directory to read devcontainer.json and get default branch
    let temp_dir = tempfile::tempdir().context("Failed to create temp directory")?;
    let temp_path = temp_dir.path();

    tracing::debug!("Cloning repository to read devcontainer.json...");

    // Clone the repository (shallow clone for speed)
    let clone_output = tokio::process::Command::new("git")
        .args([
            "clone",
            "--depth",
            "1",
            remote_url,
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
        String::from_utf8_lossy(&branch_output.stdout).trim().to_string()
    } else {
        "main".to_string() // Fallback
    };

    // Find and load devcontainer.json from the cloned repo
    let devcontainer_json_path = devcontainer::find_devcontainer_json(temp_path)?;
    let devcontainer_config = devcontainer::load(&devcontainer_json_path)?;

    // Derive pod name from repo name
    let pod_name = format!(
        "devaipod-{}",
        repo_name
            .chars()
            .map(|c| if c.is_alphanumeric() || c == '-' { c } else { '-' })
            .collect::<String>()
    );

    // For remote URLs, auto-enable service-gator with readonly + draft PR access
    // to the target repository (unless user provided explicit scopes)
    let (service_gator_config, auto_gator_info) = if !service_gator_scopes.is_empty() {
        let cli_scopes = service_gator::parse_scopes(service_gator_scopes)
            .context("Failed to parse --service-gator scopes")?;
        (service_gator::merge_configs(&config.service_gator, &cli_scopes), None)
    } else if let Some(repo_ref) = forge::parse_repo_url(remote_url) {
        // Auto-configure: read + create-draft for the target repo
        let mut sg_config = config.service_gator.clone();
        let owner_repo = repo_ref.owner_repo();

        match repo_ref.forge_type {
            forge::ForgeType::GitHub => {
                sg_config.gh.repos.insert(
                    owner_repo.clone(),
                    config::GhRepoPermission {
                        read: true,
                        create_draft: true,
                        pending_review: false,
                        write: false,
                    },
                );
            }
            forge::ForgeType::GitLab | forge::ForgeType::Forgejo | forge::ForgeType::Gitea => {
                // TODO: Add GitLab/Forgejo/Gitea support to service-gator config
                // For now, just log that we can't auto-configure
                tracing::debug!(
                    "Auto service-gator not yet supported for {} ({})",
                    repo_ref.forge_type,
                    owner_repo
                );
            }
        }
        (sg_config, Some((repo_ref.forge_type, owner_repo)))
    } else {
        (config.service_gator.clone(), None)
    };

    if dry_run {
        tracing::info!("Dry run mode - would create pod '{}'", pod_name);
        tracing::info!("  Remote URL: {}", remote_url);
        tracing::info!("  Default branch: {}", default_branch);
        if let Some((forge_type, ref owner_repo)) = auto_gator_info {
            if matches!(forge_type, forge::ForgeType::GitHub) {
                tracing::info!("  Service-gator: {} (read + draft PRs)", owner_repo);
            }
        }
        if let Some(task_desc) = task {
            tracing::info!("  Task: {}", task_desc);
        }
        return Ok(());
    }

    if let Some((forge_type, ref owner_repo)) = auto_gator_info {
        if matches!(forge_type, forge::ForgeType::GitHub) {
            tracing::debug!("Auto-enabled service-gator for {} (read + draft PRs)", owner_repo);
        }
    }

    // Start podman service
    let podman = podman::PodmanService::spawn()
        .await
        .context("Failed to start podman service")?;

    // Check if pod already exists
    if let Some(status) = podman.get_pod_status(&pod_name).await? {
        if status.is_running() {
            tracing::info!("Pod '{}' already running", pod_name);
            return Ok(());
        } else {
            tracing::debug!("Pod '{}' exists but is stopped, starting...", pod_name);
            podman
                .start_pod(&pod_name)
                .await
                .context("Failed to start existing pod")?;
            tracing::info!("Pod '{}' started", pod_name);
            return Ok(());
        }
    }

    let enable_gator = service_gator_config.is_enabled();
    let enable_network_isolation = config.network_isolation.enabled;

    // Create source from remote repo info
    let remote_info = git::RemoteRepoInfo {
        remote_url: remote_url.to_string(),
        default_branch: default_branch.clone(),
        repo_name: repo_name.clone(),
    };
    let source = pod::WorkspaceSource::RemoteRepo(remote_info);

    // Build extra labels for task description
    let mut extra_labels = Vec::new();
    if let Some(task_desc) = task {
        extra_labels.push(("io.devaipod.task".to_string(), task_desc.to_string()));
    }

    // Create the pod
    tracing::debug!("Creating pod '{}'...", pod_name);
    let devaipod_pod = pod::DevaipodPod::create(
        &podman,
        temp_path,
        &devcontainer_config,
        &pod_name,
        enable_gator,
        enable_network_isolation,
        config,
        &source,
        &extra_labels,
        Some(&service_gator_config),
    )
    .await
    .context("Failed to create devaipod pod")?;

    // Start the pod
    devaipod_pod
        .start(&podman)
        .await
        .context("Failed to start pod")?;

    // Wait for the agent to be ready
    devaipod_pod
        .wait_for_agent_ready(&podman, 120, 500)
        .await
        .context("Agent container failed to start")?;

    // Copy bind_home files
    tracing::debug!("Copying bind_home files...");
    devaipod_pod
        .copy_bind_home_files(
            &podman,
            &devaipod_pod.workspace_bind_home,
            &devaipod_pod.agent_bind_home,
            &devaipod_pod.container_home,
            devcontainer_config.effective_user(),
        )
        .await
        .context("Failed to copy bind_home files")?;

    // Configure opencode in agent container to use service-gator MCP
    if enable_gator {
        devaipod_pod
            .configure_agent_opencode(&podman, &service_gator_config)
            .await
            .context("Failed to configure agent opencode")?;
    }

    // Configure nested podman
    devaipod_pod
        .configure_nested_podman(&podman)
        .await
        .context("Failed to configure nested podman")?;

    // Install dotfiles
    if let Some(ref dotfiles) = config.dotfiles {
        devaipod_pod
            .install_dotfiles(&podman, dotfiles, devcontainer_config.effective_user())
            .await
            .context("Failed to install dotfiles")?;
        devaipod_pod
            .install_dotfiles_agent(&podman, dotfiles)
            .await
            .context("Failed to install dotfiles in agent")?;
    }

    // Run lifecycle commands
    tracing::debug!("Running lifecycle commands...");
    devaipod_pod
        .run_lifecycle_commands(&podman, &devcontainer_config)
        .await
        .context("Failed to run lifecycle commands")?;

    // Success!
    tracing::info!("Pod '{}' ready", pod_name);
    tracing::info!("  Agent: http://localhost:{}", pod::OPENCODE_PORT);

    // Send task to agent if provided and not --no-prompt
    if let Some(task_desc) = task {
        if !no_prompt {
            tracing::debug!("Sending task to agent...");
            send_task_to_agent(task_desc).await?;
        }
    }

    drop(podman);

    // SSH into workspace if requested
    if ssh {
        return cmd_ssh(&pod_name, false, &[]);
    }

    Ok(())
}

/// Send a task prompt to the agent via HTTP API
async fn send_task_to_agent(task: &str) -> Result<()> {
    let url = format!("http://localhost:{}/session/new", pod::OPENCODE_PORT);

    let client = reqwest::Client::new();
    let response = client
        .post(&url)
        .json(&serde_json::json!({
            "prompt": task
        }))
        .send()
        .await
        .context("Failed to connect to agent")?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        tracing::warn!("Agent returned {}: {}", status, body);
        // Don't fail - the pod is running, user can send task manually
    } else {
        tracing::debug!("Task sent to agent successfully");
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

    let agent_env_vars = config::collect_agent_env_vars();
    let has_common_keys =
        std::env::var("ANTHROPIC_API_KEY").is_ok() || std::env::var("OPENAI_API_KEY").is_ok();

    if agent_env_vars.is_empty() && !has_common_keys {
        eprintln!();
        eprintln!("Warning: No API keys detected for the AI agent.");
        eprintln!("   Create a config file at ~/.config/devaipod.toml");
        eprintln!("   See: https://github.com/cgwalters/devaipod#configuration");
        eprintln!();
    }
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
///
/// Uses podman exec to attach to a tmux session in the workspace container.
/// If no tmux session exists, falls back to starting an interactive shell.
fn cmd_attach(pod_name: &str) -> Result<()> {
    let container = format!("{}-workspace", pod_name);

    // First check if the container exists and is running
    let check_output = podman_command()
        .args(["container", "exists", &container])
        .status();

    match check_output {
        Ok(status) if !status.success() => {
            bail!(
                "Container '{}' not found. Is the pod running?\n\
                 Use 'devaipod list' to see running pods.",
                container
            );
        }
        Err(e) => {
            bail!("Failed to check container status: {}", e);
        }
        _ => {}
    }

    tracing::info!("Attaching to agent in {}...", container);

    // Try to attach to tmux session named "agent"
    let status = podman_command()
        .args([
            "exec",
            "-it",
            &container,
            "tmux",
            "attach-session",
            "-t",
            "agent",
        ])
        .status()
        .context("Failed to attach to workspace")?;

    // If tmux session doesn't exist, fall back to interactive shell
    if !status.success() {
        tracing::info!("No tmux session 'agent' found, starting interactive shell...");
        let shell_status = podman_command()
            .args(["exec", "-it", &container, "/bin/bash"])
            .status()
            .context("Failed to exec into workspace")?;

        if !shell_status.success() {
            bail!(
                "Failed to start shell in container (exit code: {:?})",
                shell_status.code()
            );
        }
    }

    Ok(())
}

/// Check if we're running inside a toolbox container
fn is_toolbox() -> bool {
    std::env::var_os("TOOLBOX_PATH").is_some()
}

/// Build a std::process::Command for running podman CLI.
///
/// In toolbox mode, uses flatpak-spawn to run podman on the host.
/// Otherwise, runs podman directly.
fn podman_command() -> ProcessCommand {
    if is_toolbox() {
        let mut cmd = ProcessCommand::new("flatpak-spawn");
        cmd.args(["--host", "podman"]);
        cmd
    } else {
        ProcessCommand::new("podman")
    }
}

/// SSH into workspace using podman exec
fn cmd_ssh(pod_name: &str, stdio: bool, command: &[String]) -> Result<()> {
    let container = format!("{}-workspace", pod_name);

    if stdio {
        // Stdio mode: pipe stdin/stdout directly for ProxyCommand use
        // VSCode/Zed Remote SSH uses this to tunnel SSH protocol
        let mut cmd = podman_command();
        cmd.args(["exec", "-i", &container]);

        if command.is_empty() {
            // Default to bash for shell access
            cmd.arg("bash");
        } else {
            cmd.args(command);
        }

        let status = cmd.status().context("Failed to run podman exec")?;

        if !status.success() {
            bail!("podman exec failed with exit code {:?}", status.code());
        }
    } else {
        // Interactive mode with TTY
        tracing::info!("Connecting to container '{}'...", container);

        let mut cmd = podman_command();
        cmd.args(["exec", "-it", &container]);

        if command.is_empty() {
            cmd.arg("bash");
        } else {
            cmd.args(command);
        }

        let status = cmd.status().context("Failed to run podman exec")?;

        if !status.success() {
            bail!("podman exec failed with exit code {:?}", status.code());
        }
    }

    Ok(())
}

/// Get the SSH config directory path (~/.ssh/config.d)
fn get_ssh_config_dir() -> Result<PathBuf> {
    let home = std::env::var("HOME").context("HOME environment variable not set")?;
    Ok(PathBuf::from(home).join(".ssh").join("config.d"))
}

/// Get the SSH config file path for a workspace
fn get_ssh_config_path(workspace: &str) -> Result<PathBuf> {
    Ok(get_ssh_config_dir()?.join(format!("devaipod-{}", workspace)))
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

/// Generate SSH config entry for a workspace
fn cmd_ssh_config(pod_name: &str, user: Option<&str>) -> Result<()> {
    // Determine username: --user flag, or current user
    let username = user
        .map(|s| s.to_string())
        .or_else(|| std::env::var("USER").ok())
        .unwrap_or_else(|| "user".to_string());

    // Find the devaipod binary path for the ProxyCommand
    let devaipod_path = std::env::current_exe()
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_else(|_| "devaipod".to_string());

    // Create SSH config content
    let config_content = format!(
        r#"# Generated by devaipod ssh-config
Host {pod}.devaipod
    ProxyCommand {devaipod} ssh --stdio {pod}
    User {user}
    StrictHostKeyChecking no
    UserKnownHostsFile /dev/null
    LogLevel ERROR
"#,
        pod = pod_name,
        devaipod = devaipod_path,
        user = username,
    );

    // Ensure ~/.ssh/config.d directory exists
    let config_dir = get_ssh_config_dir()?;
    std::fs::create_dir_all(&config_dir)
        .with_context(|| format!("Failed to create {}", config_dir.display()))?;

    // Write the config file
    let config_path = get_ssh_config_path(pod_name)?;
    std::fs::write(&config_path, &config_content)
        .with_context(|| format!("Failed to write {}", config_path.display()))?;

    println!("Added SSH config to {}", config_path.display());

    // Check if Include directive exists in ~/.ssh/config
    if !ssh_config_has_include() {
        println!();
        println!("Add this line to the TOP of ~/.ssh/config:");
        println!("Include ~/.ssh/config.d/*");
    }

    Ok(())
}

/// List devaipod pods using podman pod ps
fn cmd_list(json_output: bool) -> Result<()> {
    let output = podman_command()
        .args(["pod", "ps", "--filter", "name=devaipod-*", "--format=json"])
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

    if json_output {
        // For JSON output, enrich with labels from pod inspect
        let mut enriched_pods = Vec::new();
        for pod in &pods {
            let mut enriched = pod.clone();
            if let Some(name) = pod.get("Name").and_then(|v| v.as_str()) {
                if let Some(labels) = get_pod_labels(name) {
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
    }

    let mut pod_infos: Vec<PodInfo> = Vec::new();
    for pod in &pods {
        let name = pod.get("Name").and_then(|v| v.as_str()).unwrap_or("-").to_string();
        let status = pod.get("Status").and_then(|v| v.as_str()).unwrap_or("-").to_string();
        let containers = pod
            .get("Containers")
            .and_then(|v| v.as_array())
            .map(|a| a.len())
            .unwrap_or(0);
        let created = pod.get("Created").and_then(|v| v.as_str()).unwrap_or("-").to_string();

        // Get labels from pod inspect
        let (repo, pr, task) = if let Some(labels) = get_pod_labels(&name) {
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
            (repo, pr, task)
        } else {
            (None, None, None)
        };

        pod_infos.push(PodInfo {
            name,
            status,
            containers,
            created,
            repo,
            pr,
            task,
        });
    }

    // Calculate column widths
    let name_width = pod_infos.iter().map(|p| p.name.len()).max().unwrap_or(4).max(4);
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

    // Print header
    if has_repo_info {
        if has_task_info {
            println!(
                "{:<name_width$}  {:<10}  {:<repo_width$}  {:<6}  {:<30}  {}",
                "NAME",
                "STATUS",
                "REPO",
                "PR",
                "TASK",
                "CREATED",
                name_width = name_width,
                repo_width = repo_width
            );
        } else {
            println!(
                "{:<name_width$}  {:<10}  {:<repo_width$}  {:<6}  {}",
                "NAME",
                "STATUS",
                "REPO",
                "PR",
                "CREATED",
                name_width = name_width,
                repo_width = repo_width
            );
        }
    } else if has_task_info {
        println!(
            "{:<name_width$}  {:<10}  {:<30}  {}",
            "NAME",
            "STATUS",
            "TASK",
            "CREATED",
            name_width = name_width
        );
    } else {
        println!(
            "{:<name_width$}  {:<10}  {:<12}  {}",
            "NAME",
            "STATUS",
            "CONTAINERS",
            "CREATED",
            name_width = name_width
        );
    }

    // Print pods
    for info in &pod_infos {
        let created_display = format_created_time(&info.created);

        let status_display = match info.status.to_lowercase().as_str() {
            "running" => "Running",
            "stopped" => "Stopped",
            "exited" => "Exited",
            "degraded" => "Degraded",
            _ => &info.status,
        };

        // Truncate task to 30 chars for display
        let task_display = info
            .task
            .as_ref()
            .map(|t| {
                if t.len() > 30 {
                    format!("{}...", &t[..27])
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
                    "{:<name_width$}  {:<10}  {:<repo_width$}  {:<6}  {:<30}  {}",
                    info.name,
                    status_display,
                    repo_display,
                    pr_display,
                    task_display,
                    created_display,
                    name_width = name_width,
                    repo_width = repo_width
                );
            } else {
                println!(
                    "{:<name_width$}  {:<10}  {:<repo_width$}  {:<6}  {}",
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
                "{:<name_width$}  {:<10}  {:<30}  {}",
                info.name,
                status_display,
                task_display,
                created_display,
                name_width = name_width
            );
        } else {
            println!(
                "{:<name_width$}  {:<10}  {:<12}  {}",
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

    Ok(())
}

/// Get labels for a pod using podman pod inspect
fn get_pod_labels(pod_name: &str) -> Option<serde_json::Value> {
    let output = podman_command()
        .args(["pod", "inspect", "--format", "{{json .Labels}}", pod_name])
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

/// Stop a pod using podman pod stop
fn cmd_stop(pod_name: &str) -> Result<()> {
    tracing::info!("Stopping pod '{}'...", pod_name);

    let output = podman_command()
        .args(["pod", "stop", pod_name])
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
        .args(["pod", "stop", pod_name])
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

    cmd.arg(pod_name);

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

    // Clean up SSH config file if it exists
    if let Err(e) = remove_ssh_config(pod_name) {
        tracing::warn!("Failed to remove SSH config: {}", e);
    }

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
        .args(["pod", "inspect", pod_name])
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

    let pod_json: serde_json::Value =
        serde_json::from_slice(&pod_output.stdout).context("Failed to parse pod inspect output")?;

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
    }

    Ok(())
}

/// Check if the agent health endpoint is responding
fn check_agent_health(pod_name: &str) -> Option<bool> {
    let workspace_container = format!("{}-workspace", pod_name);
    let health_url = format!("http://localhost:{}/global/health", pod::OPENCODE_PORT);

    // Try to curl the health endpoint from inside the workspace container
    let check_cmd = format!("curl -sf '{}' >/dev/null 2>&1", health_url);
    let result = podman_command()
        .args(["exec", &workspace_container, "/bin/sh", "-c", &check_cmd])
        .status();

    match result {
        Ok(status) => Some(status.success()),
        Err(_) => None,
    }
}

/// Extract exposed ports from pod inspect JSON
fn extract_pod_ports(pod_json: &serde_json::Value) -> Vec<String> {
    let mut ports = Vec::new();

    // Ports are typically in InfraConfig.PortBindings
    if let Some(infra) = pod_json.get("InfraConfig") {
        if let Some(bindings) = infra.get("PortBindings") {
            if let Some(obj) = bindings.as_object() {
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
                                ports.push(format!(
                                    "{}:{} -> {}",
                                    host_ip, host_port, container_port
                                ));
                            }
                        }
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
    clap_complete::generate(shell, &mut cmd, "devaipod", &mut std::io::stdout());
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
        assert!(
            subcommands.contains(&"ssh-config"),
            "Missing 'ssh-config' command"
        );
        assert!(subcommands.contains(&"list"), "Missing 'list' command");
        assert!(subcommands.contains(&"stop"), "Missing 'stop' command");
        assert!(subcommands.contains(&"delete"), "Missing 'delete' command");
        assert!(subcommands.contains(&"logs"), "Missing 'logs' command");
        assert!(subcommands.contains(&"status"), "Missing 'status' command");
        assert!(
            subcommands.contains(&"completions"),
            "Missing 'completions' command"
        );

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
