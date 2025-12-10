use std::path::{Path, PathBuf};
use std::process::{Command as ProcessCommand, Stdio};

use clap::Parser;
use color_eyre::eyre::{bail, Context, ContextCompat, Result};
use serde::{Deserialize, Serialize};

mod config;
mod consts;
mod devfile;
mod pod;
mod secrets;
mod tmux;
mod workspace;

#[derive(Debug, Parser)]
#[command(name = "devc")]
#[command(about = "Manage git worktrees with devcontainers", long_about = None)]
struct Cli {
    /// Path to config file (default: ~/.config/devc.toml)
    #[arg(long, global = true, value_name = "PATH")]
    config: Option<PathBuf>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Parser)]
enum Command {
    /// Create a new workspace and spawn container(s)
    ///
    /// Creates a workspace from a git URL, GitHub issue URL, or local path.
    ///
    /// Examples:
    ///   devc new https://github.com/bootc-dev/bootc "work on boot feature"
    ///   devc new https://github.com/bootc-dev/bootc/issues/123 "fix issue 123"
    ///   devc new /path/to/local/repo "local development"
    New {
        /// Git URL, GitHub issue URL, or local path
        source: String,
        /// Description of the workspace purpose (optional for GitHub issue URLs)
        description: Option<String>,
        /// Workspace name (default: derived from source)
        #[arg(short, long)]
        name: Option<String>,
        /// Base branch to clone from (defaults to HEAD)
        #[arg(short, long)]
        base: Option<String>,
        /// Disable automatic /dev/kvm device binding
        #[arg(long)]
        no_kvm: bool,
        /// Pass podman secrets as environment variables (format: secret-name=ENV_VAR)
        #[arg(long = "secret", value_name = "SECRET=ENV")]
        secrets: Vec<String>,
        /// Spawn with sidecar using specified image
        #[arg(long, value_name = "IMAGE")]
        sidecar: Option<String>,
        /// Use named sidecar profile from config
        #[arg(long, value_name = "PROFILE")]
        sidecar_profile: Option<String>,
        /// Disable sidecar even if enabled in config
        #[arg(long)]
        no_sidecar: bool,
        /// Pass secret to sidecar container (repeatable)
        #[arg(long = "sidecar-secret", value_name = "SECRET=ENV")]
        sidecar_secrets: Vec<String>,
        /// Pass secret to all containers (repeatable)
        #[arg(long = "secret-all", value_name = "SECRET=ENV")]
        secrets_all: Vec<String>,
    },
    /// Enter devcontainer shell
    Enter {
        /// Worktree or workspace folder to enter (defaults to current directory)
        worktree: Option<String>,
        /// Pass podman secrets as environment variables (format: secret-name=ENV_VAR)
        #[arg(long = "secret", value_name = "SECRET=ENV")]
        secrets: Vec<String>,
        /// Enter specific container (skip tmux)
        #[arg(short = 'c', long)]
        container: Option<String>,
        /// Skip tmux even for multi-container pods
        #[arg(long)]
        no_tmux: bool,
    },
    /// List active devcontainers
    List {
        /// Output in JSON format
        #[arg(long)]
        json: bool,
    },
    /// Remove worktree and devcontainer
    Rm {
        /// Worktree name to remove
        worktree: String,
        /// Also remove the git worktree (not just the container)
        #[arg(long)]
        worktree_too: bool,
    },
    /// Remove all workspaces
    RmAll {
        /// Skip confirmation prompt
        #[arg(long)]
        yes: bool,
        /// Also remove git worktrees (not just the containers)
        #[arg(long)]
        worktree_too: bool,
    },
    /// Run a command in an ephemeral container (creates, runs, then removes)
    RunEphemeral {
        /// Command to run (defaults to interactive shell)
        #[arg(trailing_var_arg = true)]
        command: Vec<String>,
        /// Disable automatic /dev/kvm device binding
        #[arg(long)]
        no_kvm: bool,
        /// Pass podman secrets as environment variables (format: secret-name=ENV_VAR)
        #[arg(long = "secret", value_name = "SECRET=ENV")]
        secrets: Vec<String>,
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

    let cli = Cli::parse();
    run(cli)
}

fn run(cli: Cli) -> Result<()> {
    let config_path = cli.config;

    match cli.command {
        Command::New {
            source,
            description,
            name,
            base,
            no_kvm,
            secrets,
            sidecar,
            sidecar_profile,
            no_sidecar,
            sidecar_secrets,
            secrets_all,
        } => run_new_workspace(
            &source,
            description.as_deref(),
            name.as_deref(),
            base.as_deref(),
            !no_kvm,
            &secrets,
            sidecar.as_deref(),
            sidecar_profile.as_deref(),
            no_sidecar,
            &sidecar_secrets,
            &secrets_all,
            config_path.as_deref(),
        ),
        Command::Enter {
            worktree,
            secrets,
            container,
            no_tmux,
        } => run_enter(
            worktree.as_deref(),
            &secrets,
            container.as_deref(),
            no_tmux,
            config_path.as_deref(),
        ),
        Command::List { json } => run_list(json),
        Command::Rm {
            worktree,
            worktree_too,
        } => run_rm(&worktree, worktree_too),
        Command::RmAll { yes, worktree_too } => run_rm_all(yes, worktree_too),
        Command::RunEphemeral {
            command,
            no_kvm,
            secrets,
        } => run_ephemeral(command, !no_kvm, &secrets),
    }
}

/// Parse and validate secrets from CLI arguments
fn parse_secrets(secret_args: &[String]) -> Result<Vec<(String, String)>> {
    let mut secrets = Vec::new();

    for arg in secret_args {
        let secret = secrets::SecretArg::parse(arg)?;
        secrets.push((secret.secret_name, secret.env_var));
    }

    // Validate that all secrets exist in podman
    if !secrets.is_empty() {
        let secret_names: Vec<String> = secrets.iter().map(|(name, _)| name.clone()).collect();
        secrets::validate_secrets(&secret_names)?;
    }

    Ok(secrets)
}

/// Resolve sidecar configuration from CLI args and config file.
///
/// **Sidecar is ALWAYS enabled by default.** Use `--no-sidecar` to disable.
///
/// By default, the sidecar:
/// - Uses the SAME image as the main container (has same tools)
/// - Has NO network access (isolated for security)
/// - Has read-only access to sources
/// - Receives NO secrets
///
/// Users can opt-in to network access and secrets via config.
fn resolve_sidecar(
    cli_sidecar: Option<&str>,
    cli_profile: Option<&str>,
    cli_no_sidecar: bool,
    config: &config::Config,
) -> Option<devfile::SidecarSpec> {
    // If --no-sidecar is specified, disable sidecar
    if cli_no_sidecar {
        return None;
    }

    // If --sidecar <image> is specified, use that image with config defaults
    if let Some(image) = cli_sidecar {
        return Some(devfile::SidecarSpec {
            image: Some(image.to_string()),
            command: config.sidecar.command.clone(),
            mount_sources_readonly: config.sidecar.mount_sources_readonly,
            network: config.sidecar.network,
            mounts: config.sidecar.mounts.clone(),
            dotfiles: config.sidecar.dotfiles.clone(),
            dotfiles_repo: config.sidecar.dotfiles_repo.clone(),
            dotfiles_install: config.sidecar.dotfiles_install.clone(),
        });
    }

    // If --sidecar-profile <name> is specified, look up in config
    if let Some(profile_name) = cli_profile {
        if let Some(profile) = config.sidecar.profiles.get(profile_name) {
            // Profile values override base values if specified, otherwise inherit
            let mounts = if profile.mounts.is_empty() {
                config.sidecar.mounts.clone()
            } else {
                profile.mounts.clone()
            };
            let dotfiles = if profile.dotfiles.is_empty() {
                config.sidecar.dotfiles.clone()
            } else {
                profile.dotfiles.clone()
            };
            let dotfiles_repo = profile
                .dotfiles_repo
                .clone()
                .or_else(|| config.sidecar.dotfiles_repo.clone());
            let dotfiles_install = profile
                .dotfiles_install
                .clone()
                .or_else(|| config.sidecar.dotfiles_install.clone());
            return Some(devfile::SidecarSpec {
                image: profile.image.clone(),
                command: profile.command.clone(),
                mount_sources_readonly: profile.mount_sources_readonly,
                network: profile.network,
                mounts,
                dotfiles,
                dotfiles_repo,
                dotfiles_install,
            });
        } else {
            tracing::warn!(
                "Sidecar profile '{}' not found in config, using default",
                profile_name
            );
            // Fall through to default behavior
        }
    }

    // If explicit image is configured, use it
    if let Some(image) = &config.sidecar.image {
        return Some(devfile::SidecarSpec {
            image: Some(image.clone()),
            command: config.sidecar.command.clone(),
            mount_sources_readonly: config.sidecar.mount_sources_readonly,
            network: config.sidecar.network,
            mounts: config.sidecar.mounts.clone(),
            dotfiles: config.sidecar.dotfiles.clone(),
            dotfiles_repo: config.sidecar.dotfiles_repo.clone(),
            dotfiles_install: config.sidecar.dotfiles_install.clone(),
        });
    }

    // Default: sidecar is enabled, uses main container's image
    Some(devfile::SidecarSpec {
        image: None, // Will use main container's image
        command: config.sidecar.command.clone(),
        mount_sources_readonly: config.sidecar.mount_sources_readonly,
        network: config.sidecar.network,
        mounts: config.sidecar.mounts.clone(),
        dotfiles: config.sidecar.dotfiles.clone(),
        dotfiles_repo: config.sidecar.dotfiles_repo.clone(),
        dotfiles_install: config.sidecar.dotfiles_install.clone(),
    })
}

/// Find the git repository root from the current directory
fn find_git_root() -> Result<PathBuf> {
    let output = ProcessCommand::new("git")
        .args(["rev-parse", "--show-toplevel"])
        .output()
        .context("Failed to run git")?;

    if !output.status.success() {
        bail!("Not in a git repository");
    }

    let path = String::from_utf8(output.stdout)
        .context("Invalid UTF-8 in git output")?
        .trim()
        .to_string();

    Ok(PathBuf::from(path))
}

/// Find the worktrees directory (sibling to the main repo, named <repo>.worktrees)
fn get_worktrees_dir(git_root: &Path) -> Result<PathBuf> {
    let repo_name = git_root
        .file_name()
        .context("Could not determine repository name")?
        .to_string_lossy();

    let parent = git_root
        .parent()
        .context("Repository has no parent directory")?;
    Ok(parent.join(format!("{}.worktrees", repo_name)))
}

/// Parse a GitHub issue URL and return (org, repo, issue_number)
fn parse_github_issue_url(url: &str) -> Option<(String, String, u64)> {
    // Pattern: https://github.com/{org}/{repo}/issues/{number}
    if !url.starts_with("https://github.com/") && !url.starts_with("http://github.com/") {
        return None;
    }

    let parsed = url::Url::parse(url).ok()?;
    let path_segments: Vec<&str> = parsed.path_segments()?.collect();

    if path_segments.len() == 4 && path_segments[2] == "issues" {
        let org = path_segments[0].to_string();
        let repo = path_segments[1].to_string();
        let issue_number = path_segments[3].parse::<u64>().ok()?;
        Some((org, repo, issue_number))
    } else {
        None
    }
}

/// Fetch GitHub issue title from the API
fn fetch_github_issue_title(org: &str, repo: &str, issue_number: u64) -> Result<String> {
    let url = format!(
        "https://api.github.com/repos/{}/{}/issues/{}",
        org, repo, issue_number
    );

    tracing::info!("Fetching issue title from GitHub API: {}", url);

    let output = ProcessCommand::new("curl")
        .args([
            "-s",
            "-w",
            "\n%{http_code}",
            "-H",
            "Accept: application/vnd.github+json",
            "-H",
            "X-GitHub-Api-Version: 2022-11-28",
            "-H",
            "User-Agent: devc/0.1.0",
            &url,
        ])
        .output()
        .context("Failed to run curl (is curl installed?)")?;

    let output_str = String::from_utf8_lossy(&output.stdout);
    let mut lines: Vec<&str> = output_str.lines().collect();

    // Extract HTTP status code from last line (added by -w flag)
    let http_code = lines.pop().and_then(|line| line.parse::<u16>().ok());
    let response_body = lines.join("\n");

    if !output.status.success() {
        bail!("curl command failed while fetching GitHub issue");
    }

    // Check HTTP status code
    match http_code {
        Some(200) => {
            // Success, parse response
        }
        Some(404) => {
            bail!(
                "GitHub issue #{} not found in {}/{}. Please verify the issue number and repository.",
                issue_number, org, repo
            );
        }
        Some(403) => {
            bail!(
                "GitHub API rate limit exceeded. Try again later or set up authentication.\n\
                See: https://docs.github.com/en/rest/overview/rate-limits-for-the-rest-api"
            );
        }
        Some(code) => {
            bail!(
                "GitHub API returned HTTP {} while fetching issue #{}",
                code,
                issue_number
            );
        }
        None => {
            bail!("Failed to determine HTTP status code from GitHub API response");
        }
    }

    // Parse JSON response to extract title
    let json: serde_json::Value = serde_json::from_str(&response_body)
        .context("Failed to parse GitHub API response as JSON")?;

    if let Some(title) = json.get("title").and_then(|t| t.as_str()) {
        Ok(title.to_string())
    } else {
        // Check if there's a message field (error case)
        if let Some(message) = json.get("message").and_then(|m| m.as_str()) {
            bail!("GitHub API error for issue #{}: {}", issue_number, message);
        }

        bail!(
            "Could not extract issue title from GitHub API response for issue #{}. Response: {}",
            issue_number,
            response_body.chars().take(200).collect::<String>()
        );
    }
}

/// Create a new workspace from a source (URL or path) and spawn a container
fn run_new_workspace(
    source_str: &str,
    description: Option<&str>,
    name: Option<&str>,
    base: Option<&str>,
    enable_kvm: bool,
    secret_args: &[String],
    cli_sidecar: Option<&str>,
    cli_sidecar_profile: Option<&str>,
    cli_no_sidecar: bool,
    sidecar_secret_args: &[String],
    secrets_all_args: &[String],
    config_path: Option<&Path>,
) -> Result<()> {
    // Check if source is a GitHub issue URL
    if let Some((org, repo, issue_number)) = parse_github_issue_url(source_str) {
        let repo_url = format!("https://github.com/{}/{}", org, repo);
        let issue_title = fetch_github_issue_title(&org, &repo, issue_number).unwrap_or_else(|e| {
            tracing::warn!("Failed to fetch issue title: {}", e);
            format!("Issue #{}", issue_number)
        });

        tracing::info!(
            "GitHub issue detected: #{} - {}. Cloning repository: {}",
            issue_number,
            issue_title,
            repo_url
        );

        // Use user-provided description if given, otherwise use the issue title
        let final_description = description.map(|s| s.to_string()).unwrap_or(issue_title);

        return run_new_workspace_impl(
            &repo_url,
            Some(&final_description),
            name,
            base,
            enable_kvm,
            secret_args,
            cli_sidecar,
            cli_sidecar_profile,
            cli_no_sidecar,
            sidecar_secret_args,
            secrets_all_args,
            config_path,
        );
    }

    // Regular git URL or local path
    if description.is_none() {
        bail!("Description is required when not using a GitHub issue URL");
    }

    run_new_workspace_impl(
        source_str,
        description,
        name,
        base,
        enable_kvm,
        secret_args,
        cli_sidecar,
        cli_sidecar_profile,
        cli_no_sidecar,
        sidecar_secret_args,
        secrets_all_args,
        config_path,
    )
}

/// Implementation of workspace creation (refactored from run_new_workspace)
fn run_new_workspace_impl(
    source_str: &str,
    description: Option<&str>,
    name: Option<&str>,
    base: Option<&str>,
    enable_kvm: bool,
    secret_args: &[String],
    cli_sidecar: Option<&str>,
    cli_sidecar_profile: Option<&str>,
    cli_no_sidecar: bool,
    sidecar_secret_args: &[String],
    secrets_all_args: &[String],
    config_path: Option<&Path>,
) -> Result<()> {
    // Load config
    let config = config::load_config_from(config_path)?;

    // Parse CLI secrets
    let cli_main_secrets = parse_secrets(secret_args)?;
    let cli_sidecar_secrets = parse_secrets(sidecar_secret_args)?;
    let cli_all_secrets = parse_secrets(secrets_all_args)?;

    // Merge with config secrets
    let all_secrets = secrets::merge_secrets(
        &cli_main_secrets,
        &cli_sidecar_secrets,
        &cli_all_secrets,
        &config.secrets,
    );

    // Validate all secrets (CLI + config) exist in podman
    secrets::validate_resolved_secrets(&all_secrets)?;

    // Resolve sidecar config
    let sidecar_spec = resolve_sidecar(cli_sidecar, cli_sidecar_profile, cli_no_sidecar, &config);

    let source = workspace::parse_source(source_str)?;
    let ws = workspace::create_workspace(&source, name, base, description)?;

    tracing::info!(
        "Workspace '{}' created with storage: {:?}",
        ws.name,
        ws.storage
    );

    // For volume-based workspaces, we need to read the devfile from inside the volume
    let devfile = read_devfile_from_storage(&ws.storage)?;

    if let Some(df) = devfile {
        if sidecar_spec.is_some() {
            // Use pod-based multi-container setup
            let main_secrets = secrets::filter_secrets_for_role(&all_secrets, "main", None);
            let sidecar_secrets =
                secrets::filter_secrets_for_role(&all_secrets, "sidecar", Some("sidecar"));

            devfile::start_devfile_pod(
                &ws.name,
                &ws.storage,
                &df,
                true,
                enable_kvm,
                &main_secrets,
                sidecar_spec.as_ref(),
                &sidecar_secrets,
            )?;
        } else {
            // Single container setup (backward compatible)
            let main_secrets = secrets::filter_secrets_for_role(&all_secrets, "main", None);
            devfile::start_devfile_container(
                &ws.name,
                &ws.storage,
                &df,
                true,
                enable_kvm,
                &main_secrets,
            )?;
        }
    } else {
        tracing::warn!(
            "No devfile.yaml or devcontainer.json found in workspace; container not started"
        );
    }

    Ok(())
}

/// Read a file from a podman volume using `podman unshare` + `podman volume mount`.
///
/// This approach doesn't require any container images - it uses the host's
/// filesystem tools within podman's user namespace.
///
/// Returns Ok(None) if the file doesn't exist, Ok(Some(content)) if it does,
/// or an error for other failures (permission denied, volume doesn't exist, etc.)
fn read_file_from_volume(volume_name: &str, path: &str) -> Result<Option<String>> {
    // Build a shell script that:
    // 1. Mounts the volume
    // 2. Attempts to read the file (checking if it exists first)
    // 3. Unmounts the volume
    // We use a specific exit code (42) to indicate "file not found" vs other errors
    let script = format!(
        r#"
        set -e
        mount_path=$(podman volume mount {volume})
        cleanup() {{ podman volume unmount {volume} >/dev/null 2>&1 || true; }}
        trap cleanup EXIT
        target="$mount_path"{path}
        if [ ! -e "$target" ]; then
            exit 42
        fi
        cat "$target"
        "#,
        volume = volume_name,
        path = path,
    );

    let output = ProcessCommand::new("podman")
        .args(["unshare", "sh", "-c", &script])
        .output()
        .context("Failed to run podman unshare")?;

    if output.status.success() {
        let content = String::from_utf8_lossy(&output.stdout).to_string();
        Ok(Some(content))
    } else {
        // Exit code 42 means file not found (our convention)
        if output.status.code() == Some(42) {
            Ok(None)
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            bail!(
                "Failed to read {} from volume {}: {}",
                path,
                volume_name,
                stderr.trim()
            );
        }
    }
}

/// Read a devfile from storage (volume or bind mount)
fn read_devfile_from_storage(storage: &workspace::StorageMode) -> Result<Option<devfile::Devfile>> {
    match storage {
        workspace::StorageMode::Volume { name } => {
            // Try devfile candidates first
            let devfile_candidates = [
                "/devfile.yaml",
                "/.devfile.yaml",
                "/devfile.yml",
                "/.devfile.yml",
            ];

            for candidate in devfile_candidates {
                if let Some(content) = read_file_from_volume(name, candidate)? {
                    let devfile: devfile::Devfile = serde_yml::from_str(&content)
                        .with_context(|| format!("Failed to parse {}", candidate))?;
                    return Ok(Some(devfile));
                }
            }

            // Fall back to devcontainer.json
            let devcontainer_candidates =
                ["/.devcontainer/devcontainer.json", "/.devcontainer.json"];

            for candidate in devcontainer_candidates {
                if let Some(content) = read_file_from_volume(name, candidate)? {
                    // devcontainer.json uses JSONC format which allows comments
                    let content = devfile::strip_json_comments(&content);
                    // Parse devcontainer.json and convert to devfile
                    // For now, we only support simple image-based devcontainers in volumes
                    #[derive(serde::Deserialize)]
                    #[serde(rename_all = "camelCase")]
                    struct SimpleDevContainer {
                        #[serde(default)]
                        image: Option<String>,
                        #[serde(default)]
                        name: Option<String>,
                    }

                    let dc: SimpleDevContainer = serde_json::from_str(&content)
                        .with_context(|| format!("Failed to parse {}", candidate))?;

                    if let Some(image) = dc.image {
                        let container_name = dc.name.unwrap_or_else(|| "devcontainer".to_string());
                        let devfile = devfile::Devfile {
                            schema_version: "2.2.0".to_string(),
                            metadata: devfile::DevfileMetadata {
                                name: container_name.clone(),
                                version: Some("1.0.0".to_string()),
                                description: Some("Converted from devcontainer.json".to_string()),
                            },
                            components: vec![devfile::Component {
                                name: "dev".to_string(),
                                container: Some(devfile::ContainerComponent {
                                    image,
                                    command: vec!["/bin/sh".to_string()],
                                    args: vec!["-c".to_string(), "sleep infinity".to_string()],
                                    env: vec![],
                                    volume_mounts: vec![],
                                    mount_sources: true,
                                    source_mapping: None,
                                    memory_limit: None,
                                    memory_request: None,
                                    cpu_limit: None,
                                    cpu_request: None,
                                }),
                                volume: None,
                            }],
                            commands: vec![],
                        };
                        tracing::info!("Converted devcontainer.json to devfile");
                        return Ok(Some(devfile));
                    }
                }
            }

            Ok(None)
        }
        workspace::StorageMode::BindMount { host_path } => {
            // Read devfile from host filesystem (already handles devcontainer fallback)
            devfile::load_devfile(host_path)
        }
    }
}

/// Detect which dev environment configuration is available
enum DevEnvConfig {
    Devfile(devfile::Devfile),
    Devcontainer,
}

fn detect_dev_config(workspace: &Path) -> Result<Option<DevEnvConfig>> {
    // Check for devfile first (preferred)
    if let Some(df) = devfile::load_devfile(workspace)? {
        return Ok(Some(DevEnvConfig::Devfile(df)));
    }

    // Fall back to devcontainer
    let devcontainer_dir = workspace.join(".devcontainer");
    if devcontainer_dir.exists() {
        return Ok(Some(DevEnvConfig::Devcontainer));
    }

    Ok(None)
}

/// Start a devcontainer for the given workspace folder
fn start_devcontainer(workspace_folder: &Path) -> Result<()> {
    tracing::info!("Starting devcontainer for {}", workspace_folder.display());

    let output = ProcessCommand::new("devcontainer")
        .args(["up", "--docker-path", "podman", "--workspace-folder"])
        .arg(workspace_folder)
        .output()
        .context("Failed to run devcontainer up")?;

    // devcontainer CLI outputs JSON to stderr, combine both streams
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let combined = format!("{}\n{}", stdout, stderr);

    tracing::debug!("devcontainer output: {}", combined);

    // Parse the JSON output to extract result
    if let Some(result) = parse_devcontainer_output(&combined) {
        if result.outcome == "success" {
            tracing::info!("Container started: {}", result.container_id);
        } else {
            bail!(
                "devcontainer up failed: {}",
                result
                    .message
                    .unwrap_or_else(|| "unknown error".to_string())
            );
        }
    } else if !output.status.success() {
        bail!("devcontainer up failed: {}", combined);
    } else {
        tracing::warn!("Could not parse devcontainer output, but command succeeded");
    }

    Ok(())
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct DevcontainerUpResult {
    outcome: String,
    #[serde(default)]
    container_id: String,
    message: Option<String>,
}

fn parse_devcontainer_output(output: &str) -> Option<DevcontainerUpResult> {
    // devcontainer outputs JSON, find the last line that looks like JSON
    for line in output.lines().rev() {
        if line.starts_with('{') {
            if let Ok(result) = serde_json::from_str(line) {
                return Some(result);
            }
        }
    }
    None
}

/// Enter a devcontainer shell
/// Find a container by name and return its workspace name
fn find_container_by_name(name: &str) -> Result<Option<String>> {
    let output = ProcessCommand::new("podman")
        .args([
            "ps",
            "-a",
            "--format",
            "json",
            "--filter",
            &format!("name=^{}$", name),
        ])
        .output()
        .context("Failed to run podman ps")?;

    if !output.status.success() {
        return Ok(None);
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let containers: Vec<PodmanContainer> = serde_json::from_str(&stdout).unwrap_or_default();

    if let Some(container) = containers.first() {
        // Get workspace name from label or derive from container name
        if let Some(ws_name) = container.labels.get("devc.workspace") {
            return Ok(Some(ws_name.clone()));
        }
        // Fall back to deriving from container name (devfile-{workspace}-{component})
        if let Some(rest) = name.strip_prefix("devfile-") {
            if let Some(idx) = rest.rfind('-') {
                return Ok(Some(rest[..idx].to_string()));
            }
        }
    }

    Ok(None)
}

/// Enter a pod-based workspace by workspace name
fn enter_pod_workspace(
    workspace_name: &str,
    requested_container: Option<&str>,
    no_tmux: bool,
    config: &config::Config,
) -> Result<()> {
    let pod_name_str = pod::pod_name(workspace_name);
    let containers = pod::list_pod_containers(&pod_name_str)?;

    if containers.is_empty() {
        bail!("No containers found in pod {}", pod_name_str);
    }

    tracing::info!(
        "Entering pod {} (workspace: {})",
        pod_name_str,
        workspace_name
    );

    // Get the sidecar command from config (if any)
    let sidecar_command = config.sidecar.command.as_ref().filter(|c| !c.is_empty());

    // If specific container is requested, enter it directly
    if let Some(requested) = requested_container {
        let full_container_name = if requested.starts_with("devc-") {
            requested.to_string()
        } else {
            pod::container_name(workspace_name, requested)
        };

        if !containers.contains(&full_container_name) {
            bail!(
                "Container '{}' not found in pod. Available: {}",
                requested,
                containers.join(", ")
            );
        }

        // Use sidecar command if this is the sidecar container
        let cmd: Vec<&str> = if full_container_name.ends_with("-sidecar") {
            sidecar_command
                .map(|c| c.iter().map(|s| s.as_str()).collect())
                .unwrap_or_else(|| vec!["/bin/bash", "-l"])
        } else {
            vec!["/bin/bash", "-l"]
        };

        let code = pod::exec_in_container(&full_container_name, &cmd, true)?;
        if code != 0 {
            std::process::exit(code);
        }
        return Ok(());
    }

    // Multi-container pod without specific container requested
    if containers.len() > 1 && !no_tmux {
        // Use tmux for multi-container access
        if tmux::tmux_available() {
            // Convert sidecar command to a space-joined string for tmux (which passes it to shell)
            // Note: This doesn't handle complex shell quoting. For commands with quoted args,
            // users should use a wrapper script or single-argument commands.
            let sidecar_cmd_str = sidecar_command
                .map(|c| c.join(" "))
                .unwrap_or_else(|| "/bin/bash -l".to_string());

            // Build pane configs with appropriate commands
            let panes: Vec<tmux::ContainerPane> = containers
                .iter()
                .map(|c| {
                    let cmd = if c.ends_with("-sidecar") {
                        sidecar_cmd_str.as_str()
                    } else {
                        "/bin/bash -l"
                    };
                    tmux::ContainerPane {
                        name: c.as_str(),
                        command: cmd,
                    }
                })
                .collect();

            let code = tmux::enter_multi_container(workspace_name, &panes)?;
            if code != 0 {
                std::process::exit(code);
            }
            return Ok(());
        } else {
            tracing::warn!(
                "tmux not available; entering first container. Use --container to select a specific container."
            );
        }
    }

    // Fall back to entering the first container
    if let Some(first_container) = containers.first() {
        let code = pod::exec_in_container(first_container, &["/bin/bash", "-l"], true)?;
        if code != 0 {
            std::process::exit(code);
        }
    }

    Ok(())
}

fn run_enter(
    worktree: Option<&str>,
    secret_args: &[String],
    container_name: Option<&str>,
    no_tmux: bool,
    config_path: Option<&Path>,
) -> Result<()> {
    let _secrets = parse_secrets(secret_args)?;
    let config = config::load_config_from(config_path)?;
    // Note: secrets are only applied when creating containers, not when entering existing ones

    // First, check if the argument is a container name (for volume-based workspaces)
    if let Some(name) = worktree {
        if let Some(workspace_name) = find_container_by_name(name)? {
            tracing::info!("Entering container {}", name);

            // Extract component name from container name
            let component_name = name
                .strip_prefix(&format!("devfile-{}-", workspace_name))
                .unwrap_or("dev");

            let code = devfile::exec_in_container(
                &workspace_name,
                component_name,
                &["/bin/bash", "-l"],
                true,
            )?;
            if code != 0 {
                std::process::exit(code);
            }
            return Ok(());
        }

        // Check if it's a pod name or workspace name for a volume-based workspace
        // This handles `devc enter devc-infra` or `devc enter infra` for volume workspaces
        let (pod_name_to_check, ws_name) = if name.starts_with("devc-") {
            (
                name.to_string(),
                name.strip_prefix("devc-").unwrap().to_string(),
            )
        } else {
            (pod::pod_name(name), name.to_string())
        };

        if pod::pod_exists(&pod_name_to_check)? {
            return enter_pod_workspace(&ws_name, container_name, no_tmux, &config);
        }
    }

    let workspace = match worktree {
        Some(name) => {
            // Check if it's an absolute path
            let path = Path::new(name);
            if path.is_absolute() && path.exists() {
                path.to_path_buf()
            } else {
                // Treat as worktree name
                let git_root = find_git_root()?;
                let worktrees_dir = get_worktrees_dir(&git_root)?;
                let worktree_path = worktrees_dir.join(name);
                if !worktree_path.exists() {
                    bail!("Worktree not found: {}", name);
                }
                worktree_path
            }
        }
        None => std::env::current_dir().context("Failed to get current directory")?,
    };

    let workspace_name = workspace
        .file_name()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| "workspace".to_string());

    tracing::info!("Entering container for {}", workspace.display());

    // Check if workspace is pod-based
    let is_pod = devfile::is_pod_based(&workspace_name)?;

    if is_pod {
        return enter_pod_workspace(&workspace_name, container_name, no_tmux, &config);
    } else {
        // Single container workspace (legacy behavior)
        match detect_dev_config(&workspace)? {
            Some(DevEnvConfig::Devfile(df)) => {
                let (component_name, _) = devfile::find_container_component(&df)
                    .context("No container component in devfile")?;
                let code = devfile::exec_in_container(
                    &workspace_name,
                    component_name,
                    &["/bin/bash", "-l"],
                    true,
                )?;
                if code != 0 {
                    std::process::exit(code);
                }
            }
            Some(DevEnvConfig::Devcontainer) => {
                let status = ProcessCommand::new("devcontainer")
                    .args(["exec", "--docker-path", "podman", "--workspace-folder"])
                    .arg(&workspace)
                    .args(["--", "/bin/bash", "-l"])
                    .stdin(Stdio::inherit())
                    .stdout(Stdio::inherit())
                    .stderr(Stdio::inherit())
                    .status()
                    .context("Failed to run devcontainer exec")?;

                if !status.success() {
                    bail!("devcontainer exec failed");
                }
            }
            None => {
                bail!(
                    "No devfile.yaml or .devcontainer directory found in {}",
                    workspace.display()
                );
            }
        }
    }

    Ok(())
}

/// Run a command in an ephemeral container
fn run_ephemeral(command: Vec<String>, enable_kvm: bool, secret_args: &[String]) -> Result<()> {
    let secrets = parse_secrets(secret_args)?;
    let workspace_path = std::env::current_dir().context("Failed to get current directory")?;

    // Ephemeral containers use bind mount
    let storage = workspace::StorageMode::BindMount {
        host_path: workspace_path.clone(),
    };

    let workspace_name = workspace_path
        .file_name()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| "workspace".to_string());

    let cmd_args: Vec<&str> = if command.is_empty() {
        vec!["/bin/bash", "-l"]
    } else {
        command.iter().map(|s| s.as_str()).collect()
    };

    match detect_dev_config(&workspace_path)? {
        Some(DevEnvConfig::Devfile(df)) => {
            let (component_name, _) = devfile::find_container_component(&df)
                .context("No container component in devfile")?;

            tracing::info!(
                "Starting ephemeral devfile container for {}",
                workspace_path.display()
            );
            devfile::start_devfile_container(
                &workspace_name,
                &storage,
                &df,
                true,
                enable_kvm,
                &secrets,
            )?;

            tracing::info!("Running command in container");
            let code =
                devfile::exec_in_container(&workspace_name, component_name, &cmd_args, true)?;

            tracing::info!("Removing ephemeral container");
            devfile::remove_devfile_container(&workspace_name, component_name)?;

            if code != 0 {
                std::process::exit(code);
            }
        }
        Some(DevEnvConfig::Devcontainer) => {
            tracing::info!(
                "Starting ephemeral devcontainer for {}",
                workspace_path.display()
            );
            start_devcontainer(&workspace_path)?;

            tracing::info!("Running command in container");
            let status = ProcessCommand::new("devcontainer")
                .args(["exec", "--docker-path", "podman", "--workspace-folder"])
                .arg(&workspace_path)
                .arg("--")
                .args(&cmd_args)
                .stdin(Stdio::inherit())
                .stdout(Stdio::inherit())
                .stderr(Stdio::inherit())
                .status()
                .context("Failed to run devcontainer exec")?;

            let exit_code = status.code().unwrap_or(1);

            tracing::info!("Removing ephemeral container");
            remove_container_for_workspace(&workspace_path)?;

            if !status.success() {
                std::process::exit(exit_code);
            }
        }
        None => {
            bail!(
                "No devfile.yaml or .devcontainer directory found in {}",
                workspace_path.display()
            );
        }
    }

    Ok(())
}

/// Remove a container for a given workspace folder
fn remove_container_for_workspace(workspace: &Path) -> Result<()> {
    let output = ProcessCommand::new("podman")
        .args([
            "ps",
            "-q",
            "--filter",
            &format!("label=devcontainer.local_folder={}", workspace.display()),
        ])
        .output()
        .context("Failed to run podman ps")?;

    let container_id = String::from_utf8_lossy(&output.stdout).trim().to_string();

    if !container_id.is_empty() {
        tracing::debug!("Removing container {}", container_id);
        let status = ProcessCommand::new("podman")
            .args(["rm", "-f", &container_id])
            .status()
            .context("Failed to remove container")?;

        if !status.success() {
            tracing::warn!("Failed to remove container {}", container_id);
        }
    }

    Ok(())
}

/// Well-known git hosting providers with short display names
const KNOWN_GIT_HOSTS: &[(&str, &str, &str)] = &[
    // (ssh_prefix, https_host, display_prefix)
    ("git@github.com:", "github.com", "github"),
    ("git@gitlab.com:", "gitlab.com", "gitlab"),
    ("git@codeberg.org:", "codeberg.org", "codeberg"),
];

/// Format a git remote URL for display.
///
/// - GitHub URLs become `github:owner/repo`
/// - GitLab URLs become `gitlab:owner/repo`
/// - Codeberg URLs become `codeberg:owner/repo`
/// - Other URLs are shown as-is
fn format_remote_url(url: &str) -> String {
    for (ssh_prefix, https_host, display_prefix) in KNOWN_GIT_HOSTS {
        // Handle git@host:owner/repo.git format
        if let Some(rest) = url.strip_prefix(ssh_prefix) {
            let repo = rest.trim_end_matches(".git");
            return format!("{}:{}", display_prefix, repo);
        }

        // Handle https://host/owner/repo.git format
        let https_prefix = format!("https://{}/", https_host);
        let http_prefix = format!("http://{}/", https_host);
        if let Some(rest) = url
            .strip_prefix(&https_prefix)
            .or_else(|| url.strip_prefix(&http_prefix))
        {
            let repo = rest.trim_end_matches(".git");
            return format!("{}:{}", display_prefix, repo);
        }
    }

    // Return full URL for other hosts
    url.to_string()
}

/// Format a timestamp into a human-readable "time ago" string
fn format_time_since(timestamp: &str) -> String {
    use chrono::{DateTime, Utc};

    let parsed = DateTime::parse_from_rfc3339(timestamp);
    if let Ok(created_time) = parsed {
        let now = Utc::now();
        let duration = now.signed_duration_since(created_time.with_timezone(&Utc));

        let seconds = duration.num_seconds();
        if seconds < 60 {
            format!("{}s ago", seconds)
        } else if seconds < 3600 {
            let minutes = seconds / 60;
            format!("{}m ago", minutes)
        } else if seconds < 86400 {
            let hours = seconds / 3600;
            format!("{}h ago", hours)
        } else if seconds < 604800 {
            let days = seconds / 86400;
            format!("{}d ago", days)
        } else if seconds < 2592000 {
            let weeks = seconds / 604800;
            format!("{}w ago", weeks)
        } else if seconds < 31536000 {
            let months = seconds / 2592000;
            format!("{}mo ago", months)
        } else {
            let years = seconds / 31536000;
            format!("{}y ago", years)
        }
    } else {
        "-".to_string()
    }
}

/// Workspace info for JSON output
#[derive(Debug, Serialize)]
struct WorkspaceInfo {
    name: String,
    status: String,
    running: bool,
    containers: usize,
    repository: String,
    branch: String,
    description: String,
    dirty: bool,
    source: String,
    created: String,
    since: String,
}

/// List active workspaces (pods)
fn run_list(json_output: bool) -> Result<()> {
    // Query pods with our marker label
    let output = ProcessCommand::new("podman")
        .args([
            "pod",
            "ps",
            "--format",
            "json",
            "--filter",
            &format!("label={}", consts::LABEL_MARKER),
        ])
        .output()
        .context("Failed to run podman pod ps")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("podman pod ps failed: {}", stderr);
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let pods: Vec<PodmanPod> = serde_json::from_str(&stdout).unwrap_or_default();

    // Collect workspace info
    let mut infos: Vec<WorkspaceInfo> = Vec::new();

    for pod_info in &pods {
        let pod_name = &pod_info.name;
        // Strip "devc-" prefix for display - users should use workspace names without prefix
        let workspace_name = pod_name.strip_prefix("devc-").unwrap_or(pod_name);
        let running = pod_info.status == "Running";
        let (status_text, _) = format_pod_status_colored(&pod_info.status);

        // Get volume info to find source metadata (volume name matches pod name)
        let (repository, branch, description) = get_volume_metadata(pod_name);

        // Count containers (excluding infra container)
        let container_count = pod_info.containers.len().saturating_sub(1);

        // Format time since creation
        let since = format_time_since(&pod_info.created);

        infos.push(WorkspaceInfo {
            name: workspace_name.to_string(),
            status: status_text,
            running,
            containers: container_count,
            repository,
            branch,
            description,
            dirty: false, // Can't easily check git status in volumes
            source: pod_name.clone(),
            created: pod_info.created.clone(),
            since,
        });
    }

    if json_output {
        println!("{}", serde_json::to_string_pretty(&infos)?);
        return Ok(());
    }

    if infos.is_empty() {
        println!("No workspaces found.");
        return Ok(());
    }

    use comfy_table::{Attribute, Cell, Color, ContentArrangement, Table};

    let mut table = Table::new();
    table.set_content_arrangement(ContentArrangement::Dynamic);
    table.load_preset(comfy_table::presets::NOTHING);

    // Header
    table.set_header(vec![
        Cell::new("NAME").add_attribute(Attribute::Bold),
        Cell::new("STATUS").add_attribute(Attribute::Bold),
        Cell::new("CONTAINERS").add_attribute(Attribute::Bold),
        Cell::new("REPOSITORY").add_attribute(Attribute::Bold),
        Cell::new("BRANCH").add_attribute(Attribute::Bold),
        Cell::new("DESCRIPTION").add_attribute(Attribute::Bold),
        Cell::new("SINCE").add_attribute(Attribute::Bold),
    ]);

    for info in &infos {
        let status_color = if info.running {
            Color::Green
        } else {
            Color::Yellow
        };

        table.add_row(vec![
            Cell::new(&info.name),
            Cell::new(&info.status).fg(status_color),
            Cell::new(info.containers),
            Cell::new(&info.repository),
            Cell::new(&info.branch),
            Cell::new(&info.description),
            Cell::new(&info.since),
        ]);
    }

    println!("{table}");
    Ok(())
}

/// Get repository, branch, and description metadata from a volume's labels
fn get_volume_metadata(volume_name: &str) -> (String, String, String) {
    let output = ProcessCommand::new("podman")
        .args(["volume", "inspect", volume_name, "--format", "json"])
        .output();

    if let Ok(output) = output {
        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            if let Ok(volumes) = serde_json::from_str::<Vec<serde_json::Value>>(&stdout) {
                if let Some(vol) = volumes.first() {
                    if let Some(labels) = vol.get("Labels").and_then(|l| l.as_object()) {
                        let source = labels
                            .get(consts::LABEL_KEY_SOURCE)
                            .and_then(|v| v.as_str())
                            .map(|s| format_remote_url(s))
                            .unwrap_or_else(|| "-".to_string());
                        let git_ref = labels
                            .get(consts::LABEL_KEY_REF)
                            .and_then(|v| v.as_str())
                            .unwrap_or("-")
                            .to_string();
                        let description = labels
                            .get(consts::LABEL_KEY_DESCRIPTION)
                            .and_then(|v| v.as_str())
                            .unwrap_or("-")
                            .to_string();
                        return (source, git_ref, description);
                    }
                }
            }
        }
    }

    ("-".to_string(), "-".to_string(), "-".to_string())
}

/// Format pod status to a shorter form with color
fn format_pod_status_colored(status: &str) -> (String, comfy_table::Color) {
    use comfy_table::Color;

    match status {
        "Running" => ("Running".to_string(), Color::Green),
        "Exited" => ("Exited".to_string(), Color::Yellow),
        "Created" => ("Created".to_string(), Color::Cyan),
        "Degraded" => ("Degraded".to_string(), Color::Red),
        _ => (status.to_string(), Color::Reset),
    }
}

#[derive(Debug, Deserialize)]
struct PodmanPod {
    #[serde(rename = "Name")]
    name: String,
    #[serde(rename = "Status")]
    status: String,
    #[serde(rename = "Containers")]
    containers: Vec<PodmanPodContainer>,
    #[serde(rename = "Created")]
    created: String,
}

#[derive(Debug, Deserialize)]
struct PodmanPodContainer {
    #[serde(rename = "Names")]
    #[allow(dead_code)]
    names: String,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct PodmanContainer {
    #[serde(rename = "Names")]
    names: Vec<String>,
    #[serde(rename = "Status")]
    status: String,
    #[serde(rename = "Labels")]
    labels: std::collections::HashMap<String, String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_github_issue_url() {
        // Valid GitHub issue URL
        let result = parse_github_issue_url("https://github.com/bootc-dev/bootc/issues/123");
        assert!(result.is_some());
        let (org, repo, issue_number) = result.unwrap();
        assert_eq!(org, "bootc-dev");
        assert_eq!(repo, "bootc");
        assert_eq!(issue_number, 123);

        // Another valid URL
        let result = parse_github_issue_url("https://github.com/rust-lang/rust/issues/456");
        assert!(result.is_some());
        let (org, repo, issue_number) = result.unwrap();
        assert_eq!(org, "rust-lang");
        assert_eq!(repo, "rust");
        assert_eq!(issue_number, 456);

        // HTTP should also work (gets redirected to HTTPS by GitHub)
        let result = parse_github_issue_url("http://github.com/bootc-dev/bootc/issues/789");
        assert!(result.is_some());
        let (org, repo, issue_number) = result.unwrap();
        assert_eq!(org, "bootc-dev");
        assert_eq!(repo, "bootc");
        assert_eq!(issue_number, 789);

        // Invalid URLs - wrong path structure
        assert!(parse_github_issue_url("https://github.com/bootc-dev/bootc").is_none());
        assert!(parse_github_issue_url("https://github.com/bootc-dev/bootc/pulls/123").is_none());
        assert!(parse_github_issue_url("https://github.com/bootc-dev/bootc/pull/123").is_none());

        // Invalid - wrong domain
        assert!(parse_github_issue_url("https://gitlab.com/org/repo/issues/123").is_none());
        assert!(parse_github_issue_url("https://bitbucket.org/org/repo/issues/123").is_none());

        // Invalid - not a URL at all
        assert!(parse_github_issue_url("not a url").is_none());
        assert!(parse_github_issue_url("").is_none());

        // Invalid - malformed issue number
        assert!(parse_github_issue_url("https://github.com/org/repo/issues/abc").is_none());
        assert!(parse_github_issue_url("https://github.com/org/repo/issues/").is_none());

        // Invalid - too many path segments
        assert!(parse_github_issue_url("https://github.com/org/repo/issues/123/extra").is_none());

        // Invalid - too few path segments
        assert!(parse_github_issue_url("https://github.com/org").is_none());
        assert!(parse_github_issue_url("https://github.com/").is_none());

        // Edge case - issue number 0 (technically invalid but we parse it)
        let result = parse_github_issue_url("https://github.com/org/repo/issues/0");
        assert!(result.is_some());
        let (_, _, issue_number) = result.unwrap();
        assert_eq!(issue_number, 0);

        // Edge case - very large issue number
        let result = parse_github_issue_url("https://github.com/org/repo/issues/999999");
        assert!(result.is_some());
        let (_, _, issue_number) = result.unwrap();
        assert_eq!(issue_number, 999999);
    }

    #[test]
    fn test_format_time_since() {
        use chrono::{Duration, Utc};

        // Test various time deltas
        let now = Utc::now();

        // 30 seconds ago
        let timestamp = (now - Duration::seconds(30)).to_rfc3339();
        let result = format_time_since(&timestamp);
        assert!(
            result.contains("30s ago") || result.contains("29s ago") || result.contains("31s ago")
        );

        // 5 minutes ago
        let timestamp = (now - Duration::minutes(5)).to_rfc3339();
        let result = format_time_since(&timestamp);
        assert!(result.contains("5m ago") || result.contains("4m ago"));

        // 2 hours ago
        let timestamp = (now - Duration::hours(2)).to_rfc3339();
        let result = format_time_since(&timestamp);
        assert!(result.contains("2h ago") || result.contains("1h ago"));

        // 3 days ago
        let timestamp = (now - Duration::days(3)).to_rfc3339();
        let result = format_time_since(&timestamp);
        assert!(result.contains("3d ago") || result.contains("2d ago"));
    }
}

/// Remove a devcontainer (and optionally its worktree)
fn run_rm(worktree: &str, remove_worktree: bool) -> Result<()> {
    // Normalize workspace name: strip "devc-" prefix if user included it
    let worktree = worktree.strip_prefix("devc-").unwrap_or(worktree);

    let git_root = find_git_root()?;
    let worktrees_dir = get_worktrees_dir(&git_root)?;
    let worktree_path = worktrees_dir.join(worktree);

    // Check if this workspace is a pod
    let pod_name_str = pod::pod_name(worktree);
    let is_pod = pod::pod_exists(&pod_name_str)?;

    if is_pod {
        // Remove pod (which removes all containers in it)
        pod::remove_pod(&pod_name_str)?;
    } else {
        // Legacy single container removal
        if worktree_path.exists() {
            tracing::info!("Stopping devcontainer for {}", worktree_path.display());

            // Find container by label
            let output = ProcessCommand::new("podman")
                .args([
                    "ps",
                    "-q",
                    "--filter",
                    &format!(
                        "label=devcontainer.local_folder={}",
                        worktree_path.display()
                    ),
                ])
                .output()
                .context("Failed to run podman ps")?;

            let container_id = String::from_utf8_lossy(&output.stdout).trim().to_string();

            if !container_id.is_empty() {
                tracing::info!("Removing container {}", container_id);

                let status = ProcessCommand::new("podman")
                    .args(["rm", "-f", &container_id])
                    .status()
                    .context("Failed to remove container")?;

                if !status.success() {
                    tracing::warn!("Failed to remove container {}", container_id);
                }
            } else {
                tracing::info!("No running container found for this worktree");
            }
        }
    }

    // Clean up tmux session if it exists
    if let Err(e) = tmux::kill_session(worktree) {
        tracing::debug!("Failed to kill tmux session: {}", e);
    }

    // Remove the git worktree if requested
    if remove_worktree {
        if worktree_path.exists() {
            tracing::info!("Removing git worktree {}", worktree);

            let status = ProcessCommand::new("git")
                .args(["worktree", "remove", "--force"])
                .arg(&worktree_path)
                .status()
                .context("Failed to run git worktree remove")?;

            if !status.success() {
                bail!("Failed to remove git worktree");
            }

            // Also delete the branch if it matches the worktree name
            let branch_status = ProcessCommand::new("git")
                .args(["branch", "-D", worktree])
                .status();

            match branch_status {
                Ok(s) if s.success() => tracing::info!("Deleted branch {}", worktree),
                _ => tracing::debug!(
                    "Branch {} not deleted (may not exist or is checked out elsewhere)",
                    worktree
                ),
            }

            tracing::info!("Worktree removed");
        } else {
            tracing::warn!("Worktree path does not exist: {}", worktree_path.display());
        }
    }

    Ok(())
}

/// Remove all devcontainers (and optionally their worktrees)
fn run_rm_all(skip_confirm: bool, remove_worktrees: bool) -> Result<()> {
    // Query pods with our marker label
    let output = ProcessCommand::new("podman")
        .args([
            "pod",
            "ps",
            "--format",
            "json",
            "--filter",
            &format!("label={}", consts::LABEL_MARKER),
        ])
        .output()
        .context("Failed to run podman pod ps")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("podman pod ps failed: {}", stderr);
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let pods: Vec<PodmanPod> = serde_json::from_str(&stdout).unwrap_or_default();

    if pods.is_empty() {
        println!("No workspaces found.");
        return Ok(());
    }

    // Extract workspace names from pod names (strip "devc-" prefix)
    let workspaces: Vec<&str> = pods
        .iter()
        .filter_map(|p| p.name.strip_prefix("devc-"))
        .collect();

    println!("Found {} workspace(s):", workspaces.len());
    for ws in &workspaces {
        println!("  - {}", ws);
    }

    if !skip_confirm {
        use std::io::{self, Write};

        print!("\nRemove all workspaces? [y/N] ");
        io::stdout().flush()?;

        let mut input = String::new();
        io::stdin().read_line(&mut input)?;

        if !input.trim().eq_ignore_ascii_case("y") {
            println!("Aborted.");
            return Ok(());
        }
    }

    // Remove each workspace
    for ws in workspaces {
        println!("Removing {}...", ws);
        if let Err(e) = run_rm(ws, remove_worktrees) {
            tracing::error!("Failed to remove {}: {}", ws, e);
        }
    }

    println!("Done.");
    Ok(())
}
