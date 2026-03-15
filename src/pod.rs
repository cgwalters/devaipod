//! Multi-container pod orchestration for devaipod
//!
//! This module manages a pod containing multiple containers:
//! - `workspace`: The user's development environment (from devcontainer.json)
//! - `agent`: Same image running `opencode serve` with restricted security
//! - `gator`: Optional service-gator MCP server container
//!
//! All containers share the same network namespace via the pod, allowing
//! localhost communication between the agent and workspace.

use std::path::{Path, PathBuf};

use color_eyre::eyre::{bail, Context, Result};

use crate::forge::PullRequestInfo;
use crate::git::{GitRepoInfo, RemoteRepoInfo, REMOTE_AGENT, REMOTE_WORKER, REMOTE_WORKSPACE};

/// Source for workspace content - local git repo, remote URL, or PR/MR
#[derive(Debug, Clone)]
pub enum WorkspaceSource {
    /// Local git repository
    LocalRepo(GitRepoInfo),
    /// Remote git repository (URL only)
    RemoteRepo(RemoteRepoInfo),
    /// Pull/Merge request from a forge
    PullRequest(PullRequestInfo),
}

impl WorkspaceSource {
    /// Get labels to attach to the pod
    pub fn to_labels(&self) -> Vec<(String, String)> {
        match self {
            WorkspaceSource::LocalRepo(git_info) => {
                let mut labels = vec![(
                    "io.devaipod.commit".to_string(),
                    git_info.commit_sha.clone(),
                )];
                if let Some(ref url) = git_info.remote_url {
                    // Extract host/owner/repo from URL
                    if let Some(repo) = extract_repo_from_url(url) {
                        labels.push(("io.devaipod.repo".to_string(), repo));
                    }
                }
                labels
            }
            WorkspaceSource::RemoteRepo(remote_info) => {
                let mut labels = Vec::new();
                if let Some(repo) = extract_repo_from_url(&remote_info.remote_url) {
                    labels.push(("io.devaipod.repo".to_string(), repo));
                }
                labels
            }
            WorkspaceSource::PullRequest(pr_info) => pr_info.to_labels(),
        }
    }

    /// Get the upstream repository URL (origin remote)
    pub fn upstream_url(&self) -> Option<String> {
        match self {
            WorkspaceSource::LocalRepo(git_info) => git_info.remote_url.clone(),
            WorkspaceSource::RemoteRepo(remote_info) => Some(remote_info.remote_url.clone()),
            WorkspaceSource::PullRequest(pr_info) => Some(pr_info.pr_ref.upstream_url()),
        }
    }

    /// Get the branch name for this workspace source.
    pub fn branch_name(&self) -> Option<String> {
        match self {
            WorkspaceSource::LocalRepo(git_info) => git_info.branch.clone(),
            WorkspaceSource::RemoteRepo(remote_info) => Some(remote_info.default_branch.clone()),
            WorkspaceSource::PullRequest(pr_info) => Some(pr_info.head_ref.clone()),
        }
    }

    /// Get a short description for logging
    pub fn description(&self) -> String {
        match self {
            WorkspaceSource::LocalRepo(git_info) => {
                format!(
                    "commit {}",
                    &git_info.commit_sha[..8.min(git_info.commit_sha.len())]
                )
            }
            WorkspaceSource::RemoteRepo(remote_info) => {
                format!("branch {}", remote_info.default_branch)
            }
            WorkspaceSource::PullRequest(pr_info) => {
                format!("PR #{}", pr_info.pr_ref.number)
            }
        }
    }

    /// Get the project name for workspace folder derivation
    ///
    /// For local repos, this comes from the path.
    /// For remote repos and PRs, this is the repository name.
    pub fn project_name(&self, fallback_path: &std::path::Path) -> String {
        match self {
            WorkspaceSource::LocalRepo(_) => fallback_path
                .file_name()
                .map(|s| s.to_string_lossy().to_string())
                .unwrap_or_else(|| "project".to_string()),
            WorkspaceSource::RemoteRepo(remote_info) => remote_info.repo_name.clone(),
            WorkspaceSource::PullRequest(pr_info) => pr_info.pr_ref.repo.clone(),
        }
    }
}

/// Extract host/owner/repo from a git URL
fn extract_repo_from_url(url: &str) -> Option<String> {
    // Handle SSH format: git@github.com:owner/repo.git
    if let Some(rest) = url.strip_prefix("git@") {
        let rest = rest.replace(':', "/");
        let rest = rest.trim_end_matches(".git");
        return Some(rest.to_string());
    }

    // Handle HTTPS format: https://github.com/owner/repo.git
    if let Ok(parsed) = url::Url::parse(url) {
        let host = parsed.host_str()?;
        let path = parsed
            .path()
            .trim_start_matches('/')
            .trim_end_matches(".git");
        return Some(format!("{}/{}", host, path));
    }

    None
}

/// Common device paths that should be auto-passed to development containers if they exist on the host.
///
/// These devices are commonly needed for:
/// - /dev/fuse: Overlay filesystems, podman/buildah operations, FUSE mounts
/// - /dev/net/tun: VPN tools, network tunneling, container networking
/// - /dev/kvm: Hardware virtualization for VM-based testing (e.g., bootc testing)
const DEV_PASSTHROUGH_PATHS: &[&str] = &["/dev/fuse", "/dev/net/tun", "/dev/kvm"];

use crate::config::{Config, DotfilesConfig, WorkerGatorMode};
use crate::devcontainer::DevcontainerConfig;
use crate::podman::{ContainerConfig, PodmanService};

/// Add devices from devcontainer runArgs (e.g. --device=/dev/kvm).
/// Only adds devices that exist on the host and aren't already in the list.
fn collect_config_devices(config: &DevcontainerConfig, devices: &mut Vec<String>) {
    for device_spec in config.device_args() {
        let path = device_spec.split(':').next().unwrap_or(&device_spec);
        if !path.is_empty() && Path::new(path).exists() && !devices.contains(&path.to_string()) {
            devices.push(path.to_string());
        }
    }
}

/// Return the minimal security settings for nested container support.
///
/// Returns `(privileged, cap_add, security_opts)` with the targeted set of
/// privileges needed for podman-in-podman without full `--privileged`.
/// Also adds `/dev/net/tun` to `devices` if it exists on the host.
fn nested_container_security(devices: &mut Vec<String>) -> (bool, Vec<String>, Vec<String>) {
    let tun = "/dev/net/tun".to_string();
    if Path::new(&tun).exists() && !devices.contains(&tun) {
        devices.push(tun);
    }
    (
        false,
        vec!["SYS_ADMIN".to_string(), "NET_ADMIN".to_string()],
        vec![
            "unmask=/proc/*".to_string(),
            "label=disable".to_string(),
            "seccomp=unconfined".to_string(),
        ],
    )
}

/// Port for the opencode server in the agent container
pub const OPENCODE_PORT: u16 = 4096;

/// Port for the per-pod devaipod API sidecar.
pub const POD_API_PORT: u16 = 8090;

/// Port for the worker's opencode server (internal, no auth)
pub const WORKER_OPENCODE_PORT: u16 = 4098;

/// Generate a random password for API authentication
///
/// Returns a 32-character hex string (128 bits of entropy)
fn generate_api_password() -> String {
    use rand::Rng;
    let mut rng = rand::rng();
    let bytes: [u8; 16] = rng.random();
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Path for the agent's home directory (mounted from a persistent volume).
/// This matches the "devenv" user's home in the devenv-debian image.
pub const AGENT_HOME_PATH: &str = "/home/devenv";

/// JSON state file written after agent setup (dotfiles, task config) is complete.
/// Lives on the container overlay so it survives stop/start but is absent
/// after a container rebuild (which re-runs the full setup flow).
const AGENT_STATE_PATH: &str = "/var/lib/devaipod-state.json";

/// Python script for worker control (send tasks, monitor, get status).
/// Replaces `opencode run --attach --format json` which returns excessive JSON.
const WORKER_CTL_SCRIPT: &str = include_str!("../scripts/devaipod-workerctl.py");

/// Default PATH for containers when we need to synthesize one.
/// This covers the standard locations where utilities are typically found.
const DEFAULT_CONTAINER_PATH: &str = "/usr/local/bin:/usr/bin:/bin";

/// Attempt to resolve environment variable values containing devcontainer variable syntax.
///
/// Devcontainer supports variable substitution like `${containerEnv:PATH}` which cannot be
/// fully resolved outside of VS Code. This function attempts partial resolution:
///
/// - For PATH patterns like `${containerEnv:PATH}:/additional/path`, prepends a default PATH
///   to the static suffix to ensure essential directories are included
/// - For other patterns like `${containerEnv:VAR}:/some/path`, extracts the static suffix
/// - Returns `None` if the value cannot be meaningfully resolved
///
/// Returns `Some(resolved_value)` if resolved, or `None` if the variable should be skipped.
fn resolve_env_value(value: &str, var_name: &str) -> Option<String> {
    if !value.contains("${") {
        return Some(value.to_string());
    }

    // For patterns like ${containerEnv:VAR}:/some/path, extract the static suffix
    // This preserves useful paths like /usr/local/cargo/bin from PATH extensions
    if let Some(idx) = value.find("}:") {
        let suffix = &value[idx + 2..];
        // Only use suffix if it's non-empty and doesn't contain more variable references
        if !suffix.is_empty() && !suffix.contains("${") {
            // Special handling for PATH: prepend a sensible default PATH to ensure
            // essential utilities (mkdir, chmod, grep, etc.) are available.
            // Without this, containers may fail to start because the PATH only
            // contains the extension (e.g., /usr/local/cargo/bin) without /usr/bin.
            if var_name == "PATH" {
                return Some(format!("{}:{}", DEFAULT_CONTAINER_PATH, suffix));
            }
            return Some(suffix.to_string());
        }
    }

    // Cannot resolve this value
    None
}

/// Port for the service-gator MCP server
pub const GATOR_PORT: u16 = 8765;

/// Image for the service-gator container
const GATOR_IMAGE: &str = "ghcr.io/cgwalters/service-gator:latest";

/// Fallback image for the devaipod API sidecar container.
// TODO: Derive this from the running control-plane container at runtime
// (see detect_own_container_image() in main.rs for the pattern).
const DEVAIPOD_IMAGE_FALLBACK: &str = "ghcr.io/cgwalters/devaipod:latest";

/// Detect the image ID (digest) of the running control plane container.
/// Returns None when not running inside a container.
pub(crate) async fn detect_self_image_id() -> Option<String> {
    if std::env::var("DEVAIPOD_CONTAINER").ok().as_deref() != Some("1") {
        return None;
    }
    let socket_path = crate::podman::get_container_socket().ok()?;
    let docker = bollard::Docker::connect_with_unix(
        &format!("unix://{}", socket_path.display()),
        120,
        bollard::API_DEFAULT_VERSION,
    )
    .ok()?;
    match docker.inspect_container("devaipod", None).await {
        Ok(info) => {
            let image_id = info.image;
            tracing::debug!("Detected self image ID: {:?}", image_id);
            image_id
        }
        Err(e) => {
            tracing::warn!("Failed to detect self image ID: {e}");
            None
        }
    }
}

/// Detect the image of the running devaipod control-plane container.
///
/// Returns the image name if we can detect it, otherwise falls back to
/// `DEVAIPOD_IMAGE_FALLBACK`.
fn detect_self_image() -> String {
    // Explicit override — used by integration tests to point at the
    // locally-built image instead of the published registry image.
    if let Ok(image) = std::env::var("DEVAIPOD_CONTAINER_IMAGE") {
        tracing::debug!("Using image from DEVAIPOD_CONTAINER_IMAGE: {image}");
        return image;
    }

    // Only attempt detection when running inside the devaipod container
    if std::env::var("DEVAIPOD_CONTAINER").as_deref() == Ok("1") {
        let mut cmd = std::process::Command::new("podman");
        // Use the correct socket path so podman-remote can reach the host daemon.
        if let Ok(socket) = crate::podman::get_container_socket() {
            cmd.args(["--url", &format!("unix://{}", socket.display())]);
        }
        cmd.args(["inspect", "devaipod", "--format", "{{.ImageName}}"]);
        if let Ok(output) = cmd.output() {
            if output.status.success() {
                let image = String::from_utf8_lossy(&output.stdout).trim().to_string();
                if !image.is_empty() {
                    tracing::debug!("Detected devaipod self-image: {image}");
                    return image;
                }
            }
        }
        tracing::debug!(
            "Could not detect own container image, falling back to {}",
            DEVAIPOD_IMAGE_FALLBACK
        );
    }
    DEVAIPOD_IMAGE_FALLBACK.to_string()
}

/// Label name for storing the current service-gator scopes as JSON
/// Used for backwards compatibility with pre-inotify pods
pub const GATOR_SCOPES_LABEL: &str = "io.devaipod.gator-scopes";

/// Configuration for bind_home mounts passed to container config functions
#[derive(Debug, Clone, Default)]
pub struct BindHomeConfig {
    /// Paths to bind (relative to $HOME)
    pub paths: Vec<String>,
    /// Whether mounts should be read-only (used for agent container mounts)
    #[allow(dead_code)] // Will be used when implementing readonly bind mounts
    pub readonly: bool,
}

/// Get the host home directory
fn get_host_home() -> Option<PathBuf> {
    std::env::var("HOME").ok().map(PathBuf::from)
}

/// A devaipod pod managing multiple containers
#[derive(Debug, Clone)]
pub struct DevaipodPod {
    /// Name of the pod
    pub pod_name: String,
    /// Name of the workspace container
    pub workspace_container: String,
    /// Name of the agent container (task owner in orchestration mode)
    pub agent_container: String,
    /// Name of the gator container (if enabled)
    #[allow(dead_code)] // Stored for future container management
    pub gator_container: Option<String>,
    /// Name of the API sidecar container
    #[allow(dead_code)] // Stored for future container management
    pub api_container: Option<String>,
    /// Name of the worker container (if orchestration enabled)
    #[allow(dead_code)] // Stored for future container management
    pub worker_container: Option<String>,
    /// The image used for workspace and agent containers
    #[allow(dead_code)] // Stored for reference, used in operations
    pub image: String,
    /// Workspace folder inside the container
    pub workspace_folder: String,
    /// Bind home config for workspace container
    pub workspace_bind_home: BindHomeConfig,
    /// Bind home config for agent container
    pub agent_bind_home: BindHomeConfig,
    /// Container home directory path
    pub container_home: String,
    /// Task to run (if this is a 'run' mode pod)
    pub task: Option<String>,
    /// Whether service-gator is enabled
    pub enable_gator: bool,
    /// Whether orchestration mode is enabled
    pub enable_orchestration: bool,
    /// Upstream repository URL (for prompt context)
    pub repo_url: Option<String>,
    /// Git branch name in the workspace
    pub branch: Option<String>,
    /// Whether forwardPorts were configured in devcontainer.json
    pub has_forwarded_ports: bool,
}

impl DevaipodPod {
    /// Create a new pod with all containers
    ///
    /// This will:
    /// 1. Build or pull the image from devcontainer config
    /// 2. Create and initialize the workspace volume (clone git repo or PR)
    /// 3. Create the pod with metadata labels
    /// 4. Create workspace, agent, and optionally gator/proxy containers
    ///
    /// Note: Dotfiles installation happens after the pod starts via `install_dotfiles()`.
    ///
    /// The `service_gator_config` parameter should be the merged config from file + CLI.
    /// If None, uses the config from `global_config.service_gator`.
    ///
    /// The `image_override` parameter allows specifying a pre-built image to use instead
    /// of building from devcontainer.json. This is useful for testing locally-built images.
    ///
    /// The `gator_image_override` parameter allows specifying a custom service-gator image
    /// instead of the default. This is useful for testing locally-built service-gator images.
    ///
    /// The `enable_orchestration` parameter enables multi-agent orchestration mode.
    /// When true, a worker container is created in addition to the task owner (agent).
    ///
    /// The `worker_gator_mode` parameter controls how the worker accesses service-gator:
    /// - `Readonly`: Worker can only read from forge (default)
    /// - `Inherit`: Worker gets same scopes as task owner
    /// - `None`: Worker has no gator access
    #[allow(clippy::too_many_arguments)]
    pub async fn create(
        podman: &PodmanService,
        project_path: &Path,
        devcontainer_config: &DevcontainerConfig,
        pod_name: &str,
        enable_gator: bool,
        global_config: &Config,
        source: &WorkspaceSource,
        extra_labels: &[(String, String)],
        service_gator_config: Option<&crate::config::ServiceGatorConfig>,
        image_override: Option<&str>,
        gator_image_override: Option<&str>,
        task: Option<&str>,
        enable_orchestration: bool,
        worker_gator_mode: WorkerGatorMode,
    ) -> Result<Self> {
        // Note: container_home is resolved after we determine the image, since
        // we need to query the image for the user if devcontainer doesn't specify one

        // Build workspace bind_home: global bind_home + workspace-specific
        let mut workspace_paths = global_config.bind_home.paths.clone();
        if let Some(ref ws_config) = global_config.bind_home_workspace {
            workspace_paths.extend(ws_config.paths.clone());
        }
        let workspace_bind_home = BindHomeConfig {
            paths: workspace_paths,
            readonly: false, // Workspace gets read-write access
        };

        // Agent bind_home: uses the same global bind_home paths (always read-only for security)
        let agent_bind_home = BindHomeConfig {
            paths: global_config.bind_home.paths.clone(),
            readonly: true, // Agent always gets read-only access for security
        };

        let config = devcontainer_config;

        // Derive project name from source (for PRs, use repo name; for local, use path)
        let project_name = source.project_name(project_path);

        // Get workspace folder
        let workspace_folder = config.workspace_folder_for_project(&project_name);

        // Determine image - use override if provided, otherwise build/pull from devcontainer.json
        let image = if let Some(override_image) = image_override {
            tracing::info!("Using image override: {}", override_image);
            override_image.to_string()
        } else {
            // Find devcontainer.json directory for resolving relative paths in build config
            let devcontainer_json = crate::devcontainer::find_devcontainer_json(project_path)?;
            let devcontainer_dir = devcontainer_json.parent().unwrap_or(project_path);

            let image_source = config.image_source(devcontainer_dir)?;
            let image_tag = format!("devaipod-{}", pod_name);
            podman
                .ensure_image(
                    &image_source,
                    &image_tag,
                    config.has_features(),
                    Some(project_path),
                )
                .await
                .context("Failed to ensure container image")?
        };

        // Display detailed image info (name, creation time, digest)
        match podman.get_image_info(&image).await {
            Ok(info) => {
                tracing::info!("Using image: {}", info);
            }
            Err(e) => {
                tracing::debug!("Could not get image details: {}", e);
                tracing::info!("Using image: {}", image);
            }
        }

        // Determine effective user: prefer devcontainer config, fall back to image config
        // This is used for chown in clone, container_home resolution, and running commands
        let effective_user = if let Some(user) = devcontainer_config.effective_user() {
            Some(user.to_string())
        } else {
            podman.get_image_user(&image).await.unwrap_or(None)
        };

        // Resolve container home based on effective user
        let container_home = Self::resolve_container_home_for_user(effective_user.as_deref());

        // Create workspace volume and clone repo into it
        let volume_name = format!("{}-workspace", pod_name);
        let volume_already_exists = podman.volume_exists(&volume_name).await?;

        if !volume_already_exists {
            tracing::debug!(
                "Creating workspace volume and cloning {}...",
                source.description()
            );
            podman
                .create_volume(&volume_name)
                .await
                .context("Failed to create workspace volume")?;

            // Clone the repository into the volume using an init container
            // For local repos, we mount the .git directory and clone from there
            // This allows working with unpushed commits
            let (clone_script, extra_binds) = match source {
                WorkspaceSource::LocalRepo(git_info) => {
                    let script = crate::git::clone_from_local_script(
                        git_info,
                        &workspace_folder,
                        effective_user.as_deref(),
                    );
                    // Mount the local .git directory read-only
                    let git_dir = git_info.local_path.join(".git");
                    let bind = format!("{}:/mnt/host-git:ro", git_dir.display());
                    (script, vec![bind])
                }
                WorkspaceSource::RemoteRepo(remote_info) => {
                    // Use GH_TOKEN for cloning private repos if available
                    // Check env vars first, then podman secrets from config
                    let gh_token = crate::git::get_github_token_with_secret(global_config);
                    let script = crate::git::clone_remote_script(
                        remote_info,
                        &workspace_folder,
                        effective_user.as_deref(),
                        gh_token.as_deref(),
                    );
                    (script, vec![])
                }
                WorkspaceSource::PullRequest(pr_info) => {
                    // Use GH_TOKEN for cloning private repos if available
                    // Check env vars first, then podman secrets from config
                    let gh_token = crate::git::get_github_token_with_secret(global_config);
                    let script = crate::git::clone_pr_script(
                        pr_info,
                        &workspace_folder,
                        gh_token.as_deref(),
                    );
                    (script, vec![])
                }
            };

            let exit_code = podman
                .run_init_container(
                    &image,
                    &volume_name,
                    "/workspaces",
                    &["/bin/sh", "-c", &clone_script],
                    &extra_binds,
                )
                .await
                .context("Failed to run init container for git clone")?;

            if exit_code != 0 {
                // Clean up the volume on failure
                let _ = podman.remove_volume(&volume_name, true).await;
                color_eyre::eyre::bail!(
                    "Failed to clone into workspace volume (exit code {})",
                    exit_code
                );
            }
            tracing::debug!("Cloned {}", source.description());
        } else {
            tracing::debug!("Using existing workspace volume '{}'", volume_name);
        }

        // Create the pod with metadata labels
        let mut labels = source.to_labels();
        labels.extend(extra_labels.iter().cloned());

        // Record which version of devaipod created this pod
        labels.push((
            "io.devaipod.version".to_string(),
            env!("CARGO_PKG_VERSION").to_string(),
        ));

        // Add service-gator config as a label (CLI args format)
        if let Some(sg_config) = service_gator_config {
            if sg_config.is_enabled() {
                let cli_args = crate::service_gator::config_to_cli_args(sg_config);
                labels.push(("io.devaipod.service-gator".to_string(), cli_args.join(" ")));
            }
        }

        // Generate random password for opencode API authentication
        // This enables secure host-to-container API access
        let api_password = generate_api_password();
        labels.push(("io.devaipod.api-password".to_string(), api_password.clone()));

        // Publish the pod-api port to a random host port.  We use 0.0.0.0 so the
        // devaipod control-plane container can reach it via host.containers.internal.
        // The opencode server port (4096) is NOT published — the pod-api sidecar
        // proxies to it internally via localhost within the pod network namespace.
        let mut publish_ports = vec![format!("0.0.0.0::{}", POD_API_PORT)];

        // Publish ports declared in devcontainer.json forwardPorts.
        // These are published at pod creation time so they're available immediately.
        // All containers in the pod share the network namespace, so forwards work
        // regardless of which container is listening.
        let forwarded = config.publish_port_specs();
        let has_forwarded_ports = !forwarded.is_empty();
        if has_forwarded_ports {
            tracing::info!(
                "Publishing {} forwarded port(s) from devcontainer.json",
                forwarded.len()
            );
            publish_ports.extend(forwarded);
        }

        podman
            .create_pod(pod_name, &labels, &publish_ports)
            .await
            .context("Failed to create pod")?;

        // Container names
        let workspace_container = format!("{}-workspace", pod_name);
        let agent_container = format!("{}-agent", pod_name);
        let gator_container_name = format!("{}-gator", pod_name);

        // Create agent home volume for persistent agent state (credentials, config, etc.)
        let agent_home_volume = format!("{}-agent-home", pod_name);
        if !podman.volume_exists(&agent_home_volume).await? {
            podman
                .create_volume(&agent_home_volume)
                .await
                .context("Failed to create agent home volume")?;
            tracing::debug!("Created agent home volume '{}'", agent_home_volume);
        } else {
            tracing::debug!("Using existing agent home volume '{}'", agent_home_volume);
        }

        // Create agent workspace volume for isolated agent git clone
        // This allows the agent to have its own workspace using git --reference
        // to share objects with the main workspace clone.
        let agent_workspace_volume = format!("{}-agent-workspace", pod_name);
        let agent_workspace_exists = podman.volume_exists(&agent_workspace_volume).await?;
        if !agent_workspace_exists {
            podman
                .create_volume(&agent_workspace_volume)
                .await
                .context("Failed to create agent workspace volume")?;
            tracing::debug!(
                "Created agent workspace volume '{}'",
                agent_workspace_volume
            );
        } else {
            tracing::debug!(
                "Using existing agent workspace volume '{}'",
                agent_workspace_volume
            );
        }

        // Clone into agent workspace using --shared to share objects with main workspace
        if !agent_workspace_exists {
            // The main workspace volume is mounted at /mnt/main-workspace, and inside it
            // the repo is at the same relative path as workspace_folder (e.g., /workspaces/test-repo
            // becomes /mnt/main-workspace/test-repo).
            let project_name = workspace_folder
                .strip_prefix("/workspaces/")
                .unwrap_or(&workspace_folder);
            let reference_repo_path = format!("/mnt/main-workspace/{}", project_name);

            let clone_script = match source {
                WorkspaceSource::LocalRepo(git_info) => crate::git::clone_agent_workspace_script(
                    &workspace_folder,
                    &reference_repo_path,
                    git_info,
                    effective_user.as_deref(),
                ),
                WorkspaceSource::RemoteRepo(remote_info) => {
                    // Create a GitRepoInfo from the remote info for clone_agent_workspace_script
                    let git_info = crate::git::GitRepoInfo {
                        local_path: std::path::PathBuf::from(&reference_repo_path),
                        remote_url: Some(remote_info.remote_url.clone()),
                        commit_sha: "HEAD".to_string(), // Will checkout HEAD of default branch
                        branch: Some(remote_info.default_branch.clone()),
                        is_dirty: false,
                        dirty_files: vec![],
                        fork_url: remote_info.fork_url.clone(),
                    };
                    crate::git::clone_agent_workspace_script(
                        &workspace_folder,
                        &reference_repo_path,
                        &git_info,
                        effective_user.as_deref(),
                    )
                }
                WorkspaceSource::PullRequest(pr_info) => {
                    // Origin should always point to the upstream repo (where PRs merge to).
                    // If the PR is from a fork, add the fork as a separate remote.
                    let upstream_url = pr_info.pr_ref.upstream_url();
                    let fork_url = if pr_info.head_clone_url != upstream_url {
                        Some(pr_info.head_clone_url.clone())
                    } else {
                        None
                    };
                    let git_info = crate::git::GitRepoInfo {
                        local_path: std::path::PathBuf::from(&reference_repo_path),
                        remote_url: Some(upstream_url),
                        commit_sha: pr_info.head_sha.clone(),
                        branch: Some(pr_info.head_ref.clone()),
                        is_dirty: false,
                        dirty_files: vec![],
                        fork_url,
                    };
                    crate::git::clone_agent_workspace_script(
                        &workspace_folder,
                        &reference_repo_path,
                        &git_info,
                        effective_user.as_deref(),
                    )
                }
            };

            // Mount main workspace volume read-only as reference for git --reference clone
            let extra_binds = vec![format!("{}:/mnt/main-workspace:ro", volume_name)];

            tracing::debug!("Cloning agent workspace with reference to main workspace...");
            let exit_code = podman
                .run_init_container(
                    &image,
                    &agent_workspace_volume,
                    "/workspaces",
                    &["/bin/sh", "-c", &clone_script],
                    &extra_binds,
                )
                .await
                .context("Failed to run init container for agent workspace clone")?;

            if exit_code != 0 {
                // Clean up the volume on failure
                let _ = podman.remove_volume(&agent_workspace_volume, true).await;
                bail!(
                    "Failed to clone into agent workspace volume (exit code {})",
                    exit_code
                );
            }
            tracing::debug!("Agent workspace cloned successfully");
        }

        // Write scripts to agent home volume (workerctl for orchestration)
        Self::write_scripts_to_volume(podman, &image, &agent_home_volume).await?;

        // Write gator config to workspace volume (if gator is enabled)
        // Gator watches this file via inotify for live scope updates
        if enable_gator {
            let sg_config = service_gator_config.unwrap_or(&global_config.service_gator);
            let jwt_scopes = crate::service_gator::config_to_jwt_scopes(sg_config);
            Self::write_gator_config_to_volume(
                podman,
                &image,
                &agent_workspace_volume,
                &jwt_scopes,
            )
            .await?;
        }

        // Clone dotfiles to agent home volume if configured
        // This happens before containers start, with GH_TOKEN available for private repos
        if let Some(ref dotfiles) = global_config.dotfiles {
            Self::clone_dotfiles_to_volume(
                podman,
                &image,
                &agent_home_volume,
                dotfiles,
                global_config,
            )
            .await?;
        }

        // Create workspace container
        let workspace_config = Self::workspace_container_config(
            project_path,
            &workspace_folder,
            effective_user.as_deref(),
            config,
            &workspace_bind_home,
            &container_home,
            &volume_name,
            &agent_home_volume,
            &agent_workspace_volume,
            global_config,
            &labels,
        );
        podman
            .create_container(&workspace_container, &image, pod_name, workspace_config)
            .await
            .with_context(|| {
                format!(
                    "Failed to create workspace container: {}",
                    workspace_container
                )
            })?;

        // Note: Task is written to the agent home volume after dotfiles installation
        // in finalize_pod() via write_task_to_volume(). This ensures user dotfiles
        // don't overwrite the task config.

        // Create agent container with restricted security
        // Agent gets its own workspace clone and read-only access to main workspace
        // If orchestration is enabled, also mount worker workspace for git access
        //
        // IMPORTANT: We must create the worker volumes BEFORE creating the agent container,
        // because the agent container config includes a mount to the worker workspace volume.
        // If we don't create the volume first, Podman will auto-create an empty volume,
        // and when we later check volume_exists() it will return true, skipping the clone.
        let (worker_workspace_volume_name, worker_home_volume_name) = if enable_orchestration {
            // Create worker home volume for persistent worker state (separate from agent home)
            let worker_home_volume = format!("{}-worker-home", pod_name);
            if !podman.volume_exists(&worker_home_volume).await? {
                podman
                    .create_volume(&worker_home_volume)
                    .await
                    .context("Failed to create worker home volume")?;
                tracing::debug!("Created worker home volume '{}'", worker_home_volume);
            } else {
                tracing::debug!("Using existing worker home volume '{}'", worker_home_volume);
            }

            // Create worker workspace volume for isolated worker git clone
            let worker_workspace_volume = format!("{}-worker-workspace", pod_name);
            let worker_workspace_exists = podman.volume_exists(&worker_workspace_volume).await?;
            if !worker_workspace_exists {
                podman
                    .create_volume(&worker_workspace_volume)
                    .await
                    .context("Failed to create worker workspace volume")?;
                tracing::debug!(
                    "Created worker workspace volume '{}'",
                    worker_workspace_volume
                );
            } else {
                tracing::debug!(
                    "Using existing worker workspace volume '{}'",
                    worker_workspace_volume
                );
            }

            // Clone into worker workspace using --shared to share objects with task owner workspace
            if !worker_workspace_exists {
                // Worker references the task owner's workspace (agent_workspace_volume).
                // Agent volume was mounted at /workspaces when cloned, so repo is at volume_root/project_name.
                let project_name = workspace_folder
                    .strip_prefix("/workspaces/")
                    .unwrap_or(&workspace_folder);
                let reference_repo_path = format!("/mnt/owner-workspace/{}", project_name);

                let clone_script = match source {
                    WorkspaceSource::LocalRepo(git_info) => {
                        crate::git::clone_worker_workspace_script(
                            &workspace_folder,
                            &reference_repo_path,
                            git_info,
                            effective_user.as_deref(),
                        )
                    }
                    WorkspaceSource::RemoteRepo(remote_info) => {
                        let git_info = crate::git::GitRepoInfo {
                            local_path: std::path::PathBuf::from(&reference_repo_path),
                            remote_url: Some(remote_info.remote_url.clone()),
                            commit_sha: "HEAD".to_string(),
                            branch: Some(remote_info.default_branch.clone()),
                            is_dirty: false,
                            dirty_files: vec![],
                            fork_url: remote_info.fork_url.clone(),
                        };
                        crate::git::clone_worker_workspace_script(
                            &workspace_folder,
                            &reference_repo_path,
                            &git_info,
                            effective_user.as_deref(),
                        )
                    }
                    WorkspaceSource::PullRequest(pr_info) => {
                        let upstream_url = pr_info.pr_ref.upstream_url();
                        let fork_url = if pr_info.head_clone_url != upstream_url {
                            Some(pr_info.head_clone_url.clone())
                        } else {
                            None
                        };
                        let git_info = crate::git::GitRepoInfo {
                            local_path: std::path::PathBuf::from(&reference_repo_path),
                            remote_url: Some(upstream_url),
                            commit_sha: pr_info.head_sha.clone(),
                            branch: Some(pr_info.head_ref.clone()),
                            is_dirty: false,
                            dirty_files: vec![],
                            fork_url,
                        };
                        crate::git::clone_worker_workspace_script(
                            &workspace_folder,
                            &reference_repo_path,
                            &git_info,
                            effective_user.as_deref(),
                        )
                    }
                };

                // Mount task owner's workspace (agent_workspace_volume) as reference for git --shared clone
                // Also mount main workspace for git alternates chain
                let extra_binds = vec![
                    format!("{}:/mnt/owner-workspace:ro", agent_workspace_volume),
                    format!("{}:/mnt/main-workspace:ro", volume_name),
                ];

                tracing::debug!(
                    "Cloning worker workspace with reference to task owner workspace..."
                );
                let exit_code = podman
                    .run_init_container(
                        &image,
                        &worker_workspace_volume,
                        "/workspaces",
                        &["/bin/sh", "-c", &clone_script],
                        &extra_binds,
                    )
                    .await
                    .context("Failed to run init container for worker workspace clone")?;

                if exit_code != 0 {
                    let _ = podman.remove_volume(&worker_workspace_volume, true).await;
                    bail!(
                        "Failed to clone into worker workspace volume (exit code {})",
                        exit_code
                    );
                }
                tracing::debug!("Worker workspace cloned successfully");
            }

            (Some(worker_workspace_volume), Some(worker_home_volume))
        } else {
            (None, None)
        };

        let agent_config = Self::agent_container_config(
            project_path,
            &workspace_folder,
            &agent_bind_home,
            &container_home,
            Some(devcontainer_config),
            enable_gator,
            enable_orchestration,
            &volume_name,            // main workspace (read-only reference mount)
            &agent_workspace_volume, // agent's own workspace clone
            &agent_home_volume,
            worker_workspace_volume_name.as_deref(),
            global_config,
        );
        podman
            .create_container(&agent_container, &image, pod_name, agent_config)
            .await
            .with_context(|| format!("Failed to create agent container: {}", agent_container))?;

        // Create gator container if enabled
        let gator_container = if enable_gator {
            // Use override image if provided, otherwise use default
            let gator_image = gator_image_override.unwrap_or(GATOR_IMAGE);

            // Ensure gator image exists (check locally first, then pull if needed)
            podman
                .ensure_gator_image(gator_image)
                .await
                .context("Failed to ensure service-gator image")?;

            // Display detailed gator image info (name, creation time, digest)
            match podman.get_image_info(gator_image).await {
                Ok(info) => {
                    tracing::info!("Using service-gator image: {}", info);
                }
                Err(e) => {
                    tracing::debug!("Could not get service-gator image details: {}", e);
                    tracing::info!("Using service-gator image: {}", gator_image);
                }
            }

            // Mount the AGENT workspace volume where the agent's commits are, plus
            // the main workspace volume at /mnt/main-workspace because the agent's
            // git clone uses alternates pointing there for object sharing.
            // Gator reads the scope config file from the workspace volume.
            let gator_config = Self::gator_container_config(
                &agent_workspace_volume,
                "/workspaces",
                &volume_name,
                global_config,
            );
            podman
                .create_container(&gator_container_name, gator_image, pod_name, gator_config)
                .await
                .with_context(|| {
                    format!("Failed to create gator container: {}", gator_container_name)
                })?;

            Some(gator_container_name)
        } else {
            None
        };

        // Create API sidecar container (devaipod pod-api)
        let api_container_name = format!("{}-api", pod_name);
        let self_image = detect_self_image();
        let socket_path = crate::podman::get_host_socket_path()
            .context("Cannot create API sidecar without container socket")?;
        let api_config = Self::api_container_config(
            &agent_workspace_volume,
            &volume_name,
            &workspace_container,
            &agent_container,
            &socket_path,
            &api_password,
            &workspace_folder,
        );
        podman
            .create_container(&api_container_name, &self_image, pod_name, api_config)
            .await
            .with_context(|| {
                format!(
                    "Failed to create API sidecar container: {}",
                    api_container_name
                )
            })?;
        let api_container = Some(api_container_name);

        // Create worker container if orchestration is enabled
        // Note: Worker volumes were already created and cloned above (before agent container creation)
        // to avoid Podman auto-creating empty volumes when the agent container is created.
        let worker_container = if let (Some(worker_workspace_volume), Some(worker_home_volume)) =
            (&worker_workspace_volume_name, &worker_home_volume_name)
        {
            let worker_container_name = format!("{}-worker", pod_name);

            // Create worker container using the volumes created earlier
            let worker_config = Self::worker_container_config(
                project_path,
                &workspace_folder,
                &agent_bind_home,
                &container_home,
                Some(devcontainer_config),
                enable_gator,
                worker_gator_mode,
                &volume_name,            // main workspace (read-only)
                &agent_workspace_volume, // task owner workspace (read-only)
                worker_workspace_volume, // worker's own workspace
                worker_home_volume,      // worker's own home volume (read-write)
                &agent_home_volume,      // agent's home for LLM credentials (read-only)
                global_config,
            );
            podman
                .create_container(&worker_container_name, &image, pod_name, worker_config)
                .await
                .with_context(|| {
                    format!(
                        "Failed to create worker container: {}",
                        worker_container_name
                    )
                })?;

            tracing::debug!("Created worker container '{}'", worker_container_name);
            Some(worker_container_name)
        } else {
            None
        };

        let container_count = 2
            + if gator_container.is_some() { 1 } else { 0 }
            + if api_container.is_some() { 1 } else { 0 }
            + if worker_container.is_some() { 1 } else { 0 };
        tracing::debug!(
            "Created pod '{}' with {} containers",
            pod_name,
            container_count
        );

        Ok(Self {
            pod_name: pod_name.to_string(),
            workspace_container,
            agent_container,
            gator_container,
            api_container,
            worker_container,
            image,
            workspace_folder,
            workspace_bind_home,
            agent_bind_home,
            container_home,
            task: task.map(|s| s.to_string()),
            enable_gator,
            enable_orchestration,
            repo_url: source.upstream_url(),
            branch: source.branch_name(),
            has_forwarded_ports,
        })
    }

    /// Start the pod (starts all containers)
    pub async fn start(&self, podman: &PodmanService) -> Result<()> {
        podman
            .start_pod(&self.pod_name)
            .await
            .with_context(|| format!("Failed to start pod: {}", self.pod_name))?;

        tracing::debug!("Started pod '{}'", self.pod_name);

        if self.has_forwarded_ports {
            let short_name = self
                .pod_name
                .strip_prefix("devaipod-")
                .unwrap_or(&self.pod_name);
            tracing::info!(
                "Forwarded ports configured — run `devaipod status {}` to see host port mappings",
                short_name
            );
        }

        Ok(())
    }

    /// Install dotfiles in the workspace container
    ///
    /// This should be called after the pod starts but BEFORE lifecycle commands,
    /// so that bashrc, gitconfig, and other dotfiles are available for lifecycle scripts.
    pub async fn install_dotfiles(
        &self,
        podman: &PodmanService,
        dotfiles: &DotfilesConfig,
        user: Option<&str>,
    ) -> Result<()> {
        self.install_dotfiles_in_container(
            podman,
            dotfiles,
            &self.workspace_container,
            user,
            None, // use container's HOME
        )
        .await
    }

    /// Install dotfiles in the agent container
    ///
    /// This ensures .gitconfig and other dotfiles are available for git operations.
    pub async fn install_dotfiles_agent(
        &self,
        podman: &PodmanService,
        dotfiles: &DotfilesConfig,
    ) -> Result<()> {
        self.install_dotfiles_in_container(
            podman,
            dotfiles,
            &self.agent_container,
            None,
            Some(AGENT_HOME_PATH), // agent uses explicit HOME
        )
        .await
    }

    /// Install dotfiles in a container
    ///
    /// The dotfiles repo is already cloned to the agent home volume during pod creation.
    /// This method runs the install script from that pre-cloned repo.
    ///
    /// Default install behavior (if no script specified):
    /// 1. If `install.sh` exists, run it
    /// 2. Else if `install-dotfiles.sh` exists, run it
    /// 3. Else if `dotfiles/` directory exists, rsync to home
    async fn install_dotfiles_in_container(
        &self,
        podman: &PodmanService,
        dotfiles: &DotfilesConfig,
        container: &str,
        _user: Option<&str>,
        home_override: Option<&str>,
    ) -> Result<()> {
        tracing::debug!(
            "Installing dotfiles in {} from pre-cloned repo...",
            container
        );

        // The dotfiles are cloned to the agent home volume at .dotfiles
        // For workspace container, this is mounted at /opt/devaipod
        // For agent container, this is the agent's HOME
        let dotfiles_src = if home_override.is_some() {
            // Agent container - dotfiles are in its HOME
            format!("{}/.dotfiles", AGENT_HOME_PATH)
        } else {
            // Workspace container - dotfiles are mounted at /opt/devaipod
            "/opt/devaipod/.dotfiles".to_string()
        };

        // Optional HOME override (needed for agent container)
        let home_export = home_override
            .map(|h| format!("export HOME={}\n", h))
            .unwrap_or_default();

        // Build the installation script - runs from pre-cloned dotfiles
        let install_script = if let Some(script) = &dotfiles.script {
            format!(
                r#"
set -e
{home_export}
DOTFILES_DIR="{dotfiles_src}"
if [ ! -d "$DOTFILES_DIR" ]; then
    echo "Dotfiles not found at $DOTFILES_DIR, skipping installation"
    exit 0
fi
cd "$DOTFILES_DIR"
if [ -x "./{script}" ]; then
    ./{script}
elif [ -f "./{script}" ]; then
    sh "./{script}"
else
    echo "Error: Install script '{script}' not found in dotfiles repo"
    exit 1
fi
echo "Dotfiles installed successfully"
"#,
                home_export = home_export,
                dotfiles_src = dotfiles_src,
                script = script
            )
        } else {
            format!(
                r#"
set -e
{home_export}
DOTFILES_DIR="{dotfiles_src}"
if [ ! -d "$DOTFILES_DIR" ]; then
    echo "Dotfiles not found at $DOTFILES_DIR, skipping installation"
    exit 0
fi
cd "$DOTFILES_DIR"
if [ -x "./install.sh" ]; then
    ./install.sh
elif [ -f "./install.sh" ]; then
    sh ./install.sh
elif [ -x "./install-dotfiles.sh" ]; then
    ./install-dotfiles.sh
elif [ -f "./install-dotfiles.sh" ]; then
    sh ./install-dotfiles.sh
elif [ -d "./dotfiles" ]; then
    # rsync dotfiles/ to home, preserving any existing files
    if command -v rsync >/dev/null 2>&1; then
        rsync -a --ignore-existing ./dotfiles/ "$HOME/"
    else
        cp -rn ./dotfiles/. "$HOME/" 2>/dev/null || cp -r ./dotfiles/. "$HOME/"
    fi
else
    echo "Warning: No install script or dotfiles/ directory found, skipping"
fi
echo "Dotfiles installed successfully"
"#,
                home_export = home_export,
                dotfiles_src = dotfiles_src,
            )
        };

        let exit_code = podman
            .exec_quiet(container, &["/bin/sh", "-c", &install_script], None, None)
            .await
            .with_context(|| format!("Failed to install dotfiles in {}", container))?;

        if exit_code != 0 {
            tracing::warn!(
                "Dotfiles installation in {} exited with code {}. Continuing anyway.",
                container,
                exit_code
            );
        } else {
            tracing::debug!("Dotfiles installed in {}", container);
        }

        Ok(())
    }

    /// Signal that the agent container setup is complete
    ///
    /// Writes a JSON state file that the agent startup script waits for before
    /// starting opencode serve. This prevents a race condition where opencode
    /// reads its config before dotfiles/task config are installed.
    ///
    /// The state file records dotfiles git metadata (URL and commit SHA) for
    /// debugging and staleness detection. It is written to both the container
    /// overlay (for the agent's own startup script) and the agent home volume
    /// (so worker containers that mount it at /mnt/agent-home can see it too).
    pub async fn signal_agent_ready(
        &self,
        podman: &PodmanService,
        dotfiles: Option<&DotfilesConfig>,
    ) -> Result<()> {
        tracing::debug!("Signaling agent ready...");

        // Query the dotfiles commit SHA if dotfiles were installed
        let dotfiles_json = if let Some(df) = dotfiles {
            let dotfiles_dir = format!("{}/.dotfiles", AGENT_HOME_PATH);
            let sha = match podman
                .exec_output(
                    &self.agent_container,
                    &["git", "-C", &dotfiles_dir, "rev-parse", "HEAD"],
                )
                .await
            {
                Ok((_exit, stdout, _stderr)) => String::from_utf8_lossy(&stdout).trim().to_string(),
                Err(_) => String::new(),
            };
            let sha_json = if sha.is_empty() {
                "null".to_string()
            } else {
                format!("\"{}\"", sha)
            };
            format!(
                r#", "dotfiles": {{"url": "{}", "commit": {}}}"#,
                df.url, sha_json,
            )
        } else {
            String::new()
        };

        let state_json = format!(
            r#"{{"version": 1{dotfiles_json}}}"#,
            dotfiles_json = dotfiles_json,
        );

        let home_state = format!("{}/.devaipod-state.json", AGENT_HOME_PATH);
        // Write to both locations: overlay (agent reads) and home volume (worker reads).
        // Run as root since /var/lib/ is not writable by the container user.
        let cmd = format!(
            "printf '%s' '{}' | tee {} > {}",
            state_json, AGENT_STATE_PATH, home_state,
        );
        podman
            .exec(
                &self.agent_container,
                &["sh", "-c", &cmd],
                Some("root"),
                None,
            )
            .await
            .context("Failed to write agent state file")?;

        tracing::debug!("Agent state written to {}", AGENT_STATE_PATH);
        Ok(())
    }

    /// Run lifecycle commands from devcontainer.json in both workspace and agent containers
    ///
    /// Executes in order: onCreateCommand, postCreateCommand, postStartCommand
    /// Commands run in both containers to ensure consistent environment setup
    /// (e.g., nested podman configuration needed for both human and AI).
    pub async fn run_lifecycle_commands(
        &self,
        podman: &PodmanService,
        config: &DevcontainerConfig,
    ) -> Result<()> {
        let user = config.effective_user();
        let workdir = Some(self.workspace_folder.as_str());
        let containers = [&self.workspace_container, &self.agent_container];

        // onCreateCommand
        if let Some(cmd) = &config.on_create_command {
            let shell_cmd = cmd.to_shell_command();
            for container in &containers {
                tracing::debug!("Running onCreateCommand in {}...", container);
                self.run_shell_command_in(container, podman, &shell_cmd, user, workdir)
                    .await
                    .with_context(|| format!("onCreateCommand failed in {}", container))?;
            }
        }

        // postCreateCommand
        if let Some(cmd) = &config.post_create_command {
            let shell_cmd = cmd.to_shell_command();
            for container in &containers {
                tracing::debug!("Running postCreateCommand in {}...", container);
                self.run_shell_command_in(container, podman, &shell_cmd, user, workdir)
                    .await
                    .with_context(|| format!("postCreateCommand failed in {}", container))?;
            }
        }

        // postStartCommand
        if let Some(cmd) = &config.post_start_command {
            let shell_cmd = cmd.to_shell_command();
            for container in &containers {
                tracing::debug!("Running postStartCommand in {}...", container);
                self.run_shell_command_in(container, podman, &shell_cmd, user, workdir)
                    .await
                    .with_context(|| format!("postStartCommand failed in {}", container))?;
            }
        }

        Ok(())
    }

    /// Run lifecycle commands for rebuild (skips onCreateCommand)
    ///
    /// Executes: postCreateCommand, postStartCommand
    /// Used when rebuilding a container where the workspace already exists.
    /// Commands run in both containers to ensure consistent environment setup.
    pub async fn run_rebuild_lifecycle_commands(
        &self,
        podman: &PodmanService,
        config: &DevcontainerConfig,
    ) -> Result<()> {
        let user = config.effective_user();
        let workdir = Some(self.workspace_folder.as_str());
        let containers = [&self.workspace_container, &self.agent_container];

        // postCreateCommand - runs because we created new containers
        if let Some(cmd) = &config.post_create_command {
            let shell_cmd = cmd.to_shell_command();
            for container in &containers {
                tracing::debug!("Running postCreateCommand in {}...", container);
                self.run_shell_command_in(container, podman, &shell_cmd, user, workdir)
                    .await
                    .with_context(|| format!("postCreateCommand failed in {}", container))?;
            }
        }

        // postStartCommand
        if let Some(cmd) = &config.post_start_command {
            let shell_cmd = cmd.to_shell_command();
            for container in &containers {
                tracing::debug!("Running postStartCommand in {}...", container);
                self.run_shell_command_in(container, podman, &shell_cmd, user, workdir)
                    .await
                    .with_context(|| format!("postStartCommand failed in {}", container))?;
            }
        }

        Ok(())
    }

    /// Copy bind_home files into containers using podman cp
    ///
    /// This is called after the pod starts to copy credential files and other
    /// bind_home paths into the containers. Using `podman cp` instead of bind
    /// mounts avoids permission issues with rootless podman and user namespaces.
    ///
    /// For the workspace container, files are copied to the user's home directory.
    /// For the agent container, files are copied to the agent's HOME (persistent volume).
    ///
    /// Note: In container mode (devaipod running as a container), bind_home is not
    /// supported because we don't have access to the host's home directory. Use podman
    /// secrets via `[trusted.secrets]` instead.
    pub async fn copy_bind_home_files(
        &self,
        podman: &PodmanService,
        workspace_bind_home: &BindHomeConfig,
        agent_bind_home: &BindHomeConfig,
        container_home: &str,
        container_user: Option<&str>,
    ) -> Result<()> {
        // In container mode, bind_home is not supported - credentials must use secrets
        if crate::podman::is_container_mode() {
            let total_paths = workspace_bind_home.paths.len() + agent_bind_home.paths.len();
            if total_paths > 0 {
                bail!(
                    "Container mode: bind_home is not supported ({} paths configured). \
                     Use [trusted.secrets] in your config instead. See: \
                     https://github.com/cgwalters/devaipod/blob/main/docs/src/quickstart.md",
                    total_paths
                );
            }
            return Ok(());
        }

        let Some(host_home) = get_host_home() else {
            tracing::warn!("HOME environment variable not set, skipping bind_home file copy");
            return Ok(());
        };

        // Copy files to workspace container
        for relative_path in &workspace_bind_home.paths {
            let source = host_home.join(relative_path);
            let target = format!("{}/{}", container_home, relative_path);

            if !source.exists() {
                tracing::warn!(
                    "bind_home: skipping '{}' for workspace (not found at {})",
                    relative_path,
                    source.display()
                );
                continue;
            }

            tracing::debug!(
                "bind_home: copying {} -> {}:{} for workspace",
                source.display(),
                self.workspace_container,
                target
            );

            if let Err(e) = podman
                .copy_to_container(&self.workspace_container, &source, &target, container_user)
                .await
            {
                tracing::warn!(
                    "Failed to copy {} to workspace container: {}",
                    relative_path,
                    e
                );
            }
        }

        // Copy files to agent container (to agent's HOME which is a persistent volume)
        for relative_path in &agent_bind_home.paths {
            let source = host_home.join(relative_path);
            let target = format!("{}/{}", AGENT_HOME_PATH, relative_path);

            if !source.exists() {
                tracing::warn!(
                    "bind_home: skipping '{}' for agent (not found at {})",
                    relative_path,
                    source.display()
                );
                continue;
            }

            tracing::debug!(
                "bind_home: copying {} -> {}:{} for agent",
                source.display(),
                self.agent_container,
                target
            );

            // Agent container runs as non-root, but the agent home is created by the
            // startup script with correct ownership
            if let Err(e) = podman
                .copy_to_container(&self.agent_container, &source, &target, None)
                .await
            {
                tracing::warn!("Failed to copy {} to agent container: {}", relative_path, e);
            }
        }

        // Copy files to worker container (only in orchestration mode)
        // Worker uses the same bind_home config as agent since it also runs LLM API calls
        if let Some(worker_container) = &self.worker_container {
            for relative_path in &agent_bind_home.paths {
                let source = host_home.join(relative_path);
                let target = format!("{}/{}", AGENT_HOME_PATH, relative_path);

                if !source.exists() {
                    tracing::warn!(
                        "bind_home: skipping '{}' for worker (not found at {})",
                        relative_path,
                        source.display()
                    );
                    continue;
                }

                tracing::debug!(
                    "bind_home: copying {} -> {}:{} for worker",
                    source.display(),
                    worker_container,
                    target
                );

                if let Err(e) = podman
                    .copy_to_container(worker_container, &source, &target, None)
                    .await
                {
                    tracing::warn!(
                        "Failed to copy {} to worker container: {}",
                        relative_path,
                        e
                    );
                }
            }
        }

        Ok(())
    }

    // Note: service-gator MCP config is now set via OPENCODE_CONFIG_CONTENT env var
    // at container creation time in agent_container_config(), so we don't need
    // a separate configure_agent_opencode() method.

    /// Write scripts to the agent home volume before containers start
    ///
    /// This writes:
    /// - devaipod-workerctl: Worker control script for orchestration
    ///
    /// Uses a one-shot init container.
    async fn write_scripts_to_volume(
        podman: &PodmanService,
        image: &str,
        agent_home_volume: &str,
    ) -> Result<()> {
        let script = format!(
            r#"set -e
mkdir -p {agent_home}/scripts

cat > '{agent_home}/scripts/devaipod-workerctl' << 'WORKERCTL_EOF'
{worker_ctl_script}
WORKERCTL_EOF
chmod +x {agent_home}/scripts/devaipod-workerctl
"#,
            agent_home = AGENT_HOME_PATH,
            worker_ctl_script = WORKER_CTL_SCRIPT,
        );

        tracing::debug!("Writing scripts to agent home volume...");
        let exit_code = podman
            .run_init_container(
                image,
                agent_home_volume,
                AGENT_HOME_PATH,
                &["/bin/sh", "-c", &script],
                &[],
            )
            .await
            .context("Failed to write scripts to agent volume")?;

        if exit_code != 0 {
            tracing::warn!(
                "Failed to write scripts to volume (exit code {})",
                exit_code
            );
        } else {
            tracing::debug!("Scripts written to agent home volume");
        }

        Ok(())
    }

    /// Write gator configuration to the workspace volume
    ///
    /// This stores scopes persistently so they survive container restarts and can
    /// be updated via `devaipod gator add/edit`. Gator watches this file via inotify.
    async fn write_gator_config_to_volume(
        podman: &PodmanService,
        image: &str,
        workspace_volume: &str,
        scopes: &crate::service_gator::JwtScopeConfig,
    ) -> Result<()> {
        let config = crate::service_gator::GatorConfigFile::new(scopes.clone());

        let config_json =
            serde_json::to_string_pretty(&config).context("Failed to serialize gator config")?;

        // Write the config file using a heredoc in the init container
        // Escape any single quotes in the JSON
        let escaped_json = config_json.replace('\'', "'\\''");
        let config_path = format!("/workspaces/{}", crate::service_gator::GATOR_CONFIG_PATH);

        let script = format!(
            r#"set -e
mkdir -p "$(dirname '{config_path}')"
cat > '{config_path}' << 'GATOR_CONFIG_EOF'
{config_json}
GATOR_CONFIG_EOF
chmod 644 '{config_path}'
"#,
            config_path = config_path,
            config_json = escaped_json,
        );

        tracing::debug!("Writing gator config to workspace volume...");
        // Run as root so the config file is owned by root and unmodifiable by the agent
        // This prevents the agent from escalating its own scopes
        let exit_code = podman
            .run_init_container_as_root(
                image,
                workspace_volume,
                "/workspaces",
                &["/bin/sh", "-c", &script],
            )
            .await
            .context("Failed to write gator config to workspace volume")?;

        if exit_code != 0 {
            tracing::warn!(
                "Failed to write gator config to volume (exit code {})",
                exit_code
            );
        } else {
            tracing::debug!(
                "Gator config written to workspace volume at {}",
                config_path
            );
        }

        Ok(())
    }

    /// Clone dotfiles repository to the agent home volume before containers start
    ///
    /// This uses a one-shot init container with access to GH_TOKEN for private repos.
    /// The dotfiles are cloned to a staging directory, and the install script is run
    /// after the container starts.
    async fn clone_dotfiles_to_volume(
        podman: &PodmanService,
        image: &str,
        agent_home_volume: &str,
        dotfiles: &DotfilesConfig,
        global_config: &Config,
    ) -> Result<()> {
        let dotfiles_dir = format!("{}/.dotfiles", AGENT_HOME_PATH);

        // Get GH_TOKEN for private repos
        let gh_token = crate::git::get_github_token_with_secret(global_config);

        let clone_script =
            crate::git::clone_dotfiles_script(&dotfiles.url, &dotfiles_dir, gh_token.as_deref());

        tracing::debug!("Cloning dotfiles to agent home volume...");
        let (exit_code, stdout) = podman
            .run_init_container_with_output(
                image,
                agent_home_volume,
                AGENT_HOME_PATH,
                &["/bin/sh", "-c", &clone_script],
                &[],
            )
            .await
            .context("Failed to clone dotfiles to agent volume")?;

        if exit_code != 0 {
            tracing::warn!(
                "Failed to clone dotfiles (exit code {}). Continuing anyway.",
                exit_code
            );
        } else {
            // Extract and log the SHA from the output (format: "DOTFILES_SHA:<sha>")
            let mut sha_logged = false;
            for line in stdout.lines() {
                if let Some(sha) = line.strip_prefix("DOTFILES_SHA:") {
                    tracing::info!("Cloned dotfiles from {} at {}", dotfiles.url, sha);
                    sha_logged = true;
                    break;
                }
            }
            if !sha_logged {
                tracing::info!("Cloned dotfiles from {}", dotfiles.url);
            }
        }

        Ok(())
    }

    /// Write task instructions to the agent home volume
    ///
    /// This should be called after dotfiles installation to ensure the task config
    /// is not overwritten by user dotfiles. Uses podman exec to write the task file
    /// and merge instructions into the opencode config.
    ///
    /// The task file includes:
    /// - System context about the devaipod environment
    /// - Instructions for using service-gator for forge operations
    /// - Orchestration instructions (when enabled)
    /// - The user's task
    pub async fn write_task(
        &self,
        podman: &PodmanService,
        task: &str,
        enable_gator: bool,
    ) -> Result<()> {
        let task_file = ".config/opencode/devaipod-task.md";
        let config_file = ".config/opencode/opencode.json";

        // Generate the complete system prompt using the prompt module
        let task_content = crate::prompt::generate_system_prompt(
            task,
            enable_gator,
            self.enable_orchestration,
            self.repo_url.as_deref(),
            self.branch.as_deref(),
        );

        let task_file_path = format!("{}/{}", AGENT_HOME_PATH, task_file);
        let config_file_path = format!("{}/{}", AGENT_HOME_PATH, config_file);

        // Write the task markdown file
        tracing::debug!("Writing task to agent container...");
        let task_script = format!(
            r#"mkdir -p {agent_home}/.config/opencode && cat > '{agent_home}/{task_file}' << 'TASK_EOF'
{task_content}
TASK_EOF"#,
            agent_home = AGENT_HOME_PATH,
            task_file = task_file,
            task_content = task_content,
        );
        let exit_code = podman
            .exec_quiet(
                &self.agent_container,
                &["/bin/sh", "-c", &task_script],
                None,
                None,
            )
            .await
            .context("Failed to write task file")?;
        if exit_code != 0 {
            bail!("Failed to write task file (exit code {})", exit_code);
        }

        // Read existing opencode.json from container (if it exists)
        let (exit_code, stdout, _stderr) = podman
            .exec_output(&self.agent_container, &["cat", &config_file_path])
            .await
            .context("Failed to read opencode config")?;

        // Parse existing config or create new one
        // Use jsonc-parser to handle JSONC (comments, trailing commas)
        let mut config: serde_json::Value = if exit_code == 0 && !stdout.is_empty() {
            let content = String::from_utf8_lossy(&stdout);
            match jsonc_parser::parse_to_serde_value(&content, &Default::default()) {
                Ok(Some(value)) => value,
                Ok(None) | Err(_) => {
                    tracing::debug!("Could not parse existing opencode.json, creating new one");
                    serde_json::json!({"$schema": "https://opencode.ai/config.json"})
                }
            }
        } else {
            serde_json::json!({"$schema": "https://opencode.ai/config.json"})
        };

        // Merge task into instructions array
        let instructions = config.as_object_mut().and_then(|obj| {
            obj.entry("instructions")
                .or_insert(serde_json::json!([]))
                .as_array_mut()
        });
        if let Some(arr) = instructions {
            let task_path_value = serde_json::Value::String(task_file_path.clone());
            if !arr.contains(&task_path_value) {
                arr.push(task_path_value);
            }
        }

        // Disable opencode's built-in git snapshotting — we use the real git
        // history via the agent/workspace remote setup instead.
        if let Some(obj) = config.as_object_mut() {
            obj.insert("snapshot".to_string(), serde_json::json!(false));
        }

        // Write merged config back to container
        let config_json = serde_json::to_string_pretty(&config).unwrap_or_else(|_| {
            format!(
                r#"{{"$schema": "https://opencode.ai/config.json", "instructions": ["{}"]}}"#,
                task_file_path
            )
        });
        let config_script = format!(
            r#"cat > '{}' << 'CONFIG_EOF'
{}
CONFIG_EOF"#,
            config_file_path, config_json
        );
        let exit_code = podman
            .exec_quiet(
                &self.agent_container,
                &["/bin/sh", "-c", &config_script],
                None,
                None,
            )
            .await
            .context("Failed to write opencode config")?;

        if exit_code != 0 {
            bail!("Failed to write opencode config (exit code {})", exit_code);
        }
        tracing::debug!("Task written to agent container");

        // When orchestration is enabled, also write a worker-specific task file
        // to the agent home volume. The worker copies configs from /mnt/agent-home
        // at startup and will overwrite the task file with this worker-specific version
        // that omits orchestration instructions (the worker is the leaf executor).
        if self.enable_orchestration {
            let worker_task_file = ".config/opencode/devaipod-task-worker.md";
            let worker_task_content = crate::prompt::generate_worker_prompt(
                task,
                enable_gator,
                self.repo_url.as_deref(),
                self.branch.as_deref(),
            );
            let worker_task_script = format!(
                r#"cat > '{agent_home}/{worker_task_file}' << 'TASK_EOF'
{worker_task_content}
TASK_EOF"#,
                agent_home = AGENT_HOME_PATH,
                worker_task_file = worker_task_file,
                worker_task_content = worker_task_content,
            );
            let exit_code = podman
                .exec_quiet(
                    &self.agent_container,
                    &["/bin/sh", "-c", &worker_task_script],
                    None,
                    None,
                )
                .await
                .context("Failed to write worker task file")?;
            if exit_code != 0 {
                tracing::warn!("Failed to write worker task file (exit code {})", exit_code);
            } else {
                tracing::debug!("Worker task file written to agent home");
            }
        }

        Ok(())
    }

    /// Set up git remotes for bidirectional collaboration between human and agent
    ///
    /// This sets up:
    /// 1. An 'agent' remote in the workspace container pointing to the agent's workspace
    /// 2. A 'workspace' remote in the agent container pointing to the human's workspace
    /// 3. When orchestration is enabled, a 'worker' remote in the agent container pointing
    ///    to the worker's workspace at `/mnt/worker-workspace`
    ///
    /// This enables the full collaboration workflow:
    /// - Human reviews agent's commits: `git fetch agent && git diff agent/main`
    /// - Agent fetches human's changes: `git fetch workspace && git rebase workspace/main`
    /// - Task owner (agent) fetches worker's commits: `git fetch worker && git cherry-pick worker/...`
    pub async fn setup_git_remotes(&self, podman: &PodmanService) -> Result<()> {
        // Extract project name from workspace folder (e.g., /workspaces/myproject -> myproject)
        let project_name = self
            .workspace_folder
            .strip_prefix("/workspaces/")
            .unwrap_or(&self.workspace_folder);

        // Set up 'agent' remote in workspace container
        let agent_repo_path = format!("/mnt/agent-workspace/{}", project_name);
        let workspace_script = format!(
            r#"
# Mark the agent workspace as safe (different ownership in container)
git config --global --add safe.directory '{agent_repo_path}'

if git remote get-url {REMOTE_AGENT} >/dev/null 2>&1; then
    echo "Remote '{REMOTE_AGENT}' already exists, skipping"
else
    git remote add {REMOTE_AGENT} '{agent_repo_path}'
    echo "Added git remote '{REMOTE_AGENT}' pointing to agent workspace"
fi
"#,
            agent_repo_path = agent_repo_path,
            REMOTE_AGENT = REMOTE_AGENT,
        );

        tracing::debug!(
            "Setting up '{}' git remote in workspace container...",
            REMOTE_AGENT
        );
        let exit_code = podman
            .exec_quiet(
                &self.workspace_container,
                &["/bin/sh", "-c", &workspace_script],
                None,
                Some(&self.workspace_folder),
            )
            .await
            .context("Failed to set up agent git remote")?;

        if exit_code != 0 {
            tracing::warn!(
                "Failed to set up agent git remote (exit code {}). Continuing anyway.",
                exit_code
            );
        } else {
            tracing::debug!("Agent git remote set up successfully");
        }

        // Set up 'workspace' remote in agent container
        // When orchestration is enabled, also set up 'worker' remote
        let workspace_repo_path = format!("/mnt/main-workspace/{}", project_name);
        let worker_remote_setup = if self.enable_orchestration {
            let worker_repo_path = format!("/mnt/worker-workspace/{}", project_name);
            format!(
                r#"
# Mark the worker workspace as safe (different ownership in container)
git config --global --add safe.directory '{worker_repo_path}'

if git remote get-url {REMOTE_WORKER} >/dev/null 2>&1; then
    echo "Remote '{REMOTE_WORKER}' already exists, skipping"
else
    git remote add {REMOTE_WORKER} '{worker_repo_path}'
    echo "Added git remote '{REMOTE_WORKER}' pointing to worker workspace"
fi
"#,
                worker_repo_path = worker_repo_path,
                REMOTE_WORKER = REMOTE_WORKER,
            )
        } else {
            String::new()
        };

        let agent_script = format!(
            r#"
# Mark the main workspace as safe (different ownership in container)
git config --global --add safe.directory '{workspace_repo_path}'

if git remote get-url {REMOTE_WORKSPACE} >/dev/null 2>&1; then
    echo "Remote '{REMOTE_WORKSPACE}' already exists, skipping"
else
    git remote add {REMOTE_WORKSPACE} '{workspace_repo_path}'
    echo "Added git remote '{REMOTE_WORKSPACE}' pointing to main workspace"
fi
{worker_remote_setup}"#,
            workspace_repo_path = workspace_repo_path,
            worker_remote_setup = worker_remote_setup,
            REMOTE_WORKSPACE = REMOTE_WORKSPACE,
        );

        tracing::debug!(
            "Setting up '{}' git remote in agent container...",
            REMOTE_WORKSPACE
        );
        let exit_code = podman
            .exec_quiet(
                &self.agent_container,
                &["/bin/sh", "-c", &agent_script],
                None,
                Some(&self.workspace_folder),
            )
            .await
            .context("Failed to set up workspace git remote")?;

        if exit_code != 0 {
            tracing::warn!(
                "Failed to set up workspace git remote (exit code {}). Continuing anyway.",
                exit_code
            );
        } else {
            tracing::debug!("Workspace git remote set up successfully");
            if self.enable_orchestration {
                tracing::debug!("Worker git remote set up successfully");
            }
        }

        Ok(())
    }

    /// Stop the pod
    #[allow(dead_code)] // Part of public API, will be used by stop command
    pub async fn stop(&self, podman: &PodmanService) -> Result<()> {
        podman
            .stop_pod(&self.pod_name)
            .await
            .with_context(|| format!("Failed to stop pod: {}", self.pod_name))?;

        tracing::info!("Stopped pod '{}'", self.pod_name);
        Ok(())
    }

    /// Remove the pod and all containers
    #[allow(dead_code)] // Part of public API, will be used by delete command
    pub async fn remove(&self, podman: &PodmanService, force: bool) -> Result<()> {
        podman
            .remove_pod(&self.pod_name, force)
            .await
            .with_context(|| format!("Failed to remove pod: {}", self.pod_name))?;

        tracing::info!("Removed pod '{}'", self.pod_name);
        Ok(())
    }

    /// Execute a shell command in a specific container
    async fn run_shell_command_in(
        &self,
        container: &str,
        podman: &PodmanService,
        command: &str,
        user: Option<&str>,
        workdir: Option<&str>,
    ) -> Result<()> {
        let exit_code = podman
            .exec(container, &["/bin/sh", "-c", command], user, workdir)
            .await
            .context("Failed to execute command")?;

        if exit_code != 0 {
            color_eyre::eyre::bail!("Command exited with code {}: {}", exit_code, command);
        }

        Ok(())
    }

    /// Create container config for the workspace container
    #[allow(clippy::too_many_arguments)]
    fn workspace_container_config(
        _project_path: &Path,
        workspace_folder: &str,
        user: Option<&str>,
        config: &DevcontainerConfig,
        _bind_home: &BindHomeConfig,
        _container_home: &str,
        volume_name: &str,
        agent_home_volume: &str,
        agent_workspace_volume: &str,
        global_config: &crate::config::Config,
        labels: &[(String, String)],
    ) -> ContainerConfig {
        let mut env = config.container_env.clone();
        // Merge remote_env (these typically take precedence)
        env.extend(config.remote_env.clone());

        // Add env vars from global config (allowlist + explicit vars)
        env.extend(global_config.env.collect());

        // Add trusted env vars (these go to workspace and gator, NOT agent)
        // This is where credentials like GH_TOKEN are forwarded for service-gator
        env.extend(global_config.trusted_env.collect());

        // Resolve env vars containing devcontainer variable syntax like ${containerEnv:PATH}.
        // These cannot be fully resolved outside of VS Code. We attempt partial resolution
        // (e.g., extracting static suffixes) and warn about variables we can't resolve.
        let mut skipped_vars = Vec::new();
        env.retain(|key, value| {
            if !value.contains("${") {
                return true; // Keep as-is
            }
            // Try to resolve the value
            if resolve_env_value(value, key).is_some() {
                // Note: we can't update the value in-place here, so we'll do a second pass
                true
            } else {
                skipped_vars.push(key.clone());
                false
            }
        });

        // Second pass: resolve values that contain variable references
        for (key, value) in env.iter_mut() {
            if value.contains("${") {
                if let Some(resolved) = resolve_env_value(value, key) {
                    *value = resolved;
                }
            }
        }

        if !skipped_vars.is_empty() {
            tracing::warn!(
                "Skipping environment variables with unresolved references: {:?}. \
                 Variable substitution like ${{containerEnv:PATH}} is not yet fully supported.",
                skipped_vars
            );
        }

        // Tell opencode in workspace to connect to agent's server
        env.insert(
            "OPENCODE_AGENT_URL".to_string(),
            format!("http://localhost:{}", OPENCODE_PORT),
        );

        // No bind mounts - we clone the repo into the container instead
        // This avoids UID mapping issues with rootless podman
        let mounts = vec![];

        // Auto-detect development devices to pass through
        let mut devices: Vec<String> = DEV_PASSTHROUGH_PATHS
            .iter()
            .filter(|path| Path::new(path).exists())
            .map(|path| path.to_string())
            .collect();

        // Add devices from runArgs (e.g., --device=/dev/kvm or --device /dev/kvm)
        collect_config_devices(config, &mut devices);

        if !devices.is_empty() {
            tracing::debug!("Devices for workspace container: {:?}", devices);
        }

        // When nestedContainers is set, we ignore all security config from
        // devcontainer.json (privileged, capAdd, securityOpt, runArgs) and apply
        // our own known-good minimal set. This lets devcontainer.json use
        // "privileged": true for compatibility with stock tooling while devaipod
        // uses a tighter security profile.
        let (privileged, cap_add, security_opts) =
            if config.has_nested_containers() || global_config.container_nesting {
                nested_container_security(&mut devices)
            } else {
                let privileged = config.privileged || config.has_privileged_run_arg();
                let mut cap_add = config.cap_add.clone();
                for cap in config.cap_add_args() {
                    if !cap_add.contains(&cap) {
                        cap_add.push(cap);
                    }
                }
                let mut security_opts = config.security_opt.clone();
                for opt in config.security_opt_args() {
                    if !security_opts.contains(&opt) {
                        security_opts.push(opt);
                    }
                }
                (privileged, cap_add, security_opts)
            };

        // Get secrets to mount with type=env - workspace gets both trusted secrets
        // (like GH_TOKEN) and devcontainer-declared secrets (like ANTHROPIC_API_KEY).
        // Note: agent container does NOT get trusted secrets for security.
        let mut secrets = global_config.trusted_env.secret_mounts();

        // Filter out devcontainer secrets that collide with trusted secrets.
        // Trusted secrets always win to prevent malicious devcontainer.json from shadowing them.
        let trusted_env_vars: std::collections::HashSet<String> =
            secrets.iter().map(|(env_var, _)| env_var.clone()).collect();
        let devcontainer_secrets = config.devcontainer_secret_mounts();
        for (env_var, secret_name) in devcontainer_secrets {
            if trusted_env_vars.contains(&env_var) {
                tracing::warn!(
                    "Ignoring devcontainer secret '{}' for env var '{}' - shadowed by trusted secret",
                    secret_name, env_var
                );
            } else {
                secrets.push((env_var, secret_name));
            }
        }

        // Get file-based secrets (mounted as files, env var points to path)
        // Used for credentials like GOOGLE_APPLICATION_CREDENTIALS that expect a file path.
        let file_secrets = global_config.trusted_env.file_secret_mounts();

        ContainerConfig {
            mounts,
            env,
            // Set workdir to the workspace folder - where the cloned repo lives
            workdir: Some(workspace_folder.to_string()),
            user: user.map(|u| u.to_string()),
            // Keep the container running, create opencode shim in /usr/local/bin
            // The container just sleeps; users attach via tmux with `devaipod attach`
            command: Some(vec![
                "/bin/sh".to_string(),
                "-c".to_string(),
                format!(
                    r#"
# Create opencode-connect shim that attaches to the agent container's server
# This shim auto-detects existing sessions for seamless handoff from autonomous to interactive mode
# Install to /usr/local/bin so it's in PATH by default
sudo tee /usr/local/bin/opencode-connect > /dev/null << 'EOF'
#!/bin/sh
# Shim to connect to devaipod agent container
# Auto-detects existing session for seamless handoff

AGENT_URL="http://localhost:{port}"

# If user explicitly passed -s/--session, use their args as-is
case "$*" in
    *-s*|*--session*)
        exec opencode attach "$AGENT_URL" "$@"
        ;;
esac

# Try to find the root session (parentID is null) to continue
# This enables seamless handoff from autonomous agent to interactive mode
# Subagent sessions have a parentID, we want the main task session
# If detection fails (Python unavailable, curl fails, etc.), fall back to no session
SESSION_ID=$(curl -sf "$AGENT_URL/session" 2>/dev/null | \
    python3 -c "
import sys, json
try:
    sessions = json.load(sys.stdin)
    # Find sessions without a parent (root sessions)
    root_sessions = [s for s in sessions if s.get('parentID') is None]
    # Sort by creation time (oldest first) and pick the first one
    if root_sessions:
        root_sessions.sort(key=lambda s: s.get('time', {{}}).get('created', 0))
        print(root_sessions[0]['id'])
except Exception:
    pass
" 2>/dev/null || true)

if [ -n "$SESSION_ID" ]; then
    echo "Continuing session: $SESSION_ID"
    exec opencode attach "$AGENT_URL" -s "$SESSION_ID" "$@"
else
    exec opencode attach "$AGENT_URL" "$@"
fi
EOF
sudo chmod +x /usr/local/bin/opencode-connect

# Keep container running - users attach via tmux with `devaipod attach`
exec sleep infinity
"#,
                    port = OPENCODE_PORT,
                ),
            ]),
            drop_all_caps: false,
            cap_add,
            no_new_privileges: false,
            devices,
            security_opts,
            privileged,
            // Mount volumes:
            // - workspace volume at /workspaces (main workspace clone)
            // - workspace volume also at /mnt/main-workspace (read-only, for git alternates resolution)
            // - agent home volume at /opt/devaipod (read-only, for scripts)
            // - agent workspace volume at /mnt/agent-workspace (read-only, for git remote)
            //
            // Note: The /mnt/main-workspace mount is needed because the agent's git clone uses
            // --shared which creates an alternates file pointing to /mnt/main-workspace/...
            // This path must exist in the workspace container for `git fetch agent` to work.
            volume_mounts: vec![
                (volume_name.to_string(), "/workspaces".to_string()),
                (
                    volume_name.to_string(),
                    "/mnt/main-workspace:ro".to_string(),
                ),
                (
                    agent_home_volume.to_string(),
                    "/opt/devaipod:ro".to_string(),
                ),
                (
                    agent_workspace_volume.to_string(),
                    "/mnt/agent-workspace:ro".to_string(),
                ),
            ],
            secrets,
            file_secrets,
            labels: labels.iter().cloned().collect(),
            extra_create_args: config.passthrough_run_args(),
            ..Default::default()
        }
    }

    /// Create container config for the agent container
    ///
    /// The agent runs `opencode serve` with credential isolation:
    /// - Receives LLM API keys but NOT trusted credentials (GH_TOKEN, etc.)
    /// - Uses a separate home directory volume
    /// - Has the same Linux capabilities as workspace (for nested container support)
    /// - Has its own workspace clone (using git --reference to share objects)
    /// - Has read-only access to main workspace for reference
    /// - When orchestration is enabled, has read-only access to worker workspace
    ///
    /// If `devcontainer_config` is provided, env vars from its `customizations.devaipod.env_allowlist`
    /// will be forwarded to the agent.
    ///
    /// If `enable_gator` is true, OPENCODE_CONFIG_CONTENT is set with MCP config
    /// to connect opencode to the service-gator container (no auth needed).
    ///
    /// If `enable_orchestration` is true and `worker_workspace_volume` is provided,
    /// the worker's workspace is mounted read-only at `/mnt/worker-workspace`.
    #[allow(clippy::too_many_arguments)]
    fn agent_container_config(
        _project_path: &Path,
        workspace_folder: &str,
        bind_home: &BindHomeConfig,
        _container_home: &str,
        devcontainer_config: Option<&DevcontainerConfig>,
        enable_gator: bool,
        enable_orchestration: bool,
        workspace_volume: &str,
        agent_workspace_volume: &str,
        agent_home_volume: &str,
        worker_workspace_volume: Option<&str>,
        global_config: &crate::config::Config,
    ) -> ContainerConfig {
        // Agent home is mounted from a persistent volume so state survives restarts
        let agent_home = AGENT_HOME_PATH.to_string();

        let mut env = std::collections::HashMap::new();
        // HOME is already set correctly via the user's passwd entry

        // Ensure agent can find opencode in PATH
        env.insert(
            "PATH".to_string(),
            "/usr/local/bin:/usr/bin:/bin".to_string(),
        );
        // Tell opencode to create its config in the agent home
        env.insert(
            "XDG_CONFIG_HOME".to_string(),
            format!("{agent_home}/.config"),
        );
        env.insert(
            "XDG_DATA_HOME".to_string(),
            format!("{agent_home}/.local/share"),
        );

        // Forward env vars to the agent container:
        // 1. DEVAIPOD_AGENT_* vars: strip prefix and forward (e.g., DEVAIPOD_AGENT_FOO=bar -> FOO=bar)
        // 2. Vars from devcontainer.json customizations.devaipod.env_allowlist
        // 3. Vars from global config env.allowlist and env.vars
        for (key, value) in std::env::vars() {
            // Handle DEVAIPOD_AGENT_* prefix: strip and forward
            if let Some(stripped) = key.strip_prefix("DEVAIPOD_AGENT_") {
                if !stripped.is_empty() {
                    env.insert(stripped.to_string(), value);
                }
            }
        }

        // Forward DEVAIPOD_MOCK_AGENT to the agent container for integration testing.
        // When set, the agent startup script runs `devaipod mock-opencode` instead of
        // the real opencode server.
        if let Ok(val) = std::env::var("DEVAIPOD_MOCK_AGENT") {
            env.insert("DEVAIPOD_MOCK_AGENT".to_string(), val);
        }

        // Forward env vars from devcontainer.json's customizations.devaipod.env_allowlist
        if let Some(config) = devcontainer_config {
            for (key, value) in config.collect_allowlist_env_vars() {
                env.insert(key, value);
            }
        }

        // Add env vars from global config (allowlist + explicit vars)
        env.extend(global_config.env.collect());

        // No bind mounts - we clone the repo into the container instead
        // This avoids UID mapping issues with rootless podman
        let mounts = vec![];

        // Get security settings from devcontainer config to match workspace container.
        // In rootless podman, capabilities are relative to the user namespace, so the
        // agent container can safely have the same settings as workspace for nested containers.
        let (devices, privileged, security_opts, cap_add, extra_create_args) =
            if let Some(config) = devcontainer_config {
                // Auto-detect development devices to pass through
                let mut devices: Vec<String> = DEV_PASSTHROUGH_PATHS
                    .iter()
                    .filter(|path| Path::new(path).exists())
                    .map(|path| path.to_string())
                    .collect();

                // Add devices from runArgs; only pass through if they exist on the host
                collect_config_devices(config, &mut devices);

                // When nestedContainers is set, ignore all security config from
                // devcontainer.json and apply our own minimal set.
                let (privileged, cap_add, security_opts) =
                    if config.has_nested_containers() || global_config.container_nesting {
                        nested_container_security(&mut devices)
                    } else {
                        let privileged = config.privileged || config.has_privileged_run_arg();
                        let mut security_opts = config.security_opt.clone();
                        for opt in config.security_opt_args() {
                            if !security_opts.contains(&opt) {
                                security_opts.push(opt);
                            }
                        }
                        let mut cap_add = config.cap_add.clone();
                        for cap in config.cap_add_args() {
                            if !cap_add.contains(&cap) {
                                cap_add.push(cap);
                            }
                        }
                        (privileged, cap_add, security_opts)
                    };

                let extra_create_args = config.passthrough_run_args();

                (
                    devices,
                    privileged,
                    security_opts,
                    cap_add,
                    extra_create_args,
                )
            } else if global_config.container_nesting {
                let mut devices = vec![];
                let (privileged, cap_add, security_opts) = nested_container_security(&mut devices);
                (devices, privileged, security_opts, cap_add, vec![])
            } else {
                (vec![], false, vec![], vec![], vec![])
            };

        // If gcloud ADC is in bind_home, set GOOGLE_APPLICATION_CREDENTIALS to point to it
        // Files are copied to the agent's home directory after container starts
        const GCLOUD_ADC_PATH: &str = ".config/gcloud/application_default_credentials.json";
        if bind_home.paths.iter().any(|p| p == GCLOUD_ADC_PATH) {
            // Check if the file actually exists on the host
            if let Some(host_home) = get_host_home() {
                if host_home.join(GCLOUD_ADC_PATH).exists() {
                    env.insert(
                        "GOOGLE_APPLICATION_CREDENTIALS".to_string(),
                        format!("{}/{}", agent_home, GCLOUD_ADC_PATH),
                    );
                }
            }
        }

        // Build MCP config combining service-gator and any additional MCP servers
        let mut mcp_servers = serde_json::Map::new();

        if enable_gator {
            mcp_servers.insert(
                "service-gator".to_string(),
                serde_json::json!({
                    "type": "remote",
                    "url": format!("http://localhost:{}/mcp", GATOR_PORT),
                    "enabled": true
                }),
            );
        }

        // Add any additional MCP servers from config
        for (name, entry) in global_config.mcp.enabled_servers() {
            let mut server_json = serde_json::json!({
                "type": "remote",
                "url": entry.url,
                "enabled": true
            });
            if !entry.headers.is_empty() {
                server_json["headers"] = serde_json::json!(entry.headers);
            }
            mcp_servers.insert(name.to_string(), server_json);
        }

        if !mcp_servers.is_empty() {
            let mcp_config = serde_json::json!({
                "mcp": mcp_servers
            });
            env.insert(
                "OPENCODE_CONFIG_CONTENT".to_string(),
                mcp_config.to_string(),
            );
        }

        // When orchestration is enabled, set OPENCODE_WORKER_URL so the task owner
        // can use `opencode run --attach $OPENCODE_WORKER_URL` to delegate to the worker.
        // This is much cleaner than raw curl commands.
        if enable_orchestration {
            env.insert(
                "OPENCODE_WORKER_URL".to_string(),
                format!("http://localhost:{}", WORKER_OPENCODE_PORT),
            );
        }

        // Get devcontainer-declared secrets (like ANTHROPIC_API_KEY, OPENAI_API_KEY).
        // These go to the agent container since they're project-declared LLM keys.
        // Note: trusted secrets (like GH_TOKEN) do NOT go to agent for security.
        let secrets = if let Some(config) = devcontainer_config {
            config.devcontainer_secret_mounts()
        } else {
            Vec::new()
        };

        // Get file-based secrets (mounted as files, env var points to path)
        // Used for credentials like GOOGLE_APPLICATION_CREDENTIALS that expect a file path.
        let file_secrets = global_config.trusted_env.file_secret_mounts();

        let startup_script = format!(
            r#"mkdir -p {home}/.config/opencode {home}/.local/share {home}/.local/bin {home}/.cache

# Wait for devaipod to finish setup (dotfiles, task config) before starting
# opencode.  The state file lives on the container overlay so it persists
# across stop/start but is absent after a container rebuild.
while [ ! -f {state} ]; do
    sleep 0.1
done

# Mock mode: run inline mock server instead of the real opencode server.
# Used by integration tests to avoid needing a real AI provider.
# Uses Python3 (available in all devcontainer images) so no extra binary
# is required in the agent container.
if [ -n "${{DEVAIPOD_MOCK_AGENT}}" ]; then
    exec python3 -u -c "
import json, http.server, socketserver

SESSION = json.dumps([dict(id='mock-001',slug='mock',projectID='p',directory='/workspaces/test',title='Mock',version='1.0.0',time=dict(created=1700000000000,updated=1700000100000))])
MESSAGE = json.dumps([dict(info=dict(role='assistant',time=dict(created=1700000001000,completed=1700000002000),finish='stop'),parts=[dict(type='text',text='Ready.')])])

class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path.startswith('/session') and '/message' in self.path:
            body = MESSAGE
        elif self.path.startswith('/session'):
            body = SESSION
        else:
            self.send_error(404); return
        self.send_response(200)
        self.send_header('Content-Type','application/json')
        self.end_headers()
        self.wfile.write(body.encode())
    def log_message(self, *a): pass

print('Mock opencode on port {opencode_port}', flush=True)
socketserver.TCPServer(('0.0.0.0',{opencode_port}),H).serve_forever()
"
fi

# Run opencode serve, bound to 0.0.0.0 so it's accessible from the published port
exec opencode serve --port {opencode_port} --hostname 0.0.0.0"#,
            home = AGENT_HOME_PATH,
            state = AGENT_STATE_PATH,
            opencode_port = OPENCODE_PORT
        );

        ContainerConfig {
            mounts,
            env,
            // Set workdir to the workspace folder - where the cloned repo lives
            workdir: Some(workspace_folder.to_string()),
            // Run as a non-root user if possible (agent user)
            user: None, // Let the image decide, or we could set "1000" for a generic user
            command: Some(vec![
                "/bin/sh".to_string(),
                "-c".to_string(),
                startup_script,
            ]),
            // Security settings match workspace container - in rootless podman, capabilities
            // are relative to the user namespace so both containers can safely have the same
            // settings. This enables nested containers (e.g., bcvk) to work in the agent.
            drop_all_caps: false,
            cap_add,
            no_new_privileges: false,
            devices,
            security_opts,
            privileged,
            // Mount volumes:
            // - agent_workspace_volume at /workspaces: agent's own git clone
            // - workspace_volume at /mnt/main-workspace:ro: read-only reference to main workspace
            // - agent_home_volume at AGENT_HOME_PATH: persistent agent state
            // - worker_workspace_volume at /mnt/worker-workspace:ro (when orchestration enabled)
            volume_mounts: {
                let mut mounts = vec![
                    (
                        agent_workspace_volume.to_string(),
                        "/workspaces".to_string(),
                    ),
                    (
                        workspace_volume.to_string(),
                        "/mnt/main-workspace:ro".to_string(),
                    ),
                    (agent_home_volume.to_string(), AGENT_HOME_PATH.to_string()),
                ];
                // When orchestration is enabled, mount worker's workspace read-only
                // so the task owner can access worker's commits via git
                if enable_orchestration {
                    if let Some(worker_vol) = worker_workspace_volume {
                        mounts.push((
                            worker_vol.to_string(),
                            "/mnt/worker-workspace:ro".to_string(),
                        ));
                    }
                }
                mounts
            },
            secrets,
            file_secrets,
            extra_create_args,
            ..Default::default()
        }
    }

    /// Create container config for the gator (service-gator) container
    ///
    /// Runs with minimal privileges as an MCP server.
    /// Receives trusted env vars (GH_TOKEN, etc.) and JWT secrets for dynamic scope configuration.
    ///
    /// Supports two methods for passing credentials:
    /// 1. Environment variables via `[trusted.env]` - forwarded directly
    /// 2. Podman secrets via `[trusted.secrets]` - set directly as env vars using type=env
    ///
    /// Podman secrets are more secure as they avoid credentials in environment variables.
    ///
    /// For dynamic scopes, the server starts with `--scope '{"server":{"mode":"required"}}'`
    /// which requires JWT tokens for all MCP requests. Tokens are minted via the admin API
    /// The agent workspace volume is mounted read-only so tools like `git_push_local` can
    /// access the git repository to read commits for pushing.
    ///
    /// The main workspace volume is also mounted at `/mnt/main-workspace` (read-only) because
    /// the agent's git clone uses alternates pointing there for object sharing.
    ///
    /// The gator config file is read from the workspace volume at /workspaces/.devaipod/gator-config.json.
    /// Gator uses inotify to watch for changes, enabling live scope updates via `devaipod gator add`.
    fn gator_container_config(
        agent_workspace_volume: &str,
        workspace_folder: &str,
        main_workspace_volume: &str,
        global_config: &Config,
    ) -> ContainerConfig {
        let mut env = std::collections::HashMap::new();
        env.insert("HOME".to_string(), "/tmp".to_string());

        // Add trusted env vars (GH_TOKEN, GITLAB_TOKEN, JIRA_API_TOKEN, etc.)
        // These are the credentials that service-gator needs to access external services
        env.extend(global_config.trusted_env.collect());

        // Get secrets to mount with type=env - gator gets only trusted secrets
        // (like GH_TOKEN for forge access). Gator is a forge proxy and doesn't need LLM keys.
        let secrets = global_config.trusted_env.secret_mounts();

        // Get file-based secrets (mounted as files, env var points to path)
        // Used for credentials like GOOGLE_APPLICATION_CREDENTIALS that expect a file path.
        let file_secrets = global_config.trusted_env.file_secret_mounts();

        // The scope config file path inside the gator container
        // Config is at /workspaces/.devaipod/gator-config.json (same path as where it's written)
        let scope_file_path = format!(
            "{}/{}",
            workspace_folder,
            crate::service_gator::GATOR_CONFIG_PATH
        );

        // Build the command args (not including binary name since image has ENTRYPOINT)
        // Use --scope-file for inotify-based live reload of scopes
        // No JWT auth needed - each pod has its own gator instance (not multi-tenant)
        let command = vec![
            "--mcp-server".to_string(),
            format!("0.0.0.0:{}", GATOR_PORT),
            "--scope-file".to_string(),
            scope_file_path,
        ];

        // Mount the agent workspace volume read-only so git_push_local can access commits
        let agent_workspace_mount = format!("{}:ro", workspace_folder);

        ContainerConfig {
            // Mount volumes:
            // 1. Agent workspace at /workspaces - where the agent's commits are (also has gator config)
            // 2. Main workspace at /mnt/main-workspace - for git alternates object sharing
            volume_mounts: vec![
                (agent_workspace_volume.to_string(), agent_workspace_mount),
                (
                    main_workspace_volume.to_string(),
                    "/mnt/main-workspace:ro".to_string(),
                ),
            ],
            env,
            workdir: None,
            user: None,
            command: Some(command),
            // Minimal privileges
            drop_all_caps: true,
            cap_add: vec!["NET_BIND_SERVICE".to_string()],
            no_new_privileges: true,
            secrets,
            file_secrets,
            ..Default::default()
        }
    }

    /// Create container config for the devaipod API sidecar container.
    ///
    /// This container runs `devaipod pod-api` and provides git/PTY REST APIs
    /// for the pod, accessible only within the pod via localhost.
    ///
    /// The container runtime socket is bind-mounted so the sidecar can exec
    /// into the workspace container for PTY sessions. The `socket_path`
    /// parameter is the **host-side** path (resolved via `get_host_socket_path`)
    /// so the host podman can find it when creating the sibling container.
    /// The target is always `/run/docker.sock` so the sidecar's
    /// `get_container_socket()` finds it at the canonical location.
    fn api_container_config(
        agent_workspace_volume: &str,
        main_workspace_volume: &str,
        workspace_container_name: &str,
        agent_container_name: &str,
        socket_path: &std::path::Path,
        opencode_password: &str,
        workspace_folder: &str,
    ) -> ContainerConfig {
        use crate::podman::MountConfig;

        let mut env = std::collections::HashMap::new();
        env.insert("HOME".to_string(), "/tmp".to_string());
        // The workspace volume is bind-mounted and may be owned by a different UID
        // than the pod-api process. Tell git to trust it via environment-based config
        // so `git log`, `git status`, etc. work regardless of ownership.
        env.insert("GIT_CONFIG_COUNT".to_string(), "1".to_string());
        env.insert("GIT_CONFIG_KEY_0".to_string(), "safe.directory".to_string());
        env.insert("GIT_CONFIG_VALUE_0".to_string(), "*".to_string());

        let command = vec![
            "devaipod".to_string(),
            "pod-api".to_string(),
            "--port".to_string(),
            POD_API_PORT.to_string(),
            "--workspace".to_string(),
            workspace_folder.to_string(),
            "--workspace-container".to_string(),
            workspace_container_name.to_string(),
            "--agent-container".to_string(),
            agent_container_name.to_string(),
            "--opencode-password".to_string(),
            opencode_password.to_string(),
        ];

        // Bind-mount the container runtime socket. The source is the
        // host-side path (resolved via mountinfo); the target is the
        // canonical /run/docker.sock so the sidecar finds it.
        let socket_mount = MountConfig {
            source: socket_path.to_string_lossy().to_string(),
            target: "/run/docker.sock".to_string(),
            readonly: false,
        };

        ContainerConfig {
            // Bind mount: container runtime socket for exec-into-workspace PTY.
            mounts: vec![socket_mount],
            // Named volumes:
            // 1. Agent workspace at /workspaces — read-write because git fetch/push
            //    need to update refs and objects.
            // 2. Main workspace at /mnt/main-workspace — read-only for git alternates.
            volume_mounts: vec![
                (
                    agent_workspace_volume.to_string(),
                    "/workspaces".to_string(),
                ),
                (
                    main_workspace_volume.to_string(),
                    "/mnt/main-workspace:ro".to_string(),
                ),
            ],
            env,
            workdir: None,
            user: None,
            command: Some(command),
            // Minimal privileges — drop all capabilities since the only
            // privileged operation is connecting to the container runtime socket
            // (file-permission-based, not capability-based).
            drop_all_caps: true,
            no_new_privileges: true,
            // Disable SELinux labeling so we can access the bind-mounted
            // container runtime socket (which has the host's SELinux context).
            security_opts: vec!["label=disable".to_string()],
            // Healthcheck: verify the HTTP server is responding.
            healthcheck: Some(crate::podman::HealthcheckConfig {
                cmd: vec![
                    "curl".to_string(),
                    "-sf".to_string(),
                    format!("http://localhost:{}/healthz", POD_API_PORT),
                ],
                interval: Some("5s".to_string()),
                retries: Some(3),
                start_period: Some("5s".to_string()),
            }),
            ..Default::default()
        }
    }

    /// Create container config for the worker container
    ///
    /// The worker runs `opencode serve` in a similar configuration to the agent (task owner),
    /// but with different volume mounts reflecting its position in the hierarchy:
    /// - Has its own workspace volume at `/workspaces/<project>` (read-write)
    /// - Mounts task owner's workspace read-only at `/mnt/owner-workspace`
    /// - Mounts main workspace read-only at `/mnt/main-workspace` (for git alternates chain)
    /// - Has git remote `owner` pointing to `/mnt/owner-workspace/<project>`
    ///
    /// The `gator_mode` controls service-gator access:
    /// - `Readonly`: Worker can only read from forge (no PRs, no pushes)
    /// - `Inherit`: Worker gets same gator scopes as task owner
    /// - `None`: Worker has no gator access
    #[allow(clippy::too_many_arguments)]
    fn worker_container_config(
        _project_path: &Path,
        workspace_folder: &str,
        bind_home: &BindHomeConfig,
        _container_home: &str,
        devcontainer_config: Option<&DevcontainerConfig>,
        enable_gator: bool,
        gator_mode: WorkerGatorMode,
        main_workspace_volume: &str,
        owner_workspace_volume: &str,
        worker_workspace_volume: &str,
        worker_home_volume: &str,
        agent_home_volume: &str,
        global_config: &crate::config::Config,
    ) -> ContainerConfig {
        // Worker uses the same home path pattern as the agent
        let worker_home = AGENT_HOME_PATH.to_string();

        let mut env = std::collections::HashMap::new();
        env.insert("HOME".to_string(), worker_home.clone());

        // Ensure worker can find opencode in PATH
        env.insert(
            "PATH".to_string(),
            "/usr/local/bin:/usr/bin:/bin".to_string(),
        );
        // Tell opencode to create its config in the worker home
        env.insert(
            "XDG_CONFIG_HOME".to_string(),
            format!("{worker_home}/.config"),
        );
        env.insert(
            "XDG_DATA_HOME".to_string(),
            format!("{worker_home}/.local/share"),
        );

        // Forward env vars to the worker container (same pattern as agent)
        for (key, value) in std::env::vars() {
            if let Some(stripped) = key.strip_prefix("DEVAIPOD_AGENT_") {
                if !stripped.is_empty() {
                    env.insert(stripped.to_string(), value);
                }
            }
        }

        // Forward env vars from devcontainer.json's customizations.devaipod.env_allowlist
        if let Some(config) = devcontainer_config {
            for (key, value) in config.collect_allowlist_env_vars() {
                env.insert(key, value);
            }
        }

        // Add env vars from global config (allowlist + explicit vars)
        env.extend(global_config.env.collect());

        // Auto-allow all tool permissions so worker never prompts interactively.
        // This is required because the worker is driven programmatically by the task owner
        // via `opencode run --attach` and cannot respond to interactive permission prompts.
        env.insert(
            "OPENCODE_PERMISSION".to_string(),
            r#"{"*":"allow"}"#.to_string(),
        );

        let mounts = vec![];

        // Get security settings from devcontainer config (same as agent)
        let (devices, privileged, security_opts, cap_add, extra_create_args) =
            if let Some(config) = devcontainer_config {
                let mut devices: Vec<String> = DEV_PASSTHROUGH_PATHS
                    .iter()
                    .filter(|path| Path::new(path).exists())
                    .map(|path| path.to_string())
                    .collect();

                collect_config_devices(config, &mut devices);

                // When nestedContainers is set, ignore all security config from
                // devcontainer.json and apply our own minimal set.
                let (privileged, cap_add, security_opts) =
                    if config.has_nested_containers() || global_config.container_nesting {
                        nested_container_security(&mut devices)
                    } else {
                        let privileged = config.privileged || config.has_privileged_run_arg();
                        let mut security_opts = config.security_opt.clone();
                        for opt in config.security_opt_args() {
                            if !security_opts.contains(&opt) {
                                security_opts.push(opt);
                            }
                        }
                        let mut cap_add = config.cap_add.clone();
                        for cap in config.cap_add_args() {
                            if !cap_add.contains(&cap) {
                                cap_add.push(cap);
                            }
                        }
                        (privileged, cap_add, security_opts)
                    };

                let extra_create_args = config.passthrough_run_args();

                (
                    devices,
                    privileged,
                    security_opts,
                    cap_add,
                    extra_create_args,
                )
            } else if global_config.container_nesting {
                let mut devices = vec![];
                let (privileged, cap_add, security_opts) = nested_container_security(&mut devices);
                (devices, privileged, security_opts, cap_add, vec![])
            } else {
                (vec![], false, vec![], vec![], vec![])
            };

        // Handle gcloud ADC path (same as agent)
        const GCLOUD_ADC_PATH: &str = ".config/gcloud/application_default_credentials.json";
        if bind_home.paths.iter().any(|p| p == GCLOUD_ADC_PATH) {
            if let Some(host_home) = get_host_home() {
                if host_home.join(GCLOUD_ADC_PATH).exists() {
                    env.insert(
                        "GOOGLE_APPLICATION_CREDENTIALS".to_string(),
                        format!("{}/{}", worker_home, GCLOUD_ADC_PATH),
                    );
                }
            }
        }

        // Build MCP config combining service-gator and any additional MCP servers
        let mut mcp_servers = serde_json::Map::new();

        // Configure service-gator access based on gator_mode
        if enable_gator && gator_mode != WorkerGatorMode::None {
            // Worker gets access to service-gator MCP server
            // Note: The actual scope restrictions (readonly vs inherit) are enforced
            // by the gator container's scope configuration, not here.
            // For now, both Readonly and Inherit connect to the same gator instance.
            // Future: could use different gator instances or JWT scopes.
            mcp_servers.insert(
                "service-gator".to_string(),
                serde_json::json!({
                    "type": "remote",
                    "url": format!("http://localhost:{}/mcp", GATOR_PORT),
                    "enabled": true
                }),
            );
            tracing::debug!(
                "Worker gator mode: {:?} - connecting to service-gator",
                gator_mode
            );
        }

        // Add any additional MCP servers from config
        for (name, entry) in global_config.mcp.enabled_servers() {
            let mut server_json = serde_json::json!({
                "type": "remote",
                "url": entry.url,
                "enabled": true
            });
            if !entry.headers.is_empty() {
                server_json["headers"] = serde_json::json!(entry.headers);
            }
            mcp_servers.insert(name.to_string(), server_json);
        }

        if !mcp_servers.is_empty() {
            let mcp_config = serde_json::json!({
                "mcp": mcp_servers
            });
            env.insert(
                "OPENCODE_CONFIG_CONTENT".to_string(),
                mcp_config.to_string(),
            );
        }

        // Worker startup script - runs opencode serve
        // Wait for agent setup to complete, then copy configs from agent home.
        let startup_script = format!(
            r#"set -e
mkdir -p {home}/.config {home}/.local/share {home}/.local/bin {home}/.cache

# Wait for agent setup (dotfiles, task config) to complete before copying configs.
# The state file is written by devaipod after install_dotfiles_agent().
echo "Waiting for agent setup to complete..."
while [ ! -f /mnt/agent-home/.devaipod-state.json ]; do
    sleep 0.1
done
echo "Agent setup complete, copying configs..."

# Copy essential config from agent home (now guaranteed to be installed)

# Copy LLM provider credentials
if [ -d /mnt/agent-home/.config/gcloud ]; then
    cp -r /mnt/agent-home/.config/gcloud {home}/.config/
fi

# Copy opencode config
if [ -d /mnt/agent-home/.config/opencode ]; then
    cp -r /mnt/agent-home/.config/opencode {home}/.config/
fi

# Use worker-specific task file if available (omits orchestration instructions
# since the worker is the leaf executor, not an orchestrator)
if [ -f /mnt/agent-home/.config/opencode/devaipod-task-worker.md ]; then
    cp /mnt/agent-home/.config/opencode/devaipod-task-worker.md \
       {home}/.config/opencode/devaipod-task.md
fi

# Copy git identity
if [ -f /mnt/agent-home/.gitconfig ]; then
    cp /mnt/agent-home/.gitconfig {home}/.gitconfig
fi

# Run opencode serve in foreground
exec opencode serve --port {opencode_port} --hostname 127.0.0.1"#,
            home = AGENT_HOME_PATH,
            opencode_port = WORKER_OPENCODE_PORT // Worker uses a different port to avoid conflict with agent
        );

        ContainerConfig {
            mounts,
            env,
            workdir: Some(workspace_folder.to_string()),
            user: None,
            command: Some(vec![
                "/bin/sh".to_string(),
                "-c".to_string(),
                startup_script,
            ]),
            // Security settings match agent/workspace container
            drop_all_caps: false,
            cap_add,
            no_new_privileges: false,
            devices,
            security_opts,
            privileged,
            extra_create_args,
            // Mount volumes:
            // - worker_workspace_volume at /workspaces: worker's own git clone (read-write)
            // - owner_workspace_volume at /mnt/owner-workspace:ro: task owner's workspace
            // - main_workspace_volume at /mnt/main-workspace:ro: human's workspace (for alternates chain)
            // - worker_home_volume at AGENT_HOME_PATH: worker's own home (read-write)
            // - agent_home_volume at /mnt/agent-home:ro: agent's home for LLM credentials
            volume_mounts: vec![
                (
                    worker_workspace_volume.to_string(),
                    "/workspaces".to_string(),
                ),
                (
                    owner_workspace_volume.to_string(),
                    "/mnt/owner-workspace:ro".to_string(),
                ),
                (
                    main_workspace_volume.to_string(),
                    "/mnt/main-workspace:ro".to_string(),
                ),
                (
                    worker_home_volume.to_string(),
                    AGENT_HOME_PATH.to_string(), // Worker's own home, read-write
                ),
                (
                    agent_home_volume.to_string(),
                    "/mnt/agent-home:ro".to_string(), // Agent's home for LLM credentials
                ),
            ],
            ..Default::default()
        }
    }

    /// Resolve the container home directory based on the effective user
    ///
    /// Most devcontainer images use a non-root user like "vscode" or "devenv"
    /// with a home directory at /home/<user>. This function determines
    /// the correct home directory for bind mounts based on the user.
    fn resolve_container_home_for_user(user: Option<&str>) -> String {
        match user {
            Some("root") => "/root".to_string(),
            Some(user) => format!("/home/{}", user),
            // If no user specified, default to /home/user as a reasonable guess
            // (this shouldn't happen in practice since we query the image)
            None => "/home/user".to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_workspace_container_config() {
        let project_path = Path::new("/home/user/myproject");
        let workspace_folder = "/workspaces/myproject";
        let config = DevcontainerConfig::default();
        let bind_home = BindHomeConfig::default();
        let container_home = "/home/vscode";

        let volume_name = "test-volume";
        let global_config = crate::config::Config::default();
        let container_config = DevaipodPod::workspace_container_config(
            project_path,
            workspace_folder,
            Some("vscode"),
            &config,
            &bind_home,
            container_home,
            volume_name,
            "test-agent-home",
            "test-agent-workspace",
            &global_config,
            &[], // labels
        );

        // Volume mounts for workspace (2x), agent home, and agent workspace
        assert_eq!(container_config.volume_mounts.len(), 4);
        assert_eq!(container_config.volume_mounts[0].0, "test-volume");
        assert_eq!(container_config.volume_mounts[0].1, "/workspaces");
        // Same volume mounted at /mnt/main-workspace for git alternates resolution
        assert_eq!(container_config.volume_mounts[1].0, "test-volume");
        assert_eq!(
            container_config.volume_mounts[1].1,
            "/mnt/main-workspace:ro"
        );
        assert_eq!(container_config.volume_mounts[2].0, "test-agent-home");
        assert_eq!(container_config.volume_mounts[2].1, "/opt/devaipod:ro");
        assert_eq!(container_config.volume_mounts[3].0, "test-agent-workspace");
        assert_eq!(
            container_config.volume_mounts[3].1,
            "/mnt/agent-workspace:ro"
        );
        assert_eq!(container_config.user, Some("vscode".to_string()));
        // workdir is set to the workspace folder
        assert_eq!(
            container_config.workdir,
            Some("/workspaces/myproject".to_string())
        );
        // Verify command is a shell script that creates shim and runs monitor
        let cmd = container_config.command.as_ref().unwrap();
        assert_eq!(cmd[0], "/bin/sh");
        assert_eq!(cmd[1], "-c");
        assert!(cmd[2].contains("opencode-connect")); // Creates shim
        assert!(cmd[2].contains("opencode attach")); // Shim uses attach
        assert!(cmd[2].contains(&format!("http://localhost:{}", OPENCODE_PORT)));
        assert!(cmd[2].contains("sleep infinity")); // Keeps container running
        assert!(!container_config.drop_all_caps);
        assert!(!container_config.no_new_privileges);
    }

    #[test]
    fn test_workspace_container_config_with_labels() {
        let project_path = Path::new("/home/user/myproject");
        let workspace_folder = "/workspaces/myproject";
        let config = DevcontainerConfig::default();
        let bind_home = BindHomeConfig::default();
        let container_home = "/home/vscode";
        let volume_name = "test-volume";
        let global_config = crate::config::Config::default();

        // Test with labels
        let labels = vec![
            (
                "io.devaipod.repo".to_string(),
                "github.com/owner/repo".to_string(),
            ),
            ("io.devaipod.task".to_string(), "Fix the bug".to_string()),
            ("io.devaipod.mode".to_string(), "run".to_string()),
        ];

        let container_config = DevaipodPod::workspace_container_config(
            project_path,
            workspace_folder,
            Some("vscode"),
            &config,
            &bind_home,
            container_home,
            volume_name,
            "test-agent-home",
            "test-agent-workspace",
            &global_config,
            &labels,
        );

        // Verify labels are propagated to the container config
        assert_eq!(container_config.labels.len(), 3);
        assert_eq!(
            container_config.labels.get("io.devaipod.repo"),
            Some(&"github.com/owner/repo".to_string())
        );
        assert_eq!(
            container_config.labels.get("io.devaipod.task"),
            Some(&"Fix the bug".to_string())
        );
        assert_eq!(
            container_config.labels.get("io.devaipod.mode"),
            Some(&"run".to_string())
        );
    }

    #[test]
    fn test_agent_container_config() {
        let project_path = Path::new("/home/user/myproject");
        let workspace_folder = "/workspaces/myproject";
        let bind_home = BindHomeConfig::default();
        let container_home = "/home/vscode";

        let global_config = crate::config::Config::default();
        let container_config = DevaipodPod::agent_container_config(
            project_path,
            workspace_folder,
            &bind_home,
            container_home,
            None,
            false,                  // enable_gator
            false,                  // enable_orchestration
            "test-main-workspace",  // main workspace (read-only reference)
            "test-agent-workspace", // agent's own workspace clone
            "test-agent-home",
            None, // worker_workspace_volume (no orchestration)
            &global_config,
        );

        // Volume mounts: agent workspace, main workspace (readonly), and agent home
        assert_eq!(container_config.volume_mounts.len(), 3);
        // Agent's own workspace at /workspaces
        assert_eq!(container_config.volume_mounts[0].0, "test-agent-workspace");
        assert_eq!(container_config.volume_mounts[0].1, "/workspaces");
        // Main workspace as read-only reference
        assert_eq!(container_config.volume_mounts[1].0, "test-main-workspace");
        assert_eq!(
            container_config.volume_mounts[1].1,
            "/mnt/main-workspace:ro"
        );
        // Agent home for persistent state
        assert_eq!(container_config.volume_mounts[2].0, "test-agent-home");
        assert_eq!(container_config.volume_mounts[2].1, AGENT_HOME_PATH);

        // Verify command wraps opencode in a shell to create home dir
        let cmd = container_config.command.as_ref().unwrap();
        assert_eq!(cmd[0], "/bin/sh");
        assert_eq!(cmd[1], "-c");
        assert!(cmd[2].contains("opencode serve"));
        assert!(cmd[2].contains(&format!("--port {}", OPENCODE_PORT)));

        // Agent has the same security settings as workspace (not restricted)
        // to support nested containers. Security comes from credential isolation.
        assert!(!container_config.drop_all_caps);
        assert!(!container_config.no_new_privileges);
        // When no devcontainer_config is provided, cap_add is empty
        assert!(container_config.cap_add.is_empty());

        // Verify HOME is NOT overridden (it comes from passwd entry for devenv user)
        assert_eq!(container_config.env.get("HOME"), None);
    }

    #[test]
    fn test_agent_container_config_with_orchestration() {
        // Test that agent container mounts worker workspace when orchestration is enabled
        let project_path = Path::new("/home/user/myproject");
        let workspace_folder = "/workspaces/myproject";
        let bind_home = BindHomeConfig::default();
        let container_home = "/home/vscode";

        let global_config = crate::config::Config::default();
        let container_config = DevaipodPod::agent_container_config(
            project_path,
            workspace_folder,
            &bind_home,
            container_home,
            None,
            false,                  // enable_gator
            true,                   // enable_orchestration
            "test-main-workspace",  // main workspace (read-only reference)
            "test-agent-workspace", // agent's own workspace clone
            "test-agent-home",
            Some("test-worker-workspace"), // worker_workspace_volume
            &global_config,
        );

        // With orchestration enabled, should have 4 volume mounts:
        // 1. Agent workspace at /workspaces
        // 2. Main workspace at /mnt/main-workspace:ro
        // 3. Agent home at AGENT_HOME_PATH
        // 4. Worker workspace at /mnt/worker-workspace:ro
        assert_eq!(container_config.volume_mounts.len(), 4);
        assert_eq!(container_config.volume_mounts[0].0, "test-agent-workspace");
        assert_eq!(container_config.volume_mounts[0].1, "/workspaces");
        assert_eq!(container_config.volume_mounts[1].0, "test-main-workspace");
        assert_eq!(
            container_config.volume_mounts[1].1,
            "/mnt/main-workspace:ro"
        );
        assert_eq!(container_config.volume_mounts[2].0, "test-agent-home");
        assert_eq!(container_config.volume_mounts[2].1, AGENT_HOME_PATH);
        assert_eq!(container_config.volume_mounts[3].0, "test-worker-workspace");
        assert_eq!(
            container_config.volume_mounts[3].1,
            "/mnt/worker-workspace:ro"
        );

        // With orchestration enabled, agent should have OPENCODE_WORKER_URL set
        assert!(
            container_config.env.contains_key("OPENCODE_WORKER_URL"),
            "Agent container should have OPENCODE_WORKER_URL when orchestration is enabled"
        );
        assert_eq!(
            container_config.env.get("OPENCODE_WORKER_URL").unwrap(),
            &format!("http://localhost:{}", WORKER_OPENCODE_PORT)
        );
    }

    #[test]
    fn test_agent_bind_home_uses_podman_cp() {
        // Test that agent container config doesn't include bind_home mounts
        // (we use podman cp after container starts instead)
        let project_path = Path::new("/home/user/myproject");
        let workspace_folder = "/workspaces/myproject";
        let bind_home = BindHomeConfig {
            paths: vec![".config/some-app".to_string()],
            readonly: true,
        };
        let container_home = "/home/vscode";

        let global_config = crate::config::Config::default();
        let container_config = DevaipodPod::agent_container_config(
            project_path,
            workspace_folder,
            &bind_home,
            container_home,
            None,
            false, // enable_gator
            false, // enable_orchestration
            "test-main-workspace",
            "test-agent-workspace",
            "test-agent-home",
            None, // worker_workspace_volume
            &global_config,
        );

        // No bind mounts - we clone the repo into the container instead
        // bind_home files are copied using podman cp after container starts
        assert!(
            container_config.mounts.is_empty(),
            "Agent should have no mounts (we clone instead), got {} mounts",
            container_config.mounts.len()
        );
    }

    #[test]
    fn test_agent_container_config_with_file_secrets() {
        // Test that file-based secrets are passed to agent container
        let project_path = Path::new("/home/user/myproject");
        let workspace_folder = "/workspaces/myproject";
        let bind_home = BindHomeConfig::default();
        let container_home = "/home/vscode";

        let mut global_config = crate::config::Config::default();
        global_config.trusted_env.file_secrets =
            vec!["GOOGLE_APPLICATION_CREDENTIALS=gcloud_adc".to_string()];

        let container_config = DevaipodPod::agent_container_config(
            project_path,
            workspace_folder,
            &bind_home,
            container_home,
            None,
            false,                  // enable_gator
            false,                  // enable_orchestration
            "test-main-workspace",  // main workspace (read-only reference)
            "test-agent-workspace", // agent's own workspace clone
            "test-agent-home",
            None, // worker_workspace_volume (no orchestration)
            &global_config,
        );

        // Verify file_secrets are included for agent container
        assert_eq!(container_config.file_secrets.len(), 1);
        assert!(container_config.file_secrets.contains(&(
            "GOOGLE_APPLICATION_CREDENTIALS".to_string(),
            "gcloud_adc".to_string()
        )));
    }

    #[test]
    fn test_gator_container_config() {
        let agent_workspace_volume = "test-agent-workspace";
        let workspace_folder = "/workspaces";
        let main_workspace_volume = "test-main-workspace";
        let global_config = crate::config::Config::default();
        let container_config = DevaipodPod::gator_container_config(
            agent_workspace_volume,
            workspace_folder,
            main_workspace_volume,
            &global_config,
        );

        // Verify two volumes are mounted read-only
        assert_eq!(container_config.volume_mounts.len(), 2);
        // Agent workspace at /workspaces (also contains gator config)
        assert_eq!(container_config.volume_mounts[0].0, "test-agent-workspace");
        assert_eq!(container_config.volume_mounts[0].1, "/workspaces:ro");
        // Main workspace at /mnt/main-workspace (for git alternates)
        assert_eq!(container_config.volume_mounts[1].0, "test-main-workspace");
        assert_eq!(
            container_config.volume_mounts[1].1,
            "/mnt/main-workspace:ro"
        );

        // Verify command uses --scope-file for inotify-based live reload
        let cmd = container_config.command.as_ref().unwrap();
        assert_eq!(cmd[0], "--mcp-server");
        assert!(cmd.iter().any(|s| s.contains(&GATOR_PORT.to_string())));
        assert!(cmd.contains(&"--scope-file".to_string()));
        assert!(cmd
            .iter()
            .any(|s| s.contains(crate::service_gator::GATOR_CONFIG_PATH)));

        // Verify security restrictions
        assert!(container_config.drop_all_caps);
        assert!(container_config.no_new_privileges);
        assert_eq!(
            container_config.cap_add,
            vec!["NET_BIND_SERVICE".to_string()]
        );
    }

    #[test]
    fn test_api_container_config() {
        let agent_workspace_volume = "test-agent-workspace";
        let main_workspace_volume = "test-main-workspace";
        let workspace_container = "devaipod-test-workspace";
        let agent_container = "devaipod-test-agent";
        // Simulate a host-side socket path (as resolved by get_host_socket_path)
        let socket_path = std::path::Path::new("/run/user/1000/podman/podman.sock");
        let container_config = DevaipodPod::api_container_config(
            agent_workspace_volume,
            main_workspace_volume,
            workspace_container,
            agent_container,
            socket_path,
            "test-password-123",
            "/workspaces/bootc",
        );

        // Verify two named volumes are mounted
        assert_eq!(container_config.volume_mounts.len(), 2);
        // Agent workspace at /workspaces — read-write for git fetch/push
        assert_eq!(container_config.volume_mounts[0].0, "test-agent-workspace");
        assert_eq!(container_config.volume_mounts[0].1, "/workspaces");
        // Main workspace at /mnt/main-workspace (read-only for git alternates)
        assert_eq!(container_config.volume_mounts[1].0, "test-main-workspace");
        assert_eq!(
            container_config.volume_mounts[1].1,
            "/mnt/main-workspace:ro"
        );

        // Verify socket bind mount: source is the host path, target is canonical
        assert_eq!(container_config.mounts.len(), 1);
        assert_eq!(
            container_config.mounts[0].source,
            "/run/user/1000/podman/podman.sock"
        );
        assert_eq!(container_config.mounts[0].target, "/run/docker.sock");

        // Verify command runs pod-api with workspace container name and correct workspace path
        let cmd = container_config.command.as_ref().unwrap();
        assert_eq!(cmd[0], "devaipod");
        assert_eq!(cmd[1], "pod-api");
        assert!(cmd.contains(&"--port".to_string()));
        assert!(cmd.contains(&POD_API_PORT.to_string()));
        assert!(cmd.contains(&"--workspace-container".to_string()));
        assert!(cmd.contains(&workspace_container.to_string()));
        assert!(cmd.contains(&"--agent-container".to_string()));
        assert!(cmd.contains(&agent_container.to_string()));
        // Workspace path must be the full path to the git repo, not just /workspaces
        let ws_idx = cmd.iter().position(|a| a == "--workspace").unwrap();
        assert_eq!(cmd[ws_idx + 1], "/workspaces/bootc");

        // Verify security restrictions
        assert!(container_config.drop_all_caps);
        assert!(container_config.no_new_privileges);
    }

    #[test]
    fn test_gator_container_config_with_secrets() {
        let agent_workspace_volume = "test-agent-workspace";
        let workspace_folder = "/workspaces";
        let main_workspace_volume = "test-main-workspace";
        let mut global_config = crate::config::Config::default();
        global_config.trusted_env.secrets = vec![
            "GH_TOKEN=gh_token".to_string(),
            "GITLAB_TOKEN=gitlab_token".to_string(),
        ];

        let container_config = DevaipodPod::gator_container_config(
            agent_workspace_volume,
            workspace_folder,
            main_workspace_volume,
            &global_config,
        );

        // Verify secrets are listed for mounting as (env_var, secret_name) tuples
        assert_eq!(container_config.secrets.len(), 2);
        assert!(container_config
            .secrets
            .contains(&("GH_TOKEN".to_string(), "gh_token".to_string())));
        assert!(container_config
            .secrets
            .contains(&("GITLAB_TOKEN".to_string(), "gitlab_token".to_string())));

        // No *_FILE env vars with the new type=env approach
        assert!(!container_config.env.contains_key("GH_TOKEN_FILE"));
        assert!(!container_config.env.contains_key("GITLAB_TOKEN_FILE"));
    }

    #[test]
    fn test_gator_container_config_with_secrets_and_env() {
        // Test that both secrets and regular env vars work together
        let agent_workspace_volume = "test-agent-workspace";
        let workspace_folder = "/workspaces";
        let main_workspace_volume = "test-main-workspace";
        let mut global_config = crate::config::Config::default();

        // Add a secret
        global_config.trusted_env.secrets = vec!["GH_TOKEN=gh_token".to_string()];

        // Add a regular trusted env var
        global_config
            .trusted_env
            .env
            .vars
            .insert("JIRA_API_TOKEN".to_string(), "jira_value".to_string());

        let container_config = DevaipodPod::gator_container_config(
            agent_workspace_volume,
            workspace_folder,
            main_workspace_volume,
            &global_config,
        );

        // Verify secret is listed as (env_var, secret_name) tuple
        assert_eq!(container_config.secrets.len(), 1);
        assert!(container_config
            .secrets
            .contains(&("GH_TOKEN".to_string(), "gh_token".to_string())));

        // No *_FILE env var with type=env approach
        assert!(!container_config.env.contains_key("GH_TOKEN_FILE"));

        // Verify regular env var is also present
        assert_eq!(
            container_config.env.get("JIRA_API_TOKEN"),
            Some(&"jira_value".to_string())
        );
    }

    #[test]
    fn test_gator_container_config_with_file_secrets() {
        // Test that file-based secrets are passed to gator container
        let agent_workspace_volume = "test-agent-workspace";
        let workspace_folder = "/workspaces";
        let main_workspace_volume = "test-main-workspace";
        let mut global_config = crate::config::Config::default();
        global_config.trusted_env.file_secrets =
            vec!["GOOGLE_APPLICATION_CREDENTIALS=gcloud_adc".to_string()];

        let container_config = DevaipodPod::gator_container_config(
            agent_workspace_volume,
            workspace_folder,
            main_workspace_volume,
            &global_config,
        );

        // Verify file_secrets are listed as (env_var, secret_name) tuples
        assert_eq!(container_config.file_secrets.len(), 1);
        assert!(container_config.file_secrets.contains(&(
            "GOOGLE_APPLICATION_CREDENTIALS".to_string(),
            "gcloud_adc".to_string()
        )));
    }

    #[test]
    fn test_workspace_container_config_with_file_secrets() {
        // Test that file-based secrets are passed to workspace container
        let project_path = Path::new("/project");
        let workspace_folder = "/workspaces/project";
        let config = DevcontainerConfig::default();
        let bind_home = BindHomeConfig::default();
        let container_home = "/home/vscode";

        let mut global_config = crate::config::Config::default();
        global_config.trusted_env.file_secrets =
            vec!["GOOGLE_APPLICATION_CREDENTIALS=gcloud_adc".to_string()];

        let container_config = DevaipodPod::workspace_container_config(
            project_path,
            workspace_folder,
            None,
            &config,
            &bind_home,
            container_home,
            "test-volume",
            "test-agent-home",
            "test-agent-workspace",
            &global_config,
            &[], // labels
        );

        // Verify file_secrets are included for workspace container
        assert_eq!(container_config.file_secrets.len(), 1);
        assert!(container_config.file_secrets.contains(&(
            "GOOGLE_APPLICATION_CREDENTIALS".to_string(),
            "gcloud_adc".to_string()
        )));
    }

    #[test]
    fn test_pod_container_names() {
        // Verify naming convention
        let pod_name = "test-project";
        let workspace = format!("{}-workspace", pod_name);
        let agent = format!("{}-agent", pod_name);
        let gator = format!("{}-gator", pod_name);

        assert_eq!(workspace, "test-project-workspace");
        assert_eq!(agent, "test-project-agent");
        assert_eq!(gator, "test-project-gator");
    }

    #[test]
    fn test_constants() {
        assert_eq!(OPENCODE_PORT, 4096);
        assert_eq!(GATOR_PORT, 8765);
        assert_eq!(GATOR_IMAGE, "ghcr.io/cgwalters/service-gator:latest");
    }

    #[test]
    fn test_dev_passthrough_paths() {
        // Verify the device passthrough paths are what we expect
        assert!(DEV_PASSTHROUGH_PATHS.contains(&"/dev/fuse"));
        assert!(DEV_PASSTHROUGH_PATHS.contains(&"/dev/net/tun"));
        assert!(DEV_PASSTHROUGH_PATHS.contains(&"/dev/kvm"));
        assert_eq!(DEV_PASSTHROUGH_PATHS.len(), 3);
    }

    #[test]
    fn test_workspace_config_devices_detection() {
        // This test verifies that the workspace container config will include
        // devices from DEV_PASSTHROUGH_PATHS if they exist on the host.
        // We can't guarantee which devices exist, but we can test that the
        // devices field only contains paths that actually exist.
        let project_path = Path::new("/project");
        let workspace_folder = "/workspaces/project";
        let config = DevcontainerConfig::default();
        let bind_home = BindHomeConfig::default();
        let container_home = "/home/vscode";

        let global_config = crate::config::Config::default();
        let container_config = DevaipodPod::workspace_container_config(
            project_path,
            workspace_folder,
            None,
            &config,
            &bind_home,
            container_home,
            "test-volume",
            "test-agent-home",
            "test-agent-workspace",
            &global_config,
            &[], // labels
        );

        // All devices in the config should actually exist on the host
        for device in &container_config.devices {
            assert!(
                Path::new(device).exists(),
                "Device {} is in config but doesn't exist on host",
                device
            );
        }

        // All devices should be from our passthrough list
        for device in &container_config.devices {
            assert!(
                DEV_PASSTHROUGH_PATHS.contains(&device.as_str()),
                "Device {} not in DEV_PASSTHROUGH_PATHS",
                device
            );
        }
    }

    #[test]
    fn test_workspace_config_with_env() {
        let project_path = Path::new("/project");
        let workspace_folder = "/workspaces/project";
        let bind_home = BindHomeConfig::default();
        let container_home = "/home/vscode";

        let mut config = DevcontainerConfig::default();
        config
            .container_env
            .insert("FOO".to_string(), "bar".to_string());
        config
            .remote_env
            .insert("BAZ".to_string(), "qux".to_string());

        let global_config = crate::config::Config::default();
        let container_config = DevaipodPod::workspace_container_config(
            project_path,
            workspace_folder,
            None,
            &config,
            &bind_home,
            container_home,
            "test-volume",
            "test-agent-home",
            "test-agent-workspace",
            &global_config,
            &[], // labels
        );

        assert_eq!(container_config.env.get("FOO"), Some(&"bar".to_string()));
        assert_eq!(container_config.env.get("BAZ"), Some(&"qux".to_string()));
        // Verify agent URL is always set
        assert_eq!(
            container_config.env.get("OPENCODE_AGENT_URL"),
            Some(&format!("http://localhost:{}", OPENCODE_PORT))
        );
    }

    #[test]
    fn test_workspace_container_config_with_secrets() {
        // Workspace container should get trusted secrets for authenticated git, gh CLI, etc.
        let project_path = Path::new("/project");
        let workspace_folder = "/workspaces/project";
        let config = DevcontainerConfig::default();
        let bind_home = BindHomeConfig::default();
        let container_home = "/home/vscode";

        let mut global_config = crate::config::Config::default();
        global_config.trusted_env.secrets = vec![
            "GH_TOKEN=gh_token".to_string(),
            "GITLAB_TOKEN=gitlab_token".to_string(),
        ];

        let container_config = DevaipodPod::workspace_container_config(
            project_path,
            workspace_folder,
            None,
            &config,
            &bind_home,
            container_home,
            "test-volume",
            "test-agent-home",
            "test-agent-workspace",
            &global_config,
            &[], // labels
        );

        // Verify secrets are included for workspace container
        assert_eq!(container_config.secrets.len(), 2);
        assert!(container_config
            .secrets
            .contains(&("GH_TOKEN".to_string(), "gh_token".to_string())));
        assert!(container_config
            .secrets
            .contains(&("GITLAB_TOKEN".to_string(), "gitlab_token".to_string())));
    }

    #[test]
    fn test_agent_container_does_not_get_secrets() {
        // Agent container should NOT get trusted secrets (security: secrets stay out of agent)
        let project_path = Path::new("/project");
        let workspace_folder = "/workspaces/project";
        let bind_home = BindHomeConfig::default();
        let container_home = "/home/vscode";

        let mut global_config = crate::config::Config::default();
        global_config.trusted_env.secrets = vec!["GH_TOKEN=gh_token".to_string()];

        let container_config = DevaipodPod::agent_container_config(
            project_path,
            workspace_folder,
            &bind_home,
            container_home,
            None,
            false, // enable_gator
            false, // enable_orchestration
            "test-main-workspace",
            "test-agent-workspace",
            "test-agent-home",
            None, // worker_workspace_volume
            &global_config,
        );

        // Agent should have no secrets
        assert!(
            container_config.secrets.is_empty(),
            "Agent should not receive trusted secrets for security"
        );
    }

    #[test]
    fn test_resolve_env_value_no_variable() {
        // Simple values without variables pass through unchanged
        assert_eq!(
            super::resolve_env_value("/usr/bin:/usr/local/bin", "PATH"),
            Some("/usr/bin:/usr/local/bin".to_string())
        );
        assert_eq!(
            super::resolve_env_value("simple_value", "OTHER"),
            Some("simple_value".to_string())
        );
    }

    #[test]
    fn test_resolve_env_value_extracts_suffix() {
        // Pattern like ${containerEnv:PATH}:/additional/path should prepend default PATH
        // when the variable is PATH, to ensure essential utilities are available
        assert_eq!(
            super::resolve_env_value("${containerEnv:PATH}:/usr/local/cargo/bin", "PATH"),
            Some(format!(
                "{}:/usr/local/cargo/bin",
                super::DEFAULT_CONTAINER_PATH
            ))
        );
        // Multiple path components in suffix
        assert_eq!(
            super::resolve_env_value("${containerEnv:PATH}:/foo:/bar:/baz", "PATH"),
            Some(format!("{}:/foo:/bar:/baz", super::DEFAULT_CONTAINER_PATH))
        );
        // For non-PATH variables, just extract the suffix
        assert_eq!(
            super::resolve_env_value("${containerEnv:OTHER}:/some/path", "OTHER"),
            Some("/some/path".to_string())
        );
    }

    #[test]
    fn test_resolve_env_value_unresolvable() {
        // Pure variable reference with no static suffix
        assert_eq!(
            super::resolve_env_value("${containerEnv:PATH}", "PATH"),
            None
        );
        // Variable reference with empty suffix
        assert_eq!(
            super::resolve_env_value("${containerEnv:PATH}:", "PATH"),
            None
        );
        // Suffix that also contains variable references
        assert_eq!(
            super::resolve_env_value("${containerEnv:PATH}:${localEnv:HOME}", "PATH"),
            None
        );
    }

    #[test]
    fn test_workspace_config_resolves_env_with_suffix() {
        let project_path = Path::new("/project");
        let workspace_folder = "/workspaces/project";
        let bind_home = BindHomeConfig::default();
        let container_home = "/home/vscode";

        let mut config = DevcontainerConfig::default();
        // This is the pattern from bootc's devcontainer.json
        config.remote_env.insert(
            "PATH".to_string(),
            "${containerEnv:PATH}:/usr/local/cargo/bin".to_string(),
        );
        // A simple env var that should pass through
        config
            .remote_env
            .insert("SIMPLE".to_string(), "value".to_string());

        let global_config = crate::config::Config::default();
        let container_config = DevaipodPod::workspace_container_config(
            project_path,
            workspace_folder,
            None,
            &config,
            &bind_home,
            container_home,
            "test-volume",
            "test-agent-home",
            "test-agent-workspace",
            &global_config,
            &[], // labels
        );

        // PATH should include default PATH plus the suffix from devcontainer.json
        assert_eq!(
            container_config.env.get("PATH"),
            Some(&format!("{}:/usr/local/cargo/bin", DEFAULT_CONTAINER_PATH))
        );
        // Simple var should pass through unchanged
        assert_eq!(
            container_config.env.get("SIMPLE"),
            Some(&"value".to_string())
        );
    }

    #[test]
    fn test_workspace_config_skips_unresolvable_env() {
        let project_path = Path::new("/project");
        let workspace_folder = "/workspaces/project";
        let bind_home = BindHomeConfig::default();
        let container_home = "/home/vscode";

        let mut config = DevcontainerConfig::default();
        // Pure variable reference with no suffix - can't be resolved
        config.remote_env.insert(
            "UNRESOLVABLE".to_string(),
            "${containerEnv:SOME_VAR}".to_string(),
        );
        // A simple env var that should pass through
        config
            .remote_env
            .insert("SIMPLE".to_string(), "value".to_string());

        let global_config = crate::config::Config::default();
        let container_config = DevaipodPod::workspace_container_config(
            project_path,
            workspace_folder,
            None,
            &config,
            &bind_home,
            container_home,
            "test-volume",
            "test-agent-home",
            "test-agent-workspace",
            &global_config,
            &[], // labels
        );

        // UNRESOLVABLE should be skipped
        assert!(
            !container_config.env.contains_key("UNRESOLVABLE"),
            "Unresolvable env var should be skipped"
        );
        // Simple var should pass through unchanged
        assert_eq!(
            container_config.env.get("SIMPLE"),
            Some(&"value".to_string())
        );
    }

    #[test]
    fn test_workspace_config_with_caps() {
        let project_path = Path::new("/project");
        let workspace_folder = "/workspaces/project";
        let bind_home = BindHomeConfig::default();
        let container_home = "/home/vscode";

        let mut config = DevcontainerConfig::default();
        config.cap_add = vec!["SYS_PTRACE".to_string()];

        let global_config = crate::config::Config::default();
        let container_config = DevaipodPod::workspace_container_config(
            project_path,
            workspace_folder,
            None,
            &config,
            &bind_home,
            container_home,
            "test-volume",
            "test-agent-home",
            "test-agent-workspace",
            &global_config,
            &[], // labels
        );

        assert_eq!(container_config.cap_add, vec!["SYS_PTRACE".to_string()]);
    }

    #[test]
    fn test_workspace_config_with_caps_from_run_args() {
        let project_path = Path::new("/project");
        let workspace_folder = "/workspaces/project";
        let bind_home = BindHomeConfig::default();
        let container_home = "/home/vscode";

        let mut config = DevcontainerConfig::default();
        // Set capAdd structured field AND --cap-add in runArgs
        config.cap_add = vec!["SYS_PTRACE".to_string()];
        config.run_args = vec!["--cap-add=ALL".to_string()];

        let global_config = crate::config::Config::default();
        let container_config = DevaipodPod::workspace_container_config(
            project_path,
            workspace_folder,
            None,
            &config,
            &bind_home,
            container_home,
            "test-volume",
            "test-agent-home",
            "test-agent-workspace",
            &global_config,
            &[], // labels
        );

        // Both capAdd and --cap-add from runArgs should be merged
        assert!(container_config.cap_add.contains(&"SYS_PTRACE".to_string()));
        assert!(container_config.cap_add.contains(&"ALL".to_string()));
        assert_eq!(container_config.cap_add.len(), 2);
    }

    #[test]
    fn test_workspace_config_with_caps_dedup() {
        let project_path = Path::new("/project");
        let workspace_folder = "/workspaces/project";
        let bind_home = BindHomeConfig::default();
        let container_home = "/home/vscode";

        let mut config = DevcontainerConfig::default();
        // Same capability in both sources should be deduplicated
        config.cap_add = vec!["SYS_ADMIN".to_string()];
        config.run_args = vec!["--cap-add=SYS_ADMIN".to_string()];

        let global_config = crate::config::Config::default();
        let container_config = DevaipodPod::workspace_container_config(
            project_path,
            workspace_folder,
            None,
            &config,
            &bind_home,
            container_home,
            "test-volume",
            "test-agent-home",
            "test-agent-workspace",
            &global_config,
            &[], // labels
        );

        // Should be deduplicated
        assert_eq!(container_config.cap_add, vec!["SYS_ADMIN".to_string()]);
    }

    #[test]
    fn test_dotfiles_config_struct() {
        // Test that DotfilesConfig can be created and accessed
        let dotfiles = DotfilesConfig {
            url: "https://github.com/user/dotfiles".to_string(),
            script: Some("install.sh".to_string()),
        };
        assert_eq!(dotfiles.url, "https://github.com/user/dotfiles");
        assert_eq!(dotfiles.script, Some("install.sh".to_string()));

        // Test without script
        let dotfiles_no_script = DotfilesConfig {
            url: "https://github.com/user/dotfiles".to_string(),
            script: None,
        };
        assert!(dotfiles_no_script.script.is_none());
    }

    #[test]
    fn test_workspace_config_with_run_args_privileged() {
        let project_path = Path::new("/project");
        let workspace_folder = "/workspaces/project";
        let bind_home = BindHomeConfig::default();
        let container_home = "/home/vscode";

        let mut config = DevcontainerConfig::default();
        // Set privileged via runArgs (like bootc does)
        config.run_args = vec!["--privileged".to_string()];

        let global_config = crate::config::Config::default();
        let container_config = DevaipodPod::workspace_container_config(
            project_path,
            workspace_folder,
            None,
            &config,
            &bind_home,
            container_home,
            "test-volume",
            "test-agent-home",
            "test-agent-workspace",
            &global_config,
            &[], // labels
        );

        // Privileged should be true from runArgs
        assert!(
            container_config.privileged,
            "privileged should be true when --privileged is in runArgs"
        );
    }

    #[test]
    fn test_workspace_config_with_run_args_device() {
        let project_path = Path::new("/project");
        let workspace_folder = "/workspaces/project";
        let bind_home = BindHomeConfig::default();
        let container_home = "/home/vscode";

        let mut config = DevcontainerConfig::default();
        // Use /dev/null which exists on all platforms; non-existent devices
        // are filtered out at runtime (see commit 5bcf785).
        config.run_args = vec!["--device=/dev/null".to_string()];

        let global_config = crate::config::Config::default();
        let container_config = DevaipodPod::workspace_container_config(
            project_path,
            workspace_folder,
            None,
            &config,
            &bind_home,
            container_home,
            "test-volume",
            "test-agent-home",
            "test-agent-workspace",
            &global_config,
            &[], // labels
        );

        // Device should be in the devices list
        assert!(
            container_config.devices.contains(&"/dev/null".to_string()),
            "devices should include /dev/null from runArgs"
        );
    }

    #[test]
    fn test_workspace_config_privileged_direct_vs_run_args() {
        let project_path = Path::new("/project");
        let workspace_folder = "/workspaces/project";
        let bind_home = BindHomeConfig::default();
        let container_home = "/home/vscode";

        // Test direct privileged field
        let mut config1 = DevcontainerConfig::default();
        config1.privileged = true;

        let global_config = crate::config::Config::default();
        let container_config1 = DevaipodPod::workspace_container_config(
            project_path,
            workspace_folder,
            None,
            &config1,
            &bind_home,
            container_home,
            "test-volume",
            "test-agent-home",
            "test-agent-workspace",
            &global_config,
            &[], // labels
        );
        assert!(
            container_config1.privileged,
            "direct privileged field should work"
        );

        // Test both set
        let mut config2 = DevcontainerConfig::default();
        config2.privileged = true;
        config2.run_args = vec!["--privileged".to_string()];

        let container_config2 = DevaipodPod::workspace_container_config(
            project_path,
            workspace_folder,
            None,
            &config2,
            &bind_home,
            container_home,
            "test-volume",
            "test-agent-home",
            "test-agent-workspace",
            &global_config,
            &[], // labels
        );
        assert!(
            container_config2.privileged,
            "both set should still be privileged"
        );
    }

    #[test]
    fn test_worker_container_config() {
        use crate::config::WorkerGatorMode;

        let project_path = Path::new("/home/user/myproject");
        let workspace_folder = "/workspaces/myproject";
        let bind_home = BindHomeConfig::default();
        let container_home = "/home/vscode";

        let global_config = crate::config::Config::default();
        let container_config = DevaipodPod::worker_container_config(
            project_path,
            workspace_folder,
            &bind_home,
            container_home,
            None,
            false,                     // enable_gator
            WorkerGatorMode::Readonly, // gator_mode
            "test-main-workspace",     // main workspace (read-only)
            "test-owner-workspace",    // task owner workspace (read-only)
            "test-worker-workspace",   // worker's own workspace
            "test-worker-home",        // worker's own home (read-write)
            "test-agent-home",         // agent's home for LLM credentials (read-only)
            &global_config,
        );

        // Volume mounts: worker workspace, owner workspace (readonly), main workspace (readonly), worker home, agent home (readonly)
        assert_eq!(container_config.volume_mounts.len(), 5);
        // Worker's own workspace at /workspaces
        assert_eq!(container_config.volume_mounts[0].0, "test-worker-workspace");
        assert_eq!(container_config.volume_mounts[0].1, "/workspaces");
        // Task owner workspace as read-only reference
        assert_eq!(container_config.volume_mounts[1].0, "test-owner-workspace");
        assert_eq!(
            container_config.volume_mounts[1].1,
            "/mnt/owner-workspace:ro"
        );
        // Main workspace as read-only (for git alternates chain)
        assert_eq!(container_config.volume_mounts[2].0, "test-main-workspace");
        assert_eq!(
            container_config.volume_mounts[2].1,
            "/mnt/main-workspace:ro"
        );
        // Worker home volume (read-write for worker's own state)
        assert_eq!(container_config.volume_mounts[3].0, "test-worker-home");
        assert_eq!(
            container_config.volume_mounts[3].1,
            AGENT_HOME_PATH.to_string()
        );
        // Agent home volume (read-only for LLM credentials)
        assert_eq!(container_config.volume_mounts[4].0, "test-agent-home");
        assert_eq!(container_config.volume_mounts[4].1, "/mnt/agent-home:ro");

        // Verify command runs opencode serve on different port than agent
        let cmd = container_config.command.as_ref().unwrap();
        assert_eq!(cmd[0], "/bin/sh");
        assert_eq!(cmd[1], "-c");
        assert!(cmd[2].contains("opencode serve"));
        // Worker uses WORKER_OPENCODE_PORT to avoid conflict with task owner
        assert!(cmd[2].contains(&format!("--port {}", WORKER_OPENCODE_PORT)));

        // Worker has same security settings as agent (not restricted)
        assert!(!container_config.drop_all_caps);
        assert!(!container_config.no_new_privileges);

        // Verify worker has HOME set correctly
        assert_eq!(
            container_config.env.get("HOME"),
            Some(&AGENT_HOME_PATH.to_string())
        );

        // Worker should have OPENCODE_PERMISSION set to auto-allow all tools
        // This prevents interactive permission prompts when driven via opencode run --attach
        assert!(
            container_config.env.contains_key("OPENCODE_PERMISSION"),
            "Worker should have OPENCODE_PERMISSION set"
        );
        assert_eq!(
            container_config.env.get("OPENCODE_PERMISSION"),
            Some(&r#"{"*":"allow"}"#.to_string())
        );
    }

    #[test]
    fn test_worker_container_config_with_gator_inherit() {
        use crate::config::WorkerGatorMode;

        let project_path = Path::new("/home/user/myproject");
        let workspace_folder = "/workspaces/myproject";
        let bind_home = BindHomeConfig::default();
        let container_home = "/home/vscode";

        let global_config = crate::config::Config::default();
        let container_config = DevaipodPod::worker_container_config(
            project_path,
            workspace_folder,
            &bind_home,
            container_home,
            None,
            true,                     // enable_gator
            WorkerGatorMode::Inherit, // gator_mode - inherits task owner scopes
            "test-main-workspace",
            "test-owner-workspace",
            "test-worker-workspace",
            "test-worker-home",
            "test-agent-home",
            &global_config,
        );

        // Verify gator MCP config is set
        assert!(
            container_config.env.contains_key("OPENCODE_CONFIG_CONTENT"),
            "Worker with gator=inherit should have MCP config"
        );
        let mcp_config = container_config.env.get("OPENCODE_CONFIG_CONTENT").unwrap();
        assert!(
            mcp_config.contains("service-gator"),
            "MCP config should reference service-gator"
        );
    }

    #[test]
    fn test_worker_container_config_with_gator_none() {
        use crate::config::WorkerGatorMode;

        let project_path = Path::new("/home/user/myproject");
        let workspace_folder = "/workspaces/myproject";
        let bind_home = BindHomeConfig::default();
        let container_home = "/home/vscode";

        let global_config = crate::config::Config::default();
        let container_config = DevaipodPod::worker_container_config(
            project_path,
            workspace_folder,
            &bind_home,
            container_home,
            None,
            true,                  // enable_gator
            WorkerGatorMode::None, // gator_mode - no gator access
            "test-main-workspace",
            "test-owner-workspace",
            "test-worker-workspace",
            "test-worker-home",
            "test-agent-home",
            &global_config,
        );

        // Verify gator MCP config is NOT set when mode is None
        assert!(
            !container_config.env.contains_key("OPENCODE_CONFIG_CONTENT"),
            "Worker with gator=none should not have MCP config"
        );
    }

    #[test]
    fn test_workspace_config_passthrough_run_args() {
        let project_path = Path::new("/project");
        let workspace_folder = "/workspaces/project";
        let bind_home = BindHomeConfig::default();
        let container_home = "/home/vscode";

        let mut config = DevcontainerConfig::default();
        config.run_args = vec![
            "--ulimit".to_string(),
            "nofile=1024:1024".to_string(),
            "--cap-add=ALL".to_string(),
        ];

        let global_config = crate::config::Config::default();
        let container_config = DevaipodPod::workspace_container_config(
            project_path,
            workspace_folder,
            None,
            &config,
            &bind_home,
            container_home,
            "test-volume",
            "test-agent-home",
            "test-agent-workspace",
            &global_config,
            &[], // labels
        );

        // --cap-add=ALL should be extracted into cap_add, not in extra_create_args
        assert!(container_config.cap_add.contains(&"ALL".to_string()));
        // --ulimit and its value should be passed through
        assert_eq!(
            container_config.extra_create_args,
            vec!["--ulimit", "nofile=1024:1024"]
        );
    }

    #[test]
    fn test_worker_container_names() {
        // Verify naming convention for worker container
        let pod_name = "test-project";
        let worker = format!("{}-worker", pod_name);
        let worker_workspace_volume = format!("{}-worker-workspace", pod_name);

        assert_eq!(worker, "test-project-worker");
        assert_eq!(worker_workspace_volume, "test-project-worker-workspace");
    }

    #[test]
    fn test_workspace_container_with_devcontainer_secrets() {
        // Test that devcontainer.json secrets are passed to workspace container
        let project_path = Path::new("/project");
        let workspace_folder = "/workspaces/project";
        let bind_home = BindHomeConfig::default();
        let container_home = "/home/vscode";

        let json = r#"{
            "image": "foo",
            "secrets": {
                "ANTHROPIC_API_KEY": {},
                "OPENAI_API_KEY": {}
            }
        }"#;
        let config: DevcontainerConfig = serde_json::from_str(json).unwrap();
        let global_config = crate::config::Config::default();

        let container_config = DevaipodPod::workspace_container_config(
            project_path,
            workspace_folder,
            None,
            &config,
            &bind_home,
            container_home,
            "test-volume",
            "test-agent-home",
            "test-agent-workspace",
            &global_config,
            &[], // labels
        );

        // Should have devcontainer secrets
        assert_eq!(container_config.secrets.len(), 2);
        assert!(container_config.secrets.contains(&(
            "ANTHROPIC_API_KEY".to_string(),
            "ANTHROPIC_API_KEY".to_string()
        )));
        assert!(container_config
            .secrets
            .contains(&("OPENAI_API_KEY".to_string(), "OPENAI_API_KEY".to_string())));
    }

    #[test]
    fn test_agent_container_with_devcontainer_secrets() {
        // Test that devcontainer.json secrets are passed to agent container
        let project_path = Path::new("/project");
        let workspace_folder = "/workspaces/project";
        let bind_home = BindHomeConfig::default();
        let container_home = "/home/vscode";

        let json = r#"{
            "image": "foo",
            "secrets": {
                "ANTHROPIC_API_KEY": {},
                "OPENAI_API_KEY": {}
            }
        }"#;
        let config: DevcontainerConfig = serde_json::from_str(json).unwrap();
        let global_config = crate::config::Config::default();

        let container_config = DevaipodPod::agent_container_config(
            project_path,
            workspace_folder,
            &bind_home,
            container_home,
            Some(&config),
            false, // enable_gator
            false, // enable_orchestration
            "test-workspace-vol",
            "test-agent-workspace-vol",
            "test-agent-home-vol",
            None, // worker_workspace_volume
            &global_config,
        );

        // Should have devcontainer secrets (LLM keys go to agent)
        assert_eq!(container_config.secrets.len(), 2);
        assert!(container_config.secrets.contains(&(
            "ANTHROPIC_API_KEY".to_string(),
            "ANTHROPIC_API_KEY".to_string()
        )));
        assert!(container_config
            .secrets
            .contains(&("OPENAI_API_KEY".to_string(), "OPENAI_API_KEY".to_string())));
    }

    #[test]
    fn test_gator_container_does_not_get_devcontainer_secrets() {
        // Verify that gator (forge proxy) does NOT get devcontainer secrets
        // Gator only needs trusted secrets for forge access, not LLM keys
        let agent_workspace_volume = "test-agent-workspace";
        let workspace_folder = "/workspaces";
        let main_workspace_volume = "test-main-workspace";
        let global_config = crate::config::Config::default();

        let container_config = DevaipodPod::gator_container_config(
            agent_workspace_volume,
            workspace_folder,
            main_workspace_volume,
            &global_config,
        );

        // Gator should not have any secrets (no trusted secrets configured)
        assert_eq!(container_config.secrets.len(), 0);
    }

    #[test]
    fn test_workspace_container_with_both_secret_types() {
        // Test that both trusted and devcontainer secrets are merged
        let project_path = Path::new("/project");
        let workspace_folder = "/workspaces/project";
        let bind_home = BindHomeConfig::default();
        let container_home = "/home/vscode";

        let json = r#"{
            "image": "foo",
            "secrets": {
                "ANTHROPIC_API_KEY": {}
            }
        }"#;
        let config: DevcontainerConfig = serde_json::from_str(json).unwrap();

        let mut global_config = crate::config::Config::default();
        global_config.trusted_env.secrets = vec!["GH_TOKEN=gh_token".to_string()];

        let container_config = DevaipodPod::workspace_container_config(
            project_path,
            workspace_folder,
            None,
            &config,
            &bind_home,
            container_home,
            "test-volume",
            "test-agent-home",
            "test-agent-workspace",
            &global_config,
            &[], // labels
        );

        // Should have both trusted and devcontainer secrets
        assert_eq!(container_config.secrets.len(), 2);
        assert!(container_config
            .secrets
            .contains(&("GH_TOKEN".to_string(), "gh_token".to_string())));
        assert!(container_config.secrets.contains(&(
            "ANTHROPIC_API_KEY".to_string(),
            "ANTHROPIC_API_KEY".to_string()
        )));
    }

    #[test]
    fn test_workspace_container_secret_collision_trusted_wins() {
        // Test that trusted secrets take precedence over devcontainer secrets with same env var name
        let project_path = Path::new("/project");
        let workspace_folder = "/workspaces/project";
        let bind_home = BindHomeConfig::default();
        let container_home = "/home/vscode";

        // Devcontainer declares GH_TOKEN (malicious attempt to shadow trusted secret)
        let json = r#"{
            "image": "foo",
            "secrets": {
                "GH_TOKEN": {},
                "ANTHROPIC_API_KEY": {}
            }
        }"#;
        let config: DevcontainerConfig = serde_json::from_str(json).unwrap();

        // Global config has trusted GH_TOKEN
        let mut global_config = crate::config::Config::default();
        global_config.trusted_env.secrets = vec!["GH_TOKEN=gh_token_trusted".to_string()];

        let container_config = DevaipodPod::workspace_container_config(
            project_path,
            workspace_folder,
            None,
            &config,
            &bind_home,
            container_home,
            "test-volume",
            "test-agent-home",
            "test-agent-workspace",
            &global_config,
            &[], // labels
        );

        // Should have 2 secrets: trusted GH_TOKEN and devcontainer ANTHROPIC_API_KEY
        // The devcontainer GH_TOKEN should be filtered out
        assert_eq!(container_config.secrets.len(), 2);

        // Verify trusted GH_TOKEN is present (not the devcontainer one)
        assert!(container_config
            .secrets
            .contains(&("GH_TOKEN".to_string(), "gh_token_trusted".to_string())));

        // Verify devcontainer ANTHROPIC_API_KEY is present
        assert!(container_config.secrets.contains(&(
            "ANTHROPIC_API_KEY".to_string(),
            "ANTHROPIC_API_KEY".to_string()
        )));

        // Make sure there's no duplicate GH_TOKEN entry
        let gh_token_count = container_config
            .secrets
            .iter()
            .filter(|(env_var, _)| env_var == "GH_TOKEN")
            .count();
        assert_eq!(gh_token_count, 1);
    }
}
