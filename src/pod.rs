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

use color_eyre::eyre::{Context, Result};

use crate::forge::PullRequestInfo;
use crate::git::GitRepoInfo;

/// Source for workspace content - either a local git repo or a PR/MR
#[derive(Debug, Clone)]
pub enum WorkspaceSource {
    /// Local git repository
    LocalRepo(GitRepoInfo),
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
            WorkspaceSource::PullRequest(pr_info) => pr_info.to_labels(),
        }
    }

    /// Get the clone script for this source
    pub fn clone_script(&self, workspace_folder: &str) -> color_eyre::Result<String> {
        match self {
            WorkspaceSource::LocalRepo(git_info) => {
                crate::git::clone_script(git_info, workspace_folder)
            }
            WorkspaceSource::PullRequest(pr_info) => {
                Ok(crate::git::clone_pr_script(pr_info, workspace_folder))
            }
        }
    }

    /// Get a short description for logging
    pub fn description(&self) -> String {
        match self {
            WorkspaceSource::LocalRepo(git_info) => {
                format!("commit {}", &git_info.commit_sha[..8.min(git_info.commit_sha.len())])
            }
            WorkspaceSource::PullRequest(pr_info) => {
                format!("PR #{}", pr_info.pr_ref.number)
            }
        }
    }

    /// Get the project name for workspace folder derivation
    ///
    /// For local repos, this comes from the path.
    /// For PRs, this is the repository name.
    pub fn project_name(&self, fallback_path: &std::path::Path) -> String {
        match self {
            WorkspaceSource::LocalRepo(_) => fallback_path
                .file_name()
                .map(|s| s.to_string_lossy().to_string())
                .unwrap_or_else(|| "project".to_string()),
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
        let path = parsed.path().trim_start_matches('/').trim_end_matches(".git");
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

use crate::config::{Config, DotfilesConfig};
use crate::devcontainer::DevcontainerConfig;
use crate::podman::{ContainerConfig, PodmanService};

/// Port for the opencode server in the agent container
pub const OPENCODE_PORT: u16 = 4096;

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
    /// Name of the agent container
    pub agent_container: String,
    /// Name of the gator container (if enabled)
    pub gator_container: Option<String>,
    /// Name of the proxy container (if network isolation enabled)
    #[allow(dead_code)] // Used for container management
    pub proxy_container: Option<String>,
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
    pub async fn create(
        podman: &PodmanService,
        project_path: &Path,
        devcontainer_config: &DevcontainerConfig,
        pod_name: &str,
        enable_gator: bool,
        enable_network_isolation: bool,
        global_config: &Config,
        source: &WorkspaceSource,
    ) -> Result<Self> {
        // Resolve bind_home configurations
        let container_home = Self::resolve_container_home(devcontainer_config);

        // Build workspace bind_home: global bind_home + workspace-specific
        let mut workspace_paths = global_config.bind_home.clone();
        if let Some(ref ws_config) = global_config.bind_home_workspace {
            workspace_paths.extend(ws_config.paths.clone());
        }
        let workspace_bind_home = BindHomeConfig {
            paths: workspace_paths,
            readonly: false, // Workspace gets read-write access
        };

        // Build agent bind_home: global bind_home + agent-specific
        let mut agent_paths = global_config.bind_home.clone();
        if let Some(ref agent_config) = global_config.bind_home_agent {
            agent_paths.extend(agent_config.paths.clone());
        }
        let agent_bind_home = BindHomeConfig {
            paths: agent_paths,
            readonly: true, // Agent gets read-only access for security
        };

        let config = devcontainer_config;
        // Derive project name from source (for PRs, use repo name; for local, use path)
        let project_name = source.project_name(project_path);

        // Get workspace folder
        let workspace_folder = config.workspace_folder_for_project(&project_name);

        // Find devcontainer.json directory for resolving relative paths
        let devcontainer_json = crate::devcontainer::find_devcontainer_json(project_path)?;
        let devcontainer_dir = devcontainer_json.parent().unwrap_or(project_path);

        // Determine image source and ensure image is available
        let image_source = config.image_source(devcontainer_dir)?;
        let image_tag = format!("devaipod-{}", pod_name);
        let image = podman
            .ensure_image(
                &image_source,
                &image_tag,
                config.has_features(),
                Some(project_path),
            )
            .await
            .context("Failed to ensure container image")?;

        // Create workspace volume and clone repo into it
        let volume_name = format!("{}-workspace", pod_name);
        let volume_already_exists = podman.volume_exists(&volume_name).await?;

        if !volume_already_exists {
            tracing::info!("Creating workspace volume and cloning {}...", source.description());
            podman
                .create_volume(&volume_name)
                .await
                .context("Failed to create workspace volume")?;

            // Clone the repository into the volume using an init container
            let clone_script = source.clone_script(&workspace_folder)?;
            let exit_code = podman
                .run_init_container(
                    &image,
                    &volume_name,
                    "/workspaces",
                    &["/bin/sh", "-c", &clone_script],
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
            tracing::info!("Cloned {}", source.description());
        } else {
            tracing::info!("Using existing workspace volume '{}'", volume_name);
        }

        // Create the pod with metadata labels
        let labels = source.to_labels();
        podman
            .create_pod(pod_name, &labels)
            .await
            .context("Failed to create pod")?;

        // Container names
        let workspace_container = format!("{}-workspace", pod_name);
        let agent_container = format!("{}-agent", pod_name);
        let gator_container_name = format!("{}-gator", pod_name);

        // Create workspace container
        let workspace_config = Self::workspace_container_config(
            project_path,
            &workspace_folder,
            config.effective_user(),
            config,
            &workspace_bind_home,
            &container_home,
            &volume_name,
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

        // Create proxy container if network isolation is enabled
        let proxy_container_name = format!("{}-proxy", pod_name);
        let proxy_container = if enable_network_isolation {
            tracing::info!("Network isolation enabled, creating proxy container...");

            // Pull proxy image
            let proxy_image = global_config.network_isolation.proxy_image();
            podman
                .pull_image(proxy_image)
                .await
                .with_context(|| format!("Failed to pull proxy image: {}", proxy_image))?;

            // Combine allowed domains from global config and devcontainer customizations
            let mut network_config = global_config.network_isolation.clone();
            network_config
                .allowed_domains
                .extend(devcontainer_config.allowed_domains());

            let proxy_config = crate::proxy::proxy_container_config(&network_config);
            podman
                .create_container(&proxy_container_name, proxy_image, pod_name, proxy_config)
                .await
                .with_context(|| {
                    format!("Failed to create proxy container: {}", proxy_container_name)
                })?;

            Some(proxy_container_name)
        } else {
            None
        };

        // Create agent container with restricted security
        let agent_config = Self::agent_container_config(
            project_path,
            &workspace_folder,
            &agent_bind_home,
            &container_home,
            Some(devcontainer_config),
            enable_network_isolation,
            &volume_name,
        );
        podman
            .create_container(&agent_container, &image, pod_name, agent_config)
            .await
            .with_context(|| format!("Failed to create agent container: {}", agent_container))?;

        // Create gator container if enabled
        let gator_container = if enable_gator {
            // Pull gator image
            podman
                .pull_image(GATOR_IMAGE)
                .await
                .context("Failed to pull service-gator image")?;

            let gator_config = Self::gator_container_config();
            podman
                .create_container(&gator_container_name, GATOR_IMAGE, pod_name, gator_config)
                .await
                .with_context(|| {
                    format!("Failed to create gator container: {}", gator_container_name)
                })?;

            Some(gator_container_name)
        } else {
            None
        };

        let container_count = 2
            + if gator_container.is_some() { 1 } else { 0 }
            + if proxy_container.is_some() { 1 } else { 0 };
        tracing::info!(
            "Created pod '{}' with {} containers",
            pod_name,
            container_count
        );

        Ok(Self {
            pod_name: pod_name.to_string(),
            workspace_container,
            agent_container,
            gator_container,
            proxy_container,
            image,
            workspace_folder,
            workspace_bind_home,
            agent_bind_home,
            container_home,
        })
    }

    /// Start the pod (starts all containers)
    pub async fn start(&self, podman: &PodmanService) -> Result<()> {
        podman
            .start_pod(&self.pod_name)
            .await
            .with_context(|| format!("Failed to start pod: {}", self.pod_name))?;

        tracing::info!("Started pod '{}'", self.pod_name);
        Ok(())
    }

    /// Wait for the agent container to be ready
    ///
    /// Polls the agent's health endpoint until it responds or timeout is reached.
    /// The agent exposes a health endpoint at http://localhost:OPENCODE_PORT/global/health
    pub async fn wait_for_agent_ready(
        &self,
        podman: &PodmanService,
        timeout_secs: u64,
        poll_interval_ms: u64,
    ) -> Result<()> {
        use std::time::{Duration, Instant};

        let health_url = format!("http://localhost:{}/global/health", OPENCODE_PORT);
        let timeout = Duration::from_secs(timeout_secs);
        let poll_interval = Duration::from_millis(poll_interval_ms);
        let start = Instant::now();

        tracing::info!("Waiting for agent to be ready...");

        loop {
            // Check if we've exceeded timeout
            if start.elapsed() > timeout {
                return Err(color_eyre::eyre::eyre!(
                    "Agent did not become ready within {} seconds. \
                     Try checking logs with: podman logs {}",
                    timeout_secs,
                    self.agent_container
                ));
            }

            // Try to curl the health endpoint from inside the workspace container
            // (since containers share the pod's network namespace)
            let check_cmd = format!("curl -sf '{}' >/dev/null 2>&1", health_url);
            let result = podman
                .exec(
                    &self.workspace_container,
                    &["/bin/sh", "-c", &check_cmd],
                    None,
                    None,
                )
                .await;

            match result {
                Ok(0) => {
                    tracing::info!("Agent ready after {:.1}s", start.elapsed().as_secs_f64());
                    return Ok(());
                }
                Ok(_) | Err(_) => {
                    // Not ready yet, wait and retry
                    tokio::time::sleep(poll_interval).await;
                }
            }
        }
    }

    /// Install dotfiles in the workspace container
    ///
    /// This should be called after the pod starts but BEFORE lifecycle commands,
    /// so that bashrc, gitconfig, and other dotfiles are available for lifecycle scripts.
    ///
    /// The install process:
    /// 1. Clone the dotfiles repo to a temp directory
    /// 2. Run the install script (or default behavior)
    /// 3. Clean up the cloned repo
    ///
    /// Default install behavior (if no script specified):
    /// 1. If `install.sh` exists, run it
    /// 2. Else if `install-dotfiles.sh` exists, run it
    /// 3. Else if `dotfiles/` directory exists, rsync to home
    pub async fn install_dotfiles(
        &self,
        podman: &PodmanService,
        dotfiles: &DotfilesConfig,
        user: Option<&str>,
    ) -> Result<()> {
        tracing::info!("Installing dotfiles from {}...", dotfiles.url);

        // Build the installation script
        // We clone to a temp dir, run the install, then clean up
        let install_script = if let Some(script) = &dotfiles.script {
            // User specified a custom script
            format!(
                r#"
set -e
DOTFILES_TMP="$HOME/.dotfiles-install-tmp"
rm -rf "$DOTFILES_TMP"
git clone --depth 1 "{url}" "$DOTFILES_TMP"
cd "$DOTFILES_TMP"
if [ -x "./{script}" ]; then
    ./{script}
elif [ -f "./{script}" ]; then
    sh "./{script}"
else
    echo "Error: Install script '{script}' not found in dotfiles repo"
    exit 1
fi
rm -rf "$DOTFILES_TMP"
echo "Dotfiles installed successfully"
"#,
                url = dotfiles.url,
                script = script
            )
        } else {
            // Default behavior: try install.sh, install-dotfiles.sh, or rsync dotfiles/
            format!(
                r#"
set -e
DOTFILES_TMP="$HOME/.dotfiles-install-tmp"
rm -rf "$DOTFILES_TMP"
git clone --depth 1 "{url}" "$DOTFILES_TMP"
cd "$DOTFILES_TMP"
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
        rsync -av --ignore-existing ./dotfiles/ "$HOME/"
    else
        cp -rn ./dotfiles/. "$HOME/" 2>/dev/null || cp -r ./dotfiles/. "$HOME/"
    fi
else
    echo "Warning: No install script or dotfiles/ directory found, skipping"
fi
rm -rf "$DOTFILES_TMP"
echo "Dotfiles installed successfully"
"#,
                url = dotfiles.url
            )
        };

        let exit_code = podman
            .exec(
                &self.workspace_container,
                &["/bin/sh", "-c", &install_script],
                user,
                Some(&self.workspace_folder),
            )
            .await
            .context("Failed to install dotfiles")?;

        if exit_code != 0 {
            // Log warning but don't fail - dotfiles are nice to have, not critical
            tracing::warn!(
                "Dotfiles installation exited with code {}. Continuing anyway.",
                exit_code
            );
        } else {
            tracing::info!("Dotfiles installed successfully");
        }

        Ok(())
    }

    /// Run lifecycle commands from devcontainer.json in the workspace container
    ///
    /// Executes in order: onCreateCommand, postCreateCommand, postStartCommand
    pub async fn run_lifecycle_commands(
        &self,
        podman: &PodmanService,
        config: &DevcontainerConfig,
    ) -> Result<()> {
        let user = config.effective_user();
        let workdir = Some(self.workspace_folder.as_str());

        // onCreateCommand
        if let Some(cmd) = &config.on_create_command {
            tracing::info!("Running onCreateCommand...");
            self.run_shell_command(podman, &cmd.to_shell_command(), user, workdir)
                .await
                .context("onCreateCommand failed")?;
        }

        // postCreateCommand
        if let Some(cmd) = &config.post_create_command {
            tracing::info!("Running postCreateCommand...");
            self.run_shell_command(podman, &cmd.to_shell_command(), user, workdir)
                .await
                .context("postCreateCommand failed")?;
        }

        // postStartCommand
        if let Some(cmd) = &config.post_start_command {
            tracing::info!("Running postStartCommand...");
            self.run_shell_command(podman, &cmd.to_shell_command(), user, workdir)
                .await
                .context("postStartCommand failed")?;
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
    /// For the agent container, files are copied to the agent's HOME (/tmp/agent-home).
    pub async fn copy_bind_home_files(
        &self,
        podman: &PodmanService,
        workspace_bind_home: &BindHomeConfig,
        agent_bind_home: &BindHomeConfig,
        container_home: &str,
        container_user: Option<&str>,
    ) -> Result<()> {
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

        // Copy files to agent container (to agent's HOME which is /tmp/agent-home)
        // This directory is created by the agent startup script and is writable
        const AGENT_HOME: &str = "/tmp/agent-home";
        for relative_path in &agent_bind_home.paths {
            let source = host_home.join(relative_path);
            let target = format!("{}/{}", AGENT_HOME, relative_path);

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

        Ok(())
    }

    /// Configure nested podman support in the workspace container
    ///
    /// This configures the container environment for running podman inside the container:
    /// - Adjusts /etc/subuid and /etc/subgid to use UIDs within the container's namespace
    /// - Creates /etc/containers/containers.conf for cgroupless operation
    /// - Resets podman storage if the mappings changed
    ///
    /// This requires sudo access in the container and only runs if podman is installed.
    pub async fn configure_nested_podman(&self, podman: &PodmanService) -> Result<()> {
        // Shell script to configure nested podman
        // This is designed to be idempotent and safe to run multiple times
        let script = r#"
set -e

# Only proceed if podman and sudo are available
if ! command -v podman >/dev/null 2>&1; then
    echo "podman not found, skipping nested podman configuration"
    exit 0
fi
if ! command -v sudo >/dev/null 2>&1; then
    echo "sudo not found, skipping nested podman configuration"
    exit 0
fi

# Parse /proc/self/uid_map to find the maximum UID available in this namespace
# Format: <inside_uid> <outside_uid> <count>
# We sum inside_uid + count to get the max usable UID
max_uid=0
while read -r inside outside count; do
    end=$((inside + count))
    if [ "$end" -gt "$max_uid" ]; then
        max_uid=$end
    fi
done < /proc/self/uid_map

my_uid=$(id -u)
my_user=$(id -un)

# Only configure if we have a constrained UID namespace (< 100000 UIDs)
# Full namespaces have 65536+ UIDs starting at 100000+
if [ "$max_uid" -le 1000 ] || [ "$max_uid" -ge 100000 ]; then
    echo "Full UID namespace available (max=$max_uid), using default podman config"
    exit 0
fi

# Calculate subuid range: start after our UID, use remaining range
subuid_start=$((my_uid + 1))
subuid_count=$((max_uid - subuid_start))

if [ "$subuid_count" -lt 1000 ]; then
    echo "Insufficient UID range for nested podman (only $subuid_count UIDs available)"
    exit 0
fi

# Check if already configured correctly
if [ -f /etc/subuid ]; then
    current=$(grep "^${my_user}:" /etc/subuid 2>/dev/null || true)
    expected="${my_user}:${subuid_start}:${subuid_count}"
    if [ "$current" = "$expected" ]; then
        echo "Nested podman already configured"
        exit 0
    fi
fi

echo "Configuring nested podman for $my_user (subuid $subuid_start:$subuid_count)"

# Configure subuid/subgid
echo "${my_user}:${subuid_start}:${subuid_count}" | sudo tee /etc/subuid >/dev/null
echo "${my_user}:${subuid_start}:${subuid_count}" | sudo tee /etc/subgid >/dev/null

# Configure containers.conf for nested operation (cgroupless, host network)
sudo mkdir -p /etc/containers
sudo tee /etc/containers/containers.conf >/dev/null << 'CONTAINERS_CONF'
# Generated by devaipod for nested container support
[containers]
cgroups = "disabled"
netns = "host"
cgroup_manager = "cgroupfs"

[engine]
cgroup_manager = "cgroupfs"
CONTAINERS_CONF

# Reset podman storage if it exists (may have wrong UID mappings)
storage_dir="$HOME/.local/share/containers/storage"
if [ -d "$storage_dir" ]; then
    echo "Resetting podman storage for new UID mappings"
    rm -rf "$storage_dir"
fi

echo "Nested podman configured successfully"
"#;

        tracing::info!("Configuring nested podman support...");

        let exit_code = podman
            .exec(
                &self.workspace_container,
                &["/bin/sh", "-c", script],
                None,
                None,
            )
            .await
            .context("Failed to run nested podman configuration")?;

        if exit_code != 0 {
            tracing::warn!(
                "Nested podman configuration returned exit code {} (may not be available)",
                exit_code
            );
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

    /// Execute a shell command in the workspace container
    async fn run_shell_command(
        &self,
        podman: &PodmanService,
        command: &str,
        user: Option<&str>,
        workdir: Option<&str>,
    ) -> Result<()> {
        let exit_code = podman
            .exec(
                &self.workspace_container,
                &["/bin/sh", "-c", command],
                user,
                workdir,
            )
            .await
            .context("Failed to execute command")?;

        if exit_code != 0 {
            color_eyre::eyre::bail!("Command exited with code {}: {}", exit_code, command);
        }

        Ok(())
    }

    /// Create container config for the workspace container
    fn workspace_container_config(
        _project_path: &Path,
        _workspace_folder: &str,
        user: Option<&str>,
        config: &DevcontainerConfig,
        _bind_home: &BindHomeConfig,
        _container_home: &str,
        volume_name: &str,
    ) -> ContainerConfig {
        let mut env = config.container_env.clone();
        // Merge remote_env (these typically take precedence)
        env.extend(config.remote_env.clone());

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

        // Add devices from runArgs (e.g., --device=/dev/kvm)
        for device_arg in config.device_args() {
            // Parse --device=/dev/foo format (--device /dev/foo is two separate args)
            if let Some(device_spec) = device_arg.strip_prefix("--device=") {
                // Handle potential :options suffix (e.g., /dev/kvm:rwm)
                let path = device_spec.split(':').next().unwrap_or(device_spec);
                if !path.is_empty() && !devices.contains(&path.to_string()) {
                    devices.push(path.to_string());
                }
            }
        }

        if !devices.is_empty() {
            tracing::debug!("Devices for workspace container: {:?}", devices);
        }

        // Check if privileged mode is requested (either directly or via runArgs)
        let privileged = config.privileged || config.has_privileged_run_arg();

        ContainerConfig {
            mounts,
            env,
            // Don't set workdir initially - workspace folder doesn't exist until we clone
            // The clone step will create it, and lifecycle commands run in that directory
            workdir: None,
            user: user.map(|u| u.to_string()),
            // Keep the container running, create opencode shim in user's bin, print agent connection info
            command: Some(vec![
                "/bin/sh".to_string(),
                "-c".to_string(),
                format!(
                    r#"
# Create opencode-agent shim that attaches to the agent container's server
mkdir -p "$HOME/.local/bin"
cat > "$HOME/.local/bin/opencode-agent" << 'EOF'
#!/bin/sh
# Shim to connect to devaipod agent container
exec opencode attach http://localhost:{port} "$@"
EOF
chmod +x "$HOME/.local/bin/opencode-agent"

# Also create a short 'oc' alias
ln -sf "$HOME/.local/bin/opencode-agent" "$HOME/.local/bin/oc"

# Add to PATH if not already there
if ! echo "$PATH" | grep -q "$HOME/.local/bin"; then
    export PATH="$HOME/.local/bin:$PATH"
fi

echo "devaipod: opencode agent at http://localhost:{port}"
echo "devaipod: use 'opencode-agent' or 'oc' to connect (in ~/.local/bin)"
exec sleep infinity
"#,
                    port = OPENCODE_PORT
                ),
            ]),
            drop_all_caps: false,
            cap_add: config.cap_add.clone(),
            no_new_privileges: false,
            devices,
            security_opts: config.security_opt.clone(),
            privileged,
            // Mount the workspace volume (initialized with cloned repo)
            volume_mounts: vec![(volume_name.to_string(), "/workspaces".to_string())],
            ..Default::default()
        }
    }

    /// Create container config for the agent container
    ///
    /// The agent runs `opencode serve` with restricted security:
    /// - Drops all capabilities except NET_BIND_SERVICE
    /// - Sets no-new-privileges
    /// - Uses a separate home directory
    ///
    /// If `devcontainer_config` is provided, env vars from its `customizations.devaipod.env_allowlist`
    /// will be forwarded to the agent.
    ///
    /// If `use_proxy` is true, HTTP_PROXY/HTTPS_PROXY env vars are set to route
    /// traffic through the network isolation proxy.
    fn agent_container_config(
        _project_path: &Path,
        _workspace_folder: &str,
        bind_home: &BindHomeConfig,
        _container_home: &str,
        devcontainer_config: Option<&DevcontainerConfig>,
        use_proxy: bool,
        volume_name: &str,
    ) -> ContainerConfig {
        // Use /tmp as agent home - it's always writable and isolated per container.
        // In the future we could mount a named volume for persistent agent state.
        let agent_home = "/tmp/agent-home".to_string();

        let mut env = std::collections::HashMap::new();
        env.insert("HOME".to_string(), agent_home.clone());
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

        // Forward API keys to the agent container for LLM access
        // 1. DEVAIPOD_AGENT_* vars: strip prefix and forward (e.g., DEVAIPOD_AGENT_FOO=bar -> FOO=bar)
        // 2. Common API key env vars: forward as-is
        // 3. Vars from devcontainer.json customizations.devaipod.env_allowlist
        const API_KEY_VARS: &[&str] = &[
            "ANTHROPIC_API_KEY",
            "OPENAI_API_KEY",
            "GOOGLE_API_KEY",
            "GEMINI_API_KEY",
            "AZURE_OPENAI_API_KEY",
            "AZURE_OPENAI_ENDPOINT",
            "OPENROUTER_API_KEY",
            "GROQ_API_KEY",
            "MISTRAL_API_KEY",
            "COHERE_API_KEY",
            "XAI_API_KEY",
        ];

        for (key, value) in std::env::vars() {
            // Handle DEVAIPOD_AGENT_* prefix: strip and forward
            if let Some(stripped) = key.strip_prefix("DEVAIPOD_AGENT_") {
                if !stripped.is_empty() {
                    env.insert(stripped.to_string(), value);
                }
            } else if API_KEY_VARS.contains(&key.as_str()) {
                // Forward common API key vars directly
                env.insert(key, value);
            }
        }

        // Forward env vars from devcontainer.json's customizations.devaipod.env_allowlist
        if let Some(config) = devcontainer_config {
            for (key, value) in config.collect_allowlist_env_vars() {
                env.insert(key, value);
            }
        }

        // If network isolation is enabled, route traffic through the proxy
        if use_proxy {
            for (key, value) in crate::proxy::agent_proxy_env() {
                env.insert(key, value);
            }
        }

        // No bind mounts - we clone the repo into the container instead
        // This avoids UID mapping issues with rootless podman
        let mounts = vec![];

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

        ContainerConfig {
            mounts,
            env,
            // Don't set workdir initially - workspace folder doesn't exist until we clone
            // opencode serve will use the workspace folder after clone
            workdir: None,
            // Run as a non-root user if possible (agent user)
            user: None, // Let the image decide, or we could set "1000" for a generic user
            command: Some(vec![
                // Create home dir structure first (including dirs that might be needed for bind mounts),
                // then run opencode. We use mkdir -p to ensure all XDG dirs exist.
                // Note: opencode serve doesn't need the workspace folder to exist at startup.
                "/bin/sh".to_string(),
                "-c".to_string(),
                format!(
                    r#"mkdir -p {agent_home}/.config {agent_home}/.local/share {agent_home}/.local/bin {agent_home}/.cache && \
                       exec opencode serve --port {} --hostname 0.0.0.0"#,
                    OPENCODE_PORT
                ),
            ]),
            // Security restrictions
            drop_all_caps: true,
            cap_add: vec!["NET_BIND_SERVICE".to_string()],
            no_new_privileges: true,
            // Mount the workspace volume (initialized with cloned repo)
            volume_mounts: vec![(volume_name.to_string(), "/workspaces".to_string())],
            ..Default::default()
        }
    }

    /// Create container config for the gator (service-gator) container
    ///
    /// Runs with minimal privileges as an MCP server.
    fn gator_container_config() -> ContainerConfig {
        let mut env = std::collections::HashMap::new();
        env.insert("HOME".to_string(), "/tmp".to_string());

        ContainerConfig {
            mounts: vec![],
            env,
            workdir: None,
            user: None,
            command: Some(vec![
                "service-gator".to_string(),
                "--mcp-server".to_string(),
                format!("0.0.0.0:{}", GATOR_PORT),
            ]),
            // Minimal privileges
            drop_all_caps: true,
            cap_add: vec!["NET_BIND_SERVICE".to_string()],
            no_new_privileges: true,
            ..Default::default()
        }
    }

    /// Resolve the container home directory based on devcontainer config
    ///
    /// Most devcontainer images use a non-root user like "vscode" or "devenv"
    /// with a home directory at /home/<user>. This function attempts to determine
    /// the correct home directory for bind mounts.
    fn resolve_container_home(config: &DevcontainerConfig) -> String {
        if let Some(user) = config.effective_user() {
            if user == "root" {
                "/root".to_string()
            } else {
                format!("/home/{}", user)
            }
        } else {
            // Default to vscode user which is common in devcontainer images
            "/home/vscode".to_string()
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
        let container_config = DevaipodPod::workspace_container_config(
            project_path,
            workspace_folder,
            Some("vscode"),
            &config,
            &bind_home,
            container_home,
            volume_name,
        );

        // Volume mount for workspace
        assert_eq!(container_config.volume_mounts.len(), 1);
        assert_eq!(container_config.volume_mounts[0].0, "test-volume");
        assert_eq!(container_config.volume_mounts[0].1, "/workspaces");
        assert_eq!(container_config.user, Some("vscode".to_string()));
        // workdir is None initially - workspace folder created by clone step
        assert!(container_config.workdir.is_none());
        // Verify command is a shell script that creates shim, prints agent info, and sleeps
        let cmd = container_config.command.as_ref().unwrap();
        assert_eq!(cmd[0], "/bin/sh");
        assert_eq!(cmd[1], "-c");
        assert!(cmd[2].contains("opencode-agent")); // Creates shim
        assert!(cmd[2].contains("opencode attach")); // Shim uses attach
        assert!(cmd[2].contains(&format!("http://localhost:{}", OPENCODE_PORT)));
        assert!(cmd[2].contains("sleep infinity"));
        assert!(!container_config.drop_all_caps);
        assert!(!container_config.no_new_privileges);
    }

    #[test]
    fn test_agent_container_config() {
        let project_path = Path::new("/home/user/myproject");
        let workspace_folder = "/workspaces/myproject";
        let bind_home = BindHomeConfig::default();
        let container_home = "/home/vscode";

        let container_config = DevaipodPod::agent_container_config(
            project_path,
            workspace_folder,
            &bind_home,
            container_home,
            None,
            false,
            "test-volume",
        );

        // Volume mount for workspace
        assert_eq!(container_config.volume_mounts.len(), 1);

        // Verify command wraps opencode in a shell to create home dir
        let cmd = container_config.command.as_ref().unwrap();
        assert_eq!(cmd[0], "/bin/sh");
        assert_eq!(cmd[1], "-c");
        assert!(cmd[2].contains("opencode serve"));
        assert!(cmd[2].contains(&format!("--port {}", OPENCODE_PORT)));

        // Verify security restrictions
        assert!(container_config.drop_all_caps);
        assert!(container_config.no_new_privileges);
        assert_eq!(
            container_config.cap_add,
            vec!["NET_BIND_SERVICE".to_string()]
        );

        // Verify agent has isolated home in /tmp
        assert_eq!(
            container_config.env.get("HOME"),
            Some(&"/tmp/agent-home".to_string())
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

        let container_config = DevaipodPod::agent_container_config(
            project_path,
            workspace_folder,
            &bind_home,
            container_home,
            None,
            false,
            "test-volume",
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
    fn test_gator_container_config() {
        let container_config = DevaipodPod::gator_container_config();

        // Verify no mounts (gator doesn't need project access)
        assert!(container_config.mounts.is_empty());

        // Verify command includes port
        let cmd = container_config.command.as_ref().unwrap();
        assert_eq!(cmd[0], "service-gator");
        assert!(cmd.contains(&"--mcp-server".to_string()));
        assert!(cmd.iter().any(|s| s.contains(&GATOR_PORT.to_string())));

        // Verify security restrictions
        assert!(container_config.drop_all_caps);
        assert!(container_config.no_new_privileges);
        assert_eq!(
            container_config.cap_add,
            vec!["NET_BIND_SERVICE".to_string()]
        );
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

        let container_config = DevaipodPod::workspace_container_config(
            project_path,
            workspace_folder,
            None,
            &config,
            &bind_home,
            container_home,
            "test-volume",
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

        let container_config = DevaipodPod::workspace_container_config(
            project_path,
            workspace_folder,
            None,
            &config,
            &bind_home,
            container_home,
            "test-volume",
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
            Some(format!("{}:/usr/local/cargo/bin", super::DEFAULT_CONTAINER_PATH))
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
        assert_eq!(super::resolve_env_value("${containerEnv:PATH}", "PATH"), None);
        // Variable reference with empty suffix
        assert_eq!(super::resolve_env_value("${containerEnv:PATH}:", "PATH"), None);
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

        let container_config = DevaipodPod::workspace_container_config(
            project_path,
            workspace_folder,
            None,
            &config,
            &bind_home,
            container_home,
            "test-volume",
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

        let container_config = DevaipodPod::workspace_container_config(
            project_path,
            workspace_folder,
            None,
            &config,
            &bind_home,
            container_home,
            "test-volume",
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

        let container_config = DevaipodPod::workspace_container_config(
            project_path,
            workspace_folder,
            None,
            &config,
            &bind_home,
            container_home,
            "test-volume",
        );

        assert_eq!(container_config.cap_add, vec!["SYS_PTRACE".to_string()]);
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
    fn test_agent_with_network_isolation() {
        let project_path = Path::new("/home/user/myproject");
        let workspace_folder = "/workspaces/myproject";
        let bind_home = BindHomeConfig::default();
        let container_home = "/home/vscode";

        // Test with network isolation enabled
        let container_config = DevaipodPod::agent_container_config(
            project_path,
            workspace_folder,
            &bind_home,
            container_home,
            None,
            true, // use_proxy
            "test-volume",
        );

        // Should have proxy env vars set
        assert!(container_config.env.contains_key("HTTP_PROXY"));
        assert!(container_config.env.contains_key("HTTPS_PROXY"));
        assert!(container_config.env.contains_key("NO_PROXY"));

        let proxy_url = format!("http://localhost:{}", crate::proxy::PROXY_PORT);
        assert_eq!(container_config.env.get("HTTP_PROXY"), Some(&proxy_url));
        assert_eq!(container_config.env.get("HTTPS_PROXY"), Some(&proxy_url));
    }

    #[test]
    fn test_agent_without_network_isolation() {
        let project_path = Path::new("/home/user/myproject");
        let workspace_folder = "/workspaces/myproject";
        let bind_home = BindHomeConfig::default();
        let container_home = "/home/vscode";

        // Test without network isolation
        let container_config = DevaipodPod::agent_container_config(
            project_path,
            workspace_folder,
            &bind_home,
            container_home,
            None,
            false, // no proxy
            "test-volume",
        );

        // Should NOT have proxy env vars set
        assert!(!container_config.env.contains_key("HTTP_PROXY"));
        assert!(!container_config.env.contains_key("HTTPS_PROXY"));
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

        let container_config = DevaipodPod::workspace_container_config(
            project_path,
            workspace_folder,
            None,
            &config,
            &bind_home,
            container_home,
            "test-volume",
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
        // Add a device via runArgs
        config.run_args = vec!["--device=/dev/custom".to_string()];

        let container_config = DevaipodPod::workspace_container_config(
            project_path,
            workspace_folder,
            None,
            &config,
            &bind_home,
            container_home,
            "test-volume",
        );

        // Device should be in the devices list
        assert!(
            container_config
                .devices
                .contains(&"/dev/custom".to_string()),
            "devices should include /dev/custom from runArgs"
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

        let container_config1 = DevaipodPod::workspace_container_config(
            project_path,
            workspace_folder,
            None,
            &config1,
            &bind_home,
            container_home,
            "test-volume",
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
        );
        assert!(
            container_config2.privileged,
            "both set should still be privileged"
        );
    }
}
