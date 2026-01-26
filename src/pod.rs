//! Multi-container pod orchestration for devaipod
//!
//! This module manages a pod containing multiple containers:
//! - `workspace`: The user's development environment (from devcontainer.json)
//! - `agent`: Same image running `opencode serve` with restricted security
//! - `gator`: Optional service-gator MCP server container
//!
//! All containers share the same network namespace via the pod, allowing
//! localhost communication between the agent and workspace.

use std::path::Path;

use color_eyre::eyre::{Context, Result};

use crate::devcontainer::DevcontainerConfig;
use crate::podman::{ContainerConfig, MountConfig, PodmanService};

/// Port for the opencode server in the agent container
pub const OPENCODE_PORT: u16 = 4096;

/// Port for the service-gator MCP server
pub const GATOR_PORT: u16 = 8765;

/// Image for the service-gator container
const GATOR_IMAGE: &str = "ghcr.io/cgwalters/service-gator:latest";

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
    /// The image used for workspace and agent containers
    pub image: String,
    /// Workspace folder inside the container
    pub workspace_folder: String,
}

impl DevaipodPod {
    /// Create a new pod with all containers
    ///
    /// This will:
    /// 1. Build or pull the image from devcontainer config
    /// 2. Create the pod
    /// 3. Create workspace, agent, and optionally gator containers
    pub async fn create(
        podman: &PodmanService,
        project_path: &Path,
        config: &DevcontainerConfig,
        pod_name: &str,
        enable_gator: bool,
    ) -> Result<Self> {
        // Derive project name from path
        let project_name = project_path
            .file_name()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_else(|| "project".to_string());

        // Get workspace folder
        let workspace_folder = config.workspace_folder_for_project(&project_name);

        // Find devcontainer.json directory for resolving relative paths
        let devcontainer_json = crate::devcontainer::find_devcontainer_json(project_path)?;
        let devcontainer_dir = devcontainer_json
            .parent()
            .unwrap_or(project_path);

        // Determine image source and ensure image is available
        let image_source = config.image_source(devcontainer_dir)?;
        let image_tag = format!("devaipod-{}", pod_name);
        let image = podman
            .ensure_image(&image_source, &image_tag)
            .await
            .context("Failed to ensure container image")?;

        // Create the pod
        podman
            .create_pod(pod_name)
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
        );
        podman
            .create_container(&workspace_container, &image, pod_name, workspace_config)
            .await
            .with_context(|| format!("Failed to create workspace container: {}", workspace_container))?;

        // Create agent container with restricted security
        let agent_config = Self::agent_container_config(
            project_path,
            &workspace_folder,
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
                .with_context(|| format!("Failed to create gator container: {}", gator_container_name))?;

            Some(gator_container_name)
        } else {
            None
        };

        tracing::info!(
            "Created pod '{}' with {} containers",
            pod_name,
            if gator_container.is_some() { 3 } else { 2 }
        );

        Ok(Self {
            pod_name: pod_name.to_string(),
            workspace_container,
            agent_container,
            gator_container,
            image,
            workspace_folder,
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

    /// Stop the pod
    pub async fn stop(&self, podman: &PodmanService) -> Result<()> {
        podman
            .stop_pod(&self.pod_name)
            .await
            .with_context(|| format!("Failed to stop pod: {}", self.pod_name))?;

        tracing::info!("Stopped pod '{}'", self.pod_name);
        Ok(())
    }

    /// Remove the pod and all containers
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
        project_path: &Path,
        workspace_folder: &str,
        user: Option<&str>,
        config: &DevcontainerConfig,
    ) -> ContainerConfig {
        let mut env = config.container_env.clone();
        // Merge remote_env (these typically take precedence)
        env.extend(config.remote_env.clone());

        ContainerConfig {
            mounts: vec![MountConfig {
                source: project_path.to_string_lossy().to_string(),
                target: workspace_folder.to_string(),
                readonly: false,
            }],
            env,
            workdir: Some(workspace_folder.to_string()),
            user: user.map(|u| u.to_string()),
            // Keep the container running (use absolute path for reliability)
            command: Some(vec![
                "/usr/bin/sleep".to_string(),
                "infinity".to_string(),
            ]),
            drop_all_caps: false,
            cap_add: config.cap_add.clone(),
            no_new_privileges: false,
        }
    }

    /// Create container config for the agent container
    ///
    /// The agent runs `opencode serve` with restricted security:
    /// - Drops all capabilities except NET_BIND_SERVICE
    /// - Sets no-new-privileges
    /// - Uses a separate home directory
    fn agent_container_config(
        project_path: &Path,
        workspace_folder: &str,
    ) -> ContainerConfig {
        // Use /tmp as agent home - it's always writable and isolated per container.
        // In the future we could mount a named volume for persistent agent state.
        let agent_home = "/tmp/agent-home".to_string();

        let mut env = std::collections::HashMap::new();
        env.insert("HOME".to_string(), agent_home.clone());
        // Ensure agent can find opencode in PATH
        env.insert("PATH".to_string(), "/usr/local/bin:/usr/bin:/bin".to_string());
        // Tell opencode to create its config in the agent home
        env.insert("XDG_CONFIG_HOME".to_string(), format!("{agent_home}/.config"));
        env.insert("XDG_DATA_HOME".to_string(), format!("{agent_home}/.local/share"));

        ContainerConfig {
            mounts: vec![
                // Project mount - agent can read/write code
                MountConfig {
                    source: project_path.to_string_lossy().to_string(),
                    target: workspace_folder.to_string(),
                    readonly: false,
                },
            ],
            env,
            workdir: Some(workspace_folder.to_string()),
            // Run as a non-root user if possible (agent user)
            user: None, // Let the image decide, or we could set "1000" for a generic user
            command: Some(vec![
                // Create home dir first, then run opencode
                "/bin/sh".to_string(),
                "-c".to_string(),
                format!(
                    "mkdir -p {agent_home} && exec opencode serve --port {} --hostname 0.0.0.0",
                    OPENCODE_PORT
                ),
            ]),
            // Security restrictions
            drop_all_caps: true,
            cap_add: vec!["NET_BIND_SERVICE".to_string()],
            no_new_privileges: true,
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

        let container_config = DevaipodPod::workspace_container_config(
            project_path,
            workspace_folder,
            Some("vscode"),
            &config,
        );

        assert_eq!(container_config.mounts.len(), 1);
        assert_eq!(container_config.mounts[0].source, "/home/user/myproject");
        assert_eq!(container_config.mounts[0].target, "/workspaces/myproject");
        assert!(!container_config.mounts[0].readonly);
        assert_eq!(container_config.user, Some("vscode".to_string()));
        assert_eq!(container_config.workdir, Some("/workspaces/myproject".to_string()));
        assert_eq!(
            container_config.command,
            Some(vec!["/usr/bin/sleep".to_string(), "infinity".to_string()])
        );
        assert!(!container_config.drop_all_caps);
        assert!(!container_config.no_new_privileges);
    }

    #[test]
    fn test_agent_container_config() {
        let project_path = Path::new("/home/user/myproject");
        let workspace_folder = "/workspaces/myproject";

        let container_config = DevaipodPod::agent_container_config(
            project_path,
            workspace_folder,
        );

        // Verify mounts
        assert_eq!(container_config.mounts.len(), 1);
        assert_eq!(container_config.mounts[0].target, "/workspaces/myproject");

        // Verify command wraps opencode in a shell to create home dir
        let cmd = container_config.command.as_ref().unwrap();
        assert_eq!(cmd[0], "/bin/sh");
        assert_eq!(cmd[1], "-c");
        assert!(cmd[2].contains("opencode serve"));
        assert!(cmd[2].contains(&format!("--port {}", OPENCODE_PORT)));

        // Verify security restrictions
        assert!(container_config.drop_all_caps);
        assert!(container_config.no_new_privileges);
        assert_eq!(container_config.cap_add, vec!["NET_BIND_SERVICE".to_string()]);

        // Verify agent has isolated home in /tmp
        assert_eq!(
            container_config.env.get("HOME"),
            Some(&"/tmp/agent-home".to_string())
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
        assert_eq!(container_config.cap_add, vec!["NET_BIND_SERVICE".to_string()]);
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
    fn test_workspace_config_with_env() {
        let project_path = Path::new("/project");
        let workspace_folder = "/workspaces/project";
        
        let mut config = DevcontainerConfig::default();
        config.container_env.insert("FOO".to_string(), "bar".to_string());
        config.remote_env.insert("BAZ".to_string(), "qux".to_string());
        
        let container_config = DevaipodPod::workspace_container_config(
            project_path,
            workspace_folder,
            None,
            &config,
        );

        assert_eq!(container_config.env.get("FOO"), Some(&"bar".to_string()));
        assert_eq!(container_config.env.get("BAZ"), Some(&"qux".to_string()));
    }

    #[test]
    fn test_workspace_config_with_caps() {
        let project_path = Path::new("/project");
        let workspace_folder = "/workspaces/project";
        
        let mut config = DevcontainerConfig::default();
        config.cap_add = vec!["SYS_PTRACE".to_string()];
        
        let container_config = DevaipodPod::workspace_container_config(
            project_path,
            workspace_folder,
            None,
            &config,
        );

        assert_eq!(container_config.cap_add, vec!["SYS_PTRACE".to_string()]);
    }
}
