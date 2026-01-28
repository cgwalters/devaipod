//! Podman runtime - spawn podman service and interact via Docker API
//!
//! This module handles:
//! - Spawning a per-process podman service with its own socket
//! - Connecting via bollard (Docker API client)
//! - Image building/pulling
//! - Pod and container lifecycle
//!
//! We spawn our own podman service rather than relying on a system socket
//! for isolation and to avoid permission issues.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use bollard::container::{
    LogsOptions, RemoveContainerOptions, StartContainerOptions, StopContainerOptions,
};
use bollard::exec::{CreateExecOptions, StartExecResults};
use bollard::image::BuildImageOptions;
use bollard::Docker;
use color_eyre::eyre::{bail, Context, Result};
use futures_util::StreamExt;
use tokio::io::AsyncWriteExt;
use tokio::process::Command;

use crate::devcontainer::ImageSource;

/// Podman system info (subset of fields we care about)
#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PodmanSystemInfo {
    pub host: PodmanHostInfo,
}

/// Host info from podman system info
#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PodmanHostInfo {
    /// Whether this is a remote client (e.g., podman machine)
    pub service_is_remote: bool,
    /// The remote socket info
    pub remote_socket: PodmanRemoteSocket,
}

/// Remote socket info from podman system info
#[derive(Debug, serde::Deserialize)]
pub struct PodmanRemoteSocket {
    /// Socket path (e.g., "unix:///run/podman/podman.sock")
    pub path: String,
    /// Whether the socket exists
    pub exists: bool,
}

/// Podman machine inspect output (subset of fields we care about)
#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "PascalCase")]
struct PodmanMachineInspect {
    connection_info: PodmanMachineConnectionInfo,
}

/// Connection info from podman machine inspect
#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "PascalCase")]
struct PodmanMachineConnectionInfo {
    podman_socket: PodmanMachineSocket,
}

/// Socket info from podman machine inspect
#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "PascalCase")]
struct PodmanMachineSocket {
    path: String,
}

/// Get podman system info by running `podman info --format json`
fn get_podman_info() -> Result<PodmanSystemInfo> {
    let output = std::process::Command::new("podman")
        .args(["info", "--format", "json"])
        .output()
        .context("Failed to run podman info")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("podman info failed: {}", stderr);
    }

    serde_json::from_slice(&output.stdout).context("Failed to parse podman info JSON")
}

/// Standard Docker socket path (often symlinked to podman on macOS)
const DOCKER_SOCKET: &str = "/var/run/docker.sock";

/// Get the local socket path for podman in remote mode
///
/// First checks if /var/run/docker.sock exists (commonly symlinked to podman),
/// then falls back to `podman machine inspect` to get the actual socket path.
fn get_remote_socket() -> Result<PathBuf> {
    // Fast path: check if /var/run/docker.sock exists
    let docker_sock = PathBuf::from(DOCKER_SOCKET);
    if docker_sock.exists() {
        tracing::debug!("Using {} for podman connection", DOCKER_SOCKET);
        return Ok(docker_sock);
    }

    // Fallback: query podman machine for the socket path
    tracing::debug!(
        "{} not found, querying podman machine inspect",
        DOCKER_SOCKET
    );

    let output = std::process::Command::new("podman")
        .args(["machine", "inspect"])
        .output()
        .context("Failed to run podman machine inspect")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("podman machine inspect failed: {}", stderr);
    }

    // Output is an array of machine info
    let machines: Vec<PodmanMachineInspect> = serde_json::from_slice(&output.stdout)
        .context("Failed to parse podman machine inspect JSON")?;

    let machine = machines
        .into_iter()
        .next()
        .ok_or_else(|| color_eyre::eyre::eyre!("No podman machine found"))?;

    Ok(PathBuf::from(machine.connection_info.podman_socket.path))
}

/// Check if the devcontainer CLI is available on the system
fn devcontainer_cli_available() -> bool {
    std::process::Command::new("devcontainer")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// A running podman service that we own
pub struct PodmanService {
    /// The socket path we're listening on
    socket_path: PathBuf,
    /// PID of the podman system service process (None when using existing socket in toolbox)
    child_pid: Option<u32>,
    /// Bollard client connected to our socket
    client: Docker,
    /// Whether we're running in toolbox mode (using host podman via flatpak-spawn)
    toolbox_mode: bool,
}

/// Check if we're running inside a toolbox container
fn is_toolbox() -> bool {
    std::env::var_os("TOOLBOX_PATH").is_some()
}

impl PodmanService {
    /// Connect to podman, trying existing sockets before spawning a new service
    ///
    /// Connection strategy:
    /// 1. Toolbox mode: connect to host socket via flatpak-spawn
    /// 2. Remote mode (podman machine): use /var/run/docker.sock or podman machine inspect
    /// 3. Native Linux with existing socket: connect to $XDG_RUNTIME_DIR/podman/podman.sock
    /// 4. Fallback: spawn our own podman system service
    pub async fn spawn() -> Result<Self> {
        let runtime_dir = std::env::var("XDG_RUNTIME_DIR").unwrap_or_else(|_| "/tmp".to_string());

        // In toolbox, connect to existing host socket instead of spawning
        if is_toolbox() {
            return Self::connect_toolbox(&runtime_dir).await;
        }

        // Get podman info to understand the environment
        let podman_info = get_podman_info().context("Failed to get podman info")?;

        // If podman is a remote client (e.g., podman machine on macOS/Windows),
        // connect to existing socket
        if podman_info.host.service_is_remote {
            tracing::debug!(
                "Podman is in remote mode (remote socket: {})",
                podman_info.host.remote_socket.path
            );
            return Self::connect_remote().await;
        }

        // Native podman (Linux): try to use existing socket if available
        if podman_info.host.remote_socket.exists {
            // Socket path may or may not have unix:// prefix depending on podman version
            let socket_path = podman_info
                .host
                .remote_socket
                .path
                .strip_prefix("unix://")
                .unwrap_or(&podman_info.host.remote_socket.path);

            tracing::debug!("Trying existing podman socket at {}", socket_path);
            match Self::try_connect_socket(socket_path).await {
                Ok(service) => return Ok(service),
                Err(e) => {
                    tracing::debug!("Failed to connect to existing socket: {}", e);
                    // Fall through to spawn our own
                }
            }
        }

        // Fallback: spawn our own podman system service
        let socket_name = format!("devaipod-{}.sock", std::process::id());
        let socket_path = PathBuf::from(&runtime_dir).join(socket_name);

        // Remove stale socket if it exists
        let _ = std::fs::remove_file(&socket_path);

        tracing::debug!("Starting podman service at {}", socket_path.display());

        // Spawn podman system service
        // --time=0 means no idle timeout (we manage lifecycle)
        let child = Command::new("podman")
            .args([
                "system",
                "service",
                "--time=0",
                &format!("unix://{}", socket_path.display()),
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .context("Failed to spawn podman service")?;

        // Wait for socket to appear
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        while !socket_path.exists() {
            if tokio::time::Instant::now() > deadline {
                bail!(
                    "Timeout waiting for podman socket at {}",
                    socket_path.display()
                );
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }

        // Connect bollard
        let client = Docker::connect_with_unix(
            &socket_path.to_string_lossy(),
            120, // timeout
            bollard::API_DEFAULT_VERSION,
        )
        .context("Failed to connect to podman socket")?;

        // Verify connection
        client
            .ping()
            .await
            .context("Failed to ping podman service")?;

        tracing::debug!("Podman service ready");

        let child_pid = child.id().expect("child process should have pid");

        Ok(Self {
            socket_path,
            child_pid: Some(child_pid),
            client,
            toolbox_mode: false,
        })
    }

    /// Connect to existing podman socket in remote mode
    ///
    /// When podman is running as a remote client (e.g., podman machine on macOS),
    /// we connect to the existing socket instead of spawning a new service.
    /// First checks /var/run/docker.sock, then falls back to `podman machine inspect`.
    async fn connect_remote() -> Result<Self> {
        let socket_path = get_remote_socket().context(
            "Failed to get podman socket. Is podman machine running? Try: podman machine start",
        )?;

        tracing::debug!(
            "Podman remote mode: connecting to socket at {}",
            socket_path.display()
        );

        if !socket_path.exists() {
            bail!(
                "Podman machine socket {} does not exist. Is podman machine running? Try: podman machine start",
                socket_path.display()
            );
        }

        // Connect bollard
        let client = Docker::connect_with_unix(
            &socket_path.to_string_lossy(),
            120, // timeout
            bollard::API_DEFAULT_VERSION,
        )
        .context("Failed to connect to podman socket")?;

        // Verify connection
        client.ping().await.context(
            "Failed to ping podman service. Is podman machine running? Try: podman machine start",
        )?;

        tracing::debug!("Connected to podman (remote mode)");

        Ok(Self {
            socket_path,
            child_pid: None, // We don't own the process
            client,
            toolbox_mode: false,
        })
    }

    /// Try to connect to an existing podman socket
    ///
    /// Returns Ok if the socket exists and we can ping it, Err otherwise.
    async fn try_connect_socket(socket_path: &str) -> Result<Self> {
        let socket_path = PathBuf::from(socket_path);

        if !socket_path.exists() {
            bail!("Socket {} does not exist", socket_path.display());
        }

        let client = Docker::connect_with_unix(
            &socket_path.to_string_lossy(),
            120,
            bollard::API_DEFAULT_VERSION,
        )
        .context("Failed to connect to socket")?;

        client.ping().await.context("Failed to ping socket")?;

        tracing::debug!(
            "Connected to existing podman socket at {}",
            socket_path.display()
        );

        Ok(Self {
            socket_path,
            child_pid: None, // We don't own this service
            client,
            toolbox_mode: false,
        })
    }

    /// Connect to existing host podman socket (for toolbox mode)
    async fn connect_toolbox(runtime_dir: &str) -> Result<Self> {
        let socket_path = PathBuf::from(runtime_dir).join("podman/podman.sock");

        tracing::debug!(
            "Toolbox mode: connecting to host socket at {}",
            socket_path.display()
        );

        if !socket_path.exists() {
            bail!(
                "Host podman socket not found at {}. Is podman running on the host?",
                socket_path.display()
            );
        }

        // Connect bollard
        let client = Docker::connect_with_unix(
            &socket_path.to_string_lossy(),
            120, // timeout
            bollard::API_DEFAULT_VERSION,
        )
        .context("Failed to connect to host podman socket")?;

        // Verify connection
        client
            .ping()
            .await
            .context("Failed to ping host podman service")?;

        tracing::debug!("Connected to host podman service (toolbox mode)");

        Ok(Self {
            socket_path,
            child_pid: None,
            client,
            toolbox_mode: true,
        })
    }

    /// Create a Command for running podman CLI
    ///
    /// In toolbox mode, uses flatpak-spawn to run podman on the host.
    /// Otherwise, runs podman directly with our socket.
    fn podman_command(&self) -> Command {
        if self.toolbox_mode {
            let mut cmd = Command::new("flatpak-spawn");
            cmd.args(["--host", "/usr/bin/podman"]);
            cmd
        } else {
            let mut cmd = Command::new("podman");
            cmd.args(["--url", &format!("unix://{}", self.socket_path.display())]);
            cmd
        }
    }

    /// Get the bollard client
    #[allow(dead_code)] // Part of public API for future use
    pub fn client(&self) -> &Docker {
        &self.client
    }

    /// Get the socket path (for passing to nested containers if needed)
    #[allow(dead_code)]
    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }

    /// Pull an image
    pub async fn pull_image(&self, image: &str) -> Result<()> {
        use bollard::image::CreateImageOptions;

        tracing::debug!("Pulling image: {}", image);

        let options = CreateImageOptions {
            from_image: image,
            ..Default::default()
        };

        let mut stream = self.client.create_image(Some(options), None, None);
        while let Some(result) = stream.next().await {
            let info = result.context("Error pulling image")?;
            if let Some(status) = info.status {
                tracing::debug!("Pull: {}", status);
            }
        }

        tracing::debug!("Image pulled: {}", image);
        Ok(())
    }

    /// Ensure a gator image is up-to-date, using `--pull=newer` semantics
    ///
    /// This is used for service-gator images which may be local builds.
    /// For remote images, pulls only if a newer version is available.
    /// For local images (localhost/), skips the pull entirely.
    pub async fn ensure_gator_image(&self, image: &str) -> Result<()> {
        // Local images (localhost/) don't need pulling
        if image.starts_with("localhost/") {
            if self.client.inspect_image(image).await.is_ok() {
                tracing::debug!("Local image {} exists", image);
                return Ok(());
            }
            color_eyre::eyre::bail!("Local image {} not found. Build it first.", image);
        }

        // For remote images, use podman pull --policy=newer via CLI
        // This pulls only if a newer version is available
        tracing::debug!("Ensuring image {} is up-to-date (--policy=newer)", image);
        let output = tokio::process::Command::new("podman")
            .args(["pull", "--policy=newer", image])
            .output()
            .await
            .context("Failed to run podman pull")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            color_eyre::eyre::bail!("Failed to pull image {}: {}", image, stderr.trim());
        }

        Ok(())
    }

    /// Build an image from a Dockerfile
    pub async fn build_image(
        &self,
        tag: &str,
        context_path: &Path,
        dockerfile: &str,
        build_args: &HashMap<String, String>,
        target: Option<&str>,
    ) -> Result<()> {
        tracing::info!(
            "Building image from {}...",
            context_path.join(dockerfile).display()
        );

        // Create a tar archive of the build context
        let tar_data = create_tar_archive(context_path)
            .await
            .context("Failed to create build context tarball")?;

        let options = BuildImageOptions {
            dockerfile: dockerfile.to_string(),
            t: tag.to_string(),
            rm: true,
            buildargs: build_args.clone(),
            target: target.unwrap_or_default().to_string(),
            ..Default::default()
        };

        let mut stream = self
            .client
            .build_image(options, None, Some(tar_data.into()));

        while let Some(result) = stream.next().await {
            let info = result.context("Error building image")?;
            if let Some(stream) = info.stream {
                // Print build output, trimming trailing newline
                let output = stream.trim_end();
                if !output.is_empty() {
                    tracing::debug!("Build: {}", output);
                }
            }
            if let Some(error) = info.error {
                bail!("Build error: {}", error);
            }
        }

        tracing::debug!("Image built: {}", tag);
        Ok(())
    }

    /// Build an image using the devcontainer CLI
    ///
    /// This delegates to `devcontainer build` which handles:
    /// - Feature installation
    /// - Dockerfile builds with features layered on top
    /// - Complex build configurations
    ///
    /// Returns the image name on success.
    pub async fn build_with_devcontainer_cli(
        &self,
        project_path: &Path,
        tag: &str,
    ) -> Result<String> {
        tracing::info!(
            "Building image {} using devcontainer CLI (features detected)",
            tag
        );

        let output = Command::new("devcontainer")
            .args([
                "build",
                "--workspace-folder",
                &project_path.to_string_lossy(),
                "--image-name",
                tag,
            ])
            .output()
            .await
            .context("Failed to run devcontainer build")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let stdout = String::from_utf8_lossy(&output.stdout);
            bail!(
                "devcontainer build failed:\nstdout: {}\nstderr: {}",
                stdout,
                stderr
            );
        }

        tracing::info!("Image built with devcontainer CLI: {}", tag);
        Ok(tag.to_string())
    }

    /// Ensure an image is available (pull or build as needed)
    ///
    /// If `has_features` is true and the devcontainer CLI is available,
    /// this will use `devcontainer build` to handle feature installation.
    /// Otherwise, it falls back to direct podman operations (and warns if
    /// features will be ignored).
    pub async fn ensure_image(
        &self,
        source: &ImageSource,
        tag: &str,
        has_features: bool,
        project_path: Option<&Path>,
    ) -> Result<String> {
        // If features are present, try to use devcontainer CLI
        if has_features {
            if devcontainer_cli_available() {
                if let Some(path) = project_path {
                    return self.build_with_devcontainer_cli(path, tag).await;
                } else {
                    tracing::warn!(
                        "Features detected but project path not provided; \
                         falling back to direct build (features will be ignored)"
                    );
                }
            } else {
                tracing::warn!(
                    "devcontainer.json has features but devcontainer CLI is not installed. \
                     Features will be ignored. Install with: npm install -g @devcontainers/cli"
                );
            }
        }

        // Fall back to direct podman operations
        match source {
            ImageSource::Image(image) => {
                // Check if image exists locally first
                if self.client.inspect_image(image).await.is_ok() {
                    tracing::debug!("Image {} already exists locally", image);
                    return Ok(image.clone());
                }
                self.pull_image(image).await?;
                Ok(image.clone())
            }
            ImageSource::Build {
                context,
                dockerfile,
                args,
                target,
            } => {
                self.build_image(tag, context, dockerfile, args, target.as_deref())
                    .await?;
                Ok(tag.to_string())
            }
        }
    }

    /// Get the default user configured in an image
    ///
    /// Returns the user from the image's config, or None if not set or empty.
    pub async fn get_image_user(&self, image: &str) -> Result<Option<String>> {
        let info = self
            .client
            .inspect_image(image)
            .await
            .context("Failed to inspect image")?;

        // The user is in config.user
        if let Some(config) = info.config {
            if let Some(user) = config.user {
                if !user.is_empty() {
                    return Ok(Some(user));
                }
            }
        }
        Ok(None)
    }

    /// Create a pod (containers sharing network namespace)
    ///
    /// Returns the pod ID. Podman implements pods via the API but bollard
    /// doesn't have native support, so we shell out for pod operations.
    ///
    /// Labels can be provided as key-value pairs to attach metadata to the pod.
    pub async fn create_pod(&self, name: &str, labels: &[(String, String)]) -> Result<String> {
        let mut cmd = self.podman_command();
        cmd.args(["pod", "create", "--name", name]);

        // Add labels
        for (key, value) in labels {
            cmd.args(["--label", &format!("{}={}", key, value)]);
        }

        let output = cmd.output().await.context("Failed to create pod")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            bail!("Failed to create pod: {}", stderr);
        }

        let pod_id = String::from_utf8_lossy(&output.stdout).trim().to_string();
        tracing::debug!(
            "Created pod: {} ({})",
            name,
            &pod_id[..pod_id.len().min(12)]
        );
        Ok(pod_id)
    }

    /// Start a pod
    pub async fn start_pod(&self, name: &str) -> Result<()> {
        let output = self
            .podman_command()
            .args(["pod", "start", name])
            .output()
            .await
            .context("Failed to start pod")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            bail!("Failed to start pod: {}", stderr);
        }

        tracing::debug!("Started pod: {}", name);
        Ok(())
    }

    /// Stop a pod
    #[allow(dead_code)] // Part of public API, will be used by stop command
    pub async fn stop_pod(&self, name: &str) -> Result<()> {
        let output = self
            .podman_command()
            .args(["pod", "stop", name])
            .output()
            .await
            .context("Failed to stop pod")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            // Ignore "not running" errors
            if !stderr.contains("not running") {
                bail!("Failed to stop pod: {}", stderr);
            }
        }

        tracing::info!("Stopped pod: {}", name);
        Ok(())
    }

    /// Remove a pod and all its containers
    #[allow(dead_code)] // Part of public API, will be used by delete command
    pub async fn remove_pod(&self, name: &str, force: bool) -> Result<()> {
        let mut args: Vec<&str> = vec!["pod", "rm"];
        if force {
            args.push("--force");
        }
        args.push(name);

        let output = self
            .podman_command()
            .args(args)
            .output()
            .await
            .context("Failed to remove pod")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            bail!("Failed to remove pod: {}", stderr);
        }

        tracing::info!("Removed pod: {}", name);
        Ok(())
    }

    /// Create a named volume if it doesn't exist
    pub async fn create_volume(&self, name: &str) -> Result<()> {
        let output = self
            .podman_command()
            .args(["volume", "create", name])
            .output()
            .await
            .context("Failed to create volume")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            // Ignore "already exists" errors
            if !stderr.contains("already exists") {
                bail!("Failed to create volume {}: {}", name, stderr);
            }
        }

        tracing::debug!("Created volume: {}", name);
        Ok(())
    }

    /// Check if a volume exists
    pub async fn volume_exists(&self, name: &str) -> Result<bool> {
        let output = self
            .podman_command()
            .args(["volume", "exists", name])
            .output()
            .await
            .context("Failed to check volume")?;

        Ok(output.status.success())
    }

    /// Remove a volume
    #[allow(dead_code)] // Part of public API
    pub async fn remove_volume(&self, name: &str, force: bool) -> Result<()> {
        let mut args = vec!["volume", "rm"];
        if force {
            args.push("-f");
        }
        args.push(name);

        let output = self
            .podman_command()
            .args(&args)
            .output()
            .await
            .context("Failed to remove volume")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            if !stderr.contains("no such volume") {
                bail!("Failed to remove volume {}: {}", name, stderr);
            }
        }

        tracing::debug!("Removed volume: {}", name);
        Ok(())
    }

    /// Run a one-shot container to initialize a volume (e.g., clone a repo)
    ///
    /// This creates a temporary container, runs a command, and removes it.
    /// Useful for initializing volumes before the main containers start.
    ///
    /// `extra_binds` allows mounting additional host paths (e.g., for cloning from local git).
    /// Each entry is a "host_path:container_path" string.
    pub async fn run_init_container(
        &self,
        image: &str,
        volume_name: &str,
        mount_path: &str,
        command: &[&str],
        extra_binds: &[String],
    ) -> Result<i32> {
        let container_name = format!("{}-init", volume_name);

        // Remove any existing init container
        let _ = self
            .podman_command()
            .args(["rm", "-f", &container_name])
            .output()
            .await;

        // Run the init container
        let mut args = vec![
            "run".to_string(),
            "--rm".to_string(),
            "--name".to_string(),
            container_name.clone(),
            "-v".to_string(),
            format!("{}:{}", volume_name, mount_path),
        ];

        // Add extra bind mounts (with SELinux label disable and root user if any are present)
        // Root is needed because bind mounts from the host may have different UID mappings
        if !extra_binds.is_empty() {
            args.push("--security-opt".to_string());
            args.push("label=disable".to_string());
            args.push("--user".to_string());
            args.push("0".to_string());
        }
        for bind in extra_binds {
            args.push("-v".to_string());
            args.push(bind.clone());
        }

        args.push(image.to_string());
        args.extend(command.iter().map(|s| s.to_string()));

        let output = self
            .podman_command()
            .args(&args)
            .output()
            .await
            .context("Failed to run init container")?;

        // Print output for debugging
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        if !stdout.is_empty() {
            for line in stdout.lines() {
                tracing::debug!("init: {}", line);
            }
        }
        if !stderr.is_empty() && !output.status.success() {
            for line in stderr.lines() {
                tracing::warn!("init: {}", line);
            }
        }

        Ok(output.status.code().unwrap_or(1))
    }

    /// Create a container in a pod
    pub async fn create_container(
        &self,
        name: &str,
        image: &str,
        pod_name: &str,
        config: ContainerConfig,
    ) -> Result<String> {
        // We need to shell out because bollard doesn't support --pod
        let mut args: Vec<String> = vec![
            "create".to_string(),
            "--pod".to_string(),
            pod_name.to_string(),
            "--name".to_string(),
            name.to_string(),
        ];

        // Add mounts
        for mount in &config.mounts {
            args.push("-v".to_string());
            let mount_str = if mount.readonly {
                format!("{}:{}:ro", mount.source, mount.target)
            } else {
                format!("{}:{}", mount.source, mount.target)
            };
            args.push(mount_str);
        }

        // Add environment variables
        for (key, value) in &config.env {
            args.push("-e".to_string());
            args.push(format!("{}={}", key, value));
        }

        // Add working directory
        if let Some(workdir) = &config.workdir {
            args.push("-w".to_string());
            args.push(workdir.clone());
        }

        // Add user
        if let Some(user) = &config.user {
            args.push("--user".to_string());
            args.push(user.clone());
        }

        // Security options for sandboxed containers
        if config.drop_all_caps {
            args.push("--cap-drop=ALL".to_string());
        }
        for cap in &config.cap_add {
            args.push(format!("--cap-add={}", cap));
        }
        if config.no_new_privileges {
            args.push("--security-opt=no-new-privileges".to_string());
        }

        // Additional security options (e.g., for GPU passthrough)
        for opt in &config.security_opts {
            args.push(format!("--security-opt={}", opt));
        }

        // Device passthrough (for GPUs)
        for device in &config.devices {
            args.push("--device".to_string());
            args.push(device.clone());
        }

        // CDI devices (for NVIDIA GPUs with CDI)
        for cdi in &config.cdi_devices {
            args.push("--device".to_string());
            args.push(cdi.clone());
        }

        // Additional groups (e.g., video for AMD GPUs)
        for group in &config.groups {
            args.push("--group-add".to_string());
            args.push(group.clone());
        }

        // Privileged mode (for nested containers/VMs)
        if config.privileged {
            args.push("--privileged".to_string());
        }

        // Tmpfs mounts
        for tmpfs_path in &config.tmpfs_mounts {
            args.push("--tmpfs".to_string());
            args.push(tmpfs_path.clone());
        }

        // Named volume mounts
        for (volume_name, mount_path) in &config.volume_mounts {
            args.push("-v".to_string());
            args.push(format!("{}:{}", volume_name, mount_path));
        }

        // Podman secrets with type=env (directly set as environment variables)
        for (env_var, secret_name) in &config.secrets {
            args.push("--secret".to_string());
            args.push(format!("{},type=env,target={}", secret_name, env_var));
        }

        // Image
        args.push(image.to_string());

        // Command
        if let Some(cmd) = &config.command {
            args.extend(cmd.iter().cloned());
        }

        let output = self
            .podman_command()
            .args(&args)
            .output()
            .await
            .context("Failed to create container")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            bail!("Failed to create container {}: {}", name, stderr);
        }

        let container_id = String::from_utf8_lossy(&output.stdout).trim().to_string();
        tracing::debug!(
            "Created container: {} ({})",
            name,
            &container_id[..container_id.len().min(12)]
        );
        Ok(container_id)
    }

    /// Start a container
    #[allow(dead_code)] // Part of public API
    pub async fn start_container(&self, name: &str) -> Result<()> {
        self.client
            .start_container(name, None::<StartContainerOptions<String>>)
            .await
            .with_context(|| format!("Failed to start container {}", name))?;
        tracing::debug!("Started container: {}", name);
        Ok(())
    }

    /// Stop a container
    #[allow(dead_code)] // Part of public API
    pub async fn stop_container(&self, name: &str, timeout_secs: i64) -> Result<()> {
        let options = StopContainerOptions { t: timeout_secs };
        self.client
            .stop_container(name, Some(options))
            .await
            .with_context(|| format!("Failed to stop container {}", name))?;
        tracing::debug!("Stopped container: {}", name);
        Ok(())
    }

    /// Remove a container
    #[allow(dead_code)]
    pub async fn remove_container(&self, name: &str, force: bool) -> Result<()> {
        let options = RemoveContainerOptions {
            force,
            ..Default::default()
        };
        self.client
            .remove_container(name, Some(options))
            .await
            .with_context(|| format!("Failed to remove container {}", name))?;
        tracing::debug!("Removed container: {}", name);
        Ok(())
    }

    /// Execute a command in a running container
    ///
    /// If `quiet` is true, output is captured and only shown on failure.
    /// If `quiet` is false, output is streamed to stdout/stderr.
    pub async fn exec(
        &self,
        container: &str,
        cmd: &[&str],
        user: Option<&str>,
        workdir: Option<&str>,
    ) -> Result<i64> {
        self.exec_impl(container, cmd, user, workdir, false).await
    }

    /// Execute a command quietly (capture output, only show on failure)
    pub async fn exec_quiet(
        &self,
        container: &str,
        cmd: &[&str],
        user: Option<&str>,
        workdir: Option<&str>,
    ) -> Result<i64> {
        self.exec_impl(container, cmd, user, workdir, true).await
    }

    async fn exec_impl(
        &self,
        container: &str,
        cmd: &[&str],
        user: Option<&str>,
        workdir: Option<&str>,
        quiet: bool,
    ) -> Result<i64> {
        let exec = self
            .client
            .create_exec(
                container,
                CreateExecOptions {
                    cmd: Some(cmd.to_vec()),
                    user,
                    working_dir: workdir,
                    attach_stdout: Some(true),
                    attach_stderr: Some(true),
                    ..Default::default()
                },
            )
            .await
            .context("Failed to create exec")?;

        let result = self
            .client
            .start_exec(&exec.id, None)
            .await
            .context("Failed to start exec")?;

        let mut stdout_buf = Vec::new();
        let mut stderr_buf = Vec::new();

        match result {
            StartExecResults::Attached { mut output, .. } => {
                while let Some(chunk) = output.next().await {
                    match chunk {
                        Ok(bollard::container::LogOutput::StdOut { message }) => {
                            if quiet {
                                stdout_buf.extend_from_slice(&message);
                            } else {
                                tokio::io::stdout().write_all(&message).await?;
                            }
                        }
                        Ok(bollard::container::LogOutput::StdErr { message }) => {
                            if quiet {
                                stderr_buf.extend_from_slice(&message);
                            } else {
                                tokio::io::stderr().write_all(&message).await?;
                            }
                        }
                        Ok(_) => {}
                        Err(e) => {
                            tracing::warn!("Exec output error: {}", e);
                        }
                    }
                }
            }
            StartExecResults::Detached => {}
        }

        // Get exit code
        let inspect = self
            .client
            .inspect_exec(&exec.id)
            .await
            .context("Failed to inspect exec")?;

        let exit_code = inspect.exit_code.unwrap_or(-1);

        // If quiet mode and command failed, show the captured output
        if quiet && exit_code != 0 {
            if !stdout_buf.is_empty() {
                tokio::io::stdout().write_all(&stdout_buf).await?;
            }
            if !stderr_buf.is_empty() {
                tokio::io::stderr().write_all(&stderr_buf).await?;
            }
        }

        Ok(exit_code)
    }

    /// Execute a command and return its output
    ///
    /// Returns (exit_code, stdout, stderr)
    pub async fn exec_output(
        &self,
        container: &str,
        cmd: &[&str],
    ) -> Result<(i64, Vec<u8>, Vec<u8>)> {
        let exec = self
            .client
            .create_exec(
                container,
                CreateExecOptions {
                    cmd: Some(cmd.to_vec()),
                    user: None,
                    working_dir: None,
                    attach_stdout: Some(true),
                    attach_stderr: Some(true),
                    ..Default::default()
                },
            )
            .await
            .context("Failed to create exec")?;

        let result = self
            .client
            .start_exec(&exec.id, None)
            .await
            .context("Failed to start exec")?;

        let mut stdout_buf = Vec::new();
        let mut stderr_buf = Vec::new();

        match result {
            StartExecResults::Attached { mut output, .. } => {
                while let Some(chunk) = output.next().await {
                    match chunk {
                        Ok(bollard::container::LogOutput::StdOut { message }) => {
                            stdout_buf.extend_from_slice(&message);
                        }
                        Ok(bollard::container::LogOutput::StdErr { message }) => {
                            stderr_buf.extend_from_slice(&message);
                        }
                        Ok(_) => {}
                        Err(e) => {
                            tracing::warn!("Exec output error: {}", e);
                        }
                    }
                }
            }
            StartExecResults::Detached => {}
        }

        let inspect = self
            .client
            .inspect_exec(&exec.id)
            .await
            .context("Failed to inspect exec")?;

        let exit_code = inspect.exit_code.unwrap_or(-1);
        Ok((exit_code, stdout_buf, stderr_buf))
    }

    /// Get container logs
    #[allow(dead_code)]
    pub async fn logs(&self, container: &str, follow: bool) -> Result<()> {
        let options = LogsOptions::<String> {
            stdout: true,
            stderr: true,
            follow,
            ..Default::default()
        };

        let mut stream = self.client.logs(container, Some(options));
        while let Some(result) = stream.next().await {
            match result {
                Ok(bollard::container::LogOutput::StdOut { message }) => {
                    tokio::io::stdout().write_all(&message).await?;
                }
                Ok(bollard::container::LogOutput::StdErr { message }) => {
                    tokio::io::stderr().write_all(&message).await?;
                }
                Ok(_) => {}
                Err(e) => {
                    tracing::warn!("Log error: {}", e);
                    break;
                }
            }
        }
        Ok(())
    }

    /// Copy a file or directory into a running container
    ///
    /// Uses `podman cp` to copy files into the container. This avoids permission
    /// issues with bind mounts in rootless podman.
    ///
    /// The `owner` parameter sets ownership of the copied files (e.g., "1000:1000" or "vscode").
    pub async fn copy_to_container(
        &self,
        container: &str,
        source: &Path,
        target: &str,
        owner: Option<&str>,
    ) -> Result<()> {
        // First, ensure the parent directory exists in the container
        let target_parent = std::path::Path::new(target)
            .parent()
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_else(|| "/".to_string());

        // Create parent directory with mkdir -p
        let mkdir_output = self
            .podman_command()
            .args(["exec", container, "mkdir", "-p", &target_parent])
            .output()
            .await
            .context("Failed to create parent directory")?;

        if !mkdir_output.status.success() {
            let stderr = String::from_utf8_lossy(&mkdir_output.stderr);
            tracing::warn!(
                "Failed to create parent directory {}: {}",
                target_parent,
                stderr
            );
            // Continue anyway, cp might still work
        }

        // Copy the file/directory
        let container_target = format!("{}:{}", container, target);
        let output = self
            .podman_command()
            .args(["cp", &source.to_string_lossy(), &container_target])
            .output()
            .await
            .context("Failed to execute podman cp")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            color_eyre::eyre::bail!(
                "Failed to copy {} to {}:{}: {}",
                source.display(),
                container,
                target,
                stderr
            );
        }

        // Set ownership if specified
        if let Some(owner) = owner {
            let chown_output = self
                .podman_command()
                .args(["exec", container, "chown", "-R", owner, target])
                .output()
                .await
                .context("Failed to change ownership")?;

            if !chown_output.status.success() {
                let stderr = String::from_utf8_lossy(&chown_output.stderr);
                tracing::warn!("Failed to chown {} to {}: {}", target, owner, stderr);
                // Don't fail - chown might fail if running as non-root
            }
        }

        tracing::debug!("Copied {} to {}:{}", source.display(), container, target);
        Ok(())
    }
}

impl Drop for PodmanService {
    fn drop(&mut self) {
        // Only kill the child process if we spawned one (not in toolbox mode)
        if let Some(child_pid) = self.child_pid {
            if let Some(pid) = rustix::process::Pid::from_raw(child_pid as i32) {
                let _ = rustix::process::kill_process(pid, rustix::process::Signal::TERM);
            }
            // Only clean up socket if we created it
            let _ = std::fs::remove_file(&self.socket_path);
        }
    }
}

/// Configuration for creating a container
#[derive(Debug, Default, Clone)]
pub struct ContainerConfig {
    /// Volume mounts
    pub mounts: Vec<MountConfig>,
    /// Environment variables
    pub env: HashMap<String, String>,
    /// Working directory
    pub workdir: Option<String>,
    /// User to run as
    pub user: Option<String>,
    /// Command to run
    pub command: Option<Vec<String>>,
    /// Drop all capabilities
    pub drop_all_caps: bool,
    /// Capabilities to add back
    pub cap_add: Vec<String>,
    /// Prevent gaining new privileges
    pub no_new_privileges: bool,
    /// Device paths to pass through (e.g., /dev/nvidia0, /dev/kvm)
    pub devices: Vec<String>,
    /// CDI device names (e.g., nvidia.com/gpu=all)
    pub cdi_devices: Vec<String>,
    /// Security options (e.g., label=disable)
    pub security_opts: Vec<String>,
    /// Additional groups to add
    pub groups: Vec<String>,
    /// Run container in privileged mode (for nested containers/VMs)
    pub privileged: bool,
    /// Tmpfs mounts (paths that will be mounted as tmpfs)
    pub tmpfs_mounts: Vec<String>,
    /// Named volume mounts (volume_name -> mount_path)
    pub volume_mounts: Vec<(String, String)>,
    /// Podman secrets to expose as environment variables via type=env.
    /// Each tuple is (env_var_name, secret_name).
    /// Generates: --secret secret_name,type=env,target=ENV_VAR_NAME
    pub secrets: Vec<(String, String)>,
}

/// Mount configuration
#[derive(Debug, Clone)]
pub struct MountConfig {
    pub source: String,
    pub target: String,
    pub readonly: bool,
}

/// Create a tar archive of a directory
async fn create_tar_archive(path: &Path) -> Result<Vec<u8>> {
    let path = path.to_path_buf();

    // Run in blocking task since tar is sync
    tokio::task::spawn_blocking(move || {
        let mut builder = tar::Builder::new(Vec::new());
        builder
            .append_dir_all(".", &path)
            .context("Failed to add directory to tar")?;
        builder.finish().context("Failed to finish tar")?;
        Ok(builder.into_inner().context("Failed to get tar data")?)
    })
    .await
    .context("Tar task panicked")?
}

#[cfg(test)]
mod tests {
    use super::*;

    // Integration tests that require podman would go here
    // For unit tests, we'd mock the podman interactions

    #[test]
    fn test_devcontainer_cli_available() {
        // This test just verifies the function doesn't panic
        // The actual result depends on whether devcontainer CLI is installed
        let _available = devcontainer_cli_available();
    }
}
