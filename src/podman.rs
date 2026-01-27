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
    LogsOptions, RemoveContainerOptions, StartContainerOptions,
    StopContainerOptions,
};
use bollard::exec::{CreateExecOptions, StartExecResults};
use bollard::image::BuildImageOptions;
use bollard::Docker;
use color_eyre::eyre::{bail, Context, Result};
use futures_util::StreamExt;
use tokio::io::AsyncWriteExt;
use tokio::process::Command;

use crate::devcontainer::ImageSource;

/// Status of a podman pod
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PodStatus {
    Running,
    Stopped,
    Created,
    Unknown(String),
}

impl PodStatus {
    /// Check if the pod is running
    pub fn is_running(&self) -> bool {
        matches!(self, PodStatus::Running)
    }
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
    /// Spawn a new podman service with a temporary socket
    ///
    /// The service will be killed when this struct is dropped.
    /// In toolbox mode, connects to existing host socket instead of spawning.
    pub async fn spawn() -> Result<Self> {
        let runtime_dir = std::env::var("XDG_RUNTIME_DIR").unwrap_or_else(|_| "/tmp".to_string());

        // In toolbox, connect to existing host socket instead of spawning
        if is_toolbox() {
            return Self::connect_toolbox(&runtime_dir).await;
        }

        // Create a unique socket path in runtime dir or /tmp
        let socket_name = format!("devaipod-{}.sock", std::process::id());
        let socket_path = PathBuf::from(&runtime_dir).join(socket_name);

        // Remove stale socket if it exists
        let _ = std::fs::remove_file(&socket_path);

        tracing::debug!("Starting podman service at {}", socket_path.display());

        // Spawn podman system service
        // --time=0 means no idle timeout (we manage lifecycle)
        let child = Command::new("/usr/bin/podman")
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
            let mut cmd = Command::new("/usr/bin/podman");
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

        tracing::info!("Pulling image: {}", image);

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

        tracing::info!("Image pulled: {}", image);
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
            "Building image {} from {}",
            tag,
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

        let mut stream = self.client.build_image(options, None, Some(tar_data.into()));

        while let Some(result) = stream.next().await {
            let info = result.context("Error building image")?;
            if let Some(stream) = info.stream {
                // Print build output, trimming trailing newline
                let output = stream.trim_end();
                if !output.is_empty() {
                    tracing::info!("Build: {}", output);
                }
            }
            if let Some(error) = info.error {
                bail!("Build error: {}", error);
            }
        }

        tracing::info!("Image built: {}", tag);
        Ok(())
    }

    /// Ensure an image is available (pull or build as needed)
    pub async fn ensure_image(&self, source: &ImageSource, tag: &str) -> Result<String> {
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

    /// Create a pod (containers sharing network namespace)
    ///
    /// Returns the pod ID. Podman implements pods via the API but bollard
    /// doesn't have native support, so we shell out for pod operations.
    pub async fn create_pod(&self, name: &str) -> Result<String> {
        let output = self
            .podman_command()
            .args(["pod", "create", "--name", name])
            .output()
            .await
            .context("Failed to create pod")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            bail!("Failed to create pod: {}", stderr);
        }

        let pod_id = String::from_utf8_lossy(&output.stdout).trim().to_string();
        tracing::info!("Created pod: {} ({})", name, &pod_id[..pod_id.len().min(12)]);
        Ok(pod_id)
    }

    /// Get pod status. Returns None if pod doesn't exist.
    pub async fn get_pod_status(&self, name: &str) -> Result<Option<PodStatus>> {
        let output = self
            .podman_command()
            .args(["pod", "inspect", "--format", "{{.State}}", name])
            .output()
            .await
            .context("Failed to inspect pod")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            // "no pod with name or ID" means the pod doesn't exist
            if stderr.contains("no pod with name or ID") || stderr.contains("no such pod") {
                return Ok(None);
            }
            bail!("Failed to inspect pod: {}", stderr);
        }

        let state = String::from_utf8_lossy(&output.stdout).trim().to_lowercase();
        let status = match state.as_str() {
            "running" => PodStatus::Running,
            "exited" | "stopped" | "dead" => PodStatus::Stopped,
            "created" => PodStatus::Created,
            _ => PodStatus::Unknown(state),
        };
        Ok(Some(status))
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

        tracing::info!("Started pod: {}", name);
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
        tracing::debug!("Created container: {} ({})", name, &container_id[..container_id.len().min(12)]);
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
    pub async fn exec(
        &self,
        container: &str,
        cmd: &[&str],
        user: Option<&str>,
        workdir: Option<&str>,
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

        match result {
            StartExecResults::Attached { mut output, .. } => {
                while let Some(chunk) = output.next().await {
                    match chunk {
                        Ok(bollard::container::LogOutput::StdOut { message }) => {
                            tokio::io::stdout().write_all(&message).await?;
                        }
                        Ok(bollard::container::LogOutput::StdErr { message }) => {
                            tokio::io::stderr().write_all(&message).await?;
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

        Ok(inspect.exit_code.unwrap_or(-1))
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
            .args([
                "exec",
                container,
                "mkdir",
                "-p",
                &target_parent,
            ])
            .output()
            .await
            .context("Failed to create parent directory")?;

        if !mkdir_output.status.success() {
            let stderr = String::from_utf8_lossy(&mkdir_output.stderr);
            tracing::warn!("Failed to create parent directory {}: {}", target_parent, stderr);
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
                .args([
                    "exec",
                    container,
                    "chown",
                    "-R",
                    owner,
                    target,
                ])
                .output()
                .await
                .context("Failed to change ownership")?;

            if !chown_output.status.success() {
                let stderr = String::from_utf8_lossy(&chown_output.stderr);
                tracing::warn!(
                    "Failed to chown {} to {}: {}",
                    target,
                    owner,
                    stderr
                );
                // Don't fail - chown might fail if running as non-root
            }
        }

        tracing::debug!(
            "Copied {} to {}:{}",
            source.display(),
            container,
            target
        );
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
    /// Device paths to pass through (e.g., /dev/nvidia0)
    pub devices: Vec<String>,
    /// CDI device names (e.g., nvidia.com/gpu=all)
    pub cdi_devices: Vec<String>,
    /// Security options (e.g., label=disable)
    pub security_opts: Vec<String>,
    /// Additional groups to add
    pub groups: Vec<String>,
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
}
