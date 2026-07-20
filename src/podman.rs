//! Podman runtime - spawn podman service and interact via Docker API
//!
//! This module handles:
//! - Connecting to host podman/docker via mounted socket
//! - Image building/pulling
//! - Pod and container lifecycle
//!
//! We expect to run inside a container with the host's podman/docker socket
//! mounted at /run/docker.sock (or set via DOCKER_HOST).

use std::collections::HashMap;
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use bollard::Docker;
use bollard::container::{
    LogsOptions, RemoveContainerOptions, StartContainerOptions, StopContainerOptions,
    WaitContainerOptions,
};
use bollard::exec::{CreateExecOptions, StartExecResults};
use bollard::image::BuildImageOptions;
use color_eyre::eyre::{Context, Result, bail};
use futures_util::StreamExt;
use tokio::io::AsyncWriteExt;
use tokio::process::Command;

use crate::devcontainer::ImageSource;

// TODO: Instead of requiring the launcher to mount the socket with `-v` and
// pass DEVAIPOD_HOST_SOCKET, we could use the bootc approach: run with
// `--privileged --pid=host` and use `open_tree`/`move_mount` via
// `/proc/1/ns/mnt` to grab the socket from the host's mount namespace
// directly.  See bootc's `ensure_mirrored_host_mount()` in
// `crates/mount/src/mount.rs` for the implementation pattern.  This would
// eliminate the `-v` socket mount and DEVAIPOD_HOST_SOCKET entirely.

/// Modern canonical socket path (Docker and Podman)
const DOCKER_SOCKET: &str = "/run/docker.sock";

/// Traditional socket path (same on most Linux where /var/run -> /run)
const DOCKER_SOCKET_VAR: &str = "/var/run/docker.sock";

/// Legacy podman socket path (deprecated fallback)
const PODMAN_SOCKET: &str = "/run/podman/podman.sock";

/// Legacy environment variable (deprecated, use DOCKER_HOST instead)
const PODMAN_SOCKET_ENV: &str = "DEVAIPOD_PODMAN_SOCKET";

/// Find the container runtime socket path.
///
/// Probe order:
/// 1. `DOCKER_HOST` env var (standard, `unix:///path` format)
/// 2. `DEVAIPOD_PODMAN_SOCKET` env var (deprecated, warns)
/// 3. `/run/docker.sock` (modern canonical path)
/// 4. `/var/run/docker.sock` (traditional path)
/// 5. `/run/podman/podman.sock` (deprecated fallback, warns)
/// 6. `$XDG_RUNTIME_DIR/podman/podman.sock` (host rootless fallback, warns)
pub fn get_container_socket() -> Result<PathBuf> {
    // 1. DOCKER_HOST - the standard env var honored by Docker, Podman, and all major tools
    if let Ok(docker_host) = std::env::var("DOCKER_HOST")
        && let Some(path) = parse_docker_host(&docker_host)
    {
        let path = PathBuf::from(path);
        if path.exists() {
            tracing::debug!("Using {} (from DOCKER_HOST)", path.display());
            return Ok(path);
        }
        tracing::warn!(
            "DOCKER_HOST points to {} but socket does not exist",
            path.display()
        );
    }
    // If DOCKER_HOST was set but we couldn't use it, fall through to other probes

    // 2. DEVAIPOD_PODMAN_SOCKET - deprecated, mapped to DOCKER_HOST equivalent
    if let Ok(path_str) = std::env::var(PODMAN_SOCKET_ENV) {
        let path = PathBuf::from(&path_str);
        if path.exists() {
            tracing::warn!(
                "DEVAIPOD_PODMAN_SOCKET is deprecated; use DOCKER_HOST=unix://{} instead",
                path.display()
            );
            return Ok(path);
        }
    }

    // 3. /run/docker.sock - modern canonical path
    let docker_sock = PathBuf::from(DOCKER_SOCKET);
    if docker_sock.exists() {
        tracing::debug!("Using {}", DOCKER_SOCKET);
        return Ok(docker_sock);
    }

    // 4. /var/run/docker.sock - traditional path
    let docker_sock_var = PathBuf::from(DOCKER_SOCKET_VAR);
    if docker_sock_var.exists() {
        tracing::debug!("Using {}", DOCKER_SOCKET_VAR);
        return Ok(docker_sock_var);
    }

    // 5. /run/podman/podman.sock - deprecated fallback
    let podman_sock = PathBuf::from(PODMAN_SOCKET);
    if podman_sock.exists() {
        tracing::warn!(
            "Found podman socket at {}; consider mounting it at {} or setting DOCKER_HOST instead",
            PODMAN_SOCKET,
            DOCKER_SOCKET
        );
        return Ok(podman_sock);
    }

    // 6. XDG_RUNTIME_DIR for rootless podman on host
    if let Ok(xdg_runtime) = std::env::var("XDG_RUNTIME_DIR") {
        let xdg_sock = PathBuf::from(xdg_runtime).join("podman/podman.sock");
        if xdg_sock.exists() {
            tracing::info!(
                "Using rootless podman socket at {}; consider setting DOCKER_HOST=unix://{} instead",
                xdg_sock.display(),
                xdg_sock.display()
            );
            return Ok(xdg_sock);
        }
    }

    // 7. Last resort: try to spawn a local podman system service
    if let Ok(path) = ensure_podman_socket() {
        return Ok(path);
    }

    bail!(
        "No container socket found. Mount the host socket at {} or set DOCKER_HOST",
        DOCKER_SOCKET,
    )
}

/// Compute the fallback socket path for auto-spawned podman service.
///
/// Uses `$XDG_RUNTIME_DIR/podman/podman.sock` if available, otherwise
/// falls back to `/tmp/devaipod-podman-$UID/podman.sock`.
fn auto_socket_path() -> PathBuf {
    if let Ok(xdg) = std::env::var("XDG_RUNTIME_DIR") {
        PathBuf::from(xdg).join("podman/podman.sock")
    } else {
        let uid = rustix::process::getuid().as_raw();
        PathBuf::from(format!("/tmp/devaipod-podman-{}", uid)).join("podman.sock")
    }
}

/// Guard that kills the podman system service child process on drop.
///
/// This lifecycle-binds the spawned podman service to the devaipod process:
/// when devaipod exits (normally or abnormally), the child is killed.
struct PodmanServiceGuard {
    child: std::process::Child,
}

impl Drop for PodmanServiceGuard {
    fn drop(&mut self) {
        let pid = self.child.id();
        tracing::debug!("Stopping auto-spawned podman service (pid {})", pid);
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Global guard for the auto-spawned podman service process.
///
/// Using Mutex<Option<>> so we can spawn at most once per process lifetime.
static PODMAN_SERVICE_GUARD: Mutex<Option<PodmanServiceGuard>> = Mutex::new(None);

/// Ensure a podman socket is available, spawning `podman system service` if needed.
///
/// This is the last-resort fallback for environments where:
/// - No socket is mounted (no `-v /run/docker.sock`)
/// - No systemd socket activation is available (e.g. containers with podman-init as PID 1)
/// - But the `podman` CLI is installed and functional
///
/// The spawned process is lifecycle-bound to the current process via a global
/// guard that kills the child on drop.
pub(crate) fn ensure_podman_socket() -> Result<PathBuf> {
    let mut guard = PODMAN_SERVICE_GUARD
        .lock()
        .map_err(|e| color_eyre::eyre::eyre!("Lock poisoned: {}", e))?;

    let socket_path = auto_socket_path();

    // If we already spawned, check the child is still alive
    if let Some(ref mut g) = *guard {
        match g.child.try_wait() {
            Ok(None) if socket_path.exists() => {
                // Child alive and socket exists — all good
                return Ok(socket_path);
            }
            Ok(None) => {
                // Child alive but socket gone — unusual, give it a moment
                tracing::debug!("Podman service running but socket missing, waiting...");
                for _ in 0..20 {
                    if socket_path.exists() {
                        return Ok(socket_path);
                    }
                    std::thread::sleep(std::time::Duration::from_millis(100));
                }
                // Still no socket — kill the stale child and respawn below
                tracing::warn!("Podman service child alive but socket never appeared, respawning");
            }
            _ => {
                // Child exited — clear the guard
                tracing::debug!("Auto-spawned podman service has exited, will respawn if needed");
            }
        }
        // Take and drop the old guard (kills the child if still alive)
        *guard = None;
    }

    // Check if podman CLI is available
    if !std::process::Command::new("podman")
        .arg("--version")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
    {
        bail!("podman CLI not available, cannot auto-start socket service");
    }

    // If socket already exists (maybe started externally), verify it works
    if socket_path.exists() {
        if std::process::Command::new("podman")
            .args([
                "--url",
                &format!("unix://{}", socket_path.display()),
                "info",
            ])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
        {
            tracing::info!(
                "Found working podman socket at {} (externally managed)",
                socket_path.display()
            );
            return Ok(socket_path);
        }
        // Socket file exists but is stale — remove it
        tracing::debug!("Removing stale socket at {}", socket_path.display());
        let _ = std::fs::remove_file(&socket_path);
    }

    // Create the socket directory with restricted permissions (0700).
    // This prevents other users from connecting to our podman socket.
    if let Some(parent) = socket_path.parent() {
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(parent)
            .with_context(|| format!("Failed to create socket directory {}", parent.display()))?;
    }

    tracing::info!(
        "No container socket found; auto-starting podman service at {}",
        socket_path.display()
    );

    // Spawn podman system service.
    // Use pre_exec to set PR_SET_PDEATHSIG so the child is killed when we exit.
    // This is strictly better than --time=N: no idle-timeout guessing, no
    // window where orphans linger, and no risk of the service exiting mid-use.
    let mut cmd = std::process::Command::new("podman");
    cmd.args([
        "system",
        "service",
        "--time=0",
        &format!("unix://{}", socket_path.display()),
    ])
    .stdout(std::process::Stdio::null())
    .stderr(std::process::Stdio::null());

    // Lifecycle-bind the child to this process: if we exit, the kernel
    // sends SIGTERM to the podman service. No orphans, no timeouts.
    #[cfg(target_os = "linux")]
    {
        use cap_std_ext::cmdext::CapStdExtCommandExt;
        cmd.lifecycle_bind_to_parent_thread();
    }

    let child = cmd
        .spawn()
        .context("Failed to spawn podman system service")?;

    // Wait for the socket to appear
    for i in 0..50 {
        if socket_path.exists() {
            tracing::info!(
                "Podman service started at {} (took ~{}ms)",
                socket_path.display(),
                i * 100,
            );
            *guard = Some(PodmanServiceGuard { child });
            return Ok(socket_path);
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }

    // Timed out — kill the process and fail
    let mut child = child;
    let _ = child.kill();
    let _ = child.wait();
    bail!(
        "Podman service did not create socket at {} within 5 seconds",
        socket_path.display()
    )
}

/// Parse a DOCKER_HOST value and extract the socket path for unix:// scheme.
///
/// Handles:
/// - `unix:///path/to/sock` (standard URI, empty authority)
/// - `unix://path/to/sock` (common shorthand)
///
/// Returns None for non-unix schemes (with a warning).
fn parse_docker_host(value: &str) -> Option<String> {
    if let Some(rest) = value.strip_prefix("unix://") {
        // Standard URI: unix:///path (triple slash = empty authority + absolute path)
        // Also handle unix://path (double slash, treated as absolute)
        let path = if rest.is_empty() {
            tracing::warn!("DOCKER_HOST=unix:// has empty path, ignoring");
            return None;
        } else if rest.starts_with('/') {
            // unix:///absolute/path -> /absolute/path
            rest.to_string()
        } else {
            // unix://relative/path -> treat as /relative/path (common usage)
            format!("/{rest}")
        };
        Some(path)
    } else if value.starts_with("tcp://") {
        tracing::warn!(
            "DOCKER_HOST={} uses tcp:// which is not yet supported; ignoring",
            value
        );
        None
    } else if value.starts_with('/') {
        // Bare path without scheme - be lenient
        Some(value.to_string())
    } else {
        tracing::warn!(
            "DOCKER_HOST={} has unsupported scheme; only unix:// is currently supported",
            value
        );
        None
    }
}

/// Get the host-side path of the container runtime socket.
///
/// When creating sibling containers, bind mount sources are resolved on
/// the **host** filesystem, not inside our container. On rootless Linux
/// the host path (e.g. `/run/user/1002/podman/podman.sock`) differs from
/// the container-internal path (`/run/docker.sock`).
///
/// The launcher must set `DEVAIPOD_HOST_SOCKET` to the host-side path of
/// the mounted socket so we can pass it as a bind mount source. If unset,
/// we fall back to the container-internal path (which works when paths
/// happen to match, e.g. macOS podman machine or rootful Docker).
pub fn get_host_socket_path() -> Result<PathBuf> {
    if let Ok(val) = std::env::var("DEVAIPOD_HOST_SOCKET") {
        let path = PathBuf::from(&val);
        tracing::debug!(
            "Using host socket path from DEVAIPOD_HOST_SOCKET: {}",
            path.display()
        );
        return Ok(path);
    }

    let container_path = get_container_socket()?;
    if is_container_mode() {
        tracing::warn!(
            "DEVAIPOD_HOST_SOCKET not set; using container path {} as sibling mount source. \
             This may fail on rootless Linux where host and container paths differ.",
            container_path.display()
        );
    }
    Ok(container_path)
}

/// Get the host-side base path for agent workspaces.
///
/// When creating agent containers, bind mount sources are resolved on the
/// **host** filesystem. The launcher sets `DEVAIPOD_HOST_WORKDIR` to the
/// host-side directory where agent workspaces are stored.
///
/// If unset, falls back to `$XDG_DATA_HOME/devaipod/workspaces` (typically
/// `~/.local/share/devaipod/workspaces`), or `/var/lib/devaipod/workspaces`
/// as a last resort.
pub fn get_host_workdir_path() -> Result<PathBuf> {
    if let Ok(val) = std::env::var("DEVAIPOD_HOST_WORKDIR") {
        let path = PathBuf::from(&val);
        tracing::debug!(
            "Using host workdir path from DEVAIPOD_HOST_WORKDIR: {}",
            path.display()
        );
        return Ok(path);
    }

    // XDG_DATA_HOME fallback (typically ~/.local/share)
    if let Ok(xdg_data) = std::env::var("XDG_DATA_HOME") {
        let path = PathBuf::from(xdg_data).join("devaipod/workspaces");
        tracing::debug!(
            "Using host workdir path from XDG_DATA_HOME: {}",
            path.display()
        );
        return Ok(path);
    }

    // HOME-based fallback
    if let Ok(home) = std::env::var("HOME") {
        let path = PathBuf::from(home).join(".local/share/devaipod/workspaces");
        tracing::debug!("Using host workdir path under HOME: {}", path.display());
        return Ok(path);
    }

    // Absolute fallback
    let path = PathBuf::from("/var/lib/devaipod/workspaces");
    tracing::debug!("Using fallback host workdir path: {}", path.display());
    Ok(path)
}

/// Connect to the container socket and return a bollard Docker client
pub fn connect_to_container_socket() -> Result<Docker> {
    let socket_path = get_container_socket()?;
    Docker::connect_with_unix(
        &format!("unix://{}", socket_path.display()),
        120,
        bollard::API_DEFAULT_VERSION,
    )
    .context("Failed to connect to container socket")
}

/// Check if the devcontainer CLI is available on the system
fn devcontainer_cli_available() -> bool {
    std::process::Command::new("devcontainer")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Podman service connection
///
/// Connects to an existing podman/docker socket mounted into the container.
pub struct PodmanService {
    /// The socket path we're connected to
    socket_path: PathBuf,
    /// PID of the podman system service process (always None - we don't own the process)
    child_pid: Option<u32>,
    /// Bollard client connected to the socket
    client: Docker,
}

/// Check if we're running inside a container
///
/// Devaipod only runs in container mode (there is no host mode). This
/// check exists for the few places where behavior differs slightly
/// (e.g. using `host.containers.internal` vs `127.0.0.1`).
pub fn is_container_mode() -> bool {
    // Check for our mounted socket
    std::path::Path::new(DOCKER_SOCKET).exists()
        || std::path::Path::new(DOCKER_SOCKET_VAR).exists()
        || std::path::Path::new(PODMAN_SOCKET).exists()
        // Standard container indicator files
        || std::path::Path::new("/.dockerenv").exists()
        || std::path::Path::new("/run/.containerenv").exists()
}

/// Host to use when connecting to pod-published ports (e.g. opencode server).
///
/// When running on the host, published ports are on 127.0.0.1.
/// When running inside the devaipod container (without --network host), we use the
/// host gateway so we can reach ports published on the host. This allows the container
/// to work on macOS where --network host breaks port forwarding.
///
/// Override with DEVAIPOD_HOST_GATEWAY (e.g. host.containers.internal or host.docker.internal).
pub fn host_for_pod_services() -> String {
    if let Ok(host) = std::env::var("DEVAIPOD_HOST_GATEWAY") {
        return host;
    }
    if is_container_mode() {
        "host.containers.internal".to_string()
    } else {
        "127.0.0.1".to_string()
    }
}

impl PodmanService {
    /// Connect to podman via the mounted container socket
    ///
    /// We expect the host's container runtime socket to be mounted at
    /// `/run/docker.sock` or configured via `DOCKER_HOST`.
    pub async fn connect() -> Result<Self> {
        let socket_path = get_container_socket()?;
        let client = connect_to_container_socket()?;

        // Verify connection
        client
            .ping()
            .await
            .context("Failed to ping podman. Is the socket mounted correctly?")?;

        tracing::debug!("Connected to podman at {}", socket_path.display());

        Ok(Self {
            socket_path,
            child_pid: None, // We don't own the process
            client,
        })
    }

    /// Legacy alias for connect()
    pub async fn spawn() -> Result<Self> {
        Self::connect().await
    }

    /// Create a Command for running podman CLI with our socket
    fn podman_command(&self) -> Command {
        let mut cmd = Command::new("podman");
        cmd.args(["--url", &format!("unix://{}", self.socket_path.display())]);
        cmd
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
    /// For remote images, pulls unconditionally.
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

        tracing::debug!("Pulling image {}", image);
        let output = self
            .podman_command()
            .args(["pull", image])
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
        if let Some(config) = info.config
            && let Some(user) = config.user
            && !user.is_empty()
        {
            return Ok(Some(user));
        }
        Ok(None)
    }

    /// Get detailed image info (name, creation time, digest)
    ///
    /// Returns metadata about the image for display purposes.
    pub async fn get_image_info(&self, image: &str) -> Result<ImageInfo> {
        let info = self
            .client
            .inspect_image(image)
            .await
            .context("Failed to inspect image")?;

        // Get the first repo digest if available
        let digest = info.repo_digests.as_ref().and_then(|d| d.first()).cloned();

        // Get the first repo tag
        let name = info
            .repo_tags
            .as_ref()
            .and_then(|t| t.first())
            .cloned()
            .unwrap_or_else(|| image.to_string());

        // Parse creation time - bollard returns it as a string in RFC3339 format
        let created = info
            .created
            .as_ref()
            .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok());

        Ok(ImageInfo {
            name,
            created,
            digest,
        })
    }

    /// Create a pod (containers sharing network namespace)
    ///
    /// Returns the pod ID. Podman implements pods via the API but bollard
    /// doesn't have native support, so we shell out for pod operations.
    ///
    /// Labels can be provided as key-value pairs to attach metadata to the pod.
    ///
    /// The `publish_ports` parameter allows publishing container ports to the host.
    /// Format: "host_ip:host_port:container_port" or "host_ip::container_port" for random host port.
    /// Example: "127.0.0.1::4096" publishes container port 4096 to a random localhost port.
    pub async fn create_pod(
        &self,
        name: &str,
        labels: &[(String, String)],
        publish_ports: &[String],
    ) -> Result<String> {
        let mut cmd = self.podman_command();
        cmd.args(["pod", "create", "--name", name]);

        // Add labels
        for (key, value) in labels {
            cmd.args(["--label", &format!("{}={}", key, value)]);
        }

        // Add port publishing
        for port in publish_ports {
            cmd.args(["-p", port]);
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
            .args(["pod", "start", "--", name])
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
            .args(["pod", "stop", "--", name])
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
        args.push("--");
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

    /// Get labels from a pod
    pub async fn get_pod_labels(
        &self,
        name: &str,
    ) -> Result<std::collections::HashMap<String, String>> {
        let output = self
            .podman_command()
            .args(["pod", "inspect", "--format", "json", name])
            .output()
            .await
            .context("Failed to inspect pod")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            bail!("Failed to inspect pod {}: {}", name, stderr);
        }

        // Parse the JSON output
        let stdout = String::from_utf8_lossy(&output.stdout);
        let pod_info: serde_json::Value =
            serde_json::from_str(&stdout).context("Failed to parse pod inspect output")?;

        // Extract labels from the JSON
        // podman pod inspect returns: [{"Labels": {"key": "value", ...}, ...}]
        // Handle both array (standard) and object (legacy) formats
        let pod_obj = pod_info
            .as_array()
            .and_then(|arr| arr.first())
            .unwrap_or(&pod_info);
        let labels = pod_obj
            .get("Labels")
            .and_then(|l| l.as_object())
            .map(|obj| {
                obj.iter()
                    .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
                    .collect()
            })
            .unwrap_or_default();

        Ok(labels)
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
        self.run_init_container_impl(image, volume_name, mount_path, command, extra_binds, None)
            .await
    }

    /// Run an init container as root (for creating protected files)
    pub async fn run_init_container_as_root(
        &self,
        image: &str,
        volume_name: &str,
        mount_path: &str,
        command: &[&str],
    ) -> Result<i32> {
        self.run_init_container_impl(image, volume_name, mount_path, command, &[], Some("0"))
            .await
    }

    async fn run_init_container_impl(
        &self,
        image: &str,
        volume_name: &str,
        mount_path: &str,
        command: &[&str],
        extra_binds: &[String],
        user: Option<&str>,
    ) -> Result<i32> {
        // Sanitize the container name: when volume_name is a host path
        // (e.g. for HostDir bind mounts), replace slashes and use only
        // the last path component so the name is valid for podman.
        let base = std::path::Path::new(volume_name)
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| volume_name.replace('/', "-"));
        let container_name = format!("{}-init", base);

        // Remove any existing init container
        let _ = self
            .podman_command()
            .args(["rm", "-f", &container_name])
            .output()
            .await;

        // Run the init container
        let is_host_path = volume_name.starts_with('/');
        let mut args = vec![
            "run".to_string(),
            "--rm".to_string(),
            "--name".to_string(),
            container_name.clone(),
        ];

        // When the "volume" is actually a host directory bind mount, the
        // files inside may be owned by a subuid-mapped UID that rootless
        // podman's container root cannot write to. Use --privileged so the
        // init container bypasses user namespace restrictions.
        if is_host_path {
            args.push("--privileged".to_string());
        }

        args.push("-v".to_string());
        args.push(format!("{}:{}", volume_name, mount_path));

        // Add explicit user if specified
        if let Some(u) = user {
            args.push("--user".to_string());
            args.push(u.to_string());
        }

        // Add extra bind mounts (with SELinux label disable and root user if any are present)
        // Root is needed because bind mounts from the host may have different UID mappings
        if !extra_binds.is_empty() {
            if !is_host_path {
                args.push("--security-opt".to_string());
                args.push("label=disable".to_string());
            }
            if user.is_none() {
                args.push("--user".to_string());
                args.push("0".to_string());
            }
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

    /// Run an init container and return its output
    ///
    /// Same as `run_init_container` but returns (exit_code, stdout) for parsing.
    pub async fn run_init_container_with_output(
        &self,
        image: &str,
        volume_name: &str,
        mount_path: &str,
        command: &[&str],
        extra_binds: &[String],
    ) -> Result<(i32, String)> {
        // Derive a safe container name. When volume_name is a host path
        // (e.g. /home/user/.local/share/devaipod/workspaces/pod-name), use
        // only the last path component to avoid slashes in the container name.
        let safe_name = std::path::Path::new(volume_name)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or(volume_name);
        let container_name = format!("{}-init", safe_name);

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

        // When using bind mounts (host paths or extra binds), disable SELinux
        // labels and run as root so the container can access host-owned files.
        let is_bind_mount = volume_name.contains('/');
        if is_bind_mount || !extra_binds.is_empty() {
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

        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        let stderr = String::from_utf8_lossy(&output.stderr);

        if !stderr.is_empty() && !output.status.success() {
            for line in stderr.lines() {
                tracing::warn!("init: {}", line);
            }
        }

        Ok((output.status.code().unwrap_or(1), stdout))
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
            // Use init process to reap zombie processes
            "--init".to_string(),
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

        // File-based secrets (mounted as files, env var points to path)
        for (env_var, secret_name) in &config.file_secrets {
            args.push("--secret".to_string());
            args.push(secret_name.to_string()); // mounts at /run/secrets/{secret_name}
            // Set env var to point to the mounted file
            args.push("-e".to_string());
            args.push(format!("{}=/run/secrets/{}", env_var, secret_name));
        }

        // Labels
        for (key, value) in &config.labels {
            args.push("--label".to_string());
            args.push(format!("{}={}", key, value));
        }

        // Container healthcheck
        if let Some(hc) = &config.healthcheck {
            args.push("--health-cmd".to_string());
            args.push(hc.cmd.join(" "));
            if let Some(interval) = &hc.interval {
                args.push("--health-interval".to_string());
                args.push(interval.clone());
            }
            if let Some(retries) = hc.retries {
                args.push("--health-retries".to_string());
                args.push(retries.to_string());
            }
            if let Some(start_period) = &hc.start_period {
                args.push("--health-start-period".to_string());
                args.push(start_period.clone());
            }
        }

        // Extra args from devcontainer.json runArgs (passthrough)
        args.extend(config.extra_create_args.iter().cloned());

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

    /// Restart a container (unused - kept for potential future use)
    #[allow(dead_code)]
    pub async fn restart_container(&self, name: &str) -> Result<()> {
        self.client
            .restart_container(name, None)
            .await
            .with_context(|| format!("Failed to restart container {}", name))?;
        tracing::debug!("Restarted container: {}", name);
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

    /// Wait for a container to exit and return its exit code
    ///
    /// Blocks until the container exits or an error occurs.
    #[allow(dead_code)] // May be useful for future features
    pub async fn wait_container(&self, name: &str) -> Result<i64> {
        let options: WaitContainerOptions<String> = WaitContainerOptions {
            condition: "not-running".to_string(),
        };
        let mut stream = self.client.wait_container(name, Some(options));
        // The stream returns one result when the container exits
        match stream.next().await {
            Some(result) => {
                let wait_response =
                    result.with_context(|| format!("Failed to wait for container {}", name))?;
                let exit_code = wait_response.status_code;
                tracing::debug!("Container {} exited with code {}", name, exit_code);
                Ok(exit_code)
            }
            None => {
                color_eyre::eyre::bail!("Wait stream ended without result for container {}", name);
            }
        }
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

    /// Copy a file from a container to the host
    ///
    /// Returns the file contents as a String, or None if the file doesn't exist.
    pub async fn copy_from_container(
        &self,
        container: &str,
        source: &str,
    ) -> Result<Option<String>> {
        // Create a temp file to receive the content
        let temp_dir = tempfile::tempdir().context("Failed to create temp directory")?;
        let temp_file = temp_dir.path().join("content");

        let container_source = format!("{}:{}", container, source);
        let output = self
            .podman_command()
            .args(["cp", &container_source, &temp_file.to_string_lossy()])
            .output()
            .await
            .context("Failed to execute podman cp")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            // Check if file doesn't exist (common case, not an error)
            if stderr.contains("No such file or directory")
                || stderr.contains("does not exist")
                || stderr.contains("could not find")
            {
                return Ok(None);
            }
            color_eyre::eyre::bail!(
                "Failed to copy {}:{} to host: {}",
                container,
                source,
                stderr
            );
        }

        // Read the temp file
        let content = std::fs::read_to_string(&temp_file)
            .with_context(|| format!("Failed to read copied file from {}", temp_file.display()))?;

        tracing::debug!(
            "Copied {}:{} to host ({} bytes)",
            container,
            source,
            content.len()
        );
        Ok(Some(content))
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

/// Information about a container image
#[derive(Debug, Clone)]
pub struct ImageInfo {
    /// Image name (from repo tags)
    pub name: String,
    /// Creation timestamp
    pub created: Option<chrono::DateTime<chrono::FixedOffset>>,
    /// Image digest (from repo digests)
    pub digest: Option<String>,
}

impl std::fmt::Display for ImageInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name)?;
        if let Some(created) = self.created {
            write!(f, " (created {})", created.format("%Y-%m-%d %H:%M:%S %Z"))?;
        }
        if let Some(ref digest) = self.digest {
            // Extract just the sha256 digest, truncate for readability
            if let Some(sha) = digest.split('@').nth(1) {
                let short = if sha.len() > 19 { &sha[..19] } else { sha };
                write!(f, " [{}...]", short)?;
            }
        }
        Ok(())
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
    /// Podman secrets mounted as files (env_var -> secret_name).
    /// Mounted at /run/secrets/{secret_name}, env var set to that path.
    /// Generates: --secret secret_name -e ENV_VAR=/run/secrets/secret_name
    pub file_secrets: Vec<(String, String)>,
    /// Labels to attach to the container (key -> value)
    pub labels: HashMap<String, String>,
    /// Additional arguments to pass through to `podman create` verbatim.
    /// These come from devcontainer.json runArgs that aren't extracted
    /// into typed fields.
    pub extra_create_args: Vec<String>,
    /// Container healthcheck command (e.g., `["curl", "-sf", "http://localhost:8090/healthz"]`).
    /// When set, podman will run this command periodically to determine container health.
    pub healthcheck: Option<HealthcheckConfig>,
}

/// Podman container healthcheck configuration
#[derive(Debug, Clone)]
pub struct HealthcheckConfig {
    /// Command to run for the health check
    pub cmd: Vec<String>,
    /// Interval between checks (default: 30s)
    pub interval: Option<String>,
    /// Number of retries before marking unhealthy (default: 3)
    pub retries: Option<u32>,
    /// Grace period after container start before checks begin (default: 0s)
    pub start_period: Option<String>,
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
        builder.into_inner().context("Failed to get tar data")
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

    #[test]
    fn test_parse_docker_host_unix_triple_slash() {
        // Standard URI format: unix:///absolute/path
        assert_eq!(
            parse_docker_host("unix:///run/docker.sock"),
            Some("/run/docker.sock".to_string())
        );
        assert_eq!(
            parse_docker_host("unix:///var/run/docker.sock"),
            Some("/var/run/docker.sock".to_string())
        );
    }

    #[test]
    fn test_parse_docker_host_unix_double_slash() {
        // Common shorthand: unix://path (treated as absolute)
        assert_eq!(
            parse_docker_host("unix://run/docker.sock"),
            Some("/run/docker.sock".to_string())
        );
    }

    #[test]
    fn test_parse_docker_host_unix_empty() {
        // Empty path after unix://
        assert_eq!(parse_docker_host("unix://"), None);
    }

    #[test]
    fn test_parse_docker_host_tcp() {
        // tcp:// is not supported yet
        assert_eq!(parse_docker_host("tcp://localhost:2375"), None);
    }

    #[test]
    fn test_parse_docker_host_bare_path() {
        // Bare absolute path without scheme
        assert_eq!(
            parse_docker_host("/run/docker.sock"),
            Some("/run/docker.sock".to_string())
        );
    }

    #[test]
    fn test_parse_docker_host_unsupported_scheme() {
        assert_eq!(parse_docker_host("http://localhost:2375"), None);
    }
}
