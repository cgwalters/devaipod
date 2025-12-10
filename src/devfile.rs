//! Devfile parsing and container management
//!
//! Implements support for the devfile 2.x specification, translating
//! devfile container components into podman run invocations.
//!
//! Also supports devcontainer.json (JSONC format with comments) by
//! stripping comments before parsing.

use std::path::Path;
use std::process::{Command as ProcessCommand, Stdio};

use color_eyre::eyre::{bail, Context, ContextCompat, Result};
use serde::Deserialize;

use crate::workspace::StorageMode;

/// Strip JavaScript-style comments from JSON (JSONC format).
///
/// Handles both line comments (`//`) and block comments (`/* */`).
/// Takes care not to strip comments inside string literals.
pub fn strip_json_comments(input: &str) -> String {
    let mut result = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();
    let mut in_string = false;
    let mut escape_next = false;

    while let Some(c) = chars.next() {
        if escape_next {
            result.push(c);
            escape_next = false;
            continue;
        }

        if in_string {
            result.push(c);
            if c == '\\' {
                escape_next = true;
            } else if c == '"' {
                in_string = false;
            }
            continue;
        }

        match c {
            '"' => {
                in_string = true;
                result.push(c);
            }
            '/' => {
                match chars.peek() {
                    Some('/') => {
                        // Line comment - skip until newline
                        chars.next(); // consume second /
                        while let Some(&nc) = chars.peek() {
                            if nc == '\n' {
                                break;
                            }
                            chars.next();
                        }
                    }
                    Some('*') => {
                        // Block comment - skip until */
                        chars.next(); // consume *
                        while let Some(nc) = chars.next() {
                            if nc == '*' && chars.peek() == Some(&'/') {
                                chars.next(); // consume /
                                break;
                            }
                        }
                    }
                    _ => {
                        result.push(c);
                    }
                }
            }
            _ => {
                result.push(c);
            }
        }
    }

    result
}

/// Specification for an injected sidecar container
pub struct SidecarSpec {
    /// Sidecar image. If None, uses the same image as the main container.
    pub image: Option<String>,
    /// Command to run in sidecar (e.g., ["goose"])
    /// Note: This is read from config at enter time, not used during container creation.
    #[allow(dead_code)]
    pub command: Option<Vec<String>>,
    pub mount_sources_readonly: bool,
    /// Whether to enable network access (false = isolated network namespace)
    pub network: bool,
    /// Host paths to bind mount into the sidecar
    pub mounts: Vec<crate::config::MountSpec>,
    /// Host paths to mirror into sidecar at same location (read-only)
    pub dotfiles: Vec<String>,
    /// Git repository URL containing dotfiles to clone and install
    pub dotfiles_repo: Option<String>,
    /// Command to run after cloning dotfiles repo
    pub dotfiles_install: Option<String>,
}

/// Default for mountSources per devfile 2.x spec
fn default_mount_sources() -> bool {
    true
}

/// Devfile 2.x schema representation
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Devfile {
    #[allow(dead_code)]
    pub schema_version: String,
    pub metadata: DevfileMetadata,
    #[serde(default)]
    pub components: Vec<Component>,
    #[serde(default)]
    #[allow(dead_code)]
    pub commands: Vec<DevfileCommand>,
}

#[derive(Debug, Deserialize)]
pub struct DevfileMetadata {
    pub name: String,
    #[serde(default)]
    #[allow(dead_code)]
    pub version: Option<String>,
    #[serde(default)]
    #[allow(dead_code)]
    pub description: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Component {
    pub name: String,
    #[serde(default)]
    pub container: Option<ContainerComponent>,
    #[serde(default)]
    #[allow(dead_code)]
    pub volume: Option<VolumeComponent>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ContainerComponent {
    pub image: String,
    #[serde(default)]
    pub command: Vec<String>,
    #[serde(default)]
    pub args: Vec<String>,
    #[serde(default)]
    pub env: Vec<EnvVar>,
    #[serde(default)]
    #[allow(dead_code)]
    pub volume_mounts: Vec<VolumeMount>,
    /// Per devfile spec, mountSources defaults to true
    #[serde(default = "default_mount_sources")]
    pub mount_sources: bool,
    #[serde(default)]
    pub source_mapping: Option<String>,
    #[serde(default)]
    pub memory_limit: Option<String>,
    #[serde(default)]
    #[allow(dead_code)]
    pub memory_request: Option<String>,
    #[serde(default)]
    pub cpu_limit: Option<String>,
    #[serde(default)]
    #[allow(dead_code)]
    pub cpu_request: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct VolumeComponent {
    #[serde(default)]
    #[allow(dead_code)]
    pub size: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct EnvVar {
    pub name: String,
    pub value: String,
}

#[derive(Debug, Deserialize)]
pub struct VolumeMount {
    #[allow(dead_code)]
    pub name: String,
    #[allow(dead_code)]
    pub path: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DevfileCommand {
    #[allow(dead_code)]
    pub id: String,
    #[serde(default)]
    #[allow(dead_code)]
    pub exec: Option<ExecCommand>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExecCommand {
    #[allow(dead_code)]
    pub component: String,
    #[allow(dead_code)]
    pub command_line: String,
    #[serde(default)]
    #[allow(dead_code)]
    pub working_dir: Option<String>,
    #[serde(default)]
    #[allow(dead_code)]
    pub group: Option<CommandGroup>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CommandGroup {
    #[allow(dead_code)]
    pub kind: String,
    #[serde(default)]
    #[allow(dead_code)]
    pub is_default: bool,
}

/// Devcontainer.json schema (subset we support)
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct DevContainer {
    /// Container image to use
    #[serde(default)]
    image: Option<String>,
    /// Build configuration (if image is not specified)
    #[serde(default)]
    build: Option<DevContainerBuild>,
    /// Name for the container
    #[serde(default)]
    name: Option<String>,
    /// Remote user to run as
    #[serde(default)]
    #[allow(dead_code)]
    remote_user: Option<String>,
    /// Container user
    #[serde(default)]
    #[allow(dead_code)]
    container_user: Option<String>,
    /// Environment variables
    #[serde(default)]
    container_env: Option<std::collections::HashMap<String, String>>,
    /// Features to install
    #[serde(default)]
    #[allow(dead_code)]
    features: Option<serde_json::Value>,
    /// Run args for docker/podman
    #[serde(default)]
    #[allow(dead_code)]
    run_args: Option<Vec<String>>,
    /// Post-create command
    #[serde(default)]
    #[allow(dead_code)]
    post_create_command: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct DevContainerBuild {
    /// Dockerfile path
    #[serde(default)]
    dockerfile: Option<String>,
    /// Build context
    #[serde(default)]
    context: Option<String>,
}

/// Load devcontainer.json and convert to Devfile
pub fn load_devcontainer_as_devfile(workspace: &Path) -> Result<Option<Devfile>> {
    let candidates = [
        workspace.join(".devcontainer/devcontainer.json"),
        workspace.join(".devcontainer.json"),
    ];

    for path in candidates {
        if path.exists() {
            let content = std::fs::read_to_string(&path)
                .with_context(|| format!("Failed to read {}", path.display()))?;
            // devcontainer.json uses JSONC format which allows comments
            let content = strip_json_comments(&content);
            let devcontainer: DevContainer = serde_json::from_str(&content)
                .with_context(|| format!("Failed to parse {}", path.display()))?;

            // Convert to Devfile
            let devfile = devcontainer_to_devfile(&devcontainer, workspace)?;
            tracing::info!(
                "Loaded devcontainer from {} and converted to devfile",
                path.display()
            );
            return Ok(Some(devfile));
        }
    }

    Ok(None)
}

/// Convert a DevContainer to a Devfile
fn devcontainer_to_devfile(dc: &DevContainer, workspace: &Path) -> Result<Devfile> {
    let image = if let Some(img) = &dc.image {
        img.clone()
    } else if let Some(build) = &dc.build {
        // Build the image first
        let dockerfile = build.dockerfile.as_deref().unwrap_or("Dockerfile");
        let context = build.context.as_deref().unwrap_or(".");
        let devcontainer_dir = workspace.join(".devcontainer");
        let dockerfile_path = devcontainer_dir.join(dockerfile);
        let context_path = devcontainer_dir.join(context);

        // Generate a unique image name
        let workspace_name = workspace
            .file_name()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_else(|| "devcontainer".to_string());
        let image_name = format!("devc-built-{}", workspace_name);

        tracing::info!(
            "Building devcontainer image from {}",
            dockerfile_path.display()
        );

        let status = ProcessCommand::new("podman")
            .args(["build", "-t", &image_name, "-f"])
            .arg(&dockerfile_path)
            .arg(&context_path)
            .status()
            .context("Failed to run podman build")?;

        if !status.success() {
            bail!(
                "Failed to build devcontainer image from {}",
                dockerfile_path.display()
            );
        }

        image_name
    } else {
        bail!("Devcontainer must specify either 'image' or 'build'");
    };

    let name = dc
        .name
        .clone()
        .unwrap_or_else(|| "devcontainer".to_string());

    // Convert environment variables
    let env: Vec<EnvVar> = dc
        .container_env
        .as_ref()
        .map(|m| {
            m.iter()
                .map(|(k, v)| EnvVar {
                    name: k.clone(),
                    value: v.clone(),
                })
                .collect()
        })
        .unwrap_or_default();

    // Create the devfile
    Ok(Devfile {
        schema_version: "2.2.0".to_string(),
        metadata: DevfileMetadata {
            name: name.clone(),
            version: Some("1.0.0".to_string()),
            description: Some(format!("Converted from devcontainer.json")),
        },
        components: vec![Component {
            name: "dev".to_string(),
            container: Some(ContainerComponent {
                image,
                command: vec!["/bin/sh".to_string()],
                args: vec!["-c".to_string(), "sleep infinity".to_string()],
                env,
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
    })
}

/// Load a devfile from a workspace directory, or fall back to devcontainer
pub fn load_devfile(workspace: &Path) -> Result<Option<Devfile>> {
    // Check for devfile.yaml or .devfile.yaml first
    let candidates = [
        workspace.join("devfile.yaml"),
        workspace.join(".devfile.yaml"),
        workspace.join("devfile.yml"),
        workspace.join(".devfile.yml"),
    ];

    for path in candidates {
        if path.exists() {
            let content = std::fs::read_to_string(&path)
                .with_context(|| format!("Failed to read {}", path.display()))?;
            let devfile: Devfile = serde_yml::from_str(&content)
                .with_context(|| format!("Failed to parse {}", path.display()))?;
            tracing::info!("Loaded devfile from {}", path.display());
            return Ok(Some(devfile));
        }
    }

    // Fall back to devcontainer.json
    load_devcontainer_as_devfile(workspace)
}

/// Find the first container component in a devfile
pub fn find_container_component(devfile: &Devfile) -> Option<(&str, &ContainerComponent)> {
    for component in &devfile.components {
        if let Some(ref container) = component.container {
            return Some((&component.name, container));
        }
    }
    None
}

/// Find all container components in a devfile
pub fn find_container_components(devfile: &Devfile) -> Vec<(&str, &ContainerComponent)> {
    devfile
        .components
        .iter()
        .filter_map(|c| c.container.as_ref().map(|cont| (c.name.as_str(), cont)))
        .collect()
}

/// Generate a container name for a devfile-based container
fn container_name(workspace_name: &str, component_name: &str) -> String {
    format!("devfile-{}-{}", workspace_name, component_name)
}

/// Start a container based on a devfile container component
pub fn start_devfile_container(
    workspace_name: &str,
    storage: &StorageMode,
    devfile: &Devfile,
    privileged: bool,
    enable_kvm: bool,
    secrets: &[(String, String)],
) -> Result<String> {
    let (component_name, container) =
        find_container_component(devfile).context("No container component found in devfile")?;

    let name = format!("devfile-{}-{}", workspace_name, component_name);
    let source_mapping = container.source_mapping.as_deref().unwrap_or("/projects");

    // Check if container already exists
    let existing = ProcessCommand::new("podman")
        .args(["ps", "-aq", "--filter", &format!("name=^{}$", name)])
        .output()
        .context("Failed to check for existing container")?;

    let existing_id = String::from_utf8_lossy(&existing.stdout).trim().to_string();
    if !existing_id.is_empty() {
        // Container exists, check if running
        let running = ProcessCommand::new("podman")
            .args(["ps", "-q", "--filter", &format!("name=^{}$", name)])
            .output()?;
        let running_id = String::from_utf8_lossy(&running.stdout).trim().to_string();

        if !running_id.is_empty() {
            tracing::info!("Container {} already running", name);
            return Ok(running_id);
        }

        // Start existing stopped container
        tracing::info!("Starting existing container {}", name);
        let status = ProcessCommand::new("podman")
            .args(["start", &existing_id])
            .status()
            .context("Failed to start container")?;

        if !status.success() {
            bail!("Failed to start container {}", name);
        }
        return Ok(existing_id);
    }

    tracing::info!(
        "Creating devfile container '{}' from image '{}'",
        name,
        container.image
    );

    let mut cmd = ProcessCommand::new("podman");
    cmd.args(["run", "-d", "--name", &name]);
    // Skip graceful shutdown - these containers typically run `sleep infinity` which ignores SIGTERM
    cmd.args(["--stop-timeout", "0"]);

    // Add labels for tracking
    cmd.args(["--label", crate::consts::LABEL_MARKER]);
    cmd.args(["--label", &format!("devc.workspace={}", workspace_name)]);
    cmd.args(["--label", &format!("devfile.component={}", component_name)]);
    cmd.args([
        "--label",
        &format!("devfile.name={}", devfile.metadata.name),
    ]);

    // Add storage-specific labels and mount
    match storage {
        StorageMode::Volume { name: vol_name } => {
            cmd.args(["--label", &format!("devc.volume={}", vol_name)]);
            // For compatibility with devc list, store volume name as local_folder
            cmd.args([
                "--label",
                &format!("devcontainer.local_folder=volume:{}", vol_name),
            ]);

            if container.mount_sources {
                // Mount volume with :Z for SELinux exclusive access
                cmd.args(["-v", &format!("{}:{}:Z", vol_name, source_mapping)]);
                cmd.args(["-w", source_mapping]);
                cmd.args(["-e", &format!("PROJECTS_ROOT={}", source_mapping)]);
            }
        }
        StorageMode::BindMount { host_path } => {
            cmd.args([
                "--label",
                &format!("devcontainer.local_folder={}", host_path.display()),
            ]);

            if container.mount_sources {
                // Use :z for SELinux shared relabeling
                cmd.args([
                    "-v",
                    &format!("{}:{}:z", host_path.display(), source_mapping),
                ]);
                cmd.args(["-w", source_mapping]);
                cmd.args(["-e", &format!("PROJECTS_ROOT={}", source_mapping)]);
            }
        }
    }

    // Environment variables from devfile
    for env in &container.env {
        cmd.args(["-e", &format!("{}={}", env.name, env.value)]);
    }

    // Podman secrets passed as environment variables
    for (secret_name, env_var) in secrets {
        cmd.args([
            "--secret",
            &format!("{},type=env,target={}", secret_name, env_var),
        ]);
        tracing::debug!(
            "Adding podman secret '{}' as environment variable '{}'",
            secret_name,
            env_var
        );
    }

    // Resource limits
    if let Some(mem) = &container.memory_limit {
        cmd.args(["--memory", mem]);
    }
    if let Some(cpu) = &container.cpu_limit {
        cmd.args(["--cpus", cpu]);
    }

    // Privileged mode (common for dev containers)
    // When privileged, also run as root for maximum compatibility
    if privileged {
        cmd.arg("--privileged");
        cmd.args(["--user", "root"]);
    }

    // Add /dev/kvm device if it exists and KVM is enabled
    if enable_kvm && std::path::Path::new("/dev/kvm").exists() {
        cmd.args(["--device", "/dev/kvm"]);
    }

    // Command overrides ENTRYPOINT, args overrides CMD
    // In podman/docker, --entrypoint must come before the image
    if !container.command.is_empty() {
        cmd.args(["--entrypoint", &container.command[0]]);
    }

    // Image must come after all options
    cmd.arg(&container.image);

    // Remaining command elements (after entrypoint) plus args follow the image
    if container.command.len() > 1 {
        cmd.args(&container.command[1..]);
    }
    if !container.args.is_empty() {
        cmd.args(&container.args);
    }

    tracing::debug!("Running: {:?}", cmd);

    let output = cmd.output().context("Failed to run podman")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("Failed to create container: {}", stderr);
    }

    let container_id = String::from_utf8_lossy(&output.stdout).trim().to_string();
    tracing::info!("Container started: {}", container_id);

    Ok(container_id)
}

/// Start a single container inside a pod
fn start_container_in_pod(
    pod_name: &str,
    container_name: &str,
    image: &str,
    storage: &StorageMode,
    source_mapping: &str,
    mount_readonly: bool,
    env_vars: &[(&str, &str)],
    secrets: &[(String, String)],
    privileged: bool,
    enable_kvm: bool,
    labels: &[(&str, &str)],
    command: Option<&[String]>,
    args: Option<&[String]>,
    extra_mounts: &[crate::config::MountSpec],
) -> Result<String> {
    tracing::info!(
        "Creating container '{}' from image '{}' in pod '{}'",
        container_name,
        image,
        pod_name
    );

    let mut cmd = ProcessCommand::new("podman");
    cmd.args(["run", "-d", "--pod", pod_name, "--name", container_name]);
    // Note: hostname is set on the pod, not individual containers (they share UTS namespace)
    // Skip graceful shutdown - these containers typically run `sleep infinity` which ignores SIGTERM
    cmd.args(["--stop-timeout", "0"]);

    // Add marker label and caller-provided labels
    cmd.args(["--label", crate::consts::LABEL_MARKER]);
    for (key, value) in labels {
        cmd.args(["--label", &format!("{}={}", key, value)]);
    }

    // Storage mount
    match storage {
        StorageMode::Volume { name: vol_name } => {
            let selinux_opt = if mount_readonly { "ro,Z" } else { "Z" };
            cmd.args([
                "-v",
                &format!("{}:{}:{}", vol_name, source_mapping, selinux_opt),
            ]);
            cmd.args(["-w", source_mapping]);
            cmd.args(["-e", &format!("PROJECTS_ROOT={}", source_mapping)]);
        }
        StorageMode::BindMount { host_path } => {
            let selinux_opt = if mount_readonly { "ro,z" } else { "z" };
            cmd.args([
                "-v",
                &format!("{}:{}:{}", host_path.display(), source_mapping, selinux_opt),
            ]);
            cmd.args(["-w", source_mapping]);
            cmd.args(["-e", &format!("PROJECTS_ROOT={}", source_mapping)]);
        }
    }

    // Environment variables
    for (name, value) in env_vars {
        cmd.args(["-e", &format!("{}={}", name, value)]);
    }

    // Podman secrets passed as environment variables
    for (secret_name, env_var) in secrets {
        cmd.args([
            "--secret",
            &format!("{},type=env,target={}", secret_name, env_var),
        ]);
        tracing::debug!(
            "Adding podman secret '{}' as environment variable '{}'",
            secret_name,
            env_var
        );
    }

    // Extra bind mounts (e.g., config directories)
    for mount in extra_mounts {
        let src = expand_tilde(&mount.src);
        if std::path::Path::new(&src).exists() {
            let opts = if mount.readonly { "ro,z" } else { "z" };
            cmd.args(["-v", &format!("{}:{}:{}", src, mount.dst, opts)]);
            tracing::debug!("Adding bind mount: {} -> {}", src, mount.dst);
        } else {
            tracing::warn!("Mount source does not exist, skipping: {}", src);
        }
    }

    // Privileged mode
    if privileged {
        cmd.arg("--privileged");
        cmd.args(["--user", "root"]);
    }

    // Add /dev/kvm device if it exists and KVM is enabled
    if enable_kvm && std::path::Path::new("/dev/kvm").exists() {
        cmd.args(["--device", "/dev/kvm"]);
    }

    // Command overrides ENTRYPOINT, args overrides CMD
    if let Some(cmd_parts) = command {
        if !cmd_parts.is_empty() {
            cmd.args(["--entrypoint", &cmd_parts[0]]);
        }
    }

    // Image must come after all options
    cmd.arg(image);

    // Remaining command elements plus args follow the image
    if let Some(cmd_parts) = command {
        if cmd_parts.len() > 1 {
            cmd.args(&cmd_parts[1..]);
        }
    }
    if let Some(arg_parts) = args {
        if !arg_parts.is_empty() {
            cmd.args(arg_parts);
        }
    }

    tracing::debug!("Running: {:?}", cmd);

    let output = cmd.output().context("Failed to run podman")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("Failed to create container: {}", stderr);
    }

    let container_id = String::from_utf8_lossy(&output.stdout).trim().to_string();
    tracing::info!("Container started: {} ({})", container_name, container_id);

    Ok(container_id)
}

/// Expand ~ to the user's home directory
fn expand_tilde(path: &str) -> String {
    if let Some(rest) = path.strip_prefix("~/") {
        if let Ok(home) = std::env::var("HOME") {
            return format!("{}/{}", home, rest);
        }
    } else if path == "~" {
        if let Ok(home) = std::env::var("HOME") {
            return home;
        }
    }
    path.to_string()
}

/// Start a pod with all devfile containers plus optional sidecar
///
/// Creates a podman pod and starts containers inside it.
/// All containers share the same /projects volume.
///
/// Returns the pod name.
pub fn start_devfile_pod(
    workspace_name: &str,
    storage: &StorageMode,
    devfile: &Devfile,
    privileged: bool,
    enable_kvm: bool,
    main_secrets: &[(String, String)],
    sidecar: Option<&SidecarSpec>,
    sidecar_secrets: &[(String, String)],
) -> Result<String> {
    let pod_name_str = crate::pod::pod_name(workspace_name);

    // Check if pod already exists
    if crate::pod::pod_exists(&pod_name_str)? {
        tracing::info!("Pod {} already exists, checking if running", pod_name_str);
        if !crate::pod::pod_is_running(&pod_name_str)? {
            crate::pod::start_pod(&pod_name_str)?;
        } else {
            tracing::info!("Pod {} already running", pod_name_str);
        }
        return Ok(pod_name_str);
    }

    // Determine the local folder for labels (compatibility with devc list)
    let local_folder = match storage {
        StorageMode::Volume { name: vol_name } => format!("volume:{}", vol_name),
        StorageMode::BindMount { host_path } => host_path.display().to_string(),
    };

    // Create pod with labels and hostname
    // The hostname is the workspace name for a clear bash prompt
    let pod_labels = [
        ("devc.workspace", workspace_name),
        ("devcontainer.local_folder", &local_folder),
    ];
    crate::pod::create_pod(&pod_name_str, workspace_name, &pod_labels)?;

    // Find all container components
    let containers = find_container_components(devfile);
    if containers.is_empty() {
        bail!("No container components found in devfile");
    }

    // Capture the first container's image for sidecar fallback
    let main_container_image = containers
        .first()
        .map(|(_, c)| c.image.clone())
        .unwrap_or_default();

    // Start each container in the pod
    for (component_name, container) in containers {
        let container_name_str = crate::pod::container_name(workspace_name, component_name);
        let source_mapping = container.source_mapping.as_deref().unwrap_or("/projects");

        // Build environment variables from devfile
        let env_vars: Vec<(&str, &str)> = container
            .env
            .iter()
            .map(|e| (e.name.as_str(), e.value.as_str()))
            .collect();

        // Build labels
        let labels = [
            ("devc.workspace", workspace_name),
            ("devc.role", "main"),
            ("devfile.component", component_name),
            ("devfile.name", devfile.metadata.name.as_str()),
            ("devcontainer.local_folder", local_folder.as_str()),
        ];

        // Handle command and args
        let command_opt = if !container.command.is_empty() {
            Some(container.command.as_slice())
        } else {
            None
        };
        let args_opt = if !container.args.is_empty() {
            Some(container.args.as_slice())
        } else {
            None
        };

        start_container_in_pod(
            &pod_name_str,
            &container_name_str,
            &container.image,
            storage,
            source_mapping,
            false, // main containers don't mount readonly
            &env_vars,
            main_secrets,
            privileged,
            enable_kvm,
            &labels,
            command_opt,
            args_opt,
            &[], // main containers don't have extra mounts
        )?;
    }

    // Start sidecar container if provided
    if let Some(sidecar_spec) = sidecar {
        let sidecar_container_name = crate::pod::container_name(workspace_name, "sidecar");
        let source_mapping = "/projects";

        // Use sidecar's image if specified, otherwise use main container's image
        let sidecar_image = sidecar_spec.image.as_ref().unwrap_or(&main_container_image);

        let labels = [
            ("devc.workspace", workspace_name),
            ("devc.role", "sidecar"),
            ("devcontainer.local_folder", local_folder.as_str()),
        ];

        // Combine explicit mounts with dotfiles (paths that mirror to same location)
        // For dotfiles, expand ~ to /root in container (since we run as root)
        let mut all_mounts = sidecar_spec.mounts.clone();
        for dotfile_path in &sidecar_spec.dotfiles {
            let container_path = if let Some(rest) = dotfile_path.strip_prefix("~/") {
                format!("/root/{}", rest)
            } else if dotfile_path == "~" {
                "/root".to_string()
            } else {
                dotfile_path.clone()
            };
            all_mounts.push(crate::config::MountSpec {
                src: dotfile_path.clone(),
                dst: container_path,
                readonly: true,
            });
        }

        // Sidecar containers always start with `sleep infinity` to keep them running.
        // The actual sidecar command (if any) is read from the config file when
        // entering via `devc enter`, which provides a proper TTY.

        // Build the startup script - always ends with sleep infinity
        let (cmd_opt, args_opt): (Option<Vec<String>>, Option<Vec<String>>) =
            if let Some(ref repo_url) = sidecar_spec.dotfiles_repo {
                // Clone dotfiles at startup, then sleep
                let install_cmd = sidecar_spec
                    .dotfiles_install
                    .as_deref()
                    .unwrap_or("install.sh");
                let script = format!(
                    r#"set -e
if [ ! -d ~/.dotfiles ]; then
  git clone --depth 1 {} ~/.dotfiles
fi
if [ -x ~/.dotfiles/{} ]; then
  cd ~/.dotfiles && ./{}
fi
exec sleep infinity"#,
                    repo_url, install_cmd, install_cmd
                );
                (
                    Some(vec!["/bin/sh".to_string()]),
                    Some(vec!["-c".to_string(), script]),
                )
            } else {
                // Just sleep - command will be run on enter
                (
                    Some(vec!["/bin/sh".to_string()]),
                    Some(vec!["-c".to_string(), "sleep infinity".to_string()]),
                )
            };

        // Sidecars always run in the pod for consistent management
        // Note: network isolation within a pod is not possible since containers share
        // the network namespace. The 'network' config option is effectively ignored.
        if !sidecar_spec.network {
            tracing::warn!(
                "sidecar.network=false is set, but sidecars run in pods and share the network namespace"
            );
        }

        start_container_in_pod(
            &pod_name_str,
            &sidecar_container_name,
            sidecar_image,
            storage,
            source_mapping,
            sidecar_spec.mount_sources_readonly,
            &[], // No extra env vars for sidecar
            sidecar_secrets,
            privileged,
            enable_kvm,
            &labels,
            cmd_opt.as_deref(),
            args_opt.as_deref(),
            &all_mounts,
        )?;
    }

    tracing::info!("Pod {} started successfully", pod_name_str);
    Ok(pod_name_str)
}

/// Execute a command in a running devfile container
pub fn exec_in_container(
    workspace_name: &str,
    component_name: &str,
    command: &[&str],
    interactive: bool,
) -> Result<i32> {
    let name = container_name(workspace_name, component_name);

    let mut cmd = ProcessCommand::new("podman");
    cmd.arg("exec");

    if interactive {
        cmd.args(["-it"]);
    }

    cmd.arg(&name);
    cmd.args(command);

    if interactive {
        cmd.stdin(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit());
    }

    let status = cmd.status().context("Failed to exec in container")?;
    Ok(status.code().unwrap_or(1))
}

/// Stop and remove a devfile container
pub fn remove_devfile_container(workspace_name: &str, component_name: &str) -> Result<()> {
    let name = container_name(workspace_name, component_name);

    let status = ProcessCommand::new("podman")
        .args(["rm", "-f", &name])
        .status()
        .context("Failed to remove container")?;

    if status.success() {
        tracing::info!("Removed container {}", name);
    }

    Ok(())
}

/// Check if a workspace is running as a pod (multi-container) or single container
pub fn is_pod_based(workspace_name: &str) -> Result<bool> {
    crate::pod::pod_exists(&crate::pod::pod_name(workspace_name))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_devfile() {
        let yaml = r#"
schemaVersion: "2.2.0"
metadata:
  name: test-devfile
components:
  - name: dev
    container:
      image: ubuntu:22.04
      mountSources: true
      env:
        - name: FOO
          value: bar
commands:
  - id: build
    exec:
      component: dev
      commandLine: make build
"#;
        let devfile: Devfile = serde_yml::from_str(yaml).unwrap();
        assert_eq!(devfile.metadata.name, "test-devfile");
        assert_eq!(devfile.components.len(), 1);
        assert_eq!(devfile.commands.len(), 1);

        let (name, container) = find_container_component(&devfile).unwrap();
        assert_eq!(name, "dev");
        assert_eq!(container.image, "ubuntu:22.04");
        assert!(container.mount_sources);
    }

    #[test]
    fn test_find_container_components_multiple() {
        let yaml = r#"
schemaVersion: "2.2.0"
metadata:
  name: multi-container
components:
  - name: dev
    container:
      image: ubuntu:22.04
  - name: database
    container:
      image: postgres:15
  - name: storage
    volume:
      size: 1Gi
"#;
        let devfile: Devfile = serde_yml::from_str(yaml).unwrap();
        let containers = find_container_components(&devfile);
        assert_eq!(containers.len(), 2);
        assert_eq!(containers[0].0, "dev");
        assert_eq!(containers[1].0, "database");
    }

    #[test]
    fn test_parse_devcontainer_json() {
        let json = r#"{
            "image": "mcr.microsoft.com/devcontainers/base:ubuntu",
            "name": "my-devcontainer",
            "containerEnv": {
                "MY_VAR": "my_value"
            }
        }"#;

        let dc: DevContainer = serde_json::from_str(json).unwrap();
        assert_eq!(
            dc.image,
            Some("mcr.microsoft.com/devcontainers/base:ubuntu".to_string())
        );
        assert_eq!(dc.name, Some("my-devcontainer".to_string()));
        assert!(dc.container_env.is_some());
    }

    #[test]
    fn test_parse_devcontainer_with_build() {
        let json = r#"{
            "build": {
                "dockerfile": "Dockerfile.dev",
                "context": ".."
            },
            "name": "built-container"
        }"#;

        let dc: DevContainer = serde_json::from_str(json).unwrap();
        assert!(dc.image.is_none());
        assert!(dc.build.is_some());
        let build = dc.build.unwrap();
        assert_eq!(build.dockerfile, Some("Dockerfile.dev".to_string()));
        assert_eq!(build.context, Some("..".to_string()));
    }

    #[test]
    fn test_sidecar_spec() {
        // Default: uses main container image, network isolated, read-only sources
        let spec = SidecarSpec {
            image: None, // Uses main container's image
            command: Some(vec!["goose".to_string()]),
            mount_sources_readonly: true,
            network: false,
            mounts: vec![],
            dotfiles: vec![],
            dotfiles_repo: None,
            dotfiles_install: None,
        };
        assert!(spec.image.is_none());
        assert!(spec.mount_sources_readonly);
        assert!(!spec.network);
        assert_eq!(spec.command, Some(vec!["goose".to_string()]));

        // With explicit image and network access enabled
        let spec_with_network = SidecarSpec {
            image: Some("ghcr.io/anthropics/claude-code:latest".to_string()),
            command: Some(vec!["claude".to_string()]),
            mount_sources_readonly: false,
            network: true,
            mounts: vec![],
            dotfiles: vec!["~/.bashrc".to_string()],
            dotfiles_repo: Some("https://github.com/user/dotfiles".to_string()),
            dotfiles_install: Some("setup.sh".to_string()),
        };
        assert_eq!(
            spec_with_network.image,
            Some("ghcr.io/anthropics/claude-code:latest".to_string())
        );
        assert!(spec_with_network.network);
        assert!(!spec_with_network.mount_sources_readonly);
    }

    #[test]
    fn test_strip_json_comments() {
        // Line comments
        let input = r#"{
            "name": "test",
            // This is a comment
            "image": "ubuntu"
        }"#;
        let output = strip_json_comments(input);
        assert!(!output.contains("// This is a comment"));
        assert!(output.contains(r#""name": "test""#));
        assert!(output.contains(r#""image": "ubuntu""#));

        // Block comments
        let input = r#"{
            "name": "test",
            /* block comment */
            "image": "ubuntu"
        }"#;
        let output = strip_json_comments(input);
        assert!(!output.contains("/* block comment */"));
        assert!(output.contains(r#""name": "test""#));

        // Comments should not be stripped inside strings
        let input = r#"{"url": "http://example.com"}"#;
        let output = strip_json_comments(input);
        assert_eq!(output, input);

        // Real-world devcontainer.json with comments
        let input = r#"{
            "name": "bootc-devenv-debian",
            "image": "ghcr.io/bootc-dev/devenv-debian",
            "runArgs": [
                // Because we want privileged
                "--privileged"
            ]
        }"#;
        let output = strip_json_comments(input);
        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();
        assert_eq!(parsed["name"], "bootc-devenv-debian");
        assert_eq!(parsed["image"], "ghcr.io/bootc-dev/devenv-debian");
    }
}
