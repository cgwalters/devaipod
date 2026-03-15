//! Devcontainer.json parsing and image specification
//!
//! This module handles parsing devcontainer.json files and extracting
//! the information needed to build container images. It does NOT handle
//! container lifecycle - that's handled by the pod module which orchestrates
//! multiple containers (workspace, agent, gator).
//!
//! Reference: https://containers.dev/implementors/json_reference/

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use color_eyre::eyre::{bail, Context, Result};
use serde::Deserialize;

use crate::secrets::DevcontainerSecretDecl;

/// Parsed devcontainer.json configuration
///
/// We only parse the fields we need for our multi-container setup.
/// The full spec has many more fields, but we intentionally keep this minimal.
/// Some fields are parsed for future use but not yet implemented.
#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code)] // Fields are parsed for forward compatibility, used incrementally
pub struct DevcontainerConfig {
    /// Container name (used for naming the pod)
    pub name: Option<String>,

    /// Direct image reference (e.g., "mcr.microsoft.com/devcontainers/rust:1")
    pub image: Option<String>,

    /// Build configuration (alternative to image)
    pub build: Option<BuildConfig>,

    /// Workspace folder inside container
    #[serde(default = "default_workspace_folder")]
    pub workspace_folder: String,

    /// Devcontainer features to install
    #[serde(default)]
    pub features: HashMap<String, serde_json::Value>,

    /// Command to run after container is created (first time only)
    pub on_create_command: Option<Command>,

    /// Command to run after dependencies are installed
    pub post_create_command: Option<Command>,

    /// Command to run after container starts
    pub post_start_command: Option<Command>,

    /// Command to run when client attaches
    pub post_attach_command: Option<Command>,

    /// Remote user to use inside container
    pub remote_user: Option<String>,

    /// Container user (for running commands during build)
    pub container_user: Option<String>,

    /// Environment variables for the container
    #[serde(default)]
    pub container_env: HashMap<String, String>,

    /// Environment variables for remote connections
    #[serde(default)]
    pub remote_env: HashMap<String, String>,

    /// Additional mounts
    #[serde(default)]
    pub mounts: Vec<serde_json::Value>,

    /// Ports to forward
    #[serde(default)]
    pub forward_ports: Vec<serde_json::Value>,

    /// Whether to run privileged
    #[serde(default)]
    pub privileged: bool,

    /// Capabilities to add
    #[serde(default)]
    pub cap_add: Vec<String>,

    /// Security options
    #[serde(default)]
    pub security_opt: Vec<String>,

    /// Tool-specific customizations (VS Code, devaipod, etc.)
    #[serde(default)]
    pub customizations: Option<Customizations>,

    /// Additional arguments to pass to podman/docker run
    #[serde(default)]
    pub run_args: Vec<String>,

    /// Secrets configuration from devcontainer.json
    /// Maps secret names to their declarations (description, documentation URL, etc.)
    /// The key is used as both the environment variable name and the podman secret name.
    #[serde(default)]
    pub secrets: HashMap<String, DevcontainerSecretDecl>,
}

/// Tool-specific customizations in devcontainer.json
#[derive(Debug, Deserialize, Clone, Default)]
pub struct Customizations {
    /// Devaipod-specific customizations
    #[serde(default)]
    pub devaipod: Option<DevaipodCustomizations>,
}

/// Devaipod-specific customizations in devcontainer.json
///
/// Example in devcontainer.json:
/// ```json
/// {
///   "customizations": {
///     "devaipod": {
///       "env_allowlist": ["ANTHROPIC_API_KEY", "MY_CUSTOM_TOKEN"]
///     }
///   }
/// }
/// ```
#[derive(Debug, Deserialize, Clone, Default)]
#[serde(rename_all = "camelCase")]
pub struct DevaipodCustomizations {
    /// Environment variables to pass to the agent container.
    /// These are forwarded from the host environment to the agent.
    /// This is an alternative to using DEVAIPOD_AGENT_* prefix.
    #[serde(default)]
    pub env_allowlist: Vec<String>,

    /// When true, apply minimal privileges for nested container support
    /// (unmask=/proc/*, SYS_ADMIN, NET_ADMIN, seccomp=unconfined, label=disable,
    /// /dev/net/tun) instead of full --privileged.
    ///
    /// This allows devcontainer.json to use "privileged": true for compatibility
    /// with stock devcontainer CLI tooling (Docker/Podman), while devaipod uses
    /// more targeted security settings.
    #[serde(default)]
    pub nested_containers: bool,
}

fn default_workspace_folder() -> String {
    "/workspaces/project".to_string()
}

impl Default for DevcontainerConfig {
    fn default() -> Self {
        Self {
            name: None,
            image: None,
            build: None,
            workspace_folder: default_workspace_folder(),
            features: HashMap::new(),
            on_create_command: None,
            post_create_command: None,
            post_start_command: None,
            post_attach_command: None,
            remote_user: None,
            container_user: None,
            container_env: HashMap::new(),
            remote_env: HashMap::new(),
            mounts: Vec::new(),
            forward_ports: Vec::new(),
            privileged: false,
            cap_add: Vec::new(),
            security_opt: Vec::new(),
            customizations: None,
            run_args: Vec::new(),
            secrets: HashMap::new(),
        }
    }
}

/// Build configuration
#[derive(Debug, Deserialize, Default, Clone)]
#[serde(rename_all = "camelCase")]
pub struct BuildConfig {
    /// Path to Dockerfile (relative to context)
    pub dockerfile: Option<String>,

    /// Build context directory
    pub context: Option<String>,

    /// Build arguments
    #[serde(default)]
    pub args: HashMap<String, String>,

    /// Target build stage
    pub target: Option<String>,
}

/// Command can be a string, array of strings, or object with parallel commands
#[derive(Debug, Deserialize, Clone)]
#[serde(untagged)]
pub enum Command {
    /// Simple shell command
    String(String),
    /// Command with arguments
    Array(Vec<String>),
    /// Named parallel commands
    Object(HashMap<String, serde_json::Value>),
}

impl Command {
    /// Convert to a shell command string for execution
    pub fn to_shell_command(&self) -> String {
        match self {
            Command::String(s) => s.clone(),
            Command::Array(arr) => {
                // Quote arguments that need it
                arr.iter()
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
            Command::Object(map) => {
                // Run commands in parallel using & and wait for all
                let cmds: Vec<_> = map
                    .values()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect();
                if cmds.is_empty() {
                    String::new()
                } else {
                    cmds.join(" & ") + " & wait"
                }
            }
        }
    }
}

/// Specification for building/pulling a container image
#[derive(Debug, Clone)]
pub enum ImageSource {
    /// Pull an existing image
    Image(String),
    /// Build from a Dockerfile
    Build {
        /// Absolute path to build context
        context: PathBuf,
        /// Dockerfile path relative to context
        dockerfile: String,
        /// Build arguments
        args: HashMap<String, String>,
        /// Target stage
        target: Option<String>,
    },
}

impl DevcontainerConfig {
    /// Determine the image source (pull vs build)
    ///
    /// `devcontainer_dir` is the directory containing devcontainer.json,
    /// used to resolve relative paths in build config.
    pub fn image_source(&self, devcontainer_dir: &Path) -> Result<ImageSource> {
        if let Some(image) = &self.image {
            Ok(ImageSource::Image(image.clone()))
        } else if let Some(build) = &self.build {
            let context_relative = build.context.as_deref().unwrap_or(".");
            let context = devcontainer_dir
                .join(context_relative)
                .canonicalize()
                .with_context(|| {
                    format!(
                        "Build context not found: {}",
                        devcontainer_dir.join(context_relative).display()
                    )
                })?;

            let dockerfile = build
                .dockerfile
                .clone()
                .unwrap_or_else(|| "Dockerfile".to_string());

            Ok(ImageSource::Build {
                context,
                dockerfile,
                args: build.args.clone(),
                target: build.target.clone(),
            })
        } else {
            bail!(
                "devcontainer.json must specify either 'image' or 'build'. \
                 Compose-based devcontainers are not supported."
            )
        }
    }

    /// Get the workspace folder path, computing a reasonable default if not specified
    pub fn workspace_folder_for_project(&self, project_name: &str) -> String {
        if self.workspace_folder != "/workspaces/project" {
            self.workspace_folder.clone()
        } else {
            format!("/workspaces/{}", project_name)
        }
    }

    /// Get the user to run commands as inside the container
    pub fn effective_user(&self) -> Option<&str> {
        self.remote_user
            .as_deref()
            .or(self.container_user.as_deref())
    }

    /// Get environment variables from the allowlist that should be passed to the agent
    ///
    /// Collects env vars specified in customizations.devaipod.env_allowlist
    /// from the current process environment.
    pub fn collect_allowlist_env_vars(&self) -> Vec<(String, String)> {
        let Some(customizations) = &self.customizations else {
            return Vec::new();
        };
        let Some(devaipod) = &customizations.devaipod else {
            return Vec::new();
        };

        devaipod
            .env_allowlist
            .iter()
            .filter_map(|key| std::env::var(key).ok().map(|value| (key.clone(), value)))
            .collect()
    }

    /// Check if this configuration has any features defined
    pub fn has_features(&self) -> bool {
        !self.features.is_empty()
    }

    /// Check if devaipod nested containers mode is enabled
    pub fn has_nested_containers(&self) -> bool {
        self.customizations
            .as_ref()
            .and_then(|c| c.devaipod.as_ref())
            .map(|d| d.nested_containers)
            .unwrap_or(false)
    }

    /// Check if --privileged is in runArgs
    pub fn has_privileged_run_arg(&self) -> bool {
        self.run_args.iter().any(|arg| arg == "--privileged")
    }

    /// Get device paths from runArgs (e.g., --device=/dev/kvm or --device /dev/kvm)
    ///
    /// Handles both `--device=/dev/foo` and `--device /dev/foo` formats.
    /// Returns the device paths (e.g., "/dev/kvm"), not the flag itself.
    pub fn device_args(&self) -> Vec<String> {
        let mut devices = Vec::new();
        let mut iter = self.run_args.iter().peekable();

        while let Some(arg) = iter.next() {
            if let Some(value) = arg.strip_prefix("--device=") {
                // Format: --device=/dev/foo or --device=/dev/foo:rwm
                if !value.is_empty() {
                    devices.push(value.to_string());
                }
            } else if arg == "--device" {
                // Format: --device /dev/foo
                if let Some(value) = iter.next() {
                    if !value.starts_with('-') {
                        devices.push(value.to_string());
                    }
                }
            }
        }
        devices
    }

    /// Get security options from runArgs (e.g., --security-opt label=disable)
    ///
    /// Handles both `--security-opt=value` and `--security-opt value` formats.
    /// Returns just the values (e.g., "label=disable"), not the flag itself.
    pub fn security_opt_args(&self) -> Vec<String> {
        let mut opts = Vec::new();
        let mut iter = self.run_args.iter().peekable();

        while let Some(arg) = iter.next() {
            if let Some(value) = arg.strip_prefix("--security-opt=") {
                // Format: --security-opt=value
                if !value.is_empty() {
                    opts.push(value.to_string());
                }
            } else if arg == "--security-opt" {
                // Format: --security-opt value
                if let Some(value) = iter.next() {
                    if !value.starts_with('-') {
                        opts.push(value.to_string());
                    }
                }
            }
        }
        opts
    }

    /// Get capabilities from runArgs (e.g., --cap-add=ALL or --cap-add SYS_ADMIN)
    ///
    /// Handles both `--cap-add=VALUE` and `--cap-add VALUE` formats.
    /// Returns just the values (e.g., "ALL", "SYS_ADMIN"), not the flag itself.
    pub fn cap_add_args(&self) -> Vec<String> {
        let mut caps = Vec::new();
        let mut iter = self.run_args.iter().peekable();

        while let Some(arg) = iter.next() {
            if let Some(value) = arg.strip_prefix("--cap-add=") {
                // Format: --cap-add=VALUE
                if !value.is_empty() {
                    caps.push(value.to_string());
                }
            } else if arg == "--cap-add" {
                // Format: --cap-add VALUE
                if let Some(value) = iter.next() {
                    if !value.starts_with('-') {
                        caps.push(value.to_string());
                    }
                }
            }
        }
        caps
    }

    /// Get runArgs entries that aren't handled by typed extraction methods.
    ///
    /// Returns args that should be passed through verbatim to `podman create`.
    /// Known flags (--privileged, --device, --security-opt, --cap-add) are
    /// extracted by their respective methods and excluded here.
    pub fn passthrough_run_args(&self) -> Vec<String> {
        let mut passthrough = Vec::new();
        let mut iter = self.run_args.iter().peekable();

        while let Some(arg) = iter.next() {
            if arg == "--privileged" {
                // Handled by has_privileged_run_arg()
                continue;
            }

            // Flags that we extract into typed fields
            let extracted_flags = ["--device", "--security-opt", "--cap-add"];
            let is_extracted = extracted_flags
                .iter()
                .any(|flag| arg.starts_with(&format!("{}=", flag)) || arg == *flag);

            if is_extracted {
                // If it's the --flag value form (no =), skip the value too
                if !arg.contains('=') {
                    iter.next();
                }
                continue;
            }

            // Unknown flag — pass through verbatim
            passthrough.push(arg.clone());
            // If this looks like a flag with a space-separated value, include the value too
            // (i.e., starts with -- and next arg doesn't start with --)
            if arg.starts_with("--") && !arg.contains('=') {
                if let Some(next) = iter.peek() {
                    if !next.starts_with("--") {
                        passthrough.push(iter.next().unwrap().clone());
                    }
                }
            }
        }
        passthrough
    }

    /// Parse `forwardPorts` entries into podman `-p` port specs.
    ///
    /// Supports two formats from the devcontainer spec:
    /// - Integer: `3000` → `"0.0.0.0::3000"` (random host port)
    /// - String `"hostPort:containerPort"`: `"8080:3000"` → `"0.0.0.0:8080:3000"`
    ///
    /// Invalid entries are logged and skipped.
    pub fn publish_port_specs(&self) -> Vec<String> {
        let mut specs = Vec::new();
        for entry in &self.forward_ports {
            match entry {
                serde_json::Value::Number(n) => {
                    if let Some(port) = n.as_u64() {
                        if port > 0 && port <= 65535 {
                            specs.push(format!("0.0.0.0::{}", port));
                        } else {
                            tracing::warn!("forwardPorts: port {} out of range, skipping", port);
                        }
                    } else {
                        tracing::warn!("forwardPorts: invalid number {:?}, skipping", n);
                    }
                }
                serde_json::Value::String(s) => {
                    // Expected format: "hostPort:containerPort"
                    // We also handle plain port number as string: "3000"
                    let parts: Vec<&str> = s.split(':').collect();
                    match parts.len() {
                        1 => {
                            // Plain port number as string
                            match parts[0].parse::<u16>() {
                                Ok(port) if port > 0 => {
                                    specs.push(format!("0.0.0.0::{}", port));
                                }
                                Ok(0) => {
                                    tracing::warn!("forwardPorts: port 0 is invalid, skipping");
                                }
                                _ => {
                                    tracing::warn!(
                                        "forwardPorts: could not parse '{}' as port, skipping",
                                        s
                                    );
                                }
                            }
                        }
                        2 => {
                            // "hostPort:containerPort" (we only handle numeric forms)
                            let host_port = parts[0].parse::<u16>();
                            let container_port = parts[1].parse::<u16>();
                            match (host_port, container_port) {
                                (Ok(_), Ok(0)) => {
                                    tracing::warn!(
                                        "forwardPorts: container port 0 is invalid in '{}', skipping",
                                        s
                                    );
                                }
                                (Ok(hp), Ok(cp)) => {
                                    specs.push(format!("0.0.0.0:{}:{}", hp, cp));
                                }
                                _ => {
                                    tracing::warn!(
                                        "forwardPorts: could not parse '{}' as host:container port mapping, skipping",
                                        s
                                    );
                                }
                            }
                        }
                        _ => {
                            tracing::warn!("forwardPorts: unexpected format '{}', skipping", s);
                        }
                    }
                }
                other => {
                    tracing::warn!("forwardPorts: unexpected entry type {:?}, skipping", other);
                }
            }
        }
        specs
    }

    /// Get (env_var_name, secret_name) pairs for devcontainer.json secrets.
    ///
    /// For devcontainer.json, the convention is that the secret key is used as
    /// both the environment variable name and the podman secret name.
    /// Returns a vector of tuples where each tuple contains:
    /// - The environment variable name to set
    /// - The podman secret name containing the value
    ///
    /// This follows the same pattern as `TrustedEnvConfig::secret_mounts()`.
    pub fn devcontainer_secret_mounts(&self) -> Vec<(String, String)> {
        self.secrets
            .keys()
            .map(|secret_name| (secret_name.clone(), secret_name.clone()))
            .collect()
    }
}

/// Try to find devcontainer.json, returning None if not found
///
/// Searches in standard locations:
/// 1. `.devcontainer/devcontainer.json`
/// 2. `.devcontainer.json` (root)
/// 3. `.devcontainer/<subdir>/devcontainer.json` (first match)
///
/// This is useful when an image override is provided and devcontainer.json is optional.
pub fn try_find_devcontainer_json(project_path: &Path) -> Option<PathBuf> {
    // Standard location
    let standard = project_path.join(".devcontainer/devcontainer.json");
    if standard.exists() {
        return Some(standard);
    }

    // Root location
    let root = project_path.join(".devcontainer.json");
    if root.exists() {
        return Some(root);
    }

    // Check for subdirectories in .devcontainer
    let devcontainer_dir = project_path.join(".devcontainer");
    if devcontainer_dir.is_dir() {
        if let Ok(entries) = std::fs::read_dir(&devcontainer_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    let nested = path.join("devcontainer.json");
                    if nested.exists() {
                        return Some(nested);
                    }
                }
            }
        }
    }

    None
}

/// Find the devcontainer.json file for a project, returning an error if not found
///
/// See [`try_find_devcontainer_json`] for the search logic.
pub fn find_devcontainer_json(project_path: &Path) -> Result<PathBuf> {
    try_find_devcontainer_json(project_path).ok_or_else(|| {
        color_eyre::eyre::eyre!(
            "No devcontainer.json found in {}. \
             Expected at .devcontainer/devcontainer.json",
            project_path.display()
        )
    })
}

/// Load and parse a devcontainer.json file
pub fn load(path: &Path) -> Result<DevcontainerConfig> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read {}", path.display()))?;

    // Parse JSONC (JSON with comments) - devcontainer.json uses this format
    parse_jsonc(&content).with_context(|| format!("Failed to deserialize {}", path.display()))
}

/// Parse a devcontainer.json from an inline JSONC string.
///
/// This accepts the same format as a devcontainer.json file (JSON with comments).
/// Used for the `--devcontainer-json` CLI flag and web UI override.
///
/// Only image-based configs are supported for inline JSON; `build` blocks require
/// filesystem context that isn't available with inline overrides.
pub fn parse_jsonc(content: &str) -> Result<DevcontainerConfig> {
    let config: DevcontainerConfig =
        jsonc_parser::parse_to_serde_value(content, &Default::default())
            .map_err(|e| color_eyre::eyre::eyre!("Failed to parse JSONC: {}", e))?
            .map(serde_json::from_value)
            .transpose()
            .context("Failed to deserialize devcontainer JSON")?
            .unwrap_or_default();

    if config.build.is_some() && config.image.is_none() {
        bail!(
            "Inline --devcontainer-json with a 'build' block is not supported \
             (build context paths cannot be resolved). Use 'image' instead."
        );
    }

    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_image_based() {
        let json = r#"{
            "image": "mcr.microsoft.com/devcontainers/rust:1",
            "features": {
                "ghcr.io/devcontainers/features/node:1": {}
            },
            "postCreateCommand": "cargo build"
        }"#;

        let config: DevcontainerConfig = serde_json::from_str(json).unwrap();
        assert_eq!(
            config.image,
            Some("mcr.microsoft.com/devcontainers/rust:1".to_string())
        );
        assert!(config
            .features
            .contains_key("ghcr.io/devcontainers/features/node:1"));
        assert!(matches!(
            config.post_create_command,
            Some(Command::String(_))
        ));
    }

    #[test]
    fn test_parse_dockerfile_based() {
        let json = r#"{
            "build": {
                "dockerfile": "Dockerfile",
                "context": "..",
                "args": { "VARIANT": "bullseye" }
            },
            "remoteUser": "vscode"
        }"#;

        let config: DevcontainerConfig = serde_json::from_str(json).unwrap();
        assert!(config.build.is_some());
        let build = config.build.as_ref().unwrap();
        assert_eq!(build.dockerfile, Some("Dockerfile".to_string()));
        assert_eq!(build.context, Some("..".to_string()));
        assert_eq!(build.args.get("VARIANT"), Some(&"bullseye".to_string()));
        assert_eq!(config.remote_user, Some("vscode".to_string()));
    }

    #[test]
    fn test_command_to_shell() {
        let cmd = Command::String("echo hello".to_string());
        assert_eq!(cmd.to_shell_command(), "echo hello");

        let cmd = Command::Array(vec!["echo".to_string(), "hello world".to_string()]);
        assert_eq!(cmd.to_shell_command(), "echo 'hello world'");
    }

    #[test]
    fn test_workspace_folder_default() {
        let config = DevcontainerConfig::default();
        assert_eq!(
            config.workspace_folder_for_project("myproject"),
            "/workspaces/myproject"
        );
    }

    #[test]
    fn test_workspace_folder_explicit() {
        let json = r#"{"image": "foo", "workspaceFolder": "/home/user/code"}"#;
        let config: DevcontainerConfig = serde_json::from_str(json).unwrap();
        assert_eq!(
            config.workspace_folder_for_project("ignored"),
            "/home/user/code"
        );
    }

    #[test]
    fn test_parse_devaipod_customizations() {
        let json = r#"{
            "image": "foo",
            "customizations": {
                "devaipod": {
                    "envAllowlist": ["MY_API_KEY", "CUSTOM_TOKEN"]
                }
            }
        }"#;
        let config: DevcontainerConfig = serde_json::from_str(json).unwrap();

        let customizations = config.customizations.expect("customizations should exist");
        let devaipod = customizations.devaipod.expect("devaipod should exist");

        assert_eq!(devaipod.env_allowlist, vec!["MY_API_KEY", "CUSTOM_TOKEN"]);
    }

    #[test]
    fn test_has_features_empty() {
        let config = DevcontainerConfig::default();
        assert!(!config.has_features());
    }

    #[test]
    fn test_has_features_with_features() {
        let json = r#"{
            "image": "mcr.microsoft.com/devcontainers/rust:1",
            "features": {
                "ghcr.io/devcontainers/features/node:1": {}
            }
        }"#;
        let config: DevcontainerConfig = serde_json::from_str(json).unwrap();
        assert!(config.has_features());
    }

    #[test]
    fn test_has_features_empty_object() {
        let json = r#"{
            "image": "mcr.microsoft.com/devcontainers/rust:1",
            "features": {}
        }"#;
        let config: DevcontainerConfig = serde_json::from_str(json).unwrap();
        assert!(!config.has_features());
    }

    #[test]
    fn test_parse_run_args() {
        let json = r#"{
            "image": "quay.io/centos-bootc/bootc:stream9",
            "runArgs": ["--privileged"]
        }"#;
        let config: DevcontainerConfig = serde_json::from_str(json).unwrap();
        assert_eq!(config.run_args, vec!["--privileged"]);
        assert!(config.has_privileged_run_arg());
    }

    #[test]
    fn test_run_args_with_devices_equals_format() {
        let json = r#"{
            "image": "foo",
            "runArgs": ["--privileged", "--device=/dev/kvm", "--device=/dev/fuse:rwm"]
        }"#;
        let config: DevcontainerConfig = serde_json::from_str(json).unwrap();
        assert!(config.has_privileged_run_arg());

        let device_args = config.device_args();
        assert_eq!(device_args.len(), 2);
        // Now returns just the device paths, not the full --device=... string
        assert!(device_args.contains(&"/dev/kvm".to_string()));
        assert!(device_args.contains(&"/dev/fuse:rwm".to_string()));
    }

    #[test]
    fn test_run_args_with_devices_space_format() {
        let json = r#"{
            "image": "foo",
            "runArgs": ["--device", "/dev/net/tun", "--device", "/dev/kvm"]
        }"#;
        let config: DevcontainerConfig = serde_json::from_str(json).unwrap();

        let device_args = config.device_args();
        assert_eq!(device_args.len(), 2);
        assert!(device_args.contains(&"/dev/net/tun".to_string()));
        assert!(device_args.contains(&"/dev/kvm".to_string()));
    }

    #[test]
    fn test_run_args_empty() {
        let config = DevcontainerConfig::default();
        assert!(config.run_args.is_empty());
        assert!(!config.has_privileged_run_arg());
        assert!(config.device_args().is_empty());
    }

    #[test]
    fn test_run_args_no_privileged() {
        let json = r#"{
            "image": "foo",
            "runArgs": ["--device=/dev/kvm"]
        }"#;
        let config: DevcontainerConfig = serde_json::from_str(json).unwrap();
        assert!(!config.has_privileged_run_arg());
        assert_eq!(config.device_args(), vec!["/dev/kvm"]);
    }

    #[test]
    fn test_security_opt_args_equals_format() {
        let json = r#"{
            "image": "foo",
            "runArgs": ["--security-opt=label=disable", "--security-opt=unmask=/proc/*"]
        }"#;
        let config: DevcontainerConfig = serde_json::from_str(json).unwrap();
        let opts = config.security_opt_args();
        assert_eq!(opts.len(), 2);
        assert!(opts.contains(&"label=disable".to_string()));
        assert!(opts.contains(&"unmask=/proc/*".to_string()));
    }

    #[test]
    fn test_security_opt_args_space_format() {
        let json = r#"{
            "image": "foo",
            "runArgs": ["--security-opt", "label=disable", "--security-opt", "unmask=/proc/*"]
        }"#;
        let config: DevcontainerConfig = serde_json::from_str(json).unwrap();
        let opts = config.security_opt_args();
        assert_eq!(opts.len(), 2);
        assert!(opts.contains(&"label=disable".to_string()));
        assert!(opts.contains(&"unmask=/proc/*".to_string()));
    }

    #[test]
    fn test_security_opt_args_mixed_format() {
        let json = r#"{
            "image": "foo",
            "runArgs": ["--security-opt=label=disable", "--security-opt", "unmask=/proc/*", "--device=/dev/kvm"]
        }"#;
        let config: DevcontainerConfig = serde_json::from_str(json).unwrap();
        let opts = config.security_opt_args();
        assert_eq!(opts.len(), 2);
        assert!(opts.contains(&"label=disable".to_string()));
        assert!(opts.contains(&"unmask=/proc/*".to_string()));
        // Device args should still work (now returns just the device path)
        assert_eq!(config.device_args(), vec!["/dev/kvm"]);
    }

    #[test]
    fn test_security_opt_args_empty() {
        let config = DevcontainerConfig::default();
        assert!(config.security_opt_args().is_empty());
    }

    #[test]
    fn test_cap_add_args_equals_format() {
        let json = r#"{
            "image": "foo",
            "runArgs": ["--cap-add=ALL", "--cap-add=SYS_ADMIN"]
        }"#;
        let config: DevcontainerConfig = serde_json::from_str(json).unwrap();
        let caps = config.cap_add_args();
        assert_eq!(caps.len(), 2);
        assert!(caps.contains(&"ALL".to_string()));
        assert!(caps.contains(&"SYS_ADMIN".to_string()));
    }

    #[test]
    fn test_cap_add_args_space_format() {
        let json = r#"{
            "image": "foo",
            "runArgs": ["--cap-add", "ALL", "--cap-add", "SYS_PTRACE"]
        }"#;
        let config: DevcontainerConfig = serde_json::from_str(json).unwrap();
        let caps = config.cap_add_args();
        assert_eq!(caps.len(), 2);
        assert!(caps.contains(&"ALL".to_string()));
        assert!(caps.contains(&"SYS_PTRACE".to_string()));
    }

    #[test]
    fn test_cap_add_args_empty() {
        let config = DevcontainerConfig::default();
        assert!(config.cap_add_args().is_empty());
    }

    #[test]
    fn test_cap_add_args_mixed_with_other_flags() {
        let json = r#"{
            "image": "foo",
            "runArgs": ["--cap-add=NET_ADMIN", "--security-opt=label=disable", "--cap-add", "SYS_ADMIN"]
        }"#;
        let config: DevcontainerConfig = serde_json::from_str(json).unwrap();
        let caps = config.cap_add_args();
        assert_eq!(caps.len(), 2);
        assert!(caps.contains(&"NET_ADMIN".to_string()));
        assert!(caps.contains(&"SYS_ADMIN".to_string()));
        // Other extractors should still work
        assert_eq!(config.security_opt_args(), vec!["label=disable"]);
    }

    #[test]
    fn test_parse_jsonc_inline() {
        let json = r#"{
            // This is a comment
            "image": "ghcr.io/bootc-dev/devenv-debian",
            "capAdd": ["SYS_ADMIN"],
            "runArgs": ["--security-opt", "label=disable", "--cap-add=NET_ADMIN"]
        }"#;
        let config = super::parse_jsonc(json).unwrap();
        assert_eq!(
            config.image,
            Some("ghcr.io/bootc-dev/devenv-debian".to_string())
        );
        assert_eq!(config.cap_add, vec!["SYS_ADMIN"]);
        assert_eq!(
            config.run_args,
            vec!["--security-opt", "label=disable", "--cap-add=NET_ADMIN"]
        );
        // cap_add_args extracts from runArgs, separate from the structured capAdd field
        assert_eq!(config.cap_add_args(), vec!["NET_ADMIN"]);
    }

    #[test]
    fn test_parse_jsonc_empty_string() {
        // Empty string produces default config (no image), which is valid JSON
        // but will fail later at image_source() with a clear error
        let config = super::parse_jsonc("").unwrap();
        assert!(config.image.is_none());
    }

    #[test]
    fn test_parse_jsonc_rejects_build_without_image() {
        let json = r#"{"build": {"dockerfile": "Dockerfile"}}"#;
        let result = super::parse_jsonc(json);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("build context paths cannot be resolved"));
    }

    #[test]
    fn test_parse_jsonc_allows_build_with_image() {
        // If both build and image are specified, image takes precedence (per devcontainer spec)
        let json = r#"{"image": "debian", "build": {"dockerfile": "Dockerfile"}}"#;
        let config = super::parse_jsonc(json).unwrap();
        assert_eq!(config.image, Some("debian".to_string()));
    }

    #[test]
    fn test_passthrough_run_args_known_filtered() {
        let json = r#"{
            "image": "foo",
            "runArgs": ["--privileged", "--device=/dev/kvm", "--security-opt", "label=disable", "--cap-add=ALL"]
        }"#;
        let config: DevcontainerConfig = serde_json::from_str(json).unwrap();
        // All known flags should be filtered out
        assert!(config.passthrough_run_args().is_empty());
    }

    #[test]
    fn test_passthrough_run_args_unknown_passed_through() {
        let json = r#"{
            "image": "foo",
            "runArgs": ["--cap-add=ALL", "--ulimit", "nofile=1024:1024", "--hostname=myhost"]
        }"#;
        let config: DevcontainerConfig = serde_json::from_str(json).unwrap();
        let passthrough = config.passthrough_run_args();
        // --cap-add=ALL should be filtered, rest passed through
        assert_eq!(
            passthrough,
            vec!["--ulimit", "nofile=1024:1024", "--hostname=myhost"]
        );
    }

    #[test]
    fn test_passthrough_run_args_empty() {
        let config = DevcontainerConfig::default();
        assert!(config.passthrough_run_args().is_empty());
    }

    #[test]
    fn test_parse_nested_containers() {
        let json = r#"{
            "image": "foo",
            "privileged": true,
            "customizations": {
                "devaipod": {
                    "nestedContainers": true
                }
            }
        }"#;
        let config: DevcontainerConfig = serde_json::from_str(json).unwrap();
        assert!(config.has_nested_containers());
        assert!(config.privileged); // raw field is still true
    }

    #[test]
    fn test_nested_containers_default_false() {
        let json = r#"{
            "image": "foo",
            "customizations": {
                "devaipod": {
                    "envAllowlist": ["FOO"]
                }
            }
        }"#;
        let config: DevcontainerConfig = serde_json::from_str(json).unwrap();
        assert!(!config.has_nested_containers());
    }

    #[test]
    fn test_nested_containers_no_customizations() {
        let config = DevcontainerConfig::default();
        assert!(!config.has_nested_containers());
    }

    #[test]
    fn test_parse_devcontainer_secrets() {
        let json = r#"{
            "image": "foo",
            "secrets": {
                "ANTHROPIC_API_KEY": {
                    "description": "API key for Anthropic Claude"
                },
                "OPENAI_API_KEY": {
                    "description": "API key for OpenAI",
                    "documentationUrl": "https://platform.openai.com/api-keys"
                }
            }
        }"#;
        let config: DevcontainerConfig = serde_json::from_str(json).unwrap();
        assert_eq!(config.secrets.len(), 2);
        assert!(config.secrets.contains_key("ANTHROPIC_API_KEY"));
        assert!(config.secrets.contains_key("OPENAI_API_KEY"));
    }

    #[test]
    fn test_devcontainer_secret_mounts() {
        let json = r#"{
            "image": "foo",
            "secrets": {
                "ANTHROPIC_API_KEY": {
                    "description": "API key for Anthropic Claude"
                },
                "OPENAI_API_KEY": {}
            }
        }"#;
        let config: DevcontainerConfig = serde_json::from_str(json).unwrap();
        let secret_mounts = config.devcontainer_secret_mounts();

        // Should have 2 secrets, each mapping key to key
        assert_eq!(secret_mounts.len(), 2);
        assert!(secret_mounts.contains(&(
            "ANTHROPIC_API_KEY".to_string(),
            "ANTHROPIC_API_KEY".to_string()
        )));
        assert!(
            secret_mounts.contains(&("OPENAI_API_KEY".to_string(), "OPENAI_API_KEY".to_string()))
        );
    }

    #[test]
    fn test_devcontainer_secret_mounts_empty() {
        let config = DevcontainerConfig::default();
        let secret_mounts = config.devcontainer_secret_mounts();
        assert!(secret_mounts.is_empty());
    }

    #[test]
    fn test_publish_port_specs_integers() {
        let config = DevcontainerConfig {
            forward_ports: vec![serde_json::json!(3000), serde_json::json!(8080)],
            ..Default::default()
        };
        let specs = config.publish_port_specs();
        assert_eq!(specs, vec!["0.0.0.0::3000", "0.0.0.0::8080"]);
    }

    #[test]
    fn test_publish_port_specs_strings() {
        let config = DevcontainerConfig {
            forward_ports: vec![serde_json::json!("3000"), serde_json::json!("8080:3000")],
            ..Default::default()
        };
        let specs = config.publish_port_specs();
        assert_eq!(specs, vec!["0.0.0.0::3000", "0.0.0.0:8080:3000"]);
    }

    #[test]
    fn test_publish_port_specs_mixed() {
        let config = DevcontainerConfig {
            forward_ports: vec![
                serde_json::json!(3000),
                serde_json::json!("9090:8080"),
                serde_json::json!("invalid"),
                serde_json::json!(99999), // out of range
                serde_json::json!(true),  // wrong type
            ],
            ..Default::default()
        };
        let specs = config.publish_port_specs();
        assert_eq!(specs, vec!["0.0.0.0::3000", "0.0.0.0:9090:8080"]);
    }

    #[test]
    fn test_publish_port_specs_empty() {
        let config = DevcontainerConfig::default();
        let specs = config.publish_port_specs();
        assert!(specs.is_empty());
    }

    #[test]
    fn test_publish_port_specs_rejects_zero() {
        let config = DevcontainerConfig {
            forward_ports: vec![
                serde_json::json!(0),                     // integer 0
                serde_json::json!("0"),                   // string "0"
                serde_json::json!("0:3000"),              // host port 0 is ok (means random)
                serde_json::json!("8080:0"),              // container port 0 is invalid
                serde_json::json!("127.0.0.1:8080:3000"), // 3 parts, unsupported
            ],
            ..Default::default()
        };
        let specs = config.publish_port_specs();
        // Only "0:3000" should pass (host port 0 = random assignment by podman)
        assert_eq!(specs, vec!["0.0.0.0:0:3000"]);
    }

    #[test]
    fn test_parse_forward_ports_from_json() {
        let json = r#"{"image": "test", "forwardPorts": [3000, "8080:3000"]}"#;
        let config: DevcontainerConfig = serde_json::from_str(json).unwrap();
        let specs = config.publish_port_specs();
        assert_eq!(specs, vec!["0.0.0.0::3000", "0.0.0.0:8080:3000"]);
    }
}
