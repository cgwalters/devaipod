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

    /// Additional allowed domains for network isolation.
    /// Merged with the global config's allowed_domains.
    #[serde(default)]
    pub allowed_domains: Vec<String>,
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

    /// Get additional allowed domains from devcontainer customizations
    pub fn allowed_domains(&self) -> Vec<String> {
        self.customizations
            .as_ref()
            .and_then(|c| c.devaipod.as_ref())
            .map(|d| d.allowed_domains.clone())
            .unwrap_or_default()
    }

    /// Check if this configuration has any features defined
    pub fn has_features(&self) -> bool {
        !self.features.is_empty()
    }

    /// Check if --privileged is in runArgs
    pub fn has_privileged_run_arg(&self) -> bool {
        self.run_args.iter().any(|arg| arg == "--privileged")
    }

    /// Get device passthrough args from runArgs (e.g., --device=/dev/kvm)
    pub fn device_args(&self) -> Vec<String> {
        self.run_args
            .iter()
            .filter(|arg| arg.starts_with("--device"))
            .cloned()
            .collect()
    }
}

/// Find the devcontainer.json file for a project
///
/// Searches in standard locations:
/// 1. `.devcontainer/devcontainer.json`
/// 2. `.devcontainer.json` (root)
/// 3. `.devcontainer/<subdir>/devcontainer.json` (first match)
pub fn find_devcontainer_json(project_path: &Path) -> Result<PathBuf> {
    // Standard location
    let standard = project_path.join(".devcontainer/devcontainer.json");
    if standard.exists() {
        return Ok(standard);
    }

    // Root location
    let root = project_path.join(".devcontainer.json");
    if root.exists() {
        return Ok(root);
    }

    // Check for subdirectories in .devcontainer
    let devcontainer_dir = project_path.join(".devcontainer");
    if devcontainer_dir.is_dir() {
        for entry in std::fs::read_dir(&devcontainer_dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_dir() {
                let nested = path.join("devcontainer.json");
                if nested.exists() {
                    return Ok(nested);
                }
            }
        }
    }

    bail!(
        "No devcontainer.json found in {}. \
         Expected at .devcontainer/devcontainer.json",
        project_path.display()
    )
}

/// Load and parse a devcontainer.json file
pub fn load(path: &Path) -> Result<DevcontainerConfig> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read {}", path.display()))?;

    // Remove JSON comments (// style) - devcontainer.json allows them
    let content = remove_json_comments(&content);

    let config: DevcontainerConfig = serde_json::from_str(&content)
        .with_context(|| format!("Failed to parse {}", path.display()))?;

    Ok(config)
}

/// Remove // and /* */ comments from JSON (devcontainer.json extension)
fn remove_json_comments(input: &str) -> String {
    let mut result = String::with_capacity(input.len());
    let mut in_string = false;
    let mut escape_next = false;
    let mut chars = input.chars().peekable();

    while let Some(c) = chars.next() {
        if escape_next {
            result.push(c);
            escape_next = false;
            continue;
        }

        if c == '\\' && in_string {
            result.push(c);
            escape_next = true;
            continue;
        }

        if c == '"' {
            in_string = !in_string;
            result.push(c);
            continue;
        }

        if !in_string && c == '/' {
            if chars.peek() == Some(&'/') {
                // Skip until end of line
                for c in chars.by_ref() {
                    if c == '\n' {
                        result.push('\n');
                        break;
                    }
                }
                continue;
            } else if chars.peek() == Some(&'*') {
                // Block comment - skip until */
                chars.next(); // consume the '*'
                while let Some(c) = chars.next() {
                    if c == '*' && chars.peek() == Some(&'/') {
                        chars.next(); // consume the '/'
                        break;
                    }
                    // Preserve newlines to maintain line numbers in error messages
                    if c == '\n' {
                        result.push('\n');
                    }
                }
                continue;
            }
        }

        result.push(c);
    }

    result
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
    fn test_remove_json_comments() {
        let input = r#"{
            // This is a comment
            "key": "value" // inline comment
        }"#;

        let result = remove_json_comments(input);
        assert!(!result.contains("// This is a comment"));
        assert!(!result.contains("// inline"));
        assert!(result.contains("\"key\": \"value\""));
    }

    #[test]
    fn test_remove_block_comments() {
        let input = r#"{
            /* This is a block comment */
            "key": "value", /* inline block */
            "other": /* mid-line */ "data"
        }"#;

        let result = remove_json_comments(input);
        assert!(!result.contains("block comment"));
        assert!(!result.contains("inline block"));
        assert!(!result.contains("mid-line"));
        assert!(result.contains("\"key\": \"value\""));
        assert!(result.contains("\"other\":"));
        assert!(result.contains("\"data\""));
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
                    "envAllowlist": ["MY_API_KEY", "CUSTOM_TOKEN"],
                    "allowedDomains": ["api.example.com"]
                }
            }
        }"#;
        let config: DevcontainerConfig = serde_json::from_str(json).unwrap();

        let customizations = config.customizations.expect("customizations should exist");
        let devaipod = customizations.devaipod.expect("devaipod should exist");

        assert_eq!(devaipod.env_allowlist, vec!["MY_API_KEY", "CUSTOM_TOKEN"]);
        assert_eq!(devaipod.allowed_domains, vec!["api.example.com"]);
    }

    #[test]
    fn test_allowed_domains_helper() {
        let json = r#"{
            "image": "foo",
            "customizations": {
                "devaipod": {
                    "allowedDomains": ["api.custom.com", "other.example.org"]
                }
            }
        }"#;
        let config: DevcontainerConfig = serde_json::from_str(json).unwrap();

        let domains = config.allowed_domains();
        assert_eq!(domains, vec!["api.custom.com", "other.example.org"]);
    }

    #[test]
    fn test_allowed_domains_empty_when_no_customizations() {
        let config = DevcontainerConfig::default();
        assert!(config.allowed_domains().is_empty());
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
    fn test_run_args_with_devices() {
        let json = r#"{
            "image": "foo",
            "runArgs": ["--privileged", "--device=/dev/kvm", "--device=/dev/fuse:rwm"]
        }"#;
        let config: DevcontainerConfig = serde_json::from_str(json).unwrap();
        assert!(config.has_privileged_run_arg());

        let device_args = config.device_args();
        assert_eq!(device_args.len(), 2);
        assert!(device_args.contains(&"--device=/dev/kvm".to_string()));
        assert!(device_args.contains(&"--device=/dev/fuse:rwm".to_string()));
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
        assert_eq!(config.device_args(), vec!["--device=/dev/kvm"]);
    }
}
