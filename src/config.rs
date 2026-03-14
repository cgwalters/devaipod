//! Global configuration management for devaipod
//!
//! Handles loading and parsing of the configuration file. Looks for config in this order:
//! 1. `~/.config/devaipod.toml` (preferred)
//! 2. `~/.config/devc.toml` (legacy, for backward compatibility)
//!
//! Also provides backward compatibility with the legacy `~/.config/devc/secrets.toml`.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use color_eyre::eyre::{Context, Result};
use serde::{Deserialize, Serialize};

/// Target container(s) for a secret or configuration
#[derive(Debug, Deserialize, Clone, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum ContainerTarget {
    /// Main development container (default)
    #[default]
    Main,
    /// Sidecar container
    Sidecar,
    /// All containers
    All,
    /// Named container
    #[serde(untagged)]
    Named(String),
}

/// Top-level configuration
#[derive(Debug, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Environment variable configuration for containers
    #[serde(default)]
    pub env: EnvConfig,
    /// Trusted environment variable configuration (workspace + gator only, NOT agent)
    /// Use this for credentials like GH_TOKEN that should be available to
    /// trusted containers but not the AI agent container.
    #[serde(default, rename = "trusted")]
    pub trusted_env: TrustedEnvConfig,
    /// Dotfiles configuration
    #[serde(default)]
    pub dotfiles: Option<DotfilesConfig>,
    /// Default container image to use when no devcontainer.json is found.
    /// This allows working with repositories that don't have a devcontainer
    /// configuration without needing to specify --image on every command.
    #[serde(default, rename = "default-image")]
    pub default_image: Option<String>,
    /// Sidecar container configuration (planned feature, not yet implemented)
    #[serde(default)]
    #[allow(dead_code)]
    pub sidecar: SidecarConfig,
    /// Secret mappings
    #[serde(default)]
    pub secrets: HashMap<String, SecretMapping>,
    /// Service-gator MCP server configuration
    #[serde(default, rename = "service-gator")]
    pub service_gator: ServiceGatorConfig,

    /// GPU passthrough configuration (planned feature, not yet integrated)
    #[serde(default)]
    #[allow(dead_code)]
    pub gpu: GpuPassthroughConfig,
    /// Bind paths from host $HOME to container $HOME (applies to all containers)
    /// Paths are relative to $HOME on both sides.
    /// For the workspace container, these are read-write.
    /// For the agent container, these are always read-only for security.
    #[serde(default, rename = "bind_home")]
    pub bind_home: BindHomeConfig,
    /// Bind paths specifically for the workspace container (in addition to bind_home)
    #[serde(default)]
    pub bind_home_workspace: Option<BindHomeConfig>,

    /// Multi-agent orchestration configuration
    #[serde(default)]
    pub orchestration: OrchestrationConfig,

    /// Kubernetes backend configuration
    #[serde(default)]
    #[allow(dead_code)]
    pub kubernetes: KubernetesConfig,

    /// SSH configuration for editor integration
    #[serde(default)]
    pub ssh: SshConfig,

    /// Additional MCP servers to attach to agent pods
    #[serde(default)]
    pub mcp: McpServersConfig,

    /// Enable nested container support even without a devcontainer.json.
    /// When true, containers get the minimal privileges needed for
    /// nested podman (SYS_ADMIN, NET_ADMIN, unmask=/proc/*, etc.)
    /// without full --privileged.
    ///
    /// This is useful with `default-image` for repos that don't have
    /// a devcontainer.json but still need nested container support.
    #[serde(default, rename = "container-nesting")]
    pub container_nesting: bool,
}

/// Configuration for binding paths from host home to container home
#[derive(Debug, Deserialize, Default, Clone)]
#[serde(deny_unknown_fields)]
pub struct BindHomeConfig {
    /// Paths relative to $HOME to bind mount
    #[serde(default)]
    pub paths: Vec<String>,
}

/// Environment variable configuration for containers
///
/// Configures environment variables to inject into both workspace and agent containers.
/// This provides a central place to configure env vars needed for LLM providers,
/// cloud credentials, editor preferences, etc.
///
/// Example configuration:
/// ```toml
/// [env]
/// # Forward these env vars from host (if they exist)
/// allowlist = ["GOOGLE_CLOUD_PROJECT", "SSH_AUTH_SOCK"]
///
/// # Set these explicitly
/// [env.vars]
/// VERTEX_LOCATION = "global"
/// EDITOR = "vim"
/// ```
#[derive(Debug, Deserialize, Default, Clone)]
#[serde(deny_unknown_fields)]
pub struct EnvConfig {
    /// Environment variable names to forward from host to containers.
    /// These are looked up in the current environment when the pod is created.
    /// If the variable doesn't exist on the host, it's silently skipped.
    #[serde(default)]
    pub allowlist: Vec<String>,
    /// Environment variables to set explicitly in containers.
    /// These take precedence over allowlist if both specify the same key.
    #[serde(default)]
    pub vars: HashMap<String, String>,
}

impl EnvConfig {
    /// Collect environment variables to inject into containers.
    ///
    /// Returns a HashMap combining:
    /// 1. Variables from allowlist (looked up in current environment)
    /// 2. Variables from vars (explicit values, take precedence over allowlist)
    pub fn collect(&self) -> HashMap<String, String> {
        let mut result = HashMap::new();

        // First, add env vars from allowlist (looked up from current environment)
        for key in &self.allowlist {
            if let Ok(value) = std::env::var(key) {
                result.insert(key.clone(), value);
            }
        }

        // Then, add/override with explicit env vars
        for (key, value) in &self.vars {
            result.insert(key.clone(), value.clone());
        }

        result
    }
}

/// Trusted environment variable configuration
///
/// These environment variables are forwarded to trusted containers only
/// (workspace and gator), NOT to the AI agent container. This is where
/// you configure credentials like GH_TOKEN that service-gator needs
/// but that should not be exposed directly to the AI agent.
///
/// Example configuration:
/// ```toml
/// [trusted.env]
/// allowlist = ["GH_TOKEN", "GITLAB_TOKEN", "JIRA_API_TOKEN"]
///
/// [trusted.env.vars]
/// SOME_SECRET = "explicit_value"
///
/// [trusted]
/// # Use podman secrets with type=env (secrets become env vars directly)
/// # Format: "ENV_VAR_NAME=secret_name"
/// secrets = ["GH_TOKEN=gh_token", "GITLAB_TOKEN=gitlab_token"]
/// ```
#[derive(Debug, Deserialize, Default, Clone)]
#[serde(deny_unknown_fields)]
pub struct TrustedEnvConfig {
    /// Environment settings for trusted containers
    #[serde(default)]
    pub env: EnvConfig,
    /// Podman secrets to mount with type=env.
    /// Each entry is "ENV_VAR_NAME=secret_name".
    /// Example: "GH_TOKEN=gh_token" sets the GH_TOKEN environment variable
    /// directly from the secret value using podman's --secret type=env feature.
    #[serde(default)]
    pub secrets: Vec<String>,
    /// Podman secrets to mount as files.
    /// Each entry is "ENV_VAR_NAME=secret_name".
    /// The secret is mounted at /run/secrets/{secret_name} and
    /// ENV_VAR_NAME is set to that path.
    /// Example: "GOOGLE_APPLICATION_CREDENTIALS=gcloud_adc" mounts the secret
    /// as a file and sets GOOGLE_APPLICATION_CREDENTIALS=/run/secrets/gcloud_adc.
    #[serde(default)]
    pub file_secrets: Vec<String>,
}

impl TrustedEnvConfig {
    /// Collect environment variables for trusted containers.
    pub fn collect(&self) -> HashMap<String, String> {
        self.env.collect()
    }

    /// Get (env_var_name, secret_name) pairs for podman secret mounting with type=env.
    ///
    /// Parses entries in the format "ENV_VAR_NAME=secret_name" and returns
    /// a vector of tuples where each tuple contains:
    /// - The environment variable name to set
    /// - The podman secret name containing the value
    ///
    /// For each secret, podman's `--secret secret_name,type=env,target=ENV_VAR_NAME`
    /// will set the environment variable directly from the secret value.
    ///
    /// Invalid entries (missing `=`) are logged and skipped.
    pub fn secret_mounts(&self) -> Vec<(String, String)> {
        self.secrets
            .iter()
            .filter_map(|entry| {
                if let Some((env_var, secret_name)) = entry.split_once('=') {
                    let env_var = env_var.trim();
                    let secret_name = secret_name.trim();
                    if !env_var.is_empty() && !secret_name.is_empty() {
                        Some((env_var.to_string(), secret_name.to_string()))
                    } else {
                        tracing::warn!(
                            "Invalid trusted.secrets entry (empty component): '{}'",
                            entry
                        );
                        None
                    }
                } else {
                    tracing::warn!(
                        "Invalid trusted.secrets entry (expected ENV_VAR=secret_name): '{}'",
                        entry
                    );
                    None
                }
            })
            .collect()
    }

    /// Get (env_var_name, secret_name) pairs for file-based secrets.
    ///
    /// Parses entries in the format "ENV_VAR_NAME=secret_name" and returns
    /// a vector of tuples where each tuple contains:
    /// - The environment variable name to set (will be set to the mounted file path)
    /// - The podman secret name containing the value
    ///
    /// For each secret, podman's `--secret secret_name` mounts the secret at
    /// `/run/secrets/{secret_name}`, and the environment variable is set to that path.
    ///
    /// This is useful for credentials like GOOGLE_APPLICATION_CREDENTIALS that
    /// expect a file path rather than the file contents.
    ///
    /// Invalid entries (missing `=`) are logged and skipped.
    pub fn file_secret_mounts(&self) -> Vec<(String, String)> {
        self.file_secrets
            .iter()
            .filter_map(|entry| {
                if let Some((env_var, secret_name)) = entry.split_once('=') {
                    let env_var = env_var.trim();
                    let secret_name = secret_name.trim();
                    if !env_var.is_empty() && !secret_name.is_empty() {
                        Some((env_var.to_string(), secret_name.to_string()))
                    } else {
                        tracing::warn!(
                            "Invalid trusted.file_secrets entry (empty component): '{}'",
                            entry
                        );
                        None
                    }
                } else {
                    tracing::warn!(
                        "Invalid trusted.file_secrets entry (expected ENV_VAR=secret_name): '{}'",
                        entry
                    );
                    None
                }
            })
            .collect()
    }
}

/// Dotfiles configuration for provisioning user dotfiles in workspaces
///
/// Similar to devpod's dotfiles feature, this clones a git repository
/// containing dotfiles and runs an install script.
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct DotfilesConfig {
    /// Git URL of the dotfiles repository (e.g., "https://github.com/user/dotfiles")
    pub url: String,
    /// Optional install script to run after cloning (e.g., "install.sh")
    /// If not specified, the default behavior is:
    /// 1. Run `install.sh` if it exists
    /// 2. Else run `install-dotfiles.sh` if it exists
    /// 3. Else rsync `dotfiles/` directory to home if it exists
    #[serde(default)]
    pub script: Option<String>,
}

/// Prefix for environment variables that should be forwarded to the agent container.
/// Variables like `DEVAIPOD_AGENT_FOO=bar` become `FOO=bar` inside the agent container.
pub const AGENT_ENV_PREFIX: &str = "DEVAIPOD_AGENT_";

// =============================================================================
// GPU passthrough configuration
// =============================================================================

/// GPU passthrough configuration for containers
///
/// When enabled, GPUs are passed through to the workspace container.
/// Supports NVIDIA (via CDI or direct device passthrough) and AMD GPUs.
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct GpuPassthroughConfig {
    /// Whether to enable GPU passthrough (default: false)
    /// Set to "auto" to auto-detect and enable if GPUs are available
    #[serde(default)]
    pub enabled: GpuEnabled,
    /// Which containers should get GPU access
    /// Options: "workspace" (default), "agent", "all"
    #[serde(default = "default_gpu_target")]
    pub target: String,
}

fn default_gpu_target() -> String {
    "workspace".to_string()
}

/// GPU enablement mode
#[derive(Debug, Deserialize, Clone, Default, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum GpuEnabled {
    /// Disabled (default)
    #[default]
    #[serde(alias = "false")]
    Disabled,
    /// Enabled
    #[serde(alias = "true")]
    Enabled,
    /// Auto-detect and enable if GPUs available
    Auto,
}

impl Default for GpuPassthroughConfig {
    fn default() -> Self {
        Self {
            enabled: GpuEnabled::default(),
            target: default_gpu_target(),
        }
    }
}

impl GpuPassthroughConfig {
    /// Check if GPU should be enabled for the workspace container
    #[allow(dead_code)] // Preparatory for GPU passthrough integration
    pub fn workspace_enabled(&self, has_gpus: bool) -> bool {
        match self.enabled {
            GpuEnabled::Disabled => false,
            GpuEnabled::Enabled => self.target == "workspace" || self.target == "all",
            GpuEnabled::Auto => has_gpus && (self.target == "workspace" || self.target == "all"),
        }
    }

    /// Check if GPU should be enabled for the agent container
    #[allow(dead_code)] // Preparatory for GPU passthrough integration
    pub fn agent_enabled(&self, has_gpus: bool) -> bool {
        match self.enabled {
            GpuEnabled::Disabled => false,
            GpuEnabled::Enabled => self.target == "agent" || self.target == "all",
            GpuEnabled::Auto => has_gpus && (self.target == "agent" || self.target == "all"),
        }
    }
}

/// Collect environment variables prefixed with DEVAIPOD_AGENT_ and return them
/// with the prefix stripped.
///
/// Example: `DEVAIPOD_AGENT_ANTHROPIC_API_KEY=xxx` → `("ANTHROPIC_API_KEY", "xxx")`
///
/// This makes it explicit which env vars the agent container can see.
/// No hardcoded allowlist - the caller controls what gets forwarded.
pub fn collect_agent_env_vars() -> Vec<(String, String)> {
    std::env::vars()
        .filter_map(|(key, value)| {
            key.strip_prefix(AGENT_ENV_PREFIX)
                .map(|stripped| (stripped.to_string(), value))
        })
        .collect()
}

/// Sidecar container configuration
///
/// By default, sidecar is always enabled using the main container's image.
/// The sidecar runs in an isolated network namespace (no network access)
/// and receives no secrets unless explicitly configured.
///
/// Note: Sidecar feature is planned but not yet implemented.
#[derive(Debug, Deserialize, Default)]
#[serde(deny_unknown_fields)]
#[allow(dead_code)]
pub struct SidecarConfig {
    /// Sidecar image override (default: uses main container's image)
    #[serde(default)]
    pub image: Option<String>,
    /// Command to run in sidecar (e.g., ["goose"])
    #[serde(default)]
    pub command: Option<Vec<String>>,
    /// Whether to enable network access for sidecar (default: false for security)
    #[serde(default)]
    pub network: bool,
    /// Whether to mount sources as read-only (default: false - sidecar can edit files)
    #[serde(default)]
    pub mount_sources_readonly: bool,
    /// Host paths to bind mount into the sidecar (e.g., config directories)
    #[serde(default)]
    pub mounts: Vec<MountSpec>,
    /// Host paths to mirror into sidecar at the same location (read-only)
    /// Example: ["~/.bashrc", "~/.config/goose"] mounts to same paths in container
    #[serde(default)]
    pub dotfiles: Vec<String>,
    /// Git repository URL containing dotfiles to clone and install
    #[serde(default)]
    pub dotfiles_repo: Option<String>,
    /// Command to run after cloning dotfiles repo (default: "install.sh" if exists)
    #[serde(default)]
    pub dotfiles_install: Option<String>,
    /// Named sidecar profiles for quick switching
    #[serde(default)]
    pub profiles: HashMap<String, SidecarProfile>,
}

/// A bind mount specification for sidecar containers
/// Part of planned sidecar feature.
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
#[allow(dead_code)]
pub struct MountSpec {
    /// Host path to mount (supports ~ expansion)
    pub src: String,
    /// Container path to mount at
    pub dst: String,
    /// Mount as read-only (default: true for safety)
    #[serde(default = "default_true")]
    pub readonly: bool,
}

fn default_true() -> bool {
    true
}

/// A named sidecar profile for quick switching between different AI agents
/// Part of planned sidecar feature.
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
#[allow(dead_code)]
pub struct SidecarProfile {
    /// Sidecar image for this profile (if None, uses main container's image)
    #[serde(default)]
    pub image: Option<String>,
    /// Command to run in sidecar
    #[serde(default)]
    pub command: Option<Vec<String>>,
    /// Whether to enable network access (default: false)
    #[serde(default)]
    pub network: bool,
    /// Whether to mount sources as read-only (default: false)
    #[serde(default)]
    pub mount_sources_readonly: bool,
    /// Host paths to bind mount into the sidecar
    #[serde(default)]
    pub mounts: Vec<MountSpec>,
    /// Host paths to mirror into sidecar at the same location (read-only)
    #[serde(default)]
    pub dotfiles: Vec<String>,
    /// Git repository URL containing dotfiles to clone and install
    #[serde(default)]
    pub dotfiles_repo: Option<String>,
    /// Command to run after cloning dotfiles repo
    #[serde(default)]
    pub dotfiles_install: Option<String>,
}

/// Mapping of a podman secret to an environment variable
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct SecretMapping {
    /// The podman secret name
    pub secret: String,
    /// The environment variable name to expose it as
    pub env: String,
    /// Target container(s) for this secret
    #[serde(default)]
    pub container: ContainerTarget,
}

// =============================================================================
// Service-gator configuration
// =============================================================================

/// Default port for the service-gator MCP server
pub const SERVICE_GATOR_DEFAULT_PORT: u16 = 8765;

/// Service-gator MCP server configuration
///
/// Service-gator provides scope-restricted access to external services
/// (GitHub, JIRA, GitLab) for AI agents. It runs in a separate container
/// and enforces fine-grained permissions on API operations.
#[derive(Debug, Deserialize, Default, Clone)]
#[serde(deny_unknown_fields)]
pub struct ServiceGatorConfig {
    /// Whether to enable service-gator (default: false, auto-enabled if scopes configured)
    #[serde(default)]
    pub enabled: Option<bool>,
    /// Port to listen on (default: 8765)
    #[serde(default)]
    pub port: Option<u16>,
    /// GitHub scope configuration
    #[serde(default)]
    pub gh: GithubScope,
    /// JIRA scope configuration
    #[serde(default)]
    pub jira: JiraScope,
}

impl ServiceGatorConfig {
    /// Check if service-gator should be enabled.
    /// Returns true if explicitly enabled OR if any scopes are configured.
    pub fn is_enabled(&self) -> bool {
        if let Some(enabled) = self.enabled {
            return enabled;
        }
        // Auto-enable if any scopes are configured
        self.gh.read
            || !self.gh.repos.is_empty()
            || !self.gh.prs.is_empty()
            || !self.jira.projects.is_empty()
            || !self.jira.issues.is_empty()
    }

    /// Get the port to use
    #[allow(dead_code)]
    pub fn port(&self) -> u16 {
        self.port.unwrap_or(SERVICE_GATOR_DEFAULT_PORT)
    }
}

/// GitHub scope configuration for service-gator
#[derive(Debug, Deserialize, Serialize, Default, Clone)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct GithubScope {
    /// Global read-only access to all GitHub repos and endpoints
    ///
    /// When set to true, enables read access to:
    /// - All `/repos/OWNER/REPO/...` endpoints (any owner/repo)
    /// - Non-repo endpoints: `/search/...`, `/gists/...`, `/user/...`, `/orgs/...`
    /// - GraphQL queries
    ///
    /// This is the recommended default for productive AI-assisted development.
    /// Set `[service-gator.gh] read = true` in your config.
    #[serde(default)]
    pub read: bool,
    /// Repository permissions: "owner/repo" or "owner/*" → permission
    #[serde(default)]
    pub repos: HashMap<String, GhRepoPermission>,
    /// PR-specific permissions: "owner/repo#123" → permission
    #[serde(default)]
    pub prs: HashMap<String, GhResourcePermission>,
    /// Issue-specific permissions: "owner/repo#123" → permission
    #[serde(default)]
    pub issues: HashMap<String, GhResourcePermission>,
    /// GraphQL API permission level
    #[serde(default)]
    pub graphql: GraphQlPermission,
}

/// Fine-grained permissions for a GitHub repository
#[derive(Debug, Deserialize, Serialize, Default, Clone)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct GhRepoPermission {
    /// Can read the repository (view PRs, issues, code, etc.)
    #[serde(default)]
    pub read: bool,
    /// Can create draft PRs in this repo
    #[serde(default)]
    pub create_draft: bool,
    /// Can create/update/delete pending PR reviews
    #[serde(default)]
    pub pending_review: bool,
    /// Can create and push to new branches (agent-* or PR head branches).
    /// More permissive than create_draft - allows updating existing work.
    #[serde(default)]
    pub push_new_branch: bool,
    /// Full write access (merge, close, create non-draft, etc.)
    #[serde(default)]
    pub write: bool,
}

/// Permissions for a specific PR or issue
#[derive(Debug, Deserialize, Serialize, Default, Clone)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct GhResourcePermission {
    /// Can read this resource
    #[serde(default)]
    pub read: bool,
    /// Can write to this resource (comment, edit, etc.)
    #[serde(default)]
    pub write: bool,
}

/// GraphQL permission level
#[derive(Debug, Deserialize, Serialize, Default, Clone, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum GraphQlPermission {
    /// No GraphQL access (default)
    #[default]
    None,
    /// Read-only GraphQL access
    Read,
    /// Full GraphQL access
    Write,
}

/// JIRA scope configuration for service-gator
#[derive(Debug, Deserialize, Serialize, Default, Clone)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct JiraScope {
    /// Project permissions: "PROJ" → permission
    #[serde(default)]
    pub projects: HashMap<String, JiraProjectPermission>,
    /// Issue-specific permissions: "PROJ-123" → permission
    #[serde(default)]
    pub issues: HashMap<String, JiraIssuePermission>,
}

/// JIRA project permissions
#[derive(Debug, Deserialize, Serialize, Default, Clone)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct JiraProjectPermission {
    /// Can read the project (list issues, view, etc.)
    #[serde(default)]
    pub read: bool,
    /// Can create issues in this project
    #[serde(default)]
    pub create: bool,
    /// Full write access
    #[serde(default)]
    pub write: bool,
}

/// JIRA issue permissions
#[derive(Debug, Deserialize, Serialize, Default, Clone)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct JiraIssuePermission {
    /// Can read this issue
    #[serde(default)]
    pub read: bool,
    /// Can write to this issue
    #[serde(default)]
    pub write: bool,
}

// =============================================================================
// Orchestration configuration
// =============================================================================

/// Default worker timeout (used when worker timeout enforcement is implemented)
#[allow(dead_code)]
const DEFAULT_WORKER_TIMEOUT: &str = "30m";

/// Multi-agent orchestration configuration
///
/// Configures hierarchical multi-agent workflows where a "task owner" agent
/// orchestrates a "worker" agent running in an isolated container.
///
/// Orchestration is opt-in: set `enabled = true` to spawn a worker container
/// alongside the agent. When disabled (the default), only a single agent
/// container is created.
///
/// Example configuration:
/// ```toml
/// [orchestration]
/// enabled = true
/// worker_timeout = "30m"
///
/// [orchestration.worker]
/// gator = "readonly"
/// ```
#[derive(Debug, Deserialize, Default, Clone)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
#[allow(dead_code)] // Fields parsed from config but not all used yet
pub struct OrchestrationConfig {
    /// Whether to enable multi-agent orchestration (default: false).
    /// When true, a worker container is created alongside the agent.
    #[serde(default)]
    pub enabled: Option<bool>,
    /// Timeout for worker subtasks (default: "30m")
    /// Format: duration string like "30m", "1h", "90s"
    /// Note: Not yet enforced, will be used when timeout handling is implemented.
    #[serde(default)]
    pub worker_timeout: Option<String>,
    /// Worker-specific configuration
    #[serde(default)]
    pub worker: WorkerConfig,
}

impl OrchestrationConfig {
    /// Check if orchestration is enabled.
    ///
    /// Defaults to false when not explicitly configured. Set `enabled = true`
    /// in the `[orchestration]` config section to enable the worker container.
    pub fn is_enabled(&self) -> bool {
        self.enabled.unwrap_or(false)
    }

    /// Get the worker timeout string (defaults to "30m")
    ///
    /// Note: Not yet enforced, will be used when timeout handling is implemented.
    #[allow(dead_code)]
    pub fn worker_timeout(&self) -> &str {
        self.worker_timeout
            .as_deref()
            .unwrap_or(DEFAULT_WORKER_TIMEOUT)
    }
}

/// Worker container configuration
///
/// Controls how the worker agent operates within the orchestration.
#[derive(Debug, Deserialize, Default, Clone)]
#[serde(deny_unknown_fields)]
pub struct WorkerConfig {
    /// How the worker accesses service-gator (default: readonly)
    #[serde(default)]
    pub gator: WorkerGatorMode,
}

/// How the worker agent accesses service-gator
///
/// Workers are one step further from human review, so they have restricted
/// access by default. The task owner reviews worker commits before they
/// can affect external systems.
#[derive(Debug, Deserialize, Clone, Default, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum WorkerGatorMode {
    /// Worker can only read from forge (no PRs, no pushes) — default
    #[default]
    Readonly,
    /// Worker gets same gator scopes as task owner
    Inherit,
    /// Worker has no gator access; communicates only via git with task owner
    None,
}

// =============================================================================
// Kubernetes configuration
// =============================================================================

/// Default Kubernetes namespace for devaipod workspaces
const DEFAULT_KUBE_NAMESPACE: &str = "devaipod";

/// Kubernetes backend configuration
///
/// When configured, devaipod can spawn workspace pods in a Kubernetes cluster
/// instead of (or in addition to) local podman. The kubeconfig can be provided
/// as a podman secret, a file path, or auto-detected from the environment
/// (in-cluster ServiceAccount or ~/.kube/config).
///
/// Example configuration:
/// ```toml
/// [kubernetes]
/// enabled = true
/// namespace = "devaipod"
/// kubeconfig-secret = "kubeconfig"  # podman secret name containing kubeconfig YAML
/// ```
#[derive(Debug, Deserialize, Default, Clone)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
#[allow(dead_code)]
pub struct KubernetesConfig {
    /// Whether Kubernetes backend is enabled (default: false).
    /// When enabled, devaipod will attempt to connect to a Kubernetes cluster
    /// on startup using the configured kubeconfig source.
    #[serde(default)]
    pub enabled: Option<bool>,

    /// Kubernetes namespace for workspace pods (default: "devaipod").
    #[serde(default)]
    pub namespace: Option<String>,

    /// Name of a podman secret containing kubeconfig YAML.
    /// Read via `podman secret inspect --showsecret` at startup.
    /// Takes precedence over kubeconfig-path and environment detection.
    #[serde(default)]
    pub kubeconfig_secret: Option<String>,

    /// Path to a kubeconfig file. Falls back to ~/.kube/config or
    /// in-cluster ServiceAccount detection if not set.
    #[serde(default)]
    pub kubeconfig_path: Option<String>,
}

#[allow(dead_code)]
impl KubernetesConfig {
    /// Check if Kubernetes backend is enabled.
    pub fn is_enabled(&self) -> bool {
        self.enabled.unwrap_or(false)
    }

    /// Get the target namespace, defaulting to "devaipod".
    pub fn namespace(&self) -> &str {
        self.namespace.as_deref().unwrap_or(DEFAULT_KUBE_NAMESPACE)
    }
}

// =============================================================================
// SSH configuration
// =============================================================================

/// SSH configuration for editor integration
///
/// Controls automatic SSH config file generation for VSCode/Zed Remote SSH.
///
/// Example configuration:
/// ```toml
/// [ssh]
/// auto_config = true  # default: true
/// ```
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct SshConfig {
    /// Whether to automatically create SSH config entries in ~/.ssh/config.d/
    /// when workspaces are created. (default: true)
    ///
    /// Set to false to disable automatic SSH config generation.
    /// You can still manually run `devaipod ssh-config <workspace>`.
    #[serde(default = "default_true")]
    pub auto_config: bool,
}

impl Default for SshConfig {
    fn default() -> Self {
        Self { auto_config: true }
    }
}

// =============================================================================
// MCP server configuration
// =============================================================================

/// Configuration for additional MCP servers attached to agent pods
///
/// These are HTTP-based MCP servers that run as sidecar containers or
/// external services, connected to the agent via the opencode MCP config.
///
/// Example configuration:
/// ```toml
/// [mcp.advisor]
/// url = "http://localhost:8766/mcp"
/// enabled = true
///
/// [mcp.custom-tools]
/// url = "http://my-server:9000/mcp"
/// enabled = true
/// ```
#[derive(Debug, Deserialize, Default)]
pub struct McpServersConfig {
    /// Named MCP server configurations.
    /// The key is the server name used in the opencode config.
    #[serde(flatten)]
    pub servers: HashMap<String, McpServerEntry>,
}

/// A single MCP server entry
#[derive(Debug, Deserialize, Clone)]
pub struct McpServerEntry {
    /// URL of the MCP server endpoint
    pub url: String,
    /// Whether this server is enabled (default: true)
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// HTTP headers to send with requests (e.g. Authorization)
    #[serde(default)]
    pub headers: HashMap<String, String>,
}

impl McpServersConfig {
    /// Get all enabled MCP server entries
    pub fn enabled_servers(&self) -> impl Iterator<Item = (&str, &McpServerEntry)> {
        self.servers
            .iter()
            .filter(|(_, entry)| entry.enabled)
            .map(|(name, entry)| (name.as_str(), entry))
    }

    /// Merge CLI-provided MCP servers into this config
    ///
    /// Parses `name=url` strings and adds them as enabled entries.
    /// CLI entries override any existing config file entries with the same name.
    pub fn merge_cli_servers(&mut self, cli_servers: &[String]) -> color_eyre::Result<()> {
        for entry in cli_servers {
            if let Some((name, url)) = entry.split_once('=') {
                let name = name.trim();
                let url = url.trim();
                if name.is_empty() || url.is_empty() {
                    color_eyre::eyre::bail!(
                        "Invalid --mcp format: '{}'. Expected name=url (e.g., advisor=http://localhost:8766/mcp)",
                        entry
                    );
                }
                self.servers.insert(
                    name.to_string(),
                    McpServerEntry {
                        url: url.to_string(),
                        enabled: true,
                        headers: HashMap::new(),
                    },
                );
            } else {
                color_eyre::eyre::bail!(
                    "Invalid --mcp format: '{}'. Expected name=url (e.g., advisor=http://localhost:8766/mcp)",
                    entry
                );
            }
        }
        Ok(())
    }
}

/// Get the XDG config directory
fn get_config_dir() -> PathBuf {
    std::env::var("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
            PathBuf::from(home).join(".config")
        })
}

/// Get the main config file path.
///
/// Returns the first existing config file in order of preference:
/// 1. `~/.config/devaipod.toml` (preferred)
/// 2. `~/.config/devc.toml` (legacy)
///
/// If neither exists, returns the preferred path for creation.
pub fn config_path() -> PathBuf {
    let config_dir = get_config_dir();

    // Check for new name first
    let new_path = config_dir.join("devaipod.toml");
    if new_path.exists() {
        return new_path;
    }

    // Fall back to legacy name
    let legacy_path = config_dir.join("devc.toml");
    if legacy_path.exists() {
        tracing::debug!(
            "Using legacy config path {}. Consider renaming to devaipod.toml",
            legacy_path.display()
        );
        return legacy_path;
    }

    // Neither exists, return preferred path for creation
    new_path
}

/// Get the legacy secrets config path (~/.config/devc/secrets.toml)
fn legacy_secrets_path() -> PathBuf {
    get_config_dir().join("devc").join("secrets.toml")
}

/// Load configuration from the default path or a specific path
pub fn load_config(path: Option<&Path>) -> Result<Config> {
    load_config_from(path)
}

/// Load configuration from a specific path or the default
pub fn load_config_from(path: Option<&Path>) -> Result<Config> {
    let config_path = path.map(PathBuf::from).unwrap_or_else(config_path);

    let mut config = if config_path.exists() {
        let content = std::fs::read_to_string(&config_path)
            .with_context(|| format!("Failed to read config from {}", config_path.display()))?;

        toml::from_str(&content)
            .with_context(|| format!("Failed to parse config from {}", config_path.display()))?
    } else {
        tracing::debug!(
            "Config not found at {}, using defaults",
            config_path.display()
        );
        Config::default()
    };

    // Backward compatibility: merge legacy secrets if they exist
    let legacy_path = legacy_secrets_path();
    if legacy_path.exists() {
        tracing::debug!(
            "Found legacy secrets config at {}, merging with main config",
            legacy_path.display()
        );

        let content = std::fs::read_to_string(&legacy_path).with_context(|| {
            format!(
                "Failed to read legacy secrets config from {}",
                legacy_path.display()
            )
        })?;

        let legacy_config: crate::secrets::SecretsConfig =
            toml::from_str(&content).with_context(|| {
                format!(
                    "Failed to parse legacy secrets config from {}",
                    legacy_path.display()
                )
            })?;

        // Merge legacy secrets with container=Main
        let legacy_secrets_count = legacy_config.secrets.len();
        for (name, legacy_mapping) in legacy_config.secrets {
            // Only add if not already defined in the new config
            config.secrets.entry(name).or_insert_with(|| SecretMapping {
                secret: legacy_mapping.secret,
                env: legacy_mapping.env,
                container: ContainerTarget::Main,
            });
        }

        tracing::debug!("Merged {} secrets from legacy config", legacy_secrets_count);
    }

    tracing::debug!(
        "Loaded configuration with {} secret mappings",
        config.secrets.len()
    );

    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_minimal_config() {
        let toml = "";
        let config: Config = toml::from_str(toml).unwrap();
        assert!(config.sidecar.image.is_none());
        // Default is read-write so sidecar can edit files
        assert!(!config.sidecar.mount_sources_readonly);
        // Default is no network access for security
        assert!(!config.sidecar.network);
        assert_eq!(config.sidecar.profiles.len(), 0);
        assert_eq!(config.secrets.len(), 0);
        assert!(config.dotfiles.is_none());
        assert!(config.default_image.is_none());
        assert!(!config.container_nesting);
        assert!(!config.kubernetes.is_enabled());
    }

    #[test]
    fn test_parse_container_nesting() {
        let toml = r#"
container-nesting = true
"#;
        let config: Config = toml::from_str(toml).unwrap();
        assert!(config.container_nesting);
    }

    #[test]
    fn test_parse_default_image() {
        let toml = r#"
default-image = "ghcr.io/devcontainers/base:ubuntu"
"#;
        let config: Config = toml::from_str(toml).unwrap();
        assert_eq!(
            config.default_image,
            Some("ghcr.io/devcontainers/base:ubuntu".to_string())
        );
    }

    #[test]
    fn test_parse_dotfiles_config() {
        let toml = r#"
[dotfiles]
url = "https://github.com/user/dotfiles"
"#;
        let config: Config = toml::from_str(toml).unwrap();
        let dotfiles = config.dotfiles.expect("dotfiles should be present");
        assert_eq!(dotfiles.url, "https://github.com/user/dotfiles");
        assert!(dotfiles.script.is_none());
    }

    #[test]
    fn test_parse_dotfiles_config_with_script() {
        let toml = r#"
[dotfiles]
url = "https://github.com/cgwalters/homegit"
script = "install-dotfiles.sh"
"#;
        let config: Config = toml::from_str(toml).unwrap();
        let dotfiles = config.dotfiles.expect("dotfiles should be present");
        assert_eq!(dotfiles.url, "https://github.com/cgwalters/homegit");
        assert_eq!(dotfiles.script, Some("install-dotfiles.sh".to_string()));
    }

    #[test]
    fn test_parse_sidecar_config() {
        let toml = r#"
[sidecar]
image = "ghcr.io/block/goose:latest"
command = ["goose"]
network = true
mount_sources_readonly = false
"#;
        let config: Config = toml::from_str(toml).unwrap();
        assert_eq!(
            config.sidecar.image,
            Some("ghcr.io/block/goose:latest".to_string())
        );
        assert_eq!(config.sidecar.command, Some(vec!["goose".to_string()]));
        assert!(config.sidecar.network);
        assert!(!config.sidecar.mount_sources_readonly);
    }

    #[test]
    fn test_parse_sidecar_profiles() {
        let toml = r#"
[sidecar.profiles.goose]
image = "ghcr.io/block/goose:latest"
command = ["goose"]

[sidecar.profiles.claude]
image = "ghcr.io/anthropics/claude-code:latest"
command = ["claude"]
network = true
"#;
        let config: Config = toml::from_str(toml).unwrap();
        assert_eq!(config.sidecar.profiles.len(), 2);

        let goose = &config.sidecar.profiles["goose"];
        assert_eq!(goose.image, Some("ghcr.io/block/goose:latest".to_string()));
        assert_eq!(goose.command, Some(vec!["goose".to_string()]));
        // Default: no network, read-write access
        assert!(!goose.network);
        assert!(!goose.mount_sources_readonly);

        let claude = &config.sidecar.profiles["claude"];
        assert_eq!(
            claude.image,
            Some("ghcr.io/anthropics/claude-code:latest".to_string())
        );
        assert!(claude.network);
        assert!(!claude.mount_sources_readonly);
    }

    #[test]
    fn test_parse_secrets() {
        let toml = r#"
[secrets.anthropic]
secret = "anthropic-key"
env = "ANTHROPIC_API_KEY"
container = "sidecar"

[secrets.github]
secret = "github-token"
env = "GITHUB_TOKEN"
container = "all"

[secrets.openai]
secret = "openai-key"
env = "OPENAI_API_KEY"
"#;
        let config: Config = toml::from_str(toml).unwrap();
        assert_eq!(config.secrets.len(), 3);

        let anthropic = &config.secrets["anthropic"];
        assert_eq!(anthropic.secret, "anthropic-key");
        assert_eq!(anthropic.env, "ANTHROPIC_API_KEY");
        assert_eq!(anthropic.container, ContainerTarget::Sidecar);

        let github = &config.secrets["github"];
        assert_eq!(github.secret, "github-token");
        assert_eq!(github.env, "GITHUB_TOKEN");
        assert_eq!(github.container, ContainerTarget::All);

        // Default should be Main
        let openai = &config.secrets["openai"];
        assert_eq!(openai.secret, "openai-key");
        assert_eq!(openai.env, "OPENAI_API_KEY");
        assert_eq!(openai.container, ContainerTarget::Main);
    }

    #[test]
    fn test_parse_full_config() {
        let toml = r#"
[sidecar]
image = "ghcr.io/block/goose:latest"
command = ["goose"]

[sidecar.profiles.goose]
image = "ghcr.io/block/goose:latest"
command = ["goose"]

[secrets.anthropic]
secret = "anthropic-key"
env = "ANTHROPIC_API_KEY"
container = "sidecar"

[secrets.github]
secret = "github-token"
env = "GITHUB_TOKEN"
container = "all"
"#;
        let config: Config = toml::from_str(toml).unwrap();

        // Sidecar config - defaults: no network, read-write sources
        assert_eq!(
            config.sidecar.image,
            Some("ghcr.io/block/goose:latest".to_string())
        );
        assert_eq!(config.sidecar.command, Some(vec!["goose".to_string()]));
        assert!(!config.sidecar.network);
        assert!(!config.sidecar.mount_sources_readonly);
        assert_eq!(config.sidecar.profiles.len(), 1);

        // Secrets
        assert_eq!(config.secrets.len(), 2);
        assert!(config.secrets.contains_key("anthropic"));
        assert!(config.secrets.contains_key("github"));
    }

    #[test]
    fn test_container_target_default() {
        let target = ContainerTarget::default();
        assert_eq!(target, ContainerTarget::Main);
    }

    #[test]
    fn test_container_target_deserialization() {
        let toml = r#"
[secrets.test1]
secret = "test"
env = "TEST"
container = "main"

[secrets.test2]
secret = "test"
env = "TEST"
container = "sidecar"

[secrets.test3]
secret = "test"
env = "TEST"
container = "all"
"#;
        let config: Config = toml::from_str(toml).unwrap();
        assert_eq!(config.secrets["test1"].container, ContainerTarget::Main);
        assert_eq!(config.secrets["test2"].container, ContainerTarget::Sidecar);
        assert_eq!(config.secrets["test3"].container, ContainerTarget::All);
    }

    #[test]
    fn test_parse_service_gator_config() {
        let toml = r#"
[service-gator]
enabled = true
port = 9000

[service-gator.gh.repos]
"cgwalters/*" = { read = true }
"cgwalters/bootc" = { read = true, create-draft = true }

[service-gator.gh.prs]
"cgwalters/bootc#123" = { read = true, write = true }

[service-gator.jira.projects]
"BOOTC" = { read = true, create = true }
"#;
        let config: Config = toml::from_str(toml).unwrap();
        assert!(config.service_gator.enabled.unwrap());
        assert_eq!(config.service_gator.port(), 9000);
        assert_eq!(config.service_gator.gh.repos.len(), 2);
        assert!(config.service_gator.gh.repos["cgwalters/*"].read);
        assert!(!config.service_gator.gh.repos["cgwalters/*"].create_draft);
        assert!(config.service_gator.gh.repos["cgwalters/bootc"].create_draft);
        assert!(config.service_gator.gh.prs["cgwalters/bootc#123"].write);
        assert!(config.service_gator.jira.projects["BOOTC"].create);
    }

    #[test]
    fn test_service_gator_auto_enable() {
        // Empty config - not enabled
        let config = ServiceGatorConfig::default();
        assert!(!config.is_enabled());

        // Explicit enable
        let mut config = ServiceGatorConfig::default();
        config.enabled = Some(true);
        assert!(config.is_enabled());

        // Auto-enable when repos configured
        let mut config = ServiceGatorConfig::default();
        config
            .gh
            .repos
            .insert("owner/repo".to_string(), GhRepoPermission::default());
        assert!(config.is_enabled());

        // Auto-enable when gh.read = true
        let mut config = ServiceGatorConfig::default();
        config.gh.read = true;
        assert!(config.is_enabled());
    }

    #[test]
    fn test_parse_service_gator_gh_read() {
        // Test that [service-gator.gh] read = true is parsed correctly
        let toml = r#"
[service-gator.gh]
read = true
"#;
        let config: Config = toml::from_str(toml).unwrap();
        assert!(config.service_gator.gh.read);
        assert!(config.service_gator.is_enabled());
    }

    #[test]
    fn test_parse_service_gator_gh_read_with_repos() {
        // Test that gh.read = true works alongside specific repo overrides
        let toml = r#"
[service-gator.gh]
read = true

[service-gator.gh.repos]
"myorg/myrepo" = { create-draft = true }
"#;
        let config: Config = toml::from_str(toml).unwrap();
        assert!(config.service_gator.gh.read);
        assert!(config.service_gator.is_enabled());
        assert_eq!(config.service_gator.gh.repos.len(), 1);
        assert!(config.service_gator.gh.repos["myorg/myrepo"].create_draft);
    }

    #[test]
    fn test_config_path() {
        // Verify it returns a path ending with devaipod.toml (preferred) or devc.toml (legacy)
        let path = config_path();
        let path_str = path.to_string_lossy();
        assert!(
            path_str.ends_with("devaipod.toml") || path_str.ends_with("devc.toml"),
            "Expected path to end with devaipod.toml or devc.toml, got: {}",
            path_str
        );
    }

    #[test]
    fn test_parse_bind_home() {
        let toml = r#"
[bind_home]
paths = [
    ".config/gcloud/application_default_credentials.json",
    ".gitconfig",
]
"#;
        let config: Config = toml::from_str(toml).unwrap();
        assert_eq!(config.bind_home.paths.len(), 2);
        assert_eq!(
            config.bind_home.paths[0],
            ".config/gcloud/application_default_credentials.json"
        );
        assert_eq!(config.bind_home.paths[1], ".gitconfig");
    }

    #[test]
    fn test_parse_bind_home_workspace() {
        let toml = r#"
[bind_home_workspace]
paths = [".config/gcloud", ".ssh"]
"#;
        let config: Config = toml::from_str(toml).unwrap();
        let ws = config
            .bind_home_workspace
            .expect("bind_home_workspace should be present");
        assert_eq!(ws.paths.len(), 2);
        assert_eq!(ws.paths[0], ".config/gcloud");
        assert_eq!(ws.paths[1], ".ssh");
    }

    #[test]
    fn test_parse_bind_home_combined() {
        let toml = r#"
# Global bind_home applies to all containers
[bind_home]
paths = [".gitconfig", ".config/gcloud/application_default_credentials.json"]

# Workspace-specific
[bind_home_workspace]
paths = [".config/gcloud", ".ssh"]
"#;
        let config: Config = toml::from_str(toml).unwrap();

        // Global (applies to both workspace and agent)
        assert_eq!(config.bind_home.paths.len(), 2);
        assert_eq!(config.bind_home.paths[0], ".gitconfig");
        assert_eq!(
            config.bind_home.paths[1],
            ".config/gcloud/application_default_credentials.json"
        );

        // Workspace-specific additions
        let ws = config
            .bind_home_workspace
            .expect("bind_home_workspace should be present");
        assert_eq!(ws.paths.len(), 2);
    }

    #[test]
    fn test_bind_home_default_empty() {
        let toml = "";
        let config: Config = toml::from_str(toml).unwrap();
        assert!(config.bind_home.paths.is_empty());
        assert!(config.bind_home_workspace.is_none());
    }

    // =========================================================================
    // GPU configuration tests
    // =========================================================================

    #[test]
    fn test_gpu_config_default() {
        let config = GpuPassthroughConfig::default();
        assert_eq!(config.enabled, GpuEnabled::Disabled);
        assert_eq!(config.target, "workspace");
    }

    #[test]
    fn test_gpu_enabled_default() {
        assert_eq!(GpuEnabled::default(), GpuEnabled::Disabled);
    }

    #[test]
    fn test_parse_gpu_enabled_true() {
        let toml = r#"
[gpu]
enabled = "enabled"
"#;
        let config: Config = toml::from_str(toml).unwrap();
        assert_eq!(config.gpu.enabled, GpuEnabled::Enabled);
    }

    #[test]
    fn test_parse_gpu_enabled_false() {
        let toml = r#"
[gpu]
enabled = "disabled"
"#;
        let config: Config = toml::from_str(toml).unwrap();
        assert_eq!(config.gpu.enabled, GpuEnabled::Disabled);
    }

    #[test]
    fn test_parse_gpu_enabled_auto() {
        let toml = r#"
[gpu]
enabled = "auto"
"#;
        let config: Config = toml::from_str(toml).unwrap();
        assert_eq!(config.gpu.enabled, GpuEnabled::Auto);
    }

    #[test]
    fn test_parse_gpu_target_workspace() {
        let toml = r#"
[gpu]
enabled = "enabled"
target = "workspace"
"#;
        let config: Config = toml::from_str(toml).unwrap();
        assert_eq!(config.gpu.target, "workspace");
    }

    #[test]
    fn test_parse_gpu_target_agent() {
        let toml = r#"
[gpu]
enabled = "enabled"
target = "agent"
"#;
        let config: Config = toml::from_str(toml).unwrap();
        assert_eq!(config.gpu.target, "agent");
    }

    #[test]
    fn test_parse_gpu_target_all() {
        let toml = r#"
[gpu]
enabled = "enabled"
target = "all"
"#;
        let config: Config = toml::from_str(toml).unwrap();
        assert_eq!(config.gpu.target, "all");
    }

    #[test]
    fn test_gpu_workspace_enabled_disabled_mode() {
        let config = GpuPassthroughConfig {
            enabled: GpuEnabled::Disabled,
            target: "workspace".to_string(),
        };
        // Disabled means no GPU regardless of has_gpus
        assert!(!config.workspace_enabled(true));
        assert!(!config.workspace_enabled(false));
    }

    #[test]
    fn test_gpu_workspace_enabled_enabled_mode() {
        // target = workspace
        let config = GpuPassthroughConfig {
            enabled: GpuEnabled::Enabled,
            target: "workspace".to_string(),
        };
        assert!(config.workspace_enabled(true));
        assert!(config.workspace_enabled(false)); // Enabled ignores has_gpus

        // target = agent
        let config = GpuPassthroughConfig {
            enabled: GpuEnabled::Enabled,
            target: "agent".to_string(),
        };
        assert!(!config.workspace_enabled(true));
        assert!(!config.workspace_enabled(false));

        // target = all
        let config = GpuPassthroughConfig {
            enabled: GpuEnabled::Enabled,
            target: "all".to_string(),
        };
        assert!(config.workspace_enabled(true));
        assert!(config.workspace_enabled(false));
    }

    #[test]
    fn test_gpu_workspace_enabled_auto_mode() {
        // target = workspace
        let config = GpuPassthroughConfig {
            enabled: GpuEnabled::Auto,
            target: "workspace".to_string(),
        };
        assert!(config.workspace_enabled(true)); // GPUs available
        assert!(!config.workspace_enabled(false)); // No GPUs

        // target = agent
        let config = GpuPassthroughConfig {
            enabled: GpuEnabled::Auto,
            target: "agent".to_string(),
        };
        assert!(!config.workspace_enabled(true));
        assert!(!config.workspace_enabled(false));

        // target = all
        let config = GpuPassthroughConfig {
            enabled: GpuEnabled::Auto,
            target: "all".to_string(),
        };
        assert!(config.workspace_enabled(true));
        assert!(!config.workspace_enabled(false));
    }

    #[test]
    fn test_gpu_agent_enabled_disabled_mode() {
        let config = GpuPassthroughConfig {
            enabled: GpuEnabled::Disabled,
            target: "agent".to_string(),
        };
        // Disabled means no GPU regardless of has_gpus
        assert!(!config.agent_enabled(true));
        assert!(!config.agent_enabled(false));
    }

    #[test]
    fn test_gpu_agent_enabled_enabled_mode() {
        // target = agent
        let config = GpuPassthroughConfig {
            enabled: GpuEnabled::Enabled,
            target: "agent".to_string(),
        };
        assert!(config.agent_enabled(true));
        assert!(config.agent_enabled(false)); // Enabled ignores has_gpus

        // target = workspace
        let config = GpuPassthroughConfig {
            enabled: GpuEnabled::Enabled,
            target: "workspace".to_string(),
        };
        assert!(!config.agent_enabled(true));
        assert!(!config.agent_enabled(false));

        // target = all
        let config = GpuPassthroughConfig {
            enabled: GpuEnabled::Enabled,
            target: "all".to_string(),
        };
        assert!(config.agent_enabled(true));
        assert!(config.agent_enabled(false));
    }

    #[test]
    fn test_gpu_agent_enabled_auto_mode() {
        // target = agent
        let config = GpuPassthroughConfig {
            enabled: GpuEnabled::Auto,
            target: "agent".to_string(),
        };
        assert!(config.agent_enabled(true)); // GPUs available
        assert!(!config.agent_enabled(false)); // No GPUs

        // target = workspace
        let config = GpuPassthroughConfig {
            enabled: GpuEnabled::Auto,
            target: "workspace".to_string(),
        };
        assert!(!config.agent_enabled(true));
        assert!(!config.agent_enabled(false));

        // target = all
        let config = GpuPassthroughConfig {
            enabled: GpuEnabled::Auto,
            target: "all".to_string(),
        };
        assert!(config.agent_enabled(true));
        assert!(!config.agent_enabled(false));
    }

    #[test]
    fn test_parse_gpu_config_full() {
        let toml = r#"
[gpu]
enabled = "auto"
target = "all"
"#;
        let config: Config = toml::from_str(toml).unwrap();
        assert_eq!(config.gpu.enabled, GpuEnabled::Auto);
        assert_eq!(config.gpu.target, "all");
    }

    #[test]
    fn test_gpu_config_in_minimal_config() {
        let toml = "";
        let config: Config = toml::from_str(toml).unwrap();
        // Default GPU config should be disabled
        assert_eq!(config.gpu.enabled, GpuEnabled::Disabled);
        assert_eq!(config.gpu.target, "workspace");
        assert!(!config.gpu.workspace_enabled(true));
        assert!(!config.gpu.agent_enabled(true));
    }

    // =========================================================================
    // Orchestration configuration tests
    // =========================================================================

    #[test]
    fn test_orchestration_config_default() {
        let config = OrchestrationConfig::default();
        // Orchestration is disabled by default
        assert!(!config.is_enabled());
        assert_eq!(config.worker_timeout(), "30m");
        assert_eq!(config.worker.gator, WorkerGatorMode::Readonly);
    }

    #[test]
    fn test_parse_orchestration_minimal() {
        // Orchestration is disabled by default when not configured
        let toml = "";
        let config: Config = toml::from_str(toml).unwrap();
        assert!(!config.orchestration.is_enabled());
        assert_eq!(config.orchestration.worker_timeout(), "30m");
        assert_eq!(config.orchestration.worker.gator, WorkerGatorMode::Readonly);
    }

    #[test]
    fn test_parse_orchestration_explicitly_enabled() {
        let toml = r#"
[orchestration]
enabled = true
"#;
        let config: Config = toml::from_str(toml).unwrap();
        assert!(config.orchestration.is_enabled());
    }

    #[test]
    fn test_parse_orchestration_explicitly_disabled() {
        let toml = r#"
[orchestration]
enabled = false
"#;
        let config: Config = toml::from_str(toml).unwrap();
        assert!(!config.orchestration.is_enabled());
    }

    #[test]
    fn test_parse_orchestration_worker_timeout() {
        let toml = r#"
[orchestration]
enabled = true
worker-timeout = "1h"
"#;
        let config: Config = toml::from_str(toml).unwrap();
        assert!(config.orchestration.is_enabled());
        assert_eq!(config.orchestration.worker_timeout(), "1h");
    }

    #[test]
    fn test_parse_orchestration_full() {
        let toml = r#"
[orchestration]
enabled = true
worker-timeout = "45m"

[orchestration.worker]
gator = "inherit"
"#;
        let config: Config = toml::from_str(toml).unwrap();
        assert!(config.orchestration.is_enabled());
        assert_eq!(config.orchestration.worker_timeout(), "45m");
        assert_eq!(config.orchestration.worker.gator, WorkerGatorMode::Inherit);
    }

    #[test]
    fn test_worker_gator_mode_readonly() {
        let toml = r#"
[orchestration.worker]
gator = "readonly"
"#;
        let config: Config = toml::from_str(toml).unwrap();
        assert_eq!(config.orchestration.worker.gator, WorkerGatorMode::Readonly);
    }

    #[test]
    fn test_worker_gator_mode_inherit() {
        let toml = r#"
[orchestration.worker]
gator = "inherit"
"#;
        let config: Config = toml::from_str(toml).unwrap();
        assert_eq!(config.orchestration.worker.gator, WorkerGatorMode::Inherit);
    }

    #[test]
    fn test_worker_gator_mode_none() {
        let toml = r#"
[orchestration.worker]
gator = "none"
"#;
        let config: Config = toml::from_str(toml).unwrap();
        assert_eq!(config.orchestration.worker.gator, WorkerGatorMode::None);
    }

    #[test]
    fn test_worker_gator_mode_default() {
        // Default should be readonly
        assert_eq!(WorkerGatorMode::default(), WorkerGatorMode::Readonly);
    }

    // =========================================================================
    // EnvConfig tests
    // =========================================================================

    #[test]
    fn test_env_config_default() {
        let config = EnvConfig::default();
        assert!(config.allowlist.is_empty());
        assert!(config.vars.is_empty());
        assert!(config.collect().is_empty());
    }

    #[test]
    fn test_parse_env_allowlist() {
        let toml = r#"
[env]
allowlist = ["GOOGLE_CLOUD_PROJECT", "SSH_AUTH_SOCK", "VERTEX_LOCATION"]
"#;
        let config: Config = toml::from_str(toml).unwrap();
        assert_eq!(config.env.allowlist.len(), 3);
        assert!(config
            .env
            .allowlist
            .contains(&"GOOGLE_CLOUD_PROJECT".to_string()));
        assert!(config.env.allowlist.contains(&"SSH_AUTH_SOCK".to_string()));
        assert!(config
            .env
            .allowlist
            .contains(&"VERTEX_LOCATION".to_string()));
    }

    #[test]
    fn test_parse_env_vars() {
        let toml = r#"
[env.vars]
VERTEX_LOCATION = "global"
EDITOR = "vim"
"#;
        let config: Config = toml::from_str(toml).unwrap();
        assert_eq!(config.env.vars.len(), 2);
        assert_eq!(
            config.env.vars.get("VERTEX_LOCATION"),
            Some(&"global".to_string())
        );
        assert_eq!(config.env.vars.get("EDITOR"), Some(&"vim".to_string()));
    }

    #[test]
    fn test_parse_env_combined() {
        let toml = r#"
[env]
allowlist = ["GOOGLE_CLOUD_PROJECT"]

[env.vars]
VERTEX_LOCATION = "global"
EDITOR = "vim"
"#;
        let config: Config = toml::from_str(toml).unwrap();
        assert_eq!(config.env.allowlist.len(), 1);
        assert_eq!(config.env.vars.len(), 2);
    }

    #[test]
    fn test_env_config_collect_with_vars() {
        let mut env = EnvConfig::default();
        env.vars.insert("FOO".to_string(), "bar".to_string());
        env.vars.insert("BAZ".to_string(), "qux".to_string());

        let collected = env.collect();
        assert_eq!(collected.get("FOO"), Some(&"bar".to_string()));
        assert_eq!(collected.get("BAZ"), Some(&"qux".to_string()));
    }

    #[test]
    fn test_env_config_vars_override_allowlist() {
        // Set an env var that's in the allowlist
        std::env::set_var("TEST_OVERRIDE_VAR", "from_env");

        let mut env = EnvConfig::default();
        env.allowlist.push("TEST_OVERRIDE_VAR".to_string());
        // Explicit vars should override
        env.vars
            .insert("TEST_OVERRIDE_VAR".to_string(), "from_config".to_string());

        let collected = env.collect();
        assert_eq!(
            collected.get("TEST_OVERRIDE_VAR"),
            Some(&"from_config".to_string())
        );

        // Cleanup
        std::env::remove_var("TEST_OVERRIDE_VAR");
    }

    #[test]
    fn test_env_config_allowlist_skips_missing() {
        let mut env = EnvConfig::default();
        // This var shouldn't exist
        env.allowlist
            .push("DEFINITELY_NOT_SET_VAR_12345".to_string());

        let collected = env.collect();
        assert!(!collected.contains_key("DEFINITELY_NOT_SET_VAR_12345"));
    }

    // =========================================================================
    // TrustedEnvConfig tests
    // =========================================================================

    #[test]
    fn test_trusted_env_default() {
        let config = TrustedEnvConfig::default();
        assert!(config.env.allowlist.is_empty());
        assert!(config.env.vars.is_empty());
        assert!(config.collect().is_empty());
    }

    #[test]
    fn test_parse_trusted_env_allowlist() {
        let toml = r#"
[trusted.env]
allowlist = ["GH_TOKEN", "GITLAB_TOKEN", "JIRA_API_TOKEN"]
"#;
        let config: Config = toml::from_str(toml).unwrap();
        assert_eq!(config.trusted_env.env.allowlist.len(), 3);
        assert!(config
            .trusted_env
            .env
            .allowlist
            .contains(&"GH_TOKEN".to_string()));
        assert!(config
            .trusted_env
            .env
            .allowlist
            .contains(&"GITLAB_TOKEN".to_string()));
        assert!(config
            .trusted_env
            .env
            .allowlist
            .contains(&"JIRA_API_TOKEN".to_string()));
    }

    #[test]
    fn test_parse_trusted_env_vars() {
        let toml = r#"
[trusted.env.vars]
SOME_SECRET = "explicit_value"
"#;
        let config: Config = toml::from_str(toml).unwrap();
        assert_eq!(config.trusted_env.env.vars.len(), 1);
        assert_eq!(
            config.trusted_env.env.vars.get("SOME_SECRET"),
            Some(&"explicit_value".to_string())
        );
    }

    #[test]
    fn test_parse_trusted_env_combined_with_regular_env() {
        let toml = r#"
# Regular env - goes to all containers including agent
[env]
allowlist = ["GOOGLE_CLOUD_PROJECT"]

[env.vars]
VERTEX_LOCATION = "global"

# Trusted env - only goes to workspace and gator, NOT agent
[trusted.env]
allowlist = ["GH_TOKEN", "GITLAB_TOKEN"]

[trusted.env.vars]
JIRA_API_TOKEN = "from_config"
"#;
        let config: Config = toml::from_str(toml).unwrap();

        // Regular env
        assert_eq!(config.env.allowlist.len(), 1);
        assert!(config
            .env
            .allowlist
            .contains(&"GOOGLE_CLOUD_PROJECT".to_string()));
        assert_eq!(config.env.vars.len(), 1);

        // Trusted env - separate from regular
        assert_eq!(config.trusted_env.env.allowlist.len(), 2);
        assert!(config
            .trusted_env
            .env
            .allowlist
            .contains(&"GH_TOKEN".to_string()));
        assert_eq!(config.trusted_env.env.vars.len(), 1);
        assert_eq!(
            config.trusted_env.env.vars.get("JIRA_API_TOKEN"),
            Some(&"from_config".to_string())
        );
    }

    #[test]
    fn test_trusted_env_collect() {
        std::env::set_var("TEST_TRUSTED_VAR", "trusted_value");

        let mut trusted = TrustedEnvConfig::default();
        trusted.env.allowlist.push("TEST_TRUSTED_VAR".to_string());
        trusted
            .env
            .vars
            .insert("EXPLICIT_VAR".to_string(), "explicit".to_string());

        let collected = trusted.collect();
        assert_eq!(
            collected.get("TEST_TRUSTED_VAR"),
            Some(&"trusted_value".to_string())
        );
        assert_eq!(collected.get("EXPLICIT_VAR"), Some(&"explicit".to_string()));

        std::env::remove_var("TEST_TRUSTED_VAR");
    }

    // =========================================================================
    // TrustedEnvConfig secrets tests
    // =========================================================================

    #[test]
    fn test_trusted_env_secrets_default() {
        let config = TrustedEnvConfig::default();
        assert!(config.secrets.is_empty());
        assert!(config.secret_mounts().is_empty());
    }

    #[test]
    fn test_parse_trusted_env_secrets() {
        // [trusted.secrets] is now an array of "ENV_VAR=secret_name" strings
        let toml = r#"
[trusted]
secrets = ["GH_TOKEN=gh_token", "GITLAB_TOKEN=gitlab_token"]
"#;
        let config: Config = toml::from_str(toml).unwrap();
        assert_eq!(config.trusted_env.secrets.len(), 2);
        assert!(config
            .trusted_env
            .secrets
            .contains(&"GH_TOKEN=gh_token".to_string()));
        assert!(config
            .trusted_env
            .secrets
            .contains(&"GITLAB_TOKEN=gitlab_token".to_string()));
    }

    #[test]
    fn test_trusted_env_secret_mounts() {
        let mut trusted = TrustedEnvConfig::default();
        trusted.secrets = vec![
            "GH_TOKEN=gh_token".to_string(),
            "GITLAB_TOKEN=gitlab_token".to_string(),
        ];

        let mounts = trusted.secret_mounts();
        assert_eq!(mounts.len(), 2);

        // Check that both secrets are present (order preserved from Vec)
        // Format is (env_var_name, secret_name)
        let has_gh = mounts
            .iter()
            .any(|(env, secret)| env == "GH_TOKEN" && secret == "gh_token");
        let has_gitlab = mounts
            .iter()
            .any(|(env, secret)| env == "GITLAB_TOKEN" && secret == "gitlab_token");
        assert!(has_gh, "Should have GH_TOKEN secret");
        assert!(has_gitlab, "Should have GITLAB_TOKEN secret");
    }

    #[test]
    fn test_trusted_env_secret_mounts_invalid_entries() {
        let mut trusted = TrustedEnvConfig::default();
        trusted.secrets = vec![
            "GH_TOKEN=gh_token".to_string(),     // valid
            "INVALID_NO_EQUALS".to_string(),     // invalid: no =
            "=empty_var".to_string(),            // invalid: empty var name
            "EMPTY_SECRET=".to_string(),         // invalid: empty secret name
            "VALID_TWO=some_secret".to_string(), // valid
        ];

        let mounts = trusted.secret_mounts();
        // Only the 2 valid entries should be returned
        assert_eq!(mounts.len(), 2);
        assert!(mounts.iter().any(|(env, _)| env == "GH_TOKEN"));
        assert!(mounts.iter().any(|(env, _)| env == "VALID_TWO"));
    }

    #[test]
    fn test_parse_trusted_env_secrets_combined() {
        // Test combining env vars and secrets
        let toml = r#"
[trusted.env]
allowlist = ["JIRA_API_TOKEN"]

[trusted.env.vars]
SOME_VAR = "value"

[trusted]
secrets = ["GH_TOKEN=gh_token"]
"#;
        let config: Config = toml::from_str(toml).unwrap();

        // Env allowlist
        assert_eq!(config.trusted_env.env.allowlist.len(), 1);
        assert!(config
            .trusted_env
            .env
            .allowlist
            .contains(&"JIRA_API_TOKEN".to_string()));

        // Explicit vars
        assert_eq!(config.trusted_env.env.vars.len(), 1);
        assert_eq!(
            config.trusted_env.env.vars.get("SOME_VAR"),
            Some(&"value".to_string())
        );

        // Secrets (now a Vec of strings)
        assert_eq!(config.trusted_env.secrets.len(), 1);
        assert!(config
            .trusted_env
            .secrets
            .contains(&"GH_TOKEN=gh_token".to_string()));
    }

    // =========================================================================
    // File secrets tests
    // =========================================================================

    #[test]
    fn test_trusted_env_file_secrets_default() {
        let config = TrustedEnvConfig::default();
        assert!(config.file_secrets.is_empty());
        assert!(config.file_secret_mounts().is_empty());
    }

    #[test]
    fn test_parse_trusted_env_file_secrets() {
        let toml = r#"
[trusted]
file_secrets = ["GOOGLE_APPLICATION_CREDENTIALS=gcloud_adc"]
"#;
        let config: Config = toml::from_str(toml).unwrap();
        assert_eq!(config.trusted_env.file_secrets.len(), 1);
        assert!(config
            .trusted_env
            .file_secrets
            .contains(&"GOOGLE_APPLICATION_CREDENTIALS=gcloud_adc".to_string()));
    }

    #[test]
    fn test_trusted_env_file_secret_mounts() {
        let mut trusted = TrustedEnvConfig::default();
        trusted.file_secrets = vec![
            "GOOGLE_APPLICATION_CREDENTIALS=gcloud_adc".to_string(),
            "ANOTHER_CREDENTIAL_FILE=another_secret".to_string(),
        ];

        let mounts = trusted.file_secret_mounts();
        assert_eq!(mounts.len(), 2);

        // Check that both secrets are present (order preserved from Vec)
        // Format is (env_var_name, secret_name)
        let has_gcloud = mounts
            .iter()
            .any(|(env, secret)| env == "GOOGLE_APPLICATION_CREDENTIALS" && secret == "gcloud_adc");
        let has_another = mounts
            .iter()
            .any(|(env, secret)| env == "ANOTHER_CREDENTIAL_FILE" && secret == "another_secret");
        assert!(
            has_gcloud,
            "Should have GOOGLE_APPLICATION_CREDENTIALS secret"
        );
        assert!(has_another, "Should have ANOTHER_CREDENTIAL_FILE secret");
    }

    #[test]
    fn test_trusted_env_file_secret_mounts_invalid_entries() {
        let mut trusted = TrustedEnvConfig::default();
        trusted.file_secrets = vec![
            "GOOGLE_APPLICATION_CREDENTIALS=gcloud_adc".to_string(), // valid
            "INVALID_NO_EQUALS".to_string(),                         // invalid: no =
            "=empty_var".to_string(),                                // invalid: empty var name
            "EMPTY_SECRET=".to_string(),                             // invalid: empty secret name
            "VALID_TWO=some_secret".to_string(),                     // valid
        ];

        let mounts = trusted.file_secret_mounts();
        // Only the 2 valid entries should be returned
        assert_eq!(mounts.len(), 2);
        assert!(mounts
            .iter()
            .any(|(env, _)| env == "GOOGLE_APPLICATION_CREDENTIALS"));
        assert!(mounts.iter().any(|(env, _)| env == "VALID_TWO"));
    }

    #[test]
    fn test_parse_trusted_secrets_and_file_secrets_combined() {
        // Test combining regular secrets (type=env) and file_secrets
        let toml = r#"
[trusted]
secrets = ["GH_TOKEN=gh_token"]
file_secrets = ["GOOGLE_APPLICATION_CREDENTIALS=gcloud_adc"]
"#;
        let config: Config = toml::from_str(toml).unwrap();

        // Regular secrets (type=env)
        assert_eq!(config.trusted_env.secrets.len(), 1);
        let secret_mounts = config.trusted_env.secret_mounts();
        assert_eq!(secret_mounts.len(), 1);
        assert!(secret_mounts
            .iter()
            .any(|(env, secret)| env == "GH_TOKEN" && secret == "gh_token"));

        // File secrets
        assert_eq!(config.trusted_env.file_secrets.len(), 1);
        let file_mounts = config.trusted_env.file_secret_mounts();
        assert_eq!(file_mounts.len(), 1);
        assert!(
            file_mounts
                .iter()
                .any(|(env, secret)| env == "GOOGLE_APPLICATION_CREDENTIALS"
                    && secret == "gcloud_adc")
        );
    }

    // =========================================================================
    // SSH configuration tests
    // =========================================================================

    #[test]
    fn test_ssh_config_default() {
        let config = SshConfig::default();
        // Default is auto_config = true
        assert!(config.auto_config);
    }

    #[test]
    fn test_ssh_config_in_minimal_config() {
        let toml = "";
        let config: Config = toml::from_str(toml).unwrap();
        // Default should have auto_config = true
        assert!(config.ssh.auto_config);
    }

    #[test]
    fn test_parse_ssh_auto_config_true() {
        let toml = r#"
[ssh]
auto-config = true
"#;
        let config: Config = toml::from_str(toml).unwrap();
        assert!(config.ssh.auto_config);
    }

    #[test]
    fn test_parse_ssh_auto_config_false() {
        let toml = r#"
[ssh]
auto-config = false
"#;
        let config: Config = toml::from_str(toml).unwrap();
        assert!(!config.ssh.auto_config);
    }

    // =========================================================================
    // MCP server configuration tests
    // =========================================================================

    #[test]
    fn test_mcp_config_default() {
        let config = McpServersConfig::default();
        assert!(config.servers.is_empty());
        assert_eq!(config.enabled_servers().count(), 0);
    }

    #[test]
    fn test_mcp_config_in_minimal_config() {
        let toml = "";
        let config: Config = toml::from_str(toml).unwrap();
        assert!(config.mcp.servers.is_empty());
    }

    #[test]
    fn test_parse_mcp_config() {
        let toml = r#"
[mcp.advisor]
url = "http://localhost:8766/mcp"

[mcp.custom-tools]
url = "http://my-server:9000/mcp"
enabled = false
"#;
        let config: Config = toml::from_str(toml).unwrap();
        assert_eq!(config.mcp.servers.len(), 2);

        let advisor = &config.mcp.servers["advisor"];
        assert_eq!(advisor.url, "http://localhost:8766/mcp");
        assert!(advisor.enabled); // default true

        let custom = &config.mcp.servers["custom-tools"];
        assert_eq!(custom.url, "http://my-server:9000/mcp");
        assert!(!custom.enabled);
    }

    #[test]
    fn test_mcp_enabled_servers() {
        let toml = r#"
[mcp.enabled-one]
url = "http://localhost:1/mcp"

[mcp.disabled-one]
url = "http://localhost:2/mcp"
enabled = false

[mcp.enabled-two]
url = "http://localhost:3/mcp"
enabled = true
"#;
        let config: Config = toml::from_str(toml).unwrap();
        let enabled: Vec<_> = config.mcp.enabled_servers().collect();
        assert_eq!(enabled.len(), 2);
        assert!(enabled.iter().any(|(name, _)| *name == "enabled-one"));
        assert!(enabled.iter().any(|(name, _)| *name == "enabled-two"));
    }

    #[test]
    fn test_mcp_merge_cli_servers() {
        let mut config = McpServersConfig::default();
        config
            .merge_cli_servers(&[
                "advisor=http://localhost:8766/mcp".to_string(),
                "tools=http://localhost:9000/mcp".to_string(),
            ])
            .unwrap();
        assert_eq!(config.servers.len(), 2);
        assert_eq!(config.servers["advisor"].url, "http://localhost:8766/mcp");
        assert!(config.servers["advisor"].enabled);
    }

    #[test]
    fn test_mcp_merge_cli_servers_invalid() {
        let mut config = McpServersConfig::default();
        assert!(config
            .merge_cli_servers(&["no-equals-sign".to_string()])
            .is_err());
        assert!(config
            .merge_cli_servers(&["=http://empty-name".to_string()])
            .is_err());
        assert!(config
            .merge_cli_servers(&["empty-url=".to_string()])
            .is_err());
    }

    #[test]
    fn test_mcp_merge_cli_servers_empty_headers() {
        let mut config = McpServersConfig::default();
        config
            .merge_cli_servers(&["test=http://localhost:8080/mcp".to_string()])
            .unwrap();
        assert!(
            config.servers["test"].headers.is_empty(),
            "CLI-parsed MCP entries should have empty headers"
        );
    }

    #[test]
    fn test_mcp_entry_headers_default_empty() {
        let toml = r#"
url = "http://localhost:8080/mcp"
"#;
        let entry: McpServerEntry = toml::from_str(toml).unwrap();
        assert!(entry.headers.is_empty());
        assert!(entry.enabled); // default true
    }

    #[test]
    fn test_mcp_entry_with_headers_roundtrip() {
        let toml = r#"
url = "http://localhost:8080/mcp"

[headers]
Authorization = "Bearer abc123"
X-Custom = "value"
"#;
        let entry: McpServerEntry = toml::from_str(toml).unwrap();
        assert_eq!(entry.url, "http://localhost:8080/mcp");
        assert!(entry.enabled);
        assert_eq!(entry.headers.len(), 2);
        assert_eq!(
            entry.headers.get("Authorization"),
            Some(&"Bearer abc123".to_string())
        );
        assert_eq!(entry.headers.get("X-Custom"), Some(&"value".to_string()));
    }
}
