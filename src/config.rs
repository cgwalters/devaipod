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
#[derive(Debug, Deserialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ContainerTarget {
    /// Main development container (default)
    Main,
    /// Sidecar container
    Sidecar,
    /// All containers
    All,
    /// Named container
    #[serde(untagged)]
    Named(String),
}

impl Default for ContainerTarget {
    fn default() -> Self {
        ContainerTarget::Main
    }
}

/// Top-level configuration
#[derive(Debug, Deserialize, Default)]
pub struct Config {
    /// Agent configuration
    #[serde(default)]
    pub agent: AgentConfig,
    /// Dotfiles configuration
    #[serde(default)]
    pub dotfiles: Option<DotfilesConfig>,
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
    /// Network isolation configuration for agent container
    #[serde(default, rename = "network-isolation")]
    pub network_isolation: NetworkIsolationConfig,
    /// GPU passthrough configuration (planned feature, not yet integrated)
    #[serde(default)]
    #[allow(dead_code)]
    pub gpu: GpuPassthroughConfig,
    /// Bind paths from host $HOME to container $HOME (applies to all containers)
    /// Paths are relative to $HOME on both sides
    #[serde(default)]
    pub bind_home: Vec<String>,
    /// Bind paths specifically for the workspace container
    #[serde(default)]
    pub bind_home_workspace: Option<BindHomePaths>,
    /// Bind paths specifically for the agent container
    #[serde(default)]
    pub bind_home_agent: Option<BindHomePaths>,
}

/// Configuration for binding paths from host home to container home
#[derive(Debug, Deserialize, Default, Clone)]
pub struct BindHomePaths {
    /// Paths relative to $HOME to bind mount
    #[serde(default)]
    pub paths: Vec<String>,
}

/// Dotfiles configuration for provisioning user dotfiles in workspaces
///
/// Similar to devpod's dotfiles feature, this clones a git repository
/// containing dotfiles and runs an install script.
#[derive(Debug, Deserialize, Clone)]
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

/// Agent configuration
#[derive(Debug, Deserialize, Default)]
pub struct AgentConfig {
    /// Default agent to use (goose, claude, opencode)
    #[serde(default)]
    pub default_agent: Option<String>,
}

/// Prefix for environment variables that should be forwarded into the sandbox.
/// Variables like `DEVAIPOD_AGENT_FOO=bar` become `FOO=bar` inside the sandbox.
pub const AGENT_ENV_PREFIX: &str = "DEVAIPOD_AGENT_";

/// Default agent to use when none is specified in config or CLI.
pub const DEFAULT_AGENT: &str = "opencode";

// =============================================================================
// Network isolation configuration
// =============================================================================

/// Default domains allowed for agent network access (LLM API endpoints)
pub const DEFAULT_ALLOWED_DOMAINS: &[&str] = &[
    "api.anthropic.com",
    "api.openai.com",
    "api.together.xyz",
    "generativelanguage.googleapis.com",
    "api.groq.com",
    "api.mistral.ai",
    "openrouter.ai",
    "api.cohere.ai",
    "api.x.ai",
];

/// Network isolation configuration for the agent container
///
/// Uses an HTTPS forward proxy to restrict agent network access to
/// only allowed domains (LLM API endpoints). This provides defense-in-depth
/// security without requiring special privileges.
#[derive(Debug, Deserialize, Clone)]
pub struct NetworkIsolationConfig {
    /// Whether to enable network isolation (default: false)
    /// When enabled, the agent can only access domains in the allowlist.
    #[serde(default)]
    pub enabled: bool,
    /// Additional domains to allow beyond the defaults
    #[serde(default)]
    pub allowed_domains: Vec<String>,
    /// Proxy image to use (default: docker.io/ubuntu/squid:latest)
    #[serde(default)]
    pub proxy_image: Option<String>,
}

impl Default for NetworkIsolationConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            allowed_domains: Vec::new(),
            proxy_image: None,
        }
    }
}

impl NetworkIsolationConfig {
    /// Get all allowed domains (defaults + user-configured)
    pub fn all_allowed_domains(&self) -> Vec<String> {
        let mut domains: Vec<String> = DEFAULT_ALLOWED_DOMAINS
            .iter()
            .map(|s| s.to_string())
            .collect();
        domains.extend(self.allowed_domains.clone());
        domains
    }

    /// Get the proxy image to use
    pub fn proxy_image(&self) -> &str {
        self.proxy_image
            .as_deref()
            .unwrap_or("docker.io/ubuntu/squid:latest")
    }
}

// =============================================================================
// GPU passthrough configuration
// =============================================================================

/// GPU passthrough configuration for containers
///
/// When enabled, GPUs are passed through to the workspace container.
/// Supports NVIDIA (via CDI or direct device passthrough) and AMD GPUs.
#[derive(Debug, Deserialize, Clone)]
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
/// This makes it explicit which env vars the sandboxed agent can see.
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
#[derive(Debug, Deserialize)]
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

impl Default for SidecarConfig {
    fn default() -> Self {
        SidecarConfig {
            image: None,
            command: None,
            network: false,
            mount_sources_readonly: false,
            mounts: Vec::new(),
            dotfiles: Vec::new(),
            dotfiles_repo: None,
            dotfiles_install: None,
            profiles: HashMap::new(),
        }
    }
}

/// A bind mount specification for sidecar containers
/// Part of planned sidecar feature.
#[derive(Debug, Deserialize, Clone)]
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
/// (GitHub, JIRA, GitLab) for AI agents. It runs outside the bwrap sandbox
/// and enforces fine-grained permissions on API operations.
#[derive(Debug, Deserialize, Default, Clone)]
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
        !self.gh.repos.is_empty()
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
#[serde(rename_all = "kebab-case")]
pub struct GithubScope {
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
#[serde(rename_all = "kebab-case")]
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
    /// Full write access (merge, close, create non-draft, etc.)
    #[serde(default)]
    pub write: bool,
}

/// Permissions for a specific PR or issue
#[derive(Debug, Deserialize, Serialize, Default, Clone)]
#[serde(rename_all = "kebab-case")]
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
#[serde(rename_all = "kebab-case")]
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
#[serde(rename_all = "kebab-case")]
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
#[serde(rename_all = "kebab-case")]
pub struct JiraIssuePermission {
    /// Can read this issue
    #[serde(default)]
    pub read: bool,
    /// Can write to this issue
    #[serde(default)]
    pub write: bool,
}

/// Generate a service-gator scope config as TOML string
///
/// This is written to ~/.config/service-gator.toml inside the container
/// for service-gator to read.
pub fn generate_service_gator_toml(config: &ServiceGatorConfig) -> String {
    let mut output = String::new();
    output.push_str("# Generated by devaipod - do not edit manually\n");
    output.push_str("# This file is monitored and reloaded by service-gator\n\n");

    // GitHub repos
    if !config.gh.repos.is_empty() {
        output.push_str("[gh.repos]\n");
        for (pattern, perm) in &config.gh.repos {
            let mut perms = Vec::new();
            if perm.read {
                perms.push("read = true");
            }
            if perm.create_draft {
                perms.push("create-draft = true");
            }
            if perm.pending_review {
                perms.push("pending-review = true");
            }
            if perm.write {
                perms.push("write = true");
            }
            if !perms.is_empty() {
                output.push_str(&format!("\"{}\" = {{ {} }}\n", pattern, perms.join(", ")));
            }
        }
        output.push('\n');
    }

    // GitHub PRs
    if !config.gh.prs.is_empty() {
        output.push_str("[gh.prs]\n");
        for (ref_str, perm) in &config.gh.prs {
            let mut perms = Vec::new();
            if perm.read {
                perms.push("read = true");
            }
            if perm.write {
                perms.push("write = true");
            }
            if !perms.is_empty() {
                output.push_str(&format!("\"{}\" = {{ {} }}\n", ref_str, perms.join(", ")));
            }
        }
        output.push('\n');
    }

    // GitHub GraphQL
    if config.gh.graphql != GraphQlPermission::None {
        output.push_str("[gh]\n");
        let graphql_str = match config.gh.graphql {
            GraphQlPermission::None => "none",
            GraphQlPermission::Read => "read",
            GraphQlPermission::Write => "write",
        };
        output.push_str(&format!("graphql = \"{}\"\n\n", graphql_str));
    }

    // JIRA projects
    if !config.jira.projects.is_empty() {
        output.push_str("[jira.projects]\n");
        for (project, perm) in &config.jira.projects {
            let mut perms = Vec::new();
            if perm.read {
                perms.push("read = true");
            }
            if perm.create {
                perms.push("create = true");
            }
            if perm.write {
                perms.push("write = true");
            }
            if !perms.is_empty() {
                output.push_str(&format!("\"{}\" = {{ {} }}\n", project, perms.join(", ")));
            }
        }
        output.push('\n');
    }

    // JIRA issues
    if !config.jira.issues.is_empty() {
        output.push_str("[jira.issues]\n");
        for (issue, perm) in &config.jira.issues {
            let mut perms = Vec::new();
            if perm.read {
                perms.push("read = true");
            }
            if perm.write {
                perms.push("write = true");
            }
            if !perms.is_empty() {
                output.push_str(&format!("\"{}\" = {{ {} }}\n", issue, perms.join(", ")));
            }
        }
    }

    output
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
            if !config.secrets.contains_key(&name) {
                config.secrets.insert(
                    name,
                    SecretMapping {
                        secret: legacy_mapping.secret,
                        env: legacy_mapping.env,
                        container: ContainerTarget::Main,
                    },
                );
            }
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
    }

    #[test]
    fn test_generate_service_gator_toml() {
        let mut config = ServiceGatorConfig::default();
        config.gh.repos.insert(
            "owner/repo".to_string(),
            GhRepoPermission {
                read: true,
                create_draft: true,
                ..Default::default()
            },
        );
        config.jira.projects.insert(
            "PROJ".to_string(),
            JiraProjectPermission {
                read: true,
                ..Default::default()
            },
        );

        let toml = generate_service_gator_toml(&config);
        assert!(toml.contains("[gh.repos]"));
        assert!(toml.contains("\"owner/repo\""));
        assert!(toml.contains("read = true"));
        assert!(toml.contains("create-draft = true"));
        assert!(toml.contains("[jira.projects]"));
        assert!(toml.contains("\"PROJ\""));
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
bind_home = [
    ".config/gcloud/application_default_credentials.json",
    ".gitconfig",
]
"#;
        let config: Config = toml::from_str(toml).unwrap();
        assert_eq!(config.bind_home.len(), 2);
        assert_eq!(
            config.bind_home[0],
            ".config/gcloud/application_default_credentials.json"
        );
        assert_eq!(config.bind_home[1], ".gitconfig");
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
    fn test_parse_bind_home_agent() {
        let toml = r#"
[bind_home_agent]
paths = [".config/gcloud/application_default_credentials.json"]
"#;
        let config: Config = toml::from_str(toml).unwrap();
        let agent = config
            .bind_home_agent
            .expect("bind_home_agent should be present");
        assert_eq!(agent.paths.len(), 1);
        assert_eq!(
            agent.paths[0],
            ".config/gcloud/application_default_credentials.json"
        );
    }

    #[test]
    fn test_parse_bind_home_combined() {
        let toml = r#"
# Global bind_home applies to all containers
bind_home = [".gitconfig"]

# Workspace-specific
[bind_home_workspace]
paths = [".config/gcloud", ".ssh"]

# Agent-specific (read-only)
[bind_home_agent]
paths = [".config/gcloud/application_default_credentials.json"]
"#;
        let config: Config = toml::from_str(toml).unwrap();

        // Global
        assert_eq!(config.bind_home.len(), 1);
        assert_eq!(config.bind_home[0], ".gitconfig");

        // Workspace
        let ws = config
            .bind_home_workspace
            .expect("bind_home_workspace should be present");
        assert_eq!(ws.paths.len(), 2);

        // Agent
        let agent = config
            .bind_home_agent
            .expect("bind_home_agent should be present");
        assert_eq!(agent.paths.len(), 1);
    }

    #[test]
    fn test_bind_home_default_empty() {
        let toml = "";
        let config: Config = toml::from_str(toml).unwrap();
        assert!(config.bind_home.is_empty());
        assert!(config.bind_home_workspace.is_none());
        assert!(config.bind_home_agent.is_none());
    }

    #[test]
    fn test_parse_network_isolation() {
        let toml = r#"
[network-isolation]
enabled = true
allowed_domains = ["api.custom.com", "internal.example.org"]
proxy_image = "my-proxy:latest"
"#;
        let config: Config = toml::from_str(toml).unwrap();
        assert!(config.network_isolation.enabled);
        assert_eq!(
            config.network_isolation.allowed_domains,
            vec!["api.custom.com", "internal.example.org"]
        );
        assert_eq!(
            config.network_isolation.proxy_image,
            Some("my-proxy:latest".to_string())
        );
    }

    #[test]
    fn test_network_isolation_defaults() {
        let config = NetworkIsolationConfig::default();
        assert!(!config.enabled);
        assert!(config.allowed_domains.is_empty());
        assert!(config.proxy_image.is_none());
        assert_eq!(config.proxy_image(), "docker.io/ubuntu/squid:latest");
    }

    #[test]
    fn test_network_isolation_all_domains() {
        let mut config = NetworkIsolationConfig::default();
        config.allowed_domains = vec!["custom.api.com".to_string()];

        let all_domains = config.all_allowed_domains();

        // Should contain defaults + custom
        assert!(all_domains.contains(&"api.anthropic.com".to_string()));
        assert!(all_domains.contains(&"api.openai.com".to_string()));
        assert!(all_domains.contains(&"custom.api.com".to_string()));
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
}
