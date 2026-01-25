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

// TODO: Support a static allowlist in devcontainer.json, e.g.:
// "customizations": { "devaipod": { "env_allowlist": ["ANTHROPIC_API_KEY"] } }
// This would let projects define which env vars the agent needs without
// requiring users to set DEVAIPOD_AGENT_* prefixes.

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
}
