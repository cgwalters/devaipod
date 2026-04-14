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

// =============================================================================
// Source configuration
// =============================================================================

/// Source access level for bind mounts.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum SourceAccess {
    /// Read-only everywhere (control plane + agent).
    Readonly,
    /// Read-write in control plane only, NOT mounted into agent containers.
    /// This is the default because the control plane needs to write into source
    /// repos for `devaipod fetch` (adding remotes and fetching branches).
    /// Agents should never modify the user's original source trees.
    #[default]
    Controlplane,
    /// Read-write everywhere (control plane + agent containers).
    Agent,
}

/// A single source entry, supporting both shorthand and full forms.
/// Shorthand: `src = "~/src"` (defaults to readonly)
/// Full: `src = { path = "~/src", access = "controlplane" }`
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum SourceEntry {
    /// Shorthand: just a path string (defaults to readonly access)
    Short(String),
    /// Full entry with explicit access level
    Full(SourceEntryFull),
}

/// Full source entry with all options.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceEntryFull {
    pub path: String,
    #[serde(default)]
    pub access: SourceAccess,
}

/// Resolved source information after path expansion.
#[derive(Debug, Clone)]
pub struct ResolvedSource {
    pub name: String,
    pub path: PathBuf,
    pub access: SourceAccess,
}

/// Environment variable for the host's home directory.
/// Set by the launcher so container-side tilde expansion resolves to host paths.
pub const HOST_HOME_ENV: &str = "DEVAIPOD_HOST_HOME";

/// Expand `~` in a path to the host home directory.
/// Prefers DEVAIPOD_HOST_HOME (set by launcher) over HOME.
fn expand_source_path(path: &str) -> PathBuf {
    if let Some(suffix) = path.strip_prefix("~/") {
        let home = std::env::var(HOST_HOME_ENV)
            .or_else(|_| std::env::var("HOME"))
            .unwrap_or_else(|_| "/root".to_string());
        PathBuf::from(home).join(suffix)
    } else {
        PathBuf::from(path)
    }
}

/// Resolve a source shorthand like `src:github/org/repo` to a full path.
/// Returns None if the source name is not found in the config or the path doesn't
/// start with `<name>:`.
pub fn resolve_source_shorthand(source: &str, config: &Config) -> Option<PathBuf> {
    let (name, subpath) = source.split_once(':')?;
    // Verify the source name exists in config
    config.sources.get(name)?;
    // Sources are mounted at /mnt/<name> inside the container
    Some(PathBuf::from(format!("/mnt/{}", name)).join(subpath))
}

/// Translate a container-internal source path (e.g. `/mnt/src/github/org/repo`)
/// back to the host-side path using the resolved sources config.
///
/// This is needed when creating init containers via the host's podman daemon:
/// the container sees paths under `/mnt/<name>/...` but the host needs the
/// actual filesystem path (e.g. `~/src/github/org/repo`).
///
/// Returns the original path unchanged if it doesn't match any source mount.
pub fn source_path_to_host(path: &Path, config: &Config) -> PathBuf {
    let path_str = path.to_string_lossy();
    for source in config.resolve_sources() {
        let mount_prefix = format!("/mnt/{}", source.name);
        if let Some(suffix) = path_str.strip_prefix(&mount_prefix) {
            // Guard against false prefix matches: `/mnt/src` must not match
            // `/mnt/srcode/foo`. The remainder after stripping must be empty
            // (exact match) or start with `/`.
            if !suffix.is_empty() && !suffix.starts_with('/') {
                continue;
            }
            let suffix = suffix.strip_prefix('/').unwrap_or(suffix);
            if suffix.is_empty() {
                return source.path.clone();
            }
            return source.path.join(suffix);
        }
    }
    path.to_path_buf()
}

/// Validate a source name. Must be non-empty, alphanumeric + hyphens/underscores.
fn validate_source_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .chars()
            .all(|c| c.is_alphanumeric() || c == '-' || c == '_')
}

/// Names that must not be used as source names because they collide with
/// top-level config keys. If TOML sees `bind = [...]` inside a `[sources]`
/// section, it treats it as `sources.bind` rather than the top-level `bind`
/// array — a silent misparse that produces confusing errors downstream.
const RESERVED_SOURCE_NAMES: &[&str] = &[
    "agent",
    "bind",
    "env",
    "trusted",
    "dotfiles",
    "sidecar",
    "secrets",
    "gpu",
    "ssh",
    "mcp",
    "git",
    "journal",
    "orchestration",
];

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

/// Agent configuration section
///
/// Controls which AI agent backend is used and how it's started.
/// Profiles define named agent configurations with specific commands
/// and environment variables.
///
/// The `default` field accepts either a single profile name or an ordered
/// list of profile names for auto-detection:
///
/// Example configuration:
/// ```toml
/// [agent]
/// # Single default (backwards compatible)
/// default = "opencode"
///
/// # Or: ordered list for auto-detection (tries goose, falls back to opencode)
/// default = ["goose", "opencode"]
///
/// [agent.profiles.opencode]
/// command = ["opencode", "acp"]
/// env = { OPENCODE_CONFIG = "~/.config/devaipod/agents/opencode/config.json" }
///
/// [agent.profiles.goose]
/// command = ["goose", "acp"]
/// env = { GOOSE_MODE = "auto", GOOSE_CONFIG_DIR = "~/.config/devaipod/agents/goose" }
/// ```
#[derive(Debug, Default, Clone)]
pub struct AgentConfig {
    /// Default agent profile name(s). Accepts a single string or an array.
    /// When multiple profiles are specified, they're tried in order during
    /// auto-detection. Falls back to "opencode" if empty or not set.
    pub default: Vec<String>,
    /// Named agent profiles
    pub profiles: HashMap<String, AgentProfile>,
}

/// Helper for deserializing `default` field: accepts string or array of strings.
#[derive(Deserialize)]
#[serde(untagged)]
enum DefaultField {
    Single(String),
    Multiple(Vec<String>),
}

impl<'de> Deserialize<'de> for AgentConfig {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct AgentConfigRaw {
            #[serde(default)]
            default: Option<DefaultField>,
            #[serde(default)]
            profiles: HashMap<String, AgentProfile>,
        }

        let raw = AgentConfigRaw::deserialize(deserializer)?;
        let default = match raw.default {
            None => vec![],
            Some(DefaultField::Single(s)) => vec![s],
            Some(DefaultField::Multiple(v)) => v,
        };

        Ok(AgentConfig {
            default,
            profiles: raw.profiles,
        })
    }
}

impl AgentConfig {
    /// Resolve which agent profile to use.
    ///
    /// Priority: CLI flag → config default → hardcoded "opencode" fallback.
    /// If the resolved name matches a profile, returns (name, Some(profile)).
    /// If no profile exists, returns (name, None) — the caller uses the
    /// hardcoded default command.
    ///
    /// This returns the first candidate from the priority list for backwards
    /// compatibility with callers that expect a single profile.
    pub fn resolve_profile<'a>(
        &'a self,
        cli_agent: Option<&'a str>,
    ) -> (String, Option<&'a AgentProfile>) {
        // If CLI override is provided, use it directly (even if profile doesn't exist)
        if let Some(name) = cli_agent.filter(|s| !s.is_empty()) {
            let profile = self.profiles.get(name);
            return (name.to_string(), profile);
        }

        // Otherwise use the first candidate from the priority list
        let candidates = self.candidates_internal(None);
        if let Some((name, profile)) = candidates.first() {
            (name.to_string(), Some(profile))
        } else {
            // Empty list — use hardcoded opencode fallback
            ("opencode".to_string(), None)
        }
    }

    /// Get candidate agent profiles in priority order.
    ///
    /// Returns a list of (name, profile) pairs to try in order. If a CLI
    /// override is provided, returns only that profile. Otherwise, returns
    /// profiles from the `default` list (filtered to only those that exist
    /// in `profiles`), followed by the hardcoded "opencode" fallback if it's
    /// not already in the list.
    ///
    /// This is used for auto-detection: the container startup will probe for
    /// each binary in order and use the first one available.
    pub fn candidates(&self) -> Vec<(&str, &AgentProfile)> {
        self.candidates_internal(None)
    }

    fn candidates_internal<'a>(
        &'a self,
        cli_agent: Option<&'a str>,
    ) -> Vec<(&'a str, &'a AgentProfile)> {
        let mut result = Vec::new();

        // If CLI override is provided, only return that profile
        if let Some(name) = cli_agent.filter(|s| !s.is_empty()) {
            if let Some(profile) = self.profiles.get(name) {
                result.push((name, profile));
            }
            return result;
        }

        // Collect profiles from the default list
        let mut seen = std::collections::HashSet::new();
        for name in &self.default {
            if let Some(profile) = self.profiles.get(name) {
                result.push((name.as_str(), profile));
                seen.insert(name.as_str());
            }
        }

        // Add hardcoded opencode fallback if not already present
        if !seen.contains("opencode") {
            if let Some(profile) = self.profiles.get("opencode") {
                result.push(("opencode", profile));
            } else {
                // No opencode profile defined — caller will use hardcoded default
                // This is represented by returning the name with a default profile
                // But we can't construct a profile here without adding a field.
                // Instead, return empty list to signal fallback needed.
                if result.is_empty() {
                    // No profiles found at all — return empty to trigger fallback
                }
            }
        }

        result
    }

    /// Get the list of candidate binary names to check for availability.
    ///
    /// Extracts the first element of each candidate profile's command
    /// (the binary name), in priority order. Used by the startup script
    /// to verify at least one agent binary is available in the container.
    pub fn candidate_binaries(&self) -> Vec<&str> {
        self.candidates()
            .iter()
            .filter_map(|(_, profile)| profile.command.first().map(|s| s.as_str()))
            .collect()
    }
}

/// A named agent profile defining how to start a specific agent.
///
/// The command is what pod-api spawns as a child process. The env vars
/// are set on the child process. Agent config files live in the user's
/// dotfiles repo, pointed to by env vars.
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct AgentProfile {
    /// Command to start the agent (e.g., ["opencode", "acp"])
    pub command: Vec<String>,
    /// Environment variables to set when starting the agent.
    /// Values support ~ expansion to the container home path.
    #[serde(default)]
    pub env: HashMap<String, String>,
}

/// Expand `~` prefix in a string value to the given home directory.
///
/// Used for agent profile env values where `~` should resolve to
/// the container's home directory, not the host's.
#[allow(dead_code)] // Used by pod.rs when wiring agent profiles in Phase 3
pub fn expand_tilde(value: &str, home: &str) -> String {
    if let Some(suffix) = value.strip_prefix("~/") {
        format!("{}/{}", home, suffix)
    } else if value == "~" {
        home.to_string()
    } else {
        value.to_string()
    }
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

    /// Git-related configuration
    #[serde(default)]
    pub git: GitConfig,

    /// Journal repository configuration (fallback source for agents without a specific repo)
    #[serde(default)]
    pub journal: JournalConfig,

    /// Agent configuration (profiles, default agent selection)
    #[serde(default)]
    pub agent: AgentConfig,

    /// Named source directories to bind-mount into containers.
    /// Keys are names (used as mount point: /mnt/<name>), values are paths.
    #[serde(default)]
    pub sources: HashMap<String, SourceEntry>,

    /// Generic bind mounts in podman/docker `-v` format.
    /// Each entry is `source:target[:options]` (e.g. `~/data:/data:ro`).
    /// Mounted into all containers (server, workspace, agent).
    /// Tilde in the source path is expanded to the host home directory.
    #[serde(default)]
    pub bind: Vec<String>,
}

impl Config {
    /// Resolve all configured sources, expanding ~ to the host home directory.
    /// Uses DEVAIPOD_HOST_HOME if set (for container-side resolution to host paths),
    /// otherwise falls back to HOME.
    pub fn resolve_sources(&self) -> Vec<ResolvedSource> {
        self.sources
            .iter()
            .filter_map(|(name, entry)| {
                if !validate_source_name(name) {
                    tracing::warn!(
                        "Ignoring source '{}': names must be non-empty and \
                         contain only alphanumeric characters, hyphens, or underscores.",
                        name,
                    );
                    return None;
                }
                if RESERVED_SOURCE_NAMES.contains(&name.as_str()) {
                    tracing::warn!(
                        "Ignoring source '{}': name collides with a config key. \
                         This usually means `{} = ...` was placed inside a [sources] \
                         section instead of at the top level.",
                        name,
                        name,
                    );
                    return None;
                }
                let (raw_path, access) = match entry {
                    SourceEntry::Short(p) => (p.clone(), SourceAccess::Controlplane),
                    SourceEntry::Full(f) => (f.path.clone(), f.access.clone()),
                };
                let expanded = expand_source_path(&raw_path);
                Some(ResolvedSource {
                    name: name.clone(),
                    path: expanded,
                    access,
                })
            })
            .collect()
    }

    /// Parse and resolve `[bind]` entries, expanding `~` in source paths.
    ///
    /// Each entry follows podman/docker `-v` syntax: `source:target[:options]`.
    /// Invalid entries (missing `:`) are logged as warnings and skipped.
    pub fn resolve_binds(&self) -> Vec<ResolvedBind> {
        self.bind
            .iter()
            .filter_map(|spec| {
                ResolvedBind::parse(spec)
                    .map_err(|e| tracing::warn!("Ignoring invalid bind spec '{}': {}", spec, e))
                    .ok()
            })
            .collect()
    }
}

/// A parsed bind mount from the `[bind]` array.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedBind {
    /// Host-side path (tilde-expanded).
    pub source: PathBuf,
    /// Container-side mount target.
    pub target: String,
    /// Raw options string (e.g. "ro", "ro,Z"). Empty if none.
    pub options: String,
}

impl ResolvedBind {
    /// Parse a podman `-v` style spec: `source:target[:options]`.
    fn parse(spec: &str) -> Result<Self, String> {
        // Split on `:` but be careful with Windows-style paths (not relevant
        // for us, but handle the common `source:target` vs `source:target:opts`).
        let parts: Vec<&str> = spec.splitn(3, ':').collect();
        if parts.len() < 2 {
            return Err("expected source:target[:options]".to_string());
        }
        let source = expand_source_path(parts[0]);
        let target = parts[1].to_string();
        if target.is_empty() {
            return Err("target path must not be empty".to_string());
        }
        let options = parts.get(2).unwrap_or(&"").to_string();
        Ok(ResolvedBind {
            source,
            target,
            options,
        })
    }

    /// Format as a podman `-v` argument string.
    pub fn to_podman_arg(&self) -> String {
        if self.options.is_empty() {
            format!("{}:{}", self.source.display(), self.target)
        } else {
            format!("{}:{}:{}", self.source.display(), self.target, self.options)
        }
    }
}

/// Journal repository configuration
///
/// The journal repo is a fallback for agents launched without a specific source
/// repo. It provides a place for research notes, cross-cutting investigations,
/// and other work that doesn't belong to a specific project.
///
/// Example configuration:
/// ```toml
/// [journal]
/// repo = "~/src/journal"
/// ```
#[derive(Debug, Deserialize, Default, Clone)]
#[serde(deny_unknown_fields)]
pub struct JournalConfig {
    /// Path to the journal git repository.
    /// Can be a local path (~/src/journal) or a git URL.
    #[serde(default)]
    pub repo: Option<String>,
}

impl JournalConfig {
    /// Returns the resolved journal repo path, expanding ~ to $HOME.
    #[allow(dead_code)] // Used by tests; will be used by workspace creation
    pub fn repo_path(&self) -> Option<std::path::PathBuf> {
        self.repo.as_ref().map(|r| {
            if let Some(suffix) = r.strip_prefix("~/")
                && let Ok(home) = std::env::var("HOME")
            {
                return std::path::PathBuf::from(format!("{}/{}", home, suffix));
            }
            std::path::PathBuf::from(r)
        })
    }

    /// Returns true if a journal repo is configured.
    #[allow(dead_code)] // Used by tests; will be used by workspace creation
    pub fn is_configured(&self) -> bool {
        self.repo.is_some()
    }
}

/// Git-related configuration
#[derive(Debug, Deserialize, Default, Clone)]
#[serde(deny_unknown_fields)]
pub struct GitConfig {
    /// Additional git hosting provider hostnames for bare-URL normalization.
    ///
    /// Bare hostnames like `github.com/owner/repo` are automatically prepended
    /// with `https://`. The built-in list covers major public forges (GitHub,
    /// GitLab, Codeberg, etc.); use this to add private instances:
    ///
    /// ```toml
    /// [git]
    /// extra_hosts = ["forgejo.example.com", "gitea.corp.internal"]
    /// ```
    #[serde(default)]
    pub extra_hosts: Vec<String>,
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
        self.collect_with(|key| std::env::var(key).ok())
    }

    /// Collect environment variables using a custom lookup function.
    ///
    /// Like [`collect`](Self::collect), but uses the provided function
    /// to resolve allowlist entries instead of the process environment.
    fn collect_with(&self, env_lookup: impl Fn(&str) -> Option<String>) -> HashMap<String, String> {
        let mut result = HashMap::new();

        // First, add env vars from allowlist (looked up via env_lookup)
        for key in &self.allowlist {
            if let Some(value) = env_lookup(key) {
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

    /// Collect environment variables using a custom lookup function.
    ///
    /// Like [`collect`](Self::collect), but uses the provided function
    /// to resolve allowlist entries instead of the process environment.
    #[cfg(test)]
    fn collect_with(&self, env_lookup: impl Fn(&str) -> Option<String>) -> HashMap<String, String> {
        self.env.collect_with(env_lookup)
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
/// external services, connected to the agent via MCP config.
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
    /// The key is the server name used in the agent config.
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
        assert!(
            config
                .env
                .allowlist
                .contains(&"GOOGLE_CLOUD_PROJECT".to_string())
        );
        assert!(config.env.allowlist.contains(&"SSH_AUTH_SOCK".to_string()));
        assert!(
            config
                .env
                .allowlist
                .contains(&"VERTEX_LOCATION".to_string())
        );
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
        let mut env = EnvConfig::default();
        env.allowlist.push("TEST_OVERRIDE_VAR".to_string());
        // Explicit vars should override allowlist-resolved values
        env.vars
            .insert("TEST_OVERRIDE_VAR".to_string(), "from_config".to_string());

        let collected = env.collect_with(|key| match key {
            "TEST_OVERRIDE_VAR" => Some("from_env".to_string()),
            _ => None,
        });
        assert_eq!(
            collected.get("TEST_OVERRIDE_VAR"),
            Some(&"from_config".to_string())
        );
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
        assert!(
            config
                .trusted_env
                .env
                .allowlist
                .contains(&"GH_TOKEN".to_string())
        );
        assert!(
            config
                .trusted_env
                .env
                .allowlist
                .contains(&"GITLAB_TOKEN".to_string())
        );
        assert!(
            config
                .trusted_env
                .env
                .allowlist
                .contains(&"JIRA_API_TOKEN".to_string())
        );
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
        assert!(
            config
                .env
                .allowlist
                .contains(&"GOOGLE_CLOUD_PROJECT".to_string())
        );
        assert_eq!(config.env.vars.len(), 1);

        // Trusted env - separate from regular
        assert_eq!(config.trusted_env.env.allowlist.len(), 2);
        assert!(
            config
                .trusted_env
                .env
                .allowlist
                .contains(&"GH_TOKEN".to_string())
        );
        assert_eq!(config.trusted_env.env.vars.len(), 1);
        assert_eq!(
            config.trusted_env.env.vars.get("JIRA_API_TOKEN"),
            Some(&"from_config".to_string())
        );
    }

    #[test]
    fn test_trusted_env_collect() {
        let mut trusted = TrustedEnvConfig::default();
        trusted.env.allowlist.push("TEST_TRUSTED_VAR".to_string());
        trusted
            .env
            .vars
            .insert("EXPLICIT_VAR".to_string(), "explicit".to_string());

        let collected = trusted.collect_with(|key| match key {
            "TEST_TRUSTED_VAR" => Some("trusted_value".to_string()),
            _ => None,
        });
        assert_eq!(
            collected.get("TEST_TRUSTED_VAR"),
            Some(&"trusted_value".to_string())
        );
        assert_eq!(collected.get("EXPLICIT_VAR"), Some(&"explicit".to_string()));
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
        assert!(
            config
                .trusted_env
                .secrets
                .contains(&"GH_TOKEN=gh_token".to_string())
        );
        assert!(
            config
                .trusted_env
                .secrets
                .contains(&"GITLAB_TOKEN=gitlab_token".to_string())
        );
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
        assert!(
            config
                .trusted_env
                .env
                .allowlist
                .contains(&"JIRA_API_TOKEN".to_string())
        );

        // Explicit vars
        assert_eq!(config.trusted_env.env.vars.len(), 1);
        assert_eq!(
            config.trusted_env.env.vars.get("SOME_VAR"),
            Some(&"value".to_string())
        );

        // Secrets (now a Vec of strings)
        assert_eq!(config.trusted_env.secrets.len(), 1);
        assert!(
            config
                .trusted_env
                .secrets
                .contains(&"GH_TOKEN=gh_token".to_string())
        );
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
        assert!(
            config
                .trusted_env
                .file_secrets
                .contains(&"GOOGLE_APPLICATION_CREDENTIALS=gcloud_adc".to_string())
        );
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
        assert!(
            mounts
                .iter()
                .any(|(env, _)| env == "GOOGLE_APPLICATION_CREDENTIALS")
        );
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
        assert!(
            secret_mounts
                .iter()
                .any(|(env, secret)| env == "GH_TOKEN" && secret == "gh_token")
        );

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
        assert!(
            config
                .merge_cli_servers(&["no-equals-sign".to_string()])
                .is_err()
        );
        assert!(
            config
                .merge_cli_servers(&["=http://empty-name".to_string()])
                .is_err()
        );
        assert!(
            config
                .merge_cli_servers(&["empty-url=".to_string()])
                .is_err()
        );
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

    #[test]
    fn test_git_config_default() {
        let config = GitConfig::default();
        assert!(config.extra_hosts.is_empty());
    }

    #[test]
    fn test_git_config_deserialization() {
        let toml = r#"
[git]
extra_hosts = ["forgejo.example.com", "gitea.corp.internal"]
"#;
        let config: Config = toml::from_str(toml).unwrap();
        assert_eq!(config.git.extra_hosts.len(), 2);
        assert_eq!(config.git.extra_hosts[0], "forgejo.example.com");
        assert_eq!(config.git.extra_hosts[1], "gitea.corp.internal");
    }

    #[test]
    fn test_git_config_empty_extra_hosts() {
        let toml = r#"
[git]
extra_hosts = []
"#;
        let config: Config = toml::from_str(toml).unwrap();
        assert!(config.git.extra_hosts.is_empty());
    }

    #[test]
    fn test_git_config_absent_defaults_empty() {
        // When [git] section is absent entirely, extra_hosts defaults to empty
        let toml = "";
        let config: Config = toml::from_str(toml).unwrap();
        assert!(config.git.extra_hosts.is_empty());
    }

    // =========================================================================
    // Journal configuration tests
    // =========================================================================

    #[test]
    fn test_journal_config_defaults() {
        let config: Config = toml::from_str("").unwrap();
        assert!(!config.journal.is_configured());
        assert!(config.journal.repo_path().is_none());
    }

    #[test]
    fn test_journal_config_with_repo() {
        let config: Config = toml::from_str(
            r#"
            [journal]
            repo = "~/src/journal"
        "#,
        )
        .unwrap();
        assert!(config.journal.is_configured());
        // Don't assert the exact path since HOME varies
        assert!(config.journal.repo_path().is_some());
    }

    #[test]
    fn test_journal_config_with_url() {
        let config: Config = toml::from_str(
            r#"
            [journal]
            repo = "https://github.com/user/journal"
        "#,
        )
        .unwrap();
        assert!(config.journal.is_configured());
        assert_eq!(
            config.journal.repo_path().unwrap().to_str().unwrap(),
            "https://github.com/user/journal"
        );
    }

    #[test]
    fn test_journal_config_tilde_expansion() {
        let config = JournalConfig {
            repo: Some("~/src/journal".to_string()),
        };
        let path = config.repo_path().unwrap();
        // Should expand ~ when HOME is set (which it is in test environments)
        if std::env::var("HOME").is_ok() {
            assert!(!path.to_str().unwrap().starts_with("~/"));
            assert!(path.to_str().unwrap().ends_with("/src/journal"));
        }
    }

    // =========================================================================
    // Sources configuration tests
    // =========================================================================

    #[test]
    fn test_sources_default_empty() {
        let config: Config = toml::from_str("").unwrap();
        assert!(config.sources.is_empty());
        assert!(config.resolve_sources().is_empty());
    }

    #[test]
    fn test_parse_sources_shorthand() {
        let toml = r#"
[sources]
src = "~/src"
projects = "/opt/projects"
"#;
        let config: Config = toml::from_str(toml).unwrap();
        assert_eq!(config.sources.len(), 2);

        // Verify shorthand entries are parsed as Short variant
        assert!(matches!(config.sources["src"], SourceEntry::Short(ref p) if p == "~/src"));
        assert!(
            matches!(config.sources["projects"], SourceEntry::Short(ref p) if p == "/opt/projects")
        );
    }

    #[test]
    fn test_parse_sources_full_entry() {
        let toml = r#"
[sources]
src = { path = "~/src", access = "controlplane" }
work = { path = "/mnt/work", access = "agent" }
readonly-src = { path = "~/readonly" }
"#;
        let config: Config = toml::from_str(toml).unwrap();
        assert_eq!(config.sources.len(), 3);

        // Controlplane access
        match &config.sources["src"] {
            SourceEntry::Full(f) => {
                assert_eq!(f.path, "~/src");
                assert_eq!(f.access, SourceAccess::Controlplane);
            }
            _ => panic!("Expected Full entry for 'src'"),
        }

        // Agent access
        match &config.sources["work"] {
            SourceEntry::Full(f) => {
                assert_eq!(f.path, "/mnt/work");
                assert_eq!(f.access, SourceAccess::Agent);
            }
            _ => panic!("Expected Full entry for 'work'"),
        }

        // Default (controlplane) access when no explicit level given
        match &config.sources["readonly-src"] {
            SourceEntry::Full(f) => {
                assert_eq!(f.path, "~/readonly");
                assert_eq!(f.access, SourceAccess::Controlplane);
            }
            _ => panic!("Expected Full entry for 'readonly-src'"),
        }
    }

    #[test]
    fn test_parse_sources_mixed() {
        let toml = r#"
[sources]
simple = "~/simple"
complex = { path = "~/complex", access = "agent" }
"#;
        let config: Config = toml::from_str(toml).unwrap();
        assert_eq!(config.sources.len(), 2);
        assert!(matches!(config.sources["simple"], SourceEntry::Short(_)));
        assert!(matches!(config.sources["complex"], SourceEntry::Full(_)));
    }

    #[test]
    fn test_source_access_deserialize() {
        // Test all access levels
        for (input, expected) in [
            ("readonly", SourceAccess::Readonly),
            ("controlplane", SourceAccess::Controlplane),
            ("agent", SourceAccess::Agent),
        ] {
            let toml = format!(
                r#"
[sources]
test = {{ path = "/tmp", access = "{input}" }}
"#
            );
            let config: Config = toml::from_str(&toml).unwrap();
            match &config.sources["test"] {
                SourceEntry::Full(f) => assert_eq!(f.access, expected, "for access={input}"),
                _ => panic!("Expected Full entry"),
            }
        }
    }

    #[test]
    fn test_source_access_default() {
        assert_eq!(SourceAccess::default(), SourceAccess::Controlplane);
    }

    #[test]
    fn test_resolve_sources_absolute_path() {
        let toml = r#"
[sources]
data = "/opt/data"
"#;
        let config: Config = toml::from_str(toml).unwrap();
        let resolved = config.resolve_sources();
        assert_eq!(resolved.len(), 1);
        assert_eq!(resolved[0].name, "data");
        assert_eq!(resolved[0].path, PathBuf::from("/opt/data"));
        assert_eq!(resolved[0].access, SourceAccess::Controlplane);
    }

    #[test]
    fn test_resolve_sources_tilde_expansion() {
        let toml = r#"
[sources]
src = "~/src"
"#;
        let config: Config = toml::from_str(toml).unwrap();
        let resolved = config.resolve_sources();
        assert_eq!(resolved.len(), 1);
        // Should expand ~ using HOME
        let path_str = resolved[0].path.to_str().unwrap();
        assert!(!path_str.starts_with("~/"), "tilde should be expanded");
        assert!(path_str.ends_with("/src"));
    }

    #[test]
    fn test_resolve_sources_full_entry_access() {
        let toml = r#"
[sources]
src = { path = "/opt/src", access = "controlplane" }
"#;
        let config: Config = toml::from_str(toml).unwrap();
        let resolved = config.resolve_sources();
        assert_eq!(resolved.len(), 1);
        assert_eq!(resolved[0].name, "src");
        assert_eq!(resolved[0].path, PathBuf::from("/opt/src"));
        assert_eq!(resolved[0].access, SourceAccess::Controlplane);
    }

    #[test]
    fn test_expand_source_path_absolute() {
        assert_eq!(expand_source_path("/opt/data"), PathBuf::from("/opt/data"));
    }

    #[test]
    fn test_expand_source_path_tilde() {
        let expanded = expand_source_path("~/projects");
        let path_str = expanded.to_str().unwrap();
        assert!(!path_str.starts_with("~/"));
        assert!(path_str.ends_with("/projects"));
    }

    #[test]
    fn test_expand_source_path_no_tilde_prefix() {
        // Only ~/... triggers expansion; bare ~ or ~user does not
        assert_eq!(expand_source_path("~"), PathBuf::from("~"));
        assert_eq!(
            expand_source_path("relative/path"),
            PathBuf::from("relative/path")
        );
    }

    #[test]
    fn test_resolve_source_shorthand_found() {
        let toml = r#"
[sources]
src = "/opt/src"
"#;
        let config: Config = toml::from_str(toml).unwrap();
        let result = resolve_source_shorthand("src:github/org/repo", &config);
        assert_eq!(result, Some(PathBuf::from("/mnt/src/github/org/repo")));
    }

    #[test]
    fn test_resolve_source_shorthand_full_entry() {
        let toml = r#"
[sources]
src = { path = "/opt/src", access = "controlplane" }
"#;
        let config: Config = toml::from_str(toml).unwrap();
        let result = resolve_source_shorthand("src:myproject", &config);
        assert_eq!(result, Some(PathBuf::from("/mnt/src/myproject")));
    }

    #[test]
    fn test_resolve_source_shorthand_not_found() {
        let config: Config = toml::from_str("").unwrap();
        assert_eq!(resolve_source_shorthand("src:foo", &config), None);
    }

    #[test]
    fn test_resolve_source_shorthand_no_colon() {
        let config: Config = toml::from_str("").unwrap();
        assert_eq!(resolve_source_shorthand("no-colon-here", &config), None);
    }

    #[test]
    fn test_validate_source_name_valid() {
        assert!(validate_source_name("src"));
        assert!(validate_source_name("my-sources"));
        assert!(validate_source_name("src_2"));
        assert!(validate_source_name("Projects123"));
        assert!(validate_source_name("a"));
    }

    #[test]
    fn test_validate_source_name_invalid() {
        assert!(!validate_source_name(""));
        assert!(!validate_source_name("has spaces"));
        assert!(!validate_source_name("has/slash"));
        assert!(!validate_source_name("has.dot"));
        assert!(!validate_source_name("special!char"));
    }

    #[test]
    fn test_source_access_serialize() {
        // SourceAccess derives Serialize; verify round-trip
        let access = SourceAccess::Controlplane;
        let json = serde_json::to_string(&access).unwrap();
        assert_eq!(json, r#""controlplane""#);

        let access = SourceAccess::Agent;
        let json = serde_json::to_string(&access).unwrap();
        assert_eq!(json, r#""agent""#);

        let access = SourceAccess::Readonly;
        let json = serde_json::to_string(&access).unwrap();
        assert_eq!(json, r#""readonly""#);
    }

    #[test]
    fn test_sources_with_other_config() {
        // Ensure sources plays well alongside other config sections
        let toml = r#"
default-image = "ghcr.io/devcontainers/base:ubuntu"

[sources]
src = "~/src"
work = { path = "/opt/work", access = "agent" }

[env]
allowlist = ["HOME"]
"#;
        let config: Config = toml::from_str(toml).unwrap();
        assert_eq!(
            config.default_image,
            Some("ghcr.io/devcontainers/base:ubuntu".to_string())
        );
        assert_eq!(config.sources.len(), 2);
        assert_eq!(config.env.allowlist.len(), 1);
    }

    // =========================================================================
    // Bind mount tests
    // =========================================================================

    #[test]
    fn test_bind_default_empty() {
        let config: Config = toml::from_str("").unwrap();
        assert!(config.bind.is_empty());
        assert!(config.resolve_binds().is_empty());
    }

    #[test]
    fn test_bind_parse_basic() {
        let toml = r#"
bind = ["/data:/data", "/cache:/var/cache:ro"]
"#;
        let config: Config = toml::from_str(toml).unwrap();
        assert_eq!(config.bind.len(), 2);

        let resolved = config.resolve_binds();
        assert_eq!(resolved.len(), 2);

        assert_eq!(resolved[0].source, PathBuf::from("/data"));
        assert_eq!(resolved[0].target, "/data");
        assert_eq!(resolved[0].options, "");

        assert_eq!(resolved[1].source, PathBuf::from("/cache"));
        assert_eq!(resolved[1].target, "/var/cache");
        assert_eq!(resolved[1].options, "ro");
    }

    #[test]
    fn test_bind_tilde_expansion() {
        let toml = r#"
bind = ["~/data:/data"]
"#;
        let config: Config = toml::from_str(toml).unwrap();
        let resolved = config.resolve_binds();
        assert_eq!(resolved.len(), 1);
        let path_str = resolved[0].source.to_str().unwrap();
        assert!(!path_str.starts_with("~/"), "tilde should be expanded");
        assert!(path_str.ends_with("/data"));
        assert_eq!(resolved[0].target, "/data");
    }

    #[test]
    fn test_bind_invalid_spec_skipped() {
        let toml = r#"
bind = ["no-colon-here", "/valid:/valid"]
"#;
        let config: Config = toml::from_str(toml).unwrap();
        let resolved = config.resolve_binds();
        // Invalid entry is skipped, valid one kept
        assert_eq!(resolved.len(), 1);
        assert_eq!(resolved[0].target, "/valid");
    }

    #[test]
    fn test_bind_to_podman_arg() {
        let bind = ResolvedBind {
            source: PathBuf::from("/host/path"),
            target: "/container/path".to_string(),
            options: String::new(),
        };
        assert_eq!(bind.to_podman_arg(), "/host/path:/container/path");

        let bind_ro = ResolvedBind {
            source: PathBuf::from("/host"),
            target: "/mnt".to_string(),
            options: "ro".to_string(),
        };
        assert_eq!(bind_ro.to_podman_arg(), "/host:/mnt:ro");

        let bind_opts = ResolvedBind {
            source: PathBuf::from("/host"),
            target: "/mnt".to_string(),
            options: "ro,Z".to_string(),
        };
        assert_eq!(bind_opts.to_podman_arg(), "/host:/mnt:ro,Z");
    }

    #[test]
    fn test_bind_with_sources() {
        // bind and sources coexist
        let toml = r#"
bind = ["/data:/data:ro"]

[sources]
src = "~/src"
"#;
        let config: Config = toml::from_str(toml).unwrap();
        assert_eq!(config.bind.len(), 1);
        assert_eq!(config.sources.len(), 1);

        let binds = config.resolve_binds();
        assert_eq!(binds.len(), 1);
        assert_eq!(binds[0].target, "/data");

        let sources = config.resolve_sources();
        assert_eq!(sources.len(), 1);
        assert_eq!(sources[0].name, "src");
    }

    #[test]
    fn test_bind_after_sources_section_rejected() {
        // If a user puts `bind = [...]` after `[sources]`, TOML scoping makes
        // it `sources.bind` — a source named "bind" with a mangled value.
        // resolve_sources() filters out reserved names to catch this.
        let toml = r#"
[sources]
src = "~/src"

bind = ["/tmp/data:/data:ro"]
"#;
        let config: Config = toml::from_str(toml).unwrap();
        // TOML puts "bind" in sources, not top-level bind
        assert!(config.bind.is_empty(), "top-level bind should be empty");
        assert!(
            config.sources.contains_key("bind"),
            "TOML puts bind in sources"
        );

        // But resolve_sources() rejects the reserved name
        let resolved = config.resolve_sources();
        assert_eq!(resolved.len(), 1, "only 'src' should resolve");
        assert_eq!(resolved[0].name, "src");
    }

    // =========================================================================
    // Agent configuration tests
    // =========================================================================

    #[test]
    fn test_parse_agent_config() {
        let toml = r#"
[agent]
default = "opencode"

[agent.profiles.opencode]
command = ["opencode", "acp"]

[agent.profiles.goose]
command = ["goose", "acp"]
env = { GOOSE_MODE = "auto" }
"#;
        let config: Config = toml::from_str(toml).unwrap();
        assert_eq!(config.agent.default, vec!["opencode"]);
        assert_eq!(config.agent.profiles.len(), 2);

        let oc = &config.agent.profiles["opencode"];
        assert_eq!(oc.command, vec!["opencode", "acp"]);
        assert!(oc.env.is_empty());

        let goose = &config.agent.profiles["goose"];
        assert_eq!(goose.command, vec!["goose", "acp"]);
        assert_eq!(goose.env["GOOSE_MODE"], "auto");
    }

    #[test]
    fn test_parse_agent_config_empty() {
        let config: Config = toml::from_str("").unwrap();
        assert!(config.agent.default.is_empty());
        assert!(config.agent.profiles.is_empty());
    }

    #[test]
    fn test_agent_resolve_profile_cli_override() {
        let mut config = AgentConfig::default();
        config.default = vec!["goose".to_string()];
        config.profiles.insert(
            "opencode".to_string(),
            AgentProfile {
                command: vec!["opencode".to_string(), "acp".to_string()],
                env: HashMap::new(),
            },
        );
        let (name, profile) = config.resolve_profile(Some("opencode"));
        assert_eq!(name, "opencode");
        assert!(profile.is_some());
    }

    #[test]
    fn test_agent_resolve_profile_config_default() {
        let mut config = AgentConfig::default();
        config.default = vec!["goose".to_string()];
        config.profiles.insert(
            "goose".to_string(),
            AgentProfile {
                command: vec!["goose".to_string(), "acp".to_string()],
                env: HashMap::new(),
            },
        );
        let (name, profile) = config.resolve_profile(None);
        assert_eq!(name, "goose");
        assert!(profile.is_some());
    }

    #[test]
    fn test_agent_resolve_profile_hardcoded_fallback() {
        let config = AgentConfig::default();
        let (name, profile) = config.resolve_profile(None);
        assert_eq!(name, "opencode");
        assert!(profile.is_none());
    }

    #[test]
    fn test_expand_tilde_in_env() {
        assert_eq!(
            expand_tilde("~/config/file.json", "/home/dev"),
            "/home/dev/config/file.json"
        );
        assert_eq!(expand_tilde("~", "/home/dev"), "/home/dev");
        assert_eq!(
            expand_tilde("/absolute/path", "/home/dev"),
            "/absolute/path"
        );
        assert_eq!(expand_tilde("relative/path", "/home/dev"), "relative/path");
        assert_eq!(expand_tilde("~user/path", "/home/dev"), "~user/path");
    }

    #[test]
    fn test_parse_agent_config_with_env() {
        let toml = r#"
[agent.profiles.claude]
command = ["claude", "--dangerously-skip-permissions"]
env = { CLAUDE_CONFIG_DIR = "~/.config/devaipod/agents/claude" }
"#;
        let config: Config = toml::from_str(toml).unwrap();
        let claude = &config.agent.profiles["claude"];
        assert_eq!(
            claude.command,
            vec!["claude", "--dangerously-skip-permissions"]
        );
        assert_eq!(
            claude.env["CLAUDE_CONFIG_DIR"],
            "~/.config/devaipod/agents/claude"
        );
    }

    #[test]
    fn test_multiple_agent_profiles_generic_framework() {
        // Prove that the config system is fully generic: multiple agent
        // profiles with different commands and env vars coexist, and
        // resolution works for any of them without agent-specific code.
        let toml = r#"
[agent]
default = "goose"

[agent.profiles.opencode]
command = ["opencode", "acp"]
env = { OPENCODE_CONFIG = "~/.config/opencode/config.json" }

[agent.profiles.goose]
command = ["goose", "acp"]
env = { GOOSE_MODE = "auto", GOOSE_CONFIG_DIR = "~/.config/goose" }

[agent.profiles.claude-code]
command = ["claude", "--dangerously-skip-permissions"]
env = { CLAUDE_CONFIG_DIR = "~/.config/claude" }
"#;
        let config: Config = toml::from_str(toml).unwrap();
        assert_eq!(config.agent.profiles.len(), 3);

        // Default resolves to goose (from config).
        let (name, profile) = config.agent.resolve_profile(None);
        assert_eq!(name, "goose");
        let p = profile.expect("goose profile should exist");
        assert_eq!(p.command, vec!["goose", "acp"]);

        // CLI override to claude-code.
        let (name, profile) = config.agent.resolve_profile(Some("claude-code"));
        assert_eq!(name, "claude-code");
        let p = profile.expect("claude-code profile should exist");
        assert_eq!(p.command, vec!["claude", "--dangerously-skip-permissions"]);

        // CLI override to opencode.
        let (name, profile) = config.agent.resolve_profile(Some("opencode"));
        assert_eq!(name, "opencode");
        let p = profile.expect("opencode profile should exist");
        assert_eq!(p.command, vec!["opencode", "acp"]);

        // All profiles have distinct env vars — no agent-specific parsing.
        assert!(
            config.agent.profiles["goose"]
                .env
                .contains_key("GOOSE_MODE")
        );
        assert_eq!(config.agent.profiles["goose"].env["GOOSE_MODE"], "auto");
        assert!(
            config.agent.profiles["goose"]
                .env
                .contains_key("GOOSE_CONFIG_DIR")
        );
        assert!(
            config.agent.profiles["claude-code"]
                .env
                .contains_key("CLAUDE_CONFIG_DIR")
        );
        assert!(
            config.agent.profiles["opencode"]
                .env
                .contains_key("OPENCODE_CONFIG")
        );

        // Unknown agent name returns (name, None) — caller uses hardcoded
        // fallback, no panic or special handling needed.
        let (name, profile) = config.agent.resolve_profile(Some("nonexistent"));
        assert_eq!(name, "nonexistent");
        assert!(profile.is_none());
    }

    #[test]
    fn test_parse_agent_config_array_default() {
        // Test that default accepts an array of profile names
        let toml = r#"
[agent]
default = ["goose", "opencode"]

[agent.profiles.opencode]
command = ["opencode", "acp"]

[agent.profiles.goose]
command = ["goose", "acp"]
"#;
        let config: Config = toml::from_str(toml).unwrap();
        assert_eq!(config.agent.default, vec!["goose", "opencode"]);

        // First candidate should be goose
        let (name, profile) = config.agent.resolve_profile(None);
        assert_eq!(name, "goose");
        assert!(profile.is_some());
    }

    #[test]
    fn test_agent_candidates_priority_order() {
        let mut config = AgentConfig::default();
        config.default = vec!["goose".to_string(), "opencode".to_string()];
        config.profiles.insert(
            "opencode".to_string(),
            AgentProfile {
                command: vec!["opencode".to_string(), "acp".to_string()],
                env: HashMap::new(),
            },
        );
        config.profiles.insert(
            "goose".to_string(),
            AgentProfile {
                command: vec!["goose".to_string(), "acp".to_string()],
                env: HashMap::new(),
            },
        );

        let candidates = config.candidates();
        assert_eq!(candidates.len(), 2);
        assert_eq!(candidates[0].0, "goose");
        assert_eq!(candidates[1].0, "opencode");
    }

    #[test]
    fn test_agent_candidate_binaries() {
        let mut config = AgentConfig::default();
        config.default = vec!["goose".to_string(), "opencode".to_string()];
        config.profiles.insert(
            "opencode".to_string(),
            AgentProfile {
                command: vec!["opencode".to_string(), "acp".to_string()],
                env: HashMap::new(),
            },
        );
        config.profiles.insert(
            "goose".to_string(),
            AgentProfile {
                command: vec!["goose".to_string(), "acp".to_string()],
                env: HashMap::new(),
            },
        );

        let binaries = config.candidate_binaries();
        assert_eq!(binaries, vec!["goose", "opencode"]);
    }

    #[test]
    fn test_agent_candidates_with_hardcoded_fallback() {
        // When no default is set and no opencode profile exists,
        // candidates should be empty (signaling hardcoded fallback needed)
        let config = AgentConfig::default();
        let candidates = config.candidates();
        assert_eq!(candidates.len(), 0);

        // When opencode profile exists, it should be included even if not in default
        let mut config = AgentConfig::default();
        config.profiles.insert(
            "opencode".to_string(),
            AgentProfile {
                command: vec!["opencode".to_string(), "acp".to_string()],
                env: HashMap::new(),
            },
        );
        let candidates = config.candidates();
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].0, "opencode");
    }

    #[test]
    fn test_parse_agent_config_string_backwards_compat() {
        // Ensure single string still works (backwards compatibility)
        let toml = r#"
[agent]
default = "goose"

[agent.profiles.goose]
command = ["goose", "acp"]
"#;
        let config: Config = toml::from_str(toml).unwrap();
        assert_eq!(config.agent.default, vec!["goose"]);

        let (name, profile) = config.agent.resolve_profile(None);
        assert_eq!(name, "goose");
        assert!(profile.is_some());
    }
}
