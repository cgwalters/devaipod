//! Service-gator MCP server integration
//!
//! This module handles configuring the service-gator MCP server
//! which provides scope-restricted access to external services (GitHub, JIRA)
//! for AI agents running in containers.

use std::time::{SystemTime, UNIX_EPOCH};

use color_eyre::eyre::{bail, Result};
use serde::{Deserialize, Serialize};

use crate::config::{GhRepoPermission, GlProjectPermission, ServiceGatorConfig};

/// Parse CLI service-gator scope strings into a ServiceGatorConfig
///
/// Scope format: `service:target[:permissions]`
///
/// Examples:
/// - `github:readonly-all` - Read-only access to all GitHub repos
/// - `github:owner/repo` - Read access to a specific repo (default permission is read)
/// - `github:owner/*` - Read access to all repos under an owner
/// - `github:owner/repo:write` - Write access to a specific repo
/// - `github:owner/repo:read,create-draft` - Multiple permissions
///
/// Supported services:
/// - `github` or `gh`: GitHub repos
///
/// Supported permissions for GitHub:
/// - `read`: Read-only access (default)
/// - `create-draft`: Can create draft PRs
/// - `pending-review`: Can create pending PR reviews
/// - `write`: Full write access
pub fn parse_scopes(scopes: &[String]) -> Result<ServiceGatorConfig> {
    let mut config = ServiceGatorConfig::default();

    for scope in scopes {
        parse_single_scope(scope, &mut config)?;
    }

    // If any scopes were parsed, enable service-gator
    if !config.gh.repos.is_empty()
        || !config.gh.prs.is_empty()
        || !config.gitlab.projects.is_empty()
        || !config.jira.projects.is_empty()
    {
        config.enabled = Some(true);
    }

    Ok(config)
}

/// Parse a single scope string into the config
fn parse_single_scope(scope: &str, config: &mut ServiceGatorConfig) -> Result<()> {
    // Split into service:rest
    let (service, rest) = scope.split_once(':').ok_or_else(|| {
        color_eyre::eyre::eyre!(
            "Invalid scope format: '{}'. Expected 'service:target[:permissions]'",
            scope
        )
    })?;

    match service.to_lowercase().as_str() {
        "github" | "gh" => parse_github_scope(rest, config),
        "gitlab" | "gl" => parse_gitlab_scope(rest, config),
        "jira" => {
            // TODO: Add JIRA support
            bail!("JIRA scopes not yet supported in CLI: {}", scope);
        }
        other => {
            bail!(
                "Unknown service '{}' in scope '{}'. Supported: github, gitlab, jira",
                other,
                scope
            );
        }
    }
}

/// Parse a GitHub scope like `readonly-all`, `owner/repo`, or `owner/repo:write`
fn parse_github_scope(rest: &str, config: &mut ServiceGatorConfig) -> Result<()> {
    // Check for special keywords
    if rest == "readonly-all" || rest == "read-all" {
        // Grant read-only access to all repos
        config.gh.repos.insert(
            "*/*".to_string(),
            GhRepoPermission {
                read: true,
                ..Default::default()
            },
        );
        return Ok(());
    }

    // Parse target:permissions or just target
    let (target, perms_str) = if let Some((t, p)) = rest.rsplit_once(':') {
        // Check if this is actually owner/repo format or owner/repo:perms
        // The tricky part is distinguishing "owner/repo:write" from "owner/repo"
        // If the part after : looks like permissions, use it; otherwise treat as target only
        if is_permission_string(p) {
            (t, Some(p))
        } else {
            // No permissions specified, treat whole thing as target
            (rest, None)
        }
    } else {
        (rest, None)
    };

    // Parse permissions
    let permission = if let Some(perms) = perms_str {
        parse_github_permissions(perms)?
    } else {
        // Default to read-only
        GhRepoPermission {
            read: true,
            ..Default::default()
        }
    };

    // Validate target format (owner/repo or owner/*)
    if !target.contains('/') {
        bail!(
            "Invalid GitHub target '{}'. Expected 'owner/repo' or 'owner/*' format",
            target
        );
    }

    config.gh.repos.insert(target.to_string(), permission);
    Ok(())
}

/// Parse a GitLab scope like `readonly-all`, `group/project`, or `group/project:write`
fn parse_gitlab_scope(rest: &str, config: &mut ServiceGatorConfig) -> Result<()> {
    if rest == "readonly-all" || rest == "read-all" {
        config.gitlab.projects.insert(
            "*/*".to_string(),
            GlProjectPermission {
                read: true,
                ..Default::default()
            },
        );
        return Ok(());
    }

    let (target, perms_str) = if let Some((t, p)) = rest.rsplit_once(':') {
        if is_permission_string(p) {
            (t, Some(p))
        } else {
            (rest, None)
        }
    } else {
        (rest, None)
    };

    let permission = if let Some(perms) = perms_str {
        parse_gitlab_permissions(perms)?
    } else {
        GlProjectPermission {
            read: true,
            ..Default::default()
        }
    };

    if !target.contains('/') {
        bail!(
            "Invalid GitLab target '{}'. Expected 'group/project' or 'group/*' format",
            target
        );
    }

    config.gitlab.projects.insert(target.to_string(), permission);
    Ok(())
}

/// Parse comma-separated permission string into GlProjectPermission
fn parse_gitlab_permissions(perms: &str) -> Result<GlProjectPermission> {
    let mut permission = GlProjectPermission::default();

    for perm in perms.split(',') {
        match perm.trim().to_lowercase().as_str() {
            "read" => permission.read = true,
            "write" => {
                permission.read = true;
                permission.write = true;
            }
            "create-draft" | "draft" => {
                permission.read = true;
                permission.create_draft = true;
            }
            "approve" => {
                permission.read = true;
                permission.approve = true;
            }
            "push-new-branch" | "push" => {
                permission.read = true;
                permission.push_new_branch = true;
            }
            other => {
                bail!(
                    "Unknown GitLab permission '{}'. Supported: read, write, create-draft, approve, push-new-branch",
                    other
                );
            }
        }
    }

    Ok(permission)
}

/// Check if a string looks like a permission specification
fn is_permission_string(s: &str) -> bool {
    let known_perms = [
        "read",
        "write",
        "create-draft",
        "draft",
        "pending-review",
        "review",
        "push-new-branch",
        "push",
        "approve",
    ];
    s.split(',')
        .all(|p| known_perms.contains(&p.trim().to_lowercase().as_str()))
}

/// Parse comma-separated permission string into GhRepoPermission
fn parse_github_permissions(perms: &str) -> Result<GhRepoPermission> {
    let mut permission = GhRepoPermission::default();

    for perm in perms.split(',') {
        match perm.trim().to_lowercase().as_str() {
            "read" => permission.read = true,
            "write" => {
                permission.read = true; // write implies read
                permission.write = true;
            }
            "create-draft" | "draft" => {
                permission.read = true; // create-draft implies read
                permission.create_draft = true;
            }
            "pending-review" | "review" => {
                permission.read = true; // pending-review implies read
                permission.pending_review = true;
            }
            "push-new-branch" | "push" => {
                permission.read = true; // push-new-branch implies read
                permission.push_new_branch = true;
            }
            other => {
                bail!(
                    "Unknown GitHub permission '{}'. Supported: read, write, create-draft, pending-review, push-new-branch",
                    other
                );
            }
        }
    }

    Ok(permission)
}

/// Merge CLI scopes with file-based config
///
/// CLI scopes take precedence (are merged on top of) file config.
pub fn merge_configs(
    file_config: &ServiceGatorConfig,
    cli_config: &ServiceGatorConfig,
) -> ServiceGatorConfig {
    let mut merged = file_config.clone();

    // CLI explicitly enabled/disabled takes precedence
    if cli_config.enabled.is_some() {
        merged.enabled = cli_config.enabled;
    }

    // CLI port takes precedence
    if cli_config.port.is_some() {
        merged.port = cli_config.port;
    }

    // Merge GitHub repos (CLI overwrites same keys)
    for (key, value) in &cli_config.gh.repos {
        merged.gh.repos.insert(key.clone(), value.clone());
    }

    // Merge GitHub PRs
    for (key, value) in &cli_config.gh.prs {
        merged.gh.prs.insert(key.clone(), value.clone());
    }

    // Merge GitHub issues
    for (key, value) in &cli_config.gh.issues {
        merged.gh.issues.insert(key.clone(), value.clone());
    }

    // Merge GitLab projects
    for (key, value) in &cli_config.gitlab.projects {
        merged.gitlab.projects.insert(key.clone(), value.clone());
    }

    // Merge GitLab MRs
    for (key, value) in &cli_config.gitlab.mrs {
        merged.gitlab.mrs.insert(key.clone(), value.clone());
    }

    // Merge GitLab issues
    for (key, value) in &cli_config.gitlab.issues {
        merged.gitlab.issues.insert(key.clone(), value.clone());
    }

    // Merge GitLab host (CLI wins)
    if cli_config.gitlab.host.is_some() {
        merged.gitlab.host = cli_config.gitlab.host.clone();
    }

    // Merge JIRA projects
    for (key, value) in &cli_config.jira.projects {
        merged.jira.projects.insert(key.clone(), value.clone());
    }

    // Merge JIRA issues
    for (key, value) in &cli_config.jira.issues {
        merged.jira.issues.insert(key.clone(), value.clone());
    }

    merged
}

/// Generate command-line arguments for service-gator from a config
///
/// Returns the arguments to pass to the service-gator container command.
pub fn config_to_cli_args(config: &ServiceGatorConfig) -> Vec<String> {
    let mut args = Vec::new();

    // Handle global GitHub read flag - translates to */*:read wildcard
    if config.gh.read {
        args.push("--gh-repo".to_string());
        args.push("*/*:read".to_string());
    }

    // Add GitHub repo scopes
    for (pattern, perm) in &config.gh.repos {
        let mut perms = Vec::new();
        if perm.read {
            perms.push("read");
        }
        if perm.push_new_branch {
            perms.push("push-new-branch");
        }
        if perm.create_draft {
            perms.push("create-draft");
        }
        if perm.pending_review {
            perms.push("pending-review");
        }
        if perm.write {
            perms.push("write");
        }
        if !perms.is_empty() {
            args.push("--gh-repo".to_string());
            args.push(format!("{}:{}", pattern, perms.join(",")));
        }
    }

    // Add GitLab host if configured
    if let Some(ref host) = config.gitlab.host {
        args.push("--gitlab-host".to_string());
        args.push(host.clone());
    }

    // Add GitLab project scopes
    for (pattern, perm) in &config.gitlab.projects {
        let mut perms = Vec::new();
        if perm.read {
            perms.push("read");
        }
        if perm.push_new_branch {
            perms.push("push-new-branch");
        }
        if perm.create_draft {
            perms.push("create-draft");
        }
        if perm.approve {
            perms.push("approve");
        }
        if perm.write {
            perms.push("write");
        }
        if !perms.is_empty() {
            args.push("--gitlab-project".to_string());
            args.push(format!("{}:{}", pattern, perms.join(",")));
        }
    }

    // Add JIRA project scopes
    for (project, perm) in &config.jira.projects {
        let mut perms = Vec::new();
        if perm.read {
            perms.push("read");
        }
        if perm.create {
            perms.push("create");
        }
        if perm.write {
            perms.push("write");
        }
        if !perms.is_empty() {
            args.push("--jira-project".to_string());
            args.push(format!("{}:{}", project, perms.join(",")));
        }
    }

    args
}

// =============================================================================
// JWT Token Generation (unused - kept for potential future use)
// =============================================================================

/// Default token lifetime: 30 days (in seconds)
#[allow(dead_code)]
pub const DEFAULT_TOKEN_EXPIRES_IN: u64 = 30 * 24 * 3600;

/// Scope configuration for JWT tokens (matches service-gator's ScopeConfig)
///
/// This is the format expected by service-gator's JWT token `scopes` field.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct JwtScopeConfig {
    #[serde(default, skip_serializing_if = "JwtGithubScope::is_empty")]
    pub gh: JwtGithubScope,
    #[serde(default, skip_serializing_if = "JwtGitLabScope::is_empty")]
    pub gitlab: JwtGitLabScope,
}

/// GitHub scope for JWT tokens
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct JwtGithubScope {
    /// Global read access for all GitHub API endpoints
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub read: bool,
    /// Repository permissions
    #[serde(default, skip_serializing_if = "std::collections::HashMap::is_empty")]
    pub repos: std::collections::HashMap<String, JwtGhRepoPermission>,
}

impl JwtGithubScope {
    fn is_empty(&self) -> bool {
        !self.read && self.repos.is_empty()
    }
}

/// GitHub repo permission for JWT tokens
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct JwtGhRepoPermission {
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub read: bool,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub create_draft: bool,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub pending_review: bool,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub push_new_branch: bool,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub write: bool,
}

impl From<&GhRepoPermission> for JwtGhRepoPermission {
    fn from(p: &GhRepoPermission) -> Self {
        Self {
            read: p.read,
            create_draft: p.create_draft,
            pending_review: p.pending_review,
            push_new_branch: p.push_new_branch,
            write: p.write,
        }
    }
}

/// GitLab scope for JWT tokens
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct JwtGitLabScope {
    /// Project permissions
    #[serde(default, skip_serializing_if = "std::collections::HashMap::is_empty")]
    pub projects: std::collections::HashMap<String, JwtGlProjectPermission>,
    /// Host for self-hosted instances
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
}

impl JwtGitLabScope {
    fn is_empty(&self) -> bool {
        self.projects.is_empty() && self.host.is_none()
    }
}

/// GitLab project permission for JWT tokens
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct JwtGlProjectPermission {
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub read: bool,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub create_draft: bool,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub approve: bool,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub push_new_branch: bool,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub write: bool,
}

impl From<&GlProjectPermission> for JwtGlProjectPermission {
    fn from(p: &GlProjectPermission) -> Self {
        Self {
            read: p.read,
            create_draft: p.create_draft,
            approve: p.approve,
            push_new_branch: p.push_new_branch,
            write: p.write,
        }
    }
}

/// JWT claims for service-gator tokens (unused - kept for potential future use)
#[allow(dead_code)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenClaims {
    /// Issued-at timestamp (Unix seconds)
    pub iat: u64,
    /// Expiration timestamp (Unix seconds)
    pub exp: u64,
    /// The scopes this token grants
    pub scopes: JwtScopeConfig,
    /// Optional subject identifier (for logging/audit)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sub: Option<String>,
    /// Whether this token can call /token/rotate
    #[serde(default = "default_can_rotate")]
    pub can_rotate: bool,
}

#[allow(dead_code)]
fn default_can_rotate() -> bool {
    true
}

/// Get current Unix timestamp
fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time before Unix epoch")
        .as_secs()
}

/// Convert ServiceGatorConfig to JWT scope config
pub fn config_to_jwt_scopes(config: &ServiceGatorConfig) -> JwtScopeConfig {
    let mut gh = JwtGithubScope::default();

    // Map global read
    gh.read = config.gh.read;

    // Map repo permissions
    for (pattern, perm) in &config.gh.repos {
        gh.repos
            .insert(pattern.clone(), JwtGhRepoPermission::from(perm));
    }

    let mut gitlab = JwtGitLabScope::default();

    // Map GitLab project permissions
    for (pattern, perm) in &config.gitlab.projects {
        gitlab
            .projects
            .insert(pattern.clone(), JwtGlProjectPermission::from(perm));
    }
    gitlab.host = config.gitlab.host.clone();

    JwtScopeConfig { gh, gitlab }
}

/// Mint a JWT token for service-gator (unused - kept for potential future use)
///
/// This generates a signed JWT token that can be used to authenticate
/// with service-gator's MCP endpoint.
///
/// # Arguments
/// * `secret` - The JWT signing secret (SERVICE_GATOR_SECRET)
/// * `config` - The service-gator scope configuration
/// * `expires_in` - Token lifetime in seconds (default: 30 days)
/// * `subject` - Optional subject identifier for logging
#[allow(dead_code)]
pub fn mint_token(
    secret: &str,
    config: &ServiceGatorConfig,
    expires_in: Option<u64>,
    subject: Option<&str>,
) -> Result<String> {
    use jsonwebtoken::{encode, EncodingKey, Header};

    let now = now_unix();
    let exp = now + expires_in.unwrap_or(DEFAULT_TOKEN_EXPIRES_IN);

    let claims = TokenClaims {
        iat: now,
        exp,
        scopes: config_to_jwt_scopes(config),
        sub: subject.map(|s| s.to_string()),
        can_rotate: true,
    };

    let token = encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(secret.as_bytes()),
    )
    .map_err(|e| color_eyre::eyre::eyre!("Failed to sign JWT token: {}", e))?;

    Ok(token)
}

/// Mint a JWT token from a JwtScopeConfig directly (unused - kept for potential future use)
///
/// This is used when we have already-parsed scopes (e.g., from editing).
#[allow(dead_code)]
pub fn mint_token_from_scopes(
    secret: &str,
    scopes: &JwtScopeConfig,
    expires_in: Option<u64>,
    subject: Option<&str>,
) -> Result<String> {
    use jsonwebtoken::{encode, EncodingKey, Header};

    let now = now_unix();
    let exp = now + expires_in.unwrap_or(DEFAULT_TOKEN_EXPIRES_IN);

    let claims = TokenClaims {
        iat: now,
        exp,
        scopes: scopes.clone(),
        sub: subject.map(|s| s.to_string()),
        can_rotate: true,
    };

    let token = encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(secret.as_bytes()),
    )
    .map_err(|e| color_eyre::eyre::eyre!("Failed to sign JWT token: {}", e))?;

    Ok(token)
}

// =============================================================================
// Persistent Gator Configuration
// =============================================================================

/// Path to the gator config file within the agent home volume
///
/// This file stores scopes persistently, allowing `devaipod gator add/edit`
/// to update scopes that survive restarts. Gator watches this file via
/// inotify and reloads automatically when it changes.
pub const GATOR_CONFIG_PATH: &str = ".devaipod/gator-config.json";

/// Persistent gator configuration stored in the workspace volume
///
/// This is written at pod creation and updated by `devaipod gator add/edit`.
/// Gator watches this file via inotify for live reload.
///
/// The format matches what service-gator expects for --scope-file:
/// ```json
/// {
///   "scopes": {
///     "gh": { "repos": { "owner/repo": { "read": true } } }
///   }
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GatorConfigFile {
    /// Current scope configuration
    pub scopes: JwtScopeConfig,
    /// When this config was last updated (Unix timestamp)
    #[serde(default, skip_serializing_if = "is_zero")]
    pub updated_at: u64,
}

fn is_zero(n: &u64) -> bool {
    *n == 0
}

impl GatorConfigFile {
    /// Create a new gator config file
    pub fn new(scopes: JwtScopeConfig) -> Self {
        Self {
            scopes,
            updated_at: now_unix(),
        }
    }

    /// Update the scopes and timestamp
    pub fn update_scopes(&mut self, scopes: JwtScopeConfig) {
        self.scopes = scopes;
        self.updated_at = now_unix();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_scope_readonly_all() {
        let scopes = vec!["github:readonly-all".to_string()];
        let config = parse_scopes(&scopes).unwrap();

        assert!(config.is_enabled());
        assert!(config.gh.repos.contains_key("*/*"));
        let perm = &config.gh.repos["*/*"];
        assert!(perm.read);
        assert!(!perm.write);
        assert!(!perm.create_draft);
    }

    #[test]
    fn test_parse_scope_specific_repo() {
        let scopes = vec!["github:myorg/myrepo".to_string()];
        let config = parse_scopes(&scopes).unwrap();

        assert!(config.is_enabled());
        assert!(config.gh.repos.contains_key("myorg/myrepo"));
        let perm = &config.gh.repos["myorg/myrepo"];
        assert!(perm.read);
        assert!(!perm.write);
    }

    #[test]
    fn test_parse_scope_wildcard_repo() {
        let scopes = vec!["github:myorg/*".to_string()];
        let config = parse_scopes(&scopes).unwrap();

        assert!(config.gh.repos.contains_key("myorg/*"));
        assert!(config.gh.repos["myorg/*"].read);
    }

    #[test]
    fn test_parse_scope_with_write_permission() {
        let scopes = vec!["github:myorg/myrepo:write".to_string()];
        let config = parse_scopes(&scopes).unwrap();

        let perm = &config.gh.repos["myorg/myrepo"];
        assert!(perm.read); // write implies read
        assert!(perm.write);
    }

    #[test]
    fn test_parse_scope_multiple_permissions() {
        let scopes = vec!["github:myorg/myrepo:read,create-draft,pending-review".to_string()];
        let config = parse_scopes(&scopes).unwrap();

        let perm = &config.gh.repos["myorg/myrepo"];
        assert!(perm.read);
        assert!(perm.create_draft);
        assert!(perm.pending_review);
        assert!(!perm.write);
    }

    #[test]
    fn test_parse_scope_gh_alias() {
        let scopes = vec!["gh:myorg/myrepo".to_string()];
        let config = parse_scopes(&scopes).unwrap();

        assert!(config.gh.repos.contains_key("myorg/myrepo"));
    }

    #[test]
    fn test_parse_multiple_scopes() {
        let scopes = vec![
            "github:org1/repo1".to_string(),
            "github:org2/repo2:write".to_string(),
            "github:org3/*".to_string(),
        ];
        let config = parse_scopes(&scopes).unwrap();

        assert_eq!(config.gh.repos.len(), 3);
        assert!(config.gh.repos["org1/repo1"].read);
        assert!(config.gh.repos["org2/repo2"].write);
        assert!(config.gh.repos["org3/*"].read);
    }

    #[test]
    fn test_parse_scope_invalid_format() {
        let scopes = vec!["invalid".to_string()];
        assert!(parse_scopes(&scopes).is_err());
    }

    #[test]
    fn test_parse_scope_invalid_target() {
        let scopes = vec!["github:invalid_no_slash".to_string()];
        assert!(parse_scopes(&scopes).is_err());
    }

    #[test]
    fn test_merge_configs() {
        let mut file_config = ServiceGatorConfig::default();
        file_config.gh.repos.insert(
            "file/repo".to_string(),
            GhRepoPermission {
                read: true,
                ..Default::default()
            },
        );

        let mut cli_config = ServiceGatorConfig::default();
        cli_config.gh.repos.insert(
            "cli/repo".to_string(),
            GhRepoPermission {
                read: true,
                write: true,
                ..Default::default()
            },
        );
        cli_config.enabled = Some(true);

        let merged = merge_configs(&file_config, &cli_config);

        // Both repos should be present
        assert!(merged.gh.repos.contains_key("file/repo"));
        assert!(merged.gh.repos.contains_key("cli/repo"));
        // CLI enabled should take precedence
        assert_eq!(merged.enabled, Some(true));
    }

    #[test]
    fn test_config_to_cli_args() {
        let mut config = ServiceGatorConfig::default();
        config.gh.repos.insert(
            "myorg/myrepo".to_string(),
            GhRepoPermission {
                read: true,
                create_draft: true,
                ..Default::default()
            },
        );

        let args = config_to_cli_args(&config);
        assert!(args.contains(&"--gh-repo".to_string()));
        // The order of permissions in the string may vary, so just check it contains expected parts
        let repo_arg = args.iter().find(|a| a.contains("myorg/myrepo")).unwrap();
        assert!(repo_arg.contains("read"));
        assert!(repo_arg.contains("create-draft"));
    }

    #[test]
    fn test_config_to_cli_args_global_read() {
        // Test that gh.read = true generates */*:read
        let mut config = ServiceGatorConfig::default();
        config.gh.read = true;

        let args = config_to_cli_args(&config);
        assert_eq!(args.len(), 2);
        assert_eq!(args[0], "--gh-repo");
        assert_eq!(args[1], "*/*:read");
    }

    #[test]
    fn test_config_to_cli_args_global_read_with_repos() {
        // Test that gh.read = true works alongside specific repo overrides
        let mut config = ServiceGatorConfig::default();
        config.gh.read = true;
        config.gh.repos.insert(
            "myorg/myrepo".to_string(),
            GhRepoPermission {
                read: true,
                create_draft: true,
                ..Default::default()
            },
        );

        let args = config_to_cli_args(&config);
        // Should have both the global */*:read and the specific repo
        assert!(args.contains(&"--gh-repo".to_string()));
        assert!(args.contains(&"*/*:read".to_string()));
        let repo_arg = args.iter().find(|a| a.contains("myorg/myrepo")).unwrap();
        assert!(repo_arg.contains("create-draft"));
    }

    #[test]
    fn test_parse_scope_push_new_branch() {
        let scopes = vec!["github:myorg/myrepo:push-new-branch".to_string()];
        let config = parse_scopes(&scopes).unwrap();

        let perm = &config.gh.repos["myorg/myrepo"];
        assert!(perm.read); // push-new-branch implies read
        assert!(perm.push_new_branch);
        assert!(!perm.create_draft);
        assert!(!perm.write);
    }

    #[test]
    fn test_parse_scope_push_alias() {
        // "push" is a short alias for "push-new-branch"
        let scopes = vec!["github:myorg/myrepo:push".to_string()];
        let config = parse_scopes(&scopes).unwrap();

        let perm = &config.gh.repos["myorg/myrepo"];
        assert!(perm.push_new_branch);
    }

    #[test]
    fn test_parse_scope_combined_permissions() {
        let scopes = vec!["github:myorg/myrepo:read,push-new-branch,create-draft".to_string()];
        let config = parse_scopes(&scopes).unwrap();

        let perm = &config.gh.repos["myorg/myrepo"];
        assert!(perm.read);
        assert!(perm.push_new_branch);
        assert!(perm.create_draft);
        assert!(!perm.pending_review);
        assert!(!perm.write);
    }

    #[test]
    fn test_config_to_cli_args_push_new_branch() {
        let mut config = ServiceGatorConfig::default();
        config.gh.repos.insert(
            "myorg/myrepo".to_string(),
            GhRepoPermission {
                read: true,
                push_new_branch: true,
                create_draft: false,
                ..Default::default()
            },
        );

        let args = config_to_cli_args(&config);
        let repo_arg = args.iter().find(|a| a.contains("myorg/myrepo")).unwrap();
        assert!(repo_arg.contains("read"));
        assert!(repo_arg.contains("push-new-branch"));
        assert!(!repo_arg.contains("create-draft"));
    }

    #[test]
    fn test_config_to_cli_args_push_and_draft() {
        // When both push_new_branch and create_draft are true, both should be emitted
        let mut config = ServiceGatorConfig::default();
        config.gh.repos.insert(
            "myorg/myrepo".to_string(),
            GhRepoPermission {
                read: true,
                push_new_branch: true,
                create_draft: true,
                ..Default::default()
            },
        );

        let args = config_to_cli_args(&config);
        let repo_arg = args.iter().find(|a| a.contains("myorg/myrepo")).unwrap();
        assert!(repo_arg.contains("read"));
        assert!(repo_arg.contains("push-new-branch"));
        assert!(repo_arg.contains("create-draft"));
    }

    #[test]
    fn test_mint_token() {
        let mut config = ServiceGatorConfig::default();
        config.gh.repos.insert(
            "myorg/myrepo".to_string(),
            GhRepoPermission {
                read: true,
                push_new_branch: true,
                create_draft: true,
                ..Default::default()
            },
        );

        let secret = "test-secret-key-for-testing-12345";
        let token = mint_token(secret, &config, Some(3600), Some("test-agent")).unwrap();

        // Token should be a valid JWT (three parts separated by dots)
        assert_eq!(token.split('.').count(), 3);

        // Verify we can decode it
        use jsonwebtoken::{decode, DecodingKey, Validation};
        let mut validation = Validation::new(jsonwebtoken::Algorithm::HS256);
        validation.validate_exp = false; // Don't validate exp for test
        validation.required_spec_claims.clear();

        let decoded = decode::<TokenClaims>(
            &token,
            &DecodingKey::from_secret(secret.as_bytes()),
            &validation,
        )
        .expect("token should decode");

        assert_eq!(decoded.claims.sub, Some("test-agent".to_string()));
        assert!(decoded.claims.can_rotate);
        assert!(decoded.claims.scopes.gh.repos.contains_key("myorg/myrepo"));

        let repo_perm = &decoded.claims.scopes.gh.repos["myorg/myrepo"];
        assert!(repo_perm.read);
        assert!(repo_perm.push_new_branch);
        assert!(repo_perm.create_draft);
        assert!(!repo_perm.write);
    }

    #[test]
    fn test_config_to_jwt_scopes() {
        let mut config = ServiceGatorConfig::default();
        config.gh.read = true;
        config.gh.repos.insert(
            "myorg/myrepo".to_string(),
            GhRepoPermission {
                read: true,
                write: true,
                ..Default::default()
            },
        );

        let scopes = config_to_jwt_scopes(&config);
        assert!(scopes.gh.read);
        assert!(scopes.gh.repos.contains_key("myorg/myrepo"));
        assert!(scopes.gh.repos["myorg/myrepo"].write);
    }

    // =========================================================================
    // GitLab scope tests
    // =========================================================================

    #[test]
    fn test_parse_gitlab_scope_readonly_all() {
        let scopes = vec!["gitlab:readonly-all".to_string()];
        let config = parse_scopes(&scopes).unwrap();

        assert!(config.is_enabled());
        assert!(config.gitlab.projects.contains_key("*/*"));
        let perm = &config.gitlab.projects["*/*"];
        assert!(perm.read);
        assert!(!perm.write);
    }

    #[test]
    fn test_parse_gitlab_scope_specific_project() {
        let scopes = vec!["gitlab:mygroup/myproject".to_string()];
        let config = parse_scopes(&scopes).unwrap();

        assert!(config.is_enabled());
        assert!(config.gitlab.projects.contains_key("mygroup/myproject"));
        let perm = &config.gitlab.projects["mygroup/myproject"];
        assert!(perm.read);
        assert!(!perm.write);
    }

    #[test]
    fn test_parse_gitlab_scope_gl_alias() {
        let scopes = vec!["gl:mygroup/myproject".to_string()];
        let config = parse_scopes(&scopes).unwrap();
        assert!(config.gitlab.projects.contains_key("mygroup/myproject"));
    }

    #[test]
    fn test_parse_gitlab_scope_with_permissions() {
        let scopes = vec!["gitlab:mygroup/myproject:read,create-draft,approve".to_string()];
        let config = parse_scopes(&scopes).unwrap();

        let perm = &config.gitlab.projects["mygroup/myproject"];
        assert!(perm.read);
        assert!(perm.create_draft);
        assert!(perm.approve);
        assert!(!perm.push_new_branch);
        assert!(!perm.write);
    }

    #[test]
    fn test_parse_gitlab_scope_write() {
        let scopes = vec!["gitlab:mygroup/myproject:write".to_string()];
        let config = parse_scopes(&scopes).unwrap();

        let perm = &config.gitlab.projects["mygroup/myproject"];
        assert!(perm.read); // write implies read
        assert!(perm.write);
    }

    #[test]
    fn test_parse_gitlab_scope_wildcard() {
        let scopes = vec!["gitlab:mygroup/*".to_string()];
        let config = parse_scopes(&scopes).unwrap();
        assert!(config.gitlab.projects.contains_key("mygroup/*"));
        assert!(config.gitlab.projects["mygroup/*"].read);
    }

    #[test]
    fn test_parse_gitlab_scope_invalid_target() {
        let scopes = vec!["gitlab:no_slash".to_string()];
        assert!(parse_scopes(&scopes).is_err());
    }

    #[test]
    fn test_parse_mixed_github_gitlab_scopes() {
        let scopes = vec![
            "github:owner/repo:read".to_string(),
            "gitlab:group/project:read,create-draft".to_string(),
        ];
        let config = parse_scopes(&scopes).unwrap();

        assert!(config.gh.repos.contains_key("owner/repo"));
        assert!(config.gitlab.projects.contains_key("group/project"));
        assert!(config.gitlab.projects["group/project"].create_draft);
    }

    #[test]
    fn test_config_to_cli_args_gitlab_project() {
        let mut config = ServiceGatorConfig::default();
        config.gitlab.projects.insert(
            "mygroup/myproject".to_string(),
            GlProjectPermission {
                read: true,
                create_draft: true,
                ..Default::default()
            },
        );

        let args = config_to_cli_args(&config);
        assert!(args.contains(&"--gitlab-project".to_string()));
        let project_arg = args
            .iter()
            .find(|a| a.contains("mygroup/myproject"))
            .unwrap();
        assert!(project_arg.contains("read"));
        assert!(project_arg.contains("create-draft"));
    }

    #[test]
    fn test_config_to_cli_args_gitlab_host() {
        let mut config = ServiceGatorConfig::default();
        config.gitlab.host = Some("gitlab.example.com".to_string());
        config.gitlab.projects.insert(
            "group/project".to_string(),
            GlProjectPermission {
                read: true,
                ..Default::default()
            },
        );

        let args = config_to_cli_args(&config);
        assert!(args.contains(&"--gitlab-host".to_string()));
        assert!(args.contains(&"gitlab.example.com".to_string()));
    }

    #[test]
    fn test_merge_configs_gitlab() {
        let mut file_config = ServiceGatorConfig::default();
        file_config.gitlab.projects.insert(
            "file/project".to_string(),
            GlProjectPermission {
                read: true,
                ..Default::default()
            },
        );

        let mut cli_config = ServiceGatorConfig::default();
        cli_config.gitlab.projects.insert(
            "cli/project".to_string(),
            GlProjectPermission {
                read: true,
                write: true,
                ..Default::default()
            },
        );
        cli_config.gitlab.host = Some("gitlab.corp.com".to_string());

        let merged = merge_configs(&file_config, &cli_config);
        assert!(merged.gitlab.projects.contains_key("file/project"));
        assert!(merged.gitlab.projects.contains_key("cli/project"));
        assert_eq!(
            merged.gitlab.host,
            Some("gitlab.corp.com".to_string())
        );
    }

    #[test]
    fn test_config_to_jwt_scopes_gitlab() {
        let mut config = ServiceGatorConfig::default();
        config.gitlab.projects.insert(
            "group/project".to_string(),
            GlProjectPermission {
                read: true,
                create_draft: true,
                ..Default::default()
            },
        );
        config.gitlab.host = Some("gitlab.example.com".to_string());

        let scopes = config_to_jwt_scopes(&config);
        assert!(scopes.gitlab.projects.contains_key("group/project"));
        assert!(scopes.gitlab.projects["group/project"].read);
        assert!(scopes.gitlab.projects["group/project"].create_draft);
        assert_eq!(scopes.gitlab.host, Some("gitlab.example.com".to_string()));
    }
}
