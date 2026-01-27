//! Service-gator MCP server integration
//!
//! This module handles starting and configuring the service-gator MCP server
//! which provides scope-restricted access to external services (GitHub, JIRA)
//! for AI agents running in the bwrap sandbox.

use std::path::{Path, PathBuf};
use std::process::Command as ProcessCommand;

use color_eyre::eyre::{bail, Context, Result};

use crate::config::{
    generate_service_gator_toml, GhRepoPermission, ServiceGatorConfig, SERVICE_GATOR_DEFAULT_PORT,
};

/// Path to the service-gator config file (inside the container, outside the sandbox)
const SERVICE_GATOR_CONFIG_PATH: &str = "/var/run/devaipod/service-gator.toml";

/// Path to the service-gator socket/state directory
const SERVICE_GATOR_RUN_DIR: &str = "/var/run/devaipod";

/// Path to the service-gator PID file
const SERVICE_GATOR_PID_FILE: &str = "/var/run/devaipod/service-gator.pid";

/// Write the service-gator configuration file
pub fn write_config(config: &ServiceGatorConfig) -> Result<PathBuf> {
    let config_path = Path::new(SERVICE_GATOR_CONFIG_PATH);
    let run_dir = Path::new(SERVICE_GATOR_RUN_DIR);

    // Create the run directory if it doesn't exist
    std::fs::create_dir_all(run_dir)
        .with_context(|| format!("Failed to create {}", run_dir.display()))?;

    // Generate and write the config
    let toml_content = generate_service_gator_toml(config);
    std::fs::write(config_path, &toml_content)
        .with_context(|| format!("Failed to write {}", config_path.display()))?;

    tracing::info!("Wrote service-gator config to {}", config_path.display());
    Ok(config_path.to_path_buf())
}

/// Check if service-gator is available (binary exists)
pub fn is_available() -> bool {
    ProcessCommand::new("service-gator")
        .arg("--version")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Check if service-gator is already running
pub fn is_running() -> bool {
    let pid_file = Path::new(SERVICE_GATOR_PID_FILE);
    if !pid_file.exists() {
        return false;
    }

    // Read PID and check if process exists
    if let Ok(pid_str) = std::fs::read_to_string(pid_file) {
        if let Ok(pid) = pid_str.trim().parse::<i32>() {
            // Check if process is running using kill -0
            return ProcessCommand::new("kill")
                .args(["-0", &pid.to_string()])
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status()
                .map(|s| s.success())
                .unwrap_or(false);
        }
    }

    // PID file exists but invalid, clean it up
    let _ = std::fs::remove_file(pid_file);
    false
}

/// Start the service-gator MCP server
///
/// This runs service-gator in the background, listening on 127.0.0.1:PORT.
/// The server reads its scope configuration from SERVICE_GATOR_CONFIG_PATH.
pub fn start_server(config: &ServiceGatorConfig) -> Result<()> {
    if !is_available() {
        tracing::debug!("service-gator not found, skipping");
        return Ok(());
    }

    if is_running() {
        tracing::debug!("service-gator already running");
        return Ok(());
    }

    // Write the config file first
    let config_path = write_config(config)?;

    let port = config.port.unwrap_or(SERVICE_GATOR_DEFAULT_PORT);
    let addr = format!("127.0.0.1:{}", port);

    tracing::info!("Starting service-gator MCP server on {}", addr);

    // Start service-gator in the background
    let child = ProcessCommand::new("service-gator")
        .args(["--mcp-server", &addr])
        // Read config from the file we just wrote
        .env("SERVICE_GATOR_CONFIG", config_path.display().to_string())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .context("Failed to start service-gator")?;

    // Write PID file
    let pid = child.id();
    std::fs::write(SERVICE_GATOR_PID_FILE, pid.to_string()).context("Failed to write PID file")?;

    tracing::info!("service-gator started (PID {}) listening on {}", pid, addr);

    Ok(())
}

/// Stop the service-gator server if running
#[allow(dead_code)]
pub fn stop_server() -> Result<()> {
    let pid_file = Path::new(SERVICE_GATOR_PID_FILE);
    if !pid_file.exists() {
        return Ok(());
    }

    if let Ok(pid_str) = std::fs::read_to_string(pid_file) {
        if let Ok(pid) = pid_str.trim().parse::<i32>() {
            tracing::info!("Stopping service-gator (PID {})", pid);
            let _ = ProcessCommand::new("kill").arg(pid.to_string()).status();
        }
    }

    let _ = std::fs::remove_file(pid_file);
    Ok(())
}

/// Get the MCP server URL for connecting to service-gator
pub fn mcp_url(config: &ServiceGatorConfig) -> String {
    let port = config.port.unwrap_or(SERVICE_GATOR_DEFAULT_PORT);
    format!("http://127.0.0.1:{}/mcp", port)
}

/// Generate opencode configuration JSON with service-gator as an MCP server
///
/// This returns a JSON string that can be written to opencode's config file.
#[allow(dead_code)]
pub fn generate_opencode_mcp_config(config: &ServiceGatorConfig) -> String {
    let url = mcp_url(config);

    // Generate a minimal opencode config that adds service-gator as an MCP server
    serde_json::json!({
        "$schema": "https://opencode.ai/config.json",
        "mcp": {
            "service-gator": {
                "type": "remote",
                "url": url,
                "enabled": true
            }
        }
    })
    .to_string()
}

/// Path where we write the opencode config inside the agent's sandbox home
pub fn opencode_config_path(agent_home: &str) -> PathBuf {
    Path::new(agent_home)
        .join(".config")
        .join("opencode")
        .join("opencode.json")
}

/// Ensure opencode config directory exists and merge service-gator MCP config
///
/// This reads any existing opencode config, merges in the service-gator MCP server,
/// and writes the result. This is called when starting the agent.
pub fn configure_opencode(agent_home: &str, sg_config: &ServiceGatorConfig) -> Result<()> {
    let config_path = opencode_config_path(agent_home);
    let config_dir = config_path.parent().unwrap();

    // Create config directory
    std::fs::create_dir_all(config_dir)
        .with_context(|| format!("Failed to create {}", config_dir.display()))?;

    // Read existing config or start fresh
    let mut config: serde_json::Value = if config_path.exists() {
        let content = std::fs::read_to_string(&config_path)
            .with_context(|| format!("Failed to read {}", config_path.display()))?;
        serde_json::from_str(&content).unwrap_or_else(|_| serde_json::json!({}))
    } else {
        serde_json::json!({
            "$schema": "https://opencode.ai/config.json"
        })
    };

    // Add/update service-gator MCP server
    let mcp = config
        .as_object_mut()
        .unwrap()
        .entry("mcp")
        .or_insert_with(|| serde_json::json!({}));

    let url = mcp_url(sg_config);
    mcp.as_object_mut().unwrap().insert(
        "service-gator".to_string(),
        serde_json::json!({
            "type": "remote",
            "url": url,
            "enabled": true
        }),
    );

    // Write the config
    let content = serde_json::to_string_pretty(&config)?;
    std::fs::write(&config_path, content)
        .with_context(|| format!("Failed to write {}", config_path.display()))?;

    tracing::debug!(
        "Configured opencode with service-gator MCP at {}",
        config_path.display()
    );

    Ok(())
}

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
    if !config.gh.repos.is_empty() || !config.gh.prs.is_empty() || !config.jira.projects.is_empty()
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
        "gitlab" | "gl" => {
            // TODO: Add GitLab support when service-gator has it
            bail!("GitLab scopes not yet supported in CLI: {}", scope);
        }
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

/// Check if a string looks like a permission specification
fn is_permission_string(s: &str) -> bool {
    let known_perms = ["read", "write", "create-draft", "pending-review"];
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
            other => {
                bail!(
                    "Unknown GitHub permission '{}'. Supported: read, write, create-draft, pending-review",
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

    // Add GitHub repo scopes
    for (pattern, perm) in &config.gh.repos {
        let mut perms = Vec::new();
        if perm.read {
            perms.push("read");
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mcp_url() {
        let config = ServiceGatorConfig::default();
        assert_eq!(mcp_url(&config), "http://127.0.0.1:8765/mcp");

        let mut config = ServiceGatorConfig::default();
        config.port = Some(9999);
        assert_eq!(mcp_url(&config), "http://127.0.0.1:9999/mcp");
    }

    #[test]
    fn test_generate_opencode_mcp_config() {
        let config = ServiceGatorConfig::default();
        let json_str = generate_opencode_mcp_config(&config);
        let json: serde_json::Value = serde_json::from_str(&json_str).unwrap();

        assert_eq!(json["$schema"], "https://opencode.ai/config.json");
        assert_eq!(json["mcp"]["service-gator"]["type"], "remote");
        assert_eq!(
            json["mcp"]["service-gator"]["url"],
            "http://127.0.0.1:8765/mcp"
        );
        assert_eq!(json["mcp"]["service-gator"]["enabled"], true);
    }

    #[test]
    fn test_opencode_config_path() {
        let path = opencode_config_path("/home/ai");
        assert_eq!(
            path.to_str().unwrap(),
            "/home/ai/.config/opencode/opencode.json"
        );
    }

    #[test]
    fn test_configure_opencode_new_config() {
        let temp_dir = tempfile::tempdir().unwrap();
        let agent_home = temp_dir.path().to_str().unwrap();

        let sg_config = ServiceGatorConfig::default();
        configure_opencode(agent_home, &sg_config).unwrap();

        // Verify the config was created
        let config_path = opencode_config_path(agent_home);
        assert!(config_path.exists());

        // Verify contents
        let content = std::fs::read_to_string(&config_path).unwrap();
        let json: serde_json::Value = serde_json::from_str(&content).unwrap();
        assert_eq!(json["mcp"]["service-gator"]["type"], "remote");
        assert_eq!(
            json["mcp"]["service-gator"]["url"],
            "http://127.0.0.1:8765/mcp"
        );
    }

    #[test]
    fn test_configure_opencode_merges_existing() {
        let temp_dir = tempfile::tempdir().unwrap();
        let agent_home = temp_dir.path().to_str().unwrap();

        // Create existing config with some settings
        let config_path = opencode_config_path(agent_home);
        std::fs::create_dir_all(config_path.parent().unwrap()).unwrap();
        std::fs::write(
            &config_path,
            r#"{
            "$schema": "https://opencode.ai/config.json",
            "model": "anthropic/claude-sonnet-4",
            "mcp": {
                "other-server": {
                    "type": "local",
                    "command": ["some-command"]
                }
            }
        }"#,
        )
        .unwrap();

        // Configure opencode
        let sg_config = ServiceGatorConfig::default();
        configure_opencode(agent_home, &sg_config).unwrap();

        // Verify existing settings are preserved
        let content = std::fs::read_to_string(&config_path).unwrap();
        let json: serde_json::Value = serde_json::from_str(&content).unwrap();

        // Model should be preserved
        assert_eq!(json["model"], "anthropic/claude-sonnet-4");
        // Other MCP server should be preserved
        assert_eq!(json["mcp"]["other-server"]["type"], "local");
        // service-gator should be added
        assert_eq!(json["mcp"]["service-gator"]["type"], "remote");
    }

    // =========================================================================
    // Scope parsing tests
    // =========================================================================

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
}
