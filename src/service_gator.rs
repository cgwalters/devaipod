//! Service-gator MCP server integration
//!
//! This module handles starting and configuring the service-gator MCP server
//! which provides scope-restricted access to external services (GitHub, JIRA)
//! for AI agents running in the bwrap sandbox.

use std::path::{Path, PathBuf};
use std::process::Command as ProcessCommand;

use color_eyre::eyre::{Context, Result};

use crate::config::{generate_service_gator_toml, ServiceGatorConfig, SERVICE_GATOR_DEFAULT_PORT};

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
}
