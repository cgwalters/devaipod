//! Docker Compose generation for multi-container devcontainer setup
//!
//! This module transforms a simple devcontainer.json into a multi-container
//! Docker Compose configuration with:
//! - workspace: User's devcontainer (for human interaction)
//! - agent: Same image, running opencode serve (sandboxed AI execution)
//! - gator: service-gator MCP server (scoped external service access)

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use color_eyre::eyre::{bail, Context, Result};
use serde::{Deserialize, Serialize};

use crate::config::ServiceGatorConfig;

/// Default port for opencode server
pub const OPENCODE_PORT: u16 = 4096;

/// Default port for service-gator MCP server
pub const GATOR_PORT: u16 = 8765;

/// Parsed devcontainer.json (subset of fields we care about)
///
/// Some fields are parsed but not yet used in compose generation - they exist
/// to support future features and to faithfully represent the devcontainer spec.
#[derive(Debug, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code)]
pub struct DevcontainerConfig {
    /// Container name
    pub name: Option<String>,

    /// Direct image reference
    pub image: Option<String>,

    /// Build configuration
    pub build: Option<BuildConfig>,

    /// Docker Compose file(s) - if present, this is already a compose-based devcontainer
    pub docker_compose_file: Option<StringOrArray>,

    /// Service name when using compose
    pub service: Option<String>,

    /// Workspace folder inside container
    pub workspace_folder: Option<String>,

    /// Devcontainer features
    #[serde(default)]
    pub features: HashMap<String, serde_json::Value>,

    /// Lifecycle commands
    pub on_create_command: Option<Command>,
    pub post_create_command: Option<Command>,
    pub post_start_command: Option<Command>,
    pub post_attach_command: Option<Command>,

    /// Customizations (vscode extensions, etc.)
    #[serde(default)]
    pub customizations: HashMap<String, serde_json::Value>,

    /// Ports to forward
    #[serde(default)]
    pub forward_ports: Vec<serde_json::Value>,

    /// Remote user
    pub remote_user: Option<String>,

    /// Container user
    pub container_user: Option<String>,

    /// Container environment variables
    #[serde(default)]
    pub container_env: HashMap<String, String>,

    /// Remote environment variables
    #[serde(default)]
    pub remote_env: HashMap<String, String>,

    /// Additional mounts
    #[serde(default)]
    pub mounts: Vec<serde_json::Value>,

    /// Run arguments (docker run flags)
    #[serde(default)]
    pub run_args: Vec<String>,

    /// Privileged mode
    #[serde(default)]
    pub privileged: bool,

    /// Capabilities to add
    #[serde(default)]
    pub cap_add: Vec<String>,

    /// Security options
    #[serde(default)]
    pub security_opt: Vec<String>,
}

/// Build configuration in devcontainer.json
#[derive(Debug, Deserialize, Default, Clone)]
#[serde(rename_all = "camelCase")]
pub struct BuildConfig {
    /// Path to Dockerfile
    pub dockerfile: Option<String>,

    /// Build context
    pub context: Option<String>,

    /// Build arguments
    #[serde(default)]
    pub args: HashMap<String, String>,

    /// Target stage
    pub target: Option<String>,
}

/// String or array of strings (for dockerComposeFile)
#[derive(Debug, Deserialize, Clone)]
#[serde(untagged)]
pub enum StringOrArray {
    String(String),
    Array(Vec<String>),
}

/// Command can be string, array, or object with parallel commands
#[derive(Debug, Deserialize, Clone, Serialize)]
#[serde(untagged)]
pub enum Command {
    String(String),
    Array(Vec<String>),
    Object(HashMap<String, serde_json::Value>),
}

/// Generated Docker Compose configuration
#[derive(Debug, Serialize)]
pub struct ComposeConfig {
    pub version: String,
    pub services: HashMap<String, ComposeService>,
    #[serde(skip_serializing_if = "HashMap::is_empty")]
    pub volumes: HashMap<String, serde_json::Value>,
}

/// A service in the Docker Compose file
#[derive(Debug, Serialize, Default)]
pub struct ComposeService {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub image: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub build: Option<ComposeBuild>,

    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub volumes: Vec<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub command: Option<StringOrArray>,

    #[serde(skip_serializing_if = "HashMap::is_empty")]
    pub environment: HashMap<String, String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub depends_on: Option<ComposeDependsOn>,

    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub cap_drop: Vec<String>,

    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub cap_add: Vec<String>,

    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub security_opt: Vec<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub healthcheck: Option<Healthcheck>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub working_dir: Option<String>,
}

/// Build configuration for compose
#[derive(Debug, Serialize, Clone)]
pub struct ComposeBuild {
    pub context: String,
    pub dockerfile: String,
    #[serde(skip_serializing_if = "HashMap::is_empty")]
    pub args: HashMap<String, String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
}

/// Depends on with condition
#[derive(Debug, Serialize)]
#[serde(untagged)]
#[allow(dead_code)]
pub enum ComposeDependsOn {
    Simple(Vec<String>),
    WithCondition(HashMap<String, DependsOnCondition>),
}

#[derive(Debug, Serialize)]
pub struct DependsOnCondition {
    pub condition: String,
}

/// Healthcheck configuration
#[derive(Debug, Serialize)]
pub struct Healthcheck {
    pub test: Vec<String>,
    pub interval: String,
    pub timeout: String,
    pub retries: u32,
}

impl Serialize for StringOrArray {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            StringOrArray::String(s) => serializer.serialize_str(s),
            StringOrArray::Array(a) => a.serialize(serializer),
        }
    }
}

/// Output of compose generation
pub struct GeneratedCompose {
    /// The docker-compose.yml content
    pub compose_yaml: String,

    /// The augmented devcontainer.json content
    pub devcontainer_json: String,

    /// Optional generated Dockerfile (for image-based configs)
    pub dockerfile: Option<String>,

    /// The opencode shim script to install in workspace
    pub opencode_shim: String,

    /// Generated opencode config for agent
    pub opencode_config: String,
}

/// Load and parse a devcontainer.json file
pub fn load_devcontainer(path: &Path) -> Result<DevcontainerConfig> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read {}", path.display()))?;

    // Remove JSON comments (// style) - devcontainer.json allows them
    let content = remove_json_comments(&content);

    let config: DevcontainerConfig = serde_json::from_str(&content)
        .with_context(|| format!("Failed to parse {}", path.display()))?;

    Ok(config)
}

/// Remove // comments from JSON (devcontainer.json extension)
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
            }
        }

        result.push(c);
    }

    result
}

/// Generate the multi-container compose setup from a devcontainer config
pub fn generate_compose(
    devcontainer: &DevcontainerConfig,
    project_name: &str,
    workspace_folder: &str,
    gator_config: &ServiceGatorConfig,
) -> Result<GeneratedCompose> {
    // Check if this is already a compose-based devcontainer
    if devcontainer.docker_compose_file.is_some() {
        bail!(
            "Devcontainer already uses Docker Compose. \
             Extending existing compose files is not yet supported."
        );
    }

    // Determine if we need to generate a Dockerfile
    let (dockerfile_content, build_config) = if devcontainer.image.is_some() {
        // Image-based: generate a wrapper Dockerfile
        let base_image = devcontainer.image.as_ref().unwrap();
        let dockerfile = generate_wrapper_dockerfile(base_image);
        let build = ComposeBuild {
            context: "..".to_string(),
            dockerfile: ".devaipod/Dockerfile".to_string(),
            args: HashMap::new(),
            target: None,
        };
        (Some(dockerfile), build)
    } else if let Some(build) = &devcontainer.build {
        // Dockerfile-based: reference the original
        let dockerfile_path = build.dockerfile.clone().unwrap_or("Dockerfile".to_string());
        let context = build.context.clone().unwrap_or(".".to_string());

        // Adjust paths relative to .devaipod directory
        let adjusted_context = if context == "." {
            "../.devcontainer".to_string()
        } else {
            format!("../{}", context.trim_start_matches("./"))
        };

        let adjusted_dockerfile = if dockerfile_path.starts_with('/') {
            dockerfile_path
        } else {
            // Dockerfile path is relative to context
            dockerfile_path
        };

        let build_cfg = ComposeBuild {
            context: adjusted_context,
            dockerfile: adjusted_dockerfile,
            args: build.args.clone(),
            target: build.target.clone(),
        };
        (None, build_cfg)
    } else {
        bail!("Devcontainer must specify either 'image' or 'build.dockerfile'");
    };

    // Build the compose configuration
    let mut services = HashMap::new();
    let mut volumes = HashMap::new();

    // Workspace service (user's environment)
    let mut workspace_service = ComposeService {
        build: Some(build_config.clone()),
        volumes: vec![
            format!("..:{workspace_folder}:cached"),
            "workspace-home:/home/vscode".to_string(),
        ],
        command: Some(StringOrArray::String("sleep infinity".to_string())),
        environment: HashMap::new(),
        depends_on: Some(ComposeDependsOn::WithCondition({
            let mut deps = HashMap::new();
            deps.insert(
                "agent".to_string(),
                DependsOnCondition {
                    condition: "service_healthy".to_string(),
                },
            );
            deps
        })),
        ..Default::default()
    };

    // Add workspace environment variables
    workspace_service.environment.insert(
        "DEVAIPOD_AGENT_URL".to_string(),
        format!("http://agent:{OPENCODE_PORT}"),
    );
    workspace_service.environment.insert(
        "DEVAIPOD_GATOR_URL".to_string(),
        format!("http://gator:{GATOR_PORT}"),
    );

    // Forward user's container env
    for (key, value) in &devcontainer.container_env {
        workspace_service
            .environment
            .insert(key.clone(), value.clone());
    }

    services.insert("workspace".to_string(), workspace_service);

    // Agent service (sandboxed AI execution)
    let agent_service = ComposeService {
        build: Some(build_config),
        volumes: vec![
            format!("..:{workspace_folder}:cached"),
            "agent-home:/home/ai".to_string(),
            "agent-config:/etc/opencode:ro".to_string(),
        ],
        command: Some(StringOrArray::Array(vec![
            "opencode".to_string(),
            "serve".to_string(),
            "--port".to_string(),
            OPENCODE_PORT.to_string(),
            "--hostname".to_string(),
            "0.0.0.0".to_string(),
        ])),
        environment: {
            let mut env = HashMap::new();
            env.insert("HOME".to_string(), "/home/ai".to_string());
            env.insert(
                "OPENCODE_CONFIG".to_string(),
                "/etc/opencode/config.json".to_string(),
            );
            // LLM API key will be passed via devaipod's secret handling
            env.insert(
                "ANTHROPIC_API_KEY".to_string(),
                "${ANTHROPIC_API_KEY}".to_string(),
            );
            env
        },
        cap_drop: vec!["ALL".to_string()],
        cap_add: vec!["NET_BIND_SERVICE".to_string()],
        security_opt: vec!["no-new-privileges:true".to_string()],
        healthcheck: Some(Healthcheck {
            test: vec![
                "CMD".to_string(),
                "curl".to_string(),
                "-sf".to_string(),
                format!("http://localhost:{OPENCODE_PORT}/global/health"),
            ],
            interval: "2s".to_string(),
            timeout: "2s".to_string(),
            retries: 30,
        }),
        working_dir: Some(workspace_folder.to_string()),
        ..Default::default()
    };
    services.insert("agent".to_string(), agent_service);

    // Gator service (service-gator MCP server)
    if gator_config.is_enabled() {
        let gator_service = ComposeService {
            image: Some("ghcr.io/cgwalters/service-gator:latest".to_string()),
            volumes: vec!["gator-config:/config:ro".to_string()],
            command: Some(StringOrArray::Array(vec![
                "service-gator".to_string(),
                "--mcp-server".to_string(),
                format!("0.0.0.0:{GATOR_PORT}"),
            ])),
            environment: {
                let mut env = HashMap::new();
                // Tokens passed via environment
                env.insert("GH_TOKEN".to_string(), "${GH_TOKEN}".to_string());
                env.insert(
                    "JIRA_API_TOKEN".to_string(),
                    "${JIRA_API_TOKEN}".to_string(),
                );
                env
            },
            ..Default::default()
        };
        services.insert("gator".to_string(), gator_service);
        volumes.insert("gator-config".to_string(), serde_json::json!({}));
    }

    // Add volumes
    volumes.insert("workspace-home".to_string(), serde_json::json!({}));
    volumes.insert("agent-home".to_string(), serde_json::json!({}));
    volumes.insert("agent-config".to_string(), serde_json::json!({}));

    let compose = ComposeConfig {
        version: "3.8".to_string(),
        services,
        volumes,
    };

    // Generate the augmented devcontainer.json
    let augmented_devcontainer = generate_augmented_devcontainer(devcontainer, project_name)?;

    // Generate the opencode shim
    let opencode_shim = generate_opencode_shim();

    // Generate opencode config for agent
    let opencode_config = generate_opencode_config(gator_config)?;

    // Serialize compose to YAML
    let compose_yaml = serde_yaml_to_string(&compose)?;

    Ok(GeneratedCompose {
        compose_yaml,
        devcontainer_json: augmented_devcontainer,
        dockerfile: dockerfile_content,
        opencode_shim,
        opencode_config,
    })
}

/// Generate a wrapper Dockerfile for image-based devcontainers
fn generate_wrapper_dockerfile(base_image: &str) -> String {
    format!(
        r#"# Generated by devaipod - DO NOT EDIT
# This wraps the base image to add devaipod utilities

FROM {base_image}

# Install opencode shim and utilities
# The actual opencode binary should be in the base image or installed via features
COPY .devaipod/opencode-shim /usr/local/bin/opencode-wrapper
RUN chmod +x /usr/local/bin/opencode-wrapper

# If opencode exists, rename it and use our wrapper
RUN if command -v opencode >/dev/null 2>&1; then \
      mv $(which opencode) /usr/local/bin/opencode-real; \
      ln -sf /usr/local/bin/opencode-wrapper /usr/local/bin/opencode; \
    fi
"#
    )
}

/// Generate the augmented devcontainer.json that points to our compose file
fn generate_augmented_devcontainer(
    original: &DevcontainerConfig,
    project_name: &str,
) -> Result<String> {
    let mut augmented = serde_json::json!({
        "name": format!("{} (devaipod)", original.name.as_deref().unwrap_or(project_name)),
        "dockerComposeFile": "docker-compose.yml",
        "service": "workspace",
        "workspaceFolder": original.workspace_folder.as_deref().unwrap_or("/workspaces/project"),
    });

    let obj = augmented.as_object_mut().unwrap();

    // Preserve features
    if !original.features.is_empty() {
        obj.insert(
            "features".to_string(),
            serde_json::to_value(&original.features)?,
        );
    }

    // Preserve lifecycle commands
    if let Some(cmd) = &original.on_create_command {
        obj.insert("onCreateCommand".to_string(), serde_json::to_value(cmd)?);
    }
    if let Some(cmd) = &original.post_create_command {
        obj.insert("postCreateCommand".to_string(), serde_json::to_value(cmd)?);
    }
    if let Some(cmd) = &original.post_start_command {
        obj.insert("postStartCommand".to_string(), serde_json::to_value(cmd)?);
    }
    if let Some(cmd) = &original.post_attach_command {
        obj.insert("postAttachCommand".to_string(), serde_json::to_value(cmd)?);
    }

    // Preserve customizations
    if !original.customizations.is_empty() {
        obj.insert(
            "customizations".to_string(),
            serde_json::to_value(&original.customizations)?,
        );
    }

    // Preserve forwarded ports
    if !original.forward_ports.is_empty() {
        obj.insert(
            "forwardPorts".to_string(),
            serde_json::to_value(&original.forward_ports)?,
        );
    }

    // Preserve remote user
    if let Some(user) = &original.remote_user {
        obj.insert("remoteUser".to_string(), serde_json::json!(user));
    }

    // Preserve remote env
    if !original.remote_env.is_empty() {
        obj.insert(
            "remoteEnv".to_string(),
            serde_json::to_value(&original.remote_env)?,
        );
    }

    // Preserve mounts
    if !original.mounts.is_empty() {
        obj.insert(
            "mounts".to_string(),
            serde_json::to_value(&original.mounts)?,
        );
    }

    serde_json::to_string_pretty(&augmented).context("Failed to serialize devcontainer.json")
}

/// Generate the opencode shim script for workspace container
fn generate_opencode_shim() -> String {
    format!(
        r#"#!/bin/bash
# Generated by devaipod - opencode wrapper
# Transparently connects to the agent container's opencode server

set -e

AGENT_URL="${{DEVAIPOD_AGENT_URL:-http://agent:{OPENCODE_PORT}}}"

# Wait for agent to be ready
wait_for_agent() {{
    local max_attempts=30
    local attempt=1
    
    while [ $attempt -le $max_attempts ]; do
        if curl -sf "$AGENT_URL/global/health" > /dev/null 2>&1; then
            return 0
        fi
        echo "Waiting for agent container... (attempt $attempt/$max_attempts)" >&2
        sleep 1
        attempt=$((attempt + 1))
    done
    
    echo "Error: Agent container not ready after $max_attempts attempts" >&2
    echo "Check 'docker compose logs agent' for details" >&2
    exit 1
}}

# If we have the real opencode, use attach mode
if command -v opencode-real >/dev/null 2>&1; then
    wait_for_agent
    exec opencode-real attach "$AGENT_URL" "$@"
fi

# Fallback: try to use opencode directly (might not exist)
if command -v opencode >/dev/null 2>&1; then
    wait_for_agent
    exec opencode attach "$AGENT_URL" "$@"
fi

echo "Error: opencode not found. Install it or add the opencode feature." >&2
exit 1
"#
    )
}

/// Generate opencode config with service-gator MCP server
fn generate_opencode_config(gator_config: &ServiceGatorConfig) -> Result<String> {
    let mut config = serde_json::json!({
        "$schema": "https://opencode.ai/config.json"
    });

    if gator_config.is_enabled() {
        config["mcp"] = serde_json::json!({
            "service-gator": {
                "type": "remote",
                "url": format!("http://gator:{GATOR_PORT}/mcp"),
                "enabled": true
            }
        });
    }

    serde_json::to_string_pretty(&config).context("Failed to serialize opencode config")
}

/// Convert compose config to YAML string
/// Note: We use serde_json + manual conversion since serde_yaml has issues with some types
fn serde_yaml_to_string(compose: &ComposeConfig) -> Result<String> {
    // For now, use a simple YAML generation approach
    // In production, we'd want to use a proper YAML library

    let json = serde_json::to_value(compose)?;
    let yaml = json_to_yaml(&json, 0);
    Ok(yaml)
}

/// Simple JSON to YAML converter (handles our subset of types)
fn json_to_yaml(value: &serde_json::Value, indent: usize) -> String {
    let prefix = "  ".repeat(indent);

    match value {
        serde_json::Value::Null => "null".to_string(),
        serde_json::Value::Bool(b) => b.to_string(),
        serde_json::Value::Number(n) => n.to_string(),
        serde_json::Value::String(s) => {
            // Quote strings that might be ambiguous
            if s.contains(':')
                || s.contains('#')
                || s.contains('\n')
                || s.starts_with('$')
                || s.is_empty()
            {
                format!("\"{}\"", s.replace('\"', "\\\""))
            } else {
                s.clone()
            }
        }
        serde_json::Value::Array(arr) => {
            if arr.is_empty() {
                "[]".to_string()
            } else {
                let items: Vec<String> = arr
                    .iter()
                    .map(|v| {
                        let yaml = json_to_yaml(v, indent + 1);
                        if matches!(v, serde_json::Value::Object(_)) {
                            format!("{prefix}  -\n{yaml}")
                        } else {
                            format!("{prefix}  - {yaml}")
                        }
                    })
                    .collect();
                format!("\n{}", items.join("\n"))
            }
        }
        serde_json::Value::Object(obj) => {
            if obj.is_empty() {
                "{}".to_string()
            } else {
                let items: Vec<String> = obj
                    .iter()
                    .map(|(k, v)| {
                        let yaml_value = json_to_yaml(v, indent + 1);
                        if matches!(
                            v,
                            serde_json::Value::Object(_) | serde_json::Value::Array(_)
                        ) && !yaml_value.starts_with('[')
                            && !yaml_value.starts_with('{')
                        {
                            format!("{prefix}  {k}:{yaml_value}")
                        } else {
                            format!("{prefix}  {k}: {yaml_value}")
                        }
                    })
                    .collect();
                format!("\n{}", items.join("\n"))
            }
        }
    }
}

/// Find the devcontainer.json file for a project
pub fn find_devcontainer_json(project_path: &Path) -> Result<PathBuf> {
    // Standard location
    let standard = project_path.join(".devcontainer/devcontainer.json");
    if standard.exists() {
        return Ok(standard);
    }

    // Root location
    let root = project_path.join("devcontainer.json");
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

/// Write generated files to .devaipod directory
pub fn write_generated_files(project_path: &Path, generated: &GeneratedCompose) -> Result<PathBuf> {
    let devaipod_dir = project_path.join(".devaipod");
    std::fs::create_dir_all(&devaipod_dir)
        .with_context(|| format!("Failed to create {}", devaipod_dir.display()))?;

    // Write docker-compose.yml
    let compose_path = devaipod_dir.join("docker-compose.yml");
    std::fs::write(&compose_path, &generated.compose_yaml)
        .with_context(|| format!("Failed to write {}", compose_path.display()))?;

    // Write devcontainer.json
    let devcontainer_path = devaipod_dir.join("devcontainer.json");
    std::fs::write(&devcontainer_path, &generated.devcontainer_json)
        .with_context(|| format!("Failed to write {}", devcontainer_path.display()))?;

    // Write Dockerfile if generated
    if let Some(dockerfile) = &generated.dockerfile {
        let dockerfile_path = devaipod_dir.join("Dockerfile");
        std::fs::write(&dockerfile_path, dockerfile)
            .with_context(|| format!("Failed to write {}", dockerfile_path.display()))?;
    }

    // Write opencode shim
    let shim_path = devaipod_dir.join("opencode-shim");
    std::fs::write(&shim_path, &generated.opencode_shim)
        .with_context(|| format!("Failed to write {}", shim_path.display()))?;

    // Write opencode config
    let config_path = devaipod_dir.join("opencode-config.json");
    std::fs::write(&config_path, &generated.opencode_config)
        .with_context(|| format!("Failed to write {}", config_path.display()))?;

    tracing::info!(
        "Generated devaipod configuration in {}",
        devaipod_dir.display()
    );

    Ok(devaipod_dir)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_simple_devcontainer() {
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
    }

    #[test]
    fn test_parse_dockerfile_devcontainer() {
        let json = r#"{
            "build": {
                "dockerfile": "Dockerfile",
                "context": "."
            },
            "remoteUser": "vscode"
        }"#;

        let config: DevcontainerConfig = serde_json::from_str(json).unwrap();
        assert!(config.build.is_some());
        assert_eq!(
            config.build.as_ref().unwrap().dockerfile,
            Some("Dockerfile".to_string())
        );
    }

    #[test]
    fn test_remove_json_comments() {
        let input = r#"{
            // This is a comment
            "key": "value" // inline comment
        }"#;

        let result = remove_json_comments(input);
        assert!(!result.contains("// This is a comment"));
        assert!(result.contains("\"key\": \"value\""));
    }

    #[test]
    fn test_generate_opencode_shim() {
        let shim = generate_opencode_shim();
        assert!(shim.contains("#!/bin/bash"));
        assert!(shim.contains("DEVAIPOD_AGENT_URL"));
        assert!(shim.contains("opencode"));
        assert!(shim.contains("attach"));
    }

    #[test]
    fn test_generate_compose() {
        let devcontainer = DevcontainerConfig {
            image: Some("mcr.microsoft.com/devcontainers/rust:1".to_string()),
            ..Default::default()
        };

        let gator_config = ServiceGatorConfig::default();

        let result = generate_compose(
            &devcontainer,
            "test-project",
            "/workspaces/project",
            &gator_config,
        )
        .unwrap();

        assert!(result.compose_yaml.contains("workspace:"));
        assert!(result.compose_yaml.contains("agent:"));
        assert!(result.devcontainer_json.contains("dockerComposeFile"));
        assert!(result.dockerfile.is_some());
    }
}
