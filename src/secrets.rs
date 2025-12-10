//! Podman secrets configuration and management
//!
//! Supports passing podman secrets to containers via environment variables.
//! Users create secrets with `podman secret create`, and devc references them.

use std::collections::HashMap;

use color_eyre::eyre::{Context, Result};
use serde::Deserialize;

use crate::config::ContainerTarget;

/// Configuration for podman secrets mapping
#[derive(Debug, Deserialize, Default)]
pub struct SecretsConfig {
    /// Map of secret names to environment variable mappings
    #[serde(default)]
    pub secrets: HashMap<String, SecretMapping>,
}

/// Mapping of a podman secret to an environment variable
#[derive(Debug, Deserialize, Clone)]
pub struct SecretMapping {
    /// The podman secret name
    pub secret: String,
    /// The environment variable name to expose it as
    pub env: String,
}

/// A parsed secret argument from CLI in format "secret-name=ENV_VAR"
#[derive(Debug, Clone)]
pub struct SecretArg {
    /// The podman secret name
    pub secret_name: String,
    /// The environment variable name
    pub env_var: String,
}

impl SecretArg {
    /// Parse a secret argument in format "secret-name=ENV_VAR"
    pub fn parse(arg: &str) -> Result<Self> {
        let (secret_name, env_var) = arg.split_once('=').ok_or_else(|| {
            color_eyre::eyre::eyre!(
                "Invalid secret format '{}'. Expected 'secret-name=ENV_VAR'",
                arg
            )
        })?;

        if secret_name.is_empty() {
            return Err(color_eyre::eyre::eyre!(
                "Secret name cannot be empty in '{}'",
                arg
            ));
        }

        if env_var.is_empty() {
            return Err(color_eyre::eyre::eyre!(
                "Environment variable name cannot be empty in '{}'",
                arg
            ));
        }

        Ok(SecretArg {
            secret_name: secret_name.to_string(),
            env_var: env_var.to_string(),
        })
    }
}

/// Validate that all referenced podman secrets exist
pub fn validate_secrets(secret_names: &[String]) -> Result<()> {
    if secret_names.is_empty() {
        return Ok(());
    }

    // List all podman secrets
    let output = std::process::Command::new("podman")
        .args(["secret", "ls", "--format", "{{.Name}}"])
        .output()
        .context("Failed to list podman secrets")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(color_eyre::eyre::eyre!(
            "Failed to list podman secrets: {}",
            stderr
        ));
    }

    let available_secrets: Vec<String> = String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();

    // Check that all requested secrets exist
    for secret_name in secret_names {
        if !available_secrets.contains(secret_name) {
            return Err(color_eyre::eyre::eyre!(
                "Podman secret '{}' not found. Create it with: podman secret create {} /path/to/secret/file",
                secret_name,
                secret_name
            ));
        }
    }

    Ok(())
}

/// Validate that all resolved secrets exist in podman
pub fn validate_resolved_secrets(secrets: &[ResolvedSecret]) -> Result<()> {
    if secrets.is_empty() {
        return Ok(());
    }

    let secret_names: Vec<String> = secrets.iter().map(|s| s.secret_name.clone()).collect();
    validate_secrets(&secret_names)
}

/// A secret with its container target resolved
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedSecret {
    pub secret_name: String,
    pub env_var: String,
    pub target: ContainerTarget,
}

/// Filter secrets for a specific container role
///
/// - main_secrets: filter for ContainerTarget::Main or ContainerTarget::All
/// - sidecar_secrets: filter for ContainerTarget::Sidecar or ContainerTarget::All
/// - If container_name matches a Named(name) target, include that too
pub fn filter_secrets_for_role(
    secrets: &[ResolvedSecret],
    role: &str,
    container_name: Option<&str>,
) -> Vec<(String, String)> {
    secrets
        .iter()
        .filter(|secret| match (&secret.target, role, container_name) {
            // All targets always match
            (ContainerTarget::All, _, _) => true,
            // Main role matches Main target
            (ContainerTarget::Main, "main", _) => true,
            // Sidecar role matches Sidecar target
            (ContainerTarget::Sidecar, "sidecar", _) => true,
            // Named target matches if container_name matches
            (ContainerTarget::Named(name), _, Some(container)) => name == container,
            // No match
            _ => false,
        })
        .map(|secret| (secret.secret_name.clone(), secret.env_var.clone()))
        .collect()
}

/// Merge CLI-provided secrets with config file secrets
/// CLI secrets override config secrets with the same name
pub fn merge_secrets(
    cli_main_secrets: &[(String, String)],
    cli_sidecar_secrets: &[(String, String)],
    cli_all_secrets: &[(String, String)],
    config_secrets: &HashMap<String, crate::config::SecretMapping>,
) -> Vec<ResolvedSecret> {
    let mut result = Vec::new();
    let mut seen_names = std::collections::HashSet::new();

    // Add CLI secrets first (they have priority)
    for (secret_name, env_var) in cli_main_secrets {
        result.push(ResolvedSecret {
            secret_name: secret_name.clone(),
            env_var: env_var.clone(),
            target: ContainerTarget::Main,
        });
        seen_names.insert(secret_name.clone());
    }

    for (secret_name, env_var) in cli_sidecar_secrets {
        result.push(ResolvedSecret {
            secret_name: secret_name.clone(),
            env_var: env_var.clone(),
            target: ContainerTarget::Sidecar,
        });
        seen_names.insert(secret_name.clone());
    }

    for (secret_name, env_var) in cli_all_secrets {
        result.push(ResolvedSecret {
            secret_name: secret_name.clone(),
            env_var: env_var.clone(),
            target: ContainerTarget::All,
        });
        seen_names.insert(secret_name.clone());
    }

    // Add config secrets that weren't already added via CLI
    for (_, mapping) in config_secrets {
        if !seen_names.contains(&mapping.secret) {
            result.push(ResolvedSecret {
                secret_name: mapping.secret.clone(),
                env_var: mapping.env.clone(),
                target: mapping.container.clone(),
            });
        }
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_secret_arg() {
        let arg = SecretArg::parse("anthropic-key=ANTHROPIC_API_KEY").unwrap();
        assert_eq!(arg.secret_name, "anthropic-key");
        assert_eq!(arg.env_var, "ANTHROPIC_API_KEY");
    }

    #[test]
    fn test_parse_secret_arg_invalid() {
        assert!(SecretArg::parse("invalid").is_err());
        assert!(SecretArg::parse("=ENV_VAR").is_err());
        assert!(SecretArg::parse("secret=").is_err());
        assert!(SecretArg::parse("").is_err());
    }

    #[test]
    fn test_parse_secrets_config() {
        let toml = r#"
[secrets.anthropic]
secret = "anthropic-key"
env = "ANTHROPIC_API_KEY"

[secrets.openai]
secret = "openai-key"
env = "OPENAI_API_KEY"
"#;
        let config: SecretsConfig = toml::from_str(toml).unwrap();
        assert_eq!(config.secrets.len(), 2);
        assert_eq!(config.secrets["anthropic"].secret, "anthropic-key");
        assert_eq!(config.secrets["anthropic"].env, "ANTHROPIC_API_KEY");
        assert_eq!(config.secrets["openai"].secret, "openai-key");
        assert_eq!(config.secrets["openai"].env, "OPENAI_API_KEY");
    }

    #[test]
    fn test_empty_config() {
        let toml = "";
        let config: SecretsConfig = toml::from_str(toml).unwrap();
        assert_eq!(config.secrets.len(), 0);
    }

    #[test]
    fn test_filter_secrets_for_main() {
        let secrets = vec![
            ResolvedSecret {
                secret_name: "main-secret".to_string(),
                env_var: "MAIN_SECRET".to_string(),
                target: ContainerTarget::Main,
            },
            ResolvedSecret {
                secret_name: "sidecar-secret".to_string(),
                env_var: "SIDECAR_SECRET".to_string(),
                target: ContainerTarget::Sidecar,
            },
            ResolvedSecret {
                secret_name: "all-secret".to_string(),
                env_var: "ALL_SECRET".to_string(),
                target: ContainerTarget::All,
            },
        ];

        let filtered = filter_secrets_for_role(&secrets, "main", None);
        assert_eq!(filtered.len(), 2);
        assert!(filtered.contains(&("main-secret".to_string(), "MAIN_SECRET".to_string())));
        assert!(filtered.contains(&("all-secret".to_string(), "ALL_SECRET".to_string())));
    }

    #[test]
    fn test_filter_secrets_for_sidecar() {
        let secrets = vec![
            ResolvedSecret {
                secret_name: "main-secret".to_string(),
                env_var: "MAIN_SECRET".to_string(),
                target: ContainerTarget::Main,
            },
            ResolvedSecret {
                secret_name: "sidecar-secret".to_string(),
                env_var: "SIDECAR_SECRET".to_string(),
                target: ContainerTarget::Sidecar,
            },
            ResolvedSecret {
                secret_name: "all-secret".to_string(),
                env_var: "ALL_SECRET".to_string(),
                target: ContainerTarget::All,
            },
        ];

        let filtered = filter_secrets_for_role(&secrets, "sidecar", None);
        assert_eq!(filtered.len(), 2);
        assert!(filtered.contains(&("sidecar-secret".to_string(), "SIDECAR_SECRET".to_string())));
        assert!(filtered.contains(&("all-secret".to_string(), "ALL_SECRET".to_string())));
    }

    #[test]
    fn test_filter_secrets_for_named_container() {
        let secrets = vec![
            ResolvedSecret {
                secret_name: "goose-secret".to_string(),
                env_var: "GOOSE_SECRET".to_string(),
                target: ContainerTarget::Named("goose".to_string()),
            },
            ResolvedSecret {
                secret_name: "other-secret".to_string(),
                env_var: "OTHER_SECRET".to_string(),
                target: ContainerTarget::Named("other".to_string()),
            },
            ResolvedSecret {
                secret_name: "all-secret".to_string(),
                env_var: "ALL_SECRET".to_string(),
                target: ContainerTarget::All,
            },
        ];

        let filtered = filter_secrets_for_role(&secrets, "custom", Some("goose"));
        assert_eq!(filtered.len(), 2);
        assert!(filtered.contains(&("goose-secret".to_string(), "GOOSE_SECRET".to_string())));
        assert!(filtered.contains(&("all-secret".to_string(), "ALL_SECRET".to_string())));
    }

    #[test]
    fn test_filter_secrets_named_no_match() {
        let secrets = vec![
            ResolvedSecret {
                secret_name: "goose-secret".to_string(),
                env_var: "GOOSE_SECRET".to_string(),
                target: ContainerTarget::Named("goose".to_string()),
            },
            ResolvedSecret {
                secret_name: "main-secret".to_string(),
                env_var: "MAIN_SECRET".to_string(),
                target: ContainerTarget::Main,
            },
        ];

        // Named target without container_name shouldn't match
        let filtered = filter_secrets_for_role(&secrets, "main", None);
        assert_eq!(filtered.len(), 1);
        assert!(filtered.contains(&("main-secret".to_string(), "MAIN_SECRET".to_string())));
    }

    #[test]
    fn test_merge_secrets_cli_only() {
        let cli_main = vec![("secret1".to_string(), "ENV1".to_string())];
        let cli_sidecar = vec![("secret2".to_string(), "ENV2".to_string())];
        let cli_all = vec![("secret3".to_string(), "ENV3".to_string())];
        let config = HashMap::new();

        let result = merge_secrets(&cli_main, &cli_sidecar, &cli_all, &config);
        assert_eq!(result.len(), 3);

        assert_eq!(result[0].secret_name, "secret1");
        assert_eq!(result[0].env_var, "ENV1");
        assert_eq!(result[0].target, ContainerTarget::Main);

        assert_eq!(result[1].secret_name, "secret2");
        assert_eq!(result[1].env_var, "ENV2");
        assert_eq!(result[1].target, ContainerTarget::Sidecar);

        assert_eq!(result[2].secret_name, "secret3");
        assert_eq!(result[2].env_var, "ENV3");
        assert_eq!(result[2].target, ContainerTarget::All);
    }

    #[test]
    fn test_merge_secrets_config_only() {
        let cli_main = vec![];
        let cli_sidecar = vec![];
        let cli_all = vec![];

        let mut config = HashMap::new();
        config.insert(
            "config1".to_string(),
            crate::config::SecretMapping {
                secret: "secret1".to_string(),
                env: "ENV1".to_string(),
                container: ContainerTarget::Main,
            },
        );
        config.insert(
            "config2".to_string(),
            crate::config::SecretMapping {
                secret: "secret2".to_string(),
                env: "ENV2".to_string(),
                container: ContainerTarget::Sidecar,
            },
        );

        let result = merge_secrets(&cli_main, &cli_sidecar, &cli_all, &config);
        assert_eq!(result.len(), 2);

        // Order may vary, so check both secrets are present
        let has_secret1 = result
            .iter()
            .any(|s| s.secret_name == "secret1" && s.env_var == "ENV1");
        let has_secret2 = result
            .iter()
            .any(|s| s.secret_name == "secret2" && s.env_var == "ENV2");
        assert!(has_secret1);
        assert!(has_secret2);
    }

    #[test]
    fn test_merge_secrets_cli_overrides_config() {
        let cli_main = vec![("secret1".to_string(), "CLI_ENV1".to_string())];
        let cli_sidecar = vec![];
        let cli_all = vec![];

        let mut config = HashMap::new();
        config.insert(
            "config1".to_string(),
            crate::config::SecretMapping {
                secret: "secret1".to_string(),
                env: "CONFIG_ENV1".to_string(),
                container: ContainerTarget::Main,
            },
        );
        config.insert(
            "config2".to_string(),
            crate::config::SecretMapping {
                secret: "secret2".to_string(),
                env: "ENV2".to_string(),
                container: ContainerTarget::Sidecar,
            },
        );

        let result = merge_secrets(&cli_main, &cli_sidecar, &cli_all, &config);
        assert_eq!(result.len(), 2);

        // CLI version should be present
        assert_eq!(result[0].secret_name, "secret1");
        assert_eq!(result[0].env_var, "CLI_ENV1");
        assert_eq!(result[0].target, ContainerTarget::Main);

        // Config-only secret should still be present
        let has_secret2 = result
            .iter()
            .any(|s| s.secret_name == "secret2" && s.env_var == "ENV2");
        assert!(has_secret2);
    }

    #[test]
    fn test_merge_secrets_named_targets() {
        let cli_main = vec![];
        let cli_sidecar = vec![];
        let cli_all = vec![];

        let mut config = HashMap::new();
        config.insert(
            "config1".to_string(),
            crate::config::SecretMapping {
                secret: "secret1".to_string(),
                env: "ENV1".to_string(),
                container: ContainerTarget::Named("goose".to_string()),
            },
        );

        let result = merge_secrets(&cli_main, &cli_sidecar, &cli_all, &config);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].secret_name, "secret1");
        assert_eq!(result[0].env_var, "ENV1");
        assert_eq!(
            result[0].target,
            ContainerTarget::Named("goose".to_string())
        );
    }

    #[test]
    fn test_resolved_secret_equality() {
        let secret1 = ResolvedSecret {
            secret_name: "test".to_string(),
            env_var: "TEST".to_string(),
            target: ContainerTarget::Main,
        };
        let secret2 = ResolvedSecret {
            secret_name: "test".to_string(),
            env_var: "TEST".to_string(),
            target: ContainerTarget::Main,
        };
        let secret3 = ResolvedSecret {
            secret_name: "test".to_string(),
            env_var: "TEST".to_string(),
            target: ContainerTarget::Sidecar,
        };

        assert_eq!(secret1, secret2);
        assert_ne!(secret1, secret3);
    }
}
