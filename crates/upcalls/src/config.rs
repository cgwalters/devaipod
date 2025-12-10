//! Configuration for gh-restricted.
//!
//! Looks for config files in the following locations (in order):
//! 1. `$XDG_CONFIG_HOME/gh-restricted.toml` (or `~/.config/gh-restricted.toml`)
//!
//! Example configuration:
//! ```toml
//! # Allow all read operations (like the old gh-readonly behavior)
//! allow-read-all = true
//! ```

use serde::Deserialize;
use std::path::PathBuf;

/// Configuration for gh-restricted behavior.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct Config {
    /// If true, allow all read-only operations without requiring upcall validation.
    /// This provides the same behavior as the old gh-readonly wrapper.
    /// Default: false (require upcall validation for everything)
    #[serde(default)]
    pub allow_read_all: bool,
}

impl Config {
    /// Load configuration from the standard config file location.
    /// Returns default config if no config file is found.
    pub fn load() -> Self {
        if let Some(path) = Self::config_path() {
            if path.exists() {
                match std::fs::read_to_string(&path) {
                    Ok(content) => match toml::from_str(&content) {
                        Ok(config) => return config,
                        Err(e) => {
                            eprintln!("warning: failed to parse {}: {}", path.display(), e);
                        }
                    },
                    Err(e) => {
                        eprintln!("warning: failed to read {}: {}", path.display(), e);
                    }
                }
            }
        }
        Self::default()
    }

    /// Get the config file path.
    /// Uses $XDG_CONFIG_HOME/gh-restricted.toml or ~/.config/gh-restricted.toml
    fn config_path() -> Option<PathBuf> {
        // Try XDG_CONFIG_HOME first
        if let Ok(xdg_config) = std::env::var("XDG_CONFIG_HOME") {
            let path = PathBuf::from(xdg_config).join("gh-restricted.toml");
            return Some(path);
        }

        // Fall back to ~/.config
        if let Ok(home) = std::env::var("HOME") {
            let path = PathBuf::from(home)
                .join(".config")
                .join("gh-restricted.toml");
            return Some(path);
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = Config::default();
        assert!(!config.allow_read_all);
    }

    #[test]
    fn test_parse_config() {
        let toml = r#"
            allow-read-all = true
        "#;
        let config: Config = toml::from_str(toml).unwrap();
        assert!(config.allow_read_all);
    }

    #[test]
    fn test_parse_empty_config() {
        let toml = "";
        let config: Config = toml::from_str(toml).unwrap();
        assert!(!config.allow_read_all);
    }
}
