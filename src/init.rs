//! First-time user setup wizard for devaipod
//!
//! This module provides an interactive configuration wizard that helps users:
//! - Configure a dotfiles/homegit repository
//! - Set up forge tokens (GitHub, GitLab, Forgejo) via podman secrets
//! - Generate a devaipod.toml configuration file

use std::path::Path;
use std::process::Command;

use color_eyre::eyre::{bail, Context, Result};
use dialoguer::{Confirm, Input, Password, Select};

use crate::config;

/// Check if podman is available on the system
fn check_podman_available() -> Result<()> {
    let output = Command::new("podman")
        .args(["--version"])
        .output()
        .context("Failed to run 'podman --version'")?;

    if !output.status.success() {
        bail!(
            "podman is not working properly. Please install podman first.\n\
             See: https://podman.io/getting-started/installation"
        );
    }
    Ok(())
}

/// Token creation URLs for supported forges
const GITHUB_TOKEN_URL: &str =
    "https://github.com/settings/tokens/new?description=devaipod&scopes=repo,read:org";
const GITLAB_TOKEN_URL: &str = "https://gitlab.com/-/user_settings/personal_access_tokens";
const FORGEJO_TOKEN_DOCS: &str = "https://forgejo.org/docs/latest/user/oauth2-provider/";

/// Supported forge types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ForgeType {
    GitHub,
    GitLab,
    Forgejo,
}

impl ForgeType {
    fn name(&self) -> &'static str {
        match self {
            ForgeType::GitHub => "GitHub",
            ForgeType::GitLab => "GitLab",
            ForgeType::Forgejo => "Forgejo/Gitea",
        }
    }

    fn token_env_var(&self) -> &'static str {
        match self {
            ForgeType::GitHub => "GH_TOKEN",
            ForgeType::GitLab => "GITLAB_TOKEN",
            ForgeType::Forgejo => "FORGEJO_TOKEN",
        }
    }

    fn secret_name(&self) -> &'static str {
        match self {
            ForgeType::GitHub => "gh_token",
            ForgeType::GitLab => "gitlab_token",
            ForgeType::Forgejo => "forgejo_token",
        }
    }

    fn token_creation_url(&self) -> &'static str {
        match self {
            ForgeType::GitHub => GITHUB_TOKEN_URL,
            ForgeType::GitLab => GITLAB_TOKEN_URL,
            ForgeType::Forgejo => FORGEJO_TOKEN_DOCS,
        }
    }
}

/// Configuration gathered during the init wizard
#[derive(Debug, Default)]
struct InitConfig {
    dotfiles_url: Option<String>,
    forges: Vec<ForgeType>,
}

/// Run the init command
pub fn cmd_init(config_path: Option<&Path>) -> Result<()> {
    let config_path = config_path
        .map(|p| p.to_path_buf())
        .unwrap_or_else(config::config_path);

    println!();
    println!("Welcome to devaipod setup!");
    println!();
    println!("This wizard will help you configure devaipod for first-time use.");

    // Check if config already exists
    if config_path.exists() {
        println!();
        let overwrite = Confirm::new()
            .with_prompt(format!(
                "Configuration file already exists at {}. Overwrite?",
                config_path.display()
            ))
            .default(false)
            .interact()?;

        if !overwrite {
            println!("Aborted. Existing configuration preserved.");
            return Ok(());
        }
    }

    // Check that podman is available before starting
    check_podman_available()?;

    let mut init_config = InitConfig::default();

    // Step 1: Dotfiles/homegit repository
    configure_dotfiles(&mut init_config)?;

    // Step 2: Forge selection and token setup
    configure_forges(&mut init_config)?;

    // Step 3: Generate and write config file
    write_config(&config_path, &init_config)?;

    println!();
    println!("Configuration written to {}", config_path.display());
    println!();

    // Suggest agent configuration
    suggest_agent_config(&init_config);

    println!("You can now run 'devaipod up <path>' to start a workspace!");
    println!();

    Ok(())
}

/// Configure dotfiles/homegit repository
fn configure_dotfiles(config: &mut InitConfig) -> Result<()> {
    println!("--- Dotfiles Configuration ---");
    println!();
    println!("devaipod can clone and install dotfiles in your workspaces.");
    println!("A 'homegit' repository (your $HOME in git) works well for this.");
    println!();

    let use_dotfiles = Confirm::new()
        .with_prompt("Would you like to configure a dotfiles repository?")
        .default(true)
        .interact()?;

    if use_dotfiles {
        let url: String = Input::new()
            .with_prompt("Dotfiles repository URL (e.g., https://github.com/you/dotfiles)")
            .interact_text()?;

        if !url.is_empty() {
            println!();
            println!("Tip: Consider storing your devaipod and agent configuration");
            println!("     in this repository for a consistent experience across machines.");
            println!();
            config.dotfiles_url = Some(url);
        }
    }

    Ok(())
}

/// Configure forge tokens
fn configure_forges(config: &mut InitConfig) -> Result<()> {
    println!();
    println!("--- Forge Token Configuration (Optional) ---");
    println!();
    println!("Forge tokens (via podman secrets) enable AI agents to interact");
    println!("with GitHub, GitLab, or Forgejo (e.g., creating PRs).");
    println!("You can skip this step and configure tokens later.");
    println!();

    let configure_forge = Confirm::new()
        .with_prompt("Would you like to configure a forge token now?")
        .default(false)
        .interact()?;

    if !configure_forge {
        println!();
        println!("Skipping forge configuration. You can add tokens later with:");
        println!("  echo 'your-token' | podman secret create gh_token -");
        println!();
        println!("Then add to your devaipod.toml:");
        println!("  [trusted]");
        println!("  secrets = [\"GH_TOKEN=gh_token\"]");
        return Ok(());
    }

    let forge_options = ["GitHub", "GitLab", "Forgejo/Gitea"];
    let selections = Select::new()
        .with_prompt("Which forge would you like to configure?")
        .items(&forge_options)
        .default(0)
        .interact()?;

    let selected_forge = match selections {
        0 => ForgeType::GitHub,
        1 => ForgeType::GitLab,
        _ => ForgeType::Forgejo,
    };

    config.forges.push(selected_forge);
    setup_forge_token(selected_forge)?;

    // Ask about additional forges
    loop {
        let add_more = Confirm::new()
            .with_prompt("Would you like to configure another forge?")
            .default(false)
            .interact()?;

        if !add_more {
            break;
        }

        let remaining: Vec<_> = [ForgeType::GitHub, ForgeType::GitLab, ForgeType::Forgejo]
            .into_iter()
            .filter(|f| !config.forges.contains(f))
            .collect();

        if remaining.is_empty() {
            println!("All forges already configured.");
            break;
        }

        let options: Vec<_> = remaining.iter().map(|f| f.name()).collect();
        let selection = Select::new()
            .with_prompt("Select forge to configure")
            .items(&options)
            .interact()?;

        let forge = remaining[selection];
        config.forges.push(forge);
        setup_forge_token(forge)?;
    }

    Ok(())
}

/// Set up a token for a specific forge
fn setup_forge_token(forge: ForgeType) -> Result<()> {
    println!();
    println!("--- {} Token Setup ---", forge.name());
    println!();

    // Check if secret already exists
    let secret_exists = check_podman_secret_exists(forge.secret_name())?;
    if secret_exists {
        println!("Podman secret '{}' already exists.", forge.secret_name());
        let update = Confirm::new()
            .with_prompt("Would you like to update it?")
            .default(false)
            .interact()?;

        if !update {
            return Ok(());
        }
    }

    println!("To create a {} token:", forge.name());
    println!();
    println!("  1. Open: {}", forge.token_creation_url());
    println!();

    match forge {
        ForgeType::GitHub => {
            println!("  2. Create a token with these scopes:");
            println!("     - repo (for PR creation and code access)");
            println!("     - read:org (for organization repositories)");
        }
        ForgeType::GitLab => {
            println!("  2. Create a token with these scopes:");
            println!("     - api (for full API access)");
            println!("     - read_repository (for code access)");
        }
        ForgeType::Forgejo => {
            println!("  2. Go to Settings > Applications > Generate New Token");
            println!("     - Select 'repo' scope for repository access");
        }
    }
    println!();

    let ready = Confirm::new()
        .with_prompt("Do you have your token ready to enter?")
        .default(true)
        .interact()?;

    if !ready {
        println!();
        println!("You can set up the token later by running:");
        println!(
            "  echo 'your-token' | podman secret create {} -",
            forge.secret_name()
        );
        println!();
        return Ok(());
    }

    // Get the token (hidden input for security)
    let token: String = Password::new()
        .with_prompt(format!("Enter your {} token (input hidden)", forge.name()))
        .allow_empty_password(true)
        .interact()?;

    if token.is_empty() {
        println!("No token provided, skipping.");
        return Ok(());
    }

    // Create or update the podman secret
    create_podman_secret(forge.secret_name(), &token, secret_exists)?;

    println!("Token stored as podman secret '{}'.", forge.secret_name());

    Ok(())
}

/// Check if a podman secret exists
fn check_podman_secret_exists(name: &str) -> Result<bool> {
    let output = Command::new("podman")
        .args(["secret", "inspect", name])
        .output()
        .context("Failed to run podman secret inspect")?;

    Ok(output.status.success())
}

/// Create or update a podman secret
fn create_podman_secret(name: &str, value: &str, update: bool) -> Result<()> {
    // If updating, remove the old secret first
    if update {
        let status = Command::new("podman")
            .args(["secret", "rm", name])
            .status()
            .context("Failed to remove existing secret")?;

        if !status.success() {
            bail!("Failed to remove existing secret '{}'", name);
        }
    }

    // Create the new secret
    let mut child = Command::new("podman")
        .args(["secret", "create", name, "-"])
        .stdin(std::process::Stdio::piped())
        .spawn()
        .context("Failed to spawn podman secret create")?;

    use std::io::Write;
    if let Some(mut stdin) = child.stdin.take() {
        stdin
            .write_all(value.as_bytes())
            .context("Failed to write secret value")?;
    }

    let status = child.wait().context("Failed to wait for podman")?;
    if !status.success() {
        bail!("Failed to create podman secret '{}'", name);
    }

    Ok(())
}

/// Escape a string for use in TOML (handles backslashes and quotes)
fn escape_toml_string(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

/// Write the configuration file
fn write_config(path: &Path, config: &InitConfig) -> Result<()> {
    let mut content = String::new();

    content.push_str("# devaipod configuration\n");
    content.push_str("# Generated by 'devaipod init'\n");
    content.push_str("#\n");
    content.push_str(
        "# See https://github.com/cgwalters/devaipod#configuration for full documentation\n",
    );
    content.push('\n');

    // Dotfiles configuration
    if let Some(ref url) = config.dotfiles_url {
        content.push_str("# Dotfiles repository to clone into workspaces\n");
        content.push_str("[dotfiles]\n");
        content.push_str(&format!("url = \"{}\"\n", escape_toml_string(url)));
        content.push_str("# script = \"install.sh\"  # Optional: custom install script\n");
        content.push('\n');
    }

    // Trusted environment for forge tokens
    if !config.forges.is_empty() {
        content.push_str(
            "# Trusted secrets - available to workspace and service-gator, but NOT the AI agent\n",
        );
        content.push_str("# This keeps your tokens secure while enabling forge integration\n");
        content.push_str("[trusted]\n");
        content.push_str("secrets = [\n");
        for forge in &config.forges {
            content.push_str(&format!(
                "    \"{}={}\",\n",
                forge.token_env_var(),
                forge.secret_name()
            ));
        }
        content.push_str("]\n");
        content.push('\n');
    }

    // Service-gator configuration hint
    if config.forges.contains(&ForgeType::GitHub) {
        content.push_str("# Service-gator configuration for AI agent access to GitHub\n");
        content.push_str("# Uncomment and customize to enable:\n");
        content.push_str("#\n");
        content.push_str("# [service-gator.gh.repos]\n");
        content.push_str("# # Allow read access to all your repos\n");
        content.push_str("# \"your-username/*\" = { read = true }\n");
        content.push_str("# # Allow creating draft PRs in specific repos\n");
        content.push_str("# \"your-username/your-repo\" = { read = true, create-draft = true }\n");
        content.push('\n');
    }

    // Environment configuration hint
    content.push_str("# Environment variables for containers (workspace + agent)\n");
    content
        .push_str("# Configure your LLM API key here. See: https://opencode.ai/docs/providers/\n");
    content.push_str("#\n");
    content.push_str("# [env]\n");
    content.push_str("# # Forward from your shell environment\n");
    content.push_str("# allowlist = [\"ANTHROPIC_API_KEY\"]  # or OPENAI_API_KEY, etc.\n");
    content.push_str("#\n");
    content.push_str("# # Or set explicitly (less secure - visible in podman inspect)\n");
    content.push_str("# [env.vars]\n");
    content.push_str("# ANTHROPIC_API_KEY = \"your-key\"\n");

    // Ensure parent directory exists
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("Failed to create directory {}", parent.display()))?;
    }

    std::fs::write(path, &content)
        .with_context(|| format!("Failed to write config to {}", path.display()))?;

    Ok(())
}

/// Suggest agent configuration
fn suggest_agent_config(config: &InitConfig) {
    println!("--- Agent Configuration ---");
    println!();
    println!("devaipod supports any ACP-compatible agent (OpenCode, Goose, etc.).");
    println!();
    println!("Recommended next steps:");
    println!();
    println!("  1. Configure your LLM provider. See: https://opencode.ai/docs/providers/");
    println!();
    println!("     Add your API key to ~/.config/devaipod.toml:");
    println!();
    println!("     [env]");
    println!("     allowlist = [\"ANTHROPIC_API_KEY\"]  # or OPENAI_API_KEY, etc.");
    println!();

    if let Some(ref dotfiles_url) = config.dotfiles_url {
        println!("  2. Consider adding agent config to your dotfiles:");
        println!("     Agent config files are pointed to via env vars in agent profiles.");
        println!("     See the [agent.profiles] section in devaipod.toml.");
        println!();
        println!("     Your dotfiles repo: {}", dotfiles_url);
        println!();
    } else {
        println!("  2. Configure agent profiles in ~/.config/devaipod.toml:");
        println!("     [agent.profiles.opencode]");
        println!("     command = [\"opencode\", \"acp\"]");
        println!();
    }

    println!("  For OpenCode docs: https://opencode.ai/docs");
    println!();
}
