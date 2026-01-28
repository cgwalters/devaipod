//! Integration tests for devaipod
//!
//! Run with: cargo test -p integration-tests
//! Or: DEVAIPOD_PATH=./target/debug/devaipod cargo test -p integration-tests

use std::path::PathBuf;
use std::process::{Command, Output};

use color_eyre::eyre::{eyre, Context, Result};
use libtest_mimic::{Arguments, Trial};
use xshell::{cmd, Shell};

// Re-export from lib for test registration
pub(crate) use integration_tests::{integration_test, podman_integration_test, INTEGRATION_TESTS};

mod tests;

/// Create a new xshell Shell for running commands
pub(crate) fn shell() -> Result<Shell> {
    Shell::new().map_err(|e| eyre!("Failed to create shell: {}", e))
}

/// Get the workspace root directory by finding the Cargo.lock file
fn find_workspace_root() -> Option<std::path::PathBuf> {
    let mut dir = std::env::current_dir().ok()?;
    loop {
        if dir.join("Cargo.lock").exists() {
            return Some(dir);
        }
        if !dir.pop() {
            return None;
        }
    }
}

/// Get the path to the devaipod binary
///
/// Checks DEVAIPOD_PATH env var first, then looks for the binary in target directories.
/// Always returns an absolute path to ensure it works from any working directory.
pub(crate) fn get_devaipod_command() -> Result<String> {
    if let Ok(path) = std::env::var("DEVAIPOD_PATH") {
        // Convert to absolute path if relative
        let path = std::path::PathBuf::from(&path);
        if path.is_relative() {
            // Resolve relative to workspace root (where Cargo.lock is)
            if let Some(workspace_root) = find_workspace_root() {
                let abs_path = workspace_root.join(&path);
                if abs_path.exists() {
                    return Ok(abs_path.canonicalize()?.to_string_lossy().to_string());
                }
            }
            // Try current directory as fallback
            let cwd = std::env::current_dir()?;
            let abs_path = cwd.join(&path);
            if abs_path.exists() {
                return Ok(abs_path.canonicalize()?.to_string_lossy().to_string());
            }
            return Err(eyre!("Cannot find devaipod binary at {}", path.display()));
        }
        return Ok(path.to_string_lossy().to_string());
    }

    // Look for the binary in target directories relative to workspace root
    let workspace_root = find_workspace_root();
    let candidates = ["target/debug/devaipod", "target/release/devaipod"];
    for candidate in candidates {
        let path = if let Some(ref root) = workspace_root {
            root.join(candidate)
        } else {
            std::path::PathBuf::from(candidate)
        };
        if path.exists() {
            return Err(eyre!(
                "Detected {} - set DEVAIPOD_PATH={} to run using this binary",
                path.display(),
                candidate
            ));
        }
    }

    // Fall back to hoping it's in PATH
    Ok("devaipod".to_string())
}

/// Check if podman is available
pub(crate) fn podman_available() -> bool {
    let Ok(sh) = Shell::new() else {
        return false;
    };
    cmd!(sh, "podman --version")
        .ignore_status()
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Captured output from a command with decoded stdout/stderr strings
pub(crate) struct CapturedOutput {
    pub output: Output,
    pub stdout: String,
    pub stderr: String,
}

impl CapturedOutput {
    /// Create from a raw Output
    pub fn new(output: Output) -> Self {
        let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
        Self {
            output,
            stdout,
            stderr,
        }
    }

    /// Combined stdout and stderr
    pub fn combined(&self) -> String {
        format!("{}\n{}", self.stdout, self.stderr)
    }

    /// Assert that the command succeeded, printing debug info on failure
    pub fn assert_success(&self, context: &str) {
        assert!(
            self.output.status.success(),
            "{} failed:\nstdout: {}\nstderr: {}",
            context,
            self.stdout,
            self.stderr
        );
    }

    /// Check if the command succeeded
    pub fn success(&self) -> bool {
        self.output.status.success()
    }
}

/// Run the devaipod command, capturing output
///
/// This uses std::process::Command for consistent CapturedOutput handling.
pub(crate) fn run_devaipod(args: &[&str]) -> Result<CapturedOutput> {
    let devaipod = get_devaipod_command()?;
    let output = Command::new(&devaipod)
        .args(args)
        .output()
        .with_context(|| format!("Failed to run devaipod {:?}", args))?;
    Ok(CapturedOutput::new(output))
}

/// Run the devaipod command in a specific directory
pub(crate) fn run_devaipod_in(dir: &std::path::Path, args: &[&str]) -> Result<CapturedOutput> {
    let devaipod = get_devaipod_command()?;
    let output = Command::new(&devaipod)
        .current_dir(dir)
        .args(args)
        .output()
        .with_context(|| format!("Failed to run devaipod {:?} in {:?}", args, dir))?;
    Ok(CapturedOutput::new(output))
}

/// Create a temporary git repository for testing
pub(crate) struct TestRepo {
    /// Keep the temp dir alive for the lifetime of the test
    #[allow(dead_code)]
    pub temp_dir: tempfile::TempDir,
    pub repo_path: PathBuf,
}

impl TestRepo {
    /// Create a new test repository with a devcontainer.json
    pub fn new() -> Result<Self> {
        let temp_dir = tempfile::TempDir::new()?;
        let repo_path = temp_dir.path().join("test-repo");
        std::fs::create_dir_all(&repo_path)?;

        let sh = shell()?;
        let repo = repo_path.to_str().unwrap();

        // Initialize git repo
        cmd!(sh, "git -C {repo} init").run()?;
        cmd!(sh, "git -C {repo} config user.email test@example.com").run()?;
        cmd!(sh, "git -C {repo} config user.name 'Test User'").run()?;

        // Create devcontainer.json
        let devcontainer_dir = repo_path.join(".devcontainer");
        std::fs::create_dir_all(&devcontainer_dir)?;
        let devcontainer_json = r#"{
    "name": "integration-test",
    "image": "docker.io/library/alpine:latest"
}"#;
        std::fs::write(
            devcontainer_dir.join("devcontainer.json"),
            devcontainer_json,
        )?;
        std::fs::write(repo_path.join("README.md"), "# Test Repo\n")?;

        // Add remote (required by devaipod)
        cmd!(
            sh,
            "git -C {repo} remote add origin https://github.com/test/test-repo.git"
        )
        .run()?;

        // Commit
        cmd!(sh, "git -C {repo} add .").run()?;
        cmd!(sh, "git -C {repo} commit -m 'Initial commit'").run()?;

        Ok(TestRepo {
            temp_dir,
            repo_path,
        })
    }

    /// Create a minimal test repo (just git init, no devcontainer)
    pub fn new_minimal() -> Result<Self> {
        let temp_dir = tempfile::TempDir::new()?;
        let repo_path = temp_dir.path().join("minimal-repo");
        std::fs::create_dir_all(&repo_path)?;

        let sh = shell()?;
        let repo = repo_path.to_str().unwrap();

        // Initialize git repo
        cmd!(sh, "git -C {repo} init").run()?;
        cmd!(sh, "git -C {repo} config user.email test@example.com").run()?;
        cmd!(sh, "git -C {repo} config user.name 'Test User'").run()?;

        std::fs::write(repo_path.join("README.md"), "# Minimal Repo\n")?;

        // Add remote
        cmd!(
            sh,
            "git -C {repo} remote add origin https://github.com/test/minimal-repo.git"
        )
        .run()?;

        // Commit
        cmd!(sh, "git -C {repo} add .").run()?;
        cmd!(sh, "git -C {repo} commit -m 'Initial commit'").run()?;

        Ok(TestRepo {
            temp_dir,
            repo_path,
        })
    }
}

/// Pod cleanup helper - removes pods on drop
///
/// Uses std::process::Command because Shell::new() is fallible in Drop contexts.
pub(crate) struct PodGuard {
    names: Vec<String>,
}

impl PodGuard {
    pub fn new() -> Self {
        PodGuard { names: Vec::new() }
    }

    pub fn add(&mut self, name: &str) {
        self.names.push(name.to_string());
    }
}

impl Drop for PodGuard {
    fn drop(&mut self) {
        for name in &self.names {
            // Best effort cleanup - remove pod which removes all containers in it
            let _ = Command::new("podman")
                .args(["pod", "rm", "-f", name])
                .output();
            // Also try to remove associated volume
            let volume_name = format!("{}-workspace", name);
            let _ = Command::new("podman")
                .args(["volume", "rm", "-f", &volume_name])
                .output();
        }
    }
}

fn main() {
    // Initialize tracing for better debug output
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .init();

    let args = Arguments::from_args();

    // Check if podman is available for filtering tests
    let has_podman = podman_available();
    if !has_podman {
        eprintln!("Note: podman not available, skipping podman-dependent tests");
    }

    // Collect tests from the distributed slice
    let tests: Vec<Trial> = INTEGRATION_TESTS
        .iter()
        .map(|test| {
            let name = test.name;
            let f = test.f;
            let requires_podman = test.requires_podman;

            let mut trial = Trial::test(name, move || f().map_err(|e| format!("{:?}", e).into()));

            // Mark podman tests as ignored if podman is not available
            if requires_podman && !has_podman {
                trial = trial.with_ignored_flag(true);
            }

            trial
        })
        .collect();

    // Run the tests and exit with the result
    libtest_mimic::run(&args, tests).exit();
}
