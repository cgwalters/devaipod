//! Integration tests for devc

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use color_eyre::eyre::{bail, Context, Result};
use libtest_mimic::{Arguments, Trial};

// Re-export from lib for test registration
pub(crate) use integration_tests::{integration_test, podman_integration_test, INTEGRATION_TESTS};

mod tests;

/// Get the path to the devc binary
///
/// Checks DEVC_PATH env var first, then looks for the binary in target directories.
pub(crate) fn get_devc_command() -> Result<PathBuf> {
    if let Ok(path) = std::env::var("DEVC_PATH") {
        return Ok(PathBuf::from(path));
    }

    // Look for the binary in target directories
    let candidates = ["target/debug/devc", "target/release/devc"];
    for candidate in candidates {
        let path = PathBuf::from(candidate);
        if path.exists() {
            return Ok(path.canonicalize()?);
        }
    }

    // Fall back to hoping it's in PATH
    Ok(PathBuf::from("devc"))
}

/// Check if podman is available
pub(crate) fn podman_available() -> bool {
    Command::new("podman")
        .args(["--version"])
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

/// Run the devc command, capturing output
pub(crate) fn run_devc(args: &[&str]) -> Result<CapturedOutput> {
    let devc = get_devc_command()?;
    let output = Command::new(&devc)
        .args(args)
        .output()
        .with_context(|| format!("Failed to run devc {:?}", args))?;
    Ok(CapturedOutput::new(output))
}

/// Run the devc command in a specific directory
pub(crate) fn run_devc_in(dir: &Path, args: &[&str]) -> Result<CapturedOutput> {
    let devc = get_devc_command()?;
    let output = Command::new(&devc)
        .current_dir(dir)
        .args(args)
        .output()
        .with_context(|| format!("Failed to run devc {:?} in {:?}", args, dir))?;
    Ok(CapturedOutput::new(output))
}

/// Run a generic command, capturing output
pub(crate) fn run_command(program: &str, args: &[&str]) -> Result<CapturedOutput> {
    let output = Command::new(program)
        .args(args)
        .output()
        .with_context(|| format!("Failed to run {} {:?}", program, args))?;
    Ok(CapturedOutput::new(output))
}

/// Run a command and assert it succeeded, returning stdout
pub(crate) fn run_command_success(program: &str, args: &[&str]) -> Result<String> {
    let output = run_command(program, args)?;
    if !output.success() {
        bail!(
            "{} {:?} failed:\nstdout: {}\nstderr: {}",
            program,
            args,
            output.stdout,
            output.stderr
        );
    }
    Ok(output.stdout)
}

/// Create a temporary git repository for testing
pub(crate) struct TestRepo {
    /// Keep the temp dir alive for the lifetime of the test
    #[allow(dead_code)]
    base_dir: tempfile::TempDir,
    pub repo_path: PathBuf,
    pub worktrees_dir: PathBuf,
}

impl TestRepo {
    pub fn new() -> Result<Self> {
        let base_dir = tempfile::TempDir::new()?;
        let repo_path = base_dir.path().join("test-repo");
        std::fs::create_dir_all(&repo_path)?;

        // Initialize git repo
        run_command_success("git", &["-C", repo_path.to_str().unwrap(), "init"])?;
        run_command_success(
            "git",
            &[
                "-C",
                repo_path.to_str().unwrap(),
                "config",
                "user.email",
                "test@example.com",
            ],
        )?;
        run_command_success(
            "git",
            &[
                "-C",
                repo_path.to_str().unwrap(),
                "config",
                "user.name",
                "Test User",
            ],
        )?;

        // Create devfile
        let devfile = r#"schemaVersion: "2.2.0"
metadata:
  name: integration-test
  version: 1.0.0
  description: Integration test container

components:
  - name: dev
    container:
      image: docker.io/library/alpine:latest
      command: ['/bin/sh']
      args: ['-c', 'sleep infinity']
      mountSources: true
      env:
        - name: TEST_VAR
          value: integration-test-value
"#;
        std::fs::write(repo_path.join("devfile.yaml"), devfile)?;
        std::fs::write(repo_path.join("README.md"), "# Test Repo\n")?;

        // Commit
        run_command_success("git", &["-C", repo_path.to_str().unwrap(), "add", "."])?;
        run_command_success(
            "git",
            &[
                "-C",
                repo_path.to_str().unwrap(),
                "commit",
                "-m",
                "Initial commit",
            ],
        )?;

        let worktrees_dir = base_dir.path().join("test-repo.worktrees");
        std::fs::create_dir_all(&worktrees_dir)?;

        Ok(TestRepo {
            base_dir,
            repo_path,
            worktrees_dir,
        })
    }

    /// Create a git worktree
    pub fn create_worktree(&self, name: &str) -> Result<PathBuf> {
        let worktree_path = self.worktrees_dir.join(name);
        let branch_name = format!("branch-{}", name);

        // Create branch
        run_command_success(
            "git",
            &[
                "-C",
                self.repo_path.to_str().unwrap(),
                "branch",
                "-f",
                &branch_name,
                "HEAD",
            ],
        )?;

        // Create worktree
        run_command_success(
            "git",
            &[
                "-C",
                self.repo_path.to_str().unwrap(),
                "worktree",
                "add",
                worktree_path.to_str().unwrap(),
                &branch_name,
            ],
        )?;

        Ok(worktree_path)
    }
}

/// Container cleanup helper
pub(crate) struct ContainerGuard {
    names: Vec<String>,
}

impl ContainerGuard {
    pub fn new() -> Self {
        ContainerGuard { names: Vec::new() }
    }

    pub fn add(&mut self, name: &str) {
        self.names.push(name.to_string());
    }
}

impl Drop for ContainerGuard {
    fn drop(&mut self) {
        for name in &self.names {
            // Best effort cleanup
            let _ = Command::new("podman").args(["rm", "-f", name]).output();
        }
    }
}

/// Pod cleanup helper
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
        }
    }
}

/// Volume cleanup helper
pub(crate) struct VolumeGuard {
    names: Vec<String>,
}

impl VolumeGuard {
    pub fn new() -> Self {
        VolumeGuard { names: Vec::new() }
    }

    pub fn add(&mut self, name: &str) {
        self.names.push(name.to_string());
    }
}

impl Drop for VolumeGuard {
    fn drop(&mut self) {
        for name in &self.names {
            // First remove any containers using the volume
            let _ = Command::new("podman")
                .args(["rm", "-f", &format!("devfile-{}-dev", name)])
                .output();
            // Then remove the volume
            let _ = Command::new("podman")
                .args(["volume", "rm", "-f", &format!("devc-{}", name)])
                .output();
        }
    }
}

/// Get container name for a worktree
pub(crate) fn container_name(worktree_path: &Path) -> String {
    let dir_name = worktree_path.file_name().unwrap().to_str().unwrap();
    format!("devfile-{}-dev", dir_name)
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
