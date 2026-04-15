//! Integration test runner for devaipod.
//!
//! This binary uses [`libtest_mimic`] instead of the built-in test harness so
//! that tests can be registered at link time via [`linkme`] distributed slices
//! (see `integration_tests::INTEGRATION_TESTS` and `READONLY_INTEGRATION_TESTS`).
//!
//! # Key infrastructure
//!
//! - **`PodGuard`** — RAII guard that force-removes pods and their named
//!   volumes on drop. Every test that calls `devaipod up` should register
//!   the pod name with a guard so cleanup happens even on panic/failure.
//! - **`TestRepo`** — creates a temporary git repo with a `devcontainer.json`,
//!   suitable for passing to `devaipod up`.
//! - **`CapturedOutput`** — wraps `std::process::Output` with decoded strings
//!   and helpers like `assert_success()` and `extract_pod_name()`.
//! - **Leaked pod cleanup** — on startup, `cleanup_leaked_test_pods()` removes
//!   any pods labelled `io.devaipod.instance=integration-test` left behind by
//!   a previous crashed run.
//! - **Synthetic config** — `setup_synthetic_config()` creates a minimal
//!   `devaipod.toml` in a tempdir and sets `XDG_CONFIG_HOME`, isolating tests
//!   from the user's real config (which may reference missing podman secrets).
//! - **Auto-spawned podman socket** — `ensure_podman_socket()` starts
//!   `podman system service` if no socket exists (needed in environments
//!   without systemd, e.g. devaipod-in-devaipod).
//!
//! # Test modules
//!
//! Tests are organized in `tests/`:
//!
//! | Module | Coverage |
//! |--------|----------|
//! | `cli` | CLI commands: up, delete, list, exec, stop/start |
//! | `container` | Container properties, readonly API queries |
//! | `pod_api` | Pod-api HTTP endpoints (summary, completion) |
//! | `webui` | Web UI container: auth, proxy, MCP |
//! | `ssh` | SSH config generation, server, client connectivity |
//! | `advisor` | Advisor/orchestration commands |
//! | `orchestration` | Multi-agent orchestration config |
//!
//! # Running
//!
//! ```sh
//! just test-integration        # containerized (canonical, used by CI)
//! just test-integration-local  # host binary, faster iteration
//! ```

use std::path::PathBuf;
use std::process::{Command, Output};

use color_eyre::eyre::{Context, Result, eyre};
use libtest_mimic::{Arguments, Trial};
use xshell::{Shell, cmd};

/// Guard that kills the podman system service when dropped.
///
/// This ensures the auto-spawned service lives exactly as long as the test run.
struct PodmanServiceGuard {
    child: std::process::Child,
}

impl Drop for PodmanServiceGuard {
    fn drop(&mut self) {
        eprintln!(
            "Stopping auto-spawned podman service (pid {})",
            self.child.id()
        );
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

// Re-export from lib for test registration
pub(crate) use integration_tests::{
    INTEGRATION_TESTS, READONLY_INTEGRATION_TESTS, SharedFixture, container_integration_test,
    integration_test, podman_integration_test, readonly_test,
    wait_for_container_running, wait_for_file,
};

mod tests;

// Re-export WebFixture for cleanup
use tests::WebFixture;

/// Create a new xshell Shell for running commands
pub(crate) fn shell() -> Result<Shell> {
    Shell::new().map_err(|e| eyre!("Failed to create shell: {}", e))
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

/// Check if any container socket exists that podman/bollard can connect to.
fn socket_available() -> bool {
    // Check the standard locations
    for path in &[
        "/run/docker.sock",
        "/var/run/docker.sock",
        "/run/podman/podman.sock",
    ] {
        if std::path::Path::new(path).exists() {
            return true;
        }
    }
    if let Ok(docker_host) = std::env::var("DOCKER_HOST") {
        if let Some(path) = docker_host.strip_prefix("unix://") {
            let path = if path.starts_with('/') {
                path.to_string()
            } else {
                format!("/{path}")
            };
            if std::path::Path::new(&path).exists() {
                return true;
            }
        }
    }
    if let Ok(xdg) = std::env::var("XDG_RUNTIME_DIR") {
        let sock = PathBuf::from(xdg).join("podman/podman.sock");
        if sock.exists() {
            return true;
        }
    }
    false
}

/// Ensure a podman API socket is available, auto-spawning one if necessary.
///
/// In environments without systemd (e.g. devaipod-in-devaipod where PID 1 is
/// `podman-init`), there is no socket activation. The podman CLI works fine,
/// but the bollard Docker API client (and `devaipod` itself) need a socket.
///
/// Returns a guard that keeps the spawned process alive; drop it to stop the
/// service. Returns `None` if a socket already exists or if podman is not
/// available.
fn ensure_podman_socket() -> Option<PodmanServiceGuard> {
    if socket_available() {
        return None;
    }

    eprintln!("No podman socket found; auto-starting podman system service...");

    // Pick a socket path — prefer XDG_RUNTIME_DIR, fall back to /tmp
    let socket_path = if let Ok(xdg) = std::env::var("XDG_RUNTIME_DIR") {
        PathBuf::from(xdg).join("podman/podman.sock")
    } else {
        let uid = rustix::process::getuid().as_raw();
        PathBuf::from(format!("/tmp/devaipod-podman-{uid}")).join("podman.sock")
    };

    // Clean up stale socket
    if socket_path.exists() {
        let _ = std::fs::remove_file(&socket_path);
    }

    // Create parent directory with restricted permissions
    if let Some(parent) = socket_path.parent() {
        use std::os::unix::fs::DirBuilderExt;
        if let Err(e) = std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(parent)
        {
            eprintln!(
                "Failed to create socket directory {}: {e}",
                parent.display()
            );
            return None;
        }
    }

    let mut cmd = Command::new("podman");
    cmd.args([
        "system",
        "service",
        "--time=0",
        &format!("unix://{}", socket_path.display()),
    ])
    .stdout(std::process::Stdio::null())
    .stderr(std::process::Stdio::null());

    // Lifecycle-bind the child to this process: if the test runner dies, the
    // kernel sends SIGTERM to the podman service. No orphans, no timeouts.
    #[cfg(target_os = "linux")]
    {
        use cap_std_ext::cmdext::CapStdExtCommandExt;
        cmd.lifecycle_bind_to_parent_thread();
    }

    let child = match cmd.spawn() {
        Ok(child) => child,
        Err(e) => {
            eprintln!("Failed to spawn podman system service: {e}");
            return None;
        }
    };

    // Wait for socket to appear
    for i in 0..50 {
        if socket_path.exists() {
            eprintln!(
                "Podman service ready at {} (took ~{}ms)",
                socket_path.display(),
                i * 100,
            );
            // Set DOCKER_HOST so all child processes (devaipod, podman CLI) find it.
            // SAFETY: called from main() before any threads are spawned.
            unsafe {
                std::env::set_var("DOCKER_HOST", format!("unix://{}", socket_path.display()))
            };
            return Some(PodmanServiceGuard { child });
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }

    eprintln!(
        "Timed out waiting for podman socket at {}",
        socket_path.display()
    );
    let mut child = child;
    let _ = child.kill();
    let _ = child.wait();
    None
}

/// Create a synthetic devaipod config in a temp directory and point
/// `XDG_CONFIG_HOME` at it. This isolates integration tests from the user's
/// real config (which may reference podman secrets that don't exist in
/// the test environment).
///
/// Returns the temp directory (must be kept alive for the duration of tests).
fn setup_synthetic_config() -> tempfile::TempDir {
    let config_dir = tempfile::TempDir::new().expect("create temp config dir");
    let config_path = config_dir.path().join("devaipod.toml");

    // Minimal config: no secrets, no dotfiles, just defaults.
    // Tests that need specific config can pass --config explicitly.
    std::fs::write(
        &config_path,
        "# Synthetic config for integration tests\n\
         # No secrets or dotfiles — avoids dependency on host podman secrets\n",
    )
    .expect("write synthetic config");

    // SAFETY: called from main() before threads are spawned.
    unsafe { std::env::set_var("XDG_CONFIG_HOME", config_dir.path()) };
    eprintln!("Using synthetic config at {}", config_path.display());

    config_dir
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

    /// Extract pod name from "Pod 'name' ready" message in output
    ///
    /// Returns None if the pattern is not found.
    pub fn extract_pod_name(&self) -> Option<String> {
        // Look in both stdout and stderr (tracing goes to stderr)
        for line in self.combined().lines() {
            // Match pattern like: INFO Pod 'devaipod-test-repo-abc123' ready
            if line.contains("ready") {
                if let Some(rest) = line.split("Pod '").nth(1) {
                    if let Some(name) = rest.split('\'').next() {
                        return Some(name.to_string());
                    }
                }
            }
        }
        None
    }
}

/// Build a base `Command` for running devaipod with the instance env var set.
///
/// Every integration-test invocation of devaipod carries
/// `DEVAIPOD_INSTANCE=integration-test` so that pods are labeled and isolated
/// from the user's normal interactive session.
///
/// Also sets `DEVAIPOD_HOST_MODE=1` so that devaipod doesn't refuse to run
/// outside its own container image (needed for local dev and devaipod-in-devaipod).
///
/// Honors `DEVAIPOD_PATH` to locate the binary (useful for local dev where
/// the binary is at `./target/debug/devaipod-server` instead of on `$PATH`).
fn devaipod_command() -> Command {
    let binary = std::env::var("DEVAIPOD_PATH").unwrap_or_else(|_| "devaipod-server".to_string());
    let mut cmd = Command::new(binary);
    cmd.env(
        "DEVAIPOD_INSTANCE",
        integration_tests::INTEGRATION_TEST_INSTANCE,
    );
    cmd.env("DEVAIPOD_HOST_MODE", "1");
    cmd
}

/// Run the devaipod command directly.
pub(crate) fn run_devaipod(args: &[&str]) -> Result<CapturedOutput> {
    let output = devaipod_command()
        .args(args)
        .output()
        .with_context(|| format!("Failed to run devaipod {:?}", args))?;
    Ok(CapturedOutput::new(output))
}

/// Run the devaipod command in a specific directory.
pub(crate) fn run_devaipod_in(dir: &std::path::Path, args: &[&str]) -> Result<CapturedOutput> {
    let output = devaipod_command()
        .current_dir(dir)
        .args(args)
        .output()
        .with_context(|| format!("Failed to run devaipod {:?} in {:?}", args, dir))?;
    Ok(CapturedOutput::new(output))
}

/// Run the devaipod command in a specific directory with extra environment variables.
pub(crate) fn run_devaipod_in_with_env(
    dir: &std::path::Path,
    args: &[&str],
    envs: &[(&str, &str)],
) -> Result<CapturedOutput> {
    let mut cmd = devaipod_command();
    cmd.current_dir(dir).args(args);
    for (k, v) in envs {
        cmd.env(k, v);
    }
    let output = cmd
        .output()
        .with_context(|| format!("Failed to run devaipod {:?} in {:?}", args, dir))?;
    Ok(CapturedOutput::new(output))
}

/// Run the devaipod command with extra environment variables.
pub(crate) fn run_devaipod_with_env(
    args: &[&str],
    envs: &[(&str, &str)],
) -> Result<CapturedOutput> {
    let mut cmd = devaipod_command();
    cmd.args(args);
    for (k, v) in envs {
        cmd.env(k, v);
    }
    let output = cmd
        .output()
        .with_context(|| format!("Failed to run devaipod {:?}", args))?;
    Ok(CapturedOutput::new(output))
}

/// Get the path to the devaipod binary.
///
/// In the containerized test runner, devaipod-server is at /usr/bin/devaipod-server.
/// Override with DEVAIPOD_PATH for local development.
pub(crate) fn get_devaipod_binary_path() -> Result<String> {
    if let Ok(path) = std::env::var("DEVAIPOD_PATH") {
        return Ok(path);
    }
    Ok("devaipod-server".to_string())
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

        // Create devcontainer.json - use test image from env (must have git)
        let devcontainer_dir = repo_path.join(".devcontainer");
        std::fs::create_dir_all(&devcontainer_dir)?;
        let test_image = std::env::var("DEVAIPOD_TEST_IMAGE")
            .unwrap_or_else(|_| "ghcr.io/bootc-dev/devenv-debian:latest".to_string());
        let devcontainer_json = format!(
            r#"{{
    "name": "integration-test",
    "image": "{}"
}}"#,
            test_image
        );
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

    /// Create a test repository with custom devcontainer.json content
    pub fn new_with_devcontainer(devcontainer_json: &str) -> Result<Self> {
        let temp_dir = tempfile::TempDir::new()?;
        let repo_path = temp_dir.path().join("test-repo");
        std::fs::create_dir_all(&repo_path)?;

        let sh = shell()?;
        let repo = repo_path.to_str().unwrap();

        // Initialize git repo
        cmd!(sh, "git -C {repo} init").run()?;
        cmd!(sh, "git -C {repo} config user.email test@example.com").run()?;
        cmd!(sh, "git -C {repo} config user.name 'Test User'").run()?;

        // Create devcontainer.json with provided content
        let devcontainer_dir = repo_path.join(".devcontainer");
        std::fs::create_dir_all(&devcontainer_dir)?;
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

/// The prefix devaipod adds to all pod names
const POD_NAME_PREFIX: &str = "devaipod-";

/// Generate a unique test pod name with the devaipod prefix
///
/// Uses timestamp + random bits to ensure uniqueness across parallel test runs.
/// Returns the full pod name as it will be created by devaipod (with prefix).
pub(crate) fn unique_test_name(prefix: &str) -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    // Use lower bits of timestamp + nanos for uniqueness
    let val = (now.as_secs() & 0xFFFF) ^ ((now.subsec_nanos() as u64) & 0xFFFF);
    format!("{}{}-{:x}", POD_NAME_PREFIX, prefix, val)
}

/// Get the short name (without prefix) for passing to --name
///
/// devaipod's --name flag will add the prefix automatically
pub(crate) fn short_name(full_name: &str) -> &str {
    full_name.strip_prefix(POD_NAME_PREFIX).unwrap_or(full_name)
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
        let ws_base = std::env::var("DEVAIPOD_HOST_WORKDIR")
            .map(std::path::PathBuf::from)
            .or_else(|_| {
                std::env::var("HOME")
                    .map(|h| std::path::PathBuf::from(h).join(".local/share/devaipod/workspaces"))
            })
            .ok();

        for name in &self.names {
            // Best effort cleanup - remove pod which removes all containers in it
            let _ = Command::new("podman")
                .args(["pod", "rm", "-f", name])
                .output();
            // Also try to remove associated volumes
            for suffix in integration_tests::POD_VOLUME_SUFFIXES {
                let volume_name = format!("{name}{suffix}");
                let _ = Command::new("podman")
                    .args(["volume", "rm", "-f", &volume_name])
                    .output();
            }
            // Remove host-side workspace directory.
            // Use `podman unshare` because files are owned by container subuids.
            if let Some(ref base) = ws_base {
                let ws_dir = base.join(name);
                if ws_dir.exists() {
                    let _ = Command::new("podman")
                        .args(["unshare", "rm", "-rf"])
                        .arg(&ws_dir)
                        .output();
                }
            }
        }
    }
}

/// Clean up any leaked pods from a previous integration test run.
///
/// Uses `podman pod ps --filter label=io.devaipod.instance=integration-test`
/// to find and remove pods that were left behind by a crashed or interrupted
/// test run.
fn cleanup_leaked_test_pods() {
    let label_filter = format!(
        "label=io.devaipod.instance={}",
        integration_tests::INTEGRATION_TEST_INSTANCE,
    );
    let output = Command::new("podman")
        .args([
            "pod",
            "ps",
            "--filter",
            &label_filter,
            "--format",
            "{{.Name}}",
        ])
        .output();

    let output = match output {
        Ok(o) if o.status.success() => o,
        _ => return,
    };

    let names = String::from_utf8_lossy(&output.stdout);
    for name in names.lines() {
        let name = name.trim();
        if name.is_empty() {
            continue;
        }
        eprintln!("Cleaning up leaked test pod: {}", name);
        let _ = Command::new("podman")
            .args(["pod", "rm", "-f", name])
            .output();
        for suffix in integration_tests::POD_VOLUME_SUFFIXES {
            let volume_name = format!("{name}{suffix}");
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

    // Use a synthetic config to isolate tests from the user's real config.
    // This avoids failures from missing podman secrets or user-specific settings.
    // Must be kept alive for the duration of the test run (tempdir is deleted on drop).
    let _synthetic_config = setup_synthetic_config();

    // Check if podman is available for filtering tests
    let has_podman = podman_available();
    if !has_podman {
        eprintln!("Note: podman not available, skipping podman-dependent tests");
    }

    // Ensure a podman API socket is available. In environments without systemd
    // (e.g. devaipod-in-devaipod), this auto-spawns `podman system service`.
    // The guard keeps the process alive for the duration of the test run.
    let _podman_service = if has_podman {
        ensure_podman_socket()
    } else {
        None
    };

    // Clean up any pods leaked by a previous test run before starting new tests
    if has_podman {
        cleanup_leaked_test_pods();
    }

    // Collect readonly tests - these use the shared fixture
    let readonly_tests: Vec<Trial> = if has_podman && !READONLY_INTEGRATION_TESTS.is_empty() {
        // Initialize the shared fixture before creating readonly test trials
        // We do this eagerly so any initialization errors are reported upfront
        let fixture_result = SharedFixture::get();

        if let Err(ref e) = fixture_result {
            eprintln!("Failed to create shared fixture: {:?}", e);
            eprintln!("Readonly tests will be skipped");
        }

        READONLY_INTEGRATION_TESTS
            .iter()
            .map(|test| {
                let name = test.name;
                let f = test.f;
                let fixture_ok = fixture_result.is_ok();

                let trial = Trial::test(name, move || {
                    if !fixture_ok {
                        return Err("Shared fixture initialization failed".into());
                    }
                    // Safe to unwrap since we checked fixture_ok
                    let fixture = SharedFixture::get().map_err(|e| format!("{:?}", e))?;
                    f(fixture).map_err(|e| format!("{:?}", e).into())
                });

                // Mark as ignored if fixture failed
                if !fixture_ok {
                    trial.with_ignored_flag(true)
                } else {
                    trial
                }
            })
            .collect()
    } else {
        // Skip readonly tests if no podman or no tests registered
        READONLY_INTEGRATION_TESTS
            .iter()
            .map(|test| Trial::test(test.name, || Ok(())).with_ignored_flag(true))
            .collect()
    };

    let has_container_image = std::env::var("DEVAIPOD_CONTAINER_IMAGE").is_ok();

    // Collect mutating tests from the distributed slice
    let mutating_tests: Vec<Trial> = INTEGRATION_TESTS
        .iter()
        .map(|test| {
            let name = test.name;
            let f = test.f;
            let requires_podman = test.requires_podman;
            let requires_container_image = test.requires_container_image;

            let mut trial = Trial::test(name, move || f().map_err(|e| format!("{:?}", e).into()));

            // Mark podman tests as ignored if podman is not available
            if requires_podman && !has_podman {
                trial = trial.with_ignored_flag(true);
            }

            // Mark container-image tests as ignored when image is not built
            if requires_container_image && !has_container_image {
                trial = trial.with_ignored_flag(true);
            }

            trial
        })
        .collect();

    // Combine all tests
    let all_tests: Vec<Trial> = readonly_tests.into_iter().chain(mutating_tests).collect();

    // Run the tests
    let conclusion = libtest_mimic::run(&args, all_tests);

    // Clean up the shared fixtures after all tests complete
    if has_podman {
        if !READONLY_INTEGRATION_TESTS.is_empty() {
            SharedFixture::cleanup();
        }
        // Clean up web fixture (used by webui tests)
        WebFixture::cleanup();
    }

    // Exit with the result
    conclusion.exit();
}
