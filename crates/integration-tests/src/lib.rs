//! Shared library code for devaipod integration tests.
//!
//! This crate provides macros and types for registering tests, plus the
//! [`SharedFixture`] used by readonly tests.
//!
//! # Test registration macros
//!
//! Tests are registered via [`linkme`] distributed slices, not the standard
//! `#[test]` attribute. Each macro corresponds to a test category:
//!
//! - [`integration_test!`] — basic tests (no podman needed)
//! - [`podman_integration_test!`] — tests that create/destroy their own pods
//! - [`container_integration_test!`] — tests requiring the pre-built container
//!   image (`DEVAIPOD_CONTAINER_IMAGE`); skipped by `just test-integration-local`
//! - [`readonly_test!`] — tests that share a single pod via [`SharedFixture`]
//!   and must not mutate pod state
//!
//! # Shared fixture
//!
//! [`SharedFixture`] creates a pod (`devaipod-integration-shared`) once via
//! [`OnceLock`] and reuses it across all `readonly_test!` tests. It waits for
//! the pod-api healthcheck to report healthy before returning, so tests can
//! query the API immediately.
//!
//! # Volume cleanup
//!
//! Each pod creates up to 4 named volumes (see [`POD_VOLUME_SUFFIXES`]).
//! [`SharedFixture::cleanup`] removes these on teardown. Tests that create
//! their own pods should use `PodGuard` (in the test runner binary) which
//! removes pods and volumes on drop. Volumes can leak if a test run is
//! killed by SIGKILL; run `podman volume prune` periodically.
//!
//! [`OnceLock`]: std::sync::OnceLock

// Unfortunately needed here to work with linkme
#![allow(unsafe_code)]

pub mod harness;

use std::path::PathBuf;
use std::sync::OnceLock;

/// Value used for the DEVAIPOD_INSTANCE environment variable during tests.
///
/// This causes all pods created by integration tests to carry an
/// `io.devaipod.instance=integration-test` label, isolating them from
/// the user's normal devaipod session. If a test leaks a pod, the main
/// instance won't see it.
pub const INTEGRATION_TEST_INSTANCE: &str = "integration-test";

/// Name used for the shared integration test pod
pub const SHARED_POD_NAME: &str = "devaipod-integration-shared";

/// Volume suffixes created by devaipod pods (used for cleanup).
///
/// Each pod creates a main workspace volume (`-workspace`) and an agent home
/// volume (`-agent-home`).  When orchestration is enabled, worker volumes
/// are also created.  Cleanup must remove all of these.
pub const POD_VOLUME_SUFFIXES: &[&str] = &[
    "-workspace",
    "-agent-home",
    "-agent-workspace",
    "-worker-home",
    "-worker-workspace",
];

/// A test function that returns a Result
pub type TestFn = fn() -> color_eyre::Result<()>;

/// A readonly test function that receives a SharedFixture reference
pub type ReadonlyTestFn = fn(&SharedFixture) -> color_eyre::Result<()>;

/// Metadata for a registered integration test
#[derive(Debug)]
pub struct IntegrationTest {
    /// Name of the integration test
    pub name: &'static str,
    /// Test function to execute
    pub f: TestFn,
    /// Whether this test requires podman (should be skipped in environments without it)
    pub requires_podman: bool,
    /// Whether this test requires the pre-built container image
    /// (`DEVAIPOD_CONTAINER_IMAGE`). Tests with this flag are skipped
    /// when running via `just test-integration-local`.
    pub requires_container_image: bool,
}

impl IntegrationTest {
    /// Create a new integration test with the given name and function
    pub const fn new(name: &'static str, f: TestFn) -> Self {
        Self {
            name,
            f,
            requires_podman: false,
            requires_container_image: false,
        }
    }

    /// Create a new integration test that requires podman
    pub const fn new_podman(name: &'static str, f: TestFn) -> Self {
        Self {
            name,
            f,
            requires_podman: true,
            requires_container_image: false,
        }
    }

    /// Create a new integration test that requires podman and the container image
    pub const fn new_container(name: &'static str, f: TestFn) -> Self {
        Self {
            name,
            f,
            requires_podman: true,
            requires_container_image: true,
        }
    }
}

/// Metadata for a registered readonly integration test
#[derive(Debug)]
pub struct ReadonlyIntegrationTest {
    /// Name of the integration test
    pub name: &'static str,
    /// Test function to execute (receives SharedFixture)
    pub f: ReadonlyTestFn,
}

impl ReadonlyIntegrationTest {
    /// Create a new readonly integration test
    pub const fn new(name: &'static str, f: ReadonlyTestFn) -> Self {
        Self { name, f }
    }
}

/// Distributed slice holding all registered integration tests
#[linkme::distributed_slice]
pub static INTEGRATION_TESTS: [IntegrationTest];

/// Distributed slice holding all registered readonly integration tests
#[linkme::distributed_slice]
pub static READONLY_INTEGRATION_TESTS: [ReadonlyIntegrationTest];

/// Register an integration test with less boilerplate.
///
/// This macro generates the static registration for an integration test function.
///
/// # Examples
///
/// ```ignore
/// fn test_basic_functionality() -> Result<()> {
///     let output = run_devaipod(&["--help"])?;
///     output.assert_success("help");
///     Ok(())
/// }
/// integration_test!(test_basic_functionality);
/// ```
#[macro_export]
macro_rules! integration_test {
    ($fn_name:ident) => {
        ::paste::paste! {
            #[::linkme::distributed_slice($crate::INTEGRATION_TESTS)]
            static [<$fn_name:upper>]: $crate::IntegrationTest =
                $crate::IntegrationTest::new(stringify!($fn_name), $fn_name);
        }
    };
}

/// Register an integration test that requires podman and may mutate pod state.
///
/// These tests will be skipped if podman is not available.
/// Each test creates and manages its own pods.
///
/// # Examples
///
/// ```ignore
/// fn test_pod_creation() -> Result<()> {
///     // This test needs podman and creates/deletes pods
///     let output = run_devaipod(&["up", "..."])?;
///     output.assert_success("up");
///     Ok(())
/// }
/// podman_integration_test!(test_pod_creation);
/// ```
#[macro_export]
macro_rules! podman_integration_test {
    ($fn_name:ident) => {
        ::paste::paste! {
            #[::linkme::distributed_slice($crate::INTEGRATION_TESTS)]
            static [<$fn_name:upper>]: $crate::IntegrationTest =
                $crate::IntegrationTest::new_podman(stringify!($fn_name), $fn_name);
        }
    };
}

/// Register an integration test that requires the pre-built container image.
///
/// These tests need `DEVAIPOD_CONTAINER_IMAGE` set and are skipped by
/// `just test-integration-local`.
#[macro_export]
macro_rules! container_integration_test {
    ($fn_name:ident) => {
        ::paste::paste! {
            #[::linkme::distributed_slice($crate::INTEGRATION_TESTS)]
            static [<$fn_name:upper>]: $crate::IntegrationTest =
                $crate::IntegrationTest::new_container(stringify!($fn_name), $fn_name);
        }
    };
}

/// Register a readonly integration test that uses the shared pod fixture.
///
/// These tests receive a `&SharedFixture` and should only perform read operations
/// on the shared pod (query state, run commands that don't modify state, etc.).
///
/// # Examples
///
/// ```ignore
/// fn test_readonly_pod_exists(fixture: &SharedFixture) -> Result<()> {
///     // Verify the shared pod exists
///     let sh = shell()?;
///     let pod_name = fixture.pod_name();
///     let exists = cmd!(sh, "podman pod exists {pod_name}")
///         .ignore_status()
///         .output()?;
///     assert!(exists.status.success());
///     Ok(())
/// }
/// readonly_test!(test_readonly_pod_exists);
/// ```
#[macro_export]
macro_rules! readonly_test {
    ($fn_name:ident) => {
        ::paste::paste! {
            #[::linkme::distributed_slice($crate::READONLY_INTEGRATION_TESTS)]
            static [<$fn_name:upper>]: $crate::ReadonlyIntegrationTest =
                $crate::ReadonlyIntegrationTest::new(stringify!($fn_name), $fn_name);
        }
    };
}

/// Poll a condition with a timeout. Returns Ok(()) if the condition
/// returns Ok(true) before the deadline, or the last error/timeout.
pub fn poll_until<F>(
    description: &str,
    timeout: std::time::Duration,
    interval: std::time::Duration,
    mut condition: F,
) -> color_eyre::Result<()>
where
    F: FnMut() -> color_eyre::Result<bool>,
{
    let deadline = std::time::Instant::now() + timeout;
    loop {
        match condition() {
            Ok(true) => return Ok(()),
            Ok(false) => {}
            Err(e) => {
                if std::time::Instant::now() > deadline {
                    return Err(e.wrap_err(format!("Timed out: {description}")));
                }
            }
        }
        if std::time::Instant::now() > deadline {
            color_eyre::eyre::bail!("Timed out after {timeout:?}: {description}");
        }
        #[allow(clippy::disallowed_methods)] // Intentional: poll interval
        std::thread::sleep(interval);
    }
}

/// Poll until a container is running.
pub fn wait_for_container_running(
    container_name: &str,
    timeout: std::time::Duration,
) -> color_eyre::Result<()> {
    poll_until(
        &format!("container '{container_name}' running"),
        timeout,
        std::time::Duration::from_secs(1),
        || {
            let output = std::process::Command::new("podman")
                .args(["inspect", "--format", "{{.State.Status}}", container_name])
                .output()?;
            let status = String::from_utf8_lossy(&output.stdout).trim().to_string();
            Ok(status == "running")
        },
    )
}

/// Poll until a file exists on the host filesystem.
pub fn wait_for_file(
    path: &std::path::Path,
    timeout: std::time::Duration,
) -> color_eyre::Result<()> {
    poll_until(
        &format!("file '{}' exists", path.display()),
        timeout,
        std::time::Duration::from_millis(100),
        || Ok(path.exists()),
    )
}

/// Environment variable name for overriding SSH config directory.
const SSH_CONFIG_DIR_ENV: &str = "DEVAIPOD_SSH_CONFIG_DIR";

/// Shared fixture for readonly integration tests.
///
/// This fixture is created once and reused by all readonly tests.
/// It contains a test repository and a running pod that tests can query.
///
/// The fixture uses `OnceLock` for thread-safe lazy initialization.
/// Cleanup should be performed explicitly by calling `cleanup()` after tests complete.
pub struct SharedFixture {
    /// The name of the shared pod
    pod_name: String,
    /// Path to the test repository
    repo_path: PathBuf,
    /// Keep the temp dir alive
    _temp_dir: tempfile::TempDir,
    /// Keep the SSH config dir alive (avoid mutating user's ~/.ssh/config.d)
    _ssh_config_dir: tempfile::TempDir,
}

impl SharedFixture {
    /// Get the shared fixture instance, creating it on first access.
    ///
    /// This method is thread-safe and will only create the fixture once.
    /// Returns an error if fixture creation fails.
    pub fn get() -> color_eyre::Result<&'static SharedFixture> {
        static INSTANCE: OnceLock<SharedFixture> = OnceLock::new();

        // Try to get existing instance first
        if let Some(fixture) = INSTANCE.get() {
            return Ok(fixture);
        }

        // Need to initialize - this races but OnceLock handles it
        let fixture = Self::create()?;

        // get_or_init ensures only one initializer wins
        Ok(INSTANCE.get_or_init(|| fixture))
    }

    /// Create a new shared fixture (internal)
    fn create() -> color_eyre::Result<Self> {
        use color_eyre::eyre::{Context, bail};
        use std::process::Command;

        tracing::info!("Creating shared integration test fixture");

        // Create temp directory and test repo
        let temp_dir = tempfile::TempDir::new()?;
        let repo_path = temp_dir.path().join("shared-test-repo");
        std::fs::create_dir_all(&repo_path)?;

        // Initialize git repo
        let repo_str = repo_path.to_str().unwrap();

        let status = Command::new("git")
            .args(["-C", repo_str, "init"])
            .status()
            .context("Failed to run git init")?;
        if !status.success() {
            bail!("git init failed");
        }

        Command::new("git")
            .args(["-C", repo_str, "config", "user.email", "test@example.com"])
            .status()?;
        Command::new("git")
            .args(["-C", repo_str, "config", "user.name", "Test User"])
            .status()?;

        // Create devcontainer.json
        let devcontainer_dir = repo_path.join(".devcontainer");
        std::fs::create_dir_all(&devcontainer_dir)?;
        let test_image = std::env::var("DEVAIPOD_TEST_IMAGE")
            .unwrap_or_else(|_| "ghcr.io/bootc-dev/devenv-debian:latest".to_string());
        let devcontainer_json = format!(
            r#"{{
    "name": "shared-integration-test",
    "image": "{}"
}}"#,
            test_image
        );
        std::fs::write(
            devcontainer_dir.join("devcontainer.json"),
            devcontainer_json,
        )?;
        std::fs::write(repo_path.join("README.md"), "# Shared Test Repo\n")?;

        // Add remote (required by devaipod)
        Command::new("git")
            .args([
                "-C",
                repo_str,
                "remote",
                "add",
                "origin",
                "https://github.com/test/shared-test-repo.git",
            ])
            .status()?;

        // Commit
        Command::new("git")
            .args(["-C", repo_str, "add", "."])
            .status()?;
        Command::new("git")
            .args(["-C", repo_str, "commit", "-m", "Initial commit"])
            .status()?;

        // Get devaipod path
        let devaipod = Self::get_devaipod_command()?;

        // Create a temp directory for SSH configs to avoid mutating user's ~/.ssh/config.d
        let ssh_config_dir = tempfile::TempDir::new()?;

        // Remove any existing shared pod first (in case of previous failed run)
        let _ = Command::new("podman")
            .args(["pod", "rm", "-f", SHARED_POD_NAME])
            .output();
        for suffix in POD_VOLUME_SUFFIXES {
            let volume_name = format!("{SHARED_POD_NAME}{suffix}");
            let _ = Command::new("podman")
                .args(["volume", "rm", "-f", &volume_name])
                .output();
        }
        // Also remove stale host-side workspace directory from previous runs.
        // Use `podman unshare` because files may be owned by container subuids.
        let ws_base = std::env::var("DEVAIPOD_HOST_WORKDIR")
            .map(std::path::PathBuf::from)
            .or_else(|_| {
                std::env::var("HOME")
                    .map(|h| std::path::PathBuf::from(h).join(".local/share/devaipod/workspaces"))
            });
        if let Ok(base) = ws_base {
            let ws_dir = base.join(SHARED_POD_NAME);
            if ws_dir.exists() {
                tracing::info!(
                    "Removing stale host workspace dir from previous run: {}",
                    ws_dir.display()
                );
                let _ = Command::new("podman")
                    .args(["unshare", "rm", "-rf"])
                    .arg(&ws_dir)
                    .output();
            }
        }

        // Create the shared pod
        // Note: We pass "integration-shared" since devaipod adds "devaipod-" prefix
        let short_name = SHARED_POD_NAME
            .strip_prefix("devaipod-")
            .unwrap_or(SHARED_POD_NAME);
        let output = Command::new(&devaipod)
            .current_dir(&repo_path)
            .args(["up", ".", "--name", short_name])
            .env("DEVAIPOD_HOST_MODE", "1")
            .env("DEVAIPOD_INSTANCE", INTEGRATION_TEST_INSTANCE)
            .env(SSH_CONFIG_DIR_ENV, ssh_config_dir.path())
            .output()
            .context("Failed to run devaipod up for shared fixture")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let stdout = String::from_utf8_lossy(&output.stdout);
            bail!(
                "Failed to create shared pod:\nstdout: {}\nstderr: {}",
                stdout,
                stderr
            );
        }

        // Wait for the pod-api container to be healthy before returning.
        // This ensures all readonly tests can immediately reach the API
        // without per-test startup race conditions.
        let api_container = format!("{SHARED_POD_NAME}-api");
        tracing::info!("Waiting for {api_container} to become healthy...");
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
        loop {
            let inspect = Command::new("podman")
                .args([
                    "inspect",
                    "--format",
                    "{{.State.Health.Status}}",
                    &api_container,
                ])
                .output()
                .context("Failed to inspect pod-api container health")?;
            let status = String::from_utf8_lossy(&inspect.stdout).trim().to_string();
            if status == "healthy" {
                break;
            }
            if std::time::Instant::now() > deadline {
                bail!(
                    "pod-api container did not become healthy within 60s (status: {})",
                    status
                );
            }
            #[allow(clippy::disallowed_methods)] // Intentional: poll interval
            std::thread::sleep(std::time::Duration::from_secs(1));
        }

        tracing::info!("Shared fixture created with pod: {}", SHARED_POD_NAME);

        Ok(SharedFixture {
            pod_name: SHARED_POD_NAME.to_string(),
            repo_path,
            _temp_dir: temp_dir,
            _ssh_config_dir: ssh_config_dir,
        })
    }

    /// Get the path to the devaipod binary.
    ///
    /// In the containerized test runner, devaipod-server is at /usr/bin/devaipod-server.
    /// Override with DEVAIPOD_PATH for local development.
    fn get_devaipod_command() -> color_eyre::Result<String> {
        if let Ok(path) = std::env::var("DEVAIPOD_PATH") {
            return Ok(path);
        }
        Ok("devaipod-server".to_string())
    }

    /// Get the full pod name (for podman commands)
    ///
    /// Returns the full name including the `devaipod-` prefix, e.g. `devaipod-integration-shared`.
    /// Use this for direct podman commands like `podman pod inspect`.
    pub fn pod_name(&self) -> &str {
        &self.pod_name
    }

    /// Get the short pod name (for devaipod CLI commands)
    ///
    /// Returns the name without the `devaipod-` prefix, e.g. `integration-shared`.
    /// Use this for devaipod commands like `devaipod status`, `devaipod exec`, etc.
    pub fn short_name(&self) -> &str {
        self.pod_name
            .strip_prefix("devaipod-")
            .unwrap_or(&self.pod_name)
    }

    /// Get the path to the test repository
    pub fn repo_path(&self) -> &PathBuf {
        &self.repo_path
    }

    /// Get the agent container name
    pub fn agent_container(&self) -> String {
        format!("{}-agent", self.pod_name)
    }

    /// Get the api container name
    pub fn api_container(&self) -> String {
        format!("{}-api", self.pod_name)
    }

    /// Get the SSH config directory path (used for isolated testing)
    pub fn ssh_config_dir(&self) -> &std::path::Path {
        self._ssh_config_dir.path()
    }

    /// Get the environment variable tuple for SSH config directory
    pub fn ssh_config_env(&self) -> (&'static str, &str) {
        (
            SSH_CONFIG_DIR_ENV,
            self._ssh_config_dir.path().to_str().unwrap(),
        )
    }

    /// Clean up the shared fixture (remove pod and volume)
    ///
    /// This should be called after all tests complete.
    pub fn cleanup() {
        use std::process::Command;

        tracing::info!("Cleaning up shared fixture");

        // Remove the pod
        let _ = Command::new("podman")
            .args(["pod", "rm", "-f", SHARED_POD_NAME])
            .output();

        // Remove associated volumes
        for suffix in POD_VOLUME_SUFFIXES {
            let volume_name = format!("{SHARED_POD_NAME}{suffix}");
            let _ = Command::new("podman")
                .args(["volume", "rm", "-f", &volume_name])
                .output();
        }

        // Remove host-side workspace directory (workspace-v2 bind mount).
        // Must use `podman unshare` because files are owned by container subuids.
        let ws_base = std::env::var("DEVAIPOD_HOST_WORKDIR")
            .map(std::path::PathBuf::from)
            .or_else(|_| {
                std::env::var("HOME")
                    .map(|h| std::path::PathBuf::from(h).join(".local/share/devaipod/workspaces"))
            });
        if let Ok(base) = ws_base {
            let ws_dir = base.join(SHARED_POD_NAME);
            if ws_dir.exists() {
                tracing::info!("Removing host workspace dir: {}", ws_dir.display());
                let _ = Command::new("podman")
                    .args(["unshare", "rm", "-rf"])
                    .arg(&ws_dir)
                    .output();
            }
        }

        tracing::info!("Shared fixture cleanup complete");
    }
}
