//! Shared library code for integration tests
//!
//! This module contains macros and utilities for registering and running
//! integration tests for devc.

// Unfortunately needed here to work with linkme
#![allow(unsafe_code)]

/// Label used to identify containers created by integration tests
pub const INTEGRATION_TEST_LABEL: &str = "devc.integration-test=1";

/// A test function that returns a Result
pub type TestFn = fn() -> color_eyre::Result<()>;

/// Metadata for a registered integration test
#[derive(Debug)]
pub struct IntegrationTest {
    /// Name of the integration test
    pub name: &'static str,
    /// Test function to execute
    pub f: TestFn,
    /// Whether this test requires podman (should be skipped in environments without it)
    pub requires_podman: bool,
}

impl IntegrationTest {
    /// Create a new integration test with the given name and function
    pub const fn new(name: &'static str, f: TestFn) -> Self {
        Self {
            name,
            f,
            requires_podman: false,
        }
    }

    /// Create a new integration test that requires podman
    pub const fn new_podman(name: &'static str, f: TestFn) -> Self {
        Self {
            name,
            f,
            requires_podman: true,
        }
    }
}

/// Distributed slice holding all registered integration tests
#[linkme::distributed_slice]
pub static INTEGRATION_TESTS: [IntegrationTest];

/// Register an integration test with less boilerplate.
///
/// This macro generates the static registration for an integration test function.
///
/// # Examples
///
/// ```ignore
/// fn test_basic_functionality() -> Result<()> {
///     let output = run_devc(&["--help"])?;
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

/// Register an integration test that requires podman.
///
/// These tests will be skipped if podman is not available.
///
/// # Examples
///
/// ```ignore
/// fn test_container_spawn() -> Result<()> {
///     // This test needs podman
///     let output = run_devc(&["new", "..."])?;
///     output.assert_success("new");
///     Ok(())
/// }
/// podman_integration_test!(test_container_spawn);
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
