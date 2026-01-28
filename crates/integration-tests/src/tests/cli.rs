//! CLI integration tests
//!
//! These tests verify CLI behavior that doesn't require podman but still
//! exercises real functionality (not just --help output).

use color_eyre::Result;

use crate::{integration_test, run_devaipod, run_devaipod_in, shell, TestRepo};

fn test_dry_run_shows_config() -> Result<()> {
    let repo = TestRepo::new()?;

    let output = run_devaipod_in(&repo.repo_path, &["up", ".", "--dry-run"])?;
    output.assert_success("devaipod up --dry-run");

    // Dry run should show what would be created
    assert!(
        output.stdout.contains("Dry run") || output.stdout.contains("dry run"),
        "Expected dry-run message. stdout:\n{}",
        output.stdout
    );

    Ok(())
}
integration_test!(test_dry_run_shows_config);

fn test_up_requires_git_remote() -> Result<()> {
    // Create a repo without a remote
    let temp_dir = tempfile::TempDir::new()?;
    let repo_path = temp_dir.path().join("no-remote-repo");
    std::fs::create_dir_all(&repo_path)?;

    let sh = shell()?;
    let repo = repo_path.to_str().unwrap();

    // Initialize git repo without remote
    xshell::cmd!(sh, "git -C {repo} init").run()?;
    xshell::cmd!(sh, "git -C {repo} config user.email test@example.com").run()?;
    xshell::cmd!(sh, "git -C {repo} config user.name 'Test User'").run()?;

    // Create devcontainer.json
    let devcontainer_dir = repo_path.join(".devcontainer");
    std::fs::create_dir_all(&devcontainer_dir)?;
    std::fs::write(
        devcontainer_dir.join("devcontainer.json"),
        r#"{"image": "alpine:latest"}"#,
    )?;
    std::fs::write(repo_path.join("README.md"), "# Test\n")?;

    xshell::cmd!(sh, "git -C {repo} add .").run()?;
    xshell::cmd!(sh, "git -C {repo} commit -m 'Initial'").run()?;

    // Should fail without a remote
    let output = run_devaipod_in(&repo_path, &["up", ".", "--dry-run"])?;
    assert!(
        !output.success(),
        "Should fail without git remote configured"
    );
    assert!(
        output.combined().contains("remote")
            || output.combined().contains("Remote")
            || output.combined().contains("clone"),
        "Error should mention remote/clone issue: {}",
        output.combined()
    );

    Ok(())
}
integration_test!(test_up_requires_git_remote);

fn test_up_requires_devcontainer_or_image() -> Result<()> {
    // Create a repo without devcontainer.json
    let repo = TestRepo::new_minimal()?;

    // Should fail without --image
    let output = run_devaipod_in(&repo.repo_path, &["up", ".", "--dry-run"])?;
    assert!(
        !output.success(),
        "Should fail without devcontainer.json or --image"
    );
    assert!(
        output.combined().contains("devcontainer.json"),
        "Error should mention devcontainer.json: {}",
        output.combined()
    );

    Ok(())
}
integration_test!(test_up_requires_devcontainer_or_image);

fn test_image_override_bypasses_devcontainer() -> Result<()> {
    // Create a repo without devcontainer.json
    let repo = TestRepo::new_minimal()?;

    // Should succeed with --image (dry-run to avoid actually creating pod)
    let output = run_devaipod_in(
        &repo.repo_path,
        &["up", ".", "--dry-run", "--image", "alpine:latest"],
    )?;
    output.assert_success("devaipod up --image --dry-run");

    Ok(())
}
integration_test!(test_image_override_bypasses_devcontainer);

fn test_list_works() -> Result<()> {
    // List should work even when there are no pods
    let output = run_devaipod(&["list"])?;
    output.assert_success("devaipod list");
    Ok(())
}
integration_test!(test_list_works);
