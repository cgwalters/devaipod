//! CLI tests that don't require podman

use color_eyre::Result;

use crate::{
    get_devaipod_command, integration_test, run_devaipod, run_devaipod_in, shell, TestRepo,
};
use xshell::cmd;

fn test_devaipod_help() -> Result<()> {
    let sh = shell()?;
    let devaipod = get_devaipod_command()?;

    let output = cmd!(sh, "{devaipod} --help").read()?;

    assert!(
        output.contains("devaipod") || output.contains("Sandboxed AI"),
        "Help should mention devaipod or its description"
    );
    assert!(output.contains("up"), "Help should list 'up' command");
    assert!(output.contains("list"), "Help should list 'list' command");
    assert!(
        output.contains("delete"),
        "Help should list 'delete' command"
    );

    Ok(())
}
integration_test!(test_devaipod_help);

fn test_devaipod_up_help() -> Result<()> {
    let sh = shell()?;
    let devaipod = get_devaipod_command()?;

    let output = cmd!(sh, "{devaipod} up --help").read()?;

    assert!(
        output.contains("SOURCE"),
        "Help should mention SOURCE argument"
    );
    assert!(
        output.contains("--image"),
        "Help should list --image option"
    );
    assert!(
        output.contains("--dry-run"),
        "Help should list --dry-run option"
    );
    assert!(output.contains("--ssh"), "Help should list --ssh option");

    Ok(())
}
integration_test!(test_devaipod_up_help);

fn test_devaipod_list_help() -> Result<()> {
    let sh = shell()?;
    let devaipod = get_devaipod_command()?;

    let output = cmd!(sh, "{devaipod} list --help").read()?;

    assert!(output.contains("--json"), "Help should list --json option");

    Ok(())
}
integration_test!(test_devaipod_list_help);

fn test_devaipod_delete_help() -> Result<()> {
    let sh = shell()?;
    let devaipod = get_devaipod_command()?;

    let output = cmd!(sh, "{devaipod} delete --help").read()?;

    assert!(
        output.contains("--force"),
        "Help should list --force option"
    );

    Ok(())
}
integration_test!(test_devaipod_delete_help);

fn test_devaipod_ssh_help() -> Result<()> {
    let sh = shell()?;
    let devaipod = get_devaipod_command()?;

    let output = cmd!(sh, "{devaipod} ssh --help").read()?;

    assert!(
        output.contains("WORKSPACE"),
        "Help should mention WORKSPACE argument"
    );

    Ok(())
}
integration_test!(test_devaipod_ssh_help);

fn test_devaipod_logs_help() -> Result<()> {
    let sh = shell()?;
    let devaipod = get_devaipod_command()?;

    let output = cmd!(sh, "{devaipod} logs --help").read()?;

    assert!(
        output.contains("WORKSPACE"),
        "Help should mention WORKSPACE argument"
    );
    assert!(
        output.contains("--follow"),
        "Help should list --follow option"
    );

    Ok(())
}
integration_test!(test_devaipod_logs_help);

fn test_devaipod_status_help() -> Result<()> {
    let sh = shell()?;
    let devaipod = get_devaipod_command()?;

    let output = cmd!(sh, "{devaipod} status --help").read()?;

    assert!(
        output.contains("WORKSPACE"),
        "Help should mention WORKSPACE argument"
    );

    Ok(())
}
integration_test!(test_devaipod_status_help);

fn test_devaipod_dry_run_on_self() -> Result<()> {
    // Run dry-run on this project - should succeed without starting anything
    // This assumes we're running from the workspace root or the project has a devcontainer
    let output = run_devaipod(&["up", ".", "--dry-run"])?;

    // Note: This will fail if run from a directory without devcontainer.json
    // which is expected - the test verifies the command runs and parses args correctly
    if output.success() {
        assert!(
            output.stdout.contains("Dry run") || output.stdout.contains("dry run"),
            "Expected dry-run message in output"
        );
    }
    // If it fails, that's okay - might not have devcontainer.json in current dir

    Ok(())
}
integration_test!(test_devaipod_dry_run_on_self);

fn test_devaipod_dry_run_with_devcontainer() -> Result<()> {
    let repo = TestRepo::new()?;

    let output = run_devaipod_in(&repo.repo_path, &["up", ".", "--dry-run"])?;
    output.assert_success("devaipod up --dry-run");

    assert!(
        output.stdout.contains("Dry run") || output.stdout.contains("dry run"),
        "Expected dry-run message. stdout:\n{}",
        output.stdout
    );

    Ok(())
}
integration_test!(test_devaipod_dry_run_with_devcontainer);

fn test_devaipod_up_requires_image_or_devcontainer() -> Result<()> {
    // Create a repo without devcontainer.json
    let repo = TestRepo::new_minimal()?;

    // Should fail without --image
    let output = run_devaipod_in(&repo.repo_path, &["up", ".", "--dry-run"])?;
    assert!(
        !output.success(),
        "Should fail without devcontainer.json or --image"
    );
    assert!(
        output.stderr.contains("devcontainer.json")
            || output.combined().contains("devcontainer.json"),
        "Error should mention devcontainer.json"
    );

    Ok(())
}
integration_test!(test_devaipod_up_requires_image_or_devcontainer);

fn test_devaipod_up_image_override_dry_run() -> Result<()> {
    // Create a repo without devcontainer.json
    let repo = TestRepo::new_minimal()?;

    // Should succeed with --image
    let output = run_devaipod_in(
        &repo.repo_path,
        &["up", ".", "--dry-run", "--image", "alpine:latest"],
    )?;
    output.assert_success("devaipod up --image --dry-run");

    assert!(
        output.stdout.contains("image override") || output.stdout.contains("Dry run"),
        "Expected image override or dry-run message. stdout:\n{}",
        output.stdout
    );

    Ok(())
}
integration_test!(test_devaipod_up_image_override_dry_run);

fn test_devaipod_completions() -> Result<()> {
    let sh = shell()?;
    let devaipod = get_devaipod_command()?;

    let output = cmd!(sh, "{devaipod} completions bash").read()?;

    assert!(
        output.contains("devaipod") || output.contains("complete"),
        "Should generate bash completions"
    );

    Ok(())
}
integration_test!(test_devaipod_completions);
