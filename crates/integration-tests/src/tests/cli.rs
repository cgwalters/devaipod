//! CLI tests that don't require podman

use color_eyre::Result;

use crate::{integration_test, run_devc};

fn test_devc_help() -> Result<()> {
    let output = run_devc(&["--help"])?;
    output.assert_success("devc --help");

    let combined = output.combined();
    assert!(
        combined.contains("Manage git worktrees"),
        "Help should mention git worktrees"
    );
    assert!(combined.contains("new"), "Help should list 'new' command");
    assert!(
        combined.contains("enter"),
        "Help should list 'enter' command"
    );
    assert!(combined.contains("list"), "Help should list 'list' command");
    assert!(combined.contains("rm"), "Help should list 'rm' command");

    Ok(())
}
integration_test!(test_devc_help);

fn test_devc_new_help() -> Result<()> {
    let output = run_devc(&["new", "--help"])?;
    output.assert_success("devc new --help");

    let combined = output.combined();
    assert!(
        combined.contains("SOURCE"),
        "Help should mention SOURCE argument"
    );
    assert!(
        combined.contains("--name"),
        "Help should list --name option"
    );
    assert!(
        combined.contains("--base"),
        "Help should list --base option"
    );

    Ok(())
}
integration_test!(test_devc_new_help);

fn test_devc_new_sidecar_help() -> Result<()> {
    let output = run_devc(&["new", "--help"])?;
    output.assert_success("devc new --help (sidecar)");

    let combined = output.combined();
    assert!(
        combined.contains("--sidecar"),
        "Help should list --sidecar option"
    );
    assert!(
        combined.contains("--sidecar-profile"),
        "Help should list --sidecar-profile option"
    );
    assert!(
        combined.contains("--no-sidecar"),
        "Help should list --no-sidecar option"
    );
    assert!(
        combined.contains("--sidecar-secret"),
        "Help should list --sidecar-secret option"
    );
    assert!(
        combined.contains("--secret-all"),
        "Help should list --secret-all option"
    );

    Ok(())
}
integration_test!(test_devc_new_sidecar_help);

fn test_devc_enter_container_help() -> Result<()> {
    let output = run_devc(&["enter", "--help"])?;
    output.assert_success("devc enter --help");

    let combined = output.combined();
    assert!(
        combined.contains("--container"),
        "Help should list --container option"
    );
    assert!(
        combined.contains("--no-tmux"),
        "Help should list --no-tmux option"
    );

    Ok(())
}
integration_test!(test_devc_enter_container_help);

fn test_devc_config_flag_help() -> Result<()> {
    let output = run_devc(&["--help"])?;
    output.assert_success("devc --help (config)");

    let combined = output.combined();
    assert!(
        combined.contains("--config"),
        "Help should list --config option"
    );

    Ok(())
}
integration_test!(test_devc_config_flag_help);

fn test_devc_list_help() -> Result<()> {
    let output = run_devc(&["list", "--help"])?;
    output.assert_success("devc list --help");

    let combined = output.combined();
    assert!(
        combined.contains("--json"),
        "Help should list --json option"
    );

    Ok(())
}
integration_test!(test_devc_list_help);

fn test_devc_list_empty() -> Result<()> {
    let output = run_devc(&["list"])?;
    output.assert_success("devc list");

    let combined = output.combined();
    // Should contain the header or be empty
    assert!(
        combined.contains("NAME")
            || combined.contains("No workspaces")
            || combined.trim().is_empty(),
        "devc list should show header, 'No workspaces' message, or be empty: {}",
        combined
    );

    Ok(())
}
integration_test!(test_devc_list_empty);
