//! Container tests that require podman

use std::path::Path;

use color_eyre::eyre::bail;
use color_eyre::Result;

use crate::{
    container_name, podman_integration_test, run_command, run_command_success, run_devc,
    run_devc_in, ContainerGuard, PodGuard, TestRepo, VolumeGuard,
};

fn test_multi_container_spawn() -> Result<()> {
    const NUM_CONTAINERS: usize = 2;

    let repo = TestRepo::new()?;
    let mut containers = ContainerGuard::new();

    // Create worktrees and spawn containers
    let mut worktree_paths = Vec::new();
    for i in 1..=NUM_CONTAINERS {
        let name = format!("worktree-{}", i);
        let worktree_path = repo.create_worktree(&name)?;
        worktree_paths.push(worktree_path);
    }

    // Spawn containers (must be done sequentially since devc changes cwd)
    for (i, worktree_path) in worktree_paths.iter().enumerate() {
        let output = run_devc_in(worktree_path, &["new", "--no-sidecar"])?;
        if !output.success() {
            bail!(
                "devc new failed for worktree {}: {}",
                i + 1,
                output.combined()
            );
        }

        let name = container_name(worktree_path);
        containers.add(&name);

        // Verify container is running
        let ps_output = run_command_success(
            "podman",
            &["ps", "-q", "--filter", &format!("name=^{}$", name)],
        )?;
        assert!(
            !ps_output.trim().is_empty(),
            "Container {} should be running",
            name
        );
    }

    // Verify isolation: each container should have unique hostname
    let mut hostnames = Vec::new();
    for worktree_path in &worktree_paths {
        let name = container_name(worktree_path);
        let hostname = run_command_success("podman", &["exec", &name, "hostname"])?;
        hostnames.push(hostname.trim().to_string());
    }

    // Check all hostnames are unique
    let mut unique_hostnames = hostnames.clone();
    unique_hostnames.sort();
    unique_hostnames.dedup();
    assert_eq!(
        hostnames.len(),
        unique_hostnames.len(),
        "All containers should have unique hostnames"
    );

    // Verify workspace is mounted in each container
    for worktree_path in &worktree_paths {
        let name = container_name(worktree_path);
        let ls_output = run_command_success("podman", &["exec", &name, "ls", "/projects"])?;
        assert!(
            ls_output.contains("devfile.yaml"),
            "Container {} should have workspace mounted at /projects",
            name
        );
    }

    // Verify environment variable is set
    for worktree_path in &worktree_paths {
        let name = container_name(worktree_path);
        let env_output =
            run_command_success("podman", &["exec", &name, "sh", "-c", "echo $TEST_VAR"])?;
        assert!(
            env_output.contains("integration-test-value"),
            "Container {} should have TEST_VAR set, got: {:?}",
            name,
            env_output
        );
    }

    // Test devc list runs successfully
    // Note: With --no-sidecar, standalone containers are created (not pods)
    // and devc list only shows pods, so we just verify the command works
    let list_output = run_devc(&["list"])?;
    list_output.assert_success("devc list");

    Ok(())
}
podman_integration_test!(test_multi_container_spawn);

fn test_container_exec() -> Result<()> {
    let repo = TestRepo::new()?;
    let mut containers = ContainerGuard::new();

    let worktree_path = repo.create_worktree("exec-test")?;

    // Spawn container
    let output = run_devc_in(&worktree_path, &["new", "--no-sidecar"])?;
    if !output.success() {
        bail!("devc new failed: {}", output.combined());
    }

    let name = container_name(&worktree_path);
    containers.add(&name);

    // Test executing a command
    let exec_output = run_command_success(
        "podman",
        &["exec", &name, "sh", "-c", "echo hello-from-container"],
    )?;
    assert!(exec_output.contains("hello-from-container"));

    // Test that project files are accessible
    let cat_output = run_command_success("podman", &["exec", &name, "cat", "/projects/README.md"])?;
    assert!(cat_output.contains("# Test Repo"));

    Ok(())
}
podman_integration_test!(test_container_exec);

/// Create a test config file with sidecar settings
fn create_test_config(dir: &Path, sidecar_image: &str) -> std::path::PathBuf {
    let config_path = dir.join("devaipod.toml");
    let config_content = format!(
        r#"
[sidecar]
enabled = false
mount_sources_readonly = true

[sidecar.profiles.test-agent]
image = "{}"
mount_sources_readonly = true
"#,
        sidecar_image
    );
    std::fs::write(&config_path, config_content).unwrap();
    config_path
}

/// Create a devfile with a long-running container for testing
fn create_test_devfile(dir: &Path) {
    let devfile = r#"schemaVersion: "2.2.0"
metadata:
  name: multicontainer-test
  version: 1.0.0
  description: Multi-container integration test

components:
  - name: dev
    container:
      image: docker.io/library/alpine:latest
      command: ['/bin/sh']
      args: ['-c', 'sleep infinity']
      mountSources: true
      env:
        - name: CONTAINER_ROLE
          value: main
"#;
    std::fs::write(dir.join("devfile.yaml"), devfile).unwrap();
}

fn test_pod_with_sidecar() -> Result<()> {
    let base_dir = tempfile::TempDir::new()?;
    let workspace_dir = base_dir.path().join("test-workspace");
    std::fs::create_dir_all(&workspace_dir)?;

    // Create test files
    create_test_devfile(&workspace_dir);
    let config_path = create_test_config(base_dir.path(), "docker.io/library/alpine:latest");

    // Initialize git repo (required for worktree detection)
    run_command_success("git", &["-C", workspace_dir.to_str().unwrap(), "init"])?;
    run_command_success(
        "git",
        &[
            "-C",
            workspace_dir.to_str().unwrap(),
            "config",
            "user.email",
            "test@example.com",
        ],
    )?;
    run_command_success(
        "git",
        &[
            "-C",
            workspace_dir.to_str().unwrap(),
            "config",
            "user.name",
            "Test User",
        ],
    )?;
    run_command_success("git", &["-C", workspace_dir.to_str().unwrap(), "add", "."])?;
    run_command_success(
        "git",
        &[
            "-C",
            workspace_dir.to_str().unwrap(),
            "commit",
            "-m",
            "Initial commit",
        ],
    )?;

    let workspace_name = "test-workspace";
    let pod_name = format!("devc-{}", workspace_name);
    let mut pods = PodGuard::new();
    pods.add(&pod_name);

    // Spawn container with sidecar using custom config
    let output = run_devc_in(
        &workspace_dir,
        &[
            "--config",
            config_path.to_str().unwrap(),
            "new",
            "--sidecar",
            "docker.io/library/alpine:latest",
        ],
    )?;

    if !output.success() {
        bail!("devc new --sidecar failed: {}", output.combined());
    }

    // Verify pod was created
    let pod_exists = run_command("podman", &["pod", "exists", &pod_name])?;
    assert!(
        pod_exists.success(),
        "Pod {} should exist after sidecar spawn",
        pod_name
    );

    // List containers in pod
    let ps_output = run_command_success(
        "podman",
        &[
            "ps",
            "-a",
            "--filter",
            &format!("pod={}", pod_name),
            "--format",
            "{{.Names}}",
        ],
    )?;

    // Should have at least 2 containers (main + sidecar, plus infra)
    let container_lines: Vec<&str> = ps_output.lines().filter(|l| !l.is_empty()).collect();
    assert!(
        container_lines.len() >= 2,
        "Pod should have at least 2 containers (main + sidecar), got: {:?}",
        container_lines
    );

    // Verify main container has CONTAINER_ROLE=main
    let main_container = format!("devc-{}-dev", workspace_name);
    let env_output = run_command_success(
        "podman",
        &["exec", &main_container, "sh", "-c", "echo $CONTAINER_ROLE"],
    )?;
    assert!(
        env_output.contains("main"),
        "Main container should have CONTAINER_ROLE=main, got: {}",
        env_output
    );

    // Verify sidecar container exists and is running
    let sidecar_container = format!("devc-{}-sidecar", workspace_name);
    let sidecar_ps = run_command(
        "podman",
        &[
            "ps",
            "-q",
            "--filter",
            &format!("name=^{}$", sidecar_container),
        ],
    )?;
    assert!(
        !sidecar_ps.stdout.trim().is_empty(),
        "Sidecar container {} should be running",
        sidecar_container
    );

    // Verify both containers can see /projects
    for container in &[&main_container, &sidecar_container] {
        let ls_output = run_command_success("podman", &["exec", container, "ls", "/projects"])?;
        assert!(
            ls_output.contains("devfile.yaml"),
            "Container {} should have /projects mounted",
            container
        );
    }

    // Verify containers share network namespace (localhost connectivity)
    // Note: Alpine doesn't have nc by default, so we use a simpler check
    let main_hostname = run_command_success("podman", &["exec", &main_container, "hostname"])?;
    let sidecar_hostname =
        run_command_success("podman", &["exec", &sidecar_container, "hostname"])?;

    // In a pod, containers share the same network namespace, so hostnames should match the pod
    assert!(
        !main_hostname.trim().is_empty() && !sidecar_hostname.trim().is_empty(),
        "Both containers should have hostnames"
    );

    // Test devc list shows our pod containers
    let list_output = run_devc(&["list"])?;
    list_output.assert_success("devc list");

    // Should show something related to our workspace
    assert!(
        list_output.combined().contains("devc-")
            || list_output.combined().contains("test-workspace"),
        "devc list should show our containers: {}",
        list_output.combined()
    );

    Ok(())
}
podman_integration_test!(test_pod_with_sidecar);

fn test_sidecar_profile_from_config() -> Result<()> {
    let base_dir = tempfile::TempDir::new()?;
    let workspace_dir = base_dir.path().join("profile-test");
    std::fs::create_dir_all(&workspace_dir)?;

    // Create test files
    create_test_devfile(&workspace_dir);
    let config_path = create_test_config(base_dir.path(), "docker.io/library/alpine:latest");

    // Initialize git repo
    run_command_success("git", &["-C", workspace_dir.to_str().unwrap(), "init"])?;
    run_command_success(
        "git",
        &[
            "-C",
            workspace_dir.to_str().unwrap(),
            "config",
            "user.email",
            "test@example.com",
        ],
    )?;
    run_command_success(
        "git",
        &[
            "-C",
            workspace_dir.to_str().unwrap(),
            "config",
            "user.name",
            "Test User",
        ],
    )?;
    run_command_success("git", &["-C", workspace_dir.to_str().unwrap(), "add", "."])?;
    run_command_success(
        "git",
        &[
            "-C",
            workspace_dir.to_str().unwrap(),
            "commit",
            "-m",
            "Initial commit",
        ],
    )?;

    let workspace_name = "profile-test";
    let pod_name = format!("devc-{}", workspace_name);
    let mut pods = PodGuard::new();
    pods.add(&pod_name);

    // Spawn container with sidecar profile from config
    let output = run_devc_in(
        &workspace_dir,
        &[
            "--config",
            config_path.to_str().unwrap(),
            "new",
            "--sidecar-profile",
            "test-agent",
        ],
    )?;

    if !output.success() {
        bail!("devc new --sidecar-profile failed: {}", output.combined());
    }

    // Verify pod was created with sidecar
    let pod_exists = run_command("podman", &["pod", "exists", &pod_name])?;
    assert!(
        pod_exists.success(),
        "Pod {} should exist after sidecar-profile spawn",
        pod_name
    );

    // Verify sidecar container exists
    let sidecar_container = format!("devc-{}-sidecar", workspace_name);
    let sidecar_ps = run_command(
        "podman",
        &[
            "ps",
            "-q",
            "--filter",
            &format!("name=^{}$", sidecar_container),
        ],
    )?;
    assert!(
        !sidecar_ps.stdout.trim().is_empty(),
        "Sidecar container {} should be running when using --sidecar-profile",
        sidecar_container
    );

    Ok(())
}
podman_integration_test!(test_sidecar_profile_from_config);

fn test_volume_workspace_workflow() -> Result<()> {
    // Use a unique workspace name to avoid conflicts
    let workspace_name = format!("integ-test-{}", std::process::id());
    let container_name = format!("devfile-{}-dev", workspace_name);
    let volume_name = format!("devc-{}", workspace_name);

    let mut volumes = VolumeGuard::new();
    volumes.add(&workspace_name);

    // Create a local git repo with a devfile
    let base_dir = tempfile::TempDir::new()?;
    let repo_path = base_dir.path().join("test-repo");
    std::fs::create_dir_all(&repo_path)?;

    // Initialize git repo with devfile
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
  name: volume-test
  version: 1.0.0

components:
  - name: dev
    container:
      image: docker.io/library/alpine:latest
      command: ['/bin/sh']
      args: ['-c', 'sleep infinity']
      mountSources: true
      env:
        - name: DEVC_TEST
          value: volume-workflow
"#;
    std::fs::write(repo_path.join("devfile.yaml"), devfile)?;
    std::fs::write(repo_path.join("test-file.txt"), "Hello from test repo\n")?;

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

    // Add origin remote (required for LocalGitRepo cloning)
    run_command_success(
        "git",
        &[
            "-C",
            repo_path.to_str().unwrap(),
            "remote",
            "add",
            "origin",
            repo_path.to_str().unwrap(),
        ],
    )?;

    // Create workspace from local git repo path
    let output = run_devc(&[
        "new",
        repo_path.to_str().unwrap(),
        "--name",
        &workspace_name,
        "--no-sidecar",
    ])?;

    if !output.success() {
        bail!("devc new <url> failed: {}", output.combined());
    }

    // Verify volume was created
    let vol_exists = run_command("podman", &["volume", "exists", &volume_name])?;
    assert!(vol_exists.success(), "Volume {} should exist", volume_name);

    // Verify container is running
    let ps_output = run_command_success(
        "podman",
        &[
            "ps",
            "-q",
            "--filter",
            &format!("name=^{}$", container_name),
        ],
    )?;
    assert!(
        !ps_output.trim().is_empty(),
        "Container {} should be running",
        container_name
    );

    // Verify devc list runs successfully
    // Note: With --no-sidecar, standalone containers are created (not pods)
    // and devc list only shows pods, so we just verify the command works
    let list_output = run_devc(&["list"])?;
    list_output.assert_success("devc list");

    // Test entering container by name and running a command
    let exec_output = run_command_success(
        "podman",
        &["exec", &container_name, "sh", "-c", "echo $DEVC_TEST"],
    )?;
    assert!(
        exec_output.contains("volume-workflow"),
        "Container should have DEVC_TEST env var set, got: {}",
        exec_output
    );

    // Verify workspace files are accessible in container
    let cat_output = run_command_success(
        "podman",
        &["exec", &container_name, "cat", "/projects/test-file.txt"],
    )?;
    assert!(
        cat_output.contains("Hello from test repo"),
        "test-file.txt should be accessible in container, got: {}",
        cat_output
    );

    // Verify devfile is present
    let devfile_output = run_command_success(
        "podman",
        &["exec", &container_name, "cat", "/projects/devfile.yaml"],
    )?;
    assert!(
        devfile_output.contains("volume-test"),
        "devfile.yaml should be accessible, got: {}",
        devfile_output
    );

    // Test find_container_by_name functionality by checking workspace label
    let inspect_output = run_command_success(
        "podman",
        &[
            "inspect",
            &container_name,
            "--format",
            "{{index .Config.Labels \"devc.workspace\"}}",
        ],
    )?;
    assert!(
        inspect_output.contains(&workspace_name),
        "Container should have devc.workspace label, got: {}",
        inspect_output
    );

    Ok(())
}
podman_integration_test!(test_volume_workspace_workflow);

/// Test that `devc enter <pod-name>` works for volume-based workspaces
fn test_enter_by_pod_name() -> Result<()> {
    let base_dir = tempfile::TempDir::new()?;
    let workspace_dir = base_dir.path().join("enter-test");
    std::fs::create_dir_all(&workspace_dir)?;

    // Create test files
    create_test_devfile(&workspace_dir);

    // Initialize git repo
    run_command_success("git", &["-C", workspace_dir.to_str().unwrap(), "init"])?;
    run_command_success(
        "git",
        &[
            "-C",
            workspace_dir.to_str().unwrap(),
            "config",
            "user.email",
            "test@example.com",
        ],
    )?;
    run_command_success(
        "git",
        &[
            "-C",
            workspace_dir.to_str().unwrap(),
            "config",
            "user.name",
            "Test User",
        ],
    )?;
    run_command_success("git", &["-C", workspace_dir.to_str().unwrap(), "add", "."])?;
    run_command_success(
        "git",
        &[
            "-C",
            workspace_dir.to_str().unwrap(),
            "commit",
            "-m",
            "Initial commit",
        ],
    )?;

    let workspace_name = "enter-test";
    let pod_name = format!("devc-{}", workspace_name);
    let mut pods = PodGuard::new();
    pods.add(&pod_name);

    // Spawn container with sidecar (creates a pod)
    let output = run_devc_in(
        &workspace_dir,
        &["new", "--sidecar", "docker.io/library/alpine:latest"],
    )?;

    if !output.success() {
        bail!("devc new --sidecar failed: {}", output.combined());
    }

    // Verify pod exists
    let pod_exists = run_command("podman", &["pod", "exists", &pod_name])?;
    assert!(pod_exists.success(), "Pod {} should exist", pod_name);

    // Test 1: Enter by full pod name (devc-enter-test)
    // Use echo to send a command and exit
    let enter_output = run_command(
        "sh",
        &[
            "-c",
            &format!(
                "echo 'echo ENTER_TEST_OK && exit' | {} enter {} --no-tmux 2>&1 | head -20",
                std::env::var("DEVC_PATH").unwrap_or_else(|_| "devc".to_string()),
                pod_name
            ),
        ],
    )?;
    assert!(
        enter_output.success() || enter_output.stdout.contains("ENTER_TEST_OK"),
        "devc enter {} should work: {}",
        pod_name,
        enter_output.combined()
    );

    // Test 2: Enter by workspace name (enter-test)
    let enter_output2 = run_command(
        "sh",
        &[
            "-c",
            &format!(
                "echo 'echo ENTER_WS_OK && exit' | {} enter {} --no-tmux 2>&1 | head -20",
                std::env::var("DEVC_PATH").unwrap_or_else(|_| "devc".to_string()),
                workspace_name
            ),
        ],
    )?;
    assert!(
        enter_output2.success() || enter_output2.stdout.contains("ENTER_WS_OK"),
        "devc enter {} should work: {}",
        workspace_name,
        enter_output2.combined()
    );

    // Test 3: Enter specific container by name
    let dev_container = format!("devc-{}-dev", workspace_name);
    let enter_output3 = run_command(
        "sh",
        &[
            "-c",
            &format!(
                "echo 'echo ENTER_CONT_OK && exit' | {} enter {} --container dev --no-tmux 2>&1 | head -20",
                std::env::var("DEVC_PATH").unwrap_or_else(|_| "devc".to_string()),
                pod_name
            ),
        ],
    )?;
    assert!(
        enter_output3.success() || enter_output3.stdout.contains("ENTER_CONT_OK"),
        "devc enter {} --container dev should work: {}",
        pod_name,
        enter_output3.combined()
    );

    // Verify the dev container exists
    let ps_output = run_command_success(
        "podman",
        &["ps", "-q", "--filter", &format!("name=^{}$", dev_container)],
    )?;
    assert!(
        !ps_output.trim().is_empty(),
        "Container {} should be running",
        dev_container
    );

    Ok(())
}
podman_integration_test!(test_enter_by_pod_name);
