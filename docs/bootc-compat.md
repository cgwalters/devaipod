# bootc Devcontainer Compatibility Analysis

## Overview

This document analyzes the bootc project's devcontainer configuration and identifies the changes needed for devc compatibility. The bootc project currently uses GitHub Codespaces with a devcontainer configuration but does not have a devfile.yaml.

## Current bootc Devcontainer Configuration

### Location
- Configuration: `~/src/github/bootc-dev/bootc/.devcontainer/devcontainer.json`
- Container image source: `~/src/github/bootc-dev/infra/devenv/`

### devcontainer.json Analysis

```json
{
  "name": "bootc-devenv-debian",
  "image": "ghcr.io/bootc-dev/devenv-debian",
  "customizations": {
    "vscode": {
      "extensions": [
        "rust-lang.rust-analyzer",
        "golang.Go"
      ]
    }
  },
  "features": {},
  "runArgs": [
    "--privileged"
  ],
  "postCreateCommand": {
    "devenv-init": "sudo /usr/local/bin/devenv-init.sh"
  },
  "remoteEnv": {
    "PATH": "${containerEnv:PATH}:/usr/local/cargo/bin"
  }
}
```

### Container Image Configuration

The `ghcr.io/bootc-dev/devenv-debian` image is built from `Containerfile.debian` in the infra repo.

Key characteristics:

1. **Base**: Debian sid
2. **Pre-installed tools**:
   - Rust toolchain (system-wide in `/usr/local`)
   - Podman for nested containerization
   - QEMU/KVM for virtualization testing
   - GitHub CLI (gh)
   - Goose AI agent
   - bcvk (bootc VM toolkit)
   - Build dependencies for bootc (ostree, libvirt, etc.)

3. **User setup**:
   - Creates `devenv` user with passwordless sudo
   - Pre-creates `~devenv/.local/share/containers` for podman storage

4. **Volumes**: Declares two volumes to avoid overlay-on-overlay issues:
   - `/var/lib/containers`
   - `/home/devenv/.local/share/containers/`

5. **Init script** (`devenv-init.sh`):
   ```bash
   # Fix mount propagation for nested containers
   sudo mount -o remount --make-shared /

   # Make /dev/kvm accessible to all users
   chmod a+rw /dev/kvm

   # Configure podman for nested operation
   sed -i -e 's,^#cgroups =.*,cgroups = "no-conmon",' /usr/share/containers/containers.conf
   sed -i -e 's,^#cgroup_manager =.*,cgroup_manager = "cgroupfs",' /usr/share/containers/containers.conf
   ```

### Critical Requirements

1. **Privileged mode**: Required for nested podman and KVM access
2. **Device access**: `/dev/kvm` needed for VM testing (bootc runs VMs extensively)
3. **Mount propagation**: Needs shared mount propagation for nested containers
4. **Init script**: Must run `devenv-init.sh` after container creation
5. **Volumes**: Named volumes for container storage to avoid overlay issues

### GitHub Codespaces Specific Features

The current configuration is optimized for GitHub Codespaces but these features are not strictly required for local development:

- VSCode extensions configuration (IDE-specific)
- `${containerEnv:PATH}` variable interpolation (Codespaces-specific syntax)

## devc Compatibility Assessment

### Current devc Capabilities

Based on `/var/home/ai/src/github/cgwalters/aidevc/src/devfile.rs`, devc currently supports:

1. **Privileged mode**: Via `privileged` parameter (✓)
2. **KVM device passthrough**: Via `enable_kvm` parameter (✓)
3. **Environment variables**: From devfile env section (✓)
4. **Volume mounts**: Via volumeMounts in devfile (✓)
5. **Source mounting**: Automatic with SELinux relabeling (✓)
6. **Container labels**: For tracking devfile metadata (✓)

### Missing Capabilities for bootc

1. **Volume declarations**:
   - devc doesn't currently create named volumes
   - bootc needs `/var/lib/containers` and `~/.local/share/containers/` as volumes
   - Status: **NOT IMPLEMENTED**

2. **Post-create hooks**:
   - devc doesn't support postCreateCommand equivalent
   - bootc requires running `devenv-init.sh` after container starts
   - Workaround: Could use devfile `events.postStart` or add to container entrypoint
   - Status: **PARTIAL** (can use devfile events mechanism)

3. **Mount propagation options**:
   - devc doesn't configure mount propagation
   - bootc needs `--make-shared /` for nested containers
   - This is handled by the init script, but ideally would be a podman run flag
   - Status: **WORKAROUND AVAILABLE** (via init script)

4. **User switching**:
   - devc runs as root when privileged=true
   - bootc container has both root and devenv user
   - Need to specify which user to run as
   - Status: **NEEDS ENHANCEMENT**

### Compatibility Matrix

| Feature | bootc Requirement | devc Support | Status |
|---------|------------------|--------------|--------|
| Privileged mode | Yes | Yes | ✓ |
| /dev/kvm access | Yes | Yes (via enable_kvm) | ✓ |
| Named volumes | Yes (2 volumes) | No | ✗ |
| Post-create hooks | Yes (init script) | Partial (via events) | ~ |
| Mount propagation | Yes (shared) | No | ✗ |
| Custom user | Optional (devenv) | No (root only when privileged) | ✗ |
| Environment variables | Yes | Yes | ✓ |
| Source mounting | Yes | Yes | ✓ |

## Proposed devfile.yaml for bootc

Here's a proposed devfile.yaml that could work with enhanced devc support:

```yaml
schemaVersion: 2.2.0
metadata:
  name: bootc-devenv
  version: 1.0.0
  description: Development environment for bootc

components:
  - name: devenv
    container:
      image: ghcr.io/bootc-dev/devenv-debian
      command: ['/bin/bash']
      args: ['-c', 'sleep infinity']
      mountSources: true
      sourceMapping: /projects/bootc
      env:
        - name: PATH
          value: /usr/local/cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
        - name: RUSTUP_HOME
          value: /usr/local/rustup
      # Resource limits (optional)
      memoryLimit: 8Gi
      cpuLimit: "4"

      # Volume mounts for nested container storage
      volumeMounts:
        - name: container-storage-system
          path: /var/lib/containers
        - name: container-storage-user
          path: /home/devenv/.local/share/containers

  # Named volumes to avoid overlay-on-overlay
  - name: container-storage-system
    volume:
      size: 20Gi

  - name: container-storage-user
    volume:
      size: 20Gi

# Lifecycle events
events:
  postStart:
    - init-devenv

commands:
  # Post-start initialization
  - id: init-devenv
    exec:
      component: devenv
      commandLine: |
        set -euo pipefail
        # Fix mount propagation for nested containers
        sudo mount -o remount --make-shared / || true
        # Make /dev/kvm accessible (already passed through by devc)
        sudo chmod a+rw /dev/kvm || true
        # Configure podman for nested operation
        sudo sed -i -e 's,^#cgroups =.*,cgroups = "no-conmon",' /usr/share/containers/containers.conf
        sudo sed -i -e 's,^#cgroup_manager =.*,cgroup_manager = "cgroupfs",' /usr/share/containers/containers.conf
      group:
        kind: run
        isDefault: false

  - id: build
    exec:
      component: devenv
      commandLine: cargo build
      workingDir: ${PROJECT_SOURCE}
      group:
        kind: build
        isDefault: true

  - id: test
    exec:
      component: devenv
      commandLine: cargo test
      workingDir: ${PROJECT_SOURCE}
      group:
        kind: test
        isDefault: true

  - id: test-tmt
    exec:
      component: devenv
      commandLine: just test-tmt
      workingDir: ${PROJECT_SOURCE}
      group:
        kind: test
        isDefault: false

  - id: test-container
    exec:
      component: devenv
      commandLine: just test-container
      workingDir: ${PROJECT_SOURCE}
      group:
        kind: test
        isDefault: false
```

## Required devc Enhancements

To support bootc's devfile.yaml, devc needs the following enhancements:

### 1. Volume Component Support (High Priority)

**Current state**: devc parses `volume` components but doesn't use them.

**Required changes**:
- Create named volumes for volume components
- Mount volumes into containers via volumeMounts
- Support volume options (size, ephemeral, etc.)

**Implementation in `/var/home/ai/src/github/cgwalters/aidevc/src/devfile.rs`**:
```rust
// In start_devfile_container():

// Create named volumes from volume components
for component in &devfile.components {
    if let Some(ref vol) = component.volume {
        let vol_name = format!("devfile-{}-{}", devfile.metadata.name, component.name);
        // Check if volume exists
        // If not: podman volume create <name>
    }
}

// Mount volumes via volumeMounts
for mount in &container.volume_mounts {
    let vol_name = format!("devfile-{}-{}", devfile.metadata.name, mount.name);
    cmd.args(["-v", &format!("{}:{}", vol_name, mount.path)]);
}
```

### 2. Lifecycle Events Support (Medium Priority)

**Current state**: devc parses `commands` but doesn't support `events`.

**Required changes**:
- Add `events` field to Devfile struct
- Execute `postStart` commands after container creation
- Support `preStop` commands before container removal

**Implementation**:
```rust
#[derive(Debug, Deserialize)]
pub struct DevfileEvents {
    #[serde(default)]
    pub post_start: Vec<String>,
    #[serde(default)]
    pub pre_stop: Vec<String>,
}

// Add to Devfile:
#[serde(default)]
pub events: Option<DevfileEvents>,

// After container start, execute postStart commands
if let Some(ref events) = devfile.events {
    for cmd_id in &events.post_start {
        if let Some(cmd) = find_command(devfile, cmd_id) {
            exec_command_in_container(workspace, component_name, cmd)?;
        }
    }
}
```

### 3. Mount Propagation Support (Low Priority)

**Current state**: No control over mount propagation.

**Options**:
1. Add `--volume-opt` or `--mount` flags to podman run (if supported)
2. Keep using the init script approach (current workaround)
3. Add a devfile extension for podman-specific options

**Recommended**: Keep using init script for now, as this is edge-case functionality.

### 4. Custom User Support (Low Priority)

**Current state**: Always runs as root when privileged=true.

**Required changes**:
- Add optional `user` field to ContainerComponent
- Pass `--user` flag to podman run
- Document that privileged + non-root may have limitations

**Implementation**:
```rust
// In ContainerComponent:
#[serde(default)]
pub user: Option<String>,

// In start_devfile_container():
if let Some(ref user) = container.user {
    cmd.args(["--user", user]);
} else if privileged {
    cmd.args(["--user", "root"]);
}
```

## Upstream Changes to Suggest to bootc

### 1. Add devfile.yaml to bootc Repository

The bootc project currently only has a devcontainer.json. Adding a devfile.yaml would:
- Enable local development without GitHub Codespaces
- Support other devfile-compatible tools (odo, devc, etc.)
- Maintain compatibility with existing devcontainer workflow

**Suggested location**: `~/src/github/bootc-dev/bootc/devfile.yaml`

**Suggested content**: See "Proposed devfile.yaml for bootc" section above.

### 2. Document Local Development Without Codespaces

The CONTRIBUTING.md mentions toolbox but doesn't provide a complete alternative to Codespaces for the full development environment.

**Suggested addition to CONTRIBUTING.md**:
```markdown
## Using devfile.yaml for Local Development

The bootc repository includes a `devfile.yaml` that defines the same development
environment used in GitHub Codespaces. You can use this with:

- [devc](https://github.com/cgwalters/aidevc) - Lightweight devfile runner
- [odo](https://odo.dev/) - Red Hat's devfile-based development tool
- [DevPod](https://devpod.sh/) - Cross-platform dev environment manager

Example with devc:
```bash
# Start the devcontainer
devc run --privileged --enable-kvm

# Enter the container
devc enter

# Inside the container, build bootc
cargo build
```

### 3. Consider Splitting Init Script

The `devenv-init.sh` script currently requires sudo and makes system-wide changes. Consider:

1. Moving KVM permission changes to container build time or documentation
2. Making podman configuration part of the container image
3. Only keeping truly dynamic operations in the init script

This would make the container more self-contained and reduce dependency on post-create hooks.

### 4. Document Privileged Mode Requirements

The devcontainer.json uses `--privileged` but doesn't document why. Add comments explaining:

```json
{
  "runArgs": [
    // Required for:
    // 1. Nested podman for building/testing bootc container images
    // 2. /dev/kvm access for VM-based integration tests
    // 3. Mount propagation for nested container workflows
    "--privileged"
  ]
}
```

## Testing Strategy

### Phase 1: Manual Testing with Enhanced devc

1. Implement volume support in devc
2. Implement lifecycle events in devc
3. Test with bootc devfile.yaml
4. Verify:
   - Container starts with privileged mode
   - /dev/kvm is accessible
   - Nested podman works
   - Build and test commands execute
   - Volumes persist across container restarts

### Phase 2: Integration with bootc Workflow

1. Run bootc's test suite inside devc-managed container
2. Verify TMT tests work with nested VMs
3. Test bcvk integration
4. Compare experience with GitHub Codespaces

### Phase 3: Upstream Contribution

1. Submit PR to bootc with devfile.yaml
2. Update bootc documentation
3. Gather feedback from bootc maintainers
4. Iterate based on real-world usage

## Summary

The bootc devcontainer configuration is well-designed but specific to GitHub Codespaces. Converting it to devfile.yaml format requires:

**For devc**:
1. Named volume support (required)
2. Lifecycle event support (recommended)
3. Mount propagation options (optional, init script sufficient)
4. Custom user support (optional, root works)

**For bootc**:
1. Add devfile.yaml alongside devcontainer.json
2. Document local development alternatives to Codespaces
3. Consider making init script less privileged

**Priority**: Named volumes and lifecycle events are the critical missing pieces. Once implemented, bootc's development environment should work seamlessly with devc, providing a lightweight local alternative to GitHub Codespaces.
