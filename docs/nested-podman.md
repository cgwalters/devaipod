# Nested Podman: Running Podman Inside Podman Containers

This document provides comprehensive guidance on running Podman inside Podman containers (nested containerization) based on current best practices as of 2025.

## Table of Contents

1. [Overview](#overview)
2. [Recommended Approaches](#recommended-approaches)
3. [Approach 1: Privileged Containers (Simplest)](#approach-1-privileged-containers-simplest)
4. [Approach 2: Minimal Privileges (More Secure)](#approach-2-minimal-privileges-more-secure)
5. [Approach 3: Socket Forwarding (Host Podman)](#approach-3-socket-forwarding-host-podman)
6. [Approach 4: Sysbox Runtime (Alternative)](#approach-4-sysbox-runtime-alternative)
7. [SELinux Considerations](#selinux-considerations)
8. [Storage Drivers and Performance](#storage-drivers-and-performance)
9. [Practical Examples](#practical-examples)
10. [References](#references)

## Overview

Running Podman inside Podman (nested containers) is a common requirement for CI/CD pipelines, development environments, and container build workflows. However, nested containerization requires careful consideration of security, permissions, and performance tradeoffs.

### Key Challenges

- Containers require multiple UIDs/GIDs and user namespace support
- Container engines need to mount filesystems and create user namespaces
- Performance can suffer with userspace filesystem implementations (fuse-overlayfs)
- Security restrictions (seccomp, capabilities) may prevent nested container operations

### Current State (2025)

Podman 5.x has matured significantly with improved rootless support. Native overlay support (kernel 5.11+) provides better performance than fuse-overlayfs. However, fully unprivileged nested containers remain challenging without specific configurations.

## Recommended Approaches

Based on current research and best practices, here are the recommended approaches ranked by security vs. convenience:

| Approach | Security | Complexity | Performance | Use Case |
|----------|----------|------------|-------------|----------|
| Socket Forwarding | High | Low | High | Development environments |
| Minimal Privileges | Medium | High | Medium | Trusted CI/CD pipelines |
| Privileged Container | Low | Low | High | Quick testing, local development |
| Sysbox Runtime | High | Medium | High | Production, multi-tenant environments |

## Approach 1: Privileged Containers (Simplest)

The easiest way to run Podman inside a container is using the `--privileged` flag. This is suitable for local development and testing but **not recommended for production**.

### Basic Command

```bash
podman run --privileged \
  quay.io/podman/stable \
  podman run ubi8-minimal echo "Hello from nested container"
```

### With Volume Mounts

```bash
podman run --privileged \
  -v ./my-project:/workspace:Z \
  quay.io/podman/stable \
  podman build -t myapp /workspace
```

### Pros
- Simplest approach, works out of the box
- Full functionality, no special configuration needed
- Good for local development and quick testing

### Cons
- **Security risk**: Disables most container isolation
- Not suitable for CI/CD or production environments
- Container can potentially compromise the host

## Approach 2: Minimal Privileges (More Secure)

This approach grants only the necessary capabilities and devices without full `--privileged` mode. This is more secure but requires careful configuration.

### Required Settings

#### Capabilities
```bash
--cap-add CAP_SYS_ADMIN
--cap-add CAP_MKNOD
```

**Note**: `CAP_SYS_ADMIN` is powerful but less dangerous in rootless containers due to user namespace restrictions.

#### Devices
```bash
--device /dev/fuse:rw
```

Required for fuse-overlayfs filesystem support.

#### Security Options
```bash
--security-opt seccomp=unconfined
--security-opt label=disable    # For non-SELinux or if SELinux causes issues
```

**Important**: For SELinux systems (Fedora/RHEL), use `label=nested` instead of `label=disable` (see SELinux section below).

### Complete Example

```bash
podman run \
  --cap-add CAP_SYS_ADMIN \
  --cap-add CAP_MKNOD \
  --device /dev/fuse:rw \
  --security-opt seccomp=unconfined \
  --security-opt label=disable \
  -v ./workspace:/workspace:Z \
  quay.io/podman/stable \
  podman run alpine echo "Nested container"
```

### User Namespace Configuration

For rootless nested containers, ensure proper UID/GID mappings:

```bash
--userns=keep-id
```

Inside the container, verify `/etc/subuid` and `/etc/subgid` are configured:

```bash
# Inside the outer container
cat /etc/subuid
# Should show: podman:100000:65536 (or similar)

cat /etc/subgid
# Should show: podman:100000:65536 (or similar)
```

### Container Image Requirements

The official `quay.io/podman/stable` image is pre-configured with:
- Podman installed
- fuse-overlayfs installed
- Proper subuid/subgid mappings
- User "podman" with 5000 UIDs allocated

### Pros
- More secure than `--privileged`
- Explicit about required permissions
- Suitable for trusted CI/CD environments

### Cons
- Still requires powerful capabilities (CAP_SYS_ADMIN)
- May require seccomp=unconfined, which disables syscall filtering
- Complex to configure correctly

## Approach 3: Socket Forwarding (Host Podman)

Instead of running Podman inside the container, forward the host's Podman socket. This is the **most secure approach** for development environments.

### Setup Host Socket

```bash
# Enable Podman socket on host
systemctl --user enable --now podman.socket

# Verify socket exists
ls $XDG_RUNTIME_DIR/podman/podman.sock
```

### Forward Socket to Container

```bash
podman run -it \
  -v $XDG_RUNTIME_DIR/podman/podman.sock:/run/podman/podman.sock:Z \
  -e DOCKER_HOST=unix:///run/podman/podman.sock \
  --userns=keep-id \
  mydevcontainer
```

Inside the container, any Docker-compatible tool (including `docker-compose`) will use the host's Podman:

```bash
# Inside container
export DOCKER_HOST=unix:///run/podman/podman.sock
docker ps  # Actually uses host podman
```

### DevContainer Configuration

For VSCode DevContainers, add to `.devcontainer/devcontainer.json`:

```json
{
  "name": "My Dev Container",
  "image": "mydevimage",
  "mounts": [
    "source=${localEnv:XDG_RUNTIME_DIR}/podman/podman.sock,target=/run/podman/podman.sock,type=bind"
  ],
  "containerEnv": {
    "DOCKER_HOST": "unix:///run/podman/podman.sock"
  },
  "runArgs": [
    "--userns=keep-id"
  ],
  "workspaceMount": "source=${localWorkspaceFolder},target=/workspace,type=bind,Z",
  "workspaceFolder": "/workspace",
  "containerUser": "vscode"
}
```

### Pros
- **Most secure**: No elevated privileges in container
- Containers created by nested operations run directly on host
- Better performance (no nested overhead)
- No special capabilities or devices needed

### Cons
- Containers created are siblings, not nested
- May cause confusion about where containers run
- Requires host Podman socket to be accessible
- Not suitable for isolated build environments

## Approach 4: Sysbox Runtime (Alternative)

Sysbox is an OCI-compatible container runtime (runc replacement) that enables secure nested containerization without `--privileged`.

### What is Sysbox?

- Acquired by Docker in 2022, now open source
- Implements Linux user namespaces on all containers
- Makes containers behave like VMs for system-level software
- Supports systemd, Docker, Podman, K3s inside containers seamlessly
- **Does not use VMs**, purely OS-level virtualization

### Sysbox vs Podman

- **Podman**: Container manager (like Docker CLI)
- **Sysbox**: Container runtime (like runc)
- They work at different layers and can be used together

### Installation and Usage

```bash
# Install Sysbox (instructions vary by distro)
# See: https://github.com/nestybox/sysbox

# Run container with Sysbox runtime
podman run --runtime=sysbox-runc \
  myimage \
  podman run alpine echo "Nested container"
```

### Current Status

- **Podman support**: There is an open issue for running Podman inside Sysbox system containers
- **Best for Docker**: Sysbox is primarily designed for Docker nested containers
- **Alternative runtimes**: Consider crun (Red Hat's runtime) or gVisor for different isolation approaches

### Pros
- Most secure nested container approach
- No privileged mode required
- Supports complex workloads (systemd, K8s, etc.)
- Good for multi-tenant environments

### Cons
- Requires Sysbox installation and configuration
- Podman support is still experimental
- Additional complexity in runtime stack
- May not be available in all environments

## SELinux Considerations

On Fedora, RHEL, and other SELinux-enabled systems, special considerations apply.

### The `label=nested` Option

For nested containers on SELinux systems, use `label=nested` instead of `label=disable`:

```bash
podman run \
  --cap-add CAP_SYS_ADMIN \
  --cap-add CAP_MKNOD \
  --device /dev/fuse:rw \
  --security-opt seccomp=unconfined \
  --security-opt label=nested \
  quay.io/podman/stable \
  podman run alpine echo "Nested with SELinux"
```

### What `label=nested` Does

- Allows containers to modify SELinux labels on files and processes
- Required for nested container engines to work with SELinux
- More secure than `label=disable`
- Still respects SELinux policy restrictions

### Volume Labeling

When mounting volumes, use appropriate SELinux labels:

#### Private Volume (Single Container)
```bash
-v ./data:/data:Z
```
The `:Z` flag sets a unique MCS label, preventing other containers from accessing it.

#### Shared Volume (Multiple Containers)
```bash
-v ./shared:/shared:z
```
The `:z` flag sets a shared label, allowing multiple containers to access it.

#### Same MCS Label (Controlled Sharing)
```bash
# Container 1
podman run --security-opt label=level:s0:c100,c259 -v ./vol:/vol:Z ...

# Container 2
podman run --security-opt label=level:s0:c100,c259 -v ./vol:/vol:Z ...
```

### Security Options Summary

| Option | Effect | Use Case |
|--------|--------|----------|
| `label=disable` | Disables SELinux for container | Non-SELinux systems or troubleshooting |
| `label=nested` | Allows SELinux modifications | Nested containers on SELinux systems |
| `:Z` (uppercase) | Private volume label | Single container access |
| `:z` (lowercase) | Shared volume label | Multi-container access |

### Why SELinux Matters

SELinux is the primary defense against container escape. Even if a privileged container escapes, SELinux can prevent access to host files.

## Storage Drivers and Performance

### Native Overlay vs fuse-overlayfs

**Native Overlay** (Recommended for kernel 5.11+)
- Available in kernel 5.11+ for rootless containers
- Significantly faster than fuse-overlayfs
- No userspace overhead
- Requires fresh storage (`podman system reset`)

**fuse-overlayfs** (Legacy, but still useful)
- Userspace filesystem implementation
- Required for older kernels or when `/dev/fuse` is available
- ~2x slower for I/O heavy workloads
- Works in more restricted environments

### Kernel Version Check

```bash
uname -r
# If >= 5.11, native overlay is available
```

### Enabling Native Overlay

Native overlay is automatic in Podman 3.1+ with kernel 5.11+, but requires fresh storage:

```bash
# Warning: This deletes all containers and images!
podman system reset

# Verify native overlay is being used
podman info | grep graphDriverName
# Should show: overlay (not fuse-overlayfs)
```

### Migration Considerations

- **Cannot mix**: Native overlay and fuse-overlayfs cannot coexist in the same storage directory
- **Flag file**: `$STORAGE/overlay/.has-mount-program` indicates fuse-overlayfs is in use
- **Fresh start**: Migration requires `podman system reset`

### Performance Impact

For nested podman builds with large COPY layers:
- **fuse-overlayfs**: 60+ minutes for 130k files, 1.3GB
- **VFS driver**: 1.5 minutes (no overlay, direct copy)
- **Native overlay**: Similar to VFS, but with layer deduplication

For nested containers, consider VFS driver if performance is critical:

```bash
podman --storage-driver vfs run ...
```

## Practical Examples

### Example 1: CI/CD Build Container

```bash
#!/bin/bash
# Run a container that can build other containers

podman run \
  --name builder \
  --cap-add CAP_SYS_ADMIN \
  --cap-add CAP_MKNOD \
  --device /dev/fuse:rw \
  --security-opt seccomp=unconfined \
  --security-opt label=nested \
  -v $(pwd):/workspace:Z \
  -w /workspace \
  quay.io/podman/stable \
  bash -c "
    cd /workspace
    podman build -t myapp:latest .
    podman save myapp:latest -o myapp.tar
  "
```

### Example 2: DevContainer Setup

`.devcontainer/devcontainer.json`:
```json
{
  "name": "Rust + Podman DevContainer",
  "image": "ghcr.io/bootc-dev/devenv-debian",
  "runArgs": [
    "--privileged"
  ],
  "customizations": {
    "vscode": {
      "extensions": [
        "rust-lang.rust-analyzer"
      ]
    }
  },
  "postCreateCommand": "sudo /usr/local/bin/devenv-init.sh",
  "remoteEnv": {
    "PATH": "${containerEnv:PATH}:/usr/local/cargo/bin"
  }
}
```

This is the actual configuration used by the [bootc-dev/bootc](https://github.com/bootc-dev/bootc) project.

### Example 3: Socket Forwarding for Docker Compose

```bash
# Host setup
systemctl --user enable --now podman.socket

# Run container
podman run -it --rm \
  -v $XDG_RUNTIME_DIR/podman/podman.sock:/var/run/docker.sock:Z \
  -v $(pwd):/workspace:Z \
  -w /workspace \
  docker/compose:latest \
  docker-compose up
```

### Example 4: Rootless Nested Container

```bash
# Outer container as regular user
podman run -it \
  --userns=keep-id \
  --cap-add CAP_SYS_ADMIN \
  --device /dev/fuse:rw \
  --security-opt seccomp=unconfined \
  -e HOME=/home/podman \
  quay.io/podman/stable \
  bash

# Inside container
podman run --rm alpine echo "I am nested!"
```

## Best Practices Summary

1. **For Development**: Use socket forwarding (Approach 3)
2. **For CI/CD**: Use minimal privileges approach (Approach 2) with `label=nested`
3. **For Testing**: Privileged containers acceptable (Approach 1)
4. **For Production**: Consider Sysbox or avoid nested containers entirely

### Security Checklist

- [ ] Never use `--privileged` in production
- [ ] Use `label=nested` on SELinux systems, not `label=disable`
- [ ] Limit capabilities to only what's needed
- [ ] Consider socket forwarding for development workflows
- [ ] Document why nested containers are necessary
- [ ] Use official `quay.io/podman/stable` image or build equivalent
- [ ] Test with kernel 5.11+ for native overlay performance
- [ ] Monitor for security updates to Podman and container runtime

## References

### Official Documentation
- [How to use Podman inside of a container](https://www.redhat.com/en/blog/podman-inside-container) - Red Hat Blog
- [Rootless containers with Podman: The basics](https://developers.redhat.com/blog/2020/09/25/rootless-containers-with-podman-the-basics) - Red Hat Developer
- [podman-run documentation](https://docs.podman.io/en/latest/markdown/podman-run.1.html) - Podman Official Docs
- [Podman rootless tutorial](https://github.com/containers/podman/blob/main/docs/tutorials/rootless_tutorial.md) - GitHub

### Nested Container Issues and Discussions
- [Support running podman containers inside unprivileged container](https://github.com/containers/podman/issues/4131) - GitHub Issue
- [No network in nested containers](https://github.com/containers/podman/issues/5188) - GitHub Issue
- [How to run nested, rootless containers?](https://github.com/containers/podman/issues/15419) - GitHub Issue
- [Run Podman in a Test Container](https://docs.ci.openshift.org/docs/how-tos/nested-podman/) - OpenShift CI

### Storage and Performance
- [Podman is gaining rootless overlay support](https://www.redhat.com/en/blog/podman-rootless-overlay) - Red Hat Blog
- [Rootless containers with Podman and fuse-overlayfs](https://indico.cern.ch/event/757415/contributions/3421994/attachments/1855302/3047064/Podman_Rootless_Containers.pdf) - CERN Presentation
- [overlay driver performance issues](https://github.com/containers/fuse-overlayfs/issues/401) - GitHub Issue

### Security and SELinux
- [My advice on SELinux container labeling](https://developers.redhat.com/articles/2025/04/11/my-advice-selinux-container-labeling) - Red Hat Developer
- [Creating SELinux policies for containers](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/8/html/using_selinux/creating-selinux-policies-for-containers_using-selinux) - RHEL Documentation
- [Podman volumes and SELinux](https://blog.christophersmart.com/2021/01/31/podman-volumes-and-selinux/) - Christopher Smart's Blog
- [Security implications of CAP_SYS_ADMIN](https://github.com/containers/podman/discussions/23558) - GitHub Discussion

### Socket Forwarding and DevContainers
- [Running Dev Containers Locally with Podman and VSCode](https://geekingoutpodcast.substack.com/p/running-dev-containers-locally-with) - Geeking Out Podcast
- [VSCode dev container with Podman and WSL](https://qqq.ninja/blog/post/podman-wsl-dev-container/) - Quentin's Blog
- [Podman socket activation tutorial](https://github.com/containers/podman/blob/main/docs/tutorials/socket_activation.md) - GitHub

### Alternative Runtimes
- [Sysbox: Next-generation runc](https://github.com/nestybox/sysbox) - GitHub
- [Sysbox and Related Technologies Comparison](https://blog.nestybox.com/2020/10/06/related-tech-comparison.html) - Nestybox Blog
- [Extend sysbox for podman's rootful containers](https://github.com/nestybox/sysbox/issues/100) - GitHub Issue

### bootc Project
- [bootc-dev/bootc](https://github.com/bootc-dev/bootc) - GitHub
- [bootc CONTRIBUTING.md](https://github.com/bootc-dev/bootc/blob/main/CONTRIBUTING.md) - GitHub

---

**Last Updated**: 2025-12-11
**Podman Version**: 5.x
**Kernel Recommendations**: 5.11+ for native overlay support
