## Requirements

This feature requires:
- Linux-based devcontainer (x86_64 or aarch64)
- A compatible base image (Debian, Ubuntu, Fedora, or similar)

## What Gets Installed

- `/usr/local/bin/devaipod` - CLI for sandboxed AI agent environments

## Usage

devaipod is primarily run on the **host** to create podman pods with workspace and agent containers. The devcontainer feature installs the devaipod binary and sets up podman configuration for nested container operations.

```bash
# On host: create a workspace pod
devaipod up /path/to/project

# SSH into the workspace
devaipod ssh myproject

# Inside workspace: connect to the sandboxed agent
oc
```

## Architecture

When you run `devaipod up`, it creates a podman pod with:
- **Workspace container**: Your full development environment
- **Agent container**: Runs `opencode serve` with security restrictions (dropped capabilities, no-new-privileges, isolated home)
- **Optional gator container**: service-gator MCP server for scoped external access

The `oc` command in the workspace connects to the agent via `opencode attach http://localhost:4096`.

## Container Operations (Podman)

The feature sets up a rootful podman service that both human developers and
AI agents can use for nested container operations. This is safe because:
- The devcontainer runs under rootless podman on the host
- "root" inside the container is actually unprivileged on the real host
- Even `podman run --privileged` is constrained by the outer user namespace

Usage inside the container:
```bash
podman --remote run --rm alpine echo hello
```

The init script (`devaipod-init.sh`) must be run at container start to:
- Configure `/etc/containers/containers.conf` with nested-friendly defaults
- Configure subuid/subgid for nested containers
- Start the podman service at `/run/podman/podman.sock`
- Set up the `CONTAINER_HOST` environment variable

The containers.conf is pre-configured with `cgroups = "disabled"` and
`netns = "host"` so you don't need to specify these flags manually.
