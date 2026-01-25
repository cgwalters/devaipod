## Requirements

This feature requires:
- Linux-based devcontainer (x86_64 or aarch64)
- A compatible base image (Debian, Ubuntu, Fedora, or similar)

The feature will automatically install `bubblewrap` (bwrap) which is required
for the sandboxing functionality.

## What Gets Installed

- `/usr/local/bin/devaipod` - Main CLI for running sandboxed AI agents

## Usage Inside Devcontainer

Once installed, you can use devaipod commands inside the devcontainer:

```bash
# Start a tmux session with AI agent + shell
devaipod tmux

# Get a shell inside the bwrap sandbox
devaipod enter
```

## Security Model

The agent runs in a bubblewrap sandbox with:
- Read-only access to system directories (`/usr`, `/etc`, `/lib`)
- Write access only to the workspace directory
- Isolated home directory (`$HOME/ai` mounted over `$HOME`)
- PID namespace isolation

For external service access (GitHub, Jira, etc.), agents should use MCP servers
like [service-gator](https://github.com/cgwalters/service-gator) which provides
scope-based access control for CLI tools.

## Container Operations (Podman)

The feature sets up a rootful podman service that both human developers and
AI agents can use. This is safe because:
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
