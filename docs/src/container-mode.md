# Container Mode

Devaipod can run as a container image itself, rather than as a host binary. This is useful for:

- **Reproducible deployments** - same devaipod version everywhere
- **CI/CD integration** - run agents in pipelines without installing binaries
- **Server deployments** - run devaipod as a daemon managing multiple workspaces
- **Isolation** - keep devaipod itself sandboxed from the host

## Quick Start

```bash
# Pull the image
podman pull ghcr.io/cgwalters/devaipod:latest

# Run as a daemon
podman run -d --name devaipod --privileged \
  -v $XDG_RUNTIME_DIR/podman/podman.sock:/run/podman/podman.sock \
  -v ~/.config/devaipod.toml:/root/.config/devaipod.toml:ro \
  ghcr.io/cgwalters/devaipod

# Run an agent
podman exec devaipod devaipod run https://github.com/org/repo -c 'fix the bug'

# Attach to the TUI
podman exec -ti devaipod devaipod attach -l

# Use the dashboard
podman exec -ti devaipod devaipod tui

# List workspaces
podman exec devaipod devaipod list
```

## Requirements

### Privileged Mode

The `--privileged` flag is required for:
1. Access to the mounted podman socket
2. Spawning privileged workspace containers (needed for nested podman in devcontainers)

### Podman Socket

The container needs access to the host's podman socket to spawn sibling containers:

```bash
-v $XDG_RUNTIME_DIR/podman/podman.sock:/run/podman/podman.sock
```

On systems using podman machine (macOS, Windows), use the appropriate socket path from `podman machine inspect`.

## Credentials and Secrets

In container mode, devaipod cannot access the host's home directory. The `bind_home` configuration option is **not supported** and will error if configured. Instead, use podman secrets:

### Podman Secrets (Required)

Create podman secrets on the host and reference them in your config:

```bash
# Create secrets
echo "$ANTHROPIC_API_KEY" | podman secret create anthropic_api_key -
echo "$GH_TOKEN" | podman secret create gh_token -
```

Then in `~/.config/devaipod.toml`:

```toml
[trusted]
secrets = [
  "ANTHROPIC_API_KEY=anthropic_api_key",
  "GH_TOKEN=gh_token",
]

# IMPORTANT: Remove any bind_home configuration for container mode
# [bind_home]
# paths = [...]  # This will error in container mode
```

The secrets are passed through to workspace containers using podman's `--secret type=env` feature.

### Migrating from bind_home

If you have an existing config with `bind_home` for credentials, you'll need to:

1. Create podman secrets for each credential
2. Add them to `[trusted.secrets]`
3. Remove the `[bind_home]` section (or use a separate config for container mode)

## Building the Image

To build locally:

```bash
# Using just
just container-build

# Or directly
podman build -t ghcr.io/cgwalters/devaipod -f Containerfile .
```

The multi-stage Containerfile:
1. Builds devaipod from source using CentOS Stream 10
2. Creates a minimal runtime image with `podman-remote`, `git`, `tmux`, and `openssh-clients`

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│ Host                                                        │
│  ┌─────────────────────┐                                    │
│  │ podman.sock         │◄──────────────────┐               │
│  └─────────────────────┘                   │               │
│                                            │               │
│  ┌─────────────────────┐     ┌─────────────┴─────────────┐ │
│  │ devaipod container  │     │ Created workspace pods    │ │
│  │ (daemon mode)       │────►│ - workspace container     │ │
│  │                     │     │ - agent container         │ │
│  └─────────────────────┘     │ - gator container         │ │
│           ▲                  │ - worker container        │ │
│           │                  └───────────────────────────┘ │
│  podman exec -ti devaipod                                  │
│  (for TUI/CLI access)                                      │
└─────────────────────────────────────────────────────────────┘
```

The devaipod container uses podman-remote to communicate with the host's podman daemon via the mounted socket. This allows it to create "sibling" containers (workspace pods) that run alongside it on the host.

## Limitations

- **No local repository support** - Container mode only works with remote URLs, not local directories
- **SSH config** - The generated SSH config is inside the container; you'll need to use `podman exec` for SSH access
- **bind_home not supported** - The `[bind_home]` config section will error in container mode; use `[trusted.secrets]` instead

## Daemon Management

The container runs `sleep infinity` by default, acting as a daemon. To stop it:

```bash
podman stop devaipod
podman rm devaipod
```

Workspaces created by the daemon persist independently and continue running even if the devaipod container is stopped.
