# Quick Start

## Before you start

devaipod is opinionated, but also is designed to be very configurable
about the execution environment.

### devcontainer required

A core assumption of this project is that your software needs *your tools*;
your version of npm/Rust/Go etc. using your preferred base OS.

The default solution from this project is [devcontainers](https://containers.dev/).
In particular, you must have a container image with opencode and git installed
alongside your tools.

### OpenCode configuration strongly encouraged

While OpenCode does run out of the box with a $0 "Zen" model,
a foundational assumption of this project is that in general, you
will want to configure at least the provider to use your organization's
model(s).

Further, the author of this project is very strongly of the opinion
that *everyone* should write an [AGENTS.md](https://agents.md/) that
defines your style and rules - don't just accept stock model output!

The encouraged solution to both of these is to create a "dotfiles"
git repository. This is not a new concept, it's already supported
by popular devcontainer tools, and this project is one of them.

### Example dotfiles with opencode config

- [cgwalters](https://github.com/cgwalters/homegit), specifically look at
  https://github.com/cgwalters/homegit/tree/main/dotfiles/.config/opencode

## Installation

devaipod is distributed as a prebuilt container image at
`ghcr.io/cgwalters/devaipod:latest`. All you need on the host is
[Podman](https://podman.io/) (rootless is fine).

### Create podman secrets

devaipod passes credentials to agent containers via podman secrets.
Create at least your LLM API key:

```bash
echo "$ANTHROPIC_API_KEY" | podman secret create anthropic_api_key -
# Optional: GitHub token for service-gator
echo "$GH_TOKEN" | podman secret create gh_token -
```

> **macOS note:** On macOS with podman machine, verify secrets are visible
> inside the VM with `podman secret list`. If you switched machines or
> secrets aren't showing up, you may need to recreate them.

> **GHCR note:** If you get a 403 pulling `ghcr.io/cgwalters/service-gator`,
> you may need to authenticate: `podman login ghcr.io`

### Create a configuration file

Create `~/.config/devaipod.toml` referencing your secrets (see
[Configuration](configuration.md) for full options):

```toml
[trusted]
secrets = [
  "ANTHROPIC_API_KEY=anthropic_api_key",
  # "GH_TOKEN=gh_token",
]
```

### Start the devaipod daemon

The devaipod container runs as a long-lived daemon. It needs access to the
host's podman socket so it can create sibling containers (workspace pods)
on the host.

On **Linux** (rootless podman):

```bash
SOCKET=$XDG_RUNTIME_DIR/podman/podman.sock
podman volume create devaipod-state
podman run -d --name devaipod --privileged --replace \
  -p 8080:8080 \
  --add-host=host.containers.internal:host-gateway \
  -v $SOCKET:/run/docker.sock -e DEVAIPOD_HOST_SOCKET=$SOCKET \
  -v devaipod-state:/var/lib/devaipod \
  -v ~/.config/devaipod.toml:/root/.config/devaipod.toml:ro \
  ghcr.io/cgwalters/devaipod:latest
```

On **macOS** (podman machine):

On macOS, podman runs inside a Linux VM. The volume source for the socket
must be the path *inside the VM*, not the Mac-side path. For a rootful
machine that is `/run/podman/podman.sock`.

```bash
podman volume create devaipod-state
podman run -d --name devaipod --privileged --replace \
  -p 8080:8080 \
  -v /run/podman/podman.sock:/run/docker.sock \
  -e DEVAIPOD_HOST_SOCKET=/run/podman/podman.sock \
  -v devaipod-state:/var/lib/devaipod \
  -v ~/.config/devaipod.toml:/root/.config/devaipod.toml:ro \
  ghcr.io/cgwalters/devaipod:latest
```

Once started, open the web UI at <http://127.0.0.1:8080/> -- this is the
primary way to interact with devaipod. You can create workspaces, kick off
tasks, and monitor agent progress from the browser.

### Why `--privileged` and `DEVAIPOD_HOST_SOCKET`?

`--privileged` is required for access to the mounted podman socket and for
spawning workspace containers.

`DEVAIPOD_HOST_SOCKET` tells devaipod the **host-side** path of the socket.
When devaipod creates sibling containers, bind mount sources are resolved by
the host's container daemon, not inside the devaipod container. On rootless
Linux the host path (e.g. `/run/user/1000/podman/podman.sock`) differs from
the container-internal `/run/docker.sock`.

We do **not** use `--network host`. Instead, the `--add-host` flag (Linux
only; unnecessary on macOS) lets devaipod reach pod-published ports via
`host.containers.internal`. Override with `DEVAIPOD_HOST_GATEWAY` if needed.

### State volume

The `devaipod-state` volume persists the web UI auth token across container
restarts. Token lookup order: (1) podman secret
`/run/secrets/devaipod-web-token` if provided, (2)
`/var/lib/devaipod/web-token` from the state volume. If no token exists, one
is generated on first start.

## Running tasks

The web UI at <http://127.0.0.1:8080/> is the primary interface for
creating workspaces, launching tasks, and monitoring agent progress.

For CLI usage, all commands are executed inside the daemon container via
`podman exec`:

```bash
# Launch a task (service-gator auto-configured for GitHub URLs):
podman exec devaipod devaipod run https://github.com/org/repo -c 'fix typos in README.md'

# From an issue URL (default task is "Fix <issue_url>"):
podman exec devaipod devaipod run https://github.com/org/repo/issues/123

# Start a workspace with idle agents for manual interaction:
podman exec -ti devaipod devaipod up https://github.com/org/repo

# List workspaces:
podman exec devaipod devaipod list
```

A TUI is also available for terminal-based monitoring:

```bash
# Attach to the agent:
podman exec -ti devaipod devaipod attach <workspace>

# Attach to the worker (requires orchestration enabled):
podman exec -ti devaipod devaipod attach <workspace> --worker

# Get a shell in the workspace container:
podman exec -ti devaipod devaipod exec <workspace> -W
```

## Service-gator: GitHub Access for the Agent

[service-gator](service-gator.md) provides scope-controlled GitHub access (read PRs/issues, create drafts, etc.) to the AI agent without exposing your `GH_TOKEN` directly.

**Automatic for GitHub URLs:** When you run `devaipod run https://github.com/...` or `devaipod run https://github.com/.../pull/123`, service-gator is auto-enabled with **read + draft PR** permissions for that repository.

**Recommended: Global read-only config.** Create a podman secret for your GitHub token (`echo 'ghp_...' | podman secret create gh_token -`), then add to `~/.config/devaipod.toml`:

```toml
[trusted]
secrets = ["GH_TOKEN=gh_token"]

[service-gator.gh]
read = true
```

This gives all pods read-only access to all GitHub data (repos, search, gists, GraphQL). See [Service-gator Integration](service-gator.md) for write permissions and advanced configuration.

## Editor integration via SSH

Each devaipod workspace runs an embedded SSH server, allowing you to connect
with editors that support SSH remoting (Zed, VSCode, Cursor, etc.). This lets
you interrupt an autonomous task and take manual control of the codebase.

To export SSH configs from the container to the host, bind-mount a directory
to `/run/devaipod-ssh` when starting the daemon:

```bash
mkdir -p ~/.ssh/config.d/devaipod

# Add to the top of ~/.ssh/config:
# Include config.d/devaipod/*
```

Then add `-v ~/.ssh/config.d/devaipod:/run/devaipod-ssh:Z` to your
`podman run` command. When this mount exists, devaipod automatically writes
SSH configs there. You can then connect:

```bash
# Zed:
zed ssh://devaipod-<workspace>
# VSCode:
code --remote ssh-remote+devaipod-<workspace> /workspaces/<project>
```

The SSH connection goes to the workspace container, which has full access to
credentials for manual development work.

## Stopping and cleanup

The daemon runs `sleep infinity` by default. To stop it:

```bash
podman stop devaipod
podman rm devaipod
```

Workspace pods persist independently and continue running even if the
devaipod container is stopped.

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│ Host                                                        │
│  ┌─────────────────────┐                                    │
│  │ podman.sock         │◄──────────────────┐               │
│  └─────────────────────┘                   │               │
│                                            │               │
│  ┌─────────────────────┐     ┌─────────────┴─────────────┐ │
│  │ devaipod container  │     │ Workspace pod             │ │
│  │ (daemon)            │────►│ - {pod}-workspace         │ │
│  │                     │     │ - {pod}-agent             │ │
│  └─────────────────────┘     │ - {pod}-api (web UI,     │ │
│           ▲                  │     proxy, git/PTY)       │ │
│           │                  │ - {pod}-gator (optional)  │ │
│  Web UI :8080 / podman exec  │ - {pod}-worker (opt-in)  │ │
│  (primary: browser,          └───────────────────────────┘ │
│   also CLI/TUI)                                            │
└─────────────────────────────────────────────────────────────┘
```

Users interact through the **control plane web UI at :8080**, which is
authenticated by default (a login token is generated on first start and
printed to the container logs). The control plane manages pod lifecycle
and embeds each pod's agent UI in an iframe. The pod-api sidecar is the
only published port per pod (8090 internal, random host port); it serves
the vendored opencode SPA, proxies to the opencode agent (port 4096,
not published externally), and provides git/PTY endpoints. The opencode
server itself requires Basic Auth with a per-pod password that the
pod-api sidecar handles transparently.

The devaipod container uses podman-remote to communicate with the host's
podman daemon via the mounted socket. This allows it to create "sibling"
containers (workspace pods) that run alongside it on the host.

## Limitations

- **No `bind_home`** - the `[bind_home]` config option is not supported; use `[trusted.secrets]` instead

## Building from source

To build the container image locally:

```bash
podman build -t ghcr.io/cgwalters/devaipod -f Containerfile .
```

The multi-stage Containerfile builds devaipod from source using CentOS
Stream 10 and creates a minimal runtime image with `podman-remote`, `git`,
`tmux`, and `openssh-clients`.

## Next Steps

- [Configuration](configuration.md) - Customize devaipod behavior
- [Sandboxing Model](sandboxing.md) - Understand the security model
- [Secret Management](secrets.md) - Details on credential handling
