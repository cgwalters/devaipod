# Quick Start

## Before you start

devaipod is opinionated but highly configurable about the execution environment.

### devcontainer required

Your software needs *your tools* -- your version of npm/Rust/Go etc. on your preferred base OS.

Devaipod uses [devcontainers](https://containers.dev/) to provide this.
Your container image must include git and an ACP-compatible agent (OpenCode, Goose, Claude Code) alongside your tools.

### Agent selection

Devaipod supports multiple agents via the Agent Client Protocol (ACP). Configure your preferred agent in `~/.config/devaipod.toml` or use auto-detection with a multi-agent devcontainer image. See [Configuration -- Agent Configuration](configuration.md#agent-configuration) for setup.

### Agent configuration strongly encouraged

Most agents work with default models, but you will want to configure your organization's model provider and preferences.

Write an [AGENTS.md](https://agents.md/) that defines your style and rules. Do not accept stock model output.

Create a "dotfiles" git repository for your configuration. Dotfiles repos are standard in devcontainer tools, and devaipod supports them.

### Example dotfiles with opencode config

- [cgwalters](https://github.com/cgwalters/homegit), specifically look at
  https://github.com/cgwalters/homegit/tree/main/dotfiles/.config/opencode

## Requirements

- [Podman](https://podman.io/) (rootless is fine)
- The devaipod container image (prebuilt at `ghcr.io/cgwalters/devaipod:latest`,
  or build from source with `just container-build`)

## Installation

### Install the host CLI

The `devaipod` CLI is a thin host-side binary that manages the server
container and proxies commands into it. It translates working directory
paths so `devaipod diff` works from any source repository on the host.

**From a release tarball** (Linux and macOS, x86_64 and aarch64):

```bash
# Example for Linux x86_64 — substitute your platform:
curl -LO https://github.com/cgwalters/devaipod/releases/latest/download/devaipod-host-x86_64-unknown-linux-gnu.tar.gz
tar xzf devaipod-host-x86_64-unknown-linux-gnu.tar.gz
install -m 755 devaipod ~/.local/bin/   # or /usr/local/bin, anywhere on PATH
```

Available tarballs:

| Platform | Tarball |
|---|---|
| Linux x86_64 | `devaipod-host-x86_64-unknown-linux-gnu.tar.gz` |
| Linux aarch64 | `devaipod-host-aarch64-unknown-linux-gnu.tar.gz` |
| macOS x86_64 (Intel) | `devaipod-host-x86_64-apple-darwin.tar.gz` |
| macOS aarch64 (Apple Silicon) | `devaipod-host-aarch64-apple-darwin.tar.gz` |

**From source** (requires Rust toolchain):

```bash
cargo install --git https://github.com/cgwalters/devaipod devaipod-host
# or from a local checkout:
just install-host-shim
```

### Create podman secrets

devaipod passes credentials to agent containers via podman secrets.
Create your LLM API key at minimum:

```bash
echo "$ANTHROPIC_API_KEY" | podman secret create anthropic_api_key -
# Optional: GitHub token for service-gator
echo "$GH_TOKEN" | podman secret create gh_token -
```

> **macOS note:** On macOS with podman machine, verify secrets are visible
> inside the VM with `podman secret list`. If you switched machines or
> secrets are missing, recreate them.

> **GHCR note:** If you get a 403 pulling `ghcr.io/cgwalters/service-gator`,
> you may need to authenticate: `podman login ghcr.io`

### Create a configuration file

Create `~/.config/devaipod.toml` (see [Configuration](configuration.md)
for full options):

```toml
[trusted]
secrets = [
  "ANTHROPIC_API_KEY=anthropic_api_key",
  # "GH_TOKEN=gh_token",
]

# Mount host source directories into the devaipod container.
# This lets the CLI translate your cwd and enables `devaipod diff`
# from a host repo checkout.
[sources]
src = "~/src"
```

The `[sources]` section tells devaipod which host directories contain
your git repositories. See [Configuration -- Sources](configuration.md#sources)
for access levels and options.

## Starting the server

```bash
devaipod server start
```

This creates a launcher container that reads your config, resolves
`[sources]` mounts, and starts the devaipod server with the correct
bind mounts. The web UI is at <http://127.0.0.1:8080/>.

Options:

```bash
devaipod server start --port 9090                     # custom port
devaipod server start --image localhost/devaipod:latest  # use a local build
devaipod server status                                # check if running
devaipod server stop                                  # stop and remove containers
```

The default image is `ghcr.io/cgwalters/devaipod:latest`. To use a
local build, pass `--image`, set `DEVAIPOD_IMAGE`, or add
`image = "localhost/devaipod:latest"` to your `devaipod.toml`.
Resolution order: `--image` flag > `DEVAIPOD_IMAGE` env var >
config file `image` > compiled default.

## Running tasks

The web UI at <http://127.0.0.1:8080/> is the primary interface for
creating workspaces, launching tasks, and monitoring agents.

The CLI works from anywhere on the host. The shim translates your cwd
and proxies commands into the server container:

```bash
# Launch a task (service-gator auto-configured for GitHub URLs):
devaipod run https://github.com/org/repo -c 'fix typos in README.md'

# From a source directory (requires [sources] config):
cd ~/src/github/org/repo
devaipod run src:github/org/repo -c 'fix typos in README.md'

# From an issue URL (default task is "Fix <issue_url>"):
devaipod run https://github.com/org/repo/issues/123

# Start a workspace with idle agents for manual interaction:
devaipod up https://github.com/org/repo

# List workspaces:
devaipod list
```

### Reviewing agent work

When an agent finishes, review its commits from the host:

```bash
cd ~/src/github/org/repo
devaipod diff --stat   # summary of changes
devaipod diff          # full diff
devaipod fetch         # fetch agent commits into local branches
```

These commands use git's `ext::` transport to tunnel through `podman exec`
into the agent container, working even when the workspace volume uses
container-internal paths.

### TUI and shell access

```bash
# Attach to the agent TUI:
devaipod attach <workspace>

# Attach to the worker (requires orchestration enabled):
devaipod attach <workspace> --worker

# Get a shell in the workspace container:
devaipod exec <workspace> -W
```

## Service-gator: GitHub Access for the Agent

[service-gator](service-gator.md) gives the AI agent scope-controlled GitHub access (read PRs/issues, create drafts, etc.) without exposing your `GH_TOKEN`.

**Automatic for GitHub URLs:** `devaipod run https://github.com/...` or `devaipod run https://github.com/.../pull/123` auto-enables service-gator with **read + draft PR** permissions for that repository.

**Recommended: Global read-only config.** Create a podman secret for your GitHub token (`echo 'ghp_...' | podman secret create gh_token -`), then add to `~/.config/devaipod.toml`:

```toml
[trusted]
secrets = ["GH_TOKEN=gh_token"]

[service-gator.gh]
read = true
```

This gives all pods read-only access to all GitHub data (repos, search, gists, GraphQL). See [Service-gator Integration](service-gator.md) for write permissions and advanced configuration.

## Editor integration via SSH

Each devaipod workspace runs an embedded SSH server. Connect with any editor
that supports SSH remoting (Zed, VSCode, Cursor, etc.) to interrupt an
autonomous task and take manual control of the codebase.

To export SSH configs to the host, bind-mount a directory to
`/run/devaipod-ssh` when starting the daemon. `devaipod server start`
does this automatically at `~/.ssh/config.d/devaipod/`.

Add to the top of `~/.ssh/config`:

```
Include config.d/devaipod/*
```

Then connect:

```bash
# Zed:
zed ssh://devaipod-<workspace>
# VSCode:
code --remote ssh-remote+devaipod-<workspace> /workspaces/<project>
```

The SSH connection reaches the workspace container, which has full access to
credentials for manual development.

## Stopping and cleanup

```bash
devaipod server stop
```

This stops and removes both the server and launcher containers.
Workspace pods persist independently and keep running even after the
server stops.

## Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│ Host                                                             │
│  ┌──────────┐   ┌─────────────────────┐                         │
│  │ devaipod │──►│ devaipod container  │                         │
│  │ CLI shim │   │ (server/web UI)     │                         │
│  └──────────┘   └─────────┬───────────┘                         │
│       │                   │ podman.sock                          │
│       │  podman exec      │                                     │
│       └───────────────────┤   ┌───────────────────────────────┐ │
│                           └──►│ Workspace pod                 │ │
│                               │ - {pod}-workspace             │ │
│                               │ - {pod}-agent                 │ │
│                               │ - {pod}-api (web UI,          │ │
│                               │     proxy, git/PTY)           │ │
│                               │ - {pod}-gator (optional)      │ │
│                               │ - {pod}-worker (opt-in)       │ │
│                               └───────────────────────────────┘ │
└──────────────────────────────────────────────────────────────────┘
```

The host CLI shim proxies commands into the server container via
`podman exec`, translating host source paths to container mount paths.
The server uses podman-remote to create "sibling" workspace pods on
the host.

Users interact through the **control plane web UI at :8080**, which
requires authentication (a login token is generated on first start and
printed to the container logs). The control plane manages pod lifecycle
and embeds each pod's agent UI in an iframe.

## Manual setup (without the CLI shim)

Without the host shim, start the server container directly with
`podman run` and use `podman exec` for CLI commands. See the Justfile's
`container-run` target for the full invocation, or expand below:

<details>
<summary>Manual podman run commands</summary>

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

All CLI commands via `podman exec`:

```bash
podman exec devaipod devaipod run https://github.com/org/repo -c 'fix typos'
podman exec devaipod devaipod list
podman exec -ti devaipod devaipod attach <workspace>
```

</details>

## Limitations

- **No `bind_home`** -- use `[trusted.secrets]` instead

## Building from source

To build the container image locally:

```bash
just container-build
# or directly:
podman build -t localhost/devaipod -f Containerfile .
```

The multi-stage Containerfile builds devaipod from source on CentOS
Stream 10 and produces a minimal runtime image with `podman-remote`,
`git`, `tmux`, and `openssh-clients`.

To build the host CLI shim:

```bash
just install-host-shim
# or: cargo install --path crates/host-shim
```

## Next Steps

- [Configuration](configuration.md) - Customize devaipod behavior, including `[sources]`
- [Sandboxing Model](sandboxing.md) - Understand the security model
- [Secret Management](secrets.md) - Details on credential handling
