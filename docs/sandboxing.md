# Sandboxing Model

> **Implementation details:** See rustdoc for `src/main.rs` (`build_bwrap_command` function)

## Overview

devaipod isolates AI agents using [bubblewrap](https://github.com/containers/bubblewrap) inside the DevPod container. The sandbox builds a minimal root filesystem with only explicitly needed paths mounted.

## Defense in Depth

The agent runs inside **two layers of isolation**:

1. **DevPod container** - Already isolated from your host system. The container cannot access host filesystems, processes, or network namespaces beyond what's explicitly configured.

2. **bwrap sandbox** - Further restricts the agent *within* the container. The agent sees only a subset of what the container has access to.

**Key property:** The agent cannot gain privileges beyond those already exposed to the devcontainer. Even if the agent escapes the bwrap sandbox, it's still confined to the container.

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│  Host                                                       │
│  ┌───────────────────────────────────────────────────────┐  │
│  │  DevPod Container (rootless podman on host)           │  │
│  │  ┌─────────────────────────────────────────────────┐  │  │
│  │  │  bwrap Sandbox (AI Agent)                       │  │  │
│  │  │  • /usr, /lib, /etc (read-only)                 │  │  │
│  │  │  • /workspaces/<name> (read-write)              │  │  │
│  │  │  • $HOME → $HOME/ai (isolated)                  │  │  │
│  │  │  • No /var, /opt, real $HOME                    │  │  │
│  │  │  • PID namespace isolated                       │  │  │
│  │  │  ┌─────────────┐                                │  │  │
│  │  │  │  AI Agent   │ ←── /run/devaipod.sock ──→     │  │  │
│  │  │  │  (opencode) │      (JSON-RPC upcalls)        │  │  │
│  │  │  │             │ ←── /run/podman/podman.sock    │  │  │
│  │  │  └─────────────┘      (container operations)    │  │  │
│  │  └─────────────────────────────────────────────────┘  │  │
│  │                                                         │  │
│  │  Podman Service (sudo podman system service)          │  │
│  │  • Runs as root - safe because container is rootless  │  │
│  │  • Socket at /run/podman/podman.sock (world-readable) │  │
│  │                                                         │  │
│  │  Upcall Listener (runs outside sandbox)               │  │
│  │  • Executes allowlisted binaries from                 │  │
│  │    /usr/lib/devaipod/upcalls/                         │  │
│  └───────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

## What's Mounted

| Path | Access | Notes |
|------|--------|-------|
| `/usr`, `/lib`, `/lib64` | Read-only | System binaries and libraries |
| `/etc` | Read-only | System configuration |
| `/bin`, `/sbin` | Symlinks | Point to `/usr/bin`, `/usr/sbin` |
| `/workspaces/<name>` | Read-write | The project being worked on |
| `$HOME` | Isolated | Agent sees `$HOME/ai` mounted as `$HOME` |
| `/tmp`, `/run` | Fresh tmpfs | Empty, not shared with container |
| `/dev` | Minimal | Private `/dev` via bwrap `--dev` |
| `/proc` | Isolated | Private `/proc` via bwrap `--proc` |
| `/run/podman/podman.sock` | Read-only | Sandboxed podman API socket |

**Not mounted:** `/var`, `/opt`, real `$HOME`, `/root`, other container sockets

## Home Directory Isolation

The agent's `$HOME` is replaced with an isolated directory:

- Real `$HOME` contents are **completely hidden**
- `$HOME/ai/` is bind-mounted over `$HOME`
- Agent can write to its isolated home
- `$HOME` environment variable is unchanged

This prevents access to: SSH keys, git credentials, cloud tokens, API keys in dotfiles.

## Process Isolation

- `--unshare-pid`: Agent cannot see or signal other processes
- `--die-with-parent`: Agent process dies when parent exits

## Container Operations (Podman)

AI agents (and human developers) can use podman for container operations while
still confined to the sandbox. This works through a layered security model:

1. **Rootful podman service**: A rootful podman API service (`sudo podman system service`)
   is started by the container init script (`devaipod-init.sh`). It runs in the
   devcontainer but outside the AI sandbox, listening at `/run/podman/podman.sock`.

2. **Why rootful is safe**: The devcontainer itself runs under rootless podman on the
   host. This means "root" inside the container is actually an unprivileged UID on the
   real host. Even `podman run --privileged` containers are still constrained by the
   outer user namespace.

3. **Socket access**: The podman socket is bind-mounted into the AI sandbox at
   `/run/podman/podman.sock` with `CONTAINER_HOST` set appropriately. Human users
   in the devcontainer can also use podman directly (the profile sets `CONTAINER_HOST`).

### Usage

Inside the sandbox, use the `--remote` flag:

```bash
podman --remote run --rm alpine echo hello
```

The container's `/etc/containers/containers.conf` is pre-configured with
`cgroups = "disabled"` and `netns = "host"` so you don't need to specify
these flags manually.

### Security Properties

- The AI agent cannot escape to the host via container operations
- Container images are stored in the devcontainer's storage, not persisted to host
- Network access from containers follows the same rules as the devcontainer
- Even privileged containers cannot access real host resources

## Known Limitations

1. **Full network access**: Network is NOT restricted. The agent can reach any endpoint. Future work will add network isolation via proxy or iptables.

2. **Secrets in workspace**: If `.env` or other secrets exist in the workspace, the agent can read them.

## Upcalls

For operations requiring access outside the sandbox (like creating PRs), the agent uses an upcall mechanism. See `src/upcall.rs` for details.

The agent connects to `/run/devaipod.sock` and can execute binaries from `/usr/lib/devaipod/upcalls/`:
- `gh-restricted`: Configurable GitHub CLI wrapper. Set `allow-read-all = true` in 
  `~/.config/gh-restricted.toml` for read-only mode, or leave default for restricted
  write operations (draft PRs only for allowed repos).

For future work on interactive permission prompts (similar to XDG Desktop Portal),
see [todo/upcalls-portals.md](todo/upcalls-portals.md).
