# Workspace v2: From Volumes to Host Directories

Assisted-by: OpenCode (Claude Opus 4.6)

## Problem Statement

The current sandbox model creates up to 5 named volumes per pod. Code
lives inside opaque podman volumes -- invisible from the host, requiring
special transport to move data in or out. This is unnecessary complexity.

## Prior Art

**Cursor** creates git worktrees under `~/.cursor/worktrees/<repo>/`, one
per agent. The human clicks "Apply" to merge back. Max 20 worktrees, auto
cleanup.

**paude** uses `ext::podman exec` git transport and a `harvest` + `reset`
loop. Elegant but complex plumbing to solve a problem that goes away if
the workspace is just a host directory.

**Gastown** uses git worktrees with no container sandboxing -- the
worktree is the only isolation boundary.

## Design

### Core idea

The user provides **read-only source directories** (git repos, docs,
whatever). The agent gets a **writable scratch directory on the host**.
Both are bind-mounted into the container. The container provides
execution isolation; the host filesystem provides state.

```bash
# Single repo:
devaipod up ./api "fix the auth bug"

# Multiple source dirs:
devaipod up --source-dir ~/src/work "update SDK to match new API"

# Non-git content works too:
devaipod up --source-dir ~/docs ./api "update docs to match code"
```

### Layout

The agent's writable scratch directory defaults to
`~/.var/lib/devaipod/<pod-id>/`, configurable via `--agent-dir` or
`devaipod.toml`. This keeps agent state completely out of the user's
source tree.

```
Host                                     Container
───────────────────────────────────      ──────────────────────────
~/src/work/                          →   /mnt/source/         (RO)
  ├── api/
  ├── sdk/
  └── docs/

~/.var/lib/devaipod/<pod-id>/        →   /workspaces/         (RW)
  └── (initially empty -- agent
       populates via tools)
```

On pod creation, devaipod:

1. Creates `~/.var/lib/devaipod/<pod-id>/` on the host
2. Bind-mounts source directory RO at `/mnt/source/`
3. Bind-mounts agent directory RW at `/workspaces/`
4. Starts the container with the devcontainer image

That's it. Devaipod does not clone repos or set up git remotes -- the
agent does that itself using provided tools.

### Agent-side: skills and subagents

The agent is given a **skill** (or MCP tool) for working with source
content. For git repos, this provides:

- `checkout <repo>`: runs `git clone --reference /mnt/source/<repo>`
  into `/workspaces/<repo>`, sharing objects via alternates for speed.
  Configures a `source` remote pointing at `/mnt/source/<repo>`.
- `fetch-source`: runs `git fetch source` to pick up new human commits.

The agent is encouraged to **spawn subagents** per repo/subdirectory.
Each subagent works in its own `/workspaces/<repo>` checkout. This maps
naturally to the subagent container model described in
[subagent-container.md](./subagent-container.md).

For non-git content (docs, images, data), the agent simply reads from
`/mnt/source/` and writes output to `/workspaces/`.

### Human-agent interaction

Because everything is on the host filesystem, bidirectional handoff is
just ordinary filesystem operations:

- **Human sees agent work**: `cd ~/.var/lib/devaipod/<id>/api && git log`
- **Human fetches agent commits**: `git fetch ~/.var/lib/devaipod/<id>/api`
- **Agent sees human updates**: source is a live bind mount, so new
  commits appear at `/mnt/source/` in real time. Agent runs
  `git fetch source` to pick them up.

No volumes, no special transport, no harvest command.

### Review and push

Because the agent's directory is on the host, the review and push layer
(see [lightweight-review.md](./lightweight-review.md)) simplifies. Pod-api
reads the agent's git state from the bind-mounted directory. For pushing
to remotes, pod-api runs `git push` using GH_TOKEN from the agent's
directory.

### Remote and Kubernetes

Same model -- the "host" is the remote machine. To get agent work back
to the user's local machine, devaipod periodically fetches from the
remote agent directory (via SSH or a pod-api proxy endpoint) into a local
tracking branch.

## Controlplane mount strategy

Devaipod itself runs as a container. To create agent directories on the
host filesystem, the controlplane container needs `~/.var/lib/devaipod/`
bind-mounted in from the host. This follows the same pattern as
`DEVAIPOD_HOST_SOCKET` for the podman socket:

- The Justfile's `container-run` recipe adds
  `-v "$HOME/.var/lib/devaipod":/var/lib/devaipod-workspaces`
- `DEVAIPOD_HOST_WORKDIR="$HOME/.var/lib/devaipod"` tells the
  controlplane the host-side path to use in `-v` args for agent
  containers
- The controlplane creates directories under the container-side mount
  (`/var/lib/devaipod-workspaces/<pod-id>/`), but uses
  `$DEVAIPOD_HOST_WORKDIR/<pod-id>/` as the volume source when creating
  agent containers -- the host podman daemon resolves paths on the host

This is the minimal mount. We do not bind-mount `~` entirely.

## Implementation

- Add `DEVAIPOD_HOST_WORKDIR` env var and `get_host_workdir_path()`
  helper (same pattern as `DEVAIPOD_HOST_SOCKET`)
- Create `<pod-id>/` under the workdir at pod creation time
- Replace `{pod}-agent-workspace` volume with a bind mount of the
  host agent dir at `/workspaces/`
- Bind-mount source repo RO at `/mnt/source/`
- Update agent, pod-api, and gator container configs for bind mounts
- UID mapping: follow devcontainer spec (`updateRemoteUserUID` or
  equivalent), same as VS Code / other IDE devcontainer implementations
- Provide `checkout` and `fetch-source` as agent skill/MCP tool
- `devaipod delete` removes the agent directory
- `devaipod clean` garbage-collects orphaned agent dirs
- Update Justfile `container-run` with the new bind mount
- For remote pods, add periodic `git fetch` from remote to local

## Resolved Questions

- **Agent dir location**: `~/.var/lib/devaipod/<pod-id>/`, configurable.
  Keeps agent state out of the source tree entirely.
- **UID mapping**: follow the devcontainer spec, same as VS Code etc.
- **Nested source trees**: not an issue since agent dir is outside the
  source tree. Agent clones preserve whatever structure they want.
- **Migration**: no migration path. Old pods use volumes, new pods use
  host dirs.

## Open Questions

1. **Git alternates**: the alternates file must resolve from both host
   and container. Since the agent dir and source dir are in different
   filesystem locations, relative paths won't work. Write two absolute
   paths (host + container); git ignores lines that don't resolve.
   Needs validation.

2. **Remote fetch transport**: for remote/k8s, what's the best way
   to periodically fetch agent work back to the user's local machine?
   SSH, pod-api proxy, or git bundle? Defer to when remote support
   is implemented.
