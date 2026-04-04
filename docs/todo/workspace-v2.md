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
`~/.local/share/devaipod/workspaces/<pod-id>/`, configurable via `--agent-dir` or
`devaipod.toml`. This keeps agent state completely out of the user's
source tree.

```
Host                                     Container
───────────────────────────────────      ──────────────────────────
~/src/work/                          →   /mnt/source/         (RO)
  ├── api/
  ├── sdk/
  └── docs/

~/.local/share/devaipod/             →   /workspaces/         (RW)
  workspaces/<pod-id>/
  └── (initially empty -- agent
       populates via tools)
```

On pod creation, devaipod:

1. Creates `~/.local/share/devaipod/workspaces/<pod-id>/` on the host
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

- **Human sees agent work**: `cd ~/.local/share/devaipod/workspaces/<id>/api && git log`
- **Human fetches agent commits**: `git fetch ~/.local/share/devaipod/workspaces/<id>/api`
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
host filesystem, the controlplane container needs `~/.local/share/devaipod/workspaces/`
bind-mounted in from the host. This follows the same pattern as
`DEVAIPOD_HOST_SOCKET` for the podman socket:

- The Justfile's `container-run` recipe adds
  `-v "$HOME/.local/share/devaipod/workspaces":/var/lib/devaipod-workspaces`
- `DEVAIPOD_HOST_WORKDIR="$HOME/.local/share/devaipod/workspaces"` tells the
  controlplane the host-side path to use in `-v` args for agent
  containers
- The controlplane creates directories under the container-side mount
  (`/var/lib/devaipod-workspaces/<pod-id>/`), but uses
  `$DEVAIPOD_HOST_WORKDIR/<pod-id>/` as the volume source when creating
  agent containers -- the host podman daemon resolves paths on the host

This is the minimal mount. We do not bind-mount `~` entirely.

## Implementation status

### Done

- `DEVAIPOD_HOST_WORKDIR` env var and `get_host_workdir_path()` helper
- `<pod-id>/` directory creation at pod creation time
- `{pod}-agent-workspace` volume replaced with host bind mount at
  `/workspaces/` for LocalRepo
- Source repo bind-mounted RO at `/mnt/source/<dirname>/`
- `--source-dir` CLI flag: mounts additional read-only directories at
  `/mnt/source/<dirname>/` with automatic git clone into agent workspace
  for convenience
- Agent, pod-api, and gator container configs updated for bind mounts
- `devaipod delete` removes the agent directory
- Justfile `container-run` updated with workspaces bind mount
- Init container name sanitization for host-path volume sources

### Remaining

- UID mapping: see [rootless-uidmapping.md](./rootless-uidmapping.md)
- UI/model rework: workspace-anchored design (see below)
- `devaipod clean` garbage-collects orphaned agent dirs
- For remote pods, add periodic `git fetch` from remote to local

## Resolved Questions

- **Agent dir location**: `~/.local/share/devaipod/workspaces/<pod-id>/`, configurable.
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

## Phase 2: Workspace-anchored UI/model rework

The changes above are infrastructure — volumes replaced with host dirs,
source dirs mounted read-only. But the UI and data model still treat
pods as the primary object. This section describes the shift to
workspaces as the anchor.

### The conceptual shift

**Current model (pod-centric)**:
- Podman is the registry. Discovery = `podman pod ps`.
- A "workspace" is whatever is inside the pod's volumes.
- Delete the pod, everything is gone.
- The launcher asks for a git URL. That's the only entry point.

**New model (workspace-centric)**:
- The host directory (`~/.local/share/devaipod/workspaces/<name>/`) is
  the durable object. It persists across pod lifecycles.
- A pod is transient compute attached to a workspace. Start, stop,
  replace — the workspace directory survives.
- Discovery is the union of: (a) running pods (from podman), and
  (b) workspace directories on disk (from the filesystem).
- The launcher is an IDE-like source picker, not just a URL field.

This aligns with how IDEs work: you "open a project" (a directory),
and the IDE attaches compute/services to it. The project directory
is the anchor. You close the IDE, the directory remains.

### What changes in the data model

**Workspace state file**: Each workspace directory gets a
`<workspace>/.devaipod/state.json` (or similar) that records:

```json
{
  "name": "devaipod-myproject-abc123",
  "source": "https://github.com/org/myproject",
  "source_dirs": ["/home/user/src/myproject"],
  "created": "2026-04-04T12:00:00Z",
  "last_active": "2026-04-04T14:30:00Z",
  "task": "fix the auth bug",
  "title": "Auth bug fix",
  "pod_name": "devaipod-myproject-abc123",
  "completion_status": "done"
}
```

This replaces the current split across podman labels (immutable),
web pod-state-cache (ephemeral), and TUI state.json (versioned).
One file per workspace, human-readable, version-controlled by the
workspace itself.

**Discovery**: `list_workspaces()` scans the workspaces base directory
and reads each state file. For each workspace, it checks whether
a matching pod is running (via podman). Result:

| Workspace state | Pod state | UI display |
|---|---|---|
| Has state file | Running | "Running" — show agent status |
| Has state file | Stopped/missing | "Stopped" — show last-known state |
| No state file | Running (legacy) | Legacy pod — show as today |
| Directory exists, empty | — | Orphaned — candidate for cleanup |

**Recent sources cache**: A separate file at
`~/.local/share/devaipod/recent-sources.json` tracks recently-used
source directories:

```json
[
  {"path": "/home/user/src/myproject", "last_used": "2026-04-04T14:30:00Z"},
  {"path": "/home/user/src/api", "last_used": "2026-04-03T09:15:00Z"},
  {"path": "/home/user/src/docs", "last_used": "2026-03-28T16:45:00Z"}
]
```

Updated every time a workspace is created from a local source.
Capped at ~50 entries, sorted by last_used descending.

### What changes in the launcher UI

The current launcher has a single text field: "Repository URL".
The new launcher has two entry points:

**1. Local directory picker** (primary for local development):

```
┌─ New Workspace ──────────────────────────────────┐
│                                                   │
│  Source                                           │
│  ┌───────────────────────────────────────────┐    │
│  │ ~/src/myproject                        [Browse]│
│  └───────────────────────────────────────────┘    │
│                                                   │
│  Recent:                                          │
│   ~/src/api              3 hours ago              │
│   ~/src/docs             yesterday                │
│   ~/src/infra            last week                │
│                                                   │
│  Task (optional)                                  │
│  ┌───────────────────────────────────────────┐    │
│  │ fix the auth bug                          │    │
│  └───────────────────────────────────────────┘    │
│                                                   │
│  [Launch]                                         │
└───────────────────────────────────────────────────┘
```

Clicking a recent source fills in the field. The recent list is
populated from `recent-sources.json`. When the source is a local
path, it's passed to `devaipod run --source-dir <path>`.

**2. Remote URL** (unchanged, for remote repos / PRs / issues):

The existing URL field still works. Typing a URL (https://, git@)
bypasses the local picker and uses the current remote clone flow.

The two modes can coexist in the same form — the source field accepts
both paths and URLs. The "Recent" section only shows local paths.

**Key UX principle**: the common case (local development) should be
as fast as possible. Click a recent project, optionally type a task,
hit Launch. No URLs, no configuration.

### What changes in the pod list

The pod list becomes a **workspace list**. Each card shows:

- **Title** (from state file or agent status)
- **Source** (local path or remote URL)
- **Status**: Running (green), Stopped (gray), Done (purple)
- **Last active** (from state file, not from podman)
- **Actions**: Open, Start (if stopped), Stop, Delete

Stopped workspaces appear in the list (they're directories on disk).
The user can re-launch compute against a stopped workspace without
re-cloning — just `devaipod up --workspace <existing-dir>`.

Sorting: same frecency sort (running first, then by last_active).

### What changes in the CLI

New commands and flags:

```bash
# List workspaces (not just running pods)
devaipod ls              # shows workspaces + pod status
devaipod ls --running    # only running (current behavior)

# Re-attach to existing workspace directory
devaipod up --workspace ~/.local/share/devaipod/workspaces/myproject-abc123

# Clean up orphaned workspace dirs (no matching pod, old)
devaipod clean --older-than 30d

# Open workspace directory in host shell
devaipod cd myproject    # prints or cd's to workspace dir
```

### What changes in the backend

**`src/main.rs`**: `cmd_list` gains a `--all` mode (default) that
scans workspace directories AND running pods, merging the results.
`--running` gives the current behavior.

**`src/web.rs`**: `GET /api/devaipod/pods` becomes
`GET /api/devaipod/workspaces` (or an alias). Returns the merged
workspace+pod list. New endpoint `GET /api/devaipod/recent-sources`
returns the recent sources list.

**`src/agent_dir.rs`**: Gains `list_workspaces()` that scans the
base directory and reads state files. The state file is written at
workspace creation time and updated on status changes.

**`POST /api/devaipod/run`**: Gains `source_dirs` field. When the
source is a local path, it's treated as a `--source-dir`.

### Migration

No migration needed. Existing pods without workspace directories
appear as "legacy" entries in the workspace list (podman-only, no
state file). New workspaces get state files. Legacy pods can be
recreated to get a workspace directory.

### Implementation order

1. **State file**: write `.devaipod/state.json` in workspace dir at
   creation time, update on status changes.
2. **Workspace listing**: `list_workspaces()` in agent_dir.rs,
   merged with podman pod list.
3. **Recent sources**: read/write `recent-sources.json`, populate on
   workspace creation from local source.
4. **CLI**: `devaipod ls` shows workspaces, `--running` for compat.
5. **Web API**: `GET /api/devaipod/workspaces` returns merged list.
   `GET /api/devaipod/recent-sources` for the launcher.
6. **Frontend**: update pods.tsx to show workspaces, update launcher
   form to show recent sources and accept local paths.
7. **Re-attach**: `devaipod up --workspace <dir>` re-launches compute
   against an existing workspace directory.

## Phase 3: Decouple workspace containers from agent pods

The workspace container (which runs `sleep infinity` and exists solely
as a human shell target) is unnecessary overhead. Agents are
self-contained: they have their own git clone, home directory, and
`opencode serve` process. The workspace container provides no services
the agent consumes.

### What changes

**Agent pods become leaner.** Drop the workspace container from the
default pod layout. An agent pod is now: agent + api + gator (+ optional
worker). This saves one container per pod.

**SSH access adjusts.** The default `{pod}.devaipod` SSH host entry
points to the agent container instead of the workspace. The `-agent`
suffix entry is dropped (redundant). Worker entry remains as-is.

**`devaipod attach`/`exec` default target changes** from workspace to
agent. The `-W` flag becomes a no-op or error for workspace-less pods.

### `devaipod devcontainer` — standalone dev environments

A new subcommand family provides the human-facing devcontainer
experience, decoupled from agents:

```bash
devaipod devcontainer run <source>     # launch a devcontainer
devaipod devcontainer list             # list running devcontainers
devaipod devcontainer rm <name>        # remove a devcontainer
```

A devcontainer pod is: workspace + api (no agent, no gator). It gets
trusted credentials, devcontainer lifecycle commands, dotfiles — the
full human dev environment. SSH access via `{name}.devaipod`. This is
the "just give me a dev environment for this repo" path.

The REST API mirrors the CLI:
- `POST /api/devaipod/devcontainer/run`
- `GET /api/devaipod/devcontainer/list`
- `DELETE /api/devaipod/devcontainer/{name}`

### Why separate from agent pods

Agents and devcontainers have different lifecycles and trust models:
- **Agents** are autonomous, get LLM keys but not forge credentials
  (those go through gator), run headless, disposable.
- **Devcontainers** are interactive, get full trusted credentials,
  have SSH access for editors, may be long-lived.

Coupling them in one pod created confusion: the workspace container
sat idle most of the time, and users who wanted a quick dev environment
had to wait for agent infrastructure to spin up. Separating them makes
both use cases faster and simpler.

## Phase 4: Repo-centric control plane

Inspired by Cursor 3's "Agents Window" (see changelog/3-0), the
control plane UI should organize work by **git repository**, not by
individual pod. The current flat pod list doesn't scale: with 5+
concurrent agents across 3 repos, it becomes a wall of cards with no
structure.

### The conceptual shift

**Current**: flat list of pods, each showing repo/task/status. The
repo is a label on the pod. The user mentally groups them.

**New**: the primary axis is the repo. Each repo is a collapsible
section. Agents (and devcontainers) are children of the repo they're
working on. The user sees their work organized the way they think
about it: "what's happening on devaipod?", "what's happening on
infra?".

### The journal repo

Not every task maps to a single git repo. Research, planning,
cross-cutting investigations, learning — these are repo-less by
nature. Rather than leaving them in an "Uncategorized" bucket, we
strongly encourage a **journal repo**: a generic git repo that holds
research docs, notes, and acts as a persistent knowledge base.

The journal repo is:
- Configured in `devaipod.toml`: `journal-repo = "~/src/journal"`
  (or `https://github.com/user/journal`)
- Suggested on first use if not configured: "You're launching a task
  without a specific repo. Would you like to set up a journal repo
  for research and notes?"
- Pre-seeded with a simple structure: `research/`, `notes/`,
  `README.md`
- The default target when launching agents without a source directory

This means every agent always has a repo context. The flat
"uncategorized" bucket goes away. Tasks like "research the state of
WASM runtimes" or "draft an RFC for the new API" get committed to
the journal as actual documents the agent produces.

### UI layout

```
┌─ Control Plane ─────────────────────────────────────────┐
│                                                          │
│  [+ New Agent]  [Search...]  [Filter: All ▾]            │
│                                                          │
│  ▼ cgwalters/devaipod                            3 active│
│  ┌──────────────────────────────────────────────────┐    │
│  │ ● Fix auth middleware     Running  2m ago   [→]  │    │
│  │ ● Add metrics endpoint    Running  5m ago   [→]  │    │
│  │ ◉ Refactor pod.rs         Done     1h ago   [→]  │    │
│  │ ▸ Devcontainer            Running            ssh │    │
│  └──────────────────────────────────────────────────┘    │
│                                                          │
│  ▼ cgwalters/infra                               1 active│
│  ┌──────────────────────────────────────────────────┐    │
│  │ ● Update CI pipeline      Running  10m ago  [→]  │    │
│  └──────────────────────────────────────────────────┘    │
│                                                          │
│  ▼ journal                                       1 active│
│  ┌──────────────────────────────────────────────────┐    │
│  │ ● Research WASM runtimes  Running  3m ago   [→]  │    │
│  └──────────────────────────────────────────────────┘    │
│                                                          │
│  ▸ Stopped (4)                                           │
│                                                          │
└──────────────────────────────────────────────────────────┘
```

Key elements:
- Repos are grouped and collapsible. Active repos (with running
  agents) are expanded by default. Repos with only stopped/done
  agents collapse into a summary.
- Each agent row is compact: title, status dot, time, and a click-
  through arrow to the agent's opencode UI.
- Devcontainers appear under their repo too, visually distinct
  (different icon, "ssh" instead of agent status).
- The "Stopped" section at the bottom collects all repos that have
  no running agents, collapsed by default.

### Data model changes

The repo becomes a first-class grouping key. We already have
`io.devaipod.repo` as a pod label. The new API endpoint returns
pods grouped:

```
GET /api/devaipod/control-plane
```

Response:
```json
{
  "repos": [
    {
      "repo": "cgwalters/devaipod",
      "source_path": "/home/user/src/github/cgwalters/devaipod",
      "agents": [ ... ],
      "devcontainers": [ ... ]
    },
    {
      "repo": "journal",
      "source_path": "/home/user/src/journal",
      "agents": [ ... ],
      "devcontainers": []
    }
  ]
}
```

This is a view layer on top of existing data — the underlying pod
and workspace models don't change. The grouping is computed from
`io.devaipod.repo` labels and workspace state files.

### Journal repo configuration

In `devaipod.toml`:
```toml
[journal]
repo = "~/src/journal"
# Or: repo = "https://github.com/user/journal"
```

When `devaipod run` or `devaipod up` is invoked without a source
directory and no `--source-dir` flag, the journal repo is used as
the source. The agent gets the journal mounted at `/mnt/source/`
and can write research/notes/docs there.

If no journal is configured and the user launches a repo-less task,
devaipod prompts: "No source repo specified. Set up a journal repo
for research tasks? [y/N]". If yes, it creates `~/src/journal/`
with a basic structure and adds it to `devaipod.toml`.

### Interaction with `devaipod fetch/diff`

The repo-centric view makes fetch/diff more natural. Instead of
`devaipod fetch` (which auto-detects the workspace), the control
plane can show a "Review changes" button per agent that runs
fetch+diff and shows the three-dot diff inline or opens the
host-side repo with the fetched remote.

### Git worktrees as the agent workspace

The fundamental shift: agent workspaces are **git worktrees** of the
user's repo, not independent clones in a scratch directory.

Currently, `devaipod run ~/src/myrepo` creates a fresh clone inside
`~/.local/share/devaipod/workspaces/<pod-id>/myrepo/` using
`--shared` alternates. This works but creates a parallel universe:
the agent's repo is a separate clone with its own refs, and the user
needs `devaipod fetch` to bridge the gap.

With worktrees, the agent works directly on a branch of the user's
repo:

```bash
devaipod run ~/src/myrepo "fix the auth bug"

# Under the hood:
git -C ~/src/myrepo worktree add \
    ~/.local/share/devaipod/workspaces/fix-auth-abc123 \
    -b devaipod/fix-auth-abc123
```

Consequences:
- `git branch --list 'devaipod/*'` shows all agent branches in
  the user's repo. No fetch needed.
- `git log devaipod/fix-auth` and `git diff main...devaipod/fix-auth`
  work immediately from the user's repo.
- `git merge devaipod/fix-auth` or `git cherry-pick` to accept work.
- `git worktree remove` + `git branch -d` for cleanup.
- The agent state directory is a git worktree, not an opaque scratch
  dir. If the state metadata is lost, the branch and commits survive.

The `devaipod/` branch namespace provides clear provenance. `git
branch --list 'devaipod/*'` is the ground truth for "what have agents
been working on in this repo" -- no sidecar database needed.

**Agent state is ephemeral, git state is durable.** The workspace
state file (task description, session history, agent model) is
useful but not critical. If it's lost, you still have the branch
with all the commits and can pick up from there. This inverts the
current model where losing the workspace directory means losing
everything.

**Git notes for summaries.** Compact per-commit summaries ("47 tool
calls, fixed auth middleware, model: Opus 4.6") can be stored as
git notes. Notes are local-only by default (`git push` ignores
`refs/notes/*` unless explicitly configured), so they won't leak
into upstream repos. The control plane UI can display them as
context alongside the branch view.

**What about `devaipod fetch`?** For local repos, it becomes
unnecessary -- the branch is already there. For remote-only repos
(launched from a URL without a local clone), the current fetch
behavior is still needed. `devaipod fetch` can detect which case
applies: if the workspace is a worktree of a local repo, it's a
no-op; if it's a standalone clone, it adds a remote and fetches.

**What about multiple agents on the same repo?** Each gets its own
worktree on its own branch: `devaipod/fix-auth-abc123`,
`devaipod/add-metrics-def456`. Git worktrees handle this natively --
they share objects but have independent working trees and indexes.

**Container bind-mount changes.** The worktree directory is bind-
mounted RW at `/workspaces/` inside the container (same as today).
The main repo is still bind-mounted RO at `/mnt/source/`. The
difference is that the worktree's `.git` file points back to the
main repo's `.git/worktrees/<name>/`, so `git` commands inside the
container work correctly with the shared object store.

### The control plane UI

The UI reads from two sources:
1. **Podman**: running pods, their labels (`io.devaipod.repo`, etc.)
2. **Git**: `devaipod/*` branches in each known repo, worktree status

The repo-grouped layout:

```
┌─ Control Plane ─────────────────────────────────────────┐
│                                                          │
│  [+ New Agent]  [Search...]                              │
│                                                          │
│  ▼ cgwalters/devaipod                            3 agents│
│  ┌──────────────────────────────────────────────────┐    │
│  │ ● devaipod/fix-auth       Running  2m ago   [→]  │    │
│  │ ● devaipod/add-metrics    Running  5m ago   [→]  │    │
│  │ ◉ devaipod/refactor-pod   Done  +3 commits  [diff]│   │
│  │ ▸ devcontainer            Running            ssh  │   │
│  └──────────────────────────────────────────────────┘    │
│                                                          │
│  ▼ journal                                       1 agent │
│  ┌──────────────────────────────────────────────────┐    │
│  │ ● devaipod/wasm-research  Running  3m ago   [→]  │    │
│  └──────────────────────────────────────────────────┘    │
│                                                          │
│  ▸ Inactive repos (2)                                    │
│                                                          │
└──────────────────────────────────────────────────────────┘
```

Each agent row shows the **branch name** (not the task description),
because the branch is the durable identifier. The task description
is secondary (tooltip or detail view). Clicking [→] opens the agent
UI; clicking [diff] shows the three-dot diff.

Done agents with no running pod show their commit count on the
branch. The user can review the diff, merge, and clean up the
branch -- all from the control plane.

### MCP upcall: agent-initiated worktree creation

Worktree creation should be an **upcall from agent to control
plane**, not a top-down decision at pod creation time. The agent
knows what branch name makes sense, when to create additional
worktrees (for subagents), when to switch — the control plane
shouldn't guess.

The flow:

```
Agent (in container)
  │
  │  MCP tool call: worktree_create(branch: "fix-auth")
  ▼
Pod-API sidecar (localhost:3001 in pod)
  │
  │  POST /api/devaipod/pods/{pod}/worktree (with per-pod token)
  ▼
Control plane (devaipod container)
  │
  │  git worktree add ... -b devaipod/fix-auth
  │  (on host filesystem via bind mount)
  ▼
Worktree appears at /workspaces/fix-auth/ in agent container
  (already bind-mounted)
```

**Auth model.** Each agent pod gets a per-pod token at creation
time (a random secret injected as an env var). The control plane
maps token → pod identity and restricts operations to that pod's
worktrees. This is distinct from the advisor's `mcp_token` (which
grants broader privileges like `list_pods`, `propose_agent`).

**Pod-api as intermediary.** The agent talks to pod-api on
localhost (already the pattern for file access, terminal, git).
Pod-api forwards worktree requests to the control plane, adding
the per-pod token. The agent never talks directly to the control
plane — it doesn't know the control plane URL or token.

**MCP tools exposed to agents:**

| Tool | Description |
|---|---|
| `worktree_create` | Create a worktree on `devaipod/<branch>` |
| `worktree_list` | List agent's worktrees with status |
| `worktree_delete` | Remove a worktree (but keep branch) |
| `worktree_status` | Commit count, dirty state, ahead/behind |

These are implemented in pod-api (the sidecar), which calls up to
the control plane for the actual `git worktree add` since it needs
host filesystem access.

**Host filesystem constraint.** The control plane container has
the workspaces directory bind-mounted, but `git worktree add`
needs access to the **user's source repo** (the worktree's parent).
Solutions:

1. **Mount source repos into the control plane.** The control plane
   already knows the host paths (from workspace state files). Add
   them as bind mounts at control plane start, or lazily.
2. **Host-side helper.** `devaipod internals worktree-create` runs
   on the host (via `podman exec` into the control plane, which
   then execs back out — ugly).
3. **Pre-create at launch time.** When `devaipod run` is invoked
   from the host (CLI), the host process creates the worktree
   before the pod starts. The MCP upcall is for *additional*
   worktrees during the agent's lifecycle. This is probably the
   pragmatic first step.

Option 3 is the right starting point: the initial worktree is
created by the CLI (which runs on the host and has full filesystem
access). The MCP upcall is a follow-up for agent-initiated
worktrees (subagent spawning, multi-branch work).

### Implementation order

1. **Initial worktree at launch**: Change `devaipod run` (local
   repo, host CLI) to use `git worktree add` instead of
   `git clone --shared`. Branch name `devaipod/<slug>`. This
   requires no container changes — the CLI runs on the host.
2. **Per-pod token**: Generate and inject a per-pod secret at pod
   creation. Store in workspace state for the control plane to
   verify.
3. **Pod-api worktree endpoints**: Add `/worktree/create`,
   `/worktree/list`, `/worktree/status` to pod-api. Forward to
   control plane with per-pod auth.
4. **Control plane MCP for worktrees**: Extend `src/mcp.rs` (or a
   new per-pod MCP handler) with worktree tools. Requires source
   repo access — initially via pre-mounted paths.
5. **Backend**: Add repo-grouped endpoint that reads from podman +
   `git branch --list 'devaipod/*'` on known repos.
6. **Frontend**: Replace flat pod list with repo-grouped layout.
7. **Journal config**: Add `[journal]` section to config.
8. **Git notes**: Optional per-commit summaries.
9. **Cleanup CLI**: `devaipod clean` for merged branches + stale
   worktrees.
