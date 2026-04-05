# Workspace v2: From Volumes to Host Directories

Assisted-by: OpenCode (Claude Opus 4.6)

## Problem Statement

The previous sandbox model created up to 5 named volumes per pod. Code
lived inside opaque podman volumes — invisible from the host, requiring
special transport to move data in or out. This was unnecessary complexity.

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
- **Agent workspace is always a host directory**, regardless of source
  type (local repo, remote URL, or PR). The `{pod}-agent-workspace`
  volume is no longer created for agent pods. This unifies diff, fetch,
  review, and direct editing across all source types.
- Source repo bind-mounted RO at `/mnt/source/<dirname>/`
- `--source-dir` CLI flag: mounts additional read-only directories at
  `/mnt/source/<dirname>/` with automatic git clone into agent workspace
  for convenience
- Agent, pod-api, and gator container configs updated for bind mounts
- `devaipod delete` removes the agent directory
- Justfile `container-run` updated with workspaces bind mount
- Init container name sanitization for host-path volume sources
- **Multi-repo workspace support**: `find_git_repos_in_dir()` discovers
  all git repos in a workspace (shared in `agent_dir.rs`). The
  `GET /api/devaipod/pods/{name}/diffs` endpoint returns diffs for all
  repos. `devaipod fetch` fetches all repos with per-repo remote naming
  (`devaipod/<workspace>/<repo>`).
- **Harvest**: `POST /api/devaipod/pods/{name}/fetch` fetches agent
  commits into the user's source repo as `devaipod/<workspace>/*`
  branches. Auto-harvest triggers on agent completion for local-source
  workspaces. `WorkspaceState.last_harvested` tracks per-repo HEAD SHAs
  to skip redundant fetches.
- **Review TUI**: `devaipod review` provides interactive diff viewing
  with inline commenting; review comments are sent back to the agent.

### Remaining

- UID mapping: see [rootless-uidmapping.md](./rootless-uidmapping.md)
- UI/model rework: workspace-anchored design (see Phase 2 below)
- `devaipod clean` garbage-collects orphaned agent dirs
- Web UI push approval gate (CLI `devaipod push` and `devaipod pr`
  work; web UI needs buttons, viewed-files tracking, and
  Signed-off-by — see [lightweight-review.md](./lightweight-review.md))
- Web UI review component (REST API is ready, frontend needs inline
  commenting UI)

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

### Why not git worktrees

Git worktrees were considered but rejected for agent workspaces.
The fundamental problem: worktrees require write access to the
parent repo's `.git` directory (for the shared object store,
worktree metadata, and HEAD/index). Since agents produce untrusted
output that must be reviewed before acceptance, giving them write
access to the user's source repo violates the security model.

The clone-based approach is correct: agents get an isolated clone,
produce commits on a `devaipod/<slug>` branch, and the human
explicitly fetches and reviews before merging. The security
boundary is clean — the agent never writes to the user's repo.

### Branch naming convention (implemented)

Instead of worktrees, agent clones use a `devaipod/<slug>` branch
naming convention. The flow:

```bash
devaipod run ~/src/myrepo "fix the auth bug"
# Agent clone checks out branch: devaipod/fix-auth-abc123

devaipod fetch          # Adds remote, fetches agent branches
devaipod diff           # Shows three-dot diff of agent changes

# Human reviews, then:
git cherry-pick devaipod/myworkspace/devaipod/fix-auth-abc123
```

After `devaipod fetch`, the agent's branches are visible under
`devaipod/<remote-name>/devaipod/<slug>`. The `devaipod/` namespace
in the branch name provides clear provenance regardless of which
remote or clone context you're viewing it from.

**Git notes for summaries.** Compact per-commit summaries ("47 tool
calls, fixed auth middleware, model: Opus 4.6") can be stored as
git notes. Notes are local-only by default (`git push` ignores
`refs/notes/*` unless explicitly configured), so they won't leak
into upstream repos. The control plane UI can display them as
context alongside the branch view.

### The control plane UI (implemented)

The UI groups pods by `io.devaipod.repo` label via
`GET /api/devaipod/control-plane`. Each repo is a collapsible
section with agent rows (status dot, title, time) and devcontainer
rows. Active repos are expanded by default; inactive repos collapse
into a summary.

### Future: MCP upcall for agent-initiated git operations

Per-pod tokens and MCP tooling for agents to request git operations
(branch creation, status queries) from the control plane is a
natural next step. The agent would call through pod-api (localhost),
which forwards to the control plane with per-pod auth. This is
independent of the worktree question — it works with the clone-based
model too. See `docs/todo/advisor-v2.md` for the MCP architecture.

### Remaining implementation

1. **Journal config**: Add `[journal]` section to `devaipod.toml`.
   Default `devaipod run` (no source) to use journal repo.
2. **Git notes**: Optional per-commit summaries via git notes.
3. **Per-pod token**: Generate and inject a per-pod secret at pod
   creation for MCP auth.
4. **Cleanup CLI**: `devaipod clean` removes stale workspaces and
   their clone directories.
