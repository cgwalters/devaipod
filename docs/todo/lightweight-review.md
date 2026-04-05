# Lightweight Agent Change Review

**Depends on**: [workspace-v2.md](./workspace-v2.md) (workspace infrastructure
must be in place first; this doc builds on it to add review, push, and
credential flows).

**Note**: workspace-v2 replaces podman volumes with host-side directories.
The dual-workspace trust model described below (main workspace + agent
workspace on separate volumes) will need to be reworked: in the new model,
the agent's working tree is a host directory bind-mounted into the
container, and the human's source repo is bind-mounted read-only alongside
it. Pod-api operates on the same host filesystem rather than on
cross-mounted volumes. The security properties (agent can't write to the
human's repo, pod-api owns push with GH_TOKEN) are preserved, but the
mechanics change.

Right now the agent is sandboxed by default with read-only
credentials - getting changes out of its git repository
is a bit painful, and reviewing in the opencode UI is
also suboptimal (no true native git UI there, though
opencode has a hacky "changes" that we disable).

We want to increase security *and* convenience.

The workflow should support a full spectrum of operations:

- Autonomous (headless) pod that can run all the way to
  e.g. creating a draft PR that a human reviews there,
  and can act on any comments.
- Interactive pod started with task but that's fully read-only by default but
  can request review. The human can easily see the git
  diffs, comment on changes. The human can approve
  draft PR creation etc.
- Fully interactive: A devcontainer with an idle agent
  by default. The human may attach an IDE (connecting over
  SSH) or perform some initial edits directly. They
  can then have the agent take over.

🤖 Assisted-by: OpenCode (claude-opus-4-6)

The following text is LLM generated with human review.

---

## Responsibility Split: Pod-api vs Service-gator

**Pod-api owns all git operations. Service-gator owns only the
GitHub/forge API.** Previously `git_push_local` lived in
service-gator, requiring duplicated git credential plumbing.
Moving all git operations to pod-api simplifies the auth story:
pod-api already has both workspace volumes mounted and receives
GH_TOKEN for push.

**Pod-api** (has GH_TOKEN, has both workspaces mounted):
- Read agent commits (hardened against `.git/config` RCE)
- Fetch agent commits into the trusted main workspace
- Create/update branches, push to origin
- MCP tools so the agent can request branch operations

**Service-gator** (GitHub API only):
- Create draft PRs, update PR descriptions, add labels/reviewers
- No git operations, no `git push`, no local repo access

## Core Mechanism: Fetching Agent Commits

The fetch operation -- pulling agent commits from the agent workspace
into the trusted main workspace -- is the shared primitive across all
scenarios. Three things can trigger it:

- **Agent requests it**: calls pod-api MCP tool `create_or_update_branch`,
  which fetches then pushes the branch to origin.
- **Human clicks Fetch**: in the review UI, pulls latest agent commits
  for review before deciding whether to approve a push.
- **Auto-fetch**: `GitWatcher` detects ref changes via inotify and
  fetches automatically in the background.

All three run the same `git fetch` under the hood. What differs is
what happens *after* the fetch: the agent may push and create a PR
autonomously, or the human may review and approve manually.

## Scenarios

These map to the three modes described in the introduction.

### Autonomous headless pod (draft PR flow)

The agent runs a task end-to-end and produces a draft PR for
human review on GitHub. No devaipod UI needed during execution.

1. Agent makes commits in its workspace.
2. Agent calls pod-api MCP: `create_or_update_branch("fix-xyz")`.
   Pod-api fetches agent commits into main workspace, pushes branch.
3. Agent calls service-gator: `create_draft_pr("fix-xyz", "Fix xyz")`.
4. Agent can iterate: push more commits to the branch, update the
   PR description, respond to review comments -- all autonomously.
5. Human reviews on GitHub when ready, converts draft to ready.

### Interactive pod with review gate

The agent works on a task while the human monitors in the
devaipod UI. The agent cannot push without human approval.

1. Agent makes commits in its workspace.
2. Auto-fetch pulls commits into main workspace (or the human
   clicks Fetch in the UI).
3. Browser receives SSE `git.updated` event, refreshes commit log.
4. Human reviews diffs in the Changes tab. Must expand and view
   every changed file before the push button enables.
5. Human can leave inline comments (routed back to agent).
6. Human clicks **Approve & Push** (optionally with Signed-off-by).
7. Pod-api pushes from the main workspace.

This enforces a mini-GitHub-PR process: you cannot approve without
actually looking at the changed files.

### Fully interactive with IDE

The human works directly in the workspace (via SSH/IDE), possibly
making initial edits, then hands off to the agent. The same review
flow applies when the agent produces commits -- the human sees them
in the Changes tab and can approve or comment. The human's own
commits (made via IDE) are already in the main workspace and don't
need the review gate.

## Architecture

```
┌─ Browser ────────────────────────────────────────────────────────┐
│  OpenCode web UI (served by pod-api in iframe)                   │
│  Changes tab → GitReviewTab component                            │
│  • Commit log with base-commit selector                          │
│  • Per-file diffs (unified or split view)                        │
│  • Inline commenting (routes back to agent)                      │
│  • Viewed-files tracking (N/M viewed)                            │
│  • Fetch button, Approve & Push button, Signed-off-by checkbox   │
└──────────────┬───────────────────────────────────────────────────┘
               │ HTTP (relative URLs, same origin)
               ▼
┌─ Pod-api sidecar (root, DAC_OVERRIDE, our image) ───────────────┐
│                                                                  │
│  Agent workspace at /workspaces/{project} (RW)                   │
│    → git_cmd() hardened: hooks, fsmonitor, cred helpers disabled  │
│    → GET /git/log, /git/diff-range, /git/status, /git/events    │
│                                                                  │
│  Main workspace at /mnt/main-workspace/{project} (RW)            │
│    → git_cmd_trusted(): only safe.directory override             │
│    → POST /git/fetch-agent, /git/push, /git/create-branch       │
│    → Auto-fetch on GitWatcher ref change events                  │
│                                                                  │
│  MCP tools for agent:                                            │
│    → create_or_update_branch(name) — fetch + push branch         │
│                                                                  │
│  Has GH_TOKEN for push operations                                │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘

┌─ Service-gator (separate container, GitHub API only) ───────────┐
│  create_draft_pr, update_pr, add_labels, add_reviewers           │
│  No git binary, no local repo access, no git push                │
└──────────────────────────────────────────────────────────────────┘
```

### Dual-workspace trust model

Push operates on the **main workspace** (`/mnt/main-workspace/`),
not the agent workspace. The main workspace:

- Has push credentials (GH_TOKEN via trusted secrets)
- Has `.git/config` controlled by our clone scripts (agent can't write)
- Receives agent commits via auto-fetch on ref changes

Pod-api needs `DAC_OVERRIDE` to write to the main workspace git
directory (owned by UID 1000) while running as root with all other
capabilities dropped.

### Where the review panel lives in the UI

The Changes tab appears in the session side panel. On desktop:

- **File tree closed**: dedicated "review" tab in the side panel.
- **File tree open**: review content under the file tree's "changes" tab.

Both render the same `GitReviewTab` component.

## Security

### Hardened path (agent workspace reads)

The agent controls its workspace's `.git/config` and could craft
entries to achieve code execution as root. `git_cmd()` neutralizes
this via environment-based config overrides (which take precedence
over `.git/config`):

- `core.fsmonitor=false` -- prevents RCE via `git status`/`git diff`
- `core.hooksPath=/dev/null` -- disables all git hooks
- `credential.helper=""` -- prevents credential helper RCE
- `protocol.ext.allow=never` -- blocks `ext::` transport commands
- `protocol.file.allow=never` -- blocks local path traversal
- `diff.external=""` -- prevents external diff program execution
- `GIT_TERMINAL_PROMPT=0` -- prevents interactive prompts

Long-term, read-only operations should migrate to
[gix](https://github.com/GitoxideLabs/gitoxide) (pure-Rust) to
eliminate config-based execution risk by construction.

### Trusted path (main workspace)

The main workspace `.git/config` is set up by our clone scripts;
the agent has no write access. Only `safe.directory=*` is needed.

### Why `git fetch` from the agent workspace is safe

Git is content-addressed. When pod-api fetches from the agent
workspace via the local filesystem path, git verifies every object
matches its SHA hash. The local transport reads objects directly
without processing the source repo's `.git/config` or hooks.

### Credential isolation

- Agent container: no GH_TOKEN, no push credentials, no git auth
- Pod-api: has GH_TOKEN, owns all git push operations
- Service-gator: has GH_TOKEN for GitHub API only, no git operations

## Current State

The `GitReviewTab` component exists and provides read-only review:
commit log, per-file diffs, SSE auto-refresh. All read endpoints
work via `run_git()` against the agent workspace (note: `run_git()`
currently only applies `safe.directory=*`, not the full hardening
described in the Security section above — that remains to be done).

**Working today:**

- `POST /git/fetch-agent` fetches agent commits in pod-api.
- `POST /git/push` pushes a branch to origin from pod-api.
- CLI commands: `devaipod push`, `devaipod pr`, `devaipod apply`,
  `devaipod fetch`, `devaipod diff`, `devaipod review` (TUI).
- `devaipod status` (no-arg) shows repo-level overview of agent
  workspaces, branches, and PRs.
- Control plane harvest: `POST /api/devaipod/pods/{name}/fetch`
  fetches agent commits into the user's source repo. Auto-harvest
  triggers on agent completion for local-source workspaces.
- `git_push_local` removed from service-gator.

**Not yet implemented:**

- Full git hook hardening on the pod-api read path (fsmonitor,
  hooksPath, credential.helper — see Security section).
- `POST /git/create-branch` (fetch + push as new branch).
- Push approval gate in the web UI (buttons, viewed-files tracking).
- Signed-off-by checkbox in web UI.
- MCP tool `create_or_update_branch` for agent-initiated push.

## API Endpoints

All served by pod-api (port 8090).

### Read (agent workspace, hardened)

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/git/log` | GET | Commit log with `base`/`head` range params |
| `/git/diff-range` | GET | Per-file diffs with before/after content |
| `/git/status` | GET | Porcelain status + current branch name |
| `/git/events` | GET | SSE stream of ref changes (debounced 200ms) |

### Write (main workspace, trusted)

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/git/fetch-agent` | POST | Fetch agent commits into main workspace |
| `/git/push` | POST | Push branch to origin |
| `/git/create-branch` | POST | Fetch agent commits + push as branch |

### MCP tools (exposed to agent)

| Tool | Description |
|------|-------------|
| `create_or_update_branch` | Fetch + push branch. Agent calls this, then service-gator to create a draft PR. |

## Implementation Plan

### Pod-api / pod.rs

1. `git_cmd()` hardening for agent workspace reads.
2. `git_cmd_trusted()` for main workspace operations.
3. `--main-workspace` CLI arg and `AppState` field.
4. Fix `POST /git/fetch-agent` to use main workspace.
5. Fix `POST /git/push` to use main workspace.
6. Add `POST /git/create-branch` (fetch + push branch).
7. Add `branch` field to `GET /git/status`.
8. Auto-fetch in `GitWatcher` on ref changes.
9. Mount main workspace `:rw`, add `DAC_OVERRIDE`.
10. Pass GH_TOKEN to pod-api.
11. MCP tool `create_or_update_branch`.

### Service-gator

1. Remove `git_push_local`.
2. Keep GitHub API tools (`create_draft_pr`, etc.).

### Frontend (git-review-tab.tsx)

1. Fetch button with toast feedback.
2. Viewed-files tracking via accordion open/change.
3. "Approve & Push" gated on all-files-viewed.
4. Signed-off-by checkbox.
5. `data-component`/`data-action` test attributes.

### Integration tests

1. Agent commits appear in `/git/log`.
2. `/git/diff-range` returns correct diffs.
3. `POST /git/fetch-agent` fetches into main workspace.
4. `POST /git/create-branch` pushes branch to origin.

## Future Work

- Signoff backend: `POST /git/push` accepts `signoff: bool`.
- Merge step: fetch + merge before push.
- Server-side review enforcement (currently client-side only).
- Workspace agent: move push ops to a daemon in the workspace
  container to avoid UID/gitconfig issues long-term.

## References

- [integration-web.md](./integration-web.md) -- web UI integration testing plan
- [forgejo-integration.md](./forgejo-integration.md) -- full Forgejo spec (deferred)
- [opencode-webui-fork.md](./opencode-webui-fork.md) -- vendored opencode SPA architecture
