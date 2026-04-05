# Advisor Agent

An "advisor" agent is a long-running, read-only agent that observes the current
state of running pods and external services, then suggests actions for the human
to approve. Unlike regular agent pods that perform work directly, the advisor
operates as a meta-layer: it watches, analyzes, and proposes — but never acts
without explicit human approval.

## Implementation Status

**Implemented:**

- Advisor module (`src/advisor.rs`) with data types, storage layer, pod
  introspection, and workspace introspection functions
- MCP server (`src/mcp.rs`) exposing advisor tools via Streamable HTTP
  (JSON-RPC over HTTP POST) at `/api/devaipod/mcp` on the control plane
- `DraftStore` with load/save/add/list/update_status operations, persisted as
  JSON at `/var/lib/devaipod-drafts.json` inside the advisor pod
- Pod introspection via podman CLI: `list_pods()`, `pod_status()`, `pod_logs()`
- Workspace introspection via direct filesystem access: `list_workspace_summaries()`,
  `workspace_diff()` — shows all workspaces with git branch/commit info
- `DraftProposal` struct with priority, status lifecycle
  (pending/approved/dismissed/expired), and source tracking
- Generic `--mcp name=url` CLI flag on `up` and `run` commands, with
  corresponding `[mcp]` config section in `devaipod.toml`
- `McpServersConfig` with merge semantics (CLI overrides config file)
- Container image (`ghcr.io/cgwalters/devaipod:latest`) includes the opencode
  CLI binary so it can serve as the agent container for advisor pods
- `devaipod advisor` CLI subcommand: checks for `devaipod-advisor` pod,
  creates it if missing (using the devaipod repo as workspace source and
  our own image), attaches if running. Supports `--status`, `--proposals`,
  and `--source-dir` flags. Uses `cmd_run()` under the hood with the
  devaipod MCP server attached via Bearer auth.
- Separate MCP token auth (distinct from web API token) to isolate
  advisor access from general API access
- Default system prompt that instructs the advisor to survey review
  requests (via service-gator), workspaces, and pods, then propose agents

**Not yet implemented:**

- Proposal approval UI (CLI prompts or web integration)
- Launching agent pods from approved proposals
- Patrol cycle (periodic re-survey without human prompting)

## Motivation

Today, using devaipod is human-initiated: you decide what task to run, which repo
to target, and when to start. As the ecosystem matures and users manage more
concurrent agents, there's value in an agent that proactively identifies useful
work. The advisor bridges the gap between "I need to think of what to do" and
"here are agents ready to go."

Key scenarios:

- **Issue triage**: "Look at my assigned GitHub issues, analyze them, and propose
  agents to work on the most actionable ones."
- **Pod health**: "A worker pod has been stuck for 20 minutes — suggest
  restarting it or reassigning the task."
- **Cross-repo awareness**: "A dependency just released a new version — propose
  an agent to update and test it."

## Architecture

The advisor runs as a devaipod pod using devaipod's own container image.
It connects to two MCP servers:

1. **devaipod MCP** (on the control plane at `http://host.containers.internal:8080/api/devaipod/mcp`)
   — provides pod/workspace introspection and proposal management tools.
   Authenticated via a separate Bearer token (distinct from the web API token).

2. **service-gator** (in-pod at `:8765`, read-only) — provides GitHub/GitLab
   API access for discovering PRs, issues, notifications, etc.

The MCP server runs on the control plane (not inside the advisor pod) because
it needs direct access to the podman socket and host-side workspace directories.
This keeps the advisor pod truly sandboxed while giving it read-only visibility
through the MCP protocol.

```
┌──────────────────────────────────┐     ┌──────────────────────────────┐
│  Advisor Pod                      │     │  Control Plane (:8080)       │
│                                   │     │                              │
│  ┌─────────────────────────┐     │     │  POST /api/devaipod/mcp      │
│  │ opencode Agent           │─MCP─┼────▶│  • list_pods (read-only)     │
│  │ • Surveys GitHub (gator) │     │     │  • pod_status / pod_logs     │
│  │ • Inspects workspaces    │     │     │  • list_workspaces           │
│  │ • Proposes agents        │     │     │  • workspace_diff            │
│  │ • NO direct actions      │     │     │  • propose_agent             │
│  └────────┬────────────────┘     │     │  • list_proposals            │
│           │                       │     └──────────────────────────────┘
│  ┌────────┴────────────────┐     │
│  │ Service-gator (:8765 RO) │     │
│  │ • GitHub PRs, issues     │     │
│  │ • Notifications          │     │
│  └─────────────────────────┘     │
│                                   │
│  /mnt/source/ (read-only)         │  ← optional --source-dir mounts
└──────────────────────────────────┘
         │
         │ Draft proposals (via MCP)
         ▼
┌──────────────────────────────────────────────────────────────────────┐
│  Human (CLI / TUI / Web)                                             │
│                                                                      │
│  $ devaipod advisor --proposals                                      │
│  "The advisor suggests 3 agents:"                                    │
│  1. Fix flaky test in myorg/backend (#142) — [approve] [dismiss]     │
│  2. Investigate OOM in worker pod — [approve] [dismiss]              │
│  3. Bump serde to 1.0.220 across 3 repos — [approve] [dismiss]      │
│                                                                      │
│  On approve → devaipod launches the agent pod                        │
└──────────────────────────────────────────────────────────────────────┘
```

## MCP Tools

The devaipod MCP server (at `/api/devaipod/mcp` on the control plane)
exposes tools for pod/workspace introspection and proposal management.
GitHub/issue access is handled separately by service-gator.

### Introspection tools

These give the advisor visibility into the running devaipod environment.
Pod introspection functions in `src/advisor.rs` shell out to podman CLI;
workspace introspection reads host-side directories directly.

| Tool | Description | Implementation |
|------|-------------|----------------|
| `list_pods` | List all devaipod pods with status, task, and age | `list_pods()` — `podman pod ps` |
| `pod_status` | Detailed status for a specific pod | `pod_status()` — `podman pod inspect` |
| `pod_logs` | Read recent logs from a pod's agent container | `pod_logs()` — `podman logs --tail N` |
| `list_workspaces` | All workspaces with git branches, commits ahead, completion status | `list_workspace_summaries()` — direct filesystem |
| `workspace_diff` | Git diff for a workspace vs upstream | `workspace_diff()` — direct filesystem |
| `list_proposals` | List existing draft proposals and their status | `DraftStore::list()` with optional status filter |

These are strictly read-only. The advisor cannot stop, restart, or modify
pods — only observe them.

### Proposal tool (implemented)

The core capability that makes the advisor useful. The `DraftProposal` struct
captures:

```rust
pub struct DraftProposal {
    pub id: String,                    // Hex-encoded timestamp, auto-generated
    pub title: String,                 // Human-readable summary
    pub repo: String,                  // Target repository (e.g. "myorg/backend")
    pub task: String,                  // Task description for the agent
    pub rationale: String,             // Why the advisor thinks this is worth doing
    pub priority: Priority,            // High | Medium | Low
    pub source: Option<String>,        // What triggered this (e.g. "github:myorg/backend#142")
    pub estimated_scope: Option<String>, // "small" | "medium" | "large"
    pub status: ProposalStatus,        // Pending | Approved | Dismissed | Expired
    pub created_at: String,            // RFC 3339 timestamp
}
```

### Draft storage

Proposals are persisted to `/var/lib/devaipod-drafts.json` inside the advisor
pod. The `DraftStore` provides:

- `load(path)` — loads from JSON, returns empty store if file doesn't exist
- `save(path)` — serializes to pretty JSON, creates parent dirs if needed
- `add(proposal)` — adds a proposal with an auto-generated hex ID
- `list(status)` — lists all proposals or filters by status
- `update_status(id, status)` — transitions a proposal's lifecycle state

The proposal is completely inert — no pod is created, no code is touched —
until a human explicitly approves it. On approval, devaipod translates the
proposal into a `devaipod run` invocation.

## CLI Command (implemented)

`devaipod advisor` manages the advisor pod lifecycle:

```
$ devaipod advisor                     # Check for devaipod-advisor pod; create if needed, attach if running
$ devaipod advisor --status            # Show advisor pod status
$ devaipod advisor --proposals         # List current draft proposals
$ devaipod advisor "Look at issues"    # Create advisor pod with initial task
```

The subcommand checks for a pod named `devaipod-advisor`. If not found, it
creates one using devaipod's own container image. If already running, it
attaches to the existing pod.

## Example Workflow

### "What should I work on today?"

```
$ devaipod advisor "Look at my recent GitHub issues and suggest agents to tackle them"
```

The advisor:

1. Uses service-gator (read-only) to call GitHub's API: issues assigned to the
   user, sorted by recent activity
2. Filters to actionable items (has enough context, not blocked, reasonable scope)
3. For each candidate, analyzes the issue body, linked PRs, and repo state
4. Creates 3-5 draft proposals ranked by priority and estimated effort

The human sees:

```
Advisor analysis complete. 4 proposals:

1. [high] Fix race condition in connection pool (myorg/backend#287)
   Rationale: Reported by 3 users this week, has reproduction steps,
   isolated to src/pool.rs. Estimated: small.
   [a]pprove  [d]ismiss  [v]iew details

2. [high] Add retry logic for webhook delivery (myorg/api#94)
   Rationale: Blocking production rollout per comment from @teammate.
   Estimated: medium.
   [a]pprove  [d]ismiss  [v]iew details

3. [medium] Update CI to use Rust 1.84 (myorg/backend#301)
   Rationale: Routine maintenance, straightforward Dockerfile change.
   Estimated: small.
   [a]pprove  [d]ismiss  [v]iew details

4. [low] Refactor error types to use thiserror (myorg/cli#58)
   Rationale: Good cleanup, but no urgency. 12 files affected.
   Estimated: medium.
   [a]pprove  [d]ismiss  [v]iew details
```

Approving proposal #1 runs:

```
devaipod run https://github.com/myorg/backend \
  'Fix race condition in connection pool (#287). See issue for repro steps.'
```

### "Check on my running agents"

```
$ devaipod advisor "How are my running agents doing? Any that look stuck?"
```

The advisor:

1. Lists all running pods via `list_pods`
2. Checks each pod's status, git state, and recent logs
3. Identifies problems (idle too long, error loops, no commits in a while)
4. Suggests remediation (restart, provide feedback, or kill and retry)

## Integration with Existing Components

### Service-gator

The advisor reuses the existing service-gator for GitHub/JIRA access. The
advisor pod's service-gator configuration should be read-only (the default).
No additional scopes are needed beyond what a typical read-only setup provides.

### Generic MCP attachment

The advisor uses the same generic MCP mechanism available to any pod. The
`--mcp name=url` flag and `[mcp]` config section in `devaipod.toml` generalize
the service-gator pattern so that arbitrary MCP servers can be attached to any
agent. Configuration from the CLI overrides config file entries with the same
name.

### Control plane

Proposal storage lives inside the advisor pod at `/var/lib/devaipod-drafts.json`
(the `DraftStore`). The approval UI could integrate with the opencode web UI
(see [opencode-webui-fork.md](./opencode-webui-fork.md)), or start
as plain CLI prompts via `devaipod advisor --proposals`.

### Worker orchestration

The advisor complements the worker orchestration API (see
[worker-orchestration-api.md](./worker-orchestration-api.md)). Where workers
handle subtask delegation within a pod, the advisor handles top-level task
selection across the user's entire workload.

## Security Considerations

The advisor follows devaipod's existing security model:

- **Read-only by default**: The advisor cannot modify repositories, close
  issues, or push code. It only reads.
- **Proposals are inert**: Creating a proposal has no side effects. The human
  must explicitly approve before any pod is launched.
- **No credential escalation**: The advisor's service-gator config is
  independent of the launched agents' configs. Approving a proposal that
  targets a repo with write access requires the human to have already configured
  that access.
- **Scoped observation**: The `list_pods` / `pod_status` tools only expose
  devaipod-managed pods, not arbitrary containers on the host.

## Open Questions

1. **Persistent vs. one-shot**: Should the advisor run continuously (watching
   for new issues, pod state changes) or only on-demand? Continuous mode is
   more useful but costs LLM tokens.

2. **Proposal expiry**: Should draft proposals expire after some time if not
   acted on? The `ProposalStatus::Expired` variant exists but there's no
   automatic expiration logic yet.

3. **Learning from approvals**: Could the advisor learn from which proposals
   the human tends to approve/dismiss to improve future suggestions?

4. **Multiple advisors**: Could different advisor agents specialize in different
   areas (one for issue triage, one for infrastructure monitoring)?

5. ~~**Advisor as MCP server itself**~~: **Resolved** — the advisor *is* an MCP
   server (port 8766), attached via the generic `--mcp` mechanism. Any pod or
   editor can connect to it.
