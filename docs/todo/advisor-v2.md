# Advisor v2: Source-aware orchestrator

Assisted-by: OpenCode (Claude Opus 4.6)

## The problem with advisor v1

The current advisor is a pod that happens to have MCP access to the
devaipod control plane. It uses the dotfiles repo as a throwaway
workspace. It has no access to the user's source code and no persistent
state across sessions. It's reactive — you ask it "what should I work
on?" and it queries GitHub issues. It can't see what's actually in your
repos, can't correlate across projects, and forgets everything when
restarted.

The advisor should be the always-on brain that sees your entire source
tree, understands the relationships between projects, monitors external
events, and proactively orchestrates agent pods. Not a side feature —
the central concept.

## Design

### Source tree access

The advisor pod gets read-only bind mounts of the user's source
directories, same as any other pod but broader in scope. Typically
the user points the advisor at their entire source root:

```bash
devaipod advisor --source-dir ~/src
```

This mounts `~/src` at `/mnt/source/src/` (read-only) inside the
advisor pod. The advisor can browse all projects, read code, check
git status, understand dependencies between repos — without being
able to modify anything.

Multiple `--source-dir` flags work, same as regular pods. The advisor's
source dirs are persisted in its workspace state file so they survive
restarts.

### Always-on operation

The advisor runs as a long-lived pod with a persistent workspace
directory. Unlike worker pods that are spawned for a task and die,
the advisor:

- Starts on `devaipod advisor` (or auto-starts with the control plane)
- Runs a periodic **patrol cycle** (configurable interval, default
  ~15 minutes)
- Each cycle: check pod health, poll external events, scan source
  tree for changes, generate/update proposals
- Sleeps between cycles to conserve tokens
- Survives restarts via workspace state + conversation history

The patrol cycle is the core loop. Between cycles the advisor is idle
(no token cost). The cycle interval balances responsiveness against
cost.

### What the advisor sees

The advisor has three "senses":

**1. Source tree** (new in v2): Read-only access to the user's code.
The advisor can grep for patterns, read READMEs, check Cargo.toml
dependencies, look at CI configs, understand project structure. This
is what makes cross-project awareness possible.

**2. Pod state** (existing): Via the devaipod MCP tools (`list_pods`,
`pod_status`, `pod_logs`). The advisor monitors running agents,
detects stuck or failed pods, and tracks completion.

**3. External events** (existing via service-gator): GitHub
notifications, assigned issues, PR reviews requested, CI failures.
The advisor's service-gator is read-only.

### What the advisor does

The advisor's actions are limited to two categories:

**Proposals** (existing, enhanced): The advisor creates draft proposals
for new agent pods. Enhanced with source-tree context — the advisor
can read the actual code before proposing work, leading to better
task descriptions and scope estimates. Proposals require human
approval before any pod is launched.

**Health alerts** (new): When the advisor detects a stuck or failing
agent pod, it creates a health alert visible in the UI. Alerts
suggest remediation: restart, provide feedback, or kill and retry
with a refined task. Alerts are advisory — the human decides.

The advisor explicitly cannot: launch pods, stop pods, push code,
close issues, modify source files, or take any action with side
effects. It observes and recommends.

### Escalation

Agents that hit blockers can escalate to the advisor. This requires
adding an `escalate` MCP tool to the devaipod MCP server. When a
worker agent calls `escalate("stuck on flaky test, can't reproduce
locally")`, the advisor receives the escalation in its next patrol
cycle and can:

- Read the agent's logs and workspace state
- Cross-reference with source code and CI results
- Create a proposal to launch a helper agent, or suggest the human
  intervene
- Respond to the stuck agent with guidance (via a future
  inter-agent messaging tool)

This is inspired by Gastown's escalation routing, but simplified:
there's one advisor, not a hierarchy of supervisors. If the advisor
can't resolve the escalation, it surfaces it to the human.

### Capacity awareness

The advisor tracks how many agent pods are running and avoids
proposing more work than the system can handle. This is a soft
limit, not enforcement — the human can always launch more pods
manually. The advisor just stops generating proposals when it
sees N pods already running.

Configurable via `devaipod.toml`:

```toml
[advisor]
max_concurrent_agents = 5
patrol_interval_minutes = 15
source_dirs = ["~/src"]
```

## Architecture changes

### Current (advisor v1)

```
Advisor Pod                    Control Plane
┌──────────────────┐          ┌──────────────────┐
│ opencode agent   │──MCP──→  │ /api/devaipod/mcp│
│ (dotfiles repo)  │          │ (list_pods, etc.) │
│ service-gator RO │          └──────────────────┘
└──────────────────┘
     │
     └─ No source access, no persistent state,
        reactive only
```

### New (advisor v2)

```
Advisor Pod                       Control Plane
┌─────────────────────────┐      ┌──────────────────────┐
│ opencode agent           │─MCP→│ /api/devaipod/mcp    │
│ /mnt/source/ (RO)        │     │  list_pods            │
│   └── ~/src tree         │     │  pod_status / logs    │
│ /workspaces/ (RW)        │     │  propose_agent        │
│   └── persistent state   │     │  list_proposals       │
│ service-gator (RO)       │     │  receive_escalation ← │ new
└─────────────────────────┘      └──────────────────────┘
     │                                     ↑
     │ proposals + health alerts           │ escalate
     ▼                                     │
┌─────────────┐                  ┌─────────────────────┐
│ Human (UI)  │                  │ Worker Agent Pods    │
│ approve/    │                  │ (MCP: escalate tool) │
│ dismiss     │                  └─────────────────────┘
└─────────────┘
```

### MCP tool additions

Two new tools on the devaipod MCP server:

| Tool | Direction | Description |
|------|-----------|-------------|
| `escalate` | Worker → control plane | Worker reports a blocker. Stored for the advisor's next patrol. |
| `health_alert` | Advisor → control plane | Advisor reports a stuck/failed pod. Displayed in UI alongside proposals. |

Escalations are stored in the same `DraftStore` mechanism as proposals
(or a parallel `EscalationStore`). The advisor reads them via
`list_escalations` during its patrol cycle.

### System prompt changes

The advisor's system prompt needs to reflect its expanded role:

```
You are the devaipod advisor. You have read-only access to the user's
source tree at /mnt/source/. You monitor running agent pods, external
events (via service-gator), and source code changes.

Your job is to:
1. Proactively identify useful work across all projects
2. Monitor running agents and detect stuck/failed pods
3. Create proposals for new agent pods (human approval required)
4. Create health alerts when agents need attention
5. Process escalations from stuck agents

You run periodic patrol cycles. Each cycle:
- Check pod health (list_pods, pod_logs for any errors)
- Check for new escalations (list_escalations)
- Scan source tree for notable changes (new issues, dependency updates)
- Check external events (GitHub notifications via service-gator)
- Generate or update proposals based on findings

Between cycles, wait for the next cycle. Do not take actions with
side effects. Your role is to observe and recommend.
```

## Relationship to workspace-v2

The advisor is the natural orchestrator for workspace-v2. The
workspace-anchored model gives each agent a durable host directory;
the advisor sees all of them. The flow becomes:

1. Human sets up source dirs and launches advisor
2. Advisor scans source tree, monitors events
3. Advisor proposes agent pods with specific tasks
4. Human approves → devaipod creates workspace + pod
5. Agent works in its workspace
6. Agent hits blocker → escalates to advisor
7. Advisor monitors progress, alerts on problems
8. Agent completes → workspace persists for review

The advisor doesn't need to know about workspace internals (state
files, directory layout). It just sees pods via MCP and source via
bind mounts. The workspace-v2 infrastructure makes both possible.

## What this is NOT

This is not a multi-agent hierarchy like Gastown's
Mayor/Deacon/Witness/Refinery/Polecat chain. There is one advisor
and N worker pods. The advisor is a supervisor, not a manager of
managers. If complexity grows beyond what one advisor can handle,
the right move is to give the advisor better tools (summarization,
filtering), not to add layers.

This is not autonomous operation. Every proposal requires human
approval. The advisor is a force multiplier for human attention,
not a replacement for it. The "suggest, don't act" principle from
advisor v1 is preserved.

## Implementation order

1. **Source dir support for advisor**: Add `--source-dir` to
   `devaipod advisor` command, thread through to `create_advisor_pod()`.
   Store in advisor workspace state. This is the highest-value change —
   the advisor becomes useful as soon as it can read code.

2. **Patrol cycle prompt**: Update the advisor's default task/system
   prompt to describe the patrol cycle. The agent handles the timing
   itself (the LLM can be told "wait 15 minutes then run the cycle
   again" — or we add a `sleep_until_next_cycle` MCP tool).

3. **Health alerts**: Add `health_alert` MCP tool. Display alerts
   in the UI alongside proposals (same `ProposalsSection` component,
   different styling).

4. **Escalation**: Add `escalate` MCP tool for worker agents,
   `list_escalations` for the advisor. Wire into the patrol cycle.

5. **Advisor config in devaipod.toml**: `[advisor]` section with
   `source_dirs`, `patrol_interval_minutes`, `max_concurrent_agents`.
   Advisor auto-starts with control plane if configured.

6. **Auto-start**: If `[advisor]` is configured, start the advisor
   pod automatically when the control plane starts. No manual
   `devaipod advisor` needed.

## Open questions

1. **Patrol cycle implementation**: Should the advisor LLM manage its
   own timing (with a `sleep` tool), or should the control plane
   drive it by sending periodic prompts? The latter is more reliable
   but requires a "send message to running agent" capability.

2. **Source tree size**: For large source trees, the advisor can't
   read everything every cycle. It needs heuristics: check `git log
   --since` for recent changes, focus on projects with running agents,
   scan broadly on first launch then incrementally. This is prompt
   engineering, not architecture.

3. **Advisor restart**: When the advisor restarts, does it re-read
   its conversation history from the workspace? OpenCode may handle
   this via session persistence, but it needs verification.

4. **Multiple advisors**: Deferred. One advisor is the right starting
   point. If specialization is needed later (one for code, one for
   infra), it's an additive change.
