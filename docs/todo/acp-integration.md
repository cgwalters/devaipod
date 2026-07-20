# Agent Client Protocol (ACP) Integration

## Summary

Devaipod's agent layer is hardwired to OpenCode: the vendored SPA,
pod-api proxy, container startup commands, authentication, and system
prompt generation all assume OpenCode's HTTP API. This makes it
impossible to use Claude Code, Goose, or another agent as the primary
agent without OpenCode in the loop.

[ACP](https://agentclientprotocol.com) (Agent Client Protocol) is an
open standard (Apache-2.0, JSON-RPC 2.0 over stdio) that standardizes
communication between frontends and coding agents — the "LSP for AI
agents." It was created by Zed Industries and is co-maintained by
JetBrains.

Adopting ACP would:

- Decouple devaipod from any single agent framework
- Enable `--agent claude-code` or `--agent goose` at pod creation time
- Move tool permission management into devaipod's frontend (unified UX)
- Eliminate iframe integration issues (PR #50) by replacing the embedded
  OpenCode SPA with a devaipod-native frontend
- Provide a stable protocol boundary for multi-repo (#15), sidecar
  profiles (#17), and worktree mode (workspace-v2)

This feature belongs inside devaipod, not as a separate project.
Unlike service-gator (a standalone proxy with a clear network boundary),
ACP integration is how devaipod's core — pod lifecycle, web UI, pod-api
— talks to agents. It is tightly coupled to devaipod's architecture.

## ACP Protocol Overview

### Session lifecycle

1. **`initialize`** — Client sends capabilities, server responds with
   its own. Negotiates protocol version (currently `PROTOCOL_VERSION = 1`).
2. **`session/new`** — Creates a conversation session, returns a session
   ID.
3. **`session/prompt`** — Sends a user message. The server streams back
   `session/event` notifications.
4. **`session/stop`** — Cancels in-progress generation.

### Tool permissions

ACP defines three session modes controlling autonomy:

- **Ask mode** (default) — agent requests permission before any change
- **Architect mode** — planning only, no implementation tools
- **Code mode** — full tool access, minimal approval

Per-tool approval uses `session/request_permission`:

1. Agent sends a permission request with tool call details and options
2. Each option has a kind: `allow_once`, `allow_always`, `reject_once`,
   `reject_always`
3. Client (devaipod frontend) presents these to the user and responds
4. Clients can auto-approve based on user settings

Tool calls have a `kind` category (`read`, `edit`, `delete`, `execute`,
`search`, `think`, `fetch`, `other`) enabling categorized approval
policies.

Devaipod's current YOLO-by-default behavior maps to: set session mode
to Code and auto-approve all `session/request_permission` requests in
the client. The user can toggle this off to get per-tool approval — a
better UX than today's binary YOLO toggle.

### Agent-advertised features

**Slash commands**: Agents advertise available commands via
`available_commands_update` notifications. The command list is dynamic.
This is how agent-specific features (OpenCode's `/compact`, Claude
Code's `/review`) surface in a generic frontend.

**Session config options**: Agents expose arbitrary config via
`session/set_config_option`. The spec defines semantic categories
(`mode`, `model`, `thought_level`) but agents can expose whatever they
want. Model selection and agent-specific settings work without the
frontend knowing each agent's internals.

### What ACP does not cover

- Agent-specific configuration (config files, home directory layout)
- Container image selection and setup
- LLM credential management (handled by the credential proxy)
- Workspace/volume setup
- Git state tracking (handled by pod-api independently)
- MCP server configuration (see "MCP Integration Strategy" below)

These are container-level concerns, not protocol-level, and are handled
by the agent profile configuration and pod creation logic.

## MCP Integration Strategy

### Current state

Service-gator runs as a container in the pod, listening on localhost.
The agent connects to it as a regular MCP server via HTTP. This is
already agent-agnostic — any agent that supports MCP can connect to
`http://localhost:<gator-port>`.

### Near-term: per-agent MCP config

Each agent profile configures the agent to connect to service-gator's
localhost URL using the agent's native MCP config format:

```toml
[agent.profiles.opencode]
command = ["opencode", "acp"]
# opencode config.toml includes:
# [mcp.service-gator]
# transport = "http"
# url = "http://localhost:8081"

[agent.profiles.claude-code]
command = ["claude-agent-acp"]
# .claude/settings.json includes MCP server at localhost:8081
```

This is a small amount of per-agent boilerplate, but each profile
already needs agent-specific setup (YOLO config, home directory layout),
so one more config entry is not a significant burden.

### Future: MCP-over-ACP

An [RFD with a working implementation](https://agentclientprotocol.com/rfds/mcp-over-acp)
(in the `sacp-conductor` crate) defines how clients inject MCP servers
into agent sessions through the ACP channel:

1. Client declares MCP servers in `session/new` with
   `"transport": "acp"`
2. Agent routes MCP tool invocations back through the ACP channel
3. No separate processes, ports, or per-agent config needed

When this lands in the core ACP spec and agents implement it, devaipod
can migrate from per-agent MCP config to client-side injection. This
would eliminate the per-agent MCP boilerplate entirely — devaipod would
inject service-gator once, and it would work with any agent. Until then,
the per-agent config approach works fine.

## Permission Architecture

With ACP, devaipod's frontend becomes the single permission gate. Agent
harnesses run with their internal permissions set to auto-approve:

```
User → devaipod frontend → [ACP permission check] → Agent harness → Tool execution
                                                     (YOLO internally)
```

This eliminates double-prompting and provides a consistent permission UX
regardless of which agent is running. Each agent profile includes
whatever agent-specific config disables internal permission checks:

- OpenCode: `autoApprove = ["*"]` in config.toml
- Claude Code: equivalent of `--dangerously-skip-permissions`
- Goose: auto-approve in its config

The agent harnesses are still essential — they define and execute tools,
talk to the LLM, manage context windows, and act as MCP clients. ACP
standardizes how the harness *reports* what it's doing and how the
frontend *approves* it, but the harness is still the engine.

## Image Architecture

### Base image + harness layers

The Containerfile is split into a base image and per-harness extension
Containerfiles:

```
┌──────────────────────────────────────────┐
│  User's devcontainer image               │  project toolchain
├──────────────────────────────────────────┤
│  devaipod-agent-opencode                 │  opencode binary + YOLO config
│  OR devaipod-agent-claude-code           │  claude binary + skip-perms config
│  OR devaipod-agent-goose                 │  goose binary + auto-approve config
│  OR user's custom agent image            │
├──────────────────────────────────────────┤
│  devaipod-base                           │  pod-api, ACP client, git, scripts
└──────────────────────────────────────────┘
```

**`Containerfile`** builds `devaipod-base` — the control plane binary,
pod-api sidecar, ACP client, web frontend, git tooling, and scripts.
No agent harness included.

**`Containerfile.opencode`** extends `devaipod-base`, adds the opencode
binary and default YOLO configuration. This is the default agent image.

**`Containerfile.claude-code`**, **`Containerfile.goose`**, etc. follow
the same pattern. Users who want Claude Code build this locally,
solving the proprietary licensing problem — devaipod never distributes
the binary.

Users can write their own Containerfile extending `devaipod-base` to
add any ACP-compatible agent.

### Agent image extends devcontainer (option 1)

The agent container uses the same base as the workspace container
(which includes the devcontainer's toolchain). This is the current
model and the right default: when the agent runs `cargo test` or
`npm install`, those tools must be available.

> **Open question**: In the future, an independent agent image
> (option 2) that delegates build/test execution to the workspace
> container may be worth revisiting. If the agent only handles LLM
> interaction and file editing, a thin image would suffice and
> would decouple agent and devcontainer update cycles. This depends
> on how the architecture evolves. For now, option 1 avoids the
> complexity of cross-container tool execution.

## Architecture Diagram

```
┌──────────────────────────────────────────────────────────────────────┐
│  Host                                                                │
│  ┌────────────────────────────────────────────────────────────────┐  │
│  │  devaipod control plane (:8080)                                │  │
│  │  Pod management, auth, multi-pod overview                      │  │
│  └──────────────────────────┬─────────────────────────────────────┘  │
│                             │                                        │
│  ┌── Pod ───────────────────┼──────────────────────────────────────┐ │
│  │                          ▼                                      │ │
│  │  ┌──────────────────────────────────────────────────────────┐   │ │
│  │  │  pod-api sidecar (:8090)                                 │   │ │
│  │  │                                                          │   │ │
│  │  │  ┌──────────────┐  ┌──────────────────────────────────┐  │   │ │
│  │  │  │  ACP Client   │  │  Web frontend (SolidJS)          │  │   │ │
│  │  │  │  Manages stdio│  │  Renders ACP event stream        │  │   │ │
│  │  │  │  to agent     │  │  Tool approval / YOLO toggle     │  │   │ │
│  │  │  │  process      │◄─┤  Slash commands from agent       │  │   │ │
│  │  │  │               │  │  Git review panel                │  │   │ │
│  │  │  │               │  │  Multi-repo view                 │  │   │ │
│  │  │  │               │  │  Session config (model, mode)    │  │   │ │
│  │  │  └──────┬────────┘  └──────────────────────────────────┘  │   │ │
│  │  └─────────┼─────────────────────────────────────────────────┘   │ │
│  │            │ stdio (JSON-RPC)                                    │ │
│  │            ▼                                                     │ │
│  │  ┌──────────────────┐  ┌───────────┐  ┌───────────────────────┐ │ │
│  │  │ Agent container   │  │ Workspace │  │ LLM credential proxy  │ │ │
│  │  │ (pluggable)       │  │ container │  │ (service-gator ext    │ │ │
│  │  │                   │  │           │  │  or One-API)          │ │ │
│  │  │ opencode acp      │  │ Human's   │  │                       │ │ │
│  │  │ OR claude acp     │  │ shell,    │  │ Holds LLM API keys    │ │ │
│  │  │ OR goose acp      │  │ editor    │  │ Routes to providers   │ │ │
│  │  │ OR <user's agent> │  │ access    │  │ Rate limiting, logs   │ │ │
│  │  │                   │  │           │  │                       │ │ │
│  │  │ Internal perms:   │  │           │  │                       │ │ │
│  │  │ YOLO (all auto-   │  │           │  │                       │ │ │
│  │  │ approved)         │  │           │  │                       │ │ │
│  │  │                   │  │           │  │                       │ │ │
│  │  │ MCP client ──────►│◄─┤           │  │                       │ │ │
│  │  │ connects to gator │  │           │  │                       │ │ │
│  │  │ on localhost       │  │           │  │                       │ │ │
│  │  └──────────────────┘  └───────────┘  └───────────────────────┘ │ │
│  │            │                  │               │                  │ │
│  │  ┌──────────────────┐        │               │                  │ │
│  │  │ service-gator    │◄───────┘               │                  │ │
│  │  │ (forge scopes)   │                        │                  │ │
│  │  └──────────────────┘                        │                  │ │
│  └──────────────┼───────────────────────────────┼──────────────────┘ │
│                 ▼                               ▼                    │
│           Forge APIs                     LLM Provider APIs           │
│       (GitHub, GitLab, ...)        (Anthropic, OpenAI, Google, ...)  │
└──────────────────────────────────────────────────────────────────────┘
```

### Credential isolation

With ACP + the LLM credential proxy, the agent container holds **zero
credentials**:

- Forge tokens (GitHub, GitLab, JIRA) → service-gator
- LLM API keys (Anthropic, OpenAI, Google) → credential proxy
- The agent only has localhost URLs for both services

### How the LLM proxy complements ACP

ACP and the LLM proxy serve different layers:

- **ACP** is between the *frontend* and the *agent* — carries prompts,
  responses, tool calls, and approvals
- **The LLM proxy** is between the *agent* and the *LLM provider* —
  carries inference requests and holds API keys

The proxy enables agent-agnostic model routing. If the user configures
Anthropic and OpenAI keys, any agent can use either provider without
per-agent credential setup.

## Interaction with Other Features

### Multi-repo (#15)

Multi-repo is agent-agnostic infrastructure. With ACP:

- Pod-api tracks git state across all configured repos (unchanged)
- The ACP frontend renders a multi-repo git panel (replaces the
  OpenCode-specific git view)
- System prompt lists available repos regardless of agent
- Service-gator scopes are per-repo, independent of agent choice

### Worktree mode (workspace-v2)

Worktree mode changes workspace setup, not agent communication:

- `devaipod up --worktree` creates a host-side worktree and bind-mounts
  it, regardless of which agent runs
- The `harvest` command fetches agent commits from git, not from the
  agent protocol
- Per-agent home directory layout (OpenCode's `~/.config/opencode/`,
  Claude Code's `~/.claude/`) is handled by agent profile config

### Pluggable agents (#17)

With ACP as the protocol boundary, the `SidecarProfile` config selects
which agent binary to run and what image to use:

```toml
# ~/.config/devaipod.toml

[agent]
default = "opencode"

[agent.profiles.opencode]
command = ["opencode", "acp"]

[agent.profiles.claude-code]
command = ["claude-agent-acp"]  # or native ACP when available

[agent.profiles.goose]
command = ["goose", "acp"]
```

## Current OpenCode Coupling

~40+ direct references to OpenCode across the codebase:

| Area | Current | After ACP |
|------|---------|-----------|
| Port constants | `OPENCODE_PORT = 4096` | Removed; ACP uses stdio |
| Container startup | `opencode serve --port X` | Profile-defined command |
| Pod-api proxy | HTTP to `/session`, `/mcp` | ACP JSON-RPC over stdio |
| Authentication | `opencode:password` Basic auth | Not needed; stdio |
| Vendored UI | `opencode-ui/` SPA in iframe | Devaipod-native SolidJS frontend |
| System prompts | OpenCode API references | Generic or per-agent templates |
| CLI commands | `devaipod opencode mcp/session` | `devaipod agent` subcommands |
| Mock server | `run_mock_opencode()` | Mock ACP server |

Agent-agnostic areas unchanged: pod orchestration, volumes, git,
service-gator, SSH server, devcontainer parsing.

## Rust Ecosystem

- **`agent-client-protocol-schema`** — serde types from the JSON Schema
  spec. Schema-only, no runtime logic.
- **`agent-client-protocol`** — higher-level client/transport utilities.

Both are pre-1.0. Options: depend with pinned versions, or vendor the
schema types.

## Transport: stdio in Containers

ACP uses stdio (client spawns agent as child process). In devaipod's
containerized model, the pod-api sidecar acts as the ACP client:

1. Pod-api spawns the agent process inside the agent container (via
   `podman exec` or as the container's entrypoint)
2. Pod-api holds the stdio pipes and manages JSON-RPC sessions
3. Pod-api exposes ACP events over WebSocket to the web frontend
4. Pod-api relays tool approval between frontend and agent

This preserves the existing security model: the web UI never talks
directly to the agent.

## Agent ACP Support

| Agent | ACP support | Notes |
|-------|-------------|-------|
| OpenCode | Native (`opencode acp`) | ACP was designed around OpenCode |
| Claude Code | Adapter ([claude-agent-acp](https://github.com/agentclientprotocol/claude-agent-acp)) | Native support [requested](https://github.com/anthropics/claude-code/issues/6686) |
| Goose | Native | Block co-developed ACP |
| Gemini CLI | Native | ACP launch partner |
| Codex CLI | Via adapter | |
| Junie | Native | JetBrains co-maintains ACP |

## Implementation Phases

### Phase 1: Agent trait and base image

Define a Rust trait capturing what devaipod needs from an agent.
Implement it for OpenCode's existing HTTP API first (preserving current
behavior). Factor the Containerfile into `Containerfile` (base) and
`Containerfile.opencode` (default harness).

### Phase 2: ACP backend and transport

Implement the agent trait for ACP. Modify pod-api to spawn the agent
process with ACP over stdio, manage JSON-RPC sessions, and expose
events over WebSocket.

### Phase 3: Devaipod-native frontend

Replace the vendored OpenCode SPA with a SolidJS frontend that renders
ACP event streams, provides tool approval UI, integrates the git review
panel and terminal, and exposes agent-advertised slash commands and
config options.

### Phase 4: Agent profiles and `--agent` flag

Wire up profile config to pod creation. `devaipod up --agent claude-code`
selects the profile, uses the corresponding image, starts the agent with
the profile's command. Provide example Containerfiles for Claude Code
and Goose that extend the base image.

### Phase 5: MCP-over-ACP migration (when spec stabilizes)

When MCP-over-ACP lands in the core ACP spec and agents implement it,
migrate from per-agent MCP config to client-side injection via the ACP
channel. This eliminates per-agent MCP boilerplate — devaipod injects
service-gator once, works with any agent.

## Open Questions

1. **ACP crate maturity**: The Rust crates are pre-1.0. Vendor schema
   types or depend with pinned versions?

2. **Feature parity during transition**: OpenCode's HTTP API exposes MCP
   management, session persistence, and cost tracking that ACP doesn't.
   Should the frontend have agent-specific panels, or are these
   configured out-of-band?

3. **Independent agent image (option 2)**: If the agent delegates all
   build/test execution to the workspace container and only handles LLM
   interaction + file editing, a thin independent agent image could
   decouple agent and devcontainer images. Worth revisiting after the
   initial ACP integration is stable and the multi-container
   architecture matures.

4. **Subagent spawning**: The dynamic subagent design
   (subagent-container.md) assumes spawning more OpenCode instances.
   With ACP, subagents could be any agent type. Does this change the
   MCP tool design for `spawn_subagent`?

5. **Testing strategy**: How to test ACP integration without real LLM
   API keys? A mock ACP server (replacing `run_mock_opencode()`) would
   need to simulate tool calls, permission requests, and event
   streaming.

6. **ACP extensions**: Should devaipod define custom ACP extension
   methods (prefixed with `_devaipod/`) for features like git state
   notifications, service-gator scope display, or pod lifecycle events?
   Or keep these on a separate WebSocket channel?

## References

- [ACP specification](https://agentclientprotocol.com/protocol/overview)
- [ACP GitHub](https://github.com/agentclientprotocol/agent-client-protocol)
- [ACP tool calls](https://agentclientprotocol.com/protocol/tool-calls)
- [ACP session modes](https://agentclientprotocol.com/protocol/session-modes)
- [ACP slash commands](https://agentclientprotocol.com/protocol/slash-commands)
- [ACP session config](https://agentclientprotocol.com/protocol/session-config-options)
- [MCP-over-ACP RFD](https://agentclientprotocol.com/rfds/mcp-over-acp)
- [agent-client-protocol crate](https://crates.io/crates/agent-client-protocol)
- [claude-agent-acp adapter](https://github.com/agentclientprotocol/claude-agent-acp)
- [Claude Code ACP feature request](https://github.com/anthropics/claude-code/issues/6686)
- Related devaipod docs:
  - [openai-compat-proxy.md](openai-compat-proxy.md)
  - [subagent-container.md](subagent-container.md)
  - [workspace-v2.md](workspace-v2.md)
  - Issue #15 — multi-repo support
  - Issue #17 — sidecar profiles
