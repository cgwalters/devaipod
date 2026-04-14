# Agent Client Protocol (ACP) Support

Devaipod uses the Agent Client Protocol (ACP) as its agent transport. Configure a profile in `devaipod.toml` to use any ACP-compatible coding agent. Devaipod supports OpenCode, Goose, and Claude Code (via claude-agent-acp), and auto-detects which agents the container provides.

## Architecture

Pod-api and the agent run in separate containers within the same pod. Pod-api tunnels ACP over stdio into the agent container via `podman exec -i`:

```
pod-api (sidecar)  ──podman exec -i──►  agent container
   │  JSON-RPC 2.0 over stdin/stdout       │
   │                                        │ opencode acp
   ▼                                        │ goose acp
 WebSocket ◄── frontend (SolidJS)          │ claude-agent-acp
```

The agent container's entrypoint is a keep-alive loop. Pod-api starts the ACP process on demand with `podman exec -i <agent-container> <command>`. The ACP `initialize` handshake determines readiness.

The ACP client spawns the agent as a child process and communicates over its stdin/stdout pipes. `AcpClient` manages the JSON-RPC protocol and broadcasts session updates to WebSocket subscribers. When the agent dies, `is_alive()` detects this through `try_wait()` on the child process handle, and `ensure_acp_client()` clears the stale client and respawns.

## Agent Profiles

Configure agent profiles in `~/.config/devaipod.toml`:

```toml
[agent]
default = ["claude", "goose", "opencode"]

[agent.profiles.opencode]
command = ["opencode", "acp"]

[agent.profiles.goose]
command = ["goose", "acp"]
env = { GOOSE_MODE = "auto", GOOSE_PROVIDER = "gcp_vertex_ai", GOOSE_MODEL = "claude-opus-4-6" }

[agent.profiles.claude]
command = ["claude-agent-acp"]
```

The `default` field accepts a single string or an ordered array. At runtime, pod-api probes the agent container for each binary in order and selects the first one found. If `default` is unset or all probes fail, pod-api falls back to `["opencode", "acp"]`.

Agent-specific configuration (model selection, MCP servers, permissions) lives in the agent's own config files, referenced by environment variables in the profile. When `DEVAIPOD_HOST_HOME` is set and the config file exists, devaipod mounts `~/.config/devaipod.toml` read-only into the pod-api sidecar at `/tmp/.config/devaipod.toml`, so pod-api can read profile definitions. In test environments where `DEVAIPOD_HOST_HOME` is absent, pod-api falls back to the hardcoded opencode default.

## Permission Handling

Each agent auto-approves internal permissions to avoid blocking on tool use:

- **OpenCode**: `OPENCODE_PERMISSION='{"*":"allow"}'` in the agent container environment
- **Goose**: `GOOSE_MODE=auto` in the profile env
- **Claude Code**: `bypassPermissions: true` in settings.json baked into the container image

ACP `session/request_permission` requests still reach the frontend for visibility, but agents grant permissions internally without waiting for user approval.

## Session Lifecycle

The ACP session flow:

1. `initialize` → agent reports capabilities, server sends client info
2. `initialized` → handshake complete
3. `session/new` → create a new session with working directory
4. `session/prompt` → submit user prompt, returns immediately
5. `session/update` notifications → stream progress (text, tool calls, errors) to frontend
6. Response to `session/prompt` arrives asynchronously

`session/prompt` returns immediately; a background task handles the JSON-RPC response while `session/update` notifications stream to WebSocket clients in real time. The frontend shows progress as the agent works.

Additional methods:

- `session/list` → list available sessions
- `session/load` → replay session history
- `session/cancel` → cancel running prompt

## Container Images

Devaipod provides two multi-agent devcontainer images in `contrib/`:

- `Containerfile.devenv-goose` — Goose only
- `Containerfile.devenv-multi-agent` — Goose, Claude Code (via claude-agent-acp), and OpenCode

Build and use a multi-agent image:

```bash
podman build -t localhost/devenv-multi-agent:latest -f contrib/Containerfile.devenv-multi-agent .
devaipod run https://github.com/org/repo --image localhost/devenv-multi-agent:latest -c 'fix bug'
```

The agent container must include git and your development tools (Rust, Go, npm, etc.) alongside the agent binaries.

## Protocol Implementation

Devaipod uses the `agent-client-protocol-schema` crate for ACP types. `AcpClient` in `src/acp_client.rs` implements a `Send`-compatible JSON-RPC client because the upstream `ClientSideConnection` produces `!Send` futures, incompatible with axum handlers.

Implemented methods:

- `initialize` / `initialized`
- `session/new`, `session/list`, `session/load`
- `session/prompt` (fire-and-forget, streams events in real-time)
- `session/cancel`
- `session/request_permission` (forwarded to frontend)

## Testing

Integration tests use a mock agent (`DEVAIPOD_MOCK_AGENT=1`) to validate agent-agnostic behavior. The mock script, injected during pod startup, implements minimal ACP responses to verify the client, WebSocket endpoint, and frontend without agent-specific code.

Run tests:

```bash
just test-integration        # Full integration tests with containerized build
just test-integration-web    # Playwright browser tests
```

## Future Work

- **Git worktrees per session**: One worktree per ACP session prevents parallel sessions from conflicting. ACP's `session/new` accepts a `cwd` parameter for this.
- **MCP-over-ACP**: Once the RFD stabilizes, inject service-gator through the ACP channel instead of per-agent MCP config.
- **Native agent UI**: Optional `native_ui` in profiles for agents with their own web UI (OpenCode, Goose), served via iframe.

## References

- [ACP specification](https://agentclientprotocol.com/protocol/overview)
- [ACP tool calls](https://agentclientprotocol.com/protocol/tool-calls)
- [MCP-over-ACP RFD](https://agentclientprotocol.com/rfds/mcp-over-acp)
- [agent-client-protocol crate](https://crates.io/crates/agent-client-protocol)
