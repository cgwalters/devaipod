# Agent Client Protocol (ACP) Support

Devaipod uses the [Agent Client Protocol (ACP)](https://agentclientprotocol.com)
as its agent transport. Any ACP-compatible coding agent works — configure
a profile in `devaipod.toml` and ensure the agent binary is in your
devcontainer image. Devaipod auto-detects which agents the container
provides.

## Architecture

Pod-api and the agent run in separate containers within the same pod. Pod-api tunnels ACP over stdio into the agent container via `podman exec -i`:

```
pod-api (sidecar)  ──podman exec -i──►  agent container
   │  JSON-RPC 2.0 over stdin/stdout       │
   │                                        │ <agent> acp
   ▼                                        │
 WebSocket ◄── frontend (SolidJS)          │
```

The agent container's entrypoint is a keep-alive loop. Pod-api starts the ACP process on demand with `podman exec -i <agent-container> <command>`. The ACP `initialize` handshake determines readiness.

The ACP client spawns the agent as a child process and communicates over its stdin/stdout pipes. `AcpClient` manages the JSON-RPC protocol and broadcasts session updates to WebSocket subscribers. When the agent dies, `is_alive()` detects this through `try_wait()` on the child process handle, and `ensure_acp_client()` clears the stale client and respawns.

## Agent Profiles

Configure agent profiles in `~/.config/devaipod.toml`. Each profile
specifies the command to start the agent and optional environment
variables:

```toml
[agent]
default = ["my-agent", "opencode"]

[agent.profiles.my-agent]
command = ["my-agent", "acp"]

[agent.profiles.my-agent.env]
MY_AGENT_MODEL = "some-model"
```

The `default` field accepts a single string or an ordered array. At
runtime, pod-api probes the agent container for each binary in order
and selects the first one found. If `default` is unset or all probes
fail, pod-api falls back to `["opencode", "acp"]`.

See [Supported Agents](agents.md) for tested configurations.

## Permission Handling

Agents must run with permissive internal permissions so they do not
block waiting for interactive approval. Each agent achieves this
differently — through environment variables, config files, or CLI
flags. See [Supported Agents](agents.md) for per-agent examples.

ACP defines `session/request_permission` for agents that support
frontend-mediated approval. Devaipod forwards these requests to the
web UI when they occur.

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

The agent binary must be present in your devcontainer image. Set the
`image` field in your project's `devcontainer.json` to an image that
includes your preferred agent:

```json
{
  "image": "ghcr.io/example/my-devcontainer:latest"
}
```

The `ghcr.io/bootc-dev/devenv-debian` base image includes OpenCode.
For other agents, use an image that ships the agent binary.
Auto-detection probes the image for available binaries, so an image
with multiple agents works without additional configuration.

To test a different image without modifying `devcontainer.json`, pass
`--image` to override it for a single workspace:

```bash
devaipod up https://github.com/org/repo --image my-agent-image:latest
```

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
