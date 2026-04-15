# Pod Architecture

Each devaipod workspace is a **podman pod** with several containers:

| Container | Role |
|-----------|------|
| `agent` | Runs the AI coding agent via ACP; has its own workspace copy |
| `gator` | [service-gator](https://github.com/cgwalters/service-gator) — fine-grained MCP server for GitHub/GitLab/Forgejo |
| `api` | **pod-api** sidecar — ACP client, WebSocket event bridge, HTTP API for git/status |

All containers in a pod share the network namespace (localhost communication).
The `api` container exposes a `/healthz` endpoint with a podman healthcheck.

## Key source files

| File | Purpose |
|------|---------|
| `src/main.rs` | CLI entry point and all subcommand handlers |
| `src/pod.rs` | Pod creation, container configs, volume management |
| `src/pod_api.rs` | Pod-api sidecar HTTP server (axum), ACP session management |
| `src/acp_client.rs` | ACP JSON-RPC client, agent process lifecycle, WebSocket events |
| `src/podman.rs` | Podman API abstraction, `ContainerConfig`, `PodmanService` |
| `src/web.rs` | Web UI server, proxy routes, auth |
| `src/config.rs` | Configuration types and loading, agent profile resolution |
| `src/agent_dir.rs` | Host-side agent workspace directories, harvest, multi-repo discovery |
| `src/git.rs` | Git clone scripts, agent workspace init, reference clones |
| `src/advisor.rs` | Advisor data types, pod/workspace introspection, draft proposals |
| `src/mcp.rs` | MCP JSON-RPC server for advisor tools (`/api/devaipod/mcp`) |
| `src/review_tui.rs` | Interactive TUI for reviewing agent diffs (`devaipod review`) |
| `src/ssh_server.rs` | SSH server for `exec --stdio` connections |

## Volumes and workspace storage

Agent pods use **host-directory workspaces**: each pod gets a dedicated
directory on the host (under `~/.local/share/devaipod/workspaces/<pod>/`)
bind-mounted into the agent container. This directory persists across
pod stop/start/delete cycles and serves as the primary mechanism for
harvesting agent commits back into the user's source repo.

Named volumes store home directories and ancillary state.
Each pod creates up to 4 named volumes (suffixed with the pod name):
`workspace`, `agent-home`, `worker-home`, `worker-workspace`.
Worker volumes are created only when orchestration mode is enabled.

Devcontainer pods (created via `devaipod devcontainer run`) use the
main workspace volume directly (no separate agent workspace) since the
human and agent share the same workspace in devcontainer mode.

**Known bug:** `cmd_prune` and `prune_done_pods` leak volumes when removing
pods. `cmd_delete` cleans up correctly.

## Control Plane

The devaipod control plane runs as a container (named `devaipod`),
launched by the Justfile's `container-run` recipe. It runs the web server
(`devaipod web`) on port 8080. The container bind-mounts the host's
podman socket to manage agent pods.

The TUI launches inside the same container via `podman exec -ti devaipod
devaipod tui`. It shares the control plane's filesystem and network
namespace, so it reads the web server's auth token from the state
directory and calls the REST API at `http://127.0.0.1:{port}`.

Both the TUI and the web frontend use the same REST API
(`/api/devaipod/pods`, `/api/devaipod/workspaces`, etc.) as their
data source, ensuring consistent behavior across interfaces.

## Agent Client Protocol (ACP)

Pod-api acts as an ACP client, communicating with agents via JSON-RPC over stdio. The transport spawns the agent process with `podman exec -i <agent-container> <command>` and pipes JSON-RPC messages over stdin/stdout.

`AcpClient` in `src/acp_client.rs` manages the protocol:

- Spawns the agent process via `podman exec`
- Sends JSON-RPC requests and notifications
- Reads JSON-RPC responses and `session/update` notifications line-by-line
- Broadcasts ACP events to WebSocket subscribers at `/ws/events`

Agent profile resolution: config `[agent].default` → probe agent container for each candidate → hardcoded fallback. Auto-detection runs `command -v <binary>` in the agent container to check availability.

`is_alive()` detects dead agents by calling `try_wait()` on the child process handle. When `ensure_acp_client()` finds a dead process, it clears the stale client and spawns a new one on the next request.

WebSocket clients subscribe to `/ws/events` and receive updates as the agent works. The frontend renders messages, tool calls, and permission requests in a multi-pane interface. See [ACP Support](acp.md) for protocol details.

## Tracing

All log output goes to **stderr** (via `tracing_subscriber` with
`.with_writer(std::io::stderr)`). This is important because some commands
(e.g. `exec --stdio`, `gator show --json`) use stdout for structured data.
