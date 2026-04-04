# Pod Architecture

Each devaipod workspace is a **podman pod** containing several containers:

| Container | Role |
|-----------|------|
| `workspace` | User's dev environment (from devcontainer image) |
| `agent` | Runs the AI agent (opencode); has its own workspace copy |
| `gator` | [service-gator](https://github.com/cgwalters/service-gator) — fine-grained MCP server for GitHub/GitLab/Forgejo |
| `api` | **pod-api** sidecar — HTTP server for git status, summary, completion status |

All containers in a pod share the network namespace (localhost communication).
The `api` container has a `/healthz` endpoint and a podman healthcheck configured.

## Key source files

| File | Purpose |
|------|---------|
| `src/main.rs` | CLI entry point and all subcommand handlers |
| `src/pod.rs` | Pod creation, container configs, volume management |
| `src/pod_api.rs` | Pod-api sidecar HTTP server (axum) |
| `src/podman.rs` | Podman API abstraction, `ContainerConfig`, `PodmanService` |
| `src/web.rs` | Web UI server, proxy routes, auth |
| `src/config.rs` | Configuration types and loading |
| `src/ssh_server.rs` | SSH server for `exec --stdio` connections |

## Volumes

Each pod creates up to 5 named volumes (suffixed with the pod name):
`workspace`, `agent-home`, `agent-workspace`, `worker-home`, `worker-workspace`.
The worker volumes are only created when orchestration mode is enabled.

**Known issue:** `cmd_prune` and `prune_done_pods` do not clean up volumes
when removing pods. `cmd_delete` handles this correctly. This is a bug to fix.

## Control Plane

The devaipod control plane itself runs as a container (named `devaipod`),
launched by the Justfile's `container-run` recipe. It runs the web server
(`devaipod web`) and exposes port 8080. The control plane container has
the host's podman socket bind-mounted so it can manage agent pods.

The TUI is launched inside the same container via `podman exec -ti devaipod
devaipod tui`. Because it shares the control plane's filesystem and network
namespace, the TUI can read the web server's auth token from the state
directory and call the REST API at `http://127.0.0.1:{port}`.

Both the TUI and the web frontend should use the same REST API
(`/api/devaipod/pods`, `/api/devaipod/workspaces`, etc.) as their
data source. This ensures consistent behavior regardless of which
interface the user chooses.

## Tracing

All log output goes to **stderr** (via `tracing_subscriber` with
`.with_writer(std::io::stderr)`). This is important because some commands
(e.g. `exec --stdio`, `gator show --json`) use stdout for structured data.
