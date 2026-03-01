# Dynamic Port Forwarding

Allow pods to request that a port inside their network namespace be
forwarded to the host, without restarting the pod. The primary use case
is development: an agent (or human developer in a devcontainer) starts a
service on an arbitrary port and wants the host to be able to reach it.

## Motivation

Podman does not support adding port forwards to a running pod. Today,
only ports declared at pod creation time (e.g. pod-api on 8090) are
published. If you build and run a dev server inside a devcontainer, the
host can't reach it.

This is particularly painful for the "devaipod developing devaipod"
workflow. The developer runs `cargo run -- pod-api --port 9090` inside
the devcontainer to test changes, but that port is invisible to the
host browser.

Nested containerization doesn't help either: you can run `podman build`
and even `devaipod up` inside the devcontainer, but any ports published
by the nested containers land on the devcontainer's network namespace,
not the host.

## Proposed approach: `podman exec` relay

The control plane has the host podman socket and can `podman exec` into
any container. We can use this to set up a TCP relay:

1. The control plane binds a host-side TCP listener on a random port.
2. For each incoming connection, it runs
   `podman exec -i <container> socat - TCP:localhost:<target-port>`
   (or `bash -c 'exec 3<>/dev/tcp/localhost/<port> && cat <&3 & cat >&3'`
   as a fallback — this pattern is already used in `ssh_server.rs`
   `handle_direct_tcpip`).
3. It bridges the host socket to the exec'd process's stdin/stdout.

This is essentially how `kubectl port-forward` works. No changes to
the pod's network configuration, no container restart, no new
published ports at the podman layer.

### Lifecycle

- Forwards are ephemeral: they exist as long as the control plane
  process is running and the pod is alive.
- On pod stop/delete, the listener is torn down.
- On control plane restart, active forwards are lost (pods would need
  to re-request them, or they're stored in state).

### Authentication

The request to create a forward needs to be authenticated. Two options:

- **Control plane REST API** — `POST /api/devaipod/pods/{name}/port-forward`
  with `{ "container_port": 9090 }`, returns `{ "host_port": 54321 }`.
  Uses the existing bearer token auth.

- **MCP tool** — add a `port_forward` tool so the advisor or an agent
  can request it. This is appealing for the agentic workflow: an agent
  decides it needs to expose a service and requests it via MCP. But
  requires solving MCP auth first (see
  [controlplane-mcp-auth.md](./controlplane-mcp-auth.md)).

Both can coexist. The REST API is the right starting point since it's
already authenticated.

### Pod-api integration

The pod-api sidecar could also expose a `POST /port-forward` endpoint
that requests a forward from the control plane on behalf of the pod.
This would let tools running inside the pod request forwards without
needing control plane credentials — the pod-api acts as the trusted
intermediary. The control plane would verify the request came from a
known pod-api sidecar (e.g. by matching the source pod).

## API sketch

### REST

```
POST /api/devaipod/pods/{name}/port-forward
{
  "container_port": 9090,
  "container": "agent"   // optional, defaults to agent
}

Response:
{
  "host_port": 54321,
  "host_address": "127.0.0.1",
  "container_port": 9090
}
```

```
GET /api/devaipod/pods/{name}/port-forward
Response: [{ "host_port": 54321, "container_port": 9090, ... }]
```

```
DELETE /api/devaipod/pods/{name}/port-forward/{host_port}
```

### MCP tool (future)

```json
{
  "name": "port_forward",
  "description": "Forward a port from a pod to the host",
  "inputSchema": {
    "properties": {
      "pod_name": { "type": "string" },
      "container_port": { "type": "integer" }
    }
  }
}
```

## Implementation notes

- The `ssh_server.rs` `handle_direct_tcpip` function already
  implements the `podman exec` + stdin/stdout bridge pattern. The
  TCP relay can reuse this approach.
- Use `tokio::net::TcpListener::bind("127.0.0.1:0")` for the host
  listener to get a random port. Bind to 127.0.0.1 only to avoid
  exposing forwarded ports to the network.
- The control plane needs to track active forwards (pod name, host
  port, container port, listener handle) so it can tear them down
  and list them.
- Consider a maximum number of forwards per pod to prevent resource
  exhaustion.

## Related docs

- [per-pod-gateway-sidecar.md](./per-pod-gateway-sidecar.md) — the
  gateway sidecar is a static port; this is for dynamic, on-demand
  ports
- [controlplane-mcp-auth.md](./controlplane-mcp-auth.md) — MCP auth
  is a prerequisite for the MCP tool variant
