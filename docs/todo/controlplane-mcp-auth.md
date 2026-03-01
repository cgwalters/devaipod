# Control Plane MCP Authentication

The `/api/devaipod/mcp` endpoint on the control plane is unauthenticated.
Any pod in the system can reach it via `host.containers.internal:8080`
and use it to enumerate pods, read other pods' logs, and create proposals.

## Background

Pods use default rootless podman networking (bridge/pasta). This gives
every container automatic access to `host.containers.internal`, which
resolves to the host gateway (169.254.1.2 via pasta). The control plane
publishes port 8080 on `0.0.0.0`, so pods can reach it.

The rest of the control plane API (`/api/*`) is properly gated behind a
256-bit auth token (cookie or bearer). The MCP endpoint is explicitly
exempted from this with a TODO in the code:

```rust
// TODO: add lightweight auth (e.g. shared secret) for production use
```

## Attack surface

A compromised agent in any pod can call these MCP tools without
credentials:

- **`list_pods`** — enumerate all running pods with tasks, repos, metadata
- **`pod_status`** — detailed status of any pod including container states
- **`pod_logs`** — read recent logs from any pod's agent container
- **`propose_agent`** / **`list_proposals`** — create and list proposals

The `pod_logs` tool is the most concerning: a rogue agent in one pod
could read another pod's logs, which may contain LLM API keys, code
secrets, or other sensitive information from unrelated workspaces.

Note: authenticated endpoints (pod management, podman proxy, exec) are
not affected. The auth token has 256 bits of entropy.

## Proposed fix

Add authentication to the MCP endpoint. Options, roughly in order of
simplicity:

### Option A: reuse the existing bearer token

Move the MCP route inside the existing auth middleware. The MCP client
(advisor, external tools) would need to provide the same token used for
the web UI. This is the simplest change but means MCP clients need the
full control-plane token, which is high privilege.

### Option B: separate shared secret for MCP

Generate a separate MCP secret at control-plane startup. Pass it to the
advisor pod (which is the primary MCP consumer) via environment or
secret mount. MCP requests must include this secret as a bearer token
or in a custom header.

This scopes MCP access without granting full API access. Regular pods
never receive the MCP secret, so they can't call MCP tools even if they
can reach the endpoint.

### Option C: per-pod MCP tokens

Each pod gets its own MCP token (similar to the existing per-pod
api-password). The MCP endpoint validates the token and can scope
responses to only that pod's data. This is the most granular but
requires more plumbing.

## Recommendation

Option B is probably the right trade-off: one secret, scoped to MCP,
given only to the advisor pod. It's simple to implement and closes the
cross-pod log-reading attack. Option C is better long-term but can be
deferred.

## Related docs

- [per-pod-gateway-sidecar.md](./per-pod-gateway-sidecar.md) — plans
  for a per-pod auth gateway, which would also limit what pods can
  reach on the control plane
- [minimize-injection.md](./minimize-injection.md) — reducing injected
  scripts and moving logic into Rust
