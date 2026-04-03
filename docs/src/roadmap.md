# devaipod Roadmap

Priorities may shift based on user feedback and practical experience.
Design documents live in `docs/todo/`; this roadmap organizes them
into a dependency-ordered plan.

## Recently Completed

- **SSH server for editor connections**: Embedded Rust SSH server
  (russh). Supports exec, shell, PTY, and port forwarding.
- **Pod-api sidecar**: HTTP API sidecar per pod, serving the vendored
  opencode web UI and proxying agent API calls.
  See [per-pod-gateway-sidecar.md](../todo/per-pod-gateway-sidecar.md)
  (historical).
- **Script injection reduction**: Auth proxy and workspace monitor
  replaced with pod-api; clone scripts remain.
  See [minimize-injection.md](../todo/minimize-injection.md).

## In Progress / Near-term

- **Agent completion detection**: Partially implemented via `/summary`
  endpoint. Needs full idle-state detection for `run` mode.
- **Git state awareness**: Detect and warn about unpushed commits.
- **Agent readiness probes**: Partially implemented via pod-api health
  checks. Needs refinement.
- **Pod-api as lifecycle driver**: Make pod-api the single entry point
  for agent session creation and task injection, eliminating fragile
  `podman exec` patterns.
  See [pod-api-driver.md](../todo/pod-api-driver.md).
- **UI improvements**: Session titles, card layout, attach experience.
  See [ui.md](../todo/ui.md).

## Planned Work

The following features have design docs and are ordered by dependency.
Later items build on earlier ones.

### 1. Workspace v2: source tree and worktree modes

Rethink how code gets into the container. Add `--worktree` for
Cursor-like local development (agent works in a sibling worktree
bind-mounted into the container) and `--source-dir` for multi-repo
tasks (user's `~/src/work` mounted read-only, agent clones repos
on demand into a podman volume).

This is foundational -- review, push, and multi-repo support all
build on the workspace infrastructure.

See [workspace-v2.md](../todo/workspace-v2.md).

### 2. Review and push (lightweight review)

Build the review and push layer on top of workspace-v2. Pod-api
owns all git push operations using GH_TOKEN; the agent never gets
push credentials. Three modes: autonomous (headless draft PR),
interactive (human review gate in the web UI), and fully interactive
(IDE + agent handoff).

Depends on workspace-v2 for the dual-workspace trust model and
multi-repo volume layout.

See [lightweight-review.md](../todo/lightweight-review.md).

### 3. Bot/assistant accounts and credential management

Replace static PATs with OAuth2 "on behalf of user" authentication
via GitHub Apps, GitLab Applications, etc. Proper credential
storage, token refresh, and user attribution. This improves the
credential story for both review/push and service-gator.

See [bot-assistant-accounts.md](../todo/bot-assistant-accounts.md).

### 4. Subagent containers

Let the agent dynamically spawn subagent containers on demand via
MCP tools. Each subagent gets its own git clone or worktree on a
dedicated branch; commits merge back via `subagent_merge`. Replaces
the current static worker container approach.

See [subagent-container.md](../todo/subagent-container.md).

### 5. LLM credential isolation

Proxy container between agent pods and LLM providers to centralize
API key management and prevent key exfiltration from compromised
agents. Agents receive only `OPENAI_BASE_URL` pointing at the proxy.

See [openai-compat-proxy.md](../todo/openai-compat-proxy.md).

## Future / Ideas

These are larger features under consideration without a fixed
ordering. Some have design docs, others are rough ideas.

- **Kubernetes support**: Use kube-rs to create pods on k8s clusters.
  Three deployment models (devaipod-in-k8s, spawn-to-cluster,
  hybrid). See [kubernetes.md](../todo/kubernetes.md).
- **Local Forgejo instance**: Git caching, local CI/CD, and code
  review UI. Deferred in favor of the lightweight review approach
  for now. See [forgejo-integration.md](../todo/forgejo-integration.md).
- **Advisor agent**: Long-running read-only observer that proposes
  tasks for human approval based on GitHub issues and pod health.
  See [advisor.md](../todo/advisor.md).
- **Dynamic port forwarding**: Forward ports from running pods
  without restart, via `podman exec` TCP relay.
  See [dynamic-port-forwarding.md](../todo/dynamic-port-forwarding.md).
- **Quadlet/systemd integration**: Generate Quadlet units for
  proper lifecycle management.
- **Devcontainer features support**: Install devcontainer features
  into the workspace image.
- **Nested devaipods**: MCP tool for agents to spawn additional
  sandboxed environments.
- **Persistent agent state**: Named volumes for agent home across
  pod restarts.

## Testing

- **Web UI integration tests**: Playwright-based browser testing of
  git review, pod switching, and gator scope UI against real pods.
  See [integration-web.md](../todo/integration-web.md).
- **Test performance**: Improving CI speed (~243s for 65 tests).
  See [test-performance.md](../todo/test-performance.md).

## Known Limitations

- **Agent requires opencode in the image**: The agent container runs
  `opencode serve`, so opencode must be in the devcontainer image.
- **Lifecycle commands only run in workspace**: `onCreateCommand`
  etc. run in the workspace container, not the agent container.
- **Single agent type**: Only opencode is currently tested.

## Design Document Index

All `docs/todo/` documents, grouped by theme:

**Workspace and git:**
[workspace-v2.md](../todo/workspace-v2.md),
[lightweight-review.md](../todo/lightweight-review.md),
[forgejo-integration.md](../todo/forgejo-integration.md)

**Pod-api and control plane:**
[pod-api-driver.md](../todo/pod-api-driver.md),
[minimize-injection.md](../todo/minimize-injection.md),
[per-pod-gateway-sidecar.md](../todo/per-pod-gateway-sidecar.md) (done),
[rust-sidecar-monitoring.md](../todo/rust-sidecar-monitoring.md) (superseded)

**Agent execution model:**
[subagent-container.md](../todo/subagent-container.md),
[advisor.md](../todo/advisor.md)

**Credentials and security:**
[bot-assistant-accounts.md](../todo/bot-assistant-accounts.md),
[openai-compat-proxy.md](../todo/openai-compat-proxy.md)

**UI and frontend:**
[ui.md](../todo/ui.md),
[opencode-webui-fork.md](../todo/opencode-webui-fork.md),
[integration-web.md](../todo/integration-web.md)

**Infrastructure:**
[kubernetes.md](../todo/kubernetes.md),
[dynamic-port-forwarding.md](../todo/dynamic-port-forwarding.md),
[test-performance.md](../todo/test-performance.md)

**Ideas and backlog:**
[ideas.md](../todo/ideas.md)
