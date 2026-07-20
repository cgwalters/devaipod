# Sandboxed Agent Infrastructure

This document describes a rearchitecture of the devaipod project from a
monolithic control plane into a decomposed infrastructure stack for managing
sandboxed AI coding agents. The system gives a human operator full control over
what agents can access, where they push code, and how that code is reviewed
before reaching production forges.

> 🤖 Assisted-by: OpenCode (Claude Opus 4)

## Part 1: Goals and Operating Model

### The problem

AI coding agents need broad access to be useful — LLM APIs, git forges, issue
trackers, package registries — but granting that access directly is dangerous.
A prompt injection, a misbehaving agent, or a simple bug can push malicious
code, exfiltrate credentials, or burn through API quotas. Today's approach
(devaipod) addresses this with per-pod sandboxing, but it bundles too many
concerns into one project: container orchestration, a web UI, ACP protocol
implementation, service-gator sidecar management, git workspace isolation, and
agent lifecycle — all in a single Rust binary.

### The goal

A human operator manages a fleet of sandboxed AI agents that:

1. **Never hold real credentials.** Agents access LLM APIs through a proxy
   (llmproxy) and git forges through a scoped MCP server (service-gator).
   They never see the human's GitHub PAT, API keys, or SSH keys.

2. **Push code only to a staging forge.** Agents have write access to a
   staging forge instance (self-hosted Forgejo, or a private GitHub org).
   They cannot push to production forges directly.

3. **Human reviews before promotion.** The human reviews agent work in the
   staging forge and explicitly promotes it to production forges. This is
   deterministic git plumbing, not AI — the promotion path is trusted and
   auditable.

4. **Orchestration is pluggable.** For multi-agent workflows (roles, budgets,
   conventions, heartbeats), the system integrates with an orchestration layer
   (BotMinter/Ralph, Paperclip, or direct CLI). For simple "launch an agent
   on this repo" use cases, the system works standalone.

5. **Tool injection is agent-agnostic.** MCP servers (service-gator, Forgejo,
   etc.) are bridged to agents via ACP sidecars, so the same tools work
   regardless of whether the agent is OpenCode, Claude Code, Gemini CLI,
   Codex, or any other coding agent.

### Trust model

The system operates across two trust domains:

**Human domain** (holds real credentials):
- LLM API keys (OpenAI, GCP Vertex, Anthropic)
- GitHub/GitLab PATs
- Forgejo admin credentials
- SSH keys

**Agent domain** (proxied access only):
- LLM access via llmproxy URL — agents send OpenAI-format requests; the
  proxy translates and routes to backends. No raw API keys in the agent
  environment.
- Forge access via service-gator MCP — agents call MCP tools scoped to
  specific repos and operations. The agent never sees the underlying PAT.
- Git push access to the staging forge only — low-privilege credentials
  for a local or private-org forge. Even if leaked, the blast radius is
  contained.

On Linux, these trust domains map to separate OS users (human user and `ai`
user), with `sudo machinectl shell ai@` providing a controlled boundary
crossing. The human user can also run the system as a single user — in that
case, Kubernetes namespaces or podman network isolation provide the
separation.

### The staging forge

Agents push to a staging forge; humans promote to production. The staging
forge can be either:

- **Self-hosted Forgejo** — no external dependency, no API rate limits, no
  cost, works air-gapped. The control plane provisions per-agent tokens and
  manages the Forgejo lifecycle. This is the default.

- **Private GitHub org** — for users who prefer GitHub's UI and already
  have an org available. Each agent can get its own GitHub App identity
  within the org (the BotMinter model). No additional infrastructure
  needed, but requires a GitHub account and network access.

Both models share the same promotion workflow: the human reviews in the
staging forge, then deterministic git operations push approved work to
production forges.

### The code promotion workflow

This is the critical human-in-the-loop step that ensures agent output is
reviewed before reaching production:

1. Agent works on a task inside a sandboxed container.
2. Agent pushes commits to a repo on the staging forge.
3. Human uses the review TUI/CLI to inspect what agents have done:
   diffs, commit logs, branch state across staging repos.
4. Human promotes approved work to a production forge (GitHub, GitLab,
   Codeberg, any remote git forge). Promotion creates branches and/or
   PRs on the target forge using the human's credentials.
5. Promotion is deterministic — it is git operations and forge API calls,
   not AI. The promotion service evolved from the aipproval-forge project,
   which already implements `/ok`-command-triggered sync from Forgejo to
   GitHub.

The key property: agents write to a staging area, and the human
decides what leaves that staging area.


## Part 2: Architectural Components

The system is composed of independent services that communicate over the
network. Each can be deployed, upgraded, and debugged independently. The
control plane container ties them together.

### Overview

```
┌──────────────────────────────────────────────────────────────┐
│  HOST                                                        │
│  ┌────────────────┐                                          │
│  │ devaipod shim  │ thin CLI binary, proxies to control      │
│  │ (host binary)  │ plane via Connect RPC                    │
│  └───────┬────────┘                                          │
│          │ Connect RPC (HTTP+JSON / gRPC)                    │
│          ▼                                                   │
│  ┌──────────────────────────────────────────────────────┐    │
│  │  Control Plane Container (privileged)                 │    │
│  │  - devaipod service (Rust, axum + connect-rust)       │    │
│  │  - manages all other containers via podman socket     │    │
│  │  - exposes Connect RPC API                            │    │
│  │                                                       │    │
│  │  Manages:                                             │    │
│  │  ┌───────────┐ ┌──────────────┐ ┌────────┐           │    │
│  │  │ llmproxy  │ │service-gator │ │Forgejo │           │    │
│  │  │           │ │   (MCP)      │ │        │           │    │
│  │  └───────────┘ └──────────────┘ └────────┘           │    │
│  │  ┌──────────────────────────────┐                     │    │
│  │  │ Orchestration (optional)     │                     │    │
│  │  │ BotMinter, Paperclip, or    │                     │    │
│  │  │ direct CLI                   │                     │    │
│  │  └──────────────────────────────┘                     │    │
│  │  ┌──────────────────────────────────────────┐         │    │
│  │  │ Agent Pod(s)                              │         │    │
│  │  │ ┌────────────┐  ┌──────────────────────┐ │         │    │
│  │  │ │ ACP sidecar│  │ Agent container      │ │         │    │
│  │  │ │ (MCP→ACP   │◄─│ (opencode, claude,   │ │         │    │
│  │  │ │  bridge)   │  │  goose, etc.)        │ │         │    │
│  │  │ └──────┬─────┘  └──────────────────────┘ │         │    │
│  │  │        │ connects to llmproxy,            │         │    │
│  │  │        │ service-gator, Forgejo           │         │    │
│  │  └────────┼──────────────────────────────────┘         │    │
│  └───────────┼──────────────────────────────────────────┘    │
└──────────────┼───────────────────────────────────────────────┘
               ▼
      llmproxy, service-gator, Forgejo (network access)
```

### Component 1: Host shim (`devaipod` binary)

A thin Rust binary installed on the host. Its only job is to bootstrap the
control plane container and proxy commands into it.

**Responsibilities:**
- On first run: pull and launch the control plane container (privileged,
  with the host podman socket bind-mounted). On macOS, use the Docker
  socket instead.
- Translate CLI commands into Connect RPC calls to the control plane.
- Provide the review/sync TUI for inspecting and promoting agent work
  from the staging forge to production forges. The shim fetches diffs and
  branch state from the control plane (which talks to the staging forge),
  but the actual promotion (git push to production forge, PR creation)
  happens inside the control plane container, which holds the necessary
  credentials. The shim renders the TUI; the control plane does the work.
- On Linux, support `machinectl shell ai@` for crossing the user boundary
  when running in two-user mode.
- On Linux, deploy services as systemd quadlets (podman-native systemd
  integration). On macOS, run as regular containers with auto-launch on
  CLI invocation.

**What it does NOT do:** Container management, agent lifecycle, or direct
credential handling. All of that is delegated to the control plane. The
shim is a presentation layer and bootstrap tool.

### Component 2: Control plane container

The core of the system. A Rust service (axum + anthropics/connect-rust)
running inside a privileged container with access to the host's container
runtime (podman socket).

**Connect RPC API surface:**

```protobuf
service ControlPlane {
  // Stack lifecycle
  rpc Setup(SetupRequest) returns (SetupResponse);
  rpc Status(StatusRequest) returns (StatusResponse);
  rpc Teardown(TeardownRequest) returns (TeardownResponse);

  // Service management
  rpc ListServices(ListServicesRequest) returns (ListServicesResponse);
  rpc RestartService(RestartServiceRequest) returns (RestartServiceResponse);

  // Direct agent launch (no orchestrator)
  rpc RunAgent(RunAgentRequest) returns (stream RunAgentEvent);
  rpc ListAgentPods(ListAgentPodsRequest) returns (ListAgentPodsResponse);
  rpc AttachAgentPod(AttachAgentPodRequest) returns (stream AttachEvent);
  rpc StopAgentPod(StopAgentPodRequest) returns (StopAgentPodResponse);

  // Agent pod lifecycle (for orchestrator adapters)
  rpc CreateAgentPod(CreateAgentPodRequest) returns (CreateAgentPodResponse);
  rpc StreamAgentLogs(StreamAgentLogsRequest) returns (stream LogEntry);
  rpc DestroyAgentPod(DestroyAgentPodRequest) returns (DestroyAgentPodResponse);

  // Review/sync (staging forge -> production forges)
  rpc ListPendingReviews(ListPendingReviewsRequest)
      returns (ListPendingReviewsResponse);
  rpc ReviewDiff(ReviewDiffRequest) returns (stream ReviewDiffChunk);
  rpc Promote(PromoteRequest) returns (PromoteResponse);
}
```

This API is the single interface for all callers: the host shim (via Connect
RPC), orchestrator adapters (via HTTP+JSON — Connect's JSON mode means no
gRPC client needed in TypeScript or other languages), and any future web UI.

**Container lifecycle responsibilities:**
- Resolve devcontainer.json from a repo to determine the agent image.
  Pre-built images only — no local container builds in the hot path.
  If a devcontainer.json specifies a `build` section rather than an
  `image`, the control plane looks for a pre-built image in a
  configured registry (convention: the repo's CI publishes devcontainer
  images). If no pre-built image is found, the control plane falls back
  to a configurable default image and logs a warning.
- Pull images from registries.
- Create agent pods: an agent container + an ACP sidecar container sharing
  a network namespace.
- Inject environment variables: `LLMPROXY_URL`, `SERVICE_GATOR_URL`,
  `FORGEJO_URL`, agent-specific configuration.
- Mount workspace volumes (git clones of staging forge repos).
- Stream container logs.
- Clean up containers on exit or timeout.

**Container backend abstraction:**
The control plane abstracts over two backends behind a Rust trait:

```rust
trait ContainerBackend: Send + Sync {
    async fn create_pod(&self, config: PodConfig) -> Result<PodId>;
    async fn stream_logs(&self, id: &PodId) -> Result<impl Stream<Item = LogLine>>;
    async fn wait(&self, id: &PodId) -> Result<ExitStatus>;
    async fn destroy(&self, id: &PodId) -> Result<()>;
    async fn exec(&self, id: &PodId, cmd: &[&str]) -> Result<ExecHandle>;
}
```

- `PodmanBackend`: uses the podman API via the bollard crate (reused from
  current devaipod). For local/single-machine deployments.
- `KubeBackend`: uses kube-rs. For Kubernetes deployments. In the k8s model,
  agent pods go in an `agents` namespace with RBAC and NetworkPolicy
  restricting access to the `infra` namespace where llmproxy, service-gator,
  and the staging forge run.

### Component 3: ACP sidecar

A Rust binary extracted from devaipod's existing `pod_api.rs` and
`acp_client.rs`. Runs as a sidecar container in each agent pod, sharing the
agent container's network namespace.

**Purpose:** Bridge MCP servers to agents via ACP, making tool injection
agent-agnostic. The agent discovers tools through ACP session negotiation,
not through runtime-specific config files (`.mcp.json`, environment
variables, etc.).

**How it works:**
1. On startup, connects to configured MCP servers (service-gator, Forgejo
   MCP, any additional MCP servers specified in the pod config).
2. Spawns the agent process inside the agent container using
   `podman exec -i` (podman backend) or `kubectl exec -i` (k8s backend),
   communicating via ACP over the exec'd process's stdin/stdout. This is
   the same mechanism devaipod uses today — the sidecar and agent share a
   network namespace but run as separate containers, and exec provides the
   stdio pipe.
3. Exposes MCP tools as ACP capabilities to the agent.
4. The agent interacts with external services through ACP without knowing
   about MCP server URLs or credentials.

**What it replaces:** devaipod's current pod-api sidecar, but stripped down
to just the ACP/MCP bridging. No web UI serving, no git endpoints, no PTY
management. Those concerns are handled elsewhere (orchestrator UI, staging
forge, the control plane's Attach RPC).

### Component 4: llmproxy (existing, deploy as-is)

A lightweight HTTP proxy that accepts OpenAI-format API requests and routes
them to backend providers (OpenAI, GCP Vertex AI, Anthropic). Model routing
is glob-based (first match wins).

**Role in this system:** Agents inside containers set
`OPENAI_BASE_URL=http://llmproxy:<port>/v1` (the port is configured at
deployment time; llmproxy defaults to 8080) and never see raw API keys.
llmproxy holds the real credentials and handles authentication translation
(e.g., GCP OAuth token refresh for Vertex AI).

**Deployment:** Long-lived shared service, bound to a well-known port. One
instance serves all agents. Written in Rust, existing project
(github.com/LobsterTrap/llmproxy).

### Component 5: service-gator (existing, deploy as-is)

An MCP server providing scope-restricted access to GitHub, GitLab, Forgejo,
and JIRA. Agents connect via MCP and can only perform operations allowed by
the scope configuration.

**Role in this system:** The ACP sidecar connects to service-gator and
exposes its tools to agents. The human configures scopes per-agent or
per-task (e.g., read-only access to upstream repos, push-new-branch on
forks, create-draft on upstream). service-gator holds the real PATs.

**Key feature for this architecture:** service-gator supports `--scope-file`
with live reload via inotify. The control plane can dynamically update
scopes by writing a new config file, and service-gator picks up the change
immediately. This enables per-agent scope customization without restarting
the service.

**Deployment:** Long-lived shared service, bound to a well-known port. One
instance serves all agents. Written in Rust, existing project
(github.com/LobsterTrap/service-gator).

### Component 6: Staging forge (Forgejo or private GitHub org)

The staging area for all agent work. Agents push code here; the human
reviews and promotes.

**Role in this system:**
- Agents have write-access credentials to staging forge repos. These are
  provisioned per-agent: the control plane creates a Forgejo user (or
  access token scoped to specific repos) for each agent pod at launch
  time, and injects the credentials as environment variables. Tokens are
  revoked when the pod is destroyed.
- The promotion module (in the control plane) mirrors upstream repos into
  the staging forge so agents can clone and work on them.
- Agent commits land on branches. The human reviews diffs in the review
  TUI and promotes approved work to production forges.

**Deployment:** Long-lived service. For Forgejo, runs as the human user
(or in the infra namespace in k8s). For private GitHub org, no deployment
needed — the org already exists.

### Component 7: Promotion service

Deterministic git sync between the staging forge and production forges.
Evolved from aipproval-forge's sync logic (`core/sync.rs`,
`forgejo-mirror` crate, `/ok` command handling).

**Responsibilities:**
- Mirror upstream repos into the staging forge (using Forgejo's migration
  API or GitHub's fork API).
- On human command (CLI, `/ok` comment on staging forge, or TUI action):
  fetch agent branches, push to the target production forge, and
  optionally create a PR/MR.
- Forge-agnostic: supports any remote git forge as a destination. Uses
  forge APIs (GitHub, GitLab, Forgejo/Gitea) for PR/MR creation; raw git
  for the actual push.

**What it is NOT:** This is not AI. There is no LLM in the loop. This is
trusted, auditable git plumbing.

**Implementation:** Rust. Reuses aipproval-forge's `forgejo-client` and
`forgejo-mirror` crates. Runs as a module within the control plane
container — this keeps credential management centralized (the control
plane already holds forge credentials) and avoids another independent
service to deploy and monitor. The promotion RPCs (`ListPendingReviews`,
`ReviewDiff`, `Promote`) on the control plane's Connect API are the
interface to this module.

### Component 8: Orchestration layer (pluggable)

For multi-agent orchestration — roles, conventions, team coordination,
budgets, quality gates — the system integrates with an external
orchestrator. This is pluggable; the control plane API is the integration
surface.

The orchestrator calls the control plane's Connect RPC API to create,
monitor, and destroy agent pods. The control plane doesn't know or care
which orchestrator is driving it.

**Without an orchestrator:** The `devaipod run` CLI command talks directly
to the control plane's `RunAgent` RPC. Same container lifecycle, same ACP
sidecar, same tool injection — just without orchestration wrapping it.
This is the "quick launch" path for interactive use.

See Part 3 for detailed analysis of orchestration options.

### Deployment models

**Single-user, local podman (simplest):**
All services run as containers managed by the control plane container. The
host shim launches the control plane, which pulls and starts everything
else. Isolation is via podman networks and secrets. Suitable for a single
developer on a workstation.

**Two-user, Linux (strongest isolation):**
Human-side services (llmproxy, service-gator, staging forge, promotion
service) run under the human user as systemd quadlets. The orchestrator and
agent pods run under the `ai` user. The host shim uses
`machinectl shell ai@` to cross the boundary. The `ai` user never sees
human credentials.

**Kubernetes (scalable, single or multi-user):**
Two namespaces: `infra` (human-side services, real Secrets) and `agents`
(orchestrator, agent pods). RBAC restricts the `agents` ServiceAccount from
accessing `infra` Secrets. NetworkPolicy controls which services agents
can reach. The control plane uses the `KubeBackend` to create agent pods.
Works with any k8s distribution, including local ones (minikube, kind,
k3s).

### Technology choices

| Concern | Choice | Rationale |
|---------|--------|-----------|
| Control plane language | Rust | Reuses devaipod's existing container management code. Type safety matters for security-critical infrastructure. |
| Control plane RPC | Connect RPC (anthropics/connect-rust) | gRPC + HTTP/JSON + gRPC-Web from one server. Tower-based, integrates with axum. Clients can use curl, browsers, or typed gRPC clients. |
| Control plane HTTP framework | axum | Already used by devaipod. connect-rust has native axum integration. |
| Container API | bollard (podman) / kube-rs (k8s) | bollard is already used by devaipod for podman. kube-rs is the standard Rust k8s client. |
| Agent protocol | ACP (Agent Client Protocol) | Agent-agnostic tool injection. MCP servers are bridged to agents via ACP sidecars. Already implemented in devaipod. |
| Tool protocol | MCP (Model Context Protocol) | service-gator already speaks MCP. The ACP sidecar bridges MCP to agents. |
| Review TUI | Rust (ratatui) | Runs on the host, needs to be fast and responsive for reviewing diffs. |
| Promotion service | Rust | Reuses aipproval-forge crates. Deterministic, no AI dependencies. |

### Relationship to existing projects

| Project | Disposition |
|---------|-------------|
| **devaipod** (current) | Decomposed. Container lifecycle code (`pod.rs`, `podman.rs`, `devcontainer.rs`) is refactored into the control plane service. ACP code (`pod_api.rs`, `acp_client.rs`) is extracted into the standalone sidecar binary. Host shim (`crates/host-shim/`) is rewritten as a Connect RPC client. The SolidJS web UI is dropped — the orchestrator provides agent management UI when deployed; the review TUI and `devaipod status` cover the standalone case. |
| **service-gator** | Deploy as-is. No changes needed. |
| **llmproxy** | Deploy as-is. No changes needed. |
| **aipproval-forge** | Promotion logic extracted and evolved. `forgejo-client`, `forgejo-mirror` crates reused. Orchestrator/agent-spawning code replaced by the control plane. |
| **OpenShell** | Not adopted at this time. OpenShell's deep security model (landlock, seccomp, network policy, binary identity) is compelling but it currently lacks devcontainer support and MCP/ACP integration. Revisit when it matures. The control plane's `ContainerBackend` trait could gain an OpenShell backend in the future. |


## Part 3: Orchestration Options

The control plane provides sandboxed agent execution. An orchestration
layer decides *what* agents work on, *how* they coordinate, and *what
conventions* they follow. Three projects are strong candidates.

A key architectural insight: the orchestrator language doesn't matter
much, because it runs *inside the container*, not on the host. The host
shim is a thin Rust binary. The control plane is Rust. But the agent
container image can include whatever tools the task needs — including
a Go or Rust orchestrator binary alongside the coding agent. The
control plane creates the container, injects config, and lets the
orchestrator take over inside.

### BotMinter / Ralph Orchestrator

**Source:** github.com/botminter/botminter (team management CLI),
github.com/botminter/ralph-orchestrator (single-agent loop orchestrator).
Both Rust, Apache-2.0. Pre-alpha (v0.2.0).

**What it does:** BotMinter manages *teams* of coding agents — hiring
agents into roles (architect, developer, QE), applying layered conventions,
and coordinating via forge issues. Ralph Orchestrator runs the inner loop
for each agent: a persistent event-driven iteration cycle where the agent
wears different "hats" (behavioral personas) across iterations.

**Agent support:** Ralph already supports 10 named backends (Claude,
Gemini, Codex, OpenCode, Amp, Copilot, Roo, Kiro, Pi) plus a `custom`
backend for any CLI tool. Backends are swappable per-hat — you can have
Claude do architecture while Gemini does testing. All prompts are plain
Markdown; events are CLI commands (`ralph emit`) writing JSONL files. No
agent-specific protocol dependencies.

**Key architectural features:**

*Formation trait.* BotMinter's pluggable deployment abstraction. 11 methods
covering environment setup, credential delivery, member lifecycle, and
topology writing. Only `LinuxLocalFormation` (bare process) and Lima VM are
implemented; k8s is scaffolded in the data model (`Endpoint::K8s` variant
with namespace, pod, container, context fields) but has no working
implementation. This maps directly to our `ContainerBackend` trait — a
`ContainerFormation` backed by devaipod's Connect RPC API is the natural
integration point.

*Profile / Knowledge / Invariant system.* Profiles are methodology
templates (`scrum-compact`, `agentic-sdlc-minimal`) that stamp out role
definitions, process docs, and conventions. Knowledge files provide
guidance at four scoping levels (team → project → member →
member+project), all additive. Invariants are hard constraints agents must
obey (e.g., "all state-mutating commands must be idempotent"). This is
team governance infrastructure that doesn't exist in any other
orchestrator we've evaluated.

*Hat-based quality gates.* Ralph chains hats via pub/sub events with
backpressure: Builder → Devil's Advocate → Slop Detector. Event payloads
are validated (test results, coverage thresholds). Thrashing detection
abandons tasks after 3 consecutive failures. This is more sophisticated
than simple polling for ensuring output quality.

*Per-agent GitHub App identity.* Each agent gets its own bot identity via
the GitHub App Manifest Flow — own commit attribution, scoped tokens,
audit trail. For our architecture, this could be adapted to Forgejo
tokens or preserved as-is for private-GitHub-org staging.

**Forge coupling:** GitHub is baked into the coordination fabric — Projects
v2 GraphQL, status labels, App Manifest Flow, daemon polling GitHub Events
API. All concentrated in the `git/` module (~2,500 lines). Replacing this
with Forgejo API calls or abstracting behind a forge trait is bounded but
non-trivial work.

**Integration path with devaipod:**
1. Implement `ContainerFormation` backed by the control plane's Connect
   RPC API. This is the cleanest integration — Ralph runs inside the
   container, BotMinter calls the control plane to create/destroy pods.
2. Replace or abstract the `git/` module for Forgejo support, or support
   both Forgejo and private GitHub org as staging backends.
3. Adapt credential delivery: the control plane provisions per-agent
   staging forge tokens and delivers them into the container at launch.

**Strengths:**
- Rust — same language, significant dependency overlap (axum, tokio, clap,
  serde, ACP schema), potential for code sharing or even workspace
  integration
- Formation trait is architecturally ready for container backends
- Ralph's agent-agnosticism is genuine — 10 backends, plain-text prompts,
  CLI-based event protocol
- Knowledge/invariant system provides team governance without equivalent
  in other orchestrators
- Each iteration is a fresh subprocess — no persistent session state to
  manage across container restarts

**Weaknesses:**
- Pre-alpha with small team — risk of direction divergence
- GitHub coupling in the coordination layer requires significant work
  to support Forgejo
- Full multi-role team (dev, QE, reviewer) is still future work
- Less mature multi-agent coordination than Paperclip (no budgets,
  structured approvals, or org charts)

### Paperclip

**Source:** github.com/paperclipai/paperclip. TypeScript/Node.js,
PostgreSQL. Pre-production but more mature than BotMinter.

**What it does:** A centralized multi-agent management platform. A server
with a database, web UI, and adapter system. It schedules agent "runs" by
spawning CLI subprocesses, collecting output, and storing results. Agents
work on "issues" (Paperclip's own task system) through an explicit
lifecycle state machine.

**Agent support:** 6 adapters — Claude, Codex, Gemini, OpenCode, Cursor,
OpenClaw. Each adapter knows how to spawn and communicate with its
agent's CLI. Session resume across runs is supported (the adapter stores
session IDs and re-passes `--resume` on subsequent invocations).

**Key architectural features:**

*Forge-agnostic coordination.* Paperclip has its own internal issue/task
system in PostgreSQL. It does not use GitHub Issues or any forge-specific
coordination fabric. Issues go through `backlog → todo → in_progress →
in_review → done`. This is a meaningful advantage — the orchestration
layer is genuinely independent of which forge agents use.

*Execution policies.* Issues have ordered stages (review, approval) with
designated participants. Each stage gates the next. This provides
structured human-in-the-loop controls at the task level.

*Budget enforcement.* Agents have monthly cost budgets with hard/soft
thresholds. Exceeding the budget auto-pauses the agent. Budget incidents
require human resolution.

*Org charts and delegation.* Agents have `reportsTo` chains forming a
hierarchy. Issues have parent-child relationships. This models real team
structures.

*Web UI.* Full dashboard with issue boards, run transcripts, cost
tracking, activity feeds, and agent detail pages.

**Execution model:** Ephemeral subprocess per run. Each "run" spawns the
agent CLI, sends a prompt, waits for completion (or `maxTurnsPerRun`), and
exits. Between runs, all state is in PostgreSQL. The heartbeat scheduler
periodically wakes agents — there is no persistent agent process.

**Integration path with devaipod:**
A `container_sandbox` adapter in Paperclip's adapter system
(`packages/adapters/container-sandbox/`). On each heartbeat:
1. Adapter makes HTTP+JSON POST to the control plane's `CreateAgentPod`
   RPC.
2. Control plane creates the agent pod with the right image, volumes,
   env vars, and ACP sidecar.
3. Adapter streams logs from `StreamAgentLogs`.
4. On completion or timeout, adapter calls `DestroyAgentPod`.

The adapter is thin (~200-300 lines of TypeScript).

**Strengths:**
- Forge-agnostic — own issue system, doesn't depend on any forge for
  coordination
- Most mature multi-agent coordination (budgets, approvals, org charts,
  execution policies)
- Full web UI for management and monitoring
- Session resume across ephemeral runs
- Skill injection via content-addressed prompt bundles

**Weaknesses:**
- TypeScript — different language ecosystem from our Rust stack
- PostgreSQL dependency
- No deployment abstraction — no equivalent to Formation trait or
  ContainerBackend; all agents are local subprocesses
- Ephemeral run model (spawn/exit/respawn) doesn't map naturally to
  persistent-agent-in-container; each "run" would need to create and
  destroy a container, which is heavier than spawning a process
- Bridging TypeScript adapter ↔ Rust control plane adds integration
  complexity vs. same-language integration

### Gas City

**Source:** github.com/gastownhall/gascity. Go, MIT. v0.14.1, 31
releases, 1,858 commits, ~300K lines (58% tests). Extracted from Steve
Yegge's "Gas Town" — a hardcoded multi-agent system — into a
configurable SDK.

**What it is:** An orchestration-builder SDK, not an opinionated
orchestrator. All role behavior is user-supplied configuration ("packs");
the SDK provides runtime providers, work tracking, reconciliation, and
session management. Gas Town itself becomes one configuration pack among
many possible orchestration shapes.

**Agent support:** Claude, Codex, Gemini, OpenCode, Copilot. Agents are
just command strings run inside sessions. The provider abstraction
doesn't care what the command is.

**Key architectural features:**

*Runtime provider abstraction.* An 18-method `Provider` interface with
conformance tests. Five implementations:

- **tmux** — primary production runtime, full interactive terminal
  sessions (~2,700 lines)
- **subprocess** — lightweight child process, no terminal
- **exec** — script-backed escape hatch following the git credential
  helper pattern (operation name as first arg, JSON on stdin). You can
  write a `gc-session-podman` script and get container support with zero
  Go code
- **ACP** — Agent Client Protocol via JSON-RPC 2.0 over stdio, headless
  agent communication (~830 lines)
- **Kubernetes** — real, production-grade k8s provider using native
  `client-go` (~1,700 lines). Creates pods with tmux inside, handles
  file staging via tar-over-exec, secret mounting, resource limits,
  environment remapping

*Beads work tracking.* Universal persistence substrate backed by Dolt
(MySQL-compatible version-controlled DB). Everything is a bead: tasks,
messages, molecules, convoys. Parent-child relationships, labels, and
pool-based dispatch. More fine-grained than GitHub issues or Postgres
issue tables. Also has file-based and exec-backed store providers for
simpler deployments.

*Formulas, molecules, orders.* Formulas are TOML workflow definitions.
Molecules are runtime instances (bead trees). Orders pair gate conditions
(cooldown, cron, shell condition, event trigger) with actions (exec
scripts or formula instantiation). This is the workflow engine — roughly
analogous to Ralph's hats but declarative TOML rather than code.

*Controller/supervisor.* Erlang/OTP-style reconciliation loop. Dirty
check via fsnotify, config reload, agent list reconciliation (desired vs
running), wisp garbage collection, order dispatch, graceful shutdown with
interrupt→wait→kill. Crash tracking with restart budgets. Machine-wide
supervisor manages multiple cities via `flock`.

*Packs and rigs.* Packs are reusable config directories (agents,
prompts, formulas, orders). Rigs are external project directories with
independent beads, agent hooks, formula layers, and override chains.
Multi-project orchestration is first-class.

*Zero Framework Cognition.* Design principle: Go handles transport, not
reasoning. If Go contains a judgment call, it's a violation. Aligns with
our "sandbox provides infrastructure, agent decides" principle.

**Forge coupling:** None. Forge integration belongs in pack config and
agent prompts, not in Go code. No GitHub/GitLab/Forgejo API calls in
the core.

**Integration path with devaipod:**
Gas City runs *inside* the agent container. The control plane creates
the container with `gc` pre-installed and a `city.toml` injected. Gas
City uses its tmux or ACP provider to manage the coding agent session
locally within the container. It doesn't need its own K8s provider in
this model — the control plane handles container lifecycle externally.

1. Build agent container images with `gc` binary pre-installed.
2. Control plane injects `city.toml` and pack config at container
   creation time.
3. Container entrypoint runs `gc start` which launches the coding
   agent via tmux or ACP provider.
4. The beads exec provider could call back to the control plane's
   Connect RPC API for work assignment if needed.
5. Agent pushes results to the staging forge; control plane handles
   promotion.

This is the thinnest integration surface of the three options: the
control plane doesn't need to understand Gas City's internals, and Gas
City doesn't need to understand the container lifecycle.

**Strengths:**
- Most mature infrastructure — 300K lines, 31 releases, conformance-
  tested provider abstraction, Erlang/OTP-style supervision
- Forge-agnostic like Paperclip
- Real K8s provider proves container-based sessions work (though we'd
  use tmux/ACP inside containers instead)
- ACP provider for headless agent communication
- Clean separation: the orchestrator is a tool in the container image,
  not a host-side dependency
- Packs enable the same layered convention system as BotMinter's
  profiles, but configuration-only (no Go code needed)

**Weaknesses:**
- Go — different language from our Rust stack, though this matters less
  since it runs inside the container
- Dolt dependency for production beads backend (significant operational
  overhead; file-based provider is the lighter alternative)
- `internal/`-only packages — no public SDK API for library use
- No built-in team governance equivalent to BotMinter's knowledge/
  invariant system (though packs could express similar patterns)
- Younger ecosystem around it — Gas Town users are migrating, but the
  community is still forming

### Comparison

| Dimension | BotMinter/Ralph | Paperclip | Gas City |
|---|---|---|---|
| Language | Rust | TypeScript | Go |
| Maturity | Pre-alpha, ~38K lines | Pre-production | v0.14, ~300K lines |
| Forge coupling | High (GitHub) | None | None |
| Deployment abstraction | Formation trait | None | Provider interface (18 methods) |
| Agent backends | 10 via Ralph | 6 adapters | 5+ (any CLI) |
| Team governance | Profiles + knowledge + invariants | Execution policies + budgets | Packs (config-only) |
| Quality gates | Event-validated backpressure | Stage-based approvals | Orders with gate conditions |
| Human interaction | Chat-first (Telegram/Matrix) | Web-first (dashboard) | CLI/TUI |
| Agent loop model | Persistent event loop | Ephemeral subprocess | Reconciliation loop |
| State storage | Filesystem (JSONL) | PostgreSQL | Beads (Dolt or file) |
| K8s support | Scaffolded, not implemented | None | Production-grade |
| ACP support | Via sacp crate | None | Native provider |
| Integration model | Formation→ContainerBackend | Adapter→HTTP→control plane | Binary in container image |

### Assessment

All three projects are complementary to devaipod — they operate at the
orchestration layer while devaipod operates at the execution layer. The
control plane's Connect RPC API can serve any of them.

**Gas City** has the strongest infrastructure: production-grade K8s
provider, conformance-tested provider abstraction, Erlang-style
supervision, and the cleanest integration model (just a binary in the
container image). Its forge-agnosticism and "zero framework cognition"
philosophy align well with our design. The main concerns are the Dolt
dependency (mitigated by the file-based provider) and the lack of
built-in team governance features.

**BotMinter/Ralph** has the strongest agent-loop quality story:
hat-based event chains, backpressure gates, thrashing detection, and the
knowledge/invariant system for team governance. Ralph's 10-backend
agent-agnosticism is proven. The Formation trait maps naturally to our
ContainerBackend. The main risk is pre-alpha maturity and deep GitHub
coupling.

**Paperclip** has the strongest multi-agent management features:
budgets, structured approvals, org charts, web UI. Its forge-agnostic
issue system is genuinely independent. The main cost is operational
complexity (TypeScript + PostgreSQL) and no container deployment
abstraction.

These are not mutually exclusive — they target different audiences and
can layer naturally:

1. **Paperclip** — outer management plane for non-developers. "What
   should agents work on?" Web UI, issue boards, budgets, approvals,
   org charts. Talks to the control plane via HTTP+JSON.
2. **devaipod control plane** — infrastructure layer. "Where do agents
   run safely?" Container lifecycle, credentials, staging forge,
   promotion. Connect RPC API.
3. **Gas City** — inner runtime layer for developers. "How does the
   agent session work?" Runs inside the container, manages the coding
   agent via tmux/ACP provider, reconciliation, formulas, beads.

Paperclip assigns a task → control plane creates a container with `gc`
inside → Gas City manages the coding agent session → agent pushes to
staging forge → human reviews in Paperclip's UI or the review TUI.

Each layer is independently optional. `devaipod run` skips Paperclip. A
bare container with just the coding agent skips Gas City. A developer
who doesn't want a web dashboard uses Gas City + devaipod directly. A
team lead who doesn't care about tmux sessions uses Paperclip + devaipod
and the control plane runs agents without Gas City.

Ralph could also run inside a Gas City session as the agent-loop
orchestrator, or BotMinter's knowledge/invariant patterns could be
expressed as Gas City packs.

The recommended starting point: get the control plane working with
`devaipod run` (no orchestrator). The orchestration layer decision can
be deferred until the core sandbox infrastructure is solid.
