# Related Projects

The AI coding agent space is evolving rapidly. This page compares devaipod to related projects, with emphasis on licensing and cloud dependencies.

For broader context on the state of agentic AI coding tools, see [Thoughts on agentic AI coding as of Oct 2025](https://blog.verbum.org/2025/10/27/thoughts-on-agentic-ai-coding-as-of-oct-2025/).

## Comparison Table

| Project | License | Self-hostable? | Notes |
|---------|---------|----------------|-------|
| **devaipod** | Apache-2.0/MIT | Yes | No cloud services required |
| [Docker AI Sandboxes](https://docs.docker.com/ai/sandboxes/) | Proprietary | Yes | MicroVM isolation, Docker Desktop required |
| [NVIDIA OpenShell](https://github.com/NVIDIA/OpenShell) | Apache-2.0 | Yes | Docker-based sandboxing with gateway control plane, Landlock/seccomp, policy-driven egress |
| [nono](https://nono.sh/) | Apache-2.0 | Yes | OS-level sandboxing (Landlock/Seatbelt), agent-agnostic |
| [OpenHands](https://github.com/All-Hands-AI/OpenHands) | MIT | Yes | Self-hostable, Docker-based |
| [Ambient Code](https://github.com/ambient-code/platform) | MIT | Yes | Kubernetes-native, self-hosted |
| [agent-sandbox](https://github.com/kubernetes-sigs/agent-sandbox) | Apache-2.0 | Yes | Kubernetes CRD for sandboxed agent pods (k8s-sigs) |
| [paude](https://github.com/bbrowning/paude) | MIT | Yes | Podman + OpenShift backends, agent-agnostic |
| [Kortex](https://github.com/kortex-hub/kortex) | Apache-2.0 | Yes | Desktop GUI, AI + container/K8s management, Goose integration |
| [Gastown](https://github.com/steveyegge/gastown) | MIT | Yes | Multi-agent orchestration, no sandboxing |
| [Gyre](https://github.com/jsell-rh/gyre/) | No license | Yes | Built-in forge + agent orchestration platform |
| [Scion](https://github.com/GoogleCloudPlatform/scion) | Apache-2.0 | Yes | Multi-agent orchestration testbed; Docker/Podman/Apple/K8s runtimes, harness-agnostic |
| [gjoll](https://github.com/ondrejbudai/gjoll) | Apache-2.0 | Yes | Cloud VM sandboxes via OpenTofu, credential-injecting reverse proxy |
| [krunai](https://github.com/slp/krunai) | Apache-2.0 | Yes | MicroVM, but not container oriented |
| [Auto-Claude](https://github.com/AndyMik90/Auto-Claude) | AGPL-3.0 | Yes | Desktop app, no sandboxing |
| [Continue](https://github.com/continuedev/continue) | Apache-2.0 | Partial | CLI is local; "Mission Control" cloud is proprietary |
| [SWE-agent](https://github.com/princeton-nlp/SWE-agent) | MIT | Partial | Core is open; [depends on Daytona cloud](https://www.daytona.io/dotfiles/langchain-s-open-swe-runs-on-daytona-here-s-why) for some features |
| [Ona](https://ona.com/) | Proprietary | No | Cloud service, not open source |
| [Cursor](https://cursor.sh/) | Proprietary | No | Commercial product |
| Claude Code Web | Proprietary | No | Anthropic-hosted, sandboxed but not open source |

## Basic Agent Frameworks

These are the "raw" agent tools that devaipod can wrap with sandboxing. They run directly on your machine with full access to your filesystem and credentials.

### OpenCode

[OpenCode](https://github.com/anomalyco/opencode/) is the primary agent framework used by devaipod. Apache-2.0 licensed. It provides a TUI and a server mode that devaipod uses for sandboxed execution.

### Claude Code

[Claude Code](https://docs.anthropic.com/en/docs/claude-code) is Anthropic's official CLI agent. Proprietary, closed source.
Claude Code recently added [builtin sandboxing](https://code.claude.com/docs/en/sandboxing), but container-based isolation is stronger and provides a reproducible environment.

### Gemini CLI

[Gemini CLI](https://github.com/google-gemini/gemini-cli) is Google's agent CLI. Apache-2.0 licensed.

Gemini CLI has a "sandbox" mode using Docker, but **the sandboxing is insufficient for security-conscious use**:

- The sandbox isolates filesystem access, but credentials (API keys, tokens) are still passed into the container environment
- There is no credential scoping—if you give the agent a GitHub token, it has full access to all repos that token can reach
- No network isolation beyond what Docker provides by default
- No fine-grained control over what the agent can do with external services
- No devcontainer.json support—you can't use your project's existing dev environment spec

devaipod addresses these gaps: the agent container has no direct access to your GitHub token; instead, all GitHub operations go through service-gator which enforces scopes (e.g., only draft PRs to a specific repo).

### Goose

[Goose](https://github.com/block/goose) from Block is an extensible AI agent with MCP (Model Context Protocol) support. Apache-2.0 licensed, fully open source, runs locally without builtin sandboxing.

## Orchestration Platforms

### OpenHands

[OpenHands](https://github.com/All-Hands-AI/OpenHands) (formerly OpenDevin) is an open platform for AI software developers. It provides a web interface for managing agent sessions with Docker-based sandboxing. MIT licensed.

OpenHands is a more complete platform with its own web UI. devaipod focuses on CLI-first workflows, devcontainer.json compatibility, and fine-grained credential scoping via service-gator.

### Ambient Code Platform

[Ambient Code Platform](https://github.com/ambient-code/platform) is a Kubernetes-native platform for running AI coding agents. MIT licensed (except for Claude Code), self-hostable.

Ambient Code targets team/organization deployment on Kubernetes. devaipod targets individual developer workstations with zero infrastructure beyond podman. Both projects solve credential scoping—Ambient Code's broker architecture influenced devaipod's service-gator integration.

The devaipod project would like to align more with Ambient Code. A few things:

- [Podman support](https://github.com/ambient-code/platform/issues/431)
- [Image needs to be pluggable](https://github.com/ambient-code/platform/pull/364)
- It's possible to run locally with [minikube](https://minikube.sigs.k8s.io/) or [minc](https://github.com/minc-org/minc) in theory, but this adds some friction

### agent-sandbox (kubernetes-sigs)

(This section is Assisted-by: OpenCode (Claude Opus 4.6), based on source code analysis of the agent-sandbox repository)

[agent-sandbox](https://github.com/kubernetes-sigs/agent-sandbox) is a Kubernetes SIG Apps project (Apache-2.0, Go, `v1alpha1`) that provides a `Sandbox` CRD. Despite the name, it's essentially a "StatefulPod" -- a single Pod + headless Service + optional PVCs with lifecycle management (scheduled shutdown, pause/resume, expiry). Extension CRDs add templates, PVC-style claims, and warm pools for fast allocation. It supports pluggable runtimes (gVisor, Kata) via `runtimeClassName` and has managed NetworkPolicy defaults.

There is no built-in agent framework integration, no git workflow, no credential scoping, and no devcontainer.json support. It's infrastructure plumbing, not an agent execution environment.

devaipod's Kubernetes support could optionally target agent-sandbox as the underlying pod abstraction, with devaipod defining the multi-container layout (workspace + agent + gator + api) and service-gator providing credential scoping that agent-sandbox lacks. The warm pool mechanism is the most interesting piece -- pre-provisioning sandboxes for fast allocation is worth considering.

### paude

Following is Assisted-by: OpenCode (Opus 4.5)

[paude](https://github.com/bbrowning/paude) is a Python CLI that runs AI coding agents (Claude Code, Cursor CLI, Gemini CLI) inside secure containers. MIT licensed. It has a pluggable backend architecture with both Podman and OpenShift implementations, making it the closest existing project to what devaipod is trying to do with Kubernetes support.

The OpenShift backend is particularly interesting as prior art for devaipod's [Kubernetes plans](../todo/kubernetes.md). paude's approach:

- Uses `oc` CLI (subprocess) rather than a native Kubernetes client library. devaipod plans to use kube-rs instead, avoiding subprocess overhead and output parsing.
- Creates StatefulSets (not bare Pods) for workspace lifecycle, with scale-to-zero for stop/start. devaipod's pod model maps more naturally to bare Pods since each workspace is a multi-container pod with a specific lifecycle.
- Uses `oc exec` stdin/stdout tunneling with git's `ext::` protocol for code sync -- the agent makes commits inside the pod, and `git pull` tunnels through `oc exec`. This sidesteps the port-forward fragility problem entirely. devaipod should consider this pattern for Model 3 (hybrid local/remote).
- Credentials go into a tmpfs `emptyDir` volume (RAM-only, never persisted), synced via `oc cp`. This is a stronger security posture than writing credentials to a PVC.
- Network egress filtering uses a squid proxy container for Podman and Kubernetes NetworkPolicy for OpenShift, similar in spirit to how devaipod isolates agent network access via service-gator -- though service-gator operates at the API level rather than the network level.

Key differences from devaipod: paude is agent-agnostic (wraps Claude Code, Cursor, Gemini CLI) while devaipod integrates deeply with OpenCode. paude has no devcontainer.json support and uses a single container per session rather than devaipod's multi-container pod (workspace + agent + gator + api). paude has no credential scoping equivalent to service-gator -- network-level filtering is a blunter instrument than API-level scoping.

The git-over-exec-tunnel pattern is worth stealing for devaipod's hybrid model. And paude's tmpfs credential storage is a good security practice that devaipod should adopt when running in Kubernetes.

### Kortex

(This section is 85% Opus 4.6+OpenCode research, only superficial human review)

[Kortex](https://github.com/kortex-hub/kortex) is an Electron/Svelte desktop application for AI-powered container and Kubernetes management. Apache-2.0 licensed, evolved from [Podman Desktop](https://github.com/podman-desktop/podman-desktop).

Kortex occupies a different niche than devaipod: rather than sandboxing AI agents, it provides a desktop GUI that integrates AI with container and Kubernetes management. It has a pluggable "flow provider" abstraction, with [Goose](https://github.com/block/goose) as the current implementation. Goose is downloaded and spawned as a CLI subprocess (`goose run --recipe <path>`); the flow provider interface is generic enough that other agents could be plugged in via extensions.

Interesting aspects of the Goose integration:

- **MCP passthrough**: When creating a flow, users select from MCP servers registered in Kortex. Credentials are retrieved from secure storage and embedded into the Goose recipe YAML as `extensions` with `streamable_http` URIs and auth headers. This is a form of credential management, though not scoped per-operation like service-gator.
- **GUI on top of Goose**: Kortex adds a full web UI for flow creation (with AI-assisted parameter extraction from prompts), execution (xterm.js terminal streaming Goose stdout/stderr), and Kubernetes deployment (generates Job + Secret + ConfigMap YAML).
- **K8s deployment**: Flows can be deployed as Kubernetes Jobs running a hardcoded `quay.io/kortex/goose` container image (built externally in [packit/ai-workflows](https://github.com/packit/ai-workflows/tree/main/goose-container)) with the recipe mounted via ConfigMap. The image is not user-configurable. The Job is minimal: single container, no sidecars, no resource limits, no security context.
- **Chat-to-flow export**: Users can export chat conversations (powered by inference providers like Gemini) into Goose recipes, bridging interactive AI chat with automated workflows.

Key differences from devaipod:

- **No agent sandboxing**: Goose runs locally as a bare `child_process.spawn()` with full host access. No container wrapping for local execution at all.
- **No devcontainer/devfile support**: Kortex has no concept of devcontainer.json or devfiles. The execution environment is either the host (local) or a hardcoded container image (K8s). Users cannot define or customize the runtime environment.
- **Hardcoded image**: The K8s deployment image (`quay.io/kortex/goose:2025-09-03`) is a compile-time constant with no user override. The image just contains the goose binary; there's nothing else special in it.
- **GUI-first vs CLI-first**: Desktop application vs terminal tool.
- **AI manages infrastructure**: Kortex uses AI to help manage containers/K8s; devaipod uses containers to sandbox AI that writes code.

The projects could be complementary: Kortex could manage the container/K8s infrastructure that devaipod pods run on. More concretely, Kortex's MCP integration means it could consume service-gator as a tool provider, which would add the credential scoping that Kortex currently lacks for its Goose integration.

### Gyre

(This section is Assisted-by: OpenCode (Claude Opus 4.6) research, but was human reviewed)

[Gyre](https://github.com/jsell-rh/gyre/) is an autonomous software development platform built in Rust and Svelte. The repository has no LICENSE file, though the Cargo.toml says MIT. That should probably be expanded.

Gyre provides its own built-in git forge (Smart HTTP transport), merge queue, agent orchestrator, and identity provider. Agents are single-purpose, spawned via API, given a git worktree and scoped bearer token, and torn down after completing their task. External repos can be pull-mirrored into Gyre, but all agent work happens inside Gyre's forge.

Key points for comparison with devaipod:

- **No devcontainer.json**. Agent environments use a "compute target" abstraction (local processes, Docker/Podman, SSH, Kubernetes), though current implementation spawns local OS processes. Nix flake for the project's own development.
- **No per-agent container sandboxing**. The Gyre server can run in a container (Dockerfile) or NixOS VM, but agents spawned by it are local processes with git worktree + scoped token isolation. The specs describe container/K8s compute targets and eBPF audit, but these appear unfinished.
- **No outbound forge flow**. Repos can be one-way mirrored *into* Gyre, but there is no documented mechanism for pushing agent work back out as a GitHub PR. devaipod + service-gator is designed for exactly this -- agents opening scoped PRs on existing forges.
- **Supply chain security** is ambitious: `gyre-stack.lock` pins agent configuration (AGENTS.md hash, MCP servers, model ID), and pushes with non-matching stacks are rejected. Three attestation levels from "raw git push" to "Gyre-managed runtime with eBPF + SPIFFE."

cgwalters: One possible intersection here: the "local forge" mode could be an optional thing devaipod runs or configurable alongside it. I actually investigated forgejo for this purpose in the past.
It also seems like gyre could learn to reuse the devcontainer backend logic from devaipod?

### Auto-Claude

[Auto-Claude](https://github.com/AndyMik90/Auto-Claude) is an autonomous multi-agent coding framework with a desktop UI, Kanban board, and parallel agent execution. AGPL-3.0 licensed.

Auto-Claude has excellent UI/UX but runs agents directly on the host with full system access—no sandboxing. devaipod could serve as a sandboxed backend for Auto-Claude's interface.

### Gastown

[Gastown](https://github.com/steveyegge/gastown) (from Steve Yegge) is a multi-agent orchestration system for Claude Code. MIT licensed, written in Go. It provides workspace management, agent coordination via "convoys", and persistent work tracking through git-backed "hooks" (git worktrees).

Gastown focuses on **orchestration** rather than **sandboxing**:

- No container isolation—agents run in tmux sessions with full host filesystem access
- No credential scoping—agents receive your full GitHub token, API keys, etc.
- Claude Code runs with `--dangerously-skip-permissions` by default
- No devcontainer.json support
- Isolation is via git worktrees (separate working directories) and prompt-based instructions to "stay in your worktree"

Gastown and devaipod solve different problems and could be complementary: Gastown for orchestrating work distribution across many agents, devaipod for sandboxing individual agent execution with credential scoping.

### Scion

(This section is Assisted-by: OpenCode (Claude Opus 4.6) research, based on documentation and source code analysis of the Scion repository)

[Scion](https://github.com/GoogleCloudPlatform/scion) is an experimental multi-agent orchestration testbed from Google Cloud Platform. Apache-2.0 licensed, written in Go. It describes itself as a "hypervisor for agents" -- managing concurrent LLM coding agents running in containers across local machines and Kubernetes clusters.

Scion is harness-agnostic: it wraps Claude Code, Gemini CLI, OpenCode, OpenAI Codex, and any generic CLI tool via a pluggable harness interface. Each agent gets an isolated container, its own git worktree, and scoped credentials. The system supports four container runtimes (Docker, Podman, Apple Virtualization Framework, and Kubernetes) with auto-detection and runtime profiles.

The project has two operating modes. **Solo mode** runs locally with zero infrastructure -- the CLI manages agents directly via the local container runtime. **Hosted mode** adds a centralized Hub server that coordinates state and dispatches work to remote Runtime Brokers, enabling multi-machine and multi-user orchestration. The Hub includes OAuth/JWT authentication, a web dashboard (Lit + TypeScript), SQLite persistence, and WebSocket tunneling for NAT traversal.

Scion's design philosophy explicitly positions it as a lower-level substrate rather than a complete multi-agent framework. Their "less is more" principle means Scion avoids building agent memory, task graphs, or conversation protocols -- it focuses on container lifecycle, workspace isolation, and credential management. The idea is that as models improve, rigid orchestration patterns become less necessary.

Key comparisons with devaipod:

- **Scope**: Scion orchestrates *groups* of agents working in parallel on a project. devaipod sandboxes *individual* agent sessions. Scion is a team coordinator; devaipod is a secure workspace.
- **Container runtimes**: Scion supports Docker, Podman, Apple Container, and Kubernetes natively with a pluggable runtime interface. devaipod uses Podman exclusively today, with Kubernetes as a future goal. Scion's runtime abstraction is substantially more mature.
- **Credential management**: Scion uses GitHub App tokens dispensed by `sciontool credential-helper` inside the container, with tokens refreshable from the Hub. This is a per-agent credential model but doesn't scope *what operations* the agent can perform. devaipod's service-gator provides semantic, per-operation scoping (e.g., "only draft PRs to this repo") -- a fundamentally stronger isolation model for forge access.
- **Agent support**: Scion is harness-agnostic from day one. devaipod currently integrates deeply with OpenCode.
- **Kubernetes**: Scion has a full 2000+ line Kubernetes runtime with GKE-specific features (SecretProviderClass CSI, GCS FUSE, Autopilot scheduling). This is substantially ahead of devaipod's Kubernetes plans.
- **Observability**: Scion has comprehensive OpenTelemetry integration. devaipod has no equivalent yet.

**Container image architecture**: This is a fundamental design divergence. Scion requires two custom Go binaries (`sciontool` and `scion`) baked into every agent container image. `sciontool` runs as PID 1 -- it remaps the `scion` user's UID/GID to match the host (via `usermod` or direct `/etc/passwd` editing), sets up the git workspace (clone or worktree), configures the credential helper, injects agent instructions, and then execs the child process. The `scion` CLI is also installed inside the container so agents can self-orchestrate (spawn child agents, send messages). This means every image must extend Scion's `scion-base`, which itself extends a ~1GB `core-base` layer containing Go, Node, git (compiled from source), Chromium, gcloud CLI, tmux, and more. You *could* in theory copy the two binaries into an arbitrary image, but `sciontool init` assumes a `scion` user exists, plus git, sed, tmux, and passwordless sudo -- so it's not just "drop in two files."

devaipod takes the opposite approach: the agent container is a standard devcontainer image with no custom binaries required. All orchestration machinery lives in sidecar containers (service-gator for credential scoping, pod-api for git operations and status). The agent tooling (OpenCode) is installed at runtime. This means any existing devcontainer.json works unmodified -- the image doesn't need to know it's being orchestrated.

The tradeoff is real: Scion's in-container control plane gives tighter integration (credential helper, status reporting, agent-to-agent messaging all wired up automatically via `sciontool`), while devaipod's sidecar model gives image portability (bring your project's existing devcontainer) at the cost of more external plumbing.

**devcontainer.json**: devaipod uses the devcontainer.json standard for defining agent environments. Scion has zero devcontainer support -- the only reference in the entire codebase is `ENV DEVCONTAINER=true` in the Claude image Dockerfile (a signal to Claude Code, not actual spec support). Instead, Scion has its own template system with chain-based inheritance. Templates define the agent's *role* (persona, instructions, skills) while harness-configs define the *mechanics* (image, model, CLI args, auth type). The template system has features devcontainer.json lacks -- inheritance chains, Hub-synced distribution, multi-harness portability -- but can't leverage the devcontainer ecosystem. A team with an existing devcontainer.json defining their build tools and language runtimes would need to rebuild that into a custom Dockerfile for Scion.

**Agent configuration and dotfiles**: Scion has typed, per-harness knowledge of each agent's configuration layout. Each harness implementation in Go declares its config directory (`DefaultConfigDir()` returns `.config/opencode` for OpenCode, `.claude.json` for Claude, etc.) and its skills directory. The provisioning flow composes the agent's home directory in layers: harness-config `home/` provides base dotfiles (e.g., an embedded `opencode.json`), then template chain `home/` directories overlay on top (later templates win on conflict), then skills files are merged into the harness-specific skills directory. Agent instructions are injected via harness-specific methods -- OpenCode gets an `AGENTS.md` file, Claude gets settings merged into `.claude.json`. Git identity is hardcoded by `sciontool init`: every agent commits as `Scion Agent (<name>) <agent@scion.dev>` regardless of the human's identity, because Scion assumes agent work lives on throwaway branches that get squash-merged later.

devaipod takes a more generic approach: the user's dotfiles (`.gitconfig`, `.config/opencode/opencode.json`, etc.) are bind-mounted from the host or specified in devcontainer.json, and the agent container doesn't need to know the internal layout of each tool's configuration. Git identity comes from the user's own `.gitconfig`. This is simpler and preserves the human's identity on commits, but means devaipod has less ability to programmatically inject per-agent instructions or customize agent behavior at the config level. Scion's approach is more powerful for multi-agent scenarios (each agent can have a distinct persona, skills, and system prompt composed from templates) at the cost of requiring Go code changes to support a new harness's config layout.

**Git and workspace model**: In solo/local mode, Scion uses git worktrees for branch-level isolation (each agent gets a dedicated worktree under `.scion/agents/<name>/workspace/`, bind-mounted into the container). This is simple and elegant -- the host has direct filesystem access with no special transport needed. In Hub mode, agents get a shallow `git init` + `git fetch` over HTTPS and push independently to `scion/<agent-name>` branches. devaipod's workspace-v2 uses host-directory bind-mounts with `git clone --shared`, and harvests agent commits back via `ext::podman exec git-upload-pack` transport. The `ext::` tunneling is needed because alternates point at container-internal paths, which is complexity that Scion's worktree approach avoids entirely.

However, devaipod has substantially more built-in review infrastructure. Scion has no review flow at all -- their docs say "merging agent work is done via git push and pull request." devaipod provides a CLI TUI reviewer (`devaipod review`), web diff viewer with SSE auto-refresh, a harvest-then-approve-then-push pipeline, and plans for a "must view all changed files" approval gate. Scion's local worktree model also has no trust boundary at the git level -- the worktree is part of the same repo as the user's checkout, so a malicious `.gitmodules` or hook could propagate. devaipod's dual-workspace model keeps the agent's clone separate with git hardening (fsmonitor=false, hooksPath=/dev/null).

The projects are complementary rather than competing. Scion could use service-gator for fine-grained forge credential scoping, and devaipod could learn from Scion's runtime abstraction and Kubernetes integration. Scion runs agents in `--yolo` mode (full autonomy inside the container) and relies on container isolation plus git worktrees as guardrails. devaipod takes a belt-and-suspenders approach with container isolation *plus* API-level credential scoping *plus* review gates.

### krunai

As far as I can see [krunai](https://github.com/slp/krunai) is really another virtual machine launcher, it doesn't truly do much special for AI workloads - or even arguably anything at all other than having an example init script that downloads a particular CLI tool.

I think what devaipod is doing using devcontainers make sense as a mechanism to allow users to control their workload environment, and there's already good tooling to optionally launch podman/kube containers wrapped in VMs if desired.

I also think in the general case one really wants good affordance for git integration, output review etc.

## Open Core (Partial Cloud Dependencies)

### Continue

[Continue](https://github.com/continuedev/continue) provides VS Code and JetBrains extensions, plus a CLI. The extensions and CLI are Apache-2.0.

**Cloud dependency**: "Mission Control" (hub.continue.dev) is Continue's proprietary cloud platform for running cloud agents. The backend code is not open source. Local CLI execution has no sandboxing.

### SWE-agent

[SWE-agent](https://github.com/princeton-nlp/SWE-agent) from Princeton NLP provides an agent-computer interface for software engineering tasks. MIT licensed.

**Cloud dependency**: The "Open SWE" product [runs on Daytona](https://www.daytona.io/dotfiles/langchain-s-open-swe-runs-on-daytona-here-s-why), a commercial cloud service for dev environments.

## Proprietary / Cloud-Required

### Ona

[Ona](https://ona.com/) is a commercial AI agent platform. **Requires cloud services**—there is no open source version or self-hosted option.

### Cursor

[Cursor](https://cursor.sh/) is a commercial AI-first code editor based on VS Code. Proprietary, cloud-connected.

### Claude Code Web

Claude Code is also available as a hosted web service at claude.ai. Anthropic runs it in their own sandboxed infrastructure with a git proxy for credential scoping (described in their [sandboxing blog post](https://www.anthropic.com/engineering/claude-code-sandboxing)). However, **that sandbox code is not open source**—you cannot run it yourself. If you want similar sandboxing locally, you need something like devaipod.

## Other Sandboxing Tools

### Docker AI Sandboxes

[Docker AI Sandboxes](https://docs.docker.com/ai/sandboxes/) is Docker's solution for running AI coding agents in isolated environments. It uses lightweight microVMs with private Docker daemons for each sandbox.

devaipod is just a wrapper for podman and uses the **devcontainer.json** standard.

Note that the use case of running containers *inside* the sandbox is captured via nested containerization: VMs are not required.

- **Licensing**: Docker Sandboxes is part of Docker Desktop, which is [proprietary software](https://www.docker.com/legal/docker-subscription-service-agreement/) requiring paid subscriptions for commercial use in organizations with 250+ employees or $10M+ revenue; devaipod is fully open source (Apache-2.0/MIT)
- **Platform**: Docker Sandboxes requires Docker Desktop with microVM support (macOS, Windows experimental); devaipod uses podman and works on Linux natively
- **Credential scoping**: Docker Sandboxes provides isolation but does not mention fine-grained credential scoping like service-gator; devaipod can limit agent access to specific repos/operations

### nono

[nono](https://nono.sh/) ([GitHub](https://github.com/lukehinds/nono)) is an OS-level sandboxing tool for AI agents. Apache-2.0 licensed, created by Luke Hinds (creator of Sigstore).

nono defaults to Landlock on Linux and Seatbelt on macOS. I think OCI containers provide more security and are more flexible and well understood by tools.
Further, containers provide reproducible environments that are just a foundational piece.

Landlock is complementary to containerization, but how nono is doing it is conceptually against what the Landlock creators
want in my opinion: Landlock was supposed to primarily used by apps to sandbox *themselves*, not as a container-replacement framework.

### NVIDIA OpenShell

(This section is Assisted-by: OpenCode (Claude Opus 4.6) research, but has been refined and edited)

On [NVIDIA OpenShell](https://github.com/NVIDIA/OpenShell) there's a lot of overlap. One obvious thing here is that it does a pretty wild thing in running k3s inside docker (which would probably also work with podman), whereas devaipod leans into the native support for podman pods. However there are also clear advantages to k3s-in-container, among them it makes it much easier to have symmetric support for a real remote Kuberentes cluster.

I think service-gator as MCP is a stonger/better solution than the generic REST proxy. We're coming at these things from a very similar space, but a key thing here with service-gator is that the tokens are not accessible to the agent at all.
OpenShell is the closest project to devaipod in goals: both sandbox AI agents with fine-grained controls rather than just filesystem isolation. Key similarities and differences:

- **Sandboxing approach**: OpenShell uses Landlock (kernel LSM) for filesystem restrictions plus seccomp for syscall filtering, layered inside Docker containers. devaipod uses OCI containers via podman with rootless execution. The author of devaipod thinks LandLock was not intended for what OpenShell or nono.sh are doing with it and it's mostly unnecessary.
- **Network control**: OpenShell intercepts all outbound connections via an HTTP CONNECT proxy that matches destination + calling binary against a declarative YAML policy. devaipod does not isolate network access by default (although one could configure some of that at the container networking level). service-gator is used by devaipod for safe credential-based access to specific services, but it could also be used as an MCP server in OpenShell.
- **Credential management**: OpenShell uses "providers" — named credential bundles injected as environment variables at sandbox creation. Credentials are injected at runtime and never written to the sandbox filesystem. devaipod uses service-gator to avoid passing credentials to the agent at all — the agent never sees the GitHub token, it only gets scoped MCP tool access. This is a stronger isolation model for the services service-gator supports.
- **Architecture**: OpenShell runs a K3s cluster inside Docker and uses a gateway/sandbox control-plane model. This is heavier than devaipod's podman pod approach (no Kubernetes layer), but positions OpenShell better for multi-tenant and remote deployment (it already supports local, remote via SSH, and cloud gateway modes).
- **Agent support**: OpenShell is agent-agnostic — it wraps Claude Code, OpenCode, Codex, OpenClaw, and Ollama. devaipod integrates deeply with OpenCode at the moment, but supporting other agent types is a possibility.
- **Inference routing**: OpenShell has a built-in privacy router that intercepts LLM API calls and can redirect them to local or self-hosted backends, stripping/replacing credentials. devaipod has no equivalent — inference routing is handled by the agent's own configuration.
- **devcontainer.json**: devaipod uses the devcontainer.json standard for defining the agent environment. OpenShell uses community sandbox images and supports BYOC (bring your own container) but has no devcontainer.json integration.
- **git support**: Devaipod aims to have strong, native support for git, but I don't see this in OpenShell
- **Platform**: OpenShell requires Docker. devaipod uses podman (but could also pretty easily use docker). It is also a goal to support targeting Kubernetes.

The projects share the same fundamental insight that sandboxing AI agents requires more than filesystem isolation — you need network egress control, credential scoping, and defense-in-depth.

In a nutshell, I am considering:

- Rebasing devaipod on OpenShell
- Trying to contribute service-gator to that project

### gjoll

(This section is Assisted-by: OpenCode (Claude Opus 4.6), based on source code analysis of the gjoll repository)

[gjoll](https://github.com/ondrejbudai/gjoll) is a Go CLI tool that provisions cloud VM sandboxes for coding agents using standard OpenTofu `.tf` files. Apache-2.0 licensed, experimental. The design philosophy is radical simplicity: gjoll injects three variables into your `.tf` file (`gjoll_ssh_pubkey`, `gjoll_name`, `gjoll_instance_state`), runs `tofu apply`, and gets out of the way. It supports any cloud provider that has an OpenTofu provider (AWS, Proxmox, libvirt/QEMU, etc.).

The architecture is interesting because it solves similar problems to devaipod but makes fundamentally different trade-offs — full VMs instead of containers, SSH-based git transport instead of forge integration, and HTTP reverse proxies instead of MCP-based credential scoping.

(Note from devaipod author: Nothing wrong with provisioning classic mutable VMs, but I think containers are architecturally the right choice;
 where VM isolation on top of containerization is desired, there's tons of tools for that)

**Git workflow** — gjoll has a dedicated git sync mechanism via `gjoll push` and `gjoll pull`. `push` initializes a repo on the VM with `receive.denyCurrentBranch=updateInstead`, sets the remote HEAD to match the local branch via `git symbolic-ref`, and pushes over SSH (`GIT_SSH_COMMAND=ssh -F <config>`). The working tree on the VM updates immediately — no separate checkout step. `pull` fetches back from the VM and creates a local branch named `gjoll-<name>` (hyphens, not slashes, to avoid breaking tools like lazygit).

(devaipod author: This is much less heavyweight than devaipod's choice to have a git clone per pod, and has clear advantages. Similar to paude in that respect.)

The workflow is: push code to VM → agent works → pull changes back → human creates PR locally.

By contrast, devaipod's service-gator provides the agent with scoped forge access, and we plan to invest in having a good review process inside the UI, and also allow some autonomous updates.

**Credential gating** — this is gjoll's most distinctive feature and the area of strongest overlap with devaipod's goals. The `gjoll proxy` command runs local HTTP reverse proxies on the host that inject authentication headers, with SSH reverse tunnels (`-R`) making them reachable on the VM as `localhost:<port>`. Credentials never leave the host machine.

Three auth modes are supported: `gcp` (GCP Application Default Credentials via `google.DefaultTokenSource()`, with automatic token refresh), `api-key` (static key read from a local file, injected as `x-api-key` header), and no-auth passthrough. The proxy binds to `127.0.0.1:0` only — not network-reachable. Token fetch failures surface as 502 errors rather than forwarding unauthenticated requests.

However, the proxy provides **full, unscoped access** to the upstream API. Any request to `http://localhost:<port>/any/path` is forwarded with credentials attached. There is no URL path filtering, no HTTP method restrictions, no rate limiting, and no audit logging beyond error messages. A misbehaving agent can make any API call the credential allows.

There is **no support for GitHub tokens** — the proxy is designed for LLM API access (Vertex AI, Anthropic), not forge operations. To give a sandboxed agent GitHub access, you'd need to either extend the proxy with a new auth mode for Bearer tokens and add path-level scoping, or copy the token to the VM directly (their `ubuntu-claude.tf` example shows a commented-out `copy_files` approach for this, though the newer `ubuntu-claude-vertex.tf` example explicitly avoids it in favor of proxying).

The contrast with service-gator is architectural: gjoll gives the agent a **raw HTTP pipe** with credentials injected (network-level proxy), while service-gator gives the agent **semantic tools** with per-operation permission checks (MCP-level scoping). You can tell service-gator "this agent can create draft PRs on `owner/repo` but cannot force-push or delete branches." gjoll's proxy has no equivalent — it's all-or-nothing per API target.

The proxy model is well-suited for LLM API access where you *want* the agent to make arbitrary API calls to the model provider. service-gator is better for forge operations where you want to constrain what the agent can do. The two approaches are complementary rather than competing.

**Other notable differences from devaipod**:

- **Isolation unit**: Full cloud VMs (via OpenTofu) vs. OCI containers (via podman). VMs provide stronger isolation but are heavier — gjoll requires cloud infrastructure or local libvirt/QEMU, while devaipod runs with just podman.
- **Environment definition**: Raw `.tf` files vs. devcontainer.json. gjoll is maximally flexible but requires HCL knowledge; devaipod uses the standard devcontainer spec.
- **SSH security**: Per-sandbox ed25519 keypairs with `IdentitiesOnly yes` and `IdentityAgent none` (no agent forwarding). But `StrictHostKeyChecking no` for ephemeral VMs — pragmatic but means no MITM protection.

## Why devaipod?

1. **Fully open source**: Apache-2.0/MIT, no "open core" trap
2. **100% local**: No cloud services required (you bring your own LLM API keys)
3. **devcontainer.json**: Uses the standard spec, not custom formats
4. **Fine-grained credential scoping**: service-gator MCP provides scoped access (e.g., draft PRs only to specific repos)—not just filesystem sandboxing
5. **Podman-native**: Rootless containers, works in toolbox, no Docker daemon required

## Reusable Components

A design goal for devaipod is that its core components should be reusable building blocks, not a monolithic system. Projects like OpenHands, Ona, and Ambient Code are building centralized platforms for corporate/team agentic AI usage. We hope that a fully open source version of such a platform emerges, and when it does, components from devaipod should be useful:

- **service-gator**: Fine-grained credential scoping for GitHub/GitLab/Forgejo could plug into any orchestration system
- **Container sandboxing patterns**: The podman pod architecture with separate workspace/agent/gator containers
- **devcontainer.json integration**: Parsing and applying the devcontainer spec for agent environments

devaipod is designed for individual developers today, but the primitives should scale to team/org deployment when composed with appropriate orchestration.
