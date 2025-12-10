# Relationship to Continue.dev

## Overview

[Continue](https://github.com/continuedev/continue) is an open-source AI coding assistant with VS Code and JetBrains extensions, a CLI (`cn`), and a cloud platform called "Mission Control" (hub.continue.dev). This document analyzes Continue's architecture, licensing, and approach to sandboxed agent execution—particularly relevant to devaipod's goals.

## License

Continue is licensed under **Apache 2.0**, same as devaipod. The open-source repository includes:
- VS Code and JetBrains extensions
- CLI (`@continuedev/cli` / `cn`)
- Core TypeScript library
- Documentation

## Architecture Overview

Continue has evolved from an IDE-only assistant to a multi-surface agent platform:

| Surface | Description | Open Source? |
|---------|-------------|--------------|
| **IDE Extensions** | VS Code, JetBrains plugins for chat, autocomplete, edit, agent modes | ✅ Yes |
| **CLI (`cn`)** | TUI and headless modes for terminal-based agent interaction | ✅ Yes |
| **Mission Control** | Cloud platform at hub.continue.dev for running cloud agents, managing workflows, secrets | ❌ No |
| **Control Plane API** | Backend at api.continue.dev | ❌ No |

### Key Insight: Mission Control is NOT Open Source

**Mission Control (hub.continue.dev)** is Continue's proprietary cloud platform. The source code for the control plane backend and Mission Control web interface is **not** in the open-source repository. The open-source code contains:

- Client libraries to communicate with the control plane (`core/control-plane/`)
- TypeScript interfaces for agent sessions, workspaces, secrets
- Environment configuration pointing to `api.continue.dev` and `hub.continue.dev`

From `core/control-plane/env.ts`:
```typescript
const PRODUCTION_HUB_ENV: ControlPlaneEnv = {
  DEFAULT_CONTROL_PLANE_PROXY_URL: "https://api.continue.dev/",
  CONTROL_PLANE_URL: "https://api.continue.dev/",
  AUTH_TYPE: AuthType.WorkOsProd,
  APP_URL: "https://hub.continue.dev/",
};
```

The code does support an "OnPrem" auth type via MDM (Mobile Device Management) license keys, suggesting enterprise customers can self-host, but the control plane server code is not public.

## Cloud Agent Execution: "Devboxes"

Continue's cloud agents run in what they call **"devboxes"**—remote execution environments. Key findings from code analysis:

### Devbox Architecture

From `core/control-plane/client.ts`:
```typescript
export interface AgentSessionView {
  id: string;
  devboxId: string | null;  // Links to cloud execution environment
  status: string;
  agentStatus: string | null;
  repoUrl: string;
  branch: string | null;
  pullRequestUrl: string | null;
  tunnelUrl: string | null;  // For remote access
  // ...
}
```

From `extensions/cli/src/commands/devbox-entrypoint.md`:
> Context: runloop resumes a devbox by re-running the same entrypoint script, which invokes `cn serve --id <agentId> ...`

**Key observation**: Continue appears to use [Runloop](https://runloop.ai) as their devbox infrastructure provider. Runloop is a commercial service for cloud development environments.

### Devbox Lifecycle

1. **Creation**: Control plane creates a devbox via Runloop
2. **Entrypoint**: Runs `cn serve --id <agentSessionId>` with agent config
3. **Suspend/Resume**: Devboxes can suspend and resume; the CLI handles state persistence
4. **Environment**: Secrets written to `~/.continue/devbox-env`, sourced before `cn serve`
5. **Artifacts**: Agents can upload files (screenshots, logs) to S3 via presigned URLs

### No devcontainer.json Usage (Yet)

**Continue does NOT currently use devcontainer.json for cloud agents.** Their devbox infrastructure appears to be:

- Custom images/environments managed by the control plane
- No evidence of devcontainer.json parsing in the open-source code
- No `.devcontainer` directory in the Continue repository
- Agent configuration is via YAML files pushed to Mission Control, not devcontainer.json

This is a significant architectural difference from devaipod, which builds on the devcontainer spec.

## Execution Modes

Continue supports three execution modes:

### 1. Mission Control (Cloud)
```bash
# Navigate to hub.continue.dev/agents
# Run agent from web interface
```
- Runs in Continue's cloud infrastructure (devboxes via Runloop)
- Full lifecycle management, monitoring, PR creation
- Proprietary backend

### 2. TUI Mode (Local)
```bash
cn --agent continuedev/github-pr-agent
# Interactive terminal UI
```
- Runs locally on developer's machine
- No sandboxing—full access to local environment
- Open source

### 3. Headless Mode (Local/CI)
```bash
cn -p --agent my-org/snyk-agent "Run security scan" --auto
```
- Non-interactive, for CI/CD pipelines
- Runs wherever invoked (local, Docker, CI runner)
- No built-in sandboxing
- Open source

## Comparison with devaipod

| Feature | Continue | devaipod |
|---------|----------|----------|
| **Environment Spec** | Custom YAML, cloud-managed | devcontainer.json, devfile.yaml |
| **Local Sandboxing** | None (runs directly on host) | Nested containers with isolation |
| **Cloud Execution** | Proprietary (Runloop devboxes) | DevPod providers (local/K8s/cloud) |
| **Credential Management** | Mission Control secrets | podman secrets + devcontainer spec |
| **Network Isolation** | Only in cloud devboxes | Always (LLM API allowlist) |
| **Issue-Driven Workflows** | Via Mission Control | Native `devaipod run <issue-url>` |
| **Open Source Control Plane** | ❌ No | ✅ Yes (all orchestration local) |
| **IDE Integration** | VS Code, JetBrains (primary) | ACP for any compatible frontend |

## Pricing and Plans

Continue has three tiers:
- **Solo**: Free, for individuals
- **Teams**: Paid, for team collaboration
- **Enterprise**: Custom, with on-premise proxy option

The "Models Add-On" provides access to frontier models for a flat monthly fee.

## What devaipod Can Learn

### Things Continue Does Well

1. **CLI UX**: The `cn` CLI with TUI mode provides a good developer experience
2. **Agent Definitions**: YAML-based agent configs are shareable and composable
3. **MCP Integration**: First-class support for Model Context Protocol servers
4. **Session Persistence**: Chat history survives suspend/resume cycles
5. **Artifact Uploads**: Agents can upload screenshots, logs for review

### Gaps devaipod Fills

1. **Open Source Control Plane**: devaipod is fully open source, no proprietary backend
2. **Local Sandboxing**: Continue's local execution has no isolation; devaipod sandboxes by default
3. **devcontainer.json**: Standard environment spec vs. custom cloud-only configs
4. **Provider Flexibility**: DevPod works on Docker, Podman, K8s, AWS, SSH—not locked to one cloud
5. **Credential Scoping**: Fine-grained secret injection, not all-or-nothing

### Potential Collaboration/Interop

- **ACP**: Continue doesn't currently use ACP, but the protocol could enable interop
- **MCP**: Both projects use MCP; agent definitions could potentially be compatible
- **Agent Portability**: Continue agents are YAML; devaipod could potentially consume them

## Technical Deep Dive: Control Plane Client

The open-source `ControlPlaneClient` class shows the API surface:

```typescript
// From core/control-plane/client.ts
export class ControlPlaneClient {
  async resolveFQSNs(fqsns: FQSN[], orgScopeId: string | null): Promise<SecretResult[]>
  async listAssistants(organizationId: string | null): Promise<AssistantUnrolled[]>
  async getAgentSession(agentSessionId: string): Promise<AgentSessionView | null>
  async listAgentSessions(organizationId: string | null, ...): Promise<{agents: AgentSessionView[], totalCount: number}>
  // ... more methods
}
```

All these methods call `api.continue.dev` endpoints. The backend implementation is not public.

## Conclusion

Continue is a significant player in the AI coding agent space with a polished product, but its cloud agent features (Mission Control, devboxes) are proprietary. For users who want:

- **Fully open source stack**: devaipod
- **Sandboxed local execution**: devaipod
- **devcontainer.json compatibility**: devaipod
- **Self-hosted control plane**: devaipod (or Continue Enterprise, price unknown)

For users who want:

- **Managed cloud agents without infrastructure**: Continue Mission Control
- **Polished IDE integration today**: Continue extensions
- **Pre-built agent marketplace**: Continue Hub

The projects serve different needs. devaipod's focus on sandboxing, standard specs, and fully open architecture complements rather than competes with Continue's IDE-first, cloud-managed approach.

## References

- [Continue GitHub Repository](https://github.com/continuedev/continue)
- [Continue Documentation](https://docs.continue.dev)
- [Mission Control](https://hub.continue.dev)
- [Continue CLI](https://docs.continue.dev/cli/overview)
- [Runloop (apparent devbox provider)](https://runloop.ai)
