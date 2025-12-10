# Relationship to Ambient Code Platform

## Overview

[Ambient Code Platform](https://github.com/ambient-code/platform) is an open-source Kubernetes-native platform for running AI coding agents ("virtual teams"). It provides orchestration, credential management, and issue-driven workflows for agentic sessions. This document analyzes Ambient Code's architecture and how devaipod relates to it.

## License

Ambient Code Platform is licensed under **MIT**. The repository includes:
- Kubernetes operator for managing agentic sessions
- Backend API (TypeScript)
- Web frontend
- Runner components for various AI agents (Claude Code, etc.)
- Content service sidecar for git/forge operations

## Architecture Overview

Ambient Code is a Kubernetes-native platform with these components:

| Component | Description |
|-----------|-------------|
| **Operator** | Kubernetes operator managing `AgenticSession` CRDs |
| **Backend API** | REST API for session management, webhooks |
| **Frontend** | Web UI for interactive sessions and monitoring |
| **Runners** | Container images with AI agents (Claude Code, etc.) |
| **Content Service** | Sidecar for git operations and forge API access |

### Key Architectural Decisions

From [ADR-0006 (PR #364)](https://github.com/ambient-code/platform/pull/364): Agent injection architecture allows users to run agentic sessions in their own container images without requiring them to extend a base image. The platform injects agent code at runtime.

From [Issue #444](https://github.com/ambient-code/platform/issues/444): Platform-native execution with scoped credentials - a detailed ADR proposing migration of background agents (like "Amber") from GitHub Actions to platform-native execution with proper credential isolation.

## Credential Scoping: The Core Security Model

Issue #444 describes a sophisticated credential scoping architecture that addresses the same security concerns as devaipod:

### The Problem (shared with devaipod)

> "The `GITHUB_TOKEN` provided to the workflow has repository-wide scope. The spawned Claude agent can comment on or close *any* issue in the repository, not just the triggering issue. It can modify *any* pull request."

This is exactly the problem devaipod aims to solve for local development.

### Ambient Code's Solution: Dual-Port Broker Architecture

The platform proposes a **content service broker** that mediates all git and forge operations:

```
Runner (no credentials) --> Broker (:8081) --> Validates scope --> GitHub/GitLab/Forgejo
```

Key concepts:

1. **Remove credentials from runner** - The agent container has no `GITHUB_TOKEN` env var
2. **Broker validates operations** - All git pushes and issue comments go through a broker that checks against allowed scopes
3. **Attached Contexts** - Sessions declare what resources they can touch:

```yaml
spec:
  repos:
    - input:
        url: "https://github.com/org/repo"
        branch: "main"
      output:
        targetBranch: "fix/issue-42"
        createPullRequest: true

  attachedContexts:
    - type: git-issue
      url: https://github.com/org/repo/issues/42
      permissions: [comment, edit-own, minimize-own]
```

4. **Forge-agnostic** - Same broker works for GitHub, GitLab, Forgejo/Gitea

### Prior Art Acknowledgment

Issue #444 notes:

> "This architecture is similar to what Anthropic uses for Claude Code on the web, where 'the git client authenticates to [a proxy] service with a custom-built scoped credential. The proxy verifies this credential and the contents of the git interaction (e.g., ensuring it is only pushing to the configured branch), then attaches the right authentication token before sending the request to GitHub.' However, Anthropic's git proxy is not open source."

## Comparison with devaipod

| Feature | Ambient Code Platform | devaipod |
|---------|----------------------|----------|
| **Target Environment** | Kubernetes cluster | Local workstation (Docker/Podman) |
| **Environment Spec** | Custom CRDs, optional devcontainer support | devcontainer.json primary |
| **Credential Storage** | Kubernetes secrets | podman/docker secrets |
| **Credential Scoping** | Broker with attached contexts (proposed) | Secrets bridge from devcontainer.json |
| **Network Isolation** | Kubernetes network policies | Nested container namespaces |
| **Issue-Driven Workflows** | `AgenticSession` CRD with issue context | `devaipod run <issue-url>` |
| **Agent Execution** | Kubernetes pods with sidecars | DevPod workspaces with tmux |
| **Multi-Forge Support** | GitHub, GitLab, Forgejo | Currently GitHub only |
| **Open Source** | Yes (MIT) | Yes (Apache-2.0/MIT) |

### Architectural Differences

**Ambient Code** is designed for:
- Team/organization deployment on Kubernetes
- Centralized orchestration of multiple agents
- Enterprise-grade audit trails via CRDs
- Background automation ("Amber" agents triggered by labels/webhooks)

**devaipod** is designed for:
- Individual developer workstations
- Zero infrastructure beyond a container runtime
- DevPod's provider flexibility (Docker, Podman, K8s, AWS, SSH)
- Quick issue-to-PR workflows without cluster setup

### Complementary, Not Competing

The projects target different deployment scenarios:

- **Developer laptop**: Use devaipod for sandboxed local agent execution
- **Team infrastructure**: Use Ambient Code Platform for orchestrated background agents

A developer might use devaipod locally while their organization runs Ambient Code Platform for automated issue triage and background agents.

## What devaipod Can Learn

### Broker Architecture for Credential Scoping

Issue #444's dual-port broker design is directly applicable to devaipod:

1. **Current devaipod approach**: Secrets injected via `remoteEnv` in devcontainer.json - the agent has full access to these credentials
2. **Ambient Code approach**: Agent has no direct credentials; all operations go through a validating proxy

devaipod could implement a similar broker as a sidecar container that:
- Holds the actual GitHub token
- Validates git push targets against allowed branches
- Validates issue/PR operations against the triggering issue
- Logs all operations for audit

### Attached Contexts Model

The `attachedContexts` spec provides fine-grained permission declarations:

```yaml
attachedContexts:
  - type: git-issue
    url: https://github.com/org/repo/issues/42
    permissions: [comment, edit-own, minimize-own]
```

This could extend devaipod's current model where `devaipod run <issue-url>` implicitly scopes to that issue.

### Multi-Forge Support

Ambient Code's broker is designed to work with GitHub, GitLab, and Forgejo from the start. devaipod currently only parses GitHub issue URLs; the forge-agnostic design from Ambient Code could inform future expansion.

## Potential Interoperability

### Shared Credential Broker

The broker component proposed in Issue #444 could potentially be shared:
- Ambient Code runs it as a Kubernetes sidecar
- devaipod runs it as a container alongside the DevPod workspace

Both projects need the same functionality: validate git/forge operations against declared scopes.

### devcontainer.json ↔ AgenticSession Mapping

A tool could translate between formats:
- devcontainer.json `secrets` → AgenticSession `attachedContexts` 
- AgenticSession `repos` → devcontainer.json with pre-configured remotes

### ACP for Agent Communication

Both projects could expose agents via ACP (Agent Client Protocol), enabling:
- Same frontend (Zed, Neovim, etc.) connecting to either local devaipod or remote Ambient Code sessions
- Agent portability between environments

## Key Takeaways

1. **Ambient Code validates the problem space** - A Kubernetes-native platform is also solving sandboxing and credential scoping for AI agents
2. **The broker pattern is proven** - Anthropic uses a similar architecture for Claude Code on the web
3. **Scope declaration is essential** - Both projects need to express "this agent can only touch issue #42 and push to branch X"
4. **Different deployment targets** - Ambient Code for teams/clusters, devaipod for individual workstations
5. **Potential for shared components** - The credential broker logic could be extracted and reused

## References

- [Ambient Code Platform](https://github.com/ambient-code/platform)
- [Issue #444: Platform-Native Amber Execution with Scoped Credentials](https://github.com/ambient-code/platform/issues/444)
- [PR #364: ADR-0006 for Agent Injection Architecture](https://github.com/ambient-code/platform/pull/364)
- [Anthropic sandbox-runtime](https://github.com/anthropic-experimental/sandbox-runtime) (Apache 2.0)
- [Claude Code sandboxing blog post](https://www.anthropic.com/engineering/claude-code-sandboxing)
