# devaipod Roadmap

This document outlines the development roadmap for devaipod. Status is approximate
and priorities may shift based on user feedback and practical experience.

## Phase 1: Core Functionality ✅

Complete native podman implementation:

- **Native CLI commands**: `devaipod up`, `ssh`, `list`, `stop`, `delete` - no
  devpod dependency for core workflow
- **Podman-native multi-container pods**: Workspace, agent, and gator containers
  share a pod with localhost networking between them
- **Workspace shims**: `oc` and `opencode-agent` commands in workspace run
  `opencode attach http://localhost:4096` to connect to sandboxed agent
- **API key passthrough**: Agent container receives LLM API keys from host
  environment (ANTHROPIC_API_KEY, OPENAI_API_KEY, etc.)
- **Devcontainer.json parsing**: Image/build config, lifecycle commands
  (onCreateCommand, postCreateCommand, postStartCommand), environment variables,
  capabilities
- **Toolbox support**: Detection and appropriate behavior in toolbox environments
- **Agent sandboxing**: Agent runs `opencode serve` with security restrictions
  (dropped capabilities, no-new-privileges, isolated home directory)
- **Service-gator integration**: Optional MCP server container for scoped
  external service access (GitHub, JIRA)
- **Secrets from podman**: Secrets declared in devcontainer.json are fetched
  from `podman secret` store

## Phase 2: Production Readiness

Making devaipod reliable for daily use:

- **SSH server for editor connections**: VSCode/Zed Remote SSH needs an actual
  SSH server in the container. Current `ssh-config` generates ProxyCommand but
  containers lack sshd. Options:
  - Install dropbear (lightweight SSH) at container startup
  - Use VSCode Dev Containers extension instead (works with podman exec)
  - Embed SSH server in a devaipod agent binary
- **Agent readiness probes / health checks**: Detect when agent container is
  actually ready to accept connections, not just started. Currently we start
  the pod and hope opencode is listening.
- **Agent container image strategy**: Currently agent uses the same image as
  workspace, requiring opencode to be installed in every devcontainer image.
  Options:
  - Dedicated agent image with opencode pre-installed
  - Runtime install of opencode into workspace image
  - Sidecar approach with shared volume
- **Network sandboxing for agent**: Restrict agent network access to LLM API
  endpoints only. Options include HTTPS proxy with allowlist, iptables rules
  in network namespace, or DNS-based filtering.

## Phase 3: Kubernetes Support

Running devaipod workloads on Kubernetes clusters:

- **kube-rs integration**: Use kube-rs to create pods on real Kubernetes
  clusters, not just local podman. This enables remote dev environments with
  proper resource management.
- **Quadlet/systemd integration**: For local deployment, generate Quadlet
  units so pods can be managed by systemd. Enables auto-restart, logging
  integration, and proper lifecycle management.
- **Pod spec generation**: Generate Kubernetes-compatible pod specs that can
  be applied with kubectl or used in GitOps workflows.

## Phase 4: Enhanced Features

Nice-to-have functionality:

- **Devcontainer features support**: Install devcontainer features into the
  workspace image. This is complex - features are essentially scripts that
  modify the image at build time.
- **Multi-project workspaces**: Support for monorepos or multi-repo setups
  where the agent needs access to multiple projects.
- **Persistent agent state**: Named volumes for agent home directory so
  context, history, and learned patterns persist across pod restarts.
- **Full service-gator integration**: Tighter integration with service-gator
  for scoped external access - automatically configure MCP based on repository
  and user permissions.

## Known Limitations

Current constraints that users should be aware of:

- **Agent requires opencode in the image**: The agent container runs `opencode
  serve`, so opencode must be installed in the devcontainer image. There's no
  automatic injection yet.
- **No network isolation yet**: Agent has full network access. This is needed
  for LLM API calls, but also means the agent could exfiltrate data to
  arbitrary endpoints.
- **Lifecycle commands only run in workspace**: onCreateCommand etc. run in
  the workspace container, not the agent container. The agent starts with
  whatever is in the image.
- **No GPU support**: Agent container doesn't have GPU passthrough configured.
  Local LLM inference would require this.
- **Single agent type**: Only opencode is supported as the agent. Supporting
  other agents (goose, aider, etc.) would require per-agent configuration.
