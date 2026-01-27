# Architecture Pivot: Multi-Container DevPod

**Status:** Planning / Discussion  
**Date:** January 2025

## Summary

This document captures a proposed architectural pivot for devaipod: moving from a bwrap-based sandbox inside a single devcontainer to a multi-container architecture where the AI agent runs in a separate container with different security contexts.

## Background

### Current Architecture (bwrap)

```
┌─────────────────────────────────────────────────────────────┐
│  Devcontainer                                               │
│  ┌───────────────────────────────────────────────────────┐  │
│  │  bwrap sandbox                                        │  │
│  │  • opencode runs here                                 │  │
│  │  • Filesystem isolation via bind mounts               │  │
│  │  • Process isolation via namespaces                   │  │
│  │  • Network: shared (not isolated)                     │  │
│  └───────────────────────────────────────────────────────┘  │
│  service-gator (outside sandbox)                            │
└─────────────────────────────────────────────────────────────┘
```

**Limitations:**
- bwrap can't do network isolation without CAP_NET_ADMIN
- Complex process management for `opencode serve` inside sandbox
- Mixing concerns in single container

### Key Discovery: opencode Client-Server Architecture

opencode has excellent client-server support:
- `opencode serve` - headless HTTP server exposing full API
- `opencode attach <url>` - TUI/CLI connects to running server
- `opencode run --attach <url>` - batch mode against server
- Full session management, status APIs, SSE event streaming

This enables separating the AI execution environment from the user's shell.

## Proposed Architecture

### Multi-Container via Docker Compose

DevPod/devcontainer spec natively supports Docker Compose for multi-container setups. We leverage this to run workspace and agent as separate containers.

```
┌─────────────────────────────────────────────────────────────────┐
│  Docker Compose (managed by DevPod)                             │
│                                                                 │
│  ┌─────────────────────────────────────────────────────────────┐│
│  │  Same Image (built from user's devcontainer)                ││
│  │  • Project toolchain (rust, node, go, etc.)                 ││
│  │  • opencode + devaipod utilities                            ││
│  └─────────────────────────────────────────────────────────────┘│
│           │                              │                      │
│           ▼                              ▼                      │
│  ┌─────────────────┐            ┌─────────────────┐             │
│  │  workspace      │            │  agent          │             │
│  │                 │            │                 │             │
│  │  • User shell   │            │  • opencode     │             │
│  │  • IDE attached │            │    serve :4096  │             │
│  │  • Full access  │            │  • Locked down  │             │
│  │  • Has secrets  │            │  • No secrets   │             │
│  │                 │            │    (except LLM) │             │
│  │                 │            │                 │             │
│  │  $ opencode ────┼────────────┼─► attach :4096  │             │
│  │                 │            │                 │             │
│  │  /workspace ◄───┼────────────┼─► /workspace    │             │
│  │  (rw)           │            │  (rw)           │             │
│  └─────────────────┘            └─────────────────┘             │
│                                                                 │
│  ┌─────────────────┐                                            │
│  │  gator          │  (separate image)                          │
│  │  service-gator  │                                            │
│  │  :8765 MCP      │                                            │
│  │  • Has GH_TOKEN │                                            │
│  └─────────────────┘                                            │
└─────────────────────────────────────────────────────────────────┘
```

### Critical Design Decision: Same Image

Both `workspace` and `agent` containers use **the same image** built from the user's devcontainer. This is essential because:

1. **AI needs project tools** - cargo, npm, go, whatever the project requires
2. **Consistency** - human and AI work in identical environments
3. **Single build** - no separate agent image to maintain

The difference between containers is **runtime configuration**, not image:

| Aspect | workspace | agent |
|--------|-----------|-------|
| **Image** | Same | Same |
| **Command** | Shell (interactive) | `opencode serve` |
| **Security** | Normal | `cap_drop: ALL`, `no-new-privileges` |
| **Secrets** | User's tokens, SSH keys | Only LLM API key |
| **Home** | User's home with dotfiles | Isolated `/home/ai` |
| **Filesystem** | Mutable | Mutable (agent can install tools) |

### Security Model

**What's isolated:**
- Secrets/credentials (agent only has LLM API key)
- Home directory (agent can't see user's ~/.ssh, ~/.config, tokens)
- Container capabilities dropped

**What's shared:**
- Workspace/project files (both can read/write code)
- Network namespace (localhost communication between containers)
- Project toolchain (same image)

**What's NOT solved (future work):**
- Network egress isolation (agent can reach any endpoint)
- Would require proxy/firewall patterns or separate network namespaces

## Implementation Approach

### devaipod as Primary Interface

devaipod wraps DevPod, treating it as an implementation detail:

```bash
# User interacts with devaipod
devaipod up .              # Start workspace
devaipod ssh my-project    # SSH into workspace container
devaipod status            # Show workspaces + agent status
devaipod logs my-project   # Stream agent logs
devaipod stop my-project   # Stop workspace
devaipod delete my-project # Delete workspace
```

### What `devaipod up .` Does

1. **Read** user's `.devcontainer/devcontainer.json`
2. **Build** the devcontainer image (once, used by both containers)
3. **Generate** augmented compose in `.devaipod/`:
   - `docker-compose.yml` with workspace + agent + gator services
   - `devcontainer.json` pointing to compose
   - Merged opencode config with service-gator MCP
4. **Invoke** `devpod up --devcontainer-path .devaipod/devcontainer.json`
5. **Wait** for agent to be healthy
6. **Report** status

### Generated Compose Structure

```yaml
services:
  workspace:
    image: ${DEVAIPOD_IMAGE}  # Pre-built
    volumes:
      - ..:/workspaces/project
      - workspace-home:/home/vscode
    environment:
      - DEVAIPOD_AGENT_URL=http://agent:4096
      - GH_TOKEN
      - JIRA_API_TOKEN
    depends_on:
      agent:
        condition: service_healthy

  agent:
    image: ${DEVAIPOD_IMAGE}  # Same image
    cap_drop: [ALL]
    cap_add: [NET_BIND_SERVICE]
    security_opt: [no-new-privileges:true]
    volumes:
      - ..:/workspaces/project:rw
      - agent-home:/home/ai:rw
    environment:
      - ANTHROPIC_API_KEY
      - HOME=/home/ai
    command: ["opencode", "serve", "--port", "4096", "--hostname", "0.0.0.0"]
    healthcheck:
      test: ["CMD", "curl", "-sf", "http://localhost:4096/global/health"]
      interval: 2s
      timeout: 2s
      retries: 30

  gator:
    image: ghcr.io/cgwalters/service-gator:latest
    environment:
      - GH_TOKEN
      - JIRA_API_TOKEN
    command: ["service-gator", "--mcp-server", "0.0.0.0:8765"]
```

### The `opencode` Shim

Installed in the shared image, wraps opencode to transparently attach:

```bash
#!/bin/bash
# /usr/local/bin/opencode-wrapper
AGENT_URL="${DEVAIPOD_AGENT_URL:-http://agent:4096}"

# Wait for agent readiness
for i in {1..30}; do
  curl -sf "$AGENT_URL/global/health" > /dev/null 2>&1 && break
  echo "Waiting for agent..." >&2
  sleep 1
done

exec /usr/local/bin/opencode-real attach "$AGENT_URL" "$@"
```

### OpenCode Configuration Merging

Need to combine:
- User's opencode config (model preferences, custom settings)
- Our injected config (service-gator MCP server)

**Approach:** At `devaipod up` time, read user's config, merge in our MCP server, write to mounted config volume for agent.

### Feature Still Needed?

Yes, a devaipod devcontainer feature is still useful to:
1. Install opencode (if not present)
2. Install the opencode shim/wrapper
3. Install devaipod utilities
4. Pre-configure opencode with service-gator MCP

The feature prepares the image; compose generation handles orchestration.

## Benefits Over bwrap Approach

1. **Cleaner separation** - containers are natural isolation boundaries
2. **Simpler opencode management** - server in dedicated container
3. **Better security controls** - cap_drop, security_opt at container level
4. **Enables future network isolation** - separate containers could have separate networks
5. **No tmux hacks** - `opencode attach` handles TUI cleanly
6. **Session persistence** - opencode server maintains state across attach/detach
7. **Status visibility** - query agent's HTTP API for status, logs

## Open Questions

### 1. OpenCode Config Merging
How exactly do we merge user's opencode config with our injected MCP server? Need to research opencode's config loading behavior.

### 2. Feature vs Build-Time Injection
Should we use a devcontainer feature, or inject our utilities during the build phase that `devaipod up` controls?

### 3. Existing Compose Devcontainers
If user already has a docker-compose based devcontainer, how do we merge our agent/gator services?

### 4. Build Caching
Ensure single image build even though two services use it. Pre-build with explicit image name recommended.

### 5. Volume Initialization
How to populate agent-config volumes before containers start? Options:
- Bind mount from `.devaipod/` directory
- Init container pattern
- Write during `devaipod up`

### 6. Blended Autonomous/Interactive Mode
The original motivation included "interrupt autonomous runs" workflow:
- `devaipod run --issue URL` starts autonomous agent
- `devaipod attach` interrupts and opens interactive TUI on same session
- opencode's session persistence enables this

## Migration Path

1. **Phase 1:** Implement compose generation for simple devcontainers
2. **Phase 2:** Handle existing compose-based devcontainers
3. **Phase 3:** Add status/logs commands leveraging opencode API
4. **Phase 4:** Add interrupt/attach workflow for blended mode
5. **Phase 5:** Network isolation (separate networks, proxy pattern)

## Related Research

- DevPod supports Docker Compose devcontainers (with some bugs in newer syntax)
- Devcontainer spec has full Docker Compose support with `dockerComposeFile` + `service`
- opencode has rich HTTP API: sessions, messages, events, status
- opencode supports ACP (Agent Client Protocol) for programmatic control
- service-gator provides scoped MCP access to external services

## References

- [DevContainer Spec](https://containers.dev/implementors/spec/)
- [OpenCode Server Docs](https://opencode.ai/docs/server/)
- [OpenCode CLI Docs](https://opencode.ai/docs/cli/)
- [Agent Client Protocol](https://agentclientprotocol.com)
