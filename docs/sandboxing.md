# Sandboxing Model

## Overview

devaipod isolates AI agents using podman pods with multiple containers. The agent runs in a separate container with security restrictions, while the workspace container retains full privileges for development tasks.

## Defense in Depth

The agent runs with **multiple layers of isolation**:

1. **Container isolation** - The agent runs in its own container, separate from the workspace. It cannot directly access workspace processes or files outside the shared volume.

2. **Capability restrictions** - The agent container drops all Linux capabilities except `NET_BIND_SERVICE`, preventing privilege escalation.

3. **no-new-privileges** - The agent cannot gain additional privileges through setuid binaries or other mechanisms.

4. **Isolated home directory** - The agent's `$HOME` is set to `/tmp/agent-home`, an isolated directory that doesn't contain user credentials.

**Key property:** Even if the agent compromises its container, it cannot access the workspace container's environment, credentials, or elevated privileges.

## Architecture

```
┌────────────────────────────────────────────────────────────────────┐
│  Host (rootless podman)                                            │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │  Podman Pod (shared network namespace)                       │  │
│  │                                                               │  │
│  │  ┌─────────────────────┐  ┌─────────────────────┐            │  │
│  │  │ Workspace Container │  │ Agent Container     │            │  │
│  │  │ • Full dev env      │  │ • opencode serve    │            │  │
│  │  │ • Your dotfiles     │  │ • Port 4096         │            │  │
│  │  │ • GH_TOKEN, etc.    │  │ • Dropped caps      │            │  │
│  │  │ • 'oc' shim         │  │ • no-new-privileges │            │  │
│  │  └─────────────────────┘  │ • Isolated $HOME    │            │  │
│  │           │               └─────────────────────┘            │  │
│  │           │                         │                        │  │
│  │           └─────────────────────────┘                        │  │
│  │                   Shared workspace volume                     │  │
│  │                                                               │  │
│  │  ┌─────────────────────┐  ┌─────────────────────┐            │  │
│  │  │ Gator Container     │  │ Proxy Container     │            │  │
│  │  │ (optional)          │  │ (optional)          │            │  │
│  │  │ • service-gator MCP │  │ • HTTPS proxy       │            │  │
│  │  │ • Has GH_TOKEN      │  │ • Domain allowlist  │            │  │
│  │  │ • Port 8765         │  │ • Network isolation │            │  │
│  │  └─────────────────────┘  └─────────────────────┘            │  │
│  └──────────────────────────────────────────────────────────────┘  │
└────────────────────────────────────────────────────────────────────┘
```

## Container Security

### Workspace Container
- Runs your devcontainer image with full privileges
- Has access to your dotfiles, credentials, and environment
- Can run privileged operations (build, test, deploy)
- Contains `oc` and `opencode-agent` shims that connect to the agent

### Agent Container
- Same devcontainer image, but with restrictions:
  - **Drops ALL capabilities** except `NET_BIND_SERVICE`
  - **no-new-privileges** flag set
  - **Isolated home directory** at `/tmp/agent-home`
- Runs `opencode serve` on port 4096
- Receives only LLM API keys (ANTHROPIC_API_KEY, OPENAI_API_KEY, etc.)
- Does NOT receive trusted credentials (GH_TOKEN, etc.)
- Has read/write access only to the workspace volume

### Gator Container (Optional)
- Runs [service-gator](https://github.com/cgwalters/service-gator) MCP server
- Receives trusted credentials (GH_TOKEN, JIRA_API_TOKEN)
- Provides scope-restricted access to external services
- Agent connects via MCP protocol, never sees raw credentials

### Proxy Container (Optional)
- HTTPS proxy for network isolation
- Restricts agent to allowed LLM API domains
- Prevents exfiltration to arbitrary endpoints

## Volume Strategy

Workspace code is cloned into a podman volume (not bind-mounted from host):

- **Volume name:** `{pod_name}-workspace`
- **Benefits:** Avoids UID mapping issues with rootless podman
- **Access:** Both workspace and agent containers mount this volume

## Environment Variable Isolation

Environment variables are carefully partitioned:

| Variable Type | Workspace | Agent | Gator |
|---------------|-----------|-------|-------|
| LLM API keys (ANTHROPIC_API_KEY, etc.) | ✅ | ✅ | ❌ |
| Trusted env (GH_TOKEN, etc.) | ✅ | ❌ | ✅ |
| Global env allowlist | ✅ | ✅ | ✅ |
| Project env allowlist | ✅ | ✅ | ❌ |

Configure trusted environment variables in `~/.config/devaipod.toml`:

```toml
[trusted.env]
allowlist = ["GH_TOKEN", "GITLAB_TOKEN", "JIRA_API_TOKEN"]
```

## Known Limitations

1. **Workspace file access**: The agent can read/write any file in the workspace. Secrets in `.env` files are visible.

2. **Network access**: Without the proxy container, the agent has full network access. Enable network isolation in config:
   ```toml
   [network-isolation]
   enabled = true
   ```

3. **Same image requirement**: The agent container uses the same image as the workspace. OpenCode must be installed in your devcontainer image.

## External Service Access

For operations requiring access to external services (GitHub, JIRA, etc.), agents use the integrated [service-gator](https://github.com/cgwalters/service-gator) MCP server which provides scope-based access control.

See [Service-gator Integration](service-gator.md) for full documentation.
