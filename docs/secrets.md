# Secret Management

> **Implementation details:** See `src/secrets.rs` and `src/pod.rs`

## Overview

devaipod carefully partitions environment variables between containers to keep credentials secure. LLM API keys go to the agent, but trusted credentials (like `GH_TOKEN`) stay in workspace and gator containers only.

## How It Works

1. **Declare secrets in devcontainer.json:**
   ```json
   {
     "secrets": {
       "GEMINI_API_KEY": {
         "description": "API key for Google Gemini"
       },
       "ANTHROPIC_API_KEY": {
         "description": "API key for Claude"
       }
     }
   }
   ```

2. **Create matching podman secrets on your host:**
   ```bash
   echo "your-gemini-key" | podman secret create GEMINI_API_KEY -
   echo "sk-ant-xxx" | podman secret create ANTHROPIC_API_KEY -
   
   # Verify
   podman secret ls
   ```

3. **Run devaipod** - secrets are automatically:
   - Read from devcontainer.json `secrets` field
   - Fetched from podman via `podman secret inspect --showsecret`
   - Injected into the appropriate containers

## Alternative Methods

### Vertex AI / gcloud ADC

For Google Cloud Vertex AI, bind-mount your gcloud config:

```json
{
  "mounts": [{
    "source": "${localEnv:HOME}/.config/gcloud",
    "target": "/home/devenv/.config/gcloud",
    "type": "bind"
  }],
  "containerEnv": {
    "GOOGLE_CLOUD_PROJECT": "${localEnv:GOOGLE_CLOUD_PROJECT}"
  }
}
```

### Environment Variables

Pass directly via `containerEnv`:

```json
{
  "containerEnv": {
    "GEMINI_API_KEY": "${localEnv:GEMINI_API_KEY}"
  }
}
```

### Dotfiles

Configure in your dotfiles repo (e.g., `~/.config/opencode/opencode.json`).

## What Gets Forwarded to Agent Container

The agent container receives LLM API keys but NOT trusted credentials:

| Variable Type | Workspace | Agent | Gator |
|---------------|-----------|-------|-------|
| `ANTHROPIC_API_KEY` | ✅ | ✅ | ❌ |
| `OPENAI_API_KEY` | ✅ | ✅ | ❌ |
| `GEMINI_API_KEY` | ✅ | ✅ | ❌ |
| `GH_TOKEN` | ✅ | ❌ | ✅ |
| `GITLAB_TOKEN` | ✅ | ❌ | ✅ |
| Global env allowlist | ✅ | ✅ | ✅ |

### Trusted Environment Variables

Configure which credentials go to workspace and gator (but NOT agent) in `~/.config/devaipod.toml`:

```toml
[trusted.env]
# These env vars go to workspace and gator containers only
allowlist = ["GH_TOKEN", "GITLAB_TOKEN", "JIRA_API_TOKEN"]

# Or set explicit values
[trusted.env.vars]
GH_TOKEN = "ghp_xxxxxxxxxxxx"
```

### Global Environment Variables

Configure variables that go to ALL containers (including agent):

```toml
[env]
# Forward from host environment
allowlist = ["GOOGLE_CLOUD_PROJECT", "SSH_AUTH_SOCK", "VERTEX_LOCATION"]

# Set explicit values
[env.vars]
VERTEX_LOCATION = "global"
```

## GitHub Token

`GH_TOKEN` is intentionally NOT forwarded to the agent. For GitHub operations, agents should use MCP servers like [service-gator](https://github.com/cgwalters/service-gator) which run in a separate container with appropriate scope restrictions.

See [Service-gator Integration](service-gator.md) for details.
