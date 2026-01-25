# Secret Management

> **Implementation details:** See `src/secrets.rs` and `src/devpod.rs`

## Overview

devaipod bridges `devcontainer.json` secret declarations to podman secrets, passing them to devpod via `--workspace-env`. No source files are modified.

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
   - Passed to devpod via `--workspace-env NAME=value`

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

## What Gets Forwarded to Sandbox

The sandbox receives **only** environment variables with the `DEVAIPOD_AGENT_` prefix. The prefix is stripped when forwarding:

```bash
# Set in your shell or dotfiles:
export DEVAIPOD_AGENT_ANTHROPIC_API_KEY="sk-ant-xxx"
export DEVAIPOD_AGENT_GOOGLE_CLOUD_PROJECT="my-project"

# Agent sees:
# ANTHROPIC_API_KEY=sk-ant-xxx
# GOOGLE_CLOUD_PROJECT=my-project
```

This makes it explicit which secrets the agent can access. There is no hardcoded allowlist.

**NOT forwarded** (kept outside sandbox):
- `GH_TOKEN` - GitHub access should use MCP servers (like service-gator) running outside the sandbox
- `ANTHROPIC_API_KEY` (without prefix) - only the prefixed version is forwarded
- Any env var without the `DEVAIPOD_AGENT_` prefix

### Example Setup

In your dotfiles or shell profile:

```bash
# LLM API key - agent needs this
export DEVAIPOD_AGENT_ANTHROPIC_API_KEY="$ANTHROPIC_API_KEY"

# Vertex AI config - agent needs this
export DEVAIPOD_AGENT_GOOGLE_CLOUD_PROJECT="$GOOGLE_CLOUD_PROJECT"

# GH_TOKEN stays unprefixed - for MCP servers running outside sandbox
export GH_TOKEN="ghp_full_access"
```

### Different Credentials for Agent vs Outer Container

You can give the agent different credentials than human tools in the outer container:

```bash
# Full-access token for human tools and MCP servers
export GH_TOKEN="ghp_full_access"

# Restricted token for the agent (or omit to give agent no GH_TOKEN)
export DEVAIPOD_AGENT_GH_TOKEN="ghp_readonly"
```

| Variable | Outer Container | Agent Sandbox |
|----------|-----------------|---------------|
| `GH_TOKEN` | `ghp_full_access` | (not set) |
| `DEVAIPOD_AGENT_GH_TOKEN` | `ghp_readonly` | (not set) |
| `GH_TOKEN` (inside sandbox) | - | `ghp_readonly` |

The `DEVAIPOD_AGENT_*` vars are available in the outer container too (for scripts that need them), but only the stripped versions are forwarded into the sandbox.

## GitHub Token

`GH_TOKEN` is intentionally NOT forwarded to the sandbox. For GitHub operations, agents should use MCP servers like [service-gator](https://github.com/cgwalters/service-gator) which run outside the sandbox with appropriate access controls.
