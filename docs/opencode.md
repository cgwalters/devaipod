# OpenCode Integration

## Overview

[OpenCode](https://github.com/anomalyco/opencode) is an open-source TUI for AI coding agents. devaipod runs OpenCode in a sandboxed agent container within a podman pod.

## Installation

OpenCode must be available in your devcontainer image. The `ghcr.io/bootc-dev/devenv-debian` base image comes with OpenCode pre-installed.

## Configuration

OpenCode is configured via `~/.config/opencode/opencode.json`. Set this up in your dotfiles:

```json
{
  "$schema": "https://opencode.ai/config.json",
  "model": "google-vertex-anthropic/claude-sonnet-4-20250514"
}
```

### Supported Providers

| Provider | Model Example | Env Vars Needed |
|----------|---------------|-----------------|
| Vertex AI | `google-vertex-anthropic/claude-sonnet-4-20250514` | `GOOGLE_CLOUD_PROJECT` + gcloud ADC |
| Anthropic | `anthropic/claude-sonnet-4-20250514` | `ANTHROPIC_API_KEY` |
| Google Gemini | `google/gemini-2.0-flash` | `GEMINI_API_KEY` |
| OpenAI | `openai/gpt-4o` | `OPENAI_API_KEY` |

## Usage with devaipod

```bash
# Create workspace and SSH in
devaipod up /path/to/project -S
# Then run 'oc' inside the workspace to connect to the agent

# Create workspace with a task for the agent
devaipod up . "fix the type errors in main.rs"

# Run agent on a GitHub issue
devaipod run --issue https://github.com/org/repo/issues/123

# Attach to a running agent's tmux session
devaipod attach myworkspace
```

## Architecture

devaipod uses a podman pod with multiple containers:

```
┌───────────────────────────────────────────────────────────────────┐
│  Podman Pod                                                        │
│                                                                    │
│  ┌─────────────────────┐  ┌─────────────────────┐                 │
│  │ Workspace Container │  │ Agent Container     │                 │
│  │ • Full dev env      │  │ • opencode serve    │                 │
│  │ • 'oc' shim         │  │ • Port 4096         │                 │
│  │ • Your dotfiles     │  │ • Isolated $HOME    │                 │
│  └─────────────────────┘  └─────────────────────┘                 │
│                                      │                             │
│         'oc' ──────────────────────→ │ (localhost:4096)            │
│                                                                    │
└───────────────────────────────────────────────────────────────────┘
```

The workspace container has an `oc` shim that runs `opencode attach http://localhost:4096` to connect to the sandboxed agent. All containers share the same network namespace via the pod.

## Agent Support

Currently only OpenCode is supported as the AI agent. The agent container runs `opencode serve` and the workspace connects via `opencode attach`.
