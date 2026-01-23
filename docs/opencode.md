# OpenCode Integration

## Overview

[OpenCode](https://github.com/anomalyco/opencode) is an open-source TUI for AI coding agents. devaipod uses OpenCode (v1.1.12) as its default agent inside the bwrap sandbox.

## Installation

OpenCode is pre-installed in the `ghcr.io/bootc-dev/devenv-debian` base image used by the devcontainer. The devaipod devcontainer feature expects opencode to be available in the base image.

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
# Run opencode agent on local repo
devaipod run --git . "explain the main function"

# Run on a GitHub issue
devaipod run --issue https://github.com/org/repo/issues/123

# Inside devcontainer: tmux with agent + shell
devaipod tmux

# Inside devcontainer: enter sandbox shell
devaipod enter
```

## Architecture

```
┌─────────────────────────────────────────────┐
│       DevPod Container                      │
│  ┌───────────────────────────────────────┐  │
│  │       bwrap Sandbox                   │  │
│  │                                       │  │
│  │   $ opencode run "task..."            │  │
│  │                                       │  │
│  │   - Read-only /usr, /etc, /lib        │  │
│  │   - Isolated $HOME                    │  │
│  │   - Upcalls via /run/devaipod.sock    │  │
│  └───────────────────────────────────────┘  │
└─────────────────────────────────────────────┘
```

## Alternative Agents

To use a different agent, specify it with `--agent`:

```bash
devaipod run --git . --agent goose "fix the bug"
```

Or set a default in `~/.config/devc.toml`:

```toml
[agent]
default_agent = "goose"
```

The agent binary must be installed in the container image.
