# Supported Agents

Devaipod works with any ACP-compatible coding agent. This page covers
the agents tested with devaipod and how to configure each for headless
(autonomous) operation.

See [ACP Support](acp.md) for protocol details and
[Configuration](configuration.md) for the `[agent]` config section.

## OpenCode

[OpenCode](https://github.com/anomalyco/opencode) is the default agent,
pre-installed in the `ghcr.io/bootc-dev/devenv-debian` base image.

### Profile

```toml
[agent.profiles.opencode]
command = ["opencode", "acp"]
```

### Headless mode

Set `OPENCODE_PERMISSION` in `[env.vars]` to auto-approve all tools:

```toml
[env.vars]
OPENCODE_PERMISSION = '{"*":"allow"}'
```

### Model selection

OpenCode reads `~/.config/opencode/opencode.json` inside the agent
container. Set this up in your dotfiles:

```json
{
  "$schema": "https://opencode.ai/config.json",
  "model": "google-vertex-anthropic/claude-sonnet-4-20250514"
}
```

| Provider | Model format | Credentials |
|----------|-------------|-------------|
| Vertex AI | `google-vertex-anthropic/claude-sonnet-4-20250514` | `GOOGLE_CLOUD_PROJECT` + ADC |
| Anthropic | `anthropic/claude-sonnet-4-20250514` | `ANTHROPIC_API_KEY` |
| Google Gemini | `google/gemini-2.0-flash` | `GEMINI_API_KEY` |
| OpenAI | `openai/gpt-4o` | `OPENAI_API_KEY` |

## Goose

[Goose](https://github.com/block/goose) is an open-source coding agent
by Block. Install it by building a devcontainer image with the Goose
binary (see `contrib/Containerfile.devenv-goose`).

### Profile

```toml
[agent.profiles.goose]
command = ["goose", "acp"]

[agent.profiles.goose.env]
GOOSE_PROVIDER = "gcp_vertex_ai"
GOOSE_MODEL = "claude-opus-4-6"
GOOSE_MODE = "auto"
GCP_PROJECT_ID = "my-project"
GCP_REGION = "us-east5"
```

### Headless mode

Set `GOOSE_MODE = "auto"` in the profile env. This auto-approves all
tool calls.

### Model and provider selection

Goose selects its provider and model via environment variables in the
profile's `env` section:

| Provider | `GOOSE_PROVIDER` | Model env | Credentials |
|----------|-----------------|-----------|-------------|
| Vertex AI | `gcp_vertex_ai` | `GOOSE_MODEL`, `GCP_PROJECT_ID`, `GCP_REGION` | ADC (`GOOGLE_APPLICATION_CREDENTIALS`) |
| Anthropic | `anthropic` | `GOOSE_MODEL` | `ANTHROPIC_API_KEY` |
| Google Gemini | `google` | `GOOSE_MODEL` | `GOOGLE_API_KEY` |
| OpenAI | `openai` | `GOOSE_MODEL` | `OPENAI_API_KEY` |

## Claude Code

[Claude Code](https://docs.anthropic.com/en/docs/claude-code) uses the
[`claude-agent-acp`](https://github.com/agentclientprotocol/claude-agent-acp)
adapter for ACP support. Install it via
`contrib/Containerfile.devenv-multi-agent`, which includes OpenCode,
Goose, and Claude Code.

### Profile

```toml
[agent.profiles.claude]
command = ["claude-agent-acp"]

[agent.profiles.claude.env]
CLAUDE_CODE_USE_VERTEX = "1"
CLOUD_ML_REGION = "us-east5"
ANTHROPIC_VERTEX_PROJECT_ID = "my-project"
ANTHROPIC_MODEL = "claude-opus-4-6"
```

### Headless mode

The `claude-agent-acp` adapter reads `~/.claude/settings.json` for
permission mode. Bake this into your devcontainer image:

```json
{"permissions":{"defaultMode":"bypassPermissions"}}
```

The `contrib/Containerfile.devenv-multi-agent` does this automatically.

### Model selection

Set `ANTHROPIC_MODEL` in the profile env. The adapter reads this during
`session/new` to select the model.

| Provider | Env vars | Credentials |
|----------|----------|-------------|
| Vertex AI | `CLAUDE_CODE_USE_VERTEX=1`, `CLOUD_ML_REGION`, `ANTHROPIC_VERTEX_PROJECT_ID`, `ANTHROPIC_MODEL` | ADC |
| Anthropic | `ANTHROPIC_MODEL` | `ANTHROPIC_API_KEY` |

## Adding a new agent

Any agent that speaks ACP over stdio can work with devaipod:

1. Install the agent binary in a devcontainer image
2. Add a profile to `devaipod.toml` with the agent's ACP command
3. Configure headless mode via the profile's env or a settings file
   baked into the image
4. Add the profile name to the `default` list

```toml
[agent]
default = ["my-agent", "opencode"]

[agent.profiles.my-agent]
command = ["my-agent", "acp"]

[agent.profiles.my-agent.env]
MY_AGENT_AUTO_APPROVE = "true"
```
