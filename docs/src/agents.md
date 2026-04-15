# Supported Agents

Devaipod works with any ACP-compatible coding agent. This page covers
agents tested with devaipod and how to configure each for autonomous
operation.

See [ACP Support](acp.md) for protocol details and
[Configuration](configuration.md) for the `[agent]` config section.

## Headless Operation

Each agent must run with permissive internal permissions so it does not
block waiting for interactive approval. The mechanism varies by agent.

## OpenCode

[OpenCode](https://github.com/anomalyco/opencode) is the default agent,
pre-installed in the `ghcr.io/bootc-dev/devenv-debian` base image.

```toml
[agent.profiles.opencode]
command = ["opencode", "acp"]
```

**Headless mode**: Set `OPENCODE_PERMISSION` in `[env.vars]`:

```toml
[env.vars]
OPENCODE_PERMISSION = '{"*":"allow"}'
```

**Model selection**: OpenCode reads `~/.config/opencode/opencode.json`
inside the agent container (configure via dotfiles). See the
[OpenCode documentation](https://github.com/anomalyco/opencode) for
provider and model options.

## Goose

[Goose](https://github.com/block/goose) is an open-source coding agent
by Block. The devcontainer image must include the `goose` binary.

```toml
[agent.profiles.goose]
command = ["goose", "acp"]
```

**Headless mode**: Set `GOOSE_MODE = "auto"` in the profile env.

**Model selection**: Set `GOOSE_PROVIDER` and `GOOSE_MODEL` in the
profile env. See the [Goose documentation](https://block.github.io/goose/)
for provider and model options.

## Claude Code

[Claude Code](https://docs.anthropic.com/en/docs/claude-code) requires
the [`claude-agent-acp`](https://github.com/agentclientprotocol/claude-agent-acp)
adapter for ACP support. The devcontainer image must include the
`claude-agent-acp` binary.

```toml
[agent.profiles.claude]
command = ["claude-agent-acp"]
```

**Headless mode**: The adapter reads `~/.claude/settings.json` for
permission mode. The devcontainer image must include this file at
`~/.claude/settings.json`:

```json
{"permissions":{"defaultMode":"bypassPermissions"}}
```

**Model selection**: Set `ANTHROPIC_MODEL` in the profile env. See the
[Claude Code documentation](https://docs.anthropic.com/en/docs/claude-code)
for provider and model options.

## Adding a New Agent

Any agent that speaks ACP over stdio works with devaipod:

1. Include the agent binary in your devcontainer image
2. Add a profile to `devaipod.toml` with the agent's ACP command
3. Configure the agent for headless operation (env vars, config files,
   or CLI flags — whatever the agent requires)
4. Add the profile name to the `default` list

```toml
[agent]
default = ["my-agent", "opencode"]

[agent.profiles.my-agent]
command = ["my-agent", "acp"]

[agent.profiles.my-agent.env]
MY_AGENT_AUTO_APPROVE = "true"
```
