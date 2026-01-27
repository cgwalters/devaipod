# Service-gator Integration

## Overview

[service-gator](https://github.com/cgwalters/service-gator) is an MCP server that provides scope-restricted access to external services (GitHub, JIRA, GitLab) for AI agents. It runs in a **separate gator container** alongside the workspace and agent containers, providing a security boundary between the sandboxed AI agent and your external credentials.

## Architecture

```
┌───────────────────────────────────────────────────────────────────┐
│  Podman Pod                                                        │
│                                                                    │
│  ┌─────────────────────┐  ┌─────────────────────┐                 │
│  │ Workspace Container │  │ Gator Container     │                 │
│  │ • Full dev env      │  │ • service-gator     │                 │
│  │ • Has GH_TOKEN      │  │ • Has GH_TOKEN      │                 │
│  │ • (trusted)         │  │ • Scope-restricted  │                 │
│  └─────────────────────┘  └──────────┬──────────┘                 │
│                                      │ MCP (HTTP)                  │
│  ┌───────────────────────────────────┼──────────────────────────┐ │
│  │ Agent Container (restricted)      │                          │ │
│  │ • opencode serve                  │                          │ │
│  │ • NO GH_TOKEN (no direct access)  │                          │ │
│  │ • Connects to gator via MCP ──────┘                          │ │
│  │ • Dropped capabilities, no-new-privileges                    │ │
│  └──────────────────────────────────────────────────────────────┘ │
└───────────────────────────────────────────────────────────────────┘
```

## Quick Start (CLI)

The simplest way to use service-gator is via command-line flags:

```bash
# Read-only access to all GitHub repos
devaipod up . --service-gator=github:readonly-all

# Read access to specific repos
devaipod up . --service-gator=github:myorg/myrepo

# Read access to all repos in an org
devaipod up . --service-gator=github:myorg/*

# Write access to a specific repo
devaipod up . --service-gator=github:myorg/myrepo:write

# Multiple scopes
devaipod up . \
  --service-gator=github:myorg/frontend \
  --service-gator=github:myorg/backend:write
```

### CLI Scope Format

```
--service-gator=SERVICE:TARGET[:PERMISSIONS]
```

- **SERVICE**: `github` (or `gh`), `gitlab` (future), `jira` (future)
- **TARGET**: Repository pattern like `owner/repo` or `owner/*`, or special keyword like `readonly-all`
- **PERMISSIONS**: Comma-separated list (default: `read`)
  - `read` - Read-only access
  - `create-draft` - Create draft PRs
  - `pending-review` - Manage pending PR reviews
  - `write` - Full write access

## Configuration File

For persistent configuration, use `~/.config/devaipod.toml`:

```toml
# Trusted environment variables - forwarded to workspace and gator containers
# but NOT to the agent container. This is where credentials go.
[trusted.env]
allowlist = ["GH_TOKEN", "GITLAB_TOKEN", "JIRA_API_TOKEN"]

[service-gator]
# Optional: explicitly enable (auto-enabled if any scopes are configured)
enabled = true
# Optional: custom port (default: 8765)
port = 8765

# GitHub repository permissions
[service-gator.gh.repos]
# Read-only access to all repos under an owner
"myorg/*" = { read = true }

# Read + create draft PRs for a specific repo
"myorg/main-project" = { read = true, create-draft = true }

# Read + manage pending PR reviews (for AI code review)
"myorg/reviewed-repo" = { read = true, pending-review = true }

# Full write access (use sparingly!)
"myorg/trusted-repo" = { read = true, create-draft = true, pending-review = true, write = true }

# PR-specific grants (typically set dynamically)
[service-gator.gh.prs]
"myorg/repo#42" = { read = true, write = true }

# JIRA project permissions
[service-gator.jira.projects]
"MYPROJ" = { read = true, create = true }
"OTHER" = { read = true }

# JIRA issue-specific grants
[service-gator.jira.issues]
"MYPROJ-123" = { read = true, write = true }
```

### Trusted Environment Variables

The `[trusted.env]` section is critical for service-gator to work:

```toml
[trusted.env]
# These env vars are forwarded ONLY to workspace and gator containers
# The AI agent container does NOT receive these - it must go through service-gator
allowlist = ["GH_TOKEN", "GITLAB_TOKEN", "JIRA_API_TOKEN"]

# You can also set explicit values
[trusted.env.vars]
GH_TOKEN = "ghp_xxxxxxxxxxxx"
```

This ensures credentials are available to service-gator but not directly accessible by the AI agent.

## Permission Levels

### GitHub

| Permission | Description |
|------------|-------------|
| `read` | View PRs, issues, code, run status, etc. |
| `create-draft` | Create draft PRs only (safer for review workflows) |
| `pending-review` | Create, update, and delete pending PR reviews |
| `write` | Full access (merge, close, create non-draft PRs, etc.) |

### JIRA

| Permission | Description |
|------------|-------------|
| `read` | View issues, projects, search |
| `create` | Create new issues |
| `write` | Full access (update, transition, comment, etc.) |

## Pattern Matching

Repository patterns support trailing wildcards:
- `owner/repo` - Exact match
- `owner/*` - All repos under `owner`
- More specific patterns take precedence over wildcards

## How It Works

When you run `devaipod up`:

1. **devaipod parses** CLI `--service-gator` flags and merges with `~/.config/devaipod.toml`
2. **If service-gator is enabled**, devaipod creates a pod with:
   - **workspace container**: Full dev environment with trusted env vars (GH_TOKEN, etc.)
   - **gator container**: Runs `service-gator` with scopes and trusted env vars
   - **agent container**: Runs `opencode serve` with NO trusted env vars, configured to use gator MCP
3. **The agent** can use GitHub/JIRA tools via MCP, but only with the configured scopes
4. **Credentials never reach the agent** - they stay in the trusted containers

## Requirements

- `GH_TOKEN` must be configured via `[trusted.env]` in devaipod.toml or set in your environment
- For JIRA, `JIRA_API_TOKEN` should be in `[trusted.env]`

The service-gator container image (`ghcr.io/cgwalters/service-gator`) is automatically pulled.

## Security Benefits

1. **Credential Isolation**: API tokens are in workspace/gator containers only; the agent never sees them
2. **Container Separation**: Agent runs in a separate container with dropped capabilities
3. **Fine-grained Scoping**: Grant exactly the permissions needed via CLI or config
4. **MCP Protocol**: Agent communicates with external services only through the MCP interface

## See Also

- [Sandboxing Model](sandboxing.md) - Security model and container isolation
- [Secret Management](secrets.md) - Handling API keys and credentials
- [service-gator README](https://github.com/cgwalters/service-gator) - Full documentation
