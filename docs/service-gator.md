# Service-gator Integration

## Overview

[service-gator](https://github.com/cgwalters/service-gator) is an MCP server that provides scope-restricted access to external services (GitHub, JIRA, GitLab) for AI agents. It runs **outside** the bwrap sandbox but inside the devcontainer, providing a security boundary between the sandboxed agent and your external credentials.

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│  DevPod Container                                           │
│  ┌───────────────────────────────────────────────────────┐  │
│  │  service-gator MCP Server                             │  │
│  │  • Listens on 127.0.0.1:8765/mcp                      │  │
│  │  • Has access to GH_TOKEN, JIRA_API_TOKEN             │  │
│  │  • Scope configured via devaipod.toml                 │  │
│  └───────────────────────────────────────────────────────┘  │
│                          ↑ HTTP                             │
│  ┌───────────────────────│───────────────────────────────┐  │
│  │  bwrap Sandbox        │                               │  │
│  │  ┌────────────────────│────────────────────────────┐  │  │
│  │  │  opencode                                       │  │  │
│  │  │  • Config includes service-gator as remote MCP  │  │  │
│  │  │  • Connects via http://127.0.0.1:8765/mcp       │  │  │
│  │  └─────────────────────────────────────────────────┘  │  │
│  └───────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

## Configuration

Configure service-gator in `~/.config/devaipod.toml`:

```toml
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

When you run `devaipod tmux` or `devaipod run`:

1. **devaipod reads** your `~/.config/devaipod.toml`
2. **If service-gator is configured**, devaipod:
   - Writes the scope config to `/var/run/devaipod/service-gator.toml`
   - Starts service-gator MCP server on 127.0.0.1:8765
   - Configures opencode to connect to service-gator via MCP
3. **The agent** (running inside bwrap) can now use GitHub/JIRA tools, but only with the permissions you've configured

## Dynamic Configuration

service-gator monitors its config file for changes. You can update scopes at runtime:

```bash
# Inside the devcontainer (outside the sandbox)
cat >> ~/.config/devaipod.toml << 'EOF'
[service-gator.gh.prs]
"myorg/repo#99" = { read = true, write = true }
EOF
```

The new scope takes effect immediately without restarting.

## Requirements

- `service-gator` must be installed in the container image
- `GH_TOKEN` must be available in the container environment (outside the sandbox)
- For JIRA, `JIRA_API_TOKEN` and JIRA CLI (`jirust-cli`) are needed

## Security Benefits

1. **Credential Isolation**: API tokens stay outside the sandbox; the agent never sees them
2. **Fine-grained Scoping**: Grant exactly the permissions needed, no more
3. **Audit Trail**: service-gator logs all API calls with scope checks
4. **Dynamic Revocation**: Update or remove permissions instantly via config file

## See Also

- [Sandboxing Model](sandboxing.md) - How the bwrap sandbox works
- [Secret Management](secrets.md) - Handling API keys and credentials
- [service-gator README](https://github.com/cgwalters/service-gator) - Full documentation
