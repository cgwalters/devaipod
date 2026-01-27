# devaipod

**Sandboxed AI coding agents in reproducible dev environments using podman pods**

Run AI agents with confidence: your code in a devcontainer, the agent in a separate container with security restrictions.

## On the topic of AI

Note: This tool is primarily authored by @cgwalters who would "un-invent" large language models if he could because
he believes the long term negatives are likely to outweigh the gains. But since that's not possible, this project
is about maximizing the positive aspects of LLMs with a focus on software production (but not exclusively).
We need use LLMs safely and responsibly, with efficient human-in-the-loop controls and auditability.

## How It Works

devaipod uses podman pods to create a multi-container environment:

1. Parses your project's `devcontainer.json` to determine the image
2. Creates a podman pod with shared network namespace
3. Starts containers:
   - **workspace**: Your development environment with `oc` and `opencode-agent` shims
   - **agent**: Runs `opencode serve` with security restrictions (dropped capabilities, no-new-privileges)
   - **gator** (optional): [service-gator](https://github.com/cgwalters/service-gator) MCP server for controlled access to GitHub/JIRA

All containers share the same network namespace, allowing localhost communication between the agent and workspace.

## Requirements

- **podman** (rootless works, including inside toolbox containers)
- An image with `opencode` installed (e.g., [devenv-debian](https://github.com/cgwalters/devenv-debian))
- A `devcontainer.json` in your project (`.devcontainer/devcontainer.json` or `.devcontainer.json`)

## Quick Start

```bash
# Clone and build
git clone https://github.com/cgwalters/devaipod && cd devaipod
cargo build --release

# Start a pod for a local project
devaipod up /path/to/your/project

# Start from a GitHub repo
devaipod up https://github.com/org/repo

# Start from a PR and auto-SSH into workspace
devaipod up https://github.com/org/repo/pull/123 -S

# SSH into the workspace container (prefix is optional)
devaipod ssh myproject

# Run opencode (connects to sandboxed agent)
oc
```

## Commands

```bash
# Workspace lifecycle
devaipod up .                     # Create pod with workspace + agent containers
devaipod up . -S                  # Create and SSH into workspace
devaipod up . "fix the bug"       # Create with task description for agent
devaipod list                     # List devaipod workspaces
devaipod status myworkspace       # Show detailed status of a pod
devaipod logs myworkspace         # View container logs (-c agent for agent logs)
devaipod stop myworkspace         # Stop a pod
devaipod delete myworkspace       # Delete a pod
devaipod up . --dry-run           # Show what would be created

# Connecting to workspaces
devaipod ssh myworkspace          # SSH into workspace container
devaipod attach myworkspace       # Attach to agent's tmux session
devaipod ssh-config myworkspace   # Output SSH config to stdout

# Running agents
devaipod run "find typos"                    # Run agent with task
devaipod run --git . "fix the bug"           # Run on local repo
devaipod run --issue https://github.com/org/repo/issues/123

# Shell completions
devaipod completions bash         # Generate bash completions
```

Note: The `devaipod-` prefix is optional for workspace names.

### Editor Integration (WIP)

The `ssh-config` command outputs an SSH config entry to stdout:
```bash
devaipod ssh-config my-pod >> ~/.ssh/config
```

**Note**: Full SSH support for VSCode/Zed Remote SSH requires an SSH server in
the container (currently not implemented). For now, use VSCode's Dev Containers
extension or the CLI workflow.

## Key Features

- **Native podman** - no devpod dependency for core workflow
- **Sandboxed agent** - agent container runs with dropped capabilities, no-new-privileges
- **Workspace shims** - `oc` and `opencode-agent` commands run `opencode attach http://localhost:4096`
- **API keys from environment** - agent receives `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, etc.
- **Network isolation** - optionally restrict agent to allowed LLM API domains via proxy
- **Env allowlist** - per-project env vars in devcontainer.json customizations
- **Toolbox compatible** - works inside toolbox containers

## Security

The agent container runs with restricted privileges:
- Drops all capabilities except `NET_BIND_SERVICE`
- Sets `no-new-privileges`
- Uses an isolated home directory (`/tmp/agent-home`)
- Has read/write access only to the workspace

The workspace container retains normal privileges for development tasks.

For controlled access to external services (like creating PRs), use the `--service-gator` flag or configure in your `~/.config/devaipod.toml`:

```bash
# Grant the agent read-only access to all GitHub repos
devaipod up . --service-gator=github:readonly-all

# Grant read access to specific repos only
devaipod up . --service-gator=github:myorg/myrepo
```

Credentials like `GH_TOKEN` are forwarded only to trusted containers (workspace, gator), never to the agent. See [Service-gator Integration](docs/service-gator.md) for full details.

### Network Isolation

When enabled, agent network access is restricted to allowed LLM API endpoints via an HTTPS proxy:

```toml
# ~/.config/devaipod.toml
[network-isolation]
enabled = true
allowed_domains = ["api.custom.com"]  # Additional domains (LLM APIs allowed by default)
```

### Global Environment Variables

Configure environment variables to inject into all containers (workspace + agent) in `~/.config/devaipod.toml`:

```toml
[env]
# Forward these from host environment (if they exist)
allowlist = ["GOOGLE_CLOUD_PROJECT", "SSH_AUTH_SOCK", "VERTEX_LOCATION"]

# Set these explicitly
[env.vars]
VERTEX_LOCATION = "global"
EDITOR = "vim"
```

This is useful for cloud provider credentials, editor preferences, and other env vars needed in both containers.

### Per-Project Environment Variables

Projects can specify additional env vars to pass to the agent in devcontainer.json:

```json
{
  "customizations": {
    "devaipod": {
      "envAllowlist": ["MY_API_KEY", "CUSTOM_TOKEN"]
    }
  }
}
```

## Status

| Feature | Status |
|---------|--------|
| Native podman commands | ✅ Working |
| Agent container isolation | ✅ Working |
| devcontainer.json parsing | ✅ Working |
| Dockerfile builds | ✅ Working |
| Lifecycle commands | ✅ Working |
| service-gator integration | ✅ Optional |
| Network isolation | ✅ Optional (proxy-based) |
| Env allowlist | ✅ Working |
| GPU passthrough | ✅ Optional (NVIDIA/AMD) |
| PR/MR URL support | ✅ Working |
| Remote git URLs | ✅ Working |

## Documentation

- [Sandboxing Model](docs/sandboxing.md) - Security model details
- [Secret Management](docs/secrets.md) - Handling API keys and credentials
- [OpenCode Agent](docs/opencode.md) - Configuring the AI agent
- [Service-gator Integration](docs/service-gator.md) - Scope-restricted access to GitHub/JIRA

## License

Apache-2.0 OR MIT
