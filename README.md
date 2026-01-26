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

# Start a pod for your project
devaipod up /path/to/your/project

# SSH into the workspace container
devaipod ssh devaipod-myproject

# Run opencode (connects to sandboxed agent)
oc
```

## Commands

```bash
devaipod up .              # Create pod with workspace + agent containers
devaipod list              # List devaipod pods
devaipod ssh <pod>         # SSH into workspace container
devaipod ssh-config <pod>  # Generate SSH config (for editor integration)
devaipod stop <pod>        # Stop a pod
devaipod delete <pod>      # Delete a pod
devaipod up . --dry-run    # Show what would be created
```

### Editor Integration (WIP)

The `ssh-config` command generates an SSH config entry:
```bash
devaipod ssh-config my-pod  # Writes to ~/.ssh/config.d/devaipod-my-pod
```

**Note**: Full SSH support for VSCode/Zed Remote SSH requires an SSH server in
the container (currently not implemented). For now, use VSCode's Dev Containers
extension or the CLI workflow.

## Key Features

- **Native podman** - no devpod dependency for core workflow
- **Sandboxed agent** - agent container runs with dropped capabilities, no-new-privileges
- **Workspace shims** - `oc` and `opencode-agent` commands run `opencode attach http://localhost:4096`
- **API keys from environment** - agent receives `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, etc.
- **Toolbox compatible** - works inside toolbox containers

## Security

The agent container runs with restricted privileges:
- Drops all capabilities except `NET_BIND_SERVICE`
- Sets `no-new-privileges`
- Uses an isolated home directory (`/tmp/agent-home`)
- Has read/write access only to the workspace

The workspace container retains normal privileges for development tasks.

For controlled access to external services (like creating PRs), configure service-gator in your `~/.config/devaipod.toml`.

## Status

| Feature | Status |
|---------|--------|
| Native podman commands | ✅ Working |
| Agent container isolation | ✅ Working |
| devcontainer.json parsing | ✅ Working |
| Dockerfile builds | ✅ Working |
| Lifecycle commands | ✅ Working |
| service-gator integration | ✅ Optional |
| Network isolation | 🟡 Not yet (full network access) |

## Documentation

- [Sandboxing Model](docs/sandboxing.md) - Security model details
- [Secret Management](docs/secrets.md) - Handling API keys and credentials
- [OpenCode Agent](docs/opencode.md) - Configuring the AI agent
- [Service-gator Integration](docs/service-gator.md) - Scope-restricted access to GitHub/JIRA

## License

Apache-2.0 OR MIT
