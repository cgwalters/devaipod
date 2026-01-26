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
   - **workspace**: Your development environment (runs `sleep infinity`)
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
./target/release/devaipod up /path/to/your/project

# Access the workspace container
podman exec -it devaipod-yourproject-workspace bash

# Agent is running at http://localhost:4096
```

## Usage

```bash
# Start a pod (requires local path with devcontainer.json)
devaipod up .

# Dry run - show what would be created
devaipod up . --dry-run

# Stop the pod
podman pod stop devaipod-yourproject

# Remove the pod
podman pod rm devaipod-yourproject
```

## Security

The agent container runs with restricted privileges:
- Drops all capabilities except `NET_BIND_SERVICE`
- Sets `no-new-privileges`
- Uses an isolated home directory (`/tmp/agent-home`)
- Has read/write access only to the workspace

The workspace container retains normal privileges for development tasks.

For controlled access to external services (like creating PRs), configure service-gator in your `~/.config/devaipod.toml`.

## Status

**Early MVP** - Core pod orchestration works.

| Feature | Status |
|---------|--------|
| Podman pod orchestration | ✅ Working |
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
