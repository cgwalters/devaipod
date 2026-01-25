# devaipod

**Sandboxed AI coding agents in reproducible dev environments**

Run AI agents with confidence: your code in a devcontainer, the agent in an additional sandbox with only the access it needs.

## On the topic of AI

Note: This tool is primarily authored by @cgwalters who would "un-invent" large language models if he could because
he believes the long term negatives are likely to outweigh the gains. But since that's not possible, this project
is about maximizing the positive aspects of LLMs with a focus on software production (but not exclusively).
We need use LLMs safely and responsibly, with efficient human-in-the-loop controls and auditability.

## Quick Start

```bash
# Clone and build
git clone https://github.com/cgwalters/devaipod && cd devaipod
cargo build --release

# Configure (Vertex AI example)
gcloud auth application-default login
export GOOGLE_CLOUD_PROJECT="your-project-id"
devpod context set-options -o DOTFILES_URL=https://github.com/your/dotfiles

# Run
./target/release/devaipod run --git . "find typos in the docs"
```

See [Secret Management](docs/secrets.md) for detailed setup instructions.

## How It Works

devaipod combines [DevPod](https://devpod.sh/) with [bubblewrap](https://github.com/containers/bubblewrap) sandboxing:

1. **DevPod** creates a reproducible devcontainer with your code
2. **bubblewrap** runs the AI agent in a minimal sandbox inside that container

The agent can read your code and propose changes, but can't access your credentials or modify system files. Network access is currently unrestricted (needed for LLM API calls).

## Usage

```bash
# Run on local repo
devaipod run --git . "explain the main function"

# Run on GitHub issue (auto-clones repo)
devaipod run --issue https://github.com/org/repo/issues/123

# Allow agent to create PRs in specific repos
devaipod run --git . --repo owner/repo "fix the bug and create a PR"
```

Inside a devcontainer:
```bash
devaipod tmux    # Split view: agent + shell
devaipod enter   # Shell into sandbox
```

## Security

The sandbox isolates the agent from:
- Your home directory credentials (SSH keys, tokens, etc.)
- System files (read-only `/usr`, `/etc`, `/lib`)
- Other processes (PID namespace isolation)

The agent can only write to:
- The workspace (`/workspaces/<name>`)
- Its isolated home (`$HOME/ai` mounted over `$HOME`)

For controlled access to external services (like creating PRs), agents should use MCP servers like [service-gator](https://github.com/cgwalters/service-gator) which provides scope-based access control. See [Sandboxing Model](docs/sandboxing.md) for details.

## Status

**Early MVP** - Core sandboxing works.

| Feature | Status |
|---------|--------|
| Sandbox isolation | ✅ Working |
| MCP server integration | ✅ Supported (via service-gator) |
| Network isolation | 🟡 Not yet (full network access) |

## Documentation

- [Sandboxing Model](docs/sandboxing.md) - How the bwrap sandbox works
- [Secret Management](docs/secrets.md) - Handling API keys and credentials
- [OpenCode Agent](docs/opencode.md) - Configuring the default AI agent
- [Service-gator Integration](docs/service-gator.md) - Scope-restricted access to GitHub/JIRA

## License

Apache-2.0 OR MIT
