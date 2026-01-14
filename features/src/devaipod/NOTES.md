## Requirements

This feature requires:
- Linux-based devcontainer (x86_64 or aarch64)
- A compatible base image (Debian, Ubuntu, Fedora, or similar)

The feature will automatically install `bubblewrap` (bwrap) which is required
for the sandboxing functionality.

## What Gets Installed

- `/usr/local/bin/devaipod` - Main CLI for running sandboxed AI agents
- `/usr/lib/devaipod/upcalls/gh-restricted` - Restricted GitHub CLI wrapper

## Usage Inside Devcontainer

Once installed, you can use devaipod commands inside the devcontainer:

```bash
# Start a tmux session with AI agent + shell
devaipod tmux

# Get a shell inside the bwrap sandbox
devaipod enter

# Check upcall state (allowed repos, PRs)
devaipod upcall state
```

## Security Model

The agent runs in a bubblewrap sandbox with:
- Read-only access to system directories (`/usr`, `/etc`, `/lib`)
- Write access only to the workspace directory
- Isolated home directory (`$HOME/ai` mounted over `$HOME`)
- PID namespace isolation

GitHub operations go through the `gh-restricted` upcall which only allows:
- Read operations (pr list, issue view, etc.)
- Draft PR creation (only to allowed repos)
- PR comments/edits (only to PRs created by the agent)
