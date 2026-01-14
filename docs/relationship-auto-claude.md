# Relationship to Auto-Claude

## Overview

[Auto-Claude](https://github.com/AndyMik90/Auto-Claude) is an open-source autonomous multi-agent coding framework with a polished desktop UI. It provides visual task management, parallel agent execution, and self-validating QA loops. This document analyzes how devaipod could serve as a sandboxed backend for Auto-Claude's interface.

## License

Auto-Claude is licensed under **AGPL-3.0**. The repository includes:
- Electron desktop application (TypeScript)
- Python backend for agent orchestration
- Spec/QA pipeline for autonomous task execution
- Integration with Claude Code CLI

## Architecture Overview

Auto-Claude is structured as a desktop application with a Python backend:

| Component | Description |
|-----------|-------------|
| **Frontend** | Electron app with Kanban board, agent terminals, roadmap view |
| **Backend** | Python orchestration layer (`apps/backend/`) |
| **Spec Runner** | Autonomous task planning and execution |
| **QA Pipeline** | Self-validating quality assurance loop |
| **Git Worktrees** | Isolated workspaces for each task |

### Key Features

1. **Kanban Board**: Visual task management from planning through completion
2. **Parallel Execution**: Run up to 12 agent terminals simultaneously
3. **Git Worktree Isolation**: Each task works in an isolated branch
4. **Self-Validating QA**: Agents validate their own work before review
5. **AI-Powered Merge**: Automatic conflict resolution
6. **Memory Layer**: Agents retain insights across sessions

## The Interface Opportunity

Auto-Claude has an excellent UI for managing autonomous AI coding sessions:

```
┌─────────────────────────────────────────────────────────────┐
│                    Auto-Claude Kanban                        │
├───────────────┬───────────────┬───────────────┬─────────────┤
│   PLANNING    │  IN PROGRESS  │   VALIDATING  │  COMPLETED  │
├───────────────┼───────────────┼───────────────┼─────────────┤
│ ┌───────────┐ │ ┌───────────┐ │ ┌───────────┐ │             │
│ │ Add auth  │ │ │ Fix bug   │ │ │ Add tests │ │             │
│ │ feature   │ │ │ in parser │ │ │ for API   │ │             │
│ └───────────┘ │ └───────────┘ │ └───────────┘ │             │
└───────────────┴───────────────┴───────────────┴─────────────┘
                      ↓
            ┌─────────────────────┐
            │   Agent Terminals   │
            │  ┌───┐ ┌───┐ ┌───┐  │
            │  │ 1 │ │ 2 │ │ 3 │  │  ← Multiple agents working
            │  └───┘ └───┘ └───┘  │
            └─────────────────────┘
```

**The gap**: Auto-Claude runs agents directly on the host with full system access. There's no sandboxing between the agent and the developer's machine.

## devaipod as a Sandboxed Backend

devaipod could provide the sandboxing layer that Auto-Claude currently lacks:

```
┌─────────────────────────────────────────────────────────────┐
│                    Auto-Claude UI                            │
│              (Kanban, Terminals, Roadmap)                    │
└──────────────────────────┬──────────────────────────────────┘
                           │ API calls
                           ▼
┌─────────────────────────────────────────────────────────────┐
│                      devaipod                                │
│  ┌───────────────────────────────────────────────────────┐  │
│  │                 DevPod Workspace                       │  │
│  │  ┌─────────────────────────────────────────────────┐  │  │
│  │  │              bwrap Sandbox                       │  │  │
│  │  │  ┌─────────────────────────────────────────┐    │  │  │
│  │  │  │           Claude Code / OpenCode         │    │  │  │
│  │  │  │  • Read-only system access               │    │  │  │
│  │  │  │  • Write only to workspace               │    │  │  │
│  │  │  │  • No direct GitHub token access         │    │  │  │
│  │  │  └─────────────────────────────────────────┘    │  │  │
│  │  └─────────────────────────────────────────────────┘  │  │
│  │                        │                               │  │
│  │                        ▼ upcalls                       │  │
│  │  ┌─────────────────────────────────────────────────┐  │  │
│  │  │              gh-restricted                       │  │  │
│  │  │  • Draft PRs only to allowed repos              │  │  │
│  │  │  • Comments only on agent-created PRs           │  │  │
│  │  └─────────────────────────────────────────────────┘  │  │
│  └───────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

### Integration Points

1. **Task → Workspace Mapping**
   - Auto-Claude task → devaipod workspace with git worktree
   - Task metadata passed as agent context

2. **Terminal Multiplexing**
   - Auto-Claude's multi-terminal view → devaipod's tmux sessions
   - Each terminal is an isolated sandbox

3. **GitHub Operations**
   - Auto-Claude requests PR creation → devaipod upcall validates and creates draft
   - Human reviews in Auto-Claude UI, then marks ready-for-review

4. **QA Validation**
   - Auto-Claude's QA pipeline runs inside devaipod sandbox
   - Tests execute in isolated environment

## Comparison

| Feature | Auto-Claude | devaipod | Combined |
|---------|-------------|----------|----------|
| **Visual Task Management** | ✅ Kanban board | ❌ CLI only | Auto-Claude UI |
| **Parallel Agents** | ✅ Up to 12 | ✅ Multiple tmux | Both |
| **Git Worktree Isolation** | ✅ Per-task branches | ✅ Per-workspace | Both |
| **Filesystem Sandboxing** | ❌ Host access | ✅ bwrap container | devaipod |
| **Network Isolation** | ❌ Full network | ✅ LLM API allowlist | devaipod |
| **Credential Scoping** | ❌ Full token access | ✅ Upcall-mediated | devaipod |
| **Self-Validating QA** | ✅ Built-in | ⚪ User-defined | Auto-Claude |
| **Memory/Context** | ✅ Cross-session | ⚪ Via agent | Auto-Claude |
| **Desktop App** | ✅ Electron | ❌ CLI | Auto-Claude |

## Implementation Approach

### Option 1: devaipod as Backend Service

Auto-Claude could spawn devaipod as a subprocess or connect to it as a service:

```python
# Auto-Claude backend integration
import subprocess

class DevaipodBackend:
    def create_workspace(self, task_id: str, repo_url: str) -> str:
        """Create a sandboxed workspace for a task."""
        result = subprocess.run([
            "devaipod", "up",
            "--git", repo_url,
            "--name", f"task-{task_id}"
        ], capture_output=True)
        return result.stdout.decode()
    
    def run_agent(self, workspace: str, task: str, repo: str) -> None:
        """Run agent in sandboxed workspace."""
        subprocess.run([
            "devaipod", "run",
            "--workspace", workspace,
            "--repo", repo,
            task
        ])
    
    def attach_terminal(self, workspace: str) -> str:
        """Get tmux session for terminal display."""
        return f"devaipod attach {workspace}"
```

### Option 2: Shared Protocol

Define a protocol for agent orchestration that both projects implement:

```json
{
  "task": {
    "id": "task-42",
    "description": "Add authentication feature",
    "repo": "org/repo",
    "branch": "feature/auth"
  },
  "sandbox": {
    "enabled": true,
    "allowed_repos": ["org/repo"],
    "network_policy": "llm-only"
  },
  "agent": {
    "type": "claude-code",
    "model": "claude-sonnet-4-20250514"
  }
}
```

### Option 3: devaipod Feature Integration

Add devaipod as an optional feature in Auto-Claude:

```json
// Auto-Claude config
{
  "execution": {
    "backend": "devaipod",  // or "direct" for current behavior
    "sandbox": {
      "enabled": true,
      "network_isolation": true,
      "github_scope": "draft-pr-only"
    }
  }
}
```

## Benefits of Integration

### For Auto-Claude Users

1. **Security**: Agent can't access files outside workspace
2. **Credential Protection**: GitHub token never exposed to agent
3. **Audit Trail**: All GitHub operations go through gh-restricted
4. **Reproducibility**: devcontainer.json ensures consistent environment

### For devaipod Users

1. **Visual Interface**: Kanban board instead of CLI
2. **Multi-Agent Management**: Easy parallel task handling
3. **QA Pipeline**: Built-in validation before human review
4. **Memory Layer**: Context preserved across sessions

## Technical Considerations

### Process Model

Auto-Claude's current model:
```
Electron App → Python Backend → Claude Code CLI (on host)
```

With devaipod:
```
Electron App → Python Backend → devaipod → DevPod → bwrap → Claude Code
```

### State Synchronization

Both projects manage state that needs coordination:
- Auto-Claude: Task status, Kanban position, QA results
- devaipod: Workspace status, upcall permissions, PR tracking

A shared state layer or event protocol would help.

### Terminal Passthrough

Auto-Claude's terminal view would need to:
1. Connect to devaipod's tmux session
2. Pass through keystrokes
3. Display output with agent activity

This is achievable via `devaipod attach` or direct tmux socket access.

## Next Steps

1. **Prototype**: Create a minimal integration showing Auto-Claude UI with devaipod backend
2. **Define API**: Formalize the interface between orchestration and execution
3. **Test Security**: Verify sandboxing holds under Auto-Claude's multi-agent patterns
4. **Upstream Discussion**: Engage with Auto-Claude maintainers about integration interest

## Conclusion

Auto-Claude has an excellent UI/UX for managing autonomous AI coding workflows. devaipod provides the sandboxing and security layer that such tools need. Together, they could offer a compelling solution: beautiful visual management of securely sandboxed AI agents.

The AGPL-3.0 license of Auto-Claude is compatible with integration—code that links to or modifies Auto-Claude would need to be AGPL, but devaipod as a separate process invoked by Auto-Claude could remain Apache-2.0/MIT.

## References

- [Auto-Claude GitHub Repository](https://github.com/AndyMik90/Auto-Claude)
- [Auto-Claude Releases](https://github.com/AndyMik90/Auto-Claude/releases)
- [Discord Community](https://discord.gg/KCXaPBr4Dj)
- [YouTube Channel](https://www.youtube.com/@AndreMikalsen)
