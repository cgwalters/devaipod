# E2E Testing Architecture

## Overview

devaipod needs comprehensive E2E tests that verify the full autonomous workflow:
source → devpod up → agent runs → agent completes task → verify result.

## Design Goals

1. **Headless/Autonomous**: Tests run without human interaction
2. **CI-friendly**: No real API keys required for basic testing
3. **Fast feedback**: Tests complete in reasonable time
4. **Verifiable**: Clear pass/fail criteria

## Mock Agent Approach

For CI testing, we use a "mock agent" - a shell script that simulates AI agent behavior:

```bash
#!/bin/bash
# mock-agent: Simulates an AI coding agent for testing
#
# Environment variables:
#   AGENT_TASK_FILE - Path to file containing the task
#   AGENT_RESULT_FILE - Path to write result
#
# The mock agent reads the task, performs a simple action, and exits.

set -e

task=$(cat "$AGENT_TASK_FILE")

case "$task" in
  "create-file")
    echo "Hello from mock agent" > "$AGENT_RESULT_FILE"
    ;;
  "add-comment")
    echo "// Added by mock agent" >> "$AGENT_RESULT_FILE"
    ;;
  *)
    echo "Unknown task: $task" >&2
    exit 1
    ;;
esac

echo "Task completed: $task"
```

## Test Project Structure

```
test-fixtures/
├── simple-project/
│   ├── .devcontainer/
│   │   └── devcontainer.json
│   ├── mock-agent.sh
│   └── src/
│       └── main.rs
```

The devcontainer.json:
```json
{
  "name": "test-project",
  "image": "quay.io/fedora/fedora:41",
  "postCreateCommand": "chmod +x /workspaces/*/mock-agent.sh"
}
```

## E2E Test Flow

```
┌─────────────────────────────────────────────────────────────┐
│                     Test Runner                              │
│                                                              │
│  1. Create temp directory with test project                  │
│  2. Copy mock-agent.sh into project                         │
│  3. Create devcontainer.json                                │
│  4. Run: devaipod up . --agent ./mock-agent.sh              │
│  5. Wait for agent to complete (poll or timeout)            │
│  6. Verify: check result file exists with expected content  │
│  7. Cleanup: devaipod delete --force                        │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

## Agent Completion Detection

The mock agent runs in tmux. To detect completion:

1. **Poll tmux session**: Check if the session still exists
   ```bash
   devpod ssh WORKSPACE -- tmux has-session -t agent 2>/dev/null
   ```
   When it returns non-zero, agent has exited.

2. **Check result file**: After agent exits, verify expected output
   ```bash
   devpod ssh WORKSPACE -- cat /workspaces/*/result.txt
   ```

## Real Agent Testing

For testing with real AI agents (requires API keys):

```bash
# Set up secrets
echo "$ANTHROPIC_API_KEY" | podman secret create ANTHROPIC_API_KEY -

# Run test with real agent
devaipod up ./test-project --agent goose

# Agent will actually call the LLM
# Test verifies it modifies code appropriately
```

This requires:
- API keys in CI secrets
- Longer timeouts
- More complex verification

## Test Categories

### Unit Tests (fast, no containers)
- `src/secrets.rs` tests for parsing
- `src/config.rs` tests for config loading
- URL parsing, etc.

### Integration Tests (containers, no agent)
- `devaipod up/stop/delete` lifecycle
- Secret injection into devcontainer.json
- SSH access to workspace

### E2E Tests (containers + mock agent)
- Full workflow with mock-agent.sh
- Verifies tmux session management
- Verifies agent receives task and produces output

### Live Tests (containers + real agent + API)
- Optional, requires API keys
- Tests with actual goose/claude/opencode
- Longer timeouts, more flaky

## Implementation Plan

1. **Create test fixtures directory** with simple-project template
2. **Implement mock-agent.sh** as a simple task executor
3. **Add E2E test functions** in tests/integration.rs:
   - `test_mock_agent_creates_file`
   - `test_mock_agent_timeout_handling`
   - `test_agent_secrets_available`
4. **Add CI workflow** that runs E2E tests with mock agent
5. **Optional**: Add live test workflow with real API keys

## Considerations

### Timeout Handling
Tests should have appropriate timeouts:
- Container startup: 5 minutes
- Mock agent execution: 30 seconds
- Real agent execution: 5 minutes

### Cleanup
Always cleanup workspaces, even on test failure:
```rust
struct WorkspaceGuard {
    name: String,
}

impl Drop for WorkspaceGuard {
    fn drop(&mut self) {
        let _ = cleanup_workspace(&self.name);
    }
}
```

### Parallelism
E2E tests should use unique workspace names to allow parallel execution:
```rust
let workspace_name = format!("test-{}-{}", test_name, uuid::Uuid::new_v4());
```
