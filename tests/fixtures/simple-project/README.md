# Simple Test Project

This is a minimal test fixture for E2E testing of devaipod.

## Purpose

This directory contains a simple project with a mock AI agent that can be used to test the full devaipod workflow without requiring real AI API keys or network calls.

## Contents

- `.devcontainer/devcontainer.json` - Minimal devcontainer configuration using Fedora 41
- `mock-agent.sh` - Shell script that simulates an AI agent
- `src/main.rs` - Simple Rust source file (can be modified by tests)

## Mock Agent Tasks

The mock agent supports the following tasks:

### create-file
Creates a result file with known content that can be verified by tests.

```bash
AGENT_TASK=create-file AGENT_RESULT_FILE=./output.txt ./mock-agent.sh
```

### modify-file
Adds a comment line to an existing file (or creates it if missing).

```bash
AGENT_TASK=modify-file AGENT_RESULT_FILE=./output.txt ./mock-agent.sh
```

### echo-env
Writes environment variables to the result file, useful for verifying secret injection.

```bash
AGENT_TASK=echo-env AGENT_RESULT_FILE=./env-check.txt ./mock-agent.sh
```

### fail
Intentionally fails with exit code 42, useful for testing error handling.

```bash
AGENT_TASK=fail ./mock-agent.sh
```

## Usage in Tests

Example E2E test flow:

```rust
// Copy test fixture to temp directory
let test_dir = create_test_fixture("simple-project");

// Run devaipod with mock agent
run_command("devaipod", &[
    "up",
    test_dir.path(),
    "--agent", "./mock-agent.sh",
]);

// Wait for agent to complete
wait_for_agent_completion(&workspace_name);

// Verify results
let result = read_result_file(&workspace_name, "result.txt");
assert!(result.contains("Hello from mock agent!"));
```

## Design Notes

This mock agent follows the E2E testing architecture documented in `/docs/e2e-testing.md`. It provides:

- Fast, deterministic behavior for CI
- No external dependencies or API keys required
- Simple, verifiable outputs
- Multiple task types for different test scenarios
