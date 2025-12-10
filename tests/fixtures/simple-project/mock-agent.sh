#!/bin/bash
# mock-agent.sh: Simulates an AI coding agent for E2E testing
#
# This is a minimal test fixture that performs simple, verifiable actions
# to validate the devaipod workflow without requiring real AI API calls.
#
# Environment variables:
#   AGENT_TASK - The task to perform (can be passed directly)
#   AGENT_TASK_FILE - Path to file containing the task description
#   AGENT_RESULT_FILE - Path where the agent should write results (default: ./result.txt)
#
# Supported tasks:
#   create-file: Creates a result file with known content
#   modify-file: Adds a line to an existing file
#   echo-env: Echoes environment variables to verify secrets work
#   fail: Intentionally fails (for testing error handling)

set -euo pipefail

# Determine the task
if [ -n "${AGENT_TASK:-}" ]; then
    task="$AGENT_TASK"
elif [ -n "${AGENT_TASK_FILE:-}" ] && [ -f "$AGENT_TASK_FILE" ]; then
    task=$(cat "$AGENT_TASK_FILE")
else
    echo "Error: No task specified. Set AGENT_TASK or AGENT_TASK_FILE" >&2
    exit 1
fi

# Default result file location
result_file="${AGENT_RESULT_FILE:-./result.txt}"

echo "Mock agent starting..."
echo "Task: $task"
echo "Result file: $result_file"

case "$task" in
    create-file)
        echo "Creating result file with known content..."
        cat > "$result_file" <<EOF
Hello from mock agent!
Task completed successfully.
Timestamp: $(date -Iseconds)
EOF
        echo "File created: $result_file"
        ;;

    modify-file)
        if [ ! -f "$result_file" ]; then
            echo "Creating initial file for modification..."
            echo "Initial content" > "$result_file"
        fi
        echo "Modifying existing file..."
        echo "// Modified by mock agent at $(date -Iseconds)" >> "$result_file"
        echo "File modified: $result_file"
        ;;

    echo-env)
        echo "Echoing environment variables to result file..."
        cat > "$result_file" <<EOF
Environment Check
=================
USER: ${USER:-<not set>}
HOME: ${HOME:-<not set>}
PWD: ${PWD:-<not set>}
SHELL: ${SHELL:-<not set>}

Secret Environment Variables:
ANTHROPIC_API_KEY: ${ANTHROPIC_API_KEY:-<not set>}
OPENAI_API_KEY: ${OPENAI_API_KEY:-<not set>}

Custom Variables:
AGENT_TASK: ${AGENT_TASK:-<not set>}
AGENT_TASK_FILE: ${AGENT_TASK_FILE:-<not set>}
AGENT_RESULT_FILE: ${AGENT_RESULT_FILE:-<not set>}
EOF
        echo "Environment information written to: $result_file"
        ;;

    fail)
        echo "Error: Intentionally failing as requested" >&2
        exit 42
        ;;

    *)
        echo "Error: Unknown task: $task" >&2
        echo "Supported tasks: create-file, modify-file, echo-env, fail" >&2
        exit 1
        ;;
esac

echo "Mock agent completed successfully!"
echo "Task '$task' finished at $(date -Iseconds)"
exit 0
