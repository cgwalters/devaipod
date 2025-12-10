#!/bin/bash
# Integration test suite for devc
# Creates a temporary git repo, sets up devcontainer, and verifies basic functionality

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEST_DIR=""
CONTAINER_ID=""

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

cleanup() {
    log_info "Cleaning up..."
    if [[ -n "${CONTAINER_ID:-}" ]]; then
        podman stop "$CONTAINER_ID" 2>/dev/null || true
        podman rm "$CONTAINER_ID" 2>/dev/null || true
    fi
    if [[ -n "${TEST_DIR:-}" && -d "${TEST_DIR:-}" ]]; then
        rm -rf "$TEST_DIR"
    fi
}

trap cleanup EXIT

assert_success() {
    local msg="$1"
    shift
    if "$@"; then
        log_info "PASS: $msg"
    else
        log_error "FAIL: $msg"
        exit 1
    fi
}

assert_contains() {
    local msg="$1"
    local expected="$2"
    local actual="$3"
    if echo "$actual" | grep -q "$expected"; then
        log_info "PASS: $msg"
    else
        log_error "FAIL: $msg"
        log_error "Expected to contain: $expected"
        log_error "Actual: $actual"
        exit 1
    fi
}

# Test 1: Check prerequisites
test_prerequisites() {
    log_info "=== Test: Prerequisites ==="

    assert_success "devcontainer CLI is installed" command -v devcontainer
    assert_success "podman is installed" command -v podman
    assert_success "git is installed" command -v git
    # Note: cargo is only required inside the devcontainer, not on host
    if command -v cargo &>/dev/null; then
        log_info "PASS: cargo is installed (optional on host)"
    else
        log_warn "cargo not installed on host (will use devcontainer)"
    fi
}

# Test 2: Create test repo and verify devcontainer config
test_create_repo() {
    log_info "=== Test: Create test repository ==="

    TEST_DIR=$(mktemp -d)
    log_info "Test directory: $TEST_DIR"

    # Initialize git repo
    cd "$TEST_DIR"
    git init
    git config user.email "test@example.com"
    git config user.name "Test User"

    # Copy devcontainer config
    mkdir -p .devcontainer
    cp "$SCRIPT_DIR/.devcontainer/devcontainer.json" .devcontainer/

    # Create a simple file
    echo "# Test Project" > README.md
    git add .
    git commit -m "Initial commit"

    assert_success "Git repo initialized" test -d .git
    assert_success "devcontainer.json exists" test -f .devcontainer/devcontainer.json
}

# Test 3: Start devcontainer
test_start_devcontainer() {
    log_info "=== Test: Start devcontainer ==="

    cd "$TEST_DIR"

    local output
    output=$(devcontainer up --workspace-folder . 2>&1)

    assert_contains "Container started successfully" "outcome.*success" "$output"

    # Extract container ID
    CONTAINER_ID=$(echo "$output" | grep -o '"containerId":"[^"]*"' | cut -d'"' -f4)
    log_info "Container ID: $CONTAINER_ID"

    assert_success "Container ID extracted" test -n "$CONTAINER_ID"
}

# Test 4: Execute commands in devcontainer
test_exec_commands() {
    log_info "=== Test: Execute commands in devcontainer ==="

    cd "$TEST_DIR"

    # Test basic command execution
    local output
    output=$(devcontainer exec --workspace-folder . -- echo "hello from container" 2>&1)
    assert_contains "Echo command works" "hello from container" "$output"

    # Test workspace access
    output=$(devcontainer exec --workspace-folder . -- ls /workspaces 2>&1)
    if echo "$output" | grep -q "tmp"; then
        log_info "PASS: Workspace directory accessible"
    else
        log_error "FAIL: Workspace directory not accessible"
        log_error "Output: $output"
        exit 1
    fi

    # Test that we're running as expected user
    output=$(devcontainer exec --workspace-folder . -- whoami 2>&1)
    assert_contains "Running as root" "root" "$output"
}

# Test 5: Test nested containerization (podman inside devcontainer)
test_nested_containerization() {
    log_info "=== Test: Nested containerization ==="

    cd "$TEST_DIR"

    # Test podman is available
    local output
    output=$(devcontainer exec --workspace-folder . -- podman --version 2>&1)
    assert_contains "Podman available in container" "podman version" "$output"

    # Test running a nested container
    output=$(devcontainer exec --workspace-folder . -- podman run --rm docker.io/library/alpine:latest echo "nested works" 2>&1)
    assert_contains "Nested container execution works" "nested works" "$output"
}

# Test 6: Test Rust toolchain
test_rust_toolchain() {
    log_info "=== Test: Rust toolchain ==="

    cd "$TEST_DIR"

    # Test cargo is available
    local output
    output=$(devcontainer exec --workspace-folder . -- cargo --version 2>&1)
    assert_contains "Cargo available in container" "cargo" "$output"

    # Test rustc is available
    output=$(devcontainer exec --workspace-folder . -- rustc --version 2>&1)
    assert_contains "Rustc available in container" "rustc" "$output"
}

# Test 7: Build devc project
test_build_devc() {
    log_info "=== Test: Build devc project ==="

    # Use the actual project directory
    local output
    output=$(devcontainer exec --workspace-folder "$SCRIPT_DIR" -- bash -c "cd /workspaces/aidevc && cargo build --release" 2>&1)
    assert_contains "Cargo build succeeds" "Finished" "$output"

    # Test the binary exists and runs
    output=$(devcontainer exec --workspace-folder "$SCRIPT_DIR" -- /workspaces/aidevc/target/release/devc --help 2>&1)
    assert_contains "devc --help works" "Manage git worktrees" "$output"
    assert_contains "devc has 'new' command" "new" "$output"
    assert_contains "devc has 'enter' command" "enter" "$output"
    assert_contains "devc has 'list' command" "list" "$output"
    assert_contains "devc has 'rm' command" "rm" "$output"
}

# Test 8: Stop devcontainer
test_stop_devcontainer() {
    log_info "=== Test: Stop devcontainer ==="

    if [[ -n "${CONTAINER_ID:-}" ]]; then
        podman stop "$CONTAINER_ID" 2>/dev/null || true

        # Verify container is stopped
        local status
        status=$(podman inspect --format '{{.State.Status}}' "$CONTAINER_ID" 2>/dev/null || echo "removed")

        if [[ "$status" == "exited" || "$status" == "removed" ]]; then
            log_info "PASS: Container stopped successfully"
        else
            log_warn "Container status: $status"
        fi

        podman rm "$CONTAINER_ID" 2>/dev/null || true
        CONTAINER_ID=""
    fi
}

main() {
    log_info "Starting devc integration tests"
    log_info "================================"

    test_prerequisites
    test_create_repo
    test_start_devcontainer
    test_exec_commands
    test_nested_containerization
    test_rust_toolchain
    test_build_devc
    test_stop_devcontainer

    log_info "================================"
    log_info "All tests passed!"
}

main "$@"
