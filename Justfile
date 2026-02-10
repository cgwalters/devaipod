# devaipod development tasks

# Default recipe: show available commands
default:
    @just --list

# Build in debug mode
build:
    cargo build

# Build in release mode
build-release:
    cargo build --release

# Run format and type checks, record tree hash for pre-commit hook
check: install-hooks
    cargo fmt -- --check
    cargo check
    @mkdir -p target
    @git write-tree > target/checks-run

# Run unit tests (no container runtime required)
test:
    cargo test

# Default test image (must have git installed)
default_test_image := "ghcr.io/bootc-dev/devenv-debian:latest"

# Run integration tests (requires podman)
test-integration image=default_test_image:
    cargo build
    DEVAIPOD_PATH=./target/debug/devaipod DEVAIPOD_TEST_IMAGE={{image}} cargo test -p integration-tests

# Run all tests (unit + integration)
test-all: test test-integration

# Format code
fmt:
    cargo fmt

# Clean build artifacts
clean:
    cargo clean

# Run devaipod with arguments (builds release first)
run *ARGS: build-release
    ./target/release/devaipod {{ARGS}}

# Build and install to ~/.cargo/bin
install:
    cargo install --path .

# Quick smoke test: start workspace, check agent
smoke-test:
    cargo build
    ./target/debug/devaipod up . --no-agent
    ./target/debug/devaipod list
    ./target/debug/devaipod delete devc --force

# Run devaipod against our own local git tree for self-hosting development.
# This tears down any existing devcontainer completely and starts a fresh workspace
# using the devcontainer feature. Run this from outside the devcontainer (e.g. toolbox)
# to iterate on changes.
self-devenv:
    #!/usr/bin/env bash
    set -euo pipefail
    # Build the binary first
    cargo build --release
    # Stop and remove existing devpod workspace to force fresh container
    devpod stop devaipod 2>/dev/null || true
    devpod delete devaipod --force 2>/dev/null || true
    # Start fresh workspace with our local tree (uses devcontainer.json with feature)
    ./target/release/devaipod up .

# Alias for self-devenv (used by devenv-self convention)
devenv-self: self-devenv

# Default test repository for e2e GitHub tests
default_test_repo := "cgwalters/playground"

# Default workspace for e2e tests
default_test_workspace := "playground"

# Run end-to-end GitHub integration tests
# Requires a running devpod workspace with devaipod installed and gh authenticated
test-e2e-gh repo=default_test_repo workspace=default_test_workspace:
    DEVAIPOD_TEST_REPO={{repo}} DEVAIPOD_TEST_WORKSPACE={{workspace}} \
        cargo test test_e2e_gh -- --ignored --test-threads=1

# Run a specific e2e test (e.g., just test-e2e-gh-one test_e2e_gh_read_operations)
test-e2e-gh-one test repo=default_test_repo workspace=default_test_workspace:
    DEVAIPOD_TEST_REPO={{repo}} DEVAIPOD_TEST_WORKSPACE={{workspace}} \
        cargo test {{test}} -- --ignored

# Set up the test workspace for e2e tests
# Deploys the current devaipod binary and configures gh auth if GH_TOKEN is set
setup-e2e-gh workspace=default_test_workspace:
    #!/usr/bin/env bash
    set -euo pipefail
    echo "Building devaipod..."
    cargo build --release
    echo "Deploying to {{workspace}}.devpod..."
    scp target/release/devaipod {{workspace}}.devpod:/tmp/
    ssh {{workspace}}.devpod 'sudo cp /tmp/devaipod /usr/local/bin/devaipod && sudo chmod +x /usr/local/bin/devaipod'
    echo "Verifying installation..."
    ssh {{workspace}}.devpod 'devaipod --help | head -5'
    
    # Configure gh auth if GH_TOKEN is available
    if [ -n "${GH_TOKEN:-}" ]; then
        echo "Configuring gh auth with GH_TOKEN..."
        ssh {{workspace}}.devpod "echo '${GH_TOKEN}' | gh auth login --with-token" || {
            echo "Warning: gh auth failed (gh may not be installed)"
        }
        ssh {{workspace}}.devpod 'gh auth status' || true
    else
        echo "Note: GH_TOKEN not set, skipping gh auth configuration"
    fi
    
    echo "Done! Run 'just test-e2e-gh' to run the tests."

# Configure allowed repo for e2e PR creation test
# This adds the repo to the state file inside the devcontainer
allow-repo-e2e repo=default_test_repo workspace=default_test_workspace:
    #!/usr/bin/env bash
    set -euo pipefail
    echo "Adding {{repo}} to allowed repos in {{workspace}}.devpod..."
    ssh {{workspace}}.devpod 'sudo mkdir -p /run/devaipod && sudo chown $(id -u):$(id -g) /run/devaipod'
    ssh {{workspace}}.devpod "echo '{\"allowed_repos\":[\"{{repo}}\"],\"allowed_prs\":[]}' > /run/devaipod/state.json"
    echo "Done! The repo {{repo}} is now allowed for PR creation."

# ============================================================================
# Container builds
# ============================================================================

# Container image name
CONTAINER_IMAGE := "ghcr.io/cgwalters/devaipod"

# Build the container image
[group('container')]
container-build:
    podman build -t {{ CONTAINER_IMAGE }}:latest -f Containerfile .

# Test the container image
[group('container')]
container-test: container-build
    #!/usr/bin/env bash
    set -euo pipefail
    echo "Testing container image..."
    
    # Verify the binary runs
    podman run --rm {{ CONTAINER_IMAGE }}:latest devaipod --help
    
    # Verify runtime dependencies are present
    podman run --rm {{ CONTAINER_IMAGE }}:latest git --version
    podman run --rm {{ CONTAINER_IMAGE }}:latest tmux -V
    podman run --rm {{ CONTAINER_IMAGE }}:latest podman --version
    
    echo "Container tests passed!"

# Build and push container image (for CI)
[group('container')]
container-push tag="latest": container-build
    podman push {{ CONTAINER_IMAGE }}:{{ tag }}

# ============================================================================
# Documentation
# ============================================================================

# Build the documentation (mdbook) via container
build-mdbook:
    podman build -t localhost/devaipod-mdbook -f docs/Dockerfile.mdbook .

# Build docs and extract to DIR
build-mdbook-to dir: build-mdbook
    #!/usr/bin/env bash
    set -xeuo pipefail
    outdir="$(pwd)/{{dir}}"
    mkdir -p "${outdir}"
    cid=$(podman create localhost/devaipod-mdbook)
    podman cp ${cid}:/src/docs/book/. "${outdir}"
    podman rm -f ${cid}

# Serve docs locally (prints URL)
mdbook-serve: build-mdbook
    #!/usr/bin/env bash
    set -xeuo pipefail
    podman run --init --replace -d --name devaipod-mdbook --rm --publish 127.0.0.1::8000 localhost/devaipod-mdbook
    echo http://$(podman port devaipod-mdbook 8000/tcp)

# Install git hooks for development
install-hooks:
    cp scripts/pre-commit .git/hooks/pre-commit
    chmod +x .git/hooks/pre-commit
    @echo "Installed pre-commit hook"

# Default repo for agent draft PR E2E test
e2e_test_repo := "cgwalters/playground"

# E2E test: verify agent can start a task and create a draft PR
# This is a real integration test that exercises the full flow:
# 1. devaipod run with a task message
# 2. Agent starts working autonomously
# 3. Agent creates a draft PR on GitHub
#
# Requirements:
# - GH_TOKEN in environment (for service-gator to push)
# - Network access to GitHub
#
# The test polls for PR creation with a timeout.
e2e-draft-pr repo=e2e_test_repo:
    #!/usr/bin/env bash
    set -euo pipefail
    
    REPO="{{repo}}"
    TASK="Create a draft PR that adds a single line to README.md with today's date ($(date +%Y-%m-%d)) and a random UUID. The commit message should mention this is an automated test."
    
    echo "Building devaipod..."
    cargo build --release
    
    # Generate unique identifier for this test run
    TEST_ID="e2e-$(date +%s)-$$"
    POD_NAME="e2e-test-${TEST_ID}"
    
    echo "Starting devaipod with task..."
    echo "  Repo: https://github.com/${REPO}"
    echo "  Task: ${TASK}"
    
    # Start the agent with the task
    ./target/release/devaipod run "https://github.com/${REPO}" "${TASK}" --name "${POD_NAME}" || {
        echo "Failed to start devaipod"
        exit 1
    }
    
    # Function to cleanup on exit
    cleanup() {
        echo "Cleaning up pod ${POD_NAME}..."
        ./target/release/devaipod delete "${POD_NAME}" --force 2>/dev/null || true
    }
    trap cleanup EXIT
    
    echo "Agent started. Polling for draft PR creation..."
    
    # Poll for draft PR creation (timeout: 5 minutes)
    MAX_ATTEMPTS=60
    POLL_INTERVAL=5
    
    for i in $(seq 1 $MAX_ATTEMPTS); do
        echo "  Checking for draft PRs (attempt $i/$MAX_ATTEMPTS)..."
        
        # Check for draft PRs created in the last 10 minutes
        DRAFT_PRS=$(gh pr list --repo "${REPO}" --state open --draft --json number,title,createdAt --jq '.[] | select(.createdAt > (now - 600 | strftime("%Y-%m-%dT%H:%M:%SZ"))) | "\(.number): \(.title)"' 2>/dev/null || echo "")
        
        if [ -n "$DRAFT_PRS" ]; then
            echo ""
            echo "SUCCESS: Found draft PR(s):"
            echo "$DRAFT_PRS"
            echo ""
            echo "E2E test passed!"
            exit 0
        fi
        
        # Also check if agent is still working by looking at session activity
        CONTAINER="devaipod-${POD_NAME}-workspace"
        LAST_UPDATE=$(podman exec "$CONTAINER" curl -sf http://localhost:4096/session 2>/dev/null | jq -r '.[0].time.updated // 0' || echo "0")
        NOW_MS=$(($(date +%s) * 1000))
        IDLE_MS=$((NOW_MS - LAST_UPDATE))
        
        if [ "$IDLE_MS" -gt 120000 ] && [ "$i" -gt 10 ]; then
            echo "  Agent appears idle (last activity: ${IDLE_MS}ms ago)"
        fi
        
        sleep $POLL_INTERVAL
    done
    
    echo ""
    echo "TIMEOUT: No draft PR found after $((MAX_ATTEMPTS * POLL_INTERVAL)) seconds"
    echo "Check agent logs: devaipod attach ${POD_NAME}"
    exit 1
