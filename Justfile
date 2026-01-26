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

check:
    cargo fmt -- --check
    cargo check

# Run unit tests (no container runtime required)
test:
    cargo test

# Run integration tests (requires podman + devpod)
test-integration:
    cargo test -- --ignored

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
