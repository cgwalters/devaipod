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

# Run devaipod with arguments
run *ARGS:
    cargo run -- {{ARGS}}

# Build and install to ~/.cargo/bin
install:
    cargo install --path .

# Quick smoke test: start workspace, check agent
smoke-test:
    cargo build
    ./target/debug/devaipod up . --no-agent
    ./target/debug/devaipod list
    ./target/debug/devaipod delete devc --force

# Build container image for development
build-container:
    podman build -t localhost/devaipod:latest .

# Run devaipod against our own local git tree for self-hosting development
# Removes any existing workspace first, builds everything fresh
self-devenv:
    #!/usr/bin/env bash
    set -euo pipefail
    # Build the binary first
    cargo build --release
    # Build the container image
    podman build -t localhost/devaipod:latest .
    # Remove existing workspace if present (ignore errors if it doesn't exist)
    ./target/release/devaipod delete devc --force 2>/dev/null || true
    # Start fresh workspace with our local tree
    ./target/release/devaipod up .

# Alias for self-devenv (used by devenv-self convention)
devenv-self: self-devenv
