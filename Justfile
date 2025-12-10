# devc development tasks

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

# Run unit tests (no podman required)
test:
    cargo test --package devc
    DEVC_PATH="$(pwd)/target/debug/devc" cargo test --package integration-tests --test integration-tests -- --skip test_multi --skip test_container --skip test_pod --skip test_sidecar --skip test_volume

# Run integration tests (requires podman)
test-integration:
    DEVC_PATH="$(pwd)/target/debug/devc" cargo test --package integration-tests --test integration-tests

# Run all tests (unit + integration)
test-all: test test-integration

# Format code
fmt:
    cargo fmt

# Clean build artifacts
clean:
    cargo clean

# Run devc with arguments
run *ARGS:
    cargo run -- {{ARGS}}

# Build and install to ~/.cargo/bin
install:
    cargo install --path .

# Run the legacy shell integration test
test-shell:
    ./integration.sh
