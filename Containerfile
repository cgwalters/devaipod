# Containerfile for devaipod
#
# Builds devaipod as a container image for orchestrating AI agent workspaces.
# The container requires access to the host's podman socket to spawn sibling
# containers (workspace pods).
#
# Build:
#   podman build --tag ghcr.io/cgwalters/devaipod -f Containerfile .
#
# Run (web UI mode - default):
#   podman volume create devaipod-state   # optional; just container-run creates it
#   SOCKET=$XDG_RUNTIME_DIR/podman/podman.sock
#   podman run -d --name devaipod -p 8080:8080 --privileged \
#     -v devaipod-state:/var/lib/devaipod \
#     -v $SOCKET:/run/docker.sock \
#     -e DEVAIPOD_HOST_SOCKET=$SOCKET \
#     -v ~/.config/devaipod.toml:/root/.config/devaipod.toml:ro \
#     ghcr.io/cgwalters/devaipod
#
#   The devaipod-state volume stores the web auth token by default (at
#   /var/lib/devaipod/web-token) so it persists across container restarts.
#
#   # Get the web UI URL with auth token from logs (first run only; later use same URL):
#   podman logs devaipod | grep "Web UI"
#
# Run with stable auth token (via podman secret) instead of state volume:
#   openssl rand -base64 32 | podman secret create devaipod-web-token -
#   SOCKET=$XDG_RUNTIME_DIR/podman/podman.sock
#   podman run -d --name devaipod -p 8080:8080 --privileged \
#     --secret devaipod-web-token \
#     -v devaipod-state:/var/lib/devaipod \
#     -v $SOCKET:/run/docker.sock \
#     -e DEVAIPOD_HOST_SOCKET=$SOCKET \
#     -v ~/.config/devaipod.toml:/root/.config/devaipod.toml:ro \
#     ghcr.io/cgwalters/devaipod
#
# Interact via CLI:
#   podman exec devaipod devaipod run https://github.com/org/repo -c 'fix bug'
#   podman exec -ti devaipod devaipod attach -l
#   podman exec -ti devaipod devaipod tui
#
# Note: --privileged is required for socket access and for spawning privileged
# workspace containers (needed for nested podman in devcontainers).
#
# Uses BuildKit-style cache mounts for fast incremental Rust builds.

# -- source snapshot (keeps layer graph clean) --
FROM scratch AS src
COPY . /src

# -- mdbook documentation build stage --
# Builds the project documentation using mdbook. The output (static HTML) is
# copied into the final image and served by the control plane web server.
FROM docker.io/library/rust:slim AS mdbook
RUN cargo install mdbook@0.4.52 mdbook-mermaid@0.16.0 --locked
COPY --from=src /src/docs /src/docs
WORKDIR /src/docs
RUN mdbook-mermaid install . && mdbook build
# Output is in /src/docs/book

# -- opencode web UI build stage --
# Build the vendored opencode UI fork (opencode-ui/) which includes devaipod
# customizations: workspace terminal, git review tab, per-pod localStorage, etc.
#
# Layer ordering is optimised for cache reuse: dependency metadata first, then
# install, then the full source tree. This mirrors the Rust build stage pattern.
ARG OPENCODE_VERSION=v1.1.65
FROM docker.io/oven/bun:latest AS opencode-web
ARG OPENCODE_VERSION=v1.1.65

# Disable apt sandboxing for nested container environments (e.g. building
# inside a devcontainer with rootless podman). Without this, apt fails with
# "setgroups 65534 failed" when the outer container lacks CAP_SETGID for
# the _apt user. See bootc-dev/infra@491e950.
RUN echo 'APT::Sandbox::User "root";' > /etc/apt/apt.conf.d/99sandbox-disable

# Fonts are gitignored (~60MB binary); fetch from upstream for the build.
RUN apt-get update && apt-get install -y --no-install-recommends \
    git ca-certificates && rm -rf /var/lib/apt/lists/*
RUN git clone --depth 1 --filter=blob:none --sparse \
    --branch ${OPENCODE_VERSION} \
    https://github.com/anomalyco/opencode.git /tmp/oc && \
    cd /tmp/oc && git sparse-checkout set packages/ui/src/assets/fonts

WORKDIR /build

# 1. Copy only dependency-related files first so that `bun install` is cached
#    unless package.json, bun.lock, or workspace package.json files change.
COPY --from=src /src/opencode-ui/package.json /src/opencode-ui/bun.lock /src/opencode-ui/bunfig.toml /build/
COPY --from=src /src/opencode-ui/packages/app/package.json /build/packages/app/package.json
COPY --from=src /src/opencode-ui/packages/ui/package.json /build/packages/ui/package.json
COPY --from=src /src/opencode-ui/packages/sdk/js/package.json /build/packages/sdk/js/package.json
COPY --from=src /src/opencode-ui/packages/util/package.json /build/packages/util/package.json
# Patches referenced in patchedDependencies must be present for install.
COPY --from=src /src/opencode-ui/patches /build/patches

RUN bun install --frozen-lockfile

# 2. Now copy the full source and fonts (changes here skip the install layer).
COPY --from=src /src/opencode-ui /build
RUN mkdir -p packages/ui/src/assets/fonts && \
    cp /tmp/oc/packages/ui/src/assets/fonts/*.woff2 packages/ui/src/assets/fonts/

WORKDIR /build/packages/app
RUN bun run build

# Output is in /build/packages/app/dist

# -- opencode CLI binary --
# Download the opencode CLI for use in advisor pods (where this image is the agent image).
# Release artifacts are tarballs; select the right architecture at build time.
# TARGETARCH is set by buildx/podman (amd64 or arm64); opencode uses x64/arm64.
FROM quay.io/centos/centos:stream10 AS opencode-cli
ARG OPENCODE_VERSION=v1.1.65
ARG TARGETARCH
RUN ARCH="${TARGETARCH}"; \
    if [ "$ARCH" = "amd64" ] || [ -z "$ARCH" ]; then ARCH="x64"; fi; \
    curl -fsSL \
      "https://github.com/anomalyco/opencode/releases/download/${OPENCODE_VERSION}/opencode-linux-${ARCH}.tar.gz" \
      | tar xzf - -C /usr/local/bin/ opencode && \
    chmod +x /usr/local/bin/opencode

# -- build stage --
FROM quay.io/centos/centos:stream10 AS build

RUN dnf install -y \
        rust cargo \
        openssl-devel \
        gcc \
        git \
    && dnf clean all

COPY --from=src /src /src
WORKDIR /src

# Fetch dependencies (network-intensive, cached separately)
RUN --mount=type=cache,target=/src/target \
    --mount=type=cache,target=/root/.cargo/registry \
    --mount=type=cache,target=/root/.cargo/git \
    cargo fetch

# Build devaipod binary
RUN --network=none \
    --mount=type=cache,target=/src/target \
    --mount=type=cache,target=/root/.cargo/registry \
    --mount=type=cache,target=/root/.cargo/git \
    cargo build --release -p devaipod && \
    cp /src/target/release/devaipod /usr/bin/devaipod

# -- unit tests (built from the build stage, run via `just test-container`) --
FROM build AS units
RUN --network=none \
    --mount=type=cache,target=/src/target \
    --mount=type=cache,target=/root/.cargo/registry \
    --mount=type=cache,target=/root/.cargo/git \
    mkdir -p /usr/lib/devaipod/units && \
    cargo test --no-run -p devaipod --message-format=json 2>/dev/null \
      | python3 -c 'import sys,json;[print(m["executable"])for line in sys.stdin for m in[json.loads(line)]if m.get("profile",{}).get("test")and m.get("executable")]' \
      | while read bin; do install -m 0755 "$bin" "/usr/lib/devaipod/units/$(basename $bin)"; done && \
    test -n "$(ls /usr/lib/devaipod/units/)" && \
    printf '#!/bin/bash\nset -xeuo pipefail\nfor f in /usr/lib/devaipod/units/*; do echo "$f" && "$f"; done\n' \
      > /usr/bin/devaipod-units && chmod a+x /usr/bin/devaipod-units

# -- integration tests (built from the build stage) --
# Builds integration test binaries into a separate directory. These tests
# require the devaipod binary and runtime dependencies (podman, git, etc.)
# to exercise the full workflow including container orchestration.
FROM build AS integration
# Build integration test binaries in release mode. The devaipod release binary
# is already at /usr/bin/devaipod from the build stage.
# First compile with normal output so errors are visible and fail the build,
# then re-run with --message-format=json to extract the binary paths.
RUN --network=none \
    --mount=type=cache,target=/src/target \
    --mount=type=cache,target=/root/.cargo/registry \
    --mount=type=cache,target=/root/.cargo/git \
    cargo test --release --no-run -p integration-tests 2>&1 && \
    mkdir -p /usr/lib/devaipod/integration && \
    cargo test --release --no-run -p integration-tests --message-format=json 2>/dev/null \
      | python3 -c 'import sys,json;[print(m["executable"])for line in sys.stdin for m in[json.loads(line)]if m.get("profile",{}).get("test")and m.get("executable")]' \
      | while read bin; do install -m 0755 "$bin" "/usr/lib/devaipod/integration/$(basename $bin)"; done && \
    test -n "$(ls /usr/lib/devaipod/integration/)" && \
    printf '#!/bin/bash\nset -xeuo pipefail\nfor f in /usr/lib/devaipod/integration/*; do echo "$f" && "$f"; done\n' \
      > /usr/bin/devaipod-integration && chmod a+x /usr/bin/devaipod-integration

# -- integration test runner (minimal runtime image) --
# Contains integration test binaries plus runtime deps needed to run tests.
# Build: podman build --target integration-runner -t localhost/devaipod-integration .
# Run:   podman run --rm --privileged -v /run/podman/podman.sock:/run/docker.sock localhost/devaipod-integration
FROM quay.io/centos/centos:stream10 AS integration-runner

RUN dnf install -y \
        podman-remote \
        git \
        openssh-clients \
        tmux \
    && dnf clean all \
    && ln -sf /usr/bin/podman-remote /usr/bin/podman

COPY --from=integration /usr/lib/devaipod/integration /usr/lib/devaipod/integration
COPY --from=integration /usr/bin/devaipod-integration /usr/bin/devaipod-integration
COPY --from=integration /usr/bin/devaipod /usr/bin/devaipod

ENV DEVAIPOD_CONTAINER=1
ENV CONTAINER_HOST=unix:///run/docker.sock

CMD ["/usr/bin/devaipod-integration"]

# -- final minimal image --
FROM quay.io/centos/centos:stream10

# Install runtime dependencies:
# - podman-remote: for CLI fallback operations (exec, etc.)
# - git: for repository operations
# - openssh-clients: for SSH integration
# - tmux: for attach command's split-pane UI
RUN dnf install -y \
        podman-remote \
        git \
        openssh-clients \
        tmux \
    && dnf clean all \
    && ln -sf /usr/bin/podman-remote /usr/bin/podman

# Create config directory
RUN mkdir -p /root/.config

COPY --from=build /usr/bin/devaipod /usr/bin/devaipod

# Install the opencode CLI agent binary; needed when this image is used as
# the agent container for advisor pods.
COPY --from=opencode-cli /usr/local/bin/opencode /usr/local/bin/opencode

# Mark that we're running inside the official devaipod container
# This is checked by `devaipod` to require running in container mode by default
ENV DEVAIPOD_CONTAINER=1
# Tell podman-remote (aliased as podman) where the socket is mounted.
# Without this, bare `podman` commands default to /run/podman/podman.sock.
ENV CONTAINER_HOST=unix:///run/docker.sock

# Copy vendored opencode web UI fork (built from opencode-ui/ in the repo)
# This is served at /opencode/ and proxies API calls to the agent's opencode server
COPY --from=opencode-web /build/packages/app/dist /usr/share/devaipod/opencode

# Copy mdbook documentation (served at /docs/ by the control plane)
COPY --from=mdbook /src/docs/book /usr/share/devaipod/docs
WORKDIR /usr/share/devaipod

# Default: run web UI server
# The web server prints a URL with auth token to stdout on startup.
# Alternative entrypoints:
#   - `devaipod tui` for interactive TUI dashboard
#   - `sleep infinity` then use `podman exec` for commands
#   - Custom command for one-shot operations
#
# Example:
#   podman run -d -p 8080:8080 ... ghcr.io/cgwalters/devaipod
#   # Copy the URL with token from logs:
#   podman logs <container> | grep "Web UI"
EXPOSE 8080
CMD ["devaipod", "web", "--port", "8080"]
