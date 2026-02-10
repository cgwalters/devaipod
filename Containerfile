# Containerfile for devaipod
#
# Builds devaipod as a container image for orchestrating AI agent workspaces.
# The container requires access to the host's podman socket to spawn sibling
# containers (workspace pods).
#
# Build:
#   podman build --tag ghcr.io/cgwalters/devaipod -f Containerfile .
#
# Run (daemon mode):
#   podman run -d --name devaipod --privileged \
#     -v $XDG_RUNTIME_DIR/podman/podman.sock:/run/podman/podman.sock \
#     -v ~/.config/devaipod.toml:/root/.config/devaipod.toml:ro \
#     ghcr.io/cgwalters/devaipod
#
# Interact:
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

# -- build stage --
FROM quay.io/centos/centos:stream10 AS build

RUN dnf install -y \
        rust cargo \
        openssl-devel \
        gcc \
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

# Default: sleep forever, user runs commands via `podman exec`
# Alternative entrypoints:
#   - `devaipod tui` for interactive dashboard
#   - Custom command for one-shot operations
CMD ["sleep", "infinity"]
