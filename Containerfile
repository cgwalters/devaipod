FROM ghcr.io/bootc-dev/devenv-debian AS base

USER root
RUN apt-get update && apt-get install -y --no-install-recommends bubblewrap tmux \
    && rm -rf /var/lib/apt/lists/*

# Install opencode from anomalyco/opencode
ARG OPENCODE_VERSION=1.1.12
ARG TARGETARCH
RUN set -eux; \
    case "${TARGETARCH}" in \
        amd64) OPENCODE_ARCH="x64" ;; \
        arm64) OPENCODE_ARCH="arm64" ;; \
        *) echo "Unsupported architecture: ${TARGETARCH}"; exit 1 ;; \
    esac; \
    curl -fsSL "https://github.com/anomalyco/opencode/releases/download/v${OPENCODE_VERSION}/opencode-linux-${OPENCODE_ARCH}.tar.gz" -o /tmp/opencode.tar.gz \
    && tar -xzf /tmp/opencode.tar.gz -C /usr/local/bin opencode \
    && chmod +x /usr/local/bin/opencode \
    && rm /tmp/opencode.tar.gz

# Build devaipod and upcall binaries from source
FROM base AS builder
WORKDIR /build
# Copy all source files
COPY Cargo.toml Cargo.lock Makefile ./
COPY src ./src
COPY crates ./crates
# Fetch dependencies first, then build with cached directories for incremental compilation.
# - /root/.cargo: cargo registry, git checkouts, and crate sources
# - /build/target: compiled artifacts for incremental builds
# See https://www.reddit.com/r/rust/comments/126xeyx/exploring_the_problem_of_faster_cargo_docker/
RUN --mount=type=cache,target=/root/.cargo \
    --mount=type=cache,target=/build/target \
    cargo fetch
RUN --mount=type=cache,target=/root/.cargo \
    --mount=type=cache,target=/build/target \
    make bin && \
    cp target/release/devaipod target/release/gh-restricted /tmp/

# Final image with devaipod and upcall binaries installed
FROM base
WORKDIR /build
# Copy from /tmp since target/ is a cache mount
COPY --from=builder /tmp/devaipod target/release/devaipod
COPY --from=builder /tmp/gh-restricted target/release/gh-restricted
COPY Makefile ./
RUN make install && rm -rf /build
USER devenv
