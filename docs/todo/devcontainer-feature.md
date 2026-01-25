# Devcontainer Feature for devaipod

## Status: In Progress

A devcontainer feature allows any devcontainer to easily add devaipod support
without needing a custom base image.

## Implementation

The feature is located in `features/src/devaipod/` and consists of:

- `devcontainer-feature.json` - Feature metadata and options
- `install.sh` - Installation script that handles multiple distros/architectures

## Architecture Considerations

### Per-Architecture Binaries

Rust compiles to native binaries, so we need separate binaries for each architecture:

| Architecture | Target Triple | Notes |
|-------------|---------------|-------|
| x86_64 | `x86_64-unknown-linux-gnu` | Most common |
| aarch64 | `aarch64-unknown-linux-gnu` | Apple Silicon, ARM servers |

The install script detects architecture via `uname -m` and downloads the appropriate
binary from GitHub releases.

### Static vs Dynamic Linking

**Current approach:** Dynamic linking with glibc

This works for most devcontainer base images (Debian, Ubuntu, Fedora) but will
fail on Alpine (musl libc).

**Future improvement:** Build with musl for fully static binaries:
```bash
# Add targets
rustup target add x86_64-unknown-linux-musl
rustup target add aarch64-unknown-linux-musl

# Build static
cargo build --release --target x86_64-unknown-linux-musl
```

This would allow the same binary to work on any Linux distribution.

### WASM Alternative

WebAssembly could provide a single binary that works everywhere, but:

**Pros:**
- Single binary for all architectures
- Sandboxing built-in

**Cons:**
- devaipod spawns subprocesses (bwrap, AI agents) which WASM can't do
- Needs WASI for filesystem access
- Performance overhead
- Complex to implement

**Verdict:** Not practical for devaipod's use case since it orchestrates
external processes and uses Linux-specific sandboxing (bwrap).

## Release Asset Naming

GitHub releases should include pre-built binaries with this naming convention:

```
devaipod-x86_64-unknown-linux-gnu.tar.gz
devaipod-aarch64-unknown-linux-gnu.tar.gz
```

Each tarball should contain:
- `devaipod` - Main binary

## GitHub Actions for Releases

A release workflow should:

1. Build for both architectures (using cross-compilation or matrix builds)
2. Create tarballs with the binaries
3. Upload as release assets
4. Trigger the devcontainer feature publish workflow

Example matrix build:
```yaml
strategy:
  matrix:
    include:
      - target: x86_64-unknown-linux-gnu
        os: ubuntu-latest
      - target: aarch64-unknown-linux-gnu
        os: ubuntu-latest
        cross: true
```

## Usage

Once published to GHCR, users can add to their `devcontainer.json`:

```json
{
  "features": {
    "ghcr.io/cgwalters/devaipod/devaipod:1": {}
  }
}
```

Or with a specific version:
```json
{
  "features": {
    "ghcr.io/cgwalters/devaipod/devaipod:1": {
      "version": "0.1.0"
    }
  }
}
```

## TODO

- [ ] Set up GitHub Actions workflow to build release binaries for both architectures
- [ ] Test install.sh on various base images:
  - [ ] `mcr.microsoft.com/devcontainers/base:ubuntu`
  - [ ] `mcr.microsoft.com/devcontainers/base:debian`
  - [ ] `fedora:latest`
  - [ ] `alpine:latest` (will need musl build)
- [ ] Publish feature to GHCR
- [ ] Add to devcontainers community index for discoverability
- [ ] Consider musl static builds for universal compatibility
- [ ] Add feature tests using devcontainer CLI

## Testing the Feature Locally

```bash
# Install devcontainer CLI
npm install -g @devcontainers/cli

# Test the feature
devcontainer features test --features devaipod --base-image mcr.microsoft.com/devcontainers/base:ubuntu
```

## References

- [Dev Container Features Spec](https://containers.dev/implementors/features/)
- [Features Distribution](https://containers.dev/implementors/features-distribution/)
- [Feature Starter Template](https://github.com/devcontainers/feature-starter)
- [Anthropic's claude-code feature](https://github.com/anthropics/devcontainer-features) - good reference
