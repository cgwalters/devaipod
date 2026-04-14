# Contributing to devaipod

## Development Setup

Requires Rust (stable toolchain), [just](https://github.com/casey/just),
and podman (for integration tests and container builds).

Run `just` to see all available tasks.

### Quick start

```bash
just check       # Format check + type check
just test         # Unit tests (no container runtime needed, fast)
just test-integration  # Full integration tests (builds container, ~2.5 min)
```

### Pre-commit hook

`just check` installs a git hook that records which tree was checked.
The pre-commit hook warns if you commit without running `just check`.

## Architecture

See [docs/src/architecture.md](docs/src/architecture.md) for the pod architecture,
container layout, volumes, and key source files.

## Testing

### Unit tests

```bash
just test    # or: cargo test
```

Runs in under a second, no container runtime required.

### Integration tests (containerized — canonical)

```bash
just test-integration
```

This is the **canonical way to run integration tests**. It:

1. Builds the `localhost/devaipod:latest` container image from source
2. Builds an `integration-runner` image containing the compiled test binary
3. Runs the test binary inside the runner container with `--privileged`

This ensures sidecar containers (pod-api, gator) run the same binary as
the code under test. CI uses this recipe.

The test runner mounts the host podman socket at `/run/docker.sock`.
Web container tests launch **sibling containers** via podman -- volume mount
sources must use `DEVAIPOD_HOST_SOCKET` (the host-side path) because podman
resolves `-v` sources on the host filesystem.

### Integration tests (host — fast iteration)

```bash
just test-integration-local
```

Builds only the host binary; skips the container image build. Sidecar containers
use the **published** image (`ghcr.io/cgwalters/devaipod:latest`), so tests
depending on unreleased sidecar features will fail. Use `just test-integration`
for full correctness.

### Test infrastructure

Tests live in `crates/integration-tests/`. See the module-level doc comments
in `src/lib.rs` and `src/main.rs` for details on the test framework, macros,
shared fixtures, and cleanup strategy.

Stale test volumes accumulate if a test run is killed. Run
`podman volume prune` periodically to clean them up.

### Testing ACP

Integration tests validate ACP communication with a mock agent. The mock script implements minimal ACP responses to test the client, WebSocket transport, and frontend without a real agent.

Enable the mock agent in tests:

```bash
DEVAIPOD_MOCK_AGENT=1 just test-integration
```

When this variable is set, the mock script is injected into the agent container at startup. It responds to `initialize`, `session/new`, and `session/prompt` with hardcoded JSON-RPC messages.

Browser-based tests use Playwright:

```bash
just test-integration-web
```

These tests launch real pods, connect to the web UI, and verify agent interactions.

## Code Style

- Run `just check` before committing (`cargo fmt --check` + `cargo check`)
- Address all `cargo clippy --workspace -- -D warnings`
- Write tests for new functionality
- Prefer `command -v` over `which` in test code (not available in all container images)

## Commit Messages

Use conventional commit format with imperative mood:

```
component: Short description

Explain the "why" rather than the "what". Do not include
a generic "Changes" section with a bulleted list.
```

Examples:
- `pod-api: Add /healthz endpoint and container healthcheck`
- `tracing: Direct log output to stderr instead of stdout`
- `ci: Switch to containerized integration tests`

## Pull Requests

1. Create a feature branch
2. Run `just check && just test && just test-integration`
3. Submit a pull request

## AI Agent Contributions

See [AGENTS.md](AGENTS.md) for instructions specific to AI agents,
including requirements around `Signed-off-by` lines and attribution.

## License

By contributing, you agree to license your contributions under
Apache-2.0 OR MIT (same as the project).
