# Contributing to devaipod

Thank you for your interest in contributing to devaipod!

## Development Setup

1. Install Rust (stable toolchain)
2. Install dependencies:
   - `podman` for container operations
   - Optionally `devpod` for some workflows

```bash
# Build
cargo build

# Run tests (unit + sandbox tests)
cargo test

# Run integration tests (requires devpod/podman)
cargo test -- --ignored

# Format and lint
cargo fmt
cargo clippy
```

## Code Style

- Use `cargo fmt` before committing
- Address all `cargo clippy` warnings
- Write tests for new functionality
- Add rustdoc comments for public APIs

## Commit Messages

Use conventional commit format:

```
component: Short description

Longer explanation of the change if needed.
Explain the "why" rather than the "what".
```

Examples:
- `sandbox: Add network isolation via iptables`
- `devpod: Improve error messages on workspace creation failure`
- `docs: Update sandboxing documentation`

## Pull Requests

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Run `cargo fmt && cargo clippy && cargo test`
5. Submit a pull request

PRs should:
- Have a clear description of the change
- Include tests for new functionality
- Update documentation if needed

## AI Agent Contributions

See `AGENTS.md` for instructions specific to AI agents contributing to this project,
including requirements around `Signed-off-by` lines and attribution.

## License

By contributing, you agree that your contributions will be licensed under the
Apache-2.0 OR MIT license (same as the project).
