# devc - Opinionated devcontainer and devfile runner

`devc` is an opinionated CLI wrapper for running development containers using
[devcontainer](https://containers.dev/) or [devfile](https://devfile.io/)
specifications via the Docker/Podman API.

## Rationale

The [devcontainer CLI](https://github.com/devcontainers/cli) is pretty raw, and there isn't a standalone podman/docker implementation for devfile.

But more importantly devc is attempting to be a great tool for using
agentic AI CLI tools like Goose, Gemini CLI, etc. It makes it easy to
spawn two (or more) containers sharing a volume, where one container
may have more restricted configuration such as fewer (or different) access to
secrets (or networking, etc.)

## Scope

**What devc does:**
- Parses devfile.yaml and devcontainer.json
- Runs containers via Docker API (tested especially with Podman)
- Manages git worktrees alongside containers
- Passes secrets to containers for AI agent workflows

**What devc does NOT do:**
- SSH tunneling to containers (use `podman exec` directly)
- Kubernetes deployment (use other tools for that)
- Cloud VM provisioning (see [DevPod](https://devpod.sh/) for that)
- IDE integration (containers are just containers)

This is intentionally a thin, focused layer. For more general remote development
environments, see [DevPod](https://devpod.sh/).

## Goals

- **Dual format support**: Supports both devfile 2.x and devcontainer specs,
  with automatic detection (devfile preferred when both exist)
- **Podman-tested**: Uses Docker API but tested primarily with Podman
- **Git worktree integration**: Isolated development environments per branch/task
- **Simple**: Direct container execution, no daemon, no providers

## Planned Commands

```
devc new <worktree-name>    Create a git worktree and spawn a devcontainer for it
devc enter [worktree]       Enter a devcontainer shell (current worktree if not specified)
devc list                   List active devcontainers and their worktrees
devc rm <worktree>          Remove a worktree and its associated devcontainer
```

## Supported Configurations

`devc` automatically detects and uses the appropriate configuration:

| Format | Detection | Requirements |
|--------|-----------|--------------|
| **Devfile** (preferred) | `devfile.yaml` or `.devfile.yaml` in workspace root | Podman only |
| **Devcontainer** | `.devcontainer/devcontainer.json` | Podman + devcontainer CLI |

When both configurations exist, devfile takes precedence.

## Requirements

- Rust (for building)
- Podman (or Docker)
- [devcontainer CLI](https://github.com/devcontainers/cli) (only for `.devcontainer` support)

## Building

```bash
cargo build --release
```

## Testing

Run the unit tests:

```bash
cargo test
# or
just test
```

Run the integration tests (requires podman):

```bash
cargo test -- --ignored
# or
just test-integration
```

The integration tests verify the core use case of spawning multiple isolated
development containers from git worktrees, testing container isolation,
parallel execution, and cleanup.

Run the legacy shell integration test (uses devcontainer):

```bash
./integration.sh
# or
just test-shell
```

Run all tests:

```bash
just test-all
```

See `just --list` for all available development commands.

## Design Notes

### Devfile Support

Devfile containers are started directly via `podman run` with:
- Source mounting at `/projects` (configurable via `sourceMapping`)
- `PROJECTS_ROOT` environment variable set per devfile spec
- SELinux relabeling (`:z`) for Fedora/RHEL compatibility
- Container labels for tracking (`devfile.workspace`, `devfile.component`)

Container naming convention: `devfile-{workspace-name}-{component-name}`

### Nested Containerization

Running podman inside a devcontainer requires `--privileged` mode. The container
runs as root to enable nested containerization, as rootless podman inside a
container faces user namespace limitations (`newuidmap` permission issues).

Current status:
- **Privileged mode**: Required for nested podman (works with root user)
- **Rootless nested podman**: Not currently supported due to user namespace
  restrictions inside containers

Future goals include exploring unprivileged alternatives using:
- Sysbox runtime
- Custom seccomp profiles
- Podman socket forwarding from host

### KVM/Virtualization Support

When creating containers with devfiles, `devc` automatically detects and passes
through `/dev/kvm` for hardware virtualization support. This is essential for
bootc workflows and other use cases that require running VMs inside containers.

Behavior:
- **Automatic detection**: If `/dev/kvm` exists on the host, it's automatically
  bound to the container via `--device /dev/kvm`
- **Disable with flag**: Use `--no-kvm` to disable automatic KVM device binding:
  ```bash
  devc new my-workspace --no-kvm
  devc run-ephemeral --no-kvm
  ```
- **Logging**: When KVM is passed through, a log message confirms:
  `Passing through /dev/kvm for virtualization support`

This feature works seamlessly with privileged containers and enables running
QEMU/KVM-based workloads inside development environments.

### Secret Passthrough

Podman secrets can be passed to containers as environment variables, enabling AI agents
and other applications to access API keys securely without storing them in container images.

#### Creating Podman Secrets

First, create secrets using podman:

```bash
# From a file
podman secret create anthropic-key ~/.anthropic-api-key

# From stdin
echo "sk-ant-..." | podman secret create anthropic-key -

# Verify secrets exist
podman secret ls
```

#### Using Secrets with devc

Pass secrets to containers using the `--secret` flag with the format `SECRET_NAME=ENV_VAR`:

```bash
# Create a new workspace with secrets
devc new --secret anthropic-key=ANTHROPIC_API_KEY https://github.com/user/repo

# Create a container in current directory with secrets
devc new container --secret anthropic-key=ANTHROPIC_API_KEY

# Run ephemeral container with multiple secrets
devc run-ephemeral \
  --secret anthropic-key=ANTHROPIC_API_KEY \
  --secret openai-key=OPENAI_API_KEY \
  python script.py
```

**Note:** The `--secret` flag only applies when creating new containers. When using
`devc enter` to access an existing container, secrets that were configured during
container creation will already be available.

#### How It Works

Secrets are passed to podman using the `--secret` flag with `type=env`, which makes
the secret available as an environment variable inside the container. The secret content
is never stored in the container image or visible in `podman inspect` output.

Example:
```bash
# This command
devc new --secret anthropic-key=ANTHROPIC_API_KEY my-workspace

# Runs podman with
podman run --secret anthropic-key,type=env,target=ANTHROPIC_API_KEY ...
```

#### Security Notes

- Secrets are managed by podman's secret storage, which encrypts them at rest
- Secrets are only available to containers at runtime, not baked into images
- Each container gets its own isolated copy of the secret
- Secrets are validated before container creation to catch missing secrets early
- Secret values are never logged or displayed in command output

### AI Agent Sidecar Setup

devc makes it easy to run AI agents (like Goose, Claude Code, Gemini CLI) alongside your
development container. The sidecar container shares the same workspace but can have
different privileges and secrets.

#### Quick Setup for Goose

1. Create a podman secret for your API key:

```bash
# For Google/Gemini API
podman secret create google-api-key ~/.config/gemini

# Or from stdin
echo "your-api-key" | podman secret create google-api-key -
```

2. Create `~/.config/devc.toml`:

```toml
# Default sidecar configuration for AI agents
[sidecar]
command = ["goose"]
network = true  # goose needs network for API calls

# Mount goose configuration
[[sidecar.mounts]]
src = "~/.config/goose"
dst = "/root/.config/goose"
readonly = true

# Secret for Gemini API
[secrets.google]
secret = "google-api-key"
env = "GOOGLE_API_KEY"
container = "sidecar"
```

3. Clone and start working:

```bash
devc new https://github.com/user/repo
devc enter repo  # Enter main dev container
# Or enter the sidecar: devc enter repo -c sidecar
```

#### Configuration Options

The sidecar configuration supports:

| Option | Description | Default |
|--------|-------------|---------|
| `image` | Container image for sidecar | Same as main container |
| `command` | Command to run (e.g., `["goose"]`) | `sleep infinity` |
| `mount_sources_readonly` | Mount workspace as read-only | `false` |
| `mounts` | Additional host paths to mount (explicit src/dst) | `[]` |
| `dotfiles` | Host paths to mirror at same location (read-only) | `[]` |
| `dotfiles_repo` | Git repository URL to clone into `~/.dotfiles` | None |
| `dotfiles_install` | Install script to run after cloning | `install.sh` |

Note: Sidecars always run in the same pod as the main container and share its network namespace.

#### Dotfiles Support

**Simple path mirroring** - Mount files/directories to the same path in the container:

```toml
[sidecar]
dotfiles = ["~/.bashrc", "~/.gitconfig", "~/.config/goose"]
```

This mounts each path read-only to the same location in the container (e.g., `~/.bashrc` on host → `~/.bashrc` in container).

**Dotfiles repository** - Clone and install a dotfiles repo (like VS Code/Codespaces):

```toml
[sidecar]
dotfiles_repo = "https://github.com/user/dotfiles"
dotfiles_install = "install.sh"  # Optional, defaults to install.sh
```

The repo is cloned to `~/.dotfiles` and the install script is run if it exists and is executable.

#### Mount Specifications

For more control over mount paths, use explicit mount specifications:

```toml
[[sidecar.mounts]]
src = "~/.config/goose"     # Host path (~ expansion supported)
dst = "/root/.config/goose" # Container path
readonly = true             # Mount as read-only (default: true)
```

#### Secret Targeting

Secrets can be targeted to specific containers:

```toml
# Only for main container
[secrets.github]
secret = "github-token"
env = "GITHUB_TOKEN"
container = "main"

# Only for sidecar
[secrets.anthropic]
secret = "anthropic-key"
env = "ANTHROPIC_API_KEY"
container = "sidecar"

# For all containers
[secrets.shared]
secret = "some-secret"
env = "SHARED_SECRET"
container = "all"
```

#### Named Profiles

Define multiple agent configurations and switch between them:

```toml
[sidecar.profiles.goose]
command = ["goose"]
network = true

[sidecar.profiles.claude]
image = "ghcr.io/anthropics/claude-code:latest"
command = ["claude"]
network = true
```

Use profiles with `--sidecar-profile`:

```bash
devc new --sidecar-profile claude https://github.com/user/repo
```

#### Disabling Sidecar

To run without a sidecar:

```bash
devc new --no-sidecar https://github.com/user/repo
```

## License

Licensed under either of Apache License, Version 2.0 or MIT license at your option.

## Related Projects

See [RELATED.md](RELATED.md) for a comparison with similar tools (DevPod, odo, etc.).

## Contributing

See [AGENTS.md](AGENTS.md) for instructions for AI agents contributing to this project.
