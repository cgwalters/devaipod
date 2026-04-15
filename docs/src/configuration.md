# Configuration

Configure devaipod through `~/.config/devaipod.toml` and per-project `devcontainer.json` files.

## Global Configuration

Create `~/.config/devaipod.toml`:

```toml
# Container image for the devaipod server (default: ghcr.io/cgwalters/devaipod:latest).
# Set this to use a locally-built image for development.
# Can also be overridden by DEVAIPOD_IMAGE env var or --image flag.
# image = "localhost/devaipod:latest"

# Dotfiles repository - its devcontainer.json is used as a fallback
# when a project has no devcontainer.json of its own
[dotfiles]
url = "https://github.com/you/homegit"

# Global environment variables for all containers
[env]
# Forward these from host environment (if they exist)
allowlist = ["GOOGLE_CLOUD_PROJECT", "SSH_AUTH_SOCK", "VERTEX_LOCATION"]

# Set these explicitly
[env.vars]
VERTEX_LOCATION = "global"
EDITOR = "vim"

# Trusted environment variables (workspace + gator only, NOT agent)
[trusted.env]
allowlist = ["GH_TOKEN", "GITLAB_TOKEN", "JIRA_API_TOKEN"]

# Or use podman secrets (recommended)
[trusted]
secrets = ["GH_TOKEN=gh_token", "GITLAB_TOKEN=gitlab_token"]

# File-based secrets (mounted as files, env var points to path)
# Useful for credentials like gcloud ADC that expect a file path
file_secrets = ["GOOGLE_APPLICATION_CREDENTIALS=google_adc"]

# GPU passthrough (optional)
[gpu]
enabled = true  # or "auto" to detect
target = "all"  # or "workspace", "agent"

# Service-gator default configuration (optional)
[service-gator]
enabled = true
port = 8765

[service-gator.gh.repos]
"myorg/*" = { read = true }
"myorg/main-project" = { read = true, create-draft = true }
```

## Sources

The `[sources]` section declares host directories that devaipod mounts
into the server container. The CLI shim uses these to translate your
working directory (`~/src/github/org/repo` → `/mnt/src/github/org/repo`).
Required for `devaipod diff`, `devaipod fetch`, and the `src:<name>/<subpath>` shorthand.

### Basic usage

```toml
[sources]
src = "~/src"
```

This mounts `~/src` at `/mnt/src` inside the server container (read-write,
visible only to the server -- not agents). With this config,
`devaipod fetch` from `~/src/github/org/repo` on the host
fetches agent branches into your local repo, and `devaipod diff`
works immediately.

### Access levels

Each source can specify an access level controlling mount location
and write permissions:

```toml
[sources]
# Shorthand: r/w in the server container, not mounted in agents (controlplane)
src = "~/src"

# Explicit access levels:
data = { path = "~/data", access = "controlplane" }    # default
ro   = { path = "~/ref", access = "readonly" }          # read-only everywhere
shared = { path = "~/shared", access = "agent" }        # r/w in agents too
```

| Access | Server container | Agent containers |
|---|---|---|
| `controlplane` (default) | mounted r/w | not mounted |
| `readonly` | mounted `:ro` | not mounted |
| `agent` | mounted r/w | mounted r/w |

The `controlplane` default lets `devaipod fetch` write remotes and
fetch branches into your local git repos. Agents never see these
mounts, so the AI cannot modify your source trees.

### Source shorthand in CLI

With sources configured, reference repos by source name instead of full URLs:

```bash
# Instead of: devaipod run https://github.com/org/repo -c 'fix bug'
devaipod run src:github/org/repo -c 'fix bug'
```

The `src:github/org/repo` shorthand resolves to `/mnt/src/github/org/repo`
inside the container, which points to the source mount of `~/src/github/org/repo`
on the host.

## Bind Mounts

The `bind` array provides generic bind mounts using the same
`source:target[:options]` syntax as `podman -v` / `docker -v`.
Unlike `[sources]`, these lack git awareness and CWD translation --
they pass directly to all containers (server, workspace, and agent).

```toml
bind = [
  "~/data:/data:ro",
  "/var/cache/sccache:/cache",
]
```

Tilde in the source path expands to the host home directory.
Options like `ro`, `Z`, `U` pass through to podman as-is.

**Important:** `bind` must appear before any `[section]` header in
your config file. TOML scoping means `bind = [...]` after `[sources]`
becomes `sources.bind` (a source named "bind"), not the top-level
bind array. Devaipod warns about this, but the bind mounts will not
take effect.

Use `[sources]` for git source trees (enables `fetch`, `diff`, CWD
translation). Use `bind` for everything else (data directories,
caches, toolchains).

## Agent Configuration

Devaipod supports any ACP-compatible coding agent. Configure agent
profiles in `~/.config/devaipod.toml`:

```toml
[agent]
default = ["my-preferred-agent", "fallback-agent"]

[agent.profiles.my-preferred-agent]
command = ["my-agent", "acp"]

[agent.profiles.my-preferred-agent.env]
MY_AGENT_MODE = "auto"
```

### Agent Selection

The `default` field specifies which agent to use. It accepts:

- A single string: `default = "my-agent"`
- An ordered array: `default = ["first-choice", "second-choice"]`

When multiple profiles are listed, devaipod probes the agent container
for each binary in order and selects the first one found.

### Profile Definition

Each profile under `[agent.profiles.<name>]` defines:

- `command`: Array of strings, the command to start the agent's ACP mode
- `env`: Optional environment variables (model selection, permissions, etc.)

See [Supported Agents](agents.md) for tested configurations.

Agent-specific config files (model, MCP servers, etc.) belong in the agent's config directory, referenced by env vars if needed. Devaipod never writes agent config files -- the user maintains agent configurations.

### Container Image Requirements

The devcontainer image must include the agent binary and your
development tools (compilers, linters, etc.). Set the `image` field
in your project's `devcontainer.json` accordingly.

## Using Without devcontainer.json

Not all repositories include a `devcontainer.json`. Put a default
`devcontainer.json` in your dotfiles repository. When a project lacks one,
devaipod checks your dotfiles repo automatically.

**Dotfiles devcontainer.json** (recommended)

Add a `.devcontainer/devcontainer.json` to your dotfiles repo (configured via
`[dotfiles]` in devaipod.toml) for user-level defaults like your preferred image,
nested container support, and lifecycle commands:

```json
{
  "image": "ghcr.io/bootc-dev/devenv-debian",
  "customizations": {
    "devaipod": { "nestedContainers": true }
  },
  "runArgs": ["--privileged"],
  "postCreateCommand": {
    "devenv-init": "sudo /usr/local/bin/devenv-init.sh"
  }
}
```

`--privileged` in `runArgs` keeps compatibility with the stock devcontainer CLI.
`nestedContainers: true` tells devaipod to use a tighter set of capabilities instead.

To force the dotfiles devcontainer.json even when a project has its own, use
`--use-default-devcontainer` (or the checkbox in the web UI).

The resolution order is:

1. `--devcontainer-json` inline override
2. Project's devcontainer.json (skipped with `--use-default-devcontainer`)
3. Dotfiles repo's devcontainer.json
4. `--image` flag with default settings
5. `default-image` from config with default settings

**Other options**

You can also specify `--image` per-invocation or set `default-image` in the config,
but these only set the image without any lifecycle commands or customizations.

## Git Hosting Providers

devaipod recognizes bare hostnames like `github.com/owner/repo` and
prepends `https://`. The built-in list covers GitHub, GitLab,
Codeberg, Bitbucket, sr.ht, and Gitea. Add private instances via
the `[git]` section:

```toml
[git]
extra_hosts = ["forgejo.example.com", "gitea.corp.internal"]
```

This lets you run `devaipod up forgejo.example.com/team/project` without
the full URL. SSH URLs (`git@host:owner/repo.git`) convert to HTTPS
regardless of this setting.

## Per-Project Configuration

Projects use standard `devcontainer.json` with optional devaipod extensions:

```json
{
  "name": "my-project",
  "image": "ghcr.io/bootc-dev/devenv-debian:latest",
  "customizations": {
    "devaipod": {
      "envAllowlist": ["MY_API_KEY", "CUSTOM_TOKEN"]
    }
  }
}
```

### Secrets in devcontainer.json

Declare secrets that should be injected from podman:

```json
{
  "secrets": {
    "GEMINI_API_KEY": {
      "description": "API key for Google Gemini"
    },
    "ANTHROPIC_API_KEY": {
      "description": "API key for Claude"
    }
  }
}
```

Then create matching podman secrets:

```bash
echo "your-api-key" | podman secret create GEMINI_API_KEY -
```

## Environment Variable Priority

Environment variables merge in this order (later wins):

1. Global `[env]` section in devaipod.toml
2. Per-project `containerEnv` in devcontainer.json
3. Per-project `customizations.devaipod.envAllowlist`
4. Command-line `--env` flags

## Service-gator CLI Flags

Override configuration with CLI flags:

```bash
# Read-only access to all GitHub repos
devaipod up https://github.com/org/repo --service-gator=github:readonly-all

# Read + draft PR access to specific repo
devaipod up https://github.com/org/repo --service-gator=github:myorg/myrepo:read,create-draft

# Custom image
devaipod up https://github.com/org/repo --service-gator=github:myorg/myrepo --service-gator-image localhost/service-gator:dev
```

See [Service-gator Integration](service-gator.md) for full details.

## Multi-Agent Orchestration

Each workspace runs a single agent container by default. Multi-agent
orchestration -- a worker container alongside the agent that receives
delegated subtasks -- is opt-in:

```toml
[orchestration]
enabled = true           # Create a worker container (default: false)
worker_timeout = "30m"   # Timeout for worker subtasks

[orchestration.worker]
# How the worker accesses service-gator
# Options: "readonly" (default), "inherit", "none"
gator = "readonly"
```

When enabled, the agent delegates subtasks to the worker and reviews its
commits before merging.

**Worker gator options:**

- `"readonly"`: Worker can only read from forge (no PRs, no pushes) -- **default**
- `"inherit"`: Worker gets the same gator scopes as the agent
- `"none"`: Worker has no gator access

The worker operates further from human review, so its access is restricted by default.
