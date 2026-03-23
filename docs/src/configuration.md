# Configuration

devaipod is configured via `~/.config/devaipod.toml` and per-project `devcontainer.json` files.

## Global Configuration

Create `~/.config/devaipod.toml`:

```toml
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

# GitLab scope configuration (optional)
[service-gator.gitlab]
host = "gitlab.example.com"  # omit for gitlab.com

[service-gator.gitlab.projects]
"mygroup/*" = { read = true }
"mygroup/main-project" = { read = true, create-draft = true }
```

## Using Without devcontainer.json

Not all repositories include a `devcontainer.json`. The recommended approach is to
put a default `devcontainer.json` in your dotfiles repository. When a project has no
devcontainer.json, devaipod automatically checks your dotfiles repo for one.

**Dotfiles devcontainer.json** (recommended)

Add a `.devcontainer/devcontainer.json` to your dotfiles repo (configured via
`[dotfiles]` in devaipod.toml). This is the natural place for user-level defaults
like your preferred image, nested container support, and lifecycle commands:

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

The `runArgs` with `--privileged` keeps compatibility with the stock devcontainer CLI,
while `nestedContainers: true` tells devaipod to use a tighter set of capabilities
instead.

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
automatically prepends `https://`. The built-in list covers GitHub, GitLab,
Codeberg, Bitbucket, sr.ht, and Gitea. For private instances, add them via
the `[git]` section:

```toml
[git]
extra_hosts = ["forgejo.example.com", "gitea.corp.internal"]
```

This lets you run `devaipod up forgejo.example.com/team/project` without
typing the full URL. SSH URLs (`git@host:owner/repo.git`) are also
automatically converted to HTTPS regardless of this setting.

## TLS / Custom CA Certificates

If your git hosting provider uses a self-signed or internal CA certificate
(e.g., a private GitLab instance), configure extra CA certs so that all pod
containers trust them:

```toml
[tls]
extra_ca_certs = ["/certs/my-corp-ca.pem"]
```

Each entry is a path to a PEM-encoded certificate file (may contain multiple
certificates). The certificates are injected into all pod containers
(workspace, agent, service-gator, worker) via environment variables so that
git, curl, Python, Node.js, and other tools trust the extra CAs.

When running devaipod as a container, you must bind-mount the certificate
files into the devaipod container:

```bash
podman run -d --name devaipod -p 8080:8080 --privileged \
  -v /etc/pki/ca-trust/source/anchors/my-corp-ca.pem:/certs/my-corp-ca.pem:ro \
  -v ~/.config/devaipod.toml:/root/.config/devaipod.toml:ro \
  -v $SOCKET:/run/docker.sock \
  -e DEVAIPOD_HOST_SOCKET=$SOCKET \
  ghcr.io/cgwalters/devaipod
```

The `extra_ca_certs` paths in the config must match the container-side mount
paths (e.g., `/certs/my-corp-ca.pem` in the example above).

## Per-Project Configuration

Projects use standard `devcontainer.json` with optional devaipod customizations:

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

Environment variables are merged in this order (later wins):

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

# GitLab read + draft MR access
devaipod up https://gitlab.example.com/group/project --service-gator=gitlab:group/project:read,create-draft

# GitLab read-only access to all projects
devaipod up https://gitlab.example.com/group/project --service-gator=gitlab:readonly-all

# Custom image
devaipod up https://github.com/org/repo --service-gator=github:myorg/myrepo --service-gator-image localhost/service-gator:dev
```

See [Service-gator Integration](service-gator.md) for full details.

## Multi-Agent Orchestration

By default each workspace runs a single agent container. Multi-agent
orchestration — where a worker container runs alongside the agent and
receives delegated subtasks — is opt-in:

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

- `"readonly"`: Worker can only read from forge (no PRs, no pushes) — **default**
- `"inherit"`: Worker gets same gator scopes as the agent
- `"none"`: Worker has no gator access

The worker is one step further from human review, so it has restricted access by default.
