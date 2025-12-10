# Related Projects

This document compares `devc` with similar tools in the dev container ecosystem.

## Positioning

`devc` is an **opinionated, thin wrapper** for running devfiles and devcontainers
via the Docker/Podman API. It deliberately avoids:

- SSH tunneling (just use `podman exec`)
- Kubernetes integration (other tools do this)
- Cloud VM provisioning (see DevPod)
- IDE-specific features

For more general remote development, use [DevPod](https://devpod.sh/). `devc`
is for local container-based development with git worktree integration.

## Landscape Overview

| Tool | devcontainer.json | devfile.yaml | Podman-first | Kubernetes | Status |
|------|-------------------|--------------|--------------|------------|--------|
| **devc** | ✅ | ✅ | ✅ | ❌ | Active |
| [DevPod](https://devpod.sh/) | ✅ | ❌ | ❌ (Docker default) | ✅ (provider) | Active |
| [odo](https://github.com/redhat-developer/odo) | ❌ | ✅ | ✅ | ✅ | **Deprecated** (Oct 2025) |
| [devcontainer CLI](https://github.com/devcontainers/cli) | ✅ | ❌ | ❌ | ❌ | Active |
| [DevTree](https://github.com/pwrmind/DevTree) | ✅ | ❌ | ❌ | ❌ | Active |

## DevPod

[DevPod](https://github.com/loft-sh/devpod) by Loft Labs is an open-source,
client-only tool for reproducible dev environments using the devcontainer.json
standard.

**Strengths:**
- Provider-based architecture (local Docker, Kubernetes, cloud VMs, SSH)
- Works with any IDE via SSH
- Desktop app + CLI
- Active community with many providers

**Limitations:**
- No devfile.yaml support
- Docker-centric (Podman requires manual path configuration or community provider)
- No git worktree integration

## odo (Deprecated)

[odo](https://github.com/redhat-developer/odo) was Red Hat's developer CLI for
fast, iterative application development on Podman and Kubernetes using the
devfile standard.

**Deprecation:** Announced October 2025, end-of-life March 2026.
See [announcement](https://developers.redhat.com/articles/2025/10/23/odo-cli-deprecated-what-developers-need-know).

**Gap left by odo:** There is no maintained CLI tool for running devfiles
directly via Podman without Kubernetes. `devc` aims to fill this gap.

## devcontainer CLI

The [devcontainer CLI](https://github.com/devcontainers/cli) is the reference
implementation for the devcontainer.json specification.

- Requires Docker or Podman
- No devfile support
- No git worktree integration

## How devc Differs

`devc` is designed for developers who want:

1. **Devfile support without Kubernetes** - Run devfile.yaml directly via Podman
2. **Podman-first** - No Docker assumption or daemon requirement
3. **Git worktree integration** - Isolated dev environments per branch/task
4. **Simplicity** - Direct podman execution, no provider abstraction for local use

## Alternative: Contributing Devfile Support Upstream

Rather than maintaining a separate tool, devfile support could potentially be
added to existing projects:

### DevPod

[DevPod](https://github.com/loft-sh/devpod) would be a natural home for devfile
support. It's written in Go and has a provider-based architecture.

**Codebase analysis** (as of Dec 2024):
- ~67k lines of Go code (476 files, excluding vendor)
- Desktop app in TypeScript/Tauri (`desktop/`)
- Core config parsing in `pkg/devcontainer/config/` - tightly coupled to
  devcontainer.json schema (17 files, ~55k chars)
- Driver abstraction in `pkg/driver/` for Docker/Kubernetes backends
- Zero mentions of "devfile" anywhere in the codebase

**Where devfile support would go:**
1. New `pkg/devfile/` package parallel to `pkg/devcontainer/`
2. Add devfile detection in `pkg/devcontainer/config/parse.go` (currently only
   looks for `.devcontainer/devcontainer.json` or `.devcontainer.json`)
3. Translation layer: devfile → internal DevContainerConfig struct, or new
   parallel config path through the driver layer
4. Would need to add [devfile/library](https://pkg.go.dev/github.com/devfile/library)
   dependency

**Assessment:**
- **Pros:** Large active community (14k+ stars), mature codebase, multi-IDE support
- **Cons:** Significant refactoring needed - config layer is devcontainer-centric,
  no existing interest from maintainers, Go codebase
- **Effort:** High (substantial refactoring, unfamiliar codebase, need maintainer buy-in)

A [devfile support request for Gitpod](https://github.com/gitpod-io/gitpod/issues/18541)
was closed as "not planned" in 2024, suggesting limited industry appetite for
cross-format support in devcontainer-focused tools.

### Podman Desktop

[Podman Desktop](https://github.com/podman-desktop/podman-desktop) has an
extension system and would be a natural fit for devfile support.

- **Pros:** Red Hat project (devfile origins), extension architecture, TypeScript
- **Cons:** Desktop-focused (not CLI), no existing devfile extension
- **Effort:** Medium (TypeScript extension, new extension from scratch)

### Devfile Library

The official [devfile/library](https://pkg.go.dev/github.com/devfile/library)
provides Go APIs for parsing devfiles. Any Go-based tool could use this.

odo used this library, and a new lightweight CLI could be built on top of it
with minimal code. However, this is essentially what `devc` already does in Rust
using serde.
