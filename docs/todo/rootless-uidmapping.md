# Rootless Podman UID Mapping for Bind Mounts

Assisted-by: OpenCode (Claude Opus 4.6)

**Depends on**: [workspace-v2.md](./workspace-v2.md) (host-side bind mounts
must be in place; this doc addresses the UID ownership issues they create).

## Problem

Workspace-v2 replaces opaque podman volumes with host-side bind mounts.
In rootless podman, the default user namespace mapping makes bind-mounted
files unreadable by the container's non-root user.

Concrete example on a host where our user is UID 1002:

```
Rootless podman default UID mapping:
  host UID 1002 (us)   →  container UID 0 (root)
  host UIDs 655360+     →  container UIDs 1-65535

Consequence:
  Files we own on the host appear as owned by root inside the container.
  The devenv user (container UID 1000) cannot read them.
```

This affects `--source-dir` mounts at `/mnt/source/<name>` and the
existing `.git` init-container mount. The agent workspace at `/workspaces/`
is less affected because init containers clone as root then chown, but
the source mounts are read-only so chown is not an option.

## How Other Implementations Handle This

### devcontainer CLI (VS Code, Codespaces)

The devcontainer CLI implements `updateRemoteUserUID` (enabled by default
on Linux). Before creating the container, it rebuilds the image with a
Dockerfile that edits `/etc/passwd` and `/etc/group` via `sed`, changing
the `remoteUser`'s UID/GID to match the host user's UID/GID, then
`chown -R`s the home directory.

This works for **rootful Docker** where host UIDs pass through
unmodified. It does **not** solve rootless podman because the UID
that appears correct inside the container maps to a subordinate UID
on the host, not to the actual file owner.

The devcontainer spec acknowledges this gap: "Implementations may skip
this task if they... use a container engine that does this translation
automatically."

### Podman's `--userns=keep-id`

Podman provides `--userns=keep-id` which changes the mapping so the
host user's UID maps to itself (instead of to root):

```
With --userns=keep-id:
  host UID 1002 (us)   →  container UID 1002
  (other mappings adjusted accordingly)
```

Combined with `updateRemoteUserUID` (changing the container user to
UID 1002), this makes bind-mounted files accessible. The variant
`--userns=keep-id:uid=1000,gid=1000` maps the host user directly
to UID 1000 so no image modification is needed.

This is the community-standard answer, but it has tradeoffs for
nested containers — the `--userns` flag interacts with how nested
podman configures its own subordinate UIDs.

## Current State in Devaipod

Devaipod does **not** implement `updateRemoteUserUID` and does **not**
use `--userns=keep-id`. It relies on the image-baked `devenv` user
(UID 1000) and default rootless user namespace behavior.

The `AGENT_HOME_PATH` constant (`/home/devenv`) is hardcoded and
referenced ~30 times. All agent/worker containers assume this user
exists in the image's `/etc/passwd`.

Init containers work around the problem by running as root (the
host user maps to root in default rootless mode) and then
`chown -R devenv:devenv` the cloned content. This works for writable
volumes but not for read-only source mounts.

## Proposed Design: Dynamic User at Container Start

Instead of depending on a pre-baked user in the image, create the
container user dynamically at startup with a UID that matches the
bind-mount owner.

### How it works

In default rootless podman, the host user maps to container UID 0.
Files we own appear as root-owned inside the container. So the
simplest fix is: **run as root**.

But we don't actually want to run everything as root — we want a
proper non-root user for tool isolation, git authorship, and nested
container support. The answer is to create one at startup:

```bash
# In the container entrypoint, before running the agent:
useradd --uid $DEVAIPOD_USER_UID --home-dir /home/devenv \
        --create-home --shell /bin/bash devenv 2>/dev/null \
  || usermod --uid $DEVAIPOD_USER_UID devenv 2>/dev/null \
  || true

exec su-exec devenv opencode serve ...
```

Where `DEVAIPOD_USER_UID` is determined by devaipod at pod creation
time by probing the UID mapping.

### UID selection logic

At pod creation time, devaipod determines the right container UID:

1. Read `/proc/self/uid_map` (or `podman unshare cat /proc/self/uid_map`
   from host mode) to get the mapping
2. Find what container UID the host user maps to — in default rootless
   mode this is UID 0
3. Since we want a non-root user that can read root-owned files, create
   the user in group 0 (root group), and ensure bind-mounted directories
   have group-read permissions — **or** simply use `--userns=keep-id`
   and create the user at the host UID

Actually, thinking through this more carefully: if our files appear as
root-owned and we create a user in group `root`, that user can read
files with group-read permission. But the bind-mount permissions from
the host are `drwxrwx---+` (770) owned by our user and group — which
means inside the container they're owned by `root:root` with mode 770.
A user in the `root` group could read them.

However, this is fragile and depends on the host-side permissions
including group access. A cleaner approach:

### Recommended: `--userns=keep-id` with dynamic user

Use `--userns=keep-id:uid=1000,gid=1000` on pod creation. This maps
the host user to container UID 1000 (the standard devenv UID). No
image modification needed, no dynamic user creation needed, and
bind-mounted files are accessible because the host user IS the
container user.

```
With --userns=keep-id:uid=1000,gid=1000:
  host UID 1002 (us)   →  container UID 1000 (devenv)
  
  Files we own on the host appear as owned by devenv inside.
  The devenv user can read/write them. Problem solved.
```

### Interaction with nested containers

The `--userns` flag on the pod affects how nested podman (inside the
devcontainer) sets up its own user namespaces. The
`configure_subuid()` function in `main.rs` already handles constrained
UID ranges by writing `/etc/subuid` and `/etc/subgid` — this should
continue to work, but needs testing.

With `keep-id:uid=1000`, the container sees a constrained UID range
(the host user's subordinate UIDs remapped). `configure_subuid`
reads `/proc/self/uid_map` to detect this and adjusts accordingly.
This is the same situation it already handles.

### What changes

**`src/pod.rs` — `DevaipodPod::create()`:**

When creating the pod (via `podman pod create`), add
`--userns=keep-id:uid=1000,gid=1000` to the pod-level flags.
Since all containers in the pod share the user namespace, this
applies to workspace, agent, worker, gator, and api containers.

This is a one-line change to `PodmanService::create_pod()`.

**`src/podman.rs` — `create_pod()`:**

Add `--userns=keep-id:uid=1000,gid=1000` as a default argument.
Allow override via devcontainer.json or config.

**Init containers:**

Init containers currently run as root and then chown. With `keep-id`,
the host user maps to UID 1000 instead of UID 0, so init containers
run as the devenv user directly. The root fallback when extra binds
are present (`run_init_container_impl`) needs adjustment — instead
of `--user 0`, skip the override and let the user mapping handle it.

Actually, init containers are **not** part of the pod — they're
standalone `podman run` containers. They need their own
`--userns=keep-id:uid=1000,gid=1000` flag, or they need to run
as root with the default user namespace. Since init containers
already work (they clone as root, then chown), the simplest approach
is to leave them unchanged.

**`AGENT_HOME_PATH` and user assumptions:**

No change needed. The `devenv` user (UID 1000) already exists in the
devenv images. With `keep-id:uid=1000`, the host user maps to
UID 1000, which IS the devenv user. Everything just works.

### Configuration

Add a config option to control UID mapping behavior:

```toml
# In devaipod.toml
[container]
# Options: "keep-id" (default), "default", "auto"
# keep-id: use --userns=keep-id:uid=1000,gid=1000 (fixes bind mount perms)
# default: use podman's default user namespace (current behavior)
# auto: probe the image for the user UID and use keep-id with that UID
userns = "keep-id"
```

Default to `"keep-id"` for new installations. Document the change.

## Alternative Considered: Drop Non-root Default, Create User Dynamically

Instead of `keep-id`, we could:

1. Always start containers as root (the default in rootless podman)
2. At container start, create a `devenv` user with a UID that makes
   bind-mount files accessible
3. `su-exec` / `gosu` to that user before running the workload

The right UID would be 0 (root), since that's what our files map to.
But then we'd be running as root, which defeats the purpose.

We could create the user with UID 0 and a different username, but
that's just an alias for root — it provides no actual isolation.

The only way to make this work without `keep-id` is to add group
permissions: create a user in the `root` group so it can access
root-owned files. This is fragile (depends on host file permissions
including group access) and less clean than `keep-id`.

**Verdict**: `--userns=keep-id` is simpler, more correct, and
well-supported by podman. The dynamic user approach solves a problem
that `keep-id` doesn't have.

## Implementation Plan

1. Add `--userns=keep-id:uid=1000,gid=1000` to `create_pod()` as
   the default for pods with bind mounts (i.e., LocalRepo with
   workspace-v2 host dirs or any `--source-dir`)
2. Test nested container support (`configure_subuid` + podman-in-podman)
3. Test that init containers still work (they run outside the pod)
4. Add `[container] userns` config option for override
5. Update integration tests
6. Document the change in the user-facing docs

## Open Questions

1. **Image compatibility**: Does `keep-id:uid=1000` work with images
   that use a different UID for the non-root user (e.g., `vscode` at
   UID 1000 in microsoft images, or custom images with UID 1001)?
   The `uid=1000` should match the common convention, but `auto` mode
   could probe the image to find the right UID.

2. **Pod-level vs container-level**: `--userns` is set at the pod level,
   so all containers share the same mapping. Is this correct for the
   gator and api sidecars? They run with separate images that may not
   have a user at UID 1000. Need to verify they still work — they
   currently run as the image default user with `user: None`.

3. **macOS / podman machine**: On macOS, podman runs inside a VM
   (podman machine). The UID mapping may be different. Need to test.
   The devcontainer CLI only runs `updateRemoteUserUID` on Linux by
   default.

4. **Rootful podman / Docker**: If someone runs devaipod with rootful
   Docker, `--userns=keep-id` is not needed (UIDs pass through). The
   `userns = "auto"` mode should detect this and skip the flag.
