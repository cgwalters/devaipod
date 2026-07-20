#!/usr/bin/env python3
"""
Harvest git commits from legacy devaipod agent-workspace volumes into
the corresponding host repositories under ~/src/github/<org>/<repo>.

This script is READ-ONLY with respect to podman volumes — it never
deletes, modifies, or writes to any volume.  It creates git bundles
in a temp directory via `podman unshare`, then fetches those bundles
into the host repo under refs/devaipod/<session>/<branch>.

Usage:
    python3 harvest-legacy-volumes.py [--dry-run] [--cache /tmp/cache.json] [--verbose]

The --cache flag avoids re-introspecting volumes whose containers are
stopped (i.e. the volume content is immutable).  Running containers'
volumes are always introspected fresh.
"""

import argparse
import json
import logging
import os
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field, asdict
from pathlib import Path

log = logging.getLogger("harvest")

VOLUMES_ROOT = Path.home() / ".local/share/containers/storage/volumes"
SRC_ROOT = Path.home() / "src/github"
# We only care about agent-workspace volumes (where the agent's commits live).
VOLUME_SUFFIX = "-agent-workspace"
VOLUME_PREFIX = "devaipod-"
# Skip test/debug volumes.
SKIP_PATTERNS = ["test-", "debug-", "advisor-img-"]


@dataclass
class VolumeInfo:
    """Metadata extracted from a single agent-workspace volume."""
    volume_name: str
    session_id: str  # e.g. "bootc-a430b3"
    # Discovered by introspecting the git repo inside:
    repo_url: str = ""  # e.g. "https://github.com/bootc-dev/bootc"
    org: str = ""
    repo: str = ""
    project_dir: str = ""  # subdir inside volume, e.g. "bootc"
    branches: dict = field(default_factory=dict)  # branch -> sha
    main_workspace_volume: str = ""  # corresponding -workspace volume name
    error: str = ""


def run(cmd: list[str], **kwargs) -> subprocess.CompletedProcess:
    """Run a command, logging it at debug level."""
    log.debug("+ %s", " ".join(cmd))
    return subprocess.run(cmd, capture_output=True, text=True, **kwargs)


def run_unshare_git(volume_path: str, git_args: list[str],
                    alternates_path: str | None = None) -> subprocess.CompletedProcess:
    """Run a git command inside podman unshare with safe.directory=* and
    optional GIT_ALTERNATE_OBJECT_DIRECTORIES.

    safe.directory=* is needed because volume files are owned by container
    subuids, which triggers git's ownership check.  The setting is scoped
    to this subprocess via GIT_CONFIG_COUNT env vars (not persisted).
    """
    env_args = [
        "env",
        "GIT_CONFIG_COUNT=1",
        "GIT_CONFIG_KEY_0=safe.directory",
        "GIT_CONFIG_VALUE_0=*",
    ]
    if alternates_path:
        env_args.append(f"GIT_ALTERNATE_OBJECT_DIRECTORIES={alternates_path}")

    cmd = ["podman", "unshare"] + env_args + ["git", "-C", volume_path] + git_args
    return run(cmd)


def list_agent_workspace_volumes() -> list[str]:
    """Return sorted list of agent-workspace volume names, excluding test/debug."""
    result = run(["podman", "volume", "ls", "--format", "{{.Name}}"])
    if result.returncode != 0:
        log.error("Failed to list volumes: %s", result.stderr)
        sys.exit(1)

    volumes = []
    for name in sorted(result.stdout.strip().splitlines()):
        if not name.startswith(VOLUME_PREFIX):
            continue
        if not name.endswith(VOLUME_SUFFIX):
            continue
        if any(pat in name for pat in SKIP_PATTERNS):
            continue
        volumes.append(name)
    return volumes


def get_running_sessions() -> set[str]:
    """Return session IDs (e.g. 'bootc-bcf981') of currently running pods."""
    result = run(["podman", "ps", "--format", "{{.Names}}"])
    if result.returncode != 0:
        return set()

    sessions = set()
    for name in result.stdout.strip().splitlines():
        if not name.startswith(VOLUME_PREFIX):
            continue
        # Container names: devaipod-<session>-<role>
        # Strip prefix and the last component (role: agent, workspace, gator, api)
        rest = name[len(VOLUME_PREFIX):]
        parts = rest.rsplit("-", 1)
        if len(parts) == 2:
            sessions.add(parts[0])
    return sessions


def extract_session_id(volume_name: str) -> str:
    """Extract session ID from volume name.
    e.g. 'devaipod-bootc-a430b3-agent-workspace' -> 'bootc-a430b3'
    """
    rest = volume_name[len(VOLUME_PREFIX):]
    return rest[: -len(VOLUME_SUFFIX)]


def parse_github_url(url: str) -> tuple[str, str]:
    """Parse a GitHub URL into (org, repo).
    Handles:
      https://github.com/org/repo
      https://github.com/org/repo.git
      git@github.com:org/repo.git
    Returns ("", "") if not a recognized GitHub URL.
    """
    url = url.strip()
    if url.startswith("git@github.com:"):
        path = url[len("git@github.com:"):]
    elif "github.com/" in url:
        idx = url.index("github.com/") + len("github.com/")
        path = url[idx:]
    else:
        return "", ""

    path = path.removesuffix(".git").strip("/")
    parts = path.split("/")
    if len(parts) >= 2:
        return parts[0], parts[1]
    return "", ""


def introspect_volume(volume_name: str) -> VolumeInfo:
    """Introspect a single agent-workspace volume to discover its git metadata.

    This is READ-ONLY — we only read the volume via podman unshare.
    """
    session_id = extract_session_id(volume_name)
    info = VolumeInfo(volume_name=volume_name, session_id=session_id)

    vol_data = VOLUMES_ROOT / volume_name / "_data"
    if not vol_data.exists():
        info.error = f"Volume data dir not found: {vol_data}"
        return info

    # Find git repos inside the volume (usually exactly one subdir)
    # We need podman unshare to list because files are owned by subuids
    result = run(["podman", "unshare", "ls", str(vol_data)])
    if result.returncode != 0:
        info.error = f"Cannot list volume: {result.stderr}"
        return info

    subdirs = [d for d in result.stdout.strip().splitlines() if d]
    if not subdirs:
        info.error = "Volume is empty"
        return info

    # Usually exactly one project directory
    project_dir = subdirs[0]
    info.project_dir = project_dir
    repo_path = str(vol_data / project_dir)

    # Corresponding main workspace volume (for git alternates)
    info.main_workspace_volume = volume_name.replace(VOLUME_SUFFIX, "-workspace")
    main_vol_data = VOLUMES_ROOT / info.main_workspace_volume / "_data" / project_dir
    alternates_path = str(main_vol_data / ".git/objects") if main_vol_data.exists() else None

    # Get origin remote URL
    result = run_unshare_git(repo_path, ["remote", "get-url", "origin"],
                             alternates_path=alternates_path)
    if result.returncode != 0:
        info.error = f"Cannot get remote URL: {result.stderr.strip()}"
        return info

    info.repo_url = result.stdout.strip()
    info.org, info.repo = parse_github_url(info.repo_url)

    if not info.org or not info.repo:
        info.error = f"Cannot parse GitHub org/repo from URL: {info.repo_url}"
        return info

    # Get branches and their SHAs
    result = run_unshare_git(
        repo_path,
        ["branch", "--format=%(refname:short) %(objectname)"],
        alternates_path=alternates_path,
    )
    if result.returncode != 0:
        info.error = f"Cannot list branches: {result.stderr.strip()}"
        return info

    for line in result.stdout.strip().splitlines():
        parts = line.strip().split(None, 1)
        if len(parts) == 2:
            info.branches[parts[0]] = parts[1]

    return info


def create_bundle(info: VolumeInfo, bundle_dir: str) -> str | None:
    """Create a git bundle from the agent-workspace volume.

    Returns the bundle path, or None on failure.
    This is READ-ONLY on the volume — the bundle is written to a temp dir.
    """
    vol_data = VOLUMES_ROOT / info.volume_name / "_data" / info.project_dir
    main_vol_data = (
        VOLUMES_ROOT / info.main_workspace_volume / "_data" / info.project_dir
    )
    alternates_path = (
        str(main_vol_data / ".git/objects") if main_vol_data.exists() else None
    )

    bundle_path = os.path.join(
        bundle_dir, f"{info.session_id}.bundle"
    )

    # Bundle only local branches (refs/heads/*), not remotes
    result = run_unshare_git(
        str(vol_data),
        ["bundle", "create", bundle_path, "--branches"],
        alternates_path=alternates_path,
    )
    if result.returncode != 0:
        log.error(
            "  Failed to create bundle for %s: %s",
            info.volume_name,
            result.stderr.strip(),
        )
        return None

    return bundle_path


def fetch_bundle_into_host(
    info: VolumeInfo, bundle_path: str, dry_run: bool
) -> bool:
    """Fetch a git bundle into the corresponding host repo.

    Refs are stored under refs/devaipod/<session>/<branch> to avoid
    polluting the normal branch namespace.
    """
    host_repo = SRC_ROOT / info.org / info.repo
    if not host_repo.exists():
        log.warning(
            "  Host repo not found: %s — skipping (you may need to clone it first)",
            host_repo,
        )
        return False

    # Verify it's a git repo
    dot_git = host_repo / ".git"
    if not dot_git.exists() and not (host_repo / "HEAD").exists():
        log.warning("  %s is not a git repository — skipping", host_repo)
        return False

    # Fetch all branches from the bundle into refs/devaipod/<session>/...
    refspec = f"refs/heads/*:refs/devaipod/{info.session_id}/*"
    cmd = ["git", "-C", str(host_repo), "fetch", bundle_path, refspec]

    if dry_run:
        log.info("  [DRY RUN] Would run: %s", " ".join(cmd))
        return True

    result = run(cmd)
    if result.returncode != 0:
        log.error("  Fetch failed: %s", result.stderr.strip())
        return False

    # Log what was fetched
    for line in (result.stderr or result.stdout).strip().splitlines():
        if line.strip():
            log.info("  %s", line.strip())

    return True


def load_cache(cache_path: str) -> dict:
    """Load the volume introspection cache."""
    if os.path.exists(cache_path):
        with open(cache_path) as f:
            return json.load(f)
    return {}


def save_cache(cache_path: str, cache: dict):
    """Save the volume introspection cache."""
    with open(cache_path, "w") as f:
        json.dump(cache, f, indent=2)
    log.debug("Cache saved to %s", cache_path)


def main():
    parser = argparse.ArgumentParser(
        description="Harvest git commits from legacy devaipod volumes"
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would be done without actually fetching",
    )
    parser.add_argument(
        "--cache",
        default=None,
        help="Path to cache file for volume introspection results "
        "(avoids re-reading stopped volumes)",
    )
    parser.add_argument(
        "--verbose", "-v", action="store_true", help="Enable debug logging"
    )
    parser.add_argument(
        "--filter",
        default=None,
        help="Only process volumes matching this substring (e.g. 'bootc', 'composefs')",
    )
    parser.add_argument(
        "--repo",
        default=None,
        help="Only harvest volumes belonging to this org/repo "
        "(e.g. 'composefs/tar-core').  Requires introspecting all volumes "
        "first (use --cache to speed up repeat runs).  Unlike --filter, "
        "this matches on the actual git remote, not the volume name.",
    )
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)s: %(message)s",
    )

    volumes = list_agent_workspace_volumes()
    log.info("Found %d agent-workspace volumes", len(volumes))

    if args.filter:
        volumes = [v for v in volumes if args.filter in v]
        log.info("After filter '%s': %d volumes", args.filter, len(volumes))

    running_sessions = get_running_sessions()
    log.info(
        "Running sessions (will skip): %s",
        ", ".join(sorted(running_sessions)) if running_sessions else "(none)",
    )

    cache: dict = {}
    if args.cache:
        cache = load_cache(args.cache)
        log.info("Loaded cache with %d entries", len(cache))

    # Phase 1: introspect all volumes
    log.info("")
    log.info("=== Phase 1: Introspecting volumes ===")
    infos: list[VolumeInfo] = []
    for vol in volumes:
        session_id = extract_session_id(vol)

        # Skip running sessions — their volumes are in use
        if session_id in running_sessions:
            log.info("  SKIP (running): %s", vol)
            continue

        # Check cache for stopped volumes
        if vol in cache:
            info = VolumeInfo(**cache[vol])
            log.debug("  CACHED: %s -> %s/%s", vol, info.org, info.repo)
            infos.append(info)
            continue

        log.info("  Introspecting: %s ...", vol)
        info = introspect_volume(vol)

        if info.error:
            log.warning("  ERROR: %s: %s", vol, info.error)
        else:
            log.info(
                "    -> %s/%s (%d branches: %s)",
                info.org,
                info.repo,
                len(info.branches),
                ", ".join(info.branches.keys()),
            )

        infos.append(info)

        # Cache successful results only (errored volumes may be retried
        # after fixing the issue, e.g. cloning a missing host repo)
        if args.cache and not info.error:
            cache[vol] = asdict(info)

    if args.cache:
        save_cache(args.cache, cache)

    # Filter by --repo if specified (after introspection, since volume names
    # don't reliably encode the org/repo — e.g. "devaipod-218-*" is actually
    # composefs/composefs-rs).  Accepts "org/repo" or just "repo".
    if args.repo:
        if "/" in args.repo:
            match_org, match_repo = args.repo.split("/", 1)
            infos = [
                i for i in infos
                if i.org == match_org and i.repo == match_repo
            ]
        else:
            infos = [i for i in infos if i.repo == args.repo]
        log.info("After --repo '%s': %d matching volumes", args.repo, len(infos))

    # Phase 2: group by org/repo and report
    log.info("")
    log.info("=== Phase 2: Summary ===")
    by_repo: dict[str, list[VolumeInfo]] = {}
    errors = []
    for info in infos:
        if info.error:
            errors.append(info)
            continue
        key = f"{info.org}/{info.repo}"
        by_repo.setdefault(key, []).append(info)

    for key in sorted(by_repo):
        vols = by_repo[key]
        host_path = SRC_ROOT / key.replace("/", os.sep)
        exists = host_path.exists()
        status = "OK" if exists else "MISSING"
        log.info(
            "  %s: %d sessions [host: %s]", key, len(vols), status
        )
        for v in vols:
            branches_str = ", ".join(
                f"{b}={s[:8]}" for b, s in v.branches.items()
            )
            log.info("    %s: %s", v.session_id, branches_str)

    if errors:
        log.info("")
        log.info("  Volumes with errors (%d):", len(errors))
        for info in errors:
            log.info("    %s: %s", info.volume_name, info.error)

    # Phase 3: create bundles and fetch
    log.info("")
    log.info("=== Phase 3: Harvest ===")

    with tempfile.TemporaryDirectory(prefix="devaipod-harvest-") as bundle_dir:
        success = 0
        skipped = 0
        failed = 0

        for key in sorted(by_repo):
            vols = by_repo[key]
            host_path = SRC_ROOT / key.replace("/", os.sep)

            if not host_path.exists():
                log.warning("  SKIP %s — no host repo at %s", key, host_path)
                skipped += len(vols)
                continue

            log.info("  %s (%d sessions)", key, len(vols))

            for info in vols:
                log.info("    Session %s:", info.session_id)

                if args.dry_run:
                    branches = ", ".join(info.branches.keys()) or "(none)"
                    log.info(
                        "      [DRY RUN] Would fetch %s into %s/refs/devaipod/%s/",
                        branches, host_path, info.session_id,
                    )
                    success += 1
                    continue

                bundle_path = create_bundle(info, bundle_dir)
                if not bundle_path:
                    failed += 1
                    continue

                if fetch_bundle_into_host(info, bundle_path, dry_run=False):
                    success += 1
                else:
                    failed += 1

                # Remove bundle after use to save disk
                if bundle_path and os.path.exists(bundle_path):
                    os.unlink(bundle_path)

        log.info("")
        log.info("=== Done ===")
        log.info(
            "  Fetched: %d, Skipped: %d, Failed: %d, Errors: %d",
            success,
            skipped,
            failed,
            len(errors),
        )

    # Final: show how to inspect results
    if success > 0 and not args.dry_run:
        log.info("")
        log.info("To see harvested refs in a repo:")
        log.info("  git -C ~/src/github/<org>/<repo> for-each-ref refs/devaipod/")
        log.info("")
        log.info("To inspect a specific session's work:")
        log.info(
            "  git -C ~/src/github/<org>/<repo> log --oneline refs/devaipod/<session>/<branch>"
        )
        log.info("")
        log.info("To diff against upstream:")
        log.info(
            "  git -C ~/src/github/<org>/<repo> diff origin/main...refs/devaipod/<session>/<branch>"
        )


if __name__ == "__main__":
    main()
