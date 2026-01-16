#!/bin/bash
set -euo pipefail
# Set things up so that podman can run nested inside a container.
# This script is designed to work in multiple scenarios:
# - GitHub Codespaces (privileged docker container on a VM)
# - Local rootless podman (nested user namespaces)
# - VS Code Remote Containers
# - Other devcontainer environments

# Fix the propagation - may fail in nested containers where / is already shared,
# or if we don't have privileges. That's fine.
if sudo mount -o remount --make-shared / 2>/dev/null; then
    echo "Fixed mount propagation"
fi

# /dev/kvm access - safe to expose to all users (like Fedora derivatives do)
# May not exist in all environments
if [[ -e /dev/kvm ]]; then
    chmod a+rw /dev/kvm 2>/dev/null || true
fi

# Handle nested cgroups - needed for podman-in-podman
if [[ -f /usr/share/containers/containers.conf ]]; then
    sed -i -e 's,^#cgroups =.*,cgroups = "no-conmon",' /usr/share/containers/containers.conf
    sed -i -e 's,^#cgroup_manager =.*,cgroup_manager = "cgroupfs",' /usr/share/containers/containers.conf
fi

# Fix /etc/subuid and /etc/subgid for nested user namespaces.
#
# When running inside a rootless podman container, the container only has
# a limited range of UIDs mapped. The image may configure subuid with UIDs
# outside this range (e.g., 100000:65536), which won't work.
#
# We detect the available UID range from /proc/self/uid_map and reconfigure
# subuid/subgid if needed to use UIDs within the available range.
configure_nested_subuid() {
    local user=${1:-devenv}
    
    # Check if user exists
    if ! id "$user" &>/dev/null; then
        return 0
    fi
    
    # Parse uid_map to find the max UID available in this namespace
    # Format: <inside_start> <outside_start> <count>
    local max_uid=0
    while read -r inside outside count; do
        local end=$((inside + count))
        if (( end > max_uid )); then
            max_uid=$end
        fi
    done < /proc/self/uid_map
    
    # If max_uid is very large, we're on a real host or have full access
    # The default subuid config (e.g., 100000:65536) should work fine
    if (( max_uid > 100000 )); then
        return 0
    fi
    
    # We're in a constrained namespace - check if current subuid config works
    local current_start
    current_start=$(grep "^${user}:" /etc/subuid 2>/dev/null | cut -d: -f2 || echo "0")
    
    # If current config uses UIDs within our range, it's fine
    if (( current_start > 0 && current_start < max_uid )); then
        return 0
    fi
    
    # Need to reconfigure - reserve 1-9999 for system, use 10000+ for subordinate UIDs
    local subuid_start=10000
    local subuid_count=$((max_uid - subuid_start))
    
    if (( subuid_count < 1000 )); then
        echo "Warning: Limited UID range available (max=$max_uid), nested podman may not work" >&2
        return 0
    fi
    
    echo "Configuring subuid/subgid for nested containers: ${user}:${subuid_start}:${subuid_count}"
    echo "${user}:${subuid_start}:${subuid_count}" > /etc/subuid
    echo "${user}:${subuid_start}:${subuid_count}" > /etc/subgid
    
    # Reset podman storage if it exists (may have been created with wrong mappings)
    local user_home
    user_home=$(getent passwd "$user" | cut -d: -f6)
    if [[ -d "${user_home}/.local/share/containers/storage" ]]; then
        echo "Resetting podman storage for new UID mappings..."
        rm -rf "${user_home}/.local/share/containers/storage" 2>/dev/null || true
    fi
}

configure_nested_subuid devenv

# Start a rootful podman service for container operations.
#
# Rootless podman doesn't work well in nested containers because newuidmap/newgidmap
# setuid binaries fail. However, running "sudo podman" is safe here because:
# - This container runs under rootless podman on the host
# - "root" inside this container is actually an unprivileged UID on the real host
# - Even "podman run --privileged" containers are constrained by the outer user namespace
#
# We start the service with a world-accessible socket so both the devenv user
# and the AI agent sandbox can use it.
start_podman_service() {
    local socket_dir="/run/podman"
    local socket_path="${socket_dir}/podman.sock"
    
    # Check if podman is available
    if ! command -v podman &>/dev/null; then
        echo "podman not found, skipping podman service setup"
        return 0
    fi
    
    mkdir -p "$socket_dir"
    
    # Clean up any existing socket
    rm -f "$socket_path"
    
    # Start podman service in background with nohup so it survives script exit
    nohup podman system service --time=0 "unix://${socket_path}" >/dev/null 2>&1 &
    
    # Wait for socket to appear and make it world-accessible
    for i in $(seq 1 50); do
        if [ -S "$socket_path" ]; then
            chmod 666 "$socket_path"
            echo "Podman service started at $socket_path"
            break
        fi
        sleep 0.1
    done
    
    # Create environment file for shells to source
    cat > /etc/profile.d/podman-remote.sh << 'EOF'
# Use rootful podman service (safe in rootless container)
export CONTAINER_HOST="unix:///run/podman/podman.sock"
EOF
    chmod 644 /etc/profile.d/podman-remote.sh
}

start_podman_service
