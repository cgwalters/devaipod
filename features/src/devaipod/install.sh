#!/bin/bash
set -eu

# devaipod devcontainer feature installer
# Installs devaipod and gh-restricted binaries

VERSION="${VERSION:-latest}"
DEVAIPOD_REPO="cgwalters/devaipod"
# For local testing: set DEVAIPOD_LOCAL_BINARIES to a directory containing devaipod and gh-restricted
DEVAIPOD_LOCAL_BINARIES="${DEVAIPOD_LOCAL_BINARIES:-}"

echo "Activating feature 'devaipod' (version: ${VERSION})"

# Ensure running as root
if [ "$(id -u)" -ne 0 ]; then
    echo "ERROR: Script must be run as root"
    exit 1
fi

# Detect architecture
detect_arch() {
    case "$(uname -m)" in
        x86_64|amd64)
            echo "x86_64"
            ;;
        aarch64|arm64)
            echo "aarch64"
            ;;
        *)
            echo "ERROR: Unsupported architecture: $(uname -m)" >&2
            exit 1
            ;;
    esac
}

# Detect package manager
detect_package_manager() {
    for pm in apt-get apk dnf yum; do
        if command -v "$pm" >/dev/null 2>&1; then
            case $pm in
                apt-get) echo "apt" ;;
                *) echo "$pm" ;;
            esac
            return 0
        fi
    done
    echo "unknown"
}

# Install required packages
# shellcheck disable=SC2086  # Word splitting is intentional for package lists
install_packages() {
    local pkg_manager="$1"
    shift
    
    case "$pkg_manager" in
        apt)
            apt-get update
            apt-get install -y "$@"
            ;;
        apk)
            apk add --no-cache "$@"
            ;;
        dnf|yum)
            "$pkg_manager" install -y "$@"
            ;;
        *)
            echo "WARNING: Cannot install packages with unknown package manager"
            return 1
            ;;
    esac
}

# Install required system packages
install_system_packages() {
    local pkg_manager="$1"
    
    echo "Installing system packages (bubblewrap, tmux)..."
    case "$pkg_manager" in
        apt)
            install_packages apt bubblewrap tmux
            ;;
        apk)
            install_packages apk bubblewrap tmux
            ;;
        dnf|yum)
            install_packages "$pkg_manager" bubblewrap tmux
            ;;
        *)
            echo "WARNING: Cannot install packages with unknown package manager"
            return 1
            ;;
    esac
}

# Download and install devaipod from GitHub releases
install_from_github_release() {
    local version="$1"
    local arch="$2"
    local tmp_dir
    
    tmp_dir="$(mktemp -d)"
    trap 'rm -rf "$tmp_dir"' EXIT
    
    # Determine the release URL
    local base_url="https://github.com/${DEVAIPOD_REPO}/releases"
    local release_url
    
    if [ "$version" = "latest" ]; then
        release_url="${base_url}/latest/download"
    else
        release_url="${base_url}/download/v${version}"
    fi
    
    # Asset naming convention: devaipod-<arch>-unknown-linux-gnu.tar.gz
    local asset_name="devaipod-${arch}-unknown-linux-gnu.tar.gz"
    local download_url="${release_url}/${asset_name}"
    
    echo "Downloading devaipod from: ${download_url}"
    
    # Download the tarball
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL "${download_url}" -o "${tmp_dir}/devaipod.tar.gz"
    elif command -v wget >/dev/null 2>&1; then
        wget -q "${download_url}" -O "${tmp_dir}/devaipod.tar.gz"
    else
        echo "ERROR: Neither curl nor wget is available"
        exit 1
    fi
    
    # Extract and install
    echo "Extracting and installing..."
    tar -xzf "${tmp_dir}/devaipod.tar.gz" -C "${tmp_dir}"
    
    # Install binaries
    install -D -m 0755 "${tmp_dir}/devaipod" /usr/local/bin/devaipod
    
    # Install upcall binaries if present
    if [ -f "${tmp_dir}/gh-restricted" ]; then
        install -d -m 0755 /usr/lib/devaipod/upcalls
        install -D -m 0755 "${tmp_dir}/gh-restricted" /usr/lib/devaipod/upcalls/gh-restricted
    fi
    
    echo "devaipod installed successfully!"
}

# Fallback: build from source using cargo
install_from_source() {
    echo "Installing from source using cargo..."
    
    if ! command -v cargo >/dev/null 2>&1; then
        echo "ERROR: cargo not found. Please install Rust or use a pre-built binary."
        exit 1
    fi
    
    cargo install --git "https://github.com/${DEVAIPOD_REPO}" devaipod
    
    # Also build and install gh-restricted from the upcalls crate
    cargo install --git "https://github.com/${DEVAIPOD_REPO}" --package devaipod-upcalls --bin gh-restricted
    
    # Move gh-restricted to upcalls directory
    local cargo_bin="${CARGO_HOME:-$HOME/.cargo}/bin"
    if [ -f "${cargo_bin}/gh-restricted" ]; then
        install -d -m 0755 /usr/lib/devaipod/upcalls
        mv "${cargo_bin}/gh-restricted" /usr/lib/devaipod/upcalls/gh-restricted
    fi
}

# Configure podman for nested container environments
# This sets up:
# 1. An init script to configure subuid/subgid for nested user namespaces
# 2. A rootful podman service that's safe (because we're in a rootless container)
# 3. Environment variables so podman commands work transparently
configure_nested_podman() {
    echo "Configuring podman for nested containers..."
    
    # Create the devaipod init script that runs at container start
    cat > /usr/local/bin/devaipod-init.sh << 'INITSCRIPT'
#!/bin/bash
set -euo pipefail
# devaipod container initialization script
# Configures podman for nested container environments

# Fix mount propagation - may fail in some environments, that's fine
if mount -o remount --make-shared / 2>/dev/null; then
    echo "Fixed mount propagation"
fi

# /dev/kvm access - safe to expose (like Fedora derivatives do)
if [[ -e /dev/kvm ]]; then
    chmod a+rw /dev/kvm 2>/dev/null || true
fi

# Configure cgroups for nested containers
if [[ -f /usr/share/containers/containers.conf ]]; then
    sed -i -e 's,^#cgroups =.*,cgroups = "no-conmon",' /usr/share/containers/containers.conf 2>/dev/null || true
    sed -i -e 's,^#cgroup_manager =.*,cgroup_manager = "cgroupfs",' /usr/share/containers/containers.conf 2>/dev/null || true
fi

# Fix /etc/subuid and /etc/subgid for nested user namespaces
configure_nested_subuid() {
    local user=${1:-}
    
    # Find the container user if not specified
    if [[ -z "$user" ]]; then
        # Try common devcontainer user names
        for u in vscode devenv codespace; do
            if id "$u" &>/dev/null; then
                user="$u"
                break
            fi
        done
    fi
    
    [[ -z "$user" ]] && return 0
    ! id "$user" &>/dev/null && return 0
    
    # Parse uid_map to find max UID in this namespace
    local max_uid=0
    while read -r inside outside count; do
        local end=$((inside + count))
        (( end > max_uid )) && max_uid=$end
    done < /proc/self/uid_map
    
    # If we have full UID range, default config should work
    (( max_uid > 100000 )) && return 0
    
    # Check if current subuid config works
    local current_start
    current_start=$(grep "^${user}:" /etc/subuid 2>/dev/null | cut -d: -f2 || echo "0")
    (( current_start > 0 && current_start < max_uid )) && return 0
    
    # Reconfigure for constrained namespace
    local subuid_start=10000
    local subuid_count=$((max_uid - subuid_start))
    
    if (( subuid_count < 1000 )); then
        echo "Warning: Limited UID range (max=$max_uid), nested podman may not work" >&2
        return 0
    fi
    
    echo "Configuring subuid/subgid: ${user}:${subuid_start}:${subuid_count}"
    echo "${user}:${subuid_start}:${subuid_count}" > /etc/subuid
    echo "${user}:${subuid_start}:${subuid_count}" > /etc/subgid
}

configure_nested_subuid

# Start rootful podman service
# This is safe because the devcontainer runs under rootless podman on the host,
# so "root" here is actually unprivileged on the real host.
start_podman_service() {
    local socket_dir="/run/podman"
    local socket_path="${socket_dir}/podman.sock"
    
    command -v podman >/dev/null 2>&1 || return 0
    
    mkdir -p "$socket_dir"
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
}

start_podman_service
INITSCRIPT
    chmod +x /usr/local/bin/devaipod-init.sh
    
    # Create profile script to set CONTAINER_HOST
    cat > /etc/profile.d/devaipod-podman.sh << 'PROFILE'
# Use rootful podman service (safe in rootless devcontainer)
if [ -S /run/podman/podman.sock ]; then
    export CONTAINER_HOST="unix:///run/podman/podman.sock"
fi
PROFILE
    chmod 644 /etc/profile.d/devaipod-podman.sh
    
    echo "Podman configuration installed"
    echo "Run 'sudo /usr/local/bin/devaipod-init.sh' at container start"
}

# Install from local binaries (for testing)
install_from_local() {
    local bindir="$1"
    
    echo "Installing from local binaries: ${bindir}"
    
    if [ ! -f "${bindir}/devaipod" ]; then
        echo "ERROR: ${bindir}/devaipod not found"
        return 1
    fi
    
    install -D -m 0755 "${bindir}/devaipod" /usr/local/bin/devaipod
    
    if [ -f "${bindir}/gh-restricted" ]; then
        install -d -m 0755 /usr/lib/devaipod/upcalls
        install -D -m 0755 "${bindir}/gh-restricted" /usr/lib/devaipod/upcalls/gh-restricted
    fi
    
    echo "devaipod installed from local binaries"
}

# Main installation logic
main() {
    local pkg_manager
    local arch
    
    pkg_manager="$(detect_package_manager)"
    arch="$(detect_arch)"
    
    echo "Detected: package_manager=${pkg_manager}, arch=${arch}"
    
    # Install system packages (bubblewrap, tmux)
    install_system_packages "$pkg_manager" || true
    
    # Configure podman for nested containers
    configure_nested_podman
    
    # Check for local binaries first (for testing)
    if [ -n "${DEVAIPOD_LOCAL_BINARIES}" ] && [ -d "${DEVAIPOD_LOCAL_BINARIES}" ]; then
        install_from_local "${DEVAIPOD_LOCAL_BINARIES}"
    else
        # Ensure curl or wget is available for downloading
        if ! command -v curl >/dev/null 2>&1 && ! command -v wget >/dev/null 2>&1; then
            echo "Installing curl..."
            install_packages "$pkg_manager" curl || install_packages "$pkg_manager" wget
        fi
        
        # Try to install from GitHub release first
        if install_from_github_release "$VERSION" "$arch" 2>/dev/null; then
            echo "Installed from GitHub release"
        else
            echo "GitHub release not available, falling back to source build..."
            install_from_source
        fi
    fi
    
    # Verify installation
    if command -v devaipod >/dev/null 2>&1; then
        echo "devaipod installation verified"
        devaipod --version 2>/dev/null || devaipod --help | head -1
    else
        echo "ERROR: devaipod installation failed"
        exit 1
    fi
}

main
