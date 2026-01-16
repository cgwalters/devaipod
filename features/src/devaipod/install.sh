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

# Create wrapper script for devaipod configure-env
# This is called from postStartCommand in devcontainer.json
create_init_script() {
    cat > /usr/local/bin/devaipod-init.sh << 'INITSCRIPT'
#!/bin/bash
set -euo pipefail
# Wrapper script for devaipod configure-env
# Preserve DEVPOD=true so devaipod knows it's in container mode
exec env DEVPOD=true devaipod configure-env
INITSCRIPT
    chmod +x /usr/local/bin/devaipod-init.sh
    echo "Created /usr/local/bin/devaipod-init.sh"
}

# Legacy: Create profile script (configure-env will also create this)
create_profile_script() {
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
    
    # Create init script and profile for podman
    create_init_script
    create_profile_script
    
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
