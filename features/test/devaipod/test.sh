#!/bin/bash

# This test file will be executed against an auto-generated devcontainer.json that
# temporary installs the 'devaipod' feature for validation.
#
# For more information, see: https://github.com/devcontainers/cli/blob/main/docs/features/test.md

set -e

# Verify devaipod is installed and runnable
echo "Testing devaipod binary..."
if ! command -v devaipod &> /dev/null; then
    echo "ERROR: devaipod command not found"
    exit 1
fi

devaipod --help > /dev/null
echo "PASS: devaipod --help works"

# Verify gh-restricted is installed
echo "Testing gh-restricted binary..."
if [ ! -x /usr/lib/devaipod/upcalls/gh-restricted ]; then
    echo "ERROR: gh-restricted not found at /usr/lib/devaipod/upcalls/gh-restricted"
    exit 1
fi

/usr/lib/devaipod/upcalls/gh-restricted --help > /dev/null
echo "PASS: gh-restricted --help works"

# Verify bubblewrap is installed
echo "Testing bubblewrap..."
if ! command -v bwrap &> /dev/null; then
    echo "WARNING: bwrap not found (may be expected in unprivileged containers)"
else
    echo "PASS: bwrap is installed"
fi

# Test container mode detection (when DEVPOD=true)
echo "Testing container mode detection..."
export DEVPOD=true
if devaipod --help | grep -q "container mode"; then
    echo "PASS: Container mode detected with DEVPOD=true"
else
    echo "ERROR: Container mode not detected"
    exit 1
fi

echo ""
echo "All tests passed!"
