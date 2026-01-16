#!/bin/bash
set -euo pipefail
# Wrapper script for devaipod configure-env
# This is called from devcontainer.json postStartCommand
# We need to preserve DEVPOD=true so devaipod knows it's in container mode

exec env DEVPOD=true devaipod configure-env
