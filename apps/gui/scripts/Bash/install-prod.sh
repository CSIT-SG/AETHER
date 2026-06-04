#!/usr/bin/env bash
# install-prod.sh — Equivalent of install-prod.ps1
#
# Usage:
#   ./install-prod.sh [--ida-plugins-dir <path>] [--repo-root <path>] [--python-path <path>]
#
# Defaults:
#   --ida-plugins-dir   None
#   --repo-root         Three directories above this script's location
#   --python-path       first 'python' or 'python3' found on PATH

set -euo pipefail

# Resolve script directory and source utilities
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Mirrors: . .\utils\checks.ps1
# shellcheck source=utils/checks.sh
source "$SCRIPT_DIR/utils/checks.sh"

# Locate Python (sets $PYTHON_PATH)
check_python_exists   # exits 1 if not found
check_python_version 3 12 

# Default parameter values  (overridable via CLI flags)
IDA_PLUGINS_DIR=""
REPO_ROOT="${REPO_ROOT:-$(cd "$SCRIPT_DIR/../../../.." && pwd)}"
PYTHON_PATH="${PYTHON_PATH}"    # already exported by check_python_exists
PLUGIN_PACKAGE_DIR="$IDA_PLUGINS_DIR/aether-next"
REQUIREMENTS_FILE="$REPO_ROOT/apps/gui/scripts/utils/requirements.txt"
INSTALLER_SCRIPT="$REPO_ROOT/apps/gui/scripts/utils/installer.py"
LINKER="$REPO_ROOT/apps/gui/scripts/utils/linker.py"

# Argument parsing
while [[ $# -gt 0 ]]; do
    case "$1" in
        --plugins-dir) IDA_PLUGINS_DIR="$2"; shift 2 ;;
        *) echo "Unknown argument: $1" >&2; exit 1 ;;
    esac
done

# Validate required arguments
if [[ -z "$IDA_PLUGINS_DIR" ]]; then
    echo "ERROR: --plugins-dir is required." >&2
    echo "Usage: $0 --plugins-dir <path> [--repo-root <path>] [--python-path <path>]" >&2
    exit 1
fi

# pip check
if ! test_pip_exists "$PYTHON_PATH"; then
    exit 1
fi

# install pip dependencies
pip install --user --break-system-packages -r "$REQUIREMENTS_FILE"

echo "All Python dependencies are satisfied. Proceeding with installation..."

# Directory validation
if [[ ! -d "$IDA_PLUGINS_DIR" ]]; then
    echo "ERROR: IDA plugins directory not found: $IDA_PLUGINS_DIR" >&2
    exit 1
else
    echo "IDA plugins directory found: $IDA_PLUGINS_DIR"
fi

if [[ ! -d "$REPO_ROOT" ]]; then
    echo "ERROR: Repository root not found: $REPO_ROOT" >&2
    exit 1
else
    echo "Repository root found: $REPO_ROOT"
fi

# Remove and recreate plugin package directory
if [[ -d "$PLUGIN_PACKAGE_DIR" ]]; then
    echo "Existing plugin package directory found. Removing: $PLUGIN_PACKAGE_DIR"
    rm -rf "$PLUGIN_PACKAGE_DIR"
fi

echo -e "Plugin package directory deleted...\nCreating plugin package directory $PLUGIN_PACKAGE_DIR and copying source files..."
mkdir -p "$PLUGIN_PACKAGE_DIR"

# run installer.py to copy plugin source files into the package directory
$PYTHON_PATH $INSTALLER_SCRIPT $PLUGIN_PACKAGE_DIR $REPO_ROOT

if [ $? -eq 1 ]; then
    echo "Copy operation failed"
    exit 1
fi

$PYTHON_PATH $LINKER "$REPO_ROOT" "$IDA_PLUGINS_DIR"

echo "Installed AETHER GUI and RPC production artifacts in: $IDA_PLUGINS_DIR"
