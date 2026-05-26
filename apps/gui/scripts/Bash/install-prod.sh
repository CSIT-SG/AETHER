#!/usr/bin/env bash
# install-prod.sh — Equivalent of install-prod.ps1
#
# Usage:
#   ./install-prod.sh [--ida-plugins-dir <path>] [--repo-root <path>] [--python-path <path>]
#
# Defaults:
#   --ida-plugins-dir   $IDADIR/plugins
#   --repo-root         Three directories above this script's location
#   --python-path       first 'python' or 'python3' found on PATH

set -euo pipefail

# ---------------------------------------------------------------------------
# Resolve script directory and source utilities
# ---------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Mirrors: . .\utils\checks.ps1
# shellcheck source=utils/checks.sh
source "$SCRIPT_DIR/Bash_Utils/checks.sh"

# shellcheck source=utils/check-ignore.sh
source "$SCRIPT_DIR/Bash_Utils/check-ignore.sh"

# ---------------------------------------------------------------------------
# Locate Python (sets $PYTHON_PATH)
# ---------------------------------------------------------------------------
check_python_exists   # exits 1 if not found
check_python_version 3 12 

# ---------------------------------------------------------------------------
# Default parameter values  (overridable via CLI flags)
# ---------------------------------------------------------------------------
IDA_PLUGINS_DIR=""
REPO_ROOT="${REPO_ROOT:-$(cd "$SCRIPT_DIR/../../../.." && pwd)}"
PYTHON_PATH="${PYTHON_PATH}"    # already exported by check_python_exists

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------
while [[ $# -gt 0 ]]; do
    case "$1" in
        --plugins-dir) IDA_PLUGINS_DIR="$2"; shift 2 ;;
        --repo-root)       REPO_ROOT="$2";        shift 2 ;;
        --python-path)     PYTHON_PATH="$2";       shift 2 ;;
        *) echo "Unknown argument: $1" >&2; exit 1 ;;
    esac
done

# ---------------------------------------------------------------------------
# Validate required arguments
# ---------------------------------------------------------------------------
if [[ -z "$IDA_PLUGINS_DIR" ]]; then
    echo "ERROR: --plugins-dir is required." >&2
    echo "Usage: $0 --plugins-dir <path> [--repo-root <path>] [--python-path <path>]" >&2
    exit 1
fi
 
# ---------------------------------------------------------------------------
# Read and filter requirements.txt  (mirrors $PythonDependencies logic)
# ---------------------------------------------------------------------------
REQUIREMENTS_FILE="$SCRIPT_DIR/../utils/requirements.txt"
mapfile -t PYTHON_DEPENDENCIES < <(
    grep -v '^\s*#' "$REQUIREMENTS_FILE" | grep -v '^\s*$'
)

# ---------------------------------------------------------------------------
# Derived paths
# ---------------------------------------------------------------------------
PLUGIN_FILE_DEST="$IDA_PLUGINS_DIR/aether-next-plugin.py"
PLUGIN_PACKAGE_DIR="$IDA_PLUGINS_DIR/aether-next"

# ---------------------------------------------------------------------------
# pip check
# ---------------------------------------------------------------------------
if ! test_pip_exists "$PYTHON_PATH"; then
    exit 1
fi

# ---------------------------------------------------------------------------
# Dependency satisfaction loop
# ---------------------------------------------------------------------------
for dep in "${PYTHON_DEPENDENCIES[@]}"; do
    if test_pip_dependency "$PYTHON_PATH" "$dep"; then
        echo "[+] Dependency met: $dep"
    else
        echo "WARNING: [-] Dependency NOT met: $dep. Installing..." >&2
        eval "pip install --break-system-packages $dep" 
    fi
done

echo "All Python dependencies are satisfied. Proceeding with installation..."

# ---------------------------------------------------------------------------
# Directory validation
# ---------------------------------------------------------------------------
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

# ---------------------------------------------------------------------------
# Remove and recreate plugin package directory
# ---------------------------------------------------------------------------
if [[ -d "$PLUGIN_PACKAGE_DIR" ]]; then
    echo "Existing plugin package directory found. Removing: $PLUGIN_PACKAGE_DIR"
    rm -rf "$PLUGIN_PACKAGE_DIR"
fi

echo -e "Plugin package directory deleted...\nCreating plugin package directory $PLUGIN_PACKAGE_DIR and copying source files..."
mkdir -p "$PLUGIN_PACKAGE_DIR"

# Mirrors: . .\utils\Check-Ignore -Path $RepoRoot
run_check_ignore "$REPO_ROOT" "$PLUGIN_PACKAGE_DIR"

# ---------------------------------------------------------------------------
# Validate plugin shim was copied
# ---------------------------------------------------------------------------
PLUGIN_SHIM_SOURCE="$PLUGIN_PACKAGE_DIR/apps/gui/src/plugin.py"
if [[ ! -f "$PLUGIN_SHIM_SOURCE" ]]; then
    echo "ERROR: plugin.py not found: $PLUGIN_SHIM_SOURCE" >&2
    exit 1
else
    echo "Plugin shim source found: $PLUGIN_SHIM_SOURCE"
fi

# ---------------------------------------------------------------------------
# Ensure config file exists in the package
# ---------------------------------------------------------------------------
CONFIG_SOURCE="$PLUGIN_PACKAGE_DIR/apps/gui/src/aether-next-config.json"
if [[ ! -f "$CONFIG_SOURCE" ]]; then
    echo "Config file not found: $CONFIG_SOURCE. Creating an empty config file..."
    mkdir -p "$(dirname "$CONFIG_SOURCE")"
    touch "$CONFIG_SOURCE"
else
    echo "Config source found: $CONFIG_SOURCE"
fi

# ---------------------------------------------------------------------------
# Plugin shim symlink
# ---------------------------------------------------------------------------
if [[ -L "$PLUGIN_FILE_DEST" || -f "$PLUGIN_FILE_DEST" ]]; then
    echo "Existing plugin shim found. Removing: $PLUGIN_FILE_DEST"
    rm -f "$PLUGIN_FILE_DEST"
fi

echo -e "Plugin shim removed\nCreating symbolic link for plugin shim: $PLUGIN_FILE_DEST -> $PLUGIN_SHIM_SOURCE"
ln -s "$PLUGIN_SHIM_SOURCE" "$PLUGIN_FILE_DEST"

# ---------------------------------------------------------------------------
# Config symlink
# ---------------------------------------------------------------------------
CONFIG_LINK_DEST="$IDA_PLUGINS_DIR/aether-next-config.json"
if [[ -L "$CONFIG_LINK_DEST" || -f "$CONFIG_LINK_DEST" ]]; then
    echo "Existing config link found. Removing: $CONFIG_LINK_DEST"
    rm -f "$CONFIG_LINK_DEST"
else
    echo "No existing config link found. Creating symbolic link for config: $CONFIG_LINK_DEST -> $CONFIG_SOURCE"
fi

ln -s "$CONFIG_SOURCE" "$CONFIG_LINK_DEST"

echo "Installed AETHER GUI production artifacts in: $IDA_PLUGINS_DIR"
