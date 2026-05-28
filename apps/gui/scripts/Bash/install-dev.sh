#!/usr/bin/env bash
# install-dev.sh — Equivalent of install-dev.ps1
#
# Usage:
#   ./install-dev.sh [--ida-plugins-dir <path>] [--repo-root <path>]
#
# Defaults:
#   --ida-plugins-dir   $HOME/.idapro/plugins          (Linux XDG equivalent of %APPDATA%\Hex-Rays\IDA Pro\plugins)
#   --repo-root         Three directories above this script's location

set -euo pipefail

# Resolve script location and default paths
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

#import checks.sh
source "$SCRIPT_DIR/utils/checks.sh"

IDA_PLUGINS_DIR=""
REPO_ROOT="${REPO_ROOT:-$(cd "$SCRIPT_DIR/../../.." && pwd)}"

# Argument parsing
while [[ $# -gt 0 ]]; do
    case "$1" in
        --plugins-dir) IDA_PLUGINS_DIR="$2"; shift 2 ;;
        *) echo "Unknown argument: $1" >&2; exit 1 ;;
    esac
done

# Check for --plugins-dir

if [[ -z $IDA_PLUGINS_DIR ]]; then
    echo "Usage: install-dev.sh --plugins-dir /path/to/plugins/dir"
    exit 1
fi    

# Derived paths
GUI_SRC_DIR="$REPO_ROOT/gui/src"
PLUGIN_FILE_LINK="$IDA_PLUGINS_DIR/aether-next-plugin.py"
PLUGIN_FILE_TARGET="$GUI_SRC_DIR/plugin.py"
CONFIG_FILE_TARGET="$GUI_SRC_DIR/aether-next-config.json"
CONFIG_FILE_LINK="$IDA_PLUGINS_DIR/aether-next-config.json"
REQUIREMENTS_FILE="$REPO_ROOT/gui/scripts/utils/requirements.txt"


#Python envvironment checks
check_python_exists   # exits 1 if not found
check_python_version 3 12
if ! test_pip_exists "$PYTHON_PATH"; then
    exit 1
fi

# install pip dependencies
pip install --user --break-system-packages -r "$REQUIREMENTS_FILE"

echo "All Python dependencies are satisfied. Proceeding with installation..."

# Validation
if [[ ! -d "$GUI_SRC_DIR" ]]; then
    echo "ERROR: GUI source directory not found: $GUI_SRC_DIR" >&2
    exit 1
fi

if [[ ! -d "$IDA_PLUGINS_DIR" ]]; then
    echo "ERROR: IDA plugins directory not found: $IDA_PLUGINS_DIR" >&2
    exit 1
fi

# Plugin symlink — remove stale link then recreate
if [[ -L "$PLUGIN_FILE_LINK" || -f "$PLUGIN_FILE_LINK" ]]; then
    rm -f "$PLUGIN_FILE_LINK"
fi

ln -s "$PLUGIN_FILE_TARGET" "$PLUGIN_FILE_LINK"
echo "Symlink created: $PLUGIN_FILE_LINK -> $PLUGIN_FILE_TARGET"

# Config file — create if absent, then symlink
if [[ ! -f "$CONFIG_FILE_TARGET" ]]; then
    # Create an empty JSON file; the application populates defaults on first run.
    touch "$CONFIG_FILE_TARGET"
fi

if [[ -L "$CONFIG_FILE_LINK" || -f "$CONFIG_FILE_LINK" ]]; then
    rm -f "$CONFIG_FILE_LINK"
fi

ln -s "$CONFIG_FILE_TARGET" "$CONFIG_FILE_LINK"
echo "Symlink created: $CONFIG_FILE_LINK -> $CONFIG_FILE_TARGET"

echo "Installed AETHER GUI plugin links in: $IDA_PLUGINS_DIR"
