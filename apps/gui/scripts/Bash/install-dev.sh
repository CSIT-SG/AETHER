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
REPO_ROOT="${REPO_ROOT:-$(cd "$SCRIPT_DIR/../../../.." && pwd)}"

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
GUI_SRC_DIR="$REPO_ROOT/apps/gui/src"
REQUIREMENTS_FILE="$REPO_ROOT/apps/gui/scripts/utils/requirements.txt"
LINKER="$REPO_ROOT/apps/gui/scripts/utils/linker.py"


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

$PYTHON_PATH "$LINKER" "$GUI_SRC_DIR" "$IDA_PLUGINS_DIR"