#!/usr/bin/env bash
# utils/checks.sh — sourced by install-prod.sh
# Equivalent of checks.ps1

# ---------------------------------------------------------------------------
# check_python_exists
#   Verifies that 'python' (or 'python3') is on PATH.
#   Exits 1 if not found, mirrors Check-PythonExists in checks.ps1.
# ---------------------------------------------------------------------------
check_python_exists() {
    if command -v python &>/dev/null; then
        PYTHON_PATH="$(command -v python)"
    elif command -v python3 &>/dev/null; then
        PYTHON_PATH="$(command -v python3)"
    else
        echo "WARNING: Python is not installed or not in PATH." \
             "Please install Python and ensure it's in your PATH environment variable." >&2
        exit 1
    fi
    export PYTHON_PATH
}

# ---------------------------------------------------------------------------
# test_pip_exists <python_path>
#   Returns 0 (true) if pip is available, 1 (false) otherwise.
#   Mirrors Test-PipExists in checks.ps1.
# ---------------------------------------------------------------------------
test_pip_exists() {
    local python_path="${1:?python_path is required}"

    if command -v pip &>/dev/null; then
        echo "Pip found: $(command -v pip)"
        return 0
    elif "$python_path" -m pip --version &>/dev/null; then
        echo "Pip found via: $python_path -m pip"
        return 0
    else
        echo "Pip not found. Please install pip to proceed." >&2
        return 1
    fi
}

# ---------------------------------------------------------------------------
# test_pip_dependency <python_path> <package_requirement>
#   Returns 0 if the package satisfies the requirement, 1 otherwise.
#   Mirrors Test-PipDependency in checks.ps1.
#
#   Note: pip show does not understand version specifiers (>=, ==, etc.),
#   so we use 'pip install --dry-run' which honours full PEP 508 specifiers.
# ---------------------------------------------------------------------------
test_pip_dependency() {
    local python_path="${1:?python_path is required}"
    local package_requirement="${2:?package_requirement is required}"

    echo "$python_path"   # mirrors: iex "echo $PythonPath"

    # Strip version specifier to get the bare package name for pip show
    local package_name
    package_name="$(echo "$package_requirement" | sed 's/[>=<!].*//')"

    "$python_path" -m pip show "$package_name" &>/dev/null
    return $?
}
