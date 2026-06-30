#!/bin/bash

# Default variable value
VERBOSE_MODE=false

while [ $# -gt 0 ]; do
  case "$1" in
    -v|--verbose)
      VERBOSE_MODE=true
      ;;
    *)
      echo "Unknown option: $1" >&2
      echo "Usage: $0 [-v|--verbose]"
      exit 1
      ;;
  esac
  shift
done

# --- Path Logic (New format: relative to script location) ---
# SCRIPT_DIR is root/scripts
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# REPO_ROOT is root
REPO_ROOT="$(dirname "$SCRIPT_DIR")"

# Global variables
LINUX_IDA_PLUGIN_PATH="$HOME/.idapro/plugins"
SOURCE_PLUGIN_DIR="$REPO_ROOT/plugin"
REQUIREMENTS_FILE="$REPO_ROOT/requirements.txt"
PACKAGE_DIR="$SCRIPT_DIR/packages"
IDA_PRO_MCP_WHEEL_NAME="ida_pro_mcp-1.5.0a8-py3-none-any.whl"
MCP_LOCAL_PATH="$PACKAGE_DIR/$IDA_PRO_MCP_WHEEL_NAME"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

echo -e "${YELLOW}"
echo "    ▄████████    ▄████████     ███        ▄█    █▄       ▄████████    ▄████████ "
echo "   ███    ███   ███    ███ ▀█████████▄   ███    ███     ███    ███   ███    ███ "
echo "   ███    ███   ███    █▀     ▀███▀▀██   ███    ███     ███    █▀    ███    ███ "
echo "   ███    ███  ▄███▄▄▄         ███   ▀  ▄███▄▄▄▄███▄▄  ▄███▄▄▄      ▄███▄▄▄▄██▀ "
echo " ▀███████████ ▀▀███▀▀▀         ███      ▀▀███▀▀▀▀███▀  ▀▀███▀▀▀     ▀▀███▀▀▀▀▀  "
echo "   ███    ███   ███    █▄      ███        ███    ███     ███    █▄  ▀███████████ "
echo "   ███    ███   ███    ███     ███        ███    ███     ███    ███   ███    ███ "
echo "   ███    █▀    ██████████   ▄████▀      ███    █▀      ██████████   ███    ███ "
echo "                                                                     ███    ███ "
echo "                    IDA Pro MCP Plugin Installation Script"
echo -e "${NC}"

echo "Warning: This script will sync the 'plugin' folder to IDA 'plugins'."
sleep 5

if [ "$VERBOSE_MODE" = true ]; then
    echo "Verbose mode enabled."
fi

echo "========================================"
echo "Checking installed applications..."
echo "========================================"

# Python version check logic
version_ge() {
    [ "$1" = "$2" ] && return 0
    local IFS=.
    local i ver1=($1) ver2=($2)
    for ((i=0; i<${#ver1[@]}; i++)); do
        if ((10#${ver1[i]} > 10#${ver2[i]})); then return 0; fi
        if ((10#${ver1[i]} < 10#${ver2[i]})); then return 1; fi
    done
    return 0
}

PYTHON_BIN=$(command -v python3 2>/dev/null)
if [ -z "$PYTHON_BIN" ]; then
    echo "Python cannot be located."
    echo "Please install Python 3.11 or higher."
    exit 1
fi

PY_VERSION=$($PYTHON_BIN -V 2>&1 | awk '{print $2}')
if version_ge "$PY_VERSION" "3.11.0"; then
    echo "Located Python $PY_VERSION"
else
    echo "Python 3.11 or higher is required (current: $PY_VERSION)"
    exit 1
fi

# IDA Check logic
IDA_PATHS=$(find /opt "$HOME" -maxdepth 4 -type f \( -iname "ida64" -o -iname "ida" \) 2>/dev/null)
if [ -z "$IDA_PATHS" ]; then
    IDA_PATHS=$(command -v ida64 2>/dev/null || command -v ida 2>/dev/null)
fi

if [ -z "$IDA_PATHS" ]; then
    echo "IDA is not installed on this system."
    exit 1
fi

# Check if IDA is running
if pgrep -x "ida" > /dev/null || pgrep -x "ida64" > /dev/null; then
    echo -e "${YELLOW}Warning: IDA Pro is currently running. Please close all IDA instances to avoid file access errors.${NC}"
    read -p "Close running IDA processes automatically? (y/n/skip) " -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        echo -e "${CYAN}Closing IDA processes...${NC}"
        pkill -9 -x "ida" 2>/dev/null
        pkill -9 -x "ida64" 2>/dev/null
        sleep 2
    elif [[ $REPLY == "skip" ]]; then
        echo -e "${YELLOW}Proceeding with caution. Installation may fail if files are locked.${NC}"
    else
        echo -e "${RED}Installation aborted by user.${NC}"
        exit 1
    fi
fi

# Get unique directories
IDA_DIRS=$(echo "$IDA_PATHS" | xargs -n1 dirname | sort -u)

while read -r dir; do
    echo "Located IDA installation at '$dir'"
done <<< "$IDA_DIRS"

if [ ! -f "$REQUIREMENTS_FILE" ]; then
    echo -e "${RED}Cannot find requirements file at $REQUIREMENTS_FILE${NC}"
    exit 1
fi

echo -e "\n========================================"
echo "Configuring Vector RAG Resources..."
echo "========================================"

# Resource paths
EMBEDDING_DIR="$REPO_ROOT/plugin/ainalyse/chatbot/multi_agent_runtime/services/memory/memory_resources"
MODEL_FILE="$EMBEDDING_DIR/qwen3-embedding-0.6b-q4_k_m.gguf"
TIKTOKEN_FILE="$EMBEDDING_DIR/qwen.tiktoken"
EMBEDDING_MODEL_URL="https://huggingface.co/enacimie/Qwen3-Embedding-0.6B-Q4_K_M-GGUF/resolve/main/qwen3-embedding-0.6b-q4_k_m.gguf"
TIKTOKEN_URL="https://huggingface.co/Qwen/Qwen-7B/resolve/e08ed081a0cc944afe2c2cbf26375d21fde97b93/qwen.tiktoken"

mkdir -p "$EMBEDDING_DIR"

if [ ! -f "$TIKTOKEN_FILE" ]; then
    echo -e "${CYAN}Downloading qwen.tiktoken...${NC}"
    curl -L "$TIKTOKEN_URL" -o "$TIKTOKEN_FILE"
else
    echo -e "${GREEN}qwen.tiktoken already exists.${NC}"
fi

if [ ! -f "$MODEL_FILE" ]; then
    echo -e "${CYAN}Downloading qwen3-embedding-0.6b-q4_k_m.gguf...${NC}"
    curl -L "$EMBEDDING_MODEL_URL" -o "$MODEL_FILE"
else
    echo -e "${GREEN}qwen3-embedding-0.6b-q4_k_m.gguf already exists.${NC}"
fi

echo -e "\n========================================"
echo "Installing Python dependencies..."
echo "========================================"

if [ "$VERBOSE_MODE" = true ]; then
    "$PYTHON_BIN" -m pip install -r "$REQUIREMENTS_FILE" --break-system-packages
else
    "$PYTHON_BIN" -m pip install -r "$REQUIREMENTS_FILE" -q --break-system-packages
fi

if [ $? -ne 0 ]; then
    echo -e "${RED}Dependency installation failed while processing $REQUIREMENTS_FILE${NC}"
    exit 1
fi

# Verify key runtime dependencies are installed for plugin startup.
REQUIRED_PACKAGES=(
    "mcp"
    "openai"
    "psutil"
    "tiktoken"
    "PyQt5"
    "yara-python"
    "pydantic"
    "python-dotenv"
    "scikit-learn"
)

for pkg in "${REQUIRED_PACKAGES[@]}"; do
    if ! "$PYTHON_BIN" -m pip show "$pkg" > /dev/null 2>&1; then
        echo -e "${RED}Required package '$pkg' is missing after installation.${NC}"
        exit 1
    fi
done

# MCP Wheel check
if ! "$PYTHON_BIN" -m pip show ida-pro-mcp > /dev/null 2>&1; then
    if [ -f "$MCP_LOCAL_PATH" ]; then
        echo -e "${GREEN}Installing ida-pro-mcp from local path...${NC}"
        "$PYTHON_BIN" -m pip install "$MCP_LOCAL_PATH" --break-system-packages
    else
        echo -e "${RED}ida-pro-mcp local wheel not found at $MCP_LOCAL_PATH${NC}"
        exit 1
    fi
else
    echo -e "${GREEN}MCP Plugin is already installed.${NC}"
fi

echo -e "\n========================================"
echo "Syncing Plugin folder..."
echo "========================================"

# 1. Ensure target directory exists
mkdir -p "$LINUX_IDA_PLUGIN_PATH"

# 2. Clean target directory except for mcp-plugin.py
echo -e "Cleaning target plugins directory (preserving mcp-plugin.py)..."
find "$LINUX_IDA_PLUGIN_PATH" -mindepth 1 -maxdepth 1 ! -name 'mcp-plugin.py' -exec rm -rf {} +

# 3. Copy from 'plugin' (source) to 'plugins' (target)
if [ -d "$SOURCE_PLUGIN_DIR" ]; then
    echo -e "${GREEN}Copying items from $SOURCE_PLUGIN_DIR to $LINUX_IDA_PLUGIN_PATH...${NC}"
    cp -r "$SOURCE_PLUGIN_DIR"/* "$LINUX_IDA_PLUGIN_PATH/"
else
    echo -e "${RED}CRITICAL: Source folder '$SOURCE_PLUGIN_DIR' not found!${NC}"
    exit 1
fi

echo -e "\n========================================"
echo "Finalizing installation..."
echo "========================================"

# Register with IDA
ida-pro-mcp --install

echo -e "\n========================================"
echo "Patching user idapython.cfg to enable PyQt5 shim..."
echo "========================================"

USER_IDA_CFG_DIR="$HOME/.idapro/cfg"
IDAPYTHON_CFG="$USER_IDA_CFG_DIR/idapython.cfg"
mkdir -p "$USER_IDA_CFG_DIR"

if [ -f "$IDAPYTHON_CFG" ] && grep -Eq '^[[:space:]]*IDAPYTHON_USE_PYQT5_SHIM[[:space:]]*=[[:space:]]*1\b' "$IDAPYTHON_CFG"; then
    echo -e "${GREEN}User cfg already has IDAPYTHON_USE_PYQT5_SHIM = 1 at '$IDAPYTHON_CFG'.${NC}"
else
    if [ -f "$IDAPYTHON_CFG" ] && grep -Eq '^[[:space:]]*(//[[:space:]]*)?IDAPYTHON_USE_PYQT5_SHIM[[:space:]]*=' "$IDAPYTHON_CFG"; then
        sed -E -i \
            -e 's@^[[:space:]]*//[[:space:]]*IDAPYTHON_USE_PYQT5_SHIM[[:space:]]*=.*$@IDAPYTHON_USE_PYQT5_SHIM = 1@' \
            -e 's@^[[:space:]]*IDAPYTHON_USE_PYQT5_SHIM[[:space:]]*=.*$@IDAPYTHON_USE_PYQT5_SHIM = 1@' \
            "$IDAPYTHON_CFG"
        if [ $? -eq 0 ]; then
            echo -e "${GREEN}Set IDAPYTHON_USE_PYQT5_SHIM = 1 in '$IDAPYTHON_CFG'.${NC}"
        else
            echo -e "${RED}Error: Failed to update '$IDAPYTHON_CFG'.${NC}"
        fi
    else
        printf "IDAPYTHON_USE_PYQT5_SHIM = 1\n" >> "$IDAPYTHON_CFG"
        if [ $? -eq 0 ]; then
            echo -e "${GREEN}Added IDAPYTHON_USE_PYQT5_SHIM = 1 to '$IDAPYTHON_CFG'.${NC}"
        else
            echo -e "${RED}Error: Failed to add shim to '$IDAPYTHON_CFG'.${NC}"
        fi
    fi
fi

echo -e "\n${CYAN}Installation Complete!${NC}"
echo "If you encounter any issues starting MCP, please follow the manual instructions in the README.md file."
