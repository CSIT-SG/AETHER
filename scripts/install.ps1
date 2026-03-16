param(
    [switch]$VERBOSE
)

# Global variables
$WINDOWS_IDA_PLUGIN_PATH = "$env:APPDATA\Hex-Rays\IDA Pro\plugins"
$IDA_PATHS = @(
    "C:\Program Files\IDA*",
    "C:\Program Files (x86)\IDA*"
)
$PACKAGE_DIR = "$PSScriptRoot\packages"
$IDA_PRO_MCP_WHEEL_NAME = "ida_pro_mcp-1.5.0a8-py3-none-any.whl"

# Resolve repository root
$REPO_ROOT = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$SOURCE_PLUGIN_DIR = Join-Path $REPO_ROOT "plugin"
$REQUIREMENTS_FILE = Join-Path $REPO_ROOT "requirements.txt"

Write-Host @"

    ▄████████    ▄████████     ███        ▄█    █▄       ▄████████    ▄████████ 
   ███    ███   ███    ███ ▀█████████▄   ███    ███     ███    ███   ███    ███ 
   ███    ███   ███    █▀     ▀███▀▀██   ███    ███     ███    █▀    ███    ███ 
   ███    ███  ▄███▄▄▄         ███   ▀  ▄███▄▄▄▄███▄▄  ▄███▄▄▄      ▄███▄▄▄▄██▀ 
 ▀███████████ ▀▀███▀▀▀         ███      ▀▀███▀▀▀▀███▀  ▀▀███▀▀▀     ▀▀███▀▀▀▀▀  
   ███    ███   ███    █▄      ███        ███    ███     ███    █▄  ▀███████████ 
   ███    ███   ███    ███     ███        ███    ███     ███    ███   ███    ███ 
   ███    █▀    ██████████   ▄████▀      ███    █▀      ██████████   ███    ███ 
                                                                     ███    ███  
                    IDA Pro MCP Plugin Installation Script

"@ -ForegroundColor Blue

Write-Host "Warning: This script will sync the 'plugin' folder to IDA 'plugins'."
Start-Sleep -Seconds 5

if ($VERBOSE) {
    Write-Host "Verbose mode enabled."
}

Write-Host "========================================"
Write-Host "Checking installed applications..."
Write-Host "========================================"

# --- RESTORED ORIGINAL DETAILED PYTHON CHECK ---
$python = (Get-Command python -ErrorAction SilentlyContinue).Source
if (-not $python) {
    Write-Host "Python cannot be located."
    Write-Host "Please install Python 3.11 or higher."
    exit
}

$pythonVersion = & $python -V 2>&1
if($pythonVersion -is [System.Management.Automation.ErrorRecord])
{
    $pythonVersion.Exception.Message
    exit
}
else 
{
    if ($pythonVersion -match "(\d+)\.(\d+)\.(\d+)") {
        $major = [int]$matches[1]
        $minor = [int]$matches[2]

        # Check if version is 3.11 or higher
        if ($major -gt 3 -or ($major -eq 3 -and $minor -ge 11)) {
            Write-Host "Located $pythonVersion"
        } else {
            Write-Host "Python 3.11 or higher is required (current: $($pythonVersion))"
            exit
        }
    } else {
        Write-Host "Invalid Python version format: $pythonVersion"
        exit
    }
}

# --- IDA CHECK ---
$idaExe = Get-ChildItem -Path $IDA_PATHS -Filter "ida.exe" -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1

if ($idaExe) {
    $idaVersion = $idaExe.VersionInfo.FileVersion
    Write-Host "Located IDA $idaVersion ('$($idaExe.DirectoryName)')"
} else {
    Write-Host "IDA is not installed on this system."
    Write-Host "Please install IDA Pro 9.0 or higher."
    exit
}

Write-Host "`n"
Write-Host "========================================"
Write-Host "Installing dependencies..."
Write-Host "========================================"

if (-not (Test-Path $REQUIREMENTS_FILE)) {
    Write-Host "Cannot find requirements file at $REQUIREMENTS_FILE" -ForegroundColor Red
    Write-Host "Please ensure you run this installer from the repository or that requirements.txt exists." -ForegroundColor Yellow
    exit 1
}

if ($VERBOSE) {
    & $python -m pip install -r $REQUIREMENTS_FILE
} else {
    & $python -m pip install -r $REQUIREMENTS_FILE -q
}

# --- RESTORED ORIGINAL DETAILED MCP WHEEL INSTALL ---
$pluginPackage = & $python -m pip show "ida-pro-mcp" 2>$null
if ($pluginPackage) {
    Write-Host "MCP Plugin is already installed." -ForegroundColor Green
} else {
    Write-Host "MCP Plugin is not installed." -ForegroundColor Red
    
    $mcpLocalPath = Join-Path $PACKAGE_DIR $IDA_PRO_MCP_WHEEL_NAME
    if (Test-Path $mcpLocalPath) {
        Write-Host "Installing ida-pro-mcp from local path '$mcpLocalPath'..." -ForegroundColor Green
        & $python -m pip install $mcpLocalPath
    } else {
        Write-Host "ida-pro-mcp local path '$mcpLocalPath' not found. Please ensure the ida-pro-mcp directory is present." -ForegroundColor Red
        exit
    }
}

Write-Host "`n"
Write-Host "========================================"
Write-Host "Syncing Plugin folder..."
Write-Host "========================================"

# 1. Ensure target directory exists
if (-not (Test-Path $WINDOWS_IDA_PLUGIN_PATH)) {
    New-Item -ItemType Directory -Path $WINDOWS_IDA_PLUGIN_PATH | Out-Null
}

# 2. Clean target directory except for mcp-plugin.py
Write-Host "Cleaning target plugins directory (preserving mcp-plugin.py)..." -ForegroundColor Gray
Get-ChildItem -Path $WINDOWS_IDA_PLUGIN_PATH | Where-Object {
    $_.Name -ne "mcp-plugin.py"
} | Remove-Item -Recurse -Force

# 3. Copy from 'plugin' to 'plugins'
if (Test-Path $SOURCE_PLUGIN_DIR) {
    Write-Host "Copying items from $SOURCE_PLUGIN_DIR to $WINDOWS_IDA_PLUGIN_PATH..." -ForegroundColor Green
    Copy-Item -Path "$SOURCE_PLUGIN_DIR\*" -Destination $WINDOWS_IDA_PLUGIN_PATH -Recurse -Force
} else {
    Write-Host "CRITICAL: Source folder '$SOURCE_PLUGIN_DIR' not found!" -ForegroundColor Red
    exit 1
}

Write-Host "`n"
Write-Host "========================================"
Write-Host "Finalizing installation..."
Write-Host "========================================"

# Install ida_pro_mcp
ida-pro-mcp --install

Write-Host "`n"
Write-Host "Installation Complete!" -ForegroundColor Cyan
Write-Host "If you encounter any issues starting MCP, please follow the manual installation instructions in the README.md file."