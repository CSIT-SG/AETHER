param(
    [switch]$VERBOSE
)

# Global variables
$WINDOWS_IDA_PLUGIN_PATH = "$env:APPDATA\Hex-Rays\IDA Pro\plugins"
$IDA_PATHS = @(
    "C:\Program Files\IDA*",
    "C:\Program Files (x86)\IDA*"
)
$PSUTIL_WHEEL_NAME = @(
    "psutil-7.1.3-cp37-abi3-win_amd64.whl",
    "psutil-7.1.3-cp313-cp313t-win_amd64.whl",
    "psutil-7.1.3-cp314-cp314t-win_amd64.whl"
)
$IDA_PRO_MCP_WHEEL_NAME = "ida_pro_mcp-1.5.0a8-py3-none-any.whl"

# Resolve repository root
$REPO_ROOT = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$SOURCE_PLUGIN_DIR = Join-Path $REPO_ROOT "plugin"
$PACKAGE_DIR = Join-Path $PSScriptRoot "packages"
$REQUIREMENTS_FILE = Join-Path $REPO_ROOT "requirements.txt"

# Offline Version Dependencies
$requiredPsutilVersion = "7.1.2"
$requiredMCPVersion = "1.9.4"
$requiredOpenAIVersion = "1.75.0"

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
                            (Offline Version)

"@ -ForegroundColor Blue

Write-Host "Warning: This script will sync the 'plugin' folder to IDA 'plugins' (Offline)."
Start-Sleep -Seconds 5

# --- CHECK ENVIRONMENT ---
$python = (Get-Command python -ErrorAction SilentlyContinue).Source
if (-not $python) { Write-Host "Python not found."; exit 1 }

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
$idaExes = Get-ChildItem -Path $IDA_PATHS -Include "ida.exe", "ida64.exe" -Recurse -ErrorAction SilentlyContinue | Group-Object { $_.DirectoryName } | ForEach-Object { $_.Group[0] }

if ($idaExes) {
    # Check if IDA is running
    $idaProcesses = Get-Process -Name "ida", "ida64" -ErrorAction SilentlyContinue
    if ($idaProcesses) {
        Write-Host "Warning: IDA Pro is currently running. Please close all IDA instances before proceeding to avoid file access errors." -ForegroundColor Yellow
        $confirm = Read-Host "Close running IDA processes automatically? (y/n/skip)"
        if ($confirm -eq "y") {
            Write-Host "Closing IDA processes..." -ForegroundColor Cyan
            Stop-Process -Name "ida", "ida64" -Force -ErrorAction SilentlyContinue
            Start-Sleep -Seconds 2
        } elseif ($confirm -eq "skip") {
             Write-Host "Proceeding with caution. Installation may fail if files are locked." -ForegroundColor Yellow
        } else {
            Write-Host "Installation aborted by user." -ForegroundColor Red
            exit
        }
    }

    foreach ($ida in $idaExes) {
        $idaVersion = $ida.VersionInfo.FileVersion
        Write-Host "Located IDA $idaVersion ('$($ida.DirectoryName)')"
    }
} else {
    Write-Host "IDA is not installed on this system."
    Write-Host "Please install IDA Pro 9.0 or higher."
    exit
}

Write-Host "========================================"
Write-Host "Checking Offline Dependencies..."
Write-Host "========================================"

$global:quitScript = $false

function Compare-Versions {
    param ([string]$installedVersion, [string]$requiredVersion)
    $installed = $installedVersion.Split('.') | ForEach-Object { [int]$_ }
    $required = $requiredVersion.Split('.') | ForEach-Object { [int]$_ }
    for ($i = 0; $i -lt [Math]::Max($installed.Length, $required.Length); $i++) {
        $instPart = if ($i -lt $installed.Length) { $installed[$i] } else { 0 }
        $reqPart = if ($i -lt $required.Length) { $required[$i] } else { 0 }
        if ($instPart -gt $reqPart) { return $true }
        if ($instPart -lt $reqPart) { return $false }
    }
    return $true
}

function Test-PackageVersion {
    param ([string]$packageName, [string]$requiredVersion)
    $package = & $python -m pip show $packageName 2>$null
    if ($package) {
        $installed = ($package | Select-String "Version: (\S+)").Matches.Groups[1].Value
        if (Compare-Versions -installedVersion $installed -requiredVersion $requiredVersion) {
            Write-Host "$packageName $installed is installed." -ForegroundColor Green
        } else {
            Write-Host "$packageName version $installed is installed, but requires $requiredVersion." -ForegroundColor Red
            $global:quitScript = $true
        }
    } else {
        Write-Host "$packageName is not installed." -ForegroundColor Red
        $global:quitScript = $true
    }
}

# Run Offline Checks
Test-PackageVersion -packageName "mcp" -requiredVersion $requiredMCPVersion
Test-PackageVersion -packageName "openai" -requiredVersion $requiredOpenAIVersion

# --- SPECIAL PSUTIL OFFLINE INSTALL ---
if (-not (& $python -m pip show "psutil" 2>$null)) {
    Write-Host "Locating psutil wheel..." -ForegroundColor Yellow
    $selectedWheel = $null
    foreach ($wheel in $PSUTIL_WHEEL_NAME) {
        $candidate = Join-Path $PACKAGE_DIR "psutil-wheels\$wheel"
        if (Test-Path $candidate) {
            $selectedWheel = $candidate
            break
        }
    }
    if ($selectedWheel) {
        Write-Host "Installing local psutil wheel..." -ForegroundColor Green
        & $python -m pip install $selectedWheel --no-index --find-links=$PACKAGE_DIR
    } else {
        Write-Host "No local psutil wheel found." -ForegroundColor Red
        $global:quitScript = $true
    }
}

# --- SPECIAL MCP WHEEL INSTALL ---
if (-not (& $python -m pip show "ida-pro-mcp" 2>$null)) {
    $mcpLocalPath = Join-Path $PACKAGE_DIR $IDA_PRO_MCP_WHEEL_NAME
    if (Test-Path $mcpLocalPath) {
        Write-Host "Installing local MCP wheel..." -ForegroundColor Green
        & $python -m pip install $mcpLocalPath --no-index --find-links=$PACKAGE_DIR
    } else {
        Write-Host "Local MCP wheel not found." -ForegroundColor Red
        $global:quitScript = $true
    }
}

if ($global:quitScript) {
    Write-Host "Dependency check failed. Installation aborted." -ForegroundColor Red
    exit 1
}

Write-Host "`n========================================"
Write-Host "Syncing Plugin folder..."
Write-Host "========================================"

# 1. Ensure target exists
if (-not (Test-Path $WINDOWS_IDA_PLUGIN_PATH)) {
    New-Item -ItemType Directory -Path $WINDOWS_IDA_PLUGIN_PATH -Force | Out-Null
}

# 2. Clean target except for mcp-plugin.py
Write-Host "Cleaning target directory (preserving mcp-plugin.py)..." -ForegroundColor Gray
Get-ChildItem -Path $WINDOWS_IDA_PLUGIN_PATH | Where-Object {
    $_.Name -ne "mcp-plugin.py"
} | Remove-Item -Recurse -Force

# 3. Copy items from local 'plugin' to IDA 'plugins'
if (Test-Path $SOURCE_PLUGIN_DIR) {
    Write-Host "Copying plugins from $SOURCE_PLUGIN_DIR..." -ForegroundColor Green
    Copy-Item -Path "$SOURCE_PLUGIN_DIR\*" -Destination $WINDOWS_IDA_PLUGIN_PATH -Recurse -Force
} else {
    Write-Host "CRITICAL: Source folder '$SOURCE_PLUGIN_DIR' not found!" -ForegroundColor Red
    exit 1
}

Write-Host "`n========================================"
Write-Host "Finalizing installation..."
Write-Host "========================================"

# Register with IDA
ida-pro-mcp --install

# Enable PyQt5 shim in user IDA cfg to support plugin UI compatibility.
Write-Host "`n"
Write-Host "========================================"
Write-Host "Patching user idapython.cfg to enable PyQt5 shim..."
Write-Host "========================================"

function Write-Utf8NoBom {
    param(
        [string]$Path,
        [string]$Content
    )
    $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($Path, $Content, $utf8NoBom)
}

$userIdaCfgDir = Join-Path $env:APPDATA "Hex-Rays\IDA Pro\cfg"
$idapythonCfg = Join-Path $userIdaCfgDir "idapython.cfg"

if (-not (Test-Path $userIdaCfgDir)) {
    New-Item -ItemType Directory -Path $userIdaCfgDir -Force | Out-Null
}

try {
    $rawContent = ""
    if (Test-Path $idapythonCfg) {
        $rawContent = Get-Content -Path $idapythonCfg -Raw -ErrorAction SilentlyContinue
    }

    if ($rawContent -match '(?m)^\s*IDAPYTHON_USE_PYQT5_SHIM\s*=\s*1\b') {
        Write-Host "User cfg already has IDAPYTHON_USE_PYQT5_SHIM = 1 at '$idapythonCfg'." -ForegroundColor Green
    } else {
        $updatedContent = $rawContent
        $updatedContent = $updatedContent -replace '(?m)^\s*//\s*IDAPYTHON_USE_PYQT5_SHIM\s*=\s*.*$', 'IDAPYTHON_USE_PYQT5_SHIM = 1'
        $updatedContent = $updatedContent -replace '(?m)^\s*IDAPYTHON_USE_PYQT5_SHIM\s*=\s*.*$', 'IDAPYTHON_USE_PYQT5_SHIM = 1'

        if ($updatedContent -eq $rawContent) {
            if ([string]::IsNullOrWhiteSpace($updatedContent)) {
                $updatedContent = "IDAPYTHON_USE_PYQT5_SHIM = 1`r`n"
            } else {
                $updatedContent = $updatedContent.TrimEnd("`r", "`n") + "`r`nIDAPYTHON_USE_PYQT5_SHIM = 1`r`n"
            }
        }

        Write-Utf8NoBom -Path $idapythonCfg -Content $updatedContent
        Write-Host "Set IDAPYTHON_USE_PYQT5_SHIM = 1 in '$idapythonCfg'." -ForegroundColor Green
    }
} catch {
    Write-Host "Error updating '$idapythonCfg': $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host "`nInstallation Complete!" -ForegroundColor Cyan