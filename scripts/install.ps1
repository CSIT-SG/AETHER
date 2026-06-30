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

if (-not (Test-Path $REQUIREMENTS_FILE)) {
    Write-Host "Cannot find requirements file at $REQUIREMENTS_FILE" -ForegroundColor Red
    Write-Host "Please ensure you run this installer from the repository or that requirements.txt exists." -ForegroundColor Yellow
    exit 1
}

# 1. Download embedding model and tiktoken
$EMBEDDINGS_FILE = Join-Path $PSScriptRoot "embedding_requirements.ps1"
if (Test-Path $EMBEDDINGS_FILE) {
    Write-Host "`n"
    Write-Host "========================================"
    Write-Host "Configuring Vector RAG Resources..."
    Write-Host "========================================"
    & ($EMBEDDINGS_FILE)
}

# 2. Install Python dependencies
Write-Host "`n"
Write-Host "========================================"
Write-Host "Installing Python dependencies..."
Write-Host "========================================"

# Get Python Scripts directory
$pyScripts = python -c "import sysconfig, os; print(os.path.join(sysconfig.get_path('scripts')))"

if (($env:PATH -split ';') -notcontains $pyScripts) {
    # Update current session
    $env:PATH += ";$pyScripts"

    # Append to user PATH
    [System.Environment]::SetEnvironmentVariable(
        "PATH",
        ([System.Environment]::GetEnvironmentVariable("PATH", "User") + ";$pyScripts"),
        "User"
    )
}

if ($VERBOSE) {
    & $python -m pip install -r $REQUIREMENTS_FILE
} else {
    & $python -m pip install -r $REQUIREMENTS_FILE -q
}

if ($LASTEXITCODE -ne 0) {
    Write-Host "Dependency installation failed while processing $REQUIREMENTS_FILE" -ForegroundColor Red
    exit 1
}

# Verify key runtime dependencies are installed for plugin startup.
$requiredPackages = @(
    "mcp",
    "openai",
    "psutil",
    "tiktoken",
    "PyQt5",
    "yara-python",
    "pydantic",
    "python-dotenv",
    "scikit-learn"
)

foreach ($pkg in $requiredPackages) {
    $pkgInfo = & $python -m pip show $pkg 2>$null
    if (-not $pkgInfo) {
        Write-Host "Required package '$pkg' is missing after installation." -ForegroundColor Red
        exit 1
    }
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
Write-Host "Cleaning target plugins directory..." -ForegroundColor Gray
Get-ChildItem -Path "$WINDOWS_IDA_PLUGIN_PATH\ainalyse" -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force
Remove-Item -Force "$WINDOWS_IDA_PLUGIN_PATH\aether.py" -ErrorAction SilentlyContinue
if ((Test-Path "$WINDOWS_IDA_PLUGIN_PATH\plugin.py") -and (Select-String -Path "$WINDOWS_IDA_PLUGIN_PATH\plugin.py" -Pattern "aether" -Quiet)){
    Remove-Item -Force "$WINDOWS_IDA_PLUGIN_PATH\plugin.py" -ErrorAction SilentlyContinue
}

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

Write-Host "`n"
Write-Host "Installation Complete!" -ForegroundColor Cyan
Write-Host "If you encounter any issues starting MCP, please follow the manual installation instructions in the README.md file."
