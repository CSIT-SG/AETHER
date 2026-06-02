param(
    [string]$IdaPluginsDir = (Join-Path $env:APPDATA "Hex-Rays\IDA Pro\plugins"),
    [string]$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..\..\..")),
    [string]$PythonPath = (Get-Command python).Path
)

.(Join-Path $PSScriptRoot "utils\checks.ps1")

$guiSrcDir = Join-Path $RepoRoot "apps\gui\src"
$guiPluginFileLink = Join-Path $IdaPluginsDir "aether-next-gui.py"
$guiPluginFileTarget = Join-Path $guiSrcDir "plugin.py"
$rpcPluginFileLink = Join-Path $IdaPluginsDir "aether-next-rpc.py"
$rpcPluginFileTarget = Join-Path $RepoRoot "packages\rpc\src\gui_plugin.py"
$configFileTarget = Join-Path $guiSrcDir "aether-next-config.json"
$configFileLink = Join-Path $IdaPluginsDir "aether-next-config.json"

Test-PipExists -PythonPath $PythonPath
Test-PythonExists
Test-PythonVer -PythonPath $PythonPath


Invoke-Expression "$PythonPath -m pip install -r (Join-Path $RepoRoot 'apps\gui\scripts\utils\requirements.txt') --user"

if (-not (Test-Path $guiSrcDir)) {
    throw "GUI source directory not found: $guiSrcDir"
}

if (-not (Test-Path $IdaPluginsDir)) {
    throw "IDA plugins directory not found: $IdaPluginsDir"
}

if (-not (Test-Path $rpcPluginFileTarget)) {
    throw "RPC plugin file not found: $rpcPluginFileTarget"
}

if (Test-Path $guiPluginFileLink) {
    Remove-Item -LiteralPath $guiPluginFileLink -Force
}

cmd /c mklink "$guiPluginFileLink" "$guiPluginFileTarget"

if (Test-Path $rpcPluginFileLink) {
    Remove-Item -LiteralPath $rpcPluginFileLink -Force
}

cmd /c mklink "$rpcPluginFileLink" "$rpcPluginFileTarget"

# Ensure a config file exists in the GUI source and create a symlink in the IDA plugins dir
if (-not (Test-Path $configFileTarget)) {
    # Create an empty JSON file so users have something to edit; the application
    # will populate default values on first run if required.
    New-Item -ItemType File -Path $configFileTarget -Force | Out-Null
}

if (Test-Path $configFileLink) {
    Remove-Item -LiteralPath $configFileLink -Force
}

cmd /c mklink "$configFileLink" "$configFileTarget"

Write-Host "Installed AETHER GUI and RPC plugin links in: $IdaPluginsDir" -ForegroundColor Green
