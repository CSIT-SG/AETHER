param(
    [string]$IdaPluginsDir = (Join-Path $env:APPDATA "Hex-Rays\IDA Pro\plugins"),
    [string]$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..\.."))
)

.(Join-Path $PSScriptRoot "utils\checks.ps1")

$guiSrcDir = Join-Path $RepoRoot "apps\gui\src"
$pluginFileLink = Join-Path $IdaPluginsDir "aether-next-plugin.py"
$pluginFileTarget = Join-Path $guiSrcDir "plugin.py"
$configFileTarget = Join-Path $guiSrcDir "aether-next-config.json"
$configFileLink = Join-Path $IdaPluginsDir "aether-next-config.json"

Test-PipExists -PythonPath $PythonPath
Test-PythonExists -PythonPath $PythonPath
Test-PythonVer -PythonPath $PythonPath


Invoke-Expression "$PythonPath -m pip install -r '..\\utils\\requirements.txt' --user"

if (-not (Test-Path $guiSrcDir)) {
    throw "GUI source directory not found: $guiSrcDir"
}

if (-not (Test-Path $IdaPluginsDir)) {
    throw "IDA plugins directory not found: $IdaPluginsDir"
}

if (Test-Path $pluginFileLink) {
    Remove-Item -LiteralPath $pluginFileLink -Force
}

cmd /c mklink "$pluginFileLink" "$pluginFileTarget"

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

Write-Host "Installed AETHER GUI plugin links in: $IdaPluginsDir"
