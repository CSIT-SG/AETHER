param(
    [string]$IdaPluginsDir = (Join-Path $env:APPDATA "Hex-Rays\IDA Pro\plugins"),
    [string]$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..\..\.."))
)


.(Join-Path $PSScriptRoot "utils\checks.ps1")


$pluginFileDest = Join-Path $IdaPluginsDir "aether-next-plugin.py"
$pluginPackageDir = Join-Path $IdaPluginsDir "aether-next"
$ReuqirementsFile = Join-Path $RepoRoot "apps\gui\scripts\utils\requirements.txt"
$pluginShimSource = Join-Path $pluginPackageDir "apps\gui\src\plugin.py"
$configSource = Join-Path $pluginPackageDir "apps\gui\src\aether-next-config.json"


$PythonPath = Test-PythonExists
Test-PipExists -PythonPath $PythonPath
Test-PythonVer -PythonPath $PythonPath

Invoke-Expression "$PythonPath -m pip install -r $ReuqirementsFile --user"

Write-Host "All Python dependencies are satisfied. Proceeding with installation..."

if (-not (Test-Path $IdaPluginsDir)) {
    Write-Host "IDA plugins directory not found: $IdaPluginsDir"
    Write-Host "If Plugins folder is not in %APPDATA%\Roaming\Hex-Rays\IDA Pro. Run .\install-prod.ps1 -IdaPluginsDir Path\To\Plugins\Folder"
}else{
    Write-Host "IDA plugins directory found: $IdaPluginsDir"
}

if (-not (Test-Path $RepoRoot)) {
    throw "Repository root not found: $RepoRoot"
}else{
    Write-Host "Repository root found: $RepoRoot"
}

if (Test-Path $pluginPackageDir) {
    Write-Host "Existing plugin package directory found. Removing: $pluginPackageDir"
    Remove-Item -LiteralPath $pluginPackageDir -Force -Recurse
}

Write-Host "Plugin package directory deleted... `nCreating plugin package directory $PluginPackageDir and copying source files..."
New-Item -ItemType Directory -Path $PluginPackageDir | Out-Null


$installerPath = Join-Path $RepoRoot "apps\gui\scripts\utils\installer.py"
Invoke-Expression "$PythonPath '$installerPath' '$pluginPackageDir' '$RepoRoot'"


if ($LASTEXITCODE -eq 1) {
    Write-Host "Copy operation failed" -ForegroundColor Red
    exit $LASTEXITCODE
}


if (Test-Path $pluginFileDest) {
    Write-Host "Existing plugin shim found. Removing: $pluginFileDest"
    Remove-Item -LiteralPath $pluginFileDest -Force
}

Write-Host "Plugin shim removed `nCreating symbolic link for plugin shim: $pluginFileDest -> $pluginShimSource"

New-Item -ItemType SymbolicLink -Path $pluginFileDest -Target $pluginShimSource | Out-Null

# Create a symlink to the config file so users can edit it from the plugins dir
$configLinkDest = Join-Path $IdaPluginsDir "aether-next-config.json"
if (Test-Path $configLinkDest) {
    Write-Host "Existing config link found. Removing: $configLinkDest"
    Remove-Item -LiteralPath $configLinkDest -Force
}else{
    Write-Host "No existing config link found. Creating symbolic link for config: $configLinkDest -> $configSource"
}

New-Item -ItemType SymbolicLink -Path $configLinkDest -Target $configSource | Out-Null

Write-Host "Installed AETHER GUI production artifacts in: $IdaPluginsDir" -ForegroundColor Green
