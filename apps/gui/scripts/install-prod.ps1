param(
    [string]$IdaPluginsDir = (Join-Path $env:APPDATA "Hex-Rays\IDA Pro\plugins"),
    [string]$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..\.."))
)

$pluginFileDest = Join-Path $IdaPluginsDir "aether-next-plugin.py"
$pluginPackageDir = Join-Path $IdaPluginsDir "aether-next"

if (-not (Test-Path $IdaPluginsDir)) {
    throw "IDA plugins directory not found: $IdaPluginsDir"
}

if (-not (Test-Path $RepoRoot)) {
    throw "Repository root not found: $RepoRoot"
}

if (Test-Path $pluginPackageDir) {
    Remove-Item -LiteralPath $pluginPackageDir -Force -Recurse
}

New-Item -ItemType Directory -Path $pluginPackageDir | Out-Null
Copy-Item -Path (Join-Path $RepoRoot "*") -Destination $pluginPackageDir -Recurse -Force

$pluginShimSource = Join-Path $pluginPackageDir "apps\gui\src\plugin.py"
if (-not (Test-Path $pluginShimSource)) {
    throw "plugin.py not found: $pluginShimSource"
}

$configSource = Join-Path $pluginPackageDir "apps\gui\src\aether-next-config.json"
if (-not (Test-Path $configSource)) {
    # Create an empty config file in the package so installers expose something
    New-Item -ItemType File -Path $configSource -Force | Out-Null
}

if (Test-Path $pluginFileDest) {
    Remove-Item -LiteralPath $pluginFileDest -Force
}

New-Item -ItemType SymbolicLink -Path $pluginFileDest -Target $pluginShimSource | Out-Null

# Create a symlink to the config file so users can edit it from the plugins dir
$configLinkDest = Join-Path $IdaPluginsDir "aether-next-config.json"
if (Test-Path $configLinkDest) {
    Remove-Item -LiteralPath $configLinkDest -Force
}
New-Item -ItemType SymbolicLink -Path $configLinkDest -Target $configSource | Out-Null

Write-Host "Installed AETHER GUI production artifacts in: $IdaPluginsDir"
