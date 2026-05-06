param(
    [string]$IdaPluginsDir = (Join-Path $env:APPDATA "Hex-Rays\IDA Pro\plugins"),
    [string]$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..\.."))
)

$guiSrcDir = Join-Path $RepoRoot "apps\gui\src"
$packagesRoot = Join-Path $RepoRoot "packages"
$workspaceSrcDirs = @(
    $guiSrcDir
)
$pluginFileDest = Join-Path $IdaPluginsDir "aether-next-plugin.py"
$pluginPackageDir = Join-Path $IdaPluginsDir "aether-next"

if (-not (Test-Path $IdaPluginsDir)) {
    throw "IDA plugins directory not found: $IdaPluginsDir"
}

if (-not (Test-Path $guiSrcDir)) {
    throw "GUI source directory not found: $guiSrcDir"
}

if (-not (Test-Path $packagesRoot)) {
    throw "Packages directory not found: $packagesRoot"
}

$workspaceSrcDirs += Get-ChildItem -Path $packagesRoot -Directory |
    ForEach-Object { Join-Path $_.FullName "src" }

$missingSrcDirs = $workspaceSrcDirs | Where-Object { -not (Test-Path $_) }
if ($missingSrcDirs) {
    throw "Source directory not found: $($missingSrcDirs -join '; ')"
}

if (Test-Path $pluginPackageDir) {
    Remove-Item -LiteralPath $pluginPackageDir -Force -Recurse
}

New-Item -ItemType Directory -Path $pluginPackageDir | Out-Null
foreach ($srcDir in $workspaceSrcDirs) {
    Copy-Item -Path (Join-Path $srcDir "*") -Destination $pluginPackageDir -Recurse -Force
}

$bootstrap = @'
import sys
from pathlib import Path

def _add_paths() -> None:
    plugin_root = Path(__file__).resolve().parent / "aether-next"
    sys.path.insert(0, str(plugin_root))

_add_paths()

import plugin  # type: ignore

def PLUGIN_ENTRY():
    return plugin.PLUGIN_ENTRY()
'@

Set-Content -Path $pluginFileDest -Value $bootstrap

Write-Host "Installed AETHER GUI production artifacts in: $IdaPluginsDir"
