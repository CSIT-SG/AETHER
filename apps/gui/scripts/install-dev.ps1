param(
    [string]$IdaPluginsDir = (Join-Path $env:APPDATA "Hex-Rays\IDA Pro\plugins"),
    [string]$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..\.."))
)

$guiSrcDir = Join-Path $RepoRoot "apps\gui\src"
$pluginFileLink = Join-Path $IdaPluginsDir "aether-next-plugin.py"
$pluginFileTarget = Join-Path $guiSrcDir "plugin.py"

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

Write-Host "Installed AETHER GUI plugin links in: $IdaPluginsDir"
