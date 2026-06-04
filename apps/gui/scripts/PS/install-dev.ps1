param(
  [string]$IdaPluginsDir = (Join-Path $env:APPDATA "Hex-Rays\IDA Pro\plugins"),
  [string]$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..\..\..")),
  [string]$PythonPath = (Get-Command python).Path
)

.(Join-Path $PSScriptRoot "utils\checks.ps1")

$linker = Join-Path $RepoRoot "apps\gui\scripts\utils\linker.py"
$RequirementsFile = Join-Path $RepoRoot "apps\gui\scripts\utils\requirements.txt"
$guiSrcDir = Join-Path $RepoRoot "apps\gui\src"

$PythonPath = Test-PythonExists
Test-PipExists -PythonPath $PythonPath
Test-PythonVer -PythonPath $PythonPath

Invoke-Expression "$PythonPath -m pip install -r $RequirementsFile --user"

if (-not (Test-Path $guiSrcDir)) {
  throw "GUI source directory not found: $guiSrcDir"
}

if (-not (Test-Path $IdaPluginsDir)) {
  throw "IDA plugins directory not found: $IdaPluginsDir"
}

Invoke-Expression "$PythonPath '$linker' '$RepoRoot' '$IdaPluginsDir'"

Write-Host "Installed AETHER GUI and RPC plugin links in: $IdaPluginsDir" -ForegroundColor Green
