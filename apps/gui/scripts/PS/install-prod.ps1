param(
  [string]$IdaPluginsDir = (Join-Path $env:APPDATA "Hex-Rays\IDA Pro\plugins"),
  [string]$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..\..\.."))
)

.(Join-Path $PSScriptRoot "utils\checks.ps1")


$installerPath = Join-Path $RepoRoot "apps\gui\scripts\utils\installer.py"
$linker = Join-Path $RepoRoot "apps\gui\scripts\utils\linker.py"
$ReuqirementsFile = Join-Path $RepoRoot "apps\gui\scripts\utils\requirements.txt"
$pluginPackageDir = Join-Path $IdaPluginsDir "aether-next"

$PythonPath = Test-PythonExists
Test-PipExists -PythonPath $PythonPath
Test-PythonVer -PythonPath $PythonPath

Invoke-Expression "$PythonPath -m pip install -r $ReuqirementsFile --user"

Write-Host "All Python dependencies are satisfied. Proceeding with installation..."

if (-not (Test-Path $IdaPluginsDir)) {
  Write-Host "IDA plugins directory not found: $IdaPluginsDir"
  Write-Host "If Plugins folder is not in %APPDATA%\Roaming\Hex-Rays\IDA Pro. Run .\install-prod.ps1 -IdaPluginsDir Path\To\Plugins\Folder"
} else {
  Write-Host "IDA plugins directory found: $IdaPluginsDir"
}

if (-not (Test-Path $RepoRoot)) {
  throw "Repository root not found: $RepoRoot"
} else {
  Write-Host "Repository root found: $RepoRoot"
}

if (Test-Path $pluginPackageDir) {
  Write-Host "Existing plugin package directory found. Removing: $pluginPackageDir"
  Remove-Item -LiteralPath $pluginPackageDir -Force -Recurse
}

Write-Host "Plugin package directory deleted... `nCreating plugin package directory $PluginPackageDir and copying source files..."
New-Item -ItemType Directory -Path $PluginPackageDir | Out-Null

Invoke-Expression "$PythonPath '$installerPath' '$pluginPackageDir' '$RepoRoot'"

if ($LASTEXITCODE -eq 1) {
  Write-Host "Copy operation failed" -ForegroundColor Red
  exit $LASTEXITCODE
}

Invoke-Expression "$PythonPath '$linker' '$RepoRoot' '$IdaPluginsDir'"

Write-Host "Installed AETHER artifacts in: $IdaPluginsDir" -ForegroundColor Green
