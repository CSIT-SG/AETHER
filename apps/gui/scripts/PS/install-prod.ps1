param(
    [string]$IdaPluginsDir = (Join-Path $env:APPDATA "Hex-Rays\IDA Pro\plugins"),
    [string]$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..\..\..")),
    [string]$PythonPath = (Get-Command python).Path
)

. .\PS_Utils\checks.ps1

$PythonDependencies =@(Get-Content -Path "..\utils\requirements.txt")
$PythonDependencies = $PythonDependencies | Where-Object { -not [string]::IsNullOrWhiteSpace($_) -and -not $_.StartsWith("#") }


$pluginFileDest = Join-Path $IdaPluginsDir "aether-next-plugin.py"
$pluginPackageDir = Join-Path $IdaPluginsDir "aether-next"
Test-PipExists -PythonPath $PythonPath
Test-PythonExists -PythonPath $PythonPath
Test-PythonVer -PythonPath $PythonPath


foreach ($dep in $PythonDependencies) {
    if(Test-PipDependency -PythonPath $PythonPath -PackageRequirement $dep){
        Write-Host "[+] Dependency met: $dep"
    }else {
        Write-Warning "[-] Dependency NOT met: $dep. Installing..."
        Invoke-Expression "$PythonPath -m pip install $dep"
    }
}

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
. .\PS_Utils\Check-Ignore -Path $RepoRoot

$pluginShimSource = Join-Path $pluginPackageDir "apps\gui\src\plugin.py"
if (-not (Test-Path $pluginShimSource)) {
    throw "plugin.py not found: $pluginShimSource"
}else{
    Write-Host "Plugin shim source found: $pluginShimSource"
}

$configSource = Join-Path $pluginPackageDir "apps\gui\src\aether-next-config.json"
if (-not (Test-Path $configSource)) {
    # Create an empty config file in the package so installers expose something
    Write-Host "Config file not found: $configSource. Creating an empty config file..."
    New-Item -ItemType File -Path $configSource -Force | Out-Null
}else{
    Write-Host "Config source found: $configSource"
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

Write-Host "Installed AETHER GUI production artifacts in: $IdaPluginsDir"
