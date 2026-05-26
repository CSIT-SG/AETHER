function Test-PythonExists{
    try{
    $PythonPath = (Get-Command python).Path 
    }catch{
        Write-Warning "Python is not installed or not in PATH. Please install Python and ensure it's in your PATH environment variable."
        exit 1
    }
}

function Test-PythonVer {
    param (
        [string]$PythonPath = "",
        [int]$RequiredMajor = 3,
        [int]$RequiredMinor = 12
    )
    $versionRaw = & $PythonPath -c "import sys; print(f'{sys.version_info.major} {sys.version_info.minor}')" 2>$null
        
    if ($LASTEXITCODE -eq 0 -and $versionRaw) {
        $major, $minor = $versionRaw.Split(" ") | ForEach-Object { [int]$_ }

        if ($major -eq $RequiredMajor -and $minor -ge $RequiredMinor) {
            Write-Host "Python version $major.$minor detected. Requirement satisfied." -ForegroundColor Green
        }else{
            Write-Error "CRITICAL: Python version $major.$minor unsupported. Python $RequiredMajor.$RequiredMinor or above is required. Please update your Python environment."
            exit 1
        }
    }
} 

function Test-PipExists{
    param(
        [string]$PythonPath
    )
    $pipCheck = Get-Command pip -ErrorAction SilentlyContinue
    if (-not $pipCheck) {
    # Method A: Try using ensurepip (safest for modern Python)
    Write-Host "Pip not found. Please install pip to proceed"
    exit 1
    }else{
        Write-Host "Pip found: $($pipCheck.Source)"
    }
}

function Test-PipDependency {
    param(
        [string]$PackageRequirement,
        [string]$PythonPath
    )
    iex "echo $PythonPath"
    $null = & $PythonPath -m pip show $PackageRequirement 2>&1

    if ($LASTEXITCODE -eq 0) {
        return $true
    } else {
        return $false
    }
}