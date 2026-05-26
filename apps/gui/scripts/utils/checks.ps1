function Check-PythonExists{
    try{
    $PythonPath = (Get-Command python).Path 
    }catch{
        Write-Warning "Python is not installed or not in PATH. Please install Python and ensure it's in your PATH environment variable."
        exit 1
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
    }else{
        Write-Host "Pip found: $($pipCheck.Source)"
    }
    return $pipCheck
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