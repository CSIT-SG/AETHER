[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
    [string]$Path
)

# 1. INTERNAL RULES CONFIGURATION
$GitignoreRules = @(Get-Content -Path "..\utils\ignore.txt")
$GitignoreRules = $GitignoreRules | Where-Object { -not [string]::IsNullOrWhiteSpace($_) -and -not $_.StartsWith("#") }

# 2. THE MATCHING ENGINE
function Test-IsMatch {
    param (
        [string]$TargetTemplate,
        [bool]$IsDirectory
    )
    
    $normalized = $TargetTemplate.Replace('\', '/')
    
    # Catch all files/folders starting with a dot
    if ($normalized -match "(^|/)\.") {
        if ($normalized -notmatch "\.gitignore$") { return $true }
    }

    foreach ($line in $GitignoreRules) {
        $rule = $line.Trim()
        if ($rule.StartsWith('#') -or [string]::IsNullOrWhiteSpace($rule)) { continue }

        $ruleIsDirectoryOnly = $rule.EndsWith('/')
        if ($ruleIsDirectoryOnly -and -not $IsDirectory) { continue }

        $regexPattern = [regex]::Escape($rule)
        $regexPattern = $regexPattern.Replace('\*', '.*').Replace('\?', '.')

        if ($ruleIsDirectoryOnly) {
            $regexPattern = "(^|/)$([regex]::Escape($rule.TrimEnd('/')))(/|$)"
        } else {
            $regexPattern = "(^|/)$regexPattern"
        }

        if ($normalized -match $regexPattern) {
            return $true
        }
    }
    return $false
}

# 3. EXECUTION LOGIC WITH DIRECTORY PRUNING
if (Test-Path $Path) {
    $item = Get-Item $Path
    
    # CASE A: Single File Evaluation
    if ($item -is [System.IO.FileInfo]) {
        $result = Test-IsMatch -TargetTemplate $item.FullName -IsDirectory $false
        $status = if ($result) { "IGNORED" } else { "ALLOWED" }
        $color  = if ($result) { "Yellow" } else { "Green" }
        Write-Host "[$status] -> $($item.FullName)" -ForegroundColor $color
    } 
    
    # CASE B: Folder Evaluation with Real-Time Pruning
    if ($item -is [System.IO.DirectoryInfo]) {
        Write-Host "[*] Auditing workspace folder: $($item.FullName)" -ForegroundColor Cyan
        Write-Host "[*] Optimization Active: Ignored folders will be bypassed completely.`n" -ForegroundColor Gray
        
        # A hash set to keep track of directories we have chosen to prune
        $prunedDirectories = [System.Collections.Generic.HashSet[string]]::new()

        Get-ChildItem -Path $item.FullName -Force | ForEach-Object {
            # Compute path relative to our root scanning directory
            $relativePath = $_.FullName.Substring($item.FullName.Length + 1)
            $isDir = $_.PSIsContainer

            # STEP 1: Check if this item lives inside a directory we already chose to skip
            foreach ($prunedPath in $prunedDirectories) {
                if ($relativePath.StartsWith("$prunedPath/") -or $relativePath -eq $prunedPath) {
                    # Simply return to skip processing this file/subdirectory entirely
                    return
                }
            }

            # STEP 2: Evaluate if this specific item hits our ignore filters
            $result = Test-IsMatch -TargetTemplate $relativePath -IsDirectory $isDir

            if ($result) {
                if ($isDir) {
                    # Mark this directory tree as banned!
                    $null = $prunedDirectories.Add($relativePath)
                    Write-Host "[PRUNED DIRECTORY] skipping entry and all contents -> $relativePath" -ForegroundColor Red
                } else {
                    Write-Host "[IGNORED FILE] -> $relativePath" -ForegroundColor Yellow
                }
            } else {
                $copyPath = (Join-Path $Path $relativePath)
                Write-Host "[ALLOWED] -> $copyPath Copying..." -ForegroundColor Green
                Copy-Item -Path $copyPath -Destination $pluginPackageDir -Recurse -Force
                Write-Host "[COPIED] -> $relativePath" -ForegroundColor Green
            }
        }
    }
} else {
    $result = Test-IsMatch -TargetTemplate $Path -IsDirectory $false
    $status = if ($result) { "IGNORED" } else { "ALLOWED" }
    Write-Host "[$status] (Literal Text Execution) -> $Path"
}