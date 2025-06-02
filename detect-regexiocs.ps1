# Detect-RegexIOCs.ps1
# Detects files with IOCs using regex patterns

# Define target directory
$targetDir = "C:\LabFiles"

# Ensure target directory exists
if (-not (Test-Path $targetDir)) {
    Write-Warning "Target directory $targetDir does not exist. Exiting."
    exit
}

# Define regex patterns for IOCs
$ipPattern = "\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b"  # Matches IPs
$sqlPattern = "SELECT|UNION|INSERT|DELETE|DROP|UPDATE"  # Matches SQL injection keywords
$commandPattern = "powershell|cmd\.exe|rundll32|regsvr32|iex|downloadstring"  # Matches malicious commands

# Search for IOCs in files
Write-Host "Scanning files in $targetDir for IOCs..." -ForegroundColor DarkYellow
$files = Get-ChildItem -Path $targetDir -Filter "SuspiciousLog_*.txt" -Recurse

foreach ($file in $files) {
    Write-Host "`nAnalyzing file: $($file.FullName)" -ForegroundColor Cyan

    # Check for suspicious IPs
    $ipMatches = Select-String -Path $file.FullName -Pattern $ipPattern -AllMatches
    if ($ipMatches) {
        Write-host "Suspicious IPs found:" -ForegroundColor Red
        $ipMatches | ForEach-Object { Write-host " - $($_.Matches.Value)" -ForegroundColor Yellow }
    }

    # Check for SQL injection attempts
    $sqlMatches = Select-String -Path $file.FullName -Pattern $sqlPattern -AllMatches
    if ($sqlMatches) {
        Write-host "Potential SQL injection attempts found:" -ForegroundColor Red
        $sqlMatches | ForEach-Object { Write-Host " - $($_.Line)" -ForegroundColor Yellow }
    }

    # Check for malicious commands
    $commandMatches = Select-String -Path $file.FullName -Pattern $commandPattern -AllMatches
    if ($commandMatches) {
        Write-host "Malicious commands found:" -ForegroundColor Red
        $commandMatches | ForEach-Object { Write-Host " - $($_.Line)" -ForegroundColor Yellow }
    }

    if (-not $ipMatches -and -not $sqlMatches -and -not $commandMatches) {
        Write-Output "No IOCs detected in this file."
    }
}

# Summary
Write-Output "`nScan complete. Review the output for potential threats."