# Detect-RegexIOCs.ps1
# Detects files with IOCs using regex patterns

# Define target directory
$targetDir = "C:\LabFiles"

# Define regex patterns for IOCs
$ipPattern = "\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b"  # Matches IPs
$sqlPattern = "SELECT|UNION|INSERT|DELETE|DROP|UPDATE"  # Matches SQL injection keywords
$commandPattern = "powershell|cmd\.exe|rundll32|regsvr32|iex|downloadstring"  # Matches malicious commands

# Search for IOCs in files
Write-Output "Scanning files in $targetDir for IOCs..."
$files = Get-ChildItem -Path $targetDir -Filter "SuspiciousLog_*.txt" -Recurse

foreach ($file in $files) {
    Write-Output "`nAnalyzing file: $($file.FullName)"

    # Check for suspicious IPs
    $ipMatches = Select-String -Path $file.FullName -Pattern $ipPattern -AllMatches
    if ($ipMatches) {
        Write-Output "Suspicious IPs found:"
        $ipMatches | ForEach-Object { Write-Output " - $($_.Matches.Value)" }
    }

    # Check for SQL injection attempts
    $sqlMatches = Select-String -Path $file.FullName -Pattern $sqlPattern -AllMatches
    if ($sqlMatches) {
        Write-Output "Potential SQL injection attempts found:"
        $sqlMatches | ForEach-Object { Write-Output " - $($_.Line)" }
    }

    # Check for malicious commands
    $commandMatches = Select-String -Path $file.FullName -Pattern $commandPattern -AllMatches
    if ($commandMatches) {
        Write-Output "Malicious commands found:"
        $commandMatches | ForEach-Object { Write-Output " - $($_.Line)" }
    }

    if (-not $ipMatches -and -not $sqlMatches -and -not $commandMatches) {
        Write-Output "No IOCs detected in this file."
    }
}

# Summary
Write-Output "`nScan complete. Review the output for potential threats."