<#
    Threat Detection Script – Paired with Teske's IOC Simulation
    Target: DC1.becausesecurity.pri
    Detects: AD Recon, Remoting, LOLBins, Persistence, Registry, GPO, Service Abuse
    Author: Teske Lab
#>

# Set up report path
$ReportPath = "C:\LabFiles\Detection_Report.csv"
$Results = @()
$Now = Get-Date

Write-Host "`n[+] Starting detection scan for lab IOCs..."

# --------------------------
# 1. Detect AD Recon (4662)
# --------------------------
Write-Host "[*] Checking for AD enumeration events..."
Get-WinEvent -LogName Security -MaxEvents 500 |
Where-Object { $_.Id -eq 4662 -and $_.Message -match "Read Property" } |
ForEach-Object {
    $Results += [PSCustomObject]@{
        TimeCreated = $_.TimeCreated
        Detection   = "AD Enumeration (4662)"
        Details     = $_.Message -replace "`r|`n", ' '
    }
}

# --------------------------
# 2. Detect PowerShell Remoting / Script Execution (4104)
# --------------------------
Write-Host "[*] Checking for PowerShell remoting/script blocks..."
Get-WinEvent -LogName "Microsoft-Windows-PowerShell/Operational" -MaxEvents 300 |
Where-Object { $_.Id -eq 4104 -and $_.Message -match "Invoke-Command|Enter-PSSession|New-PSSession" } |
ForEach-Object {
    $Results += [PSCustomObject]@{
        TimeCreated = $_.TimeCreated
        Detection   = "PowerShell Remoting/ScriptBlock (4104)"
        Details     = $_.Message -replace "`r|`n", ' '
    }
}

# --------------------------
# 3. Detect Scheduled Tasks (4698)
# --------------------------
Write-Host "[*] Checking for scheduled task creation..."
Get-WinEvent -LogName Security -MaxEvents 300 |
Where-Object { $_.Id -eq 4698 -or $_.Message -match "FakePersistenceTask" } |
ForEach-Object {
    $Results += [PSCustomObject]@{
        TimeCreated = $_.TimeCreated
        Detection   = "Scheduled Task Persistence (4698)"
        Details     = $_.Message -replace "`r|`n", ' '
    }
}

# --------------------------
# 4. Detect Registry Run Key Persistence
# --------------------------
Write-Host "[*] Checking registry for Run key backdoors..."
$RunPath = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run"
$RunKeys = Get-ItemProperty -Path $RunPath

foreach ($entry in $RunKeys.PSObject.Properties) {
    if ($entry.Value -match "cmd.exe|regstart") {
        $Results += [PSCustomObject]@{
            TimeCreated = $Now
            Detection   = "Registry Run Key Persistence"
            Details     = "$($entry.Name) = $($entry.Value)"
        }
    }
}

# --------------------------
# 5. Detect Service Creation (7045)
# --------------------------
Write-Host "[*] Checking for fake service creation..."
Get-WinEvent -LogName System -MaxEvents 200 |
Where-Object { $_.Id -eq 7045 -and $_.Message -match "FakeService|cmd.exe" } |
ForEach-Object {
    $Results += [PSCustomObject]@{
        TimeCreated = $_.TimeCreated
        Detection   = "Suspicious Service Creation (7045)"
        Details     = $_.Message -replace "`r|`n", ' '
    }
}

# --------------------------
# 6. Detect LOLBin Execution (4688)
# --------------------------
Write-Host "[*] Scanning for LOLBin executions..."
$lolbins = @("ntdsutil.exe", "esentutl.exe", "reg.exe", "sc.exe")
Get-WinEvent -LogName Security -FilterXPath "*[System/EventID=4688]" -MaxEvents 500 |
Where-Object {
    $_.Message -and ($lolbins | Where-Object { $_.ToLower() -in $_.Message.ToLower() })
} |
ForEach-Object {
    $Results += [PSCustomObject]@{
        TimeCreated = $_.TimeCreated
        Detection   = "LOLBin Execution (4688)"
        Details     = $_.Message -replace "`r|`n", ' '
    }
}

# --------------------------
# 7. Output Results
# --------------------------
if ($Results.Count -gt 0) {
    $Results | Format-Table -AutoSize
    $Results | Export-Csv -Path $ReportPath -NoTypeInformation
    Write-Host "`n[+] Detection complete. Report saved to: $ReportPath"
} else {
    Write-Host "`n[+] No matching threat activity detected."
}
