# Teske Lab Threat IOC Detection Script (Unified & Formatted)
# Timestamp: 2025-06-02T16:12
$ReportPath = "C:\LabFiles\Detection_Report_Full.csv"
$Results = @()
$Now = Get-Date

Write-Host "`n[+] Starting IOC detection..."

# AD Recon via LDAP (4662)
Write-Host "[*] Detecting AD enumeration..."
Get-WinEvent -LogName Security -MaxEvents 500 |
Where-Object { $_.Id -eq 4662 -and $_.Message -match "Read Property" } |
ForEach-Object {
    $Results += [PSCustomObject]@{
        TimeCreated = $_.TimeCreated
        Detection   = "AD Enumeration (4662)"
        Details     = $_.Message -replace "`r|`n", ' '
    }
}

# PowerShell Remoting / ScriptBlock (4104)
Write-Host "[*] Detecting PowerShell Remoting / Invoke-Command..."
Get-WinEvent -LogName "Microsoft-Windows-PowerShell/Operational" -MaxEvents 300 |
Where-Object { $_.Id -eq 4104 -and $_.Message -match "Invoke-Command|Enter-PSSession|New-PSSession" } |
ForEach-Object {
    $Results += [PSCustomObject]@{
        TimeCreated = $_.TimeCreated
        Detection   = "PowerShell ScriptBlock (4104)"
        Details     = $_.Message -replace "`r|`n", ' '
    }
}

# Remote Logon Activity (4624 Type 3)
Write-Host "[*] Detecting remote logons (Type 3)..."
Get-WinEvent -LogName Security -MaxEvents 300 |
Where-Object {
    $_.Id -eq 4624 -and $_.Message -match "Logon Type:\s+3" -and $_.Message -match "Source Network Address"
} |
ForEach-Object {
    $Results += [PSCustomObject]@{
        TimeCreated = $_.TimeCreated
        Detection   = "Remote Logon (4624 Type 3)"
        Details     = $_.Message -replace "`r|`n", ' '
    }
}

# Scheduled Task Creation (4698)
Write-Host "[*] Detecting scheduled tasks..."
Get-WinEvent -LogName Security -MaxEvents 300 |
Where-Object { $_.Id -eq 4698 -or $_.Message -match "FakePersistenceTask" } |
ForEach-Object {
    $Results += [PSCustomObject]@{
        TimeCreated = $_.TimeCreated
        Detection   = "Scheduled Task Persistence (4698)"
        Details     = $_.Message -replace "`r|`n", ' '
    }
}

# Registry Run Key Persistence
Write-Host "[*] Checking for Run key persistence..."
$RunPath = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run"
try {
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
} catch {
    Write-Host "[!] Error reading registry Run key: $_"
}

# Service Creation via sc.exe (7045)
Write-Host "[*] Detecting suspicious services..."
Get-WinEvent -LogName System -MaxEvents 200 |
Where-Object { $_.Id -eq 7045 -and $_.Message -match "FakeService|cmd.exe" } |
ForEach-Object {
    $Results += [PSCustomObject]@{
        TimeCreated = $_.TimeCreated
        Detection   = "Suspicious Service Creation (7045)"
        Details     = $_.Message -replace "`r|`n", ' '
    }
}

# LOLBin Execution (4688)
Write-Host "[*] Scanning for LOLBin process creation..."
$lolbins = @("ntdsutil.exe", "esentutl.exe", "reg.exe", "sc.exe")
$lolbinEvents = Get-WinEvent -LogName Security -FilterXPath "*[System/EventID=4688]" -MaxEvents 500

foreach ($event in $lolbinEvents) {
    if ($event.Message) {
        $msg = $event.Message.ToLower()
        foreach ($bin in $lolbins) {
            if ($msg -like "*$bin*") {
                $Results += [PSCustomObject]@{
                    TimeCreated = $event.TimeCreated
                    Detection   = "LOLBin Execution (4688)"
                    Details     = $event.Message -replace "`r|`n", ' '
                }
                break
            }
        }
    }
}

# Output Results
if ($Results.Count -gt 0) {
    $Results | Format-Table -AutoSize
    $Results | Export-Csv -Path $ReportPath -NoTypeInformation -Encoding UTF8
    Write-Host "`n[+] Detection complete. Output written to: $ReportPath"
} else {
    Write-Host "`n[+] No matching indicators found in this run."
}
