# Detect-adIOCs.ps1
# Detects AD Recon, lateral movement, scheduled task, registry runkey, service abuse

# Output paths
$ReportPath = "C:\Labfiles\ThreatHunterReport.csv"
$Results = @()

Write-Host "`n[+] Running threat detection..."

# Detect AD Enumeration via LDAP Queries
Write-Host "[*] Checking for excessive AD user/computer/group queries..."
$ADQueryEvents = Get-WinEvent -LogName Security -MaxEvents 500 |
    Where-Object {
        $_.Id -eq 4662 -and $_.Message -match "Read Property"
    }

foreach ($event in $ADQueryEvents) {
    $Results += [PSCustomObject]@{
        TimeCreated = $event.TimeCreated
        Detection   = "Possible AD Enumeration (4662)"
        Details     = $event.Message -replace "`r|`n", ' '
    }
}

# Detect Lateral Movement via Invoke-Command / WinRM
Write-Host "[*] Checking for suspicious remote WinRM activity..."
$RemoteSessions = Get-WinEvent -LogName Security -MaxEvents 300 |
    Where-Object {
        $_.Id -eq 4624 -and $_.Message -match "Logon Type:\s+3" -and $_.Message -match "Source Network Address"
    }

foreach ($event in $RemoteSessions) {
    $Results += [PSCustomObject]@{
        TimeCreated = $event.TimeCreated
        Detection   = "Potential WinRM Lateral Movement (4624)"
        Details     = $event.Message -replace "`r|`n", ' '
    }
}

# Detect Scheduled Task Creation
Write-Host "[*] Checking for suspicious scheduled tasks..."
$TaskEvents = Get-WinEvent -LogName Security -MaxEvents 200 |
    Where-Object { $_.Id -eq 4698 -or $_.Message -match "FakePersistenceTask" }

foreach ($event in $TaskEvents) {
    $Results += [PSCustomObject]@{
        TimeCreated = $event.TimeCreated
        Detection   = "Suspicious Scheduled Task (4698)"
        Details     = $event.Message -replace "`r|`n", ' '
    }
}

# Detect Registry Run Key Persistence
Write-Host "[*] Checking registry Run keys for suspicious entries..."
$RunKey = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run"
$RunValues = Get-ItemProperty -Path $RunKey

foreach ($name in $RunValues.PSObject.Properties.Name) {
    if ($RunValues.$name -match "cmd.exe|powershell|reg_persist") {
        $Results += [PSCustomObject]@{
            TimeCreated = Get-Date
            Detection   = "Suspicious Registry Run Key Persistence"
            Details     = "$name = $($RunValues.$name)"
        }
    }
}


# Detect Suspicious Service Creation
Write-Host "[*] Checking for suspicious service installs..."
$ServiceEvents = Get-WinEvent -LogName System -MaxEvents 200 |
    Where-Object { $_.Id -eq 7045 -and $_.Message -match "TestService|cmd.exe" }

foreach ($event in $ServiceEvents) {
    $Results += [PSCustomObject]@{
        TimeCreated = $event.TimeCreated
        Detection   = "Suspicious Service Creation (7045)"
        Details     = $event.Message -replace "`r|`n", ' '
    }
}


# Output Results
if ($Results.Count -gt 0) {
    $Results | Format-Table -AutoSize
    $Results | Export-Csv -Path $ReportPath -NoTypeInformation
    Write-Host "`n[+] Threat indicators saved to $ReportPath"
} else {
    Write-Host "`n[+] No threats or simulated IOCs detected."
}
