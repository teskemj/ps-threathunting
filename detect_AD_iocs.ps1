
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
        Detection   = "PowerShell Remoting (4104)"
        Details     = $_.Message -replace "`r|`n", ' '
    }
}

# WinRM Lateral Movement (4624)
Write-Host "[*] Detecting potential WinRM-based lateral movement..."
Get-WinEvent -LogName Security -MaxEvents 1000 |
Where-Object {
    $_.Id -eq 4624 -and
    $_.Message -match "Logon Type:		3" -and
    $_.Message -match "Elevated Token:		Yes"
} |
ForEach-Object {
    $Results += [PSCustomObject]@{
        TimeCreated = $_.TimeCreated
        Detection   = "Potential WinRM Lateral Movement (4624)"
        Details     = $_.Message -replace "`r|`n", ' '
    }
}

# Scheduled Task Creation (4698)
Write-Host "[*] Detecting suspicious scheduled tasks..."
Get-WinEvent -LogName Security -MaxEvents 500 |
Where-Object { $_.Id -eq 4698 } |
ForEach-Object {
    $Results += [PSCustomObject]@{
        TimeCreated = $_.TimeCreated
        Detection   = "Suspicious Scheduled Task (4698)"
        Details     = $_.Message -replace "`r|`n", ' '
    }
}

# Registry Run Key Persistence
Write-Host "[*] Detecting suspicious Run keys in registry..."
$runKeys = Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run" -ErrorAction SilentlyContinue
if ($runKeys) {
    $runKeys.PSObject.Properties | ForEach-Object {
        $Results += [PSCustomObject]@{
            TimeCreated = $Now
            Detection   = "Suspicious Registry Run Key Persistence"
            Details     = "$($_.Name) = $($_.Value)"
        }
    }
}

# Service Creation (7045)
Write-Host "[*] Detecting service installations..."
Get-WinEvent -LogName System -MaxEvents 500 |
Where-Object { $_.Id -eq 7045 } |
ForEach-Object {
    $Results += [PSCustomObject]@{
        TimeCreated = $_.TimeCreated
        Detection   = "Suspicious Service Creation (7045)"
        Details     = $_.Message -replace "`r|`n", ' '
    }
}

# LOLBins Detection (4688)
Write-Host "[*] Detecting LOLBins used by threat actors..."
$lolbins = "powershell.exe","cmd.exe","rundll32.exe","regsvr32.exe","mshta.exe","wscript.exe","cscript.exe","wmic.exe","forfiles.exe","certutil.exe","bitsadmin.exe","ntdsutil.exe","esentutl.exe"
Get-WinEvent -LogName Security -MaxEvents 1000 |
Where-Object { $_.Id -eq 4688 -and $_.Message } |
ForEach-Object {
    $msg = $_.Message.ToLower()
    if ($lolbins | Where-Object { $msg -like "*$_*" }) {
        $Results += [PSCustomObject]@{
            TimeCreated = $_.TimeCreated
            Detection   = "LOLBin Execution (4688)"
            Details     = $_.Message -replace "`r|`n", ' '
        }
    }
}

# Output to CSV
Write-Host "[+] Writing results to $ReportPath"
$Results | Export-Csv -Path $ReportPath -NoTypeInformation -Encoding UTF8
Write-Host "[+] IOC detection completed.`n"
