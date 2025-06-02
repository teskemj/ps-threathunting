# detect_AD_iocsv1.ps1

$ReportPath = "C:\LabFiles\Detection_Report_Full.csv"
$Results = @()
$Now = Get-Date
$Days = -15

Write-Host "`n[+] Starting IOC detection..."

# AD Recon via LDAP (4662)
Write-Host "[*] Detecting AD enumeration..."
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4662; StartTime=$Now.AddDays($Days)} |
Where-Object { $_.Message -match "Read Property" } |
ForEach-Object {
    $Results += [PSCustomObject]@{
        TimeCreated = $_.TimeCreated
        Detection   = "AD Enumeration (4662)"
        Details     = $_.Message -replace "`r|`n", ' '
    }
}

# PowerShell Remoting / ScriptBlock (4104)
Write-Host "[*] Detecting PowerShell Remoting / Invoke-Command..."
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational'; Id=4104; StartTime=$Now.AddDays($Days)} |
Where-Object { $_.Message -match "Invoke-Command|Enter-PSSession|New-PSSession" } |
ForEach-Object {
    $Results += [PSCustomObject]@{
        TimeCreated = $_.TimeCreated
        Detection   = "PowerShell Remoting / ScriptBlock (4104)"
        Details     = $_.Message -replace "`r|`n", ' '
    }
}

# WinRM Lateral Movement (4624)
Write-Host "[*] Detecting WinRM-based lateral movement..."
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624; StartTime=$Now.AddDays($Days)} |
Where-Object { $_.Message -match "Logon Type:\s+3" -and $_.Message -match "Impersonation Level:\s+(Impersonation|Delegation)" -and $_.Message -match "Source Network Address" } |
ForEach-Object {
    $Results += [PSCustomObject]@{
        TimeCreated = $_.TimeCreated
        Detection   = "Potential WinRM Lateral Movement (4624)"
        Details     = $_.Message -replace "`r|`n", ' '
    }
}

# Scheduled Task Creation (4698)
Write-Host "[*] Detecting suspicious scheduled task creation..."
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4698; StartTime=$Now.AddDays($Days)} |
ForEach-Object {
    $Results += [PSCustomObject]@{
        TimeCreated = $_.TimeCreated
        Detection   = "Suspicious Scheduled Task (4698)"
        Details     = $_.Message -replace "`r|`n", ' '
    }
}

# Registry Persistence via Run Key
Write-Host "[*] Detecting suspicious Run key persistence..."
Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run" -ErrorAction SilentlyContinue |
ForEach-Object {
    $_.PSObject.Properties | ForEach-Object {
        $Results += [PSCustomObject]@{
            TimeCreated = $Now
            Detection   = "Suspicious Registry Run Key Persistence"
            Details     = "$($_.Name) = $($_.Value)"
        }
    }
}

# Service Creation (7045)
Write-Host "[*] Detecting suspicious service creation..."
Get-WinEvent -FilterHashtable @{LogName='System'; Id=7045; StartTime=$Now.AddDays($days)} |
ForEach-Object {
    $Results += [PSCustomObject]@{
        TimeCreated = $_.TimeCreated
        Detection   = "Suspicious Service Creation (7045)"
        Details     = $_.Message -replace "`r|`n", ' '
    }
}

# Export the results
if ($Results.Count -gt 0) {
    $Results | Export-Csv -Path $ReportPath -NoTypeInformation -Force
    Write-Host "[+] Detection results saved to $ReportPath"
} else {
    Write-Host "[-] No suspicious events detected in the selected time range."
}
