
# Threat Hunting with PowerShell - Merged Detection Script (Optimized with Brute Force Detection)

$Results = @()

# Set output path
$reportPath = "C:\labfiles\Threat_Hunting_Detections.csv"

# LOLBins Detection (4688)
Write-Host "[*] Detecting LOLBins used by threat actors..."
$lolbins = @("powershell.exe","cmd.exe","rundll32.exe","regsvr32.exe","mshta.exe","wscript.exe","cscript.exe","wmic.exe","forfiles.exe","certutil.exe","bitsadmin.exe","ntdsutil.exe","esentutl.exe")
$events = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4688} -MaxEvents 1000
foreach ($event in $events) {
    $msg = $event.Message.ToLower()
    if ($lolbins | Where-Object { $msg -like "*$_*" }) {
        $Results += [PSCustomObject]@{
            TimeCreated = $event.TimeCreated
            Detection   = "LOLBin Execution (4688)"
            Details     = $event.Message -replace "`r|`n", ' '
        }
    }
}

# Additional detection logic for brute force and other TTPs would follow here...

# Export results
$Results | Export-Csv -Path $reportPath -NoTypeInformation -Force
Write-Host "`n[+] Detection report written to: $reportPath"


# Brute Force Logon Detection (4625)
Write-Host "[*] Detecting brute force attempts (multiple 4625 failures)..."
$logonFailures = Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4625; StartTime=(Get-Date).AddDays(-1)} | Group-Object -Property {$_.Properties[5].Value} | Where-Object { $_.Count -gt 5 }
foreach ($failure in $logonFailures) {
    $Results += [PSCustomObject]@{
        TimeCreated = (Get-Date)
        Detection   = "Potential Brute Force (4625)"
        Details     = "Username: $($failure.Name) | Failed Attempts: $($failure.Count)"
    }
}

# DCSync Detection via Directory Service Replication (4662)
Write-Host "[*] Detecting DCSync replication activity (4662)..."
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4662; StartTime=(Get-Date).AddDays(-1)} | Where-Object {
    $_.Message -match "Replicating Directory Changes"
} | ForEach-Object {
    $Results += [PSCustomObject]@{
        TimeCreated = $_.TimeCreated
        Detection   = "Potential DCSync (4662)"
        Details     = $_.Message -replace "`r|`n", ' '
    }
}

# Registry Persistence Detection
Write-Host "[*] Detecting suspicious registry run key persistence..."
$regPaths = @(
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
)
foreach ($path in $regPaths) {
    if (Test-Path $path) {
        Get-ItemProperty -Path $path | ForEach-Object {
            $_.PSObject.Properties | ForEach-Object {
                $Results += [PSCustomObject]@{
                    TimeCreated = (Get-Date)
                    Detection   = "Suspicious Registry Run Key Persistence"
                    Details     = "$($_.Name) = $($_.Value)"
                }
            }
        }
    }
}
