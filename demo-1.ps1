# Quick Fileless Malware Detection Script
Write-Host "Checking for Fileless Malware Indicators..."

# Suspicious Processes
Write-Host "`nSuspicious PowerShell Processes:"
Get-Process -Name powershell, pwsh | Select-Object Id, ProcessName, CommandLine

# In-Memory Processes
Write-Host "`nProcesses Without File Paths:"
Get-Process | Where-Object { $_.Path -eq $null -or -not (Test-Path $_.Path) } | Select-Object Id, ProcessName

# Registry Persistence
Write-Host "`nSuspicious Registry Run Keys:"
$regPaths = @("HKLM:\Software\Microsoft\Windows\CurrentVersion\Run", "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run")
foreach ($path in $regPaths) {
    Get-ItemProperty -Path $path -ErrorAction SilentlyContinue | Select-Object PSPath, *
}

# Scheduled Tasks
Write-Host "`nSuspicious Scheduled Tasks:"
Get-ScheduledTask | Where-Object { $_.Actions.Execute -match "powershell|wmic" } | Select-Object TaskName, Actions

# PowerShell Logs (last 10 suspicious scripts)
Write-Host "`nRecent PowerShell Script Blocks:"
Get-WinEvent -LogName "Microsoft-Windows-PowerShell/Operational" -MaxEvents 10 -ErrorAction SilentlyContinue | Where-Object { $_.Id -eq 4104 } | Select-Object TimeCreated, @{Name="ScriptBlock";Expression={$_.Properties[2].Value}}