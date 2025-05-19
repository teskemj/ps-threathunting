
# Basic checks for running PowerShell processes 
Get-Process -Name powershell, pwsh | Select-Object Id, ProcessName, Path, CommandLine

<# Red flag:
 # Check for PowerShell processes with suspicious command lines
 # Example of suspicious command line:
 # Commandline: powershell.exe -NoProfile -ExecutionPolicy Bypass -EncodedCommand <base64_string>
 # Example of encoded command:
 # EncodedCommand: JABzY3JpcHQgPSAiJHNjcmlwdCI7IAoJQGltcGxlbWVudCB0aXRsZSA9ICJNYWx3YXJlIFRlc3QiOw==
 # Decoded: $script = "$script"; @implement title = "Malware Test"; 
 #>

# Checking for Fileless Malware Indicators
# Quick Fileless Malware Detection Script 
Get-Process | Where-Object { $_.Path -eq $null -or -not (Test-Path $_.Path) } | Select-Object Id, ProcessName, ParentProcessId

# Check for suspicious PowerShell processes and tasks
Get-Process -Name powershell, pwsh | Select-Object Id, ProcessName, CommandLine 
Get-ScheduledTask | Where-Object { $_.State -eq "Ready" -or $_.State -eq "Running" } | Select-Object TaskName, TaskPath, Actions

# Check common Registry persistence keys
$regPaths = @(
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce"
)

foreach ($path in $regPaths) {
    Get-ItemProperty -Path $path -ErrorAction SilentlyContinue | Select-Object *
}