# create-adiocs.ps1

<#
    Threat Simulation Script
    Target: DC1.becausesecurity.pri
    Goal: Simulate common AD threat actor behaviors for detection exercises
    Author: Teske Training Lab
#>

# --------------------------
# 1. Enumerate AD Environment
# --------------------------
Write-Host "`n[+] Simulating AD Recon..."
Get-ADUser -Filter * -Properties LastLogonDate | Select-Object Name, LastLogonDate | Out-Null
Get-ADComputer -Filter * | Out-Null
Get-ADGroupMember -Identity "Domain Admins" | Out-Null

# --------------------------
# 2. Simulate Lateral Movement via Invoke-Command
# --------------------------
Write-Host "[+] Simulating WinRM lateral movement..."
Invoke-Command -ComputerName DC1 -ScriptBlock {
    hostname
    whoami
    ipconfig /all
} | Out-Null

# --------------------------
# 3. Simulate Scheduled Task (Persistence)
# --------------------------
Write-Host "[+] Creating fake scheduled task (persistence)..."
$Action = New-ScheduledTaskAction -Execute "cmd.exe" -Argument "/c echo Lateral Test > C:\Windows\Temp\lateral_test.txt"
$Trigger = New-ScheduledTaskTrigger -AtStartup
$Principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
Register-ScheduledTask -TaskName "FakePersistenceTask" -Action $Action -Trigger $Trigger -Principal $Principal | Out-Null

# --------------------------
# 4. Registry Persistence via Run Key
# --------------------------
Write-Host "[+] Writing to Run registry key..."
Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "Updater" -Value "cmd.exe /c echo Registry Persistence >> C:\Windows\Temp\reg_persist.txt"

# --------------------------
# 5. Simulate GPO Enumeration
# --------------------------
Write-Host "[+] Enumerating GPOs..."
Get-GPO -All | Select DisplayName, GpoStatus | Out-Null
Get-GPResultantSetOfPolicy -ReportType Html -Path "$env:TEMP\GPOReport.html"

# --------------------------
# 6. Simulate Suspicious Service Creation (T1543.003)
# --------------------------
Write-Host "[+] Creating fake service to mimic abuse..."
sc.exe create TestService binPath= "cmd.exe /c echo Service executed >> C:\Windows\Temp\service_log.txt"
sc.exe start TestService

# --------------------------
# 7. Cleanup Option (optional)
# --------------------------
# Uncomment the following to remove artifacts
<#
Unregister-ScheduledTask -TaskName "FakePersistenceTask" -Confirm:$false
Remove-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "Updater"
sc.exe stop TestService
sc.exe delete TestService
Remove-Item "$env:TEMP\GPOReport.html"
Remove-Item "C:\Windows\Temp\lateral_test.txt","C:\Windows\Temp\reg_persist.txt","C:\Windows\Temp\service_log.txt"
#>


