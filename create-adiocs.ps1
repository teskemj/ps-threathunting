# Create-ADIOCs.ps1
# Generates IOCs in for testing threat hunting techniques on a lab domain controller

# Set up test directory
$StagingPath = "C:\LabFiles\ThreatIOC"
New-Item -Path $StagingPath -ItemType Directory -Force | Out-Null
Write-Host "`n[+] Staging path created at $StagingPath"

# --------------------------
# Active Directory Enumeration
# --------------------------
Write-Host "[*] Simulating AD reconnaissance..."
Get-ADUser -Filter * -Properties LastLogonDate | Select-Object -First 5 | Out-Null
Get-ADGroupMember -Identity "Domain Admins" | Out-Null
Get-ADComputer -Filter * | Out-Null

# --------------------------
# PowerShell Remoting (Invoke-Command)
# --------------------------
Write-Host "[*] Simulating lateral movement with Invoke-Command..."
Invoke-Command -ComputerName localhost -ScriptBlock {
    whoami; hostname; ipconfig
} | Out-Null


# Scheduled Task (Persistence)
Write-Host "[*] Creating scheduled task for persistence simulation..."
$Action = New-ScheduledTaskAction -Execute "cmd.exe" -Argument "/c echo FakePersistence > C:\Windows\Temp\persistence.txt"
$Trigger = New-ScheduledTaskTrigger -AtStartup
$Principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
Register-ScheduledTask -TaskName "FakePersistenceTask" -Action $Action -Trigger $Trigger -Principal $Principal | Out-Null


# Registry Run Key Persistence
Write-Host "[*] Adding registry Run key..."
Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "UpdateService" -Value "cmd.exe /c echo RegistryStart >> C:\Windows\Temp\regstart.txt"


# Simulate GPO Enumeration
Write-Host "[*] Simulating GPO enumeration..."
Get-GPO -All | Select DisplayName, GpoStatus | Out-Null
Get-GPResultantSetOfPolicy -ReportType Html -Path "$env:TEMP\GPOReport.html"


# Service Creation via SC.EXE (Persistence/Privilege Abuse)
Write-Host "[*] Creating suspicious service..."
sc.exe create FakeService binPath= "cmd.exe /c echo ServiceExecuted >> C:\Windows\Temp\svc_io.txt" | Out-Null
sc.exe start FakeService | Out-Null


# LOLBin Execution for NTDS Capture Simulation
# ntdsutil->had to do this manually
Write-Host "[*] Simulating ntdsutil activity..."
$NTDSLog = "$StagingPath\ntdsutil-script.txt"
@"
activate instance ntds
ifm
create full $StagingPath
quit
quit
"@ | Set-Content -Path $NTDSLog

Start-Process -FilePath "ntdsutil.exe" -ArgumentList "script $NTDSLog" -NoNewWindow -Wait

# esentutl
Write-Host "[*] Running esentutl for offline db simulation..."
$FakeDB = "$StagingPath\offline.dit"
New-Item $FakeDB -ItemType File -Force | Out-Null
Start-Process -FilePath "esentutl.exe" -ArgumentList "/k $FakeDB" -NoNewWindow -Wait

# reg.exe
Write-Host "[*] Simulating SYSTEM hive extraction with reg.exe..."
reg.exe save HKLM\SYSTEM "$StagingPath\SYSTEM_HIVE_SAVE" /y | Out-Null

Write-Host "`n[+] IOC simulation complete."
Write-Host "[+] Artifacts written to: $StagingPath"
Write-Host "[+] You may now run detection scripts or collect logs (e.g., 4688, 4698, 7045, 4104)."
