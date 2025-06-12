# Create-EventLogIOCs.ps1
# Generates IOCs in event logs on a lab test domain controller for threat hunting practice


# Import Active Directory module
Import-Module ActiveDirectory -ErrorAction SilentlyContinue
if (-not (Get-Module -Name ActiveDirectory)) {
    Write-Warning "Active Directory module not available. Exiting."
    exit
}

# Define variables
$domain = (Get-ADDomain).DNSRoot
$dummyUser = "testuser"
$dummyPassword = "P@ssw0rd123"
$fakeC2IP = "10.0.0.1"  # Fake C2 IP (ensure this is not in use)
$tempGroup = "TempAdmins"

# Create dummy user if not exists
if (-not (Get-ADUser -Filter {SamAccountName -eq $dummyUser})) {
    New-ADUser -Name $dummyUser -AccountPassword (ConvertTo-SecureString $dummyPassword -AsPlainText -Force) -Enabled $true
    Write-Output "Created dummy user: $dummyUser"
}

# Simulate failed logins (generates event ID 4625 on domain controller)
for ($i = 0; $i -lt 5; $i++) {
    $de = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$domain", $dummyUser, "wrongpassword")
    try {
        $de.RefreshCache()  # This will fail due to wrong password
    } catch {
        Write-Output "Simulated failed login attempt $i"
    }
    Start-Sleep -Seconds 1
}

# Simulate privilege escalation
New-ADGroup -Name $tempGroup -GroupScope Global -Description "Temporary group for IOC simulation"
Add-ADGroupMember -Identity $tempGroup -Members $dummyUser
Write-Output "Added $dummyUser to $tempGroup"
Start-Sleep -Seconds 5
Remove-ADGroupMember -Identity $tempGroup -Members $dummyUser -Confirm:$false
Remove-ADGroup -Identity $tempGroup -Confirm:$false
Write-Output "Removed $dummyUser from $tempGroup and deleted the group"

# Launch suspicious process (generates process creation event)
$encodedCommand = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes("Write-Host 'Simulated malicious activity'"))
Start-Process powershell.exe -ArgumentList "-EncodedCommand $encodedCommand" -WindowStyle Hidden
Write-Output "Launched suspicious PowerShell process"

# Make outbound connection to fake C2 IP
try {
    Invoke-WebRequest -Uri "http://$fakeC2IP" -Method Get -ErrorAction SilentlyContinue
    Write-Output "Simulated outbound connection to $fakeC2IP"
} catch {
    Write-Output "Outbound connection attempt logged"
}

# Create dummy service (generates service creation event)
try {
    New-Service -Name "DummyService" -BinaryPathName "C:\Windows\System32\notepad.exe" -ErrorAction SilentlyContinue
    Write-Output "Created dummy service: DummyService"
} catch {
    Write-Warning "Failed to create service: $_"
}

# Modify registry (add and remove a key)
$regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
$regName = "DummyKey"
try {
    Set-ItemProperty -Path $regPath -Name $regName -Value "notepad.exe" -ErrorAction SilentlyContinue
    Write-Output "Added registry key: $regPath\$regName"
    Start-Sleep -Seconds 1
    Remove-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue
    Write-Output "Removed registry key: $regPath\$regName"
} catch {
    Write-Warning "Registry modification failed: $_"
}

# Attempt to access NTDS.dit (generates file access event)
try {
    Get-Content -Path "C:\Windows\NTDS\NTDS.dit" -ErrorAction SilentlyContinue
    Write-Output "Attempted access to NTDS.dit"
} catch {
    Write-Output "File access attempt logged"
}

# Write-Output "Removed dummy user: $dummyUser"
Write-Output "`nIOCs have been generated. Check the event logs for simulated malicious activity."