# Module 1: Enterprise


# Step 1: List all running processes with details
Get-Process | Select-Object Name, Id, Path, StartTime | Sort-Object StartTime -Descending

# Step 2: Filter for processes with no file path (potential memory-resident malware)
Get-Process | Where-Object { $_.Path -eq $null } | Select-Object Name, Id

# Step 3: Check network connections for a specific process (e.g., notepad.exe)
$processId = (Get-Process -Name "ms-teams").Id
Get-NetTCPConnection | Where-Object { $_.OwningProcess -eq $processId } | Select-Object LocalAddress, RemoteAddress, State

# Step 1: Get recent failed login attempts from the Security log
Get-WinEvent -LogName "Security" -MaxEvents 100 | 
Where-Object { $_.Id -eq 4625 } | 
Select-Object TimeCreated, @{Name="Account";Expression={$_.Properties[5].Value}}, Message

# Step 2: Count failed logins by account to spot patterns
Get-WinEvent -LogName "Security" -MaxEvents 1000 | 
Where-Object { $_.Id -eq 4625 } | 
Group-Object { $_.Properties[5].Value } | 
Select-Object Name, Count | Sort-Object Count -Descending

<# Example output:
TimeCreated           Account  Message
-----------           -------  -------
2/25/2025 10:15:23 AM JDOE     An account failed to log on...
2/25/2025 10:15:20 AM JDOE     An account failed to log on...


Name  Count
----  -----
JDOE  10
ADMIN  2
#>

# Event ID 4625: Check for failed logins
Get-WinEvent -LogName "Security" -MaxEvents 200 | 
Where-Object { $_.Id -eq 4625 } | 
Select-Object TimeCreated, @{Name="Account";Expression={$_.Properties[5].Value}}, Message

# Event ID 4672: Look for new privilege assignments
Get-WinEvent -LogName "Security" -MaxEvents 200 | 
Where-Object { $_.Id -eq 4672 } | 
Select-Object TimeCreated, @{Name="Account";Expression={$_.Properties[1].Value}}, Message

# Event ID 4688: Monitor process creation
Get-WinEvent -LogName "Security" -MaxEvents 200 | 
Where-Object { $_.Id -eq 4688 } | 
Select-Object TimeCreated, @{Name="Process";Expression={$_.Properties[8].Value}}, Message


# Step 1: Query recent 4648 events with account details
Get-WinEvent -LogName "Security" -MaxEvents 200 | 
Where-Object { $_.Id -eq 4648 } | 
Select-Object TimeCreated, 
             @{Name="AccountUsed";Expression={$_.Properties[5].Value}}, 
             @{Name="TargetResource";Expression={$_.Properties[11].Value}}, 
             Message

# Step 2: Group by account to spot frequent usage
Get-WinEvent -LogName "Security" -MaxEvents 1000 | 
Where-Object { $_.Id -eq 4648 } | 
Group-Object { $_.Properties[5].Value } | 
Select-Object Name, Count | Sort-Object Count -Descending

# Module 2: Active Directory

#  Step 1: List all users with SPNs set (kerberoasting)
Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName | 
Select-Object Name,SamAccountName,ServicePrincipalName

# Step 2: Check for recently created Admin accounts
Get-ADUser -Filter {Enabled -eq $true -and PasswordLastSet -gt (Get-Date).AddDays(-30) -and MemberOf -like "*Administrators*"} |
Select-Object Name, SamAccountName, PasswordLastSet

# 
Get-ADUser -Filter {WhenCreated -gt (Get-Date).AddDays(-7)} -Properties Name, SamAccountName, WhenCreated, MemberOf |
Where-Object { $_.MemberOf -like "*Admin*" } |
Select-Object Name, SamAccountName, WhenCreated


$data = Get-Content -Path "normalfile.txt" 
$matches = select-string -InputObject $data -Pattern "password" -AllMatches
$matches.Matches.Count



