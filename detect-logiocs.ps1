# Detect-SimpleIOCs.ps1
# A simple script to teach junior analysts threat hunting by detecting common IOCs in Windows event logs.
# Threat hunting tactic: Analyze event logs to find signs of malicious activity.

# Safety check: Ensure script runs in a lab environment
# Lesson: Always verify your environment to avoid running scripts in production!
$computerName = $env:COMPUTERNAME
if ($computerName -notlike "*DC*") {
    Write-Warning "This script should only run in a lab environment (computer name with 'LAB'). Exiting."
    exit
}

# Set time range to last 24 hours
# Lesson: Limiting the time range reduces noise and focuses on recent activity.
$startTime = (Get-Date).AddDays(-24)

# Initialize results array to store detected IOCs
$results = @()

# IOC 1: Failed Logins (Event ID 4625)
# We look in the Security log for event ID 4625.
try {
    $events = Get-WinEvent -FilterHashtable @{
        LogName = "Security"
        ID = 4625
        StartTime = $startTime
    } -ErrorAction SilentlyContinue
    foreach ($event in $events) {
        # Check for our test user or any user with multiple failures
        $user = $event.Properties[5].Value # TargetUserName
        $results += [PSCustomObject]@{
            TimeCreated = $event.TimeCreated
            Description = "Failed login attempt for user $user"
            WhySuspicious = "Multiple failed logins may indicate a brute-force attack."
        }
    }
} catch {
    Write-Warning "Error checking failed logins: $_"
}

# IOC 2: Suspicious PowerShell Process (Event ID 4688)
# We look in the Security log for event ID 4688 (process creation) with PowerShell.
try {
    $events = Get-WinEvent -FilterHashtable @{
        LogName = "Security"
        ID = 4688
        StartTime = $startTime
    } -ErrorAction SilentlyContinue | Where-Object { $_.Properties[5].Value -like "*powershell.exe" }
    foreach ($event in $events) {
        $command = $event.Properties[13].Value # CommandLine
        $results += [PSCustomObject]@{
            TimeCreated = $event.TimeCreated
            Description = "PowerShell process started with command: $command"
            WhySuspicious = "PowerShell with unusual commands may indicate malicious scripts."
        }
    }
} catch {
    Write-Warning "Error checking PowerShell processes: $_"
}

# IOC 3: New Service Creation (Event ID 7045)1
# Lesson: Attackers create services to persist on a system (MITRE ATT&CK: T1543).# We look in the System log for event ID 7045 (new service).
try {
    $events = Get-WinEvent -FilterHashtable @{
        LogName = "System"
        ID = 7045
        StartTime = $startTime
    } -ErrorAction SilentlyContinue
    foreach ($event in $events) {
        $serviceName = $event.Properties[0].Value # ServiceName
        $results += [PSCustomObject]@{
            TimeCreated = $event.TimeCreated
            Description = "New service created: $serviceName"
            WhySuspicious = "New services, especially with odd binaries, may indicate persistence."
        }
    }
} catch {
    Write-Warning "Error checking new services: $_"
}

# Display results
# Lesson: Review and interpret results to decide if further investigation is needed.
if ($results.Count -eq 0) {
    Write-Output "No suspicious activity detected in the last 30 days."
} else {
    Write-Output "`nSuspicious Activity Detected:"
    Write-Output "-----------------------------"
    $results | Sort-Object TimeCreated | Format-Table -AutoSize -Property TimeCreated, Description, WhySuspicious
    Write-Output "Next Steps: Check the event logs manually to confirm these events and investigate further."
}

