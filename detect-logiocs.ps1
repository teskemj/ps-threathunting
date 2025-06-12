# Detect-SimpleIOCs.ps1
# Threat hunting tactic: Analyze event logs to find signs of malicious activity.

# Set time range to last 30 days
# Lesson: Limiting the time range reduces noise and focuses on recent activity.
$startTime = (Get-Date).AddDays(-30)

# Initialize results array to store detected IOCs
$results = @()

# IOC 1: Failed Logins (Event ID 4625)
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
if ($results.Count -eq 0) {
    Write-Output "No suspicious activity detected in the last 30 days."
} else {
    Write-Output "`nSuspicious Activity Detected:"
    Write-Output "-----------------------------"
    $results | Sort-Object TimeCreated | Format-Table -AutoSize -Property TimeCreated, Description, WhySuspicious
    Write-Output "Next Steps: Check the event logs manually to confirm these events and investigate further."
}

