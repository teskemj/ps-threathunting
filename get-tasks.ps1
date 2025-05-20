# Get-ScheduledTaskActions.ps1
# Displays the actions of scheduled tasks on the system

# Optional: Specify a task name to filter (leave empty to list all tasks)
$taskName = ""  # Example: "MalwarePersist"

# Ensure the ScheduledTasks module is available
Import-Module ScheduledTasks -ErrorAction SilentlyContinue
if (-not (Get-Module -Name ScheduledTasks)) {
    Write-Warning "ScheduledTasks module not available. Exiting."
    exit
}

# Get scheduled tasks
try {
    if ($taskName) {
        $tasks = Get-ScheduledTask -TaskName $taskName -ErrorAction Stop
    } else {
        $tasks = Get-ScheduledTask -ErrorAction Stop
    }
} catch {
    Write-Warning "Failed to retrieve scheduled tasks: $_"
    exit
}

# Display actions for each task
foreach ($task in $tasks) {
    Write-Output "`nTask Name: $($task.TaskName)"
    Write-Output "Task Path: $($task.TaskPath)"
    
    # Get the actions associated with the task
    $actions = $task.Actions
    if ($actions) {
        Write-Output "Actions:"
        foreach ($action in $actions) {
            # Check the type of action (most common is Execute)
            if ($action.ActionType -eq "Execute") {
                Write-Output " - Execute: $($action.Execute)"
                Write-Output "   Arguments: $($action.Arguments)"
                Write-Output "   Working Directory: $($action.WorkingDirectory)"
            } else {
                Write-Output " - Type: $($action.ActionType)"
                Write-Output "   Details: $($action | Format-List | Out-String)"
            }
        }
    } else {
        Write-Output "No actions found for this task."
    }
}

Write-Output "`nCompleted retrieval of scheduled task actions."