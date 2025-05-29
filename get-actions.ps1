Get-ScheduledTask |
    Where-Object { $_.State -eq "Ready" -or $_.State -eq "Running" } |
    ForEach-Object {
        $task = $_
        if ($task.Actions) {
            foreach ($action in $task.Actions) {
                [PSCustomObject]@{
                    TaskName        = $task.TaskName
                    TaskPath        = $task.TaskPath
                    ActionType      = $action.ActionType
                    Execute         = $action.Execute
                    Arguments       = $action.Arguments
                    WorkingDirectory = $action.WorkingDirectory
                }
            }
        }
    } | Format-Table -AutoSize
