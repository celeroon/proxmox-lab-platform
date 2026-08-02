$logs = Get-EventLog -List

foreach ($log in $logs) {
    $entries = $log.Entries.Count
    $logName = $log.LogDisplayName
    if ($entries -gt 0) {
        Write-Host "Clearing $entries entries from $logName..."
        Clear-EventLog -LogName $log.Log
        Write-Host "Cleared!"
    } else {
        Write-Host "$logName has no entries to clear."
    }
}

Write-Host "Log clearing process completed."