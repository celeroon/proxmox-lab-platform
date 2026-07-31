# Define audit policy settings in a hashtable
$AuditSettings = @{
    "Security System Extension"           = "Success"
    "System Integrity"                    = "Failure"
    "Security State Change"               = "Success"
    
    "Logon"                                = "Success,Failure"
    "Logoff"                               = "Success"
    "Account Lockout"                      = "Failure"
    "Special Logon"                        = "Success"
    "Other Logon/Logoff Events"            = "Success,Failure"
    "User / Device Claims"                 = "Success"
    "Group Membership"                     = "Success"

    "File System"                          = "Success,Failure"
    "Registry"                             = "Success,Failure"
    "Kernel Object"                        = "Failure"
    "Handle Manipulation"                  = "Success"
    "File Share"                           = "Success,Failure"
    "Other Object Access Events"           = "Success,Failure"
    "Detailed File Share"                  = "Success,Failure"
    "Removable Storage"                    = "Success,Failure"

    "Sensitive Privilege Use"              = "Success"

    "Process Creation"                     = "Success"
    "Process Termination"                  = "Success"
    "DPAPI Activity"                       = "Success,Failure"
    "Plug and Play Events"                 = "Success"

    "Audit Policy Change"                  = "Success"
    "Authentication Policy Change"         = "Success"
    "Authorization Policy Change"          = "Success"
    "Other Policy Change Events"           = "Success,Failure"

    "Security Group Management"            = "Success"
    "User Account Management"              = "Success,Failure"

    "Credential Validation"                = "Failure"
}

# Apply each audit policy setting
foreach ($Subcategory in $AuditSettings.Keys) {
    $AuditValue = $AuditSettings[$Subcategory]
    
    $SuccessFlag = if ($AuditValue -match "Success") { "/success:enable" } else { "/success:disable" }
    $FailureFlag = if ($AuditValue -match "Failure") { "/failure:enable" } else { "/failure:disable" }

    Write-Host "Configuring: $Subcategory -> $AuditValue" -ForegroundColor Yellow
    AuditPol /set /subcategory:"$Subcategory" $SuccessFlag $FailureFlag
}

Write-Host "Audit policies updated successfully!" -ForegroundColor Green
