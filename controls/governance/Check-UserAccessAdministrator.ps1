function Check-UserAccessAdministrator {
    [CmdletBinding()]
    param()

    $controlResult = [PSCustomObject]@{
        Control = "Ensure that use of the 'User Access Administrator' role is monitored"
        ControlDescription = "The User Access Administrator role can grant access to any Azure resource and should be closely monitored and rarely used."
        Finding = ""
        Result = ""
        Evidence = ""
        RemediationSteps = ""
        AffectedAccounts = @()
    }

    try {
        $evidence = Format-EvidenceSection -Title "USER ACCESS ADMINISTRATOR ASSESSMENT" -Content "Assessment Date: $(Get-Date)" -IsHeader
        
        # Get User Access Administrator role
        $uaRole = Get-MgRoleManagementDirectoryRoleDefinition | Where-Object { 
            $_.DisplayName -eq "User Access Administrator"
        }
        
        if (-not $uaRole) {
            # This is an Azure RBAC role, not Entra ID role
            $evidence += "`nNote: User Access Administrator is an Azure RBAC role, not an Entra ID role"
            $evidence += "`nThis check requires Azure Resource Manager access"
            
            # Check for monitoring of high-privilege Entra roles instead
            $evidence += "`n`nChecking equivalent Entra ID roles:"
            
            # Global Administrator can do everything
            $globalAdminRole = Get-MgRoleManagementDirectoryRoleDefinition | Where-Object { 
                $_.DisplayName -eq "Global Administrator"
            }
            
            $globalAdmins = Get-MgRoleManagementDirectoryRoleAssignment -Filter "roleDefinitionId eq '$($globalAdminRole.Id)'"
            
            $evidence += "`nGlobal Administrators (equivalent privilege): $($globalAdmins.Count)"
            
            foreach ($admin in $globalAdmins) {
                try {
                    $user = Get-MgUser -UserId $admin.PrincipalId -ErrorAction SilentlyContinue
                    if ($user) {
                        $controlResult.AffectedAccounts += [PSCustomObject]@{
                            Name = $user.DisplayName
                            Id = $user.Id
                            Details = "Global Administrator - requires monitoring"
                        }
                    }
                } catch {}
            }
        }
        
        # Check for audit log monitoring
        $evidence += "`n`nAudit Log Monitoring:"
        
        # Check if diagnostic settings exist
        try {
            $diagnosticSettings = Get-MgAuditLogDirectoryAudit -Top 1
            if ($diagnosticSettings) {
                $evidence += "`nDirectory audit logs are accessible"
                $controlResult.Finding = "High-privilege roles exist and audit logs are available for monitoring"
                $controlResult.Result = "PARTIALLY COMPLIANT"
            }
        }
        catch {
            $evidence += "`nUnable to access audit logs"
            $controlResult.Finding = "High-privilege roles exist but monitoring cannot be verified"
            $controlResult.Result = "NOT COMPLIANT"
        }
        
        $controlResult.Evidence = $evidence
        
        if ($controlResult.Result -ne "COMPLIANT") {
            $controlResult.RemediationSteps = @"
<ol>
    <li>For Azure User Access Administrator role:
        <ul>
            <li>Monitor via Azure Activity Logs</li>
            <li>Create alerts for role assignments</li>
            <li>Review usage monthly</li>
        </ul>
    </li>
    <li>For Entra ID Global Administrator monitoring:
        <ul>
            <li>Enable audit log collection to Log Analytics</li>
            <li>Create alerts for privileged operations</li>
            <li>Monitor role activations and assignments</li>
        </ul>
    </li>
    <li>Implement alerting:
        <ul>
            <li>Alert on new role assignments</li>
            <li>Alert on privilege escalation</li>
            <li>Weekly reports of privileged actions</li>
        </ul>
    </li>
    <li>Consider removing permanent assignments and using PIM</li>
</ol>
"@
        }
    }
    catch {
        $controlResult.Finding = "Error assessing User Access Administrator monitoring: $_"
        $controlResult.Result = "ERROR"
        $controlResult.Evidence = "Error details: $_"
    }
    
    return $controlResult
}

# Execute the control check
Check-UserAccessAdministrator