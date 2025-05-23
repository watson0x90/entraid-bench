function Check-GlobalAdminCount {
    [CmdletBinding()]
    param()

    $controlResult = [PSCustomObject]@{
        Control = "Ensure fewer than 5 users have global administrator assignment"
        ControlDescription = "Limit Global Administrator assignments to between 2-4 users for security (CIS 6.26)"
        Finding = ""
        Result = ""
        Evidence = ""
        RemediationSteps = ""
        AffectedAccounts = @()
    }

    try {
        # Get Global Administrator role
        $globalAdminRole = Get-MgRoleManagementDirectoryRoleDefinition | 
            Where-Object { $_.DisplayName -eq "Global Administrator" }
        
        # Get assignments
        $globalAdmins = Get-MgRoleManagementDirectoryRoleAssignment -Filter "roleDefinitionId eq '$($globalAdminRole.Id)'"
        
        $activeAdmins = @()
        foreach ($admin in $globalAdmins) {
            try {
                $user = Get-MgUser -UserId $admin.PrincipalId -ErrorAction SilentlyContinue
                if ($user) {
                    $activeAdmins += $user
                    $controlResult.AffectedAccounts += [PSCustomObject]@{
                        Name = $user.DisplayName
                        Id = $user.Id
                        Details = "Global Administrator"
                    }
                }
            } catch {}
        }
        
        $evidence = "Global Administrator Count: $($activeAdmins.Count)`n"
        $evidence += "Recommended: 2-4 Global Administrators`n"
        
        if ($activeAdmins.Count -ge 2 -and $activeAdmins.Count -le 4) {
            $controlResult.Finding = "Global Administrator count is within recommended range"
            $controlResult.Result = "COMPLIANT"
        }
        elseif ($activeAdmins.Count -eq 1) {
            $controlResult.Finding = "Only 1 Global Administrator (need at least 2 for redundancy)"
            $controlResult.Result = "NOT COMPLIANT"
        }
        elseif ($activeAdmins.Count -ge 5) {
            $controlResult.Finding = "Too many Global Administrators ($($activeAdmins.Count))"
            $controlResult.Result = "NOT COMPLIANT"
        }
        else {
            $controlResult.Finding = "No Global Administrators found"
            $controlResult.Result = "ERROR"
        }
        
        $controlResult.Evidence = $evidence
    }
    catch {
        $controlResult.Finding = "Error checking Global Administrator count: $_"
        $controlResult.Result = "ERROR"
    }
    
    return $controlResult
}