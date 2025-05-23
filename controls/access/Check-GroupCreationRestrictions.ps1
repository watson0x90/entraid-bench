function Check-GroupCreationRestrictions {
    [CmdletBinding()]
    param()

    $controlResult = [PSCustomObject]@{
        Control = "Ensure group creation is restricted"
        ControlDescription = "Users should not be able to create security groups or M365 groups (CIS 6.19, 6.21)"
        Finding = ""
        Result = ""
        Evidence = ""
        RemediationSteps = ""
        AffectedAccounts = @()
    }

    try {
        $groupSettings = Get-MgGroupSetting
        $authPolicy = Get-MgPolicyAuthorizationPolicy
        
        $issues = @()
        
        # Check if users can create security groups
        $canCreateSecurityGroups = $authPolicy.DefaultUserRolePermissions.AllowedToCreateSecurityGroups
        if ($canCreateSecurityGroups -eq $true) {
            $issues += "Users can create security groups"
        }
        
        # Check if users can create M365 groups
        $canCreateM365Groups = $authPolicy.DefaultUserRolePermissions.AllowedToCreateGroups
        if ($canCreateM365Groups -eq $true) {
            $issues += "Users can create Microsoft 365 groups"
        }
        
        if ($issues.Count -eq 0) {
            $controlResult.Finding = "Group creation properly restricted"
            $controlResult.Result = "COMPLIANT"
        }
        else {
            $controlResult.Finding = "Group creation not restricted: $($issues -join ', ')"
            $controlResult.Result = "NOT COMPLIANT"
        }
    }
    catch {
        $controlResult.Finding = "Error checking group creation restrictions: $_"
        $controlResult.Result = "ERROR"
    }
    
    return $controlResult
}