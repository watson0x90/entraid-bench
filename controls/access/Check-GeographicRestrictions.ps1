function Check-GeographicRestrictions {
    [CmdletBinding()]
    param()

    $controlResult = [PSCustomObject]@{
        Control = "Ensure that an exclusionary geographic Conditional Access Policy is set up"
        ControlDescription = "Block access from countries where your organization doesn't operate (CIS 6.2.2)"
        Finding = ""
        Result = ""
        Evidence = ""
        RemediationSteps = ""
        AffectedAccounts = @()
    }

    try {
        $policies = Get-MgIdentityConditionalAccessPolicy
        $geoBlockPolicies = @()
        
        foreach ($policy in $policies) {
            if ($policy.State -eq "enabled" -and $policy.Conditions.Locations) {
                if ($policy.Conditions.Locations.ExcludeLocations -or 
                    $policy.Conditions.Locations.IncludeLocations) {
                    $geoBlockPolicies += $policy
                }
            }
        }
        
        if ($geoBlockPolicies.Count -gt 0) {
            $controlResult.Finding = "Geographic restrictions are configured"
            $controlResult.Result = "COMPLIANT"
        }
        else {
            $controlResult.Finding = "No geographic restrictions configured"
            $controlResult.Result = "NOT COMPLIANT"
        }
    }
    catch {
        $controlResult.Finding = "Error checking geographic restrictions: $_"
        $controlResult.Result = "ERROR"
    }
    
    return $controlResult
}