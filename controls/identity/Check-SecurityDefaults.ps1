function Check-SecurityDefaults {
    [CmdletBinding()]
    param()

    $controlResult = [PSCustomObject]@{
        Control = "Ensure that 'security defaults' is properly configured"
        ControlDescription = "Security defaults should be disabled when using Conditional Access policies for more granular control (CIS 6.1.1)"
        Finding = ""
        Result = ""
        Evidence = ""
        RemediationSteps = ""
        AffectedAccounts = @()
    }

    try {
        $securityDefaults = Get-MgPolicyIdentitySecurityDefaultEnforcementPolicy
        $conditionalAccessPolicies = Get-MgIdentityConditionalAccessPolicy | Where-Object { $_.State -eq "enabled" }
        
        $evidence = "Security Defaults Status: $($securityDefaults.IsEnabled)`n"
        $evidence += "Active Conditional Access Policies: $($conditionalAccessPolicies.Count)`n"
        
        if ($securityDefaults.IsEnabled -eq $false -and $conditionalAccessPolicies.Count -ge 3) {
            $controlResult.Finding = "Security defaults disabled with adequate CA policies"
            $controlResult.Result = "COMPLIANT"
        }
        elseif ($securityDefaults.IsEnabled -eq $true) {
            $controlResult.Finding = "Security defaults are enabled (blocks CA customization)"
            $controlResult.Result = "NOT COMPLIANT"
        }
        else {
            $controlResult.Finding = "Security defaults disabled without adequate replacements"
            $controlResult.Result = "NOT COMPLIANT"
        }
        
        $controlResult.Evidence = $evidence
    }
    catch {
        $controlResult.Finding = "Error checking security defaults: $_"
        $controlResult.Result = "ERROR"
    }
    
    return $controlResult
}