function Check-LegacyAuthentication {
    [CmdletBinding()]
    param()

    $controlResult = [PSCustomObject]@{
        Control = "Enable Conditional Access policies to block legacy authentication"
        ControlDescription = "Legacy authentication protocols don't support MFA and are a common attack vector. These should be blocked for all users."
        Finding = ""
        Result = ""
        Evidence = ""
        RemediationSteps = ""
        AffectedAccounts = @()
    }

    try {
        # Get Conditional Access policies
        $policies = Get-MgIdentityConditionalAccessPolicy
        
        $evidence = Format-EvidenceSection -Title "LEGACY AUTHENTICATION ASSESSMENT" -Content "Assessment Date: $(Get-Date)" -IsHeader
        
        # Look for policies blocking legacy auth
        $legacyBlockPolicies = @()
        
        foreach ($policy in $policies) {
            if ($policy.State -eq "enabled") {
                # Check if policy blocks legacy authentication
                $conditions = $policy.Conditions
                
                if ($conditions.ClientAppTypes -contains "exchangeActiveSync" -or
                    $conditions.ClientAppTypes -contains "other" -or
                    ($conditions.Applications.IncludeApplications -contains "All" -and 
                     $policy.GrantControls.BuiltInControls -contains "block")) {
                    
                    $legacyBlockPolicies += $policy
                    $evidence += "`n`nLegacy Auth Blocking Policy Found: $($policy.DisplayName)"
                    $evidence += "`nState: $($policy.State)"
                    $evidence += "`nApplies to: $(if ($conditions.Users.IncludeUsers -contains 'All') { 'All Users' } else { 'Specific Users/Groups' })"
                }
            }
        }
        
        # Check for comprehensive coverage
        $hasComprehensivePolicy = $false
        foreach ($policy in $legacyBlockPolicies) {
            if ($policy.Conditions.Users.IncludeUsers -contains "All" -and
                $policy.Conditions.Applications.IncludeApplications -contains "All") {
                $hasComprehensivePolicy = $true
                break
            }
        }
        
        if ($hasComprehensivePolicy) {
            $controlResult.Finding = "Legacy authentication is blocked for all users"
            $controlResult.Result = "COMPLIANT"
            $evidence += "`n`nStatus: Comprehensive legacy authentication blocking is in place"
        }
        elseif ($legacyBlockPolicies.Count -gt 0) {
            $controlResult.Finding = "Legacy authentication is partially blocked"
            $controlResult.Result = "PARTIALLY COMPLIANT"
            $evidence += "`n`nStatus: Some legacy auth blocking exists but coverage is incomplete"
        }
        else {
            $controlResult.Finding = "Legacy authentication is not blocked"
            $controlResult.Result = "NOT COMPLIANT"
            $evidence += "`n`nStatus: No policies found blocking legacy authentication"
            $evidence += "`n`nRisks:"
            $evidence += "`n- Legacy protocols don't support MFA"
            $evidence += "`n- Common target for password spray attacks"
            $evidence += "`n- Used in 99% of password spray attacks"
        }
        
        $controlResult.Evidence = $evidence
        
        if ($controlResult.Result -ne "COMPLIANT") {
            $controlResult.RemediationSteps = @"
<ol>
    <li>Navigate to Microsoft Entra admin center > Protection > Conditional Access</li>
    <li>Create a new policy: "Block Legacy Authentication"</li>
    <li>Configure as follows:
        <ul>
            <li>Users: Include All users</li>
            <li>Cloud apps: All cloud apps</li>
            <li>Conditions > Client apps > Select "Exchange ActiveSync clients" and "Other clients"</li>
            <li>Grant: Block access</li>
        </ul>
    </li>
    <li>Enable in report-only mode first to assess impact</li>
    <li>After validation, enable the policy</li>
</ol>
"@
        }
    }
    catch {
        $controlResult.Finding = "Error assessing legacy authentication: $_"
        $controlResult.Result = "ERROR"
        $controlResult.Evidence = "Error details: $_"
    }
    
    return $controlResult
}

# Execute the control check
Check-LegacyAuthentication