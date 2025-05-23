function Check-SignInRiskPolicy {
    [CmdletBinding()]
    param()

    $controlResult = [PSCustomObject]@{
        Control = "Enable Azure AD Identity Protection sign-in risk policies"
        ControlDescription = "Sign-in risk policies protect against suspicious sign-in attempts by requiring MFA or blocking access based on risk level."
        Finding = ""
        Result = ""
        Evidence = ""
        RemediationSteps = ""
        AffectedAccounts = @()
    }

    try {
        # Check for P2 license
        $hasP2License = Test-EntraIDP2License
        
        if (-not $hasP2License) {
            $controlResult.Finding = "Microsoft Entra ID P2 license required for Identity Protection"
            $controlResult.Result = "INFORMATION NEEDED"
            $controlResult.Evidence = "Identity Protection requires P2 licensing"
            return $controlResult
        }
        
        # Get Conditional Access policies
        $policies = Get-MgIdentityConditionalAccessPolicy
        
        $evidence = Format-EvidenceSection -Title "SIGN-IN RISK POLICY ASSESSMENT" -Content "Assessment Date: $(Get-Date)" -IsHeader
        
        # Look for sign-in risk policies
        $signInRiskPolicies = @()
        foreach ($policy in $policies) {
            if ($policy.State -eq "enabled" -and $policy.Conditions.SignInRiskLevels) {
                $signInRiskPolicies += $policy
                $evidence += "`n`nSign-in Risk Policy Found: $($policy.DisplayName)"
                $evidence += "`nRisk Levels: $($policy.Conditions.SignInRiskLevels -join ', ')"
                $evidence += "`nActions: $($policy.GrantControls.BuiltInControls -join ', ')"
            }
        }
        
        # Check coverage
        $hasHighRiskPolicy = $false
        $hasMediumRiskPolicy = $false
        
        foreach ($policy in $signInRiskPolicies) {
            if ($policy.Conditions.SignInRiskLevels -contains "high") {
                $hasHighRiskPolicy = $true
            }
            if ($policy.Conditions.SignInRiskLevels -contains "medium") {
                $hasMediumRiskPolicy = $true
            }
        }
        
        if ($hasHighRiskPolicy -and $hasMediumRiskPolicy) {
            $controlResult.Finding = "Sign-in risk policies are properly configured"
            $controlResult.Result = "COMPLIANT"
            $evidence += "`n`nStatus: Comprehensive sign-in risk protection is in place"
        }
        elseif ($signInRiskPolicies.Count -gt 0) {
            $controlResult.Finding = "Sign-in risk policies are partially configured"
            $controlResult.Result = "PARTIALLY COMPLIANT"
        }
        else {
            $controlResult.Finding = "No sign-in risk policies are configured"
            $controlResult.Result = "NOT COMPLIANT"
            $evidence += "`n`nStatus: No protection against risky sign-ins"
        }
        
        $controlResult.Evidence = $evidence
        
        if ($controlResult.Result -ne "COMPLIANT") {
            $controlResult.RemediationSteps = @"
<ol>
    <li>Navigate to Microsoft Entra admin center > Protection > Conditional Access</li>
    <li>Create a policy for high-risk sign-ins:
        <ul>
            <li>Name: "Block high-risk sign-ins"</li>
            <li>Users: All users</li>
            <li>Conditions > Sign-in risk: High</li>
            <li>Grant: Block access</li>
        </ul>
    </li>
    <li>Create a policy for medium-risk sign-ins:
        <ul>
            <li>Name: "Require MFA for medium-risk sign-ins"</li>
            <li>Users: All users</li>
            <li>Conditions > Sign-in risk: Medium</li>
            <li>Grant: Require multifactor authentication</li>
        </ul>
    </li>
</ol>
"@
        }
    }
    catch {
        $controlResult.Finding = "Error assessing sign-in risk policy: $_"
        $controlResult.Result = "ERROR"
        $controlResult.Evidence = "Error details: $_"
    }
    
    return $controlResult
}

# Execute the control check
Check-SignInRiskPolicy