function Check-UserRiskPolicy {
    [CmdletBinding()]
    param()

    $controlResult = [PSCustomObject]@{
        Control = "Enable Azure AD Identity Protection user risk policies"
        ControlDescription = "User risk policies help protect against compromised user accounts by requiring password changes or blocking access when risky behavior is detected."
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
            $controlResult.Evidence = "Identity Protection requires P2 licensing. User risk policies cannot be assessed without appropriate licensing."
            $controlResult.RemediationSteps = "Obtain Microsoft Entra ID P2 or Microsoft 365 E5 licensing to enable Identity Protection features."
            return $controlResult
        }
        
        # Get Conditional Access policies
        $policies = Get-MgIdentityConditionalAccessPolicy
        
        $evidence = Format-EvidenceSection -Title "USER RISK POLICY ASSESSMENT" -Content "Assessment Date: $(Get-Date)" -IsHeader
        
        # Look for user risk policies
        $userRiskPolicies = @()
        foreach ($policy in $policies) {
            if ($policy.State -eq "enabled" -and $policy.Conditions.UserRiskLevels) {
                $userRiskPolicies += $policy
                $evidence += "`n`nUser Risk Policy Found: $($policy.DisplayName)"
                $evidence += "`nRisk Levels: $($policy.Conditions.UserRiskLevels -join ', ')"
                $evidence += "`nActions: $($policy.GrantControls.BuiltInControls -join ', ')"
            }
        }
        
        # Check for comprehensive coverage
        $hasHighRiskPolicy = $false
        $hasMediumRiskPolicy = $false
        
        foreach ($policy in $userRiskPolicies) {
            if ($policy.Conditions.UserRiskLevels -contains "high") {
                $hasHighRiskPolicy = $true
            }
            if ($policy.Conditions.UserRiskLevels -contains "medium") {
                $hasMediumRiskPolicy = $true
            }
        }
        
        if ($hasHighRiskPolicy -and $hasMediumRiskPolicy) {
            $controlResult.Finding = "User risk policies are properly configured for medium and high risk"
            $controlResult.Result = "COMPLIANT"
            $evidence += "`n`nStatus: Comprehensive user risk protection is in place"
        }
        elseif ($hasHighRiskPolicy -or $hasMediumRiskPolicy) {
            $controlResult.Finding = "User risk policies are partially configured"
            $controlResult.Result = "PARTIALLY COMPLIANT"
            $evidence += "`n`nStatus: Some user risk protection exists but coverage is incomplete"
            
            if (-not $hasHighRiskPolicy) {
                $evidence += "`nMissing: High risk user policy"
            }
            if (-not $hasMediumRiskPolicy) {
                $evidence += "`nMissing: Medium risk user policy"
            }
        }
        else {
            $controlResult.Finding = "No user risk policies are configured"
            $controlResult.Result = "NOT COMPLIANT"
            $evidence += "`n`nStatus: No protection against risky users"
            
            # Get risky users if available
            try {
                $riskyUsers = Get-MgRiskyUser -Top 20
                if ($riskyUsers.Count -gt 0) {
                    $evidence += "`n`nCurrent Risky Users: $($riskyUsers.Count)"
                    foreach ($user in $riskyUsers | Select-Object -First 10) {
                        $controlResult.AffectedAccounts += [PSCustomObject]@{
                            Name = $user.UserDisplayName
                            Id = $user.Id
                            Details = "Risk Level: $($user.RiskLevel), Risk State: $($user.RiskState)"
                        }
                    }
                }
            } catch {
                $evidence += "`n`nUnable to retrieve risky users"
            }
        }
        
        $controlResult.Evidence = $evidence
        
        if ($controlResult.Result -ne "COMPLIANT") {
            $controlResult.RemediationSteps = @"
<ol>
    <li>Navigate to Microsoft Entra admin center > Protection > Conditional Access</li>
    <li>Create a policy for high-risk users:
        <ul>
            <li>Name: "Block high-risk users"</li>
            <li>Users: All users</li>
            <li>Conditions > User risk: High</li>
            <li>Grant: Block access</li>
        </ul>
    </li>
    <li>Create a policy for medium-risk users:
        <ul>
            <li>Name: "Require password change for medium-risk users"</li>
            <li>Users: All users</li>
            <li>Conditions > User risk: Medium</li>
            <li>Grant: Require password change</li>
        </ul>
    </li>
    <li>Test policies in report-only mode first</li>
    <li>Enable policies after validation</li>
</ol>
"@
        }
    }
    catch {
        $controlResult.Finding = "Error assessing user risk policy: $_"
        $controlResult.Result = "ERROR"
        $controlResult.Evidence = "Error details: $_"
    }
    
    return $controlResult
}

# Execute the control check
Check-UserRiskPolicy