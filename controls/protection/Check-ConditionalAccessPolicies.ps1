function Check-ConditionalAccessPolicies {
    [CmdletBinding()]
    param()

    $controlResult = [PSCustomObject]@{
        Control = "Ensure comprehensive Conditional Access policies are configured"
        ControlDescription = "A comprehensive set of Conditional Access policies should be in place to protect against various threat vectors."
        Finding = ""
        Result = ""
        Evidence = ""
        RemediationSteps = ""
        AffectedAccounts = @()
    }

    try {
        $evidence = Format-EvidenceSection -Title "CONDITIONAL ACCESS COMPREHENSIVE ASSESSMENT" -Content "Assessment Date: $(Get-Date)" -IsHeader
        
        # Get all CA policies
        $policies = Get-MgIdentityConditionalAccessPolicy
        $enabledPolicies = $policies | Where-Object { $_.State -eq "enabled" }
        
        $evidence += "`nTotal Policies: $($policies.Count)"
        $evidence += "`nEnabled Policies: $($enabledPolicies.Count)"
        $evidence += "`nReport-Only Policies: $(($policies | Where-Object { $_.State -eq 'enabledForReportingButNotEnforced' }).Count)"
        $evidence += "`nDisabled Policies: $(($policies | Where-Object { $_.State -eq 'disabled' }).Count)"
        
        # Check for key security controls
        $securityChecks = @{
            MFAForAll = $false
            BlockLegacyAuth = $false
            AdminMFA = $false
            RiskySignIn = $false
            RiskyUser = $false
            DeviceCompliance = $false
            TrustedLocations = $false
            SessionControls = $false
        }
        
        foreach ($policy in $enabledPolicies) {
            # Check for MFA for all users
            if ($policy.Conditions.Users.IncludeUsers -contains "All" -and
                $policy.GrantControls.BuiltInControls -contains "mfa") {
                $securityChecks.MFAForAll = $true
            }
            
            # Check for legacy auth blocking
            if ($policy.Conditions.ClientAppTypes -contains "exchangeActiveSync" -or
                $policy.Conditions.ClientAppTypes -contains "other") {
                $securityChecks.BlockLegacyAuth = $true
            }
            
            # Check for admin MFA
            if ($policy.Conditions.Users.IncludeRoles -and
                $policy.GrantControls.BuiltInControls -contains "mfa") {
                $securityChecks.AdminMFA = $true
            }
            
            # Check for risk-based policies
            if ($policy.Conditions.SignInRiskLevels) {
                $securityChecks.RiskySignIn = $true
            }
            if ($policy.Conditions.UserRiskLevels) {
                $securityChecks.RiskyUser = $true
            }
            
            # Check for device compliance
            if ($policy.GrantControls.BuiltInControls -contains "compliantDevice") {
                $securityChecks.DeviceCompliance = $true
            }
            
            # Check for location-based policies
            if ($policy.Conditions.Locations) {
                $securityChecks.TrustedLocations = $true
            }
            
            # Check for session controls
            if ($policy.SessionControls) {
                $securityChecks.SessionControls = $true
            }
        }
        
        $evidence += "`n`nSecurity Control Coverage:"
        $passedChecks = 0
        foreach ($check in $securityChecks.GetEnumerator()) {
            $status = if ($check.Value) { "✓ PRESENT" ; $passedChecks++ } else { "✗ MISSING" }
            $evidence += "`n$status - $($check.Key)"
        }
        
        $coverage = [math]::Round(($passedChecks / $securityChecks.Count) * 100)
        $evidence += "`n`nOverall Coverage: $coverage% ($passedChecks/$($securityChecks.Count) controls)"
        
        if ($coverage -ge 80) {
            $controlResult.Finding = "Comprehensive Conditional Access policies are configured"
            $controlResult.Result = "COMPLIANT"
        }
        elseif ($coverage -ge 50) {
            $controlResult.Finding = "Conditional Access policies provide partial coverage"
            $controlResult.Result = "PARTIALLY COMPLIANT"
        }
        else {
            $controlResult.Finding = "Conditional Access policies are insufficient"
            $controlResult.Result = "NOT COMPLIANT"
        }
        
        $controlResult.Evidence = $evidence
        
        if ($controlResult.Result -ne "COMPLIANT") {
            $controlResult.RemediationSteps = @"
<ol>
    <li>Implement missing security controls:
        <ul>
            $(if (-not $securityChecks.MFAForAll) { '<li>Require MFA for all users</li>' })
            $(if (-not $securityChecks.BlockLegacyAuth) { '<li>Block legacy authentication</li>' })
            $(if (-not $securityChecks.AdminMFA) { '<li>Require MFA for administrators</li>' })
            $(if (-not $securityChecks.RiskySignIn) { '<li>Configure sign-in risk policies</li>' })
            $(if (-not $securityChecks.RiskyUser) { '<li>Configure user risk policies</li>' })
            $(if (-not $securityChecks.DeviceCompliance) { '<li>Require compliant devices</li>' })
            $(if (-not $securityChecks.TrustedLocations) { '<li>Configure trusted locations</li>' })
            $(if (-not $securityChecks.SessionControls) { '<li>Implement session controls</li>' })
        </ul>
    </li>
    <li>Use Microsoft's Conditional Access templates as a starting point</li>
    <li>Test all policies in report-only mode first</li>
    <li>Implement gradually to avoid user disruption</li>
</ol>
"@
        }
    }
    catch {
        $controlResult.Finding = "Error assessing Conditional Access policies: $_"
        $controlResult.Result = "ERROR"
        $controlResult.Evidence = "Error details: $_"
    }
    
    return $controlResult
}

# Execute the control check
Check-ConditionalAccessPolicies