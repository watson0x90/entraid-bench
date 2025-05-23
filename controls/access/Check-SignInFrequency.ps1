function Check-SignInFrequency {
    [CmdletBinding()]
    param()

    $controlResult = [PSCustomObject]@{
        Control = "Ensure Sign-in frequency is enabled and browser sessions are not persistent for Administrative users"
        ControlDescription = "Administrative sessions should have sign-in frequency policies to limit session duration and prevent persistent browser sessions."
        Finding = ""
        Result = ""
        Evidence = ""
        RemediationSteps = ""
        AffectedAccounts = @()
    }

    try {
        $evidence = Format-EvidenceSection -Title "SIGN-IN FREQUENCY ASSESSMENT" -Content "Assessment Date: $(Get-Date)" -IsHeader
        
        # Get Conditional Access policies
        $policies = Get-MgIdentityConditionalAccessPolicy
        $frequencyPolicies = @()
        
        # Get admin roles for reference
        $adminRoles = Get-MgRoleManagementDirectoryRoleDefinition | Where-Object { 
            $_.IsBuiltIn -eq $true -and $_.DisplayName -match "Administrator"
        }
        
        foreach ($policy in $policies) {
            if ($policy.State -eq "enabled" -and $policy.SessionControls) {
                # Check for sign-in frequency settings
                if ($policy.SessionControls.SignInFrequency -or 
                    $policy.SessionControls.PersistentBrowser) {
                    
                    # Check if it targets admin roles
                    $targetsAdmins = $false
                    if ($policy.Conditions.Users.IncludeRoles) {
                        $targetsAdmins = $true
                    }
                    
                    if ($targetsAdmins) {
                        $frequencyPolicies += $policy
                        $evidence += "`n`nAdmin Session Policy Found: $($policy.DisplayName)"
                        
                        if ($policy.SessionControls.SignInFrequency) {
                            $evidence += "`nSign-in Frequency: $($policy.SessionControls.SignInFrequency.Value) $($policy.SessionControls.SignInFrequency.Type)"
                        }
                        
                        if ($policy.SessionControls.PersistentBrowser) {
                            $evidence += "`nPersistent Browser: $($policy.SessionControls.PersistentBrowser.Mode)"
                        }
                    }
                }
            }
        }
        
        # Check coverage
        $hasProperPolicy = $false
        foreach ($policy in $frequencyPolicies) {
            $hasFrequency = $policy.SessionControls.SignInFrequency -and 
                           $policy.SessionControls.SignInFrequency.Value -le 4  # 4 hours or less
            
            $blocksPersistent = $policy.SessionControls.PersistentBrowser -and
                               $policy.SessionControls.PersistentBrowser.Mode -eq "never"
            
            if ($hasFrequency -or $blocksPersistent) {
                $hasProperPolicy = $true
            }
        }
        
        if ($hasProperPolicy) {
            $controlResult.Finding = "Sign-in frequency policies are configured for administrators"
            $controlResult.Result = "COMPLIANT"
            $evidence += "`n`nStatus: Admin session controls are properly configured"
        }
        elseif ($frequencyPolicies.Count -gt 0) {
            $controlResult.Finding = "Some session policies exist but may not be properly configured"
            $controlResult.Result = "PARTIALLY COMPLIANT"
            $evidence += "`n`nStatus: Policies exist but need configuration review"
        }
        else {
            $controlResult.Finding = "No sign-in frequency policies found for administrators"
            $controlResult.Result = "NOT COMPLIANT"
            $evidence += "`n`nStatus: Admin sessions have no time limits"
            $evidence += "`n`nRisks:"
            $evidence += "`n- Admin sessions remain active indefinitely"
            $evidence += "`n- Increased risk from unattended workstations"
            $evidence += "`n- Persistent cookies increase attack surface"
        }
        
        $controlResult.Evidence = $evidence
        
        if ($controlResult.Result -ne "COMPLIANT") {
            $controlResult.RemediationSteps = @"
<ol>
    <li>Navigate to Microsoft Entra admin center > Protection > Conditional Access</li>
    <li>Create new policy: "Admin Session Management"</li>
    <li>Configure:
        <ul>
            <li>Users: Include "Directory roles" (select all admin roles)</li>
            <li>Cloud apps: All cloud apps</li>
            <li>Session controls:
                <ul>
                    <li>Sign-in frequency: 4 hours (or less)</li>
                    <li>Persistent browser session: Never</li>
                </ul>
            </li>
        </ul>
    </li>
    <li>Consider even shorter sessions for highly privileged roles (1-2 hours)</li>
    <li>Test impact on admin productivity before full deployment</li>
</ol>
"@
        }
    }
    catch {
        $controlResult.Finding = "Error assessing sign-in frequency policies: $_"
        $controlResult.Result = "ERROR"
        $controlResult.Evidence = "Error details: $_"
    }
    
    return $controlResult
}

# Execute the control check
Check-SignInFrequency