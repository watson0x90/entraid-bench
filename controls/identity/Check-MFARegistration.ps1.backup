function Check-MFARegistration {
    [CmdletBinding()]
    param()

    $controlResult = [PSCustomObject]@{
        Control = "Ensure multifactor authentication is enabled for all users"
        ControlDescription = "All users should have MFA enabled to protect against password compromise (CIS 6.1.2)"
        Finding = ""
        Result = ""
        Evidence = ""
        RemediationSteps = ""
        AffectedAccounts = @()
    }

    try {
        $evidence = Format-EvidenceSection -Title "MFA REGISTRATION ASSESSMENT" -Content "Assessment Date: $(Get-Date)" -IsHeader
        
        # Check for MFA policies
        $policies = Get-MgIdentityConditionalAccessPolicy
        $mfaPolicies = @()
        
        foreach ($policy in $policies) {
            if ($policy.State -eq "enabled" -and 
                $policy.GrantControls.BuiltInControls -contains "mfa") {
                $mfaPolicies += $policy
                
                $isAllUsers = $policy.Conditions.Users.IncludeUsers -contains "All"
                $evidence += "`n`nMFA Policy Found: $($policy.DisplayName)"
                $evidence += "`nApplies to: $(if ($isAllUsers) { 'All Users' } else { 'Specific Users/Groups' })"
            }
        }
        
        # Check if Security Defaults is enabled (which enforces MFA)
        $securityDefaults = Get-MgPolicyIdentitySecurityDefaultEnforcementPolicy
        if ($securityDefaults.IsEnabled) {
            $evidence += "`n`nSecurity Defaults: Enabled (enforces MFA for all users)"
            $controlResult.Finding = "MFA is enforced for all users via Security Defaults"
            $controlResult.Result = "COMPLIANT"
        }
        else {
            # Check for comprehensive MFA policy
            $hasAllUsersMFA = $false
            foreach ($policy in $mfaPolicies) {
                if ($policy.Conditions.Users.IncludeUsers -contains "All") {
                    $hasAllUsersMFA = $true
                    break
                }
            }
            
            if ($hasAllUsersMFA) {
                $controlResult.Finding = "MFA is enforced for all users via Conditional Access"
                $controlResult.Result = "COMPLIANT"
                $evidence += "`n`nStatus: Comprehensive MFA policy exists for all users"
            }
            else {
                # Check MFA registration status
                try {
                    $users = Get-MgUser -Top 50 -Property DisplayName,UserPrincipalName,Id
                    $usersWithoutMFA = @()
                    
                    foreach ($user in $users) {
                        try {
                            $authMethods = Get-MgUserAuthenticationMethod -UserId $user.Id
                            $mfaMethods = $authMethods | Where-Object { 
                                $_.AdditionalProperties.'@odata.type' -match 'phone|fido2|windowsHello|microsoftAuthenticator'
                            }
                            
                            if ($mfaMethods.Count -eq 0) {
                                $usersWithoutMFA += $user
                            }
                        } catch {}
                    }
                    
                    if ($usersWithoutMFA.Count -gt 0) {
                        $controlResult.Finding = "Some users do not have MFA configured"
                        $controlResult.Result = "NOT COMPLIANT"
                        $evidence += "`n`nUsers without MFA: $($usersWithoutMFA.Count) (from sample of $($users.Count))"
                        
                        foreach ($user in $usersWithoutMFA | Select-Object -First 20) {
                            $controlResult.AffectedAccounts += [PSCustomObject]@{
                                Name = $user.DisplayName
                                Id = $user.Id
                                Details = "User without MFA methods configured"
                            }
                        }
                    }
                    else {
                        $controlResult.Finding = "All sampled users have MFA configured"
                        $controlResult.Result = "COMPLIANT"
                    }
                } catch {
                    $evidence += "`n`nUnable to check individual user MFA status"
                    $controlResult.Result = "PARTIALLY COMPLIANT"
                }
            }
        }
        
        $controlResult.Evidence = $evidence
        
        if ($controlResult.Result -ne "COMPLIANT") {
            $controlResult.RemediationSteps = @"
<ol>
    <li>Choose one of these approaches:</li>
    <li>Option A - Enable Security Defaults (simple but less flexible):
        <ul>
            <li>Navigate to Microsoft Entra admin center > Identity > Overview > Properties</li>
            <li>Click "Manage security defaults"</li>
            <li>Set to "Enabled"</li>
        </ul>
    </li>
    <li>Option B - Create Conditional Access policy (more control):
        <ul>
            <li>Navigate to Protection > Conditional Access</li>
            <li>Create new policy: "Require MFA for all users"</li>
            <li>Users: All users</li>
            <li>Cloud apps: All cloud apps</li>
            <li>Grant: Require multifactor authentication</li>
        </ul>
    </li>
    <li>Run MFA registration campaigns for users without MFA</li>
</ol>
"@
        }
    }
    catch {
        $controlResult.Finding = "Error assessing MFA registration: $_"
        $controlResult.Result = "ERROR"
        $controlResult.Evidence = "Error details: $_"
    }
    
    return $controlResult
}

# Execute the control check
Check-MFARegistration