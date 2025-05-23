function Check-SelfServicePasswordReset {
    [CmdletBinding()]
    param()

    $controlResult = [PSCustomObject]@{
        Control = "Ensure 'Self service password reset enabled' is set to 'All'"
        ControlDescription = "Self-service password reset (SSPR) should be enabled for all users to reduce helpdesk burden and improve security."
        Finding = ""
        Result = ""
        Evidence = ""
        RemediationSteps = ""
        AffectedAccounts = @()
    }

    try {
        # Get password reset policies
        $passwordResetPolicy = Get-MgPolicyAuthenticationMethodPolicyAuthenticationMethodConfiguration -AuthenticationMethodConfigurationId "TemporaryAccessPass"
        
        $evidence = Format-EvidenceSection -Title "SELF-SERVICE PASSWORD RESET ASSESSMENT" -Content "Assessment Date: $(Get-Date)" -IsHeader
        
        # Get SSPR configuration from directory settings
        $directorySettings = Get-MgDirectorySetting
        $ssprSettings = $directorySettings | Where-Object { $_.DisplayName -like "*Password*Reset*" }
        
        # Check if SSPR is enabled
        # Note: Direct SSPR API may require specific permissions
        $evidence += "`n`nSSPR Configuration:"
        
        # Alternative: Check authentication methods
        $authMethods = Get-MgPolicyAuthenticationMethodPolicy
        $evidence += "`nAuthentication Methods Policy ID: $($authMethods.Id)"
        
        # Check user authentication methods to infer SSPR
        $sampleUsers = Get-MgUser -Top 10 -Property DisplayName,UserPrincipalName,Id
        $usersWithAuthMethods = 0
        
        foreach ($user in $sampleUsers) {
            try {
                $methods = Get-MgUserAuthenticationMethod -UserId $user.Id
                if ($methods.Count -gt 1) {
                    $usersWithAuthMethods++
                }
            } catch {}
        }
        
        $evidence += "`nSample users with multiple auth methods: $usersWithAuthMethods/$($sampleUsers.Count)"
        
        if ($usersWithAuthMethods -eq $sampleUsers.Count) {
            $controlResult.Finding = "SSPR appears to be enabled (all sampled users have multiple auth methods)"
            $controlResult.Result = "COMPLIANT"
            $evidence += "`n`nStatus: Users have multiple authentication methods configured"
        }
        elseif ($usersWithAuthMethods -gt 0) {
            $controlResult.Finding = "SSPR may be partially enabled"
            $controlResult.Result = "PARTIALLY COMPLIANT"
            $evidence += "`n`nStatus: Some users have multiple authentication methods"
            
            # Get users without multiple methods
            foreach ($user in $sampleUsers) {
                try {
                    $methods = Get-MgUserAuthenticationMethod -UserId $user.Id
                    if ($methods.Count -le 1) {
                        $controlResult.AffectedAccounts += [PSCustomObject]@{
                            Name = $user.DisplayName
                            Id = $user.Id
                            Details = "User may not have SSPR configured"
                        }
                    }
                } catch {}
            }
        }
        else {
            $controlResult.Finding = "SSPR does not appear to be enabled"
            $controlResult.Result = "NOT COMPLIANT"
            $evidence += "`n`nStatus: Users lack multiple authentication methods for password reset"
        }
        
        $controlResult.Evidence = $evidence
        
        if ($controlResult.Result -ne "COMPLIANT") {
            $controlResult.RemediationSteps = @"
<ol>
    <li>Navigate to Microsoft Entra admin center > Identity > Users > Password reset</li>
    <li>Under "Self service password reset enabled", select "All"</li>
    <li>Configure authentication methods:
        <ul>
            <li>Set "Number of methods required to reset" to 2</li>
            <li>Enable appropriate methods (Mobile phone, Email, Security questions, etc.)</li>
        </ul>
    </li>
    <li>Configure notifications:
        <ul>
            <li>Enable user and admin notifications</li>
        </ul>
    </li>
    <li>Click Save</li>
    <li>Communicate the change to users and provide guidance</li>
</ol>
"@
        }
    }
    catch {
        $controlResult.Finding = "Error assessing SSPR configuration: $_"
        $controlResult.Result = "ERROR"
        $controlResult.Evidence = "Error details: $_"
    }
    
    return $controlResult
}

# Execute the control check
Check-SelfServicePasswordReset