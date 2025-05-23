function Check-PasswordPolicies {
    [CmdletBinding()]
    param()

    $controlResult = [PSCustomObject]@{
        Control = "Ensure password policies meet CIS requirements"
        ControlDescription = "Check lockout threshold (≤10), lockout duration (≥60s), password reset notifications, and re-confirmation settings (CIS 6.6-6.11)"
        Finding = ""
        Result = ""
        Evidence = ""
        RemediationSteps = ""
        AffectedAccounts = @()
    }

    try {
        $evidence = Format-EvidenceSection -Title "PASSWORD POLICY ASSESSMENT" -Content "Assessment Date: $(Get-Date)" -IsHeader
        $issues = @()
        
        # Get authentication methods policy for password protection settings
        $authMethodPolicy = Get-MgPolicyAuthenticationMethodPolicy
        
        # Get group settings for additional password configurations
        $groupSettings = Get-MgGroupSetting
        
        # Check Smart Lockout settings (these are often in authentication methods policy)
        $evidence += "`n`nSmart Lockout Configuration:"
        
        # Note: Direct API access to lockout settings may require specific permissions
        # Using alternative methods to check configuration
        
        # Check password reset notification settings
        $passwordResetSettings = $groupSettings.Values | Where-Object { $_.Name -like "*PasswordReset*" }
        
        if ($passwordResetSettings) {
            foreach ($setting in $passwordResetSettings) {
                $evidence += "`n$($setting.Name): $($setting.Value)"
            }
        }
        
        # Check re-confirmation settings
        $reconfirmSettings = $groupSettings.Values | Where-Object { $_.Name -like "*Reconfirm*" -or $_.Name -like "*ReAuthenticate*" }
        
        if ($reconfirmSettings) {
            $evidence += "`n`nRe-confirmation Settings:"
            foreach ($setting in $reconfirmSettings) {
                $evidence += "`n$($setting.Name): $($setting.Value)"
            }
        }
        
        # Since we can't directly access all lockout settings via Graph API, provide general assessment
        $evidence += "`n`nNote: Some password policy settings require Azure AD portal verification"
        
        # Determine compliance based on available settings
        if ($passwordResetSettings -or $reconfirmSettings) {
            $controlResult.Finding = "Password policies are configured (manual verification required for lockout settings)"
            $controlResult.Result = "PARTIALLY COMPLIANT"
            $evidence += "`n`nStatus: Some password policies detected, manual verification needed for complete assessment"
        }
        else {
            $controlResult.Finding = "Unable to fully assess password policies via API"
            $controlResult.Result = "INFORMATION NEEDED"
            $evidence += "`n`nStatus: Manual verification required in Azure portal"
        }
        
        $controlResult.Evidence = $evidence
        
        $controlResult.RemediationSteps = @"
<ol>
    <li>Navigate to Microsoft Entra admin center > Identity > Authentication methods > Password protection</li>
    <li>Configure Smart Lockout settings:
        <ul>
            <li>Lockout threshold: 10 or fewer attempts</li>
            <li>Lockout duration: 60 seconds or more</li>
        </ul>
    </li>
    <li>Go to Users > Password reset > Notifications:
        <ul>
            <li>Enable "Notify users on password resets"</li>
            <li>Enable "Notify all admins when other admins reset their password"</li>
        </ul>
    </li>
    <li>Configure re-confirmation:
        <ul>
            <li>Set "Number of days before users are asked to re-confirm" to a value greater than 0 (e.g., 180)</li>
        </ul>
    </li>
</ol>
"@
    }
    catch {
        $controlResult.Finding = "Error assessing password policies: $_"
        $controlResult.Result = "ERROR"
        $controlResult.Evidence = "Error details: $_"
    }
    
    return $controlResult
}

# Execute the control check
Check-PasswordPolicies