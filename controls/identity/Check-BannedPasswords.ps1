function Check-BannedPasswords {
    [CmdletBinding()]
    param()

    $controlResult = [PSCustomObject]@{
        Control = "Ensure custom banned passwords lists are used"
        ControlDescription = "Organizations should maintain a custom list of banned passwords including company-specific terms to prevent easily guessable passwords."
        Finding = ""
        Result = ""
        Evidence = ""
        RemediationSteps = ""
        AffectedAccounts = @()
    }

    try {
        # Get banned password settings
        $groupSettings = Get-MgGroupSetting
        
        $evidence = Format-EvidenceSection -Title "BANNED PASSWORD ASSESSMENT" -Content "Assessment Date: $(Get-Date)" -IsHeader
        
        # Find password protection settings
        $enableBannedPasswordCheck = $groupSettings.Values | Where-Object { $_.Name -eq "EnableBannedPasswordCheck" }
        $bannedPasswordList = $groupSettings.Values | Where-Object { $_.Name -eq "BannedPasswordList" }
        
        $evidence += "`n`nPassword Protection Settings:"
        $evidence += "`nBanned Password Check Enabled: $($enableBannedPasswordCheck.Value)"
        
        if ($bannedPasswordList) {
            $passwordCount = if ($bannedPasswordList.Value) { $bannedPasswordList.Value.Count } else { 0 }
            $evidence += "`nCustom Banned Passwords Count: $passwordCount"
        }
        
        # Assess compliance
        if ($enableBannedPasswordCheck.Value -eq $true -and $bannedPasswordList.Value.Count -gt 0) {
            $controlResult.Finding = "Custom banned passwords are properly configured"
            $controlResult.Result = "COMPLIANT"
            $evidence += "`n`nStatus: Custom password protection is active with $passwordCount banned terms"
        }
        elseif ($enableBannedPasswordCheck.Value -eq $true) {
            $controlResult.Finding = "Banned password check is enabled but no custom passwords are defined"
            $controlResult.Result = "PARTIALLY COMPLIANT"
            $evidence += "`n`nStatus: Feature enabled but list is empty"
        }
        else {
            $controlResult.Finding = "Custom banned password protection is not enabled"
            $controlResult.Result = "NOT COMPLIANT"
            $evidence += "`n`nStatus: Feature disabled - users can use company-specific terms in passwords"
        }
        
        $controlResult.Evidence = $evidence
        
        if ($controlResult.Result -ne "COMPLIANT") {
            $controlResult.RemediationSteps = @"
<ol>
    <li>Navigate to Microsoft Entra admin center > Identity > Protection > Password protection</li>
    <li>Set "Enforce custom list" to Yes</li>
    <li>Add organization-specific terms to the custom banned password list:
        <ul>
            <li>Company name and variations</li>
            <li>Product names</li>
            <li>Office locations</li>
            <li>Common industry terms</li>
        </ul>
    </li>
    <li>Save the configuration</li>
</ol>
"@
        }
    }
    catch {
        $controlResult.Finding = "Error assessing banned passwords: $_"
        $controlResult.Result = "ERROR"
        $controlResult.Evidence = "Error details: $_"
    }
    
    return $controlResult
}

# Execute the control check
Check-BannedPasswords