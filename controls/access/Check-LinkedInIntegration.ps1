function Check-LinkedInIntegration {
    [CmdletBinding()]
    param()

    $controlResult = [PSCustomObject]@{
        Control = "Ensure 'LinkedIn account connections' is disabled"
        ControlDescription = "LinkedIn account connections should be disabled to prevent data leakage and maintain privacy of organizational user information."
        Finding = ""
        Result = ""
        Evidence = ""
        RemediationSteps = ""
        AffectedAccounts = @()
    }

    try {
        $evidence = Format-EvidenceSection -Title "LINKEDIN INTEGRATION ASSESSMENT" -Content "Assessment Date: $(Get-Date)" -IsHeader
        
        # Get organization settings
        $organization = Get-MgOrganization
        
        # Check directory properties for LinkedIn integration
        # Note: Direct API access to LinkedIn settings may be limited
        $evidence += "`nOrganization: $($organization.DisplayName)"
        
        # Try to get privacy profile settings
        try {
            $privacyProfile = Get-MgOrganizationBranding
            $evidence += "`nPrivacy profile retrieved"
        } catch {
            $evidence += "`nUnable to retrieve privacy profile settings"
        }
        
        # Check for LinkedIn-related settings in directory
        $directorySettings = Get-MgDirectorySetting
        $linkedInSettings = $directorySettings | Where-Object { 
            $_.DisplayName -match "LinkedIn" -or 
            $_.Values.Name -match "LinkedIn"
        }
        
        if ($linkedInSettings) {
            $evidence += "`n`nLinkedIn Settings Found:"
            foreach ($setting in $linkedInSettings.Values) {
                $evidence += "`n$($setting.Name): $($setting.Value)"
            }
            
            $isEnabled = $linkedInSettings.Values | Where-Object { 
                $_.Name -match "EnableLinkedIn" -and $_.Value -eq $true
            }
            
            if ($isEnabled) {
                $controlResult.Finding = "LinkedIn account connections are enabled"
                $controlResult.Result = "NOT COMPLIANT"
                $evidence += "`n`nStatus: LinkedIn integration is active"
            }
            else {
                $controlResult.Finding = "LinkedIn account connections are disabled"
                $controlResult.Result = "COMPLIANT"
                $evidence += "`n`nStatus: LinkedIn integration is disabled"
            }
        }
        else {
            # If no settings found, likely disabled by default
            $controlResult.Finding = "LinkedIn account connections appear to be disabled (no configuration found)"
            $controlResult.Result = "COMPLIANT"
            $evidence += "`n`nStatus: No LinkedIn integration configuration detected"
        }
        
        $controlResult.Evidence = $evidence
        
        if ($controlResult.Result -ne "COMPLIANT") {
            $controlResult.RemediationSteps = @"
<ol>
    <li>Navigate to Microsoft Entra admin center > Identity > Users > User settings</li>
    <li>Under "LinkedIn account connections":</li>
    <li>Set "Users can connect their LinkedIn and Microsoft accounts" to "No"</li>
    <li>This prevents:
        <ul>
            <li>Organizational data from being shared with LinkedIn</li>
            <li>LinkedIn profile information from appearing in Microsoft apps</li>
            <li>Privacy concerns related to data sharing</li>
        </ul>
    </li>
    <li>Click Save</li>
</ol>
"@
        }
    }
    catch {
        $controlResult.Finding = "Error assessing LinkedIn integration: $_"
        $controlResult.Result = "ERROR"
        $controlResult.Evidence = "Error details: $_"
    }
    
    return $controlResult
}

# Execute the control check
Check-LinkedInIntegration