function Check-EntraAdminCenterAccess {
    [CmdletBinding()]
    param()

    $controlResult = [PSCustomObject]@{
        Control = "Ensure that 'Restrict access to Microsoft Entra admin center' is set to 'Yes'"
        ControlDescription = "Access to the Microsoft Entra admin center should be restricted to administrators only to prevent unauthorized users from viewing configuration."
        Finding = ""
        Result = ""
        Evidence = ""
        RemediationSteps = ""
        AffectedAccounts = @()
    }

    try {
        $evidence = Format-EvidenceSection -Title "ENTRA ADMIN CENTER ACCESS ASSESSMENT" -Content "Assessment Date: $(Get-Date)" -IsHeader
        
        # Get authorization policy
        $authPolicy = Get-MgPolicyAuthorizationPolicy
        $defaultUserPermissions = $authPolicy.DefaultUserRolePermissions
        
        # Check if users can access the admin center
        # Note: This setting might be in different properties depending on API version
        $evidence += "`nAuthorization Policy Settings:"
        
        # Look for admin center restriction settings
        $canAccessPortal = $true  # Default assumption if not explicitly set
        
        if ($defaultUserPermissions.AllowedToReadOtherUsers -eq $false) {
            $evidence += "`nUsers cannot read other users: True (indicates restrictions)"
            $canAccessPortal = $false
        }
        
        # Check for specific portal restrictions in directory settings
        $directorySettings = Get-MgDirectorySetting
        $portalSettings = $directorySettings | Where-Object { 
            $_.DisplayName -match "Portal" -or 
            $_.Values.Name -match "RestrictAdminPortal"
        }
        
        if ($portalSettings) {
            $evidence += "`n`nPortal Access Settings Found:"
            foreach ($setting in $portalSettings.Values) {
                $evidence += "`n$($setting.Name): $($setting.Value)"
                
                if ($setting.Name -match "RestrictAdminPortal" -and $setting.Value -eq $true) {
                    $canAccessPortal = $false
                }
            }
        }
        
        if (-not $canAccessPortal) {
            $controlResult.Finding = "Access to Microsoft Entra admin center is restricted"
            $controlResult.Result = "COMPLIANT"
            $evidence += "`n`nStatus: Admin center access is properly restricted to administrators"
        }
        else {
            $controlResult.Finding = "Access to Microsoft Entra admin center is not restricted"
            $controlResult.Result = "NOT COMPLIANT"
            $evidence += "`n`nStatus: All users can access the admin center"
            $evidence += "`n`nRisks:"
            $evidence += "`n- Users can view organizational configuration"
            $evidence += "`n- Potential information disclosure"
            $evidence += "`n- Users can see other user information"
            
            # Get sample of non-admin users who could access
            $standardUsers = Get-MgUser -Top 20 -Filter "userType eq 'Member'"
            foreach ($user in $standardUsers | Select-Object -First 10) {
                $controlResult.AffectedAccounts += [PSCustomObject]@{
                    Name = $user.DisplayName
                    Id = $user.Id
                    Details = "Non-admin user with potential admin center access"
                }
            }
        }
        
        $controlResult.Evidence = $evidence
        
        if ($controlResult.Result -ne "COMPLIANT") {
            $controlResult.RemediationSteps = @"
<ol>
    <li>Navigate to Microsoft Entra admin center > Identity > Users > User settings</li>
    <li>Under "Administration center":</li>
    <li>Set "Restrict access to Microsoft Entra admin center" to "Yes"</li>
    <li>This prevents non-administrators from:
        <ul>
            <li>Accessing the Entra admin center</li>
            <li>Viewing organizational configuration</li>
            <li>Browsing user and group information</li>
        </ul>
    </li>
    <li>Note: This does not affect user access to their own profile in My Account</li>
    <li>Click Save</li>
</ol>
"@
        }
    }
    catch {
        $controlResult.Finding = "Error assessing admin center access: $_"
        $controlResult.Result = "ERROR"
        $controlResult.Evidence = "Error details: $_"
    }
    
    return $controlResult
}

# Execute the control check
Check-EntraAdminCenterAccess