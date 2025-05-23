function Check-DeviceRegistrationMFA {
    [CmdletBinding()]
    param()

    $controlResult = [PSCustomObject]@{
        Control = "Ensure that 'Require Multifactor Authentication to register or join devices' is set to 'Yes'"
        ControlDescription = "MFA should be required when registering or joining devices to prevent unauthorized device enrollment."
        Finding = ""
        Result = ""
        Evidence = ""
        RemediationSteps = ""
        AffectedAccounts = @()
    }

    try {
        $evidence = Format-EvidenceSection -Title "DEVICE REGISTRATION MFA ASSESSMENT" -Content "Assessment Date: $(Get-Date)" -IsHeader
        
        # Get device registration policy settings
        $authPolicy = Get-MgPolicyAuthorizationPolicy
        $deviceSettings = Get-MgPolicyDeviceRegistrationPolicy -ErrorAction SilentlyContinue
        
        # Check multiple possible locations for this setting
        $evidence += "`nChecking device registration settings..."
        
        # Method 1: Check authorization policy
        if ($authPolicy.DefaultUserRolePermissions) {
            $evidence += "`n`nAuthorization Policy Settings:"
            if ($authPolicy.DefaultUserRolePermissions.AllowedToCreateTenants -eq $false) {
                $evidence += "`nTenant creation restricted (good security practice)"
            }
        }
        
        # Method 2: Check device registration policy
        if ($deviceSettings) {
            $evidence += "`n`nDevice Registration Policy Found:"
            $evidence += "`nUser Registration: $($deviceSettings.UserRegistration)"
            $evidence += "`nAzure AD Join: $($deviceSettings.AzureADJoin)"
            
            # Check if MFA is required
            if ($deviceSettings.MultiFactorAuthConfiguration -eq "required") {
                $controlResult.Finding = "MFA is required for device registration"
                $controlResult.Result = "COMPLIANT"
                $evidence += "`nMFA Requirement: Required"
            }
            else {
                $controlResult.Finding = "MFA may not be required for device registration"
                $controlResult.Result = "PARTIALLY COMPLIANT"
                $evidence += "`nMFA Requirement: Not enforced at policy level"
            }
        }
        else {
            # Method 3: Check Conditional Access for device registration
            $evidence += "`n`nDevice registration policy not directly accessible, checking Conditional Access..."
            
            $policies = Get-MgIdentityConditionalAccessPolicy
            $deviceRegPolicies = @()
            
            foreach ($policy in $policies) {
                if ($policy.State -eq "enabled" -and
                    ($policy.Conditions.Applications.IncludeUserActions -contains "urn:user:registerdevice" -or
                     $policy.Conditions.Applications.IncludeUserActions -contains "urn:user:joindevice")) {
                    
                    $deviceRegPolicies += $policy
                    $evidence += "`n`nDevice Registration CA Policy: $($policy.DisplayName)"
                    
                    if ($policy.GrantControls.BuiltInControls -contains "mfa") {
                        $evidence += "`nRequires MFA: Yes"
                    }
                }
            }
            
            if ($deviceRegPolicies | Where-Object { $_.GrantControls.BuiltInControls -contains "mfa" }) {
                $controlResult.Finding = "MFA is required for device registration via Conditional Access"
                $controlResult.Result = "COMPLIANT"
            }
            else {
                $controlResult.Finding = "MFA is not required for device registration"
                $controlResult.Result = "NOT COMPLIANT"
                $evidence += "`n`nNo policies found requiring MFA for device registration"
            }
        }
        
        $controlResult.Evidence = $evidence
        
        if ($controlResult.Result -ne "COMPLIANT") {
            $controlResult.RemediationSteps = @"
<ol>
    <li>Navigate to Microsoft Entra admin center > Devices > Device settings</li>
    <li>Under "Require Multi-Factor Authentication to register or join devices with Azure AD":
        <ul>
            <li>Set to "Yes"</li>
        </ul>
    </li>
    <li>Alternative: Create Conditional Access policy:
        <ul>
            <li>Name: "Require MFA for device registration"</li>
            <li>Users: All users</li>
            <li>Cloud apps: Select user actions > Register or join devices</li>
            <li>Grant: Require multi-factor authentication</li>
        </ul>
    </li>
    <li>This prevents:
        <ul>
            <li>Unauthorized device enrollment</li>
            <li>Attackers registering rogue devices</li>
            <li>Shadow IT device sprawl</li>
        </ul>
    </li>
</ol>
"@
        }
    }
    catch {
        $controlResult.Finding = "Error assessing device registration MFA: $_"
        $controlResult.Result = "ERROR"
        $controlResult.Evidence = "Error details: $_"
    }
    
    return $controlResult
}

# Execute the control check
Check-DeviceRegistrationMFA