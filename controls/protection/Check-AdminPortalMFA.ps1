function Check-AdminPortalMFA {
    [CmdletBinding()]
    param()

    $controlResult = [PSCustomObject]@{
        Control = "Ensure that multifactor authentication is required to access Microsoft Admin Portals"
        ControlDescription = "MFA should be required when accessing any Microsoft admin portal to protect administrative interfaces."
        Finding = ""
        Result = ""
        Evidence = ""
        RemediationSteps = ""
        AffectedAccounts = @()
    }

    try {
        $evidence = Format-EvidenceSection -Title "ADMIN PORTAL MFA ASSESSMENT" -Content "Assessment Date: $(Get-Date)" -IsHeader
        
        # Known admin portal application IDs
        $adminPortalAppIds = @{
            "Azure Portal" = "c44b4083-3bb0-49c1-b47d-974e53cbdf3c"
            "Microsoft 365 Admin Center" = "00000006-0000-0ff1-ce00-000000000000"
            "Exchange Admin Center" = "00000002-0000-0ff1-ce00-000000000000"
            "SharePoint Admin Center" = "00000003-0000-0ff1-ce00-000000000000"
            "Teams Admin Center" = "cc15fd57-2c6c-4117-a88c-83b1d56b4bbe"
            "Security & Compliance Center" = "00000007-0000-0ff1-ce00-000000000000"
        }
        
        # Get Conditional Access policies
        $policies = Get-MgIdentityConditionalAccessPolicy
        $adminPortalPolicies = @()
        
        foreach ($policy in $policies) {
            if ($policy.State -eq "enabled") {
                # Check if policy covers admin portals
                $coversAdminPortals = $false
                
                # Check if it includes all apps
                if ($policy.Conditions.Applications.IncludeApplications -contains "All") {
                    $coversAdminPortals = $true
                }
                else {
                    # Check for specific admin portal apps
                    foreach ($appId in $adminPortalAppIds.Values) {
                        if ($policy.Conditions.Applications.IncludeApplications -contains $appId) {
                            $coversAdminPortals = $true
                            break
                        }
                    }
                }
                
                if ($coversAdminPortals -and $policy.GrantControls.BuiltInControls -contains "mfa") {
                    $adminPortalPolicies += $policy
                    $evidence += "`n`nAdmin Portal MFA Policy: $($policy.DisplayName)"
                    $evidence += "`nCovers: $(if ($policy.Conditions.Applications.IncludeApplications -contains 'All') { 'All applications' } else { 'Specific admin portals' })"
                }
            }
        }
        
        # Check for comprehensive coverage
        if ($adminPortalPolicies.Count -gt 0) {
            # Check if any policy covers all users
            $coversAllUsers = $false
            foreach ($policy in $adminPortalPolicies) {
                if ($policy.Conditions.Users.IncludeUsers -contains "All") {
                    $coversAllUsers = $true
                    break
                }
            }
            
            if ($coversAllUsers) {
                $controlResult.Finding = "MFA is required for admin portal access"
                $controlResult.Result = "COMPLIANT"
                $evidence += "`n`nStatus: Comprehensive MFA protection for admin portals"
            }
            else {
                $controlResult.Finding = "MFA is partially required for admin portals"
                $controlResult.Result = "PARTIALLY COMPLIANT"
                $evidence += "`n`nStatus: Some users may access admin portals without MFA"
            }
        }
        else {
            $controlResult.Finding = "MFA is not required for admin portal access"
            $controlResult.Result = "NOT COMPLIANT"
            $evidence += "`n`nStatus: No policies enforce MFA for admin portals"
            $evidence += "`n`nRisks:"
            $evidence += "`n- Administrators can access portals with password only"
            $evidence += "`n- Increased risk of unauthorized admin access"
            $evidence += "`n- Potential for configuration changes by compromised accounts"
        }
        
        $controlResult.Evidence = $evidence
        
        if ($controlResult.Result -ne "COMPLIANT") {
            $controlResult.RemediationSteps = @"
<ol>
    <li>Navigate to Microsoft Entra admin center > Protection > Conditional Access</li>
    <li>Create new policy: "Require MFA for Admin Portals"</li>
    <li>Configure:
        <ul>
            <li>Users: All users</li>
            <li>Cloud apps: Either
                <ul>
                    <li>Select "All cloud apps" (broadest protection)</li>
                    <li>OR select specific admin portals:
                        <ul>
                            <li>Microsoft Azure Management</li>
                            <li>Microsoft 365 Admin Center</li>
                            <li>Exchange Admin Center</li>
                            <li>SharePoint Admin Center</li>
                            <li>Teams Admin Center</li>
                        </ul>
                    </li>
                </ul>
            </li>
            <li>Grant: Require multi-factor authentication</li>
        </ul>
    </li>
    <li>Consider adding additional controls:
        <ul>
            <li>Require compliant device</li>
            <li>Require Hybrid Azure AD joined device</li>
            <li>Require approved client app</li>
        </ul>
    </li>
</ol>
"@
        }
    }
    catch {
        $controlResult.Finding = "Error assessing admin portal MFA: $_"
        $controlResult.Result = "ERROR"
        $controlResult.Evidence = "Error details: $_"
    }
    
    return $controlResult
}

# Execute the control check
Check-AdminPortalMFA