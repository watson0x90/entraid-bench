function Check-TenantCreationRestriction {
    [CmdletBinding()]
    param()

    $controlResult = [PSCustomObject]@{
        Control = "Ensure 'Restrict non-admin users from creating tenants' is set to 'Yes'"
        ControlDescription = "Prevent non-administrative users from creating new Entra ID tenants to avoid shadow IT and unmanaged environments."
        Finding = ""
        Result = ""
        Evidence = ""
        RemediationSteps = ""
        AffectedAccounts = @()
    }

    try {
        # Get authorization policy
        $authPolicy = Get-MgPolicyAuthorizationPolicy
        $defaultUserPermissions = $authPolicy.DefaultUserRolePermissions
        
        $evidence = Format-EvidenceSection -Title "TENANT CREATION RESTRICTION ASSESSMENT" -Content "Assessment Date: $(Get-Date)" -IsHeader
        $evidence += "`n`nCurrent Configuration:"
        $evidence += "`nAllowedToCreateTenants: $($defaultUserPermissions.AllowedToCreateTenants)"
        
        # Check if properly restricted (false means restricted)
        if ($defaultUserPermissions.AllowedToCreateTenants -eq $false) {
            $controlResult.Finding = "Non-admin users are properly restricted from creating tenants"
            $controlResult.Result = "COMPLIANT"
            $evidence += "`n`nStatus: Tenant creation is restricted to administrators only"
        }
        else {
            $controlResult.Finding = "Non-admin users can create new tenants"
            $controlResult.Result = "NOT COMPLIANT"
            $evidence += "`n`nStatus: Any user can create new Entra ID tenants"
            $evidence += "`n`nRisks:"
            $evidence += "`n- Shadow IT environments"
            $evidence += "`n- Unmanaged data storage"
            $evidence += "`n- Compliance violations"
            $evidence += "`n- Budget overruns"
            
            # Get sample of standard users who could create tenants
            $standardUsers = Get-MgUser -Top 20 -Filter "userType eq 'Member'"
            foreach ($user in $standardUsers) {
                $controlResult.AffectedAccounts += [PSCustomObject]@{
                    Name = $user.DisplayName
                    Id = $user.Id
                    Details = "Standard user with tenant creation rights"
                }
            }
        }
        
        $controlResult.Evidence = $evidence
        
        if ($controlResult.Result -ne "COMPLIANT") {
            $controlResult.RemediationSteps = @"
<ol>
    <li>Navigate to Microsoft Entra admin center > Identity > Users > User settings</li>
    <li>Find "Users can create Azure AD tenants"</li>
    <li>Set this option to "No"</li>
    <li>Click Save</li>
    <li>Note: Only Global Administrators will be able to create new tenants after this change</li>
</ol>
"@
        }
    }
    catch {
        $controlResult.Finding = "Error assessing tenant creation restriction: $_"
        $controlResult.Result = "ERROR"
        $controlResult.Evidence = "Error details: $_"
    }
    
    return $controlResult
}

# Execute the control check
Check-TenantCreationRestriction