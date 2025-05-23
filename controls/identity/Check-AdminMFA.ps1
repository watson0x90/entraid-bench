function Check-AdminMFA {
    [CmdletBinding()]
    param()

    $controlResult = [PSCustomObject]@{
        Control = "Ensure multifactor authentication is enabled for all users in administrative roles"
        ControlDescription = "All administrative role holders must have MFA enabled to protect privileged access (CIS 6.1.2)"
        Finding = ""
        Result = ""
        Evidence = ""
        RemediationSteps = ""
        AffectedAccounts = @()
    }

    try {
        $evidence = Format-EvidenceSection -Title "ADMIN MFA ASSESSMENT" -Content "Assessment Date: $(Get-Date)" -IsHeader
        
        # Get all administrative roles
        $adminRoles = Get-MgRoleManagementDirectoryRoleDefinition | Where-Object { 
            $_.IsBuiltIn -eq $true -and 
            ($_.DisplayName -match "Administrator" -or $_.DisplayName -match "Admin")
        }
        
        $evidence += "`nAdministrative Roles Found: $($adminRoles.Count)"
        
        # Check for admin-specific MFA policies
        $policies = Get-MgIdentityConditionalAccessPolicy
        $adminMfaPolicies = @()
        
        foreach ($policy in $policies) {
            if ($policy.State -eq "enabled" -and 
                $policy.GrantControls.BuiltInControls -contains "mfa" -and
                $policy.Conditions.Users.IncludeRoles) {
                
                $adminMfaPolicies += $policy
                $evidence += "`n`nAdmin MFA Policy Found: $($policy.DisplayName)"
                $evidence += "`nTarget Roles: $($policy.Conditions.Users.IncludeRoles.Count) roles"
            }
        }
        
        # Check coverage
        $coveredRoleIds = @()
        foreach ($policy in $adminMfaPolicies) {
            $coveredRoleIds += $policy.Conditions.Users.IncludeRoles
        }
        $coveredRoleIds = $coveredRoleIds | Select-Object -Unique
        
        $uncoveredRoles = $adminRoles | Where-Object { $coveredRoleIds -notcontains $_.Id }
        
        # Get admins without MFA
        $adminsWithoutMFA = @()
        foreach ($role in $adminRoles) {
            $roleAssignments = Get-MgRoleManagementDirectoryRoleAssignment -Filter "roleDefinitionId eq '$($role.Id)'"
            
            foreach ($assignment in $roleAssignments) {
                try {
                    $user = Get-MgUser -UserId $assignment.PrincipalId -ErrorAction SilentlyContinue
                    if ($user) {
                        $authMethods = Get-MgUserAuthenticationMethod -UserId $user.Id
                        $mfaMethods = $authMethods | Where-Object { 
                            $_.AdditionalProperties.'@odata.type' -match 'phone|fido2|windowsHello|microsoftAuthenticator'
                        }
                        
                        if ($mfaMethods.Count -eq 0) {
                            $adminsWithoutMFA += [PSCustomObject]@{
                                User = $user
                                Role = $role.DisplayName
                            }
                        }
                    }
                } catch {}
            }
        }
        
        if ($adminMfaPolicies.Count -gt 0 -and $uncoveredRoles.Count -eq 0) {
            $controlResult.Finding = "All administrative roles have MFA requirements"
            $controlResult.Result = "COMPLIANT"
            $evidence += "`n`nStatus: Comprehensive MFA coverage for all admin roles"
        }
        elseif ($adminsWithoutMFA.Count -gt 0) {
            $controlResult.Finding = "Some administrators do not have MFA configured"
            $controlResult.Result = "NOT COMPLIANT"
            $evidence += "`n`nAdmins without MFA: $($adminsWithoutMFA.Count)"
            
            foreach ($admin in $adminsWithoutMFA | Select-Object -First 20) {
                $controlResult.AffectedAccounts += [PSCustomObject]@{
                    Name = $admin.User.DisplayName
                    Id = $admin.User.Id
                    Details = "Admin role without MFA: $($admin.Role)"
                }
            }
        }
        else {
            $controlResult.Finding = "Admin MFA policies exist but may not cover all roles"
            $controlResult.Result = "PARTIALLY COMPLIANT"
            $evidence += "`n`nUncovered admin roles: $($uncoveredRoles.Count)"
        }
        
        $controlResult.Evidence = $evidence
        
        if ($controlResult.Result -ne "COMPLIANT") {
            $controlResult.RemediationSteps = @"
<ol>
    <li>Navigate to Microsoft Entra admin center > Protection > Conditional Access</li>
    <li>Create new policy: "Require MFA for all administrators"</li>
    <li>Configure:
        <ul>
            <li>Users: Select "Directory roles" and include all administrative roles</li>
            <li>Cloud apps: All cloud apps</li>
            <li>Grant: Require multifactor authentication</li>
        </ul>
    </li>
    <li>For admins without MFA:
        <ul>
            <li>Require immediate MFA registration</li>
            <li>Consider using phishing-resistant methods for admins</li>
        </ul>
    </li>
</ol>
"@
        }
    }
    catch {
        $controlResult.Finding = "Error assessing admin MFA: $_"
        $controlResult.Result = "ERROR"
        $controlResult.Evidence = "Error details: $_"
    }
    
    return $controlResult
}

# Execute the control check
Check-AdminMFA