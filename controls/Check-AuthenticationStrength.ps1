function Check-AuthenticationStrength {
    [CmdletBinding()]
    param()

    try {
        $controlTitle = "Ensure 'Phishing-resistant MFA strength' is required for Administrators"
        $controlDescription = "Authentication strength is a Conditional Access control that allows administrators to specify which combination of authentication methods can be used to access a resource. For example, they can make only phishing-resistant authentication methods available to access a sensitive resource. But to access a non-sensitive resource, they can allow less secure multifactor authentication (MFA) combinations, such as password + SMS. Microsoft has 3 built-in authentication strengths. MFA strength, Passwordless MFA strength, and Phishing-resistant MFA strength. Ensure administrator roles are using a CA policy with Phishing-resistant MFA strength."

        # Retrieve all Conditional Access policies
        $policies = Get-MgIdentityConditionalAccessPolicy | Sort-Object DisplayName
        
        # Get all administrator roles for reference
        $adminRoles = Get-MgRoleManagementDirectoryRoleDefinition | Where-Object { 
            $_.IsBuiltIn -eq $true -and $_.DisplayName -match "Administrator"
        } | Select-Object DisplayName, Id
        
        $evidence = "Administrator roles requiring phishing-resistant MFA protection:`n"
        $phishingResistantPolicies = @()
        
        foreach ($policy in $policies) {
            $policyDetails = Get-MgIdentityConditionalAccessPolicy -ConditionalAccessPolicyId $policy.Id
            $authenticationStrength = $policy.GrantControls.AuthenticationStrength
            
            # Check if policy is for administrators and uses phishing-resistant MFA
            if ($authenticationStrength.id -eq "00000000-0000-0000-0000-000000000004") {
                $phishingResistantPolicies += $policy
                
                $evidence += "`n- Policy Name: $($policy.DisplayName)"
                $evidence += "`n  State: $($policy.State)"
                $evidence += "`n  Authentication Strength: Phishing-resistant MFA"
                
                # Check if policy applies to admin roles
                if ($policyDetails.Conditions.Users.IncludeRoles) {
                    $evidence += "`n  Applied to roles:"
                    foreach ($roleId in $policyDetails.Conditions.Users.IncludeRoles) {
                        $roleName = ($adminRoles | Where-Object { $_.Id -eq $roleId }).DisplayName
                        $evidence += "`n    - $roleName"
                    }
                }
                
                $evidence += "`n"
            }
        }

        # Get admin roles NOT covered by phishing-resistant MFA policies
        $coveredRoleIds = @()
        foreach ($policy in $phishingResistantPolicies) {
            $policyDetails = Get-MgIdentityConditionalAccessPolicy -ConditionalAccessPolicyId $policy.Id
            if ($policyDetails.Conditions.Users.IncludeRoles) {
                $coveredRoleIds += $policyDetails.Conditions.Users.IncludeRoles
            }
        }
        
        $uncoveredAdminRoles = $adminRoles | Where-Object { $coveredRoleIds -notcontains $_.Id }
        
        if ($phishingResistantPolicies.Count -gt 0) {
            # Check if ALL admin roles are covered
            if ($uncoveredAdminRoles.Count -eq 0) {
                $controlFinding = "Phishing-resistant MFA strength is enabled for all administrators."
                $controlResult = "COMPLIANT"
            } else {
                $controlFinding = "Phishing-resistant MFA strength is enabled for some administrators, but not all critical roles are covered."
                $controlResult = "NOT COMPLIANT"
                
                $evidence += "`nAdmin roles NOT protected by phishing-resistant MFA policies:`n"
                foreach ($role in $uncoveredAdminRoles) {
                    $evidence += "`n- $($role.DisplayName)"
                }
                
                # Create affected accounts
                $affectedAccounts = @()
                foreach ($role in $uncoveredAdminRoles) {
                    try {
                        # Use regular role assignments instead of PIM assignments
                        $roleDefinition = Get-MgRoleManagementDirectoryRoleDefinition -UnifiedRoleDefinitionId $role.Id
                        if ($roleDefinition) {
                            $roleAssignments = Get-MgRoleManagementDirectoryRoleAssignment -Filter "roleDefinitionId eq '$($role.Id)'"
                            
                            foreach ($assignment in $roleAssignments) {
                                try {
                                    $user = Get-MgUser -UserId $assignment.PrincipalId -ErrorAction SilentlyContinue
                                    if ($user) {
                                        $affectedAccounts += [PSCustomObject]@{
                                            Name = $user.DisplayName
                                            Id = $user.Id
                                            Details = "Role: $($role.DisplayName)"
                                        }
                                    } else {
                                        $sp = Get-MgServicePrincipal -ServicePrincipalId $assignment.PrincipalId -ErrorAction SilentlyContinue
                                        if ($sp) {
                                            $affectedAccounts += [PSCustomObject]@{
                                                Name = $sp.DisplayName
                                                Id = $sp.Id
                                                Details = "Service Principal with Role: $($role.DisplayName)"
                                            }
                                        }
                                    }
                                } catch {
                                    # Skip if can't resolve
                                }
                            }
                        }
                    } catch {
                        # Skip if can't get role assignments
                    }
                }
            }
        } else {
            $controlFinding = "No policies with phishing-resistant MFA strength found for administrators."
            $controlResult = "NOT COMPLIANT"
            
            $evidence = "No Conditional Access policies were found that enforce phishing-resistant MFA for administrator roles.`n`n"
            $evidence += "List of administrator roles that should be protected:`n"
            
            foreach ($role in $adminRoles) {
                $evidence += "- $($role.DisplayName)`n"
            }
            
            # Create affected accounts for all admin roles
            $affectedAccounts = @()
            foreach ($role in $adminRoles) {
                try {
                    # Use regular role assignments instead of PIM assignments
                    $roleDefinition = Get-MgRoleManagementDirectoryRoleDefinition -UnifiedRoleDefinitionId $role.Id
                    if ($roleDefinition) {
                        $roleAssignments = Get-MgRoleManagementDirectoryRoleAssignment -Filter "roleDefinitionId eq '$($role.Id)'"
                        
                        foreach ($assignment in $roleAssignments) {
                            try {
                                $user = Get-MgUser -UserId $assignment.PrincipalId -ErrorAction SilentlyContinue
                                if ($user) {
                                    $affectedAccounts += [PSCustomObject]@{
                                        Name = $user.DisplayName
                                        Id = $user.Id
                                        Details = "Role: $($role.DisplayName)"
                                    }
                                } else {
                                    $sp = Get-MgServicePrincipal -ServicePrincipalId $assignment.PrincipalId -ErrorAction SilentlyContinue
                                    if ($sp) {
                                        $affectedAccounts += [PSCustomObject]@{
                                            Name = $sp.DisplayName
                                            Id = $sp.Id
                                            Details = "Service Principal with Role: $($role.DisplayName)"
                                        }
                                    }
                                }
                            } catch {
                                # Skip if can't resolve
                            }
                        }
                    }
                } catch {
                    # Skip if can't get role assignments
                }
            }
        }
        
        # Add remediation steps for non-compliant findings
        $remediationSteps = $null
        if ($controlResult -eq "NOT COMPLIANT") {
            $remediationSteps = @"
<ol>
    <li>Navigate to the Microsoft Entra admin center at <a href="https://entra.microsoft.com" target="_blank">https://entra.microsoft.com</a></li>
    <li>Go to <strong>Protection > Conditional Access</strong></li>
    <li>Create a new Conditional Access policy with the following settings:
        <ul>
            <li><strong>Name</strong>: Admin Phishing-Resistant MFA Policy</li>
            <li><strong>Users</strong>: Include all directory roles with "Administrator" in the name</li>
            <li><strong>Cloud apps</strong>: All cloud apps</li>
            <li><strong>Conditions</strong>: Configure as needed for your environment</li>
            <li><strong>Grant</strong>: Require authentication strength, select "Phishing-resistant MFA"</li>
        </ul>
    </li>
    <li>Set the policy to "On" and save</li>
    <li>Monitor the policy in the Sign-in logs to ensure it's working as expected</li>
</ol>
"@
        }

        return [PSCustomObject]@{
            Control = $controlTitle
            ControlDescription = $controlDescription
            Finding = $controlFinding
            Result = $controlResult
            Evidence = $evidence
            AffectedAccounts = $affectedAccounts
            RemediationSteps = $remediationSteps
        }
    }
    catch {
        Write-Error "An error occurred: $_"
    }
}

# Call the function to check the settings
Check-AuthenticationStrength