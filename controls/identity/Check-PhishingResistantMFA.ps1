function Check-PhishingResistantMFA {
    [CmdletBinding()]
    param()

    $controlResult = [PSCustomObject]@{
        Control = "Ensure 'Phishing-resistant MFA strength' is required for Administrators"
        ControlDescription = "Administrators should be required to use phishing-resistant authentication methods (FIDO2, Windows Hello, Certificate-based) to prevent MFA bypass attacks."
        Finding = ""
        Result = ""
        Evidence = ""
        RemediationSteps = ""
        AffectedAccounts = @()
    }

    try {
        # Get all Conditional Access policies
        $policies = Get-MgIdentityConditionalAccessPolicy
        
        # Get administrator role definitions
        $adminRoles = Get-MgRoleManagementDirectoryRoleDefinition | Where-Object { 
            $_.IsBuiltIn -eq $true -and $_.DisplayName -match "Administrator"
        }
        
        $evidence = Format-EvidenceSection -Title "PHISHING-RESISTANT MFA ASSESSMENT" -Content "Assessment Date: $(Get-Date)" -IsHeader
        $evidence += "`n`nAdministrator Roles Found: $($adminRoles.Count)"
        
        # Look for policies with phishing-resistant MFA
        $phishingResistantPolicies = @()
        
        foreach ($policy in $policies) {
            if ($policy.State -eq "enabled" -and 
                $policy.GrantControls.AuthenticationStrength.Id -eq "00000000-0000-0000-0000-000000000004") {
                
                $phishingResistantPolicies += $policy
                $evidence += "`n`nPhishing-Resistant Policy Found: $($policy.DisplayName)"
                
                # Check which roles are covered
                if ($policy.Conditions.Users.IncludeRoles) {
                    $evidence += "`nCovers roles:"
                    foreach ($roleId in $policy.Conditions.Users.IncludeRoles) {
                        $roleName = ($adminRoles | Where-Object { $_.Id -eq $roleId }).DisplayName
                        $evidence += "`n  - $roleName"
                    }
                }
            }
        }
        
        # Determine which admin roles are NOT covered
        $coveredRoleIds = @()
        foreach ($policy in $phishingResistantPolicies) {
            $policyDetails = Get-MgIdentityConditionalAccessPolicy -ConditionalAccessPolicyId $policy.Id
            if ($policyDetails.Conditions.Users.IncludeRoles) {
                $coveredRoleIds += $policyDetails.Conditions.Users.IncludeRoles
            }
        }
        
        $uncoveredRoles = $adminRoles | Where-Object { $coveredRoleIds -notcontains $_.Id }
        
        if ($phishingResistantPolicies.Count -gt 0 -and $uncoveredRoles.Count -eq 0) {
            $controlResult.Finding = "All administrator roles are protected with phishing-resistant MFA"
            $controlResult.Result = "COMPLIANT"
        }
        elseif ($phishingResistantPolicies.Count -gt 0) {
            $controlResult.Finding = "Some administrator roles lack phishing-resistant MFA protection"
            $controlResult.Result = "PARTIALLY COMPLIANT"
            
            # Get affected accounts
            foreach ($role in $uncoveredRoles) {
                $roleAssignments = Get-MgRoleManagementDirectoryRoleAssignment -Filter "roleDefinitionId eq '$($role.Id)'"
                foreach ($assignment in $roleAssignments) {
                    try {
                        $user = Get-MgUser -UserId $assignment.PrincipalId -ErrorAction SilentlyContinue
                        if ($user) {
                            $controlResult.AffectedAccounts += [PSCustomObject]@{
                                Name = $user.DisplayName
                                Id = $user.Id
                                Details = "Admin role without phishing-resistant MFA: $($role.DisplayName)"
                            }
                        }
                    } catch {}
                }
            }
        }
        else {
            $controlResult.Finding = "No phishing-resistant MFA policies found for administrators"
            $controlResult.Result = "NOT COMPLIANT"
        }
        
        $controlResult.Evidence = $evidence
        
        if ($controlResult.Result -ne "COMPLIANT") {
            $controlResult.RemediationSteps = @"
<ol>
    <li>Navigate to Microsoft Entra admin center > Protection > Conditional Access</li>
    <li>Create a new policy or modify existing ones</li>
    <li>Under Users, include all administrator directory roles</li>
    <li>Under Grant, select "Require authentication strength"</li>
    <li>Choose "Phishing-resistant MFA"</li>
    <li>Enable the policy after testing in report-only mode</li>
</ol>
"@
        }
    }
    catch {
        $controlResult.Finding = "Error assessing phishing-resistant MFA: $_"
        $controlResult.Result = "ERROR"
        $controlResult.Evidence = "Error details: $_"
    }
    
    return $controlResult
}

# Execute the control check
Check-PhishingResistantMFA