function Check-CustomSubscriptionRoles {
    [CmdletBinding()]
    param()

    $controlResult = [PSCustomObject]@{
        Control = "Ensure that no custom subscription administrator roles exist"
        ControlDescription = "Custom subscription administrator roles should be avoided. Use built-in roles following least privilege principles instead."
        Finding = ""
        Result = ""
        Evidence = ""
        RemediationSteps = ""
        AffectedAccounts = @()
    }

    try {
        $evidence = Format-EvidenceSection -Title "CUSTOM SUBSCRIPTION ROLES ASSESSMENT" -Content "Assessment Date: $(Get-Date)" -IsHeader
        
        # Note: This is primarily an Azure RBAC concern, not Entra ID
        $evidence += "`nNote: Custom subscription roles are Azure RBAC concepts"
        $evidence += "`nChecking for custom Entra ID roles that might grant excessive permissions..."
        
        # Get custom role definitions in Entra ID
        $customRoles = Get-MgRoleManagementDirectoryRoleDefinition | Where-Object { 
            $_.IsBuiltIn -eq $false
        }
        
        $evidence += "`n`nCustom Entra ID Roles Found: $($customRoles.Count)"
        
        if ($customRoles.Count -gt 0) {
            $excessiveRoles = @()
            
            foreach ($role in $customRoles) {
                $evidence += "`n`nCustom Role: $($role.DisplayName)"
                $evidence += "`nDescription: $($role.Description)"
                
                # Check for excessive permissions
                $hasWildcard = $false
                $permissions = $role.RolePermissions.AllowedResourceActions
                
                foreach ($permission in $permissions) {
                    if ($permission -like "*.*" -or $permission -eq "*") {
                        $hasWildcard = $true
                        $evidence += "`nWARNING: Wildcard permission found: $permission"
                    }
                }
                
                if ($hasWildcard) {
                    $excessiveRoles += $role
                }
                
                # Check assignments
                $assignments = Get-MgRoleManagementDirectoryRoleAssignment -Filter "roleDefinitionId eq '$($role.Id)'"
                $evidence += "`nAssignments: $($assignments.Count)"
                
                foreach ($assignment in $assignments) {
                    try {
                        $user = Get-MgUser -UserId $assignment.PrincipalId -ErrorAction SilentlyContinue
                        if ($user) {
                            $controlResult.AffectedAccounts += [PSCustomObject]@{
                                Name = $user.DisplayName
                                Id = $user.Id
                                Details = "Assigned custom role: $($role.DisplayName)"
                            }
                        }
                    } catch {}
                }
            }
            
            if ($excessiveRoles.Count -gt 0) {
                $controlResult.Finding = "Custom roles with excessive permissions found"
                $controlResult.Result = "NOT COMPLIANT"
                $evidence += "`n`nStatus: $($excessiveRoles.Count) custom roles have wildcard permissions"
            }
            else {
                $controlResult.Finding = "Custom roles exist but appear to follow least privilege"
                $controlResult.Result = "PARTIALLY COMPLIANT"
                $evidence += "`n`nStatus: Custom roles found but no wildcard permissions detected"
            }
        }
        else {
            $controlResult.Finding = "No custom roles found in Entra ID"
            $controlResult.Result = "COMPLIANT"
            $evidence += "`n`nStatus: Only built-in roles are in use"
        }
        
        $controlResult.Evidence = $evidence
        
        if ($controlResult.Result -ne "COMPLIANT") {
            $controlResult.RemediationSteps = @"
<ol>
    <li>Review all custom roles:
        <ul>
            <li>Navigate to Entra admin center > Identity > Roles and administrators</li>
            <li>Filter by "Custom" roles</li>
            <li>Review permissions for each custom role</li>
        </ul>
    </li>
    <li>For each custom role:
        <ul>
            <li>Determine if a built-in role can meet the requirements</li>
            <li>Remove wildcard permissions</li>
            <li>Follow least privilege principles</li>
        </ul>
    </li>
    <li>For Azure subscription roles:
        <ul>
            <li>Use Azure portal > Subscriptions > Access control (IAM)</li>
            <li>Review custom roles at subscription scope</li>
            <li>Replace with built-in roles where possible</li>
        </ul>
    </li>
    <li>Document business justification for any remaining custom roles</li>
</ol>
"@
        }
    }
    catch {
        $controlResult.Finding = "Error assessing custom subscription roles: $_"
        $controlResult.Result = "ERROR"
        $controlResult.Evidence = "Error details: $_"
    }
    
    return $controlResult
}

# Execute the control check
Check-CustomSubscriptionRoles