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
        # Ensure we have a valid connection
        if (-not (Test-GraphConnection)) {
            throw "No valid Graph connection"
        }
        
        $evidence = Format-EvidenceSection -Title "ADMIN MFA ASSESSMENT" -Content "Assessment Date: $(Get-Date)" -IsHeader
        
        # Get all administrative roles with error handling
        Write-Verbose "Getting administrative roles..."
        $adminRoles = @()
        try {
            # Get role definitions without -Top parameter (causes issues with some endpoints)
            $allRoles = Get-MgRoleManagementDirectoryRoleDefinition -ErrorAction Stop
            $adminRoles = $allRoles | Where-Object { 
                $_.IsBuiltIn -eq $true -and 
                ($_.DisplayName -match "Administrator" -or $_.DisplayName -match "Admin")
            }
        }
        catch {
            Write-Warning "Failed to get role definitions: $_"
            # Try alternative approach using activated directory roles
            try {
                $allDirectoryRoles = Get-MgDirectoryRole -ErrorAction Stop
                $adminRoles = $allDirectoryRoles | Where-Object {
                    $_.DisplayName -match "Administrator" -or $_.DisplayName -match "Admin"
                }
                Write-Verbose "Using activated directory roles as fallback"
            }
            catch {
                throw "Unable to retrieve administrative roles: $_"
            }
        }
        
        $evidence += "`nAdministrative Roles Found: $($adminRoles.Count)"
        
        if ($adminRoles.Count -eq 0) {
            $controlResult.Finding = "No administrative roles found (unexpected)"
            $controlResult.Result = "ERROR"
            $controlResult.Evidence = $evidence + "`n`nError: No admin roles detected. This is unexpected."
            return $controlResult
        }
        
        # Check for admin-specific MFA policies
        Write-Verbose "Checking Conditional Access policies..."
        $policies = @()
        $adminMfaPolicies = @()
        
        try {
            # Get all CA policies (no pagination issues typically)
            $policies = Get-MgIdentityConditionalAccessPolicy -ErrorAction Stop
        }
        catch {
            if ($_.Exception.Message -match "Premium|license|P1|P2|InvalidLicense") {
                Write-Warning "Conditional Access requires P1/P2 license"
                $evidence += "`n`nNote: Conditional Access requires Entra ID P1 or P2 license"
            }
            elseif ($_.Exception.Message -match "Forbidden|403") {
                Write-Warning "Insufficient permissions for Conditional Access: $_"
                $evidence += "`n`nNote: Unable to check Conditional Access policies (insufficient permissions)"
            }
            else {
                Write-Warning "Failed to get Conditional Access policies: $_"
            }
        }
        
        if ($policies.Count -gt 0) {
            foreach ($policy in $policies) {
                if ($policy.State -eq "enabled" -and 
                    $policy.GrantControls.BuiltInControls -contains "mfa" -and
                    $policy.Conditions.Users.IncludeRoles) {
                    
                    $adminMfaPolicies += $policy
                    $evidence += "`n`nAdmin MFA Policy Found: $($policy.DisplayName)"
                    $evidence += "`nTarget Roles: $($policy.Conditions.Users.IncludeRoles.Count) roles"
                }
            }
        }
        
        # Check Security Defaults as alternative
        Write-Verbose "Checking Security Defaults..."
        $securityDefaultsEnabled = $false
        try {
            $securityDefaults = Get-MgPolicyIdentitySecurityDefaultEnforcementPolicy -ErrorAction Stop
            if ($securityDefaults.IsEnabled) {
                $securityDefaultsEnabled = $true
                $evidence += "`n`nSecurity Defaults: ENABLED (enforces MFA for all admins)"
            }
        }
        catch {
            Write-Verbose "Unable to check Security Defaults: $_"
        }
        
        # Get admin users and check their MFA status
        Write-Verbose "Checking admin users..."
        $adminsWithoutMFA = @()
        $totalAdmins = 0
        
        foreach ($role in $adminRoles | Select-Object -First 5) { # Limit to avoid throttling
            try {
                # Get role assignments
                $roleAssignments = @()
                if ($role.Id) {
                    $roleAssignments = Get-MgRoleManagementDirectoryRoleAssignment -Filter "roleDefinitionId eq '$($role.Id)'" -ErrorAction Stop
                }
                
                foreach ($assignment in $roleAssignments) {
                    $totalAdmins++
                    try {
                        $user = Get-MgUser -UserId $assignment.PrincipalId -ErrorAction Stop
                        
                        # Check MFA status (simplified check)
                        $hasMfa = $false
                        try {
                            $authMethods = Get-MgUserAuthenticationMethod -UserId $user.Id -ErrorAction Stop
                            $hasMfa = ($authMethods.Count -gt 1) # Simple check: more than just password
                        }
                        catch {
                            # Can't check individual MFA status
                            Write-Verbose "Unable to check MFA for user $($user.DisplayName)"
                        }
                        
                        if (-not $hasMfa -and -not $securityDefaultsEnabled) {
                            $adminsWithoutMFA += [PSCustomObject]@{
                                User = $user
                                Role = $role.DisplayName
                            }
                        }
                    }
                    catch {
                        Write-Verbose "Error processing user assignment: $_"
                    }
                }
            }
            catch {
                Write-Verbose "Error getting role assignments for $($role.DisplayName): $_"
            }
        }
        
        $evidence += "`n`nTotal Admin Users Checked: $totalAdmins"
        
        # Determine compliance
        if ($securityDefaultsEnabled) {
            $controlResult.Finding = "Security Defaults enforce MFA for all administrators"
            $controlResult.Result = "COMPLIANT"
            $evidence += "`n`nStatus: All admins protected by Security Defaults"
        }
        elseif ($adminMfaPolicies.Count -gt 0 -and $adminsWithoutMFA.Count -eq 0) {
            $controlResult.Finding = "Conditional Access policies enforce MFA for administrators"
            $controlResult.Result = "COMPLIANT"
            $evidence += "`n`nStatus: Admin MFA enforced via Conditional Access"
        }
        elseif ($adminMfaPolicies.Count -gt 0) {
            $controlResult.Finding = "Some MFA policies exist but coverage may be incomplete"
            $controlResult.Result = "PARTIALLY COMPLIANT"
            $evidence += "`n`nStatus: Partial MFA coverage for admins"
            
            if ($adminsWithoutMFA.Count -gt 0) {
                $evidence += "`nAdmins potentially without MFA: $($adminsWithoutMFA.Count)"
                
                foreach ($admin in $adminsWithoutMFA | Select-Object -First 10) {
                    $controlResult.AffectedAccounts += [PSCustomObject]@{
                        Name = $admin.User.DisplayName
                        Id = $admin.User.Id
                        Details = "Admin role without confirmed MFA: $($admin.Role)"
                    }
                }
            }
        }
        else {
            $controlResult.Finding = "No MFA enforcement found for administrators"
            $controlResult.Result = "NOT COMPLIANT"
            $evidence += "`n`nStatus: Administrators are not required to use MFA"
            
            if ($policies.Count -eq 0) {
                $evidence += "`nNote: No Conditional Access policies found (may require P1/P2 license)"
            }
        }
        
        $controlResult.Evidence = $evidence
        
        if ($controlResult.Result -ne "COMPLIANT") {
            $controlResult.RemediationSteps = @"
<ol>
    <li>Choose one of these approaches:</li>
    <li>Option A - Enable Security Defaults (free, simple):
        <ul>
            <li>Navigate to Microsoft Entra admin center > Properties</li>
            <li>Click "Manage security defaults"</li>
            <li>Set to "Enabled"</li>
        </ul>
    </li>
    <li>Option B - Create Conditional Access policy (requires P1/P2):
        <ul>
            <li>Navigate to Protection > Conditional Access</li>
            <li>Create new policy: "Require MFA for administrators"</li>
            <li>Users: Select "Directory roles" and include all admin roles</li>
            <li>Cloud apps: All cloud apps</li>
            <li>Grant: Require multifactor authentication</li>
        </ul>
    </li>
</ol>
"@
        }
    }
    catch {
        $controlResult.Finding = "Error assessing admin MFA"
        $controlResult.Result = "ERROR"
        $controlResult.Evidence = "Error details: $_`n`nThis may be due to insufficient permissions or API limitations."
        $controlResult.RemediationSteps = "Ensure the account has appropriate permissions to read role assignments and user authentication methods."
    }
    
    return $controlResult
}

# Execute the control check
Check-AdminMFA