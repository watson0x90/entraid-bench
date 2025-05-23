function Check-AzureManagementRestriction {
    [CmdletBinding()]
    param()

    $controlResult = [PSCustomObject]@{
        Control = "Ensure 'Microsoft Azure Management' is limited to administrative roles"
        ControlDescription = "Access to Azure Management should be restricted to administrative roles only to prevent unauthorized access to Azure resources."
        Finding = ""
        Result = ""
        Evidence = ""
        RemediationSteps = ""
        AffectedAccounts = @()
    }

    try {
        $evidence = Format-EvidenceSection -Title "AZURE MANAGEMENT RESTRICTION ASSESSMENT" -Content "Assessment Date: $(Get-Date)" -IsHeader
        
        # Azure Management application ID
        $azureManagementAppId = "797f4846-ba00-4fd7-ba43-dac1f8f63013"
        
        # Get Conditional Access policies
        $policies = Get-MgIdentityConditionalAccessPolicy
        $mgmtPolicies = @()
        
        foreach ($policy in $policies) {
            if ($policy.State -eq "enabled") {
                # Check if policy targets Azure Management
                if ($policy.Conditions.Applications.IncludeApplications -contains $azureManagementAppId -or
                    $policy.Conditions.Applications.IncludeApplications -contains "All") {
                    
                    $mgmtPolicies += $policy
                    $evidence += "`n`nAzure Management Policy Found: $($policy.DisplayName)"
                    $evidence += "`nState: $($policy.State)"
                    
                    # Check if it restricts to admin roles
                    if ($policy.Conditions.Users.IncludeRoles) {
                        $evidence += "`nRestricted to admin roles: Yes"
                        $evidence += "`nNumber of roles: $($policy.Conditions.Users.IncludeRoles.Count)"
                    }
                    elseif ($policy.Conditions.Users.IncludeUsers -contains "All") {
                        $evidence += "`nWARNING: Policy applies to all users"
                    }
                }
            }
        }
        
        # Check for proper restrictions
        $hasProperRestriction = $false
        foreach ($policy in $mgmtPolicies) {
            if ($policy.Conditions.Users.IncludeRoles -and 
                $policy.GrantControls.BuiltInControls -contains "block") {
                # Policy blocks non-admin access
                $hasProperRestriction = $true
            }
            elseif ($policy.Conditions.Users.ExcludeRoles -and
                   $policy.Conditions.Users.IncludeUsers -contains "All") {
                # Policy applies to all except admin roles
                $hasProperRestriction = $true
            }
        }
        
        if ($hasProperRestriction) {
            $controlResult.Finding = "Azure Management is properly restricted to administrative roles"
            $controlResult.Result = "COMPLIANT"
            $evidence += "`n`nStatus: Access controls properly configured"
        }
        elseif ($mgmtPolicies.Count -gt 0) {
            $controlResult.Finding = "Azure Management has some restrictions but may not be properly limited"
            $controlResult.Result = "PARTIALLY COMPLIANT"
            $evidence += "`n`nStatus: Policies exist but configuration needs review"
        }
        else {
            $controlResult.Finding = "Azure Management is not restricted to administrative roles"
            $controlResult.Result = "NOT COMPLIANT"
            $evidence += "`n`nStatus: No restrictions found - any user can access Azure Management"
        }
        
        $controlResult.Evidence = $evidence
        
        if ($controlResult.Result -ne "COMPLIANT") {
            $controlResult.RemediationSteps = @"
<ol>
    <li>Navigate to Microsoft Entra admin center > Protection > Conditional Access</li>
    <li>Create new policy: "Restrict Azure Management to Admins"</li>
    <li>Configure:
        <ul>
            <li>Users: Include "All users", Exclude "Directory roles" (select all admin roles)</li>
            <li>Cloud apps: Select "Microsoft Azure Management"</li>
            <li>Access controls > Grant: Block access</li>
        </ul>
    </li>
    <li>Alternative approach:
        <ul>
            <li>Users: Include "Directory roles" (select admin roles only)</li>
            <li>Cloud apps: Microsoft Azure Management</li>
            <li>Grant: Require MFA + compliant device</li>
        </ul>
    </li>
    <li>Test in report-only mode first</li>
</ol>
"@
        }
    }
    catch {
        $controlResult.Finding = "Error assessing Azure Management restrictions: $_"
        $controlResult.Result = "ERROR"
        $controlResult.Evidence = "Error details: $_"
    }
    
    return $controlResult
}

# Execute the control check
Check-AzureManagementRestriction