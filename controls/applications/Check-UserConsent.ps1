function Check-UserConsent {
    [CmdletBinding()]
    param()

    $controlResult = [PSCustomObject]@{
        Control = "Ensure user consent to apps accessing company data on their behalf is not allowed"
        ControlDescription = "Users should not be able to consent to applications accessing company data without administrative approval to prevent data exfiltration."
        Finding = ""
        Result = ""
        Evidence = ""
        RemediationSteps = ""
        AffectedAccounts = @()
    }

    try {
        # Get authorization policy
        $authPolicy = Get-MgPolicyAuthorizationPolicy
        $userRolePermissions = $authPolicy.DefaultUserRolePermissions
        
        $evidence = Format-EvidenceSection -Title "USER CONSENT ASSESSMENT" -Content "Assessment Date: $(Get-Date)" -IsHeader
        
        # Check permission grant policies
        $permissionGrantPolicies = $userRolePermissions.PermissionGrantPoliciesAssigned
        
        $evidence += "`n`nUser Consent Configuration:"
        $evidence += "`nPermission Grant Policies: $($permissionGrantPolicies -join ', ')"
        
        # Check if users can consent
        $allowUserConsent = $false
        
        if ($permissionGrantPolicies -contains "ManagePermissionGrantsForSelf.microsoft-user-default-legacy" -or
            $permissionGrantPolicies -contains "ManagePermissionGrantsForSelf.microsoft-user-default-low") {
            $allowUserConsent = $true
        }
        
        if (-not $allowUserConsent -or $permissionGrantPolicies.Count -eq 0) {
            $controlResult.Finding = "User consent for applications is properly restricted"
            $controlResult.Result = "COMPLIANT"
            $evidence += "`n`nStatus: Users cannot consent to applications"
        }
        else {
            $controlResult.Finding = "Users can consent to applications accessing company data"
            $controlResult.Result = "NOT COMPLIANT"
            $evidence += "`n`nStatus: Users can grant consent to applications"
            $evidence += "`n`nRisks:"
            $evidence += "`n- Malicious apps can trick users into granting access"
            $evidence += "`n- Data exfiltration through consented apps"
            $evidence += "`n- Shadow IT application usage"
            
            # Check for admin consent workflow
            $adminConsentPolicy = Get-MgPolicyAdminConsentRequestPolicy -ErrorAction SilentlyContinue
            if ($adminConsentPolicy -and $adminConsentPolicy.IsEnabled) {
                $evidence += "`n`nMitigation: Admin consent workflow is enabled"
                $controlResult.Result = "PARTIALLY COMPLIANT"
            }
        }
        
        $controlResult.Evidence = $evidence
        
        if ($controlResult.Result -ne "COMPLIANT") {
            $controlResult.RemediationSteps = @"
<ol>
    <li>Navigate to Microsoft Entra admin center > Identity > Applications > Enterprise applications</li>
    <li>Click "Consent and permissions" > "User consent settings"</li>
    <li>Select "Do not allow user consent"</li>
    <li>Enable the admin consent workflow:
        <ul>
            <li>Go to "Admin consent requests"</li>
            <li>Set "Users can request admin consent" to Yes</li>
            <li>Configure reviewers and notifications</li>
        </ul>
    </li>
    <li>Click Save</li>
</ol>
"@
        }
    }
    catch {
        $controlResult.Finding = "Error assessing user consent settings: $_"
        $controlResult.Result = "ERROR"
        $controlResult.Evidence = "Error details: $_"
    }
    
    return $controlResult
}

# Execute the control check
Check-UserConsent