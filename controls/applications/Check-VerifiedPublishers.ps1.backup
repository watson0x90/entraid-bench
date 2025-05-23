function Check-VerifiedPublishers {
    [CmdletBinding()]
    param()

    $controlResult = [PSCustomObject]@{
        Control = "Ensure that 'User consent for applications' is set to 'Allow for verified publishers'"
        ControlDescription = "If user consent is allowed, it should be restricted to applications from verified publishers only."
        Finding = ""
        Result = ""
        Evidence = ""
        RemediationSteps = ""
        AffectedAccounts = @()
    }

    try {
        $evidence = Format-EvidenceSection -Title "VERIFIED PUBLISHERS ASSESSMENT" -Content "Assessment Date: $(Get-Date)" -IsHeader
        
        # Get authorization policy
        $authPolicy = Get-MgPolicyAuthorizationPolicy
        $defaultUserPermissions = $authPolicy.DefaultUserRolePermissions
        
        # Check permission grant policies
        $permissionGrantPolicies = $defaultUserPermissions.PermissionGrantPoliciesAssigned
        
        $evidence += "`nUser Consent Configuration:"
        $evidence += "`nPermission Grant Policies: $($permissionGrantPolicies -join ', ')"
        
        # Check the specific policy configuration
        $allowsUserConsent = $false
        $requiresVerifiedPublisher = $false
        
        if ($permissionGrantPolicies -contains "ManagePermissionGrantsForSelf.microsoft-user-default-low") {
            $allowsUserConsent = $true
            $requiresVerifiedPublisher = $true
            $evidence += "`n`nConsent Policy: Allow user consent for apps from verified publishers (low risk)"
        }
        elseif ($permissionGrantPolicies -contains "ManagePermissionGrantsForSelf.microsoft-user-default-legacy") {
            $allowsUserConsent = $true
            $requiresVerifiedPublisher = $false
            $evidence += "`n`nConsent Policy: Allow user consent for all apps (legacy - high risk)"
        }
        elseif ($permissionGrantPolicies.Count -eq 0) {
            $allowsUserConsent = $false
            $evidence += "`n`nConsent Policy: User consent is completely blocked"
        }
        
        # Get apps without verified publishers
        $apps = Get-MgServicePrincipal -Top 100 -Property DisplayName,AppId,PublisherName,VerifiedPublisher
        $unverifiedApps = $apps | Where-Object { 
            $_.VerifiedPublisher.VerifiedPublisherId -eq $null -and 
            $_.PublisherName -ne "Microsoft Corporation"
        }
        
        $evidence += "`n`nApplication Publisher Analysis:"
        $evidence += "`nTotal Applications: $($apps.Count)"
        $evidence += "`nUnverified Publisher Apps: $($unverifiedApps.Count)"
        
        # Determine compliance
        if (-not $allowsUserConsent) {
            $controlResult.Finding = "User consent is completely blocked (more restrictive than verified publishers only)"
            $controlResult.Result = "COMPLIANT"
            $evidence += "`n`nStatus: User consent is disabled entirely"
        }
        elseif ($requiresVerifiedPublisher) {
            $controlResult.Finding = "User consent is restricted to verified publishers"
            $controlResult.Result = "COMPLIANT"
            $evidence += "`n`nStatus: Users can only consent to apps from verified publishers"
        }
        else {
            $controlResult.Finding = "User consent is not restricted to verified publishers"
            $controlResult.Result = "NOT COMPLIANT"
            $evidence += "`n`nStatus: Users can consent to any application"
            $evidence += "`n`nRisks:"
            $evidence += "`n- Users can grant permissions to unverified apps"
            $evidence += "`n- Increased phishing risk"
            $evidence += "`n- Potential data exfiltration"
            
            # List unverified apps
            if ($unverifiedApps.Count -gt 0) {
                $evidence += "`n`nUnverified Applications:"
                foreach ($app in $unverifiedApps | Select-Object -First 10) {
                    $evidence += "`n- $($app.DisplayName)"
                    $evidence += "`n  Publisher: $($app.PublisherName)"
                    
                    $controlResult.AffectedAccounts += [PSCustomObject]@{
                        Name = $app.DisplayName
                        Id = $app.Id
                        Details = "Unverified app - Publisher: $($app.PublisherName)"
                    }
                }
            }
        }
        
        $controlResult.Evidence = $evidence
        
        if ($controlResult.Result -ne "COMPLIANT") {
            $controlResult.RemediationSteps = @"
<ol>
    <li>Navigate to Microsoft Entra admin center > Enterprise applications > Consent and permissions</li>
    <li>Click "User consent settings"</li>
    <li>Select one of these options:
        <ul>
            <li><strong>Recommended:</strong> "Allow user consent for apps from verified publishers, for selected permissions"</li>
            <li><strong>Most Restrictive:</strong> "Do not allow user consent"</li>
        </ul>
    </li>
    <li>If allowing verified publishers:
        <ul>
            <li>Review the list of permissions users can consent to</li>
            <li>Remove high-risk permissions from the allowed list</li>
        </ul>
    </li>
    <li>Review existing unverified applications:
        <ul>
            <li>Audit permissions granted</li>
            <li>Remove unnecessary apps</li>
            <li>Contact publishers to complete verification</li>
        </ul>
    </li>
</ol>
"@
        }
    }
    catch {
        $controlResult.Finding = "Error assessing verified publishers: $_"
        $controlResult.Result = "ERROR"
        $controlResult.Evidence = "Error details: $_"
    }
    
    return $controlResult
}

# Execute the control check
Check-VerifiedPublishers