function Check-IntegratedApps {
    [CmdletBinding()]
    param()

    $controlResult = [PSCustomObject]@{
        Control = "Ensure user consent to apps accessing company data on their behalf is controlled"
        ControlDescription = "Integrated applications that access company data should be properly reviewed and controlled to prevent unauthorized data access."
        Finding = ""
        Result = ""
        Evidence = ""
        RemediationSteps = ""
        AffectedAccounts = @()
    }

    try {
        $evidence = Format-EvidenceSection -Title "INTEGRATED APPS ASSESSMENT" -Content "Assessment Date: $(Get-Date)" -IsHeader
        
        # Get apps with permissions
        $apps = Get-MgServicePrincipal -Top 100 -Property DisplayName,AppId,PublisherName,AppRoleAssignments
        
        # Get apps with delegated permissions
        $delegatedPermissionGrants = Get-MgOauth2PermissionGrant -Top 100
        
        $evidence += "`nIntegrated Applications Analysis:"
        $evidence += "`nTotal Service Principals: $($apps.Count)"
        $evidence += "`nDelegated Permission Grants: $($delegatedPermissionGrants.Count)"
        
        # Analyze high-risk permissions
        $highRiskPermissions = @(
            "Mail.Read",
            "Mail.ReadWrite", 
            "Mail.Send",
            "Files.Read.All",
            "Files.ReadWrite.All",
            "Sites.Read.All",
            "Sites.ReadWrite.All",
            "User.Read.All",
            "Group.Read.All",
            "Directory.Read.All"
        )
        
        $riskyApps = @()
        
        foreach ($grant in $delegatedPermissionGrants) {
            $scope = $grant.Scope -split ' '
            $hasHighRisk = $false
            
            foreach ($permission in $scope) {
                if ($highRiskPermissions -contains $permission) {
                    $hasHighRisk = $true
                    break
                }
            }
            
            if ($hasHighRisk) {
                try {
                    $app = Get-MgServicePrincipal -ServicePrincipalId $grant.ClientId -ErrorAction SilentlyContinue
                    if ($app) {
                        $riskyApps += [PSCustomObject]@{
                            App = $app
                            Permissions = $grant.Scope
                            ConsentType = $grant.ConsentType
                        }
                    }
                } catch {}
            }
        }
        
        $evidence += "`n`nHigh-Risk Permission Grants: $($riskyApps.Count)"
        
        # Check consent configuration
        $authPolicy = Get-MgPolicyAuthorizationPolicy
        $permissionGrantPolicies = $authPolicy.DefaultUserRolePermissions.PermissionGrantPoliciesAssigned
        
        $userCanConsent = $permissionGrantPolicies.Count -gt 0
        
        if (-not $userCanConsent -and $riskyApps.Count -eq 0) {
            $controlResult.Finding = "User consent is blocked and no high-risk app permissions found"
            $controlResult.Result = "COMPLIANT"
            $evidence += "`n`nStatus: Integrated apps are properly controlled"
        }
        elseif (-not $userCanConsent) {
            $controlResult.Finding = "User consent is blocked but existing high-risk permissions found"
            $controlResult.Result = "PARTIALLY COMPLIANT"
            $evidence += "`n`nStatus: New consent blocked but $($riskyApps.Count) apps have high-risk permissions"
            
            # List risky apps
            foreach ($riskyApp in $riskyApps | Select-Object -First 10) {
                $evidence += "`n`nApp: $($riskyApp.App.DisplayName)"
                $evidence += "`nPermissions: $($riskyApp.Permissions)"
                $evidence += "`nConsent Type: $($riskyApp.ConsentType)"
                
                $controlResult.AffectedAccounts += [PSCustomObject]@{
                    Name = $riskyApp.App.DisplayName
                    Id = $riskyApp.App.Id
                    Details = "High-risk permissions: $($riskyApp.Permissions)"
                }
            }
        }
        else {
            $controlResult.Finding = "Users can consent to apps accessing company data"
            $controlResult.Result = "NOT COMPLIANT"
            $evidence += "`n`nStatus: Users can grant apps access to company data"
            $evidence += "`nHigh-risk apps found: $($riskyApps.Count)"
        }
        
        $controlResult.Evidence = $evidence
        
        if ($controlResult.Result -ne "COMPLIANT") {
            $controlResult.RemediationSteps = @"
<ol>
    <li>Review and restrict user consent:
        <ul>
            <li>Navigate to Enterprise applications > Consent and permissions</li>
            <li>Set appropriate consent policies</li>
            <li>Consider blocking all user consent</li>
        </ul>
    </li>
    <li>Audit existing application permissions:
        <ul>
            <li>Review all apps with high-risk permissions</li>
            <li>Remove unnecessary permissions</li>
            <li>Delete unused applications</li>
        </ul>
    </li>
    <li>Implement app governance:
        <ul>
            <li>Enable Cloud App Security if available</li>
            <li>Set up alerts for new app consent</li>
            <li>Regular quarterly app reviews</li>
        </ul>
    </li>
    <li>High-risk permissions to review:
        <ul>
            <li>Mail access (Read/Write/Send)</li>
            <li>Files access (especially All sites)</li>
            <li>Directory read permissions</li>
            <li>User/Group information access</li>
        </ul>
    </li>
</ol>
"@
        }
    }
    catch {
        $controlResult.Finding = "Error assessing integrated apps: $_"
        $controlResult.Result = "ERROR"
        $controlResult.Evidence = "Error details: $_"
    }
    
    return $controlResult
}

# Execute the control check
Check-IntegratedApps