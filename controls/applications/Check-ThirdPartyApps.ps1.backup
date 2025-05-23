function Check-ThirdPartyApps {
    [CmdletBinding()]
    param()

    $controlResult = [PSCustomObject]@{
        Control = "Ensure third party integrated applications are not allowed"
        ControlDescription = "Third-party application integration should be controlled to prevent unauthorized data access and shadow IT."
        Finding = ""
        Result = ""
        Evidence = ""
        RemediationSteps = ""
        AffectedAccounts = @()
    }

    try {
        $evidence = Format-EvidenceSection -Title "THIRD-PARTY APPS ASSESSMENT" -Content "Assessment Date: $(Get-Date)" -IsHeader
        
        # Get authorization policy
        $authPolicy = Get-MgPolicyAuthorizationPolicy
        $defaultUserPermissions = $authPolicy.DefaultUserRolePermissions
        
        # Check if users can consent to apps
        $permissionGrantPolicies = $defaultUserPermissions.PermissionGrantPoliciesAssigned
        
        $evidence += "`nUser Consent Settings:"
        $evidence += "`nPermission Grant Policies: $($permissionGrantPolicies -join ', ')"
        
        # Get enterprise applications
        $enterpriseApps = Get-MgServicePrincipal -Top 100 -Property DisplayName,AppId,PublisherName,CreatedDateTime
        
        # Filter for third-party apps (not Microsoft)
        $thirdPartyApps = $enterpriseApps | Where-Object { 
            $_.PublisherName -ne "Microsoft Corporation" -and 
            $_.PublisherName -ne "Microsoft" -and
            $_.PublisherName -ne $null
        }
        
        $evidence += "`n`nEnterprise Applications Analysis:"
        $evidence += "`nTotal Applications: $($enterpriseApps.Count)"
        $evidence += "`nThird-Party Applications: $($thirdPartyApps.Count)"
        
        # Check if user consent is blocked
        $userConsentBlocked = $permissionGrantPolicies.Count -eq 0 -or 
                            -not ($permissionGrantPolicies -match "microsoft-user-default")
        
        if ($userConsentBlocked -and $thirdPartyApps.Count -eq 0) {
            $controlResult.Finding = "Third-party apps are blocked and none are currently installed"
            $controlResult.Result = "COMPLIANT"
            $evidence += "`n`nStatus: No third-party apps found and user consent is blocked"
        }
        elseif ($userConsentBlocked) {
            $controlResult.Finding = "User consent is blocked but existing third-party apps are present"
            $controlResult.Result = "PARTIALLY COMPLIANT"
            $evidence += "`n`nStatus: New third-party apps are blocked but $($thirdPartyApps.Count) existing apps found"
            
            # List third-party apps
            $evidence += "`n`nThird-Party Applications:"
            foreach ($app in $thirdPartyApps | Select-Object -First 20) {
                $evidence += "`n- $($app.DisplayName)"
                $evidence += "`n  Publisher: $($app.PublisherName)"
                $evidence += "`n  Created: $($app.CreatedDateTime)"
                
                $controlResult.AffectedAccounts += [PSCustomObject]@{
                    Name = $app.DisplayName
                    Id = $app.Id
                    Details = "Third-party app - Publisher: $($app.PublisherName)"
                }
            }
        }
        else {
            $controlResult.Finding = "Third-party apps are allowed via user consent"
            $controlResult.Result = "NOT COMPLIANT"
            $evidence += "`n`nStatus: Users can consent to third-party applications"
            $evidence += "`nThird-party apps found: $($thirdPartyApps.Count)"
        }
        
        $controlResult.Evidence = $evidence
        
        if ($controlResult.Result -ne "COMPLIANT") {
            $remediationSteps = @"
<ol>
    <li>Block user consent for applications:
        <ul>
            <li>Navigate to Enterprise applications > Consent and permissions</li>
            <li>Set "User consent for applications" to "Do not allow user consent"</li>
        </ul>
    </li>
    <li>Review existing third-party applications:
        <ul>
            <li>Go to Enterprise applications</li>
            <li>Filter by "Application type: Enterprise Applications"</li>
            <li>Review each non-Microsoft application</li>
            <li>Remove unnecessary applications</li>
        </ul>
    </li>
    <li>Implement admin consent workflow:
        <ul>
            <li>Enable admin consent requests</li>
            <li>Configure reviewers</li>
            <li>Set up notifications</li>
        </ul>
    </li>
    <li>Create a whitelist of approved applications if needed</li>
</ol>
"@
            
            if ($thirdPartyApps.Count -gt 0) {
                $remediationSteps += @"
<p><strong>Existing Third-Party Apps to Review:</strong> $($thirdPartyApps.Count) applications found</p>
"@
            }
            
            $controlResult.RemediationSteps = $remediationSteps
        }
    }
    catch {
        $controlResult.Finding = "Error assessing third-party apps: $_"
        $controlResult.Result = "ERROR"
        $controlResult.Evidence = "Error details: $_"
    }
    
    return $controlResult
}

# Execute the control check
Check-ThirdPartyApps