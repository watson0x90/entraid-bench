function Check-ApplicationRegistration {
    [CmdletBinding()]
    param()

    $controlResult = [PSCustomObject]@{
        Control = "Ensure that 'Users can register applications' is set to 'No'"
        ControlDescription = "Application registration should be restricted to administrators to prevent users from creating unauthorized applications."
        Finding = ""
        Result = ""
        Evidence = ""
        RemediationSteps = ""
        AffectedAccounts = @()
    }

    try {
        $evidence = Format-EvidenceSection -Title "APPLICATION REGISTRATION ASSESSMENT" -Content "Assessment Date: $(Get-Date)" -IsHeader
        
        # Get authorization policy
        $authPolicy = Get-MgPolicyAuthorizationPolicy
        $defaultUserPermissions = $authPolicy.DefaultUserRolePermissions
        
        # Check if users can register applications
        $canRegisterApps = $defaultUserPermissions.AllowedToCreateApps
        
        $evidence += "`nApplication Registration Settings:"
        $evidence += "`nUsers can register applications: $canRegisterApps"
        
        if ($canRegisterApps -eq $false) {
            $controlResult.Finding = "Application registration is properly restricted to administrators"
            $controlResult.Result = "COMPLIANT"
            $evidence += "`n`nStatus: Only administrators can register new applications"
        }
        else {
            $controlResult.Finding = "Users can register applications"
            $controlResult.Result = "NOT COMPLIANT"
            $evidence += "`n`nStatus: Any user can register applications"
            $evidence += "`n`nRisks:"
            $evidence += "`n- Users can create apps with broad permissions"
            $evidence += "`n- Potential for data exfiltration via custom apps"
            $evidence += "`n- Shadow IT application development"
            $evidence += "`n- Compliance and security review bypass"
            
            # Get recently created apps by non-admins
            try {
                $recentApps = Get-MgApplication -Top 20 -OrderBy "createdDateTime desc"
                $evidence += "`n`nRecently Created Applications:"
                
                foreach ($app in $recentApps | Select-Object -First 10) {
                    $evidence += "`n- $($app.DisplayName)"
                    $evidence += "`n  Created: $($app.CreatedDateTime)"
                    
                    # Try to get owner
                    try {
                        $owners = Get-MgApplicationOwner -ApplicationId $app.Id
                        if ($owners) {
                            $owner = Get-MgUser -UserId $owners[0].Id -ErrorAction SilentlyContinue
                            if ($owner) {
                                $evidence += "`n  Owner: $($owner.DisplayName)"
                            }
                        }
                    } catch {}
                }
                
                # Get non-admin users who could register apps
                $standardUsers = Get-MgUser -Top 10 -Filter "userType eq 'Member'"
                foreach ($user in $standardUsers) {
                    $controlResult.AffectedAccounts += [PSCustomObject]@{
                        Name = $user.DisplayName
                        Id = $user.Id
                        Details = "User can register applications"
                    }
                }
            }
            catch {
                $evidence += "`n`nUnable to retrieve recent application registrations"
            }
        }
        
        $controlResult.Evidence = $evidence
        
        if ($controlResult.Result -ne "COMPLIANT") {
            $controlResult.RemediationSteps = @"
<ol>
    <li>Navigate to Microsoft Entra admin center > Identity > Users > User settings</li>
    <li>Under "App registrations":
        <ul>
            <li>Set "Users can register applications" to "No"</li>
        </ul>
    </li>
    <li>This prevents:
        <ul>
            <li>Unauthorized application development</li>
            <li>Apps with excessive permissions</li>
            <li>Shadow IT proliferation</li>
            <li>Data exfiltration risks</li>
        </ul>
    </li>
    <li>For developers who need to register apps:
        <ul>
            <li>Create a dedicated group for app developers</li>
            <li>Grant "Application Developer" role to group members</li>
            <li>Implement approval workflow</li>
        </ul>
    </li>
    <li>Review existing applications created by non-admins</li>
</ol>
"@
        }
    }
    catch {
        $controlResult.Finding = "Error assessing application registration: $_"
        $controlResult.Result = "ERROR"
        $controlResult.Evidence = "Error details: $_"
    }
    
    return $controlResult
}

# Execute the control check
Check-ApplicationRegistration