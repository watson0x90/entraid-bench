function Check-GuestManagement {
    [CmdletBinding()]
    param()

    $controlResult = [PSCustomObject]@{
        Control = "Ensure guest user management meets CIS requirements"
        ControlDescription = "Check guest invite restrictions and regular reviews (CIS 6.3.2, 6.16)"
        Finding = ""
        Result = ""
        Evidence = ""
        RemediationSteps = ""
        AffectedAccounts = @()
    }

    try {
        $authPolicy = Get-MgPolicyAuthorizationPolicy
        $externalIdentitiesPolicy = Get-MgPolicyExternalIdentitiesPolicy
        
        # Check guest invite settings
        $allowInvitesFrom = $authPolicy.AllowInvitesFrom
        
        # Check for guest users not reviewed recently
        $guestUsers = Get-MgUser -Filter "userType eq 'Guest'" -Property DisplayName,UserPrincipalName,CreatedDateTime,SignInActivity
        
        $staleGuests = $guestUsers | Where-Object {
            $_.SignInActivity.LastSignInDateTime -lt (Get-Date).AddDays(-90)
        }
        
        $issues = @()
        if ($allowInvitesFrom -eq "everyone") {
            $issues += "Guest invites not restricted to admins"
        }
        if ($staleGuests.Count -gt 0) {
            $issues += "$($staleGuests.Count) guests haven't signed in for 90+ days"
        }
        
        if ($issues.Count -eq 0) {
            $controlResult.Finding = "Guest management properly configured"
            $controlResult.Result = "COMPLIANT"
        }
        else {
            $controlResult.Finding = "Guest management issues: $($issues -join ', ')"
            $controlResult.Result = "NOT COMPLIANT"
            
            foreach ($guest in $staleGuests | Select-Object -First 20) {
                $controlResult.AffectedAccounts += [PSCustomObject]@{
                    Name = $guest.DisplayName
                    Id = $guest.Id
                    Details = "Stale guest account - Last sign-in: $($guest.SignInActivity.LastSignInDateTime)"
                }
            }
        }
    }
    catch {
        $controlResult.Finding = "Error checking guest management: $_"
        $controlResult.Result = "ERROR"
    }
    
    return $controlResult
}