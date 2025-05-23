function Check-DynamicGuestGroup {
    [CmdletBinding()]
    param()

    $controlResult = [PSCustomObject]@{
        Control = "Ensure a dynamic group for guest users is created"
        ControlDescription = "A dynamic group containing all guest users enables consistent policy application and simplified guest management."
        Finding = ""
        Result = ""
        Evidence = ""
        RemediationSteps = ""
        AffectedAccounts = @()
    }

    try {
        # Get all dynamic groups
        $dynamicGroups = Get-MgGroup | Where-Object { $_.GroupTypes -contains "DynamicMembership" }
        
        $evidence = Format-EvidenceSection -Title "DYNAMIC GUEST GROUP ASSESSMENT" -Content "Assessment Date: $(Get-Date)" -IsHeader
        $evidence += "`n`nDynamic Groups Found: $($dynamicGroups.Count)"
        
        # Look for guest user dynamic groups
        $guestGroups = $dynamicGroups | Where-Object { 
            $_.MembershipRule -like "*user.userType*-eq*`"Guest`"*" -or
            $_.MembershipRule -like "*user.userType*eq*'Guest'*"
        }
        
        # Get current guest users
        $guestUsers = Get-MgUser -Filter "userType eq 'Guest'" -Top 50
        $evidence += "`nGuest Users in Tenant: $($guestUsers.Count)+"
        
        if ($guestGroups.Count -gt 0) {
            $controlResult.Finding = "Dynamic group for guest users exists"
            $controlResult.Result = "COMPLIANT"
            
            foreach ($group in $guestGroups) {
                $evidence += "`n`nGuest Dynamic Group Found:"
                $evidence += "`nName: $($group.DisplayName)"
                $evidence += "`nRule: $($group.MembershipRule)"
                $evidence += "`nProcessing State: $($group.MembershipRuleProcessingState)"
            }
        }
        else {
            $controlResult.Finding = "No dynamic group for guest users found"
            $controlResult.Result = "NOT COMPLIANT"
            
            if ($guestUsers.Count -gt 0) {
                $evidence += "`n`nImpact: $($guestUsers.Count)+ guest users are not automatically grouped"
                
                foreach ($guest in $guestUsers | Select-Object -First 20) {
                    $controlResult.AffectedAccounts += [PSCustomObject]@{
                        Name = $guest.DisplayName
                        Id = $guest.Id
                        Details = "Guest user not in dynamic group"
                    }
                }
            }
        }
        
        $controlResult.Evidence = $evidence
        
        if ($controlResult.Result -ne "COMPLIANT") {
            $controlResult.RemediationSteps = @"
<ol>
    <li>Navigate to Microsoft Entra admin center > Identity > Groups > All groups</li>
    <li>Click "New group"</li>
    <li>Configure as follows:
        <ul>
            <li>Group type: Security</li>
            <li>Group name: All Guest Users</li>
            <li>Membership type: Dynamic User</li>
        </ul>
    </li>
    <li>Click "Add dynamic query"</li>
    <li>Set the rule to: <code>user.userType -eq "Guest"</code></li>
    <li>Click Save to create the group</li>
    <li>Use this group for Conditional Access policies and access reviews</li>
</ol>
"@
        }
    }
    catch {
        $controlResult.Finding = "Error assessing dynamic guest group: $_"
        $controlResult.Result = "ERROR"
        $controlResult.Evidence = "Error details: $_"
    }
    
    return $controlResult
}

# Execute the control check
Check-DynamicGuestGroup