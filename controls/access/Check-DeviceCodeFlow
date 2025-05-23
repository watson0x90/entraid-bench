function Check-DeviceCodeFlow {
    [CmdletBinding()]
    param()

    $controlResult = [PSCustomObject]@{
        Control = "Ensure that an exclusionary device code flow policy is set up"
        ControlDescription = "Device code flow should be blocked except for specific scenarios to prevent phishing attacks where users are tricked into authenticating attacker-controlled devices."
        Finding = ""
        Result = ""
        Evidence = ""
        RemediationSteps = ""
        AffectedAccounts = @()
    }

    try {
        $evidence = Format-EvidenceSection -Title "DEVICE CODE FLOW ASSESSMENT" -Content "Assessment Date: $(Get-Date)" -IsHeader
        
        # Get Conditional Access policies
        $policies = Get-MgIdentityConditionalAccessPolicy
        $deviceCodePolicies = @()
        
        foreach ($policy in $policies) {
            if ($policy.State -eq "enabled") {
                # Check if policy addresses device code flow
                if ($policy.Conditions.AuthenticationFlows -and
                    $policy.Conditions.AuthenticationFlows.TransferMethods -contains "deviceCodeFlow") {
                    
                    $deviceCodePolicies += $policy
                    $evidence += "`n`nDevice Code Flow Policy Found: $($policy.DisplayName)"
                    $evidence += "`nState: $($policy.State)"
                    
                    # Check if it blocks
                    if ($policy.GrantControls.BuiltInControls -contains "block") {
                        $evidence += "`nAction: Block"
                        
                        # Check exclusions
                        if ($policy.Conditions.Users.ExcludeUsers -or 
                            $policy.Conditions.Users.ExcludeGroups) {
                            $evidence += "`nHas exclusions: Yes (for authorized scenarios)"
                        }
                    }
                }
            }
        }
        
        if ($deviceCodePolicies.Count -gt 0) {
            $hasBlockingPolicy = $deviceCodePolicies | Where-Object { 
                $_.GrantControls.BuiltInControls -contains "block" 
            }
            
            if ($hasBlockingPolicy) {
                $controlResult.Finding = "Device code flow is properly restricted"
                $controlResult.Result = "COMPLIANT"
                $evidence += "`n`nStatus: Device code flow is blocked with appropriate controls"
            }
            else {
                $controlResult.Finding = "Device code flow policies exist but may not block access"
                $controlResult.Result = "PARTIALLY COMPLIANT"
                $evidence += "`n`nStatus: Policies exist but configuration needs review"
            }
        }
        else {
            $controlResult.Finding = "No device code flow restrictions found"
            $controlResult.Result = "NOT COMPLIANT"
            $evidence += "`n`nStatus: Device code flow is unrestricted"
            $evidence += "`n`nRisks:"
            $evidence += "`n- Users can be phished to authenticate attacker devices"
            $evidence += "`n- Attackers can gain persistent access to resources"
            $evidence += "`n- Common vector for consent phishing attacks"
        }
        
        $controlResult.Evidence = $evidence
        
        if ($controlResult.Result -ne "COMPLIANT") {
            $controlResult.RemediationSteps = @"
<ol>
    <li>Navigate to Microsoft Entra admin center > Protection > Conditional Access</li>
    <li>Create new policy: "Block Device Code Flow"</li>
    <li>Configure:
        <ul>
            <li>Users: Include "All users"</li>
            <li>Cloud apps: All cloud apps</li>
            <li>Conditions > Authentication flows: Select "Device code flow"</li>
            <li>Grant: Block access</li>
        </ul>
    </li>
    <li>If needed for specific scenarios (e.g., Azure CLI):
        <ul>
            <li>Exclude specific service accounts or groups</li>
            <li>Document the business justification</li>
            <li>Monitor usage closely</li>
        </ul>
    </li>
</ol>
"@
        }
    }
    catch {
        $controlResult.Finding = "Error assessing device code flow policies: $_"
        $controlResult.Result = "ERROR"
        $controlResult.Evidence = "Error details: $_"
    }
    
    return $controlResult
}

# Execute the control check
Check-DeviceCodeFlow