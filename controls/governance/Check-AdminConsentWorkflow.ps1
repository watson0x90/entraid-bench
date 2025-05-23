function Check-AdminConsentWorkflow {
    [CmdletBinding()]
    param()

    $controlResult = [PSCustomObject]@{
        Control = "Ensure the admin consent workflow is enabled"
        ControlDescription = "Admin consent workflow allows users to request admin approval for apps, providing oversight while enabling productivity."
        Finding = ""
        Result = ""
        Evidence = ""
        RemediationSteps = ""
        AffectedAccounts = @()
    }

    try {
        $evidence = Format-EvidenceSection -Title "ADMIN CONSENT WORKFLOW ASSESSMENT" -Content "Assessment Date: $(Get-Date)" -IsHeader
        
        # Get admin consent request policy
        $consentPolicy = Get-MgPolicyAdminConsentRequestPolicy
        
        $evidence += "`nAdmin Consent Workflow Configuration:"
        $evidence += "`nEnabled: $($consentPolicy.IsEnabled)"
        
        if ($consentPolicy.IsEnabled) {
            $evidence += "`nNotify Reviewers: $($consentPolicy.NotifyReviewers)"
            $evidence += "`nReminders Enabled: $($consentPolicy.RemindersEnabled)"
            $evidence += "`nRequest Duration: $($consentPolicy.RequestDurationInDays) days"
            
            # Check reviewers
            if ($consentPolicy.Reviewers) {
                $evidence += "`n`nConfigured Reviewers:"
                foreach ($reviewer in $consentPolicy.Reviewers) {
                    $evidence += "`n- $($reviewer.Query)"
                }
                
                $controlResult.Finding = "Admin consent workflow is properly configured"
                $controlResult.Result = "COMPLIANT"
                $evidence += "`n`nStatus: Users can request admin consent with proper approval process"
            }
            else {
                $controlResult.Finding = "Admin consent workflow is enabled but no reviewers configured"
                $controlResult.Result = "PARTIALLY COMPLIANT"
                $evidence += "`n`nStatus: Workflow enabled but needs reviewers"
            }
        }
        else {
            $controlResult.Finding = "Admin consent workflow is disabled"
            $controlResult.Result = "NOT COMPLIANT"
            $evidence += "`n`nStatus: Users cannot request admin consent for applications"
            $evidence += "`n`nRisks:"
            $evidence += "`n- Users may circumvent IT to use needed applications"
            $evidence += "`n- Shadow IT proliferation"
            $evidence += "`n- No process for legitimate app requests"
        }
        
        $controlResult.Evidence = $evidence
        
        if ($controlResult.Result -ne "COMPLIANT") {
            $controlResult.RemediationSteps = @"
<ol>
    <li>Navigate to Microsoft Entra admin center > Identity > Applications > Enterprise applications</li>
    <li>Select "Consent and permissions" > "Admin consent settings"</li>
    <li>Under "Admin consent requests":
        <ul>
            <li>Set "Users can request admin consent to apps they are unable to consent to" to "Yes"</li>
            <li>Select reviewers (recommend 2-3 IT/Security staff)</li>
            <li>Enable email notifications</li>
            <li>Enable reminders</li>
            <li>Set request expiration (e.g., 30 days)</li>
        </ul>
    </li>
    <li>Click Save</li>
    <li>Communicate the process to users</li>
</ol>
"@
        }
    }
    catch {
        $controlResult.Finding = "Error assessing admin consent workflow: $_"
        $controlResult.Result = "ERROR"
        $controlResult.Evidence = "Error details: $_"
    }
    
    return $controlResult
}

# Execute the control check
Check-AdminConsentWorkflow