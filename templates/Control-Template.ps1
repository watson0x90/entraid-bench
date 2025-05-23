function Check-ControlName {
    [CmdletBinding()]
    param()

    $controlResult = [PSCustomObject]@{
        Control = "Control title from CIS benchmark"
        ControlDescription = "Detailed description of what this control checks"
        Finding = ""
        Result = ""
        Evidence = ""
        RemediationSteps = ""
        AffectedAccounts = @()
    }

    try {
        # Ensure we have a valid connection
        if (-not (Test-GraphConnection)) {
            throw "No valid Graph connection"
        }
        
        $evidence = Format-EvidenceSection -Title "CONTROL NAME ASSESSMENT" -Content "Assessment Date: $(Get-Date)" -IsHeader
        
        # Example: Get data with proper error handling
        Write-Verbose "Getting required data..."
        $data = @()
        
        try {
            # Primary method - try with optimal parameters
            $data = Get-MgSomeResource -Top 100 -ErrorAction Stop
        }
        catch {
            # Handle common API issues
            if ($_.Exception.Message -match "UnsupportedQuery|page size") {
                Write-Verbose "Pagination not supported, getting all data"
                try {
                    $data = Get-MgSomeResource -ErrorAction Stop
                    # Limit in PowerShell if needed
                    $data = $data | Select-Object -First 100
                }
                catch {
                    throw "Unable to retrieve data: $_"
                }
            }
            elseif ($_.Exception.Message -match "Premium|license|P1|P2|InvalidLicense") {
                # Handle license requirements
                $controlResult.Finding = "This control requires Entra ID P1/P2 license"
                $controlResult.Result = "INFORMATION NEEDED"
                $controlResult.Evidence = $evidence + "`n`nLicense requirement: Entra ID P1 or P2 required for this assessment"
                $controlResult.RemediationSteps = "Obtain appropriate licensing to assess this control"
                return $controlResult
            }
            elseif ($_.Exception.Message -match "Forbidden|403|Unauthorized|401") {
                # Handle permission issues
                $controlResult.Finding = "Insufficient permissions to assess this control"
                $controlResult.Result = "INFORMATION NEEDED"
                $controlResult.Evidence = $evidence + "`n`nPermission issue: $($_.Exception.Message)"
                $controlResult.RemediationSteps = "Ensure the account has the following permissions: [List Required Permissions]"
                return $controlResult
            }
            else {
                throw $_
            }
        }
        
        # Process the data
        $evidence += "`nData points analyzed: $($data.Count)"
        
        # Perform your compliance check
        $compliantItems = 0
        $nonCompliantItems = @()
        
        foreach ($item in $data) {
            # Your compliance logic here
            if ($true) { # Replace with actual check
                $compliantItems++
            }
            else {
                $nonCompliantItems += $item
            }
        }
        
        # Determine compliance status
        if ($nonCompliantItems.Count -eq 0) {
            $controlResult.Finding = "All items are compliant"
            $controlResult.Result = "COMPLIANT"
            $evidence += "`n`nStatus: Full compliance achieved"
        }
        elseif ($nonCompliantItems.Count -lt ($data.Count / 2)) {
            $controlResult.Finding = "Some items are non-compliant"
            $controlResult.Result = "PARTIALLY COMPLIANT"
            $evidence += "`n`nStatus: $($nonCompliantItems.Count) of $($data.Count) items need attention"
            
            # Add affected accounts (limit to prevent huge lists)
            foreach ($item in $nonCompliantItems | Select-Object -First 20) {
                $controlResult.AffectedAccounts += [PSCustomObject]@{
                    Name = $item.DisplayName
                    Id = $item.Id
                    Details = "Specific issue with this item"
                }
            }
        }
        else {
            $controlResult.Finding = "Majority of items are non-compliant"
            $controlResult.Result = "NOT COMPLIANT"
            $evidence += "`n`nStatus: Significant compliance issues found"
        }
        
        $controlResult.Evidence = $evidence
        
        if ($controlResult.Result -ne "COMPLIANT") {
            $controlResult.RemediationSteps = @"
<ol>
    <li>Step 1: Navigate to appropriate admin center</li>
    <li>Step 2: Configure the setting</li>
    <li>Step 3: Apply to all users/resources</li>
    <li>Step 4: Verify the change</li>
</ol>
"@
        }
    }
    catch {
        $controlResult.Finding = "Error assessing control"
        $controlResult.Result = "ERROR"
        $controlResult.Evidence = "Error details: $_`n`nStack trace: $($_.ScriptStackTrace)"
        $controlResult.RemediationSteps = "Review the error message and ensure proper permissions are granted."
    }
    
    return $controlResult
}

# Execute the control check
Check-ControlName