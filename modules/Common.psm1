# Common utilities and helper functions

function Show-EntraIDBanner {
    Write-Host @"

╔═══════════════════════════════════════════════════════════════════════════╗
║                                                                           ║
║   ███████╗███╗   ██╗████████╗██████╗  █████╗ ██╗██████╗                 ║
║   ██╔════╝████╗  ██║╚══██╔══╝██╔══██╗██╔══██╗██║██╔══██╗                ║
║   █████╗  ██╔██╗ ██║   ██║   ██████╔╝███████║██║██║  ██║                ║
║   ██╔══╝  ██║╚██╗██║   ██║   ██╔══██╗██╔══██║██║██║  ██║                ║
║   ███████╗██║ ╚████║   ██║   ██║  ██║██║  ██║██║██████╔╝                ║
║   ╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝╚═════╝                 ║
║                                                                           ║
║              Security Benchmark Assessment Tool v2.0                      ║
║                                                                           ║
╚═══════════════════════════════════════════════════════════════════════════╝

"@ -ForegroundColor Cyan
}

function Get-StatusColor {
    param([string]$Status)
    
    switch ($Status) {
        "COMPLIANT" { return "Green" }
        "PARTIALLY COMPLIANT" { return "Yellow" }
        "NOT COMPLIANT" { return "Red" }
        "INFORMATION NEEDED" { return "Cyan" }
        "NOT APPLICABLE" { return "DarkGray" }
        "ERROR" { return "Magenta" }
        default { return "White" }
    }
}

function Get-TenantInformation {
    try {
        $org = Get-MgOrganization
        return @{
            DisplayName = $org.DisplayName
            TenantId = $org.Id
            CreatedDateTime = $org.CreatedDateTime
            VerifiedDomains = $org.VerifiedDomains
            OnPremisesSyncEnabled = $org.OnPremisesSyncEnabled
        }
    }
    catch {
        throw "Failed to retrieve tenant information: $_"
    }
}

function Test-EntraIDP2License {
    try {
        # Try to call a P2-only API
        $null = Get-MgRoleManagementDirectoryRoleAssignmentScheduleInstance -Top 1 -ErrorAction Stop
        return $true
    }
    catch {
        if ($_.Exception.Message -match "AadPremiumLicenseRequired|Microsoft Entra ID P2|Entra ID Governance") {
            return $false
        }
        # Other errors might be transient
        return $true
    }
}

function Show-AssessmentSummary {
    param(
        [Parameter(Mandatory)]
        [array]$Results,
        
        [hashtable]$CategoryResults
    )
    
    Write-Host "`n╔═══════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║                     ASSESSMENT SUMMARY                            ║" -ForegroundColor Cyan
    Write-Host "╚═══════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    
    # Overall statistics
    $total = $Results.Count
    $compliant = ($Results | Where-Object { $_.Result -eq "COMPLIANT" }).Count
    $partiallyCompliant = ($Results | Where-Object { $_.Result -eq "PARTIALLY COMPLIANT" }).Count
    $nonCompliant = ($Results | Where-Object { $_.Result -eq "NOT COMPLIANT" }).Count
    $infoNeeded = ($Results | Where-Object { $_.Result -eq "INFORMATION NEEDED" }).Count
    $notApplicable = ($Results | Where-Object { $_.Result -eq "NOT APPLICABLE" }).Count
    $errors = ($Results | Where-Object { $_.Result -eq "ERROR" }).Count
    
    Write-Host "`nTotal Controls Assessed: $total" -ForegroundColor White
    Write-Host "├─ Compliant:           $compliant" -ForegroundColor Green
    Write-Host "├─ Partially Compliant: $partiallyCompliant" -ForegroundColor Yellow
    Write-Host "├─ Non-Compliant:       $nonCompliant" -ForegroundColor Red
    Write-Host "├─ Information Needed:  $infoNeeded" -ForegroundColor Cyan
    Write-Host "├─ Not Applicable:      $notApplicable" -ForegroundColor DarkGray
    Write-Host "└─ Errors:              $errors" -ForegroundColor Magenta
    
    # Calculate compliance percentage
    $assessableControls = $total - $infoNeeded - $notApplicable - $errors
    if ($assessableControls -gt 0) {
        $compliancePercentage = [math]::Round(($compliant / $assessableControls) * 100, 2)
        $complianceColor = if ($compliancePercentage -ge 80) { "Green" } 
                           elseif ($compliancePercentage -ge 60) { "Yellow" } 
                           else { "Red" }
        
        Write-Host "`nOverall Compliance Score: " -NoNewline
        Write-Host "$compliancePercentage%" -ForegroundColor $complianceColor
    }
    
    # Category breakdown
    if ($CategoryResults -and $CategoryResults.Count -gt 0) {
        Write-Host "`nResults by Category:" -ForegroundColor White
        
        foreach ($category in $CategoryResults.Keys | Sort-Object) {
            $catResults = $CategoryResults[$category]
            $catCompliant = ($catResults | Where-Object { $_.Result -eq "COMPLIANT" }).Count
            $catTotal = $catResults.Count
            
            Write-Host "├─ $($category.ToUpper()): $catCompliant/$catTotal compliant" -ForegroundColor Gray
        }
    }
}

Export-ModuleMember -Function *