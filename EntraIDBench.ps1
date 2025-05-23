#Requires -Version 5.1
<#
.SYNOPSIS
    Comprehensive Entra ID Security Benchmark Assessment Tool
.DESCRIPTION
    Performs detailed security assessment of Microsoft Entra ID configuration
    against industry best practices and compliance frameworks.
.PARAMETER ControlCategories
    Specific categories to assess (identity, access, governance, protection, applications)
.PARAMETER ExportFormat
    Output format for the report (HTML, JSON, CSV)
.PARAMETER SkipLicenseCheck
    Skip the P2 license check (some controls will show as INFORMATION NEEDED)
.PARAMETER OutputPath
    Path where reports and evidence will be saved
.EXAMPLE
    .\EntraIDBench.ps1
    Runs full assessment with default settings
.EXAMPLE
    .\EntraIDBench.ps1 -ControlCategories identity,access -ExportFormat HTML
    Runs only identity and access controls with HTML output
#>
[CmdletBinding()]
param(
    [ValidateSet('identity', 'access', 'governance', 'protection', 'applications', 'all')]
    [string[]]$ControlCategories = @('all'),
    
    [ValidateSet('HTML', 'JSON', 'CSV', 'ALL')]
    [string[]]$ExportFormat = @('HTML', 'CSV'),
    
    [switch]$SkipLicenseCheck,
    
    [string]$OutputPath = ".\output\Assessment_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
)

#region Initialize Environment
$ErrorActionPreference = 'Stop'
$VerbosePreference = 'Continue'

# Create output directory
if (-not (Test-Path $OutputPath)) {
    New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null
}

# Import modules
$modulePath = Join-Path $PSScriptRoot "modules"
Import-Module (Join-Path $modulePath "Common.psm1") -Force
Import-Module (Join-Path $modulePath "Authentication.psm1") -Force
Import-Module (Join-Path $modulePath "Evidence.psm1") -Force
Import-Module (Join-Path $modulePath "Reporting.psm1") -Force

# Show banner
Show-EntraIDBanner

# Initialize logging
Start-Transcript -Path (Join-Path $OutputPath "Assessment_Log.txt")
#endregion

#region Authentication and License Check
try {
    Write-Host "`n[*] Authenticating to Microsoft Graph..." -ForegroundColor Cyan
    $authResult = Connect-EntraIDGraph
    
    if (-not $authResult.Success) {
        throw "Failed to authenticate: $($authResult.Message)"
    }
    
    Write-Host "[+] Successfully authenticated as: $($authResult.Account)" -ForegroundColor Green
    
    # Get tenant information
    $tenantInfo = Get-TenantInformation
    Write-Host "[*] Assessing tenant: $($tenantInfo.DisplayName) ($($tenantInfo.TenantId))" -ForegroundColor Cyan
    
    # Check license unless skipped
    $hasP2License = $false
    if (-not $SkipLicenseCheck) {
        Write-Host "[*] Checking for Entra ID P2 license..." -ForegroundColor Cyan
        $hasP2License = Test-EntraIDP2License
        
        if ($hasP2License) {
            Write-Host "[+] Entra ID P2 license detected" -ForegroundColor Green
        } else {
            Write-Host "[!] No Entra ID P2 license detected. Some controls will show limited results." -ForegroundColor Yellow
        }
    }
    
    # Create assessment context
    $assessmentContext = @{
        TenantInfo = $tenantInfo
        HasP2License = $hasP2License
        StartTime = Get-Date
        OutputPath = $OutputPath
        Categories = if ($ControlCategories -contains 'all') { 
            @('identity', 'access', 'governance', 'protection', 'applications') 
        } else { 
            $ControlCategories 
        }
    }
}
catch {
    Write-Host "[!] Initialization failed: $_" -ForegroundColor Red
    Stop-Transcript
    exit 1
}
#endregion

#region Run Control Assessments
Write-Host "`n[*] Starting security assessment..." -ForegroundColor Cyan
Write-Host "[*] Categories to assess: $($assessmentContext.Categories -join ', ')" -ForegroundColor Cyan

$allResults = @()
$categoryResults = @{}

foreach ($category in $assessmentContext.Categories) {
    Write-Host "`n[*] Assessing '$category' controls..." -ForegroundColor Cyan
    
    $controlsPath = Join-Path $PSScriptRoot "controls\$category"
    if (-not (Test-Path $controlsPath)) {
        Write-Host "[!] Category path not found: $controlsPath" -ForegroundColor Red
        continue
    }
    
    $controlScripts = Get-ChildItem -Path $controlsPath -Filter "*.ps1" | Sort-Object Name
    if ($controlScripts.Count -eq 0) {
        Write-Host "[!] No control scripts found in category: $category" -ForegroundColor Yellow
        continue
    }
    
    Write-Host "[*] Found $($controlScripts.Count) controls in category '$category'" -ForegroundColor Gray
    
    $categoryResults[$category] = @()
    $controlNumber = 0
    
    foreach ($script in $controlScripts) {
        $controlNumber++
        $percentComplete = [math]::Round(($controlNumber / $controlScripts.Count) * 100)
        
        Write-Progress -Activity "Assessing $category controls" `
                      -Status "Running $($script.BaseName)" `
                      -PercentComplete $percentComplete `
                      -CurrentOperation "Control $controlNumber of $($controlScripts.Count)"
        
        try {
            Write-Host "  [>] Running: $($script.BaseName)..." -ForegroundColor Yellow -NoNewline
            
            # Load and execute the control script
            . $script.FullName
            
            # The script should define a function with the same name as the file
            $functionName = $script.BaseName
            if (Get-Command -Name $functionName -ErrorAction SilentlyContinue) {
                $result = & $functionName
                
                # Add metadata
                $result | Add-Member -NotePropertyName Category -NotePropertyValue $category -Force
                $result | Add-Member -NotePropertyName ControlId -NotePropertyValue $script.BaseName -Force
                $result | Add-Member -NotePropertyName AssessmentTime -NotePropertyValue (Get-Date) -Force
                
                # Handle evidence
                if ($result.Evidence -and $result.Evidence.Length -gt 1000) {
                    $evidencePath = Save-Evidence -Evidence $result.Evidence `
                                                 -ControlId $script.BaseName `
                                                 -OutputPath $assessmentContext.OutputPath
                    $result | Add-Member -NotePropertyName EvidenceFile -NotePropertyValue $evidencePath -Force
                }
                
                # Handle affected accounts
                if ($result.AffectedAccounts -and $result.AffectedAccounts.Count -gt 0) {
                    $accountsPath = Save-AffectedAccounts -Accounts $result.AffectedAccounts `
                                                         -ControlId $script.BaseName `
                                                         -OutputPath $assessmentContext.OutputPath
                    $result | Add-Member -NotePropertyName AffectedAccountsFile -NotePropertyValue $accountsPath -Force
                }
                
                $categoryResults[$category] += $result
                $allResults += $result
                
                # Display result
                $statusColor = Get-StatusColor -Status $result.Result
                Write-Host " [$($result.Result)]" -ForegroundColor $statusColor
                
                if ($result.Finding) {
                    Write-Host "     Finding: $($result.Finding)" -ForegroundColor Gray
                }
            }
            else {
                throw "Control function '$functionName' not found in script"
            }
        }
        catch {
            Write-Host " [ERROR]" -ForegroundColor Red
            Write-Host "     Error: $_" -ForegroundColor Red
            
            # Create error result
            $errorResult = [PSCustomObject]@{
                Control = $script.BaseName
                ControlDescription = "Error executing control"
                Finding = "An error occurred during assessment"
                Result = "ERROR"
                Evidence = "Error details: $_`nStack trace: $($_.ScriptStackTrace)"
                Category = $category
                ControlId = $script.BaseName
                AssessmentTime = Get-Date
            }
            
            $categoryResults[$category] += $errorResult
            $allResults += $errorResult
        }
    }
    
    Write-Progress -Activity "Assessing $category controls" -Completed
}
#endregion

#region Generate Reports
Write-Host "`n[*] Generating reports..." -ForegroundColor Cyan

# Add final context data
$assessmentContext.EndTime = Get-Date
$assessmentContext.Duration = $assessmentContext.EndTime - $assessmentContext.StartTime
$assessmentContext.TotalControls = $allResults.Count
$assessmentContext.Results = $allResults
$assessmentContext.CategoryResults = $categoryResults

# Generate requested report formats
$generatedReports = @()

foreach ($format in $ExportFormat) {
    if ($format -eq 'ALL') {
        $formats = @('HTML', 'JSON', 'CSV')
    } else {
        $formats = @($format)
    }
    
    foreach ($fmt in $formats) {
        try {
            Write-Host "  [>] Generating $fmt report..." -ForegroundColor Yellow -NoNewline
            
            $reportPath = switch ($fmt) {
                'HTML' { Export-HTMLReport -Context $assessmentContext -OutputPath $OutputPath }
                'JSON' { Export-JSONReport -Context $assessmentContext -OutputPath $OutputPath }
                'CSV'  { Export-CSVReport -Context $assessmentContext -OutputPath $OutputPath }
            }
            
            if ($reportPath -and (Test-Path $reportPath)) {
                $generatedReports += $reportPath
                Write-Host " [SUCCESS]" -ForegroundColor Green
            } else {
                Write-Host " [FAILED]" -ForegroundColor Red
            }
        }
        catch {
            Write-Host " [ERROR: $_]" -ForegroundColor Red
        }
    }
}
#endregion

#region Display Summary
Write-Host "`n" -NoNewline
Show-AssessmentSummary -Results $allResults -CategoryResults $categoryResults

Write-Host "`n[*] Assessment completed in: $($assessmentContext.Duration.ToString('mm\:ss'))" -ForegroundColor Cyan
Write-Host "[*] Output directory: $OutputPath" -ForegroundColor Cyan

foreach ($report in $generatedReports) {
    Write-Host "[+] Report generated: $report" -ForegroundColor Green
}

# Try to open HTML report if generated
$htmlReport = $generatedReports | Where-Object { $_ -like "*.html" } | Select-Object -First 1
if ($htmlReport -and (Test-Path $htmlReport)) {
    Write-Host "`n[*] Opening HTML report..." -ForegroundColor Cyan
    try {
        Start-Process $htmlReport
    }
    catch {
        Write-Host "[!] Could not open report automatically: $_" -ForegroundColor Yellow
    }
}
#endregion

Stop-Transcript