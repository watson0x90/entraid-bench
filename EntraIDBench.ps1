#Requires -Version 5.1
<#
.SYNOPSIS
    Comprehensive Entra ID Security Benchmark Assessment Tool
.DESCRIPTION
    Performs detailed security assessment of Microsoft Entra ID configuration
    against industry best practices and compliance frameworks.
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

# Create output directory
if (-not (Test-Path $OutputPath)) {
    New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null
}

# Import modules quietly
$modulePath = Join-Path $PSScriptRoot "modules"
$savedVerbosePreference = $VerbosePreference
$VerbosePreference = 'SilentlyContinue'
$savedWarningPreference = $WarningPreference
$WarningPreference = 'SilentlyContinue'

Import-Module (Join-Path $modulePath "Common.psm1") -Force
Import-Module (Join-Path $modulePath "Authentication.psm1") -Force
Import-Module (Join-Path $modulePath "Evidence.psm1") -Force
Import-Module (Join-Path $modulePath "Reporting.psm1") -Force

# Restore preferences
$WarningPreference = $savedWarningPreference
if ($PSBoundParameters.ContainsKey('Verbose')) {
    $VerbosePreference = 'Continue'
} else {
    $VerbosePreference = $savedVerbosePreference
}

# Show banner
Show-EntraIDBanner

# Initialize logging
$logPath = Join-Path $OutputPath "Assessment_Log.txt"
Start-Transcript -Path $logPath -Force
#endregion

#region Authentication and License Check
try {
    Write-Host "`n[*] Authenticating to Microsoft Graph..." -ForegroundColor Cyan
    
    # First ensure Microsoft.Graph module is installed
    Write-Host "[*] Checking Microsoft Graph PowerShell module..." -ForegroundColor Cyan
    $graphModule = Get-Module -ListAvailable -Name Microsoft.Graph
    if (-not $graphModule) {
        Write-Host "[!] Microsoft Graph PowerShell module not found. Installing..." -ForegroundColor Yellow
        try {
            Install-Module Microsoft.Graph -Scope CurrentUser -Force -AllowClobber
            Write-Host "[+] Microsoft Graph module installed successfully" -ForegroundColor Green
        }
        catch {
            Write-Host "[!] Failed to install Microsoft Graph module: $_" -ForegroundColor Red
            Write-Host "[!] Please install manually: Install-Module Microsoft.Graph -Scope CurrentUser" -ForegroundColor Red
            Stop-Transcript
            exit 1
        }
    }
    
    # Import required Graph modules
    Write-Host "[*] Importing Microsoft Graph modules..." -ForegroundColor Cyan
    $requiredModules = @(
        'Microsoft.Graph.Authentication',
        'Microsoft.Graph.Identity.DirectoryManagement',
        'Microsoft.Graph.Identity.SignIns',
        'Microsoft.Graph.Users',
        'Microsoft.Graph.Groups',
        'Microsoft.Graph.Applications'
    )
    
    foreach ($module in $requiredModules) {
        try {
            Import-Module $module -ErrorAction SilentlyContinue
        }
        catch {
            Write-Host "[!] Warning: Could not import $module" -ForegroundColor Yellow
        }
    }
    
    # Attempt authentication
    $authResult = Connect-EntraIDGraph
    
    if (-not $authResult.Success) {
        throw "Failed to authenticate: $($authResult.Message)"
    }
    
    Write-Host "[+] Successfully authenticated as: $($authResult.Account)" -ForegroundColor Green
    
    # Verify connection by making a test call
    Write-Host "[*] Verifying connection..." -ForegroundColor Cyan
    try {
        $testOrg = Get-MgOrganization -ErrorAction Stop
        Write-Host "[+] Connection verified successfully" -ForegroundColor Green
    }
    catch {
        Write-Host "[!] Connection verification failed: $_" -ForegroundColor Red
        Write-Host "[!] Attempting to reconnect..." -ForegroundColor Yellow
        
        # Try disconnecting and reconnecting
        Disconnect-MgGraph -ErrorAction SilentlyContinue
        $authResult = Connect-EntraIDGraph
        
        if (-not $authResult.Success) {
            throw "Failed to re-authenticate after connection test failure"
        }
    }
    
    # Get tenant information
    Write-Host "[*] Getting tenant information..." -ForegroundColor Cyan
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
            Write-Host "[!] Consider using -SkipLicenseCheck to bypass this check if you know P2 features are available." -ForegroundColor Yellow
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
    Write-Host "`n[!] CRITICAL: Authentication failed!" -ForegroundColor Red
    Write-Host "[!] Error: $_" -ForegroundColor Red
    Write-Host "`n[*] Troubleshooting steps:" -ForegroundColor Yellow
    Write-Host "    1. Ensure you have the Microsoft Graph PowerShell module installed" -ForegroundColor Yellow
    Write-Host "    2. Try running: Connect-MgGraph -Scopes 'User.Read.All','Directory.Read.All'" -ForegroundColor Yellow
    Write-Host "    3. Ensure your account has appropriate permissions in Entra ID" -ForegroundColor Yellow
    Write-Host "    4. Check if MFA or Conditional Access policies are blocking the sign-in" -ForegroundColor Yellow
    Write-Host "    5. Try clearing cached credentials: Disconnect-MgGraph" -ForegroundColor Yellow
    
    Stop-Transcript
    exit 1
}
#endregion

#region Run Control Assessments
Write-Host "`n[*] Starting security assessment..." -ForegroundColor Cyan
Write-Host "[*] Categories to assess: $($assessmentContext.Categories -join ', ')" -ForegroundColor Cyan

$allResults = @()
$categoryResults = @{}
$totalErrors = 0

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
    $categoryErrors = 0
    
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
                # Execute with error handling
                $result = $null
                try {
                    $result = & $functionName
                }
                catch {
                    # Create error result for control execution failure
                    $result = [PSCustomObject]@{
                        Control = $script.BaseName
                        ControlDescription = "Error executing control"
                        Finding = "Control execution failed: $($_.Exception.Message)"
                        Result = "ERROR"
                        Evidence = "Error: $_`nStack: $($_.ScriptStackTrace)"
                        RemediationSteps = "Review the error and ensure proper permissions are granted."
                        AffectedAccounts = @()
                    }
                    $categoryErrors++
                    $totalErrors++
                }
                
                if ($result) {
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
                    
                    if ($result.Finding -and $result.Result -ne "COMPLIANT") {
                        Write-Host "     Finding: $($result.Finding)" -ForegroundColor Gray
                    }
                }
            }
            else {
                throw "Control function '$functionName' not found in script"
            }
        }
        catch {
            Write-Host " [ERROR]" -ForegroundColor Red
            Write-Host "     Error: $_" -ForegroundColor Red
            $categoryErrors++
            $totalErrors++
            
            # Create error result
            $errorResult = [PSCustomObject]@{
                Control = $script.BaseName
                ControlDescription = "Error loading control"
                Finding = "Control could not be loaded or executed"
                Result = "ERROR"
                Evidence = "Error details: $_`nStack trace: $($_.ScriptStackTrace)"
                RemediationSteps = "Check the control script for syntax errors."
                AffectedAccounts = @()
                Category = $category
                ControlId = $script.BaseName
                AssessmentTime = Get-Date
            }
            
            $categoryResults[$category] += $errorResult
            $allResults += $errorResult
        }
    }
    
    Write-Progress -Activity "Assessing $category controls" -Completed
    
    if ($categoryErrors -gt 0) {
        Write-Host "  [!] Category completed with $categoryErrors errors" -ForegroundColor Yellow
    } else {
        Write-Host "  [+] Category completed successfully" -ForegroundColor Green
    }
}

if ($totalErrors -gt 0) {
    Write-Host "`n[!] Assessment completed with $totalErrors total errors" -ForegroundColor Yellow
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