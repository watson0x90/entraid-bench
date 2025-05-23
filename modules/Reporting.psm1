# Report generation functions

function Export-HTMLReport {
    param(
        [Parameter(Mandatory)]
        [hashtable]$Context,
        
        [Parameter(Mandatory)]
        [string]$OutputPath
    )
    
    $reportPath = Join-Path $OutputPath "EntraID_Security_Assessment_$(Get-Date -Format 'yyyyMMdd_HHmmss').html"
    
    # Calculate statistics
    $results = $Context.Results
    $total = $results.Count
    $compliant = ($results | Where-Object { $_.Result -eq "COMPLIANT" }).Count
    $partiallyCompliant = ($results | Where-Object { $_.Result -eq "PARTIALLY COMPLIANT" }).Count
    $nonCompliant = ($results | Where-Object { $_.Result -eq "NOT COMPLIANT" }).Count
    $infoNeeded = ($results | Where-Object { $_.Result -eq "INFORMATION NEEDED" }).Count
    $notApplicable = ($results | Where-Object { $_.Result -eq "NOT APPLICABLE" }).Count
    $errors = ($results | Where-Object { $_.Result -eq "ERROR" }).Count
    
    $assessableControls = $total - $infoNeeded - $notApplicable - $errors
    $compliancePercentage = if ($assessableControls -gt 0) {
        [math]::Round(($compliant / $assessableControls) * 100, 2)
    } else { 0 }
    
    # Generate HTML
    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Entra ID Security Assessment Report</title>
    <style>
        :root {
            --primary-color: #0078d4;
            --success-color: #107c10;
            --warning-color: #ffb900;
            --danger-color: #d13438;
            --info-color: #00b7c3;
            --dark-color: #323130;
            --light-bg: #f3f2f1;
            --white: #ffffff;
            --shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', -apple-system, BlinkMacSystemFont, sans-serif;
            line-height: 1.6;
            color: var(--dark-color);
            background-color: var(--light-bg);
        }
        
        .container {
            max-width: 1400px;
            margin: 0 auto;
            padding: 20px;
        }
        
        .header {
            background: linear-gradient(135deg, var(--primary-color) 0%, #005a9e 100%);
            color: var(--white);
            padding: 40px;
            border-radius: 10px;
            margin-bottom: 30px;
            box-shadow: var(--shadow);
        }
        
        .header h1 {
            font-size: 2.5rem;
            font-weight: 600;
            margin-bottom: 10px;
        }
        
        .header .subtitle {
            font-size: 1.2rem;
            opacity: 0.9;
        }
        
        .metadata {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 15px;
            margin-top: 20px;
        }
        
        .metadata-item {
            background: rgba(255,255,255,0.1);
            padding: 10px 15px;
            border-radius: 5px;
        }
        
        .metadata-label {
            font-size: 0.9rem;
            opacity: 0.8;
        }
        
        .metadata-value {
            font-size: 1.1rem;
            font-weight: 600;
        }
        
        .summary-section {
            background: var(--white);
            padding: 30px;
            border-radius: 10px;
            margin-bottom: 30px;
            box-shadow: var(--shadow);
        }
        
        .summary-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        
        .stat-card {
            background: var(--light-bg);
            padding: 20px;
            border-radius: 8px;
            text-align: center;
            transition: transform 0.2s;
        }
        
        .stat-card:hover {
            transform: translateY(-2px);
            box-shadow: var(--shadow);
        }
        
        .stat-number {
            font-size: 2.5rem;
            font-weight: 700;
            margin-bottom: 5px;
        }
        
        .stat-label {
            font-size: 0.9rem;
            text-transform: uppercase;
            letter-spacing: 1px;
            opacity: 0.8;
        }
        
        .stat-compliant { color: var(--success-color); }
        .stat-partial { color: var(--warning-color); }
        .stat-noncompliant { color: var(--danger-color); }
        .stat-info { color: var(--info-color); }
        .stat-error { color: var(--danger-color); }
        
        .compliance-meter {
            margin: 30px 0;
            text-align: center;
        }
        
        .meter-container {
            width: 100%;
            max-width: 600px;
            height: 30px;
            background: var(--light-bg);
            border-radius: 15px;
            margin: 0 auto 10px;
            overflow: hidden;
            position: relative;
        }
        
        .meter-fill {
            height: 100%;
            border-radius: 15px;
            transition: width 1s ease-out;
            position: relative;
            overflow: hidden;
        }
        
        .meter-fill::after {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: linear-gradient(
                90deg,
                rgba(255,255,255,0) 0%,
                rgba(255,255,255,0.3) 50%,
                rgba(255,255,255,0) 100%
            );
            animation: shimmer 2s infinite;
        }
        
        @keyframes shimmer {
            0% { transform: translateX(-100%); }
            100% { transform: translateX(100%); }
        }
        
        .meter-label {
            font-size: 1.5rem;
            font-weight: 600;
            margin-top: 10px;
        }
        
        .filters {
            background: var(--white);
            padding: 20px;
            border-radius: 10px;
            margin-bottom: 20px;
            box-shadow: var(--shadow);
        }
        
        .filter-buttons {
            display: flex;
            flex-wrap: wrap;
            gap: 10px;
        }
        
        .filter-btn {
            padding: 8px 16px;
            border: 2px solid transparent;
            background: var(--light-bg);
            border-radius: 5px;
            cursor: pointer;
            transition: all 0.2s;
            font-size: 0.9rem;
            font-weight: 500;
        }
        
        .filter-btn:hover {
            transform: translateY(-1px);
            box-shadow: var(--shadow);
        }
        
        .filter-btn.active {
            background: var(--primary-color);
            color: var(--white);
        }
        
        .controls-section {
            background: var(--white);
            padding: 30px;
            border-radius: 10px;
            box-shadow: var(--shadow);
        }
        
        .category-group {
            margin-bottom: 30px;
        }
        
        .category-header {
            background: var(--light-bg);
            padding: 15px 20px;
            border-radius: 8px;
            margin-bottom: 15px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        
        .category-title {
            font-size: 1.3rem;
            font-weight: 600;
            text-transform: capitalize;
        }
        
        .category-stats {
            font-size: 0.9rem;
            color: #666;
        }
        
        .control-item {
            background: var(--white);
            border: 1px solid #e1e1e1;
            border-radius: 8px;
            margin-bottom: 15px;
            overflow: hidden;
            transition: all 0.2s;
        }
        
        .control-item:hover {
            box-shadow: var(--shadow);
        }
        
        .control-header {
            padding: 20px;
            cursor: pointer;
            display: flex;
            justify-content: space-between;
            align-items: center;
            background: var(--light-bg);
        }
        
        .control-header:hover {
            background: #e8e7e6;
        }
        
        .control-title {
            font-size: 1.1rem;
            font-weight: 600;
            flex: 1;
            margin-right: 20px;
        }
        
        .control-status {
            padding: 6px 12px;
            border-radius: 4px;
            font-size: 0.85rem;
            font-weight: 600;
            white-space: nowrap;
        }
        
        .status-compliant {
            background: var(--success-color);
            color: var(--white);
        }
        
        .status-partial {
            background: var(--warning-color);
            color: var(--white);
        }
        
        .status-noncompliant {
            background: var(--danger-color);
            color: var(--white);
        }
        
        .status-info {
            background: var(--info-color);
            color: var(--white);
        }
        
        .status-notapplicable {
            background: #666;
            color: var(--white);
        }
        
        .status-error {
            background: var(--danger-color);
            color: var(--white);
        }
        
        .control-content {
            padding: 20px;
            display: none;
            border-top: 1px solid #e1e1e1;
        }
        
        .control-content.active {
            display: block;
        }
        
        .control-section {
            margin-bottom: 20px;
        }
        
        .control-section h4 {
            color: var(--primary-color);
            margin-bottom: 10px;
            font-size: 1rem;
            font-weight: 600;
        }
        
        .evidence-box {
            background: var(--light-bg);
            padding: 15px;
            border-radius: 5px;
            font-family: 'Consolas', 'Monaco', monospace;
            font-size: 0.9rem;
            white-space: pre-wrap;
            word-wrap: break-word;
            max-height: 400px;
            overflow-y: auto;
            border: 1px solid #e1e1e1;
        }
        
        .remediation-box {
            background: #e3f2fd;
            border-left: 4px solid var(--primary-color);
            padding: 15px;
            border-radius: 5px;
            margin-top: 15px;
        }
        
        .affected-accounts {
            margin-top: 15px;
        }
        
        .accounts-table {
            width: 100%;
            border-collapse: collapse;
            font-size: 0.9rem;
        }
        
        .accounts-table th,
        .accounts-table td {
            padding: 10px;
            text-align: left;
            border-bottom: 1px solid #e1e1e1;
        }
        
        .accounts-table th {
            background: var(--light-bg);
            font-weight: 600;
        }
        
        .footer {
            text-align: center;
            padding: 40px 20px;
            color: #666;
            font-size: 0.9rem;
        }
        
        .expand-all-btn {
            background: var(--primary-color);
            color: var(--white);
            border: none;
            padding: 10px 20px;
            border-radius: 5px;
            cursor: pointer;
            font-size: 0.9rem;
            font-weight: 500;
            margin-bottom: 20px;
        }
        
        .expand-all-btn:hover {
            background: #005a9e;
        }
        
        @media (max-width: 768px) {
            .container {
                padding: 10px;
            }
            
            .header {
                padding: 20px;
            }
            
            .header h1 {
                font-size: 1.8rem;
            }
            
            .summary-grid {
                grid-template-columns: 1fr;
            }
            
            .filter-buttons {
                flex-direction: column;
            }
            
            .filter-btn {
                width: 100%;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <!-- Header -->
        <div class="header">
            <h1>Entra ID Security Assessment Report</h1>
            <div class="subtitle">Comprehensive Security Benchmark Analysis</div>
            <div class="metadata">
                <div class="metadata-item">
                    <div class="metadata-label">Tenant</div>
                    <div class="metadata-value">$($Context.TenantInfo.DisplayName)</div>
                </div>
                <div class="metadata-item">
                    <div class="metadata-label">Assessment Date</div>
                    <div class="metadata-value">$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</div>
                </div>
                <div class="metadata-item">
                    <div class="metadata-label">Duration</div>
                    <div class="metadata-value">$($Context.Duration.ToString('mm\:ss'))</div>
                </div>
                <div class="metadata-item">
                    <div class="metadata-label">Total Controls</div>
                    <div class="metadata-value">$total</div>
                </div>
            </div>
        </div>
        
        <!-- Summary Section -->
        <div class="summary-section">
            <h2>Executive Summary</h2>
            
            <div class="summary-grid">
                <div class="stat-card">
                    <div class="stat-number stat-compliant">$compliant</div>
                    <div class="stat-label">Compliant</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number stat-partial">$partiallyCompliant</div>
                    <div class="stat-label">Partially Compliant</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number stat-noncompliant">$nonCompliant</div>
                    <div class="stat-label">Non-Compliant</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number stat-info">$infoNeeded</div>
                    <div class="stat-label">Info Needed</div>
                </div>
                $(if ($notApplicable -gt 0) {
                '<div class="stat-card">
                    <div class="stat-number">'+$notApplicable+'</div>
                    <div class="stat-label">Not Applicable</div>
                </div>'
                })
                $(if ($errors -gt 0) {
                '<div class="stat-card">
                    <div class="stat-number stat-error">'+$errors+'</div>
                    <div class="stat-label">Errors</div>
                </div>'
                })
            </div>
            
            <div class="compliance-meter">
                <div class="meter-container">
                    <div class="meter-fill" style="width: $compliancePercentage%; background: $(
                        if ($compliancePercentage -ge 80) { 'var(--success-color)' }
                        elseif ($compliancePercentage -ge 60) { 'var(--warning-color)' }
                        else { 'var(--danger-color)' }
                    );"></div>
                </div>
                <div class="meter-label">Overall Compliance: $compliancePercentage%</div>
            </div>
        </div>
        
        <!-- Filters -->
        <div class="filters">
            <h3>Filter Controls</h3>
            <div class="filter-buttons">
                <button class="filter-btn active" onclick="filterControls('all')">All Controls</button>
                <button class="filter-btn" onclick="filterControls('compliant')">Compliant</button>
                <button class="filter-btn" onclick="filterControls('partial')">Partially Compliant</button>
                <button class="filter-btn" onclick="filterControls('noncompliant')">Non-Compliant</button>
                <button class="filter-btn" onclick="filterControls('info')">Information Needed</button>
                $(if ($errors -gt 0) {
                '<button class="filter-btn" onclick="filterControls(''error'')">Errors</button>'
                })
            </div>
        </div>
        
        <!-- Controls Section -->
        <div class="controls-section">
            <h2>Detailed Assessment Results</h2>
            <button class="expand-all-btn" onclick="toggleAllControls()">Expand All</button>
"@
    
    # Group results by category
    $groupedResults = $results | Group-Object -Property Category
    
    foreach ($categoryGroup in $groupedResults | Sort-Object Name) {
        $categoryName = $categoryGroup.Name
        $categoryControls = $categoryGroup.Group | Sort-Object Control
        
        $catCompliant = ($categoryControls | Where-Object { $_.Result -eq "COMPLIANT" }).Count
        $catTotal = $categoryControls.Count
        
        $html += @"
            <div class="category-group">
                <div class="category-header">
                    <div class="category-title">$categoryName</div>
                    <div class="category-stats">$catCompliant / $catTotal Compliant</div>
                </div>
"@
        
        foreach ($control in $categoryControls) {
            $statusClass = switch ($control.Result) {
                "COMPLIANT" { "compliant" }
                "PARTIALLY COMPLIANT" { "partial" }
                "NOT COMPLIANT" { "noncompliant" }
                "INFORMATION NEEDED" { "info" }
                "NOT APPLICABLE" { "notapplicable" }
                "ERROR" { "error" }
                default { "unknown" }
            }
            
            $dataStatus = $statusClass
            
            $html += @"
                <div class="control-item" data-status="$dataStatus">
                    <div class="control-header" onclick="toggleControl(this)">
                        <div class="control-title">$($control.Control)</div>
                        <div class="control-status status-$statusClass">$($control.Result)</div>
                    </div>
                    <div class="control-content">
                        <div class="control-section">
                            <h4>Description</h4>
                            <p>$($control.ControlDescription)</p>
                        </div>
                        
                        <div class="control-section">
                            <h4>Finding</h4>
                            <p>$($control.Finding)</p>
                        </div>
"@
            
            if ($control.Evidence) {
                # Escape HTML in evidence
                $escapedEvidence = [System.Web.HttpUtility]::HtmlEncode($control.Evidence)
                $html += @"
                        <div class="control-section">
                            <h4>Evidence</h4>
                            <div class="evidence-box">$escapedEvidence</div>
                        </div>
"@
            }
            
            if ($control.RemediationSteps) {
                $html += @"
                        <div class="control-section">
                            <h4>Remediation Steps</h4>
                            <div class="remediation-box">
                                $($control.RemediationSteps)
                            </div>
                        </div>
"@
            }
            
            if ($control.AffectedAccounts -and $control.AffectedAccounts.Count -gt 0) {
                $html += @"
                        <div class="control-section">
                            <h4>Affected Accounts</h4>
                            <div class="affected-accounts">
                                <table class="accounts-table">
                                    <thead>
                                        <tr>
                                            <th>Name</th>
                                            <th>ID</th>
                                            <th>Details</th>
                                        </tr>
                                    </thead>
                                    <tbody>
"@
                
                $displayCount = [Math]::Min(10, $control.AffectedAccounts.Count)
                for ($i = 0; $i -lt $displayCount; $i++) {
                    $account = $control.AffectedAccounts[$i]
                    $html += @"
                                        <tr>
                                            <td>$([System.Web.HttpUtility]::HtmlEncode($account.Name))</td>
                                            <td>$([System.Web.HttpUtility]::HtmlEncode($account.Id))</td>
                                            <td>$([System.Web.HttpUtility]::HtmlEncode($account.Details))</td>
                                        </tr>
"@
                }
                
                if ($control.AffectedAccounts.Count -gt 10) {
                    $html += @"
                                        <tr>
                                            <td colspan="3"><em>... and $($control.AffectedAccounts.Count - 10) more accounts</em></td>
                                        </tr>
"@
                }
                
                $html += @"
                                    </tbody>
                                </table>
                            </div>
                        </div>
"@
            }
            
            $html += @"
                    </div>
                </div>
"@
        }
        
        $html += @"
            </div>
"@
    }
    
    $html += @"
        </div>
        
        <!-- Footer -->
        <div class="footer">
            <p>Generated by Entra ID Security Benchmark Tool v2.0</p>
            <p>Report Date: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</p>
        </div>
    </div>
    
    <script>
        function toggleControl(header) {
            const content = header.nextElementSibling;
            content.classList.toggle('active');
        }
        
        function toggleAllControls() {
            const contents = document.querySelectorAll('.control-content');
            const allActive = Array.from(contents).every(content => content.classList.contains('active'));
            
            contents.forEach(content => {
                if (allActive) {
                    content.classList.remove('active');
                } else {
                    content.classList.add('active');
                }
            });
            
            const btn = document.querySelector('.expand-all-btn');
            btn.textContent = allActive ? 'Expand All' : 'Collapse All';
        }
        
        function filterControls(status) {
            const controls = document.querySelectorAll('.control-item');
            const buttons = document.querySelectorAll('.filter-btn');
            
            // Update active button
            buttons.forEach(btn => btn.classList.remove('active'));
            event.target.classList.add('active');
            
            // Filter controls
            controls.forEach(control => {
                if (status === 'all' || control.dataset.status === status) {
                    control.style.display = 'block';
                } else {
                    control.style.display = 'none';
                }
            });
        }
        
        // Animate compliance meter on load
        window.addEventListener('load', () => {
            const meterFill = document.querySelector('.meter-fill');
            setTimeout(() => {
                meterFill.style.width = meterFill.style.width;
            }, 100);
        });
    </script>
</body>
</html>
"@
    
    # Save the report
    $html | Out-File -FilePath $reportPath -Encoding UTF8
    
    return $reportPath
}

function Export-JSONReport {
    param(
        [Parameter(Mandatory)]
        [hashtable]$Context,
        
        [Parameter(Mandatory)]
        [string]$OutputPath
    )
    
    $reportPath = Join-Path $OutputPath "EntraID_Security_Assessment_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
    
    $jsonReport = @{
        metadata = @{
            reportVersion = "2.0"
            assessmentDate = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
            tenant = $Context.TenantInfo
            duration = $Context.Duration.ToString()
            hasP2License = $Context.HasP2License
        }
        summary = @{
            totalControls = $Context.Results.Count
            compliant = ($Context.Results | Where-Object { $_.Result -eq "COMPLIANT" }).Count
            partiallyCompliant = ($Context.Results | Where-Object { $_.Result -eq "PARTIALLY COMPLIANT" }).Count
            nonCompliant = ($Context.Results | Where-Object { $_.Result -eq "NOT COMPLIANT" }).Count
            informationNeeded = ($Context.Results | Where-Object { $_.Result -eq "INFORMATION NEEDED" }).Count
            notApplicable = ($Context.Results | Where-Object { $_.Result -eq "NOT APPLICABLE" }).Count
            errors = ($Context.Results | Where-Object { $_.Result -eq "ERROR" }).Count
        }
        results = $Context.Results | Select-Object -Property * -ExcludeProperty AffectedAccounts | ForEach-Object {
            $result = $_
            if ($result.AffectedAccounts -and $result.AffectedAccounts.Count -gt 0) {
                $result | Add-Member -NotePropertyName AffectedAccountsCount -NotePropertyValue $result.AffectedAccounts.Count -Force
            }
            $result
        }
    }
    
    $jsonReport | ConvertTo-Json -Depth 10 | Out-File -FilePath $reportPath -Encoding UTF8
    
    return $reportPath
}

function Export-CSVReport {
    param(
        [Parameter(Mandatory)]
        [hashtable]$Context,
        
        [Parameter(Mandatory)]
        [string]$OutputPath
    )
    
    $reportPath = Join-Path $OutputPath "EntraID_Security_Assessment_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
    
    $csvData = $Context.Results | Select-Object @(
        'Category',
        'ControlId',
        'Control',
        'Result',
        'Finding',
        @{Name='AssessmentTime'; Expression={$_.AssessmentTime.ToString('yyyy-MM-dd HH:mm:ss')}},
        @{Name='HasEvidence'; Expression={if($_.Evidence) {'Yes'} else {'No'}}},
        @{Name='HasRemediation'; Expression={if($_.RemediationSteps) {'Yes'} else {'No'}}},
        @{Name='AffectedAccountsCount'; Expression={if($_.AffectedAccounts) {$_.AffectedAccounts.Count} else {0}}}
    )
    
    $csvData | Export-Csv -Path $reportPath -NoTypeInformation -Encoding UTF8
    
    return $reportPath
}

Export-ModuleMember -Function *