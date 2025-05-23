# Evidence collection and management

function Save-Evidence {
    param(
        [Parameter(Mandatory)]
        [string]$Evidence,
        
        [Parameter(Mandatory)]
        [string]$ControlId,
        
        [Parameter(Mandatory)]
        [string]$OutputPath
    )
    
    $evidencePath = Join-Path $OutputPath "Evidence"
    if (-not (Test-Path $evidencePath)) {
        New-Item -Path $evidencePath -ItemType Directory -Force | Out-Null
    }
    
    $fileName = "$($ControlId)_Evidence_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
    $filePath = Join-Path $evidencePath $fileName
    
    # Add metadata to evidence
    $fullEvidence = @"
Control ID: $ControlId
Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
================================================================================

$Evidence
"@
    
    $fullEvidence | Out-File -FilePath $filePath -Encoding UTF8
    
    return $filePath
}

function Save-AffectedAccounts {
    param(
        [Parameter(Mandatory)]
        [array]$Accounts,
        
        [Parameter(Mandatory)]
        [string]$ControlId,
        
        [Parameter(Mandatory)]
        [string]$OutputPath
    )
    
    if ($Accounts.Count -eq 0) {
        return $null
    }
    
    $accountsPath = Join-Path $OutputPath "AffectedAccounts"
    if (-not (Test-Path $accountsPath)) {
        New-Item -Path $accountsPath -ItemType Directory -Force | Out-Null
    }
    
    $fileName = "$($ControlId)_AffectedAccounts_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
    $filePath = Join-Path $accountsPath $fileName
    
    # Ensure accounts are valid objects
    $validAccounts = $Accounts | Where-Object { $_ -ne $null }
    
    if ($validAccounts.Count -gt 0) {
        $validAccounts | Export-Csv -Path $filePath -NoTypeInformation -Encoding UTF8
        return $filePath
    }
    
    return $null
}

function Capture-Configuration {
    param(
        [Parameter(Mandatory)]
        [string]$ConfigurationType,
        
        [Parameter(Mandatory)]
        [string]$OutputPath
    )
    
    $configPath = Join-Path $OutputPath "Configurations"
    if (-not (Test-Path $configPath)) {
        New-Item -Path $configPath -ItemType Directory -Force | Out-Null
    }
    
    $fileName = "$($ConfigurationType)_Config_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
    $filePath = Join-Path $configPath $fileName
    
    try {
        $config = switch ($ConfigurationType) {
            "ConditionalAccess" {
                Get-MgIdentityConditionalAccessPolicy | Select-Object -Property * -ExcludeProperty '@odata.type'
            }
            "AuthenticationMethods" {
                Get-MgPolicyAuthenticationMethodPolicy
            }
            "SecurityDefaults" {
                Get-MgPolicyIdentitySecurityDefaultEnforcementPolicy
            }
            default {
                throw "Unknown configuration type: $ConfigurationType"
            }
        }
        
        $config | ConvertTo-Json -Depth 10 | Out-File -FilePath $filePath -Encoding UTF8
        return $filePath
    }
    catch {
        Write-Warning "Failed to capture $ConfigurationType configuration: $_"
        return $null
    }
}

function Format-EvidenceSection {
    param(
        [string]$Title,
        [string]$Content,
        [switch]$IsHeader
    )
    
    if ($IsHeader) {
        return @"
========================================
$Title
========================================
$Content
"@
    }
    else {
        return @"

--- $Title ---
$Content
"@
    }
}

Export-ModuleMember -Function *