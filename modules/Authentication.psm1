# Authentication and connection management

function Connect-EntraIDGraph {
    [CmdletBinding()]
    param(
        [string[]]$AdditionalScopes = @()
    )
    
    $requiredScopes = @(
        'User.Read.All',
        'Directory.Read.All',
        'Policy.Read.All',
        'Policy.ReadWrite.AuthenticationMethod',
        'RoleManagement.Read.All',
        'Group.Read.All',
        'Application.Read.All',
        'IdentityRiskEvent.Read.All',
        'IdentityRiskyUser.Read.All',
        'SecurityEvents.Read.All',
        'UserAuthenticationMethod.Read.All',
        'Organization.Read.All',
        'GroupMember.Read.All',
        'PrivilegedAccess.Read.AzureAD',
        'ConditionalAccessPolicy.Read.All'
    )
    
    $allScopes = $requiredScopes + $AdditionalScopes | Select-Object -Unique
    
    try {
        # Check if already connected
        $context = Get-MgContext
        if ($context) {
            Write-Verbose "Already connected to Microsoft Graph as $($context.Account)"
            
            # Verify we have required scopes
            $missingScopes = $allScopes | Where-Object { $_ -notin $context.Scopes }
            
            if ($missingScopes.Count -eq 0) {
                return @{
                    Success = $true
                    Account = $context.Account
                    TenantId = $context.TenantId
                    Message = "Using existing connection"
                }
            }
            else {
                Write-Warning "Current connection missing required scopes. Reconnecting..."
                Disconnect-MgGraph | Out-Null
            }
        }
        
        # Connect with required scopes
        Write-Verbose "Connecting to Microsoft Graph with $($allScopes.Count) scopes..."
        Connect-MgGraph -Scopes $allScopes -NoWelcome
        
        $context = Get-MgContext
        return @{
            Success = $true
            Account = $context.Account
            TenantId = $context.TenantId
            Message = "Successfully connected"
        }
    }
    catch {
        return @{
            Success = $false
            Account = $null
            TenantId = $null
            Message = $_.Exception.Message
        }
    }
}

function Test-GraphConnection {
    try {
        $context = Get-MgContext
        if ($context) {
            # Test with a simple API call
            $null = Get-MgOrganization -ErrorAction Stop
            return $true
        }
        return $false
    }
    catch {
        return $false
    }
}

function Get-GraphAPIErrorDetails {
    param([System.Management.Automation.ErrorRecord]$ErrorRecord)
    
    $errorDetails = @{
        Message = $ErrorRecord.Exception.Message
        Category = $ErrorRecord.CategoryInfo.Category
        ErrorId = $ErrorRecord.FullyQualifiedErrorId
    }
    
    # Try to extract Graph API specific error information
    if ($ErrorRecord.Exception.Response) {
        try {
            $reader = [System.IO.StreamReader]::new($ErrorRecord.Exception.Response.GetResponseStream())
            $responseBody = $reader.ReadToEnd()
            $reader.Close()
            
            $graphError = $responseBody | ConvertFrom-Json
            if ($graphError.error) {
                $errorDetails.Code = $graphError.error.code
                $errorDetails.GraphMessage = $graphError.error.message
                $errorDetails.InnerError = $graphError.error.innerError
            }
        }
        catch {
            # Unable to parse Graph error
        }
    }
    
    return $errorDetails
}

Export-ModuleMember -Function *