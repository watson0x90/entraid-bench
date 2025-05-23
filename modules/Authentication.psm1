# Authentication and connection management

function Connect-EntraIDGraph {
    [CmdletBinding()]
    param(
        [string[]]$AdditionalScopes = @()
    )
    
    # Scopes that are confirmed to work in the environment
    $workingScopes = @(
        'User.Read',
        'Organization.Read.All',
        'User.Read.All',
        'Directory.Read.All',
        'Group.Read.All',
        'RoleManagement.Read.All',
        'Policy.Read.All',
        'Policy.Read.ConditionalAccess',
        'UserAuthenticationMethod.Read.All',
        'Application.Read.All',
        'AuditLog.Read.All',
        'IdentityRiskEvent.Read.All',
        'IdentityRiskyUser.Read.All'
    )
    
    $allScopes = $workingScopes + $AdditionalScopes | Select-Object -Unique
    
    try {
        # First check if we're already connected
        $context = $null
        try {
            $context = Get-MgContext -ErrorAction SilentlyContinue
        }
        catch {
            # No context exists
        }
        
        if ($context) {
            Write-Verbose "Already connected to Microsoft Graph as $($context.Account)"
            
            # Verify we have required scopes
            $missingScopes = $allScopes | Where-Object { $_ -notin $context.Scopes }
            
            if ($missingScopes.Count -eq 0) {
                # Test the connection
                try {
                    $null = Get-MgOrganization -ErrorAction Stop
                    return @{
                        Success = $true
                        Account = $context.Account
                        TenantId = $context.TenantId
                        Message = "Using existing connection"
                        Scopes = $context.Scopes
                    }
                }
                catch {
                    Write-Warning "Existing connection is not working. Reconnecting..."
                    Disconnect-MgGraph -ErrorAction SilentlyContinue
                }
            }
            else {
                Write-Warning "Current connection missing required scopes. Reconnecting..."
                Write-Verbose "Missing scopes: $($missingScopes -join ', ')"
                Disconnect-MgGraph -ErrorAction SilentlyContinue
            }
        }
        
        # Connect with required scopes
        Write-Verbose "Connecting to Microsoft Graph with $($allScopes.Count) scopes..."
        
        # Try different authentication methods
        $connected = $false
        $lastError = $null
        
        # Method 1: Interactive browser authentication
        try {
            Write-Verbose "Attempting interactive browser authentication..."
            Connect-MgGraph -Scopes $allScopes -NoWelcome -ErrorAction Stop
            $connected = $true
        }
        catch {
            $lastError = $_
            Write-Verbose "Interactive authentication failed: $_"
        }
        
        # Method 2: Device code flow (if interactive fails)
        if (-not $connected) {
            try {
                Write-Host "[!] Interactive authentication failed. Trying device code flow..." -ForegroundColor Yellow
                Connect-MgGraph -Scopes $allScopes -UseDeviceCode -NoWelcome -ErrorAction Stop
                $connected = $true
            }
            catch {
                $lastError = $_
                Write-Verbose "Device code authentication failed: $_"
            }
        }
        
        if (-not $connected) {
            throw "All authentication methods failed. Last error: $lastError"
        }
        
        # Verify the connection
        $context = Get-MgContext
        if (-not $context) {
            throw "Connected but no context available"
        }
        
        # Test with a simple API call
        try {
            $null = Get-MgOrganization -ErrorAction Stop
        }
        catch {
            throw "Connected but unable to make API calls: $_"
        }
        
        return @{
            Success = $true
            Account = $context.Account
            TenantId = $context.TenantId
            Message = "Successfully connected"
            Scopes = $allScopes
        }
    }
    catch {
        return @{
            Success = $false
            Account = $null
            TenantId = $null
            Message = $_.Exception.Message
            Scopes = @()
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
    if ($ErrorRecord.Exception -is [Microsoft.Graph.PowerShell.Authentication.Exceptions.MsalException]) {
        $errorDetails.AuthError = $true
        $errorDetails.MsalError = $ErrorRecord.Exception.ErrorCode
    }
    
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

function Ensure-GraphConnection {
    <#
    .SYNOPSIS
    Ensures a valid Graph connection exists, attempting to reconnect if needed
    #>
    [CmdletBinding()]
    param()
    
    if (-not (Test-GraphConnection)) {
        Write-Host "[!] Graph connection lost. Attempting to reconnect..." -ForegroundColor Yellow
        $result = Connect-EntraIDGraph
        
        if (-not $result.Success) {
            throw "Failed to reconnect to Microsoft Graph: $($result.Message)"
        }
        
        Write-Host "[+] Successfully reconnected" -ForegroundColor Green
    }
    
    return $true
}

Export-ModuleMember -Function *