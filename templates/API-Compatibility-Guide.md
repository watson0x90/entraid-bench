# Microsoft Graph API Compatibility Guide for Entra ID Assessment

## Table of Contents
1. [Common API Issues and Solutions](#common-api-issues-and-solutions)
2. [Permission Requirements](#permission-requirements)
3. [License-Dependent Features](#license-dependent-features)
4. [Error Handling Patterns](#error-handling-patterns)
5. [API Throttling Considerations](#api-throttling-considerations)
6. [Alternative Approaches](#alternative-approaches)
7. [Connection Best Practices](#connection-best-practices)
8. [Common Error Messages](#common-error-messages)
9. [API-Specific Quirks](#api-specific-quirks)
10. [Code Examples](#code-examples)

## Common API Issues and Solutions

### 1. Pagination Parameter Issues

**Problem**: Some endpoints don't support `-Top`, `-Skip`, or `-Filter` parameters.

**Affected Endpoints**:
- `Get-MgDirectoryRole` - No pagination support
- `Get-MgOrganization` - Limited filter support
- `Get-MgPolicyIdentitySecurityDefaultEnforcementPolicy` - Single object endpoint
- `Get-MgGroupSetting` - Limited pagination
- `Get-MgPolicyAuthorizationPolicy` - Single object endpoint

**Solution**:
```powershell
# Instead of:
$roles = Get-MgDirectoryRole -Top 10

# Use:
$roles = Get-MgDirectoryRole
# Then limit in PowerShell if needed:
$rolesSubset = $roles | Select-Object -First 10
```

### 2. ConsistencyLevel Requirements

Some endpoints require the `-ConsistencyLevel` parameter for certain operations:

```powershell
# Count operations often need ConsistencyLevel
$users = Get-MgUser -Count userCount -ConsistencyLevel eventual

# Advanced queries may also need it
$guestUsers = Get-MgUser -Filter "userType eq 'Guest'" -ConsistencyLevel eventual
```

## Permission Requirements

### Core Permissions by API

| API Call | Minimum Permission Required | Notes |
|----------|---------------------------|-------|
| **User Management** | | |
| Get-MgUser | User.Read.All | Basic user info |
| Get-MgUserAuthenticationMethod | UserAuthenticationMethod.Read.All | MFA methods |
| Get-MgUserMemberOf | Directory.Read.All | Group memberships |
| **Role Management** | | |
| Get-MgDirectoryRole | RoleManagement.Read.Directory | Activated roles only |
| Get-MgRoleManagementDirectoryRoleDefinition | RoleManagement.Read.Directory | All role definitions |
| Get-MgRoleManagementDirectoryRoleAssignment | RoleManagement.Read.Directory | Role assignments |
| **Conditional Access** | | |
| Get-MgIdentityConditionalAccessPolicy | ConditionalAccessPolicy.Read.All | Requires P1/P2 |
| Get-MgIdentityConditionalAccessNamedLocation | ConditionalAccessPolicy.Read.All | Requires P1/P2 |
| **Identity Protection** | | |
| Get-MgRiskyUser | IdentityRiskyUser.Read.All | Requires P2 |
| Get-MgRiskDetection | IdentityRiskEvent.Read.All | Requires P2 |
| **Applications** | | |
| Get-MgApplication | Application.Read.All | App registrations |
| Get-MgServicePrincipal | Application.Read.All | Enterprise apps |
| Get-MgOauth2PermissionGrant | DelegatedPermissionGrant.Read.All | Consent grants |
| **Groups** | | |
| Get-MgGroup | Group.Read.All | Group information |
| Get-MgGroupMember | GroupMember.Read.All | Group members |
| **Policies** | | |
| Get-MgPolicyAuthorizationPolicy | Policy.Read.All | Auth policies |
| Get-MgPolicyIdentitySecurityDefaultEnforcementPolicy | Policy.Read.All | Security defaults |
| **Audit Logs** | | |
| Get-MgAuditLogDirectoryAudit | AuditLog.Read.All | Directory audits |
| Get-MgAuditLogSignIn | AuditLog.Read.All | Sign-in logs |

### Permission Scope Combinations

For comprehensive assessment, request these scopes:
```powershell
$requiredScopes = @(
    'User.Read.All',
    'Directory.Read.All',
    'Policy.Read.All',
    'RoleManagement.Read.All',
    'Group.Read.All',
    'Application.Read.All',
    'IdentityRiskEvent.Read.All',      # P2
    'IdentityRiskyUser.Read.All',      # P2
    'UserAuthenticationMethod.Read.All',
    'Organization.Read.All',
    'ConditionalAccessPolicy.Read.All', # P1/P2
    'AuditLog.Read.All'
)
```

## License-Dependent Features

### Free/Basic License
- User and group management
- Basic directory roles
- Security defaults
- Basic authentication methods
- Password policies
- Self-service password reset (basic)

### P1 License Required
- Conditional Access policies
- Group-based licensing
- Self-service group management
- Password writeback
- Cloud app discovery

### P2 License Required
- Identity Protection (risky users/sign-ins)
- Privileged Identity Management (PIM)
- Access reviews
- Entitlement management
- Identity governance features

### License Detection Code
```powershell
function Test-FeatureLicense {
    param([string]$Feature)
    
    try {
        switch ($Feature) {
            "ConditionalAccess" {
                $null = Get-MgIdentityConditionalAccessPolicy -Top 1 -ErrorAction Stop
                return $true
            }
            "IdentityProtection" {
                $null = Get-MgRiskyUser -Top 1 -ErrorAction Stop
                return $true
            }
            "PIM" {
                $null = Get-MgRoleManagementDirectoryRoleAssignmentScheduleInstance -Top 1 -ErrorAction Stop
                return $true
            }
        }
    }
    catch {
        if ($_.Exception.Message -match "Premium|license|P1|P2|InvalidLicense") {
            return $false
        }
        throw $_  # Re-throw if not a license issue
    }
}
```

## Error Handling Patterns

### Pattern 1: License Check
```powershell
try {
    $policies = Get-MgIdentityConditionalAccessPolicy
} catch {
    if ($_.Exception.Message -match "Premium|license|P1|P2|InvalidLicense") {
        # Handle license requirement
        Write-Warning "Conditional Access requires P1/P2 license"
        # Set result to INFORMATION NEEDED
    } else {
        # Handle other errors
        throw $_
    }
}
```

### Pattern 2: Pagination Fallback
```powershell
try {
    # Try with pagination
    $users = Get-MgUser -Top 100
} catch {
    if ($_.Exception.Message -match "page size|UnsupportedQuery|does not support") {
        # Get without pagination
        $users = Get-MgUser
        # Limit in PowerShell
        $users = $users | Select-Object -First 100
    } else {
        throw $_
    }
}
```

### Pattern 3: Permission Handling
```powershell
try {
    $data = Get-MgSomeResource
} catch {
    if ($_.Exception.Message -match "Forbidden|403|Unauthorized|401|Insufficient privileges") {
        # Handle permission issue
        Write-Warning "Insufficient permissions. Required: SomePermission.Read.All"
        # Set result to INFORMATION NEEDED
    } else {
        throw $_
    }
}
```

### Pattern 4: Fallback Methods
```powershell
# Try primary method
$roles = $null
try {
    # Get all role definitions
    $roles = Get-MgRoleManagementDirectoryRoleDefinition
} catch {
    Write-Warning "Failed to get role definitions, trying activated roles"
    try {
        # Fall back to activated roles only
        $roles = Get-MgDirectoryRole
    } catch {
        Write-Error "Unable to retrieve roles by any method"
    }
}
```

## API Throttling Considerations

### Rate Limits
- Microsoft Graph has rate limits per app and per tenant
- Limits vary by endpoint and license type
- Monitor for 429 (Too Many Requests) errors

### Best Practices
```powershell
# Add delays in bulk operations
foreach ($user in $users) {
    try {
        # Do operation
        Get-MgUserAuthenticationMethod -UserId $user.Id
        
        # Add small delay to avoid throttling
        Start-Sleep -Milliseconds 200
    }
    catch {
        if ($_.Exception.Response.StatusCode -eq 429) {
            # Get retry-after header
            $retryAfter = $_.Exception.Response.Headers['Retry-After']
            Write-Warning "Throttled. Waiting $retryAfter seconds"
            Start-Sleep -Seconds $retryAfter
            # Retry operation
        }
    }
}
```

### Batch Operations
For bulk operations, consider using batch requests:
```powershell
# Example: Get multiple users in one request
$batch = @{
    requests = @(
        @{
            id = "1"
            method = "GET"
            url = "/users/user1@domain.com"
        },
        @{
            id = "2"
            method = "GET"
            url = "/users/user2@domain.com"
        }
    )
}

# Note: Batch operations require direct API calls, not available in PowerShell SDK
```

## Alternative Approaches

### 1. Role Information
```powershell
# Primary: Get all role definitions
try {
    $roles = Get-MgRoleManagementDirectoryRoleDefinition
} catch {
    # Fallback: Get only activated roles
    $roles = Get-MgDirectoryRole
    Write-Warning "Using activated roles only (fallback method)"
}
```

### 2. User MFA Status
```powershell
# Method 1: Check authentication methods
try {
    $methods = Get-MgUserAuthenticationMethod -UserId $userId
    $hasMFA = ($methods.Count -gt 1)
} catch {
    # Method 2: Check if security defaults are enabled
    $secDefaults = Get-MgPolicyIdentitySecurityDefaultEnforcementPolicy
    if ($secDefaults.IsEnabled) {
        $hasMFA = $true  # Security defaults enforce MFA
    } else {
        # Method 3: Check sign-in logs for MFA usage
        $signIns = Get-MgAuditLogSignIn -Filter "userId eq '$userId'" -Top 10
        $hasMFA = ($signIns | Where-Object { $_.AuthenticationRequirement -eq 'multiFactorAuthentication' }).Count -gt 0
    }
}
```

### 3. Conditional Access Assessment
```powershell
# If no P1/P2 license
if (-not $hasConditionalAccessLicense) {
    # Check security defaults as alternative
    $secDefaults = Get-MgPolicyIdentitySecurityDefaultEnforcementPolicy
    if ($secDefaults.IsEnabled) {
        Write-Host "Security Defaults provide basic protection"
    } else {
        Write-Warning "No Conditional Access or Security Defaults configured"
    }
}
```

## Connection Best Practices

### Initial Connection
```powershell
function Connect-WithFallback {
    $connected = $false
    
    # Method 1: Interactive
    try {
        Connect-MgGraph -Scopes $requiredScopes -NoWelcome
        $connected = $true
    } catch {
        Write-Warning "Interactive auth failed: $_"
    }
    
    # Method 2: Device code
    if (-not $connected) {
        try {
            Connect-MgGraph -Scopes $requiredScopes -UseDeviceCode -NoWelcome
            $connected = $true
        } catch {
            Write-Warning "Device code auth failed: $_"
        }
    }
    
    # Method 3: Environment/Managed Identity (for automation)
    if (-not $connected) {
        try {
            Connect-MgGraph -Identity -NoWelcome
            $connected = $true
        } catch {
            Write-Warning "Managed identity auth failed: $_"
        }
    }
    
    if (-not $connected) {
        throw "All authentication methods failed"
    }
    
    # Verify connection
    try {
        $org = Get-MgOrganization
        Write-Host "Connected to: $($org.DisplayName)"
    } catch {
        throw "Connected but unable to query organization"
    }
}
```

### Connection Validation
```powershell
function Test-GraphConnection {
    try {
        $context = Get-MgContext
        if (-not $context) { return $false }
        
        # Test with simple call
        $null = Get-MgOrganization -ErrorAction Stop
        return $true
    } catch {
        return $false
    }
}
```

### Re-connection Logic
```powershell
function Invoke-WithReconnect {
    param([ScriptBlock]$ScriptBlock)
    
    try {
        & $ScriptBlock
    } catch {
        if ($_.Exception.Message -match "token|expired|unauthorized") {
            Write-Warning "Token expired, reconnecting..."
            Disconnect-MgGraph
            Connect-MgGraph -Scopes $requiredScopes -NoWelcome
            & $ScriptBlock  # Retry
        } else {
            throw $_
        }
    }
}
```

## Common Error Messages

| Error Message | Meaning | Solution |
|--------------|---------|----------|
| "UnsupportedQuery" | Endpoint doesn't support parameter | Remove -Top, -Skip, -Filter |
| "Request_UnsupportedQuery" | Query parameter not supported | Simplify query, remove parameters |
| "InvalidLicense" | Feature requires higher license | Check P1/P2 requirement |
| "Forbidden" / 403 | Insufficient permissions | Add required scope and reconnect |
| "Unauthorized" / 401 | Authentication issue | Reconnect to Graph |
| "InvalidAuthenticationToken" | Token expired | Reconnect to Graph |
| "TooManyRequests" / 429 | Rate limited | Add delays, check Retry-After |
| "BadRequest" / 400 | Malformed request | Check parameters and syntax |
| "NotFound" / 404 | Resource doesn't exist | Verify ID/name is correct |
| "ServiceUnavailable" / 503 | Service temporarily down | Retry with backoff |

## API-Specific Quirks

### Get-MgUser
```powershell
# Supports -ConsistencyLevel for count
Get-MgUser -Count userCount -ConsistencyLevel eventual

# Complex filters may need ConsistencyLevel
Get-MgUser -Filter "accountEnabled eq false and userType eq 'Guest'" -ConsistencyLevel eventual

# Select specific properties for performance
Get-MgUser -Property DisplayName,UserPrincipalName,Id -Top 100
```

### Get-MgGroup
```powershell
# Dynamic group membership rules need special handling
$dynamicGroups = Get-MgGroup -Filter "groupTypes/any(c:c eq 'DynamicMembership')"

# Large groups may timeout when expanding members
# Get members separately
$group = Get-MgGroup -GroupId $groupId
$members = Get-MgGroupMember -GroupId $groupId -All
```

### Get-MgDirectoryRole vs Get-MgRoleManagementDirectoryRoleDefinition
```powershell
# DirectoryRole = Activated roles only
$activatedRoles = Get-MgDirectoryRole

# RoleDefinition = All available roles
$allRoles = Get-MgRoleManagementDirectoryRoleDefinition

# To activate a role
$roleDefinition = Get-MgRoleManagementDirectoryRoleDefinition -Filter "displayName eq 'Global Administrator'"
$activatedRole = New-MgDirectoryRole -RoleTemplateId $roleDefinition.TemplateId
```

### Conditional Access Policies
```powershell
# State can be: enabled, disabled, enabledForReportingButNotEnforced
$activePolicies = Get-MgIdentityConditionalAccessPolicy | Where-Object { $_.State -eq "enabled" }

# Conditions are complex objects
foreach ($policy in $activePolicies) {
    # Check what it applies to
    $users = $policy.Conditions.Users
    $apps = $policy.Conditions.Applications
    $locations = $policy.Conditions.Locations
    
    # Check what it enforces
    $controls = $policy.GrantControls
    $session = $policy.SessionControls
}
```

## Code Examples

### Complete Error Handling Example
```powershell
function Get-UsersWithFallback {
    param(
        [int]$Limit = 100,
        [string]$Filter
    )
    
    $users = @()
    
    # Try optimal method
    try {
        if ($Filter) {
            $users = Get-MgUser -Filter $Filter -Top $Limit -ConsistencyLevel eventual -ErrorAction Stop
        } else {
            $users = Get-MgUser -Top $Limit -ErrorAction Stop
        }
        Write-Verbose "Retrieved $($users.Count) users with pagination"
        return $users
    }
    catch {
        Write-Warning "Pagination failed: $_"
    }
    
    # Try without pagination
    try {
        if ($Filter) {
            $users = Get-MgUser -Filter $Filter -ConsistencyLevel eventual -ErrorAction Stop
        } else {
            $users = Get-MgUser -ErrorAction Stop
        }
        
        # Limit in PowerShell
        if ($users.Count -gt $Limit) {
            Write-Verbose "Limiting $($users.Count) users to $Limit in PowerShell"
            $users = $users | Select-Object -First $Limit
        }
        
        return $users
    }
    catch {
        Write-Warning "Standard query failed: $_"
    }
    
    # Try without filter
    if ($Filter) {
        try {
            Write-Warning "Trying without filter"
            $allUsers = Get-MgUser -ErrorAction Stop
            
            # Apply filter in PowerShell (simplified)
            if ($Filter -match "userType eq 'Guest'") {
                $users = $allUsers | Where-Object { $_.UserType -eq 'Guest' }
            } else {
                $users = $allUsers
            }
            
            return $users | Select-Object -First $Limit
        }
        catch {
            Write-Error "All methods failed: $_"
            return @()
        }
    }
    
    throw "Unable to retrieve users"
}
```

### Comprehensive Permission Check
```powershell
function Test-RequiredPermissions {
    $permissions = @{
        'User.Read.All' = { Get-MgUser -Top 1 }
        'Group.Read.All' = { Get-MgGroup -Top 1 }
        'RoleManagement.Read.All' = { Get-MgRoleManagementDirectoryRoleDefinition -Top 1 }
        'ConditionalAccessPolicy.Read.All' = { Get-MgIdentityConditionalAccessPolicy -Top 1 }
        'IdentityRiskyUser.Read.All' = { Get-MgRiskyUser -Top 1 }
    }
    
    $results = @{}
    
    foreach ($permission in $permissions.GetEnumerator()) {
        try {
            $null = & $permission.Value -ErrorAction Stop
            $results[$permission.Key] = "Granted"
        }
        catch {
            if ($_.Exception.Message -match "Insufficient privileges|Forbidden") {
                $results[$permission.Key] = "Not Granted"
            }
            elseif ($_.Exception.Message -match "Premium|license") {
                $results[$permission.Key] = "License Required"
            }
            else {
                $results[$permission.Key] = "Error: $_"
            }
        }
    }
    
    return $results
}
```

## Quick Reference Card

```powershell
# Connection
Connect-MgGraph -Scopes "User.Read.All","Directory.Read.All" -NoWelcome

# Test connection
if (-not (Test-GraphConnection)) { throw "Not connected" }

# Get users with fallback
try {
    $users = Get-MgUser -Top 100
} catch {
    $users = Get-MgUser | Select-Object -First 100
}

# Check for P1/P2 features
$hasP2 = $false
try {
    $null = Get-MgRiskyUser -Top 1
    $hasP2 = $true
} catch {
    # P2 not available
}

# Handle licenses gracefully
if (-not $hasP2) {
    # Use alternative checks
    $secDefaults = Get-MgPolicyIdentitySecurityDefaultEnforcementPolicy
}

# Always add error context
catch {
    Write-Error "Failed to get users: $_"
    Write-Error "Ensure you have User.Read.All permission"
}
```