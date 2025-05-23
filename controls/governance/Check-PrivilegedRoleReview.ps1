function Check-PrivilegedRoleReview {
    [CmdletBinding()]
    param()

    $controlResult = [PSCustomObject]@{
        Control = "Ensure that all 'privileged' role assignments are periodically reviewed"
        ControlDescription = "Privileged role assignments should be reviewed regularly to ensure they remain appropriate and follow least privilege principles."
        Finding = ""
        Result = ""
        Evidence = ""
        RemediationSteps = ""
        AffectedAccounts = @()
    }

    try {
        $evidence = Format-EvidenceSection -Title "PRIVILEGED ROLE REVIEW ASSESSMENT" -Content "Assessment Date: $(Get-Date)" -IsHeader
        
        # Get privileged roles
        $privilegedRoles = Get-MgRoleManagementDirectoryRoleDefinition | Where-Object { 
            $_.IsPrivileged -eq $true
        }
        
        $evidence += "`nPrivileged Roles Found: $($privilegedRoles.Count)"
        
        # Check for access reviews (requires P2)
        $hasP2License = Test-EntraIDP2License
        
        if ($hasP2License) {
            try {
                # Get access review definitions
                $accessReviews = Get-MgIdentityGovernanceAccessReviewDefinition
                $roleReviews = @()
                
                foreach ($review in $accessReviews) {
                    # Check if review is for privileged roles
                    if ($review.Scope.Query -match "roleDefinitionId" -or 
                        $review.DisplayName -match "role|admin|privilege") {
                        $roleReviews += $review
                        $evidence += "`n`nRole Review Found: $($review.DisplayName)"
                        $evidence += "`nStatus: $($review.Status)"
                        $evidence += "`nRecurrence: $($review.Settings.Recurrence.Pattern.Type)"
                    }
                }
                
                if ($roleReviews.Count -gt 0) {
                    $controlResult.Finding = "Access reviews are configured for privileged roles"
                    $controlResult.Result = "COMPLIANT"
                    $evidence += "`n`nStatus: Regular reviews are in place"
                }
                else {
                    $controlResult.Finding = "No access reviews found for privileged roles"
                    $controlResult.Result = "NOT COMPLIANT"
                    $evidence += "`n`nStatus: Privileged roles are not regularly reviewed"
                }
            }
            catch {
                $evidence += "`n`nUnable to check access reviews: $_"
                $controlResult.Result = "PARTIALLY COMPLIANT"
            }
        }
        else {
            # Check role assignment dates for manual review
            $oldAssignments = @()
            $evidence += "`n`nChecking role assignment ages (P2 required for automated reviews):"
            
            foreach ($role in $privilegedRoles | Select-Object -First 5) {
                $assignments = Get-MgRoleManagementDirectoryRoleAssignment -Filter "roleDefinitionId eq '$($role.Id)'"
                
                foreach ($assignment in $assignments) {
                    # Calculate age (if creation date available)
                    if ($assignment.CreatedDateTime) {
                        $age = (Get-Date) - $assignment.CreatedDateTime
                        if ($age.Days -gt 180) {
                            $oldAssignments += [PSCustomObject]@{
                                Role = $role.DisplayName
                                Age = $age.Days
                                PrincipalId = $assignment.PrincipalId
                            }
                        }
                    }
                }
            }
            
            if ($oldAssignments.Count -gt 0) {
                $controlResult.Finding = "Some privileged role assignments are older than 180 days without review"
                $controlResult.Result = "NOT COMPLIANT"
                $evidence += "`n`nOld assignments found: $($oldAssignments.Count)"
                
                foreach ($old in $oldAssignments | Select-Object -First 10) {
                    try {
                        $user = Get-MgUser -UserId $old.PrincipalId -ErrorAction SilentlyContinue
                        if ($user) {
                            $controlResult.AffectedAccounts += [PSCustomObject]@{
                                Name = $user.DisplayName
                                Id = $user.Id
                                Details = "Role: $($old.Role), Age: $($old.Age) days"
                            }
                        }
                    } catch {}
                }
            }
            else {
                $controlResult.Finding = "Manual verification required (Entra ID P2 needed for access reviews)"
                $controlResult.Result = "INFORMATION NEEDED"
            }
        }
        
        $controlResult.Evidence = $evidence
        
        if ($controlResult.Result -ne "COMPLIANT") {
            $controlResult.RemediationSteps = @"
<ol>
    <li>For automated reviews (requires Entra ID P2):
        <ul>
            <li>Navigate to Identity Governance > Access reviews</li>
            <li>Create new access review</li>
            <li>Select "Teams + Groups" or "Applications"</li>
            <li>Choose privileged role groups</li>
            <li>Set recurrence (quarterly recommended)</li>
            <li>Configure reviewers and notifications</li>
        </ul>
    </li>
    <li>For manual reviews:
        <ul>
            <li>Export privileged role assignments monthly</li>
            <li>Review with management for continued need</li>
            <li>Document justifications</li>
            <li>Remove unnecessary assignments</li>
        </ul>
    </li>
    <li>Implement PIM for just-in-time access where possible</li>
</ol>
"@
        }
    }
    catch {
        $controlResult.Finding = "Error assessing privileged role reviews: $_"
        $controlResult.Result = "ERROR"
        $controlResult.Evidence = "Error details: $_"
    }
    
    return $controlResult
}

# Execute the control check
Check-PrivilegedRoleReview