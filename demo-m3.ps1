# Connect Microsoft Graph to RoleManagement scope
Connect-MgGraph -Scopes "RoleManagement.Read.Directory"

# Ensure the role exists in your tenant
$role = Get-MgDirectoryRole | Where-Object { $_.DisplayName -eq "Global Administrator" }

# List all users assigned to that role
Get-MgDirectoryRoleMember -DirectoryRoleId $role.Id | ForEach-Object {
    Get-MgUser -UserId $_.Id
}


# Connect to Microsoft Graph with the auditlog scope
Connect-MgGraph -Scopes AuditLog.Read.All

Get-MgAuditLogSignIn -Top 10 | Where-Object { $_.ConditionalAccessStatus -eq "notApplied" -or $_.AuthenticationRequirement -eq "singleFactorAuthentication" } |Select-Object UserDisplayName, IPAddress, AppDisplayName, ConditionalAccessStatus, AuthenticationRequirement, RiskDetail


# Connect to Microsoft Graph with the Directory scope
Connect-MgGraph -Scopes Directory.Read.All

# Viewing dangerous scopes and unverified publishers
Get-MgOauth2PermissionGrant -Top 10 | Where-Object { $_.Scope –match` "Mail.Read|Files.Read|offline_access" } | `
Select-Object ClientId, ConsentType, PrincipalId, ResourceId, Scope
