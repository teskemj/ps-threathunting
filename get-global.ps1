Connect-MgGraph -Scopes "RoleManagement.Read.Directory"

# Ensure the role exists in your tenant
$role = Get-MgDirectoryRole | Where-Object { $_.DisplayName -eq "Global Administrator" }

# List all users assigned to that role
Get-MgDirectoryRoleMember -DirectoryRoleId $role.Id | ForEach-Object {
    Get-MgUser -UserId $_.Id
}
