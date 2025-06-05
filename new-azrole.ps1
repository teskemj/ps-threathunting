Connect-AzAccount

# Define variables
$UserPrincipalName = "jane.doe@techsolutions-wi.com"
$RoleName = "User Access Administrator"
$Scope = "/subscriptions/f4af2ab3-0ef6-4188-8d70-8fb2ae2ce711"

# Get user and role objects
$User = Get-AzADUser -UserPrincipalName $UserPrincipalName
$Role = Get-AzRoleDefinition -Name $RoleName

# Assign role
New-AzRoleAssignment -ObjectId $User.Id -RoleDefinitionId $Role.Id -Scope $Scope