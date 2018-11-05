$tenantId = (Get-AzureADTenantDetail).ObjectId
$jsonDepth = 99
$folderPath = Join-Path -Path $PSScriptRoot -ChildPath $tenantId

if (-not (Test-Path -Path $folderPath)) {
    New-Item -Path $folderPath -ItemType Directory
}

Connect-AzureAD -TenantId $tenantId

$mfaUsers = Get-MsolUser -All | 
    Select-Object DisplayName, UserPrincipalName, MFAStatus, WhenCreated |
    Add-Member -MemberType NoteProperty -Name MFAStatus -Value 'Disabled' -PassThru
    
    if ($null -ne $_.StrongAuthenticationRequirements.State) {
        $_.MFAStatus = $_.StrongAuthenticationRequirements.State
    }
}

$mfaUsers | ConvertTo-Json -Depth $jsonDepth | Out-File -FilePath (Join-Path -Path $folderPath -ChildPath 'userMFAStatus.json') -Force

Get-AzureADDomain | ConvertTo-Json -Depth $jsonDepth | Out-File -FilePath (Join-Path -Path $folderPath -ChildPath 'domains.json') -Force
Get-AzureADDirectoryRole | ConvertTo-Json -Depth $jsonDepth | Out-File -FilePath (Join-Path -Path $folderPath -ChildPath 'roles.json') -Force
Get-AzureADGroup | ConvertTo-Json -Depth $jsonDepth | Out-File -FilePath (Join-Path -Path $folderPath -ChildPath 'groups.json') -Force
Get-AzureADUser | ConvertTo-Json -Depth $jsonDepth | Out-File -FilePath (Join-Path -Path $folderPath -ChildPath 'users.json') -Force
Get-AzureADPolicy | ConvertTo-Json -Depth $jsonDepth | Out-File -FilePath (Join-Path -Path $folderPath -ChildPath 'tokenpolicies.json') -Force 
Get-AzureADSubscribedSku | ConvertTo-Json -Depth $jsonDepth | Out-File -FilePath (Join-Path -Path $folderPath -ChildPath 'subscribedSkus.json') -Force 
Get-AzureADTenantDetail | ConvertTo-Json -Depth $jsonDepth | Out-File -FilePath (Join-Path -Path $folderPath -ChildPath 'tenantDetail.json') -Force


$roles = Get-Content -Path (Join-Path -Path $folderPath -ChildPath 'roles.json') | ConvertFrom-Json
$roleMembers = [System.Collections.ArrayList]::new()

foreach ($role in $roles) {
    $members = Get-AzureADDirectoryRoleMember -ObjectId $role.ObjectId
    $members | 
    Add-Member -MemberType NoteProperty -Name DirectoryRoleName -Value $role.DisplayName -PassThru |
    Add-Member -MemberType NoteProperty -Name RoleObjectId -Value $role.ObjectId -PassThru |
    Add-Member -MemberType NoteProperty -Name IsRoleDisabled -Value $role.RoleDisabled

    [void]$roleMembers.Add($members)
}

$roleMembers | ConvertTo-Json -Depth $jsonDepth | Out-File (Join-Path -Path $folderPath -ChildPath 'roleMembers.json') -Force