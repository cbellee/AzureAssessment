$tenants = Get-ChildItem -Path $PSScriptRoot\..\data\tenants -Directory
$subscriptions = Get-ChildItem -Path $PSScriptRoot\..\data\subscriptions -Directory 
$tenantId = (Get-ChildItem $subscriptions.fullname -Filter subscriptionData.json | Select-Object -First 1 | Get-Content | ConvertFrom-Json).TenantId

If (-not (Get-AzureADCurrentSessionInfo)) {
    Connect-AzureAD -TenantId $TenantId
}

function Get-RecursiveAzureADGroupMemberUsers {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $True, ValueFromPipeline = $true)]
        $AzureGroup,
        [Parameter()]
        $TenantId
    )
    Begin {
        If (-not(Get-AzureADCurrentSessionInfo)) {
            Connect-AzureAD -TenantId $TenantId
        }
    }

    Process {
        Write-Verbose -Message "Enumerating $($AzureGroup.DisplayName)"
        $Members = Get-AzureADGroupMember -ObjectId $AzureGroup.ObjectId -All $true    
        $UserMembers = $Members | Where-Object {$_.ObjectType -eq 'User'}
        
        If ($Members | Where-Object {$_.ObjectType -eq 'Group'}) {
            $UserMembers += $Members | Where-Object {$_.ObjectType -eq 'Group'} | ForEach-Object { Get-RecursiveAzureAdGroupMemberUsers -AzureGroup $_}
        }
    }

    End {
        Return $UserMembers
    }
}

foreach ($tenant in $tenants) {

    # import JSON files
    $userData = Get-Content -Path "$($tenant.FullName)\users.json" | ConvertFrom-Json
    $domainData = Get-Content -Path "$($tenant.FullName)\Domains.json" | ConvertFrom-Json
    $roleMembers = Get-Content -Path "$($tenant.FullName)\roleMembers.json" | ConvertFrom-Json
    $userMFAStatusData = Get-Content -Path "$($tenant.FullName)\userMFAStatus.json" | ConvertFrom-Json
    $userMFAStatusDataHash = @{}
    $uniqueUsers = @{}
    $userMFAStatusData | Foreach-Object {$userMFAStatusDataHash[$_.UserPrincipalName] = $_.MFAStatus}

    Describe "Directory.$($tenant.Name)" {   
        foreach ($user in $roleMembers.value | Where-Object ObjectType -eq 'User') {				
            # collect unique users
            $uniqueUsers[$user.UserPrincipalName] += $user.DirectoryRoleName
        }
        foreach ($uniqueUser in $uniqueUsers.GetEnumerator()) {
            
            It "user '$($uniqueUser.Name)' in Directory role(s) '$($uniqueUser.value)' is not an external account" {
                ($uniqueUser.Name -split '@')[1] -in $domainData.Name -and ($uniqueUser.Name -split '@')[0] -match '#EXT#' | Should Be $false
            }
            
            It "user '$($uniqueUser.Name)' in Directory role '$($uniqueUser.value)' has Multi-Factor Authentication enabled" {
                $userMFAStatusDataHash[$($uniqueUser.Name)] | Should Be 'Enforced'
            }
        }
    }
}

foreach ($subscription in $subscriptions) {

    #$roleDefinitionData = Get-Content -Path "$($subscription.FullName)\azureRoleDefinitionData.json" | ConvertFrom-Json
    $subscriptionData = Get-Content -Path "$($subscription.FullName)\subscriptionData.json" | ConvertFrom-Json
    $roleAssignmentData = Get-Content -Path "$($subscription.FullName)\azureRoleAssignmentData.json" | ConvertFrom-Json
    $subscriptionData = Get-Content -Path "$($subscription.FullName)\subscriptionData.json" | ConvertFrom-Json

    Describe "RBAC.$($subscriptionData.SubscriptionId)" {
        foreach ($roleAssignment in $roleAssignmentData) {
            if ($roleAssignment.Scope -eq "/subscriptions/$($subscriptionData.SubscriptionId)") {
                if ($roleAssignment.ObjectType -eq 'User') {
                    switch ($roleAssignment) {
                        {$roleAssignment.RoleDefinitionName -eq 'Contributor'} {
                        
                            It "user '$($roleAssignment.SignInName)' in RBAC role '$($roleAssignment.RoleDefinitionName)' has MFA enabled" {
                                $userMFAStatusDataHash[$($roleAssignment.SignInName)] | Should Be 'Enforced'
                            }
                        }

                        {$roleAssignment.RoleDefinitionName -eq 'Owner'} {
                            It "user '$($roleAssignment.SignInName)' in RBAC role '$($roleAssignment.RoleDefinitionName)' has MFA enabled" {
                                $userMFAStatusDataHash[$($roleAssignment.SignInName)] | Should Be 'Enforced'
                            }
                        }
                    } # switch
                } # if
                elseif ($roleAssignment.ObjectType -eq 'Group') {
                    switch ($roleAssignment) {
                        {$roleAssignment.RoleDefinitionName -eq 'Contributor'} {                           
                                foreach ($principal in (Get-AzureADGroup -ObjectId $roleAssignment.ObjectId | Get-RecursiveAzureADGroupMemberUsers)) {
                                    It "user '$($principal.UserPrincipalName)' in RBAC role '$($roleAssignment.RoleDefinitionName)' has MFA enabled" {
                                        $userMFAStatusDataHash[$($principal.UserPrincipalName)] | Should Be 'Enforced'
                                    }
                                }
                            }

                        {$roleAssignment.RoleDefinitionName -eq 'Owner'} {
                            foreach ($principal in (Get-AzureADGroup -ObjectId $roleAssignment.ObjectId | Get-RecursiveAzureADGroupMemberUsers)) {
                                It "user '$($principal.UserPrincipalName)' in RBAC role '$($roleAssignment.RoleDefinitionName)' has MFA enabled" {
                                    $userMFAStatusDataHash[$($principal.UserPrincipalName)] | Should Be 'Enforced'
                                }
                            }
                        }
                    } # switch
                } # elseif
            } # if
        } # foreach
    }
}
