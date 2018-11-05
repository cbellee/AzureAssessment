[CmdletBinding()]

param(
    $diagnosticsLogsCategories,
    $allowedVmExtensions,
    $subscription,
    $azureDatacenterIpRanges,
    $defaultRules
)

    # set context to current subscription
    Write-Information -MessageData "setting subscription context to '$($subscription.Name)'"
    Set-AzureRmContext -SubscriptionObject $subscription | Out-Null

    # get vm Backup data
    Write-Information -MessageData "getting VM Backup info..."
    $vmBackupItems = Get-VMBackupItems

    # get Azure Update Configuration for all automation accounts
    Write-Information -MessageData "getting VM update configuration info..."
    $vmUpdateConfigurationData = (Get-AzureRmAutomationAccount | 
            ForEach-Object {
            Get-AzureRmAutomationSoftwareUpdateConfiguration -ResourceGroupName $_.ResourceGroupName -AutomationAccountName $_.AutomationAccountName
        }).UpdateConfiguration.AzureVirtualMachines    

    # get resources
    Write-Information -MessageData "getting VMs..."
    $vms = Search-AzureRmGraph -Subscription $subscription -Query "where type =~ 'Microsoft.Compute/virtualMachines'"

    Write-Information -MessageData "getting vNets..."
    $vnets = Search-AzureRmGraph -Subscription $subscription -Query "where type =~ 'Microsoft.Network/virtualNetworks'"

    Write-Information -MessageData "getting NSGs..."
    $nsgs = Search-AzureRmGraph -Subscription $subscription -Query "where type =~ 'Microsoft.Network/networkSecurityGroups'"

    Write-Information -MessageData "getting Storage Accounts..."
    $storageAccounts = Search-AzureRmGraph -Subscription $subscription -Query "where type =~ 'Microsoft.Storage/storageAccounts'"

    Write-Information -MessageData "getting VM extensions..."
    $vmExtensions = Search-AzureRmGraph -Subscription $subscription -Query "where type =~ 'Microsoft.Compute/virtualMachines/extensions'" | 
        ForEach-Object {
        $vmName = $_.resourceId.trim('/') -split '/' | Select-Object -Index 7
        $_ | Add-Member -MemberType NoteProperty -Name vmName -Value $vmName -PassThru
    }

    Write-Information -MessageData "getting SQL servers..."
    $sqlServers = Search-AzureRmGraph -Subscription $subscription -Query "where type =~'Microsoft.Sql/servers'"

    Write-Information -MessageData "getting SQL databases..."
    $sqlDatabases = Search-AzureRmGraph -Subscription $subscription -Query "where type =~'Microsoft.Sql/databases'"

    Write-Information -MessageData "getting network watchers..."
    $networkWatchers = Search-AzureRmGraph -Subscription $subscription -Query "where type =~ 'Microsoft.Network/networkWatchers'"

    Write-Information -MessageData "getting diagnostics..."
    $diagnostics = @()
    Search-AzureRmGraph -Subscription $subscription -Query "project type, id" |
        Where-Object {$_.type -in $resourceDiagnostics} | 
        ForEach-Object {
        $diagnosticData = $null
        $diagnosticData = Get-AzureRmDiagnosticSetting -ResourceId $_.id -ErrorAction SilentlyContinue
        $diagData = New-DiagnosticsDataLogObject -Data $diagnosticData
        $diagnostics += $_ | 
            Add-Member -MemberType NoteProperty -Name DiagnosticsSettings -Value $diagData -PassThru |
            Add-Member -MemberType NoteProperty -Name WorkspaceId -Value $diagnosticData.WorkspaceId -PassThru
    }
    
    #region pester tests
    Describe -Name 'VirtualMachines' -Tag 'Compute' -Fixture {
        Context -Name $subscription.id -Fixture {
            Write-Information -MessageData "performing 'VirtualMachines' tests..."

            foreach ($vm in $vms) {
                $resource = $vm.id

                It "'$resource' has tags" {
                    $vm.tags | Should Not BeNullOrEmpty
                }

                It "'$resource' has managed OS disk" {
                    $vm.properties.storageProfile.osDisk.managedDisk | Should Not BeNullOrEmpty
                }

                It "'$resource' has managed Data disks" {
                    foreach ($dataDisk in $vm.properties.storageProfile.dataDisks) {
                        $dataDisk.ManagedDisk | Should Not BeNullOrEmpty
                    }
                }

                It "'$resource' has disk encryption enabled" {
                    $vm.properties.storageProfile.osDisk.managedDisk.encryptionSettings | Should Not BeNullOrEmpty
                }

                It "'$resource' has boot diagnostics enabled" {
                    $vm.properties.diagnosticsProfile.bootDiagnostics.enabled | Should be $true
                }

                It "'$resource' has accelerated networking enabled" {
                    $nics = $vm.properties.networkProfile.networkInterfaces
                    foreach ($nic in $nics) {
                        (Search-AzureRmGraph -Subscription $subscription -Query "where type =~ 'Microsoft.Compute/networkInterfaces' and id == '$($nic.id)'").properties.enableAcceleratedNetworking | 
                            Should Be $true
                    }
                }

                It "'$resource' has no Public Nics" {
                    $nics = $vm.properties.networkProfile.networkInterfaces
                    foreach ($nic in $nics) {
                        (Search-AzureRmGraph -Subscription $subscription -Query "where type =~ 'Microsoft.Compute/networkInterfaces' and id == '$($nic.id)'").properties.ipConfigurations.publicIpAddress.id | 
                            Should BeNullOrEmpty
                    }
                }
            
                It "'$resource' has recovery vault backup enabled" {
                    $vmBackupItems.Where( {$_.virtualMachineId -eq $vm.id})  | Should Not BeNullOrEmpty
                }

                It "'$resource' has a successful recovery vault backup" {
                    $foundVm = $null
                    $foundVm = $vmBackupItems.Where( {$_.virtualMachineId -eq $vm.id})
                    $foundVm.LastBackupStatus | Should BeExactly 'Completed'
                }

                It "'$resource' has update management configured" {
                    $vm.id -in $vmUpdateConfigurationData | Should Be $true
                }

                if ($null -ne $vm.properties.osProfile.windowsConfiguration) {
                    foreach ($extensionName in $allowedVmExtensions.Windows) {
                        It "'$resource' has extension '$extensionName' installed successfully" {
                            $vmExtensions.Where( {$_.vmName -eq $vm.Name -and $_.resourceGroup -eq $vm.resourceGroup -and $_.name -eq $extensionName -and $_.properties.provisioningState -eq 'Succeeded'}) | 
                                Should Not BeNullOrEmpty
                        }
                    }
                }
                else {
                    foreach ($extensionName in $allowedVmExtensions.Linux) {
                        It "'$resource' has extension '$extensionName' installed successfully" {
                            $vmExtensions.Where( {$_.vmName -eq $vm.Name -and $_.resourceGroup -eq $vm.resourceGroup -and $_.name -eq $extensionName -and $_.properties.provisioningState -eq 'Succeeded'}) | 
                                Should Not BeNullOrEmpty
                        }
                    }
                }
            }
        }
    }

    Describe -Name 'Alerts' -Tag 'Monitoring' -Fixture {  
        Context -Name $subscription.id -Fixture {
            Write-Information -MessageData "performing 'Alerts' tests..."

            It "subscription '$($subscription.id)' has an activitylogalert for 'Microsoft.Authorization/policyAssignments/write'" {
                Search-AzureRmGraph -Subscription $subscription -Query "where type =~ 'Microsoft.Insights/activitylogalerts' | `
                extend alertType = properties.condition.allOf | `
                where alertType.equals == 'Microsoft.Authorization/policyAssignments/write'" |
                    Should Not BeNullOrEmpty
            }

            It "subscription '$($subscription.id)' has an activitylogalert for 'Microsoft.Network/networkSecurityGroups/write'" {
                Search-AzureRmGraph -Subscription $subscription -Query "where type =~ 'Microsoft.Insights/activitylogalerts' | `
                extend alertType = properties.condition.allOf | `
                where alertType.equals == 'Microsoft.Network/networkSecurityGroups/write'" |
                    Should Not BeNullOrEmpty
            }

            It "subscription '$($subscription.id)' has an activitylogalert for 'Microsoft.Network/networkSecurityGroups/delete'" {
                Search-AzureRmGraph -Subscription $subscription -Query "where type =~ 'Microsoft.Insights/activitylogalerts' | `
                extend alertType = properties.condition.allOf | `
                where alertType.equals == 'Microsoft.Network/networkSecurityGroups/delete'" |
                    Should Not BeNullOrEmpty
            }

            It "subscription '$($subscription.id)' has an activitylogalert for 'Microsoft.Network/networkSecurityGroups/securityRules/write'" {
                Search-AzureRmGraph -Subscription $subscription -Query "where type =~ 'Microsoft.Insights/activitylogalerts' | `
                extend alertType = properties.condition.allOf | `
                where alertType.equals == 'Microsoft.Network/networkSecurityGroups/securityRules/write'" |
                    Should Not BeNullOrEmpty
            }

            It "subscription '$($subscription.id)' has an activitylogalert for 'Microsoft.Network/networkSecurityGroups/securityRules/delete'" {
                Search-AzureRmGraph -Subscription $subscription -Query "where type =~ 'Microsoft.Insights/activitylogalerts' | `
                extend alertType = properties.condition.allOf | `
                where alertType.equals == 'Microsoft.Network/networkSecurityGroups/securityRules/delete'" |
                    Should Not BeNullOrEmpty
            }

            It "subscription '$($subscription.id)' has an activitylogalert for 'Microsoft.Security/securitySolutions/write'" {
                Search-AzureRmGraph -Subscription $subscription -Query "where type =~ 'Microsoft.Insights/activitylogalerts' | `
                extend alertType = properties.condition.allOf | `
                where alertType.equals == 'Microsoft.Security/securitySolutions/write'" |
                    Should Not BeNullOrEmpty
            }

            It "subscription '$($subscription.id)' has an activitylogalert for 'Microsoft.Security/securitySolutions/delete'" {
                Search-AzureRmGraph -Subscription $subscription -Query "where type =~ 'Microsoft.Insights/activitylogalerts' | `
                extend alertType = properties.condition.allOf | `
                where alertType.equals == 'Microsoft.Security/securitySolutions/delete'" |
                    Should Not BeNullOrEmpty
            }

            It "subscription '$($subscription.id)' has an activitylogalert for 'Microsoft.Security/policies/write'" {
                Search-AzureRmGraph -Subscription $subscription -Query "where type =~ 'Microsoft.Insights/activitylogalerts' | `
                extend alertType = properties.condition.allOf | `
                where alertType.equals == 'Microsoft.Security/policies/write'" |
                    Should Not BeNullOrEmpty
            }

            It "subscription '$($subscription.id)' has an activitylogalert for 'Microsoft.Security/policies/delete'" {
                Search-AzureRmGraph -Subscription $subscription -Query "where type =~ 'Microsoft.Insights/activitylogalerts' | `
                extend alertType = properties.condition.allOf | `
                where alertType.equals == 'Microsoft.Security/policies/delete'" |
                    Should Not BeNullOrEmpty
            }

            It "subscription '$($subscription.id)' has an activitylogalert for 'Microsoft.Sql/servers/firewallRules/write'" {
                Search-AzureRmGraph -Subscription $subscription -Query "where type =~ 'Microsoft.Insights/activitylogalerts' | `
                extend alertType = properties.condition.allOf | `
                where alertType.equals == 'Microsoft.Sql/servers/firewallRules/write'" |
                    Should Not BeNullOrEmpty
            }

            It "subscription '$($subscription.id)' has an activitylogalert for 'Microsoft.Sql/servers/firewallRules/delete'" {
                Search-AzureRmGraph -Subscription $subscription -Query "where type =~ 'Microsoft.Insights/activitylogalerts' | `
                extend alertType = properties.condition.allOf | `
                where alertType.equals == 'Microsoft.Sql/servers/firewallRules/delete'" |
                    Should Not BeNullOrEmpty
            }
        }
    }

    Describe -Name 'VirtualNetworks' -Tag 'Network' -Fixture {
        Context -Name $subscription.id -Fixture {
            Write-Information -MessageData "performing 'VirtualNetworks' tests..."

            foreach ($vnet in $vnets) {
                $resource = $vnet.id

                It "'$resource' has tags" {
                    $vnet.tags | Should Not BeNullOrEmpty
                }

                It "'$resource' has standard DDOS protection enabled" {
                    $vnet.properties.enableDdosProtection | Should Be $true
                }

                It "'$resource' has VM protection enabled" {
                    $vnet.properties.enableVmProtection | Should Be $true
                }
            
                if ($null -ne $vnet.properties.VirtualNetworkPeerings) {
                    foreach ($peer in $vnet.properties.VirtualNetworkPeerings) {
                        It "$($peer.id)' is Connected" {
                            $peer.properties.PeeringState | Should Be Exactly 'Connected'
                        }
                    }
                }

                foreach ($subnet in $vnet.properties.subnets) {
                    $resource = $subnet.id

                    if ($subnet.name -eq 'GatewaySubnet') {
                        It "'$resource' does not have a networkSecurityGroup" {
                            $subnet.properties.networkSecurityGroup | Should BeNullOrEmpty
                        }
                    }
                    else {
                        It "'$resource' has a networkSecurityGroup" {
                            $subnet.properties.networkSecurityGroup | Should Not BeNullOrEmpty
                        }

                        It "'$resource' has a routeTable" {
                            $subnet.properties.routeTable | Should Not BeNullOrEmpty
                        }
                    }
                }
            } 
        }
    }

    Describe -Name 'NetworkSecurityGroups' -Tag 'Network' -Fixture {    
        Context -Name $subscription.id -Fixture {   
            Write-Information -MessageData "performing 'NetworkSecurityGroups' tests..."

            foreach ($nsg in $nsgs) {
                $resource = $nsg.id

                It "'$resource' has tags" {
                    $nsg.tags | Should Not BeNullOrEmpty
                }

                foreach ($rule in $nsg.properties.securityRules) {
                    $resource = $rule.id
                    $destPortRange = $rule.destinationPortRange 
                    $destPrefixes = $rule.destinationAddressPrefix
                    $sourcePrefixes = $rule.sourceAddressPrefix

                    foreach ($destPrefix in $destPrefixes) {
                        if ($rule.direction -eq 'Outbound' -and $rule.access -eq 'Allow' -and $rule.priority -notin $defaultRules) {
                            switch ($destPrefix) {
                                'Internet' {
                                    It "'$resource' destination port range is not '*'" {
                                        $destPortRange | Should Not Be '*'
                                    }
                                    break
                                }

                                'VirtualNetwork' {                        
                                    break
                                }
                                
                                'AzureLoadBalancer' {
                                    break
                                }      

                                '*' {
                                    It "'$resource' destination port range is not '*'" {
                                        $destPortRange | Should Not Be '*'
                                    }
                                    break
                                }  
                            
                                {$_ -in $azureDataCenterIpRanges} {
                                    break
                                }   
                                
                                {$_ -notin $azureDataCenterIpRanges} {

                                    if (Assert-PublicIp -IpAddress $_) {
                                        It "'$resource' destination port range is not '*'" {
                                            $destPortRange | Should Not Be '*'
                                        }
                                    }
                                    break
                                }                     

                                default {
                                    "default hit for '$_'"
                                }
                            }
                        }
                    }

                    foreach ($sourcePrefix in $sourcePrefixes) {
                        if ($rule.direction -eq 'Inbound' -and $rule.access -eq 'Allow' -and $rule.priority -notin $defaultRules) {
                            switch ($sourcePrefix) {
                                'Internet' {
                                    It "'$resource' destination port range is not '*'" {
                                        $destPortRange | Should Not Be '*'
                                    }
                                    break
                                }

                                'VirtualNetwork' {                        
                                    break
                                }
                                
                                'AzureLoadBalancer' {
                                    break
                                }      

                                '*' {
                                    It "'$resource' destination port range is not '*'" {
                                        $destPortRange | Should Not Be '*'
                                    }
                                    break
                                }  
                            
                                {$_ -in $azureDataCenterIpRanges} {
                                    break
                                }   
                                
                                {$_ -notin $azureDataCenterIpRanges} {

                                    if (Assert-PublicIp -IpAddress $_) {
                                        It "'$resource' destination port range is not '*'" {
                                            $destPortRange | Should Not Be '*'
                                        }
                                    }
                                    break
                                }                     

                                default {
                                    "'default' hit for '$_'"
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    Describe -Name 'StorageAccounts' -Tag 'Storage' -Fixture {
        Context -Name $subscription.id -Fixture {
            Write-Information -MessageData "performing 'StorageAccounts' tests..."

            $startTime = (Get-Date).AddDays(-89).ToString('s')
            $endTime = (Get-Date).ToString('s')
            $authHeader = Get-AuthHeader

            foreach ($storageAccount in $storageAccounts) {
                $resource = $storageAccount.id

                It "'$resource' blob service has encryption enabled" {
                    $storageAccount.properties.encryption.services.blob.enabled | Should Be $true
                }

                It "'$resource' file service has encryption enabled" {
                    $storageAccount.properties.encryption.services.file.enabled | Should Be $true
                }

                It "'$resource' has only HTTPS traffic enabled" {
                    $storageAccount.properties.enableHttpsTrafficOnly | Should Be $true
                }

                It "'$resource' has regenerated storage account keys in the last 90 days" {
                    Get-AzureRmAzureMonitorLog -SubscriptionId $subscription.Id -AuthHeader $authHeader -ResourceId $storageAccount.id -StartTime $startTime -EndTime $endTime | 
                        Where-Object {$_.operationName.value -eq 'Microsoft.Storage/storageAccounts/regenerateKey/action'} | Should Not BeNullOrEmpty
                }

                foreach ($container in (Get-AzureRmStorageContainer -StorageAccountName $storageAccount.name -ResourceGroupName $storageAccount.resourceGroup)) {
                    It "'$($container.id)' has no anonymous blob or container level access" {
                        $container.publicAccess | Should Be 'None'
                    }
                }
            }  
        }
    }

    Describe -Name 'DiagnosticLogs' -Tag 'Monitoring' -Fixture {
        Context -Name $subscription.id -Fixture {
            Write-Information -MessageData "performing 'DiagnosticLogs' tests..."
            foreach ($diagnostic in $diagnostics) {
                $resource = $diagnostic.id

                foreach ($diagnosticsLogsCategory in $diagnosticsLogsCategories | Where-Object ResourceType -eq $diagnostics.Type) {
                    It "'$resource' has diagnostics category '$($diagnosticsLogsCategory.Category)' enabled" {
                        $diagnostics.DiagnosticsSettings.$($diagnosticsLogsCategory.Category) | Should Not BeNullOrEmpty
                    }
                }
            }
        }
    }
 
    Describe -Name 'NetworkWatchers' -Tag 'Network' -Fixture {  
        Context -Name $subscription.id -Fixture { 
            Write-Information -MessageData "performing 'NetworkWatchers' tests..."
            foreach ($vnet in $vnets | Select-Object -Property Location -Unique) {
                It "networkWatcher is enabled in '$($vnet.Location)'" {
                    $networkWatchers.Where( {$_.Location -eq $vnet.Location}) | Should Not BeNullOrEmpty
                }
            }

            foreach ($nsg in $nsgs) {
                $resource = $nsg.id
                It "'$resource' has network watcher flow logging enabled" {
                    $nsg.id -in $networkWatchers.properties.flowLogs.properties.targetResourceId | Should Be $true
                }
            }

            foreach ($networkWatcher in $networkWatchers) {
                foreach ($nsgResource in $networkWatchers.properties.flowLogs) {
                    $resource = $nsgResource.properties.targetResourceId
                    <#
                    It "'$resource' has flow logging enabled" {
                        $nsgResource.properties.targetResourceId -in $nsgs.id -and $nsgResource.properties.enabled -eq $true | Should Be $true
                    }
                    #>
                    if ($nsgResource.properties.targetResourceId -in $nsgs.id) {
                        It "'$resource has flog log retention enabled'" {
                            $nsgResource.properties.retentionPolicy.enabled | Should Be $true
                        }

                        It "'$resource' has a flow log retention policy greater than 90 days" {
                            $nsgResource.properties.retentionPolicy.days | Should Not BeLessThan 90
                        }

                        It "'$resource' has a flow analytics enabled" {
                            $nsgResource.properties.flowAnalyticsConfiguration.networkWatcherFlowAnalyticsConfiguration.enabled | Should Be $true
                        }
                    }
                }
            }
        }
    }

    Describe -Name 'KeyVaults' -Tag 'Secret' -Fixture {  
        Context -Name $subscription.id -Fixture { 
            foreach ($keyVault in $keyVaults) {
                Get-AzureKeyVaultCertificate -VaultName $keyVault.name -ErrorAction SilentlyContinue | ForEach-Object {
                    It "'$($_.id)' certificate should have an expiry date" {
                        $_.Expires | Should Not BeNullOrEmpty
                    }
                }

                Get-AzureKeyVaultSecret -VaultName $keyVault.name -ErrorAction SilentlyContinue | ForEach-Object {
                    It "'$($_.id)' secret should have an expiry date" {
                        $_.Expires | Should Not BeNullOrEmpty
                    }
                }

                Get-AzureKeyVaultKey -VaultName $keyVault.name -ErrorAction SilentlyContinue | ForEach-Object {
                    It "'$($_.id)' key should have an expiry date" {
                        $_.Expires | Should Not BeNullOrEmpty
                    }
                }
            }
        }
    }
    
    Describe -Name 'SQLServers' -Tag 'Data' -Fixture {  
        Context -Name $subscription.id -Fixture { 
            Write-Information -MessageData "performing 'SQLServers' tests..."
            foreach ($sqlServer in $sqlServers) {
                $resource = $sqlServer.id
                $auditing = Get-AzureRmSqlServerAuditing -ServerName $sqlServer.name -ResourceGroupName $sqlServer.resourceGroup
                $threatDetection = Get-AzureRmSqlServerThreatDetectionPolicy -ServerName $sqlServer.name -ResourceGroupName $sqlServer.resourceGroup
                $adAdmin = Get-AzureRmSqlServerActiveDirectoryAdministrator -ServerName $sqlServer.name -ResourceGroupName $sqlServer.resourceGroup
                $sqlServerFwRules = Get-AzureRmSqlServerFirewallRule -ServerName $sqlServer.name -ResourceGroupName $sqlServer.resourceGroup

                It "'$resource' has auditing enabled" {
                    $auditing.AuditState | Should Be 'Enabled'
                }

                It "'$resource' has auditing retention set to >= 90 days" {
                    $auditing.RetentionInDays | Should Not BeLessThan 90 
                }

                It "'$resource' has threat detection enabled" {
                    $threatDetection.ThreatDetectionState | Should Be 'Enabled'
                }

                It "'$resource' has all threat detection types enabled" {
                    $threatDetection.ExcludedDetectionTypes | Should BeNullOrEmpty
                }

                It "'$resource' has threat detection email address set" {
                    $threatDetection.NotificationRecipientsEmails | Should Not BeNullOrEmpty
                }

                It "'$resource' has threat detection email admins enabled" {
                    $threatDetection.EmailAdmins | Should Be $true
                }

                It "'$resource' has threat detection  retention set to >= 90 days" {
                    $threatDetection.RetentionInDays | Should Not BeLessThan 90 
                }

                It "'$resource' has AAD admin account set" {
                    $adAdmin | Should Not BeNullOrEmpty
                }

                It "'$resource' does not allow permissive network access" {
                    $sqlServerFwRules.StartIpAddress -eq '0.0.0.0' -or $sqlServerFwRules.EndIpAddress -eq '0.0.0.0' | Should Be $false
                }
            }
        }
    }

    Describe -Name 'SQLServers' -Tag 'Data' -Fixture {  
        Context -Name $subscription.id -Fixture { 

            foreach ($sqlDatabase in $sqlDatabases) {
                $databaseAuditing = Get-AzureRmSqlDatabaseAuditing -ServerName $sqlDatabase.serverName -DatabaseName $sqlDatabase.name -ResourceGroupName $sqlDatabase.resourceGroup
                $databaseThreatDetection = Get-AzureRmSqlDatabaseThreatDetectionPolicy -ServerName $sqlDatabase.serverName -DatabaseName $sqlDatabase.name -ResourceGroupName $sqlDatabase.resourceGroup
                $databaseTDE = Get-AzureRmSqlDatabaseTransparentDataEncryption -ServerName $sqlDatabase.serverName -DatabaseName $sqlDatabase.name -ResourceGroupName $sqlDatabase.resourceGroup

                It "'$resource' has database auditing enabled" {
                    $databaseAuditing.AuditState | Should Be 'Enabled'
                }

                It "'$resource' has database auditing retention set to >= 90 days" {
                    $databaseAuditing.RetentionInDays | Should Not BeLessThan 90
                }

                It "'$resource' has database threat detection enabled" {
                    $databaseThreatDetection.ThreatDetectionState | Should Be 'Enabled'
                }

                It "'$resource' has database threat detection set to >= 90 days" {
                    $databaseThreatDetection.RetentionInDays |  Should Not BeLessThan 90
                }

                It "'$resource' has all database threat detection types enabled" {
                    $databaseThreatDetection.ExcludedDetectionTypes | Should BeNullOrEmpty
                }

                It "'$resource' has all database threat detection send email enabled" {
                    $databaseThreatDetection.EmailAdmins | Should Be $true
                }

                It "'$resource' has transparent data encryption enabled" {
                    $databaseTDE.State | Should Be 'Enabled'
                }
            }
        }
    }
    #endregion

