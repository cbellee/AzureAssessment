#region functions
function Switch-InvalidFileCharacters {

    [CmdletBinding()]

    param(
        [Parameter(ValueFromPipeline = $true)]
        [string]
        $inputString,

        [string]
        $replacementChar = '_'
    )

    begin {
        $invalidFileNameChars = [system.io.path]::GetInvalidFileNameChars()
        $invalidFileNameChars += ' '
    }

    process {
        if ($null -eq $_ -or $_.Length -le 0) {
            return
        }

        $newName = New-Object char[] $_.Length
        $chars = $_.ToCharArray()

        for ($i = 0 ; $i -lt $chars.count ; $i++) {
            if ($chars[$i] -in $invalidFileNameChars) {
                $newName[$i] = $replacementChar
            }
            else {
                $newName[$i] = $chars[$i]
            }
        }

        return -join $newName
    }
}
function Get-AzureDatacenterIpRanges {

    [CmdletBinding()]

    param (
        [Parameter()]
        [string]
        $source = "https://www.microsoft.com/en-us/download/confirmation.aspx?id=41653"    
    )

    $ErrorActionPreference = 'Stop'

    try {
        # get the XML file
        $downloadPage = Invoke-WebRequest -Uri $source -UseBasicParsing
        $xmlFileUri = $downloadPage.RawContent.split('"') -like 'https://*PublicIps*' | Select-Object -First 1
        $response = Invoke-WebRequest -Uri $xmlFileUri -UseBasicParsing
        [xml]$xmlResponse = [System.Text.Encoding]::UTF8.GetString($response.Content)

        # return an array of IP addresses
        return $xmlResponse.AzurePublicIpAddresses.Region.iprange.subnet 
    }
    catch {
        throw $_
    }
}
function Get-IPBytes {

    [CmdletBinding()]

    param (
        [Parameter()]
        [ValidateScript( {[System.Net.IpAddress]::Parse($_)})]
        [string]
        $ipAddress
    )

    $ipBytes = [System.Net.IPAddress]::Parse($ipAddress).GetAddressBytes()
    [array]::Reverse($ipBytes)

    return [System.BitConverter]::ToInt32($ipBytes, 0) 
}
function Assert-IpIsInRange {
    
    [CmdletBinding()]
    
    param (
        [Parameter()]
        [string]
        $StartIp,

        [Parameter()]
        [string]
        $EndIp,

        [Parameter()]
        [string]
        $IpAddress
    )

    $sIp = Get-IPBytes -IpAddress $StartIp
    $eIp = Get-IPBytes -ipAddress $EndIp
    $ip = Get-IPBytes -ipAddress $IpAddress

    return $ip -ge $sIp -and $ip -le $eIp
}
function Assert-PublicIp {
    
    [CmdletBinding()]

    param (
        [Parameter()]
        [string]
        $IpAddress
    )

    try {
        if ($IpAddress.ToCharArray() -contains '/') {
            $IpAddress = $IpAddress | Split-Path -Parent
        } 

        $ip = [System.Net.IPAddress]::Parse($IpAddress)

        $result = (Assert-IpIsInRange -startIp 10.0.0.0 -endIp 10.255.255.255 -ipAddress $ip) -or `
        (Assert-IpIsInRange -startIp 192.168.0.0 -endIp 192.168.255.255 -ipAddress $ip) -or `
        (Assert-IpIsInRange -startIp 172.16.0.0 -endIp 172.16.255.255 -ipAddress $ip)  

        return -not $result
    }
    catch {
        throw $_
    }
}
function Get-VMBackupItems {
    # recovery services vault data for current subscription context
    $vaults = Get-AzureRmRecoveryServicesVault
    $backupItems = @()

    foreach ($vault in $vaults) {
        Set-AzureRmRecoveryServicesVaultContext -Vault $vault
        $containers = Get-AzureRmRecoveryServicesBackupContainer -ContainerType AzureVM -Status Registered -BackupManagementType AzureVM 

        foreach ($container in $containers) {
            $backupitems += Get-AzureRmRecoveryServicesBackupItem -Container $container -WorkloadType AzureVM
        }
    }
    return $backupItems
}
function New-DiagnosticsDataLogObject {

    [CmdletBinding()]

    param(
        [Parameter()]
        [object]
        $Data
    )

    class RetentionPolicy {
        [bool]$Enabled
        [int]$Days
    }

    class DiagnosticsLog {

        [RetentionPolicy]$RetentionPolicy
        [string]$Category
    }

    $a = @()
    $Data.Logs | Foreach-Object {
        if ($null -ne $_.Category) {
            $d = [DiagnosticsLog]::new()
            $r = [RetentionPolicy]::new()
            $r.Enabled = $_.RetentionPolicy.Enabled
            $r.Days = $_.RetentionPolicy.Days
            $d.RetentionPolicy = $r
            $d.Category = $_.Category
            $a += $d
        }
    }
    return $a
}
function Get-ResourceDiagnosticsData {
    param(
        [Parameter()]
        [string[]]
        $ResourceDiagnostics
    )
    # get resource diagnostics data
    $diagnostics = @()

    Get-AzureRmResource | ForEach-Object {
        if ($_.ResourceType -in $ResourceDiagnostics) {
            $diagnosticData = $null
            $diagnosticData = Get-AzureRmDiagnosticSetting -ResourceId $_.resourceId -ErrorAction SilentlyContinue
            $diagData = New-DiagnosticsDataLogObject -Data $diagnosticData
            $diagnostics += $_ | 
                Add-Member -MemberType NoteProperty -Name DiagnosticsSettings -Value $diagData -PassThru |
                Add-Member -MemberType NoteProperty -Name WorkspaceId -Value $diagnosticData.WorkspaceId -PassThru
        }
        else {
            return
        }
    }
}
function Get-AuthHeader {
    [CmdletBinding()]

    $azureRmProfile = [Microsoft.Azure.Commands.Common.Authentication.Abstractions.AzureRmProfileProvider]::Instance.Profile
    $azureRmContext = Get-AzureRmContext
    $profileClient = New-Object Microsoft.Azure.Commands.ResourceManager.Common.RMProfileClient($azureRmProfile)
    $accessToken = $profileClient.AcquireAccessToken($azureRmContext.Subscription.TenantId).AccessToken

    # build REST API header
    $authHeader = @{
        'Content-Type'  = 'application/json'
        'Accept'        = 'application/json'
        'Authorization' = "Bearer $accessToken"
    }

    return $authHeader
}
function Get-AzureRmAzureMonitorLog {

    [CmdletBinding()]

    param(
        [string]
        $SubscriptionId,

        [hashtable]
        $AuthHeader,

        [string]
        $ResourceId,

        [string]
        $StartTime,

        [string]
        $EndTime
    )

    $apiVersion = "2015-04-01"
    $filter = "eventTimestamp ge '$StartTime' and eventTimestamp le '$EndTime' and eventChannels eq 'Operation' and resourceId eq '$ResourceId'"
    $request = "https://management.azure.com/subscriptions/$($SubscriptionId)/providers/microsoft.insights/eventtypes/management/values?api-version=${apiVersion}&`$filter=${filter}"
    $results = @()

    $result = Invoke-RestMethod -Uri $request `
        -Headers $AuthHeader `
        -Method Get

    while ($result.nextLink) {
        $results += $result.value
        $result = Invoke-RestMethod -Uri $result.nextLink `
            -Headers $AuthHeader `
            -Method Get
    }
    
    return $results
}

Export-ModuleMember -Function *
#endregion