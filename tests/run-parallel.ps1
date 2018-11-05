#Requires -Version 5.1

[CmdletBinding()]

param(
    [Parameter(Mandatory)]
    [guid]$TenantId = '',

    [Parameter(Mandatory)]
    [guid[]]$ExcludedSubscriptions = @('', ''),

    [Parameter()]
    [int]$MaxResults = 5000,

    [Parameter()]
    [int[]]$DefaultRules = @(65000, 65001, 65500)
)

$InformationPreference = 'Continue'
$testPath = (Resolve-Path -Path "$PSScriptRoot\resource.tests.parallel.ps1").Path

# import custom module
$modulePath = (Resolve-Path -Path "$PSScriptRoot\..\modules\AzureAssessment.psd1").Path
Import-Module -Name $modulePath -Force

# install the Resource Graph (pre-release) module from PowerShell Gallery
if (-not (Get-Module -Name AzureRm.ResourceGraph -ListAvailable)) {
    try {
        Write-Information -MessageData "installing module 'AzureRm.ResourceGraph'"
        Install-Module -Name AzureRm.ResourceGraph -AllowPrerelease -ErrorAction Stop
    }
    catch {
        throw "Error Occurred installing module 'AzureRm.ResourceGraph' `n$_"
    }
}

# connect to Azure
if ((Get-AzureRmContext).Tenant.Id -ne $TenantId) {
    Connect-AzureRmAccount -TenantId $TenantId
}

# import diagnostics categories
Write-Information -MessageData "importing diagnostics categories csv file $PSScriptRoot\..\data\diagnosticLogCategories.txt"
$diagnosticsLogsCategories = Import-Csv -Delimiter "`t" -Path $PSScriptRoot\..\data\diagnosticLogCategories.txt | 
    Select-Object -Property ResourceType, Category

$allowedVmExtensions = @{
    'Linux'   = 'OmsAgentForLinux', 'LinuxAsm'
    'Windows' = 'Monitoring', 'MicrosoftMonitoringAgent', 'IaaSAntimalware', 'IaaSDiagnostics'
}

# get list of subscriptions
Write-Information -MessageData "searching for subscriptions in tenant '$TenantId'..."
$subscriptions = Get-AzureRmSubscription -TenantId $TenantId | Where-Object SubscriptionId -notin $Excludedsubscriptions

if ($subscriptions.Count -le 0) {
    Write-Warning -Message "no subscriptions found in Tenant '$TenantId'"
    return
}

# get total number of resources in all subscriptions
$numResources = Search-AzureRmGraph -Subscription $subscriptions.Id -Query "summarize resourceCount=count()" -First $MaxResults | 
    Select-Object -ExpandProperty resourceCount
Write-Information -MessageData "found $numResources resources in $($subscriptions.count) subscriptions..."

# get Azure Datacenter IP ranges
Write-Information -MessageData "getting current Azure Datacenter ranges..."
$azureDatacenterIpRanges = Get-AzureDatacenterIpRanges

###############################################
# execute tests in parallel using runspaces
###############################################

$maxThreads = $env:NUMBER_OF_PROCESSORS
$pipelines = @()
$pipelineResults = @()

# create runspace pool for multi-threading
$initialSessionState = [initialsessionstate]::CreateDefault()
$initialSessionState.ImportPSModule($modulePath)
$rsPool = [RunspaceFactory]::CreateRunspacePool(1, $maxThreads, $initialSessionState, $Host)
$rsPool.open()

# scriptblock to parallelize
$scriptblock = {
    param(
        $Subscription,
        $DiagnosticsLogsCategories,
        $AllowedVmExtensions,
        $AzureDatacenterIpRanges,
        $DefaultRules,
        $Path
    )

    Invoke-Pester -PassThru -Strict -Quiet -Script @{
        Path       = $Path
        Parameters = @{
            Subscription              = $Subscription
            DiagnosticsLogsCategories = $DiagnosticsLogsCategories
            AllowedVmExtensions       = $AllowedVmExtensions
            AzureDatacenterIpRanges   = $AzureDatacenterIpRanges
            DefaultRules              = $DefaultRules
        }
    }
}

###################################################
# loop through subscriptions and spin up 
# a new runspace for each then execute Pester tests
###################################################

foreach ($subscription in $subscriptions) {
    $pipeline = [PowerShell]::Create()
    [void]$pipeline.AddScript($scriptblock)
    [void]$pipeline.AddArgument($subscription)
    [void]$pipeline.AddArgument($diagnosticsLogsCategories)
    [void]$pipeline.AddArgument($allowedVmExtensions)
    [void]$pipeline.AddArgument($azureDatacenterIpRanges)
    [void]$pipeline.AddArgument($DefaultRules)
    [void]$pipeline.AddArgument($testPath)

    Write-Information -MessageData "Starting runspace for subscription: '$($subscription.Name)'"

    $pipeline.RunspacePool = $rsPool
    $pipelines += [PSCustomObject]@{ Pipe = $pipeline; Status = $pipeline.BeginInvoke() }
}

# wait until all runspaces have completed
while ($pipelines.Status.IsCompleted -notcontains $true) {}
 
foreach ($pipeline in $pipelines ) {
    # retrieve the results of the asynchronous call & dispose of pipeline
    $pipelineResults += $pipeline.Pipe.EndInvoke($pipeline.Status)
    $pipeline.Pipe.Dispose()
}

# save results as JSON
$pipelineResults | ConvertTo-Json -Depth 99 | Out-File -FilePath $PSScriptRoot\results\results.json -Force

# close & dispose runspace pool
$rsPool.Close() 
$rsPool.Dispose()

# output as html report
$html = $pipelineResults.TestResult | 
    Sort-Object -Property Context, Describe, Passed -Descending | 
    Select-Object -Property `
@{n = 'Result'; e = {$_.Passed}}, 
@{n = 'Subscription'; e = {$_.Context}}, 
@{n = 'ResourceType'; e = {$_.Describe}}, 
@{n = 'Test'; e = {$_.Name}} | 
    ConvertTo-Html -CssUri 'css/style.css' -Title "Azure Assessment"

$html -replace '<td>True</td>', '<td bgcolor="#00FF00">Pass</td>' -replace `
    '<td>False</td>', '<td bgcolor="#FF0000">Fail</td>' `
    -replace '<table>', '<table class="blueTable">' | 
    Out-File -FilePath $PSScriptRoot\results\results.html -Force -Encoding utf8