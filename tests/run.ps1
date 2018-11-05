[CmdletBinding()]

param(
    [Parameter(Mandatory)]
    [guid]$tenantId = '',

    [Parameter(Mandatory)]
    [guid[]]$excludedSubscriptions = @('', ''),

    [Parameter()]
    [int]$maxResults = 5000
)

$results = Invoke-Pester -PassThru -Strict -Quiet -Script @{
    Path       = "$PSScriptRoot\resource.tests.ps1"
    Parameters = @{
        TenantId              = $tenantId
        ExcludedSubscriptions = $excludedSubscriptions
        MaxResults            = $maxResults
    }
}

# save results as JSON
$results | ConvertTo-Json -Depth 99 | Out-File -FilePath $PSScriptRoot\results\results.json -Force

# convert JSON to HTML report
$html = $results.TestResult | 
    Sort-Object -Property Context, Describe, Passed -Descending | 
    Select-Object -Property `
@{n = 'Result'; e = {$_.Passed}}, 
@{n = 'Subscription'; e = {$_.Context}}, 
@{n = 'ResourceType'; e = {$_.Describe}}, 
@{n = 'Test'; e = {$_.Name}} | 
    ConvertTo-Html -CssUri 'css/style.css' -Title "Azure Assessment"

$html -replace '<td>True</td>', '<td bgcolor="#00FF00">Pass</td>' -replace '<td>False</td>', '<td bgcolor="#FF0000">Fail</td>' -replace '<table>', '<table class="blueTable">' | 
    Out-File -FilePath $PSScriptRoot\results\results.html -Force -Encoding utf8