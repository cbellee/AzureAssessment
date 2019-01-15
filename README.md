# Azure Assessment

A combination of PowerShell Pester tests and Azure Resource Graph to collect & evaluate resources in all Azure subscriptions in a tenant against the [CIS Microsoft Azure Foundations Benchmark](https://azure.microsoft.com/en-au/resources/cis-microsoft-azure-foundations-security-benchmark/en-us/)

## Pre-requisites

PowerShell: v5.1 (untested on PowerShell core v6.0+ or newer Az-* modules)

PowerShell Modules: 'AzureRM.Profile', 'AzureRM.RecoveryServices', 'AzureRM.Resources', 'AzureRM.Insights', 'AzureRM.Storage', 'AzureRM.KeyVault', 'AzureRM.Sql', 'AzureRM.ResourceGraph'

[Azure Resource Graph Module](https://docs.microsoft.com/en-us/azure/governance/resource-graph/first-query-powershell#add-the-resource-graph-module)

# Install the Resource Graph module from PowerShell Gallery
Install-Module -Name Az.ResourceGraph

## Usage

- Open a PowerShell command window
- Change current working dir to <repository root>/tests
- Execute run-parallel.ps1 script with mandatory parameters

`PS C:> ./run-parallel.ps1 -TenantId 246bc2f6-b346-4d11-b4c6-f7caa1a14ef5 -ExcludedSubscriptions @('8c8f1cc6-2399-43d0-97cb-99c92cd2f4d1', '3eed024d-e77d-4f97-868e-ccb2ce0ed78f') `

## Output
The script will execute the ./tests/resource.tests.parallel.ps1 Pester script for each subscription in parallel using PowerShell runspaces. Once complete, two files will be created in /tests/results (results.html & results.json)
