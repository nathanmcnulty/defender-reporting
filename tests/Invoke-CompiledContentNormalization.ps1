#Requires -Version 7.6
[CmdletBinding()]
param([Parameter(Mandatory = $true)][string]$DatasetPath, [Parameter(Mandatory = $true)][string]$OutputPath)
$ErrorActionPreference = 'Stop'
. (Join-Path (Split-Path -Path $PSScriptRoot -Parent) 'build\Import-SharedHelpers.ps1')
$payloadContract = (Get-NormalizationExecutionPlan -Path $DatasetPath -CompiledPayloadSupported -UseExperimentalCompiledSmallPayload).CompiledPayloadContract
$result = Invoke-BoundedContentStorePayloadProjection -DataPath $DatasetPath -PayloadOutputPath $OutputPath -PayloadContract $payloadContract
$result | ConvertTo-Json
