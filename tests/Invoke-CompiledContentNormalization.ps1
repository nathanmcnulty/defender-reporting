#Requires -Version 7.0
[CmdletBinding()]
param([Parameter(Mandatory = $true)][string]$DatasetPath, [Parameter(Mandatory = $true)][string]$OutputPath)
$ErrorActionPreference = 'Stop'
. (Join-Path (Split-Path -Path $PSScriptRoot -Parent) 'build\Import-SharedHelpers.ps1')
$result = Invoke-BoundedContentStorePayloadProjection -DataPath $DatasetPath -PayloadOutputPath $OutputPath
$result | ConvertTo-Json
