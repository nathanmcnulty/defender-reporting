#Requires -Version 7.6
[CmdletBinding()]
param([string]$SetupRoot = (Split-Path $PSScriptRoot -Parent))

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$setupPath = Join-Path $SetupRoot 'Setup-AzureResources.ps1'
$errors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile($setupPath, [ref]$null, [ref]$errors)
if ($errors.Count) { throw 'Setup source is not parseable.' }

# Inspect the real deployment payload AST without invoking setup or any cloud command.
$runtimeTables = @($ast.FindAll({
    param($node)
    if ($node -isnot [Management.Automation.Language.HashtableAst]) { return $false }
    $keys = @($node.KeyValuePairs | ForEach-Object { $_.Item1.Value })
    return 'version' -in $keys -and ('language' -in $keys -or 'name' -in $keys)
}, $true))
if ($runtimeTables.Count -ne 2) { throw "Expected the Function and Automation runtime payloads; found $($runtimeTables.Count)." }
foreach ($table in $runtimeTables) {
    $runtime = & ([scriptblock]::Create($table.Extent.Text))
    if ($runtime.version -cne '7.6') { throw 'A maintained setup payload does not select PowerShell 7.6.' }
    $language = if ($runtime.ContainsKey('language')) { $runtime.language } else { $runtime.name }
    if ($language -ine 'powershell') { throw 'The runtime language changed unexpectedly.' }
}

$source = Get-Content $setupPath -Raw
if ($source -notmatch "\`$Script:RuntimeEnvName = 'PowerShell-76-AzAccounts'") { throw 'The new Automation environment must have a distinct 7.6 identity.' }
if ($source -notmatch 'runtimeEnvironment\s*=\s*\$Script:RuntimeEnvName') { throw 'The runbook lost its explicit runtime environment binding.' }
if ($source -match 'PowerShell-74-AzAccounts|version\s*=\s*[''\"]7\.4[''\"]') { throw 'An old maintained setup runtime selection remains.' }

foreach ($relativePath in @('build/azure/runbook-source.ps1', 'azure/Invoke-DashboardPipeline.ps1')) {
    $runbook = Get-Content (Join-Path $SetupRoot $relativePath) -Raw
    if ($runbook -notmatch 'Runtime: PowerShell 7\.6') { throw "$relativePath does not document the new runtime baseline." }
}
Write-Output 'Setup runtime regression passed: two PowerShell 7.6 payloads, distinct Automation environment, explicit binding, and generated runbook guidance.'
