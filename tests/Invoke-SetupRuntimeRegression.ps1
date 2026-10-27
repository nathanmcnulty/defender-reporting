#Requires -Version 7.6
[CmdletBinding()]
param([string]$SetupRoot = (Split-Path $PSScriptRoot -Parent))

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
# Maintained path policy; see docs/powershell-baseline.md. New scripts require classification.
$entrypoints = @(
    'azure/function-app/profile.ps1'
    'azure/Invoke-DashboardPipeline.ps1'
    'azure/Upload-Templates.ps1'
    'build/azure/Build-FunctionApp.ps1'
    'build/azure/Build-Runbook.ps1'
    'build/azure/Build-TemplatePublisher.ps1'
    'build/azure/runbook-source.ps1'
    'build/azure/Watch-AutomationJob.ps1'
    'build/Build-AzureReleasePackage.ps1'
    'build/Build-FunctionAppPackage.ps1'
    'build/Build-SharedHelpers.ps1'
    'build/Build-ValidationHelpers.ps1'
    'build/Invoke-AzureDeploymentValidation.ps1'
    'build/Invoke-LiveDashboardDryRun.ps1'
    'build/Invoke-RegressionValidation.ps1'
    'build/Publish-DashboardTemplates.ps1'
    'build/Validate-DashboardReports.ps1'
    'Generate-VulnerabilityDashboard.ps1'
    'Invoke-NvdCveExport.ps1'
    'Invoke-VulnerabilityExport.ps1'
    'Setup-AzureResources.ps1'
    'Setup-GitHubActionServicePrincipal.ps1'
    'tests/Compare-BenchmarkEvidence.ps1'
    'tests/Generate-SyntheticLargeExports.ps1'
    'tests/helpers/controlled-fixture/Build-ControlledFixture.ps1'
    'tests/helpers/Invoke-LaunchBoundOwner.ps1'
    'tests/helpers/Invoke-LaunchBoundOwnerBridge.ps1'
    'tests/helpers/LaunchBoundFixture.ps1'
    'tests/helpers/Stop-LaunchBoundOwnerFixture.ps1'
    'tests/helpers/Wait-LaunchBoundFixtureExit.ps1'
    'tests/Invoke-AtomicDashboardPublicationRegression.ps1'
    'tests/Invoke-AzureRunbookValidation.ps1'
    'tests/Invoke-BenchmarkSeries.ps1'
    'tests/Invoke-CompiledContentNormalization.ps1'
    'tests/Invoke-HostedDashboardRuntimeSmoke.ps1'
    'tests/Invoke-HostedSmokeDiagnosticsRegression.ps1'
    'tests/Invoke-HostedSmokeOwnershipRegression.ps1'
    'tests/Invoke-HostedSmokeSafetyRegression.ps1'
    'tests/Invoke-HotPhaseReview.ps1'
    'tests/Invoke-InstalledInventoryRegression.ps1'
    'tests/Invoke-LargeDatasetValidation.ps1'
    'tests/Invoke-LargeImportCoverage.ps1'
    'tests/Invoke-LaunchBoundFixtureContracts.ps1'
    'tests/Invoke-LaunchBoundNativeControls.ps1'
    'tests/Invoke-LaunchBoundOwnerRegression.ps1'
    'tests/Invoke-RoutineSemanticReview.ps1'
    'tests/Invoke-SetupArtifactValidationRegression.ps1'
    'tests/Invoke-SetupRuntimeRegression.ps1'
    'tests/Invoke-SetupSchedulingRegression.ps1'
    'tests/Invoke-ValidationModeComparison.ps1'
    'tests/Invoke-WithPwshMemoryGuard.ps1'
    'tests/manual/Invoke-DashboardPathCoverage.ps1'
    'tests/manual/Invoke-LegacyFallbackCachePath.ps1'
    'tests/Measure-BranchVsMainBenchmark.ps1'
    'tests/Measure-MachineRefreshBenchmark.ps1'
    'tests/Measure-RunbookInputLoadExperiment.ps1'
    'tests/Measure-RunbookOnlyAzureBenchmark.ps1'
    'tests/Measure-StressRun.ps1'
    'tests/New-BenchmarkDataset.ps1'
    'tests/New-SyntheticLegacyVulnSnapshotSet.ps1'
    'tests/New-SyntheticLiveExport.ps1'
    'tests/New-SyntheticSnapshotDelta.ps1'
    'tests/New-SyntheticUploadManifest.ps1'
    'tests/Record-BenchmarkHistory.ps1'
    'tests/Run-SharedHelperRegression.ps1'
)
$inheritedFragments = @(
    'build/Import-SharedHelpers.ps1'
    'build/Import-ValidationHelpers.ps1'
    'build/private/ArtifactManifestTools.ps1'
    'build/private/AzureArtifactBuildTools.ps1'
    'build/private/DashboardTemplatePublishTools.ps1'
    'src/powershell/Provisioning/Azure/AzureProvisioning.ps1'
    'src/powershell/Shared/Core/CompiledVulnContentProjector.ps1'
    'src/powershell/Shared/Core/Core.ps1'
    'src/powershell/Shared/Dashboard/DashboardGeneration.ps1'
    'src/powershell/Shared/DefenderApi/MdeExport.ps1'
    'src/powershell/Shared/Enrichment/EnrichmentProjection.ps1'
    'src/powershell/Shared/Enrichment/EnrichmentReaders.ps1'
    'src/powershell/Shared/Enrichment/NvdExport.ps1'
    'src/powershell/Shared/Stores/MachineStore.ps1'
    'src/powershell/Shared/Stores/VulnerabilitySnapshotImport.ps1'
    'src/powershell/Shared/Stores/VulnerabilityStore.ps1'
    'src/powershell/Validation/Audit/DashboardAudit.ps1'
    'src/powershell/Validation/Audit/LargeDatasetAudit.ps1'
    'src/powershell/Validation/Orchestration/ValidationOrchestration.ps1'
    'tests/Import-BenchmarkDatasetCatalog.ps1'
    'tests/helpers/BenchmarkEvidenceTools.ps1'
    'tests/helpers/BenchmarkSeriesTools.ps1'
    'tests/helpers/HostedSmokeDiagnostics.ps1'
    'tests/helpers/LaunchBoundOwner.ps1'
    'tests/helpers/TestScriptSupport.ps1'
    'tests/helpers/ValidationReviewSupport.ps1'
    'tests/helpers/controlled-fixture/InstalledInventory.ps1'
)
$dataFiles = @(
    'azure/function-app/requirements.psd1'
    'build/PSScriptAnalyzerSettings.psd1'
)

function Assert-PowerShellBaseline {
    param([string]$Source, [string]$Label)
    $parseErrors = $null
    $scriptAst = [Management.Automation.Language.Parser]::ParseInput($Source, [ref]$null, [ref]$parseErrors)
    if ($parseErrors.Count) { throw "$Label is not parseable." }
    $requirements = $scriptAst.ScriptRequirements
    if ($null -eq $requirements -or $null -eq $requirements.RequiredPSVersion -or
        $requirements.RequiredPSVersion -ne [version]'7.6') {
        throw "$Label must declare an effective #Requires -Version 7.6."
    }
}

function Get-StaticAstValue {
    param([Management.Automation.Language.Ast]$Ast)
    # SafeGetValue rejects commands, variable mutation and other executable expressions.
    # Do not replace this with ScriptBlock.Create or invocation of Extent.Text.
    $Ast.SafeGetValue()
}

$staticValueMarker = @{ Value = 'unchanged' }
$unsafeErrors = $null
$unsafeAst = [Management.Automation.Language.Parser]::ParseInput(
    '@{ version = $($staticValueMarker.Value = ''changed''; ''7.6''); language = ''PowerShell'' }',
    [ref]$null, [ref]$unsafeErrors)
if ($unsafeErrors.Count) { throw 'The side-effect rejection fixture must be valid syntax.' }
$unsafeTable = $unsafeAst.Find({ param($node) $node -is [Management.Automation.Language.HashtableAst] }, $true)
$unsafeRejected = $false
try { $null = Get-StaticAstValue $unsafeTable }
catch { $unsafeRejected = $true }
if (-not $unsafeRejected -or $staticValueMarker.Value -cne 'unchanged') {
    throw 'Static payload extraction accepted or executed a side-effect expression.'
}

# Exercise the same AST gate against finite in-memory inputs. Never invoke these scripts.
Assert-PowerShellBaseline "#Requires -Version 7.6`nparam()" 'positive baseline'
foreach ($version in @('7.0', '7.2', '7.4', 'missing', 'literal-only')) {
    $sample = switch ($version) {
        'missing' { 'param()' }
        'literal-only' { "param()`n`$example = '#Requires -Version 7.6'" }
        default { "#Requires -Version $version`nparam()" }
    }
    $rejected = $false
    try { Assert-PowerShellBaseline $sample "negative $version" }
    catch { $rejected = $true }
    if (-not $rejected) { throw "The baseline gate accepted $version." }
}

$classifiedPaths = @($entrypoints) + @($inheritedFragments) + @($dataFiles)
if (@($classifiedPaths | Sort-Object -Unique).Count -ne $classifiedPaths.Count) {
    throw 'PowerShell policy contains duplicate or conflicting classifications.'
}
# Include nonignored new source during precommit validation; installed/vendor/build outputs
# under ignored paths are not silently adopted into the maintained repository policy.
$inventory = @(& git -C $SetupRoot ls-files --cached --others --exclude-standard -- '*.ps1' '*.psm1' '*.psd1')
if ($LASTEXITCODE -ne 0) { throw 'Cannot inventory repository PowerShell sources.' }
$inventory = @($inventory | Sort-Object -Unique)
$unclassified = @($inventory | Where-Object { $_ -cnotin $classifiedPaths })
$missing = @($classifiedPaths | Where-Object { $_ -cnotin $inventory })
if ($unclassified.Count -or $missing.Count) {
    throw "PowerShell policy inventory changed. Unclassified: $($unclassified -join ', '); missing: $($missing -join ', ')."
}
foreach ($relativePath in $classifiedPaths) {
    if (-not (Test-Path -LiteralPath (Join-Path $SetupRoot $relativePath) -PathType Leaf)) {
        throw "Classified PowerShell source is missing: $relativePath"
    }
}
foreach ($relativePath in $entrypoints) {
    Assert-PowerShellBaseline (Get-Content -LiteralPath (Join-Path $SetupRoot $relativePath) -Raw) $relativePath
}

# The generated Function entrypoint is ignored build output. Inspect its canonical
# literal header without invoking the builder or evaluating an assignment.
$builderErrors = $null
$builderAst = [Management.Automation.Language.Parser]::ParseFile(
    (Join-Path $SetupRoot 'build/azure/Build-FunctionApp.ps1'), [ref]$null, [ref]$builderErrors)
if ($builderErrors.Count) { throw 'Function App builder source is not parseable.' }
$headerAssignments = @($builderAst.FindAll({
    param($node)
    $node -is [Management.Automation.Language.AssignmentStatementAst] -and
    $node.Left -is [Management.Automation.Language.VariableExpressionAst] -and
    $node.Left.VariablePath.UserPath -ceq 'functionAppHeader'
}, $true))
if ($headerAssignments.Count -ne 1 -or
    $headerAssignments[0].Operator -ne [Management.Automation.Language.TokenKind]::Equals) {
    throw 'Expected one literal Function App header assignment.'
}
$headerLiterals = @($headerAssignments[0].Right.FindAll({
    param($node)
    $node -is [Management.Automation.Language.StringConstantExpressionAst]
}, $true))
if ($headerLiterals.Count -ne 1 -or
    $headerAssignments[0].Right.Extent.Text.Trim() -cne $headerLiterals[0].Extent.Text.Trim()) {
    throw 'Function App header must remain a single literal string.'
}
$functionHeader = Get-StaticAstValue $headerLiterals[0]
if ($functionHeader -isnot [string]) { throw 'Function App header is not static string data.' }
Assert-PowerShellBaseline $functionHeader 'generated Function App header'

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
    $runtime = Get-StaticAstValue $table
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
Write-Output "Setup runtime regression passed: $($entrypoints.Count) classified PowerShell 7.6 entrypoints, five negative guard cases, static payload side-effect rejection, generated Function header, two runtime payloads, distinct Automation environment, explicit binding, and generated runbook guidance."
