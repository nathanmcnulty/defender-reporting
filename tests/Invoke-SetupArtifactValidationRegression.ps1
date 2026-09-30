#Requires -Version 7.0
[CmdletBinding()]
param(
    [string]$ReleaseRoot,
    [string]$PublishedFixturePath,
    [ValidatePattern('^$|^[0-9a-f]{32}$')]
    [string]$AssetGeneration
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path $PSScriptRoot -Parent
if ($ReleaseRoot) {
    . (Join-Path $ReleaseRoot 'azure\shared-helpers.ps1')
    . (Join-Path $ReleaseRoot 'azure\AzureProvisioning.ps1')
}
else {
    . (Join-Path $repoRoot 'build\Import-SharedHelpers.ps1')
    . (Join-Path $repoRoot 'src\powershell\Provisioning\Azure\AzureProvisioning.ps1')
}
$setupRoot = if ($ReleaseRoot) { $ReleaseRoot } else { $repoRoot }
$errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile((Join-Path $setupRoot 'Setup-AzureResources.ps1'), [ref]$null, [ref]$errors)
if ($errors.Count) { throw ($errors | Out-String) }
$completedGate = $ast.Find({ param($node) $node -is [System.Management.Automation.Language.IfStatementAst] -and $node.Clauses[0].Item1.Extent.Text -eq '$finalStatus -eq ''Completed''' }, $true)
if (-not $completedGate) { throw 'Setup completed-job gate not found.' }
$gateText = $completedGate.Clauses[0].Item2.Extent.Text
$gate = [scriptblock]::Create($gateText.Substring(1, $gateText.Length - 2))
$preflight = $ast.Find({ param($node) $node -is [System.Management.Automation.Language.IfStatementAst] -and $node.Clauses[0].Item1.Extent.Text -eq '-not $SkipValidation -and $SkipMdePermissions -and $ComputeType -eq ''AutomationAccount''' }, $true)
if (-not $preflight) { throw 'Setup expected-count preflight not found.' }
$preflightBlock = [scriptblock]::Create($preflight.Extent.Text.Replace('$PSBoundParameters', '$preflightBoundParameters'))
$main = $ast.Find({ param($node) $node -is [System.Management.Automation.Language.TryStatementAst] -and $node.Body.Extent.Text -like '*Step 1: Verifying Azure connection*' }, $true)
if ($preflight.Extent.StartOffset -ge $main.Extent.StartOffset) { throw 'Count preflight must precede all Azure setup.' }
$datasetResolver = $ast.Find({ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Resolve-ValidationDatasetPath' }, $true)
. ([scriptblock]::Create($datasetResolver.Extent.Text))

function Assert-True([bool]$Condition, [string]$Message) {
    if (-not $Condition) { throw $Message }
}
function Get-StorageBlobRestHeaderSet { return @{} }
function Invoke-WebRequest {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidOverwritingBuiltInCmdlets', '', Justification = 'Scoped mock copies fixture blobs instead of making network requests.')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '', Justification = 'Blob download mock accepts the production web request signature.')]
    param($Uri, $Headers, $OutFile, [switch]$UseBasicParsing)
    Assert-True (([uri]$Uri).Host -eq $script:ExpectedBlobHost) 'Verifier attempted an unexpected remote host.'
    $name = [uri]::UnescapeDataString(([uri]$Uri).AbsolutePath.Substring('/dashboards/'.Length))
    $script:BlobReads.Add($name)
    $source = Join-Path $script:FixtureRoot $name
    if (-not (Test-Path -LiteralPath $source -PathType Leaf)) { throw "Mock blob '$name' is missing." }
    Copy-Item -LiteralPath $source -Destination $OutFile -Force
}
function Invoke-ArmApi {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '', Justification = 'Completed-job stream mock accepts the production ARM signature.')]
    param($Path, $Method, $Description)
    return [pscustomobject]@{ value = @() }
}

function Invoke-CompletedGate {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '', Justification = 'Variables are consumed by the extracted production Setup block.')]
    [CmdletBinding()]
    param([string]$Mode)
    $SkipMdePermissions = $true
    $StorageAccountName = 'fixturestorage'
    $effectiveDashboardDeliveryMode = $Mode
    $resolvedValidationExpectedTotalRows = 1
    $jobId = 'requested-resource-id'
    $validationJobId = 'current-job'
    $validationStartedOnUtc = [datetimeoffset]'2026-09-30T00:00:00Z'
    $subPath = '/subscriptions/mock'
    $ResourceGroupName = 'mock'
    $AutomationAccountName = 'mock'
    $Script:ArmApiVersions = @{ AutomationAccount = '2023-11-01' }
    & $gate
}

function Invoke-CountPreflight {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '', Justification = 'Variables are consumed by the extracted production preflight block.')]
    [CmdletBinding()]
    param($ValidationExpectedTotalRows, [bool]$SkipValidation = $false, [string]$ValidationDatasetPath = '')
    $SkipMdePermissions = $true
    $ComputeType = 'AutomationAccount'
    $preflightBoundParameters = $PSBoundParameters
    . $preflightBlock
}

$tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('setup-artifact-regression-' + [guid]::NewGuid().ToString('N'))
$script:FixtureRoot = Join-Path $tempRoot 'blobs'
$script:ExpectedBlobHost = 'fixturestorage.blob.core.windows.net'
$script:BlobReads = [System.Collections.Generic.List[string]]::new()
try {
    [void](New-Item -Path $script:FixtureRoot -ItemType Directory -Force)
    $payloadPath = Join-Path $tempRoot 'payload.json.gz'
    Write-GzipTextFile -Path $payloadPath -Content '{"vulnsFormat":"rows-v1","lookups":{},"vulns":[[0]]}'
    $payloadHash = (Get-FileHash -LiteralPath $payloadPath).Hash.ToLowerInvariant()
    $base64 = [Convert]::ToBase64String([System.IO.File]::ReadAllBytes($payloadPath))
    $selfHtml = '<html><script id="dataFormat" type="application/json">compressed</script><script id="vulnsData" type="application/json">' + $base64 + '</script></html>'
    $selfPath = Join-Path $script:FixtureRoot 'VulnerabilityDashboard.html'
    $hostedPath = Join-Path $script:FixtureRoot 'VulnerabilityDashboard.Hosted.html'
    foreach ($mode in @('SelfContained', 'Hosted', 'Dual')) {
        $hostedName = if ($mode -eq 'Dual') { 'VulnerabilityDashboard.Hosted.html' } else { 'VulnerabilityDashboard.html' }
        $assetName = ($hostedName -replace '\.html$', '') + '.assets'
        if ($AssetGeneration) { $assetName += "/generations/$AssetGeneration" }
        $assetRoot = Join-Path $script:FixtureRoot $assetName
        $assets = @('runtime/dashboard.css', 'runtime/dashboard.js', 'runtime/pako.js', 'vendor/chart.js', 'data/summary.json', 'data/payload.json.gz', 'optional/pdf-export.bundle.js', 'optional/pdf-export.runtime.js')
        foreach ($asset in $assets) {
            $path = Join-Path $assetRoot $asset
            [void](New-Item -Path (Split-Path $path -Parent) -ItemType Directory -Force)
            [System.IO.File]::WriteAllText($path, 'fixture')
        }
        Copy-Item -LiteralPath $payloadPath -Destination (Join-Path $assetRoot 'data/payload.json.gz') -Force
        $summary = [ordered]@{ meta = [ordered]@{ payloadSha256 = $payloadHash; vulnCount = 1; deviceCount = 1; cveCount = 1 } }
        $summaryPath = Join-Path $assetRoot 'data/summary.json'
        [System.IO.File]::WriteAllText($summaryPath, ($summary | ConvertTo-Json -Depth 10))
        [System.IO.File]::WriteAllText($selfPath, $selfHtml)
        if ($mode -ne 'SelfContained') {
            $target = if ($mode -eq 'Dual') { $hostedPath } else { $selfPath }
            $config = [ordered]@{
                payloadUrl = "$assetName/data/payload.json.gz"; payloadSummaryUrl = "$assetName/data/summary.json"
                chartJsUrl = "$assetName/vendor/chart.js"
                pdfExportRuntimeMode = 'external'; pdfExportRuntimeUrl = "$assetName/optional/pdf-export.runtime.js"
                pdfExportBundleMode = 'external'; pdfExportBundleUrl = "$assetName/optional/pdf-export.bundle.js"
            }
            $hostedHtml = '<html><script id="dashboardConfig" type="application/json">' + ($config | ConvertTo-Json -Compress) + '</script>' + (($assets | ForEach-Object { "$assetName/$_" }) -join ' ') + '</html>'
            [System.IO.File]::WriteAllText($target, $hostedHtml)
        }
        $status = [pscustomobject]@{
            status = 'succeeded'; stage = 'Completed'; runId = 'current-run'; automationJobId = 'current-job'
            startedOnUtc = '2026-09-30T00:00:01Z'; updatedOnUtc = '2026-09-30T00:00:02Z'
            storageAccountName = 'fixturestorage'; dashboardDeliveryMode = $mode; useExistingExportsOnly = $true
            vulnerabilities = 1; devices = 1; cves = 1; dashboardBlobName = 'VulnerabilityDashboard.html'
            hostedDashboardBlobName = if ($mode -eq 'Dual') { 'VulnerabilityDashboard.Hosted.html' } else { $null }
            artifactSha256 = [pscustomobject]@{}
        }
        foreach ($file in (Get-ChildItem -LiteralPath $script:FixtureRoot -Recurse -File)) {
            $name = [System.IO.Path]::GetRelativePath($script:FixtureRoot, $file.FullName).Replace('\', '/')
            $status.artifactSha256 | Add-Member -NotePropertyName $name -NotePropertyValue (Get-FileHash -LiteralPath $file.FullName).Hash.ToLowerInvariant() -Force
        }
        $statusPath = Join-Path $script:FixtureRoot '_diagnostics/ExportAndGenerate.status.json'
        [void](New-Item -Path (Split-Path $statusPath -Parent) -ItemType Directory -Force)
        $statusText = $status | ConvertTo-Json -Depth 15
        [System.IO.File]::WriteAllText($statusPath, $statusText)
        $script:BlobReads.Clear()
        Invoke-CompletedGate -Mode $mode
        if ($mode -ne 'SelfContained') {
            foreach ($asset in @('optional/pdf-export.runtime.js', 'optional/pdf-export.bundle.js')) {
                Assert-True ($script:BlobReads.Contains("$assetName/$asset")) "Configured PDF asset '$asset' was not downloaded."
            }
        }
        else { Assert-True (-not ($script:BlobReads | Where-Object { $_ -like '*optional/*' })) 'SelfContained defaults downloaded external PDF assets.' }

        $cases = @('MissingStatus', 'StaleJob', 'StaleStart', 'MissingRun', 'FailedStatus', 'WrongStage', 'WrongMode', 'WrongStorage', 'WrongRows', 'MissingDevices', 'WrongHtmlHash', 'MissingHtml', 'StaleHtml')
        if ($mode -ne 'SelfContained') { $cases += @('MissingAsset', 'StaleAsset', 'SummaryHash', 'SummaryRows', 'PayloadRows', 'MissingPdfRuntime', 'StalePdfRuntime', 'MissingPdfHash', 'WrongPdfHash', 'MissingPdfBundle', 'StalePdfBundle') }
        if ($mode -eq 'Dual') { $cases += 'DualIdentity' }
        foreach ($case in $cases) {
            $changedStatus = $statusText | ConvertFrom-Json -Depth 15
            $changedPath = $null
            $originalBytes = $null
            switch ($case) {
                'MissingStatus' { $changedPath = $statusPath }
                'StaleJob' { $changedStatus.automationJobId = 'old-job' }
                'StaleStart' { $changedStatus.startedOnUtc = '2026-09-29T23:59:59Z' }
                'MissingRun' { $changedStatus.runId = '' }
                'FailedStatus' { $changedStatus.status = 'failed' }
                'WrongStage' { $changedStatus.stage = 'Publishing' }
                'WrongMode' { $changedStatus.dashboardDeliveryMode = 'Auto' }
                'WrongStorage' { $changedStatus.storageAccountName = 'otherstorage' }
                'WrongRows' { $changedStatus.vulnerabilities = 2 }
                'MissingDevices' { $changedStatus.devices = 0 }
                'WrongHtmlHash' { $changedStatus.artifactSha256.'VulnerabilityDashboard.html' = ('0' * 64) }
                'MissingHtml' { $changedPath = $selfPath }
                'StaleHtml' { $changedPath = $selfPath }
                'MissingAsset' { $changedPath = Join-Path $assetRoot 'runtime/dashboard.js' }
                'StaleAsset' { $changedPath = Join-Path $assetRoot 'runtime/dashboard.js' }
                'MissingPdfRuntime' { $changedPath = Join-Path $assetRoot 'optional/pdf-export.runtime.js' }
                'StalePdfRuntime' { $changedPath = Join-Path $assetRoot 'optional/pdf-export.runtime.js' }
                'MissingPdfHash' { $changedStatus.artifactSha256.PSObject.Properties.Remove("$assetName/optional/pdf-export.runtime.js") }
                'WrongPdfHash' { $changedStatus.artifactSha256.PSObject.Properties["$assetName/optional/pdf-export.runtime.js"].Value = ('0' * 64) }
                'MissingPdfBundle' { $changedPath = Join-Path $assetRoot 'optional/pdf-export.bundle.js' }
                'StalePdfBundle' { $changedPath = Join-Path $assetRoot 'optional/pdf-export.bundle.js' }
                'SummaryHash' { $changedPath = $summaryPath }
                'SummaryRows' { $changedPath = $summaryPath }
                'PayloadRows' { $changedPath = Join-Path $assetRoot 'data/payload.json.gz' }
                'DualIdentity' { $changedPath = $selfPath }
            }
            if ($changedPath) {
                $originalBytes = [System.IO.File]::ReadAllBytes($changedPath)
                if ($case -like 'Missing*') { Remove-Item -LiteralPath $changedPath -Force }
                elseif ($case -in @('SummaryHash', 'SummaryRows')) {
                    $changedSummary = ([System.Text.Encoding]::UTF8.GetString($originalBytes) | ConvertFrom-Json)
                    if ($case -eq 'SummaryHash') { $changedSummary.meta.payloadSha256 = ('0' * 64) } else { $changedSummary.meta.vulnCount = 2 }
                    [System.IO.File]::WriteAllText($changedPath, ($changedSummary | ConvertTo-Json -Depth 10))
                }
                elseif ($case -in @('PayloadRows', 'DualIdentity')) {
                    $wrongPayload = Join-Path $tempRoot 'wrong.json.gz'
                    $wrongJson = if ($case -eq 'PayloadRows') { '{"vulns":[[0],[1]]}' } else { '{"vulns":[[1]]}' }
                    Write-GzipTextFile -Path $wrongPayload -Content $wrongJson
                    if ($case -eq 'PayloadRows') { Copy-Item -LiteralPath $wrongPayload -Destination $changedPath -Force }
                    else { [System.IO.File]::WriteAllText($changedPath, ('<script id="vulnsData" type="application/json">' + [Convert]::ToBase64String([System.IO.File]::ReadAllBytes($wrongPayload)) + '</script>')) }
                }
                else { [System.IO.File]::WriteAllText($changedPath, 'stale fixture') }
                if ($case -in @('SummaryHash', 'SummaryRows', 'PayloadRows', 'DualIdentity')) {
                    $changedName = [System.IO.Path]::GetRelativePath($script:FixtureRoot, $changedPath).Replace('\', '/')
                    $changedStatus.artifactSha256.PSObject.Properties[$changedName].Value = (Get-FileHash -LiteralPath $changedPath).Hash.ToLowerInvariant()
                    if ($case -eq 'PayloadRows') {
                        $changedSummary = Get-Content -LiteralPath $summaryPath -Raw | ConvertFrom-Json
                        $changedSummary.meta.payloadSha256 = (Get-FileHash -LiteralPath $changedPath).Hash.ToLowerInvariant()
                        [System.IO.File]::WriteAllText($summaryPath, ($changedSummary | ConvertTo-Json -Depth 10))
                        $changedStatus.artifactSha256.PSObject.Properties["$assetName/data/summary.json"].Value = (Get-FileHash -LiteralPath $summaryPath).Hash.ToLowerInvariant()
                    }
                }
            }
            if ($case -ne 'MissingStatus') { [System.IO.File]::WriteAllText($statusPath, ($changedStatus | ConvertTo-Json -Depth 15)) }
            $caught = $null
            try { Invoke-CompletedGate -Mode $mode } catch { $caught = $_ }
            Assert-True ($null -ne $caught) "Completed $mode job incorrectly passed $case."
            if ($changedPath) { [System.IO.File]::WriteAllBytes($changedPath, $originalBytes) }
            [System.IO.File]::WriteAllText($summaryPath, ($summary | ConvertTo-Json -Depth 10))
            [System.IO.File]::WriteAllText($statusPath, $statusText)
        }
        if ($mode -ne 'SelfContained') {
            foreach ($unsafeUrl in @('https://attacker.invalid/pdf.js', '//attacker.invalid/pdf.js', "$assetName/../pdf.js", "$assetName/optional/../../pdf.js", "$assetName/optional/%2e%2e/pdf.js", "$assetName/optional/pdf.js?remote=1", "$assetName/optional/pdf.js#fragment", "$assetName\optional\pdf.js", 'other.assets/optional/pdf.js', '')) {
                $unsafeConfig = [ordered]@{} + $config
                $unsafeConfig.pdfExportRuntimeUrl = $unsafeUrl
                $unsafeHtml = $hostedHtml.Replace(($config | ConvertTo-Json -Compress), ($unsafeConfig | ConvertTo-Json -Compress))
                [System.IO.File]::WriteAllText($target, $unsafeHtml)
                $unsafeStatus = $statusText | ConvertFrom-Json -Depth 15
                $unsafeStatus.artifactSha256.PSObject.Properties[$hostedName].Value = (Get-FileHash -LiteralPath $target).Hash.ToLowerInvariant()
                [System.IO.File]::WriteAllText($statusPath, ($unsafeStatus | ConvertTo-Json -Depth 15))
                $script:BlobReads.Clear()
                $caught = $null
                try { Invoke-CompletedGate -Mode $mode } catch { $caught = $_ }
                Assert-True ($null -ne $caught -and $caught.Exception.Message -like '*Invalid configured published PDF asset*') "Unsafe PDF URL '$unsafeUrl' was not rejected."
                Assert-True ($script:BlobReads.Count -le 3) 'Unsafe PDF configuration triggered asset downloads.'
            }
            [System.IO.File]::WriteAllText($target, $hostedHtml)
            [System.IO.File]::WriteAllText($statusPath, $statusText)
            $customName = "$assetName/optional/configured-pdf.runtime.js"
            Copy-Item -LiteralPath (Join-Path $assetRoot 'optional/pdf-export.runtime.js') -Destination (Join-Path $script:FixtureRoot $customName)
            $customConfig = [ordered]@{} + $config
            $customConfig.pdfExportRuntimeUrl = $customName
            [System.IO.File]::WriteAllText($target, $hostedHtml.Replace(($config | ConvertTo-Json -Compress), ($customConfig | ConvertTo-Json -Compress)))
            $customStatus = $statusText | ConvertFrom-Json -Depth 15
            $customStatus.artifactSha256.PSObject.Properties[$hostedName].Value = (Get-FileHash -LiteralPath $target).Hash.ToLowerInvariant()
            $customStatus.artifactSha256 | Add-Member -NotePropertyName $customName -NotePropertyValue (Get-FileHash -LiteralPath (Join-Path $script:FixtureRoot $customName)).Hash.ToLowerInvariant()
            [System.IO.File]::WriteAllText($statusPath, ($customStatus | ConvertTo-Json -Depth 15))
            $script:BlobReads.Clear()
            Invoke-CompletedGate -Mode $mode
            Assert-True ($script:BlobReads.Contains($customName)) 'Verifier did not download the configured alternate PDF runtime path.'
            Write-Host "$mode configured PDF paths: alternate path accepted and 10 unsafe URLs rejected."
        }
        Write-Host "$mode completed-job gate: valid fixture and $($cases.Count) rejection cases passed."
    }
    foreach ($value in @(0, 1.5, '1.5', $true, $null, 50000001)) {
        $caught = $null
        try { Invoke-CountPreflight -ValidationExpectedTotalRows $value } catch { $caught = $_ }
        Assert-True ($null -ne $caught) 'Setup preflight accepted an invalid original count.'
    }
    $caught = $null
    try { Invoke-CountPreflight } catch { $caught = $_ }
    Assert-True ($null -ne $caught) 'Seeded setup must require an authoritative expectation.'
    Invoke-CountPreflight -ValidationExpectedTotalRows '1'
    Invoke-CountPreflight -SkipValidation $true -ValidationDatasetPath 'nonexistent' -ValidationExpectedTotalRows 1.5
    $dataset = Join-Path $tempRoot 'dataset'
    [void](New-Item -Path $dataset -ItemType Directory -Force)
    [System.IO.File]::WriteAllText((Join-Path $dataset 'synthetic-manifest.json'), '{"expectedDashboardRows":1}')
    Invoke-CountPreflight -ValidationDatasetPath $dataset
    if ($PublishedFixturePath) {
        $script:FixtureRoot = Join-Path $tempRoot 'published-candidate'
        Copy-Item -LiteralPath $PublishedFixturePath -Destination $script:FixtureRoot -Recurse
        $fixtureStatus = Get-Content -LiteralPath (Join-Path $script:FixtureRoot '_diagnostics/ExportAndGenerate.status.json') -Raw | ConvertFrom-Json -Depth 30
        $script:ExpectedBlobHost = "$($fixtureStatus.storageAccountName).blob.core.windows.net"
        $parameters = @{
            AccountName = $fixtureStatus.storageAccountName; DashboardDeliveryMode = $fixtureStatus.dashboardDeliveryMode
            ExpectedTotalRows = 2; ExpectedJobId = $fixtureStatus.automationJobId; NotBefore = [datetimeoffset]$fixtureStatus.startedOnUtc
        }
        $script:BlobReads.Clear()
        $evidence = Test-AzurePublishedDashboardEvidence @parameters
        Assert-True ($evidence.payload_row_count -eq 2 -and $evidence.hosted_assets_validated) 'Saved production candidate did not validate.'
        $publishedHostedName = if ($fixtureStatus.dashboardDeliveryMode -eq 'Dual') { $fixtureStatus.hostedDashboardBlobName } else { $fixtureStatus.dashboardBlobName }
        $publishedConfig = Get-DashboardHtmlScriptContent -Html (Get-Content -LiteralPath (Join-Path $script:FixtureRoot $publishedHostedName) -Raw) -ScriptId 'dashboardConfig' | ConvertFrom-Json -Depth 20
        $pdfName = [string]$publishedConfig.pdfExportRuntimeUrl
        Assert-True ($script:BlobReads.Contains($pdfName)) 'Saved production candidate PDF runtime was not downloaded.'
        Assert-True ($fixtureStatus.artifactSha256.PSObject.Properties[$pdfName].Value -eq (Get-FileHash -LiteralPath (Join-Path $script:FixtureRoot $pdfName)).Hash.ToLowerInvariant()) 'Saved production candidate lacks the matching optional runtime hash.'
        Write-Host 'Saved two-row production candidate passed offline with configured PDF runtime download and current-status hash.'
    }
    Write-Host 'Setup artifact validation regression passed.'
}
finally {
    if (Test-Path -LiteralPath $tempRoot) { Remove-Item -LiteralPath $tempRoot -Recurse -Force }
}