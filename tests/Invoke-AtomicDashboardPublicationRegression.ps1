#Requires -Version 7.0
[CmdletBinding()]
param(
    [string]$JqPath = $env:DASHBOARD_SYNC_JQ,
    [string]$BashPath = $env:DASHBOARD_SYNC_BASH,
    [string]$RunbookSourcePath = (Join-Path (Split-Path $PSScriptRoot -Parent) 'build/azure/runbook-source.ps1')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path $PSScriptRoot -Parent
if (-not $JqPath) {
    $jqCommand = Microsoft.PowerShell.Core\Get-Command jq -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($jqCommand) { $JqPath = $jqCommand.Source }
}
if (-not $BashPath) {
    if ($IsWindows) {
        $gitCommand = Microsoft.PowerShell.Core\Get-Command git -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($gitCommand) {
            $gitBash = Join-Path (Split-Path $gitCommand.Source -Parent) '../bin/bash.exe'
            if (Test-Path -LiteralPath $gitBash -PathType Leaf) { $BashPath = (Resolve-Path -LiteralPath $gitBash).Path }
        }
    }
    if (-not $BashPath) {
        $bashCommand = Microsoft.PowerShell.Core\Get-Command bash -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($bashCommand) { $BashPath = $bashCommand.Source }
    }
}
if (-not $JqPath -or -not (Test-Path -LiteralPath $JqPath -PathType Leaf)) {
    throw 'Real jq is required: install jq on PATH (Ubuntu: sudo apt-get install jq; Windows: winget install --id jqlang.jq --exact), or pass -JqPath / set DASHBOARD_SYNC_JQ. No dependency is downloaded or test skipped.'
}
if (-not $BashPath -or -not (Test-Path -LiteralPath $BashPath -PathType Leaf)) {
    throw 'Bash is required: install bash on PATH (Git Bash on Windows), or pass -BashPath / set DASHBOARD_SYNC_BASH.'
}
$JqPath = (Resolve-Path -LiteralPath $JqPath).Path
$BashPath = (Resolve-Path -LiteralPath $BashPath).Path
& $JqPath --version
if ($LASTEXITCODE -ne 0) { throw 'The configured jq executable could not run.' }
. (Join-Path $repoRoot 'build/Import-SharedHelpers.ps1')
. (Join-Path $repoRoot 'src/powershell/Provisioning/Azure/AzureProvisioning.ps1')
$parseErrors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($RunbookSourcePath, [ref]$null, [ref]$parseErrors)
if ($parseErrors.Count) { throw ($parseErrors | Out-String) }
foreach ($name in @('Export-ToBlobStorage', 'Get-DashboardBlobContentType', 'Compress-GzipFile')) {
    $definition = $ast.Find({ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $name }, $true)
    . ([scriptblock]::Create($definition.Extent.Text))
}
if (-not $ast.Extent.Text.Contains('-AssetGeneration $Script:PipelineRunId')) { throw 'Runbook does not opt into immutable generation paths.' }
$statusFailureDefinition = $ast.Find({ param($node) $node -is [System.Management.Automation.Language.IfStatementAst] -and $node.Clauses[0].Item1.Extent.Text -eq '-not $finalStatusUploaded' }, $true)
if (-not $statusFailureDefinition) { throw 'Final status upload is not checked.' }
$statusFailureCheck = [scriptblock]::Create($statusFailureDefinition.Extent.Text)
$script:BoundedMetadataReader = ${function:Get-DashboardReferenceHtmlFromPath}
$script:BoundedMetadataReads = 0
function Get-DashboardReferenceHtmlFromPath {
    param([string]$Path)
    $script:BoundedMetadataReads++
    & $script:BoundedMetadataReader -Path $Path
}
$readerParameter = $ast.ParamBlock.Parameters | Where-Object { $_.Name.VariablePath.UserPath -eq 'UseBoundedPublicationMetadataReader' }
if ($readerParameter) {
    if ($readerParameter.DefaultValue.Extent.Text -ne '$false') { throw 'Runbook bounded metadata reader must default to false.' }
}
elseif (-not $ast.Extent.Text.Contains('$UseBoundedPublicationMetadataReader = $false')) { throw 'Function bounded metadata reader must remain fixed false.' }
$publisherDefinition = $ast.Find({ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Export-ToBlobStorage' }, $true)
$publisherParameter = $publisherDefinition.Body.ParamBlock.Parameters | Where-Object { $_.Name.VariablePath.UserPath -eq 'UseBoundedPublicationMetadataReader' }
if ($publisherParameter.DefaultValue.Extent.Text -ne '$false') { throw 'Publisher bounded metadata reader must default to false.' }
$readerBranches = @($publisherDefinition.Body.FindAll({ param($node) $node -is [System.Management.Automation.Language.IfStatementAst] -and $node.Clauses[0].Item1.Extent.Text -eq '$UseBoundedPublicationMetadataReader' }, $true))
if ($readerBranches.Count -ne 3) { throw 'All three publication metadata reads must be gated.' }
foreach ($branch in $readerBranches) {
    if ($branch.Clauses[0].Item2.Extent.Text -notlike '*Get-DashboardReferenceHtmlFromPath -Path*' -or $branch.ElseClause.Extent.Text -notlike '*Get-Content -LiteralPath* -Raw*') { throw 'Metadata reader branch changed the legacy default.' }
}
$publisherCalls = @($ast.FindAll({ param($node) $node -is [System.Management.Automation.Language.CommandAst] -and $node.GetCommandName() -eq 'Export-ToBlobStorage' }, $true))
if ($publisherCalls.Count -ne 3 -or @($publisherCalls | Where-Object { $_.Extent.Text -notlike '*-UseBoundedPublicationMetadataReader $UseBoundedPublicationMetadataReader*' }).Count) { throw 'Pipeline export calls must forward the reader flag.' }
$Script:BlobContainers = @{ Exports = 'exports'; Dashboards = 'dashboards' }
$Script:BlobAccessTiers = @{ Exports = 'Hot'; Dashboards = 'Hot' }
$Script:DashboardBlobName = 'VulnerabilityDashboard.html'
$Script:HostedDashboardBlobName = 'VulnerabilityDashboard.Hosted.html'
$Script:DashboardTrackedBlobNames = @($Script:DashboardBlobName, $Script:HostedDashboardBlobName)
$Script:DashboardTrackedAssetDirectories = @('VulnerabilityDashboard.assets', 'VulnerabilityDashboard.Hosted.assets')
$script:Blobs = @{}
$script:Uploads = [System.Collections.Generic.List[string]]::new()
$script:FailUpload = 0
$script:CorruptRead = $false
$script:FailPrune = $false
$script:LockHeld = $false
$script:HeartbeatFailed = $false
$script:CommitThenFail = $false
$script:RestoreFails = $false

function Start-DashboardPublicationLock {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'In-memory lease mock.')]
    param($AccountName, $StorageToken, $RootNames)
    if ($script:LockHeld) { throw '409 lease already held' }
    $script:LockHeld = $true
    foreach ($name in $RootNames) { if (-not $script:Blobs.ContainsKey($name)) { $script:Blobs[$name] = [byte[]]::new(0) } }
    return @{ LeaseId = 'fixture-lease'; AccountName = $AccountName; StorageToken = $StorageToken }
}
function Assert-DashboardPublicationLock {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '', Justification = 'Mock preserves production lock signature.')]
    param($Lock)
    if (-not $script:LockHeld -or $script:HeartbeatFailed) { throw 'Lease ownership lost' }
}
function Stop-DashboardPublicationLock {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'In-memory lease mock.')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '', Justification = 'Mock preserves production lock signature.')]
    param($Lock)
    $script:LockHeld = $false
}
function Get-DashboardRootETag {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '', Justification = 'Mock preserves production root metadata signature.')]
    param($AccountName, $StorageToken, $BlobName)
    return Get-BlobHash $script:Blobs[$BlobName]
}

function Assert-True([bool]$Condition, [string]$Message) { if (-not $Condition) { throw $Message } }
function Get-BlobList {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '', Justification = 'Scoped mock uses the production Blob signature.')]
    param($AccountName, $Container, $StorageToken)
    if ($Container -eq 'dashboards') { return @($script:Blobs.Keys) }
    return @('_fixture')
}
function Get-BlobContent {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '', Justification = 'Scoped mock uses the production Blob signature.')]
    param($AccountName, $Container, $BlobName, $DestinationPath, $StorageToken)
    if (-not $script:Blobs.ContainsKey($BlobName)) { throw "Missing mock blob $BlobName" }
    [void](New-Item -Path (Split-Path $DestinationPath -Parent) -ItemType Directory -Force)
    $bytes = $script:Blobs[$BlobName]
    if ($script:CorruptRead -and $BlobName -like '*.assets/*') { $bytes = [byte[]]@(1,2,3) }
    [System.IO.File]::WriteAllBytes($DestinationPath, $bytes)
}
function Set-BlobContent {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'In-memory regression mock.')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '', Justification = 'Scoped mock uses the production Blob signature.')]
    param($AccountName, $Container, $BlobName, $SourcePath, $StorageToken, $ContentType, $AccessTier, $Conditions)
    if ($Container -ne 'dashboards') { return }
    if ($Conditions['If-None-Match'] -eq '*' -and $script:Blobs.ContainsKey($BlobName)) { throw '412 immutable blob exists' }
    if ($BlobName -in $Script:DashboardTrackedBlobNames) {
        if ($Conditions['x-ms-lease-id'] -ne 'fixture-lease' -or -not $script:LockHeld) { throw '412 stale root lease' }
        if ($Conditions['If-Match'] -ne (Get-BlobHash $script:Blobs[$BlobName])) { throw '412 stale root ETag' }
        if ($script:RestoreFails -and $script:CommitThenFail) { throw 'Injected restoration failure' }
    }
    $script:Uploads.Add($BlobName)
    if ($script:Uploads.Count -eq $script:FailUpload) { throw 'Injected upload failure.' }
    $script:Blobs[$BlobName] = [System.IO.File]::ReadAllBytes($SourcePath)
    if ($script:CommitThenFail -and $BlobName -in $Script:DashboardTrackedBlobNames) { $script:RestoreFails = $true; throw 'Injected response loss after root commit' }
}
function Remove-Blob {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'In-memory regression mock.')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '', Justification = 'Scoped mock uses the production Blob signature.')]
    param($AccountName, $Container, $BlobName, $StorageToken)
    if ($script:FailPrune) { throw 'Injected retention failure.' }
    $script:Blobs.Remove($BlobName)
}
function Get-BlobHash([byte[]]$Bytes) { return [Convert]::ToHexString([System.Security.Cryptography.SHA256]::HashData($Bytes)) }
function Assert-PriorUnchanged($Prior) {
    foreach ($name in $Prior.Keys) {
        Assert-True ($script:Blobs.ContainsKey($name) -and (Get-BlobHash $script:Blobs[$name]) -eq (Get-BlobHash $Prior[$name])) "Prior blob changed or disappeared: $name"
    }
}

function Invoke-ServingFixture {
    param([string]$FirstRoot, [string]$NextRoot, [string]$FixturePath, [string]$RootName, [switch]$Embedded)
    $bash = $BashPath
    [void](New-Item -ItemType Directory -Path "$FixturePath/bin", "$FixturePath/data", "$FixturePath/remote" -Force)
    $mockCurl = @'
#!/bin/sh
out=
headers=
url=
while [ "$#" -gt 0 ]; do
    case "$1" in
        --output) out=$2; shift 2 ;;
        --dump-header) headers=$2; shift 2 ;;
        --header) shift 2 ;;
        http*) url=$1; shift ;;
        *) shift ;;
    esac
done
case "$url" in
    http://identity/*) printf '{"access_token":"fixture"}'; exit 0 ;;
    https://fixture.blob.core.windows.net/dashboards/*) name=${url#https://fixture.blob.core.windows.net/dashboards/} ;;
    *) echo 'Unexpected remote URI' >&2; exit 97 ;;
esac
printf '%s\n' "$name" >> "$FIXTURE_LOG"
[ "$name" != "${FAIL_BLOB:-}" ] || exit 22
cp "$FIXTURE_REMOTE/$name" "$out" || exit 22
if [ -n "$headers" ]; then
    printf 'x-ms-meta-sha256: %s\r\n' "$(sha256sum "$out" | cut -d' ' -f1)" > "$headers"
fi
'@
    Write-Utf8File -Path "$FixturePath/bin/curl" -Content ($mockCurl -replace "`r`n", "`n")
    $scriptPath = "$FixturePath/startup.sh"
    $startup = (Get-DashboardContainerSyncScript -AccountName fixture -HtmlBlobName $RootName) -replace "`r`n", "`n"
    Write-Utf8File -Path $scriptPath -Content $startup
    $productionCall = $startup.Substring(0, $startup.LastIndexOf("`nmkdir -p " + '"$DATA_ROOT"')) + @'

mkdir -p "$DATA_ROOT" || exit 1
for attempt in 1; do
    sync_dashboard || echo 'Dashboard sync failed; retaining the previous local generation.' >&2
done
'@
    Write-Utf8File -Path "$FixturePath/production-call.sh" -Content $productionCall
    Write-Utf8File -Path "$FixturePath/bin/tr" -Content @'
#!/bin/sh
[ "${FAIL_TR:-0}" != 1 ] || exit 91
exec "$SERVE_REAL_TR" "$@"
'@
    Write-Utf8File -Path "$FixturePath/bin/mv" -Content @'
#!/bin/sh
if [ "${FAIL_INDEX_RENAME:-0}" = 1 ] && [ "$2" = "$DATA_ROOT/index.html" ]; then exit 92; fi
exec "$SERVE_REAL_MV" "$@"
'@
    $env:SERVE_JQ = $JqPath
    $env:SERVE_FIXTURE = $FixturePath
    $env:SERVE_WINDOWS = [int]$IsWindows
    $invoke = @'
set -eu
if [ "$SERVE_WINDOWS" = 1 ]; then
    fixture=$(cygpath -u "$SERVE_FIXTURE")
    jqpath=$(cygpath -u "$SERVE_JQ")
else
    fixture=$SERVE_FIXTURE
    jqpath=$SERVE_JQ
fi
jqdir=$(dirname "$jqpath")
export SERVE_REAL_TR=$(command -v tr) SERVE_REAL_MV=$(command -v mv)
export PATH="$fixture/bin:$jqdir:$PATH"
chmod +x "$fixture/bin/curl" "$fixture/bin/tr" "$fixture/bin/mv"
export DATA_ROOT="$fixture/data" FIXTURE_REMOTE="$fixture/remote" FIXTURE_LOG="$fixture/requests.txt" IDENTITY_HEADER=fixture IDENTITY_ENDPOINT=http://identity/token SYNC_ONCE=1
sh "$fixture/startup.sh"
'@
    Copy-Item -Path "$FirstRoot/*" -Destination "$FixturePath/remote" -Recurse -Force
    Assert-True (-not (Test-Path "$FixturePath/data/index.html")) 'Fresh sync fixture already has a stale index.'
    & $bash -c $invoke
    Assert-True ($LASTEXITCODE -eq 0) 'Generated container shell rejected the complete generation.'
    $oldIndexHash = (Get-FileHash "$FixturePath/data/index.html").Hash
    Assert-True ($oldIndexHash -eq (Get-FileHash "$FirstRoot/$RootName").Hash) 'Fresh sync did not publish the exact candidate HTML.'
    $oldFiles = @(Get-ChildItem "$FixturePath/data" -Recurse -File)
    $oldHashes = @{}
    foreach ($file in $oldFiles) { $oldHashes[$file.FullName] = (Get-FileHash $file.FullName).Hash }
    Copy-Item -Path "$NextRoot/*" -Destination "$FixturePath/remote" -Recurse -Force
    $html = Get-Content (Join-Path $NextRoot $RootName) -Raw
    $required = @(Get-DashboardRequiredAssetName -Html $html -HtmlBlobName $RootName)
    Assert-True ($required.Count -eq $(if ($Embedded) { 0 } else { 8 })) 'Shell fixture dependency count is incorrect.'
    $productionInvoke = $invoke.Replace('sh "$fixture/startup.sh"', 'sh "$fixture/production-call.sh"')
    foreach ($fault in @('FAIL_TR', 'FAIL_INDEX_RENAME')) {
        [Environment]::SetEnvironmentVariable($fault, '1')
        try { $result = @(& $bash -c $productionInvoke 2>&1) } finally { [Environment]::SetEnvironmentVariable($fault, $null) }
        Assert-True ($LASTEXITCODE -eq 0) 'Production failure handler did not allow the serving loop to continue.'
        Assert-True (($result -join "`n").Contains('Dashboard sync failed; retaining the previous local generation.')) "Production caller did not observe $fault sync failure."
        Assert-True ((Get-FileHash "$FixturePath/data/index.html").Hash -eq $oldIndexHash) "$fault exposed candidate HTML."
        foreach ($path in $oldHashes.Keys) { Assert-True ((Get-FileHash $path).Hash -eq $oldHashes[$path]) "$fault changed prior dependencies." }
        Assert-True (@(Get-ChildItem "$FixturePath/data" -Force -Directory -Filter '.sync.*').Count -eq 0) "$fault leaked staging files."
    }
    $configJson = Get-DashboardHtmlScriptContent -Html $html -ScriptId dashboardConfig
    $invalidRoots = @($html.Replace($configJson, '{invalid'), [regex]::Replace($html, '(?is)<script\b[^>]*\bid="dashboardConfig"[^>]*>.*?</script>', ''))
    $missingPdfConfig = $configJson | ConvertFrom-Json
    $missingPdfConfig | Add-Member -NotePropertyName pdfExportRuntimeMode -NotePropertyValue external -Force
    $missingPdfConfig.PSObject.Properties.Remove('pdfExportRuntimeUrl')
    $invalidRoots += $html.Replace($configJson, ($missingPdfConfig | ConvertTo-Json -Compress))
    if (-not $Embedded) {
        $missingHostedConfig = $configJson | ConvertFrom-Json
        $missingHostedConfig.PSObject.Properties.Remove('payloadUrl')
        $invalidRoots += $html.Replace($configJson, ($missingHostedConfig | ConvertTo-Json -Compress))
    }
    foreach ($invalidHtml in $invalidRoots) {
        Write-Utf8File -Path "$FixturePath/remote/$RootName" -Content $invalidHtml
        & $bash -c $invoke
        Assert-True ($LASTEXITCODE -ne 0) 'Malformed or missing required config was accepted by the shell.'
        Assert-True ((Get-FileHash "$FixturePath/data/index.html").Hash -eq $oldIndexHash) 'Invalid config exposed candidate HTML.'
        foreach ($path in $oldHashes.Keys) { Assert-True ((Get-FileHash $path).Hash -eq $oldHashes[$path]) 'Invalid config changed prior dependencies.' }
    }
    Write-Utf8File -Path "$FixturePath/remote/$RootName" -Content $html
    foreach ($name in $required) {
        $env:FAIL_BLOB = $name
        & $bash -c $invoke
        Assert-True ($LASTEXITCODE -ne 0) "Failed download was accepted: $name"
        Assert-True ((Get-FileHash "$FixturePath/data/index.html").Hash -eq $oldIndexHash) 'Failed rollover changed local index.'
        foreach ($path in $oldHashes.Keys) { Assert-True ((Get-FileHash $path).Hash -eq $oldHashes[$path]) 'Failed rollover changed prior dependencies.' }
    }
    $env:FAIL_BLOB = ''
    & $bash -c $invoke
    Assert-True ($LASTEXITCODE -eq 0) 'Complete rollover was rejected.'
    if ($Embedded) {
        Assert-True ((Get-FileHash "$FixturePath/data/index.html").Hash -eq (Get-FileHash "$NextRoot/$RootName").Hash) 'Embedded rollover bytes mismatch.'
        Write-Output 'Generated container shell: fresh embedded zero-dependency sync, rollover, production-context tr/index-rename failures and invalid config rejection passed.'
        return
    }
    foreach ($name in $required) { Assert-True ((Get-FileHash "$FixturePath/data/$name").Hash -eq (Get-FileHash "$NextRoot/$name").Hash) 'Serving dependency bytes mismatch.' }
    $prefix = Get-DashboardPublishedAssetPrefix -Html $html -HtmlBlobName $RootName
    $legacyPrefix = [System.IO.Path]::GetFileNameWithoutExtension($RootName) + '.assets/'
    foreach ($name in $required) {
        $legacyName = $name.Replace($prefix, $legacyPrefix)
        [void](New-Item -Path (Split-Path "$FixturePath/remote/$legacyName" -Parent) -ItemType Directory -Force)
        Copy-Item "$NextRoot/$name" "$FixturePath/remote/$legacyName" -Force
    }
    $legacyHtml = $html.Replace($prefix, $legacyPrefix)
    $mixedHtml = $html
    $mixedConfig = Get-DashboardHtmlScriptContent -Html $html -ScriptId dashboardConfig | ConvertFrom-Json
    foreach ($property in @('pdfExportRuntimeUrl', 'pdfExportBundleUrl')) {
        $name = [string]$mixedConfig.$property
        $mixedHtml = $mixedHtml.Replace($name, $name.Replace($prefix, $legacyPrefix))
    }
    Write-Utf8File -Path "$FixturePath/remote/$RootName" -Content $mixedHtml
    & $bash -c $invoke
    Assert-True ($LASTEXITCODE -eq 0) 'Mixed versioned payload and legacy PDF dependencies were rejected.'
    $mixedLocal = Get-Content "$FixturePath/data/index.html" -Raw
    Assert-True ($mixedLocal.Contains($prefix + 'data/payload.json.gz') -and $mixedLocal.Contains('/local-generations/')) 'Mixed legacy rewriting changed versioned references.'
    Write-Utf8File -Path "$FixturePath/remote/$RootName" -Content $legacyHtml
    & $bash -c $invoke
    Assert-True ($LASTEXITCODE -eq 0) 'Legacy eight-dependency root was rejected.'
    $legacyLocalHtml = Get-Content "$FixturePath/data/index.html" -Raw
    Assert-True ($legacyLocalHtml.Contains('/local-generations/')) 'Legacy dependencies were not made locally immutable.'
    $legacyIndexHash = (Get-FileHash "$FixturePath/data/index.html").Hash
    $legacyFiles = @(Get-ChildItem "$FixturePath/data" -Recurse -File)
    $legacyHashes = @{}
    foreach ($file in $legacyFiles) { $legacyHashes[$file.FullName] = (Get-FileHash $file.FullName).Hash }
    $env:FAIL_BLOB = $required[0].Replace($prefix, $legacyPrefix)
    Write-Utf8File -Path "$FixturePath/remote/$RootName" -Content ($legacyHtml + '<!-- rollover -->')
    & $bash -c $invoke
    $env:FAIL_BLOB = ''
    Assert-True ($LASTEXITCODE -ne 0 -and (Get-FileHash "$FixturePath/data/index.html").Hash -eq $legacyIndexHash) 'Legacy failed rollover replaced the index.'
    foreach ($path in $legacyHashes.Keys) { Assert-True ((Get-FileHash $path).Hash -eq $legacyHashes[$path]) 'Legacy failed rollover changed old bytes.' }
    Write-Utf8File -Path "$FixturePath/remote/$RootName" -Content ($legacyHtml.Replace(($legacyPrefix + 'vendor/chart.js'), 'https://attacker.invalid/script.js'))
    $beforeRequests = @(Get-Content "$FixturePath/requests.txt").Count
    & $bash -c $invoke
    Assert-True ($LASTEXITCODE -ne 0) 'Unsafe configured URI was accepted by the container shell.'
    $newRequests = @(Get-Content "$FixturePath/requests.txt") | Select-Object -Skip $beforeRequests
    Assert-True (@($newRequests | Where-Object { $_ -ne $RootName }).Count -eq 0) 'Unsafe root triggered dependency downloads.'
    Write-Output 'Generated container shell: generation and legacy eight-dependency roots, nine failed download rollovers, production-context tr/index-rename failures, exact bytes, invalid config and unsafe URI rejection passed.'
}

$tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('atomic-dashboard-' + [guid]::NewGuid().ToString('N'))
$servingEnvironment = @{}
foreach ($name in @('SERVE_JQ', 'SERVE_FIXTURE', 'SERVE_WINDOWS', 'FAIL_BLOB', 'FAIL_TR', 'FAIL_INDEX_RENAME')) {
    $servingEnvironment[$name] = [Environment]::GetEnvironmentVariable($name)
}
try {
    foreach ($name in @('FAIL_BLOB', 'FAIL_TR', 'FAIL_INDEX_RENAME')) { [Environment]::SetEnvironmentVariable($name, $null) }
    [void](New-Item -Path $tempRoot -ItemType Directory -Force)
    $exports = Join-Path $tempRoot 'exports'
    [void](New-Item -Path $exports -ItemType Directory -Force)
    & (Join-Path $PSScriptRoot 'Generate-SyntheticLargeExports.ps1') -SourcePath $tempRoot -OutputPath $exports -TargetDeviceCount 2 -TargetTotalVulnRows 2 -SnapshotCount 1 -ContentTemplateCount 2 -MinimumAvailableMemoryGB 0.5 -MinimumFreeDiskGB 1 | Out-Null
    $library = Join-Path $tempRoot 'library.js'
    [System.IO.File]::WriteAllText($library, 'window.fixture = true;')
    $payload = Join-Path $tempRoot 'payload.json.gz'
    Write-GzipTextFile -Path $payload -Content '{"vulnsFormat":"rows-v1","lookups":{},"vulns":[[0]]}'
    $compressedLibrary = Join-Path $tempRoot 'library.js.gz'
    Write-GzipTextFile -Path $compressedLibrary -Content 'window.fixture = true;'
    $template = Get-Content -LiteralPath (Join-Path $repoRoot 'templates/dashboard.html') -Raw
    $bundle = @{
        TemplateHtml = $template; TemplateCss = 'body { color: black; }'; TemplateJs = 'window.fixture = true;'
        PakoLibraryPath = $library; ChartJsLibraryPath = $library; PdfExportBundleSourcePath = $library
        ChartJsBundlePath = $compressedLibrary; PdfExportBundlePath = $compressedLibrary; PayloadPath = $payload
        TemplateJsModules = [ordered]@{ 'dashboard/00-test.js' = 'window.fixture = true;'; 'dashboard/90-pdf-export.js' = 'window.pdfFixture = true;' }
    }
    foreach ($mode in @('SelfContained', 'Hosted', 'Dual')) {
        $script:Blobs = @{}
        $versions = @()
        foreach ($versionNumber in 1..3) {
            $root = Join-Path $tempRoot "$mode-$versionNumber"
            [void](New-Item -Path $root -ItemType Directory -Force)
            $generation = [guid]::NewGuid().ToString('N')
            if ($mode -in @('SelfContained', 'Dual')) {
                $null = Write-DashboardArtifactBundle @bundle -OutputPath (Join-Path $root $Script:DashboardBlobName)
            }
            if ($mode -in @('Hosted', 'Dual')) {
                $hostedName = if ($mode -eq 'Dual') { $Script:HostedDashboardBlobName } else { $Script:DashboardBlobName }
                $null = Write-DashboardArtifactBundle @bundle -OutputPath (Join-Path $root $hostedName) -SplitAssets $true -AssetGeneration $generation
                $html = Get-Content -LiteralPath (Join-Path $root $hostedName) -Raw
                $prefix = Get-DashboardPublishedAssetPrefix -Html $html -HtmlBlobName $hostedName
                Assert-True ($prefix -like "*/generations/$generation/") 'Generator emitted a mutable prefix.'
                foreach ($asset in @(Get-DashboardHostedAssetLayout).Values) {
                    Assert-True ($html.Contains("$prefix$asset")) "HTML/config does not reference $asset"
                    Assert-True (Test-Path -LiteralPath (Join-Path $root "$prefix$asset")) "Generation asset missing: $asset"
                }
            }
            $versions += [pscustomobject]@{ Root = $root; Generation = $generation }
        }
        $publish = {
            param($Root, [bool]$ExplicitRoot = $true, [bool]$UseBoundedPublicationMetadataReader = $false)
            $rootParameter = @{}
            if ($ExplicitRoot) { $rootParameter.DashboardRootPath = $Root }
            if ($UseBoundedPublicationMetadataReader) { $rootParameter.UseBoundedPublicationMetadataReader = $true }
            $script:BoundedMetadataReads = 0
            Export-ToBlobStorage -AccountName fixture -StorageToken fixture -ExportsPath $exports -DashboardPath (Join-Path $Root $Script:DashboardBlobName) @rootParameter | Out-Null
            Assert-True (($script:BoundedMetadataReads -gt 0) -eq $UseBoundedPublicationMetadataReader) 'Publisher selected the wrong metadata reader.'
        }
        $script:Uploads.Clear()
        & $publish $versions[0].Root $false
        $untouchedReferences = @()
        if ($mode -eq 'Hosted') {
            $otherRoot = Join-Path $tempRoot 'untouched-root'
            [void](New-Item -Path $otherRoot -ItemType Directory -Force)
            $otherPath = Join-Path $otherRoot $Script:HostedDashboardBlobName
            $null = Write-DashboardArtifactBundle @bundle -OutputPath $otherPath
            $otherHtml = Get-Content $otherPath -Raw
            $otherConfigJson = Get-DashboardHtmlScriptContent -Html $otherHtml -ScriptId dashboardConfig
            $otherConfig = $otherConfigJson | ConvertFrom-Json
            foreach ($dependency in @('pdfExportRuntime', 'pdfExportBundle')) {
                $name = 'VulnerabilityDashboard.Hosted.assets/generations/' + ('f' * 32) + "/optional/$dependency.js"
                $otherConfig | Add-Member -NotePropertyName ($dependency + 'Mode') -NotePropertyValue external -Force
                $otherConfig | Add-Member -NotePropertyName ($dependency + 'Url') -NotePropertyValue $name -Force
                $script:Blobs[$name] = [System.IO.File]::ReadAllBytes($library)
                $untouchedReferences += $name
            }
            $script:Blobs[$Script:HostedDashboardBlobName] = [Text.Encoding]::UTF8.GetBytes($otherHtml.Replace($otherConfigJson, ($otherConfig | ConvertTo-Json -Compress)))
            $legacyName = 'VulnerabilityDashboard.Hosted.assets/optional/legacy.js'
            $script:Blobs[$legacyName] = [System.IO.File]::ReadAllBytes($library)
            $untouchedReferences += $legacyName
        }
        $prior = $script:Blobs.Clone()
        $metadataRoot = if ($mode -eq 'Dual') { $Script:HostedDashboardBlobName } else { $Script:DashboardBlobName }
        $pdfPrefix = [System.IO.Path]::GetFileNameWithoutExtension($metadataRoot) + '.assets/generations/' + ('e' * 32) + '/'
        $pdfNames = @(($pdfPrefix + 'runtime/pdf.js'), ($pdfPrefix + 'data/pdf.json.gz'), ($pdfPrefix + 'optional/unreferenced.js'))
        $pdfConfig = [ordered]@{ pdfExportRuntimeMode = 'external'; pdfExportRuntimeUrl = $pdfNames[0]; pdfExportBundleMode = 'external'; pdfExportBundleUrl = $pdfNames[1] } | ConvertTo-Json -Compress
        $pdfHtml = '<script id="dataFormat">compressed</script><script id="dashboardConfig" type="application/json">' + $pdfConfig + '</script><script src="' + $pdfNames[0] + '"></script><link href="' + $pdfNames[1] + '">'
        $validPriorVariants = @(
            ('<script data-note='' id="dashboardConfig"''>{}</script>' + $pdfHtml),
            ('<!-- user''s <script id="dashboardConfig">{}</script><link href="fake.js"> -->' + $pdfHtml),
            ('<!---->' + $pdfHtml),
            ('<!-- user''s normal note -->' + $pdfHtml),
            ('<!DOCTYPE html><script>const text="</script >' + $pdfHtml),
            ('<script>const text="</ScRiPt' + "`t>" + $pdfHtml)
        )
        foreach ($variant in $validPriorVariants) {
            $script:Blobs = $prior.Clone()
            $script:Blobs[$metadataRoot] = [Text.Encoding]::UTF8.GetBytes($variant)
            foreach ($name in $pdfNames) { $script:Blobs[$name] = [System.IO.File]::ReadAllBytes($library) }
            $pdfPrior = $script:Blobs.Clone()
            $script:Uploads.Clear()
            & $publish $versions[1].Root $true $true
            Assert-True (-not $script:LockHeld) 'Valid metadata publication leaked the lease.'
            foreach ($name in $pdfNames) {
                Assert-True ($script:Blobs.ContainsKey($name) -and (Get-BlobHash $script:Blobs[$name]) -ceq (Get-BlobHash $pdfPrior[$name])) "Previous PDF generation lost bytes: $name"
            }
        }
        $invalidPriorVariants = @(
            ('<script id="dataFormat">compressed</script><!-->' + $pdfHtml.Replace('<script id="dataFormat">compressed</script>', '') + '<!-- end -->'),
            ('<script id="dataFormat">compressed</script><!--->' + $pdfHtml.Replace('<script id="dataFormat">compressed</script>', '') + '<!-- end -->'),
            ('<script id="dataFormat">compressed</script><!-- note --!>' + $pdfHtml.Replace('<script id="dataFormat">compressed</script>', '') + '<!-- end -->'),
            ('<!--<!-->' + $pdfHtml + '<!-- end -->'),
            ($pdfHtml + '<script id="dashboardConfig">{}</script>'),
            $pdfHtml.Replace('id="dashboardConfig"', 'type="application/json" id=''dashboardConfig'''),
            ($pdfHtml + '<script>const phantom='' <link href="fake.js">'';</script>'),
            ('<!-- user''s unfinished note' + $pdfHtml),
            ('<!--' + (' ' * 1MB) + '-->' + $pdfHtml),
            ('<script id="dashboardConfig">' + (' ' * 1MB) + '{}</script>'),
            ('<![CDATA[ignored]]>' + $pdfHtml)
        )
        foreach ($variant in $invalidPriorVariants) {
            $script:Blobs = $prior.Clone()
            $script:Blobs[$metadataRoot] = [Text.Encoding]::UTF8.GetBytes($variant)
            foreach ($name in $pdfNames) { $script:Blobs[$name] = [System.IO.File]::ReadAllBytes($library) }
            $pdfPrior = $script:Blobs.Clone()
            $script:Uploads.Clear()
            $failed = $false
            try { & $publish $versions[1].Root $true $true } catch { $failed = $true }
            Assert-True ($script:BoundedMetadataReads -gt 0) 'Parser rejection did not select the opted-in bounded reader.'
            Assert-True $failed 'Ambiguous or unsupported prior metadata was accepted.'
            Assert-PriorUnchanged $pdfPrior
            Assert-True (-not $script:LockHeld) 'Rejected prior metadata leaked the lease.'
            Assert-True (@($script:Uploads | Where-Object { $_ -notlike '_publication/recovery/*' }).Count -eq 0) 'Rejected prior metadata wrote candidate blobs.'
        }
        $script:Blobs = $prior.Clone()
        $script:Uploads.Clear()
        Write-Output "$mode metadata publisher: $($validPriorVariants.Count) valid PDF retention and $($invalidPriorVariants.Count) fail-closed whole-generation/lease checks passed."
        $uploadCount = 1 + @(Get-ChildItem -LiteralPath $versions[1].Root -File -Recurse).Count + 2 * @($prior.Keys | Where-Object { $_ -in $Script:DashboardTrackedBlobNames -and $prior[$_].Length -gt 0 }).Count
        foreach ($failurePosition in 1..$uploadCount) {
            $script:Blobs = $prior.Clone()
            $script:Uploads.Clear()
            $script:FailUpload = $failurePosition
            $failed = $false
            try { & $publish $versions[1].Root } catch { $failed = $true }
            Assert-True $failed "Expected failure at upload $failurePosition in $mode"
            Assert-PriorUnchanged $prior
        }
        $script:FailUpload = 0
        if ($mode -ne 'SelfContained') {
            $candidateHtmlPath = Join-Path $versions[1].Root $(if ($mode -eq 'Dual') { $Script:HostedDashboardBlobName } else { $Script:DashboardBlobName })
            $references = @(Get-DashboardRequiredAssetName -Html (Get-Content $candidateHtmlPath -Raw) -HtmlBlobName ([System.IO.Path]::GetFileName($candidateHtmlPath)))
            foreach ($reference in $references) {
                $path = Join-Path $versions[1].Root $reference
                Move-Item -LiteralPath $path -Destination "$path.absent"
                $script:Blobs = $prior.Clone()
                $failed = $false
                try { & $publish $versions[1].Root } catch { $failed = $_.Exception.Message -like '*Missing required dashboard dependency*' }
                Move-Item -LiteralPath "$path.absent" -Destination $path
                Assert-True $failed "Missing required dependency was accepted: $reference"
                Assert-PriorUnchanged $prior
            }
        }
        $script:Blobs = $prior.Clone()
        $script:HeartbeatFailed = $true
        $failed = $false
        try { & $publish $versions[1].Root } catch { $failed = $true }
        $script:HeartbeatFailed = $false
        Assert-True $failed 'Heartbeat failure was accepted.'
        Assert-PriorUnchanged $prior
        $rootName = if ($mode -eq 'Dual') { $Script:HostedDashboardBlobName } else { $Script:DashboardBlobName }
        $script:LockHeld = $false
        $failed = $false
        try { Set-BlobContent -AccountName fixture -Container dashboards -BlobName $rootName -SourcePath (Join-Path $versions[1].Root $rootName) -StorageToken fixture -Conditions @{'x-ms-lease-id' = 'fixture-lease'; 'If-Match' = (Get-BlobHash $script:Blobs[$rootName])} } catch { $failed = $_.Exception.Message -like '*stale root lease*' }
        Assert-True $failed 'Lost lease committed a root.'
        $script:LockHeld = $true
        $failed = $false
        try { Set-BlobContent -AccountName fixture -Container dashboards -BlobName $rootName -SourcePath (Join-Path $versions[1].Root $rootName) -StorageToken fixture -Conditions @{'x-ms-lease-id' = 'fixture-lease'; 'If-Match' = 'stale-etag'} } catch { $failed = $_.Exception.Message -like '*stale root ETag*' }
        $script:LockHeld = $false
        Assert-True $failed 'Stale ETag committed a root.'
        Assert-PriorUnchanged $prior
        Assert-True (-not $script:LockHeld) 'Failure leaked the publication lease.'
        $script:Blobs = $prior.Clone()
        $script:LockHeld = $true
        $beforeUploads = $script:Uploads.Count
        $failed = $false
        try { & $publish $versions[1].Root } catch { $failed = $true }
        $script:LockHeld = $false
        Assert-True ($failed -and $script:Uploads.Count -eq $beforeUploads) 'Contending publisher staged files.'
        Assert-PriorUnchanged $prior
        if ($mode -ne 'SelfContained') {
            $script:Blobs = $prior.Clone()
            $script:CorruptRead = $true
            $failed = $false
            try { & $publish $versions[1].Root } catch { $failed = $true }
            $script:CorruptRead = $false
            Assert-True $failed 'Hash corruption was accepted.'
            Assert-PriorUnchanged $prior
        }
        $script:Blobs = $prior.Clone()
        $script:Uploads.Clear()
        $script:CommitThenFail = $true
        $failed = $false
        try { & $publish $versions[1].Root } catch { $failed = $_.Exception.Message -like '*DashboardPublicationIndeterminate*' }
        $script:CommitThenFail = $false
        $script:RestoreFails = $false
        Assert-True $failed 'Commit/restore response failures did not report an indeterminate outcome.'
        Assert-True (@($script:Blobs.Keys | Where-Object { $_ -like '_publication/recovery/*.identity.json' }).Count -gt 0) 'Durable recovery identities were deleted.'
        foreach ($name in ($prior.Keys | Where-Object { $_ -like '*.assets/*' })) { Assert-True ($script:Blobs.ContainsKey($name)) 'Uncertain publication deleted old assets.' }
        $script:Blobs = $prior.Clone()
        $script:Uploads.Clear()
        & $publish $versions[1].Root
        foreach ($file in (Get-ChildItem -LiteralPath $versions[1].Root -File -Recurse)) {
            $name = [System.IO.Path]::GetRelativePath($versions[1].Root, $file.FullName).Replace('\', '/')
            Assert-True ((Get-BlobHash $script:Blobs[$name]) -eq (Get-FileHash -LiteralPath $file.FullName).Hash) "Candidate blob mismatch: $name"
        }
        foreach ($name in ($prior.Keys | Where-Object { $_ -like '*.assets/*' })) { Assert-True ((Get-BlobHash $prior[$name]) -eq (Get-BlobHash $script:Blobs[$name])) 'Previous generation was pruned.' }
        if ($mode -eq 'Dual') { Assert-True ($script:Uploads[-1] -eq $Script:HostedDashboardBlobName) 'Hosted commit was not last.' }
        $second = $script:Blobs.Clone()
        $script:FailPrune = $true
        & $publish $versions[2].Root
        $script:FailPrune = $false
        $script:Blobs = $second.Clone()
        & $publish $versions[2].Root
        if ($mode -ne 'SelfContained') {
            Assert-True (@($script:Blobs.Keys | Where-Object { $_ -like "*/generations/$($versions[0].Generation)/*" }).Count -eq 0) 'Old generation was not pruned.'
            Assert-True (@($script:Blobs.Keys | Where-Object { $_ -like "*/generations/$($versions[1].Generation)/*" }).Count -eq 8) 'Previous complete generation was not retained.'
        }
        foreach ($reference in $untouchedReferences) { Assert-True ($script:Blobs.ContainsKey($reference)) 'Untouched compressed root PDF or conservative legacy dependency was pruned.' }
        foreach ($finalStatusUploaded in @($true, $false)) {
            $Script:DashboardPublicationOutcome = 'DashboardPublished'
            $failed = $false
            try { & $statusFailureCheck } catch { $failed = $_.Exception.Message -like '*DashboardPublishedStatusFailed*' }
            Assert-True ($failed -eq (-not $finalStatusUploaded)) 'Final status failure outcome was not explicit.'
            if (-not $finalStatusUploaded) { Assert-True ($Script:DashboardPublicationOutcome -eq 'DashboardPublishedStatusFailed') 'Published status failure was mislabeled.' }
        }
        Write-Output "$mode publication: $uploadCount upload failures, success, readback and retention checks passed."
        Invoke-ServingFixture -FirstRoot $versions[0].Root -NextRoot $versions[1].Root -FixturePath (Join-Path $tempRoot "serving-$mode") -RootName $rootName -Embedded:($mode -eq 'SelfContained')
    }
}
finally {
    Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
    foreach ($name in $servingEnvironment.Keys) { [Environment]::SetEnvironmentVariable($name, $servingEnvironment[$name]) }
}