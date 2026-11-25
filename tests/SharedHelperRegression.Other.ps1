# Shared-helper regression fragment (Other). Dot-sourced by Run-SharedHelperRegression.ps1; not an entrypoint.

function Test-SaveJSLibraryFileRefreshesEmptyCache {
    [CmdletBinding()]
    param()

    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('library-cache-empty-' + [guid]::NewGuid().ToString('N'))
    [void](New-Item -Path $tempRoot -ItemType Directory -Force)
    $outputPath = Join-Path $tempRoot 'library.js'
    $secondOutputPath = Join-Path $tempRoot 'library-second.js'
    $existingInvokeWebRequestFunction = Get-Command -Name Invoke-WebRequest -CommandType Function -ErrorAction SilentlyContinue
    $existingInvokeWebRequestScriptBlock = if ($null -ne $existingInvokeWebRequestFunction) { (Get-Item -Path Function:Invoke-WebRequest).ScriptBlock } else { $null }

    try {
        $script:LibraryCacheRefreshDownloadAttempts = 0
        function Invoke-WebRequest {
            [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidOverwritingBuiltInCmdlets', '', Justification = 'Regression test shim for Save-JSLibraryFile without network access.')]
            param(
                [Parameter(Mandatory = $true)]
                [string]$Uri,

                [Parameter(Mandatory = $true)]
                [string]$OutFile,

                [Parameter(Mandatory = $false)]
                [int]$TimeoutSec
            )

            $null = $Uri
            $null = $TimeoutSec
            $script:LibraryCacheRefreshDownloadAttempts++
            [System.IO.File]::WriteAllText($OutFile, ("download-{0}" -f $script:LibraryCacheRefreshDownloadAttempts), [System.Text.UTF8Encoding]::new($false))
        }

        $null = Save-JSLibraryFile -Url 'https://example.invalid/library.js' -Name 'Test Library' -OutputPath $outputPath -Critical $true -CacheBasePath $tempRoot
        $cacheDirectory = Join-Path $tempRoot '.dashboard-cache\libraries'
        $cacheFile = Get-ChildItem -Path $cacheDirectory -File | Select-Object -First 1
        [System.IO.File]::WriteAllBytes($cacheFile.FullName, [byte[]]@())

        $null = Save-JSLibraryFile -Url 'https://example.invalid/library.js' -Name 'Test Library' -OutputPath $secondOutputPath -Critical $true -CacheBasePath $tempRoot
        $refreshedContent = Get-Content -LiteralPath $secondOutputPath -Raw
        $refreshedCacheLength = (Get-Item -LiteralPath $cacheFile.FullName).Length

        Assert-True ($script:LibraryCacheRefreshDownloadAttempts -eq 2) 'Expected an empty cached JavaScript library to be refreshed instead of reused.'
        Assert-True ($refreshedContent -eq 'download-2') 'Expected refreshed library output to come from the second download attempt.'
        Assert-True ($refreshedCacheLength -gt 0) 'Expected refreshed JavaScript library cache file to be non-empty.'
    }
    finally {
        if ($null -ne $existingInvokeWebRequestScriptBlock) {
            Set-Item -Path Function:Invoke-WebRequest -Value $existingInvokeWebRequestScriptBlock
        }
        else {
            Remove-Item -Path Function:Invoke-WebRequest -Force -ErrorAction SilentlyContinue
        }
        Remove-Variable -Name LibraryCacheRefreshDownloadAttempts -Scope Script -ErrorAction SilentlyContinue

        if (Test-Path -LiteralPath $tempRoot) {
            Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

function Test-LocalExportArtifactCleanup {
    [CmdletBinding()]
    param()

    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('export-artifact-cleanup-' + [guid]::NewGuid().ToString('N'))
    $machineCurrentFileName = Split-Path -Leaf (Get-MachineCurrentPath -BasePath $tempRoot)
    $vulnCurrentFileName = Split-Path -Leaf (Get-VulnCurrentPath -BasePath $tempRoot)
    [void](New-Item -Path $tempRoot -ItemType Directory -Force)

    try {
        foreach ($relativePath in @(
            $machineCurrentFileName,
            $vulnCurrentFileName,
            'synthetic-manifest.json',
            '.dashboard-cache/payloads/payload-old.json.gz',
            '.vuln-content-store-staging-123/VulnCurrentRefs.json.gz',
            '.synthetic-progress.json'
        )) {
            $fullPath = Join-Path $tempRoot $relativePath
            $directory = Split-Path -Path $fullPath -Parent
            if (-not [string]::IsNullOrWhiteSpace($directory)) {
                [void](New-Item -Path $directory -ItemType Directory -Force)
            }
            Set-Content -Path $fullPath -Value '' -Encoding utf8
        }

        Clear-StaleLocalExportArtifact -BasePath $tempRoot -KeepNames @($machineCurrentFileName, $vulnCurrentFileName)

        Assert-True ((Test-Path -LiteralPath (Join-Path $tempRoot $machineCurrentFileName) -PathType Leaf)) 'Expected canonical machine store file to remain after cleanup.'
        Assert-True ((Test-Path -LiteralPath (Join-Path $tempRoot $vulnCurrentFileName) -PathType Leaf)) 'Expected canonical vulnerability store file to remain after cleanup.'
        Assert-True (-not (Test-Path -LiteralPath (Join-Path $tempRoot 'synthetic-manifest.json'))) 'Expected stale synthetic manifest to be removed.'
        Assert-True (-not (Test-Path -LiteralPath (Join-Path $tempRoot '.dashboard-cache'))) 'Expected transient dashboard cache directory to be removed.'
        Assert-True (-not (Test-Path -LiteralPath (Join-Path $tempRoot '.vuln-content-store-staging-123'))) 'Expected transient content-store staging directory to be removed.'
        Assert-True (-not (Test-Path -LiteralPath (Join-Path $tempRoot '.synthetic-progress.json'))) 'Expected transient synthetic progress file to be removed.'
    }
    finally {
        if (Test-Path -LiteralPath $tempRoot) {
            Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

function Test-HttpRetryDelayHelperBehavior {
    [CmdletBinding()]
    param()

    $fixedNow = [datetimeoffset]'2026-01-01T00:00:00Z'
    $retryAfterDate = $fixedNow.AddSeconds(9).ToString('r', [System.Globalization.CultureInfo]::InvariantCulture)

    Assert-True ((Get-HttpRetryDelayOverride -Headers @{ 'Retry-After' = '7' } -ReferenceTime $fixedNow) -eq 7000) 'Expected Retry-After integer seconds to convert to milliseconds.'
    Assert-True ((Get-HttpRetryDelayOverride -Headers @{ 'Retry-After' = $retryAfterDate } -ReferenceTime $fixedNow) -eq 9000) 'Expected Retry-After HTTP-date values to convert to milliseconds.'
    Assert-True ((Get-HttpRetryDelayOverride -Headers @{ 'x-ms-retry-after-ms' = '250' }) -eq 250) 'Expected retry-after-ms headers to convert directly to milliseconds.'
    Assert-True ((Get-HttpRetryDelayOverride -Headers @{ 'Retry-After' = '2147484' } -ReferenceTime $fixedNow) -eq [int]::MaxValue) 'Expected oversized Retry-After second values to clamp to the maximum supported sleep interval.'
    Assert-True ((Get-HttpRetryDelayOverride -Headers @{ 'x-ms-retry-after-ms' = '21474836470' }) -eq [int]::MaxValue) 'Expected oversized retry-after-ms header values to clamp to the maximum supported sleep interval.'
    Assert-True ($null -eq (Get-HttpRetryDelayOverride -Headers @{} -ReferenceTime $fixedNow)) 'Expected the retry delay helper to return no override when no retry headers are present.'
}

function Test-WebRequestWithRetryTransientTransportBehavior {
    [CmdletBinding()]
    param()

    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('webrequest-transient-retry-' + [guid]::NewGuid().ToString('N'))
    [void](New-Item -Path $tempRoot -ItemType Directory -Force)

    try {
        $outputFile = Join-Path $tempRoot 'download.bin'
        $script:TransientWebRequestAttempts = 0
        $script:TransientWebRequestSleeps = [System.Collections.Generic.List[int]]::new()

        Set-Item -Path Function:Invoke-WebRequest -Value {
            param(
                [string]$Uri,
                [string]$Method,
                [hashtable]$Headers,
                [string]$OutFile,
                [string]$InFile,
                [string]$ContentType,
                [int]$TimeoutSec,
                [string]$ErrorAction
            )

            $null = $Uri, $Method, $Headers, $InFile, $ContentType, $TimeoutSec, $ErrorAction

            $script:TransientWebRequestAttempts++
            if ($script:TransientWebRequestAttempts -eq 1) {
                throw [System.Net.WebException]::new('The operation has timed out', [System.Net.WebExceptionStatus]::Timeout)
            }

            [System.IO.File]::WriteAllText($OutFile, 'ok', [System.Text.UTF8Encoding]::new($false))
            return [PSCustomObject]@{ StatusCode = 200 }
        }

        Set-Item -Path Function:Start-Sleep -Value {
            param([int]$Milliseconds)

            $script:TransientWebRequestSleeps.Add($Milliseconds)
        }

        $null = Invoke-WebRequestWithRetry -Uri 'https://example.invalid/blob/data.json.gz?sig=secret' -OutFile $outputFile -MaxRetries 3 -InitialDelayMs 1500 -RetryTransientTransportFailures

        Assert-True ($script:TransientWebRequestAttempts -eq 2) 'Expected transport retries to rerun Invoke-WebRequest after a timeout.'
        Assert-True ($script:TransientWebRequestSleeps.Count -eq 1 -and $script:TransientWebRequestSleeps[0] -eq 1500) 'Expected the first transport retry to use the configured fallback delay.'
        Assert-True ((Test-Path -LiteralPath $outputFile -PathType Leaf)) 'Expected transport retry to eventually materialize the requested download file.'
    }
    finally {
        Remove-Item -Path Function:Invoke-WebRequest -ErrorAction SilentlyContinue
        Remove-Item -Path Function:Start-Sleep -ErrorAction SilentlyContinue
        Remove-Variable -Name TransientWebRequestAttempts -Scope Script -ErrorAction SilentlyContinue
        Remove-Variable -Name TransientWebRequestSleeps -Scope Script -ErrorAction SilentlyContinue

        if (Test-Path -LiteralPath $tempRoot) {
            Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

function Test-WriteBase64FileContentMatchesReferenceOutput {
    [CmdletBinding()]
    param()

    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('base64-writer-regression-' + [guid]::NewGuid().ToString('N'))
    [void](New-Item -Path $tempRoot -ItemType Directory -Force)
    $filePath = Join-Path $tempRoot 'fixture.bin'

    try {
        $bytes = [byte[]]::new(65539)
        for ($index = 0; $index -lt $bytes.Length; $index++) {
            $bytes[$index] = [byte](($index * 17 + 29) % 256)
        }
        [System.IO.File]::WriteAllBytes($filePath, $bytes)

        $singleLineWriter = [System.IO.StringWriter]::new([System.Globalization.CultureInfo]::InvariantCulture)
        try {
            Write-Base64FileContent -Writer $singleLineWriter -FilePath $filePath
            $singleLineActual = $singleLineWriter.ToString()
        }
        finally {
            $singleLineWriter.Dispose()
        }

        $wrappedWriter = [System.IO.StringWriter]::new([System.Globalization.CultureInfo]::InvariantCulture)
        try {
            Write-Base64FileContent -Writer $wrappedWriter -FilePath $filePath -InsertLineBreaks
            $wrappedActual = $wrappedWriter.ToString()
        }
        finally {
            $wrappedWriter.Dispose()
        }

        $singleLineExpected = Get-Base64FileContent -FilePath $filePath
        $wrappedExpected = Get-Base64FileContent -FilePath $filePath -InsertLineBreaks

        Assert-True ($singleLineActual -eq $singleLineExpected) 'Expected streamed base64 writer to match the reference single-line output.'
        Assert-True ($wrappedActual -eq $wrappedExpected) 'Expected streamed base64 writer to match the reference wrapped output.'
    }
    finally {
        if (Test-Path -LiteralPath $tempRoot) {
            Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

function Test-FunctionAppWriteOutputNoEnumeratePreservesJObject {
    [CmdletBinding()]
    param()

    $repoRoot = Split-Path -Path $PSScriptRoot -Parent
    $functionAppPath = Join-Path $repoRoot 'azure\function-app\ExportAndGenerate\run.ps1'
    Assert-True ((Test-Path -LiteralPath $functionAppPath -PathType Leaf)) "Expected generated Function App artifact at '$functionAppPath'."

    $artifactText = Get-Content -LiteralPath $functionAppPath -Raw
    $functionMatch = [regex]::Match($artifactText, '(?s)function Write-Output \{.*?\r?\n\}\r?\n\r?\n\$isPastDue')
    Assert-True ($functionMatch.Success) 'Expected generated Function App artifact to contain the traced Write-Output override.'

    $functionDefinition = $functionMatch.Value -replace '\r?\n\r?\n\$isPastDue\z', ''
    $observed = @(& {
        function Write-PipelineFileTraceLine {
            param($Message)

            $null = $Message
        }

        . ([scriptblock]::Create($functionDefinition))

        $token = [Newtonsoft.Json.Linq.JObject]::Parse('{"ob":true,"id":"device-001"}')
        @(Write-Output -InputObject $token -NoEnumerate)
    })

    Assert-True ($observed.Count -eq 1) 'Expected Function App Write-Output -NoEnumerate to emit exactly one object.'
    Assert-True ($observed[0] -is [Newtonsoft.Json.Linq.JObject]) 'Expected Function App Write-Output -NoEnumerate to preserve JObject identity.'
    Assert-True ((Get-VulnPropertyValue -InputObject $observed[0] -Name 'ob') -eq $true) 'Expected Function App Write-Output -NoEnumerate to preserve compact boolean properties.'
}

function Test-FunctionExecutionInvocationDoesNotReplay {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseApprovedVerbs', '', Justification = 'Local network-free test doubles preserve production call signatures and cannot mutate external state.')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Local network-free test doubles preserve production call signatures and cannot mutate external state.')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '', Justification = 'Local network-free test doubles preserve production call signatures and cannot mutate external state.')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidOverwritingBuiltInCmdlets', '', Justification = 'Local network-free test doubles preserve production call signatures and cannot mutate external state.')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '', Justification = 'Local network-free test doubles preserve production call signatures and cannot mutate external state.')]
    [CmdletBinding()]
    param()
    $path = Join-Path (Split-Path $PSScriptRoot -Parent) 'build/Invoke-AzureDeploymentValidation.ps1'
    $ast = [Management.Automation.Language.Parser]::ParseFile($path, [ref]$null, [ref]$null)
    $node = $ast.Find({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ceq 'Start-FunctionExecution'}, $false)
    . ([scriptblock]::Create($node.Extent.Text))
    $calls = [Collections.Generic.List[string]]::new()
    function Write-ValidationLogLine { param($Message,$ForegroundColor) $calls.Add($Message) }
    function Start-Sleep { param($Seconds) }
    function Wait-FunctionHostReady { param($HostName,$MasterKey,$TimeoutMinutes) }
    function Wait-FunctionAdminFunctionReady { param($HostName,$MasterKey,$TimeoutMinutes) }
    $posts = [ref]0
    function Invoke-FunctionAdminRequest { param($Method,$HostName,$MasterKey,$Path,$Body) $posts.Value++;if($posts.Value -eq 1){throw 'response lost after accepted POST'};[pscustomobject]@{StatusCode=202} }
    $failure=$null
    try { $null=Start-FunctionExecution -HostName 'test.invalid' -MasterKey 'test-only' } catch {$failure=$_}
    Assert-True ($posts.Value -eq 1 -and $null -ne $failure -and $failure.Exception.Message -like '*Reconcile*no retry*') 'Uncertain non-idempotent POST must stop after one attempt, not replay a mutation.'
    $postObserved=[ref]([datetime]::MinValue)
    function Invoke-FunctionAdminRequest { param($Method,$HostName,$MasterKey,$Path,$Body) $posts.Value++;$postObserved.Value=[datetime]::UtcNow;[pscustomobject]@{StatusCode=202} }
    $start=Start-FunctionExecution -HostName 'test.invalid' -MasterKey 'test-only'
    Assert-True ($start -is [datetime] -and $start.Kind -eq [DateTimeKind]::Utc -and $start -le $postObserved.Value) 'Invocation timestamp must be a single real UTC DateTime recorded before POST.'
    Assert-True ($calls[0] -like 'Submitting one Function App invocation at*') 'Invocation intent must be logged before the transport call.'
}

function Test-GetBlobListPagination {
    [CmdletBinding()]
    param()

    $sourcePath = Join-Path (Split-Path $PSScriptRoot -Parent) 'build\azure\runbook-source.ps1'
    $parseTokens = $null
    $parseErrors = $null
    $sourceAst = [System.Management.Automation.Language.Parser]::ParseFile($sourcePath, [ref]$parseTokens, [ref]$parseErrors)
    Assert-True ($parseErrors.Count -eq 0) 'Expected the runbook source to parse.'
    $definition = $sourceAst.Find({ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Get-BlobList' }, $true)
    . ([scriptblock]::Create($definition.Extent.Text))

    function Get-BlobHeader { param($StorageToken) return @{ Authorization = "Bearer $StorageToken" } }
    function Get-BlobErrorStatusCode { param($ErrorRecord) return $ErrorRecord.Exception.PSObject.Properties['StatusCode']?.Value }
    function Invoke-WebRequestWithRetry {
        param($Uri, $Headers, $Method)
        Assert-True ($Method -eq 'Get' -and $Headers.Authorization -eq 'Bearer fixture-token') 'Expected authenticated GET requests.'
        $requests.Add([string]$Uri)
        Assert-True ($pages.Count -gt 0) 'Expected pagination to terminate without an extra request.'
        return [PSCustomObject]@{ Content = $pages.Dequeue() }
    }

    $special = 'history + / ? & ' + [char]0x96EA
    $historyName = 'VulnHistory_2026_Q3.json.gz'
    $cases = @(
        @{ Pages = @('<EnumerationResults><Blobs><Blob><Name>VulnCurrent.json.gz</Name></Blob></Blobs><NextMarker>next</NextMarker></EnumerationResults>', "<EnumerationResults><Blobs><Blob><Name>$historyName</Name></Blob></Blobs><NextMarker /></EnumerationResults>"); Expected = @('VulnCurrent.json.gz', $historyName); Marker = 'next'; Fails = $false }
        @{ Pages = @("<EnumerationResults><Blobs /><NextMarker>$([System.Security.SecurityElement]::Escape($special))</NextMarker></EnumerationResults>", "<EnumerationResults><Blobs><Blob><Name>$historyName</Name></Blob></Blobs></EnumerationResults>"); Expected = @($historyName); Marker = $special; Fails = $false }
        @{ Pages = @('<EnumerationResults><Blobs /><NextMarker /></EnumerationResults>'); Expected = @(); Marker = ''; Fails = $false }
        @{ Pages = @('<EnumerationResults><NextMarker /></EnumerationResults>'); Expected = @(); Marker = ''; Fails = $false }
        @{ Pages = @('<EnumerationResults><Blobs /><NextMarker>same</NextMarker></EnumerationResults>', '<EnumerationResults><Blobs /><NextMarker>same</NextMarker></EnumerationResults>'); Expected = @(); Marker = 'same'; Fails = $true }
        @{ Pages = @('<EnumerationResults><Blobs /><NextMarker>first</NextMarker></EnumerationResults>', '<EnumerationResults><Blobs /><NextMarker>second</NextMarker></EnumerationResults>', '<EnumerationResults><Blobs /><NextMarker>first</NextMarker></EnumerationResults>'); Expected = @(); Marker = 'first'; Fails = $true }
        @{ Pages = @('<EnumerationResults><Blobs /><NextMarker>A</NextMarker></EnumerationResults>', '<EnumerationResults><Blobs /><NextMarker>a</NextMarker></EnumerationResults>', "<EnumerationResults><Blobs><Blob><Name>$historyName</Name></Blob></Blobs><NextMarker /></EnumerationResults>"); Expected = @($historyName); Marker = 'A'; Fails = $false }
    )
    foreach ($case in $cases) {
        $pages = [System.Collections.Generic.Queue[string]]::new()
        foreach ($page in $case.Pages) { $pages.Enqueue($page) }
        $requests = [System.Collections.Generic.List[string]]::new()
        $failure = $null
        $actual = @()
        try { $actual = @(Get-BlobList -AccountName 'fixture' -Container 'exports' -StorageToken 'fixture-token' -Prefix $special) }
        catch { $failure = $_ }
        Assert-True ($requests.Count -eq $case.Pages.Count) 'Expected every continuation page to be requested exactly once.'
        $baseUri = 'https://fixture.blob.core.windows.net/exports?restype=container&comp=list&prefix=' + [System.Uri]::EscapeDataString($special)
        Assert-True ($requests[0] -ceq $baseUri) 'Expected the prefix to be URI encoded without an initial marker.'
        if ($requests.Count -gt 1) {
            Assert-True ($requests[1] -ceq ($baseUri + '&marker=' + [System.Uri]::EscapeDataString($case.Marker))) 'Expected the continuation marker to be URI encoded exactly once.'
        }
        if ($case.Fails) {
            Assert-True ($null -ne $failure -and $failure.Exception.Message -like '*repeated continuation marker*') 'Expected a repeated marker or cycle to fail instead of returning truncated names.'
        }
        else {
            Assert-True ($null -eq $failure) "Expected successful pagination: $failure"
            Assert-True ($actual.Count -eq $case.Expected.Count -and ($actual -join '|') -ceq ($case.Expected -join '|')) 'Expected all names, including second-page history, or an empty result.'
        }
    }
}

function Test-ProgressStallAssessmentDistinguishesSlowAndStalledWork {
    [CmdletBinding()]
    param()

    . (Join-Path $PSScriptRoot 'helpers\TestScriptSupport.ps1')
    $now = [datetime]'2026-07-11T12:00:00Z'
    $healthy = Get-ProgressStallAssessment -LastProgressUtc $now.AddSeconds(-299) -NowUtc $now -WarningSeconds 300 -FailureSeconds 1800
    $warning = Get-ProgressStallAssessment -LastProgressUtc $now.AddSeconds(-301) -NowUtc $now -WarningSeconds 300 -FailureSeconds 1800
    $failed = Get-ProgressStallAssessment -LastProgressUtc $now.AddSeconds(-1801) -NowUtc $now -WarningSeconds 300 -FailureSeconds 1800
    Assert-True ($healthy.State -eq 'Healthy') 'Expected recent slow progress to remain healthy.'
    Assert-True ($warning.State -eq 'Warning') 'Expected a warning after the warning no-progress interval.'
    Assert-True ($failed.State -eq 'Failed') 'Expected a failure after the failure no-progress interval.'

    $repoRoot = Split-Path -Path $PSScriptRoot -Parent
    $runbookSource = Get-Content -LiteralPath (Join-Path $repoRoot 'build\azure\runbook-source.ps1') -Raw
    Assert-True ($runbookSource.Contains("'normalizedPhaseItemCount'")) 'Expected the Azure status callback to persist device/template work heartbeats.'
    Assert-True ($runbookSource.Contains('Read-AdvancedHuntingBundle -Path $tempExports -IncludeDeviceUsers -IncludeInventoryData')) 'Expected Azure normalization to load Advanced Hunting inventory enrichment in the single bundle pass.'
    Assert-True ($runbookSource.Contains('$nvdCveData = Read-NvdCveData -Path $tempExports')) 'Expected Azure normalization to load NVD enrichment.'
    Assert-True ($runbookSource.Contains('-AdvancedHuntingInventoryData $advancedHuntingInventoryData -NvdCveData $nvdCveData')) 'Expected Azure normalization to preserve all source enrichment inputs.'
}

function Test-FullGarbageCollectionRequestsLargeObjectHeapCompaction {
    [CmdletBinding()]
    param()

    $buffer = [byte[]]::new(100000)
    [System.GC]::KeepAlive($buffer)
    $buffer = $null
    Invoke-FullGarbageCollection
    Assert-True ([System.Runtime.GCSettings]::LargeObjectHeapCompactionMode -eq [System.Runtime.GCLargeObjectHeapCompactionMode]::Default) 'Expected the one-shot large-object heap compaction request to be consumed by full collection.'
}

function Test-CompiledContentStringArrayRoundTrip {
    [CmdletBinding()]
    param()
    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('compiled-string-arrays-' + [guid]::NewGuid().ToString('N'))
    try {
        [void](New-Item -Path $tempRoot -ItemType Directory -Force)
        $cases = @(
            @{ Value = ' synthetic scalar '; Expected = @(' synthetic scalar ') }
            @{ Value = @('first', $null, '', ' ', ('Unicode-' + [char]0x6D4B + [char]0x8BD5), 'first'); Expected = @('first', '', ' ', ('Unicode-' + [char]0x6D4B + [char]0x8BD5), 'first') }
            @{ Value = @(); Expected = @() }
            @{ Value = $null; Expected = @() }
            @{ Value = ''; Expected = @() }
            @{ Value = '  '; Expected = @() }
            @{ Missing = $true; Expected = @() }
        )
        $rows = for ($i = 0; $i -lt $cases.Count; $i++) {
            $row = Get-TestVulnRow -Id "string-array-$i" -CveId "CVE-2026-$i" -SnapshotDate '2026-07-10' -Version '1.0'
            $row.DeviceId = "synthetic-device-$i"
            foreach ($field in @('MachineTags', 'DiskPaths', 'RegistryPaths')) {
                if ($cases[$i].ContainsKey('Missing')) { $row.PSObject.Properties.Remove($field) }
                else { $row.$field = $cases[$i].Value }
            }
            $row
        }
        $inputPath = Join-Path $tempRoot 'rows.ndjson.gz'
        $refPath = Join-Path $tempRoot 'refs.ndjson.gz'
        $dictionaryPath = Join-Path $tempRoot 'dictionary.json.gz'
        Write-NdjsonRecordsFile -Path $inputPath -Records $rows
        Initialize-CompiledVulnContentProjector
        $count = [DefenderReporting.Store.VulnContentProjector]::Project(@($inputPath), @($refPath), $dictionaryPath)
        $dictionary = Read-VulnContentDictionary -Path $dictionaryPath
        $expanded = @(Read-VulnContentRefRows -DictionaryPath $dictionaryPath -RefPaths @($refPath))
        Assert-True ($count -eq $cases.Count -and $expanded.Count -eq $cases.Count) 'Expected every synthetic row to survive projection and expansion.'
        for ($i = 0; $i -lt $cases.Count; $i++) {
            foreach ($entry in @(
                @{ Actual = $dictionary.deviceProfiles[$i].t; Field = 'MachineTags' }
                @{ Actual = $dictionary.contentTemplates[$i].dp; Field = 'DiskPaths' }
                @{ Actual = $dictionary.contentTemplates[$i].rp; Field = 'RegistryPaths' }
            )) {
                $actual = ConvertTo-Json -InputObject @($entry.Actual) -Compress
                $expected = ConvertTo-Json -InputObject @($cases[$i].Expected) -Compress
                Assert-True ($actual -ceq $expected) "Expected dictionary case $i field $($entry.Field) to preserve array contents."
            }
            foreach ($field in @('MachineTags', 'DiskPaths', 'RegistryPaths')) {
                $actual = ConvertTo-Json -InputObject @($expanded[$i].$field) -Compress
                $expected = ConvertTo-Json -InputObject @($cases[$i].Expected | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }) -Compress
                Assert-True ($actual -ceq $expected) "Expected case $i field $field to round-trip: $expected; got $actual."
            }
        }
    }
    finally {
        if (Test-Path -LiteralPath $tempRoot) { Remove-Item -LiteralPath $tempRoot -Recurse -Force }
    }
}
