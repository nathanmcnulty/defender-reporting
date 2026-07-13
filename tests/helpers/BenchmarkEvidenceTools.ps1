# Versioned benchmark evidence shared by local and Azure benchmark entrypoints.

$script:BenchmarkEvidenceSchemaVersion = 1

function Get-BenchmarkGitEvidence {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param([Parameter(Mandatory = $true)][string]$RepoPath)

    $resolvedRepoPath = [System.IO.Path]::GetFullPath($RepoPath)
    $commit = (& git -C $resolvedRepoPath rev-parse HEAD 2>$null | Select-Object -First 1)
    $branch = (& git -C $resolvedRepoPath branch --show-current 2>$null | Select-Object -First 1)
    $status = @(& git -C $resolvedRepoPath status --porcelain=v1 --untracked-files=all 2>$null)
    return [PSCustomObject]@{
        repo_path = $resolvedRepoPath
        commit = [string]$commit
        branch = [string]$branch
        dirty = ($status.Count -gt 0)
        status = @($status)
    }
}

function Get-BenchmarkArtifactFingerprintEvidence {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param([Parameter(Mandatory = $true)][string]$RepoPath)

    $runbookPath = Join-Path $RepoPath 'azure\Invoke-DashboardPipeline.ps1'
    $functionPath = Join-Path $RepoPath 'azure\function-app\ExportAndGenerate\run.ps1'
    $readFingerprint = {
        param($Path)
        if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return $null }
        $match = [regex]::Match((Get-Content -LiteralPath $Path -Raw), '(?m)^# ArtifactFingerprint:\s*([0-9a-f]{64})\s*$')
        if ($match.Success) { return $match.Groups[1].Value }
        return $null
    }
    return [PSCustomObject]@{
        runbook = & $readFingerprint $runbookPath
        function_app = & $readFingerprint $functionPath
    }
}

function Get-BenchmarkDatasetEvidence {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param([Parameter(Mandatory = $true)][string]$DatasetPath)

    $resolvedPath = [System.IO.Path]::GetFullPath($DatasetPath)
    $manifestPath = Join-Path $resolvedPath 'synthetic-manifest.json'
    $benchmarkMetadataPath = Join-Path $resolvedPath 'benchmark-dataset.json'
    $files = @(
        Get-ChildItem -LiteralPath $resolvedPath -File -ErrorAction Stop | Sort-Object Name | ForEach-Object {
            [PSCustomObject]@{
                name = $_.Name
                bytes = [int64]$_.Length
                sha256 = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
            }
        }
    )
    return [PSCustomObject]@{
        path = $resolvedPath
        identity = if (Test-Path -LiteralPath $benchmarkMetadataPath -PathType Leaf) { Get-Content -LiteralPath $benchmarkMetadataPath -Raw | ConvertFrom-Json -Depth 30 } else { $null }
        manifest = if (Test-Path -LiteralPath $manifestPath -PathType Leaf) { Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json -Depth 30 } else { $null }
        files = $files
        total_bytes = [int64](($files | Measure-Object -Property bytes -Sum).Sum)
    }
}

function Get-BenchmarkEvidenceEnvelope {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory = $true)][string]$Kind,
        [Parameter(Mandatory = $true)][string]$RepoPath,
        [Parameter(Mandatory = $false)][AllowNull()]$Dataset,
        [Parameter(Mandatory = $false)][AllowNull()]$Environment,
        [Parameter(Mandatory = $false)][AllowNull()]$Execution,
        [Parameter(Mandatory = $false)][AllowNull()]$Validation
    )

    return [PSCustomObject]@{
        evidence_schema_version = $script:BenchmarkEvidenceSchemaVersion
        kind = $Kind
        generated_utc = [datetime]::UtcNow.ToString('o')
        git = Get-BenchmarkGitEvidence -RepoPath $RepoPath
        artifacts = Get-BenchmarkArtifactFingerprintEvidence -RepoPath $RepoPath
        dataset = $Dataset
        environment = $Environment
        execution = $Execution
        validation = $Validation
    }
}

function Write-BenchmarkEvidenceEnvelope {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)]$Evidence
    )

    $resolvedPath = [System.IO.Path]::GetFullPath($Path)
    $parent = Split-Path -Path $resolvedPath -Parent
    [void](New-Item -Path $parent -ItemType Directory -Force)
    $stagePath = $resolvedPath + '.tmp-' + [guid]::NewGuid().ToString('N')
    try {
        [System.IO.File]::WriteAllText($stagePath, ($Evidence | ConvertTo-Json -Depth 50), [System.Text.UTF8Encoding]::new($false))
        Move-Item -LiteralPath $stagePath -Destination $resolvedPath -Force
    }
    finally {
        if (Test-Path -LiteralPath $stagePath -PathType Leaf) { Remove-Item -LiteralPath $stagePath -Force -ErrorAction SilentlyContinue }
    }
}

function Assert-AzureDashboardCandidateEvidence {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory = $true)][string]$DashboardRootPath,
        [Parameter(Mandatory = $true)]$RunbookStatus,
        [Parameter(Mandatory = $true)][ValidateSet('SelfContained', 'Hosted', 'Dual')][string]$DashboardDeliveryMode,
        [Parameter(Mandatory = $true)][ValidateRange(1, 50000000)][int]$ExpectedTotalRows,
        [Parameter(Mandatory = $false)][scriptblock]$PayloadRowCounter
    )

    if ([string]$RunbookStatus.status -ne 'succeeded' -or [string]$RunbookStatus.stage -ne 'Completed') {
        throw "Runbook status evidence is not a succeeded Completed document."
    }
    if ([int64]$RunbookStatus.vulnerabilities -ne $ExpectedTotalRows) {
        throw "Runbook status reported $($RunbookStatus.vulnerabilities) vulnerabilities; expected $ExpectedTotalRows."
    }
    foreach ($countName in @('devices', 'cves')) {
        if (-not $RunbookStatus.PSObject.Properties[$countName] -or [int]$RunbookStatus.$countName -le 0) {
            throw "Runbook status is missing a positive '$countName' count."
        }
    }

    $dashboardBlobName = [string]$RunbookStatus.dashboardBlobName
    if ([string]::IsNullOrWhiteSpace($dashboardBlobName)) { throw 'Runbook status is missing dashboardBlobName.' }
    $dashboardPath = Join-Path $DashboardRootPath ($dashboardBlobName -replace '/', [System.IO.Path]::DirectorySeparatorChar)
    if (-not (Test-Path -LiteralPath $dashboardPath -PathType Leaf)) { throw "Published dashboard '$dashboardBlobName' is missing." }

    $result = [ordered]@{
        dashboard_blob_name = $dashboardBlobName
        dashboard_sha256 = (Get-FileHash -LiteralPath $dashboardPath -Algorithm SHA256).Hash.ToLowerInvariant()
        dashboard_bytes = [int64](Get-Item -LiteralPath $dashboardPath).Length
        vulnerabilities = [int64]$RunbookStatus.vulnerabilities
        devices = [int]$RunbookStatus.devices
        cves = [int]$RunbookStatus.cves
        hosted_assets_validated = $false
    }

    if ($DashboardDeliveryMode -in @('Hosted', 'Dual')) {
        $hostedBlobName = if ($DashboardDeliveryMode -eq 'Dual') { [string]$RunbookStatus.hostedDashboardBlobName } else { $dashboardBlobName }
        if ([string]::IsNullOrWhiteSpace($hostedBlobName)) { throw 'Runbook status is missing the hosted dashboard blob name.' }
        $hostedPath = Join-Path $DashboardRootPath ($hostedBlobName -replace '/', [System.IO.Path]::DirectorySeparatorChar)
        if (-not (Test-Path -LiteralPath $hostedPath -PathType Leaf)) { throw "Published hosted dashboard '$hostedBlobName' is missing." }
        $assetDirectoryName = [System.IO.Path]::GetFileNameWithoutExtension($hostedBlobName) + '.assets'
        $assetRoot = Join-Path $DashboardRootPath $assetDirectoryName
        $requiredAssets = @(
            'runtime/dashboard.css', 'runtime/dashboard.js', 'runtime/pako.js', 'vendor/chart.js',
            'data/summary.json', 'data/payload.json.gz', 'optional/pdf-export.bundle.js'
        )
        foreach ($relativeAssetPath in $requiredAssets) {
            $assetPath = Join-Path $assetRoot ($relativeAssetPath -replace '/', [System.IO.Path]::DirectorySeparatorChar)
            if (-not (Test-Path -LiteralPath $assetPath -PathType Leaf)) { throw "Published hosted dashboard asset '$assetDirectoryName/$relativeAssetPath' is missing." }
        }

        $payloadPath = Join-Path $assetRoot 'data\payload.json.gz'
        $summaryPath = Join-Path $assetRoot 'data\summary.json'
        $summary = Get-Content -LiteralPath $summaryPath -Raw | ConvertFrom-Json -Depth 30
        $payloadSha256 = (Get-FileHash -LiteralPath $payloadPath -Algorithm SHA256).Hash.ToLowerInvariant()
        if ([string]$summary.meta.payloadSha256 -ne $payloadSha256) { throw 'Hosted payload SHA-256 does not match summary metadata.' }
        foreach ($countName in @('vulnCount', 'deviceCount', 'cveCount')) {
            if (-not $summary.meta.PSObject.Properties[$countName]) { throw "Hosted summary metadata is missing '$countName'." }
        }
        if ([int64]$summary.meta.vulnCount -ne $ExpectedTotalRows) { throw 'Hosted summary vulnerability count does not match the expected row count.' }
        if ([int]$summary.meta.deviceCount -ne [int]$RunbookStatus.devices -or [int]$summary.meta.cveCount -ne [int]$RunbookStatus.cves) {
            throw 'Hosted summary device/CVE counts do not match runbook status.'
        }
        if ($null -ne $PayloadRowCounter) {
            $payloadRowCount = [int64](& $PayloadRowCounter $payloadPath)
            if ($payloadRowCount -ne $ExpectedTotalRows) { throw "Published payload contains $payloadRowCount rows; expected $ExpectedTotalRows." }
            $result['payload_row_count'] = $payloadRowCount
        }
        $hostedHtml = Get-Content -LiteralPath $hostedPath -Raw
        foreach ($relativeAssetPath in @('data/payload.json.gz', 'data/summary.json', 'runtime/dashboard.js')) {
            if (-not $hostedHtml.Contains("$assetDirectoryName/$relativeAssetPath")) { throw "Hosted dashboard HTML does not reference '$relativeAssetPath'." }
        }
        $result['hosted_blob_name'] = $hostedBlobName
        $result['payload_sha256'] = $payloadSha256
        $result['payload_bytes'] = [int64](Get-Item -LiteralPath $payloadPath).Length
        $result['summary_sha256'] = (Get-FileHash -LiteralPath $summaryPath -Algorithm SHA256).Hash.ToLowerInvariant()
        $result['hosted_assets_validated'] = $true
    }

    return [PSCustomObject]$result
}

function Get-GzipDecompressedContentEvidence {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param([Parameter(Mandatory = $true)][string]$Path)

    $file = $null
    $gzip = $null
    $hash = $null
    try {
        $file = [System.IO.File]::OpenRead($Path)
        $gzip = [System.IO.Compression.GZipStream]::new($file, [System.IO.Compression.CompressionMode]::Decompress)
        $hash = [System.Security.Cryptography.IncrementalHash]::CreateHash([System.Security.Cryptography.HashAlgorithmName]::SHA256)
        $buffer = [byte[]]::new(65536)
        $totalBytes = 0L
        while (($read = $gzip.Read($buffer, 0, $buffer.Length)) -gt 0) {
            $hash.AppendData($buffer, 0, $read)
            $totalBytes += $read
        }
        return [PSCustomObject]@{
            path = [System.IO.Path]::GetFullPath($Path)
            decompressed_bytes = $totalBytes
            decompressed_sha256 = [Convert]::ToHexString($hash.GetHashAndReset()).ToLowerInvariant()
        }
    }
    finally {
        if ($hash) { $hash.Dispose() }
        if ($gzip) { $gzip.Dispose() }
        if ($file) { $file.Dispose() }
    }
}
