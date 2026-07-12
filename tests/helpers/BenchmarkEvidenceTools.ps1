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
