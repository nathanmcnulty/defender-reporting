# Shared-helper regression fragment (Artifact). Dot-sourced by Run-SharedHelperRegression.ps1; not an entrypoint.

function Test-ArtifactManifestRejectsOutputInsideSourceRoot {
    [CmdletBinding()]
    param()

    $repoRoot = Split-Path -Path $PSScriptRoot -Parent
    $artifactManifestToolsPath = Join-Path $repoRoot 'build\private\ArtifactManifestTools.ps1'
    Assert-True ((Test-Path -LiteralPath $artifactManifestToolsPath -PathType Leaf)) "Expected artifact manifest helper script at '$artifactManifestToolsPath'."

    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('artifact-manifest-output-root-' + [guid]::NewGuid().ToString('N'))
    try {
        [void](New-Item -Path (Join-Path $tempRoot 'src\powershell\Shared') -ItemType Directory -Force)
        [void](New-Item -Path (Join-Path $tempRoot 'build\manifests') -ItemType Directory -Force)
        Set-Content -LiteralPath (Join-Path $tempRoot 'src\powershell\Shared\Core.ps1') -Value 'function Invoke-TestManifestHelper { }' -Encoding utf8

        $manifestPath = Join-Path $tempRoot 'build\manifests\artifact-test.json'
        $manifest = [ordered]@{
            artifactName = 'artifact-test'
            outputPath = 'src/powershell/Shared/generated-helper.ps1'
            sourceRoots = @('src/powershell/Shared')
            sourceFiles = @('src/powershell/Shared/Core.ps1')
        }
        $manifest | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $manifestPath -Encoding utf8

        $failure = $null
        try {
            . $artifactManifestToolsPath
            $null = Read-PowerShellArtifactManifest -ManifestPath $manifestPath -RepoRoot $tempRoot
        }
        catch {
            $failure = $_
        }

        Assert-True ($null -ne $failure) 'Expected manifest validation to reject generated outputs under a tracked sourceRoot.'
        Assert-True (($failure.Exception.Message -like '*inside sourceRoot*') -or ($failure.Exception.Message -like '*Generated outputs must stay outside tracked source roots*')) 'Expected manifest validation failure to explain that generated outputs must stay outside sourceRoots.'
    }
    finally {
        if (Test-Path -LiteralPath $tempRoot) {
            Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

function Test-ArtifactManifestRejectsSourceRootOverlap {
    [CmdletBinding()]
    param()

    $repoRoot = Split-Path -Path $PSScriptRoot -Parent
    $artifactManifestToolsPath = Join-Path $repoRoot 'build\private\ArtifactManifestTools.ps1'
    Assert-True ((Test-Path -LiteralPath $artifactManifestToolsPath -PathType Leaf)) "Expected artifact manifest helper script at '$artifactManifestToolsPath'."

    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('artifact-manifest-overlap-' + [guid]::NewGuid().ToString('N'))
    try {
        [void](New-Item -Path (Join-Path $tempRoot 'src\powershell\Shared\Nested') -ItemType Directory -Force)
        [void](New-Item -Path (Join-Path $tempRoot 'build\manifests') -ItemType Directory -Force)
        Set-Content -LiteralPath (Join-Path $tempRoot 'src\powershell\Shared\Nested\Helper.ps1') -Value 'function Invoke-TestNestedManifestHelper { }' -Encoding utf8

        $manifestPath = Join-Path $tempRoot 'build\manifests\artifact-test.json'
        $manifest = [ordered]@{
            artifactName = 'artifact-test'
            outputPath = 'build/generated/shared-helper.ps1'
            sourceRoots = @(
                'src/powershell/Shared'
                'src/powershell/Shared/Nested'
            )
            sourceFiles = @('src/powershell/Shared/Nested/Helper.ps1')
        }
        $manifest | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $manifestPath -Encoding utf8

        $failure = $null
        try {
            . $artifactManifestToolsPath
            $null = Read-PowerShellArtifactManifest -ManifestPath $manifestPath -RepoRoot $tempRoot
        }
        catch {
            $failure = $_
        }

        Assert-True ($null -ne $failure) 'Expected manifest validation to reject overlapping sourceRoots.'
        Assert-True ($failure.Exception.Message -like '*overlapping sourceRoots*') 'Expected manifest validation failure to call out overlapping sourceRoots.'
    }
    finally {
        if (Test-Path -LiteralPath $tempRoot) {
            Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

function Test-ArtifactManifestRejectsSourceFileOutsideSourceRoot {
    [CmdletBinding()]
    param()

    $repoRoot = Split-Path -Path $PSScriptRoot -Parent
    $artifactManifestToolsPath = Join-Path $repoRoot 'build\private\ArtifactManifestTools.ps1'
    Assert-True ((Test-Path -LiteralPath $artifactManifestToolsPath -PathType Leaf)) "Expected artifact manifest helper script at '$artifactManifestToolsPath'."

    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('artifact-manifest-outside-root-' + [guid]::NewGuid().ToString('N'))
    try {
        [void](New-Item -Path (Join-Path $tempRoot 'src\powershell\Shared') -ItemType Directory -Force)
        [void](New-Item -Path (Join-Path $tempRoot 'src\powershell\Validation') -ItemType Directory -Force)
        [void](New-Item -Path (Join-Path $tempRoot 'build\manifests') -ItemType Directory -Force)
        Set-Content -LiteralPath (Join-Path $tempRoot 'src\powershell\Validation\ValidationHelper.ps1') -Value 'function Invoke-TestValidationHelper { }' -Encoding utf8

        $manifestPath = Join-Path $tempRoot 'build\manifests\artifact-test.json'
        $manifest = [ordered]@{
            artifactName = 'artifact-test'
            outputPath = 'build/generated/shared-helper.ps1'
            sourceRoots = @('src/powershell/Shared')
            sourceFiles = @('src/powershell/Validation/ValidationHelper.ps1')
        }
        $manifest | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $manifestPath -Encoding utf8

        $failure = $null
        try {
            . $artifactManifestToolsPath
            $null = Read-PowerShellArtifactManifest -ManifestPath $manifestPath -RepoRoot $tempRoot
        }
        catch {
            $failure = $_
        }

        Assert-True ($null -ne $failure) 'Expected manifest validation to reject source files outside the declared sourceRoots.'
        Assert-True ($failure.Exception.Message -like '*outside the declared sourceRoots*') 'Expected manifest validation failure to explain the source-file boundary violation.'
    }
    finally {
        if (Test-Path -LiteralPath $tempRoot) {
            Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

function Test-ArtifactManifestRejectsCrossArtifactSourceConflict {
    [CmdletBinding()]
    param()

    $repoRoot = Split-Path -Path $PSScriptRoot -Parent
    $artifactManifestToolsPath = Join-Path $repoRoot 'build\private\ArtifactManifestTools.ps1'
    Assert-True ((Test-Path -LiteralPath $artifactManifestToolsPath -PathType Leaf)) "Expected artifact manifest helper script at '$artifactManifestToolsPath'."

    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('artifact-manifest-conflict-' + [guid]::NewGuid().ToString('N'))
    try {
        [void](New-Item -Path (Join-Path $tempRoot 'src\powershell\Shared') -ItemType Directory -Force)
        [void](New-Item -Path (Join-Path $tempRoot 'build\manifests') -ItemType Directory -Force)
        Set-Content -LiteralPath (Join-Path $tempRoot 'src\powershell\Shared\SharedHelper.ps1') -Value 'function Invoke-TestConflictHelper { }' -Encoding utf8

        $sharedManifestPath = Join-Path $tempRoot 'build\manifests\shared.json'
        $validationManifestPath = Join-Path $tempRoot 'build\manifests\validation.json'
        [ordered]@{
            artifactName = 'shared-helpers'
            outputPath = 'build/generated/shared-helper.ps1'
            sourceRoots = @('src/powershell/Shared')
            sourceFiles = @('src/powershell/Shared/SharedHelper.ps1')
        } | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $sharedManifestPath -Encoding utf8
        [ordered]@{
            artifactName = 'validation-helpers'
            outputPath = 'build/generated/validation-helper.ps1'
            sourceRoots = @('src/powershell/Shared')
            sourceFiles = @('src/powershell/Shared/SharedHelper.ps1')
        } | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $validationManifestPath -Encoding utf8

        $failure = $null
        try {
            . $artifactManifestToolsPath
            $null = Test-PowerShellArtifactManifestConflict -ManifestPaths @($sharedManifestPath, $validationManifestPath) -RepoRoot $tempRoot
        }
        catch {
            $failure = $_
        }

        Assert-True ($null -ne $failure) 'Expected manifest conflict validation to reject shared source file ownership across artifacts.'
        Assert-True (-not [string]::IsNullOrWhiteSpace([string]$failure.Exception.Message)) 'Expected manifest conflict validation failure to produce a useful error message.'
    }
    finally {
        if (Test-Path -LiteralPath $tempRoot) {
            Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

function Test-ArtifactManifestUsesContentFingerprint {
    [CmdletBinding()]
    param()

    $repoRoot = Split-Path -Path $PSScriptRoot -Parent
    $artifactManifestToolsPath = Join-Path $repoRoot 'build\private\ArtifactManifestTools.ps1'
    Assert-True ((Test-Path -LiteralPath $artifactManifestToolsPath -PathType Leaf)) "Expected artifact manifest helper script at '$artifactManifestToolsPath'."

    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('artifact-manifest-fingerprint-' + [guid]::NewGuid().ToString('N'))
    try {
        [void](New-Item -Path (Join-Path $tempRoot 'src\powershell\Shared') -ItemType Directory -Force)
        [void](New-Item -Path (Join-Path $tempRoot 'build\generated') -ItemType Directory -Force)
        [void](New-Item -Path (Join-Path $tempRoot 'build\manifests') -ItemType Directory -Force)

        $sourcePath = Join-Path $tempRoot 'src\powershell\Shared\Helper.ps1'
        $buildScriptPath = Join-Path $tempRoot 'build\Build-TestArtifact.ps1'
        $manifestPath = Join-Path $tempRoot 'build\manifests\artifact-test.json'

        Set-Content -LiteralPath $sourcePath -Value 'function Invoke-TestArtifactHelper { "alpha" }' -Encoding utf8
        Set-Content -LiteralPath $buildScriptPath -Value '# synthetic build script for fingerprint coverage' -Encoding utf8
        [ordered]@{
            artifactName = 'artifact-test'
            description = 'Synthetic manifest for fingerprint coverage.'
            outputPath = 'build/generated/artifact-test.ps1'
            sourceRoots = @('src/powershell/Shared')
            sourceFiles = @('src/powershell/Shared/Helper.ps1')
        } | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $manifestPath -Encoding utf8

        . $artifactManifestToolsPath
        $artifactManifest = Build-PowerShellArtifactFromManifest -ManifestPath $manifestPath -RepoRoot $tempRoot -BuildScriptPath $buildScriptPath
        Assert-True ((Test-PowerShellArtifactRequiresBuild -ManifestPath $manifestPath -RepoRoot $tempRoot -BuildScriptPath $buildScriptPath) -eq $false) 'Expected freshly generated artifact to satisfy the current content fingerprint.'

        $outputWriteTime = (Get-Item -LiteralPath $artifactManifest.OutputPath).LastWriteTimeUtc
        Set-Content -LiteralPath $sourcePath -Value 'function Invoke-TestArtifactHelper { "beta" }' -Encoding utf8
        (Get-Item -LiteralPath $sourcePath).LastWriteTimeUtc = $outputWriteTime.AddSeconds(-5)
        (Get-Item -LiteralPath $buildScriptPath).LastWriteTimeUtc = $outputWriteTime.AddSeconds(-10)
        (Get-Item -LiteralPath $manifestPath).LastWriteTimeUtc = $outputWriteTime.AddSeconds(-10)

        Assert-True (Test-PowerShellArtifactRequiresBuild -ManifestPath $manifestPath -RepoRoot $tempRoot -BuildScriptPath $buildScriptPath) 'Expected content changes with older timestamps to invalidate the generated artifact fingerprint.'
    }
    finally {
        if (Test-Path -LiteralPath $tempRoot) {
            Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

function Test-ArtifactManifestRejectsGeneratedOutputWithoutFingerprint {
    [CmdletBinding()]
    param()

    $repoRoot = Split-Path -Path $PSScriptRoot -Parent
    $artifactManifestToolsPath = Join-Path $repoRoot 'build\private\ArtifactManifestTools.ps1'
    Assert-True ((Test-Path -LiteralPath $artifactManifestToolsPath -PathType Leaf)) "Expected artifact manifest helper script at '$artifactManifestToolsPath'."

    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('artifact-manifest-fingerprint-missing-' + [guid]::NewGuid().ToString('N'))
    try {
        [void](New-Item -Path (Join-Path $tempRoot 'src\powershell\Shared') -ItemType Directory -Force)
        [void](New-Item -Path (Join-Path $tempRoot 'build\generated') -ItemType Directory -Force)
        [void](New-Item -Path (Join-Path $tempRoot 'build\manifests') -ItemType Directory -Force)

        $sourcePath = Join-Path $tempRoot 'src\powershell\Shared\Helper.ps1'
        $buildScriptPath = Join-Path $tempRoot 'build\Build-TestArtifact.ps1'
        $manifestPath = Join-Path $tempRoot 'build\manifests\artifact-test.json'
        $outputPath = Join-Path $tempRoot 'build\generated\artifact-test.ps1'

        Set-Content -LiteralPath $sourcePath -Value 'function Invoke-TestArtifactHelper { "alpha" }' -Encoding utf8
        [ordered]@{
            artifactName = 'artifact-test'
            description = 'Synthetic manifest for fingerprint metadata coverage.'
            outputPath = 'build/generated/artifact-test.ps1'
            sourceRoots = @('src/powershell/Shared')
            sourceFiles = @('src/powershell/Shared/Helper.ps1')
        } | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $manifestPath -Encoding utf8

        $buildScriptContent = @"
[System.IO.File]::WriteAllText('$($outputPath.Replace('\', '\\'))', 'function Invoke-TestArtifactHelper { "from-build" }', [System.Text.UTF8Encoding]::new(`$true))
"@
        Set-Content -LiteralPath $buildScriptPath -Value $buildScriptContent -Encoding utf8

        . $artifactManifestToolsPath
        $failure = $null
        try {
            $null = Resolve-PowerShellArtifactOutputPath -ManifestPath $manifestPath -RepoRoot $tempRoot -BuildScriptPath $buildScriptPath
        }
        catch {
            $failure = $_
        }

        Assert-True ($null -ne $failure) 'Expected artifact resolution to reject generated outputs without embedded fingerprint metadata.'
        Assert-True ($failure.Exception.Message -like '*missing fingerprint metadata*') 'Expected artifact resolution failure to mention missing fingerprint metadata.'
    }
    finally {
        if (Test-Path -LiteralPath $tempRoot) {
            Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

function Test-CanonicalLayoutHelper {
    [CmdletBinding()]
    param()

    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('layout-helper-test-' + [guid]::NewGuid().ToString('N'))
    $advancedHuntingCurrentFileName = Split-Path -Leaf (Get-AdvancedHuntingCurrentPath -BasePath $tempRoot)
    $machineCurrentFileName = Split-Path -Leaf (Get-MachineCurrentPath -BasePath $tempRoot)
    $vulnCurrentFileName = Split-Path -Leaf (Get-VulnCurrentPath -BasePath $tempRoot)
    [void](New-Item -Path $tempRoot -ItemType Directory -Force)

    try {
        foreach ($name in @(
            $advancedHuntingCurrentFileName,
            $machineCurrentFileName,
            'Machines_History_2026Q1.json.gz',
            $vulnCurrentFileName,
            'VulnHistory_2026Q1.json.gz',
            'VulnHistoryRows_2026Q1.json.gz'
        )) {
            Set-Content -Path (Join-Path $tempRoot $name) -Value '' -Encoding utf8
        }

        $canonicalLocalNames = @(Get-CanonicalExportStoreFileNames -BasePath $tempRoot)
        Assert-True ($canonicalLocalNames.Count -eq 6) 'Expected six canonical local store files.'

        $existingNames = @(
            $canonicalLocalNames +
            @(
                'Machines_History_20260301T010101Z_deadbeef.json.gz',
                'VulnHistory_2026.json.gz',
                'VulnHistoryRows_2026.json.gz',
                '.dashboard-cache/payloads/payload-old.json.gz',
                'synthetic-manifest.json'
            )
        )
        $staleNames = @(Get-StaleExportStoreArtifactNames -ExistingNames $existingNames -CanonicalNames $canonicalLocalNames)

        Assert-True ('Machines_History_20260301T010101Z_deadbeef.json.gz' -in $staleNames) 'Expected stale machine segment to be removable.'
        Assert-True ('VulnHistory_2026.json.gz' -in $staleNames) 'Expected stale yearly vuln history file to be removable.'
        Assert-True ('VulnHistoryRows_2026.json.gz' -in $staleNames) 'Expected stale yearly vuln history rows file to be removable.'
        Assert-True ('.dashboard-cache/payloads/payload-old.json.gz' -in $staleNames) 'Expected transient dashboard cache artifacts to be removable.'
        Assert-True ('synthetic-manifest.json' -in $staleNames) 'Expected synthetic manifest to be removable when it is no longer part of the desired export set.'
        Assert-True ((Get-QuarterPeriodKeyFromDate -Date '2026-02-15') -eq '2026Q1') 'Quarter helper returned an unexpected value.'
        Assert-True ((Convert-ToYmdDate -DateValue '2/15/2026') -eq '2026-02-15') 'Date normalization returned an unexpected value.'
    }
    finally {
        if (Test-Path -LiteralPath $tempRoot) {
            Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

function Test-FileSetFingerprintIgnoresTimestampChange {
    [CmdletBinding()]
    param()

    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('file-fingerprint-stability-' + [guid]::NewGuid().ToString('N'))
    [void](New-Item -Path $tempRoot -ItemType Directory -Force)

    try {
        $filePath = Join-Path $tempRoot 'source.json.gz'
        Set-Content -LiteralPath $filePath -Value 'alpha' -NoNewline -Encoding utf8

        $initialFingerprint = Get-FileSetFingerprint -Version 'test-cache-v1' -Files @((Get-Item -LiteralPath $filePath))
        [System.IO.File]::SetLastWriteTimeUtc($filePath, ([datetime]::UtcNow.AddDays(-7)))
        $timestampOnlyFingerprint = Get-FileSetFingerprint -Version 'test-cache-v1' -Files @((Get-Item -LiteralPath $filePath))

        Set-Content -LiteralPath $filePath -Value 'bravo' -NoNewline -Encoding utf8
        $contentChangedFingerprint = Get-FileSetFingerprint -Version 'test-cache-v1' -Files @((Get-Item -LiteralPath $filePath))

        Assert-True ($initialFingerprint -eq $timestampOnlyFingerprint) 'Expected file-set fingerprints to ignore timestamp-only changes when content is unchanged.'
        Assert-True ($timestampOnlyFingerprint -ne $contentChangedFingerprint) 'Expected file-set fingerprints to change when file content changes.'
    }
    finally {
        if (Test-Path -LiteralPath $tempRoot) {
            Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}
