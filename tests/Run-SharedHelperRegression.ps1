#Requires -Version 7.0

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string[]]$TestName,

    [Parameter(Mandatory = $false)]
    [ValidateSet('Artifact', 'Store', 'Normalization', 'Benchmark', 'Generator', 'Validation', 'Other')]
    [string[]]$Category,

    [Parameter(Mandatory = $false)]
    [ValidateRange(0, 10000)]
    [int]$StopAfter = 0,

    [Parameter(Mandatory = $false)]
    [string]$JUnitOutputPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

. (Join-Path (Split-Path -Path $PSScriptRoot -Parent) 'build\Import-SharedHelpers.ps1')
. (Join-Path $PSScriptRoot 'helpers\BenchmarkSeriesTools.ps1')
. (Join-Path $PSScriptRoot 'helpers\BenchmarkEvidenceTools.ps1')

function Assert-True {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [bool]$Condition,

        [Parameter(Mandatory = $true)]
        [string]$Message
    )

    if (-not $Condition) {
        throw $Message
    }
}

function Get-OutputRecordText {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        $Record
    )

    if ($null -eq $Record) {
        return $null
    }

    if ($Record -is [System.Management.Automation.InformationRecord]) {
        return [string]$Record.MessageData
    }

    return ($Record | Out-String).Trim()
}

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

function Get-TestVulnRow {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Id,

        [Parameter(Mandatory = $true)]
        [string]$CveId,

        [Parameter(Mandatory = $true)]
        [string]$SnapshotDate,

        [Parameter(Mandatory = $true)]
        [string]$Version
    )

    return [PSCustomObject]@{
        Id                           = $Id
        DeviceId                     = 'device-001'
        DeviceName                   = 'device01.contoso.com'
        RbacGroupName                = 'Servers'
        OSPlatform                   = 'Windows 11'
        OSVersion                    = '10.0.22631'
        MachineTags                  = @('Prod')
        CveId                        = $CveId
        SoftwareVendor               = 'Contoso'
        SoftwareName                 = 'Legacy Agent'
        SoftwareVersion              = $Version
        VulnerabilitySeverityLevel   = 'High'
        CvssScore                    = 8.1
        ExploitabilityLevel          = 'ExploitationLikely'
        RecommendationReference      = 'KB000001'
        RecommendedSecurityUpdate    = 'KB000001'
        RecommendedSecurityUpdateId  = 'KB000001'
        RecommendedSecurityUpdateUrl = 'https://example.invalid/kb000001'
        SecurityUpdateAvailable      = $true
        FirstSeenTimestamp           = $SnapshotDate
        LastSeenTimestamp            = $SnapshotDate
        DiskPaths                    = @('C:\Program Files\Legacy Agent\agent.exe')
        RegistryPaths                = @('HKLM\Software\Contoso\LegacyAgent')
        CveBatchTitle                = 'January 2026 Security Updates'
        CveBatchUrl                  = 'https://example.invalid/batch/jan-2026'
        IsOnboarded                  = $true
    }
}

function Get-TestMachineRecord {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Id
    )

    return [PSCustomObject]@{
        id                    = $Id
        computerDnsName       = ($Id + '.contoso.com')
        rbacGroupName         = 'Servers'
        osPlatform            = 'Windows'
        osVersion             = '10.0.22631'
        machineTags           = @('Prod')
        lastIpAddress         = '10.0.0.10'
        lastExternalIpAddress = '52.0.0.10'
        healthStatus          = 'Active'
        riskScore             = 'Medium'
        exposureLevel         = 'High'
        deviceValue           = 'Normal'
        managedBy             = 'Intune'
        isAadJoined           = $true
        lastSeen              = '2026-04-22T00:00:00Z'
        firstSeen             = '2026-04-01T00:00:00Z'
    }
}

function Get-TestQuarterlyHistoryDocument {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$PeriodKey,

        [Parameter(Mandatory = $true)]
        [object[]]$Snapshots
    )

    $latestDate = $null
    foreach ($snapshot in @($Snapshots)) {
        if ($null -eq $snapshot) { continue }
        $snapshotDate = [string](Get-VulnPropertyValue -InputObject $snapshot -Name 'date')
        if ([string]::IsNullOrWhiteSpace($snapshotDate)) { continue }

        if ([string]::IsNullOrWhiteSpace($latestDate) -or ([datetime]$snapshotDate -gt [datetime]$latestDate)) {
            $latestDate = $snapshotDate
        }
    }

    return [PSCustomObject]@{
        year = [int]$PeriodKey.Substring(0, 4)
        period = $PeriodKey
        quarter = [int]$PeriodKey.Substring($PeriodKey.Length - 1)
        latestDate = $latestDate
        snapshots = @($Snapshots)
    }
}

function Test-VulnPropertyHelpersSupportSupportedRowShapes {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '', Justification = 'Regression test name intentionally refers to multiple supported row shapes.')]
    [CmdletBinding()]
    param()

    $psRow = [PSCustomObject]@{
        Id = 'ps-row-001'
        MachineTags = @('Prod', 'Pilot')
    }
    $dictionaryRow = [ordered]@{
        Id = 'dict-row-001'
        MachineTags = @('Blue')
    }
    $jsonRow = [Newtonsoft.Json.Linq.JObject]::Parse('{"Id":"json-row-001","MachineTags":["Ring0","Ring1"]}')

    Assert-True ([string](Get-VulnPropertyValue -InputObject $psRow -Name 'Id') -eq 'ps-row-001') 'Expected PSObject vulnerability rows to expose Id through Get-VulnPropertyValue.'
    Assert-True ([string](Get-VulnPropertyValue -InputObject $dictionaryRow -Name 'Id') -eq 'dict-row-001') 'Expected dictionary-backed vulnerability rows to expose Id through Get-VulnPropertyValue.'
    Assert-True ([string](Get-VulnPropertyValue -InputObject $jsonRow -Name 'Id') -eq 'json-row-001') 'Expected JObject vulnerability rows to expose Id through Get-VulnPropertyValue.'

    $psTags = @(Get-StringArray -Value (Get-VulnPropertyValue -InputObject $psRow -Name 'MachineTags'))
    $dictionaryTags = @(Get-StringArray -Value (Get-VulnPropertyValue -InputObject $dictionaryRow -Name 'MachineTags'))
    $jsonTags = @(Get-StringArray -Value (Get-VulnPropertyValue -InputObject $jsonRow -Name 'MachineTags'))

    Assert-True ($psTags.Count -eq 2 -and $psTags[0] -eq 'Prod' -and $psTags[1] -eq 'Pilot') 'Expected PSObject array properties to round-trip through Get-VulnPropertyValue.'
    Assert-True ($dictionaryTags.Count -eq 1 -and $dictionaryTags[0] -eq 'Blue') 'Expected dictionary array properties to round-trip through Get-VulnPropertyValue.'
    Assert-True ($jsonTags.Count -eq 2 -and $jsonTags[0] -eq 'Ring0' -and $jsonTags[1] -eq 'Ring1') 'Expected JObject array properties to round-trip through Get-VulnPropertyValue.'

    Assert-True ((Test-VulnPropertyPresence -InputObject $psRow -Name 'Id') -eq $true) 'Expected Test-VulnPropertyPresence to report present PSObject properties.'
    Assert-True ((Test-VulnPropertyPresence -InputObject $psRow -Name 'Missing') -eq $false) 'Expected Test-VulnPropertyPresence to report missing PSObject properties as absent.'
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

function Test-NormalizedPayloadCacheRejectsManifestHashMismatch {
    [CmdletBinding()]
    param()

    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('payload-cache-hash-mismatch-' + [guid]::NewGuid().ToString('N'))
    [void](New-Item -Path $tempRoot -ItemType Directory -Force)

    try {
        $currentRow = Get-TestVulnRow -Id 'cache-hash-001' -CveId 'CVE-2026-0801' -SnapshotDate '2026-03-20' -Version '8.0.0'
        Write-NdjsonRecordsFile -Path (Get-VulnCurrentPath -BasePath $tempRoot) -Records @($currentRow)

        $payloadPath = Join-Path $tempRoot 'payload.json.gz'
        Write-GzipTextFile -Path $payloadPath -Content '{"lookups":{"devices":[],"cves":[]},"vulnsFormat":"rows-v1","vulns":[]}'

        $cacheEntry = Publish-NormalizedPayloadCache -BasePath $tempRoot -PayloadPath $payloadPath -VulnCount 0 -DeviceCount 0 -CveCount 0 -Quality ([PSCustomObject]@{ FirstLastSwappedCount = 0 })
        Assert-True ($null -ne $cacheEntry) 'Expected normalized payload cache publish to create an entry.'
        Assert-True ($null -ne (Get-NormalizedPayloadCacheEntry -BasePath $tempRoot)) 'Expected normalized payload cache entry to be reusable before corruption.'

        Set-Content -LiteralPath $cacheEntry.PayloadPath -Value 'corrupt' -NoNewline -Encoding utf8
        $cacheMiss = Get-NormalizedPayloadCacheEntry -BasePath $tempRoot

        $throwFailure = $null
        try {
            $null = Confirm-NormalizedPayloadManifestPayloadSha -Manifest $cacheEntry.Manifest -PayloadPath $cacheEntry.PayloadPath -ThrowOnMismatch
        }
        catch {
            $throwFailure = $_
        }

        Assert-True ($null -eq $cacheMiss) 'Expected normalized payload cache lookup to reject a payload whose bytes do not match the manifest hash.'
        Assert-True ($null -ne $throwFailure) 'Expected strict normalized payload manifest confirmation to throw on hash mismatch.'
    }
    finally {
        if (Test-Path -LiteralPath $tempRoot) {
            Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

function Test-NormalizedPayloadManifestSourceSummary {
    [CmdletBinding()]
    param()

    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('payload-source-metadata-' + [guid]::NewGuid().ToString('N'))
    [void](New-Item -Path $tempRoot -ItemType Directory -Force)

    try {
        Write-GzipTextFile -Path (Get-MachineCurrentPath -BasePath $tempRoot) -Content '[{"id":"device-001"}]'
        Write-GzipTextFile -Path (Get-AdvancedHuntingCurrentPath -BasePath $tempRoot) -Content '[{"CveId":"CVE-2026-0802"}]'
        Write-GzipTextFile -Path (Get-NvdCveCurrentPath -BasePath $tempRoot) -Content '{"records":[{"CveId":"CVE-2026-0802"}]}'

        $sourceMetadata = Get-DashboardSourceSummary `
            -BasePath $tempRoot `
            -MachineCount 1 `
            -AdvancedHuntingCveCount 2 `
            -AdvancedHuntingDeviceUserCount 3 `
            -AdvancedHuntingInventoryTupleCount 4 `
            -NvdCveCount 5 `
            -NormalizationMode 'regression-test'

        Assert-True ($sourceMetadata.Version -eq 'dashboard-source-metadata-v1') 'Expected source metadata to include a version marker.'
        Assert-True ($sourceMetadata.MachineData.RecordCount -eq 1) 'Expected source metadata to preserve machine record count.'
        Assert-True ($sourceMetadata.MachineData.Source.FileCount -eq 1) 'Expected source metadata to include machine source file summary.'
        Assert-True ($sourceMetadata.AdvancedHunting.CveCount -eq 2) 'Expected source metadata to preserve Advanced Hunting CVE count.'
        Assert-True ($sourceMetadata.AdvancedHunting.DeviceUserCount -eq 3) 'Expected source metadata to preserve Advanced Hunting device-user count.'
        Assert-True ($sourceMetadata.AdvancedHunting.InventoryTupleCount -eq 4) 'Expected source metadata to preserve Advanced Hunting inventory tuple count.'
        Assert-True ($sourceMetadata.NvdCve.RecordCount -eq 5) 'Expected source metadata to preserve NVD CVE count.'

        $payloadPath = Join-Path $tempRoot 'payload.json.gz'
        Write-GzipTextFile -Path $payloadPath -Content '{"lookups":{"devices":[],"cves":[]},"vulnsFormat":"rows-v1","vulns":[]}'

        $cacheEntry = Publish-NormalizedPayloadCache -BasePath $tempRoot -PayloadPath $payloadPath -VulnCount 0 -DeviceCount 1 -CveCount 5 -Quality ([PSCustomObject]@{ FirstLastSwappedCount = 0 }) -SourceMetadata $sourceMetadata
        Assert-True ($null -ne $cacheEntry.Manifest.SourceMetadata) 'Expected normalized payload manifest to carry source metadata.'
        Assert-True ($cacheEntry.Manifest.SourceMetadata.AdvancedHunting.DeviceUserCount -eq 3) 'Expected manifest source metadata to retain enrichment counts.'

        $htmlPath = Join-Path $tempRoot 'dashboard.html'
        Set-Content -LiteralPath $htmlPath -Value '<html></html>' -NoNewline -Encoding utf8
        $sidecarPath = Write-DashboardValidationSidecar -HtmlPath $htmlPath -PayloadManifest $cacheEntry.Manifest -DashboardPayloadSha256 $cacheEntry.Manifest.PayloadSha256 -DashboardPayloadRowCount 0
        $sidecar = Get-Content -LiteralPath $sidecarPath -Raw | ConvertFrom-Json -Depth 20

        Assert-True ($null -ne $sidecar.SourceMetadata) 'Expected validation sidecar to copy source metadata from the payload manifest.'
        Assert-True ($sidecar.SourceMetadata.NvdCve.RecordCount -eq 5) 'Expected validation sidecar source metadata to retain NVD counts.'
    }
    finally {
        if (Test-Path -LiteralPath $tempRoot) {
            Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

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

function Test-VulnContentStoreExistenceNeedsRef {
    [CmdletBinding()]
    param()

    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('content-store-existence-' + [guid]::NewGuid().ToString('N'))
    [void](New-Item -Path $tempRoot -ItemType Directory -Force)

    try {
        Set-Content -Path (Get-VulnContentDictionaryPath -BasePath $tempRoot) -Value '{}' -Encoding utf8
        Assert-True ((Test-VulnContentStoreExistence -BasePath $tempRoot) -eq $false) 'Dictionary-only content store should not be treated as valid.'

        Set-Content -Path (Get-VulnCurrentRefsPath -BasePath $tempRoot) -Value '' -Encoding utf8
        Assert-True ((Test-VulnContentStoreExistence -BasePath $tempRoot) -eq $true) 'Current refs should make a minimal content store valid.'

        Set-Content -Path (Get-VulnHistoryPath -BasePath $tempRoot -PeriodKey '2026Q1') -Value '' -Encoding utf8
        Assert-True ((Test-VulnContentStoreExistence -BasePath $tempRoot) -eq $false) 'History periods should require matching history refs sidecars.'

        Set-Content -Path (Get-VulnHistoryRefsPath -BasePath $tempRoot -PeriodKey '2026Q1') -Value '' -Encoding utf8
        Assert-True ((Test-VulnContentStoreExistence -BasePath $tempRoot) -eq $true) 'Matching history refs should restore content-store validity.'
    }
    finally {
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

function Test-InitializeMachineHistoryStoreBackfillsCurrentRecordMetadata {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '', Justification = 'Regression test name intentionally refers to current records and metadata fields as a set.')]
    [CmdletBinding()]
    param()

    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('machine-store-init-' + [guid]::NewGuid().ToString('N'))
    [void](New-Item -Path $tempRoot -ItemType Directory -Force)

    try {
        $expectedObservedOn = Get-Date -Format 'yyyy-MM-dd'
        Write-NdjsonRecordsFile -Path (Get-MachineCurrentPath -BasePath $tempRoot) -Records @(
            (Get-TestMachineRecord -Id 'machine-001'),
            [PSCustomObject]@{
                id = 'machine-002'
                removed = $true
            }
        )

        $store = Initialize-MachineHistoryStore -Path $tempRoot
        $currentRecord = $store.CurrentRecords['machine-001']
        $periodKey = Get-QuarterPeriodKeyFromDate -Date $expectedObservedOn
        $historyRecords = @($store.HistoryRecordsByPeriod[$periodKey])

        Assert-True ($store.CurrentRecords.Count -eq 1) 'Expected removal records to be excluded from the current machine map.'
        Assert-True ($null -ne $currentRecord) 'Expected the surviving machine record to remain in the current machine map.'
        Assert-True ([string]$currentRecord.observedOn -eq $expectedObservedOn) 'Expected current machine records without observedOn to be backfilled once during initialization.'
        Assert-True ([string]$currentRecord.stateHash -eq [string](Get-MachineStateHash -Machine $currentRecord)) 'Expected current machine records without stateHash to be backfilled during initialization.'
        Assert-True ($historyRecords.Count -eq 1) 'Expected current machine records to seed history when no history store exists yet.'
        Assert-True ([string]$historyRecords[0].id -eq 'machine-001') 'Expected seeded history to include the surviving machine record.'
        Assert-True ([string]$historyRecords[0].observedOn -eq $expectedObservedOn) 'Expected seeded history rows to preserve the backfilled observedOn value.'
    }
    finally {
        if (Test-Path -LiteralPath $tempRoot) {
            Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

function Test-InitializeMachineHistoryStoreSupportsStateHashOnlyCurrentMap {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '', Justification = 'Regression test name intentionally refers to current records and metadata fields as a set.')]
    [CmdletBinding()]
    param()

    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('machine-store-statehash-' + [guid]::NewGuid().ToString('N'))
    [void](New-Item -Path $tempRoot -ItemType Directory -Force)

    try {
        $machineRecord = Get-TestMachineRecord -Id 'machine-001'
        Write-NdjsonRecordsFile -Path (Get-MachineCurrentPath -BasePath $tempRoot) -Records @(
            $machineRecord,
            [PSCustomObject]@{
                id = 'machine-002'
                removed = $true
            }
        )

        $store = Initialize-MachineHistoryStore -Path $tempRoot -LoadCurrentRecordsStateHashOnly
        $currentRecordStateHash = [string]$store.CurrentRecords['machine-001']

        Assert-True ($store.CurrentRecords.Count -eq 1) 'Expected removal records to be excluded from the current machine stateHash map.'
        Assert-True (-not [string]::IsNullOrWhiteSpace($currentRecordStateHash)) 'Expected stateHash-only initialization to preserve the surviving machine state hash.'
        Assert-True ($currentRecordStateHash -eq [string](Get-MachineStateHash -Machine $machineRecord)) 'Expected stateHash-only initialization to compute the same current-machine state hash as the full-record path.'
        Assert-True ($store.HistoryRecordsByPeriod.Count -eq 0) 'Expected stateHash-only initialization to skip synthetic history seeding when the current map does not retain full snapshot records.'
    }
    finally {
        if (Test-Path -LiteralPath $tempRoot) {
            Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

function Test-MdeMachineRefreshPublishPlanSupportsStateHashOnlyCurrentMap {
    [CmdletBinding()]
    param()

    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('machine-refresh-plan-statehash-' + [guid]::NewGuid().ToString('N'))
    [void](New-Item -Path $tempRoot -ItemType Directory -Force)
    $originalRestMethod = (Get-Command -Name Invoke-RestMethodWithRetry -CommandType Function).ScriptBlock

    try {
        Write-NdjsonRecordsFile -Path (Get-MachineCurrentPath -BasePath $tempRoot) -Records @(
            (Get-TestMachineRecord -Id 'machine-001'),
            (Get-TestMachineRecord -Id 'machine-002')
        )

        $store = Initialize-MachineHistoryStore -Path $tempRoot -LoadCurrentRecordsStateHashOnly
        $changedMachine = Get-TestMachineRecord -Id 'machine-002'
        $changedMachine.riskScore = 'High'
        $newMachine = Get-TestMachineRecord -Id 'machine-003'
        $script:MockMachineRefreshPlanResponses = @(
            [PSCustomObject]@{
                value = @(
                    Get-TestMachineRecord -Id 'machine-001'
                    $changedMachine
                    $newMachine
                )
            }
        )
        $script:MockMachineRefreshPlanIndex = 0

        Set-Item -Path Function:Invoke-RestMethodWithRetry -Value {
            param(
                [string]$Uri,
                [hashtable]$Headers,
                [string]$Method
            )

            [void]$Uri
            [void]$Headers
            [void]$Method

            if ($script:MockMachineRefreshPlanIndex -ge $script:MockMachineRefreshPlanResponses.Count) {
                throw 'Mock machine refresh plan responses were exhausted unexpectedly.'
            }

            $response = $script:MockMachineRefreshPlanResponses[$script:MockMachineRefreshPlanIndex]
            $script:MockMachineRefreshPlanIndex++
            return $response
        }

        $stagedCurrentPath = Join-Path $tempRoot 'Machines_Current.staged.json.gz'
        $refreshPlan = Get-MdeMachineRefreshPublishPlan -Headers @{ Authorization = 'Bearer test' } -BaseApiUrl 'https://example.invalid' -ObservedOn '2026-05-10' -CurrentRecords $store.CurrentRecords -StagedCurrentPath $stagedCurrentPath
        $stagedCurrentRecords = @(Read-MachineRecordsFromFile -Path $refreshPlan.StagedCurrentPath)
        $stagedHistoryRecords = @(Read-MachineRecordsFromFile -Path $refreshPlan.StagedHistoryPath)

        Assert-True ($refreshPlan.MachineCount -eq 3) 'Expected the refresh plan to preserve all fetched machine rows when the current map is stateHash-only.'
        Assert-True ($refreshPlan.ChangeCount -eq 2) 'Expected the refresh plan to detect one changed machine and one new machine when current rows are represented by state hashes.'
        Assert-True ($refreshPlan.PageCount -eq 1) 'Expected the refresh plan to consume the mocked single-page machine response.'
        Assert-True ($store.CurrentRecords.Count -eq 0) 'Expected the refresh plan to remove every surviving current-machine entry from the stateHash-only map.'
        Assert-True ($stagedCurrentRecords.Count -eq 3) 'Expected the staged current machine file to include every fetched machine row.'
        Assert-True ($stagedHistoryRecords.Count -eq 2) 'Expected the staged history file to include only the changed and new machine rows.'
    }
    finally {
        Set-Item -Path Function:Invoke-RestMethodWithRetry -Value $originalRestMethod
        Remove-Variable -Name MockMachineRefreshPlanResponses -Scope Script -ErrorAction SilentlyContinue
        Remove-Variable -Name MockMachineRefreshPlanIndex -Scope Script -ErrorAction SilentlyContinue
        if (Test-Path -LiteralPath $tempRoot) {
            Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

function Test-MachineHistoryRemovePathsAllowsEmptyPublishedHistorySet {
    [CmdletBinding()]
    param()

    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('machine-history-remove-empty-' + [guid]::NewGuid().ToString('N'))
    [void](New-Item -Path $tempRoot -ItemType Directory -Force)

    try {
        $publishedHistoryNames = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        $removePaths = @(Get-MachineHistoryRemovePaths -BasePath $tempRoot -PublishedHistoryNames $publishedHistoryNames)

        Assert-True ($removePaths.Count -eq 0) 'Expected empty machine history cleanup inputs to be accepted without removable paths.'
    }
    finally {
        if (Test-Path -LiteralPath $tempRoot) {
            Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

function Test-RestoreStoreTransactionRejectsInvalidJournalShape {
    [CmdletBinding()]
    param()

    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('store-transaction-invalid-' + [guid]::NewGuid().ToString('N'))
    $externalTransactionRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('store-transaction-external-' + [guid]::NewGuid().ToString('N'))
    [void](New-Item -Path $tempRoot -ItemType Directory -Force)
    [void](New-Item -Path $externalTransactionRoot -ItemType Directory -Force)

    try {
        $journalPath = Get-StoreTransactionJournalPath -BasePath $tempRoot -StoreName 'machines'
        Write-StoreTransactionState -Path $journalPath -State ([PSCustomObject]@{
                StoreName = 'machines'
                TransactionRoot = $externalTransactionRoot
                Phase = 'Prepared'
                Files = @([PSCustomObject]@{
                        TargetPath = Get-MachineCurrentPath -BasePath $tempRoot
                        StagePath = Join-Path $externalTransactionRoot 'Machines_Current.json.gz'
                        BackupPath = Join-Path $externalTransactionRoot 'replace-0-Machines_Current.json.gz.bak'
                        TargetExisted = $false
                    })
                RemovedFiles = @()
            })

        $failure = $null
        try {
            Restore-StoreTransaction -BasePath $tempRoot -StoreName 'machines'
        }
        catch {
            $failure = $_
        }

        Assert-True ($null -ne $failure) 'Expected invalid transaction journals to be rejected before rollback begins.'
        Assert-True ($failure.Exception.Message -like "*references transaction root*$externalTransactionRoot*outside*") 'Expected invalid transaction journal failures to explain that the transaction root escaped the store base path.'
        Assert-True ((Test-Path -LiteralPath $journalPath -PathType Leaf)) 'Expected invalid transaction journals to remain on disk for manual inspection.'
    }
    finally {
        foreach ($path in @($tempRoot, $externalTransactionRoot)) {
            if (Test-Path -LiteralPath $path) {
                Remove-Item -LiteralPath $path -Recurse -Force -ErrorAction SilentlyContinue
            }
        }
    }
}

function Test-InitializeMachineHistoryStoreRejectsExpiredLegacyMigration {
    [CmdletBinding()]
    param()

    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('machine-store-expired-legacy-' + [guid]::NewGuid().ToString('N'))
    [void](New-Item -Path $tempRoot -ItemType Directory -Force)
    $originalRemovalDate = $Script:LegacyVulnMigrationRemovalDate

    try {
        Write-NdjsonRecordsFile -Path (Join-Path $tempRoot 'Machines_2026-05-01.json') -Records @(
            (Get-TestMachineRecord -Id 'machine-001')
        )
        $Script:LegacyVulnMigrationRemovalDate = '2000-01-01'

        $failure = $null
        try {
            $null = Initialize-MachineHistoryStore -Path $tempRoot
        }
        catch {
            $failure = $_
        }

        Assert-True ($null -ne $failure) 'Expected expired machine legacy migration support to fail fast.'
        Assert-True ($failure.Exception.Message -like '*Legacy machine snapshot compatibility support expired on 2000-01-01*') 'Expected machine legacy migration failures to explain the compatibility cutoff date.'
    }
    finally {
        $Script:LegacyVulnMigrationRemovalDate = $originalRemovalDate
        if (Test-Path -LiteralPath $tempRoot) {
            Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

function Test-InitializeAdvancedHuntingStoreRejectsExpiredLegacyMigration {
    [CmdletBinding()]
    param()

    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('advancedhunting-store-expired-legacy-' + [guid]::NewGuid().ToString('N'))
    [void](New-Item -Path $tempRoot -ItemType Directory -Force)
    $originalRemovalDate = $Script:LegacyVulnMigrationRemovalDate

    try {
        Write-NdjsonRecordsFile -Path (Join-Path $tempRoot 'AdvancedHunting_123_2026-05-01.json') -Records @(
            [PSCustomObject]@{
                CveId = 'CVE-2026-0001'
                PublishedDate = '2026-05-01'
                VulnerabilityDescription = 'Expired legacy compatibility test'
                EpssScore = 0.42
                AffectedSoftware = @('Legacy App')
                LastModifiedTime = '2026-05-01T00:00:00Z'
            }
        )
        $Script:LegacyVulnMigrationRemovalDate = '2000-01-01'

        $failure = $null
        try {
            $null = Initialize-AdvancedHuntingStore -Path $tempRoot
        }
        catch {
            $failure = $_
        }

        Assert-True ($null -ne $failure) 'Expected expired Advanced Hunting legacy migration support to fail fast.'
        Assert-True ($failure.Exception.Message -like '*Legacy Advanced Hunting snapshot compatibility support expired on 2000-01-01*') 'Expected Advanced Hunting legacy migration failures to explain the compatibility cutoff date.'
    }
    finally {
        $Script:LegacyVulnMigrationRemovalDate = $originalRemovalDate
        if (Test-Path -LiteralPath $tempRoot) {
            Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

function Test-PublishVulnerabilityHistoryStoreRejectsExpiredImplicitLegacyMigration {
    [CmdletBinding()]
    param()

    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('vuln-store-expired-implicit-' + [guid]::NewGuid().ToString('N'))
    [void](New-Item -Path $tempRoot -ItemType Directory -Force)
    $originalRemovalDate = $Script:LegacyVulnMigrationRemovalDate

    try {
        Write-NdjsonRecordsFile -Path (Join-Path $tempRoot 'VulnExport_1_2026-05-01.json') -Records @(
            (Get-TestVulnRow -Id 'vuln-001' -CveId 'CVE-2026-0001' -SnapshotDate '2026-05-01' -Version '1.0.0')
        )
        $Script:LegacyVulnMigrationRemovalDate = '2000-01-01'

        $failure = $null
        try {
            $null = Publish-VulnerabilityHistoryStore -OutputPath $tempRoot
        }
        catch {
            $failure = $_
        }

        Assert-True ($null -ne $failure) 'Expected implicit vulnerability legacy migration to be blocked after the cutoff date.'
        Assert-True (($failure.Exception.Message -like '*legacy*') -and ($failure.Exception.Message -like '*2000-01-01*')) ("Expected vulnerability legacy migration failures to explain the compatibility cutoff date. Actual: {0}`nStack: {1}" -f $failure.Exception.Message, $failure.ScriptStackTrace)
    }
    finally {
        $Script:LegacyVulnMigrationRemovalDate = $originalRemovalDate
        if (Test-Path -LiteralPath $tempRoot) {
            Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

function Test-PublishVulnerabilityHistoryStoreAllowsExplicitDownloadedLegacyFilesAfterCutoff {
    [CmdletBinding()]
    param()

    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('vuln-store-explicit-download-' + [guid]::NewGuid().ToString('N'))
    [void](New-Item -Path $tempRoot -ItemType Directory -Force)
    $originalRemovalDate = $Script:LegacyVulnMigrationRemovalDate

    try {
        $downloadedFile = Join-Path $tempRoot 'VulnExport_1_2026-05-01.json'
        Write-NdjsonRecordsFile -Path $downloadedFile -Records @(
            (Get-TestVulnRow -Id 'vuln-001' -CveId 'CVE-2026-0001' -SnapshotDate '2026-05-01' -Version '1.0.0')
        )
        $Script:LegacyVulnMigrationRemovalDate = '2000-01-01'

        $result = Publish-VulnerabilityHistoryStore -OutputPath $tempRoot -DownloadedFiles @($downloadedFile)

        Assert-True ($result.CurrentRows -eq 1) 'Expected explicitly downloaded vulnerability snapshots to continue canonicalizing after the legacy cutoff.'
        Assert-True ((Test-Path -LiteralPath (Get-VulnCurrentPath -BasePath $tempRoot) -PathType Leaf)) 'Expected the canonical vulnerability current store to be written for explicit downloaded snapshots.'
    }
    finally {
        $Script:LegacyVulnMigrationRemovalDate = $originalRemovalDate
        if (Test-Path -LiteralPath $tempRoot) {
            Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

function Test-GetMdeAccessTokenReportsMissingConfigurationDiagnostic {
    [CmdletBinding()]
    param()

    $failure = $null
    try {
        $null = Get-MdeAccessToken -AppId 'app-001' -AppSecret 'secret-value'
    }
    catch {
        $failure = $_
    }

    Assert-True ($null -ne $failure) 'Expected incomplete MDE credential configuration to fail.'
    Assert-True ($failure.Exception.Message -like '*TenantId is missing*') 'Expected missing-credential diagnostics to identify the specific missing MDE setting.'
    Assert-True ($failure.Exception.Message -like '*Provide -AccessToken or -TenantId/-AppId/-AppSecret*') 'Expected missing-credential diagnostics to preserve the remediation guidance.'
}

function Test-GetMdeAccessTokenReportsAuthenticationContext {
    [CmdletBinding()]
    param()

    Set-Item -Path Function:Invoke-RestMethod -Value {
        throw [System.Exception]::new('invalid_client')
    }

    try {
        $failure = $null
        try {
            $null = Invoke-MdeClientCredentialTokenRequest -TenantId 'tenant-001' -AppId 'app-001' -AppSecretText 'secret-value'
        }
        catch {
            $failure = $_
        }

        Assert-True ($null -ne $failure) 'Expected failed MDE authentication attempts to surface context-rich diagnostics.'
        $message = [string]$failure.Exception.Message
        Assert-True ($message.Contains("tenant 'tenant-001'")) 'Expected authentication failures to include the tenant identifier.'
        Assert-True ($message.Contains("app 'app-001'")) 'Expected authentication failures to include the app identifier.'
        Assert-True ($message.Contains("resource 'https://api.securitycenter.microsoft.com'")) 'Expected authentication failures to include the resource identifier.'
        Assert-True ($message.Contains('invalid_client')) 'Expected authentication failures to preserve the underlying error message.'
    }
    finally {
        Remove-Item -Path Function:Invoke-RestMethod -ErrorAction SilentlyContinue
    }
}

function Test-NewMdeAccessTokenContextRejectsMissingExpirationMetadata {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '', Justification = 'Test function name mirrors the scenario under test.')]
    [CmdletBinding()]
    param()

    $failure = $null
    try {
        $null = New-MdeTokenContext -AccessToken 'token-without-expiry' -CanRefresh $true -RefreshScript { return $null } -SourceDescription 'test context'
    }
    catch {
        $failure = $_
    }

    Assert-True ($null -ne $failure) 'Expected refreshable MDE token contexts to reject missing expiration metadata.'
    Assert-True ($failure.Exception.Message -like "*require expiration metadata*") 'Expected missing-expiration validation to explain why refreshable MDE token contexts cannot be created.'
}

function Test-MdeRequestHeaderRefreshesNearExpiryTokenContext {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '', Justification = 'Test function name mirrors the scenario under test.')]
    [CmdletBinding()]
    param()

    $script:MockMdeTokenRequestCount = 0
    Set-Item -Path Function:Invoke-RestMethod -Value {
        $script:MockMdeTokenRequestCount++
        if ($script:MockMdeTokenRequestCount -eq 1) {
            return [PSCustomObject]@{
                access_token = 'token-initial'
                expires_in   = 3600
            }
        }

        return [PSCustomObject]@{
            access_token = 'token-refreshed'
            expires_in   = 3600
        }
    }

    try {
        $tokenContext = New-MdeAccessTokenContext -TenantId 'tenant-001' -AppId 'app-001' -AppSecret 'secret-value'
        $headers = Get-MdeHeaderCollection -TokenContext $tokenContext
        Assert-True ($headers.Authorization -eq 'Bearer token-initial') 'Expected the initial MDE header collection to use the original token.'

        $tokenContext.ExpiresOnUtc = [datetime]::UtcNow.AddMinutes(4)
        $resolvedHeaders = Resolve-MdeHeaderCollection -Headers $headers

        Assert-True ($resolvedHeaders.Authorization -eq 'Bearer token-refreshed') 'Expected near-expiry MDE headers to refresh the bearer token before the next request.'
        Assert-True ($script:MockMdeTokenRequestCount -eq 2) 'Expected MDE token refresh to reacquire a token exactly once when the remaining lifetime drops below the refresh window.'
    }
    finally {
        Remove-Item -Path Function:Invoke-RestMethod -ErrorAction SilentlyContinue
        Remove-Variable -Name MockMdeTokenRequestCount -Scope Script -ErrorAction SilentlyContinue
    }
}

function Test-MdeRequestHeaderKeepsExplicitAccessTokenContextStable {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '', Justification = 'Test function name mirrors the scenario under test.')]
    [CmdletBinding()]
    param()

    $tokenContext = New-MdeAccessTokenContext -AccessToken 'token-explicit'
    $headers = Get-MdeHeaderCollection -TokenContext $tokenContext
    $resolvedHeaders = Resolve-MdeHeaderCollection -Headers $headers

    Assert-True ($tokenContext.CanRefresh -eq $false) 'Expected explicitly supplied access tokens to remain non-refreshable.'
    Assert-True ($resolvedHeaders.Authorization -eq 'Bearer token-explicit') 'Expected explicit MDE access tokens to remain usable without refresh metadata.'
}

function Test-BulkSnapshotImportSmoke {
    [CmdletBinding()]
    param()

    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('bulk-snapshot-import-smoke-' + [guid]::NewGuid().ToString('N'))
    [void](New-Item -Path $tempRoot -ItemType Directory -Force)

    try {
        @(
            @{ Name = 'VulnExport_1_2026-01-01.json'; Rows = @((Get-TestVulnRow -Id 'legacy-001' -CveId 'CVE-2026-0001' -SnapshotDate '2026-01-01' -Version '1.0.0')) }
            @{ Name = 'VulnExport_1_2026-01-02.json'; Rows = @((Get-TestVulnRow -Id 'legacy-002' -CveId 'CVE-2026-0002' -SnapshotDate '2026-01-02' -Version '1.0.1')) }
        ) | ForEach-Object {
            $path = Join-Path $tempRoot $_.Name
            $lines = @($_.Rows | ForEach-Object { $_ | ConvertTo-Json -Compress -Depth 8 })
            [System.IO.File]::WriteAllLines($path, $lines, [System.Text.UTF8Encoding]::new($false))
        }

        $publishResult = Publish-VulnStoreFromBulkSnapshot -BasePath $tempRoot -RemoveSnapshotFiles
        $storeRows = @(Read-VulnStoreRow -BasePath $tempRoot)

        Assert-True ((Test-Path -LiteralPath (Get-VulnCurrentPath -BasePath $tempRoot) -PathType Leaf)) 'Canonical vuln current file was not materialized.'
        Assert-True ((Test-Path -LiteralPath (Get-VulnHistoryPath -BasePath $tempRoot -PeriodKey '2026Q1') -PathType Leaf)) 'Canonical quarterly vuln history file was not materialized.'
        Assert-True ((Test-Path -LiteralPath (Get-VulnHistoryRowsPath -BasePath $tempRoot -PeriodKey '2026Q1') -PathType Leaf)) 'Canonical quarterly vuln history rows file was not materialized.'
        Assert-True (@(Get-VulnLegacySnapshotFile -BasePath $tempRoot).Count -eq 0) 'Downloaded vulnerability snapshots were not removed.'
        Assert-True ($publishResult.CurrentRows -eq 1) 'Expected one current row after migrating the smoke fixture.'
        Assert-True ($publishResult.HistoryYears -eq 1) 'Expected one history period after importing the smoke fixture.'
        Assert-True ($storeRows.Count -eq 2) 'Expected migrated store to expose one current row and one historical row.'
    }
    finally {
        if (Test-Path -LiteralPath $tempRoot) {
            Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

function Test-BulkSnapshotImportSingleSnapshot {
    [CmdletBinding()]
    param()

    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('bulk-snapshot-import-single-' + [guid]::NewGuid().ToString('N'))
    [void](New-Item -Path $tempRoot -ItemType Directory -Force)

    try {
        $path = Join-Path $tempRoot 'VulnExport_1_2026-03-20.json'
        $row = Get-TestVulnRow -Id 'single-001' -CveId 'CVE-2026-0099' -SnapshotDate '2026-03-20' -Version '1.0.0'
        [System.IO.File]::WriteAllLines($path, @($row | ConvertTo-Json -Compress -Depth 8), [System.Text.UTF8Encoding]::new($false))

        $publishResult = Publish-VulnStoreFromBulkSnapshot -BasePath $tempRoot -RemoveSnapshotFiles
        $storeRows = @(Read-VulnStoreRow -BasePath $tempRoot)

        Assert-True ((Test-Path -LiteralPath (Get-VulnCurrentPath -BasePath $tempRoot) -PathType Leaf)) 'Canonical vuln current file was not materialized for a single snapshot.'
        Assert-True (@(Get-ChildItem -Path $tempRoot -Filter 'VulnHistory_*.json.gz' -File -ErrorAction SilentlyContinue).Count -eq 0) 'Single-snapshot migration should not create history period files.'
        Assert-True ($publishResult.CurrentRows -eq 1) 'Expected one current row after importing a single snapshot.'
        Assert-True ($publishResult.HistoryYears -eq 0) 'Expected zero history periods after importing a single snapshot.'
        Assert-True ($storeRows.Count -eq 1) 'Expected single-snapshot import to expose only one current row.'
    }
    finally {
        if (Test-Path -LiteralPath $tempRoot) {
            Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

function Test-BulkSnapshotImportMultipartSnapshot {
    [CmdletBinding()]
    param()

    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('bulk-snapshot-import-multipart-' + [guid]::NewGuid().ToString('N'))
    [void](New-Item -Path $tempRoot -ItemType Directory -Force)

    try {
        @(
            @{
                Name = 'VulnExport_1_2026-01-01_part_0.json'
                Rows = @(
                    (Get-TestVulnRow -Id 'multipart-001' -CveId 'CVE-2026-1001' -SnapshotDate '2026-01-01' -Version '1.0.0')
                )
            }
            @{
                Name = 'VulnExport_1_2026-01-01_part_1.json'
                Rows = @(
                    (Get-TestVulnRow -Id 'multipart-002' -CveId 'CVE-2026-1002' -SnapshotDate '2026-01-01' -Version '1.0.0')
                )
            }
            @{
                Name = 'VulnExport_1_2026-01-02.json'
                Rows = @(
                    (Get-TestVulnRow -Id 'multipart-003' -CveId 'CVE-2026-1003' -SnapshotDate '2026-01-02' -Version '1.0.1')
                )
            }
        ) | ForEach-Object {
            $path = Join-Path $tempRoot $_.Name
            $lines = @($_.Rows | ForEach-Object { $_ | ConvertTo-Json -Compress -Depth 8 })
            [System.IO.File]::WriteAllLines($path, $lines, [System.Text.UTF8Encoding]::new($false))
        }

        Assert-True (Test-IsLegacyVulnSnapshotFileName -Name 'VulnExport_1_2026-01-01_part_0.json.gz') 'Expected multipart legacy snapshot names to be recognized.'
        Assert-True (Test-IsLegacyVulnSnapshotFileName -Name 'VulnExport_1_2026-01-02.json.gz') 'Expected legacy single-part snapshot names to remain recognized.'

        $publishResult = Publish-VulnStoreFromBulkSnapshot -BasePath $tempRoot -RemoveSnapshotFiles
        $storeRows = @(Read-VulnStoreRow -BasePath $tempRoot)
        $currentRows = @($storeRows | Where-Object { (Get-VulnPropertyValue -InputObject $_ -Name 'Id') -eq 'multipart-003' })
        $historyRows = @($storeRows | Where-Object { (Get-VulnPropertyValue -InputObject $_ -Name 'Id') -in @('multipart-001', 'multipart-002') })

        Assert-True ((Test-Path -LiteralPath (Get-VulnCurrentPath -BasePath $tempRoot) -PathType Leaf)) 'Canonical vuln current file was not materialized for multipart snapshots.'
        Assert-True ((Test-Path -LiteralPath (Get-VulnHistoryPath -BasePath $tempRoot -PeriodKey '2026Q1') -PathType Leaf)) 'Canonical quarterly vuln history file was not materialized for multipart snapshots.'
        Assert-True (@(Get-VulnLegacySnapshotFile -BasePath $tempRoot).Count -eq 0) 'Multipart vulnerability snapshots were not removed after publishing.'
        Assert-True ($publishResult.DownloadedFiles -eq 3) 'Expected all multipart snapshot files to be counted during publish.'
        Assert-True ($publishResult.CurrentRows -eq 1) 'Expected multipart import to leave one current row for the latest snapshot date.'
        Assert-True ($publishResult.HistoryYears -eq 1) 'Expected multipart import to create one history period.'
        Assert-True ($storeRows.Count -eq 3) 'Expected multipart import to preserve all rows across current and history.'
        Assert-True ($currentRows.Count -eq 1) 'Expected latest multipart snapshot import to retain one current row.'
        Assert-True ($historyRows.Count -eq 2) 'Expected prior multipart snapshot rows to be preserved in history.'
    }
    finally {
        if (Test-Path -LiteralPath $tempRoot) {
            Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

function Test-BulkSnapshotImportMergesIntoExistingCanonicalStore {
    [CmdletBinding()]
    param()

    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('bulk-snapshot-import-existing-store-' + [guid]::NewGuid().ToString('N'))
    [void](New-Item -Path $tempRoot -ItemType Directory -Force)

    try {
        $initialSnapshotPath = Join-Path $tempRoot 'VulnExport_1_2026-01-01.json'
        $initialRows = @(
            (Get-TestVulnRow -Id 'merge-001' -CveId 'CVE-2026-2001' -SnapshotDate '2026-01-01' -Version '1.0.0')
        )
        [System.IO.File]::WriteAllLines($initialSnapshotPath, @($initialRows | ForEach-Object { $_ | ConvertTo-Json -Compress -Depth 8 }), [System.Text.UTF8Encoding]::new($false))

        $null = Publish-VulnStoreFromBulkSnapshot -BasePath $tempRoot -RemoveSnapshotFiles

        $deltaSnapshotPath = Join-Path $tempRoot 'VulnExport_1_2026-01-02.json'
        $deltaRows = @(
            (Get-TestVulnRow -Id 'merge-001' -CveId 'CVE-2026-2001' -SnapshotDate '2026-01-02' -Version '1.0.0')
            (Get-TestVulnRow -Id 'merge-002' -CveId 'CVE-2026-2002' -SnapshotDate '2026-01-02' -Version '2.0.0')
        )
        [System.IO.File]::WriteAllLines($deltaSnapshotPath, @($deltaRows | ForEach-Object { $_ | ConvertTo-Json -Compress -Depth 8 }), [System.Text.UTF8Encoding]::new($false))

        $publishResult = Publish-VulnStoreFromBulkSnapshot -BasePath $tempRoot -RemoveSnapshotFiles
        $storeRows = @(Read-VulnStoreRow -BasePath $tempRoot)
        $storeIds = @($storeRows | ForEach-Object { [string](Get-VulnPropertyValue -InputObject $_ -Name 'Id') })

        Assert-True ((Test-Path -LiteralPath (Get-VulnCurrentPath -BasePath $tempRoot) -PathType Leaf)) 'Canonical vuln current file was not preserved when merging into an existing store.'
        Assert-True (@(Get-ChildItem -Path $tempRoot -Filter 'VulnHistory_*.json.gz' -File -ErrorAction SilentlyContinue).Count -eq 0) 'Merging an unchanged carry-forward snapshot into an existing store should not create history.'
        Assert-True (@(Get-VulnLegacySnapshotFile -BasePath $tempRoot).Count -eq 0) 'Delta vulnerability snapshots were not removed after merging into an existing store.'
        Assert-True ($publishResult.CurrentRows -eq 2) 'Expected the existing canonical store merge to retain both current rows from the latest snapshot.'
        Assert-True ($publishResult.HistoryYears -eq 0) 'Expected the existing canonical store merge to avoid creating history when rows are only carried forward or added.'
        Assert-True ([string]$publishResult.LatestSnapshotDate -eq '2026-01-02') 'Expected the existing canonical store merge to advance the latest snapshot date.'
        Assert-True ($storeRows.Count -eq 2) 'Expected the merged existing store to expose exactly the carried-forward and newly added current rows.'
        Assert-True (('merge-001' -in $storeIds) -and ('merge-002' -in $storeIds)) 'Expected the merged existing store to retain the original row and add the new row.'
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

function Test-BulkVulnerabilitySnapshotDownloadMultipartNameUniqueness {
    [CmdletBinding()]
    param()

    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('bulk-download-multipart-' + [guid]::NewGuid().ToString('N'))
    [void](New-Item -Path $tempRoot -ItemType Directory -Force)

    $originalRestMethod = (Get-Command -Name Invoke-RestMethodWithRetry -CommandType Function).ScriptBlock
    $originalWebRequest = (Get-Command -Name Invoke-WebRequestWithRetry -CommandType Function).ScriptBlock

    try {
        $script:MockMultipartExportFiles = @(
            'https://example.invalid/flat-va/2026-01-01/org/json/_RbacGroupId=1/part-000.c000.json.gz'
            'https://example.invalid/flat-va/2026-01-01/org/json/_RbacGroupId=1/part-000.c001.json.gz'
            'https://example.invalid/flat-va/2026-01-02/org/json/_RbacGroupId=1/part-001.c000.json.gz'
        )

        Set-Item -Path Function:Invoke-RestMethodWithRetry -Value {
            param(
                [string]$Uri,
                [string]$Method,
                [hashtable]$Headers,
                [object]$Body,
                [string]$ContentType,
                [int]$MaxRetries,
                [int]$InitialDelayMs,
                [double]$BackoffMultiplier,
                [int]$TimeoutSec,
                [switch]$RetryTransientTransportFailures
            )

            $null = $Uri, $Method, $Headers, $Body, $ContentType, $MaxRetries, $InitialDelayMs, $BackoffMultiplier, $TimeoutSec, $RetryTransientTransportFailures

            return [PSCustomObject]@{
                exportFiles = @($script:MockMultipartExportFiles)
            }
        }

        Set-Item -Path Function:Invoke-WebRequestWithRetry -Value {
            param(
                [string]$Uri,
                [string]$Method,
                [hashtable]$Headers,
                [string]$OutFile,
                [string]$InFile,
                [string]$ContentType,
                [int]$MaxRetries,
                [int]$InitialDelayMs,
                [double]$BackoffMultiplier,
                [int]$TimeoutSec,
                [switch]$RetryTransientTransportFailures
            )

            $null = $Method, $Headers, $InFile, $ContentType, $MaxRetries, $InitialDelayMs, $BackoffMultiplier, $TimeoutSec, $RetryTransientTransportFailures

            [System.IO.File]::WriteAllText($OutFile, $Uri, [System.Text.UTF8Encoding]::new($false))
        }

        $result = Invoke-MdeBulkVulnerabilitySnapshotDownload -Headers @{} -OutputPath $tempRoot -ExportUrl 'https://example.invalid/api/machines/SoftwareVulnerabilitiesExport'
        $downloadedNames = @($result.DownloadedFiles | ForEach-Object { Split-Path -Leaf $_ })

        Assert-True ($result.ExportFileCount -eq 3) 'Expected mocked multipart download to surface three export files.'
        Assert-True ($downloadedNames.Count -eq 3) 'Expected mocked multipart download to emit three local files.'
        Assert-True (@($downloadedNames | Sort-Object -Unique).Count -eq 3) 'Expected multipart download filenames to remain unique.'
        Assert-True ('VulnExport_1_2026-01-01_part_0.json.gz' -in $downloadedNames) 'Expected first multipart file name to include part_0.'
        Assert-True ('VulnExport_1_2026-01-01_part_1.json.gz' -in $downloadedNames) 'Expected second multipart file name to include part_1.'
        Assert-True ('VulnExport_1_2026-01-02_part_0.json.gz' -in $downloadedNames) 'Expected next snapshot date to reset the multipart counter.'
    }
    finally {
        Set-Item -Path Function:Invoke-RestMethodWithRetry -Value $originalRestMethod
        Set-Item -Path Function:Invoke-WebRequestWithRetry -Value $originalWebRequest
        Remove-Variable -Name MockMultipartExportFiles -Scope Script -ErrorAction SilentlyContinue

        if (Test-Path -LiteralPath $tempRoot) {
            Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

function Test-BulkVulnerabilitySnapshotDownloadStagingBehavior {
    [CmdletBinding()]
    param()

    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('bulk-download-staging-' + [guid]::NewGuid().ToString('N'))
    [void](New-Item -Path $tempRoot -ItemType Directory -Force)

    $originalRestMethod = (Get-Command -Name Invoke-RestMethodWithRetry -CommandType Function).ScriptBlock
    $originalWebRequest = (Get-Command -Name Invoke-WebRequestWithRetry -CommandType Function).ScriptBlock

    try {
        $script:CapturedBulkExportUri = ''
        $script:CapturedBulkExportMaxRetries = 0
        $script:CapturedBulkExportTimeoutSec = 0
        $script:CapturedDownloadOutFiles = [System.Collections.Generic.List[string]]::new()
        $script:CapturedDownloadMaxRetries = 0
        $script:CapturedDownloadTimeoutSec = 0

        Set-Item -Path Function:Invoke-RestMethodWithRetry -Value {
            param(
                [string]$Uri,
                [string]$Method,
                [hashtable]$Headers,
                [object]$Body,
                [string]$ContentType,
                [int]$MaxRetries,
                [int]$InitialDelayMs,
                [double]$BackoffMultiplier,
                [int]$TimeoutSec,
                [switch]$RetryTransientTransportFailures
            )

            $null = $Method, $Headers, $Body, $ContentType, $InitialDelayMs, $BackoffMultiplier, $RetryTransientTransportFailures

            $script:CapturedBulkExportUri = $Uri
            $script:CapturedBulkExportMaxRetries = $MaxRetries
            $script:CapturedBulkExportTimeoutSec = $TimeoutSec

            return [PSCustomObject]@{
                exportFiles = @('https://example.invalid/flat-va/2026-01-01/org/json/_RbacGroupId=1/part-000.c000.json.gz?sig=secret')
            }
        }

        Set-Item -Path Function:Invoke-WebRequestWithRetry -Value {
            param(
                [string]$Uri,
                [string]$Method,
                [hashtable]$Headers,
                [string]$OutFile,
                [string]$InFile,
                [string]$ContentType,
                [int]$MaxRetries,
                [int]$InitialDelayMs,
                [double]$BackoffMultiplier,
                [int]$TimeoutSec,
                [switch]$RetryTransientTransportFailures
            )

            $null = $Uri, $Method, $Headers, $InFile, $ContentType, $InitialDelayMs, $BackoffMultiplier, $RetryTransientTransportFailures

            $script:CapturedDownloadOutFiles.Add($OutFile)
            $script:CapturedDownloadMaxRetries = $MaxRetries
            $script:CapturedDownloadTimeoutSec = $TimeoutSec
            [System.IO.File]::WriteAllText($OutFile, 'payload', [System.Text.UTF8Encoding]::new($false))
        }

        $result = Invoke-MdeBulkVulnerabilitySnapshotDownload -Headers @{} -OutputPath $tempRoot -ExportUrl 'https://example.invalid/api/machines/SoftwareVulnerabilitiesExport'
        $finalPath = Join-Path $tempRoot 'VulnExport_1_2026-01-01_part_0.json.gz'
        $stagingPath = Join-Path $tempRoot '.VulnExport_1_2026-01-01_part_0.json.gz.partial'

        Assert-True ($script:CapturedBulkExportUri -eq 'https://example.invalid/api/machines/SoftwareVulnerabilitiesExport?sasValidHours=6') 'Expected bulk export requests to request the maximum supported SAS lifetime.'
        Assert-True ($script:CapturedBulkExportMaxRetries -eq 4) 'Expected bulk export metadata fetches to use the tighter retry budget.'
        Assert-True ($script:CapturedBulkExportTimeoutSec -eq 600) 'Expected bulk export metadata fetches to use the configured timeout.'
        Assert-True ($script:CapturedDownloadOutFiles.Count -eq 1) 'Expected exactly one staged bulk snapshot download.'
        Assert-True ((Split-Path -Path $script:CapturedDownloadOutFiles[0] -Leaf) -eq '.VulnExport_1_2026-01-01_part_0.json.gz.partial') 'Expected bulk snapshot downloads to stage into transient partial files.'
        Assert-True ($script:CapturedDownloadMaxRetries -eq 6) 'Expected bulk snapshot downloads to use the higher download retry budget.'
        Assert-True ($script:CapturedDownloadTimeoutSec -eq 1800) 'Expected bulk snapshot downloads to use the longer download timeout.'
        Assert-True ((Test-IsTransientExportArtifactName -Name '.VulnExport_1_2026-01-01_part_0.json.gz.partial') -eq $true) 'Expected staged download files to be classified as transient export artifacts.'
        Assert-True ((Test-Path -LiteralPath $finalPath -PathType Leaf)) 'Expected the staged vulnerability snapshot to be renamed into the final export file.'
        Assert-True (-not (Test-Path -LiteralPath $stagingPath -PathType Leaf)) 'Expected staging files to be removed after a successful download.'
        Assert-True ($result.DownloadedFiles.Count -eq 1 -and $result.DownloadedFiles[0] -eq $finalPath) 'Expected the downloader to report only the finalized export file.'
    }
    finally {
        Set-Item -Path Function:Invoke-RestMethodWithRetry -Value $originalRestMethod
        Set-Item -Path Function:Invoke-WebRequestWithRetry -Value $originalWebRequest
        Remove-Variable -Name CapturedBulkExportUri -Scope Script -ErrorAction SilentlyContinue
        Remove-Variable -Name CapturedBulkExportMaxRetries -Scope Script -ErrorAction SilentlyContinue
        Remove-Variable -Name CapturedBulkExportTimeoutSec -Scope Script -ErrorAction SilentlyContinue
        Remove-Variable -Name CapturedDownloadOutFiles -Scope Script -ErrorAction SilentlyContinue
        Remove-Variable -Name CapturedDownloadMaxRetries -Scope Script -ErrorAction SilentlyContinue
        Remove-Variable -Name CapturedDownloadTimeoutSec -Scope Script -ErrorAction SilentlyContinue

        if (Test-Path -LiteralPath $tempRoot) {
            Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

function Test-BulkVulnerabilitySnapshotDownloadRetriesEmptyBlob {
    [CmdletBinding()]
    param()

    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('bulk-download-empty-blob-' + [guid]::NewGuid().ToString('N'))
    [void](New-Item -Path $tempRoot -ItemType Directory -Force)

    $originalRestMethod = (Get-Command -Name Invoke-RestMethodWithRetry -CommandType Function).ScriptBlock
    $originalWebRequest = (Get-Command -Name Invoke-WebRequestWithRetry -CommandType Function).ScriptBlock

    try {
        $script:EmptyBlobDownloadAttempts = 0
        $script:EmptyBlobRetrySleeps = [System.Collections.Generic.List[int]]::new()

        Set-Item -Path Function:Invoke-RestMethodWithRetry -Value {
            param(
                [string]$Uri,
                [string]$Method,
                [hashtable]$Headers,
                [object]$Body,
                [string]$ContentType,
                [int]$MaxRetries,
                [int]$InitialDelayMs,
                [double]$BackoffMultiplier,
                [int]$TimeoutSec,
                [switch]$RetryTransientTransportFailures
            )

            $null = $Uri, $Method, $Headers, $Body, $ContentType, $MaxRetries, $InitialDelayMs, $BackoffMultiplier, $TimeoutSec, $RetryTransientTransportFailures

            return [PSCustomObject]@{
                exportFiles = @('https://example.invalid/flat-va/2026-01-01/org/json/_RbacGroupId=1/part-000.c000.json.gz?sig=secret')
            }
        }

        Set-Item -Path Function:Start-Sleep -Value {
            param(
                [int]$Milliseconds
            )

            $script:EmptyBlobRetrySleeps.Add($Milliseconds)
        }

        Set-Item -Path Function:Invoke-WebRequestWithRetry -Value {
            param(
                [string]$Uri,
                [string]$Method,
                [hashtable]$Headers,
                [string]$OutFile,
                [string]$InFile,
                [string]$ContentType,
                [int]$MaxRetries,
                [int]$InitialDelayMs,
                [double]$BackoffMultiplier,
                [int]$TimeoutSec,
                [switch]$RetryTransientTransportFailures
            )

            $null = $Uri, $Method, $Headers, $InFile, $ContentType, $MaxRetries, $InitialDelayMs, $BackoffMultiplier, $TimeoutSec, $RetryTransientTransportFailures

            $script:EmptyBlobDownloadAttempts++
            if ($script:EmptyBlobDownloadAttempts -eq 1) {
                [System.IO.File]::WriteAllText($OutFile, '', [System.Text.UTF8Encoding]::new($false))
                return
            }

            [System.IO.File]::WriteAllText($OutFile, 'payload', [System.Text.UTF8Encoding]::new($false))
        }

        $result = Invoke-MdeBulkVulnerabilitySnapshotDownload -Headers @{} -OutputPath $tempRoot -ExportUrl 'https://example.invalid/api/machines/SoftwareVulnerabilitiesExport'
        $finalPath = Join-Path $tempRoot 'VulnExport_1_2026-01-01_part_0.json.gz'
        $stagingPath = Join-Path $tempRoot '.VulnExport_1_2026-01-01_part_0.json.gz.partial'

        Assert-True ($script:EmptyBlobDownloadAttempts -eq 2) 'Expected zero-byte bulk snapshot downloads to be retried.'
        Assert-True ($script:EmptyBlobRetrySleeps.Count -eq 1 -and $script:EmptyBlobRetrySleeps[0] -eq 2000) 'Expected the first empty bulk snapshot retry to wait for the configured initial delay.'
        Assert-True ((Test-Path -LiteralPath $finalPath -PathType Leaf)) 'Expected a retried empty bulk snapshot download to eventually finalize the export file.'
        Assert-True (-not (Test-Path -LiteralPath $stagingPath -PathType Leaf)) 'Expected empty bulk snapshot retries to clean up their partial files before retrying.'
        Assert-True ($result.DownloadedFiles.Count -eq 1 -and $result.DownloadedFiles[0] -eq $finalPath) 'Expected the downloader to report the finalized export path after retrying an empty blob.'
    }
    finally {
        Set-Item -Path Function:Invoke-RestMethodWithRetry -Value $originalRestMethod
        Set-Item -Path Function:Invoke-WebRequestWithRetry -Value $originalWebRequest
        Remove-Item -Path Function:Start-Sleep -ErrorAction SilentlyContinue
        Remove-Variable -Name EmptyBlobDownloadAttempts -Scope Script -ErrorAction SilentlyContinue
        Remove-Variable -Name EmptyBlobRetrySleeps -Scope Script -ErrorAction SilentlyContinue

        if (Test-Path -LiteralPath $tempRoot) {
            Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

function Test-BulkVulnerabilitySnapshotDownloadEmptyBlobExhaustionBehavior {
    [CmdletBinding()]
    param()

    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('bulk-download-empty-blob-exhaustion-' + [guid]::NewGuid().ToString('N'))
    [void](New-Item -Path $tempRoot -ItemType Directory -Force)

    $originalRestMethod = (Get-Command -Name Invoke-RestMethodWithRetry -CommandType Function).ScriptBlock
    $originalWebRequest = (Get-Command -Name Invoke-WebRequestWithRetry -CommandType Function).ScriptBlock

    try {
        $script:EmptyBlobExhaustionDownloadAttempts = 0
        $script:EmptyBlobExhaustionSleeps = [System.Collections.Generic.List[int]]::new()

        Set-Item -Path Function:Invoke-RestMethodWithRetry -Value {
            param(
                [string]$Uri,
                [string]$Method,
                [hashtable]$Headers,
                [object]$Body,
                [string]$ContentType,
                [int]$MaxRetries,
                [int]$InitialDelayMs,
                [double]$BackoffMultiplier,
                [int]$TimeoutSec,
                [switch]$RetryTransientTransportFailures
            )

            $null = $Uri, $Method, $Headers, $Body, $ContentType, $MaxRetries, $InitialDelayMs, $BackoffMultiplier, $TimeoutSec, $RetryTransientTransportFailures

            return [PSCustomObject]@{
                exportFiles = @('https://example.invalid/flat-va/2026-01-01/org/json/_RbacGroupId=1/part-000.c000.json.gz?sig=secret')
            }
        }

        Set-Item -Path Function:Start-Sleep -Value {
            param(
                [int]$Milliseconds
            )

            $script:EmptyBlobExhaustionSleeps.Add($Milliseconds)
        }

        Set-Item -Path Function:Invoke-WebRequestWithRetry -Value {
            param(
                [string]$Uri,
                [string]$Method,
                [hashtable]$Headers,
                [string]$OutFile,
                [string]$InFile,
                [string]$ContentType,
                [int]$MaxRetries,
                [int]$InitialDelayMs,
                [double]$BackoffMultiplier,
                [int]$TimeoutSec,
                [switch]$RetryTransientTransportFailures
            )

            $null = $Uri, $Method, $Headers, $InFile, $ContentType, $MaxRetries, $InitialDelayMs, $BackoffMultiplier, $TimeoutSec, $RetryTransientTransportFailures

            $script:EmptyBlobExhaustionDownloadAttempts++
            [System.IO.File]::WriteAllText($OutFile, '', [System.Text.UTF8Encoding]::new($false))
        }

        $downloadFailure = $null
        try {
            $null = Invoke-MdeBulkVulnerabilitySnapshotDownload -Headers @{} -OutputPath $tempRoot -ExportUrl 'https://example.invalid/api/machines/SoftwareVulnerabilitiesExport'
        }
        catch {
            $downloadFailure = $_
        }

        $finalPath = Join-Path $tempRoot 'VulnExport_1_2026-01-01_part_0.json.gz'
        $stagingPath = Join-Path $tempRoot '.VulnExport_1_2026-01-01_part_0.json.gz.partial'

        Assert-True ($null -ne $downloadFailure) 'Expected persistently empty bulk snapshot downloads to fail after exhausting retries.'
        Assert-True ($script:EmptyBlobExhaustionDownloadAttempts -eq 4) 'Expected empty bulk snapshot downloads to stop after four attempts.'
        Assert-True (($script:EmptyBlobExhaustionSleeps -join ',') -eq '2000,4000,8000') 'Expected empty bulk snapshot retries to use exponential backoff before the final failure.'
        Assert-True ([string]$downloadFailure.Exception.Message -eq 'Downloaded file is empty: https://example.invalid/flat-va/2026-01-01/org/json/_RbacGroupId=1/part-000.c000.json.gz') 'Expected the empty bulk snapshot failure to surface the sanitized blob URL.'
        Assert-True (-not (Test-Path -LiteralPath $stagingPath -PathType Leaf)) 'Expected empty bulk snapshot retry exhaustion to clean up the staged partial file.'
        Assert-True (-not (Test-Path -LiteralPath $finalPath -PathType Leaf)) 'Expected empty bulk snapshot retry exhaustion to avoid finalizing an output file.'
    }
    finally {
        Set-Item -Path Function:Invoke-RestMethodWithRetry -Value $originalRestMethod
        Set-Item -Path Function:Invoke-WebRequestWithRetry -Value $originalWebRequest
        Remove-Item -Path Function:Start-Sleep -ErrorAction SilentlyContinue
        Remove-Variable -Name EmptyBlobExhaustionDownloadAttempts -Scope Script -ErrorAction SilentlyContinue
        Remove-Variable -Name EmptyBlobExhaustionSleeps -Scope Script -ErrorAction SilentlyContinue

        if (Test-Path -LiteralPath $tempRoot) {
            Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

function Test-BulkVulnerabilitySnapshotDownloadMoveFailureCleanupBehavior {
    [CmdletBinding()]
    param()

    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('bulk-download-move-failure-' + [guid]::NewGuid().ToString('N'))
    [void](New-Item -Path $tempRoot -ItemType Directory -Force)

    $originalRestMethod = (Get-Command -Name Invoke-RestMethodWithRetry -CommandType Function).ScriptBlock
    $originalWebRequest = (Get-Command -Name Invoke-WebRequestWithRetry -CommandType Function).ScriptBlock

    try {
        Set-Item -Path Function:Invoke-RestMethodWithRetry -Value {
            param(
                [string]$Uri,
                [string]$Method,
                [hashtable]$Headers,
                [object]$Body,
                [string]$ContentType,
                [int]$MaxRetries,
                [int]$InitialDelayMs,
                [double]$BackoffMultiplier,
                [int]$TimeoutSec,
                [switch]$RetryTransientTransportFailures
            )

            $null = $Uri, $Method, $Headers, $Body, $ContentType, $MaxRetries, $InitialDelayMs, $BackoffMultiplier, $TimeoutSec, $RetryTransientTransportFailures

            return [PSCustomObject]@{
                exportFiles = @('https://example.invalid/flat-va/2026-01-01/org/json/_RbacGroupId=1/part-000.c000.json.gz?sig=secret')
            }
        }

        Set-Item -Path Function:Invoke-WebRequestWithRetry -Value {
            param(
                [string]$Uri,
                [string]$Method,
                [hashtable]$Headers,
                [string]$OutFile,
                [string]$InFile,
                [string]$ContentType,
                [int]$MaxRetries,
                [int]$InitialDelayMs,
                [double]$BackoffMultiplier,
                [int]$TimeoutSec,
                [switch]$RetryTransientTransportFailures
            )

            $null = $Uri, $Method, $Headers, $InFile, $ContentType, $MaxRetries, $InitialDelayMs, $BackoffMultiplier, $TimeoutSec, $RetryTransientTransportFailures
            [System.IO.File]::WriteAllText($OutFile, 'payload', [System.Text.UTF8Encoding]::new($false))
        }

        $finalPath = Join-Path $tempRoot 'VulnExport_1_2026-01-01_part_0.json.gz'
        $stagingPath = Join-Path $tempRoot '.VulnExport_1_2026-01-01_part_0.json.gz.partial'
        [void](New-Item -Path $finalPath -ItemType Directory -Force)

        $moveFailure = $null
        try {
            $null = Invoke-MdeBulkVulnerabilitySnapshotDownload -Headers @{} -OutputPath $tempRoot -ExportUrl 'https://example.invalid/api/machines/SoftwareVulnerabilitiesExport'
        }
        catch {
            $moveFailure = $_
        }

        Assert-True ($null -ne $moveFailure) 'Expected a conflicting move target to surface a failure.'
        Assert-True ((Test-Path -LiteralPath $finalPath -PathType Container)) 'Expected the conflicting destination directory to remain in place.'
        Assert-True (-not (Test-Path -LiteralPath $stagingPath -PathType Leaf)) 'Expected move failures to clean up the staged partial file.'
    }
    finally {
        Set-Item -Path Function:Invoke-RestMethodWithRetry -Value $originalRestMethod
        Set-Item -Path Function:Invoke-WebRequestWithRetry -Value $originalWebRequest

        if (Test-Path -LiteralPath $tempRoot) {
            Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

function Test-BulkVulnerabilitySnapshotDownloadCleanupBehavior {
    [CmdletBinding()]
    param()

    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('bulk-download-staging-failure-' + [guid]::NewGuid().ToString('N'))
    [void](New-Item -Path $tempRoot -ItemType Directory -Force)

    $originalRestMethod = (Get-Command -Name Invoke-RestMethodWithRetry -CommandType Function).ScriptBlock
    $originalWebRequest = (Get-Command -Name Invoke-WebRequestWithRetry -CommandType Function).ScriptBlock

    try {
        Set-Item -Path Function:Invoke-RestMethodWithRetry -Value {
            param(
                [string]$Uri,
                [string]$Method,
                [hashtable]$Headers,
                [object]$Body,
                [string]$ContentType,
                [int]$MaxRetries,
                [int]$InitialDelayMs,
                [double]$BackoffMultiplier,
                [int]$TimeoutSec,
                [switch]$RetryTransientTransportFailures
            )

            $null = $Uri, $Method, $Headers, $Body, $ContentType, $MaxRetries, $InitialDelayMs, $BackoffMultiplier, $TimeoutSec, $RetryTransientTransportFailures

            return [PSCustomObject]@{
                exportFiles = @('https://example.invalid/flat-va/2026-01-01/org/json/_RbacGroupId=1/part-000.c000.json.gz?sig=secret')
            }
        }

        Set-Item -Path Function:Invoke-WebRequestWithRetry -Value {
            param(
                [string]$Uri,
                [string]$Method,
                [hashtable]$Headers,
                [string]$OutFile,
                [string]$InFile,
                [string]$ContentType,
                [int]$MaxRetries,
                [int]$InitialDelayMs,
                [double]$BackoffMultiplier,
                [int]$TimeoutSec,
                [switch]$RetryTransientTransportFailures
            )

            $null = $Uri, $Method, $Headers, $InFile, $ContentType, $MaxRetries, $InitialDelayMs, $BackoffMultiplier, $TimeoutSec, $RetryTransientTransportFailures

            [System.IO.File]::WriteAllText($OutFile, 'partial', [System.Text.UTF8Encoding]::new($false))
            throw [System.TimeoutException]::new('The download timed out')
        }

        $downloadFailure = $null
        try {
            $null = Invoke-MdeBulkVulnerabilitySnapshotDownload -Headers @{} -OutputPath $tempRoot -ExportUrl 'https://example.invalid/api/machines/SoftwareVulnerabilitiesExport'
        }
        catch {
            $downloadFailure = $_
        }

        Assert-True ($null -ne $downloadFailure) 'Expected staged bulk snapshot downloads to surface failures when the download never completes.'
        Assert-True (-not (Test-Path -LiteralPath (Join-Path $tempRoot '.VulnExport_1_2026-01-01_part_0.json.gz.partial') -PathType Leaf)) 'Expected failed staged downloads to remove their partial files.'
        Assert-True (-not (Test-Path -LiteralPath (Join-Path $tempRoot 'VulnExport_1_2026-01-01_part_0.json.gz') -PathType Leaf)) 'Expected failed staged downloads to avoid leaving behind a finalized snapshot file.'
    }
    finally {
        Set-Item -Path Function:Invoke-RestMethodWithRetry -Value $originalRestMethod
        Set-Item -Path Function:Invoke-WebRequestWithRetry -Value $originalWebRequest

        if (Test-Path -LiteralPath $tempRoot) {
            Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

function Test-VulnCurrentFileRejectsDuplicateId {
    [CmdletBinding()]
    param()

    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('vuln-current-duplicate-' + [guid]::NewGuid().ToString('N'))
    [void](New-Item -Path $tempRoot -ItemType Directory -Force)

    try {
        $currentPath = Get-VulnCurrentPath -BasePath $tempRoot
        Write-NdjsonRecordsFile -Path $currentPath -Records @(
            (Get-TestVulnRow -Id 'duplicate-001' -CveId 'CVE-2026-0101' -SnapshotDate '2026-03-20' -Version '1.0.0'),
            (Get-TestVulnRow -Id 'duplicate-001' -CveId 'CVE-2026-0101' -SnapshotDate '2026-03-21' -Version '1.0.1')
        )

        $duplicateFailure = $null
        try {
            $null = Test-VulnCurrentFile -Path $currentPath
        }
        catch {
            $duplicateFailure = $_
        }

        Assert-True ($null -ne $duplicateFailure) 'Expected current-file validation to reject duplicate Id values.'
        Assert-True (([string]$duplicateFailure).Contains("duplicate Id 'duplicate-001'")) 'Expected duplicate current-file validation failure to mention the repeated Id.'
    }
    finally {
        if (Test-Path -LiteralPath $tempRoot) {
            Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

function Test-RepairVulnHistoryLayoutSkipsCanonicalQuarterlyStore {
    [CmdletBinding()]
    param()

    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('repair-vuln-layout-skip-' + [guid]::NewGuid().ToString('N'))
    [void](New-Item -Path $tempRoot -ItemType Directory -Force)

    try {
        $periodKey = '2026Q1'
        $historyPath = Get-VulnHistoryPath -BasePath $tempRoot -PeriodKey $periodKey
        $historyRowsPath = Get-VulnHistoryRowsPath -BasePath $tempRoot -PeriodKey $periodKey
        $historyDocument = Get-TestQuarterlyHistoryDocument -PeriodKey $periodKey -Snapshots @(
            [PSCustomObject]@{
                date = '2026-03-20'
                closed = @(
                    [PSCustomObject]@{
                        reason = 'removed'
                        row = (Get-TestVulnRow -Id 'canonical-q1' -CveId 'CVE-2026-0100' -SnapshotDate '2026-03-20' -Version '1.0.0')
                    }
                )
            }
        )

        Write-VulnHistoryDocument -Path $historyPath -HistoryDocument $historyDocument
        Write-VulnHistoryRowsFile -Path $historyRowsPath -HistoryDocument $historyDocument

        $originalHistoryContent = Read-GzipTextFile -Path $historyPath
        $originalRowsContent = Read-GzipTextFile -Path $historyRowsPath
        $requiresRepair = Test-VulnStoreRequiresCanonicalRepair -BasePath $tempRoot

        $repairedPeriods = Repair-VulnHistoryLayout -BasePath $tempRoot

        Assert-True ($requiresRepair -eq $false) 'Expected valid canonical quarterly history layout to avoid repair.'
        Assert-True ($repairedPeriods -eq 1) 'Expected canonical quarterly history layout to be treated as already repaired.'
        Assert-True ((Read-GzipTextFile -Path $historyPath) -eq $originalHistoryContent) 'Expected canonical quarterly history file to be left untouched.'
        Assert-True ((Read-GzipTextFile -Path $historyRowsPath) -eq $originalRowsContent) 'Expected canonical quarterly history rows sidecar to be left untouched.'
    }
    finally {
        if (Test-Path -LiteralPath $tempRoot) {
            Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

function Test-VulnStoreRequiresCanonicalRepairDetectsMalformedQuarterlyHistory {
    [CmdletBinding()]
    param()

    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('repair-vuln-layout-malformed-' + [guid]::NewGuid().ToString('N'))
    [void](New-Item -Path $tempRoot -ItemType Directory -Force)

    try {
        $periodKey = '2026Q1'
        $historyPath = Get-VulnHistoryPath -BasePath $tempRoot -PeriodKey $periodKey
        $historyRowsPath = Get-VulnHistoryRowsPath -BasePath $tempRoot -PeriodKey $periodKey

        Write-GzipTextFile -Path $historyPath -Content 'skip-deserialize-sentinel'
        Write-NdjsonRecordsFile -Path $historyRowsPath -Records @((Get-TestVulnRow -Id 'malformed-q1' -CveId 'CVE-2026-0109' -SnapshotDate '2026-03-20' -Version '1.0.9'))

        Assert-True ((Test-VulnStoreRequiresCanonicalRepair -BasePath $tempRoot) -eq $true) 'Expected malformed quarterly history content to require repair.'
    }
    finally {
        if (Test-Path -LiteralPath $tempRoot) {
            Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

function Test-RepairVulnHistoryLayoutRebuildsCanonicalQuarterlyRowSidecar {
    [CmdletBinding()]
    param()

    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('repair-vuln-layout-sidecar-' + [guid]::NewGuid().ToString('N'))
    [void](New-Item -Path $tempRoot -ItemType Directory -Force)

    try {
        $periodKey = '2026Q1'
        $historyPath = Get-VulnHistoryPath -BasePath $tempRoot -PeriodKey $periodKey
        $historyRowsPath = Get-VulnHistoryRowsPath -BasePath $tempRoot -PeriodKey $periodKey
        $expectedRow = Get-TestVulnRow -Id 'canonical-row-001' -CveId 'CVE-2026-0110' -SnapshotDate '2026-03-20' -Version '1.1.0'
        $historyDocument = Get-TestQuarterlyHistoryDocument -PeriodKey $periodKey -Snapshots @(
            [PSCustomObject]@{
                date = '2026-03-20'
                closed = @(
                    [PSCustomObject]@{
                        reason = 'changed'
                        row = $expectedRow
                        replacementId = 'canonical-row-001'
                    }
                )
            }
        )

        Write-VulnHistoryDocument -Path $historyPath -HistoryDocument $historyDocument
        Write-NdjsonRecordsFile -Path $historyRowsPath -Records @((Get-TestVulnRow -Id 'canonical-row-stale' -CveId 'CVE-2026-0999' -SnapshotDate '2026-03-20' -Version '9.9.9'))

        Assert-True ((Test-VulnStoreRequiresCanonicalRepair -BasePath $tempRoot) -eq $true) 'Expected mismatched quarterly rows sidecar to require repair.'

        $repairedPeriods = Repair-VulnHistoryLayout -BasePath $tempRoot
        $repairedRows = @(Read-VulnNdjsonRecordsFromPath -Path $historyRowsPath)

        Assert-True ($repairedPeriods -eq 1) 'Expected canonical quarterly rows sidecar repair to preserve one quarterly period.'
        Assert-True ($repairedRows.Count -eq 1) 'Expected repaired quarterly rows sidecar to contain one row.'
        Assert-True ([string](Get-VulnPropertyValue -InputObject $repairedRows[0] -Name 'Id') -eq 'canonical-row-001') 'Expected repaired quarterly rows sidecar to be rebuilt from the history document.'
    }
    finally {
        if (Test-Path -LiteralPath $tempRoot) {
            Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

function Test-RepairVulnHistoryLayoutRepairsLegacyYearlyStore {
    [CmdletBinding()]
    param()

    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('repair-vuln-layout-legacy-' + [guid]::NewGuid().ToString('N'))
    [void](New-Item -Path $tempRoot -ItemType Directory -Force)

    try {
        $legacyHistoryPath = Join-Path $tempRoot 'VulnHistory_2026.json.gz'
        $legacyDocument = [PSCustomObject]@{
            year = 2026
            latestDate = '2026-04-02'
            snapshots = @(
                [PSCustomObject]@{
                    date = '2026-01-02'
                    closed = @(
                        [PSCustomObject]@{
                            reason = 'removed'
                            row = (Get-TestVulnRow -Id 'legacy-q1' -CveId 'CVE-2026-0101' -SnapshotDate '2026-01-02' -Version '1.0.0')
                        }
                    )
                },
                [PSCustomObject]@{
                    date = '2026-04-02'
                    closed = @(
                        [PSCustomObject]@{
                            reason = 'changed'
                            row = (Get-TestVulnRow -Id 'legacy-q2' -CveId 'CVE-2026-0102' -SnapshotDate '2026-04-02' -Version '2.0.0')
                            replacementId = 'legacy-q2'
                        }
                    )
                }
            )
        }

        Write-VulnHistoryDocument -Path $legacyHistoryPath -HistoryDocument $legacyDocument

        $repairedPeriods = Repair-VulnHistoryLayout -BasePath $tempRoot

        Assert-True ($repairedPeriods -eq 2) 'Expected yearly legacy history to split into two quarterly periods.'
        Assert-True ((Test-Path -LiteralPath (Get-VulnHistoryPath -BasePath $tempRoot -PeriodKey '2026Q1') -PathType Leaf)) 'Expected repaired Q1 history file to exist.'
        Assert-True ((Test-Path -LiteralPath (Get-VulnHistoryPath -BasePath $tempRoot -PeriodKey '2026Q2') -PathType Leaf)) 'Expected repaired Q2 history file to exist.'
        Assert-True ((Test-Path -LiteralPath (Get-VulnHistoryRowsPath -BasePath $tempRoot -PeriodKey '2026Q1') -PathType Leaf)) 'Expected repaired Q1 history rows file to exist.'
        Assert-True ((Test-Path -LiteralPath (Get-VulnHistoryRowsPath -BasePath $tempRoot -PeriodKey '2026Q2') -PathType Leaf)) 'Expected repaired Q2 history rows file to exist.'
        Assert-True (-not (Test-Path -LiteralPath $legacyHistoryPath -PathType Leaf)) 'Expected legacy yearly history file to be removed after repair.'

        $q1Rows = @(Read-VulnNdjsonRecordsFromPath -Path (Get-VulnHistoryRowsPath -BasePath $tempRoot -PeriodKey '2026Q1'))
        $q2Rows = @(Read-VulnNdjsonRecordsFromPath -Path (Get-VulnHistoryRowsPath -BasePath $tempRoot -PeriodKey '2026Q2'))
        Assert-True ($q1Rows.Count -eq 1) 'Expected repaired Q1 history to retain one closed row.'
        Assert-True ($q2Rows.Count -eq 1) 'Expected repaired Q2 history to retain one closed row.'
        Assert-True ([string](Get-VulnPropertyValue -InputObject $q1Rows[0] -Name 'Id') -eq 'legacy-q1') 'Expected repaired Q1 history row Id to be preserved.'
        Assert-True ([string](Get-VulnPropertyValue -InputObject $q2Rows[0] -Name 'Id') -eq 'legacy-q2') 'Expected repaired Q2 history row Id to be preserved.'
    }
    finally {
        if (Test-Path -LiteralPath $tempRoot) {
            Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

function Test-VulnHistoryFileValidatesQuarterlyHistoryDocument {
    [CmdletBinding()]
    param()

    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('history-file-validator-' + [guid]::NewGuid().ToString('N'))
    [void](New-Item -Path $tempRoot -ItemType Directory -Force)

    try {
        $periodKey = '2026Q1'
        $historyPath = Get-VulnHistoryPath -BasePath $tempRoot -PeriodKey $periodKey
        $historyDocument = Get-TestQuarterlyHistoryDocument -PeriodKey $periodKey -Snapshots @(
            [PSCustomObject]@{
                date = '2026-01-15'
                closed = @(
                    [PSCustomObject]@{
                        reason = 'removed'
                        row = (Get-TestVulnRow -Id 'validator-q1-a' -CveId 'CVE-2026-0120' -SnapshotDate '2026-01-15' -Version '1.2.0')
                    }
                )
            },
            [PSCustomObject]@{
                date = '2026-03-20'
                closed = @(
                    [PSCustomObject]@{
                        reason = 'changed'
                        row = (Get-TestVulnRow -Id 'validator-q1-b' -CveId 'CVE-2026-0121' -SnapshotDate '2026-03-20' -Version '1.2.1')
                        replacementId = 'validator-q1-b'
                    }
                )
            }
        )

        Write-VulnHistoryDocument -Path $historyPath -HistoryDocument $historyDocument

        Assert-True ((Test-VulnHistoryFile -Path $historyPath) -eq 2) 'Expected deep quarterly history validation to accept JObject-backed history documents.'
    }
    finally {
        if (Test-Path -LiteralPath $tempRoot) {
            Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

function Test-VulnCanonicalSignatureStability {
    [CmdletBinding()]
    param()

    $baseline = Get-TestVulnRow -Id 'stable-001' -CveId 'CVE-2026-0003' -SnapshotDate '2026-03-17' -Version '1.0.0'
    $variant = Get-TestVulnRow -Id 'stable-001' -CveId 'CVE-2026-0003' -SnapshotDate '2026-03-19' -Version '1.0.0'
    $variant.OSVersion = '10.0.99999'
    $variant.RecommendedSecurityUpdate = 'KB999999'
    $variant.RecommendedSecurityUpdateId = 'KB999999'
    $variant.RecommendedSecurityUpdateUrl = 'https://example.invalid/kb999999'
    $variant.CveBatchTitle = 'March 2026 Security Updates'
    $variant.CveBatchUrl = 'https://example.invalid/batch/mar-2026'
    $variant.DiskPaths = @('C:\Program Files\Legacy Agent\alt.exe')
    $variant.RegistryPaths = @('HKLM\Software\Contoso\LegacyAgentV2')

    $baselineSignature = Get-VulnCanonicalRowSignature -Row $baseline
    $variantSignature = Get-VulnCanonicalRowSignature -Row $variant

    Assert-True ($baselineSignature -eq $variantSignature) 'Canonical vulnerability signature should ignore volatile metadata changes for the same Id.'
}

function Test-MergeVulnObservedWindowRows {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '')]
    [CmdletBinding()]
    param()

    $first = Get-TestVulnRow -Id 'merge-001' -CveId 'CVE-2026-0004' -SnapshotDate '2026-03-17' -Version '1.0.0'
    $second = Get-TestVulnRow -Id 'merge-001' -CveId 'CVE-2026-0004' -SnapshotDate '2026-03-19' -Version '1.0.0'
    $second.RecommendedSecurityUpdate = 'KB000099'
    $second.RecommendedSecurityUpdateId = 'KB000099'
    $third = Get-TestVulnRow -Id 'merge-001' -CveId 'CVE-2026-0004' -SnapshotDate '2026-03-23' -Version '1.0.0'
    $third.RecommendedSecurityUpdate = 'KB000123'
    $third.RecommendedSecurityUpdateId = 'KB000123'
    $sameDayDuplicate = Get-TestVulnRow -Id 'merge-001' -CveId 'CVE-2026-0004' -SnapshotDate '2026-03-19' -Version '1.0.0'
    $sameDayDuplicate.RecommendedSecurityUpdate = 'KB000100'
    $sameDayDuplicate.RecommendedSecurityUpdateId = 'KB000100'
    $otherId = Get-TestVulnRow -Id 'merge-002' -CveId 'CVE-2026-0005' -SnapshotDate '2026-03-19' -Version '2.0.0'

    $merged = @(Merge-VulnObservedWindowRows -Rows @($first, $second, $third, $sameDayDuplicate, $otherId))
    $mergeIdRows = @($merged | Where-Object { $_.Id -eq 'merge-001' } | Sort-Object FirstSeenTimestamp, LastSeenTimestamp)

    Assert-True ($mergeIdRows.Count -eq 2) 'Expected same-Id windows with overlap or a one-day gap to collapse into two observation windows.'
    Assert-True ($mergeIdRows[0].FirstSeenTimestamp -eq '2026-03-17') 'Expected merged window to preserve the earliest first-seen date.'
    Assert-True ($mergeIdRows[0].LastSeenTimestamp -eq '2026-03-19') 'Expected merged window to span the one-day observation gap.'
    Assert-True ($mergeIdRows[0].RecommendedSecurityUpdate -eq 'KB000100') 'Expected merged window to retain the latest row metadata.'
    Assert-True ($mergeIdRows[1].FirstSeenTimestamp -eq '2026-03-23') 'Expected distant reappearance to remain a separate window.'
    Assert-True ($mergeIdRows[1].LastSeenTimestamp -eq '2026-03-23') 'Expected distant reappearance to remain a separate window.'
}

function Test-ReadNormalizedVulnStoreRow {
    [CmdletBinding()]
    param()

    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('normalized-vuln-reader-' + [guid]::NewGuid().ToString('N'))
    [void](New-Item -Path $tempRoot -ItemType Directory -Force)

    try {
        $historyRow = Get-TestVulnRow -Id 'normalized-001' -CveId 'CVE-2026-0006' -SnapshotDate '2026-03-17' -Version '1.0.0'
        $currentRow = Get-TestVulnRow -Id 'normalized-001' -CveId 'CVE-2026-0006' -SnapshotDate '2026-03-19' -Version '1.0.0'
        $currentRow.RecommendedSecurityUpdate = 'KB000777'
        $currentRow.RecommendedSecurityUpdateId = 'KB000777'

        Write-NdjsonRecordsFile -Path (Get-VulnCurrentPath -BasePath $tempRoot) -Records @($currentRow)
        [void](New-Item -Path (Get-VulnHistoryPath -BasePath $tempRoot -PeriodKey '2026Q1') -ItemType File -Force)
        Write-NdjsonRecordsFile -Path (Get-VulnHistoryRowsPath -BasePath $tempRoot -PeriodKey '2026Q1') -Records @($historyRow)

        $normalizedRows = @(Read-NormalizedVulnStoreRow -BasePath $tempRoot)

        Assert-True ($normalizedRows.Count -eq 1) 'Expected normalized vuln reader to collapse overlapping same-Id windows from store history.'
        Assert-True ($normalizedRows[0].FirstSeenTimestamp -eq '2026-03-17') 'Expected normalized vuln reader to preserve the earliest first-seen date.'
        Assert-True ($normalizedRows[0].LastSeenTimestamp -eq '2026-03-19') 'Expected normalized vuln reader to preserve the latest last-seen date.'
        Assert-True ($normalizedRows[0].RecommendedSecurityUpdate -eq 'KB000777') 'Expected normalized vuln reader to retain the newest row metadata.'
    }
    finally {
        if (Test-Path -LiteralPath $tempRoot) {
            Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

function Test-ResolveNormalizedLookupIndexListHandlesScalarAndCollectionValues {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '', Justification = 'Regression test name intentionally covers both scalar and collection values.')]
    [CmdletBinding()]
    param()

    $lookupList = [System.Collections.Generic.List[string]]::new()
    $indexMap = @{}

    $singleValueIndices = Resolve-NormalizedLookupIndexList -Values 'C:\Windows\System32\kernel32.dll' -List $lookupList -IndexMap $indexMap
    $mixedValueIndices = Resolve-NormalizedLookupIndexList -Values @('C:\Windows\System32\kernel32.dll', $null, 'HKLM\Software\Microsoft\Windows') -List $lookupList -IndexMap $indexMap
    $emptyValueIndices = Resolve-NormalizedLookupIndexList -Values @() -List $lookupList -IndexMap $indexMap

    Assert-True ($singleValueIndices.Count -eq 1) 'Expected scalar lookup input to resolve to a single lookup index.'
    Assert-True ($singleValueIndices[0] -eq 0) 'Expected the first scalar lookup input to create lookup index 0.'
    Assert-True ($mixedValueIndices.Count -eq 2) 'Expected mixed lookup input to skip nulls and keep two resolved values.'
    Assert-True ($mixedValueIndices[0] -eq 0) 'Expected repeated lookup values to reuse the existing lookup index.'
    Assert-True ($mixedValueIndices[1] -eq 1) 'Expected a new lookup value to receive the next lookup index.'
    Assert-True ($lookupList.Count -eq 2) 'Expected lookup storage to contain only the two unique non-null values.'
    Assert-True ($null -eq $emptyValueIndices) 'Expected empty lookup input to return no indices.'
}

function Test-ResolveNormalizedInventoryLookupSkipsEmptyInventoryData {
    [CmdletBinding()]
    param()

    $context = Get-NormalizationContext
    $emptyInventoryIndex = Resolve-NormalizedInventoryLookup `
        -DeviceId 'device-001' `
        -SoftwareVendor 'contoso' `
        -SoftwareName 'legacy_agent' `
        -SoftwareVersion '6.0.0' `
        -Context $context

    $inventoryKey = Get-AdvancedHuntingInventoryMatchKey -DeviceId 'device-001' -SoftwareVendor 'contoso' -SoftwareName 'legacy_agent' -SoftwareVersion '6.0.0'
    $context.AdvancedHuntingInventoryData = @{
        $inventoryKey = [PSCustomObject]@{
            ProductCodeCpe = 'cpe:/a:contoso:legacy_agent:6.0.0'
            EndOfSupportStatus = 'supported'
            EndOfSupportDate = '2027-10-01'
        }
    }

    $populatedInventoryIndex = Resolve-NormalizedInventoryLookup `
        -DeviceId 'device-001' `
        -SoftwareVendor 'contoso' `
        -SoftwareName 'legacy_agent' `
        -SoftwareVersion '6.0.0' `
        -Context $context

    $compactIdentityInventoryIndex = Resolve-NormalizedInventoryLookup `
        -DeviceId 'device-001' `
        -SoftwareIdentityKey 'contoso|legacy_agent|6.0.0' `
        -Context $context

    Assert-True ($emptyInventoryIndex -eq -1) 'Expected empty inventory data to skip normalized inventory lookup creation.'
    Assert-True ($context.Lookups.inventory.Count -eq 1) 'Expected only the populated inventory lookup to materialize in the lookup table.'
    Assert-True ($populatedInventoryIndex -eq 0) 'Expected populated inventory data to create the first normalized inventory lookup.'
    Assert-True ($compactIdentityInventoryIndex -eq $populatedInventoryIndex) 'Expected the compact software identity key to resolve the same normalized inventory lookup.'
    Assert-True ([string]$context.Lookups.inventory[0].cpe -eq 'cpe:/a:contoso:legacy_agent:6.0.0') 'Expected populated inventory lookup to preserve ProductCodeCpe.'
}

function Test-AddNormalizedCveUsesStableSeverityIndexLookup {
    [CmdletBinding()]
    param()

    $context = Get-NormalizationContext

    $highCveIndex = Add-NormalizedCve -CveId 'CVE-2026-1001' -CvssScore '9.0' -SeverityLevel 'High' -ExploitabilityLevel 'High' -CveUrl 'https://example.test/CVE-2026-1001' -CveBatchTitle 'baseline' -Context $context
    $noneCveIndex = Add-NormalizedCve -CveId 'CVE-2026-1002' -CvssScore '0.0' -SeverityLevel 'None' -ExploitabilityLevel 'Unproven' -CveUrl 'https://example.test/CVE-2026-1002' -CveBatchTitle 'baseline' -Context $context
    $unknownCveIndex = Add-NormalizedCve -CveId 'CVE-2026-1003' -CvssScore '5.0' -SeverityLevel 'Unexpected' -ExploitabilityLevel 'ProofOfConcept' -CveUrl 'https://example.test/CVE-2026-1003' -CveBatchTitle 'baseline' -Context $context

    Assert-True ($context.Lookups.cves[$highCveIndex].sv -eq 1) 'Expected High severity CVEs to serialize severity lookup index 1.'
    Assert-True ($context.Lookups.cves[$noneCveIndex].sv -eq 4) 'Expected None severity CVEs to serialize severity lookup index 4.'
    Assert-True ($context.Lookups.cves[$unknownCveIndex].sv -eq -1) 'Expected unknown severity CVEs to preserve the fallback lookup index.'
}

function Test-GetNormalizedRecordLookupHandlesScalarPathInputs {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '', Justification = 'Regression test name intentionally refers to multiple path inputs.')]
    [CmdletBinding()]
    param()

    $context = Get-NormalizationContext

    $recordLookup = Get-NormalizedRecordLookup `
        -DeviceId 'device-001' `
        -DeviceName 'device-001.contoso.com' `
        -GroupName 'Pilot' `
        -OsPlatform 'Windows10' `
        -OsVersion '10.0.26100' `
        -MachineTags @('Pilot') `
        -SoftwareVendor 'contoso' `
        -SoftwareName 'legacy_agent' `
        -RecommendationReference '' `
        -CveId 'CVE-2026-1004' `
        -CvssScore '6.5' `
        -SeverityLevel 'Medium' `
        -ExploitabilityLevel 'High' `
        -CveUrl 'https://example.test/CVE-2026-1004' `
        -CveBatchTitle 'baseline' `
        -RecommendedSecurityUpdate '' `
        -RecommendedSecurityUpdateId '' `
        -RecommendedSecurityUpdateUrl '' `
        -SoftwareVersion '6.0.0' `
        -DiskPaths 'C:\Windows\System32\kernel32.dll' `
        -RegistryPaths 'HKLM\Software\Microsoft\Windows' `
        -SecurityUpdateAvailable $false `
        -Context $context

    Assert-True ($recordLookup.ContentLookup.dp.Count -eq 1) 'Expected scalar disk path input to resolve to a single normalized lookup index.'
    Assert-True ($recordLookup.ContentLookup.dp[0] -eq 0) 'Expected scalar disk path input to create lookup index 0.'
    Assert-True ($recordLookup.ContentLookup.rp.Count -eq 1) 'Expected scalar registry path input to resolve to a single normalized lookup index.'
    Assert-True ($recordLookup.ContentLookup.rp[0] -eq 0) 'Expected scalar registry path input to create lookup index 0.'
    Assert-True ($context.Lookups.diskPaths.Count -eq 1) 'Expected scalar disk path input to materialize one disk path lookup.'
    Assert-True ($context.Lookups.regPaths.Count -eq 1) 'Expected scalar registry path input to materialize one registry path lookup.'
}

function Test-InvokeNormalizationProgressCallbackUsesCountAndHeartbeat {
    [CmdletBinding()]
    param()

    $progressEvents = [System.Collections.Generic.List[object]]::new()
    $progressState = New-NormalizationProgressState -ProgressInterval 3 -HeartbeatIntervalSeconds 60 -CheckInterval 1

    Invoke-NormalizationProgressCallback -State $progressState -Count 1 -Callback {
        param($ProgressEvent)

        $progressEvents.Add($ProgressEvent) | Out-Null
    }
    Assert-True ($progressEvents.Count -eq 0) 'Expected normalization progress callback to remain quiet before the progress interval is reached.'

    Invoke-NormalizationProgressCallback -State $progressState -Count 3 -Callback {
        param($ProgressEvent)

        $progressEvents.Add($ProgressEvent) | Out-Null
    }

    Assert-True ($progressEvents.Count -eq 1) 'Expected normalization progress callback to fire when the progress interval is reached.'
    Assert-True ([string]$progressEvents[0].Kind -eq 'progress') 'Expected normalization progress callback events to identify progress updates.'
    Assert-True ([string]$progressEvents[0].MarkerType -eq 'progress') 'Expected interval-driven normalization callback events to be labeled as progress updates.'
    Assert-True ([long]$progressEvents[0].Count -eq 3) 'Expected normalization progress callback events to carry the processed row count.'

    $heartbeatEvents = [System.Collections.Generic.List[object]]::new()
    $heartbeatState = [PSCustomObject]@{
        ProgressInterval = 100
        HeartbeatIntervalSeconds = 60
        CheckInterval = 1
        Stopwatch = [PSCustomObject]@{
            Elapsed = [TimeSpan]::FromSeconds(61)
        }
        LastHeartbeatSecond = -1
    }

    Invoke-NormalizationProgressCallback -State $heartbeatState -Count 1 -Callback {
        param($ProgressEvent)

        $heartbeatEvents.Add($ProgressEvent) | Out-Null
    }

    Assert-True ($heartbeatEvents.Count -eq 1) 'Expected normalization progress callback to emit a heartbeat event after the heartbeat interval elapses.'
    Assert-True ([string]$heartbeatEvents[0].MarkerType -eq 'heartbeat') 'Expected elapsed-time normalization callback events to be labeled as heartbeats.'
}

function Test-ConvertToNormalizedDataReportsContentStoreNormalizationPhase {
    [CmdletBinding()]
    param()

    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('normalized-progress-callback-' + [guid]::NewGuid().ToString('N'))
    [void](New-Item -Path $tempRoot -ItemType Directory -Force)
    $outputPath = Join-Path $tempRoot 'normalized-vulns.json'

    try {
        $currentRow = Get-TestVulnRow -Id 'progress-callback-001' -CveId 'CVE-2026-0999' -SnapshotDate '2026-03-20' -Version '1.0.0'
        $historyRow = Get-TestVulnRow -Id 'progress-callback-002' -CveId 'CVE-2026-1000' -SnapshotDate '2026-03-18' -Version '1.0.1'
        Write-NdjsonRecordsFile -Path (Get-VulnCurrentPath -BasePath $tempRoot) -Records @($currentRow)
        [void](New-Item -Path (Get-VulnHistoryPath -BasePath $tempRoot -PeriodKey '2026Q1') -ItemType File -Force)
        Write-NdjsonRecordsFile -Path (Get-VulnHistoryRowsPath -BasePath $tempRoot -PeriodKey '2026Q1') -Records @($historyRow)
        Publish-VulnContentStoreUnlocked -BasePath $tempRoot

        $events = [System.Collections.Generic.List[object]]::new()
        $result = ConvertTo-NormalizedData -DataPath $tempRoot -VulnOutputPath $outputPath -Machines @{} -AdvancedHuntingData @{} -SkipObservedWindowMerge -NormalizationProgressCallback {
            param($ProgressEvent)

            $events.Add([PSCustomObject]@{
                Kind = [string]$ProgressEvent.Kind
                Phase = [string]$ProgressEvent.Phase
                Message = [string]$ProgressEvent.Message
                }) | Out-Null
        }

        Assert-True ($result.VulnCount -eq 2) 'Expected content-store normalization to preserve both onboarded test rows.'
        Assert-True ($events.Count -gt 0) 'Expected ConvertTo-NormalizedData to forward normalization callback events when a callback is provided.'

        $phaseNames = @($events | Where-Object { [string]$_.Kind -eq 'phase' } | ForEach-Object { [string]$_.Phase })
        Assert-True ('LoadContentStoreDeviceProfiles' -in $phaseNames) 'Expected content-store normalization to report device-profile loading through the normalization callback.'
        Assert-True ('LoadContentStoreTemplates' -in $phaseNames) 'Expected content-store normalization to report template loading through the normalization callback.'
        Assert-True ('StreamContentStoreRefs' -in $phaseNames) 'Expected content-store normalization to report ref streaming through the normalization callback.'
        Assert-True ('StreamContentStoreCurrentRefs' -in $phaseNames) 'Expected content-store normalization to split current ref streaming into its own normalization phase.'
        Assert-True ('StreamContentStoreHistoryRefs' -in $phaseNames) 'Expected content-store normalization to split history ref streaming into its own normalization phase.'
    }
    finally {
        if (Test-Path -LiteralPath $tempRoot) {
            Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

function Test-ConvertToNormalizedDataUsesStableDeviceIdFallback {
    [CmdletBinding()]
    param()

    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('normalized-device-key-' + [guid]::NewGuid().ToString('N'))
    [void](New-Item -Path $tempRoot -ItemType Directory -Force)
    $outputPath = Join-Path $tempRoot 'normalized-vulns.json'

    try {
        $first = Get-TestVulnRow -Id 'device-fallback-001' -CveId 'CVE-2026-0007' -SnapshotDate '2026-03-20' -Version '1.0.0'
        $second = Get-TestVulnRow -Id 'device-fallback-002' -CveId 'CVE-2026-0008' -SnapshotDate '2026-03-20' -Version '1.1.0'
        $second.DeviceName = 'device01-renamed.contoso.com'
        $second.RbacGroupName = 'Pilot'
        $second.OSVersion = '10.0.99999'

        Write-NdjsonRecordsFile -Path (Get-VulnCurrentPath -BasePath $tempRoot) -Records @($first, $second)

        $result = ConvertTo-NormalizedData -DataPath $tempRoot -VulnOutputPath $outputPath -Machines @{} -AdvancedHuntingData @{}

        Assert-True ($result.Lookups.devices.Count -eq 1) 'Expected normalization to reuse DeviceId when machine enrichment is missing.'
        Assert-True ([string]$result.Lookups.devices[0].id -eq 'device-001') 'Expected normalized device entry to keep the stable DeviceId.'
    }
    finally {
        if (Test-Path -LiteralPath $tempRoot) {
            Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

function Test-ConvertToNormalizedDataWritesExpectedRowCount {
    [CmdletBinding()]
    param()

    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('normalized-row-count-' + [guid]::NewGuid().ToString('N'))
    [void](New-Item -Path $tempRoot -ItemType Directory -Force)
    $outputPath = Join-Path $tempRoot 'normalized-vulns.json'

    try {
        $currentRow = Get-TestVulnRow -Id 'row-count-001' -CveId 'CVE-2026-0009' -SnapshotDate '2026-03-20' -Version '1.0.0'
        $historyRow = Get-TestVulnRow -Id 'row-count-002' -CveId 'CVE-2026-0010' -SnapshotDate '2026-03-18' -Version '1.1.0'

        Write-NdjsonRecordsFile -Path (Get-VulnCurrentPath -BasePath $tempRoot) -Records @($currentRow)
        [void](New-Item -Path (Get-VulnHistoryPath -BasePath $tempRoot -PeriodKey '2026Q1') -ItemType File -Force)
        Write-NdjsonRecordsFile -Path (Get-VulnHistoryRowsPath -BasePath $tempRoot -PeriodKey '2026Q1') -Records @($historyRow)

        $result = ConvertTo-NormalizedData -DataPath $tempRoot -VulnOutputPath $outputPath -Machines @{} -AdvancedHuntingData @{}

        if ($result.VulnsPath) {
            $writtenRowCount = Get-CompactVulnJsonRowCount -Path $result.VulnsPath
        }
        elseif ($result.VulnColumnPaths) {
            # Column-store format: count entries in the device-index column
            $colJson = Get-Content -Path $result.VulnColumnPaths['d'] -Raw
            $writtenRowCount = ([Newtonsoft.Json.Linq.JArray]::Parse($colJson)).Count
        }
        else {
            throw 'ConvertTo-NormalizedData returned neither VulnsPath nor VulnColumnPaths.'
        }

        Assert-True ($result.VulnCount -eq 2) 'Expected normalized data to include both current and history vulnerability rows.'
        Assert-True ($writtenRowCount -eq $result.VulnCount) 'Expected normalized vuln file row count to match the processed vulnerability count.'
    }
    finally {
        if (Test-Path -LiteralPath $tempRoot) {
            Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

function Test-ConvertToNormalizedDataWritesDirectPayload {
    [CmdletBinding()]
    param()

    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('normalized-direct-payload-' + [guid]::NewGuid().ToString('N'))
    [void](New-Item -Path $tempRoot -ItemType Directory -Force)
    $outputPath = Join-Path $tempRoot 'normalized-vulns.json'
    $payloadPath = Join-Path $tempRoot 'payload.json.gz'

    try {
        $currentRow = Get-TestVulnRow -Id 'direct-payload-001' -CveId 'CVE-2026-0111' -SnapshotDate '2026-03-20' -Version '1.0.0'
        $historyRow = Get-TestVulnRow -Id 'direct-payload-002' -CveId 'CVE-2026-0112' -SnapshotDate '2026-03-18' -Version '1.1.0'

        Write-NdjsonRecordsFile -Path (Get-VulnCurrentPath -BasePath $tempRoot) -Records @($currentRow)
        [void](New-Item -Path (Get-VulnHistoryPath -BasePath $tempRoot -PeriodKey '2026Q1') -ItemType File -Force)
        Write-NdjsonRecordsFile -Path (Get-VulnHistoryRowsPath -BasePath $tempRoot -PeriodKey '2026Q1') -Records @($historyRow)
        Write-NdjsonRecordsFile -Path (Get-AdvancedHuntingCurrentPath -BasePath $tempRoot) -Records @(
            [PSCustomObject]@{
                CveId = 'CVE-2026-0111'
                PublishedDate = '2026-03-20'
                VulnerabilityDescription = 'Direct payload filtering regression.'
                EpssScore = 0.42
                AffectedSoftware = @(
                    'contoso:legacy_agent'
                    'microsoft:windows_11'
                )
            }
        )

        $result = ConvertTo-NormalizedData -DataPath $tempRoot -VulnOutputPath $outputPath -PayloadOutputPath $payloadPath -Machines @{} -AdvancedHuntingData (Read-AdvancedHuntingData -Path $tempRoot)
        $payload = Read-GzipTextFile -Path $payloadPath | ConvertFrom-Json -Depth 100
        $payloadCve = @($payload.lookups.cves | Where-Object { $_.id -eq 'CVE-2026-0111' })[0]
        $payloadAffectedSoftware = @($payloadCve.as | ForEach-Object { [string]$payload.lookups.affSoftware[[int]$_] } | Sort-Object)

        Assert-True ([string]::IsNullOrWhiteSpace([string]$result.VulnsPath)) 'Expected direct payload mode not to materialize a vuln rows file.'
        Assert-True ($null -eq $result.VulnColumnPaths) 'Expected direct payload mode not to materialize vuln column files.'
        Assert-True ([string]$result.PayloadPath -eq $payloadPath) 'Expected direct payload mode to return the payload path.'
        Assert-True ((Get-CompressedPayloadVulnCount -Path $payloadPath) -eq $result.VulnCount) 'Expected direct payload row count to match the processed vulnerability count.'
        Assert-True ($payloadAffectedSoftware.Count -eq 1) 'Expected direct payload mode to filter affected software down to dataset vendors.'
        Assert-True ($payloadAffectedSoftware[0] -eq 'contoso:legacy_agent') 'Expected direct payload mode to preserve only matching affected software vendor entries.'
    }
    finally {
        if (Test-Path -LiteralPath $tempRoot) {
            Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

function Test-ConvertToNormalizedDataPreservesOptionalNvdFallback {
    [CmdletBinding()]
    param()

    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('normalized-optional-nvd-' + [guid]::NewGuid().ToString('N'))
    [void](New-Item -Path $tempRoot -ItemType Directory -Force)
    $outputPath = Join-Path $tempRoot 'normalized-vulns.json'
    $payloadPath = Join-Path $tempRoot 'payload.json.gz'

    try {
        $ahPreferredRow = Get-TestVulnRow -Id 'optional-nvd-001' -CveId 'CVE-2026-0131' -SnapshotDate '2026-03-20' -Version '1.0.0'
        $nvdFallbackRow = Get-TestVulnRow -Id 'optional-nvd-002' -CveId 'CVE-2026-0132' -SnapshotDate '2026-03-20' -Version '1.1.0'

        Write-NdjsonRecordsFile -Path (Get-VulnCurrentPath -BasePath $tempRoot) -Records @($ahPreferredRow, $nvdFallbackRow)
        Write-NdjsonRecordsFile -Path (Get-AdvancedHuntingCurrentPath -BasePath $tempRoot) -Records @(
            [PSCustomObject]@{
                CveId = 'CVE-2026-0131'
                PublishedDate = '2026-03-19'
                VulnerabilityDescription = 'Advanced Hunting description wins.'
                EpssScore = 0.73
                AffectedSoftware = @(
                    'contoso:legacy_agent'
                    'microsoft:windows_11'
                )
            }
        )

        $nvdDocument = [PSCustomObject]@{
            records = @(
                [PSCustomObject]@{
                    CveId = 'CVE-2026-0131'
                    PublishedDate = '2026-03-10'
                    LastModifiedDate = '2026-03-22'
                    VulnerabilityDescription = 'NVD description should remain fallback only.'
                    BaseScore = 9.8
                    BaseSeverity = 'Critical'
                    Vector = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'
                    CisaExploitAdd = '2026-03-23'
                    CisaActionDue = '2026-04-01'
                    CisaRequiredAction = 'Patch now.'
                    Weaknesses = @('CWE-79')
                }
                [PSCustomObject]@{
                    CveId = 'CVE-2026-0132'
                    PublishedDate = '2026-02-11'
                    LastModifiedDate = '2026-03-25'
                    VulnerabilityDescription = 'NVD description fills missing Advanced Hunting data.'
                    BaseScore = 7.5
                    BaseSeverity = 'High'
                    Vector = 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N'
                    CisaExploitAdd = '2026-03-26'
                    CisaActionDue = '2026-04-05'
                    CisaRequiredAction = 'Prioritize patching.'
                    Weaknesses = @('CWE-416', 'CWE-787')
                }
            )
        }
        Write-GzipTextFile -Path (Get-NvdCveCurrentPath -BasePath $tempRoot) -Content ($nvdDocument | ConvertTo-Json -Compress -Depth 20)

        $result = ConvertTo-NormalizedData `
            -DataPath $tempRoot `
            -VulnOutputPath $outputPath `
            -PayloadOutputPath $payloadPath `
            -Machines @{} `
            -AdvancedHuntingData (Read-AdvancedHuntingData -Path $tempRoot) `
            -NvdCveData (Read-NvdCveData -Path $tempRoot)

        $payload = Read-GzipTextFile -Path $payloadPath | ConvertFrom-Json -Depth 100
        $ahPreferred = @($payload.lookups.cves | Where-Object { $_.id -eq 'CVE-2026-0131' })[0]
        $nvdFallback = @($payload.lookups.cves | Where-Object { $_.id -eq 'CVE-2026-0132' })[0]
        $ahAffectedSoftware = @($ahPreferred.as | ForEach-Object { [string]$payload.lookups.affSoftware[[int]$_] } | Sort-Object)
        $nvdWeaknesses = @($nvdFallback.nw | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) })

        Assert-True ($result.VulnCount -eq 2) 'Expected optional NVD regression test to normalize both CVEs.'
        Assert-True ([string]$ahPreferred.pd -eq '2026-03-19') 'Expected Advanced Hunting PublishedDate to win when present.'
        Assert-True ([string]$ahPreferred.desc -eq 'Advanced Hunting description wins.') 'Expected Advanced Hunting description to win when present.'
        Assert-True ([math]::Abs(([double]$ahPreferred.ep) - 0.73) -lt 0.00001) 'Expected Advanced Hunting EPSS score to be preserved.'
        Assert-True ($ahAffectedSoftware.Count -eq 1) 'Expected Advanced Hunting affected software to stay filtered to dataset vendors.'
        Assert-True ($ahAffectedSoftware[0] -eq 'contoso:legacy_agent') 'Expected filtered affected software to preserve the matching vendor entry.'
        Assert-True ([string]$ahPreferred.nlm -eq '2026-03-22') 'Expected NVD last-modified metadata to be preserved alongside Advanced Hunting fields.'
        Assert-True ([double]$ahPreferred.nbs -eq 9.8) 'Expected NVD base score to be preserved.'
        Assert-True ([string]$ahPreferred.nsv -eq 'Critical') 'Expected NVD base severity to be preserved.'

        Assert-True ([string]$nvdFallback.pd -eq '2026-02-11') 'Expected NVD PublishedDate to backfill when Advanced Hunting data is missing.'
        Assert-True ([string]$nvdFallback.desc -eq 'NVD description fills missing Advanced Hunting data.') 'Expected NVD description to backfill when Advanced Hunting data is missing.'
        Assert-True ($null -eq $nvdFallback.ep) 'Expected EPSS score to stay empty when Advanced Hunting does not provide it.'
        Assert-True ($null -eq $nvdFallback.as) 'Expected affected software to stay empty when Advanced Hunting does not provide it.'
        Assert-True ([string]$nvdFallback.nact -eq 'Prioritize patching.') 'Expected NVD-required action to be preserved.'
        Assert-True ($nvdWeaknesses.Count -eq 2) 'Expected NVD weaknesses to be preserved as an array.'
    }
    finally {
        if (Test-Path -LiteralPath $tempRoot) {
            Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

function Test-ConvertToNormalizedDataCanConsumeLookupsOnPayloadClose {
    [CmdletBinding()]
    param()

    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('normalized-consume-lookups-' + [guid]::NewGuid().ToString('N'))
    [void](New-Item -Path $tempRoot -ItemType Directory -Force)
    $outputPath = Join-Path $tempRoot 'normalized-vulns.json'
    $payloadPath = Join-Path $tempRoot 'payload.json.gz'

    try {
        $currentRow = Get-TestVulnRow -Id 'consume-lookups-001' -CveId 'CVE-2026-0151' -SnapshotDate '2026-03-20' -Version '2.0.0'

        Write-NdjsonRecordsFile -Path (Get-VulnCurrentPath -BasePath $tempRoot) -Records @($currentRow)

        $result = ConvertTo-NormalizedData -DataPath $tempRoot -VulnOutputPath $outputPath -PayloadOutputPath $payloadPath -Machines @{} -AdvancedHuntingData @{} -ConsumeLookupsOnPayloadClose
        $payload = Read-GzipTextFile -Path $payloadPath | ConvertFrom-Json -Depth 100

        Assert-True ([string]::IsNullOrWhiteSpace([string]$result.VulnsPath)) 'Expected consuming payload mode not to materialize a vuln rows file.'
        Assert-True ([string]$result.PayloadPath -eq $payloadPath) 'Expected consuming payload mode to return the payload path.'
        Assert-True ($result.LookupsConsumed -eq $true) 'Expected consuming payload mode to report that lookups were released during payload close.'
        Assert-True ($null -eq $result.Lookups) 'Expected consuming payload mode not to retain the lookup record.'
        Assert-True ($result.DeviceCount -eq 1) 'Expected consuming payload mode to preserve the device count summary.'
        Assert-True ($result.CveCount -eq 1) 'Expected consuming payload mode to preserve the CVE count summary.'
        Assert-True ((Get-CompressedPayloadVulnCount -Path $payloadPath) -eq $result.VulnCount) 'Expected consuming payload mode to keep the payload row count aligned with processed vulnerabilities.'
        Assert-True ($payload.lookups.devices.Count -eq 1) 'Expected consuming payload mode to still serialize device lookups into the payload.'
        Assert-True ($payload.lookups.cves.Count -eq 1) 'Expected consuming payload mode to still serialize CVE lookups into the payload.'
    }
    finally {
        if (Test-Path -LiteralPath $tempRoot) {
            Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

function Invoke-WithContentDictionaryStreamProbe {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory = $true)]
        [object[]]$DeviceProfiles,

        [Parameter(Mandatory = $true)]
        [object[]]$ContentTemplates,

        [Parameter(Mandatory = $true)]
        [scriptblock]$Action
    )

    $originalArrayEntriesReader = ${function:Read-VulnContentDictionaryArrayEntries}
    $originalAddNormalizedDevice = ${function:Add-NormalizedDevice}
    $originalResolveNormalizedContentLookup = ${function:Resolve-NormalizedContentLookup}
    $deviceProfileEntries = @($DeviceProfiles)
    $contentTemplateEntries = @($ContentTemplates)
    $deviceProfileReadCount = 0
    $contentTemplateReadCount = 0
    $probeState = [PSCustomObject]@{
        DeviceProfilesBuffered = $false
        ContentTemplatesBuffered = $false
        FirstDeviceProfileProcessed = $false
        FirstContentTemplateProcessed = $false
    }

    try {
        Set-Item -Path Function:Read-VulnContentDictionaryArrayEntries -Value ({
                param(
                    [Parameter(Mandatory = $true)]
                    [string]$Path,

                    [Parameter(Mandatory = $true)]
                    [ValidateSet('deviceProfiles', 'contentTemplates')]
                    [string]$PropertyName
                )

                $null = $Path

                $entries = switch ($PropertyName) {
                    'deviceProfiles' { $deviceProfileReadCount++; $deviceProfileEntries }
                    'contentTemplates' { $contentTemplateReadCount++; $contentTemplateEntries }
                    default { @() }
                }
                $isNormalizationRead = switch ($PropertyName) {
                    'deviceProfiles' { $deviceProfileReadCount -gt 1 }
                    'contentTemplates' { $contentTemplateReadCount -gt 1 }
                    default { $false }
                }

                if ($entries.Count -eq 0) {
                    return
                }

                Write-Output -InputObject $entries[0] -NoEnumerate
                for ($entryIndex = 1; $entryIndex -lt $entries.Count; $entryIndex++) {
                    switch ($PropertyName) {
                        'deviceProfiles' {
                            if ($isNormalizationRead -and -not $probeState.FirstDeviceProfileProcessed) {
                                $probeState.DeviceProfilesBuffered = $true
                            }
                        }
                        'contentTemplates' {
                            if ($isNormalizationRead -and -not $probeState.FirstContentTemplateProcessed) {
                                $probeState.ContentTemplatesBuffered = $true
                            }
                        }
                    }

                    Write-Output -InputObject $entries[$entryIndex] -NoEnumerate
                }
            }.GetNewClosure())

        Set-Item -Path Function:Add-NormalizedDevice -Value ({
                param(
                    [Parameter(Mandatory = $false)]
                    [AllowNull()]
                    [object]$DeviceId,

                    [Parameter(Mandatory = $false)]
                    [AllowNull()]
                    [object]$DeviceName,

                    [Parameter(Mandatory = $false)]
                    [AllowNull()]
                    [object]$GroupName,

                    [Parameter(Mandatory = $false)]
                    [AllowNull()]
                    [object]$OsPlatform,

                    [Parameter(Mandatory = $false)]
                    [AllowNull()]
                    [object]$OsVersion,

                    [Parameter(Mandatory = $false)]
                    [AllowNull()]
                    [object[]]$MachineTags,

                    [Parameter(Mandatory = $true)]
                    [pscustomobject]$Context
                )

                if (-not $probeState.FirstDeviceProfileProcessed) {
                    $probeState.FirstDeviceProfileProcessed = $true
                }

                & $originalAddNormalizedDevice @PSBoundParameters
            }.GetNewClosure())

        Set-Item -Path Function:Resolve-NormalizedContentLookup -Value ({
                param(
                    [Parameter(Mandatory = $false)]
                    [AllowNull()]
                    [object]$SoftwareVendor,

                    [Parameter(Mandatory = $false)]
                    [AllowNull()]
                    [object]$SoftwareName,

                    [Parameter(Mandatory = $false)]
                    [AllowNull()]
                    [object]$RecommendationReference,

                    [Parameter(Mandatory = $false)]
                    [AllowNull()]
                    [object]$CveId,

                    [Parameter(Mandatory = $false)]
                    [AllowNull()]
                    [object]$CvssScore,

                    [Parameter(Mandatory = $false)]
                    [AllowNull()]
                    [object]$SeverityLevel,

                    [Parameter(Mandatory = $false)]
                    [AllowNull()]
                    [object]$ExploitabilityLevel,

                    [Parameter(Mandatory = $false)]
                    [AllowNull()]
                    [object]$CveUrl,

                    [Parameter(Mandatory = $false)]
                    [AllowNull()]
                    [object]$CveBatchTitle,

                    [Parameter(Mandatory = $false)]
                    [AllowNull()]
                    [object]$RecommendedSecurityUpdate,

                    [Parameter(Mandatory = $false)]
                    [AllowNull()]
                    [object]$RecommendedSecurityUpdateId,

                    [Parameter(Mandatory = $false)]
                    [AllowNull()]
                    [object]$RecommendedSecurityUpdateUrl,

                    [Parameter(Mandatory = $false)]
                    [AllowNull()]
                    [object]$SoftwareVersion,

                    [Parameter(Mandatory = $false)]
                    [AllowNull()]
                    [object[]]$DiskPaths,

                    [Parameter(Mandatory = $false)]
                    [AllowNull()]
                    [object[]]$RegistryPaths,

                    [Parameter(Mandatory = $false)]
                    [AllowNull()]
                    [object]$SecurityUpdateAvailable,

                    [Parameter(Mandatory = $true)]
                    [pscustomobject]$Context
                )

                if (-not $probeState.FirstContentTemplateProcessed) {
                    $probeState.FirstContentTemplateProcessed = $true
                }

                & $originalResolveNormalizedContentLookup @PSBoundParameters
            }.GetNewClosure())

        $result = & $Action
        return [PSCustomObject]@{
            Result = $result
            State = $probeState
        }
    }
    finally {
        if ($null -ne $originalArrayEntriesReader) {
            Set-Item -Path Function:Read-VulnContentDictionaryArrayEntries -Value $originalArrayEntriesReader
        }

        if ($null -ne $originalAddNormalizedDevice) {
            Set-Item -Path Function:Add-NormalizedDevice -Value $originalAddNormalizedDevice
        }

        if ($null -ne $originalResolveNormalizedContentLookup) {
            Set-Item -Path Function:Resolve-NormalizedContentLookup -Value $originalResolveNormalizedContentLookup
        }
    }
}

function Test-ConvertToNormalizedDataContentStorePathDoesNotUseLegacyDictionaryReader {
    [CmdletBinding()]
    param()

    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('normalized-content-store-streaming-' + [guid]::NewGuid().ToString('N'))
    [void](New-Item -Path $tempRoot -ItemType Directory -Force)
    $outputPath = Join-Path $tempRoot 'normalized-vulns.json'
    $payloadPath = Join-Path $tempRoot 'payload.json.gz'
    $originalDictionaryReader = $null

    try {
        $currentRow = Get-TestVulnRow -Id 'content-store-streaming-001' -CveId 'CVE-2026-0152' -SnapshotDate '2026-03-20' -Version '2.0.0'
        $historyRow = Get-TestVulnRow -Id 'content-store-streaming-002' -CveId 'CVE-2026-0153' -SnapshotDate '2026-03-18' -Version '2.0.1'
        $streamedDeviceProfiles = @(
            [PSCustomObject]@{
                id = [string]$currentRow.DeviceId
                n = [string]$currentRow.DeviceName
                g = [string]$currentRow.RbacGroupName
                o = [string]$currentRow.OSPlatform
                ov = [string]$currentRow.OSVersion
                t = @($currentRow.MachineTags)
                ob = ($currentRow.IsOnboarded -eq $true)
            }
            [PSCustomObject]@{
                id = [string]$historyRow.DeviceId
                n = [string]$historyRow.DeviceName
                g = [string]$historyRow.RbacGroupName
                o = [string]$historyRow.OSPlatform
                ov = [string]$historyRow.OSVersion
                t = @($historyRow.MachineTags)
                ob = ($historyRow.IsOnboarded -eq $true)
            }
        )
        $streamedContentTemplates = @(
            [PSCustomObject]@{
                c = [string]$currentRow.CveId
                sv = [string]$currentRow.SoftwareVendor
                sn = [string]$currentRow.SoftwareName
                ver = [string]$currentRow.SoftwareVersion
                sev = [string]$currentRow.VulnerabilitySeverityLevel
                sc = $currentRow.CvssScore
                ex = [string]$currentRow.ExploitabilityLevel
                rr = [string]$currentRow.RecommendationReference
                ru = [string]$currentRow.RecommendedSecurityUpdate
                rid = [string]$currentRow.RecommendedSecurityUpdateId
                url = [string]$currentRow.RecommendedSecurityUpdateUrl
                ua = ($currentRow.SecurityUpdateAvailable -eq $true)
                dp = @($currentRow.DiskPaths)
                rp = @($currentRow.RegistryPaths)
                bt = [string]$currentRow.CveBatchTitle
                bu = [string]$currentRow.CveBatchUrl
            }
            [PSCustomObject]@{
                c = [string]$historyRow.CveId
                sv = [string]$historyRow.SoftwareVendor
                sn = [string]$historyRow.SoftwareName
                ver = [string]$historyRow.SoftwareVersion
                sev = [string]$historyRow.VulnerabilitySeverityLevel
                sc = $historyRow.CvssScore
                ex = [string]$historyRow.ExploitabilityLevel
                rr = [string]$historyRow.RecommendationReference
                ru = [string]$historyRow.RecommendedSecurityUpdate
                rid = [string]$historyRow.RecommendedSecurityUpdateId
                url = [string]$historyRow.RecommendedSecurityUpdateUrl
                ua = ($historyRow.SecurityUpdateAvailable -eq $true)
                dp = @($historyRow.DiskPaths)
                rp = @($historyRow.RegistryPaths)
                bt = [string]$historyRow.CveBatchTitle
                bu = [string]$historyRow.CveBatchUrl
            }
        )

        Write-NdjsonRecordsFile -Path (Get-VulnCurrentPath -BasePath $tempRoot) -Records @($currentRow)
        [void](New-Item -Path (Get-VulnHistoryPath -BasePath $tempRoot -PeriodKey '2026Q1') -ItemType File -Force)
        Write-NdjsonRecordsFile -Path (Get-VulnHistoryRowsPath -BasePath $tempRoot -PeriodKey '2026Q1') -Records @($historyRow)
        Publish-VulnContentStoreUnlocked -BasePath $tempRoot

        $originalDictionaryReader = ${function:Read-VulnContentDictionary}
        Set-Item -Path Function:Read-VulnContentDictionary -Value {
            param(
                [Parameter(Mandatory = $true)]
                [string]$Path
            )

            throw "ConvertTo-NormalizedData should stream the content dictionary during content-store normalization instead of calling Read-VulnContentDictionary for '$Path'."
        }

        $probeResult = Invoke-WithContentDictionaryStreamProbe -DeviceProfiles $streamedDeviceProfiles -ContentTemplates $streamedContentTemplates -Action {
            ConvertTo-NormalizedData -DataPath $tempRoot -VulnOutputPath $outputPath -PayloadOutputPath $payloadPath -Machines @{} -AdvancedHuntingData @{} -SkipObservedWindowMerge -ConsumeLookupsOnPayloadClose
        }
        $result = $probeResult.Result
        $probeState = $probeResult.State

        Assert-True ($result.VulnCount -eq 2) 'Expected content-store normalization to preserve both current and history rows while bypassing the legacy dictionary reader.'
        Assert-True ([string]$result.PayloadPath -eq $payloadPath) 'Expected content-store normalization to still write the direct payload output.'
        Assert-True ((Get-CompressedPayloadVulnCount -Path $payloadPath) -eq $result.VulnCount) 'Expected content-store streaming normalization to keep payload row count aligned with processed rows.'
        Assert-True ($probeState.FirstDeviceProfileProcessed -eq $true) 'Expected the streaming probe to observe the first content-store device profile being consumed.'
        Assert-True ($probeState.FirstContentTemplateProcessed -eq $true) 'Expected the streaming probe to observe the first content-store template being consumed.'
        Assert-True ($probeState.DeviceProfilesBuffered -eq $false) 'Expected content-store normalization to consume device profiles as they stream instead of buffering the full dictionary array first.'
        Assert-True ($probeState.ContentTemplatesBuffered -eq $false) 'Expected content-store normalization to consume content templates as they stream instead of buffering the full dictionary array first.'
    }
    finally {
        if ($null -ne $originalDictionaryReader) {
            Set-Item -Path Function:Read-VulnContentDictionary -Value $originalDictionaryReader
        }

        if (Test-Path -LiteralPath $tempRoot) {
            Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

function Test-ConvertToNormalizedDataSupportsDirectMergeDeviceLookup {
    [CmdletBinding()]
    param()

    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('normalized-direct-merge-device-lookup-' + [guid]::NewGuid().ToString('N'))
    [void](New-Item -Path $tempRoot -ItemType Directory -Force)
    $outputPath = Join-Path $tempRoot 'normalized-vulns.json'
    $payloadPath = Join-Path $tempRoot 'payload.json.gz'

    try {
        $firstRow = Get-TestVulnRow -Id 'direct-merge-001' -CveId 'CVE-2026-0154' -SnapshotDate '2026-03-20' -Version '2.0.2'
        $secondRow = Get-TestVulnRow -Id 'direct-merge-002' -CveId 'CVE-2026-0155' -SnapshotDate '2026-03-20' -Version '2.0.3'
        $firstRow.DeviceId = 'direct-merge-device-001'
        $firstRow.DeviceName = 'direct-merge-device-001.contoso.com'
        $secondRow.DeviceId = 'direct-merge-device-002'
        $secondRow.DeviceName = 'direct-merge-device-002.contoso.com'
        $machineRows = @(
            [PSCustomObject]@{
                id = [string]$firstRow.DeviceId
                computerDnsName = [string]$firstRow.DeviceName
                rbacGroupName = [string]$firstRow.RbacGroupName
                osPlatform = [string]$firstRow.OSPlatform
                osVersion = [string]$firstRow.OSVersion
                machineTags = @($firstRow.MachineTags)
                lastIpAddress = '10.0.0.11'
                lastExternalIpAddress = ''
                healthStatus = 'Active'
                riskScore = 'Medium'
                exposureLevel = 'Medium'
                deviceValue = 'Normal'
                managedBy = 'Intune'
                isAadJoined = $true
                lastSeen = '2026-03-20'
                firstSeen = '2026-02-01'
            }
            [PSCustomObject]@{
                id = [string]$secondRow.DeviceId
                computerDnsName = [string]$secondRow.DeviceName
                rbacGroupName = [string]$secondRow.RbacGroupName
                osPlatform = [string]$secondRow.OSPlatform
                osVersion = [string]$secondRow.OSVersion
                machineTags = @($secondRow.MachineTags)
                lastIpAddress = '10.0.0.12'
                lastExternalIpAddress = ''
                healthStatus = 'Active'
                riskScore = 'Low'
                exposureLevel = 'Low'
                deviceValue = 'Normal'
                managedBy = 'Intune'
                isAadJoined = $true
                lastSeen = '2026-03-20'
                firstSeen = '2026-02-02'
            }
        )
        $deviceProfiles = @(
            [PSCustomObject]@{
                id = [string]$firstRow.DeviceId
                n = [string]$firstRow.DeviceName
                g = [string]$firstRow.RbacGroupName
                o = [string]$firstRow.OSPlatform
                ov = [string]$firstRow.OSVersion
                t = @($firstRow.MachineTags)
                ob = ($firstRow.IsOnboarded -eq $true)
            }
            [PSCustomObject]@{
                id = [string]$secondRow.DeviceId
                n = [string]$secondRow.DeviceName
                g = [string]$secondRow.RbacGroupName
                o = [string]$secondRow.OSPlatform
                ov = [string]$secondRow.OSVersion
                t = @($secondRow.MachineTags)
                ob = ($secondRow.IsOnboarded -eq $true)
            }
        )
        $contentTemplates = @(
            [PSCustomObject]@{
                c = [string]$firstRow.CveId
                sv = [string]$firstRow.SoftwareVendor
                sn = [string]$firstRow.SoftwareName
                ver = [string]$firstRow.SoftwareVersion
                sev = [string]$firstRow.VulnerabilitySeverityLevel
                sc = $firstRow.CvssScore
                ex = [string]$firstRow.ExploitabilityLevel
                rr = [string]$firstRow.RecommendationReference
                ru = [string]$firstRow.RecommendedSecurityUpdate
                rid = [string]$firstRow.RecommendedSecurityUpdateId
                url = [string]$firstRow.RecommendedSecurityUpdateUrl
                ua = ($firstRow.SecurityUpdateAvailable -eq $true)
                dp = @($firstRow.DiskPaths)
                rp = @($firstRow.RegistryPaths)
                bt = [string]$firstRow.CveBatchTitle
                bu = [string]$firstRow.CveBatchUrl
            }
            [PSCustomObject]@{
                c = [string]$secondRow.CveId
                sv = [string]$secondRow.SoftwareVendor
                sn = [string]$secondRow.SoftwareName
                ver = [string]$secondRow.SoftwareVersion
                sev = [string]$secondRow.VulnerabilitySeverityLevel
                sc = $secondRow.CvssScore
                ex = [string]$secondRow.ExploitabilityLevel
                rr = [string]$secondRow.RecommendationReference
                ru = [string]$secondRow.RecommendedSecurityUpdate
                rid = [string]$secondRow.RecommendedSecurityUpdateId
                url = [string]$secondRow.RecommendedSecurityUpdateUrl
                ua = ($secondRow.SecurityUpdateAvailable -eq $true)
                dp = @($secondRow.DiskPaths)
                rp = @($secondRow.RegistryPaths)
                bt = [string]$secondRow.CveBatchTitle
                bu = [string]$secondRow.CveBatchUrl
            }
        )

        Write-NdjsonRecordsFile -Path (Get-VulnCurrentPath -BasePath $tempRoot) -Records @($firstRow, $secondRow)
        [System.IO.File]::WriteAllText((Join-Path $tempRoot 'Machines_Current.json'), ($machineRows | ConvertTo-Json -Compress -Depth 20), [System.Text.UTF8Encoding]::new($false))
        Publish-VulnContentStoreUnlocked -BasePath $tempRoot

        $probeResult = Invoke-WithContentDictionaryStreamProbe -DeviceProfiles $deviceProfiles -ContentTemplates $contentTemplates -Action {
            ConvertTo-NormalizedData -DataPath $tempRoot -VulnOutputPath $outputPath -PayloadOutputPath $payloadPath -Machines @{} -AdvancedHuntingData @{} -AdvancedHuntingDeviceUsers @{} -AdvancedHuntingInventoryData @{} -NvdCveData @{} -SkipObservedWindowMerge -DirectMergeDeviceLookup
        }
        $result = $probeResult.Result
        $payload = Read-GzipTextFile -Path $payloadPath | ConvertFrom-Json -Depth 100

        Assert-True ($result.VulnCount -eq 2) 'Expected direct-merge device lookup projection to preserve all vulnerability rows.'
        Assert-True ((Get-CompressedPayloadVulnCount -Path $payloadPath) -eq $result.VulnCount) 'Expected direct-merge device lookup projection to keep payload row count aligned with processed rows.'
        Assert-True ($payload.lookups.devices.Count -eq 2) 'Expected direct-merge device lookup projection to materialize both device lookups from the current-machine stream.'
    }
    finally {
        if (Test-Path -LiteralPath $tempRoot) {
            Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

function Test-ConvertToNormalizedDataDirectMergeDeviceLookupRejectsOutOfOrderMachineStream {
    [CmdletBinding()]
    param()

    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('normalized-direct-merge-device-order-' + [guid]::NewGuid().ToString('N'))
    [void](New-Item -Path $tempRoot -ItemType Directory -Force)
    $outputPath = Join-Path $tempRoot 'normalized-vulns.json'

    try {
        $firstRow = Get-TestVulnRow -Id 'direct-merge-order-001' -CveId 'CVE-2026-0156' -SnapshotDate '2026-03-20' -Version '2.0.4'
        $secondRow = Get-TestVulnRow -Id 'direct-merge-order-002' -CveId 'CVE-2026-0157' -SnapshotDate '2026-03-20' -Version '2.0.5'
        $firstRow.DeviceId = 'direct-merge-order-device-001'
        $firstRow.DeviceName = 'direct-merge-order-device-001.contoso.com'
        $secondRow.DeviceId = 'direct-merge-order-device-002'
        $secondRow.DeviceName = 'direct-merge-order-device-002.contoso.com'
        $deviceProfiles = @(
            [PSCustomObject]@{
                id = [string]$firstRow.DeviceId
                n = [string]$firstRow.DeviceName
                g = [string]$firstRow.RbacGroupName
                o = [string]$firstRow.OSPlatform
                ov = [string]$firstRow.OSVersion
                t = @($firstRow.MachineTags)
                ob = ($firstRow.IsOnboarded -eq $true)
            }
            [PSCustomObject]@{
                id = [string]$secondRow.DeviceId
                n = [string]$secondRow.DeviceName
                g = [string]$secondRow.RbacGroupName
                o = [string]$secondRow.OSPlatform
                ov = [string]$secondRow.OSVersion
                t = @($secondRow.MachineTags)
                ob = ($secondRow.IsOnboarded -eq $true)
            }
        )
        $contentTemplates = @(
            [PSCustomObject]@{
                c = [string]$firstRow.CveId
                sv = [string]$firstRow.SoftwareVendor
                sn = [string]$firstRow.SoftwareName
                ver = [string]$firstRow.SoftwareVersion
                sev = [string]$firstRow.VulnerabilitySeverityLevel
                sc = $firstRow.CvssScore
                ex = [string]$firstRow.ExploitabilityLevel
                rr = [string]$firstRow.RecommendationReference
                ru = [string]$firstRow.RecommendedSecurityUpdate
                rid = [string]$firstRow.RecommendedSecurityUpdateId
                url = [string]$firstRow.RecommendedSecurityUpdateUrl
                ua = ($firstRow.SecurityUpdateAvailable -eq $true)
                dp = @($firstRow.DiskPaths)
                rp = @($firstRow.RegistryPaths)
                bt = [string]$firstRow.CveBatchTitle
                bu = [string]$firstRow.CveBatchUrl
            }
            [PSCustomObject]@{
                c = [string]$secondRow.CveId
                sv = [string]$secondRow.SoftwareVendor
                sn = [string]$secondRow.SoftwareName
                ver = [string]$secondRow.SoftwareVersion
                sev = [string]$secondRow.VulnerabilitySeverityLevel
                sc = $secondRow.CvssScore
                ex = [string]$secondRow.ExploitabilityLevel
                rr = [string]$secondRow.RecommendationReference
                ru = [string]$secondRow.RecommendedSecurityUpdate
                rid = [string]$secondRow.RecommendedSecurityUpdateId
                url = [string]$secondRow.RecommendedSecurityUpdateUrl
                ua = ($secondRow.SecurityUpdateAvailable -eq $true)
                dp = @($secondRow.DiskPaths)
                rp = @($secondRow.RegistryPaths)
                bt = [string]$secondRow.CveBatchTitle
                bu = [string]$secondRow.CveBatchUrl
            }
        )
        $machineRows = @(
            [PSCustomObject]@{
                id = [string]$secondRow.DeviceId
                computerDnsName = [string]$secondRow.DeviceName
                rbacGroupName = [string]$secondRow.RbacGroupName
                osPlatform = [string]$secondRow.OSPlatform
                osVersion = [string]$secondRow.OSVersion
                machineTags = @($secondRow.MachineTags)
            }
            [PSCustomObject]@{
                id = [string]$firstRow.DeviceId
                computerDnsName = [string]$firstRow.DeviceName
                rbacGroupName = [string]$firstRow.RbacGroupName
                osPlatform = [string]$firstRow.OSPlatform
                osVersion = [string]$firstRow.OSVersion
                machineTags = @($firstRow.MachineTags)
            }
        )

        Write-NdjsonRecordsFile -Path (Get-VulnCurrentPath -BasePath $tempRoot) -Records @($firstRow, $secondRow)
        [System.IO.File]::WriteAllText((Join-Path $tempRoot 'Machines_Current.json'), ($machineRows | ConvertTo-Json -Compress -Depth 20), [System.Text.UTF8Encoding]::new($false))
        Publish-VulnContentStoreUnlocked -BasePath $tempRoot

        $caught = $null
        try {
            $null = Invoke-WithContentDictionaryStreamProbe -DeviceProfiles $deviceProfiles -ContentTemplates $contentTemplates -Action {
                ConvertTo-NormalizedData -DataPath $tempRoot -VulnOutputPath $outputPath -Machines @{} -AdvancedHuntingData @{} -AdvancedHuntingDeviceUsers @{} -AdvancedHuntingInventoryData @{} -NvdCveData @{} -SkipObservedWindowMerge -DirectMergeDeviceLookup
            }
        }
        catch {
            $caught = $_
        }

        Assert-True ($null -ne $caught) 'Expected direct-merge device lookup projection to fail fast when the machine stream order does not match content-store device profiles.'
        Assert-True ($caught.Exception.Message -like '*requires exact current machine order*') 'Expected direct-merge order mismatch to report the exact-order contract.'
    }
    finally {
        if (Test-Path -LiteralPath $tempRoot) {
            Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

function Test-ConvertToNormalizedDataDirectMergeDeviceLookupRejectsBlankDeviceId {
    [CmdletBinding()]
    param()

    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('normalized-direct-merge-blank-device-id-' + [guid]::NewGuid().ToString('N'))
    [void](New-Item -Path $tempRoot -ItemType Directory -Force)
    $outputPath = Join-Path $tempRoot 'normalized-vulns.json'

    try {
        $firstRow = Get-TestVulnRow -Id 'direct-merge-blank-001' -CveId 'CVE-2026-0158' -SnapshotDate '2026-03-20' -Version '2.0.6'
        $secondRow = Get-TestVulnRow -Id 'direct-merge-blank-002' -CveId 'CVE-2026-0159' -SnapshotDate '2026-03-20' -Version '2.0.7'
        $firstRow.DeviceId = 'direct-merge-blank-device-001'
        $firstRow.DeviceName = 'direct-merge-blank-device-001.contoso.com'
        $secondRow.DeviceId = ''
        $secondRow.DeviceName = 'direct-merge-blank-device-002.contoso.com'
        $deviceProfiles = @(
            [PSCustomObject]@{
                id = [string]$firstRow.DeviceId
                n = [string]$firstRow.DeviceName
                g = [string]$firstRow.RbacGroupName
                o = [string]$firstRow.OSPlatform
                ov = [string]$firstRow.OSVersion
                t = @($firstRow.MachineTags)
                ob = ($firstRow.IsOnboarded -eq $true)
            }
            [PSCustomObject]@{
                id = [string]$secondRow.DeviceId
                n = [string]$secondRow.DeviceName
                g = [string]$secondRow.RbacGroupName
                o = [string]$secondRow.OSPlatform
                ov = [string]$secondRow.OSVersion
                t = @($secondRow.MachineTags)
                ob = ($secondRow.IsOnboarded -eq $true)
            }
        )
        $contentTemplates = @(
            [PSCustomObject]@{
                c = [string]$firstRow.CveId
                sv = [string]$firstRow.SoftwareVendor
                sn = [string]$firstRow.SoftwareName
                ver = [string]$firstRow.SoftwareVersion
                sev = [string]$firstRow.VulnerabilitySeverityLevel
                sc = $firstRow.CvssScore
                ex = [string]$firstRow.ExploitabilityLevel
                rr = [string]$firstRow.RecommendationReference
                ru = [string]$firstRow.RecommendedSecurityUpdate
                rid = [string]$firstRow.RecommendedSecurityUpdateId
                url = [string]$firstRow.RecommendedSecurityUpdateUrl
                ua = ($firstRow.SecurityUpdateAvailable -eq $true)
                dp = @($firstRow.DiskPaths)
                rp = @($firstRow.RegistryPaths)
                bt = [string]$firstRow.CveBatchTitle
                bu = [string]$firstRow.CveBatchUrl
            }
            [PSCustomObject]@{
                c = [string]$secondRow.CveId
                sv = [string]$secondRow.SoftwareVendor
                sn = [string]$secondRow.SoftwareName
                ver = [string]$secondRow.SoftwareVersion
                sev = [string]$secondRow.VulnerabilitySeverityLevel
                sc = $secondRow.CvssScore
                ex = [string]$secondRow.ExploitabilityLevel
                rr = [string]$secondRow.RecommendationReference
                ru = [string]$secondRow.RecommendedSecurityUpdate
                rid = [string]$secondRow.RecommendedSecurityUpdateId
                url = [string]$secondRow.RecommendedSecurityUpdateUrl
                ua = ($secondRow.SecurityUpdateAvailable -eq $true)
                dp = @($secondRow.DiskPaths)
                rp = @($secondRow.RegistryPaths)
                bt = [string]$secondRow.CveBatchTitle
                bu = [string]$secondRow.CveBatchUrl
            }
        )
        $machineRows = @(
            [PSCustomObject]@{
                id = [string]$firstRow.DeviceId
                computerDnsName = [string]$firstRow.DeviceName
                rbacGroupName = [string]$firstRow.RbacGroupName
                osPlatform = [string]$firstRow.OSPlatform
                osVersion = [string]$firstRow.OSVersion
                machineTags = @($firstRow.MachineTags)
                lastIpAddress = '10.0.0.21'
                lastExternalIpAddress = ''
                healthStatus = 'Active'
                riskScore = 'Medium'
                exposureLevel = 'Medium'
                deviceValue = 'Normal'
                managedBy = 'Intune'
                isAadJoined = $true
                lastSeen = '2026-03-20'
                firstSeen = '2026-02-01'
            }
            [PSCustomObject]@{
                id = 'direct-merge-blank-device-002'
                computerDnsName = 'direct-merge-blank-device-002.contoso.com'
                rbacGroupName = [string]$secondRow.RbacGroupName
                osPlatform = [string]$secondRow.OSPlatform
                osVersion = [string]$secondRow.OSVersion
                machineTags = @($secondRow.MachineTags)
                lastIpAddress = '10.0.0.22'
                lastExternalIpAddress = ''
                healthStatus = 'Active'
                riskScore = 'Low'
                exposureLevel = 'Low'
                deviceValue = 'Normal'
                managedBy = 'Intune'
                isAadJoined = $true
                lastSeen = '2026-03-20'
                firstSeen = '2026-02-02'
            }
        )

        Write-NdjsonRecordsFile -Path (Get-VulnCurrentPath -BasePath $tempRoot) -Records @($firstRow, $secondRow)
        [System.IO.File]::WriteAllText((Join-Path $tempRoot 'Machines_Current.json'), ($machineRows | ConvertTo-Json -Compress -Depth 20), [System.Text.UTF8Encoding]::new($false))
        Publish-VulnContentStoreUnlocked -BasePath $tempRoot

        $caught = $null
        try {
            Invoke-WithContentDictionaryStreamProbe -DeviceProfiles $deviceProfiles -ContentTemplates $contentTemplates -Action {
                ConvertTo-NormalizedData -DataPath $tempRoot -VulnOutputPath $outputPath -Machines @{} -AdvancedHuntingData @{} -AdvancedHuntingDeviceUsers @{} -AdvancedHuntingInventoryData @{} -NvdCveData @{} -SkipObservedWindowMerge -DirectMergeDeviceLookup
            } | Out-Null
        }
        catch {
            $caught = $_
        }

        Assert-True ($null -ne $caught) 'Expected direct-merge device lookup to reject blank device IDs.'
        Assert-True ($caught.Exception.Message.Contains('requires non-empty device IDs')) 'Expected direct-merge device lookup blank device ID error to explain the exact-order requirement.'
    }
    finally {
        if (Test-Path -LiteralPath $tempRoot) {
            Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

function Test-InvokeContentStoreNormalizationReleasesTransientContextBeforePayloadClose {
    [CmdletBinding()]
    param()

    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('normalized-content-store-context-release-' + [guid]::NewGuid().ToString('N'))
    [void](New-Item -Path $tempRoot -ItemType Directory -Force)
    $outputPath = Join-Path $tempRoot 'normalized-vulns.json'
    $payloadPath = Join-Path $tempRoot 'payload.json.gz'
    $originalWriteMemoryUsage = if (Test-Path -LiteralPath Function:\Write-MemoryUsage) {
        Get-Item -LiteralPath Function:\Write-MemoryUsage
    }
    else {
        $null
    }

    try {
        Set-Item -LiteralPath Function:\Write-MemoryUsage -Value {
            param(
                [Parameter(Mandatory = $false)]
                [string]$Label = ''
            )

            Write-Output ("mock memory usage: {0}" -f $Label)
        }

        $currentRow = Get-TestVulnRow -Id 'content-store-context-release-001' -CveId 'CVE-2026-0154' -SnapshotDate '2026-03-20' -Version '2.0.0'
        $currentRow.DeviceId = 'device-context-release-001'
        $currentRow.DeviceName = 'device-context-release-001.contoso.com'

        Write-NdjsonRecordsFile -Path (Get-VulnCurrentPath -BasePath $tempRoot) -Records @($currentRow)
        Publish-VulnContentStoreUnlocked -BasePath $tempRoot

        $context = Get-NormalizationContext
        $machines = @{
            'device-context-release-001' = [PSCustomObject]@{
                id = 'device-context-release-001'
                computerDnsName = 'device-context-release-001.contoso.com'
                rbacGroupName = 'Prod'
                osPlatform = 'Windows 11'
                osVersion = '10.0.26100'
                machineTags = 'Prod'
                lastIpAddress = '10.0.0.21'
                lastExternalIpAddress = '52.0.0.21'
                healthStatus = 'Active'
                riskScore = 'Medium'
                exposureLevel = 'Low'
                deviceValue = 'Normal'
                managedBy = 'Intune'
                isAadJoined = $true
                lastSeen = '2026-03-20'
                firstSeen = '2026-03-01'
            }
        }
        $advancedHuntingData = @{
            'CVE-2026-0154' = @{
                PublishedDate = '2026-03-20'
                VulnerabilityDescription = 'Context release regression.'
                EpssScore = 0.18
                AffectedSoftware = @('contoso:legacy_agent')
            }
        }
        $advancedHuntingDeviceUsers = @{
            'device-context-release-001' = @('alice@contoso.com')
        }
        $advancedHuntingInventoryData = @{
            (Get-AdvancedHuntingInventoryMatchKey -DeviceId 'device-context-release-001' -SoftwareVendor 'Contoso' -SoftwareName 'Legacy Agent' -SoftwareVersion '2.0.0') = [PSCustomObject]@{
                ProductCodeCpe = 'cpe:/a:contoso:legacy_agent:2.0.0'
                EndOfSupportStatus = 'supported'
                EndOfSupportDate = '2027-12-31'
            }
        }
        $nvdCveData = @{
            'CVE-2026-0154' = [PSCustomObject]@{
                PublishedDate = '2026-03-19'
                LastModifiedDate = '2026-03-21'
                VulnerabilityDescription = 'NVD fallback metadata.'
                BaseScore = 7.1
                BaseSeverity = 'High'
                Vector = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N'
                CisaExploitAdd = $null
                CisaActionDue = $null
                CisaRequiredAction = $null
                Weaknesses = @('CWE-416')
            }
        }

        $result = @(Invoke-ContentStoreNormalization `
            -DataPath $tempRoot `
            -VulnOutputPath $outputPath `
            -Context $context `
            -Machines $machines `
            -AdvancedHuntingData $advancedHuntingData `
            -AdvancedHuntingDeviceUsers $advancedHuntingDeviceUsers `
            -AdvancedHuntingInventoryData $advancedHuntingInventoryData `
            -NvdCveData $nvdCveData `
            -PayloadOutputPath $payloadPath `
            -ConsumeLookupsOnPayloadClose)

        Assert-True ($result.Count -eq 1) 'Expected content-store normalization to suppress hosted memory diagnostics from the return pipeline.'

        $normalizationResult = $result[0]
        Assert-True ($normalizationResult.ProcessedCount -eq 1) 'Expected content-store context-release regression fixture to normalize one row.'
        Assert-True ([string]$normalizationResult.PayloadPath -eq $payloadPath) 'Expected content-store context-release regression fixture to write the direct payload output.'
        Assert-True ((Get-CompressedPayloadVulnCount -Path $payloadPath) -eq $normalizationResult.ProcessedCount) 'Expected content-store context-release regression payload row count to match the processed count.'
        Assert-True ($context.Machines.Count -eq 0) 'Expected content-store normalization to release machine lookups before payload close.'
        Assert-True ($context.AdvancedHuntingData.Count -eq 0) 'Expected content-store normalization to release Advanced Hunting CVE data before payload close.'
        Assert-True ($context.AdvancedHuntingDeviceUsers.Count -eq 0) 'Expected content-store normalization to release Advanced Hunting device-user data before payload close.'
        Assert-True ($context.NvdCveData.Count -eq 0) 'Expected content-store normalization to release NVD CVE data before payload close.'
        Assert-True ($context.AdvancedHuntingInventoryData.Count -eq 0) 'Expected content-store normalization to release inventory enrichment before payload close once ref streaming completes.'
    }
    finally {
        if ($null -ne $originalWriteMemoryUsage) {
            Set-Item -LiteralPath Function:\Write-MemoryUsage -Value $originalWriteMemoryUsage.ScriptBlock
        }
        elseif (Test-Path -LiteralPath Function:\Write-MemoryUsage) {
            Remove-Item -LiteralPath Function:\Write-MemoryUsage -Force -ErrorAction SilentlyContinue
        }

        if (Test-Path -LiteralPath $tempRoot) {
            Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

function Test-GetNormalizedContentLookupCacheEntryOmitsInventoryIdentityWhenUnused {
    [CmdletBinding()]
    param()

    $contentLookup = [PSCustomObject]@{
        sw = 1
        cve = 2
        ver = 3
        upd = 4
        ua = 1
        dp = ,([int[]]@(5))
        rp = ,([int[]]@(6))
    }

    $withoutInventoryIdentity = @(Get-NormalizedContentLookupCacheEntry -ContentLookup $contentLookup)
    $withInventoryIdentity = @(Get-NormalizedContentLookupCacheEntry -IncludeInventoryIdentity -SoftwareInventoryIdentityKey 'Contoso|Legacy Agent|2.0.0' -ContentLookup $contentLookup)

    Assert-True ($withoutInventoryIdentity.Count -eq 7) 'Expected content lookup cache entries without inventory data to omit the extra software identity fields.'
    Assert-True ($withInventoryIdentity.Count -eq 8) 'Expected content lookup cache entries with inventory data to retain only the compact software identity key.'
    Assert-True ([string]$withInventoryIdentity[7] -eq 'Contoso|Legacy Agent|2.0.0') 'Expected inventory-aware cache entries to preserve the compact software identity key.'
}

function Test-GetContentStoreDeviceProfileIdentityCacheOmitsIdsWhenUnused {
    [CmdletBinding()]
    param()

    $deviceProfileIds = [System.Collections.Generic.List[string]]::new()
    $deviceProfileIds.Add('device-001') | Out-Null
    $deviceProfileIds.Add('device-002') | Out-Null

    $withoutInventoryIdentity = @(Get-ContentStoreDeviceProfileIdentityCache -DeviceProfileIds $deviceProfileIds)
    $withInventoryIdentity = @(Get-ContentStoreDeviceProfileIdentityCache -IncludeInventoryIdentity -DeviceProfileIds $deviceProfileIds)

    Assert-True ($withoutInventoryIdentity.Count -eq 0) 'Expected content-store device profile identity cache to stay empty when inventory enrichment is not in use.'
    Assert-True ($withInventoryIdentity.Count -eq 2) 'Expected content-store device profile identity cache to preserve device IDs when inventory enrichment is enabled.'
    Assert-True ([string]$withInventoryIdentity[0] -eq 'device-001') 'Expected the first cached device ID to be preserved for inventory enrichment.'
    Assert-True ([string]$withInventoryIdentity[1] -eq 'device-002') 'Expected the second cached device ID to be preserved for inventory enrichment.'
}

function Test-ConvertToNormalizedDataDeduplicatesRepeatedCveLookup {
    [CmdletBinding()]
    param()

    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('normalized-repeat-cve-' + [guid]::NewGuid().ToString('N'))
    [void](New-Item -Path $tempRoot -ItemType Directory -Force)
    $outputPath = Join-Path $tempRoot 'normalized-vulns.json'
    $payloadPath = Join-Path $tempRoot 'payload.json.gz'

    try {
        $firstRow = Get-TestVulnRow -Id 'repeat-cve-001' -CveId 'CVE-2026-0155' -SnapshotDate '2026-03-20' -Version '1.0.0'
        $secondRow = Get-TestVulnRow -Id 'repeat-cve-002' -CveId 'CVE-2026-0155' -SnapshotDate '2026-03-21' -Version '1.0.1'

        Write-NdjsonRecordsFile -Path (Get-VulnCurrentPath -BasePath $tempRoot) -Records @($firstRow, $secondRow)

        $result = ConvertTo-NormalizedData -DataPath $tempRoot -VulnOutputPath $outputPath -PayloadOutputPath $payloadPath -Machines @{} -AdvancedHuntingData @{}
        $payload = Read-GzipTextFile -Path $payloadPath | ConvertFrom-Json -Depth 100

        Assert-True ($result.VulnCount -eq 2) 'Expected repeated-CVE regression test to preserve both vulnerability rows.'
        Assert-True ($result.CveCount -eq 1) 'Expected repeated rows sharing the same CVE definition to reuse a single CVE lookup.'
        Assert-True ($payload.lookups.cves.Count -eq 1) 'Expected the payload to materialize only one CVE lookup for repeated CVE rows.'
    }
    finally {
        if (Test-Path -LiteralPath $tempRoot) {
            Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

function Test-ConvertToNormalizedDataReportsZeroOnboardedContentStoreDiagnostic {
    [CmdletBinding()]
    param()

    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('normalized-zero-onboarded-content-store-' + [guid]::NewGuid().ToString('N'))
    [void](New-Item -Path $tempRoot -ItemType Directory -Force)
    $outputPath = Join-Path $tempRoot 'normalized-vulns.json'

    try {
        $currentRow = Get-TestVulnRow -Id 'zero-onboarded-001' -CveId 'CVE-2026-0156' -SnapshotDate '2026-03-20' -Version '4.0.0'
        $currentRow.IsOnboarded = $false

        Write-NdjsonRecordsFile -Path (Get-VulnCurrentPath -BasePath $tempRoot) -Records @($currentRow)
        Publish-VulnContentStoreUnlocked -BasePath $tempRoot

        $errorMessage = $null
        try {
            $null = ConvertTo-NormalizedData -DataPath $tempRoot -VulnOutputPath $outputPath -Machines @{} -AdvancedHuntingData @{} -SkipObservedWindowMerge
            throw 'Expected zero-onboarded content-store normalization to fail with a diagnostic message.'
        }
        catch {
            $errorMessage = [string]$_.Exception.Message
        }

        Assert-True ($errorMessage -like "*No onboarded vulnerabilities were produced while normalizing content-store refs*") 'Expected zero-onboarded content-store failures to identify the content-store path.'
        Assert-True ($errorMessage -like '*device profiles 1 total/0 onboarded*') 'Expected zero-onboarded content-store failures to report device profile counts.'
        Assert-True ($errorMessage -like '*content templates 1*') 'Expected zero-onboarded content-store failures to report content template counts.'
        Assert-True ($errorMessage -like '*ob missing or false*') 'Expected zero-onboarded content-store failures to hint at compact onboarding flags.'
    }
    finally {
        if (Test-Path -LiteralPath $tempRoot) {
            Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

function Test-ConvertToNormalizedDataIncludesAdvancedHuntingDeviceUserMap {
    [CmdletBinding()]
    param()

    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('normalized-device-users-' + [guid]::NewGuid().ToString('N'))
    [void](New-Item -Path $tempRoot -ItemType Directory -Force)
    $outputPath = Join-Path $tempRoot 'normalized-vulns.json'

    try {
        $currentRow = Get-TestVulnRow -Id 'device-users-001' -CveId 'CVE-2026-0121' -SnapshotDate '2026-03-20' -Version '1.0.0'
        $currentRow.DeviceId = 'device-users-001'
        $currentRow.DeviceName = 'device-users-001.contoso.com'

        Write-NdjsonRecordsFile -Path (Get-VulnCurrentPath -BasePath $tempRoot) -Records @($currentRow)
        Write-NdjsonRecordsFile -Path (Get-AdvancedHuntingCurrentPath -BasePath $tempRoot) -Records @(
            [PSCustomObject]@{
                CveId = 'CVE-2026-0121'
                PublishedDate = '2026-03-20'
                VulnerabilityDescription = 'Device-user tooltip regression.'
                EpssScore = 0.15
                AffectedSoftware = @('contoso:legacy_agent')
            }
            [PSCustomObject]@{
                DeviceId = 'device-users-001'
                LoggedOnUsers = '[{"AccountName":"alice","DomainName":"CONTOSO"},{"UserPrincipalName":"bob@contoso.com"},{"AccountName":"alice","DomainName":"CONTOSO"}]'
                LastModifiedTime = '2026-03-20T08:30:00Z'
            }
        )

        $machines = @{
            'device-users-001' = [PSCustomObject]@{
                id = 'device-users-001'
                computerDnsName = 'device-users-001.contoso.com'
                rbacGroupName = 'Servers'
                osPlatform = 'Windows 11'
                osVersion = '10.0.22631'
                machineTags = @('Prod')
                lastIpAddress = '10.0.0.21'
                lastExternalIpAddress = '52.0.0.21'
                healthStatus = 'Active'
                riskScore = 'Medium'
                exposureLevel = 'Medium'
                deviceValue = 'Normal'
                managedBy = 'Intune'
                isAadJoined = $true
                lastSeen = '2026-03-20'
                firstSeen = '2026-02-01'
            }
        }

        $advancedHuntingData = Read-AdvancedHuntingData -Path $tempRoot
        $advancedHuntingDeviceUsers = Read-AdvancedHuntingDeviceUserMap -Path $tempRoot
        $result = ConvertTo-NormalizedData -DataPath $tempRoot -VulnOutputPath $outputPath -Machines $machines -AdvancedHuntingData $advancedHuntingData -AdvancedHuntingDeviceUsers $advancedHuntingDeviceUsers

        $device = @($result.Lookups.devices | Where-Object { $_.id -eq 'device-users-001' })[0]
        $users = @($device.m.u)

        Assert-True ($advancedHuntingDeviceUsers.Count -eq 1) 'Expected one device-user entry to be loaded from Advanced Hunting.'
        Assert-True ($users.Count -eq 2) 'Expected normalized machine info to include two unique logged-on users.'
        Assert-True ('CONTOSO\alice' -in $users) 'Expected normalized device users to include the domain-qualified account name.'
        Assert-True ('bob@contoso.com' -in $users) 'Expected normalized device users to include the user principal name.'
    }
    finally {
        if (Test-Path -LiteralPath $tempRoot) {
            Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

function Test-WriteCombinedPayloadGzipPreservesColumnPayload {
    [CmdletBinding()]
    param()

    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('combined-payload-columns-' + [guid]::NewGuid().ToString('N'))
    [void](New-Item -Path $tempRoot -ItemType Directory -Force)
    $outputPath = Join-Path $tempRoot 'normalized-vulns.json'
    $columnPath = Join-Path $tempRoot 'columns'
    $payloadPath = Join-Path $tempRoot 'payload.json.gz'

    try {
        $currentRow = Get-TestVulnRow -Id 'combined-columns-001' -CveId 'CVE-2026-0211' -SnapshotDate '2026-03-21' -Version '2.0.0'
        $historyRow = Get-TestVulnRow -Id 'combined-columns-002' -CveId 'CVE-2026-0212' -SnapshotDate '2026-03-19' -Version '2.1.0'

        Write-NdjsonRecordsFile -Path (Get-VulnCurrentPath -BasePath $tempRoot) -Records @($currentRow)
        [void](New-Item -Path (Get-VulnHistoryPath -BasePath $tempRoot -PeriodKey '2026Q1') -ItemType File -Force)
        Write-NdjsonRecordsFile -Path (Get-VulnHistoryRowsPath -BasePath $tempRoot -PeriodKey '2026Q1') -Records @($historyRow)

        $result = ConvertTo-NormalizedData -DataPath $tempRoot -VulnOutputPath $outputPath -VulnColumnDirectoryPath $columnPath -Machines @{} -AdvancedHuntingData @{}
        Write-CombinedPayloadGzip -Lookups $result.Lookups -VulnColumnPaths $result.VulnColumnPaths -OutputPath $payloadPath

        $payload = Read-GzipTextFile -Path $payloadPath | ConvertFrom-Json -Depth 100

        Assert-True ([string]::IsNullOrWhiteSpace([string]$result.VulnsPath)) 'Expected explicit column normalization not to materialize a vuln rows file.'
        Assert-True ($null -ne $result.VulnColumnPaths) 'Expected explicit column normalization to return vuln column paths.'
        Assert-True ($payload.vulnsFormat -eq 'columns-v1') 'Expected combined payload writer to preserve the columns-v1 payload format.'
        Assert-True ((Get-CompressedPayloadVulnCount -Path $payloadPath) -eq $result.VulnCount) 'Expected combined payload row count to match the processed vulnerability count.'
        Assert-True (@($payload.vulns.d).Count -eq $result.VulnCount) 'Expected device column count to match the processed vulnerability count.'
    }
    finally {
        if (Test-Path -LiteralPath $tempRoot) {
            Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

function Test-NormalizedVulnColumnCacheRebuildsPayloadWithFreshLookups {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '', Justification = 'Regression test name is intentionally plural because it validates payload rebuild behavior across cached lookup inputs.')]
    [CmdletBinding()]
    param()

    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('normalized-column-cache-' + [guid]::NewGuid().ToString('N'))
    [void](New-Item -Path $tempRoot -ItemType Directory -Force)
    $outputPath = Join-Path $tempRoot 'normalized-vulns.json'
    $columnPath = Join-Path $tempRoot 'columns'
    $originalPayloadPath = Join-Path $tempRoot 'original-payload.json.gz'
    $reusedPayloadPath = Join-Path $tempRoot 'reused-payload.json.gz'

    try {
        $currentRow = Get-TestVulnRow -Id 'column-cache-001' -CveId 'CVE-2026-0511' -SnapshotDate '2026-03-21' -Version '6.0.0'
        $historyRow = Get-TestVulnRow -Id 'column-cache-002' -CveId 'CVE-2026-0512' -SnapshotDate '2026-03-19' -Version '6.1.0'
        $historyRow.DeviceId = 'device-002'
        $historyRow.DeviceName = 'device02.contoso.com'
        $historyRow.MachineTags = @('Pilot', 'Prod')

        Write-NdjsonRecordsFile -Path (Get-VulnCurrentPath -BasePath $tempRoot) -Records @($currentRow)
        [void](New-Item -Path (Get-VulnHistoryPath -BasePath $tempRoot -PeriodKey '2026Q1') -ItemType File -Force)
        Write-NdjsonRecordsFile -Path (Get-VulnHistoryRowsPath -BasePath $tempRoot -PeriodKey '2026Q1') -Records @($historyRow)
        Write-NdjsonRecordsFile -Path (Get-AdvancedHuntingCurrentPath -BasePath $tempRoot) -Records @(
            [PSCustomObject]@{
                CveId = 'CVE-2026-0511'
                PublishedDate = '2026-03-20'
                VulnerabilityDescription = 'Column cache rebuild regression.'
                EpssScore = 0.31
                AffectedSoftware = @('contoso:legacy_agent')
            }
            [PSCustomObject]@{
                CveId = 'CVE-2026-0512'
                PublishedDate = '2026-03-18'
                VulnerabilityDescription = 'Column cache rebuild regression history row.'
                EpssScore = 0.22
                AffectedSoftware = @('contoso:legacy_agent')
            }
        )

        Publish-VulnContentStoreUnlocked -BasePath $tempRoot

        $advancedHuntingData = Read-AdvancedHuntingData -Path $tempRoot
        $advancedHuntingDeviceUsers = Read-AdvancedHuntingDeviceUserMap -Path $tempRoot
        $advancedHuntingInventoryData = Read-AdvancedHuntingInventoryData -Path $tempRoot
        $normalizedResult = ConvertTo-NormalizedData `
            -DataPath $tempRoot `
            -VulnOutputPath $outputPath `
            -VulnColumnDirectoryPath $columnPath `
            -Machines @{} `
            -AdvancedHuntingData $advancedHuntingData `
            -AdvancedHuntingDeviceUsers $advancedHuntingDeviceUsers `
            -AdvancedHuntingInventoryData $advancedHuntingInventoryData `
            -SkipObservedWindowMerge
        Write-CombinedPayloadGzip -Lookups $normalizedResult.Lookups -VulnColumnPaths $normalizedResult.VulnColumnPaths -OutputPath $originalPayloadPath

        $cacheEntry = Publish-NormalizedVulnColumnCache `
            -BasePath $tempRoot `
            -VulnColumnPaths $normalizedResult.VulnColumnPaths `
            -VulnCount $normalizedResult.VulnCount `
            -Dates @($normalizedResult.Lookups.dates) `
            -Quality $normalizedResult.Quality `
            -SkipObservedWindowMerge `
            -InventoryTupleCount $advancedHuntingInventoryData.Count
        $restoredCacheEntry = Get-NormalizedVulnColumnCacheEntry -BasePath $tempRoot -SkipObservedWindowMerge
        $restoredLookups = Restore-ContentStoreNormalizedLookupsFromColumnCache `
            -DataPath $tempRoot `
            -Machines @{} `
            -AdvancedHuntingData $advancedHuntingData `
            -AdvancedHuntingDeviceUsers $advancedHuntingDeviceUsers `
            -AdvancedHuntingInventoryData $advancedHuntingInventoryData `
            -CachedDates @($restoredCacheEntry.Manifest.Dates)
        Write-CombinedPayloadGzip -Lookups $restoredLookups.Lookups -VulnColumnPaths $restoredCacheEntry.ColumnPaths -OutputPath $reusedPayloadPath

        $originalPayloadJson = Read-GzipTextFile -Path $originalPayloadPath
        $reusedPayloadJson = Read-GzipTextFile -Path $reusedPayloadPath

        Assert-True ($null -ne $cacheEntry) 'Expected normalized vuln column cache publish to succeed.'
        Assert-True ($null -ne $restoredCacheEntry) 'Expected normalized vuln column cache retrieval to succeed.'
        Assert-True ($advancedHuntingInventoryData.Count -eq 0) 'Expected test fixture to avoid Advanced Hunting inventory tuples so column cache reuse stays valid.'
        Assert-True ((Get-CompressedPayloadVulnCount -Path $originalPayloadPath) -eq (Get-CompressedPayloadVulnCount -Path $reusedPayloadPath)) 'Expected cached column payload rebuild to preserve vulnerability row count.'
        Assert-True ($originalPayloadJson -eq $reusedPayloadJson) 'Expected cached normalized vuln columns plus rebuilt lookups to reproduce the same payload JSON.'
    }
    finally {
        if (Test-Path -LiteralPath $tempRoot) {
            Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

function Test-NormalizedVulnColumnCacheRefreshesInventoryColumn {
    [CmdletBinding()]
    param()

    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('normalized-column-cache-inventory-' + [guid]::NewGuid().ToString('N'))
    [void](New-Item -Path $tempRoot -ItemType Directory -Force)
    $outputPath = Join-Path $tempRoot 'normalized-vulns.json'
    $columnPath = Join-Path $tempRoot 'columns'
    $refreshedColumnPath = Join-Path $tempRoot 'refreshed-columns'
    $originalPayloadPath = Join-Path $tempRoot 'original-payload.json.gz'
    $reusedPayloadPath = Join-Path $tempRoot 'reused-payload.json.gz'

    try {
        $currentRow = Get-TestVulnRow -Id 'column-cache-inventory-001' -CveId 'CVE-2026-0611' -SnapshotDate '2026-03-21' -Version '6.0.0'
        Write-NdjsonRecordsFile -Path (Get-VulnCurrentPath -BasePath $tempRoot) -Records @($currentRow)

        Write-NdjsonRecordsFile -Path (Get-AdvancedHuntingCurrentPath -BasePath $tempRoot) -Records @(
            [PSCustomObject]@{
                CveId = 'CVE-2026-0611'
                PublishedDate = '2026-03-20'
                VulnerabilityDescription = 'Column cache inventory regression.'
                EpssScore = 0.31
                AffectedSoftware = @('contoso:legacy_agent')
            }
            [PSCustomObject]@{
                DeviceId = 'device-001'
                SoftwareVendor = 'contoso'
                SoftwareName = 'legacy_agent'
                SoftwareVersion = '6.0.0'
                ProductCodeCpe = 'cpe:/a:contoso:legacy_agent:6.0.0'
                EndOfSupportStatus = 'supported'
                EndOfSupportDate = '2027-10-01'
            }
        )

        Publish-VulnContentStoreUnlocked -BasePath $tempRoot

        $advancedHuntingData = Read-AdvancedHuntingData -Path $tempRoot
        $advancedHuntingDeviceUsers = Read-AdvancedHuntingDeviceUserMap -Path $tempRoot
        $advancedHuntingInventoryData = Read-AdvancedHuntingInventoryData -Path $tempRoot
        $normalizedResult = ConvertTo-NormalizedData `
            -DataPath $tempRoot `
            -VulnOutputPath $outputPath `
            -VulnColumnDirectoryPath $columnPath `
            -Machines @{} `
            -AdvancedHuntingData $advancedHuntingData `
            -AdvancedHuntingDeviceUsers $advancedHuntingDeviceUsers `
            -AdvancedHuntingInventoryData $advancedHuntingInventoryData `
            -SkipObservedWindowMerge
        Write-CombinedPayloadGzip -Lookups $normalizedResult.Lookups -VulnColumnPaths $normalizedResult.VulnColumnPaths -OutputPath $originalPayloadPath

        $cacheEntry = Publish-NormalizedVulnColumnCache `
            -BasePath $tempRoot `
            -VulnColumnPaths $normalizedResult.VulnColumnPaths `
            -VulnCount $normalizedResult.VulnCount `
            -Dates @($normalizedResult.Lookups.dates) `
            -Quality $normalizedResult.Quality `
            -SkipObservedWindowMerge `
            -InventoryTupleCount $advancedHuntingInventoryData.Count
        $restoredCacheEntry = Get-NormalizedVulnColumnCacheEntry -BasePath $tempRoot -SkipObservedWindowMerge
        $restoredLookups = Restore-ContentStoreNormalizedLookupsFromColumnCache `
            -DataPath $tempRoot `
            -Machines @{} `
            -AdvancedHuntingData $advancedHuntingData `
            -AdvancedHuntingDeviceUsers $advancedHuntingDeviceUsers `
            -AdvancedHuntingInventoryData $advancedHuntingInventoryData `
            -CachedDates @($restoredCacheEntry.Manifest.Dates)
        $restoredColumnPaths = Restore-NormalizedVulnColumnPathsFromCache `
            -CachedColumnPaths $restoredCacheEntry.ColumnPaths `
            -RestoredLookupsResult $restoredLookups `
            -OutputDirectoryPath $refreshedColumnPath `
            -CachedInventoryTupleCount ([int]$restoredCacheEntry.Manifest.InventoryTupleCount)
        Write-CombinedPayloadGzip -Lookups $restoredLookups.Lookups -VulnColumnPaths $restoredColumnPaths.ColumnPaths -OutputPath $reusedPayloadPath

        $originalPayloadJson = Read-GzipTextFile -Path $originalPayloadPath
        $reusedPayloadJson = Read-GzipTextFile -Path $reusedPayloadPath

        Assert-True ($null -ne $cacheEntry) 'Expected normalized vuln column cache publish to succeed for an inventory-backed fixture.'
        Assert-True ($null -ne $restoredCacheEntry) 'Expected normalized vuln column cache retrieval to succeed for an inventory-backed fixture.'
        Assert-True ($advancedHuntingInventoryData.Count -eq 1) 'Expected the inventory-backed fixture to produce one Advanced Hunting inventory tuple.'
        Assert-True ($restoredColumnPaths.RefreshedInventoryColumn -eq $true) 'Expected cached inventory column regeneration to run for an inventory-backed fixture.'
        Assert-True ($restoredLookups.Lookups.inventory.Count -eq $normalizedResult.Lookups.inventory.Count) 'Expected refreshed inventory lookups to preserve the same lookup cardinality as the original normalization.'
        Assert-True ((Get-CompressedPayloadVulnCount -Path $originalPayloadPath) -eq (Get-CompressedPayloadVulnCount -Path $reusedPayloadPath)) 'Expected refreshed inventory-column payload rebuild to preserve vulnerability row count.'
        Assert-True ($originalPayloadJson -eq $reusedPayloadJson) 'Expected cached normalized vuln columns plus refreshed inventory column to reproduce the same payload JSON.'
    }
    finally {
        if (Test-Path -LiteralPath $tempRoot) {
            Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

function Test-AdvancedHuntingBundleMatchesDedicatedReaderData {
    [CmdletBinding()]
    param()

    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('advanced-hunting-bundle-' + [guid]::NewGuid().ToString('N'))
    [void](New-Item -Path $tempRoot -ItemType Directory -Force)

    try {
        Write-NdjsonRecordsFile -Path (Get-AdvancedHuntingCurrentPath -BasePath $tempRoot) -Records @(
            [PSCustomObject]@{
                CveId = 'CVE-2026-0711'
                PublishedDate = '2026-03-20'
                VulnerabilityDescription = @('Bundle regression line 1.', 'Bundle regression line 2.')
                EpssScore = 0.31
                AffectedSoftware = @('contoso:legacy_agent')
                IsExploitAvailable = 'true'
            }
            [PSCustomObject]@{
                DeviceId = 'device-001'
                LoggedOnUsers = @(
                    [PSCustomObject]@{ UserPrincipalName = 'user1@contoso.com' }
                    [PSCustomObject]@{ DomainName = 'CONTOSO'; AccountName = 'user2' }
                )
            }
            [PSCustomObject]@{
                DeviceId = 'device-001'
                SoftwareVendor = 'contoso'
                SoftwareName = 'legacy_agent'
                SoftwareVersion = '6.0.0'
                ProductCodeCpe = 'cpe:/a:contoso:legacy_agent:6.0.0'
                EndOfSupportStatus = 'supported'
                EndOfSupportDate = '2027-10-01'
            }
        )

        $advancedHuntingData = Read-AdvancedHuntingData -Path $tempRoot
        $advancedHuntingDeviceUsers = Read-AdvancedHuntingDeviceUserMap -Path $tempRoot
        $advancedHuntingInventoryData = Read-AdvancedHuntingInventoryData -Path $tempRoot
        $bundle = Read-AdvancedHuntingBundle -Path $tempRoot -IncludeDeviceUsers -IncludeInventoryData

        Assert-True ($bundle.AdvancedHuntingData.Count -eq $advancedHuntingData.Count) 'Expected Advanced Hunting bundle CVE count to match the dedicated reader.'
        Assert-True ($bundle.DeviceUsers.Count -eq $advancedHuntingDeviceUsers.Count) 'Expected Advanced Hunting bundle device-user count to match the dedicated reader.'
        Assert-True ($bundle.InventoryData.Count -eq $advancedHuntingInventoryData.Count) 'Expected Advanced Hunting bundle inventory count to match the dedicated reader.'

        $bundleCve = $bundle.AdvancedHuntingData['CVE-2026-0711']
        $dedicatedCve = $advancedHuntingData['CVE-2026-0711']
        Assert-True ($bundleCve.PublishedDate -eq $dedicatedCve.PublishedDate) 'Expected bundle CVE published date to match the dedicated reader.'
        Assert-True ($bundleCve.VulnerabilityDescription -eq $dedicatedCve.VulnerabilityDescription) 'Expected bundle CVE description to match the dedicated reader.'
        Assert-True ($bundleCve.EpssScore -eq $dedicatedCve.EpssScore) 'Expected bundle CVE EPSS score to match the dedicated reader.'
        Assert-True ($bundleCve.IsExploitAvailable -eq $dedicatedCve.IsExploitAvailable) 'Expected bundle CVE exploit availability to match the dedicated reader.'
        Assert-True (@($bundleCve.AffectedSoftware).Count -eq @($dedicatedCve.AffectedSoftware).Count) 'Expected bundle CVE affected software count to match the dedicated reader.'
        Assert-True (@($bundleCve.AffectedSoftware)[0] -eq @($dedicatedCve.AffectedSoftware)[0]) 'Expected bundle CVE affected software values to match the dedicated reader.'

        $bundleUsers = @($bundle.DeviceUsers['device-001'])
        $dedicatedUsers = @($advancedHuntingDeviceUsers['device-001'])
        Assert-True ($bundleUsers.Count -eq $dedicatedUsers.Count) 'Expected bundle device-user list length to match the dedicated reader.'
        Assert-True ($bundleUsers[0] -eq $dedicatedUsers[0]) 'Expected bundle device-user list to preserve the first user.'
        Assert-True ($bundleUsers[1] -eq $dedicatedUsers[1]) 'Expected bundle device-user list to preserve the second user.'

        $inventoryKey = Get-AdvancedHuntingInventoryMatchKey -DeviceId 'device-001' -SoftwareVendor 'contoso' -SoftwareName 'legacy_agent' -SoftwareVersion '6.0.0'
        $bundleInventory = $bundle.InventoryData[$inventoryKey]
        $dedicatedInventory = $advancedHuntingInventoryData[$inventoryKey]
        Assert-True ($bundleInventory.ProductCodeCpe -eq $dedicatedInventory.ProductCodeCpe) 'Expected bundle inventory ProductCodeCpe to match the dedicated reader.'
        Assert-True ($bundleInventory.EndOfSupportStatus -eq $dedicatedInventory.EndOfSupportStatus) 'Expected bundle inventory EndOfSupportStatus to match the dedicated reader.'
        Assert-True ($bundleInventory.EndOfSupportDate -eq $dedicatedInventory.EndOfSupportDate) 'Expected bundle inventory EndOfSupportDate to match the dedicated reader.'
    }
    finally {
        if (Test-Path -LiteralPath $tempRoot) {
            Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

function Test-AdvancedHuntingBundleStringArrayFiltersSparseInputs {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '', Justification = 'Regression test name intentionally refers to multiple sparse inputs.')]
    [CmdletBinding()]
    param()

    $emptyResult = ConvertTo-AdvancedHuntingBundleStringArray -Value @()
    Assert-True ($emptyResult -is [string[]]) 'Expected empty Advanced Hunting bundle string arrays to preserve the string[] output type.'
    Assert-True ($emptyResult.Count -eq 0) 'Expected an empty Advanced Hunting bundle input to remain empty.'

    $singletonResult = ConvertTo-AdvancedHuntingBundleStringArray -Value 'contoso:legacy_agent'
    Assert-True ($singletonResult -is [string[]]) 'Expected singleton Advanced Hunting bundle values to preserve the string[] output type.'
    Assert-True ($singletonResult.Count -eq 1) 'Expected a singleton Advanced Hunting bundle value to stay a single entry.'
    Assert-True ($singletonResult[0] -eq 'contoso:legacy_agent') 'Expected a singleton Advanced Hunting bundle value to remain unchanged.'

    $filteredResult = ConvertTo-AdvancedHuntingBundleStringArray -Value @($null, 'contoso:legacy_agent', '   ', 'fabrikam:browser', "`t")
    Assert-True ($filteredResult -is [string[]]) 'Expected filtered Advanced Hunting bundle values to preserve the string[] output type.'
    Assert-True ($filteredResult.Count -eq 2) 'Expected Advanced Hunting bundle string normalization to drop null and whitespace-only entries.'
    Assert-True ($filteredResult[0] -eq 'contoso:legacy_agent') 'Expected Advanced Hunting bundle string normalization to preserve the first non-empty value.'
    Assert-True ($filteredResult[1] -eq 'fabrikam:browser') 'Expected Advanced Hunting bundle string normalization to preserve later non-empty values in order.'
}

function Test-ReadNormalizationMachineLookupMatchesCompressedMachineLookup {
    [CmdletBinding()]
    param()

    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('machine-tuple-reader-' + [guid]::NewGuid().ToString('N'))
    [void](New-Item -Path $tempRoot -ItemType Directory -Force)

    try {
        Write-NdjsonRecordsFile -Path (Get-MachineCurrentPath -BasePath $tempRoot) -Records @(
            [PSCustomObject]@{
                id = 'device-live'
                computerDnsName = 'device-live.contoso.com'
                rbacGroupName = 'Servers'
                osPlatform = 'Windows'
                osVersion = '10.0.22631'
                machineTags = @('Prod')
                lastIpAddress = '10.0.0.1'
                lastExternalIpAddress = '203.0.113.10'
                healthStatus = 'Active'
                riskScore = 'Medium'
                exposureLevel = 'High'
                deviceValue = 'Normal'
                managedBy = 'Intune'
                isAadJoined = $true
                lastSeen = '2026-03-20'
                firstSeen = '2026-03-10'
            }
            [PSCustomObject]@{
                id = 'device-sparse'
                computerDnsName = 'device-sparse.contoso.com'
                rbacGroupName = 'Servers'
                osPlatform = 'Windows'
                osVersion = '10.0.22631'
                machineTags = @('Prod')
                lastIpAddress = $null
                lastExternalIpAddress = $null
                healthStatus = $null
                riskScore = $null
                exposureLevel = $null
                deviceValue = $null
                managedBy = $null
                isAadJoined = $null
                lastSeen = $null
                firstSeen = $null
            }
            [PSCustomObject]@{
                id = 'device-removed'
                removed = $true
                observedOn = '2026-03-20'
                stateHash = 'removed'
            }
        )

        $standardMachines = Read-MachineData -Path $tempRoot
        $compressedMachines = @{}
        foreach ($deviceId in @($standardMachines.Keys)) {
            $compressedMachines[$deviceId] = $standardMachines[$deviceId]
        }
        Compress-NormalizationMachineLookup -Machines $compressedMachines | Out-Null

        $tupleMachines = Read-NormalizationMachineLookup -Path $tempRoot

        Assert-True ($tupleMachines.Count -eq $compressedMachines.Count) 'Expected tuple-mode machine loading to preserve the same machine count as the compressed machine lookup path.'
        Assert-True ($tupleMachines.ContainsKey('device-live')) 'Expected tuple-mode machine loading to preserve populated machines.'
        Assert-True ($tupleMachines.ContainsKey('device-sparse')) 'Expected tuple-mode machine loading to retain sparse machines when extended normalization metadata is present.'
        Assert-True (-not $tupleMachines.ContainsKey('device-removed')) 'Expected tuple-mode machine loading to drop removed machines from the current lookup.'

        $expectedTuple = [object[]]$compressedMachines['device-live']
        $actualTuple = [object[]]$tupleMachines['device-live']
        Assert-True ($actualTuple -is [System.Array]) 'Expected tuple-mode machine loading to materialize array-backed normalization tuples.'
        Assert-True ($actualTuple.Length -eq $expectedTuple.Length) 'Expected tuple-mode machine loading to preserve the normalization tuple shape.'

        $expectedSparseTuple = [object[]]$compressedMachines['device-sparse']
        $actualSparseTuple = [object[]]$tupleMachines['device-sparse']
        Assert-True ($actualSparseTuple -is [System.Array]) 'Expected tuple-mode machine loading to materialize sparse machines as array-backed normalization tuples.'
        Assert-True ($actualSparseTuple.Length -eq $expectedSparseTuple.Length) 'Expected tuple-mode machine loading to preserve the sparse normalization tuple shape.'

        for ($tupleIndex = 0; $tupleIndex -lt $expectedTuple.Length; $tupleIndex++) {
            $expectedTupleValue = ConvertTo-Json -InputObject $expectedTuple[$tupleIndex] -Compress -Depth 20
            $actualTupleValue = ConvertTo-Json -InputObject $actualTuple[$tupleIndex] -Compress -Depth 20
            Assert-True ($actualTupleValue -eq $expectedTupleValue) "Expected tuple-mode machine loading to preserve tuple slot $tupleIndex."
        }

        for ($tupleIndex = 0; $tupleIndex -lt $expectedSparseTuple.Length; $tupleIndex++) {
            $expectedSparseTupleValue = ConvertTo-Json -InputObject $expectedSparseTuple[$tupleIndex] -Compress -Depth 20
            $actualSparseTupleValue = ConvertTo-Json -InputObject $actualSparseTuple[$tupleIndex] -Compress -Depth 20
            Assert-True ($actualSparseTupleValue -eq $expectedSparseTupleValue) "Expected tuple-mode machine loading to preserve sparse tuple slot $tupleIndex."
        }
    }
    finally {
        if (Test-Path -LiteralPath $tempRoot) {
            Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

function Test-ReadFileBackedNormalizationMachineLookupMatchesCompressedMachineLookup {
    [CmdletBinding()]
    param()

    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('machine-file-backed-reader-' + [guid]::NewGuid().ToString('N'))
    [void](New-Item -Path $tempRoot -ItemType Directory -Force)
    $fileBackedMachines = $null

    try {
        Write-NdjsonRecordsFile -Path (Get-MachineCurrentPath -BasePath $tempRoot) -Records @(
            [PSCustomObject]@{
                id = 'device-live'
                computerDnsName = 'device-live.contoso.com'
                rbacGroupName = 'Servers'
                osPlatform = 'Windows'
                osVersion = '10.0.22631'
                machineTags = @('Prod')
                lastIpAddress = '10.0.0.1'
                lastExternalIpAddress = '203.0.113.10'
                healthStatus = 'Active'
                riskScore = 'Medium'
                exposureLevel = 'High'
                deviceValue = 'Normal'
                managedBy = 'Intune'
                isAadJoined = $true
                lastSeen = '2026-03-20'
                firstSeen = '2026-03-10'
            }
            [PSCustomObject]@{
                id = 'device-sparse'
                computerDnsName = 'device-sparse.contoso.com'
                rbacGroupName = 'Servers'
                osPlatform = 'Windows'
                osVersion = '10.0.22631'
                machineTags = @('Prod')
                lastIpAddress = $null
                lastExternalIpAddress = $null
                healthStatus = $null
                riskScore = $null
                exposureLevel = $null
                deviceValue = $null
                managedBy = $null
                isAadJoined = $null
                lastSeen = $null
                firstSeen = $null
            }
            [PSCustomObject]@{
                id = 'device-removed'
                removed = $true
                observedOn = '2026-03-20'
                stateHash = 'removed'
            }
        )

        $standardMachines = Read-MachineData -Path $tempRoot
        $compressedMachines = @{}
        foreach ($deviceId in @($standardMachines.Keys)) {
            $compressedMachines[$deviceId] = $standardMachines[$deviceId]
        }
        Compress-NormalizationMachineLookup -Machines $compressedMachines | Out-Null

        $fileBackedMachines = Read-NormalizationMachineLookup -Path $tempRoot -FileBacked

        Assert-True (Test-FileBackedNormalizationMachineLookup -Machines $fileBackedMachines) 'Expected file-backed tuple-mode machine loading to return a file-backed lookup.'
        Assert-True ((Get-NormalizationMachineLookupCount -Machines $fileBackedMachines) -eq $compressedMachines.Count) 'Expected file-backed tuple-mode machine loading to preserve the same machine count as the compressed machine lookup path.'

        $expectedTuple = [object[]]$compressedMachines['device-live']
        $actualTuple = Read-FileBackedNormalizationMachineTuple -Machines $fileBackedMachines -DeviceId 'device-live'
        Assert-True ($actualTuple -is [System.Array]) 'Expected file-backed tuple-mode machine loading to materialize array-backed normalization tuples.'
        Assert-True ($actualTuple.Length -eq $expectedTuple.Length) 'Expected file-backed tuple-mode machine loading to preserve the normalization tuple shape.'

        $expectedSparseTuple = [object[]]$compressedMachines['device-sparse']
        $actualSparseTuple = Read-FileBackedNormalizationMachineTuple -Machines $fileBackedMachines -DeviceId 'device-sparse'
        Assert-True ($actualSparseTuple -is [System.Array]) 'Expected file-backed tuple-mode machine loading to materialize sparse machines as array-backed normalization tuples.'
        Assert-True ($actualSparseTuple.Length -eq $expectedSparseTuple.Length) 'Expected file-backed tuple-mode machine loading to preserve the sparse normalization tuple shape.'

        Assert-True ($null -eq (Read-FileBackedNormalizationMachineTuple -Machines $fileBackedMachines -DeviceId 'device-removed')) 'Expected file-backed tuple-mode machine loading to drop removed machines from the current lookup.'

        for ($tupleIndex = 0; $tupleIndex -lt $expectedTuple.Length; $tupleIndex++) {
            $expectedTupleValue = ConvertTo-Json -InputObject $expectedTuple[$tupleIndex] -Compress -Depth 20
            $actualTupleValue = ConvertTo-Json -InputObject $actualTuple[$tupleIndex] -Compress -Depth 20
            Assert-True ($actualTupleValue -eq $expectedTupleValue) "Expected file-backed tuple-mode machine loading to preserve tuple slot $tupleIndex."
        }

        for ($tupleIndex = 0; $tupleIndex -lt $expectedSparseTuple.Length; $tupleIndex++) {
            $expectedSparseTupleValue = ConvertTo-Json -InputObject $expectedSparseTuple[$tupleIndex] -Compress -Depth 20
            $actualSparseTupleValue = ConvertTo-Json -InputObject $actualSparseTuple[$tupleIndex] -Compress -Depth 20
            Assert-True ($actualSparseTupleValue -eq $expectedSparseTupleValue) "Expected file-backed tuple-mode machine loading to preserve sparse tuple slot $tupleIndex."
        }
    }
    finally {
        if ($null -ne $fileBackedMachines) {
            Remove-FileBackedNormalizationMachineLookup -Machines $fileBackedMachines
        }

        if (Test-Path -LiteralPath $tempRoot) {
            Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

function Test-ReadBucketedFileBackedNormalizationMachineLookupMatchesCompressedMachineLookup {
    [CmdletBinding()]
    param()

    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('machine-bucketed-reader-' + [guid]::NewGuid().ToString('N'))
    [void](New-Item -Path $tempRoot -ItemType Directory -Force)
    $bucketedMachines = $null

    try {
        Write-NdjsonRecordsFile -Path (Get-MachineCurrentPath -BasePath $tempRoot) -Records @(
            [PSCustomObject]@{
                id = 'device-live'
                computerDnsName = 'device-live.contoso.com'
                rbacGroupName = 'Servers'
                osPlatform = 'Windows'
                osVersion = '10.0.22631'
                machineTags = @('Prod')
                lastIpAddress = '10.0.0.1'
                lastExternalIpAddress = '203.0.113.10'
                healthStatus = 'Active'
                riskScore = 'Medium'
                exposureLevel = 'High'
                deviceValue = 'Normal'
                managedBy = 'Intune'
                isAadJoined = $true
                lastSeen = '2026-03-20'
                firstSeen = '2026-03-10'
            }
            [PSCustomObject]@{
                id = 'device-sparse'
                computerDnsName = 'device-sparse.contoso.com'
                rbacGroupName = 'Servers'
                osPlatform = 'Windows'
                osVersion = '10.0.22631'
                machineTags = @('Prod')
                lastIpAddress = $null
                lastExternalIpAddress = $null
                healthStatus = $null
                riskScore = $null
                exposureLevel = $null
                deviceValue = $null
                managedBy = $null
                isAadJoined = $null
                lastSeen = $null
                firstSeen = $null
            }
            [PSCustomObject]@{
                id = 'device-removed'
                removed = $true
                observedOn = '2026-03-20'
                stateHash = 'removed'
            }
        )

        $standardMachines = Read-MachineData -Path $tempRoot
        $compressedMachines = @{}
        foreach ($deviceId in @($standardMachines.Keys)) {
            $compressedMachines[$deviceId] = $standardMachines[$deviceId]
        }
        Compress-NormalizationMachineLookup -Machines $compressedMachines | Out-Null

        $bucketedMachines = Read-NormalizationMachineLookup -Path $tempRoot -FileBacked -Bucketed

        Assert-True (Test-FileBackedNormalizationMachineLookup -Machines $bucketedMachines) 'Expected bucketed file-backed tuple-mode machine loading to return a file-backed lookup.'
        Assert-True ((Get-NormalizationMachineLookupCount -Machines $bucketedMachines) -eq $compressedMachines.Count) 'Expected bucketed file-backed tuple-mode machine loading to preserve the same machine count as the compressed machine lookup path.'

        $expectedTuple = [object[]]$compressedMachines['device-live']
        $actualTuple = Read-FileBackedNormalizationMachineTuple -Machines $bucketedMachines -DeviceId 'device-live'
        Assert-True ($actualTuple -is [System.Array]) 'Expected bucketed file-backed tuple-mode machine loading to materialize array-backed normalization tuples.'
        Assert-True ($actualTuple.Length -eq $expectedTuple.Length) 'Expected bucketed file-backed tuple-mode machine loading to preserve the normalization tuple shape.'

        $expectedSparseTuple = [object[]]$compressedMachines['device-sparse']
        $actualSparseTuple = Read-FileBackedNormalizationMachineTuple -Machines $bucketedMachines -DeviceId 'device-sparse'
        Assert-True ($actualSparseTuple -is [System.Array]) 'Expected bucketed file-backed tuple-mode machine loading to materialize sparse machines as array-backed normalization tuples.'
        Assert-True ($actualSparseTuple.Length -eq $expectedSparseTuple.Length) 'Expected bucketed file-backed tuple-mode machine loading to preserve the sparse normalization tuple shape.'

        Assert-True ($null -eq (Read-FileBackedNormalizationMachineTuple -Machines $bucketedMachines -DeviceId 'device-removed')) 'Expected bucketed file-backed tuple-mode machine loading to drop removed machines from the current lookup.'

        for ($tupleIndex = 0; $tupleIndex -lt $expectedTuple.Length; $tupleIndex++) {
            $expectedTupleValue = ConvertTo-Json -InputObject $expectedTuple[$tupleIndex] -Compress -Depth 20
            $actualTupleValue = ConvertTo-Json -InputObject $actualTuple[$tupleIndex] -Compress -Depth 20
            Assert-True ($actualTupleValue -eq $expectedTupleValue) "Expected bucketed file-backed tuple-mode machine loading to preserve tuple slot $tupleIndex."
        }

        for ($tupleIndex = 0; $tupleIndex -lt $expectedSparseTuple.Length; $tupleIndex++) {
            $expectedSparseTupleValue = ConvertTo-Json -InputObject $expectedSparseTuple[$tupleIndex] -Compress -Depth 20
            $actualSparseTupleValue = ConvertTo-Json -InputObject $actualSparseTuple[$tupleIndex] -Compress -Depth 20
            Assert-True ($actualSparseTupleValue -eq $expectedSparseTupleValue) "Expected bucketed file-backed tuple-mode machine loading to preserve sparse tuple slot $tupleIndex."
        }
    }
    finally {
        if ($null -ne $bucketedMachines) {
            Remove-FileBackedNormalizationMachineLookup -Machines $bucketedMachines
        }

        if (Test-Path -LiteralPath $tempRoot) {
            Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

function Test-NormalizationMachineTupleExtendsLegacyTuple {
    [CmdletBinding()]
    param()

    $legacyTuple = [object[]]@(
        '10.0.0.30',
        '203.0.113.30',
        'Active',
        'Medium',
        'High',
        'Normal',
        'Intune',
        $true,
        '2026-04-22T00:00:00Z',
        '2026-04-01T00:00:00Z'
    )

    $normalizationTuple = ConvertTo-NormalizationMachineTuple -Machine $legacyTuple

    Assert-True ($normalizationTuple -is [object[]]) 'Expected legacy machine tuples to normalize as an object[] array.'
    Assert-True ($normalizationTuple.Count -eq 15) 'Expected legacy machine tuples with 10 elements to be extended to 15 normalization slots.'

    foreach ($index in 0..9) {
        Assert-True ($normalizationTuple[$index] -eq $legacyTuple[$index]) ("Expected normalization tuple slot {0} to preserve the legacy tuple value." -f $index)
    }

    foreach ($index in 10..14) {
        Assert-True ($null -eq $normalizationTuple[$index]) ("Expected normalization tuple slot {0} to be null-padded for legacy tuples without expanded metadata." -f $index)
    }
}

function Test-LegacyMachineTupleFallbackPreservesProjectedRowMetadata {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '', Justification = 'Regression test name intentionally describes legacy tuple fallback behavior.')]
    [CmdletBinding()]
    param()

    $legacyMachineTuple = [object[]]@(
        '10.0.0.30',
        '203.0.113.30',
        'Active',
        'Medium',
        'High',
        'Normal',
        'Intune',
        $true,
        '2026-04-22T00:00:00Z',
        '2026-04-01T00:00:00Z'
    )

    $projection = Get-MachineProjection -Machine $legacyMachineTuple
    Assert-True ($null -eq $projection.ComputerDnsName) 'Expected legacy tuples without expanded metadata to preserve a null ComputerDnsName projection.'
    Assert-True ($null -eq $projection.OSPlatform) 'Expected legacy tuples without expanded metadata to preserve a null OSPlatform projection.'
    Assert-True ($null -eq $projection.OSVersion) 'Expected legacy tuples without expanded metadata to preserve a null OSVersion projection.'

    $context = Get-NormalizationContext
    $context.Machines['device-legacy'] = $legacyMachineTuple

    $deviceIndex = Add-NormalizedDevice `
        -DeviceId 'device-legacy' `
        -DeviceName 'legacy-device.contoso.com' `
        -GroupName 'Pilot' `
        -OsPlatform 'Windows11' `
        -OsVersion '10.0.26100' `
        -MachineTags @('Pilot') `
        -Context $context

    $deviceLookup = $context.Lookups.devices[$deviceIndex]

    Assert-True ($deviceLookup.n -eq 'legacy-device.contoso.com') 'Expected Add-NormalizedDevice to fall back to the row DeviceName when a legacy tuple has no ComputerDnsName.'
    Assert-True ($context.Lookups.groups[$deviceLookup.g] -eq 'Pilot') 'Expected Add-NormalizedDevice to fall back to the row GroupName when a legacy tuple has no RBAC group.'
    Assert-True ($context.Lookups.platforms[$deviceLookup.o] -eq 'Windows11') 'Expected Add-NormalizedDevice to fall back to the row OSPlatform when a legacy tuple has no platform metadata.'
    Assert-True ($deviceLookup.ov -eq '10.0.26100') 'Expected Add-NormalizedDevice to fall back to the row OSVersion when a legacy tuple has no OSVersion metadata.'
    Assert-True ($context.Lookups.tags[$deviceLookup.t[0]] -eq 'Pilot') 'Expected Add-NormalizedDevice to fall back to row machine tags when a legacy tuple has no tag metadata.'
    Assert-True ($deviceLookup.m.ip -eq '10.0.0.30') 'Expected Add-NormalizedDevice to preserve machine info pulled from the legacy tuple.'
}

function Test-SourceCveEnrichmentReadsExploitAvailabilityFromObjectRecord {
    [CmdletBinding()]
    param()

    $vendorSet = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    [void]$vendorSet.Add((Get-VendorMatchKey -Vendor 'Contoso'))

    $advancedHunting = @{
        'CVE-2026-7777' = [PSCustomObject]@{
            PublishedDate = '2026-04-14'
            VulnerabilityDescription = 'Example vulnerability description.'
            EpssScore = 0.0042
            AffectedSoftware = @('Contoso:Legacy Agent')
            IsExploitAvailable = $true
        }
    }

    $enrichment = Get-SourceCveEnrichment -CveId 'CVE-2026-7777' -AdvancedHunting $advancedHunting -NvdCveData $null -VendorSet $vendorSet

    Assert-True ($enrichment.IsExploitAvailable -eq $true) 'Expected exploit availability to be preserved for PSCustomObject-based Advanced Hunting records.'
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

function Test-BenchmarkSeriesSummaryHandlesAzureOnlyRunMode {
    [CmdletBinding()]
    param()

    $azureOnlyRun = [PSCustomObject]@{
        include_local_benchmark = $false
        local_only = $false
        current = [PSCustomObject]@{
            local = $null
            runbook = [PSCustomObject]@{
                elapsed_seconds = 575.25
            }
            function_app = [PSCustomObject]@{
                active_elapsed_seconds = 530.51
                end_to_end_elapsed_seconds = 532.12
                pickup_delay_seconds = 1.61
            }
        }
    }

    $summary = Get-BenchmarkSeriesMetricSummary -RunResults @($azureOnlyRun) -LocalOnly:$false -IncludeLocalBenchmark:$false -IncludePersistentLocalWorkflow:$false

    Assert-True (-not (Test-BenchmarkIncludesLocalRun -BenchmarkObject $azureOnlyRun)) 'Expected Azure-only benchmark runs to report that no local benchmark was included.'
    Assert-True ($null -eq $summary.local_elapsed_seconds) 'Expected Azure-only benchmark summaries to omit local elapsed metrics.'
    Assert-True ($null -ne $summary.runbook_elapsed_seconds) 'Expected Azure-only benchmark summaries to retain runbook elapsed metrics.'
    Assert-True ($null -ne $summary.function_active_elapsed_seconds) 'Expected Azure-only benchmark summaries to retain Function App elapsed metrics.'
}

function Test-BenchmarkSeriesSummaryHandlesCombinedRunMode {
    [CmdletBinding()]
    param()

    $combinedRun = [PSCustomObject]@{
        include_local_benchmark = $true
        local_only = $false
        current = [PSCustomObject]@{
            local = [PSCustomObject]@{
                elapsed_seconds = 120.5
            }
            runbook = [PSCustomObject]@{
                elapsed_seconds = 575.25
            }
            function_app = [PSCustomObject]@{
                active_elapsed_seconds = 530.51
                end_to_end_elapsed_seconds = 532.12
                pickup_delay_seconds = 1.61
            }
        }
    }

    $summary = Get-BenchmarkSeriesMetricSummary -RunResults @($combinedRun) -LocalOnly:$false -IncludeLocalBenchmark:$true -IncludePersistentLocalWorkflow:$false

    Assert-True (Test-BenchmarkIncludesLocalRun -BenchmarkObject $combinedRun) 'Expected combined Azure plus local benchmark runs to report that a local benchmark was included.'
    Assert-True ($null -ne $summary.local_elapsed_seconds) 'Expected combined benchmark summaries to retain local elapsed metrics.'
}

function Test-BenchmarkSeriesSummaryHandlesLocalOnlyRunMode {
    [CmdletBinding()]
    param()

    $localOnlyRun = [PSCustomObject]@{
        local_only = $true
        current = [PSCustomObject]@{
            local = [PSCustomObject]@{
                elapsed_seconds = 98.75
            }
            runbook = $null
            function_app = $null
        }
    }

    $summary = Get-BenchmarkSeriesMetricSummary -RunResults @($localOnlyRun) -LocalOnly:$true -IncludeLocalBenchmark:$false -IncludePersistentLocalWorkflow:$false

    Assert-True (Test-BenchmarkIncludesLocalRun -BenchmarkObject $localOnlyRun) 'Expected local-only benchmark runs to report that a local benchmark was included even when the explicit include_local_benchmark flag is absent.'
    Assert-True ($null -ne $summary.local_elapsed_seconds) 'Expected local-only benchmark summaries to retain local elapsed metrics.'
    Assert-True ($null -eq $summary.runbook_elapsed_seconds) 'Expected local-only benchmark summaries to omit runbook elapsed metrics.'
    Assert-True ($null -eq $summary.function_active_elapsed_seconds) 'Expected local-only benchmark summaries to omit Function App elapsed metrics.'
}

function Test-BenchmarkIncludesLocalRunHandlesLegacyInferenceShape {
    [CmdletBinding()]
    param()

    $legacyRun = [PSCustomObject]@{
        local_only = $false
        persistent_local_workflow = $true
        current = [PSCustomObject]@{
            local = [PSCustomObject]@{
                elapsed_seconds = 142.25
            }
            runbook = [PSCustomObject]@{
                elapsed_seconds = 575.25
            }
            function_app = [PSCustomObject]@{
                active_elapsed_seconds = 530.51
                end_to_end_elapsed_seconds = 532.12
                pickup_delay_seconds = 1.61
            }
        }
    }

    Assert-True (Test-BenchmarkIncludesLocalRun -BenchmarkObject $legacyRun) 'Expected benchmark history helpers to infer local benchmark capture from legacy result shapes that include a local result but omit include_local_benchmark.'
}

function Test-BenchmarkModeScenarioKeyHandlesLegacyModeMapping {
    [CmdletBinding()]
    param()

    Assert-True ((Get-BenchmarkModeScenarioKey -BenchmarkMode 'current-only') -eq 'current-only') 'Expected the legacy current-only benchmark mode to normalize to the current-only scenario.'
    Assert-True ((Get-BenchmarkModeScenarioKey -BenchmarkMode 'azure-current-only') -eq 'current-only') 'Expected azure-current-only benchmark mode to normalize to the current-only scenario.'
    Assert-True ((Get-BenchmarkModeScenarioKey -BenchmarkMode 'azure-plus-local-current-only') -eq 'current-only') 'Expected azure-plus-local-current-only benchmark mode to normalize to the current-only scenario.'
    Assert-True ((Get-BenchmarkModeScenarioKey -BenchmarkMode 'branch-vs-main') -eq 'branch-vs-main') 'Expected the legacy branch-vs-main benchmark mode to normalize to the branch-vs-main scenario.'
    Assert-True ((Get-BenchmarkModeScenarioKey -BenchmarkMode 'azure-branch-vs-main') -eq 'branch-vs-main') 'Expected azure-branch-vs-main benchmark mode to normalize to the branch-vs-main scenario.'
    Assert-True ((Get-BenchmarkModeScenarioKey -BenchmarkMode 'azure-plus-local-branch-vs-main') -eq 'branch-vs-main') 'Expected azure-plus-local-branch-vs-main benchmark mode to normalize to the branch-vs-main scenario.'
}

function Test-WriteProgressMarkerIncludesEtaWhenTotalCountKnown {
    [CmdletBinding()]
    param()

    $progressState = New-ProgressMarkerState -ActivityName 'ETA regression' -ProgressInterval 10 -HeartbeatIntervalSeconds 60 -CheckInterval 1 -TotalCount 100
    $outputRecords = @(& {
            Write-ProgressMarker -State $progressState -Count 10 -UnitLabel 'row(s)'
        } 6>&1)
    $outputText = (@($outputRecords | ForEach-Object { Get-OutputRecordText -Record $_ }) -join [Environment]::NewLine)

    Assert-True (-not [string]::IsNullOrWhiteSpace($outputText)) 'Expected Write-ProgressMarker to emit a progress message when the interval is reached.'
    Assert-True ($outputText.Contains('ETA ')) 'Expected Write-ProgressMarker to include ETA text when the total row count is known.'
    Assert-True ($outputText.Contains('10.0% complete')) 'Expected Write-ProgressMarker ETA output to preserve the percent complete marker.'
}

function Test-ValidationHelperPayloadCanonicalization {
    [CmdletBinding()]
    param()

    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('validation-helper-payload-formats-' + [guid]::NewGuid().ToString('N'))
    [void](New-Item -Path $tempRoot -ItemType Directory -Force)
    $repoRoot = Split-Path -Path $PSScriptRoot -Parent
    $rowsOutputPath = Join-Path $tempRoot 'rows-normalized.json'
    $rowsPayloadPath = Join-Path $tempRoot 'rows-payload.json.gz'
    $columnsOutputPath = Join-Path $tempRoot 'columns-normalized.json'
    $columnPath = Join-Path $tempRoot 'columns'
    $columnsPayloadPath = Join-Path $tempRoot 'columns-payload.json.gz'

    try {
        . (Join-Path $repoRoot 'build\Import-ValidationHelpers.ps1')

        $currentRow = Get-TestVulnRow -Id 'validation-format-001' -CveId 'CVE-2026-0311' -SnapshotDate '2026-03-20' -Version '3.0.0'
        $historyRow = Get-TestVulnRow -Id 'validation-format-002' -CveId 'CVE-2026-0312' -SnapshotDate '2026-03-18' -Version '3.1.0'
        $historyRow.DeviceId = 'device-002'
        $historyRow.DeviceName = 'device02.contoso.com'
        $historyRow.MachineTags = @('Pilot', 'Prod')
        $historyRow.DiskPaths = @('C:\Program Files\Legacy Agent\agent-alt.exe')
        $historyRow.RegistryPaths = @('HKLM\Software\Contoso\LegacyAgentAlt')

        Write-NdjsonRecordsFile -Path (Get-VulnCurrentPath -BasePath $tempRoot) -Records @($currentRow)
        [void](New-Item -Path (Get-VulnHistoryPath -BasePath $tempRoot -PeriodKey '2026Q1') -ItemType File -Force)
        Write-NdjsonRecordsFile -Path (Get-VulnHistoryRowsPath -BasePath $tempRoot -PeriodKey '2026Q1') -Records @($historyRow)

        $rowsResult = ConvertTo-NormalizedData -DataPath $tempRoot -VulnOutputPath $rowsOutputPath -PayloadOutputPath $rowsPayloadPath -Machines @{} -AdvancedHuntingData @{}
        $columnsResult = ConvertTo-NormalizedData -DataPath $tempRoot -VulnOutputPath $columnsOutputPath -VulnColumnDirectoryPath $columnPath -Machines @{} -AdvancedHuntingData @{}
        Write-CombinedPayloadGzip -Lookups $columnsResult.Lookups -VulnColumnPaths $columnsResult.VulnColumnPaths -OutputPath $columnsPayloadPath

        $rowFormatSignatures = @(Read-PayloadCanonicalSignatureStream -PayloadPath $rowsPayloadPath | Sort-Object)
        $columnFormatSignatures = @(Read-PayloadCanonicalSignatureStream -PayloadPath $columnsPayloadPath | Sort-Object)

        Assert-True ($rowsResult.VulnCount -eq 2) 'Expected rows-v1 payload fixture to contain two vulnerability rows.'
        Assert-True ($columnsResult.VulnCount -eq 2) 'Expected columns-v1 payload fixture to contain two vulnerability rows.'
        Assert-True ($rowFormatSignatures.Count -eq $columnFormatSignatures.Count) 'Expected validation helper canonicalization to return the same number of rows for rows-v1 and columns-v1 payloads.'
        Assert-True (@(Compare-Object -ReferenceObject $rowFormatSignatures -DifferenceObject $columnFormatSignatures).Count -eq 0) 'Expected validation helper canonicalization to treat rows-v1 and columns-v1 payloads as semantically equivalent.'
    }
    finally {
        if (Test-Path -LiteralPath $tempRoot) {
            Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

function Test-ValidationHelperSourceCanonicalization {
    [CmdletBinding()]
    param()

    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('validation-helper-source-canonicalization-' + [guid]::NewGuid().ToString('N'))
    [void](New-Item -Path $tempRoot -ItemType Directory -Force)
    $repoRoot = Split-Path -Path $PSScriptRoot -Parent

    try {
        . (Join-Path $repoRoot 'build\Import-ValidationHelpers.ps1')

        $row = Get-TestVulnRow -Id 'validation-source-001' -CveId 'CVE-2026-0313' -SnapshotDate '2026-03-20' -Version '3.2.0'
        $row.CvssScore = 8.15
        $row.VulnerabilitySeverityLevel = 'High'
        $row.ExploitabilityLevel = 'ExploitIsPublic'
        $row.FirstSeenTimestamp = '2026-03-21T00:00:00Z'
        $row.LastSeenTimestamp = '2026-03-18T00:00:00Z'
        $row.DiskPaths = @('C:\z-agent.dll', 'C:\a-agent.dll')
        $row.RegistryPaths = @('HKLM\Software\Contoso\ZAgent', 'HKLM\Software\Contoso\AAgent')
        Write-NdjsonRecordsFile -Path (Get-VulnCurrentPath -BasePath $tempRoot) -Records @($row)

        $machines = @{
            'device-001' = [PSCustomObject]@{
                id = 'device-001'
                computerDnsName = 'device01.contoso.com'
                rbacGroupName = 'Servers'
                osPlatform = 'Windows 11'
                osVersion = '10.0.22631'
                machineTags = @('Prod', 'Ring0')
                lastIpAddress = '10.0.0.21'
                lastExternalIpAddress = '52.0.0.21'
                healthStatus = 'Active'
                riskScore = 'Medium'
                exposureLevel = 'Low'
                deviceValue = 'Normal'
                managedBy = 'Intune'
                isAadJoined = $true
                lastSeen = '2026-03-22T00:00:00Z'
                firstSeen = '2026-02-15T00:00:00Z'
            }
        }
        $advancedHunting = @{
            'CVE-2026-0313' = [PSCustomObject]@{
                PublishedDate = '2026-03-05T10:11:12Z'
                VulnerabilityDescription = "  Source`n canonical   description  "
                EpssScore = 0.8123
                AffectedSoftware = @('contoso:legacy agent', 'fabrikam:other')
                IsExploitAvailable = $true
            }
        }
        $nvdCveData = @{
            'CVE-2026-0313' = [PSCustomObject]@{
                PublishedDate = '2026-03-04T00:00:00Z'
                VulnerabilityDescription = 'NVD fallback description'
                LastModifiedDate = '2026-03-17T01:02:03Z'
                BaseScore = 8.0
                BaseSeverity = 'HIGH'
                Vector = 'AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'
                CisaExploitAdd = '2026-03-18T00:00:00Z'
                CisaActionDue = '2026-04-01T00:00:00Z'
                CisaRequiredAction = " Patch`r`n immediately "
                Weaknesses = @('CWE-79', 'CWE-20')
            }
        }
        $inventoryKey = Get-AdvancedHuntingInventoryMatchKey -DeviceId $row.DeviceId -SoftwareVendor $row.SoftwareVendor -SoftwareName $row.SoftwareName -SoftwareVersion $row.SoftwareVersion
        $advancedHuntingInventory = @{
            $inventoryKey = [PSCustomObject]@{
                ProductCodeCpe = 'cpe:/a:contoso:legacy_agent'
                EndOfSupportStatus = 'supported'
                EndOfSupportDate = '2028-01-01T00:00:00Z'
            }
        }
        $vendorSet = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        [void]$vendorSet.Add((Get-VendorMatchKey -Vendor $row.SoftwareVendor))

        $firstLastSwappedCount = 0
        $missingMachineCount = 0
        $signatures = @(Read-SourceCanonicalSignatureStream -ExportsPath $tempRoot -Machines $machines -AdvancedHunting $advancedHunting -AdvancedHuntingInventory $advancedHuntingInventory -NvdCveData $nvdCveData -VendorSet $vendorSet -FirstLastSwappedCount ([ref]$firstLastSwappedCount) -MissingMachineCount ([ref]$missingMachineCount))

        $expectedRow = [PSCustomObject]@{
            DeviceId = 'device-001'
            DeviceName = 'device01.contoso.com'
            RbacGroupName = 'Servers'
            OSPlatform = 'Windows 11'
            OSVersion = '10.0.22631'
            MachineTags = @('Prod', 'Ring0')
            MachineInfo = [PSCustomObject]@{
                ip = '10.0.0.21'
                eip = '52.0.0.21'
                hs = 'Active'
                rs = 'Medium'
                el = 'Low'
                dv = 'Normal'
                mb = 'Intune'
                aad = $true
                ls = '2026-03-22'
                fs = '2026-02-15'
            }
            CveId = 'CVE-2026-0313'
            CvssScore = 8.15
            VulnerabilitySeverityLevel = 'High'
            ExploitabilityLevel = 'ExploitIsPublic'
            CveBatchUrl = $row.CveBatchUrl
            CveBatchTitle = $row.CveBatchTitle
            PublishedDate = '2026-03-05'
            VulnerabilityDescription = 'Source canonical description'
            EpssScore = 0.8123
            AffectedSoftware = @('contoso:legacy agent')
            IsExploitAvailable = $true
            NvdLastModifiedDate = '2026-03-17'
            NvdBaseScore = 8.0
            NvdBaseSeverity = 'HIGH'
            NvdVector = 'AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'
            NvdKevDate = '2026-03-18'
            NvdActionDue = '2026-04-01'
            NvdRequiredAction = 'Patch immediately'
            NvdWeaknesses = @('CWE-79', 'CWE-20')
            SoftwareVendor = 'Contoso'
            SoftwareName = 'Legacy Agent'
            SoftwareVersion = '3.2.0'
            RecommendationReference = 'KB000001'
            ProductCodeCpe = 'cpe:/a:contoso:legacy_agent'
            EndOfSupportStatus = 'supported'
            EndOfSupportDate = '2028-01-01'
            FirstSeenTimestamp = '2026-03-18'
            LastSeenTimestamp = '2026-03-21'
            SecurityUpdateAvailable = $true
            RecommendedSecurityUpdate = 'KB000001'
            RecommendedSecurityUpdateId = 'KB000001'
            RecommendedSecurityUpdateUrl = 'https://example.invalid/kb000001'
            DiskPaths = @('C:\z-agent.dll', 'C:\a-agent.dll')
            RegistryPaths = @('HKLM\Software\Contoso\ZAgent', 'HKLM\Software\Contoso\AAgent')
        }
        $expectedSignature = Get-CanonicalValidationRowSignature -Row $expectedRow

        Assert-True ($signatures.Count -eq 1) 'Expected source canonicalization fixture to emit one signature.'
        Assert-True ($signatures[0] -eq $expectedSignature) 'Expected source canonicalization to preserve the canonical row signature for enriched source records.'
        Assert-True ($firstLastSwappedCount -eq 1) 'Expected source canonicalization to continue tracking reordered first/last seen timestamps.'
        Assert-True ($missingMachineCount -eq 0) 'Expected source canonicalization fixture to resolve machine metadata without fallback misses.'
    }
    finally {
        if (Test-Path -LiteralPath $tempRoot) {
            Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

function Test-WriteCombinedPayloadGzipCanConsumeColumnLookupData {
    [CmdletBinding()]
    param()

    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('payload-consume-lookups-' + [guid]::NewGuid().ToString('N'))
    [void](New-Item -Path $tempRoot -ItemType Directory -Force)
    $repoRoot = Split-Path -Path $PSScriptRoot -Parent
    $columnsOutputPath = Join-Path $tempRoot 'columns-normalized.json'
    $columnPath = Join-Path $tempRoot 'columns'
    $payloadPath = Join-Path $tempRoot 'columns-payload.json.gz'

    try {
        . (Join-Path $repoRoot 'build\Import-ValidationHelpers.ps1')

        $currentRow = Get-TestVulnRow -Id 'payload-consume-001' -CveId 'CVE-2026-0411' -SnapshotDate '2026-03-20' -Version '4.0.0'
        $historyRow = Get-TestVulnRow -Id 'payload-consume-002' -CveId 'CVE-2026-0412' -SnapshotDate '2026-03-18' -Version '4.1.0'
        $historyRow.DeviceId = 'device-002'
        $historyRow.DeviceName = 'device02.contoso.com'

        Write-NdjsonRecordsFile -Path (Get-VulnCurrentPath -BasePath $tempRoot) -Records @($currentRow)
        [void](New-Item -Path (Get-VulnHistoryPath -BasePath $tempRoot -PeriodKey '2026Q1') -ItemType File -Force)
        Write-NdjsonRecordsFile -Path (Get-VulnHistoryRowsPath -BasePath $tempRoot -PeriodKey '2026Q1') -Records @($historyRow)

        $columnsResult = ConvertTo-NormalizedData -DataPath $tempRoot -VulnOutputPath $columnsOutputPath -VulnColumnDirectoryPath $columnPath -Machines @{} -AdvancedHuntingData @{}
        $deviceCountBeforeConsume = @($columnsResult.Lookups.devices).Count
        $cveCountBeforeConsume = @($columnsResult.Lookups.cves).Count

        Write-CombinedPayloadGzip -Lookups $columnsResult.Lookups -VulnColumnPaths $columnsResult.VulnColumnPaths -OutputPath $payloadPath -ConsumeLookups

        $payloadSignatures = @(Read-PayloadCanonicalSignatureStream -PayloadPath $payloadPath | Sort-Object)

        Assert-True ($deviceCountBeforeConsume -gt 0) 'Expected the payload fixture to start with populated device lookups before consuming them.'
        Assert-True ($cveCountBeforeConsume -gt 0) 'Expected the payload fixture to start with populated CVE lookups before consuming them.'
        Assert-True ($payloadSignatures.Count -eq 2) 'Expected the consumed-lookups payload fixture to preserve both vulnerability rows.'
        Assert-True ($null -eq $columnsResult.Lookups.devices) 'Expected payload gzip with -ConsumeLookups to release device lookups after serialization.'
        Assert-True ($null -eq $columnsResult.Lookups.software) 'Expected payload gzip with -ConsumeLookups to release software lookups after serialization.'
        Assert-True ($null -eq $columnsResult.Lookups.cves) 'Expected payload gzip with -ConsumeLookups to release CVE lookups after serialization.'
    }
    finally {
        if (Test-Path -LiteralPath $tempRoot) {
            Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

function Test-GetDashboardEmbeddedPayloadInspectionStreamsSelfContainedPayload {
    [CmdletBinding()]
    param()

    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('dashboard-embedded-payload-inspection-' + [guid]::NewGuid().ToString('N'))
    [void](New-Item -Path $tempRoot -ItemType Directory -Force)
    $payloadPath = Join-Path $tempRoot 'payload.json.gz'
    $htmlPath = Join-Path $tempRoot 'dashboard.html'

    try {
        Write-GzipTextFile -Path $payloadPath -Content '{"vulnsFormat":"rows-v1","vulns":[[0,0,0,0,"2026-03-20","2026-03-21",null,null,null,null,null],[1,1,1,1,"2026-03-18","2026-03-19",null,null,null,null,null]],"lookups":{"devices":[{"id":"device-001"},{"id":"device-002"}],"cves":[{"id":"CVE-2026-1001"},{"id":"CVE-2026-1002"}]}}'
        $payloadSha256 = Get-FileSha256Hex -Path $payloadPath

        $template = @"
<html>
<head><script id="dataFormat" type="application/json">compressed</script></head>
<body>
<script id="vulnsData" type="application/json">__PAYLOAD__</script>
</body>
</html>
"@
        Write-TemplatedHtml -Template $template -Segments @(@{ Placeholder = '__PAYLOAD__'; Base64FilePath = $payloadPath }) -OutputPath $htmlPath -InsertBase64LineBreaks

        $inspection = Get-DashboardEmbeddedPayloadInspection -Path $htmlPath

        Assert-True ($inspection.DataFormat -eq 'compressed') 'Expected self-contained dashboard inspection to report compressed data format.'
        Assert-True ($inspection.PayloadRowCount -eq 2) 'Expected self-contained dashboard inspection to preserve the embedded payload row count.'
        Assert-True ($inspection.PayloadSha256 -eq $payloadSha256) 'Expected self-contained dashboard inspection to preserve the embedded payload SHA256.'
    }
    finally {
        if (Test-Path -LiteralPath $tempRoot) {
            Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

function Test-MeasureStressRunWritesProgressAndFinalReport {
    [CmdletBinding()]
    param()

    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('measure-stress-run-report-' + [guid]::NewGuid().ToString('N'))
    $datasetRoot = Join-Path $tempRoot 'dataset'
    $outputRoot = Join-Path $tempRoot 'output'
    [void](New-Item -Path $datasetRoot -ItemType Directory -Force)
    [void](New-Item -Path $outputRoot -ItemType Directory -Force)
    $repoRoot = Split-Path -Path $PSScriptRoot -Parent
    $measureScriptPath = Join-Path $repoRoot 'tests\Measure-StressRun.ps1'
    $dashboardPath = Join-Path $outputRoot 'dashboard.html'
    $reportPath = Join-Path $outputRoot 'stress-report.json'
    $stdoutPath = Join-Path $outputRoot 'measure.stdout.log'
    $stderrPath = Join-Path $outputRoot 'measure.stderr.log'
    $process = $null

    try {
        . (Join-Path $repoRoot 'build\Import-ValidationHelpers.ps1')

        $row = Get-TestVulnRow -Id 'stress-report-001' -CveId 'CVE-2026-0701' -SnapshotDate '2026-03-20' -Version '7.0.0'
        Write-NdjsonRecordsFile -Path (Get-VulnCurrentPath -BasePath $datasetRoot) -Records @($row)

        $machines = @(
            [PSCustomObject]@{
                id = 'device-001'
                computerDnsName = 'device01.contoso.com'
                rbacGroupName = 'Servers'
                osPlatform = 'Windows 11'
                osVersion = '10.0.22631'
                machineTags = @('Prod')
                lastIpAddress = '10.0.0.21'
                lastExternalIpAddress = ''
                healthStatus = 'Active'
                riskScore = 'Medium'
                exposureLevel = 'Medium'
                deviceValue = 'Normal'
                managedBy = 'Intune'
                isAadJoined = $true
                lastSeen = '2026-03-20'
                firstSeen = '2026-02-01'
            }
        )

        [System.IO.File]::WriteAllText((Join-Path $datasetRoot 'Machines_Current.json'), ($machines | ConvertTo-Json -Compress -Depth 20), [System.Text.UTF8Encoding]::new($false))
        Write-GzipTextFile -Path (Get-AdvancedHuntingCurrentPath -BasePath $datasetRoot) -Content '[]'
        [System.IO.File]::WriteAllText((Join-Path $datasetRoot 'synthetic-manifest.json'), (([ordered]@{
            actualDeviceCount = 1
            actualCurrentRows = 1
            actualHistoryRows = 0
        }) | ConvertTo-Json -Compress), [System.Text.UTF8Encoding]::new($false))

        # Keep this regression hermetic. Dashboard generation normally reuses
        # these pinned client libraries from its dataset cache, so provide
        # minimal non-empty fixtures rather than depending on public CDNs.
        Initialize-RegressionDashboardLibraryCache -BasePath $datasetRoot

        $pwshCommand = Get-Command -Name 'pwsh' -ErrorAction Stop
        $argumentList = @(
            '-NoProfile'
            '-File'
            $measureScriptPath
            '-Name'
            'stress-report-regression'
            '-SyntheticOutputPath'
            $datasetRoot
            '-DashboardOutputPath'
            $dashboardPath
            '-ReportOutputPath'
            $reportPath
            '-Validate'
            '-ValidationMode'
            'artifacts'
            '-PollIntervalSeconds'
            '1'
        )

        $process = Start-Process -FilePath $pwshCommand.Source -ArgumentList $argumentList -WorkingDirectory $repoRoot -RedirectStandardOutput $stdoutPath -RedirectStandardError $stderrPath -PassThru

        $reportSeenWhileRunning = $false
        $deadline = [datetime]::UtcNow.AddSeconds(30)
        while ([datetime]::UtcNow -lt $deadline) {
            $process.Refresh()
            if (Test-Path -LiteralPath $reportPath -PathType Leaf) {
                if (-not $process.HasExited) {
                    $reportSeenWhileRunning = $true
                }
                break
            }

            if ($process.HasExited) {
                break
            }

            Start-Sleep -Milliseconds 200
        }

        $process.WaitForExit()

        if (-not $IsWindows) {
            $stdoutContent = if (Test-Path -LiteralPath $stdoutPath -PathType Leaf) { Get-Content -LiteralPath $stdoutPath -Raw } else { '' }
            $stderrContent = if (Test-Path -LiteralPath $stderrPath -PathType Leaf) { Get-Content -LiteralPath $stderrPath -Raw } else { '' }
            $processOutput = @($stdoutContent, $stderrContent) -join [Environment]::NewLine

            Assert-True ($process.ExitCode -ne 0) 'Expected Measure-StressRun regression fixture to fail fast on non-Windows platforms.'
            Assert-True (-not (Test-Path -LiteralPath $reportPath -PathType Leaf)) 'Expected non-Windows Measure-StressRun execution to avoid writing a stress report.'
            Assert-True ($processOutput.Contains('currently supports Windows only')) 'Expected non-Windows Measure-StressRun execution to explain the Windows-only platform guard.'
            return
        }

        if (-not (Test-Path -LiteralPath $reportPath -PathType Leaf)) {
            $stdoutContent = if (Test-Path -LiteralPath $stdoutPath -PathType Leaf) { Get-Content -LiteralPath $stdoutPath -Raw } else { '' }
            $stderrContent = if (Test-Path -LiteralPath $stderrPath -PathType Leaf) { Get-Content -LiteralPath $stderrPath -Raw } else { '' }
            throw ("Measure-StressRun did not create its report (exit code {0}).`nSTDOUT:`n{1}`nSTDERR:`n{2}" -f $process.ExitCode, $stdoutContent, $stderrContent)
        }

        $report = Get-Content -LiteralPath $reportPath -Raw | ConvertFrom-Json -Depth 20

        Assert-True $reportSeenWhileRunning 'Expected Measure-StressRun to persist a progress report before the wrapper process exits.'
        Assert-True ($report.report_state -eq 'completed') 'Expected Measure-StressRun to finalize the persisted report after the child process exits.'
        if ($report.return_code -ne 0) {
            $childStdoutPath = [string]$report.stdout_path
            $childStderrPath = [string]$report.stderr_path
            $stdoutContent = if (Test-Path -LiteralPath $childStdoutPath -PathType Leaf) { Get-Content -LiteralPath $childStdoutPath -Raw } else { '' }
            $stderrContent = if (Test-Path -LiteralPath $childStderrPath -PathType Leaf) { Get-Content -LiteralPath $childStderrPath -Raw } else { '' }
            throw ("Expected Measure-StressRun regression fixture to complete successfully (exit code {0}).`nSTDOUT:`n{1}`nSTDERR:`n{2}" -f $report.return_code, $stdoutContent, $stderrContent)
        }
        Assert-True ($report.sample_count -gt 0) 'Expected Measure-StressRun regression fixture to record at least one process-tree sample.'
        Assert-True ($report.dashboard_exists -eq $true) 'Expected Measure-StressRun regression fixture to generate the dashboard output.'
        Assert-True ($report.benchmark_evidence.evidence_schema_version -eq 1) 'Expected Measure-StressRun to persist the versioned benchmark evidence envelope.'
        Assert-True ($report.benchmark_evidence.dataset.files.Count -gt 0) 'Expected Measure-StressRun benchmark evidence to include dataset artifact hashes.'
    }
    finally {
        if ($null -ne $process -and -not $process.HasExited) {
            Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue
        }

        if (Test-Path -LiteralPath $tempRoot) {
            Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

function Test-ValidationHelperStandaloneImport {
    [CmdletBinding()]
    param()

    $repoRoot = Split-Path -Path $PSScriptRoot -Parent
    $pwshPath = Get-Command pwsh -CommandType Application -ErrorAction SilentlyContinue |
        Select-Object -First 1 -ExpandProperty Source
    if ([string]::IsNullOrWhiteSpace($pwshPath)) {
        throw 'pwsh is required to run validation helper import regression checks.'
    }

    $smokeScript = @'
$ErrorActionPreference = 'Stop'

. '__REPO_ROOT__\build\Import-ValidationHelpers.ps1'

$row = [PSCustomObject]@{
    DeviceId = 'device-standalone-001'
    DeviceName = 'device01.contoso.com'
    RbacGroupName = 'Prod'
    OSPlatform = 'Windows11'
    OSVersion = '23H2'
    MachineTags = @('Pilot')
    MachineInfo = [PSCustomObject]@{
        ip = '10.0.0.5'
        eip = '52.160.0.5'
        hs = 'Active'
        rs = 'Medium'
        el = 'Low'
        dv = 'Standard'
        mb = 'Intune'
        aad = $true
        ls = '2026-03-20'
        fs = '2026-03-01'
    }
    CveId = 'CVE-2026-0401'
    CvssScore = '7.5'
    VulnerabilitySeverityLevel = 'High'
    ExploitabilityLevel = 'ExploitIsPublic'
    CveBatchUrl = 'https://example.invalid/CVE-2026-0401'
    CveBatchTitle = 'Windows cumulative update'
    PublishedDate = '2026-03-02'
    VulnerabilityDescription = 'Standalone validation helper import smoke test'
    EpssScore = '0.81'
    AffectedSoftware = @('microsoft:windows')
    IsExploitAvailable = $true
    NvdLastModifiedDate = '2026-03-18'
    NvdBaseScore = '8.0'
    NvdBaseSeverity = 'HIGH'
    NvdVector = 'AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'
    NvdKevDate = '2026-03-19'
    NvdActionDue = '2026-04-01'
    NvdRequiredAction = 'Patch immediately'
    NvdWeaknesses = @('CWE-79')
    SoftwareVendor = 'microsoft'
    SoftwareName = 'windows'
    SoftwareVersion = '10.0.26100.1'
    RecommendationReference = 'Windows Security Update'
    ProductCodeCpe = 'cpe:/o:microsoft:windows_11'
    EndOfSupportStatus = 'supported'
    EndOfSupportDate = '2027-10-01'
    FirstSeenTimestamp = '2026-03-03'
    LastSeenTimestamp = '2026-03-20'
    SecurityUpdateAvailable = $true
    RecommendedSecurityUpdate = 'March 2026 cumulative update'
    RecommendedSecurityUpdateId = 'KB6000001'
    RecommendedSecurityUpdateUrl = 'https://example.invalid/kb6000001'
    DiskPaths = @('C:\Windows\System32\kernel32.dll')
    RegistryPaths = @('HKLM\Software\Microsoft\Windows')
}

$signature = Get-CanonicalValidationRowSignature -Row $row
if ([string]::IsNullOrWhiteSpace($signature)) {
    throw 'Standalone validation helper import smoke returned an empty signature.'
}
'@.Replace('__REPO_ROOT__', $repoRoot.Replace("'", "''"))

    & $pwshPath -NoProfile -Command $smokeScript
    if ($LASTEXITCODE -ne 0) {
        throw 'Standalone validation helper import smoke failed.'
    }
}

function Test-DashboardValidationFailureExtendedEnrichmentGate {
    [CmdletBinding()]
    param()

    $repoRoot = Split-Path -Path $PSScriptRoot -Parent

    . (Join-Path $repoRoot 'build\Import-ValidationHelpers.ps1')

    $audit = [PSCustomObject]@{
        RowComparison = [PSCustomObject]@{
            Match = $true
            MissingCount = 0
            ExtraCount = 0
        }
        EnrichmentAudit = [PSCustomObject]@{
            PublishedDateMismatchCount = 0
            DescriptionMismatchCount = 0
            EpssMismatchCount = 0
            AffectedSoftwareMismatchCount = 0
            ExploitAvailableMismatchCount = 1
            NvdLastModifiedMismatchCount = 0
            NvdBaseScoreMismatchCount = 1
            NvdBaseSeverityMismatchCount = 0
            NvdVectorMismatchCount = 0
            NvdKevMismatchCount = 0
            NvdActionDueMismatchCount = 0
            NvdRequiredActionMismatchCount = 0
            NvdWeaknessMismatchCount = 0
        }
        ReportComparisons = @()
        LegacyMigrationAudit = [PSCustomObject]@{
            Enabled = $false
        }
    }

    $failures = @(Get-DashboardValidationFailure -Audit $audit)

    Assert-True ($failures.Count -eq 1) 'Expected extended enrichment mismatch counters to add exactly one validation failure.'
    Assert-True ($failures[0] -eq 'Dashboard enrichment fields do not match the source data.') 'Expected extended enrichment mismatch counters to use the standard enrichment failure message.'
}

function Test-StreamingDashboardAuditDetectsSourceMismatchDespitePayloadParity {
    [CmdletBinding()]
    param()

    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('streaming-dashboard-source-parity-' + [guid]::NewGuid().ToString('N'))
    [void](New-Item -Path $tempRoot -ItemType Directory -Force)
    $repoRoot = Split-Path -Path $PSScriptRoot -Parent
    $payloadPath = Join-Path $tempRoot 'payload.json.gz'
    $vulnOutputPath = Join-Path $tempRoot 'normalized-vulns.json'
    $htmlPath = Join-Path $tempRoot 'dashboard.html'

    try {
        . (Join-Path $repoRoot 'build\Import-ValidationHelpers.ps1')

        $currentRow = Get-TestVulnRow -Id 'streaming-audit-001' -CveId 'CVE-2026-0321' -SnapshotDate '2026-03-20' -Version '4.0.0'
        Write-NdjsonRecordsFile -Path (Get-VulnCurrentPath -BasePath $tempRoot) -Records @($currentRow)

        $normalizedResult = ConvertTo-NormalizedData -DataPath $tempRoot -VulnOutputPath $vulnOutputPath -PayloadOutputPath $payloadPath -Machines @{} -AdvancedHuntingData @{}
        $payloadCacheEntry = Publish-NormalizedPayloadCache -BasePath $tempRoot -PayloadPath $normalizedResult.PayloadPath -VulnCount $normalizedResult.VulnCount -DeviceCount $normalizedResult.Lookups.devices.Count -CveCount $normalizedResult.Lookups.cves.Count -Quality $normalizedResult.Quality

        $dashboardConfigJson = ([ordered]@{ payloadUrl = 'payload.json.gz' } | ConvertTo-Json -Compress)
        $dashboardHtml = @(
            '<!DOCTYPE html>'
            '<html lang="en">'
            '<head><meta charset="utf-8"><title>Streaming Audit Fixture</title></head>'
            '<body>'
            '<script id="dataFormat" type="application/json">external-compressed</script>'
            ('<script id="dashboardConfig" type="application/json">' + $dashboardConfigJson + '</script>')
            '</body>'
            '</html>'
        ) -join [Environment]::NewLine
        [System.IO.File]::WriteAllText($htmlPath, $dashboardHtml, [System.Text.UTF8Encoding]::new($false))

        $previousForceFull = $Script:DashboardValidationForceFull
        $Script:DashboardValidationForceFull = $true
        try {
            $primeAudit = Get-StreamingDashboardAuditResult -ResolvedHtmlPath $htmlPath -ResolvedExportsPath $tempRoot -PayloadCacheEntry $payloadCacheEntry

            $changedRow = Get-TestVulnRow -Id 'streaming-audit-001' -CveId 'CVE-2026-0321' -SnapshotDate '2026-03-20' -Version '9.9.9'
            $addedRow = Get-TestVulnRow -Id 'streaming-audit-002' -CveId 'CVE-2026-0322' -SnapshotDate '2026-03-21' -Version '4.1.0'
            Write-NdjsonRecordsFile -Path (Get-VulnCurrentPath -BasePath $tempRoot) -Records @($changedRow, $addedRow)

            $contentStoreFiles = @(
                Get-VulnContentDictionaryPath -BasePath $tempRoot
                Get-VulnCurrentRefsPath -BasePath $tempRoot
                Get-VulnHistoryRefsPath -BasePath $tempRoot -PeriodKey '2026Q1'
            )
            foreach ($contentStoreFile in $contentStoreFiles) {
                if (-not [string]::IsNullOrWhiteSpace($contentStoreFile) -and (Test-Path -LiteralPath $contentStoreFile -PathType Leaf)) {
                    Remove-Item -LiteralPath $contentStoreFile -Force -ErrorAction SilentlyContinue
                }
            }

            $audit = Get-StreamingDashboardAuditResult -ResolvedHtmlPath $htmlPath -ResolvedExportsPath $tempRoot -PayloadCacheEntry $payloadCacheEntry
        }
        finally {
            $Script:DashboardValidationForceFull = $previousForceFull
        }

        Assert-True ($primeAudit.RowComparison.Match -eq $true) 'Expected the priming forced streaming audit to succeed before the source exports diverge.'
        Assert-True ($primeAudit.SemanticParity.SourceSignatureCacheUsed -eq $false) 'Expected the priming forced streaming audit to build the source signature cache.'
        Assert-True ((Test-Path -LiteralPath $payloadPath -PathType Leaf)) 'Expected the streaming audit to preserve externally referenced payload files after the priming pass.'
        Assert-True ($audit.PayloadParity.Match -eq $true) 'Expected dashboard payload bytes to remain equal to the cached normalized payload.'
        Assert-True ($audit.SemanticParity.PayloadByteParityMatch -eq $true) 'Expected streaming audit diagnostics to record dashboard payload byte parity.'
        Assert-True ($audit.RowComparison.Match -eq $false) 'Expected streaming semantic parity to fail when the source exports diverge from the dashboard payload.'
        Assert-True ($audit.RowComparison.MissingCount -eq 2) 'Expected the added row and changed row signature to be reported as missing from the dashboard payload.'
        Assert-True ($audit.RowComparison.ExtraCount -eq 1) 'Expected the dashboard version of the changed row to be reported as extra.'
        Assert-True ([string]$audit.SemanticParity.ComparisonPayloadSource -eq 'cached-payload') 'Expected source streaming audit to reuse the cached payload when byte parity proves dashboard equivalence.'
        Assert-True ($audit.SemanticParity.SourceSignatureCacheUsed -eq $false) 'Expected the streaming audit to bypass the cached source signature set after the source exports fingerprint changes.'
        Assert-True ((Test-Path -LiteralPath $payloadPath -PathType Leaf)) 'Expected the streaming audit to preserve externally referenced payload files after full comparison completes.'
    }
    finally {
        if (Test-Path -LiteralPath $tempRoot) {
            Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

function Test-StreamingDashboardAuditReusesCachedPayloadSignatureSet {
    [CmdletBinding()]
    param()

    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('streaming-dashboard-payload-signatures-' + [guid]::NewGuid().ToString('N'))
    [void](New-Item -Path $tempRoot -ItemType Directory -Force)
    $repoRoot = Split-Path -Path $PSScriptRoot -Parent
    $payloadPath = Join-Path $tempRoot 'payload.json.gz'
    $vulnOutputPath = Join-Path $tempRoot 'normalized-vulns.json'
    $htmlPath = Join-Path $tempRoot 'dashboard.html'

    try {
        . (Join-Path $repoRoot 'build\Import-ValidationHelpers.ps1')

        $currentRow = Get-TestVulnRow -Id 'streaming-cache-001' -CveId 'CVE-2026-0421' -SnapshotDate '2026-03-20' -Version '5.0.0'
        Write-NdjsonRecordsFile -Path (Get-VulnCurrentPath -BasePath $tempRoot) -Records @($currentRow)

        $normalizedResult = ConvertTo-NormalizedData -DataPath $tempRoot -VulnOutputPath $vulnOutputPath -PayloadOutputPath $payloadPath -Machines @{} -AdvancedHuntingData @{}
        $payloadCacheEntry = Publish-NormalizedPayloadCache -BasePath $tempRoot -PayloadPath $normalizedResult.PayloadPath -VulnCount $normalizedResult.VulnCount -DeviceCount $normalizedResult.Lookups.devices.Count -CveCount $normalizedResult.Lookups.cves.Count -Quality $normalizedResult.Quality

        $dashboardConfigJson = ([ordered]@{ payloadUrl = 'payload.json.gz' } | ConvertTo-Json -Compress)
        $dashboardHtml = @(
            '<!DOCTYPE html>'
            '<html lang="en">'
            '<head><meta charset="utf-8"><title>Streaming Audit Cache Fixture</title></head>'
            '<body>'
            '<script id="dataFormat" type="application/json">external-compressed</script>'
            ('<script id="dashboardConfig" type="application/json">' + $dashboardConfigJson + '</script>')
            '</body>'
            '</html>'
        ) -join [Environment]::NewLine
        [System.IO.File]::WriteAllText($htmlPath, $dashboardHtml, [System.Text.UTF8Encoding]::new($false))

        $previousForceFull = $Script:DashboardValidationForceFull
        $Script:DashboardValidationForceFull = $true
        try {
            $firstAudit = Get-StreamingDashboardAuditResult -ResolvedHtmlPath $htmlPath -ResolvedExportsPath $tempRoot -PayloadCacheEntry $payloadCacheEntry
            $secondAudit = Get-StreamingDashboardAuditResult -ResolvedHtmlPath $htmlPath -ResolvedExportsPath $tempRoot -PayloadCacheEntry $payloadCacheEntry
        }
        finally {
            $Script:DashboardValidationForceFull = $previousForceFull
        }

        Assert-True ($firstAudit.RowComparison.Match -eq $true) 'Expected the initial forced streaming audit to succeed before caching payload signatures.'
        Assert-True ($firstAudit.SemanticParity.SourceSignatureCacheUsed -eq $false) 'Expected the initial forced streaming audit to build the source signature cache.'
        Assert-True ($firstAudit.SemanticParity.PayloadSignatureCacheUsed -eq $false) 'Expected the initial forced streaming audit to build the payload signature cache.'
        Assert-True ($secondAudit.RowComparison.Match -eq $true) 'Expected the repeated forced streaming audit to preserve semantic parity.'
        Assert-True ($secondAudit.SemanticParity.SourceSignatureCacheUsed -eq $true) 'Expected the repeated forced streaming audit to reuse the cached source signature set.'
        Assert-True ($secondAudit.SemanticParity.PayloadSignatureCacheUsed -eq $true) 'Expected the repeated forced streaming audit to reuse the cached payload signature set.'
        Assert-True ([double]$secondAudit.SemanticParity.SourceSignatureElapsedSeconds -lt [double]$firstAudit.SemanticParity.SourceSignatureElapsedSeconds) 'Expected cached source signature reuse to reduce the source signature phase time on the repeated forced streaming audit.'
        Assert-True ([double]$secondAudit.SemanticParity.PayloadSignatureElapsedSeconds -lt [double]$firstAudit.SemanticParity.PayloadSignatureElapsedSeconds) 'Expected cached payload signature reuse to reduce the payload signature phase time on the repeated forced streaming audit.'
    }
    finally {
        if (Test-Path -LiteralPath $tempRoot) {
            Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

function Test-DashboardAuditBootstrapsSyntheticLargePayloadCacheWithNormalizationLookup {
    [CmdletBinding()]
    param()

    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('dashboard-audit-synthetic-bootstrap-' + [guid]::NewGuid().ToString('N'))
    [void](New-Item -Path $tempRoot -ItemType Directory -Force)
    $repoRoot = Split-Path -Path $PSScriptRoot -Parent
    $payloadPath = Join-Path $tempRoot 'payload.json.gz'
    $vulnOutputPath = Join-Path $tempRoot 'normalized-vulns.json'
    $htmlPath = Join-Path $tempRoot 'dashboard.html'

    try {
        . (Join-Path $repoRoot 'build\Import-ValidationHelpers.ps1')

        $row = Get-TestVulnRow -Id 'synthetic-bootstrap-001' -CveId 'CVE-2026-0521' -SnapshotDate '2026-03-20' -Version '6.0.0'
        Write-NdjsonRecordsFile -Path (Get-VulnCurrentPath -BasePath $tempRoot) -Records @($row)

        $machines = @(
            [PSCustomObject]@{
                id = 'device-001'
                computerDnsName = 'device01.contoso.com'
                rbacGroupName = 'Servers'
                osPlatform = 'Windows 11'
                osVersion = '10.0.22631'
                machineTags = @('Prod')
                lastIpAddress = '10.0.0.21'
                lastExternalIpAddress = ''
                healthStatus = 'Active'
                riskScore = 'Medium'
                exposureLevel = 'Medium'
                deviceValue = 'Normal'
                managedBy = 'Intune'
                isAadJoined = $true
                lastSeen = '2026-03-20'
                firstSeen = '2026-02-01'
            }
        )

        [System.IO.File]::WriteAllText((Join-Path $tempRoot 'Machines_Current.json'), ($machines | ConvertTo-Json -Compress -Depth 20), [System.Text.UTF8Encoding]::new($false))
        Write-GzipTextFile -Path (Get-AdvancedHuntingCurrentPath -BasePath $tempRoot) -Content '[]'
        [System.IO.File]::WriteAllText((Join-Path $tempRoot 'synthetic-manifest.json'), (([ordered]@{
            actualCurrentRows = 100000
            actualHistoryRows = 0
        }) | ConvertTo-Json -Compress), [System.Text.UTF8Encoding]::new($false))

        $normalizationMachines = Read-NormalizationMachineLookup -Path $tempRoot
        $normalizedResult = ConvertTo-NormalizedData -DataPath $tempRoot -VulnOutputPath $vulnOutputPath -PayloadOutputPath $payloadPath -Machines $normalizationMachines -AdvancedHuntingData @{} -AdvancedHuntingDeviceUsers @{} -AdvancedHuntingInventoryData @{} -NvdCveData @{} -SkipObservedWindowMerge

        $dashboardConfigJson = ([ordered]@{ payloadUrl = 'payload.json.gz' } | ConvertTo-Json -Compress)
        $dashboardHtml = @(
            '<!DOCTYPE html>'
            '<html lang="en">'
            '<head><meta charset="utf-8"><title>Synthetic Bootstrap Fixture</title></head>'
            '<body>'
            '<script id="dataFormat" type="application/json">external-compressed</script>'
            ('<script id="dashboardConfig" type="application/json">' + $dashboardConfigJson + '</script>')
            '</body>'
            '</html>'
        ) -join [Environment]::NewLine
        [System.IO.File]::WriteAllText($htmlPath, $dashboardHtml, [System.Text.UTF8Encoding]::new($false))

        $payloadCacheEntryBeforeAudit = Get-NormalizedPayloadCacheEntry -BasePath $tempRoot -SkipObservedWindowMerge
        $audit = Get-DashboardAuditResult -ResolvedHtmlPath $htmlPath -ResolvedExportsPath $tempRoot
        $payloadCacheEntryAfterAudit = Get-NormalizedPayloadCacheEntry -BasePath $tempRoot -SkipObservedWindowMerge

        Assert-True ($null -eq $payloadCacheEntryBeforeAudit) 'Expected synthetic large-dataset validation to start without a normalized payload cache entry.'
        Assert-True ($normalizedResult.VulnCount -eq 1) 'Expected the synthetic bootstrap fixture to generate exactly one normalized vulnerability row.'
        Assert-True ($audit.RowComparison.Match -eq $true) 'Expected dashboard audit to preserve semantic parity after bootstrapping a synthetic large-dataset payload cache from tuple-backed machines.'
        Assert-True ($null -ne $payloadCacheEntryAfterAudit) 'Expected synthetic large-dataset validation to publish a normalized payload cache entry.'
    }
    finally {
        if (Test-Path -LiteralPath $tempRoot) {
            Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

function Test-DashboardValidationUsesStableFallbackDeviceProfile {
    [CmdletBinding()]
    param()

    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('dashboard-validation-device-profile-' + [guid]::NewGuid().ToString('N'))
    [void](New-Item -Path $tempRoot -ItemType Directory -Force)
    $dashboardScriptPath = Join-Path (Split-Path -Path $PSScriptRoot -Parent) 'Generate-VulnerabilityDashboard.ps1'
    $outputPath = Join-Path $tempRoot 'dashboard.html'
    $auditPath = Join-Path $tempRoot 'audit.json'

    try {
        $first = Get-TestVulnRow -Id 'device-profile-001' -CveId 'CVE-2026-0107' -SnapshotDate '2026-03-20' -Version '1.0.0'
        $second = Get-TestVulnRow -Id 'device-profile-002' -CveId 'CVE-2026-0108' -SnapshotDate '2026-03-20' -Version '1.1.0'
        $second.DeviceName = 'device01-renamed.contoso.com'
        $second.RbacGroupName = 'Pilot'
        $second.OSVersion = '10.0.99999'
        $second.MachineTags = @('Pilot')
        $second.DiskPaths = @('C:\Program Files\Legacy Agent\agent-renamed.exe')
        $second.RegistryPaths = @('HKLM\Software\Contoso\LegacyAgentRenamed')

        Write-NdjsonRecordsFile -Path (Get-VulnCurrentPath -BasePath $tempRoot) -Records @($first, $second)
        [System.IO.File]::WriteAllText((Join-Path $tempRoot 'Machines_Current.json'), '[]', [System.Text.UTF8Encoding]::new($false))
        Write-GzipTextFile -Path (Get-AdvancedHuntingCurrentPath -BasePath $tempRoot) -Content '[]'

        & $dashboardScriptPath -DirectoryPath $tempRoot -OutputPath $outputPath -ExportMachineData:$false -Validate -ValidationOutputPath $auditPath | Out-Null

        $audit = Get-Content -Path $auditPath -Raw | ConvertFrom-Json -Depth 100
        Assert-True ($audit.RowComparison.Match -eq $true) 'Expected dashboard validation to reuse the stable fallback device profile for machine-less rows.'
        Assert-True ($audit.RowComparison.MissingCount -eq 0) 'Expected no missing rows when fallback device metadata varies across rows.'
        Assert-True ($audit.RowComparison.ExtraCount -eq 0) 'Expected no extra rows when fallback device metadata varies across rows.'
    }
    finally {
        if (Test-Path -LiteralPath $tempRoot) {
            Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

function Test-DashboardOpenStateAuditUsesPatchEvidenceAndInactivityCutoff {
    [CmdletBinding()]
    param()

    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('dashboard-open-state-audit-' + [guid]::NewGuid().ToString('N'))
    [void](New-Item -Path $tempRoot -ItemType Directory -Force)
    $dashboardScriptPath = Join-Path (Split-Path -Path $PSScriptRoot -Parent) 'Generate-VulnerabilityDashboard.ps1'
    $outputPath = Join-Path $tempRoot 'dashboard.html'
    $auditPath = Join-Path $tempRoot 'audit.json'

    try {
        $patchedRow = Get-TestVulnRow -Id 'patched-001' -CveId 'CVE-2026-0201' -SnapshotDate '2026-03-01' -Version '1.0.0'
        $patchedRow.DeviceId = 'device-patched'
        $patchedRow.DeviceName = 'device-patched.contoso.com'

        $assumedOpenRow = Get-TestVulnRow -Id 'open-001' -CveId 'CVE-2026-0202' -SnapshotDate '2026-03-01' -Version '1.1.0'
        $assumedOpenRow.DeviceId = 'device-open'
        $assumedOpenRow.DeviceName = 'device-open.contoso.com'

        $staleRow = Get-TestVulnRow -Id 'stale-001' -CveId 'CVE-2026-0203' -SnapshotDate '2026-01-01' -Version '1.2.0'
        $staleRow.DeviceId = 'device-stale'
        $staleRow.DeviceName = 'device-stale.contoso.com'
        $staleRow.FirstSeenTimestamp = '2026-01-01'
        $staleRow.LastSeenTimestamp = '2026-01-01'

        Write-NdjsonRecordsFile -Path (Get-VulnCurrentPath -BasePath $tempRoot) -Records @($assumedOpenRow, $staleRow)
        [void](New-Item -Path (Get-VulnHistoryPath -BasePath $tempRoot -PeriodKey '2026Q1') -ItemType File -Force)
        Write-NdjsonRecordsFile -Path (Get-VulnHistoryRowsPath -BasePath $tempRoot -PeriodKey '2026Q1') -Records @($patchedRow)

        $machines = @(
            [PSCustomObject]@{
                id = 'device-patched'
                computerDnsName = 'device-patched.contoso.com'
                rbacGroupName = 'Servers'
                osPlatform = 'Windows 11'
                osVersion = '10.0.22631'
                machineTags = @('Prod')
                lastIpAddress = '10.0.0.10'
                lastExternalIpAddress = ''
                healthStatus = 'Active'
                riskScore = 'Medium'
                exposureLevel = 'Medium'
                deviceValue = 'Normal'
                managedBy = 'Intune'
                isAadJoined = $true
                lastSeen = '2026-03-10'
                firstSeen = '2026-02-01'
            }
            [PSCustomObject]@{
                id = 'device-open'
                computerDnsName = 'device-open.contoso.com'
                rbacGroupName = 'Servers'
                osPlatform = 'Windows 11'
                osVersion = '10.0.22631'
                machineTags = @('Prod')
                lastIpAddress = '10.0.0.11'
                lastExternalIpAddress = ''
                healthStatus = 'Active'
                riskScore = 'Medium'
                exposureLevel = 'Medium'
                deviceValue = 'Normal'
                managedBy = 'Intune'
                isAadJoined = $true
                lastSeen = '2026-03-01'
                firstSeen = '2026-02-01'
            }
            [PSCustomObject]@{
                id = 'device-stale'
                computerDnsName = 'device-stale.contoso.com'
                rbacGroupName = 'Servers'
                osPlatform = 'Windows 11'
                osVersion = '10.0.22631'
                machineTags = @('Prod')
                lastIpAddress = '10.0.0.12'
                lastExternalIpAddress = ''
                healthStatus = 'Inactive'
                riskScore = 'Low'
                exposureLevel = 'Low'
                deviceValue = 'Normal'
                managedBy = 'Intune'
                isAadJoined = $true
                lastSeen = '2026-01-01'
                firstSeen = '2025-12-01'
            }
        )

        [System.IO.File]::WriteAllText((Join-Path $tempRoot 'Machines_Current.json'), ($machines | ConvertTo-Json -Compress -Depth 20), [System.Text.UTF8Encoding]::new($false))
        Write-GzipTextFile -Path (Get-AdvancedHuntingCurrentPath -BasePath $tempRoot) -Content '[]'

        & $dashboardScriptPath -DirectoryPath $tempRoot -OutputPath $outputPath -ExportMachineData:$false -Validate -ValidationOutputPath $auditPath | Out-Null

        $audit = Get-Content -Path $auditPath -Raw | ConvertFrom-Json -Depth 100
        Assert-True ([string]$audit.OpenStateAudit.LatestObservedDate -eq '2026-03-10') 'Expected latest observed date to follow the most recent machine heartbeat.'
        Assert-True ($audit.OpenStateAudit.ProvenPatchedRowCount -eq 1) 'Expected exactly one row with positive patch evidence.'
        Assert-True ($audit.OpenStateAudit.AssumedOpenRowCount -eq 2) 'Expected two rows to remain in the assumed-open bucket.'
        Assert-True ($audit.OpenStateAudit.InactiveSuppressedRowCount -eq 1) 'Expected one assumed-open row to age out after the inactivity cutoff.'
        Assert-True ($audit.OpenStateAudit.CurrentOpenRowCount -eq 1) 'Expected only one row to remain open at the latest observed date.'
        Assert-True ($audit.OpenStateAudit.CurrentOpenDeviceCount -eq 1) 'Expected only one device to contribute to the current open backlog.'
    }
    finally {
        if (Test-Path -LiteralPath $tempRoot) {
            Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

function Test-DashboardValidationPreservesNoneSeverityData {
    [CmdletBinding()]
    param()

    $fixturePath = Join-Path $PSScriptRoot 'fixtures\legacy-migration-none-severity'
    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('dashboard-none-severity-' + [guid]::NewGuid().ToString('N'))
    [void](New-Item -Path $tempRoot -ItemType Directory -Force)
    $dashboardScriptPath = Join-Path (Split-Path -Path $PSScriptRoot -Parent) 'Generate-VulnerabilityDashboard.ps1'
    $outputPath = Join-Path $tempRoot 'dashboard.html'
    $auditPath = Join-Path $tempRoot 'audit.json'

    try {
        Copy-Item -Path (Join-Path $fixturePath '*') -Destination $tempRoot -Recurse -Force
        $null = Publish-VulnStoreFromBulkSnapshot -BasePath $tempRoot -RemoveSnapshotFiles

        $cachePath = Join-Path $tempRoot '.dashboard-cache'
        if (Test-Path -LiteralPath $cachePath) {
            Remove-Item -LiteralPath $cachePath -Recurse -Force -ErrorAction SilentlyContinue
        }

        & $dashboardScriptPath -DirectoryPath $tempRoot -OutputPath $outputPath -ExportMachineData:$false -Validate -ValidationOutputPath $auditPath | Out-Null

        $audit = Get-Content -Path $auditPath -Raw | ConvertFrom-Json -Depth 100
        Assert-True ($audit.RowComparison.Match -eq $true) 'Expected dashboard validation to preserve rows with VulnerabilitySeverityLevel=None.'
        Assert-True ($audit.RowComparison.MissingCount -eq 0) 'Expected no missing rows for none-severity data.'
        Assert-True ($audit.RowComparison.ExtraCount -eq 0) 'Expected no extra rows for none-severity data.'
    }
    finally {
        if (Test-Path -LiteralPath $tempRoot) {
            Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

function Test-DashboardSplitAssetsGenerationAndValidation {
    [CmdletBinding()]
    param()

    $fixturePath = Join-Path $PSScriptRoot 'fixtures\legacy-migration-none-severity'
    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('dashboard-split-assets-' + [guid]::NewGuid().ToString('N'))
    [void](New-Item -Path $tempRoot -ItemType Directory -Force)
    $dashboardScriptPath = Join-Path (Split-Path -Path $PSScriptRoot -Parent) 'Generate-VulnerabilityDashboard.ps1'
    $outputPath = Join-Path $tempRoot 'dashboard.html'
    $auditPath = Join-Path $tempRoot 'audit.json'
    $validateOnlyAuditPath = Join-Path $tempRoot 'audit-validate-only.json'
    $assetsPath = Join-Path $tempRoot 'dashboard.assets'
    $expectedHostedAssetRelativePaths = @(
        'runtime\dashboard.css'
        'runtime\dashboard.js'
        'runtime\pako.js'
        'vendor\chart.js'
        'data\summary.json'
        'optional\pdf-export.runtime.js'
        'optional\pdf-export.bundle.js'
        'data\payload.json.gz'
    )

    try {
        Copy-Item -Path (Join-Path $fixturePath '*') -Destination $tempRoot -Recurse -Force
        $null = Publish-VulnStoreFromBulkSnapshot -BasePath $tempRoot -RemoveSnapshotFiles

        $cachePath = Join-Path $tempRoot '.dashboard-cache'
        if (Test-Path -LiteralPath $cachePath) {
            Remove-Item -LiteralPath $cachePath -Recurse -Force -ErrorAction SilentlyContinue
        }

        & $dashboardScriptPath -DirectoryPath $tempRoot -OutputPath $outputPath -ExportMachineData:$false -SplitAssets -Validate -ValidationOutputPath $auditPath | Out-Null

        Assert-True ((Test-Path -LiteralPath $outputPath -PathType Leaf)) 'Expected split-assets generation to write the dashboard HTML.'
        Assert-True ((Test-Path -LiteralPath $assetsPath -PathType Container)) 'Expected split-assets generation to create the sibling asset directory.'

        foreach ($assetRelativePath in $expectedHostedAssetRelativePaths) {
            Assert-True ((Test-Path -LiteralPath (Join-Path $assetsPath $assetRelativePath) -PathType Leaf)) ("Expected split-assets generation to write '{0}'." -f $assetRelativePath)
        }

        $dashboardHtml = Get-Content -LiteralPath $outputPath -Raw
        Assert-True ($dashboardHtml.Contains('dashboard.assets/runtime/dashboard.css')) 'Expected split-assets dashboard HTML to reference the external stylesheet.'
        Assert-True ($dashboardHtml.Contains('dashboard.assets/runtime/dashboard.js')) 'Expected split-assets dashboard HTML to reference the external dashboard script.'
        Assert-True ($dashboardHtml.Contains('dashboard.assets/data/payload.json.gz')) 'Expected split-assets dashboard HTML to reference the external payload.'
        Assert-True ($dashboardHtml.Contains('external-compressed')) 'Expected split-assets dashboard HTML to advertise the external-compressed payload mode.'

        $audit = Get-Content -LiteralPath $auditPath -Raw | ConvertFrom-Json -Depth 100
        Assert-True ($audit.RowComparison.Match -eq $true) 'Expected split-assets dashboard validation to match the normalized source rows.'
        Assert-True ($audit.RowComparison.MissingCount -eq 0) 'Expected no missing rows in split-assets dashboard validation.'
        Assert-True ($audit.RowComparison.ExtraCount -eq 0) 'Expected no extra rows in split-assets dashboard validation.'

        & $dashboardScriptPath -DirectoryPath $tempRoot -OutputPath $outputPath -ValidateOnly -ValidationOutputPath $validateOnlyAuditPath | Out-Null

        $validateOnlyAudit = Get-Content -LiteralPath $validateOnlyAuditPath -Raw | ConvertFrom-Json -Depth 100
        Assert-True ($validateOnlyAudit.RowComparison.Match -eq $true) 'Expected ValidateOnly to read and validate the external split-assets payload.'
        Assert-True ($validateOnlyAudit.RowComparison.MissingCount -eq 0) 'Expected ValidateOnly split-assets validation to report no missing rows.'
        Assert-True ($validateOnlyAudit.RowComparison.ExtraCount -eq 0) 'Expected ValidateOnly split-assets validation to report no extra rows.'
    }
    finally {
        if (Test-Path -LiteralPath $tempRoot) {
            Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

function Test-DashboardValidateOnlyFailsWhenHostedPayloadMissing {
    [CmdletBinding()]
    param()

    $fixturePath = Join-Path $PSScriptRoot 'fixtures\legacy-migration-none-severity'
    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('dashboard-hosted-negative-' + [guid]::NewGuid().ToString('N'))
    [void](New-Item -Path $tempRoot -ItemType Directory -Force)
    $dashboardScriptPath = Join-Path (Split-Path -Path $PSScriptRoot -Parent) 'Generate-VulnerabilityDashboard.ps1'
    $outputPath = Join-Path $tempRoot 'dashboard.html'
    $auditPath = Join-Path $tempRoot 'audit.json'
    $assetsPath = Join-Path $tempRoot 'dashboard.assets'
    $validateStdoutPath = Join-Path $tempRoot 'validate-only.stdout.log'
    $validateStderrPath = Join-Path $tempRoot 'validate-only.stderr.log'

    try {
        Copy-Item -Path (Join-Path $fixturePath '*') -Destination $tempRoot -Recurse -Force
        $null = Publish-VulnStoreFromBulkSnapshot -BasePath $tempRoot -RemoveSnapshotFiles

        & $dashboardScriptPath -DirectoryPath $tempRoot -OutputPath $outputPath -ExportMachineData:$false -SplitAssets | Out-Null

        $payloadAssetPath = Join-Path $assetsPath 'data\payload.json.gz'
        Assert-True ((Test-Path -LiteralPath $payloadAssetPath -PathType Leaf)) 'Expected split-assets generation to write a hosted payload before the negative validation step.'
        Remove-Item -LiteralPath $payloadAssetPath -Force

        $pwshCommand = Get-Command -Name 'pwsh' -ErrorAction Stop
        $validationProcess = Start-Process -FilePath $pwshCommand.Source -ArgumentList @(
            '-NoProfile'
            '-File'
            $dashboardScriptPath
            '-DirectoryPath'
            $tempRoot
            '-OutputPath'
            $outputPath
            '-ValidateOnly'
            '-ValidationOutputPath'
            $auditPath
        ) -WorkingDirectory (Split-Path -Path $dashboardScriptPath -Parent) -RedirectStandardOutput $validateStdoutPath -RedirectStandardError $validateStderrPath -PassThru -Wait
        $validationExitCode = $validationProcess.ExitCode

        Assert-True ($validationExitCode -ne 0) 'Expected ValidateOnly to fail when a hosted dashboard payload asset is missing.'
        Assert-True (-not (Test-Path -LiteralPath $auditPath -PathType Leaf)) 'Expected missing hosted payload validation to avoid writing a passing audit artifact.'
    }
    finally {
        $global:LASTEXITCODE = 0
        if (Test-Path -LiteralPath $tempRoot) {
            Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

function Test-PackageOnlyRejectsMismatchedNormalizedPayloadManifest {
    [CmdletBinding()]
    param()

    $fixturePath = Join-Path $PSScriptRoot 'fixtures\legacy-migration-none-severity'
    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('dashboard-package-negative-' + [guid]::NewGuid().ToString('N'))
    [void](New-Item -Path $tempRoot -ItemType Directory -Force)
    $dashboardScriptPath = Join-Path (Split-Path -Path $PSScriptRoot -Parent) 'Generate-VulnerabilityDashboard.ps1'
    $normalizedPayloadPath = Join-Path $tempRoot '.local\payload\dashboard-payload.json.gz'
    $normalizedManifestPath = Join-Path $tempRoot '.local\payload\dashboard-payload.json'
    $tamperedPayloadPath = Join-Path $tempRoot '.local\payload\dashboard-payload-tampered.json.gz'
    $outputPath = Join-Path $tempRoot 'dashboard.html'
    $packageStdoutPath = Join-Path $tempRoot 'package-only.stdout.log'
    $packageStderrPath = Join-Path $tempRoot 'package-only.stderr.log'

    try {
        Copy-Item -Path (Join-Path $fixturePath '*') -Destination $tempRoot -Recurse -Force
        $null = Publish-VulnStoreFromBulkSnapshot -BasePath $tempRoot -RemoveSnapshotFiles

        & $dashboardScriptPath -DirectoryPath $tempRoot -ExportMachineData:$false -NormalizeOnly -NormalizedPayloadOutputPath $normalizedPayloadPath -NormalizedPayloadManifestOutputPath $normalizedManifestPath | Out-Null
        Assert-True ((Test-Path -LiteralPath $normalizedPayloadPath -PathType Leaf)) 'Expected NormalizeOnly to materialize a payload for the package-only negative test.'
        Assert-True ((Test-Path -LiteralPath $normalizedManifestPath -PathType Leaf)) 'Expected NormalizeOnly to materialize a manifest for the package-only negative test.'

        Write-GzipTextFile -Path $tamperedPayloadPath -Content '{"lookups":{"devices":[],"cves":[]},"vulnsFormat":"rows-v1","vulns":[]}'

        $pwshCommand = Get-Command -Name 'pwsh' -ErrorAction Stop
        $packageProcess = Start-Process -FilePath $pwshCommand.Source -ArgumentList @(
            '-NoProfile'
            '-File'
            $dashboardScriptPath
            '-DirectoryPath'
            $tempRoot
            '-OutputPath'
            $outputPath
            '-ExportMachineData:$false'
            '-PackageOnly'
            '-NormalizedPayloadInputPath'
            $tamperedPayloadPath
            '-NormalizedPayloadManifestInputPath'
            $normalizedManifestPath
        ) -WorkingDirectory (Split-Path -Path $dashboardScriptPath -Parent) -RedirectStandardOutput $packageStdoutPath -RedirectStandardError $packageStderrPath -PassThru -Wait
        $packageExitCode = $packageProcess.ExitCode

        Assert-True ($packageExitCode -ne 0) 'Expected package-only generation to reject a payload whose bytes do not match the provided manifest.'
        Assert-True (-not (Test-Path -LiteralPath $outputPath -PathType Leaf)) 'Expected package-only manifest mismatch to avoid writing a dashboard.'
    }
    finally {
        $global:LASTEXITCODE = 0
        if (Test-Path -LiteralPath $tempRoot) {
            Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

function Test-DashboardDualPackagingGenerationAndValidation {
    [CmdletBinding()]
    param()

    $fixturePath = Join-Path $PSScriptRoot 'fixtures\legacy-migration-none-severity'
    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('dashboard-dual-package-' + [guid]::NewGuid().ToString('N'))
    [void](New-Item -Path $tempRoot -ItemType Directory -Force)
    $dashboardScriptPath = Join-Path (Split-Path -Path $PSScriptRoot -Parent) 'Generate-VulnerabilityDashboard.ps1'
    $selfContainedOutputPath = Join-Path $tempRoot 'dashboard.html'
    $hostedOutputPath = Join-Path $tempRoot 'dashboard.Hosted.html'
    $hostedAssetsPath = Join-Path $tempRoot 'dashboard.Hosted.assets'
    $expectedHostedAssetRelativePaths = @(
        'runtime\dashboard.css'
        'runtime\dashboard.js'
        'runtime\pako.js'
        'vendor\chart.js'
        'data\summary.json'
        'optional\pdf-export.runtime.js'
        'optional\pdf-export.bundle.js'
        'data\payload.json.gz'
    )
    $normalizedPayloadPath = Join-Path $tempRoot '.local\payload\dashboard-payload.json.gz'
    $selfAuditPath = Join-Path $tempRoot 'audit.json'
    $hostedAuditPath = Join-Path $tempRoot 'audit.hosted.json'
    $hostedValidateOnlyAuditPath = Join-Path $tempRoot 'audit.hosted.validate-only.json'

    try {
        Copy-Item -Path (Join-Path $fixturePath '*') -Destination $tempRoot -Recurse -Force
        $null = Publish-VulnStoreFromBulkSnapshot -BasePath $tempRoot -RemoveSnapshotFiles

        $cachePath = Join-Path $tempRoot '.dashboard-cache'
        if (Test-Path -LiteralPath $cachePath) {
            Remove-Item -LiteralPath $cachePath -Recurse -Force -ErrorAction SilentlyContinue
        }

        & $dashboardScriptPath -DirectoryPath $tempRoot -ExportMachineData:$false -NormalizeOnly -NormalizedPayloadOutputPath $normalizedPayloadPath | Out-Null
        Assert-True ((Test-Path -LiteralPath $normalizedPayloadPath -PathType Leaf)) 'Expected NormalizeOnly to materialize the normalized payload for dual packaging.'

        $packageOutput = @(& $dashboardScriptPath -DirectoryPath $tempRoot -OutputPath $selfContainedOutputPath -ExportMachineData:$false -PackageOnly -NormalizedPayloadInputPath $normalizedPayloadPath -DualPackage -Validate -ValidationOutputPath $selfAuditPath 6>&1)
        $packageMessages = @($packageOutput | ForEach-Object { Get-OutputRecordText -Record $_ } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
        $hostedWriteMessageIndex = -1
        $selfContainedWriteMessageIndex = -1
        for ($i = 0; $i -lt $packageMessages.Count; $i++) {
            if ($hostedWriteMessageIndex -lt 0 -and $packageMessages[$i].Contains('Writing hosted dashboard to')) {
                $hostedWriteMessageIndex = $i
            }

            if ($selfContainedWriteMessageIndex -lt 0 -and $packageMessages[$i].Contains('Writing self-contained dashboard to')) {
                $selfContainedWriteMessageIndex = $i
            }
        }

        Assert-True ((Test-Path -LiteralPath $selfContainedOutputPath -PathType Leaf)) 'Expected dual packaging to write the self-contained dashboard HTML.'
        Assert-True ((Test-Path -LiteralPath $hostedOutputPath -PathType Leaf)) 'Expected dual packaging to write the hosted dashboard HTML.'
        Assert-True ((Test-Path -LiteralPath $hostedAssetsPath -PathType Container)) 'Expected dual packaging to create the hosted sibling asset directory.'
        Assert-True ($hostedWriteMessageIndex -ge 0) 'Expected dual packaging output to announce hosted dashboard generation.'
        Assert-True ($selfContainedWriteMessageIndex -ge 0) 'Expected dual packaging output to announce self-contained dashboard generation.'
        Assert-True ($hostedWriteMessageIndex -lt $selfContainedWriteMessageIndex) 'Expected dual packaging to write the hosted dashboard before the self-contained dashboard.'

        foreach ($assetRelativePath in $expectedHostedAssetRelativePaths) {
            Assert-True ((Test-Path -LiteralPath (Join-Path $hostedAssetsPath $assetRelativePath) -PathType Leaf)) ("Expected dual packaging to write '{0}' to the hosted asset directory." -f $assetRelativePath)
        }

        Assert-True ((Test-Path -LiteralPath ($selfContainedOutputPath + '.validation.json') -PathType Leaf)) 'Expected dual packaging to write a self-contained validation sidecar.'
        Assert-True ((Test-Path -LiteralPath ($hostedOutputPath + '.validation.json') -PathType Leaf)) 'Expected dual packaging to write a hosted validation sidecar.'

        $selfContainedHtml = Get-Content -LiteralPath $selfContainedOutputPath -Raw
        Assert-True ($selfContainedHtml.Contains('<script id="vulnsData" type="application/json">')) 'Expected the self-contained dashboard to embed the compressed payload script.'
        Assert-True ($selfContainedHtml.Contains('compressed')) 'Expected the self-contained dashboard to advertise the embedded compressed payload mode.'

        $hostedHtml = Get-Content -LiteralPath $hostedOutputPath -Raw
        Assert-True ($hostedHtml.Contains('dashboard.Hosted.assets/runtime/dashboard.css')) 'Expected the hosted dual-packaged dashboard to reference the hosted stylesheet.'
        Assert-True ($hostedHtml.Contains('dashboard.Hosted.assets/runtime/dashboard.js')) 'Expected the hosted dual-packaged dashboard to reference the hosted dashboard script.'
        Assert-True ($hostedHtml.Contains('dashboard.Hosted.assets/data/payload.json.gz')) 'Expected the hosted dual-packaged dashboard to reference the hosted payload.'
        Assert-True ($hostedHtml.Contains('external-compressed')) 'Expected the hosted dual-packaged dashboard to advertise the external-compressed payload mode.'

        $selfAudit = Get-Content -LiteralPath $selfAuditPath -Raw | ConvertFrom-Json -Depth 100
        Assert-True ($selfAudit.RowComparison.Match -eq $true) 'Expected dual packaging validation to preserve rows in the self-contained dashboard.'
        Assert-True ($selfAudit.RowComparison.MissingCount -eq 0) 'Expected no missing rows in self-contained dual packaging validation.'
        Assert-True ($selfAudit.RowComparison.ExtraCount -eq 0) 'Expected no extra rows in self-contained dual packaging validation.'

        $hostedAudit = Get-Content -LiteralPath $hostedAuditPath -Raw | ConvertFrom-Json -Depth 100
        Assert-True ($hostedAudit.RowComparison.Match -eq $true) 'Expected dual packaging validation to preserve rows in the hosted dashboard.'
        Assert-True ($hostedAudit.RowComparison.MissingCount -eq 0) 'Expected no missing rows in hosted dual packaging validation.'
        Assert-True ($hostedAudit.RowComparison.ExtraCount -eq 0) 'Expected no extra rows in hosted dual packaging validation.'

        & $dashboardScriptPath -DirectoryPath $tempRoot -OutputPath $hostedOutputPath -ValidateOnly -ValidationOutputPath $hostedValidateOnlyAuditPath | Out-Null

        $hostedValidateOnlyAudit = Get-Content -LiteralPath $hostedValidateOnlyAuditPath -Raw | ConvertFrom-Json -Depth 100
        Assert-True ($hostedValidateOnlyAudit.RowComparison.Match -eq $true) 'Expected ValidateOnly to validate the hosted dual-packaged dashboard.'
        Assert-True ($hostedValidateOnlyAudit.RowComparison.MissingCount -eq 0) 'Expected ValidateOnly hosted dual packaging validation to report no missing rows.'
        Assert-True ($hostedValidateOnlyAudit.RowComparison.ExtraCount -eq 0) 'Expected ValidateOnly hosted dual packaging validation to report no extra rows.'
    }
    finally {
        if (Test-Path -LiteralPath $tempRoot) {
            Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

function Test-VulnContentStoreRoundTrip {
    [CmdletBinding()]
    param()

    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('vuln-content-store-' + [guid]::NewGuid().ToString('N'))
    [void](New-Item -Path $tempRoot -ItemType Directory -Force)
    $originalDictionaryReader = $null

    try {
        $currentRow = Get-TestVulnRow -Id 'content-001' -CveId 'CVE-2026-0101' -SnapshotDate '2026-03-20' -Version '1.0.0'
        $historyRow = Get-TestVulnRow -Id 'content-002' -CveId 'CVE-2026-0102' -SnapshotDate '2026-03-18' -Version '1.1.0'
        $historyRow.DeviceId = 'device-002'
        $historyRow.DeviceName = 'device02.contoso.com'
        $historyRow.MachineTags = @('Pilot', 'Servers')

        Write-NdjsonRecordsFile -Path (Get-VulnCurrentPath -BasePath $tempRoot) -Records @($currentRow)
        Write-NdjsonRecordsFile -Path (Get-VulnHistoryRowsPath -BasePath $tempRoot -PeriodKey '2026Q1') -Records @($historyRow)

        Publish-VulnContentStoreUnlocked -BasePath $tempRoot

        $originalDictionaryReader = ${function:Read-VulnContentDictionary}
        Set-Item -Path Function:Read-VulnContentDictionary -Value {
            param(
                [Parameter(Mandatory = $true)]
                [string]$Path
            )

            throw "Read-VulnContentStoreRow should stream reduced content lookups instead of calling Read-VulnContentDictionary for '$Path'."
        }

        $roundTripped = @(Read-VulnContentStoreRow -BasePath $tempRoot | Sort-Object Id)

        Assert-True ((Test-Path -LiteralPath (Get-VulnContentDictionaryPath -BasePath $tempRoot) -PathType Leaf)) 'Expected vulnerability content dictionary sidecar to be created.'
        Assert-True ((Test-Path -LiteralPath (Get-VulnCurrentRefsPath -BasePath $tempRoot) -PathType Leaf)) 'Expected vulnerability current refs sidecar to be created.'
        Assert-True ((Test-Path -LiteralPath (Get-VulnHistoryRefsPath -BasePath $tempRoot -PeriodKey '2026Q1') -PathType Leaf)) 'Expected vulnerability history refs sidecar to be created.'
        Assert-True ((Test-VulnContentStoreSupportsDirectMerge -BasePath $tempRoot) -eq $true) 'Expected compact source-order content dictionaries to remain eligible for direct merge.'
        Assert-True ($roundTripped.Count -eq 2) 'Expected content sidecar round-trip to return both current and history rows.'

        $expectedRows = @($currentRow, $historyRow) | Sort-Object Id
        for ($i = 0; $i -lt $expectedRows.Count; $i++) {
            $expected = $expectedRows[$i]
            $actual = $roundTripped[$i]

            foreach ($propertyName in @(
                'Id',
                'DeviceId',
                'DeviceName',
                'RbacGroupName',
                'OSPlatform',
                'OSVersion',
                'CveId',
                'SoftwareVendor',
                'SoftwareName',
                'SoftwareVersion',
                'VulnerabilitySeverityLevel',
                'ExploitabilityLevel',
                'RecommendationReference',
                'RecommendedSecurityUpdate',
                'RecommendedSecurityUpdateId',
                'RecommendedSecurityUpdateUrl',
                'FirstSeenTimestamp',
                'LastSeenTimestamp',
                'CveBatchTitle',
                'CveBatchUrl'
            )) {
                Assert-True ([string]$expected.$propertyName -eq [string]$actual.$propertyName) "Expected content sidecar round-trip to preserve property '$propertyName'."
            }

            Assert-True ((@($expected.MachineTags) -join '|') -eq (@($actual.MachineTags) -join '|')) 'Expected content sidecar round-trip to preserve machine tags.'
            Assert-True ((@($expected.DiskPaths) -join '|') -eq (@($actual.DiskPaths) -join '|')) 'Expected content sidecar round-trip to preserve disk paths.'
            Assert-True ((@($expected.RegistryPaths) -join '|') -eq (@($actual.RegistryPaths) -join '|')) 'Expected content sidecar round-trip to preserve registry paths.'
            Assert-True (($expected.SecurityUpdateAvailable -eq $true) -eq ($actual.SecurityUpdateAvailable -eq $true)) 'Expected content sidecar round-trip to preserve update availability.'
            Assert-True (($expected.IsOnboarded -eq $true) -eq ($actual.IsOnboarded -eq $true)) 'Expected content sidecar round-trip to preserve onboarded state.'
        }
    }
    finally {
        if ($null -ne $originalDictionaryReader) {
            Set-Item -Path Function:Read-VulnContentDictionary -Value $originalDictionaryReader
        }

        if (Test-Path -LiteralPath $tempRoot) {
            Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

function Test-ProceduralSyntheticDatasetGeneration {
    [CmdletBinding()]
    param()

    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('procedural-synthetic-' + [guid]::NewGuid().ToString('N'))
    $firstPath = Join-Path $tempRoot 'first'
    $secondPath = Join-Path $tempRoot 'second'
    $overlayPath = Join-Path $tempRoot 'overlay'
    $initialImportPath = Join-Path $tempRoot 'initial-import'
    try {
        [void](New-Item -Path $firstPath -ItemType Directory -Force)
        [void](New-Item -Path $secondPath -ItemType Directory -Force)
        $writerSource = Join-Path $PSScriptRoot 'helpers\SyntheticDatasetWriter.cs'
        if ($null -eq ('DefenderReporting.Synthetic.SyntheticDatasetWriter' -as [type])) { Add-Type -Path $writerSource }
        foreach ($path in @($firstPath, $secondPath)) {
            $result = [DefenderReporting.Synthetic.SyntheticDatasetWriter]::Generate($path, 16, 240, 4242, '2026-07-11', 4, 80, 0.10, 0.05, $true)
            Assert-True ($result.CurrentRows + $result.HistoryRows -eq 240) 'Expected procedural writer to emit the requested total row count.'
            ([ordered]@{
                manifestVersion = 2; generatorVersion = 'procedural-streaming-v1'; modelVersion = 'procedural-v1'; datasetId = 'procedural-test';
                preset = 'BalancedMediumHeavy'; seed = 4242; generationDate = '2026-07-11'; snapshotOrdinal = 0;
                actualDeviceCount = 16; actualCurrentRows = $result.CurrentRows; actualHistoryRows = $result.HistoryRows;
                actualTotalVulnRows = 240; targetDeviceCount = 16; targetTotalVulnRows = 240; contentTemplateCount = 80
            }) | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath (Join-Path $path 'synthetic-manifest.json') -Encoding utf8
        }

        foreach ($firstFile in @(Get-ChildItem -LiteralPath $firstPath -Filter '*.json.gz' -File | Sort-Object Name)) {
            $secondFile = Join-Path $secondPath $firstFile.Name
            Assert-True ((Test-Path -LiteralPath $secondFile -PathType Leaf)) "Expected deterministic rerun artifact '$($firstFile.Name)'."
            Assert-True ((Get-FileHash $firstFile.FullName).Hash -eq (Get-FileHash $secondFile).Hash) "Expected byte-stable procedural artifact '$($firstFile.Name)'."
        }

        Assert-True (Test-VulnContentStoreExistence -BasePath $firstPath) 'Expected procedural seed to create a valid content store.'
        Assert-True (@(Read-VulnContentStoreRow -BasePath $firstPath).Count -eq 240) 'Expected procedural content refs to expand to every requested row.'
        foreach ($historyFile in @(Get-ChildItem -LiteralPath $firstPath -Filter 'VulnHistory_*.json.gz' -File)) {
            Assert-True ((Test-VulnHistoryFileLightweight -Path $historyFile.FullName) -ge 0) "Expected valid procedural history metadata in '$($historyFile.Name)'."
        }

        & (Join-Path $PSScriptRoot 'New-SyntheticSnapshotDelta.ps1') -SourcePath $firstPath -OutputPath $overlayPath -TargetLatestDate '2026-07-12'
        $overlayManifest = Get-Content -LiteralPath (Join-Path $overlayPath 'synthetic-manifest.json') -Raw | ConvertFrom-Json -Depth 30
        Assert-True ([string]$overlayManifest.incrementMode -eq 'AdvanceSnapshot') 'Expected procedural delta to use AdvanceSnapshot mode.'
        foreach ($category in @('added', 'changed', 'removed', 'reopened', 'persistent')) {
            Assert-True ([int]$overlayManifest.churn.$category -gt 0) "Expected deterministic overlay churn category '$category' to contain rows."
        }
        Assert-True (@(Get-ChildItem -LiteralPath $overlayPath -Filter 'VulnExport_*_2026-07-12.json.gz' -File).Count -gt 0) 'Expected procedural delta to emit grouped bulk snapshot files.'
        if ($IsWindows) { Assert-True ([int]$overlayManifest.hardLinkedSeedFiles -gt 0) 'Expected Windows procedural overlays to hard-link unchanged seed artifacts.' }
        Assert-True ((Get-FileHash (Join-Path $firstPath 'VulnContentDictionary.json.gz')).Hash -eq (Get-FileHash (Join-Path $overlayPath 'VulnContentDictionary.json.gz')).Hash) 'Expected overlay creation to preserve the base dictionary.'

        [void](New-Item -Path $initialImportPath -ItemType Directory -Force)
        Copy-Item -LiteralPath (Join-Path $overlayPath 'synthetic-manifest.json') -Destination $initialImportPath
        foreach ($snapshotFile in @(Get-ChildItem -LiteralPath $overlayPath -Filter 'VulnExport_*_2026-07-12.json.gz' -File)) {
            Copy-Item -LiteralPath $snapshotFile.FullName -Destination $initialImportPath
        }
        $initialResult = Publish-VulnStoreFromBulkSnapshot -BasePath $initialImportPath -SnapshotFilePaths @(
            Get-ChildItem -LiteralPath $initialImportPath -Filter 'VulnExport_*.json.gz' -File | ForEach-Object { $_.FullName }
        )
        Assert-True ($initialResult.CurrentRows -gt 0) 'Expected procedural initial import to publish current rows.'
        Assert-True (Test-VulnStoreExistence -BasePath $initialImportPath) 'Expected procedural initial import to create the canonical store.'
        Assert-True (Test-VulnContentStoreExistence -BasePath $initialImportPath) 'Expected procedural initial import to create content sidecars.'
        Assert-True (@(Read-VulnContentStoreRow -BasePath $initialImportPath).Count -eq $initialResult.CurrentRows) 'Expected procedural initial import refs to expand to every canonical current row.'
    }
    finally {
        if (Test-Path -LiteralPath $tempRoot) { Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue }
    }
}

function Initialize-RegressionDashboardLibraryCache {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$BasePath)

    $libraryCachePath = Join-Path $BasePath '.dashboard-cache\libraries'
    [void](New-Item -Path $libraryCachePath -ItemType Directory -Force)
    foreach ($library in @(
            @{ Name = 'Chart.js'; Url = 'https://cdn.jsdelivr.net/npm/chart.js@4.4.1/dist/chart.umd.js' },
            @{ Name = 'pdfmake'; Url = 'https://cdnjs.cloudflare.com/ajax/libs/pdfmake/0.2.7/pdfmake.min.js' },
            @{ Name = 'vfs_fonts'; Url = 'https://cdnjs.cloudflare.com/ajax/libs/pdfmake/0.2.7/vfs_fonts.min.js' },
            @{ Name = 'html2canvas'; Url = 'https://cdnjs.cloudflare.com/ajax/libs/html2canvas/1.4.1/html2canvas.min.js' },
            @{ Name = 'pako'; Url = 'https://cdn.jsdelivr.net/npm/pako@2.1.0/dist/pako.min.js' }
        )) {
        $hashBytes = [System.Security.Cryptography.SHA256]::HashData([System.Text.Encoding]::UTF8.GetBytes([string]$library.Url))
        $urlHash = ([System.BitConverter]::ToString($hashBytes)).Replace('-', '').ToLowerInvariant().Substring(0, 16)
        $safeName = ([string]$library.Name -replace '[^A-Za-z0-9._-]', '-')
        $cachePath = Join-Path $libraryCachePath ("{0}-{1}.js" -f $safeName, $urlHash)
        [System.IO.File]::WriteAllText($cachePath, ('/* offline regression fixture: ' + $safeName + ' */'), [System.Text.UTF8Encoding]::new($false))
    }
}

function Test-VulnObservedWindowCacheRoundTrip {
    [CmdletBinding()]
    param()

    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('vuln-observed-cache-' + [guid]::NewGuid().ToString('N'))
    [void](New-Item -Path $tempRoot -ItemType Directory -Force)
    $originalDictionaryReader = $null

    try {
        $currentRow = Get-TestVulnRow -Id 'merge-001' -CveId 'CVE-2026-0004' -SnapshotDate '2026-03-17' -Version '1.0.0'
        $historyRow = Get-TestVulnRow -Id 'merge-001' -CveId 'CVE-2026-0004' -SnapshotDate '2026-03-19' -Version '1.0.0'
        $historyRow.RecommendedSecurityUpdate = 'KB000099'
        $historyRow.RecommendedSecurityUpdateId = 'KB000099'
        $otherHistoryRow = Get-TestVulnRow -Id 'merge-002' -CveId 'CVE-2026-0005' -SnapshotDate '2026-03-23' -Version '2.0.0'

        Write-NdjsonRecordsFile -Path (Get-VulnCurrentPath -BasePath $tempRoot) -Records @($currentRow)
        Write-NdjsonRecordsFile -Path (Get-VulnHistoryRowsPath -BasePath $tempRoot -PeriodKey '2026Q1') -Records @($historyRow, $otherHistoryRow)

        Publish-VulnContentStoreUnlocked -BasePath $tempRoot
        $expectedRows = @(Write-MergedVulnObservedWindowRows -Source { @($currentRow, $historyRow, $otherHistoryRow) } | Sort-Object Id, FirstSeenTimestamp, LastSeenTimestamp)
        $cachePath = Publish-VulnObservedWindowCache -BasePath $tempRoot

        Assert-True ((Test-Path -LiteralPath $cachePath -PathType Leaf)) 'Expected observed-window cache to be created.'

        $originalDictionaryReader = ${function:Read-VulnContentDictionary}
        Set-Item -Path Function:Read-VulnContentDictionary -Value {
            param(
                [Parameter(Mandatory = $true)]
                [string]$Path
            )

            throw "Get-NormalizationSourceRows should stream reduced content lookups for compact observed-window caches instead of calling Read-VulnContentDictionary for '$Path'."
        }

        # Read the cache through Get-NormalizationSourceRows which auto-detects
        # the compact ref format (T5) or legacy full-record format.
        $cachedRows = @(Get-NormalizationSourceRows -DataPath $tempRoot | Sort-Object Id, FirstSeenTimestamp, LastSeenTimestamp)
        Assert-True ($expectedRows.Count -eq $cachedRows.Count) 'Expected observed-window cache to preserve merged row count.'

        for ($i = 0; $i -lt $expectedRows.Count; $i++) {
            $expected = $expectedRows[$i]
            $actual = $cachedRows[$i]
            foreach ($propertyName in @(
                'Id',
                'DeviceId',
                'CveId',
                'RecommendedSecurityUpdate',
                'RecommendedSecurityUpdateId',
                'FirstSeenTimestamp',
                'LastSeenTimestamp'
            )) {
                Assert-True ([string]$expected.$propertyName -eq [string]$actual.$propertyName) "Expected observed-window cache to preserve property '$propertyName'."
            }
        }
    }
    finally {
        if ($null -ne $originalDictionaryReader) {
            Set-Item -Path Function:Read-VulnContentDictionary -Value $originalDictionaryReader
        }

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

function Test-FunctionExecutionStatusSummaryIncludesNormalizationProgressInfo {
    [CmdletBinding()]
    param()

    $repoRoot = Split-Path -Path $PSScriptRoot -Parent
    $validationScriptPath = Join-Path $repoRoot 'build\Invoke-AzureDeploymentValidation.ps1'
    Assert-True ((Test-Path -LiteralPath $validationScriptPath -PathType Leaf)) "Expected validation script at '$validationScriptPath'."

    $scriptText = Get-Content -LiteralPath $validationScriptPath -Raw
    $functionMatch = [regex]::Match($scriptText, '(?s)function Get-FunctionExecutionStatusSummaryText \{.*?\r?\n\}\r?\n\r?\nfunction Set-FunctionExecutionControlBlob')
    Assert-True ($functionMatch.Success) 'Expected validation script to contain Get-FunctionExecutionStatusSummaryText.'

    $functionDefinition = $functionMatch.Value -replace '\r?\n\r?\nfunction Set-FunctionExecutionControlBlob\z', ''
    $originalCulture = [System.Globalization.CultureInfo]::CurrentCulture
    $originalUiCulture = [System.Globalization.CultureInfo]::CurrentUICulture
    try {
        $nonEnglishCulture = [System.Globalization.CultureInfo]::GetCultureInfo('de-DE')
        [System.Threading.Thread]::CurrentThread.CurrentCulture = $nonEnglishCulture
        [System.Threading.Thread]::CurrentThread.CurrentUICulture = $nonEnglishCulture

        $summary = & {
            . ([scriptblock]::Create($functionDefinition))

            Get-FunctionExecutionStatusSummaryText -StatusDocument ([PSCustomObject]@{
                    status = 'running'
                    stage = 'NormalizeDashboardData'
                    message = 'Streaming content-store vulnerability references into the normalized payload.'
                    pipelineArchitectureVersion = 'monolithic-v1'
                    normalizedPayloadCacheHit = $false
                    normalizedSubPhase = 'StreamContentStoreRefs'
                    normalizedRowCount = 125000
                })
        }
    }
    finally {
        [System.Threading.Thread]::CurrentThread.CurrentCulture = $originalCulture
        [System.Threading.Thread]::CurrentThread.CurrentUICulture = $originalUiCulture
    }

    Assert-True ($summary -like '*arch=monolithic-v1*') 'Expected validation status summary text to retain architecture metadata.'
    Assert-True ($summary -like '*payloadCache=miss*') 'Expected validation status summary text to retain payload-cache metadata.'
    Assert-True ($summary -like '*subphase=StreamContentStoreRefs*') 'Expected validation status summary text to surface normalization subphase metadata.'
    Assert-True ($summary -like '*rows=125,000*') 'Expected validation status summary text to surface formatted normalization row counts.'
    Assert-True ($summary -notlike '*rows=125.000*') 'Expected validation status summary text to avoid host-culture row count formatting.'
}

function Test-BenchmarkEvidenceEnvelopeWritesTransactionally {
    [CmdletBinding()]
    param()

    $repoRoot = Split-Path -Path $PSScriptRoot -Parent
    . (Join-Path $PSScriptRoot 'helpers\BenchmarkEvidenceTools.ps1')
    $schemaPath = Join-Path $PSScriptRoot 'benchmark-evidence.schema.json'
    Assert-True (Test-Path -LiteralPath $schemaPath -PathType Leaf) 'Expected the benchmark evidence JSON schema to exist.'

    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('benchmark-evidence-' + [guid]::NewGuid().ToString('N'))
    try {
        [void](New-Item -Path $tempRoot -ItemType Directory -Force)
        [System.IO.File]::WriteAllText((Join-Path $tempRoot 'synthetic-manifest.json'), '{"datasetId":"evidence-test","actualTotalVulnRows":1}', [System.Text.UTF8Encoding]::new($false))
        [System.IO.File]::WriteAllText((Join-Path $tempRoot 'VulnCurrentRefs.json'), '[0,0,0,"2026-01-01","2026-01-01"]', [System.Text.UTF8Encoding]::new($false))
        $dataset = Get-BenchmarkDatasetEvidence -DatasetPath $tempRoot
        $evidence = Get-BenchmarkEvidenceEnvelope -Kind 'regression' -RepoPath $repoRoot -Dataset $dataset -Execution ([PSCustomObject]@{ status = 'completed' })
        $outputPath = Join-Path $tempRoot 'result\evidence.json'
        Write-BenchmarkEvidenceEnvelope -Path $outputPath -Evidence $evidence

        $written = Get-Content -LiteralPath $outputPath -Raw | ConvertFrom-Json -Depth 50
        Assert-True ($written.evidence_schema_version -eq 1) 'Expected benchmark evidence schema version 1.'
        Assert-True ($written.dataset.files.Count -eq 2) 'Expected benchmark evidence to hash every source dataset artifact before writing its result.'
        Assert-True (-not [string]::IsNullOrWhiteSpace([string]$written.artifacts.runbook)) 'Expected benchmark evidence to capture the generated runbook fingerprint.'
        Assert-True (@(Get-ChildItem -LiteralPath (Split-Path $outputPath -Parent) -Filter '*.tmp-*' -File).Count -eq 0) 'Expected transactional benchmark evidence publication to clean staging files.'
    }
    finally {
        if (Test-Path -LiteralPath $tempRoot) { Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue }
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

function Test-AzureValidationHarnessRequiresExecutionGuardAndRestoration {
    [CmdletBinding()]
    param()

    $repoRoot = Split-Path -Path $PSScriptRoot -Parent
    $path = Join-Path $PSScriptRoot 'Invoke-AzureRunbookValidation.ps1'
    Assert-True (Test-Path -LiteralPath $path -PathType Leaf) 'Expected the guarded Azure validation harness.'
    $text = Get-Content -LiteralPath $path -Raw
    Assert-True ($text.Contains("if (-not `$Execute)")) 'Expected Azure validation to require the explicit Execute guard.'
    Assert-True ($text.Contains("Restore-ValidationContainer 'exports'")) 'Expected Azure validation finally cleanup to restore exports.'
    Assert-True ($text.Contains("Restore-ValidationContainer 'dashboards'")) 'Expected Azure validation finally cleanup to restore dashboards.'
    Assert-True ($text.Contains("'automation','runbook','replace-content'")) 'Expected Azure validation to restore published runbook content.'
    Assert-True ($text.Contains("'--if-none-match','*'")) 'Expected Azure validation to acquire its lock atomically.'
    Assert-True ($text.Contains('ValidatePublishedSemanticParity')) 'Expected Azure validation to expose published source-to-dashboard semantic sign-off.'
    Assert-True ($text.Contains('-ForceFullValidation')) 'Expected published semantic sign-off to bypass prior attestations and perform a fresh comparison.'

    $caught = $null
    try {
        & $path -SubscriptionId 'test-subscription' -AutomationAccountName 'test-account' -AutomationResourceGroup 'test-group' -RunbookName 'test-runbook' -StorageAccountName 'test-storage' -DatasetPath (Join-Path $repoRoot 'exports')
    }
    catch { $caught = $_ }
    Assert-True ($null -ne $caught -and $caught.Exception.Message -like '*Re-run with -Execute*') 'Expected the Azure harness to reject mutation without -Execute before contacting Azure.'
}

function Test-AzureDashboardCandidateEvidenceRejectsIncompletePublication {
    [CmdletBinding()]
    param()

    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('azure-dashboard-evidence-' + [guid]::NewGuid().ToString('N'))
    $assetRoot = Join-Path $tempRoot 'VulnerabilityDashboard.assets'
    try {
        foreach ($relativePath in @('runtime\dashboard.css', 'runtime\dashboard.js', 'runtime\pako.js', 'vendor\chart.js', 'optional\pdf-export.bundle.js')) {
            $path = Join-Path $assetRoot $relativePath
            [void](New-Item -Path (Split-Path $path -Parent) -ItemType Directory -Force)
            [System.IO.File]::WriteAllText($path, 'fixture', [System.Text.UTF8Encoding]::new($false))
        }
        $payloadPath = Join-Path $assetRoot 'data\payload.json.gz'
        [void](New-Item -Path (Split-Path $payloadPath -Parent) -ItemType Directory -Force)
        Write-GzipTextFile -Path $payloadPath -Content '{"vulnsFormat":"rows-v1","lookups":{},"vulns":[[0]]}'
        $payloadSha = (Get-FileHash -LiteralPath $payloadPath -Algorithm SHA256).Hash.ToLowerInvariant()
        $summary = [ordered]@{ version = 1; meta = [ordered]@{ payloadSha256 = $payloadSha; vulnCount = 1; deviceCount = 1; cveCount = 1 }; filterCatalog = [ordered]@{ groups = @(); tags = @(); devices = @() } }
        [System.IO.File]::WriteAllText((Join-Path $assetRoot 'data\summary.json'), ($summary | ConvertTo-Json -Compress -Depth 10), [System.Text.UTF8Encoding]::new($false))
        $html = 'VulnerabilityDashboard.assets/data/payload.json.gz VulnerabilityDashboard.assets/data/summary.json VulnerabilityDashboard.assets/runtime/dashboard.js'
        [System.IO.File]::WriteAllText((Join-Path $tempRoot 'VulnerabilityDashboard.html'), $html, [System.Text.UTF8Encoding]::new($false))
        $status = [PSCustomObject]@{ status = 'succeeded'; stage = 'Completed'; vulnerabilities = 1; devices = 1; cves = 1; dashboardBlobName = 'VulnerabilityDashboard.html'; hostedDashboardBlobName = $null }

        $valid = Assert-AzureDashboardCandidateEvidence -DashboardRootPath $tempRoot -RunbookStatus $status -DashboardDeliveryMode Hosted -ExpectedTotalRows 1 -PayloadRowCounter { param($Path) Get-CompressedPayloadVulnCount -Path $Path }
        Assert-True ($valid.hosted_assets_validated -eq $true -and $valid.payload_row_count -eq 1) 'Expected complete hosted candidate evidence to pass.'

        $comparisonPayloadPath = Join-Path $tempRoot 'comparison.json.gz'
        Write-GzipTextFile -Path $comparisonPayloadPath -Content '{"vulnsFormat":"rows-v1","lookups":{},"vulns":[[0]]}'
        $payloadContentEvidence = Get-GzipDecompressedContentEvidence -Path $payloadPath
        $comparisonContentEvidence = Get-GzipDecompressedContentEvidence -Path $comparisonPayloadPath
        Assert-True ($payloadContentEvidence.decompressed_sha256 -eq $comparisonContentEvidence.decompressed_sha256 -and $payloadContentEvidence.decompressed_bytes -eq $comparisonContentEvidence.decompressed_bytes) 'Expected streaming decompressed evidence to prove exact JSON equality independently of gzip bytes.'
        Write-GzipTextFile -Path $comparisonPayloadPath -Content '{"vulnsFormat":"rows-v1","lookups":{},"vulns":[[1]]}'
        $comparisonContentEvidence = Get-GzipDecompressedContentEvidence -Path $comparisonPayloadPath
        Assert-True ($payloadContentEvidence.decompressed_sha256 -ne $comparisonContentEvidence.decompressed_sha256) 'Expected streaming decompressed evidence to detect one changed row.'

        $summary.meta.payloadSha256 = ('0' * 64)
        [System.IO.File]::WriteAllText((Join-Path $assetRoot 'data\summary.json'), ($summary | ConvertTo-Json -Compress -Depth 10), [System.Text.UTF8Encoding]::new($false))
        $caught = $null
        try { $null = Assert-AzureDashboardCandidateEvidence -DashboardRootPath $tempRoot -RunbookStatus $status -DashboardDeliveryMode Hosted -ExpectedTotalRows 1 }
        catch { $caught = $_ }
        Assert-True ($null -ne $caught -and $caught.Exception.Message -like '*SHA-256*') 'Expected a stale summary payload hash to fail candidate acceptance.'

        Remove-Item -LiteralPath (Join-Path $assetRoot 'runtime\dashboard.js') -Force
        $caught = $null
        try { $null = Assert-AzureDashboardCandidateEvidence -DashboardRootPath $tempRoot -RunbookStatus $status -DashboardDeliveryMode Hosted -ExpectedTotalRows 1 }
        catch { $caught = $_ }
        Assert-True ($null -ne $caught -and $caught.Exception.Message -like '*asset*missing*') 'Expected a missing hosted asset to fail candidate acceptance.'
    }
    finally {
        if (Test-Path -LiteralPath $tempRoot) { Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue }
    }
}

function Test-NormalizationExecutionPlanUsesCardinalityAndLegacyFallback {
    [CmdletBinding()]
    param()

    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('normalization-plan-' + [guid]::NewGuid().ToString('N'))
    try {
        [void](New-Item -Path $tempRoot -ItemType Directory -Force)
        [System.IO.File]::WriteAllText((Join-Path $tempRoot 'synthetic-manifest.json'), '{"actualDeviceCount":50000,"contentTemplateCount":5000}', [System.Text.UTF8Encoding]::new($false))
        $safe = Get-NormalizationExecutionPlan -Path $tempRoot -DeliveryMode Dual
        Assert-True ($safe.SafeToExecute -eq $true -and $safe.DeviceLookupMode -eq 'compiled-file-backed') 'Expected the production-representative manifest to select safe compiled file-backed normalization.'
        Assert-True ($safe.EstimatedPrivateMemoryMb -eq 260) 'Expected the estimate to remain calibrated to the measured 50k-device/5k-template Azure run.'

        [System.IO.File]::WriteAllText((Join-Path $tempRoot 'synthetic-manifest.json'), '{"actualDeviceCount":50000,"contentTemplateCount":187500}', [System.Text.UTF8Encoding]::new($false))
        $bounded = Get-NormalizationExecutionPlan -Path $tempRoot
        Assert-True ($bounded.SafeToExecute -eq $true -and $bounded.ContentNormalizationMode -eq 'compiled-bounded-standard-payload') 'Expected unenriched high content cardinality to select compiled bounded normalization.'
        [System.IO.File]::WriteAllText((Join-Path $tempRoot 'Machines_Current.json'), '[]', [System.Text.UTF8Encoding]::new($false))
        $unsafe = Get-NormalizationExecutionPlan -Path $tempRoot
        Assert-True ($unsafe.SafeToExecute -eq $false -and $unsafe.ContentNormalizationMode -eq 'partitioned-required') 'Expected enriched high content cardinality to fail before unsafe retained normalization state is allocated.'

        $repoRoot = Split-Path -Path $PSScriptRoot -Parent
        $legacy = Get-NormalizationExecutionPlan -Path (Join-Path $repoRoot 'exports')
        Assert-True ($legacy.SafeToExecute -eq $true -and $legacy.DeviceProfileCount -gt 0 -and $legacy.ContentTemplateCount -gt 0) 'Expected the checked-in exports dataset to remain supported without procedural metadata.'
    }
    finally { if (Test-Path -LiteralPath $tempRoot) { Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue } }
}

function Test-BenchmarkWorkloadProfilesArePinned {
    [CmdletBinding()]
    param()
    $repoRoot = Split-Path -Path $PSScriptRoot -Parent
    . (Join-Path $PSScriptRoot 'Import-BenchmarkDatasetCatalog.ps1')
    $catalog = @(Import-BenchmarkDatasetCatalog -RepoRoot $repoRoot)
    $expectedProfiles = @('ProductionRepresentative', 'RowVolumeStress', 'ContentCardinalityStress', 'DeviceCardinalityStress', 'HistoryChurnStress', 'UnicodeAndSparsityEdgeCases')
    foreach ($workloadName in $expectedProfiles) {
        $definition = @($catalog | Where-Object workloadProfile -eq $workloadName)
        Assert-True ($definition.Count -eq 1) "Expected exactly one pinned '$workloadName' workload definition."
        foreach ($propertyName in @('workloadProfileVersion', 'modelVersion', 'seed', 'targetDeviceCount', 'targetTotalVulnRows', 'contentTemplateCount', 'expectedEnvelope')) {
            Assert-True ($null -ne $definition[0].PSObject.Properties[$propertyName]) "Expected '$workloadName' to pin '$propertyName'."
        }
    }
}

function Test-CompiledBoundedContentNormalizationExpandedParity {
    [CmdletBinding()]
    param()
    $repoRoot = Split-Path -Path $PSScriptRoot -Parent
    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('compiled-content-parity-' + [guid]::NewGuid().ToString('N'))
    try {
        [void](New-Item -Path $tempRoot -ItemType Directory -Force)
        $first = Get-TestVulnRow -Id 'compiled-parity-1' -CveId 'CVE-2026-7001' -SnapshotDate '2026-07-10' -Version '1.0.0'
        $second = Get-TestVulnRow -Id 'compiled-parity-2' -CveId 'CVE-2026-7002' -SnapshotDate '2026-07-11' -Version '2.0.0'
        $unicodeRegistrySuffix = ([string][char]0x6D4B) + ([string][char]0x8BD5)
        $second.DiskPaths = @(); $second.RegistryPaths = @('HKLM:\Software\Unicode-' + $unicodeRegistrySuffix)
        Write-NdjsonRecordsFile -Path (Get-VulnCurrentPath -BasePath $tempRoot) -Records @($first, $second)
        Publish-VulnContentStoreUnlocked -BasePath $tempRoot
        $baselinePath = Join-Path $tempRoot 'baseline.json.gz'
        $null = ConvertTo-NormalizedData -DataPath $tempRoot -VulnOutputPath (Join-Path $tempRoot 'baseline.json') -PayloadOutputPath $baselinePath -Machines @{} -AdvancedHuntingData @{} -AdvancedHuntingDeviceUsers @{} -AdvancedHuntingInventoryData @{} -NvdCveData @{} -SkipObservedWindowMerge -ConsumeLookupsOnPayloadClose
        [System.IO.File]::WriteAllText((Join-Path $tempRoot 'synthetic-manifest.json'), '{"actualDeviceCount":1,"contentTemplateCount":10001}', [System.Text.UTF8Encoding]::new($false))
        $compiledPath = Join-Path $tempRoot 'compiled.json.gz'
        $compiled = ConvertTo-NormalizedData -DataPath $tempRoot -VulnOutputPath (Join-Path $tempRoot 'compiled.json') -PayloadOutputPath $compiledPath -Machines @{} -AdvancedHuntingData @{} -AdvancedHuntingDeviceUsers @{} -AdvancedHuntingInventoryData @{} -NvdCveData @{} -SkipObservedWindowMerge -ConsumeLookupsOnPayloadClose
        Assert-True ($compiled.VulnCount -eq 2 -and $compiled.LookupsConsumed) 'Expected the compiled bounded path to publish both rows directly to the standard payload.'
        Assert-True ($null -ne $compiled.CompiledMemoryTelemetry) 'Expected the compiled path to report bounded transient-memory telemetry.'
        Assert-True ($compiled.CompiledMemoryTelemetry.peakWorkingSetMb -gt 0 -and $compiled.CompiledMemoryTelemetry.peakPrivateMemoryMb -gt 0 -and $compiled.CompiledMemoryTelemetry.peakGcHeapMb -gt 0) 'Expected compiled telemetry to capture positive pre-trim peaks.'
        Assert-True ($compiled.CompiledMemoryTelemetry.postTrimWorkingSetMb -le $compiled.CompiledMemoryTelemetry.preTrimWorkingSetMb) 'Expected post-trim working set not to exceed the pre-trim reading.'
        Assert-True ($compiled.CompiledMemoryTelemetry.sampleIntervalMilliseconds -eq 0) 'Expected compiled telemetry to record phase-checkpoint sampling without a contending background timer.'
        & node (Join-Path $repoRoot 'tests\helpers\Assert-ExpandedPayloadParity.js') $baselinePath $compiledPath
        Assert-True ($LASTEXITCODE -eq 0) 'Expected compiled and compatibility payloads to have expanded semantic parity.'

        $baselineManifest = [PSCustomObject]@{ GeneratedOnUtc = '2026-07-12T00:00:00Z'; PayloadSha256 = (Get-FileSha256Hex -Path $baselinePath); VulnCount = 2; DeviceCount = 1; CveCount = 2 }
        $compiledManifest = [PSCustomObject]@{ GeneratedOnUtc = '2026-07-12T00:00:00Z'; PayloadSha256 = (Get-FileSha256Hex -Path $compiledPath); VulnCount = 2; DeviceCount = 1; CveCount = 2 }
        $baselineSummary = Get-DashboardPayloadSummaryJson -PayloadPath $baselinePath -PayloadManifest $baselineManifest | ConvertFrom-Json -Depth 30
        $compiledSummary = Get-DashboardPayloadSummaryJson -PayloadPath $compiledPath -PayloadManifest $compiledManifest | ConvertFrom-Json -Depth 30
        Assert-True ((@($baselineSummary.filterCatalog.groups) -join '|') -eq (@($compiledSummary.filterCatalog.groups) -join '|')) 'Expected legacy vuln-first and compiled lookup-first summaries to preserve group catalogs.'
        Assert-True ((@($baselineSummary.filterCatalog.devices | ConvertTo-Json -Compress -Depth 10) -join '') -eq (@($compiledSummary.filterCatalog.devices | ConvertTo-Json -Compress -Depth 10) -join '')) 'Expected both payload property orders to preserve summary device catalogs.'

        $cacheEntry = Publish-NormalizedPayloadCache -BasePath $tempRoot -PayloadPath $compiledPath -VulnCount 2 -DeviceCount 1 -CveCount 2 -SkipObservedWindowMerge
        $cacheHit = Get-NormalizedPayloadCacheEntry -BasePath $tempRoot -SkipObservedWindowMerge
        Assert-True ($null -ne $cacheEntry -and $null -ne $cacheHit) 'Expected a second compiled payload access to resolve through the normalized payload cache.'
        Assert-True ((Get-FileSha256Hex -Path $cacheHit.PayloadPath) -eq (Get-FileSha256Hex -Path $compiledPath)) 'Expected the cache-hit payload to preserve the compiled payload hash.'
        $cacheSummary = Get-DashboardPayloadSummaryJson -PayloadPath $cacheHit.PayloadPath -PayloadManifest $cacheHit.Manifest | ConvertFrom-Json -Depth 30
        Assert-True ($cacheSummary.meta.vulnCount -eq 2 -and @($cacheSummary.filterCatalog.devices).Count -eq 1) 'Expected cache-hit summary generation to preserve row and device counts.'

        $invalidTailPath = Join-Path $tempRoot 'lookup-first-invalid-tail.json.gz'
        Write-GzipTextFile -Path $invalidTailPath -Content '{"lookups":{"groups":["group"],"tags":[],"devices":[{"id":"device","n":"name","g":0,"t":[]}]},"vulns":[INVALID]}'
        $invalidTailSummary = Get-DashboardPayloadSummaryJson -PayloadPath $invalidTailPath | ConvertFrom-Json -Depth 20
        Assert-True (@($invalidTailSummary.filterCatalog.devices).Count -eq 1) 'Expected lookup-first summary generation to stop before tokenizing vulnerability rows.'
    }
    finally { if (Test-Path -LiteralPath $tempRoot) { Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue } }
}

function Test-SyntheticUploadManifestSelectsRawReplayArtifact {
    [CmdletBinding()]
    param()
    $repoRoot = Split-Path -Path $PSScriptRoot -Parent
    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('upload-manifest-' + [guid]::NewGuid().ToString('N'))
    try {
        [void](New-Item -Path $tempRoot -ItemType Directory -Force)
        foreach ($name in @('VulnExport_100_2026-07-12.json.gz', 'Machines_Current.json.gz', 'AdvancedHunting_Current.json.gz', 'VulnCurrentRefs.json.gz')) {
            [System.IO.File]::WriteAllText((Join-Path $tempRoot $name), $name, [System.Text.UTF8Encoding]::new($false))
        }
        $manifestPath = Join-Path $tempRoot 'upload.json'
        & (Join-Path $repoRoot 'tests\New-SyntheticUploadManifest.ps1') -DatasetPath $tempRoot -OutputPath $manifestPath -Mode RawReplay | Out-Null
        $manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json -Depth 20
        $names = @($manifest.artifacts | ForEach-Object name)
        Assert-True ('VulnExport_100_2026-07-12.json.gz' -in $names) 'Expected raw replay upload manifest to include dated vulnerability exports.'
        Assert-True ('Machines_Current.json.gz' -in $names) 'Expected raw replay upload manifest to include the machine snapshot.'
        Assert-True ('VulnCurrentRefs.json.gz' -notin $names) 'Expected raw replay upload manifest to exclude precomputed content refs.'
    }
    finally { if (Test-Path -LiteralPath $tempRoot) { Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue } }
}

function Test-LargeDatasetValidationSemanticModeForcesFullReplay {
    [CmdletBinding()]
    param()

    $repoRoot = Split-Path -Path $PSScriptRoot -Parent
    $validationScriptPath = Join-Path $repoRoot 'tests\Invoke-LargeDatasetValidation.ps1'
    Assert-True ((Test-Path -LiteralPath $validationScriptPath -PathType Leaf)) "Expected large-dataset validation script at '$validationScriptPath'."

    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('large-dataset-forcefull-' + [guid]::NewGuid().ToString('N'))
    try {
        [void](New-Item -Path $tempRoot -ItemType Directory -Force)

        $syntheticOutputPath = Join-Path $tempRoot 'synthetic'
        $dashboardOutputPath = Join-Path $tempRoot 'dashboard.html'
        $validationOutputPath = Join-Path $tempRoot 'dashboard-audit.json'
        $diagnosticPhaseLogPath = Join-Path $tempRoot 'phase-log.tsv'

        & $validationScriptPath `
            -SourcePath (Join-Path $repoRoot 'exports') `
            -SyntheticOutputPath $syntheticOutputPath `
            -TargetDeviceCount 50 `
            -TargetTotalVulnRows 5000 `
            -MinimumAvailableMemoryGB 4 `
            -Validate `
            -ValidationMode semantic `
            -ForceFullValidation `
            -DashboardOutputPath $dashboardOutputPath `
            -ValidationOutputPath $validationOutputPath `
            -DiagnosticPhaseLogPath $diagnosticPhaseLogPath | Out-Null

        $reportPath = Join-Path $syntheticOutputPath 'stress-validation-report.json'
        Assert-True ((Test-Path -LiteralPath $reportPath -PathType Leaf)) 'Expected large-dataset validation to emit a stress-validation report.'
        Assert-True ((Test-Path -LiteralPath $validationOutputPath -PathType Leaf)) 'Expected large-dataset validation to emit a semantic audit.'

        $report = Get-Content -LiteralPath $reportPath -Raw | ConvertFrom-Json -Depth 20
        $audit = Get-Content -LiteralPath $validationOutputPath -Raw | ConvertFrom-Json -Depth 100

        Assert-True ($report.validation.validationMode -eq 'semantic') 'Expected the stress-validation report to record semantic validation mode.'
        Assert-True ($report.validation.forceFullValidation -eq $true) 'Expected the stress-validation report to record forced full semantic replay.'
        Assert-True ($report.validation.auditSummary.attestationUsed -eq $false) 'Expected semantic sign-off to avoid attestation reuse.'
        Assert-True ([string]$audit.AuditMode -notlike '*attested*') 'Expected semantic sign-off audit mode to reflect a fresh replay rather than attested validation.'
    }
    finally {
        if (Test-Path -LiteralPath $tempRoot) {
            Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

function Test-GenerateSyntheticLargeExportsUsesStablePlannerOrdering {
    [CmdletBinding()]
    param()

    $repoRoot = Split-Path -Path $PSScriptRoot -Parent
    $generatorScriptPath = Join-Path $repoRoot 'tests\Generate-SyntheticLargeExports.ps1'
    Assert-True ((Test-Path -LiteralPath $generatorScriptPath -PathType Leaf)) "Expected synthetic large-export generator script at '$generatorScriptPath'."

    $pwshCommand = Get-Command -Name 'pwsh' -ErrorAction Stop
    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('synthetic-ordering-' + [guid]::NewGuid().ToString('N'))

    try {
        [void](New-Item -Path $tempRoot -ItemType Directory -Force)

        $runDirectories = @(
            (Join-Path $tempRoot 'run-a')
            (Join-Path $tempRoot 'run-b')
        )

        foreach ($runDirectory in $runDirectories) {
            # The generator atomically replaces OutputPath. Redirecting live
            # process logs inside that directory prevents the Windows rename.
            $runName = Split-Path -Path $runDirectory -Leaf
            $stdoutPath = Join-Path $tempRoot ($runName + '.stdout.log')
            $stderrPath = Join-Path $tempRoot ($runName + '.stderr.log')

            $argumentList = @(
                '-NoProfile'
                '-File'
                $generatorScriptPath
                '-SourcePath'
                (Join-Path $repoRoot 'exports')
                '-OutputPath'
                $runDirectory
                '-TargetDeviceCount'
                '12'
                '-TargetTotalVulnRows'
                '300'
                '-MinimumAvailableMemoryGB'
                '1'
                '-Seed'
                '20260322'
            )

            $process = Start-Process -FilePath $pwshCommand.Source -ArgumentList $argumentList -WorkingDirectory $repoRoot -RedirectStandardOutput $stdoutPath -RedirectStandardError $stderrPath -PassThru
            $process.WaitForExit()

            $stdoutContent = if (Test-Path -LiteralPath $stdoutPath -PathType Leaf) { Get-Content -LiteralPath $stdoutPath -Raw } else { '' }
            $stderrContent = if (Test-Path -LiteralPath $stderrPath -PathType Leaf) { Get-Content -LiteralPath $stderrPath -Raw } else { '' }
            $processOutput = @($stdoutContent, $stderrContent) -join [Environment]::NewLine

            Assert-True ($process.ExitCode -eq 0) ("Expected deterministic generator smoke run to succeed. Output:`n{0}" -f $processOutput.Trim())
        }

        $manifestPropertyNames = @(
            'preset'
            'seed'
            'targetDeviceCount'
            'targetTotalVulnRows'
            'targetCurrentRows'
            'targetHistoryRows'
            'actualDeviceCount'
            'includeRawRows'
            'actualCurrentRows'
            'actualHistoryRows'
            'actualTotalVulnRows'
            'scaleFactor'
            'sourceCurrentRows'
            'sourceHistoryRows'
            'sourceRowProfiles'
            'historyPeriods'
            'advancedHuntingRows'
            'contentTemplateCount'
            'uniqueCveIdCount'
            'normalizedCveLookupCount'
        )

        $normalizedManifestJson = foreach ($runDirectory in $runDirectories) {
            $manifest = Get-Content -LiteralPath (Join-Path $runDirectory 'synthetic-manifest.json') -Raw | ConvertFrom-Json -Depth 20
            $normalizedManifest = [ordered]@{}
            foreach ($propertyName in $manifestPropertyNames) {
                $property = $manifest.PSObject.Properties[$propertyName]
                $normalizedManifest[$propertyName] = if ($null -ne $property) { $property.Value } else { $null }
            }

            $normalizedManifest | ConvertTo-Json -Depth 20 -Compress
        }

        Assert-True ($normalizedManifestJson[0] -eq $normalizedManifestJson[1]) 'Expected synthetic manifests to match across fresh PowerShell processes when using the same seed.'

        $gzipPaths = @(
            @{ RelativePath = 'Machines_Current.json.gz'; PathResolver = { param($basePath) (Get-MachineCurrentPath -BasePath $basePath) } }
            @{ RelativePath = 'VulnCurrentRefs.json.gz'; PathResolver = { param($basePath) (Get-VulnCurrentRefsPath -BasePath $basePath) } }
            @{ RelativePath = 'AdvancedHunting_Current.json.gz'; PathResolver = { param($basePath) (Get-AdvancedHuntingCurrentPath -BasePath $basePath) } }
            @{ RelativePath = 'VulnContentDictionary.json.gz'; PathResolver = { param($basePath) (Get-VulnContentDictionaryPath -BasePath $basePath) } }
        )

        foreach ($gzipPathInfo in $gzipPaths) {
            $firstPath = & $gzipPathInfo.PathResolver $runDirectories[0]
            $secondPath = & $gzipPathInfo.PathResolver $runDirectories[1]
            Assert-True ((Read-GzipTextFile -Path $firstPath) -eq (Read-GzipTextFile -Path $secondPath)) ("Expected {0} to be stable across fresh PowerShell processes." -f $gzipPathInfo.RelativePath)
        }

        $historyRefNamesA = @((Get-ChildItem -LiteralPath $runDirectories[0] -Filter 'VulnHistoryRefs_*.json.gz' -File | Sort-Object Name).Name)
        $historyRefNamesB = @((Get-ChildItem -LiteralPath $runDirectories[1] -Filter 'VulnHistoryRefs_*.json.gz' -File | Sort-Object Name).Name)

        Assert-True (($historyRefNamesA.Count -eq $historyRefNamesB.Count) -and ((@($historyRefNamesA) -join '|') -eq (@($historyRefNamesB) -join '|'))) 'Expected synthetic history ref file sets to match across fresh PowerShell processes.'

        foreach ($historyRefName in $historyRefNamesA) {
            $firstPath = Join-Path $runDirectories[0] $historyRefName
            $secondPath = Join-Path $runDirectories[1] $historyRefName
            Assert-True ((Read-GzipTextFile -Path $firstPath) -eq (Read-GzipTextFile -Path $secondPath)) ("Expected history ref file '{0}' to be stable across fresh PowerShell processes." -f $historyRefName)
        }
    }
    finally {
        if (Test-Path -LiteralPath $tempRoot) {
            Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

function Test-HotPhaseReviewArtifactsModeSmoke {
    [CmdletBinding()]
    param()

    $repoRoot = Split-Path -Path $PSScriptRoot -Parent
    $reviewScriptPath = Join-Path $repoRoot 'tests\Invoke-HotPhaseReview.ps1'
    Assert-True ((Test-Path -LiteralPath $reviewScriptPath -PathType Leaf)) "Expected hot-phase review script at '$reviewScriptPath'."

    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('hot-phase-review-smoke-' + [guid]::NewGuid().ToString('N'))
    try {
        [void](New-Item -Path $tempRoot -ItemType Directory -Force)
        $outputRoot = Join-Path $tempRoot 'review'
        $stdoutPath = Join-Path $tempRoot 'stdout.log'
        $stderrPath = Join-Path $tempRoot 'stderr.log'

        if (-not $IsWindows) {
            $pwshCommand = Get-Command -Name 'pwsh' -ErrorAction Stop
            $argumentList = @(
                '-NoProfile'
                '-File'
                $reviewScriptPath
                '-DirectoryPath'
                (Join-Path $repoRoot 'exports')
                '-OutputRoot'
                $outputRoot
                '-ValidationMode'
                'artifacts'
                '-PollIntervalSeconds'
                '1'
            )

            $process = Start-Process -FilePath $pwshCommand.Source -ArgumentList $argumentList -WorkingDirectory $repoRoot -RedirectStandardOutput $stdoutPath -RedirectStandardError $stderrPath -PassThru
            $process.WaitForExit()

            $stdoutContent = if (Test-Path -LiteralPath $stdoutPath -PathType Leaf) { Get-Content -LiteralPath $stdoutPath -Raw } else { '' }
            $stderrContent = if (Test-Path -LiteralPath $stderrPath -PathType Leaf) { Get-Content -LiteralPath $stderrPath -Raw } else { '' }
            $processOutput = @($stdoutContent, $stderrContent) -join [Environment]::NewLine

            Assert-True ($process.ExitCode -ne 0) 'Expected Invoke-HotPhaseReview regression smoke to fail fast on non-Windows platforms.'
            Assert-True (-not (Test-Path -LiteralPath (Join-Path $outputRoot 'hot-phase-review.json') -PathType Leaf)) 'Expected non-Windows hot-phase review execution to avoid writing a review report.'
            Assert-True ($processOutput.Contains('currently supports Windows only')) 'Expected non-Windows hot-phase review execution to explain the Windows-only platform guard.'
            return
        }

        & $reviewScriptPath `
            -DirectoryPath (Join-Path $repoRoot 'exports') `
            -OutputRoot $outputRoot `
            -ValidationMode artifacts `
            -PollIntervalSeconds 1 | Out-Null

        $reportPath = Join-Path $outputRoot 'hot-phase-review.json'
        Assert-True ((Test-Path -LiteralPath $reportPath -PathType Leaf)) 'Expected hot-phase review smoke to emit a report.'

        $report = Get-Content -LiteralPath $reportPath -Raw | ConvertFrom-Json -Depth 20
        Assert-True ($report.status -eq 'success') 'Expected hot-phase review smoke to complete successfully.'
        Assert-True ($report.review.validationMode -eq 'artifacts') 'Expected hot-phase review smoke to record artifact validation mode.'
        Assert-True ($report.artifactValidationSummary.passed -eq $true) 'Expected artifact-mode hot-phase review smoke to validate hosted and self-contained outputs.'
        Assert-True (@($report.generatorPhases).Count -gt 0) 'Expected hot-phase review smoke to capture generator phase timings.'
        Assert-True ((Test-Path -LiteralPath $report.artifacts.hostedDashboardPath -PathType Leaf)) 'Expected hot-phase review smoke to emit the hosted dashboard artifact.'
    }
    finally {
        if (Test-Path -LiteralPath $tempRoot) {
            Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

function Test-GetDashboardTemplateContentAcceptsExplicitTemplatesPathWithEmptyDefaultRoot {
    [CmdletBinding()]
    param()

    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('dashboard-template-path-' + [guid]::NewGuid().ToString('N'))

    try {
        $templatesPath = Join-Path $tempRoot 'templates'
        $moduleDirectoryPath = Join-Path $templatesPath 'dashboard'
        [void](New-Item -Path $templatesPath -ItemType Directory -Force)
        [void](New-Item -Path $moduleDirectoryPath -ItemType Directory -Force)
        [System.IO.File]::WriteAllText((Join-Path $templatesPath 'dashboard.html'), '<html></html>', [System.Text.UTF8Encoding]::new($false))
        [System.IO.File]::WriteAllText((Join-Path $templatesPath 'dashboard.css'), 'body { }', [System.Text.UTF8Encoding]::new($false))
        [System.IO.File]::WriteAllText((Join-Path $moduleDirectoryPath '00-core.js'), 'window.__templatePathRegression = true;', [System.Text.UTF8Encoding]::new($false))
        [System.IO.File]::WriteAllText((Join-Path $templatesPath 'dashboard.modules.json'), (@{ version = 1; modules = @('dashboard/00-core.js') } | ConvertTo-Json -Compress), [System.Text.UTF8Encoding]::new($false))

        $templates = Get-DashboardTemplateContent -TemplatesPath $templatesPath -DefaultRootPath ''

        Assert-True ($templates.Html -eq '<html></html>') 'Expected template loading to honor the explicit templates path when DefaultRootPath is blank.'
        Assert-True ($templates.Css -eq 'body { }') 'Expected CSS template loading to honor the explicit templates path when DefaultRootPath is blank.'
        Assert-True ($templates.Js -like '*window.__templatePathRegression = true;*') 'Expected template loading to bundle JavaScript modules from the explicit templates path.'
        Assert-True (($templates.JsModules.Keys -contains 'dashboard/00-core.js')) 'Expected template module map to preserve the declared dashboard module path.'
    }
    finally {
        if (Test-Path -LiteralPath $tempRoot) {
            Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

function Invoke-SharedHelperRegressionTest {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,

        [Parameter(Mandatory = $true)]
        [string]$SuccessMessage
    )

    $testCommand = Get-Command -Name $Name -CommandType Function -ErrorAction Stop
    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()

    Write-Output ("START {0}" -f $Name)
    & $testCommand
    $stopwatch.Stop()

    Write-Output ("  {0} ({1} ms)" -f $SuccessMessage, $stopwatch.ElapsedMilliseconds)
}

Write-Output 'Running shared-helper regression checks...'
$sharedHelperRegressionTests = @(
    @{ Name = 'Test-ArtifactManifestRejectsOutputInsideSourceRoot'; SuccessMessage = 'Artifact manifest output-root guard checks passed.' }
    @{ Name = 'Test-ArtifactManifestRejectsSourceRootOverlap'; SuccessMessage = 'Artifact manifest overlap guard checks passed.' }
    @{ Name = 'Test-ArtifactManifestRejectsSourceFileOutsideSourceRoot'; SuccessMessage = 'Artifact manifest source-root boundary checks passed.' }
    @{ Name = 'Test-ArtifactManifestRejectsCrossArtifactSourceConflict'; SuccessMessage = 'Artifact manifest cross-artifact conflict checks passed.' }
    @{ Name = 'Test-ArtifactManifestUsesContentFingerprint'; SuccessMessage = 'Artifact manifest fingerprint freshness checks passed.' }
    @{ Name = 'Test-ArtifactManifestRejectsGeneratedOutputWithoutFingerprint'; SuccessMessage = 'Artifact manifest fingerprint metadata checks passed.' }
    @{ Name = 'Test-CanonicalLayoutHelper'; SuccessMessage = 'Canonical layout helper checks passed.' }
    @{ Name = 'Test-FileSetFingerprintIgnoresTimestampChange'; SuccessMessage = 'File-set fingerprint stability checks passed.' }
    @{ Name = 'Test-NormalizedPayloadCacheRejectsManifestHashMismatch'; SuccessMessage = 'Normalized payload cache integrity checks passed.' }
    @{ Name = 'Test-NormalizedPayloadManifestSourceSummary'; SuccessMessage = 'Normalized payload source metadata checks passed.' }
    @{ Name = 'Test-SaveJSLibraryFileRefreshesEmptyCache'; SuccessMessage = 'JavaScript library cache refresh checks passed.' }
    @{ Name = 'Test-VulnContentStoreExistenceNeedsRef'; SuccessMessage = 'Content-store existence checks passed.' }
    @{ Name = 'Test-LocalExportArtifactCleanup'; SuccessMessage = 'Local export artifact cleanup checks passed.' }
    @{ Name = 'Test-InitializeMachineHistoryStoreBackfillsCurrentRecordMetadata'; SuccessMessage = 'Machine store initialization checks passed.' }
    @{ Name = 'Test-InitializeMachineHistoryStoreSupportsStateHashOnlyCurrentMap'; SuccessMessage = 'Machine store stateHash-only initialization checks passed.' }
    @{ Name = 'Test-MdeMachineRefreshPublishPlanSupportsStateHashOnlyCurrentMap'; SuccessMessage = 'Machine refresh plan stateHash-only checks passed.' }
    @{ Name = 'Test-MachineHistoryRemovePathsAllowsEmptyPublishedHistorySet'; SuccessMessage = 'Machine history cleanup empty-set checks passed.' }
    @{ Name = 'Test-RestoreStoreTransactionRejectsInvalidJournalShape'; SuccessMessage = 'Store transaction journal validation checks passed.' }
    @{ Name = 'Test-InitializeMachineHistoryStoreRejectsExpiredLegacyMigration'; SuccessMessage = 'Machine legacy migration cutoff checks passed.' }
    @{ Name = 'Test-InitializeAdvancedHuntingStoreRejectsExpiredLegacyMigration'; SuccessMessage = 'Advanced Hunting legacy migration cutoff checks passed.' }
    @{ Name = 'Test-PublishVulnerabilityHistoryStoreRejectsExpiredImplicitLegacyMigration'; SuccessMessage = 'Implicit vulnerability legacy migration cutoff checks passed.' }
    @{ Name = 'Test-PublishVulnerabilityHistoryStoreAllowsExplicitDownloadedLegacyFilesAfterCutoff'; SuccessMessage = 'Explicit vulnerability snapshot import cutoff checks passed.' }
    @{ Name = 'Test-BulkSnapshotImportSmoke'; SuccessMessage = 'Bulk snapshot import smoke checks passed.' }
    @{ Name = 'Test-BulkSnapshotImportSingleSnapshot'; SuccessMessage = 'Single-snapshot vulnerability import checks passed.' }
    @{ Name = 'Test-BulkSnapshotImportMultipartSnapshot'; SuccessMessage = 'Multipart vulnerability import checks passed.' }
    @{ Name = 'Test-BulkSnapshotImportMergesIntoExistingCanonicalStore'; SuccessMessage = 'Existing-store vulnerability merge checks passed.' }
    @{ Name = 'Test-HttpRetryDelayHelperBehavior'; SuccessMessage = 'Retry delay helper checks passed.' }
    @{ Name = 'Test-WebRequestWithRetryTransientTransportBehavior'; SuccessMessage = 'Web request transient transport retry checks passed.' }
    @{ Name = 'Test-BulkVulnerabilitySnapshotDownloadMultipartNameUniqueness'; SuccessMessage = 'Multipart vulnerability download naming checks passed.' }
    @{ Name = 'Test-BulkVulnerabilitySnapshotDownloadStagingBehavior'; SuccessMessage = 'Multipart vulnerability download staging checks passed.' }
    @{ Name = 'Test-BulkVulnerabilitySnapshotDownloadRetriesEmptyBlob'; SuccessMessage = 'Multipart vulnerability empty-blob retry checks passed.' }
    @{ Name = 'Test-BulkVulnerabilitySnapshotDownloadEmptyBlobExhaustionBehavior'; SuccessMessage = 'Multipart vulnerability empty-blob retry exhaustion checks passed.' }
    @{ Name = 'Test-BulkVulnerabilitySnapshotDownloadMoveFailureCleanupBehavior'; SuccessMessage = 'Multipart vulnerability move-failure cleanup checks passed.' }
    @{ Name = 'Test-BulkVulnerabilitySnapshotDownloadCleanupBehavior'; SuccessMessage = 'Multipart vulnerability failed-download cleanup checks passed.' }
    @{ Name = 'Test-GetMdeAccessTokenReportsMissingConfigurationDiagnostic'; SuccessMessage = 'MDE token-source diagnostics checks passed.' }
    @{ Name = 'Test-GetMdeAccessTokenReportsAuthenticationContext'; SuccessMessage = 'MDE authentication context diagnostics checks passed.' }
    @{ Name = 'Test-NewMdeAccessTokenContextRejectsMissingExpirationMetadata'; SuccessMessage = 'MDE token expiration metadata checks passed.' }
    @{ Name = 'Test-MdeRequestHeaderRefreshesNearExpiryTokenContext'; SuccessMessage = 'MDE proactive token refresh checks passed.' }
    @{ Name = 'Test-MdeRequestHeaderKeepsExplicitAccessTokenContextStable'; SuccessMessage = 'Explicit MDE access token compatibility checks passed.' }
    @{ Name = 'Test-VulnCurrentFileRejectsDuplicateId'; SuccessMessage = 'Current-file duplicate Id checks passed.' }
    @{ Name = 'Test-RepairVulnHistoryLayoutSkipsCanonicalQuarterlyStore'; SuccessMessage = 'Canonical quarterly history repair skip checks passed.' }
    @{ Name = 'Test-VulnStoreRequiresCanonicalRepairDetectsMalformedQuarterlyHistory'; SuccessMessage = 'Canonical quarterly history gate checks passed.' }
    @{ Name = 'Test-RepairVulnHistoryLayoutRebuildsCanonicalQuarterlyRowSidecar'; SuccessMessage = 'Canonical quarterly rows-sidecar repair checks passed.' }
    @{ Name = 'Test-RepairVulnHistoryLayoutRepairsLegacyYearlyStore'; SuccessMessage = 'Legacy yearly history repair checks passed.' }
    @{ Name = 'Test-VulnHistoryFileValidatesQuarterlyHistoryDocument'; SuccessMessage = 'Quarterly history validation checks passed.' }
    @{ Name = 'Test-VulnCanonicalSignatureStability'; SuccessMessage = 'Canonical vulnerability signature checks passed.' }
    @{ Name = 'Test-MergeVulnObservedWindowRows'; SuccessMessage = 'Vulnerability observation merge checks passed.' }
    @{ Name = 'Test-ReadNormalizedVulnStoreRow'; SuccessMessage = 'Normalized vulnerability store reader checks passed.' }
    @{ Name = 'Test-ResolveNormalizedLookupIndexListHandlesScalarAndCollectionValues'; SuccessMessage = 'Lookup index list normalization checks passed.' }
    @{ Name = 'Test-ResolveNormalizedInventoryLookupSkipsEmptyInventoryData'; SuccessMessage = 'Inventory lookup normalization checks passed.' }
    @{ Name = 'Test-AddNormalizedCveUsesStableSeverityIndexLookup'; SuccessMessage = 'CVE severity lookup checks passed.' }
    @{ Name = 'Test-GetNormalizedRecordLookupHandlesScalarPathInputs'; SuccessMessage = 'Scalar path lookup checks passed.' }
    @{ Name = 'Test-InvokeNormalizationProgressCallbackUsesCountAndHeartbeat'; SuccessMessage = 'Normalization progress callback cadence checks passed.' }
    @{ Name = 'Test-ConvertToNormalizedDataReportsContentStoreNormalizationPhase'; SuccessMessage = 'Content-store normalization phase callback checks passed.' }
    @{ Name = 'Test-ConvertToNormalizedDataUsesStableDeviceIdFallback'; SuccessMessage = 'Stable device fallback identity checks passed.' }
    @{ Name = 'Test-ConvertToNormalizedDataWritesExpectedRowCount'; SuccessMessage = 'Normalized vuln row-count checks passed.' }
    @{ Name = 'Test-ConvertToNormalizedDataWritesDirectPayload'; SuccessMessage = 'Direct payload normalization checks passed.' }
    @{ Name = 'Test-ConvertToNormalizedDataPreservesOptionalNvdFallback'; SuccessMessage = 'Optional NVD fallback normalization checks passed.' }
    @{ Name = 'Test-ConvertToNormalizedDataCanConsumeLookupsOnPayloadClose'; SuccessMessage = 'Consuming payload-close lookup checks passed.' }
    @{ Name = 'Test-ConvertToNormalizedDataContentStorePathDoesNotUseLegacyDictionaryReader'; SuccessMessage = 'Content-store streaming normalization checks passed.' }
    @{ Name = 'Test-ConvertToNormalizedDataSupportsDirectMergeDeviceLookup'; SuccessMessage = 'Direct-merge device lookup success-path checks passed.' }
    @{ Name = 'Test-ConvertToNormalizedDataDirectMergeDeviceLookupRejectsOutOfOrderMachineStream'; SuccessMessage = 'Direct-merge device lookup exact-order guard checks passed.' }
    @{ Name = 'Test-ConvertToNormalizedDataDirectMergeDeviceLookupRejectsBlankDeviceId'; SuccessMessage = 'Direct-merge device lookup blank-device guard checks passed.' }
    @{ Name = 'Test-InvokeContentStoreNormalizationReleasesTransientContextBeforePayloadClose'; SuccessMessage = 'Content-store transient context-release and hosted-memory diagnostics checks passed.' }
    @{ Name = 'Test-ConvertToNormalizedDataDeduplicatesRepeatedCveLookup'; SuccessMessage = 'Repeated CVE lookup deduplication checks passed.' }
    @{ Name = 'Test-ConvertToNormalizedDataReportsZeroOnboardedContentStoreDiagnostic'; SuccessMessage = 'Zero-onboarded content-store diagnostics checks passed.' }
    @{ Name = 'Test-ConvertToNormalizedDataIncludesAdvancedHuntingDeviceUserMap'; SuccessMessage = 'Advanced Hunting device-user normalization checks passed.' }
    @{ Name = 'Test-WriteCombinedPayloadGzipPreservesColumnPayload'; SuccessMessage = 'Combined payload writer column-path checks passed.' }
    @{ Name = 'Test-NormalizedVulnColumnCacheRebuildsPayloadWithFreshLookups'; SuccessMessage = 'Normalized vuln column cache reuse checks passed.' }
    @{ Name = 'Test-NormalizedVulnColumnCacheRefreshesInventoryColumn'; SuccessMessage = 'Inventory-backed normalized vuln column cache reuse checks passed.' }
    @{ Name = 'Test-WriteBase64FileContentMatchesReferenceOutput'; SuccessMessage = 'Streamed base64 writer checks passed.' }
    @{ Name = 'Test-BenchmarkSeriesSummaryHandlesAzureOnlyRunMode'; SuccessMessage = 'Benchmark series mode checks passed.' }
    @{ Name = 'Test-BenchmarkSeriesSummaryHandlesCombinedRunMode'; SuccessMessage = 'Benchmark series mode checks passed.' }
    @{ Name = 'Test-BenchmarkSeriesSummaryHandlesLocalOnlyRunMode'; SuccessMessage = 'Benchmark series mode checks passed.' }
    @{ Name = 'Test-BenchmarkIncludesLocalRunHandlesLegacyInferenceShape'; SuccessMessage = 'Benchmark series mode checks passed.' }
    @{ Name = 'Test-BenchmarkModeScenarioKeyHandlesLegacyModeMapping'; SuccessMessage = 'Benchmark series mode checks passed.' }
    @{ Name = 'Test-WriteProgressMarkerIncludesEtaWhenTotalCountKnown'; SuccessMessage = 'Progress marker ETA checks passed.' }
    @{ Name = 'Test-WriteCombinedPayloadGzipCanConsumeColumnLookupData'; SuccessMessage = 'Payload lookup consumption checks passed.' }
    @{ Name = 'Test-GetDashboardEmbeddedPayloadInspectionStreamsSelfContainedPayload'; SuccessMessage = 'Embedded payload inspection checks passed.' }
    @{ Name = 'Test-VulnContentStoreRoundTrip'; SuccessMessage = 'Vulnerability content store round-trip checks passed.' }
    @{ Name = 'Test-ProceduralSyntheticDatasetGeneration'; SuccessMessage = 'Procedural synthetic generation and immutable overlay checks passed.' }
    @{ Name = 'Test-MeasureStressRunWritesProgressAndFinalReport'; SuccessMessage = 'Measure-StressRun report persistence checks passed.' }
    @{ Name = 'Test-GenerateSyntheticLargeExportsUsesStablePlannerOrdering'; SuccessMessage = 'Synthetic planner ordering checks passed.' }
    @{ Name = 'Test-LargeDatasetValidationSemanticModeForcesFullReplay'; SuccessMessage = 'Large-dataset semantic sign-off checks passed.' }
    @{ Name = 'Test-HotPhaseReviewArtifactsModeSmoke'; SuccessMessage = 'Hot-phase review wrapper smoke checks passed.' }
    @{ Name = 'Test-GetDashboardTemplateContentAcceptsExplicitTemplatesPathWithEmptyDefaultRoot'; SuccessMessage = 'Dashboard template explicit-path checks passed.' }
    @{ Name = 'Test-ValidationHelperPayloadCanonicalization'; SuccessMessage = 'Validation helper payload-format checks passed.' }
    @{ Name = 'Test-ValidationHelperSourceCanonicalization'; SuccessMessage = 'Validation helper source canonicalization checks passed.' }
    @{ Name = 'Test-ValidationHelperStandaloneImport'; SuccessMessage = 'Validation helper standalone import checks passed.' }
    @{ Name = 'Test-DashboardValidationFailureExtendedEnrichmentGate'; SuccessMessage = 'Validation helper failure-gate checks passed.' }
    @{ Name = 'Test-StreamingDashboardAuditDetectsSourceMismatchDespitePayloadParity'; SuccessMessage = 'Streaming dashboard source-parity checks passed.' }
    @{ Name = 'Test-StreamingDashboardAuditReusesCachedPayloadSignatureSet'; SuccessMessage = 'Streaming dashboard payload-signature reuse checks passed.' }
    @{ Name = 'Test-DashboardAuditBootstrapsSyntheticLargePayloadCacheWithNormalizationLookup'; SuccessMessage = 'Dashboard synthetic large-dataset bootstrap checks passed.' }
    @{ Name = 'Test-DashboardValidationUsesStableFallbackDeviceProfile'; SuccessMessage = 'Dashboard validation fallback device profile checks passed.' }
    @{ Name = 'Test-DashboardOpenStateAuditUsesPatchEvidenceAndInactivityCutoff'; SuccessMessage = 'Dashboard open-state audit checks passed.' }
    @{ Name = 'Test-DashboardValidationPreservesNoneSeverityData'; SuccessMessage = 'Dashboard none-severity validation checks passed.' }
    @{ Name = 'Test-DashboardSplitAssetsGenerationAndValidation'; SuccessMessage = 'Dashboard split-assets generation and validation checks passed.' }
    @{ Name = 'Test-DashboardValidateOnlyFailsWhenHostedPayloadMissing'; SuccessMessage = 'Hosted dashboard missing-payload negative checks passed.' }
    @{ Name = 'Test-PackageOnlyRejectsMismatchedNormalizedPayloadManifest'; SuccessMessage = 'Package-only manifest mismatch negative checks passed.' }
    @{ Name = 'Test-DashboardDualPackagingGenerationAndValidation'; SuccessMessage = 'Dashboard dual packaging generation and validation checks passed.' }
    @{ Name = 'Test-AdvancedHuntingBundleMatchesDedicatedReaderData'; SuccessMessage = 'Advanced Hunting bundle reader checks passed.' }
    @{ Name = 'Test-AdvancedHuntingBundleStringArrayFiltersSparseInputs'; SuccessMessage = 'Advanced Hunting bundle sparse string-array checks passed.' }
    @{ Name = 'Test-ReadNormalizationMachineLookupMatchesCompressedMachineLookup'; SuccessMessage = 'Machine tuple reader checks passed.' }
    @{ Name = 'Test-ReadFileBackedNormalizationMachineLookupMatchesCompressedMachineLookup'; SuccessMessage = 'File-backed machine tuple reader checks passed.' }
    @{ Name = 'Test-ReadBucketedFileBackedNormalizationMachineLookupMatchesCompressedMachineLookup'; SuccessMessage = 'Bucketed file-backed machine tuple reader checks passed.' }
    @{ Name = 'Test-NormalizationMachineTupleExtendsLegacyTuple'; SuccessMessage = 'Machine tuple extension checks passed.' }
    @{ Name = 'Test-LegacyMachineTupleFallbackPreservesProjectedRowMetadata'; SuccessMessage = 'Legacy tuple fallback checks passed.' }
    @{ Name = 'Test-SourceCveEnrichmentReadsExploitAvailabilityFromObjectRecord'; SuccessMessage = 'Source enrichment exploit-availability checks passed.' }
    @{ Name = 'Test-VulnPropertyHelpersSupportSupportedRowShapes'; SuccessMessage = 'Vulnerability property helper shape checks passed.' }
    @{ Name = 'Test-VulnObservedWindowCacheRoundTrip'; SuccessMessage = 'Observed-window cache round-trip checks passed.' }
    @{ Name = 'Test-FunctionAppWriteOutputNoEnumeratePreservesJObject'; SuccessMessage = 'Function App Write-Output -NoEnumerate checks passed.' }
    @{ Name = 'Test-FunctionExecutionStatusSummaryIncludesNormalizationProgressInfo'; SuccessMessage = 'Function execution status summary metadata checks passed.' }
    @{ Name = 'Test-BenchmarkEvidenceEnvelopeWritesTransactionally'; SuccessMessage = 'Benchmark evidence schema and transactional publication checks passed.' }
    @{ Name = 'Test-ProgressStallAssessmentDistinguishesSlowAndStalledWork'; SuccessMessage = 'Progress stall warning/failure checks passed.' }
    @{ Name = 'Test-FullGarbageCollectionRequestsLargeObjectHeapCompaction'; SuccessMessage = 'Large-object heap compaction checks passed.' }
    @{ Name = 'Test-AzureValidationHarnessRequiresExecutionGuardAndRestoration'; SuccessMessage = 'Azure validation guard and restoration checks passed.' }
    @{ Name = 'Test-AzureDashboardCandidateEvidenceRejectsIncompletePublication'; SuccessMessage = 'Azure candidate artifact evidence checks passed.' }
    @{ Name = 'Test-NormalizationExecutionPlanUsesCardinalityAndLegacyFallback'; SuccessMessage = 'Cardinality-aware normalization plan and legacy fallback checks passed.' }
    @{ Name = 'Test-BenchmarkWorkloadProfilesArePinned'; SuccessMessage = 'Versioned benchmark workload profile checks passed.' }
    @{ Name = 'Test-CompiledBoundedContentNormalizationExpandedParity'; SuccessMessage = 'Compiled bounded content normalization expanded-parity checks passed.' }
    @{ Name = 'Test-SyntheticUploadManifestSelectsRawReplayArtifact'; SuccessMessage = 'Synthetic raw replay upload-manifest checks passed.' }
)

function Get-SharedHelperRegressionCategory {
    param([Parameter(Mandatory = $true)][string]$Name)

    if ($Name -match 'ArtifactManifest|CanonicalLayout|FileSetFingerprint') { return 'Artifact' }
    if ($Name -match 'Synthetic|Benchmark|StressRun|ProgressMarker') { return 'Benchmark' }
    if ($Name -match 'Validation|Audit|Dashboard|Template|PackageOnly|HotPhase') { return 'Validation' }
    if ($Name -match 'Normalized|Normalization|Payload|Lookup|MachineTuple|CveEnrichment') { return 'Normalization' }
    if ($Name -match 'Vuln|Machine|AdvancedHunting|Store|Snapshot|Mde') { return 'Store' }
    if ($Name -match 'Generate') { return 'Generator' }
    return 'Other'
}

function Write-SharedHelperRegressionJUnit {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][System.Collections.Generic.List[object]]$Results
    )

    $parent = Split-Path -Path $Path -Parent
    if (-not [string]::IsNullOrWhiteSpace($parent)) { [void](New-Item -Path $parent -ItemType Directory -Force) }
    $settings = [System.Xml.XmlWriterSettings]::new()
    $settings.Indent = $true
    $settings.Encoding = [System.Text.UTF8Encoding]::new($false)
    $writer = [System.Xml.XmlWriter]::Create([System.IO.Path]::GetFullPath($Path), $settings)
    try {
        $writer.WriteStartDocument()
        $writer.WriteStartElement('testsuite')
        $writer.WriteAttributeString('name', 'SharedHelperRegression')
        $writer.WriteAttributeString('tests', [string]$Results.Count)
        $writer.WriteAttributeString('failures', [string]@($Results | Where-Object { -not $_.Passed }).Count)
        $writer.WriteAttributeString('time', [string][math]::Round((($Results | Measure-Object -Property Seconds -Sum).Sum), 3))
        foreach ($result in $Results) {
            $errorMessage = [regex]::Replace(([regex]::Replace([string]$result.ErrorMessage, "`e\[[0-9;]*m", '')), '[^\x09\x0A\x0D\x20-\uD7FF\uE000-\uFFFD]', '')
            $errorDetail = [regex]::Replace(([regex]::Replace([string]$result.ErrorDetail, "`e\[[0-9;]*m", '')), '[^\x09\x0A\x0D\x20-\uD7FF\uE000-\uFFFD]', '')
            $writer.WriteStartElement('testcase')
            $writer.WriteAttributeString('name', [string]$result.Name)
            $writer.WriteAttributeString('classname', ('SharedHelperRegression.' + [string]$result.Category))
            $writer.WriteAttributeString('time', [string][math]::Round([double]$result.Seconds, 3))
            if (-not $result.Passed) {
                $writer.WriteStartElement('failure')
                $writer.WriteAttributeString('message', $errorMessage)
                $writer.WriteString($errorDetail)
                $writer.WriteEndElement()
            }
            $writer.WriteEndElement()
        }
        $writer.WriteEndElement()
        $writer.WriteEndDocument()
    }
    finally { $writer.Dispose() }
}

$selectedTests = @($sharedHelperRegressionTests | Where-Object {
        $entry = $_
        $nameMatch = (-not $TestName -or @($TestName | Where-Object { $entry.Name -like $_ }).Count -gt 0)
        $testCategory = Get-SharedHelperRegressionCategory -Name $entry.Name
        $categoryMatch = (-not $Category -or $Category -contains $testCategory)
        $nameMatch -and $categoryMatch
    })
if ($StopAfter -gt 0) { $selectedTests = @($selectedTests | Select-Object -First $StopAfter) }
if ($selectedTests.Count -eq 0) { throw 'No shared-helper regression tests matched the requested selection.' }

$repoRoot = Split-Path -Path $PSScriptRoot -Parent
Initialize-RegressionDashboardLibraryCache -BasePath (Join-Path $repoRoot '.local\shared-regression-fixtures')

$results = [System.Collections.Generic.List[object]]::new()
$failure = $null
foreach ($sharedHelperRegressionTest in $selectedTests) {
    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        Invoke-SharedHelperRegressionTest -Name $sharedHelperRegressionTest.Name -SuccessMessage $sharedHelperRegressionTest.SuccessMessage
        $stopwatch.Stop()
        $results.Add([PSCustomObject]@{ Name = $sharedHelperRegressionTest.Name; Category = Get-SharedHelperRegressionCategory $sharedHelperRegressionTest.Name; Seconds = $stopwatch.Elapsed.TotalSeconds; Passed = $true; ErrorMessage = ''; ErrorDetail = '' })
    }
    catch {
        $stopwatch.Stop()
        $failure = $_
        $results.Add([PSCustomObject]@{ Name = $sharedHelperRegressionTest.Name; Category = Get-SharedHelperRegressionCategory $sharedHelperRegressionTest.Name; Seconds = $stopwatch.Elapsed.TotalSeconds; Passed = $false; ErrorMessage = $_.Exception.Message; ErrorDetail = [string]$_ })
        break
    }
}

if (-not [string]::IsNullOrWhiteSpace($JUnitOutputPath)) { Write-SharedHelperRegressionJUnit -Path $JUnitOutputPath -Results $results }
if ($null -ne $failure) { throw $failure }

Write-Output 'Shared-helper regression checks passed.'
