. (Join-Path -Path $PSScriptRoot -ChildPath 'ArtifactManifestTools.ps1')

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-AzureArtifactBuildContext {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$BuildScriptRoot
    )

    $buildRoot = Split-Path -Path $BuildScriptRoot -Parent
    $repoRoot = Split-Path -Path $buildRoot -Parent

    return [PSCustomObject]@{
        BuildRoot = $buildRoot
        RepoRoot = $repoRoot
        BuildSharedHelpersPath = Join-Path -Path $buildRoot -ChildPath 'Build-SharedHelpers.ps1'
        SharedHelpersPath = Join-Path -Path $buildRoot -ChildPath 'generated\shared-helpers.ps1'
        RunbookSourcePath = Join-Path -Path $BuildScriptRoot -ChildPath 'runbook-source.ps1'
        RunbookOutputPath = Join-Path -Path $repoRoot -ChildPath 'azure\Invoke-DashboardPipeline.ps1'
        FunctionAppRoot = Join-Path -Path $repoRoot -ChildPath 'azure\function-app'
    }
}

function Assert-BuildPath {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [ValidateSet('Leaf', 'Container')]
        [string]$PathType
    )

    if (-not (Test-Path -LiteralPath $Path -PathType $PathType)) {
        throw "Required path not found: $Path"
    }
}

function Initialize-ParentDirectory {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $parentPath = Split-Path -Path $Path -Parent
    if (-not [string]::IsNullOrWhiteSpace($parentPath) -and -not (Test-Path -LiteralPath $parentPath -PathType Container)) {
        New-Item -Path $parentPath -ItemType Directory -Force | Out-Null
    }
}

function Get-AzurePackageManifestPath {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$PackagePath
    )

    $packageDirectory = Split-Path -Path $PackagePath -Parent
    $packageBaseName = [System.IO.Path]::GetFileNameWithoutExtension($PackagePath)
    if ([string]::IsNullOrWhiteSpace($packageDirectory) -or [string]::IsNullOrWhiteSpace($packageBaseName)) {
        throw "Could not derive a package manifest path from '$PackagePath'."
    }

    return Join-Path -Path $packageDirectory -ChildPath ($packageBaseName + '.manifest.json')
}

function Get-AzureFunctionAppPackageDefaultOutputPath {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$RepoRoot
    )

    return Join-Path -Path $RepoRoot -ChildPath '.local\local-reports\function-app-package\defender-reporting-function-app.zip'
}

function Resolve-DashboardTemplatesPath {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$RepoRoot,

        [Parameter(Mandatory = $false)]
        [string]$TemplatesPath
    )

    $resolvedTemplatesPath = if ([string]::IsNullOrWhiteSpace($TemplatesPath)) {
        Join-Path -Path $RepoRoot -ChildPath 'templates'
    }
    else {
        [System.IO.Path]::GetFullPath($TemplatesPath)
    }

    Assert-BuildPath -Path $resolvedTemplatesPath -PathType Container
    return $resolvedTemplatesPath
}

function Get-DashboardTemplateContentType {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [System.IO.FileInfo]$File
    )

    switch ($File.Extension.ToLowerInvariant()) {
        '.html' { return 'text/html' }
        '.css' { return 'text/css' }
        '.js' { return 'application/javascript' }
        '.json' { return 'application/json' }
        default { return 'application/octet-stream' }
    }
}

function Get-DashboardTemplatePublishState {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$TemplatesPath,

        [Parameter(Mandatory = $false)]
        [string]$RepoRoot
    )

    $templateFiles = @(
        Get-ChildItem -LiteralPath $TemplatesPath -File -Recurse -ErrorAction Stop |
            Sort-Object FullName
    )
    if ($templateFiles.Count -eq 0) {
        throw "No template files found under '$TemplatesPath'."
    }

    $fingerprintBuilder = [System.Text.StringBuilder]::new()
    $resolvedRepoRoot = if ([string]::IsNullOrWhiteSpace($RepoRoot)) { $null } else { [System.IO.Path]::GetFullPath($RepoRoot) }
    $templateEntries = foreach ($file in $templateFiles) {
        $relativePath = [System.IO.Path]::GetRelativePath($TemplatesPath, $file.FullName).Replace('\', '/')
        $contentSha256 = Get-FileContentSha256Hex -Path $file.FullName
        $contentType = Get-DashboardTemplateContentType -File $file
        $sourcePath = if ($null -ne $resolvedRepoRoot -and (Test-ArtifactPathWithinRoot -Path $file.FullName -Root $resolvedRepoRoot)) {
            Get-RepoRelativeDisplayPath -Path $file.FullName -RepoRoot $resolvedRepoRoot
        }
        else {
            $file.FullName
        }

        [void]$fingerprintBuilder.AppendLine("path:$relativePath")
        [void]$fingerprintBuilder.AppendLine("sha256:$contentSha256")
        [void]$fingerprintBuilder.AppendLine("contentType:$contentType")

        [PSCustomObject]@{
            Path = $relativePath
            SourcePath = $sourcePath
            FullPath = $file.FullName
            Sha256 = $contentSha256
            ContentType = $contentType
            SizeBytes = $file.Length
        }
    }

    $templatesDisplayPath = if ($null -ne $resolvedRepoRoot -and (Test-ArtifactPathWithinRoot -Path $TemplatesPath -Root $resolvedRepoRoot)) {
        Get-RepoRelativeDisplayPath -Path $TemplatesPath -RepoRoot $resolvedRepoRoot
    }
    else {
        $TemplatesPath
    }

    return [PSCustomObject]@{
        TemplatesPath = $TemplatesPath
        TemplatesDisplayPath = $templatesDisplayPath
        FileCount = $templateEntries.Count
        TotalSizeBytes = [int64]($templateEntries | Measure-Object -Property SizeBytes -Sum | Select-Object -ExpandProperty Sum)
        Fingerprint = Get-TextSha256Hex -Text $fingerprintBuilder.ToString()
        Files = @($templateEntries)
    }
}

function ConvertTo-PlainTextToken {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [System.Security.SecureString]$Token
    )

    $tokenPointer = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Token)
    try {
        return [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($tokenPointer)
    }
    finally {
        [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($tokenPointer)
    }
}

function Get-StorageAccessToken {
    [CmdletBinding()]
    [OutputType([string])]
    param()

    $getAzAccessTokenCommand = Get-Command -Name 'Get-AzAccessToken' -ErrorAction SilentlyContinue
    if ($null -ne $getAzAccessTokenCommand) {
        $hasAzContext = $true
        $getAzContextCommand = Get-Command -Name 'Get-AzContext' -ErrorAction SilentlyContinue
        if ($null -ne $getAzContextCommand) {
            try {
                $azContext = Get-AzContext -ErrorAction Stop
                $hasAzContext = ($null -ne $azContext -and $null -ne $azContext.Account)
            }
            catch {
                $hasAzContext = $false
            }
        }

        if ($hasAzContext) {
            try {
                $tokenResponse = Get-AzAccessToken -ResourceUrl 'https://storage.azure.com/' -AsSecureString -ErrorAction Stop
                return ConvertTo-PlainTextToken -Token $tokenResponse.Token
            }
            catch {
                Write-Verbose "Az PowerShell token acquisition failed: $_"
            }
        }
    }

    if ($null -ne (Get-Command -Name 'az' -CommandType Application -ErrorAction SilentlyContinue)) {
        try {
            $azAccessToken = (& az 'account' 'get-access-token' '--resource' 'https://storage.azure.com/' '--query' 'accessToken' '-o' 'tsv' 2>&1 | Out-String)
            if ($LASTEXITCODE -eq 0 -and -not [string]::IsNullOrWhiteSpace($azAccessToken)) {
                return $azAccessToken.Trim()
            }

            if ($LASTEXITCODE -ne 0 -and -not [string]::IsNullOrWhiteSpace($azAccessToken)) {
                Write-Verbose ("Azure CLI token acquisition failed: {0}" -f $azAccessToken.Trim())
            }
        }
        catch {
            Write-Verbose "Azure CLI token acquisition failed: $_"
        }
    }

    throw "No Azure Storage token source available. Run Connect-AzAccount or az login, then retry."
}

function Publish-BlobFileWithRetry {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$StorageAccountName,

        [Parameter(Mandatory = $true)]
        [string]$ContainerName,

        [Parameter(Mandatory = $true)]
        [string]$BlobName,

        [Parameter(Mandatory = $true)]
        [string]$FilePath,

        [Parameter(Mandatory = $true)]
        [string]$ContentType,

        [Parameter(Mandatory = $true)]
        [string]$StorageToken,

        [Parameter(Mandatory = $false)]
        [int]$MaxRetries = 3,

        [Parameter(Mandatory = $false)]
        [int]$InitialRetryDelaySeconds = 2
    )

    Assert-BuildPath -Path $FilePath -PathType Leaf
    $blobUri = "https://$StorageAccountName.blob.core.windows.net/$ContainerName/$BlobName"
    $headers = @{
        'Authorization'    = "Bearer $StorageToken"
        'x-ms-version'     = '2021-12-02'
        'x-ms-blob-type'   = 'BlockBlob'
        'x-ms-access-tier' = 'Cool'
    }

    $retryDelaySeconds = $InitialRetryDelaySeconds
    for ($attempt = 1; $attempt -le $MaxRetries; $attempt++) {
        try {
            Invoke-RestMethod -Uri $blobUri -Method Put -Headers $headers -InFile $FilePath -ContentType $ContentType -ErrorAction Stop
            return
        }
        catch {
            if ($attempt -eq $MaxRetries) {
                throw "Failed to upload '$BlobName' to container '$ContainerName' in storage account '$StorageAccountName' after $MaxRetries attempt(s): $_"
            }

            Start-Sleep -Seconds $retryDelaySeconds
            $retryDelaySeconds *= 2
        }
    }
}

function Get-AzureSharedAssemblyInput {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory = $true)]
        [pscustomobject]$BuildContext,

        [Parameter(Mandatory = $true)]
        [string]$Marker
    )

    Assert-BuildPath -Path $BuildContext.BuildSharedHelpersPath -PathType Leaf
    Assert-BuildPath -Path $BuildContext.RunbookSourcePath -PathType Leaf

    & $BuildContext.BuildSharedHelpersPath

    Assert-BuildPath -Path $BuildContext.SharedHelpersPath -PathType Leaf
    $sharedHelpersFingerprint = Read-PowerShellArtifactEmbeddedFingerprint -Path $BuildContext.SharedHelpersPath
    if ([string]::IsNullOrWhiteSpace($sharedHelpersFingerprint)) {
        throw "Generated shared helpers '$($BuildContext.SharedHelpersPath)' are missing fingerprint metadata. Re-run '$($BuildContext.BuildSharedHelpersPath)'."
    }

    $runbookSource = Get-Content -Path $BuildContext.RunbookSourcePath -Raw
    $sharedHelpers = Get-Content -Path $BuildContext.SharedHelpersPath -Raw
    $lineEnding = if ($runbookSource.Contains("`r`n")) { "`r`n" } else { "`n" }
    $normalizedMarker = $Marker -replace "`r?`n", $lineEnding
    $sharedHelpersText = if ($sharedHelpers -is [System.Array]) {
        @($sharedHelpers) -join $lineEnding
    }
    else {
        [string]$sharedHelpers
    }

    return [PSCustomObject]@{
        RunbookSource = $runbookSource
        LineEnding = $lineEnding
        NormalizedMarker = $normalizedMarker
        NormalizedSharedHelpers = ($sharedHelpersText -replace "`r?`n", $lineEnding).TrimEnd()
        SharedHelpersFingerprint = $sharedHelpersFingerprint
    }
}

function Assert-AzureArtifactFingerprint {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ArtifactPath,

        [Parameter(Mandatory = $true)]
        [string]$ExpectedFingerprint,

        [Parameter(Mandatory = $true)]
        [string]$ArtifactDescription
    )

    Assert-BuildPath -Path $ArtifactPath -PathType Leaf
    $artifactContent = Get-Content -LiteralPath $ArtifactPath -Raw -ErrorAction Stop
    $embeddedFingerprint = $null
    $fingerprintMatches = [System.Text.RegularExpressions.Regex]::Matches($artifactContent, '(?m)^# ArtifactFingerprint:\s*([0-9a-f]{64})\s*$')
    if ($fingerprintMatches.Count -gt 0) {
        $embeddedFingerprint = $fingerprintMatches[$fingerprintMatches.Count - 1].Groups[1].Value.ToLowerInvariant()
    }
    if ([string]::IsNullOrWhiteSpace($embeddedFingerprint)) {
        throw "$ArtifactDescription '$ArtifactPath' is missing embedded fingerprint metadata."
    }

    if ($embeddedFingerprint -ne $ExpectedFingerprint) {
        throw "$ArtifactDescription '$ArtifactPath' does not match the current shared-helper fingerprint. Expected '$ExpectedFingerprint' but found '$embeddedFingerprint'."
    }

    return [PSCustomObject]@{
        ArtifactPath = $ArtifactPath
        Fingerprint = $embeddedFingerprint
    }
}

function Get-AzAccountsModuleStagingSummary {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ModuleRoot,

        [Parameter(Mandatory = $false)]
        [string]$RepoRoot
    )

    Assert-BuildPath -Path $ModuleRoot -PathType Container
    $manifestCandidates = @(
        Get-ChildItem -LiteralPath $ModuleRoot -Filter 'Az.Accounts.psd1' -Recurse -File -ErrorAction Stop
    )
    if ($manifestCandidates.Count -eq 0) {
        throw "No Az.Accounts module manifest was found under '$ModuleRoot'."
    }

    $manifestValidationFailures = [System.Collections.Generic.List[object]]::new()
    $validManifests = foreach ($manifestCandidate in $manifestCandidates) {
        $manifestDisplayPath = if (-not [string]::IsNullOrWhiteSpace($RepoRoot) -and (Test-ArtifactPathWithinRoot -Path $manifestCandidate.FullName -Root $RepoRoot)) {
            Get-RepoRelativeDisplayPath -Path $manifestCandidate.FullName -RepoRoot $RepoRoot
        }
        else {
            $manifestCandidate.FullName
        }

        try {
            $moduleManifest = Test-ModuleManifest -Path $manifestCandidate.FullName -ErrorAction Stop
            [PSCustomObject]@{
                Path = $manifestCandidate.FullName
                DisplayPath = $manifestDisplayPath
                ModuleVersion = [version]$moduleManifest.Version
            }
        }
        catch {
            $validationMessage = if ($_.Exception -and -not [string]::IsNullOrWhiteSpace([string]$_.Exception.Message)) {
                [string]$_.Exception.Message
            }
            else {
                [string]$_
            }

            $manifestValidationFailures.Add([PSCustomObject]@{
                    Path = $manifestCandidate.FullName
                    DisplayPath = $manifestDisplayPath
                    Error = (($validationMessage -replace '\s+', ' ').Trim())
                }) | Out-Null
            continue
        }
    }

    $orderedValidManifests = @($validManifests | Sort-Object -Property ModuleVersion -Descending)
    $selectedManifest = $orderedValidManifests | Select-Object -First 1
    if ($null -eq $selectedManifest) {
        $failurePreview = @(
            $manifestValidationFailures |
                Select-Object -First 5 |
                ForEach-Object { "'$($_.DisplayPath)': $($_.Error)" }
        )
        $failureSuffix = if ($failurePreview.Count -gt 0) {
            " Validation failures: {0}{1}" -f ($failurePreview -join '; '), $(if ($manifestValidationFailures.Count -gt $failurePreview.Count) { '; ...' } else { '' })
        }
        else {
            ''
        }

        throw "Az.Accounts staging under '$ModuleRoot' does not contain a valid module manifest after checking $($manifestCandidates.Count) candidate(s).$failureSuffix"
    }

    $fileCount = @(Get-ChildItem -LiteralPath $ModuleRoot -Recurse -File -ErrorAction Stop).Count
    if ($fileCount -lt 5) {
        throw "Az.Accounts staging under '$ModuleRoot' is incomplete (found $fileCount file(s))."
    }

    $manifestDisplayPath = [string]$selectedManifest.DisplayPath
    $bundledVersions = @(
        $orderedValidManifests |
            Sort-Object -Property ModuleVersion -Descending -Unique |
            ForEach-Object { $_.ModuleVersion.ToString() }
    )
    $bundledManifestPaths = @(
        $orderedValidManifests |
            ForEach-Object { [string]$_.DisplayPath }
    )

    return [PSCustomObject]@{
        ModuleRoot = $ModuleRoot
        ManifestPath = $selectedManifest.Path
        ManifestDisplayPath = $manifestDisplayPath
        ModuleVersion = $selectedManifest.ModuleVersion.ToString()
        BundledVersions = $bundledVersions
        BundledManifestPaths = $bundledManifestPaths
        FileCount = $fileCount
        InvalidManifestCandidateCount = $manifestValidationFailures.Count
    }
}

function Initialize-AzureFunctionAppArtifactState {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory = $true)]
        [pscustomobject]$BuildContext
    )

    $buildScriptPath = Join-Path -Path $BuildContext.BuildRoot -ChildPath 'azure\Build-FunctionApp.ps1'
    $entryPointPath = Join-Path -Path $BuildContext.FunctionAppRoot -ChildPath 'ExportAndGenerate\run.ps1'
    $moduleRoot = Join-Path -Path $BuildContext.FunctionAppRoot -ChildPath 'Modules\Az.Accounts'

    if (Test-Path -LiteralPath $buildScriptPath -PathType Leaf) {
        & $buildScriptPath | ForEach-Object { Write-Host $_ }
    }
    elseif ((Test-Path -LiteralPath $entryPointPath -PathType Leaf) -and (Test-Path -LiteralPath $moduleRoot -PathType Container)) {
        # Prebuilt release-package flow: the generated entry point and staged modules
        # are already present even though the source build script is not shipped.
    }
    else {
        throw "Function App build script not found at $buildScriptPath and prebuilt artifacts are incomplete. Expected '$entryPointPath' and '$moduleRoot'."
    }

    $sharedHelpersFingerprint = Read-PowerShellArtifactEmbeddedFingerprint -Path $BuildContext.SharedHelpersPath
    if ([string]::IsNullOrWhiteSpace($sharedHelpersFingerprint)) {
        throw "Generated shared helpers '$($BuildContext.SharedHelpersPath)' are missing fingerprint metadata."
    }

    $entryPointFingerprintState = Assert-AzureArtifactFingerprint -ArtifactPath $entryPointPath -ExpectedFingerprint $sharedHelpersFingerprint -ArtifactDescription 'Azure Function App entry point artifact'
    $moduleSummary = Get-AzAccountsModuleStagingSummary -ModuleRoot $moduleRoot -RepoRoot $BuildContext.RepoRoot

    return [PSCustomObject]@{
        BuildScriptPath = $buildScriptPath
        EntryPointPath = $entryPointPath
        ModuleRoot = $moduleRoot
        SharedHelpersFingerprint = $sharedHelpersFingerprint
        EntryPointFingerprintState = $entryPointFingerprintState
        ModuleSummary = $moduleSummary
    }
}

function Write-Utf8BomFile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$Content
    )

    Initialize-ParentDirectory -Path $Path
    [System.IO.File]::WriteAllText($Path, $Content, [System.Text.UTF8Encoding]::new($true))
}