Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Assert-DashboardTemplatePublishPath {
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

function Initialize-DashboardTemplatePublishParentDirectory {
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

function Write-DashboardTemplatePublishUtf8BomFile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$Content
    )

    Initialize-DashboardTemplatePublishParentDirectory -Path $Path
    [System.IO.File]::WriteAllText($Path, $Content, [System.Text.UTF8Encoding]::new($true))
}

function Get-DashboardTemplatePublishTextSha256Hex {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$Text
    )

    $hashBytes = [System.Security.Cryptography.SHA256]::HashData([System.Text.Encoding]::UTF8.GetBytes($Text))
    return ([System.BitConverter]::ToString($hashBytes)).Replace('-', '').ToLowerInvariant()
}

function Get-DashboardTemplatePublishFileContentSha256Hex {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    Assert-DashboardTemplatePublishPath -Path $Path -PathType Leaf
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Test-DashboardTemplatePublishPathWithinRoot {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [string]$Root
    )

    $resolvedPath = [System.IO.Path]::GetFullPath($Path)
    $resolvedRoot = [System.IO.Path]::GetFullPath($Root)
    $comparison = [System.StringComparison]::OrdinalIgnoreCase

    if ($resolvedPath.Equals($resolvedRoot, $comparison)) {
        return $true
    }

    $rootWithSeparator = $resolvedRoot.TrimEnd('\', '/') + [System.IO.Path]::DirectorySeparatorChar
    return $resolvedPath.StartsWith($rootWithSeparator, $comparison)
}

function Get-DashboardTemplatePublishDisplayPath {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [string]$RepoRoot
    )

    $resolvedPath = [System.IO.Path]::GetFullPath($Path)
    $resolvedRoot = [System.IO.Path]::GetFullPath($RepoRoot)
    if ($resolvedPath.StartsWith($resolvedRoot, [System.StringComparison]::OrdinalIgnoreCase)) {
        return $resolvedPath.Substring($resolvedRoot.Length + 1).Replace('\', '/')
    }

    return $resolvedPath.Replace('\', '/')
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

    Assert-DashboardTemplatePublishPath -Path $resolvedTemplatesPath -PathType Container
    return $resolvedTemplatesPath
}

function Get-DashboardTemplatePublishContentType {
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
        $contentSha256 = Get-DashboardTemplatePublishFileContentSha256Hex -Path $file.FullName
        $contentType = Get-DashboardTemplatePublishContentType -File $file
        $sourcePath = if ($null -ne $resolvedRepoRoot -and (Test-DashboardTemplatePublishPathWithinRoot -Path $file.FullName -Root $resolvedRepoRoot)) {
            Get-DashboardTemplatePublishDisplayPath -Path $file.FullName -RepoRoot $resolvedRepoRoot
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

    $templatesDisplayPath = if ($null -ne $resolvedRepoRoot -and (Test-DashboardTemplatePublishPathWithinRoot -Path $TemplatesPath -Root $resolvedRepoRoot)) {
        Get-DashboardTemplatePublishDisplayPath -Path $TemplatesPath -RepoRoot $resolvedRepoRoot
    }
    else {
        $TemplatesPath
    }

    return [PSCustomObject]@{
        TemplatesPath = $TemplatesPath
        TemplatesDisplayPath = $templatesDisplayPath
        FileCount = $templateEntries.Count
        TotalSizeBytes = [int64]($templateEntries | Measure-Object -Property SizeBytes -Sum | Select-Object -ExpandProperty Sum)
        Fingerprint = Get-DashboardTemplatePublishTextSha256Hex -Text $fingerprintBuilder.ToString()
        Files = @($templateEntries)
    }
}

function ConvertTo-DashboardTemplatePublishPlainTextToken {
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

function Get-DashboardTemplatePublishStorageAccessToken {
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
                return ConvertTo-DashboardTemplatePublishPlainTextToken -Token $tokenResponse.Token
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

function Publish-DashboardTemplateBlobFileWithRetry {
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

    Assert-DashboardTemplatePublishPath -Path $FilePath -PathType Leaf
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
