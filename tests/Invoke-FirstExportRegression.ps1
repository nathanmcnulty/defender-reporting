#Requires -Version 7.6
[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path $PSScriptRoot -Parent
. (Join-Path $repoRoot 'build/Import-SharedHelpers.ps1')
function Assert-True([bool]$Condition, [string]$Message) { if (-not $Condition) { throw $Message } }

# Exercise the real entrypoint and parameter sets, substituting only the imported
# API/store boundary. A new PowerShell location deliberately differs from OS cwd.
$tempRoot = Join-Path ([IO.Path]::GetTempPath()) ('first-export-' + [guid]::NewGuid().ToString('N'))
try {
    [void][IO.Directory]::CreateDirectory((Join-Path $tempRoot 'build'))
    Copy-Item -LiteralPath (Join-Path $repoRoot 'Invoke-VulnerabilityExport.ps1') -Destination $tempRoot
    @'
function New-MdeAccessTokenContext {
    param($AccessToken, $TenantId, $AppId, $AppSecret, $ResourceAppIdUri, [switch]$WriteStatus)
    [IO.File]::WriteAllText((Join-Path $PSScriptRoot 'auth-called.txt'), 'synthetic')
    if (-not (Test-Path -LiteralPath $OutputPath -PathType Container)) { throw 'Output must exist before auth' }
    [IO.File]::WriteAllText((Join-Path $OutputPath 'auth-mock.txt'), 'synthetic')
    return @{}
}
function Get-MdeHeaderCollection { param($TokenContext) return @{} }
function Export-MdeBulkVulnerabilityData { param($Headers, $OutputPath, $ExportUrl) return @() }
function Publish-VulnerabilityHistoryStore {
    param($OutputPath, $DownloadedFiles)
    return @{ DownloadedFiles = 0; CurrentRows = 0; HistoryYears = 0 }
}
function Export-MdeMachineData {
    param($Headers, $OutputPath, $BaseApiUrl)
    return @{ MachineCount = 0; ChangeCount = 0; OutputFiles = @() }
}
function Get-ExportTransferArtifactNames { param($BasePath) return @() }
function Clear-StaleLocalExportArtifact { param($BasePath, $KeepNames) }
function Get-VulnCurrentPath { param($BasePath) return (Join-Path $BasePath 'VulnCurrent.json.gz') }
'@ | Set-Content -LiteralPath (Join-Path $tempRoot 'build/Import-SharedHelpers.ps1') -Encoding utf8
    Push-Location $tempRoot
    try {
        & ./Invoke-VulnerabilityExport.ps1 -AccessToken 'synthetic-not-a-token' -OutputPath './missing exports'
        Assert-True (Test-Path -LiteralPath './missing exports/auth-mock.txt') 'Explicit first-run path did not reach mocked export.'
        $syntheticSecret = [Security.SecureString]::new()
        $syntheticSecret.AppendChar('x')
        & ./Invoke-VulnerabilityExport.ps1 -TenantId 'synthetic' -AppId 'synthetic' -AppSecret $syntheticSecret
        Assert-True (Test-Path -LiteralPath './exports/auth-mock.txt') 'Default first-run credentials path did not reach mocked export.'
        Set-Content -LiteralPath './blocked.txt' -Value 'synthetic'
        Remove-Item -LiteralPath './build/auth-called.txt'
        foreach ($invalidPath in @('Env:\FIRST_EXPORT_INVALID', (Join-Path $tempRoot 'blocked.txt'))) {
            $failedOutput = & (Join-Path $PSHOME 'pwsh') -NoProfile -File ./Invoke-VulnerabilityExport.ps1 -AccessToken 'synthetic-not-a-token' -OutputPath $invalidPath 2>&1
            Assert-True ($LASTEXITCODE -eq 1) 'Non-filesystem and file output paths must fail before authentication.'
            Assert-True (-not ($failedOutput -match 'Export completed successfully')) 'Invalid output must not reach successful export.'
            Assert-True (-not (Test-Path -LiteralPath './build/auth-called.txt')) 'Invalid output must not call authentication.'
        }
    }
    finally { Pop-Location }

    # Real Advanced Hunting query/annotation/store publication, network replaced
    # by a three-response queue. Cover every empty subset, not just all-empty.
    function Invoke-RestMethodWithRetry {
        param($Uri, $Headers, $Method, $Body)
        if ($Uri -ne 'https://synthetic.invalid/query' -or $Method -ne 'Post' -or $null -eq $Headers -or -not ($Body | ConvertFrom-Json).Query) { throw 'Unexpected API boundary.' }
        $script:QueryCalls++
        return @{ Results = $script:QueryResults.Dequeue() }
    }
    for ($mask = 0; $mask -lt 8; $mask++) {
        $path = Join-Path $tempRoot "hunting-$mask"
        [void][IO.Directory]::CreateDirectory($path)
        $priorPath = Join-Path $path 'AdvancedHunting_Current.json.gz'
        if ($mask -eq 0) { Write-NdjsonRecordsFile -Path $priorPath -Records @([pscustomobject]@{ RecordType = 'Cve'; CveId = 'CVE-2026-0009' }) }
        $priorHash = if ($mask -eq 0) { (Get-FileHash -LiteralPath $priorPath).Hash } else { $null }
        $records = @(
            [pscustomobject]@{ CveId = 'CVE-2026-0001'; VulnerabilityDescription = 'Synthetic CVE' }
            [pscustomobject]@{ DeviceId = 'synthetic-device'; LoggedOnUsers = '[]' }
            [pscustomobject]@{ DeviceId = 'synthetic-device'; SoftwareVendor = 'synthetic'; SoftwareName = 'test'; SoftwareVersion = '1.0' }
        )
        $script:QueryCalls = 0
        $script:QueryResults = [Collections.Generic.Queue[object]]::new()
        $expected = 0
        for ($i = 0; $i -lt 3; $i++) {
            if ($mask -band (1 -shl $i)) { $script:QueryResults.Enqueue(@($records[$i])); $expected++ }
            else { $script:QueryResults.Enqueue(@()) }
        }
        $result = Invoke-MdeAdvancedHuntingStoreRefresh -Headers @{} -OutputPath $path -QueryUrl 'https://synthetic.invalid/query'
        Assert-True ($script:QueryCalls -eq 3) 'All three query boundaries must execute.'
        Assert-True ($result.Success -eq ($expected -gt 0)) "Wrong empty-result status for mask $mask."
        Assert-True ($result.RecordCount -eq $expected) "Lost enrichment for mask $mask."
        if ($expected) {
            $published = @(Read-VulnNdjsonRecordsFromPath -Path $result.OutputFile)
            Assert-True ($published.Count -eq $expected) "Wrong published record count for mask $mask."
            Assert-True (@($published | Where-Object { -not $_.RecordType }).Count -eq 0) 'Every nonempty row must retain its type.'
        }
        else {
            Assert-True ($null -eq $result.OutputFile) 'All-empty must not publish an invented store.'
            Assert-True ((Get-FileHash -LiteralPath $priorPath).Hash -eq $priorHash) 'All-empty must preserve prior canonical enrichment bytes.'
            Assert-True (@(Get-ChildItem -LiteralPath $path -Force).Count -eq 1) 'All-empty must not leave staging, lock or transaction artifacts.'
        }
    }
    Write-Output 'First-export and all Advanced Hunting empty subsets passed.'
}
finally {
    if (Test-Path -LiteralPath $tempRoot) { Remove-Item -LiteralPath $tempRoot -Recurse -Force }
}

# The intentionally failing native child probes set LASTEXITCODE. Publish this
# test entrypoint's successful outcome for in-process preflight callers too.
exit 0
