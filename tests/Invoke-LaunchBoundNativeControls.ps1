#Requires -Version 7.0
[CmdletBinding()]
param([Parameter(Mandatory)][string]$EvidencePath, [Parameter(Mandatory)][string]$ProductManifest, [Parameter(Mandatory)][string]$ProductManifestSha256, [switch]$DiagnosticOnly)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
if (-not $IsWindows) { throw 'Windows native control required.' }
if ($PSVersionTable.PSVersion -lt [version]'7.6') { throw 'Existing PowerShell 7.6+ required.' }
$powerShellPath = [Environment]::ProcessPath
if ([IO.Path]::GetFileName($powerShellPath) -ine 'pwsh.exe' -or -not [IO.Path]::IsPathFullyQualified($powerShellPath)) { throw 'Known PowerShell executable required.' }
if (Test-Path -LiteralPath $EvidencePath) { throw 'Fresh evidence destination required.' }
[void](New-Item -ItemType Directory -Path $EvidencePath)
$fixture = Join-Path $PSScriptRoot 'helpers/LaunchBoundFixture.ps1'
if (-not ('LaunchBound.NativeControls' -as [type])) { Add-Type -Path @((Join-Path $PSScriptRoot 'helpers/LaunchBoundJob.cs'), (Join-Path $PSScriptRoot 'helpers/LaunchBoundNativeControls.cs'), (Join-Path $PSScriptRoot 'helpers/LaunchBoundExitObserver.cs'), (Join-Path $PSScriptRoot 'helpers/controlled-fixture/Program.cs')) }
$fixtureImage=Join-Path (Split-Path -Parent $ProductManifest) 'LaunchBoundFixture.exe'
$fixtureRuntime=[LaunchBoundTests.ControlledFixture]::VerifyProduct($fixtureImage,$ProductManifest,$ProductManifestSha256)
$neighbor = [Diagnostics.Process]::new()
$neighborStarted = $false
$caught = $null; $cleanupError = $null; $cases = @(); $powerShellCases=@(); $neighborSurvived = $false
try {
    $neighbor.StartInfo = [Diagnostics.ProcessStartInfo]::new($powerShellPath)
    $neighbor.StartInfo.UseShellExecute = $false; $neighbor.StartInfo.CreateNoWindow = $true
    $neighbor.StartInfo.ArgumentList.Add('-NoProfile'); $neighbor.StartInfo.ArgumentList.Add('-NonInteractive'); $neighbor.StartInfo.ArgumentList.Add('-Command'); $neighbor.StartInfo.ArgumentList.Add('Start-Sleep -Seconds 180')
    if (-not $neighbor.Start()) { throw 'Neighbor fixture failed.' }
    $neighborStarted = $true
    $heldNeighbor = $neighbor.SafeHandle
    if ($heldNeighbor.IsInvalid -or $heldNeighbor.IsClosed) { throw 'Neighbor handle unavailable.' }
    $cases = [LaunchBound.NativeControls]::RunControlled($fixtureImage,$ProductManifest,$ProductManifestSha256,$EvidencePath,$neighbor.Id,[bool]$DiagnosticOnly)
    if(-not $DiagnosticOnly){$powerShellCases=[LaunchBound.NativeControls]::RunPowerShellIntegration($powerShellPath,$fixture,(Join-Path $EvidencePath 'powershell-integration'))}
    [void][LaunchBoundTests.ControlledFixture]::VerifyProduct($fixtureImage,$ProductManifest,$ProductManifestSha256)
    if ($neighbor.HasExited) { throw 'Unrelated fixture was terminated.' }
    $neighborSurvived = $true
}
catch { $caught = $_ }
finally {
    try {
        if ($neighborStarted -and -not $neighbor.HasExited) { $neighbor.Kill(); if (-not $neighbor.WaitForExit(5000)) { throw 'Neighbor fixture cleanup unconfirmed.' } }
    } catch { $cleanupError = $_ }
    finally { $neighbor.Dispose() }
}
$status = if ($null -eq $caught -and $null -eq $cleanupError) { 'passed' } else { 'failed' }
[ordered]@{status=$status;diagnosticOnly=[bool]$DiagnosticOnly;powerShellVersion=$PSVersionTable.PSVersion.ToString();powerShellPath=$powerShellPath;fixtureImage=$fixtureImage;fixtureRuntime=$fixtureRuntime;productManifest=$ProductManifest;productManifestSha256=$ProductManifestSha256;cases=@($cases);powerShellIntegrationCases=@($powerShellCases);neighborSurvived=$neighborSurvived;neighborCleanupConfirmed=$null -eq $cleanupError;exceptionType=$(if($caught){$caught.Exception.GetType().Name}else{$null});cleanupExceptionType=$(if($cleanupError){$cleanupError.Exception.GetType().Name}else{$null});scope='controlled native family plus mandatory real PowerShell integration; historical console-host provenance, Edge and large-data acceptance remain separate'} | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $EvidencePath 'result.json')
if ($caught) { throw $caught }; if ($cleanupError) { throw $cleanupError }
