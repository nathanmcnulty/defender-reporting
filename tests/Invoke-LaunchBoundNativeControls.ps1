#Requires -Version 7.0
[CmdletBinding()]
param([Parameter(Mandatory)][string]$PythonPath, [Parameter(Mandatory)][string]$EvidencePath)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
if (-not $IsWindows) { throw 'Windows native control required.' }
if (Test-Path -LiteralPath $EvidencePath) { throw 'Fresh evidence destination required.' }
[void](New-Item -ItemType Directory -Path $EvidencePath)
$fixture = Join-Path $PSScriptRoot 'helpers/launch-bound-fixture.py'
Add-Type -Path @((Join-Path $PSScriptRoot 'helpers/LaunchBoundJob.cs'), (Join-Path $PSScriptRoot 'helpers/LaunchBoundNativeControls.cs'))
$neighbor = [Diagnostics.Process]::new()
$neighborStarted = $false
$caught = $null; $cleanupError = $null; $cases = @(); $neighborSurvived = $false
try {
    $neighbor.StartInfo = [Diagnostics.ProcessStartInfo]::new($PythonPath)
    $neighbor.StartInfo.UseShellExecute = $false; $neighbor.StartInfo.CreateNoWindow = $true
    $neighbor.StartInfo.ArgumentList.Add('-c'); $neighbor.StartInfo.ArgumentList.Add('import time; time.sleep(180)')
    if (-not $neighbor.Start()) { throw 'Neighbor fixture failed.' }
    $neighborStarted = $true
    $heldNeighbor = $neighbor.SafeHandle
    if ($heldNeighbor.IsInvalid -or $heldNeighbor.IsClosed) { throw 'Neighbor handle unavailable.' }
    $cases = [LaunchBound.NativeControls]::Run($PythonPath, $fixture, $EvidencePath, $neighbor.Id)
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
[ordered]@{status=$status;cases=@($cases);neighborSurvived=$neighborSurvived;neighborCleanupConfirmed=$null -eq $cleanupError;exceptionType=$(if($caught){$caught.Exception.GetType().Name}else{$null});cleanupExceptionType=$(if($cleanupError){$cleanupError.Exception.GetType().Name}else{$null});scope='native nested-job mechanism controls, not Edge or large-data acceptance'} | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $EvidencePath 'result.json')
if ($caught) { throw $caught }; if ($cleanupError) { throw $cleanupError }
