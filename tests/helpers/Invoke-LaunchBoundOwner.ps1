# Sole-client JSONL adapter. Browser bytes never enter protocol stdout.
# Unexpected input/EOF closes the exclusive job, but produces no clean completion receipt.
[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot 'LaunchBoundOwner.ps1')
. (Join-Path $PSScriptRoot 'HostedSmokeDiagnostics.ps1')
Initialize-LaunchBoundOwner
$owner = $null
$nonce = [guid]::NewGuid().ToString('N') + [guid]::NewGuid().ToString('N')
$runId = $null; $profilePath = $null; $sequence = 0
function Write-OwnerReply($Reply) { [Console]::Out.WriteLine(($Reply | ConvertTo-Json -Compress -Depth 8)); [Console]::Out.Flush() }
function Read-OwnerRequest {
    $builder = [Text.StringBuilder]::new()
    while ($true) {
        $character = [Console]::In.Read()
        if ($character -lt 0) { return $null }
        if ($character -eq 10) { break }
        if ($builder.Length -ge 65536) { throw 'Oversize protocol line.' }
        [void]$builder.Append([char]$character)
    }
    $document = [Text.Json.JsonDocument]::Parse($builder.ToString())
    try {
        if ($document.RootElement.ValueKind -ne [Text.Json.JsonValueKind]::Object) { throw 'Invalid protocol.' }
        $names = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
        foreach ($property in $document.RootElement.EnumerateObject()) { if (-not $names.Add($property.Name)) { throw 'Duplicate key.' } }
    }
    finally { $document.Dispose() }
    return $builder.ToString() | ConvertFrom-Json -AsHashtable -Depth 8
}
try {
    Write-OwnerReply @{ v = 1; nonce = $nonce; ready = $true }
    while ($null -ne ($request = Read-OwnerRequest)) {
        $allowed = @('v','nonce','runId','profile','seq','command')
        if ($request.command -ceq 'start') { $allowed += @('executable','arguments') }
        if (@($request.Keys | Where-Object { $_ -cnotin $allowed }).Count -gt 0 -or @($allowed | Where-Object { -not $request.ContainsKey($_) }).Count -gt 0) { throw 'Invalid fields.' }
        if ($request.command -isnot [string] -or $request.runId -isnot [string] -or $request.profile -isnot [string] -or $request.nonce -isnot [string] -or ($request.v -isnot [int] -and $request.v -isnot [long]) -or $request.v -ne 1 -or $request.nonce -cne $nonce -or ($request.seq -isnot [long] -and $request.seq -isnot [int]) -or $request.seq -ne $sequence + 1) { throw 'Invalid binding.' }
        $sequence++
        $commandClock = [Diagnostics.Stopwatch]::StartNew()
        if ($request.command -ceq 'start') {
            if ($null -ne $owner -or $request.runId -cnotmatch '^[a-f0-9]{32}$' -or $request.profile -isnot [string] -or -not [IO.Path]::IsPathFullyQualified($request.profile) -or $request.executable -isnot [string] -or $request.arguments -isnot [array] -or $request.arguments.Count -gt 128 -or @($request.arguments | Where-Object { $_ -isnot [string] }).Count -gt 0) { throw 'Invalid launch.' }
            $runId = $request.runId; $profilePath = $request.profile
            $owner = [LaunchBound.JobOwner]::new($runId, $profilePath)
            $value = $owner.Start($request.executable, [string[]]$request.arguments, $profilePath)
        }
        else {
            if ($null -eq $owner -or $request.runId -cne $runId -or $request.profile -cne $profilePath) { throw 'Wrong run.' }
            switch -CaseSensitive ($request.command) {
                'query' { $value = $owner.Query(4500) }
                'terminate' { $value = $owner.Stop(5000) }
                'dispose' {
                    $value = $owner.Query(4500)
                    if (-not $value.Confirmed) { throw 'Unconfirmed close.' }
                }
                default { throw 'Invalid command.' }
            }
        }
        Assert-LaunchBoundProfileContained -Owner $owner -ProfilePath $profilePath
        $budget = if ($request.command -cin @('start','terminate')) { 15000 } else { 5000 }
        if ($commandClock.ElapsedMilliseconds -ge $budget) { throw 'Late owner result.' }
        Write-OwnerReply @{ v = 1; nonce = $nonce; runId = $runId; profile = $profilePath; seq = $sequence; command = $request.command; ok = $true; value = $value }
        if ($request.command -ceq 'dispose') { break }
    }
}
catch {
    $cause = $_.Exception.GetBaseException()
    $nativeCode = if ($cause -is [ComponentModel.Win32Exception]) { $cause.NativeErrorCode } else { $null }
    Write-OwnerReply @{ v = 1; nonce = $nonce; runId = $runId; profile = $profilePath; seq = $sequence; ok = $false; category = 'owner-operation'; nativeErrorCode = $nativeCode; setup = $(if ($null -ne $owner) { $owner.Setup } else { $null }) }
    exit 1
}
finally { if ($null -ne $owner) { $owner.Dispose() } }
