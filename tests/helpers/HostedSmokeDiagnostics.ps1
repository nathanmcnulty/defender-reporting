function Initialize-HostedSmokeCapture {
    [CmdletBinding()]
    param()

    if ('HostedSmoke.Capture' -as [type]) { return }
    Add-Type -TypeDefinition @'
using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
namespace HostedSmoke {
    public sealed class StreamResult {
        public long Bytes;
        public string Text;
        public bool Truncated;
    }
    public sealed class Result {
        public bool Started;
        public bool TimedOut;
        public bool DrainIncomplete;
        public int? ExitCode;
        public StreamResult Stdout = new StreamResult { Text = "" };
        public StreamResult Stderr = new StreamResult { Text = "" };
    }
    public static class Capture {
        [DllImport("shell32.dll", SetLastError = true)]
        static extern IntPtr CommandLineToArgvW([MarshalAs(UnmanagedType.LPWStr)] string command, out int count);
        [DllImport("kernel32.dll")] static extern IntPtr LocalFree(IntPtr pointer);
        static string NormalizeProfile(string profile) {
            if (String.IsNullOrEmpty(profile) || !Path.IsPathFullyQualified(profile)) return null;
            return Path.GetFullPath(profile.Replace('/', '\\')).TrimEnd('\\');
        }
        public static bool OwnsProfile(string command, string profile) {
            var expected = NormalizeProfile(profile);
            if (expected == null || String.IsNullOrEmpty(command)) return false;
            int count;
            var pointer = CommandLineToArgvW(command, out count);
            if (pointer == IntPtr.Zero) throw new InvalidOperationException();
            try {
                string value = null;
                int matches = 0;
                for (int i = 1; i < count; i++) {
                    var argument = Marshal.PtrToStringUni(Marshal.ReadIntPtr(pointer, i * IntPtr.Size));
                    if (argument.StartsWith("--user-data-dir=", StringComparison.Ordinal)) { value = argument.Substring(16); matches++; }
                    else if (argument == "--user-data-dir") {
                        if (++i >= count) return false;
                        value = Marshal.PtrToStringUni(Marshal.ReadIntPtr(pointer, i * IntPtr.Size)); matches++;
                    }
                }
                return matches == 1 && String.Equals(NormalizeProfile(value), expected, StringComparison.OrdinalIgnoreCase);
            } finally { LocalFree(pointer); }
        }
        static async Task<StreamResult> Drain(Stream stream, int limit, CancellationToken token) {
            var buffer = new byte[8192];
            using (var retained = new MemoryStream()) {
                long total = 0;
                try {
                    int count;
                    while ((count = await stream.ReadAsync(buffer, 0, buffer.Length, token)) > 0) {
                        total += count;
                        int keep = Math.Min(count, limit - (int)retained.Length);
                        if (keep > 0) retained.Write(buffer, 0, keep);
                    }
                } catch (OperationCanceledException) { }
                  catch (IOException) { }
                  catch (ObjectDisposedException) { }
                return new StreamResult {
                    Bytes = total, Text = Encoding.UTF8.GetString(retained.ToArray()),
                    Truncated = total > retained.Length
                };
            }
        }
        public static Result Run(string executable, string[] arguments, int milliseconds) {
            var result = new Result();
            using (var process = new Process())
            using (var cancel = new CancellationTokenSource()) {
                process.StartInfo = new ProcessStartInfo(executable) {
                    UseShellExecute = false, RedirectStandardOutput = true,
                    RedirectStandardError = true, CreateNoWindow = true
                };
                foreach (var argument in arguments) process.StartInfo.ArgumentList.Add(argument);
                try { result.Started = process.Start(); } catch { return result; }
                if (!result.Started) return result;
                var stdout = Drain(process.StandardOutput.BaseStream, 64 * 1024 * 1024, cancel.Token);
                var stderr = Drain(process.StandardError.BaseStream, 64 * 1024, cancel.Token);
                if (!process.WaitForExit(milliseconds)) {
                    result.TimedOut = true;
                    try { process.Kill(true); } catch { }
                    process.WaitForExit(5000);
                }
                if (process.HasExited) result.ExitCode = process.ExitCode;
                var drains = Task.WhenAll(stdout, stderr);
                if (!drains.Wait(5000)) {
                    result.DrainIncomplete = true;
                    cancel.Cancel();
                    process.StandardOutput.Close();
                    process.StandardError.Close();
                }
                if (drains.Wait(5000)) {
                    result.Stdout = stdout.Result;
                    result.Stderr = stderr.Result;
                }
                return result;
            }
        }
    }
}
'@
}

function ConvertTo-HostedSmokeSafeStderr {
    [CmdletBinding()]
    param([AllowEmptyString()][string]$Text)

    $boundedText = $Text.Substring(0, [math]::Min(65536, $Text.Length))
    $records = [System.Collections.Generic.List[string]]::new()
    foreach ($line in ($boundedText -split '\r?\n')) {
        if ([string]::IsNullOrWhiteSpace($line)) { continue }
        if ($records.Count -ge 128) { break }
        $category = 'unknown'
        if ($line -match '^\[\d+:\d+:\d+[/\d.]*:(?:ERROR|WARNING|INFO):(?<Source>[a-z_]+)\.(?:cc|h)\(\d+\)\]') {
            $category = switch ($Matches.Source) {
                'process_singleton' { 'command-forwarding' }
                'sandbox_win' { 'sandbox' }
                'gpu_process_host' { 'gpu' }
                'ssl_client_socket_impl' { 'tls' }
                'crashpad_client_win' { 'crash-handler' }
                default { 'chromium-log' }
            }
        }
        elseif ($line -ceq 'Opening in existing browser session.') { $category = 'command-forwarding' }
        $hash = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([Text.Encoding]::UTF8.GetBytes($line))).ToLowerInvariant()
        $records.Add("category=$category example=[redacted] sha256=$hash")
    }
    return $records.ToArray()
}

function Get-HostedSmokeDomState {
    [CmdletBinding()]
    param([AllowEmptyString()][string]$Dom, [switch]$Canary)

    if ([string]::IsNullOrWhiteSpace($Dom)) { return 'empty-dom' }
    if ($Canary) {
        if ($Dom -match 'data-hosted-smoke-canary="ready"') { return 'ready' }
        return 'canary-missing'
    }
    $probe = [regex]::Match($Dom, '<div\b[^>]*\bid="hostedDashboardSmokeProbe"[^>]*>', 'IgnoreCase')
    if (-not $probe.Success) { return 'probe-missing' }
    if ($probe.Value -notmatch '\bdata-state="ready"') { return 'probe-not-ready' }
    if ($Dom -notmatch 'id="statsSummary"' -or $Dom -notmatch 'id="reportSelector"') { return 'dashboard-shell-missing' }
    if ($probe.Value -notmatch 'data-delivery-mode="split-assets"') { return 'delivery-mode-mismatch' }
    if ($probe.Value -notmatch 'data-runtime-checks="[^"<>]*report-switching[^"<>]*filter-popover[^"<>]*"') { return 'runtime-checks-missing' }
    if ($probe.Value -notmatch 'data-payload-rows="[1-9]\d*"') { return 'payload-missing' }
    return 'ready'
}

function Get-HostedSmokeOutcome {
    [CmdletBinding()]
    param($Canary, $Dashboard)

    if ($Canary.forwardingHint -or $Dashboard.forwardingHint) { return 'command-forwarding-suspected' }
    if ($Canary.state -ne 'ready') { return 'headless-control-failure' }
    if ($Dashboard.state -ne 'ready') { return 'dashboard-probe-failure' }
    return 'passed'
}

function Get-HostedSmokeProbeEvidence {
    [CmdletBinding()]
    param([AllowEmptyString()][string]$Dom)

    $state = 'unavailable'
    $errorClass = 'unavailable'
    $phase = 'unavailable'
    $reason = 'unavailable'
    $probe = [regex]::Match($Dom, '<div\b[^>]*\bid="hostedDashboardSmokeProbe"[^>]*>', 'IgnoreCase')
    if ($probe.Success) {
        $state = 'unknown'
        if ($probe.Value -match '\bdata-state="(?<State>ready|error|timeout)"') { $state = $Matches.State }
        if ($probe.Value -match '\bdata-error-class="(?<Class>timeout|assertion|operation|none)"') { $errorClass = $Matches.Class }
        if ($probe.Value -match '\bdata-failure-phase="(?<Phase>wait-ready|payload|inflate|count|report-switch|filter-popover|complete)"') { $phase = $Matches.Phase }
        if ($probe.Value -match '\bdata-failure-reason="(?<Reason>readiness-timeout|payload-config|payload-mode|payload-url|payload-fetch|payload-response|payload-read|inflate-runtime|inflate-operation|inflate-parse|payload-count|report-selector|report-option|report-section|report-dispatch|report-activation-timeout|report-active-count|report-active-id|report-validation|filter-pill|filter-shell|filter-open|filter-open-timeout|filter-body|filter-apply|filter-close|filter-close-timeout|none)"') { $reason = $Matches.Reason }
    }
    return [pscustomobject]@{ State = $state; ErrorClass = $errorClass; Phase = $phase; Reason = $reason }
}

function Get-HostedSmokeOwnedSnapshot {
    param([string]$ProfilePath, [object[]]$Known = @())
    $all = @(Get-CimInstance Win32_Process -ErrorAction Stop)
    $byId = @{}
    foreach ($item in $all) { $byId[[int]$item.ProcessId] = $item }
    $records = @{}
    foreach ($item in $all) {
        if ($item.Name -eq 'msedge.exe' -and [HostedSmoke.Capture]::OwnsProfile($item.CommandLine, $ProfilePath)) {
            if ($item.CreationDate -isnot [datetime]) { throw 'Unknown owned identity.' }
            $records[[int]$item.ProcessId] = [pscustomobject]@{ Pid = [int]$item.ProcessId; Created = $item.CreationDate; RootPid = [int]$item.ProcessId; RootCreated = $item.CreationDate }
        }
    }
    # Preserve accountability for known children after their root exits or its PID is reused.
    foreach ($previous in $Known) {
        $item = $byId[$previous.Pid]
        if ($null -ne $item) {
            if ($item.CreationDate -isnot [datetime]) { throw 'Unknown owned identity.' }
            if ($item.CreationDate -eq $previous.Created) { $records[$previous.Pid] = $previous }
        }
    }
    do {
        $added = $false
        foreach ($item in $all) {
            $parent = $records[[int]$item.ParentProcessId]
            if ($null -eq $parent -or $records.ContainsKey([int]$item.ProcessId)) { continue }
            if ($item.CreationDate -isnot [datetime]) { throw 'Unknown owned identity.' }
            if ($parent.Created -le $item.CreationDate) {
                $records[[int]$item.ProcessId] = [pscustomobject]@{ Pid = [int]$item.ProcessId; Created = $item.CreationDate; RootPid = $parent.RootPid; RootCreated = $parent.RootCreated }
                $added = $true
            }
        }
    } while ($added)
    return [pscustomobject]@{ Records = @($records.Values); ById = $byId }
}

function Stop-HostedSmokeProfileProcess {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Only stops freshly verified disposable smoke identities.')]
    [CmdletBinding()]
    param([string]$ProfilePath, [switch]$AccountingIncomplete)

    $failures = [Collections.Generic.List[string]]::new()
    $diagnostics = [Collections.Generic.List[string]]::new()
    if (-not $IsWindows) { return [pscustomobject]@{ Confirmed = $false; Failures = @('process-enumeration-unsupported'; if ($AccountingIncomplete) { 'process-accounting-incomplete' }); Diagnostics = @() } }
    try {
        if (-not [IO.Path]::IsPathFullyQualified($ProfilePath)) { throw 'Invalid profile.' }
        Initialize-HostedSmokeCapture
        $snapshot = Get-HostedSmokeOwnedSnapshot -ProfilePath $ProfilePath
    }
    catch { return [pscustomobject]@{ Confirmed = $false; Failures = @('process-enumeration-failure'; if ($AccountingIncomplete) { 'process-accounting-incomplete' }); Diagnostics = @() } }
    $known = $snapshot.Records
    $cleanupClock = [Diagnostics.Stopwatch]::StartNew()
    foreach ($entry in @($known | Sort-Object @{ Expression = { $_.Pid -eq $_.RootPid } }, @{ Expression = 'Created'; Descending = $true })) {
        if ($cleanupClock.ElapsedMilliseconds -ge 5000) { $failures.Add('process-termination-timeout'); break }
        $process = $null
        try {
            $fresh = @(Get-CimInstance Win32_Process -Filter "ProcessId=$($entry.Pid) OR ProcessId=$($entry.RootPid)" -ErrorAction Stop)
            $current = @($fresh | Where-Object { $_.ProcessId -eq $entry.Pid })
            if ($current.Count -eq 0) { $diagnostics.Add('process-exited-before-termination'); continue }
            if ($current.Count -ne 1 -or $current[0].CreationDate -isnot [datetime]) { $failures.Add('process-identity-unverified'); continue }
            if ($current[0].CreationDate -ne $entry.Created) { $diagnostics.Add('process-pid-reused'); continue }
            $root = @($fresh | Where-Object { $_.ProcessId -eq $entry.RootPid })
            if ($root.Count -gt 0 -and ($root.Count -ne 1 -or $root[0].CreationDate -ne $entry.RootCreated -or -not [HostedSmoke.Capture]::OwnsProfile($root[0].CommandLine, $ProfilePath))) {
                $failures.Add('process-identity-unverified'); continue
            }
            $process = Get-Process -Id $entry.Pid -ErrorAction SilentlyContinue
            if ($null -eq $process) {
                $remaining = @(Get-CimInstance Win32_Process -Filter "ProcessId=$($entry.Pid)" -ErrorAction Stop)
                if (@($remaining | Where-Object { $_.CreationDate -eq $entry.Created }).Count -gt 0) { $failures.Add('process-identity-unverified') }
                else { $diagnostics.Add('process-exited-before-termination') }
                continue
            }
            if ([Math]::Abs($process.StartTime.ToUniversalTime().Ticks - $entry.Created.ToUniversalTime().Ticks) -ge 10000) { $failures.Add('process-identity-unverified'); continue }
            # Kill only this verified handle; tree-kill can race or include unverified descendants.
            try { $process.Kill() }
            catch {
                if (-not $process.HasExited) { throw }
                $diagnostics.Add('process-exited-during-termination')
            }
            $remainingMilliseconds = [int][Math]::Max(0, 5000 - $cleanupClock.ElapsedMilliseconds)
            if (-not $process.WaitForExit($remainingMilliseconds)) { $failures.Add('process-termination-timeout') }
        }
        catch {
            $cause = $_.Exception.GetBaseException()
            if ($cause -is [UnauthorizedAccessException] -or ($cause -is [ComponentModel.Win32Exception] -and $cause.NativeErrorCode -eq 5)) { $failures.Add('process-access-denied') }
            else { $failures.Add('process-termination-failure') }
        }
        finally {
            if ($null -ne $process) {
                try { $process.Dispose() } catch { $failures.Add('process-disposal-failure') }
            }
        }
    }
    $confirmed = $false
    $finalSnapshotTaken = $false
    try {
        do {
            if ($finalSnapshotTaken -and $cleanupClock.ElapsedMilliseconds -ge 5000) { break }
            $finalSnapshotTaken = $true
            $snapshot = Get-HostedSmokeOwnedSnapshot -ProfilePath $ProfilePath -Known $known
            $known = $snapshot.Records
            if ($known.Count -eq 0) { $confirmed = $true; break }
            $remainingMilliseconds = [int][Math]::Max(0, 5000 - $cleanupClock.ElapsedMilliseconds)
            if ($remainingMilliseconds -eq 0) { break }
            Start-Sleep -Milliseconds ([Math]::Min(100, $remainingMilliseconds))
        } while ($true)
        if (-not $confirmed) { $failures.Add('owned-process-remains') }
    }
    catch { $failures.Add('process-verification-failure') }
    if ($AccountingIncomplete) { $confirmed = $false; $failures.Add('process-accounting-incomplete') }
    return [pscustomobject]@{ Confirmed = $confirmed; Failures = @($failures | Select-Object -Unique); Diagnostics = @($diagnostics | Select-Object -Unique) }
}

function Invoke-HostedSmokeAttempt {
    [CmdletBinding()]
    param(
        [string]$Executable,
        [string[]]$Arguments,
        [int]$WaitMilliseconds,
        [ValidateSet('canary', 'dashboard')][string]$Kind,
        [string]$RunPath,
        [scriptblock]$ProcessRunner = {
            param($App, $Flags, $Wait)
            Initialize-HostedSmokeCapture
            [HostedSmoke.Capture]::Run($App, $Flags, $Wait)
        }
    )

    $capture = & $ProcessRunner $Executable $Arguments $WaitMilliseconds
    $safeStderr = @(ConvertTo-HostedSmokeSafeStderr -Text $capture.Stderr.Text)
    $probeEvidence = Get-HostedSmokeProbeEvidence -Dom $capture.Stdout.Text
    $state = if (-not $capture.Started) { 'no-process' }
        elseif ($capture.TimedOut) { 'timeout' }
        elseif ($capture.DrainIncomplete) { 'incomplete-stream' }
        elseif ($capture.ExitCode -ne 0) { 'nonzero-exit' }
        elseif ($capture.Stdout.Truncated) { 'dom-capture-limit' }
        else { Get-HostedSmokeDomState -Dom $capture.Stdout.Text -Canary:($Kind -eq 'canary') }
    $record = [ordered]@{
        kind = $Kind
        state = $state
        started = [bool]$capture.Started
        exitCode = $capture.ExitCode
        stdoutBytes = [long]$capture.Stdout.Bytes
        stderrBytes = [long]$capture.Stderr.Bytes
        stdoutTruncated = [bool]$capture.Stdout.Truncated
        stderrTruncated = [bool]$capture.Stderr.Truncated
        drainIncomplete = [bool]$capture.DrainIncomplete
        forwardingHint = [bool](@($safeStderr | Where-Object { $_ -like 'category=command-forwarding *' }).Count)
        probeState = $probeEvidence.State
        probeErrorClass = $probeEvidence.ErrorClass
        probePhase = $probeEvidence.Phase
        probeReason = $probeEvidence.Reason
        flags = @('--headless=new', '--disable-gpu', '--disable-extensions', '--no-first-run', '--no-default-browser-check', '--disable-background-networking', '--user-data-dir=[isolated]', '--virtual-time-budget=[bounded]', '--dump-dom')
    }
    $record | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $RunPath "$Kind.json") -Encoding utf8
    $safeStderr | Set-Content -LiteralPath (Join-Path $RunPath "$Kind.stderr.sanitized.log") -Encoding utf8
    $capture.Stdout.Text = ''
    $capture.Stderr.Text = ''
    return [pscustomobject]$record
}