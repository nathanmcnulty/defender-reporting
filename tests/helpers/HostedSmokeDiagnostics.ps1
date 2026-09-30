function Initialize-HostedSmokeCapture {
    [CmdletBinding()]
    param()

    if ('HostedSmoke.Capture' -as [type]) { return }
    Add-Type -TypeDefinition @'
using System;
using System.Diagnostics;
using System.IO;
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

function Stop-HostedSmokeProfileProcess {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Only stops disposable smoke processes with the unique run-owned profile path.')]
    [CmdletBinding()]
    param([string]$ProfilePath)

    $failures = [Collections.Generic.List[string]]::new()
    if (-not $IsWindows) { return [pscustomobject]@{ Confirmed = $false; Failures = @('process-enumeration-unsupported') } }
    try {
        $owned = @(Get-CimInstance Win32_Process -Filter "Name = 'msedge.exe'" -ErrorAction Stop | Where-Object {
            $_.CommandLine -and $_.CommandLine.Contains($ProfilePath, [StringComparison]::OrdinalIgnoreCase)
        })
    }
    catch { return [pscustomobject]@{ Confirmed = $false; Failures = @('process-enumeration-failure') } }
    foreach ($entry in $owned) {
        $process = $null
        try {
            $process = Get-Process -Id $entry.ProcessId -ErrorAction Stop
            if ($null -ne $process) {
                $process.Kill($true)
                if (-not $process.WaitForExit(5000)) { $failures.Add('process-termination-timeout') }
            }
        }
        catch { $failures.Add('process-termination-failure') }
        finally {
            if ($null -ne $process) {
                try { $process.Dispose() } catch { $failures.Add('process-disposal-failure') }
            }
        }
    }
    $confirmed = $false
    try {
        $remaining = @(Get-CimInstance Win32_Process -Filter "Name = 'msedge.exe'" -ErrorAction Stop | Where-Object {
            $_.CommandLine -and $_.CommandLine.Contains($ProfilePath, [StringComparison]::OrdinalIgnoreCase)
        })
        $confirmed = $remaining.Count -eq 0
        if (-not $confirmed) { $failures.Add('owned-process-remains') }
    }
    catch { $failures.Add('process-verification-failure') }
    return [pscustomobject]@{ Confirmed = $confirmed; Failures = $failures.ToArray() }
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