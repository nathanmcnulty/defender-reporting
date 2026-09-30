#Requires -Version 7.0
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '', Justification = 'Cleanup cmdlet mocks preserve the actual production parameter bindings.')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Cleanup mocks only record calls and throw synthetic failures; they do not mutate external state.')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '', Justification = 'Variables are consumed by the actual AST-extracted finally and post-cleanup check.')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidOverwritingBuiltInCmdlets', '', Justification = 'Child-scope cmdlet mocks inject cleanup failures without changing the caller or real processes.')]
[CmdletBinding()]
param([string]$EchoArgument, [switch]$CaptureChild)

if ($CaptureChild) {
    [Console]::Write($EchoArgument)
    [Console]::Error.Write('bounded-error')
    return
}

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'helpers\HostedSmokeDiagnostics.ps1')

function Assert-SmokeDiagnostic {
    param([bool]$Condition, [string]$Message)
    if (-not $Condition) { throw $Message }
}

$tempRoot = Join-Path ([IO.Path]::GetTempPath()) ('smoke diagnostics spaces ' + [guid]::NewGuid().ToString('N'))
[void](New-Item -ItemType Directory -Path $tempRoot)
try {
    $secrets = @('eyJhbGciOiJIUzI1NiJ9.private.signature', 'OAuthSecret123', 'SASSecret456', 'CookieSecret789', 'BearerSecret123', 'AccountSecret123', 'TenantSecret123')
    $raw = @"
[123:456:0930/123456.789:ERROR:ssl_client_socket_impl.cc(123)] https://tenant.invalid/?sig=$($secrets[2])
Authorization: Bearer $($secrets[4])
Cookie: auth=$($secrets[3])
POST /token?client_secret=$($secrets[1])
{"access_token":"$($secrets[0])"}
AccountKey=$($secrets[5]);Server=private;Password=$($secrets[1])
C:\Users\Private User\TenantSecret123\project-metadata
Opening in existing browser session.
"@
    $safe = @(ConvertTo-HostedSmokeSafeStderr -Text $raw) -join "`n"
    foreach ($secret in $secrets + @('Private User', 'tenant.invalid', 'project-metadata', 'access_token', 'AccountKey')) {
        Assert-SmokeDiagnostic (-not $safe.Contains($secret)) 'Sanitized stderr leaked input.'
    }
    Assert-SmokeDiagnostic ($safe.Contains('category=tls example=[redacted]')) 'Known category missing.'
    Assert-SmokeDiagnostic ($safe.Contains('category=unknown example=[redacted] sha256=')) 'Unknown line must be hashed, not copied.'
    Assert-SmokeDiagnostic (@(ConvertTo-HostedSmokeSafeStderr -Text (("unknown`n") * 10000)).Count -eq 128) 'Sanitizer must be bounded.'
    Assert-SmokeDiagnostic ((Get-HostedSmokeDomState -Dom " `r`n") -eq 'empty-dom') 'Whitespace DOM must fail.'
    Assert-SmokeDiagnostic ((Get-HostedSmokeDomState -Dom '<div id="hostedDashboardSmokeProbe" data-state="error">TenantSecret123</div>') -eq 'probe-not-ready') 'Probe text must not be returned.'
    Assert-SmokeDiagnostic ((Get-HostedSmokeDomState -Dom '<div data-state="ready"></div><div id="hostedDashboardSmokeProbe" data-state="error"></div>') -eq 'probe-not-ready') 'Readiness must belong to the probe.'
    $ready = [pscustomobject]@{ state = 'ready'; forwardingHint = $false }
    $empty = [pscustomobject]@{ state = 'empty-dom'; forwardingHint = $false }
    $forwarded = [pscustomobject]@{ state = 'empty-dom'; forwardingHint = $true }
    Assert-SmokeDiagnostic ((Get-HostedSmokeOutcome -Canary $ready -Dashboard $ready) -eq 'passed') 'Successful controls misclassified.'
    Assert-SmokeDiagnostic ((Get-HostedSmokeOutcome -Canary $empty -Dashboard $empty) -eq 'headless-control-failure') 'Empty controls must not blame the dashboard.'
    Assert-SmokeDiagnostic ((Get-HostedSmokeOutcome -Canary $ready -Dashboard $empty) -eq 'dashboard-probe-failure') 'Canary/dashboard distinction lost.'
    Assert-SmokeDiagnostic ((Get-HostedSmokeOutcome -Canary $forwarded -Dashboard $empty) -eq 'command-forwarding-suspected') 'Forwarding evidence lost.'
    $privateDom = '<div id="hostedDashboardSmokeProbe" data-state="error" data-error-class="assertion" data-failure-phase="payload" data-failure-reason="payload-response">TenantSecret123 CookieSecret789</div>'
    $probeEvidence = Get-HostedSmokeProbeEvidence -Dom $privateDom
    Assert-SmokeDiagnostic ($probeEvidence.State -eq 'error' -and $probeEvidence.ErrorClass -eq 'assertion' -and $probeEvidence.Phase -eq 'payload' -and $probeEvidence.Reason -eq 'payload-response') 'Safe probe reason evidence lost.'
    $probeEvidence = Get-HostedSmokeProbeEvidence -Dom '<div id="hostedDashboardSmokeProbe" data-state="TenantSecret123" data-error-class="CookieSecret789"></div>'
    Assert-SmokeDiagnostic ($probeEvidence.State -eq 'unknown' -and $probeEvidence.ErrorClass -eq 'unavailable') 'Probe fields must be allowlisted.'
    Assert-SmokeDiagnostic ($probeEvidence.Phase -eq 'unavailable' -and $probeEvidence.Reason -eq 'unavailable') 'Unknown phase/reason must not escape.'

    $tokens = $null
    $parseErrors = $null
    $smokeAst = [Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot 'Invoke-HostedDashboardRuntimeSmoke.ps1'), [ref]$tokens, [ref]$parseErrors)
    Assert-SmokeDiagnostic ($parseErrors.Count -eq 0) 'Hosted smoke parse failed.'
    $mainTry = $smokeAst.EndBlock.Statements | Where-Object { $_ -is [Management.Automation.Language.TryStatementAst] } | Select-Object -Last 1
    $finallyText = $mainTry.Finally.Extent.Text
    $postCleanupCheck = ($smokeAst.EndBlock.Statements | Where-Object { $_ -is [Management.Automation.Language.IfStatementAst] -and $_.Extent.StartOffset -gt $mainTry.Extent.EndOffset } | Select-Object -First 1).Extent.Text
    $processCases = if ($IsWindows) { @('cim', 'termination') } else { @('unsupported') }
    foreach ($case in @('helper-throw', 'server-profile', 'provider', 'provider-primary', 'unrelated') + $processCases) {
        & {
            $profilePath = Join-Path $tempRoot 'PRIVATE_PROFILE_SECRET'
            $smokeRoot = Join-Path $tempRoot 'PRIVATE_SITE_SECRET'
            $diagnosticRunPath = Join-Path $tempRoot 'PRIVATE_DIAGNOSTICS_SECRET\missing'
            $serverJob = 'synthetic-job'
            $primaryFailure = $case -in @('helper-throw', 'unsupported', 'cim', 'termination', 'server-profile', 'provider-primary')
            $priorCleanupFailures = @()
            $outcome = if ($primaryFailure) { 'dashboard-probe-failure' } else { 'passed' }
            $setupPhase = 'dashboard-capture'
            $failureClass = if ($primaryFailure) { 'runtime' } else { $null }
            $failureLine = 1
            $ControlFixture = $true
            $extensionSessionCount = 0
            $runId = 'synthetic-run'
            $calls = [Collections.Generic.List[string]]::new()
            $retained = [Collections.Generic.List[object]]::new()
            if ($case -eq 'helper-throw') {
                function Stop-HostedSmokeProfileProcess {
                    [CmdletBinding()] param($ProfilePath)
                    throw 'PRIVATE_HELPER_SECRET C:\PRIVATE_PATH_SECRET'
                }
            }
            function Get-CimInstance {
                [CmdletBinding()] param($ClassName, $Filter)
                $calls.Add('process-enumeration')
                if ($case -eq 'cim') { throw 'PRIVATE_CIM_SECRET C:\PRIVATE_PATH_SECRET' }
                if ($case -eq 'termination') { [pscustomobject]@{ CommandLine = $profilePath; ProcessId = -1 } }
            }
            function Stop-Job {
                [CmdletBinding()] param($Job)
                $calls.Add('server-stop')
                if ($case -eq 'server-profile') { throw 'PRIVATE_SERVER_SECRET' }
            }
            function Wait-Job { [CmdletBinding()] param($Job, $Timeout) $calls.Add('server-wait') }
            function Remove-Job { [CmdletBinding()] param($Job, [switch]$Force) $calls.Add('server-remove') }
            function Test-Path {
                [CmdletBinding()] param($LiteralPath)
                $calls.Add($LiteralPath)
                return $case -eq 'server-profile' -and $LiteralPath -eq $profilePath
            }
            function Remove-Item {
                [CmdletBinding()] param($LiteralPath, [switch]$Recurse, [switch]$Force)
                $calls.Add('profile-remove')
                throw 'PRIVATE_PROFILE_SECRET'
            }
            if ($case -notin @('provider', 'provider-primary', 'unrelated')) {
                function Set-Content {
                    [CmdletBinding()] param($LiteralPath, $Encoding, [Parameter(ValueFromPipeline)]$Value)
                    process { $retained.Add(($Value | ConvertFrom-Json)) }
                }
            }
            $body = if ($case -eq 'unrelated') { "throw 'Unrelated original failure'" }
                elseif ($primaryFailure) { "throw 'Original dashboard-probe-failure'" }
                else { '' }
            $caught = [Collections.Generic.List[object]]::new()
            $streams = & {
                try { & ([scriptblock]::Create('try { ' + $body + ' } finally ' + $finallyText + "`n" + $postCleanupCheck)) -Verbose }
                catch { $caught.Add($_) }
            } *>&1 | Out-String
            $visible = $streams + (($caught | ForEach-Object { $_.ToString() }) -join "`n") + ($retained | ConvertTo-Json -Depth 5)
            foreach ($secret in @('PRIVATE_HELPER_SECRET', 'PRIVATE_CIM_SECRET', 'PRIVATE_PATH_SECRET', 'PRIVATE_SERVER_SECRET', 'PRIVATE_PROFILE_SECRET', 'PRIVATE_SITE_SECRET', 'PRIVATE_DIAGNOSTICS_SECRET', $tempRoot, 'DirectoryNotFoundException', 'Set-Content:')) {
                Assert-SmokeDiagnostic (-not $visible.Contains($secret)) 'Cleanup output leaked private exception/path/provider stack.'
            }
            foreach ($expected in @('server-stop', 'server-wait', 'server-remove', $profilePath, $smokeRoot)) {
                $phaseLabel = if ($expected -eq $profilePath) { 'profile' } elseif ($expected -eq $smokeRoot) { 'site' } else { $expected }
                Assert-SmokeDiagnostic ($calls.Contains($expected)) "Cleanup continuation failed: case=$case phase=$phaseLabel."
            }
            if ($primaryFailure) {
                Assert-SmokeDiagnostic ($caught.Count -eq 1 -and $caught[0].Exception.Message -eq 'Original dashboard-probe-failure') 'Cleanup masked the meaningful original failure.'
            }
            if ($case -eq 'unrelated') {
                Assert-SmokeDiagnostic ($caught.Count -eq 1 -and $caught[0].Exception.Message -eq 'Unrelated original failure') 'Cleanup masked an unrelated original failure.'
            }
            if ($case -like 'provider*' -or $case -eq 'unrelated') {
                Assert-SmokeDiagnostic ($streams.Contains('diagnostic-write-failure')) 'Actual missing-directory provider failure was not safely classified.'
                if ($case -eq 'provider') { Assert-SmokeDiagnostic ($caught.Count -eq 1 -and $caught[0].Exception.Message -like 'Hosted smoke cleanup/diagnostic failure;*') 'Standalone diagnostic write failure was not safe.' }
            }
            else {
                Assert-SmokeDiagnostic ($retained.Count -eq 1 -and $retained[0].outcome -eq 'cleanup-failure' -and $retained[0].originalOutcome -eq 'dashboard-probe-failure') 'Cleanup result/original outcome missing.'
                if ($case -in @('helper-throw', 'unsupported', 'cim', 'termination')) { Assert-SmokeDiagnostic (-not $retained[0].processCleanupConfirmed) 'Unknown/remaining owned processes falsely confirmed clean.' }
                if ($case -eq 'unsupported') { Assert-SmokeDiagnostic (-not $calls.Contains('process-enumeration')) 'Unsupported platform must not enumerate Windows processes.' }
                if ($case -in @('cim', 'termination')) { Assert-SmokeDiagnostic ($calls.Contains('process-enumeration')) 'Windows cleanup must exercise actual helper enumeration.' }
                $expectedCode = switch ($case) { 'helper-throw' { 'process-cleanup-failure' } 'unsupported' { 'process-enumeration-unsupported' } 'cim' { 'process-enumeration-failure' } 'termination' { 'process-termination-failure' } 'server-profile' { 'profile-removal-failure' } }
                Assert-SmokeDiagnostic ($retained[0].cleanupFailures -contains $expectedCode) 'Fixed cleanup failure code missing.'
            }
        }
    }

    foreach ($case in @(
        @{ Started = $true; TimedOut = $false; ExitCode = 0; Dom = ''; Truncated = $false; Incomplete = $false; Expected = 'empty-dom' },
        @{ Started = $true; TimedOut = $true; ExitCode = 1; Dom = ''; Truncated = $false; Incomplete = $false; Expected = 'timeout' },
        @{ Started = $true; TimedOut = $false; ExitCode = 7; Dom = ''; Truncated = $false; Incomplete = $false; Expected = 'nonzero-exit' },
        @{ Started = $false; TimedOut = $false; ExitCode = $null; Dom = ''; Truncated = $false; Incomplete = $false; Expected = 'no-process' },
        @{ Started = $true; TimedOut = $false; ExitCode = 0; Dom = $privateDom; Truncated = $false; Incomplete = $false; Expected = 'probe-not-ready' },
        @{ Started = $true; TimedOut = $false; ExitCode = 0; Dom = $privateDom; Truncated = $true; Incomplete = $false; Expected = 'dom-capture-limit' },
        @{ Started = $true; TimedOut = $false; ExitCode = 0; Dom = $privateDom; Truncated = $false; Incomplete = $true; Expected = 'incomplete-stream' }
    )) {
        $runner = {
            [pscustomobject]@{
                Started = $case.Started; TimedOut = $case.TimedOut; ExitCode = $case.ExitCode; DrainIncomplete = $case.Incomplete
                Stdout = [pscustomobject]@{ Text = $case.Dom; Bytes = [Text.Encoding]::UTF8.GetByteCount($case.Dom); Truncated = $case.Truncated }
                Stderr = [pscustomobject]@{ Text = $raw; Bytes = [Text.Encoding]::UTF8.GetByteCount($raw); Truncated = $false }
            }
        }
        $result = Invoke-HostedSmokeAttempt -Executable 'not-launched' -Arguments @('secret-url') -WaitMilliseconds 100 -Kind dashboard -RunPath $tempRoot -ProcessRunner $runner
        Assert-SmokeDiagnostic ($result.state -eq $case.Expected) 'Injected process classification failed.'
        Assert-SmokeDiagnostic ($result.stdoutBytes -eq [Text.Encoding]::UTF8.GetByteCount($case.Dom) -and $result.stderrBytes -gt 0 -and $result.exitCode -eq $case.ExitCode) 'Byte/exit evidence lost.'
        $persisted = (Get-ChildItem -LiteralPath $tempRoot -File | Get-Content -Raw) -join "`n"
        foreach ($secret in $secrets + @('secret-url', 'Private User', 'tenant.invalid')) {
            Assert-SmokeDiagnostic (-not $persisted.Contains($secret)) 'Artifacts leaked input.'
        }
    }

    Initialize-HostedSmokeCapture
    $pwshPath = (Get-Process -Id $PID).Path
    $capture = [HostedSmoke.Capture]::Run($pwshPath, @('-NoProfile', '-File', $PSCommandPath, '-CaptureChild', '-EchoArgument', $tempRoot), 10000)
    Assert-SmokeDiagnostic ($capture.Started -and $capture.ExitCode -eq 0 -and $capture.Stdout.Text -eq $tempRoot) 'ArgumentList did not preserve spaces.'
    Assert-SmokeDiagnostic ($capture.Stderr.Text -eq 'bounded-error') 'Concurrent stderr drain failed.'
    $capture = [HostedSmoke.Capture]::Run($pwshPath, @('-NoProfile', '-Command', '[Console]::Error.Write(("x" * 100000)); [Console]::Write("ok")'), 10000)
    Assert-SmokeDiagnostic ($capture.Stderr.Bytes -eq 100000 -and $capture.Stderr.Truncated -and $capture.Stderr.Text.Length -eq 65536 -and $capture.Stdout.Text -eq 'ok') 'Stream capture bounds failed.'
    $capture = [HostedSmoke.Capture]::Run($pwshPath, @('-NoProfile', '-Command', 'while ($true) {}'), 100)
    Assert-SmokeDiagnostic ($capture.TimedOut) 'Process timeout did not stop the child.'
    $capture = [HostedSmoke.Capture]::Run((Join-Path $tempRoot 'missing executable'), @(), 100)
    Assert-SmokeDiagnostic (-not $capture.Started) 'Launch failure must return no-process.'
    Write-Output 'Hosted smoke diagnostics regressions passed (actual-helper/full-finally cleanup, real missing-directory provider privacy, original failure preservation, injected outcomes, quoting, bounded concurrent drains, timeout, launch failure).'
}
finally {
    Remove-Item -LiteralPath $tempRoot -Recurse -Force
}