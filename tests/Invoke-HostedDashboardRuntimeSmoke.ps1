#Requires -Version 7.0

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [ValidateScript({
        if (-not (Test-Path -LiteralPath $_ -PathType Leaf)) {
            throw 'Dashboard HTML file does not exist.'
        }
        return $true
    })]
    [string]$DashboardPath,

    [Parameter(Mandatory = $false)]
    [string]$EdgePath,

    [Parameter(Mandatory = $false)]
    [int]$Port = 0,

    [Parameter(Mandatory = $false)]
    [ValidateRange(5, 300)]
    [int]$TimeoutSeconds = 45,

    [Parameter(Mandatory = $false)]
    [string]$DiagnosticsPath,

    [Parameter(Mandatory = $false)]
    [switch]$ControlFixture,

    [Parameter(Mandatory = $false)]
    [switch]$AllowSkip
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'helpers\HostedSmokeDiagnostics.ps1')

function Get-FreeTcpPort {
    [CmdletBinding()]
    [OutputType([int])]
    param()

    $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
    try {
        $listener.Start()
        return [int]$listener.LocalEndpoint.Port
    }
    finally {
        $listener.Stop()
    }
}

function Resolve-EdgeExecutablePath {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $false)]
        [string]$RequestedPath
    )

    if (-not [string]::IsNullOrWhiteSpace($RequestedPath)) {
        if (Test-Path -LiteralPath $RequestedPath -PathType Leaf) {
            return [System.IO.Path]::GetFullPath($RequestedPath)
        }

        throw 'Requested Microsoft Edge executable was not found.'
    }

    $candidateRoots = @(
        ${env:ProgramFiles(x86)}
        $env:ProgramFiles
        $env:LocalAppData
    ) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }

    $candidates = @($candidateRoots | ForEach-Object { Join-Path $_ 'Microsoft\Edge\Application\msedge.exe' })

    foreach ($candidate in $candidates) {
        if (Test-Path -LiteralPath $candidate -PathType Leaf) {
            return [System.IO.Path]::GetFullPath($candidate)
        }
    }

    $command = Get-Command -Name 'msedge.exe' -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($command -and (Test-Path -LiteralPath $command.Source -PathType Leaf)) {
        return [System.IO.Path]::GetFullPath($command.Source)
    }

    return $null
}

function Start-StaticHttpServer {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Starts a temporary local HTTP listener used only for a smoke test.')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseUsingScopeModifierInNewRunspaces', '', Justification = 'ThreadJob arguments are passed through param() inside the script block.')]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$RootPath,

        [Parameter(Mandatory = $true)]
        [string]$IndexFileName,

        [Parameter(Mandatory = $true)]
        [int]$ListenPort
    )

    return Start-ThreadJob -Name 'HostedDashboardSmokeHttpServer' -ArgumentList $RootPath, $IndexFileName, $ListenPort -ScriptBlock {
        param($ServerRootPath, $ServerIndexFileName, $ServerPort)

        $ErrorActionPreference = 'Stop'
        $listener = [System.Net.HttpListener]::new()
        $listener.Prefixes.Add("http://127.0.0.1:$ServerPort/")
        $listener.Start()

        try {
            $root = [System.IO.Path]::GetFullPath($ServerRootPath)
            $pendingContextTask = $null
            while ($listener.IsListening) {
                try {
                    if ($null -eq $pendingContextTask) {
                        $pendingContextTask = $listener.GetContextAsync()
                    }

                    if (-not $pendingContextTask.Wait(250)) {
                        continue
                    }

                    $context = $pendingContextTask.GetAwaiter().GetResult()
                    $pendingContextTask = $null
                }
                catch {
                    break
                }

                try {
                    $requestPath = [System.Uri]::UnescapeDataString($context.Request.Url.AbsolutePath.TrimStart('/'))
                    if ([string]::IsNullOrWhiteSpace($requestPath)) {
                        $requestPath = $ServerIndexFileName
                    }

                    $localRelativePath = $requestPath.Replace('/', [System.IO.Path]::DirectorySeparatorChar)
                    $targetPath = [System.IO.Path]::GetFullPath((Join-Path $root $localRelativePath))
                    if (-not $targetPath.StartsWith($root, [System.StringComparison]::OrdinalIgnoreCase)) {
                        $context.Response.StatusCode = 403
                        continue
                    }

                    if (-not (Test-Path -LiteralPath $targetPath -PathType Leaf)) {
                        $context.Response.StatusCode = 404
                        continue
                    }

                    $extension = [System.IO.Path]::GetExtension($targetPath).ToLowerInvariant()
                    $context.Response.ContentType = switch ($extension) {
                        '.html' { 'text/html; charset=utf-8' }
                        '.css' { 'text/css; charset=utf-8' }
                        '.js' { 'application/javascript; charset=utf-8' }
                        '.json' { 'application/json; charset=utf-8' }
                        '.gz' { 'application/gzip' }
                        default { 'application/octet-stream' }
                    }
                    $context.Response.StatusCode = 200

                    $fileStream = [System.IO.File]::OpenRead($targetPath)
                    try {
                        $context.Response.ContentLength64 = $fileStream.Length
                        $fileStream.CopyTo($context.Response.OutputStream)
                    }
                    finally {
                        $fileStream.Dispose()
                    }
                }
                catch {
                    try { $context.Response.StatusCode = 500 } catch { $null = $_ }
                }
                finally {
                    try { $context.Response.OutputStream.Close() } catch { $null = $_ }
                }
            }
        }
        finally {
            if ($listener.IsListening) {
                $listener.Stop()
            }
            $listener.Close()
        }
    }
}

if ($ControlFixture -and -not [string]::IsNullOrWhiteSpace($DashboardPath)) {
    throw 'Use either -ControlFixture or -DashboardPath, not both.'
}
if (-not $ControlFixture -and [string]::IsNullOrWhiteSpace($DashboardPath)) {
    throw 'Provide -DashboardPath or -ControlFixture.'
}
$Port = if ($Port -gt 0) { $Port } else { Get-FreeTcpPort }
$edgeExecutablePath = Resolve-EdgeExecutablePath -RequestedPath $EdgePath

if ([string]::IsNullOrWhiteSpace($edgeExecutablePath)) {
    if ($AllowSkip) {
        Write-Warning 'Microsoft Edge was not found; hosted dashboard runtime smoke skipped.'
        return
    }

    throw 'Microsoft Edge was not found. Provide -EdgePath or install Edge to run the hosted dashboard runtime smoke.'
}

$serverJob = $null
$runId = 'hosted-smoke-' + [datetime]::UtcNow.ToString('yyyyMMddTHHmmssfffZ') + '-' + [guid]::NewGuid().ToString('N')
$repoRoot = Split-Path $PSScriptRoot -Parent
if ([string]::IsNullOrWhiteSpace($DiagnosticsPath)) {
    $DiagnosticsPath = Join-Path $repoRoot '.local\hosted-smoke-diagnostics'
}
$diagnosticRunPath = Join-Path ([IO.Path]::GetFullPath($DiagnosticsPath)) $runId
$profilePath = Join-Path ([System.IO.Path]::GetTempPath()) ('edge dashboard smoke ' + [guid]::NewGuid().ToString('N'))
$smokeRoot = Join-Path ([System.IO.Path]::GetTempPath()) $runId
$servedRoot = Join-Path $smokeRoot 'site'
$outcome = 'setup-failure'
$canaryResult = $null
$dashboardResult = $null
$extensionSessionCount = 0
$setupPhase = 'temporary-directories'
$failureClass = $null
$failureLine = $null
$priorCleanupFailures = @()
$inputDashboardPath = $DashboardPath

try {
    [void](New-Item -Path $diagnosticRunPath -ItemType Directory -Force)
    [void](New-Item -Path $smokeRoot -ItemType Directory -Force)
    [void](New-Item -Path $servedRoot -ItemType Directory -Force)
    if ($ControlFixture) {
        $setupPhase = 'fixture-generation'
        $fixtureDataPath = Join-Path $smokeRoot 'fixture-data'
        [void](New-Item -Path $fixtureDataPath -ItemType Directory -Force)
        Copy-Item -Path (Join-Path $PSScriptRoot 'fixtures\legacy-migration\*') -Destination $fixtureDataPath -Recurse -Force
        $setupPhase = 'hosted-generation'
        $inputDashboardPath = Join-Path $servedRoot 'control.Hosted.html'
        $LASTEXITCODE = 0
        & (Join-Path $repoRoot 'Generate-VulnerabilityDashboard.ps1') -DirectoryPath $fixtureDataPath -OutputPath $inputDashboardPath -SplitAssets -ExportMachineData:$false *> $null
        if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $inputDashboardPath -PathType Leaf)) {
            throw 'Control fixture Hosted generation failed.'
        }
    }
    $setupPhase = 'probe-injection'
    $resolvedDashboardPath = [System.IO.Path]::GetFullPath($inputDashboardPath)
    $dashboardRoot = Split-Path -Path $resolvedDashboardPath -Parent
    $dashboardFileName = Split-Path -Path $resolvedDashboardPath -Leaf
    if (-not $ControlFixture) {
        Copy-Item -Path (Join-Path $dashboardRoot '*') -Destination $servedRoot -Recurse -Force
    }
    Set-Content -LiteralPath (Join-Path $servedRoot 'canary.html') -Value '<!doctype html><html><body><script>document.body.setAttribute("data-hosted-smoke-canary", "ready");</script></body></html>' -Encoding utf8

    $probeDashboardPath = Join-Path $servedRoot $dashboardFileName
    $dashboardHtml = Get-Content -LiteralPath $probeDashboardPath -Raw
    $bodyCloseIndex = $dashboardHtml.LastIndexOf('</body>', [System.StringComparison]::OrdinalIgnoreCase)
    if ($bodyCloseIndex -lt 0) {
        throw 'Dashboard HTML did not contain a closing body tag for the smoke probe.'
    }

    $probeTimeoutMilliseconds = [math]::Min(120000, [math]::Max(10000, ($TimeoutSeconds * 1000) - 1000))
    $probeScript = @'
<script>
(function () {
    var probeId = 'hostedDashboardSmokeProbe';
    var probeTimeoutMilliseconds = __PROBE_TIMEOUT_MS__;
    var reportOptions = [
        ['active-vulnerabilities', 'Active Vulnerabilities'],
        ['remediation-activity', 'Remediation Activity'],
        ['impact-analysis', 'Impact Analysis'],
        ['devices-by-remediation', 'Devices by Remediation'],
        ['remediations-by-device', 'Remediations by Device']
    ];
    var probeCompleted = false;
    var latestDashboardReadyValidation = null;
    var failurePhase = 'wait-ready';
    var failureReason = 'readiness-timeout';
    var failureClass = 'timeout';

    function markFailure(phase, reason, errorClass) {
        failurePhase = phase;
        failureReason = reason;
        failureClass = errorClass;
    }

    function publishProbe(state, validation, message, payloadRows, runtimeChecks, errorClass) {
        var existingProbe = document.getElementById(probeId);
        if (existingProbe && existingProbe.getAttribute('data-state') === 'ready') {
            return;
        }

        var probe = existingProbe || document.createElement('div');
        probe.id = probeId;
        probe.hidden = true;
        probe.setAttribute('data-state', state);
        probe.setAttribute('data-failure-phase', failurePhase);
        probe.setAttribute('data-failure-reason', failureReason);
        if (errorClass) {
            probe.setAttribute('data-error-class', errorClass);
        }
        if (validation) {
            probe.setAttribute('data-dashboard-ready', String(Boolean(validation.ready)));
            probe.setAttribute('data-active-report', validation.activeReportId || '');
            probe.setAttribute('data-delivery-mode', validation.deliveryMode || '');
        }
        if (typeof payloadRows === 'number') {
            probe.setAttribute('data-payload-rows', String(payloadRows));
        }
        if (Array.isArray(runtimeChecks) && runtimeChecks.length > 0) {
            probe.setAttribute('data-runtime-checks', runtimeChecks.join(','));
        }
        probe.textContent = message || state;

        if (!existingProbe) {
            document.body.appendChild(probe);
        }
    }

    function getValidation() {
        return window.dashboardValidation || null;
    }

    function getHostedPayloadRowCount(payload) {
        if (!payload || !payload.vulns) {
            return -1;
        }

        if (Array.isArray(payload.vulns)) {
            return payload.vulns.length;
        }

        if (payload.vulns.d && Array.isArray(payload.vulns.d)) {
            return payload.vulns.d.length;
        }

        return -1;
    }

    function getDashboardConfig() {
        markFailure('payload', 'payload-config', 'assertion');
        var configElement = document.getElementById('dashboardConfig');
        if (!configElement || !configElement.textContent) {
            throw new Error('dashboardConfig was not available.');
        }

        return JSON.parse(configElement.textContent);
    }

    function assertRuntime(condition, reason) {
        if (!condition) {
            markFailure(failurePhase, reason, 'assertion');
            throw new Error('Hosted smoke assertion failed.');
        }
    }

    function waitForCondition(reason, predicate, timeoutMilliseconds) {
        markFailure(failurePhase, reason, 'operation');
        var startedAt = Date.now();
        return new Promise(function (resolve, reject) {
            function poll() {
                try {
                    if (predicate()) {
                        resolve();
                        return;
                    }

                    if ((Date.now() - startedAt) > timeoutMilliseconds) {
                        failureClass = 'timeout';
                        reject(new Error('Hosted smoke condition timed out.'));
                        return;
                    }

                    window.setTimeout(poll, 25);
                } catch (error) {
                    reject(error);
                }
            }

            poll();
        });
    }

    async function waitForDashboardReady() {
        markFailure('wait-ready', 'readiness-timeout', 'timeout');
        await waitForCondition('readiness-timeout', function () {
            var validation = getValidation();
            return validation && validation.ready === true;
        }, probeTimeoutMilliseconds);

        return getValidation();
    }

    async function validateReportSwitching() {
        markFailure('report-switch', 'report-selector', 'operation');
        var selector = document.getElementById('reportSelector');
        assertRuntime(selector, 'report-selector');

        reportOptions.forEach(function (entry) {
            var option = Array.prototype.find.call(selector.options || [], function (candidate) {
                return candidate.value === entry[0];
            });
            assertRuntime(option, 'report-option');
        });

        for (var index = 0; index < reportOptions.length; index++) {
            var reportId = reportOptions[index][0];
            var expectedSectionId = reportId + '-section';
            var section = document.getElementById(expectedSectionId);
            assertRuntime(section, 'report-section');

            markFailure('report-switch', 'report-dispatch', 'operation');
            selector.value = reportId;
            selector.dispatchEvent(new Event('change', { bubbles: true }));

            await waitForCondition('report-activation-timeout', function () {
                return section.classList.contains('active') && !section.hasAttribute('aria-busy');
            }, Math.min(10000, probeTimeoutMilliseconds));

            var activeSections = Array.prototype.slice.call(document.querySelectorAll('.report-section.active'));
            assertRuntime(activeSections.length === 1, 'report-active-count');
            assertRuntime(activeSections[0].id === expectedSectionId, 'report-active-id');

            var validation = getValidation();
            assertRuntime(validation && validation.activeReportId === reportId, 'report-validation');
        }
    }

    async function validateFilterPopover() {
        markFailure('filter-popover', 'filter-pill', 'operation');
        var severityPill = document.getElementById('filterPillSeverity');
        var popover = document.getElementById('filterPopover');
        assertRuntime(severityPill, 'filter-pill');
        assertRuntime(popover, 'filter-shell');

        markFailure('filter-popover', 'filter-open', 'operation');
        severityPill.click();
        await waitForCondition('filter-open-timeout', function () {
            return popover.hidden === false
                && popover.getAttribute('aria-hidden') === 'false'
                && popover.getAttribute('data-filter-key') === 'filterSeverity';
        }, Math.min(5000, probeTimeoutMilliseconds));

        assertRuntime(document.getElementById('filterPopoverBody'), 'filter-body');
        assertRuntime(document.getElementById('filterPopoverApplyButton'), 'filter-apply');

        var closeButton = document.getElementById('filterPopoverCloseButton');
        assertRuntime(closeButton, 'filter-close');
        markFailure('filter-popover', 'filter-close', 'operation');
        closeButton.click();

        await waitForCondition('filter-close-timeout', function () {
            return popover.hidden === true && popover.getAttribute('aria-hidden') === 'true';
        }, Math.min(5000, probeTimeoutMilliseconds));
    }

    async function validateRuntimeInteractions() {
        await validateReportSwitching();
        await validateFilterPopover();
        return ['report-switching', 'filter-popover'];
    }

    async function runHostedAssetProbe() {
        var validation = await waitForDashboardReady();
        var config = getDashboardConfig();
        markFailure('payload', 'payload-mode', 'assertion');
        if (!validation || validation.deliveryMode !== 'split-assets') {
            throw new Error('Dashboard validation snapshot did not report split-assets mode.');
        }
        if (!config.payloadUrl) {
            markFailure('payload', 'payload-url', 'assertion');
            throw new Error('Split-assets dashboard config did not include a payloadUrl.');
        }
        if (!window.pako || typeof window.pako.inflate !== 'function') {
            markFailure('inflate', 'inflate-runtime', 'assertion');
            throw new Error('pako did not load before the hosted asset probe.');
        }

        markFailure('payload', 'payload-fetch', 'operation');
        var response = await fetch(config.payloadUrl, { cache: 'no-cache' });
        if (!response.ok) {
            markFailure('payload', 'payload-response', 'assertion');
            throw new Error('Hosted payload fetch failed.');
        }

        markFailure('payload', 'payload-read', 'operation');
        var compressedBytes = new Uint8Array(await response.arrayBuffer());
        markFailure('inflate', 'inflate-operation', 'operation');
        var payloadText = window.pako.inflate(compressedBytes, { to: 'string' });
        markFailure('inflate', 'inflate-parse', 'operation');
        var payload = JSON.parse(payloadText);
        markFailure('count', 'payload-count', 'assertion');
        var payloadRows = getHostedPayloadRowCount(payload);
        if (payloadRows <= 0) {
            throw new Error('Hosted payload shape was not recognized.');
        }

        var runtimeChecks = await validateRuntimeInteractions();

        probeCompleted = true;
        markFailure('complete', 'none', 'none');
        publishProbe('ready', getValidation() || validation, 'hosted-payload-ready', payloadRows, runtimeChecks);
    }

    window.addEventListener('dashboard-ready', function (event) {
        var validation = event.detail && event.detail.validation ? event.detail.validation : getValidation();
        latestDashboardReadyValidation = validation;
    });

    function startProbe() {
        runHostedAssetProbe().catch(function () {
            if (probeCompleted) { return; }
            probeCompleted = true;
            publishProbe(failureClass === 'timeout' ? 'timeout' : 'error', getValidation(), failureReason, undefined, undefined, failureClass);
        });
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', startProbe);
    } else {
        startProbe();
    }

    window.setTimeout(function () {
        if (!probeCompleted) {
            probeCompleted = true;
            failureClass = 'timeout';
            publishProbe('timeout', getValidation() || latestDashboardReadyValidation, failureReason, undefined, undefined, failureClass);
        }
    }, probeTimeoutMilliseconds);
})();
</script>
'@.Replace('__PROBE_TIMEOUT_MS__', [string]$probeTimeoutMilliseconds)
    $dashboardHtml = $dashboardHtml.Insert($bodyCloseIndex, "`r`n$probeScript`r`n")
    Set-Content -LiteralPath $probeDashboardPath -Value $dashboardHtml -Encoding utf8 -NoNewline

    $setupPhase = 'loopback-server'
    $serverJob = Start-StaticHttpServer -RootPath $servedRoot -IndexFileName $dashboardFileName -ListenPort $Port
    $dashboardUrl = 'http://127.0.0.1:{0}/{1}' -f $Port, [System.Uri]::EscapeDataString($dashboardFileName)
    Write-Verbose 'Started loopback hosted dashboard server.'

    $serverReady = $false
    for ($attempt = 0; $attempt -lt 40 -and -not $serverReady; $attempt++) {
        try {
            $response = Invoke-WebRequest -Uri $dashboardUrl -TimeoutSec 1 -UseBasicParsing
            $serverReady = ($response.StatusCode -eq 200)
        }
        catch {
            Start-Sleep -Milliseconds 100
        }
    }
    if (-not $serverReady) {
        throw 'Timed out waiting for loopback hosted dashboard server.'
    }
    Write-Verbose 'Local hosted dashboard server is ready.'

    $virtualTimeBudgetMilliseconds = [math]::Min(120000, [math]::Max(5000, $TimeoutSeconds * 1000))
    $edgeArguments = @(
        '--headless=new',
        '--disable-gpu',
        '--disable-extensions',
        '--no-first-run',
        '--no-default-browser-check',
        '--disable-background-networking',
        "--user-data-dir=$profilePath",
        "--virtual-time-budget=$virtualTimeBudgetMilliseconds",
        '--dump-dom',
        $dashboardUrl
    )
    $waitMilliseconds = ($TimeoutSeconds * 1000) + 15000
    $setupPhase = 'edge-session-check'
    if ($IsWindows) {
        $existingEdge = @(Get-CimInstance Win32_Process -Filter "Name = 'msedge.exe'")
        $extensionSessionCount = @($existingEdge | Where-Object { $_.CommandLine -match '(?i)(?:vscode|copilot|playwright|--remote-debugging)' }).Count
        if ($extensionSessionCount -gt 0) {
            $outcome = 'existing-extension-session'
            throw 'Existing automation/extension Edge session detected; no additional Edge session was launched or terminated.'
        }
    }
    $canaryArguments = @($edgeArguments[0..($edgeArguments.Count - 2)]) + @("http://127.0.0.1:$Port/canary.html")
    $setupPhase = 'canary-capture'
    $canaryResult = Invoke-HostedSmokeAttempt -Executable $edgeExecutablePath -Arguments $canaryArguments -WaitMilliseconds $waitMilliseconds -Kind canary -RunPath $diagnosticRunPath
    $canaryCleanup = Stop-HostedSmokeProfileProcess -ProfilePath $profilePath
    if (-not $canaryCleanup.Confirmed -or $canaryCleanup.Failures.Count -gt 0) {
        $priorCleanupFailures = @($canaryCleanup.Failures)
        $outcome = 'cleanup-failure'
        throw 'Canary process cleanup failed.'
    }
    $setupPhase = 'dashboard-capture'
    $dashboardResult = Invoke-HostedSmokeAttempt -Executable $edgeExecutablePath -Arguments $edgeArguments -WaitMilliseconds $waitMilliseconds -Kind dashboard -RunPath $diagnosticRunPath
    $outcome = Get-HostedSmokeOutcome -Canary $canaryResult -Dashboard $dashboardResult
    if ($outcome -ne 'passed') {
        throw "Hosted smoke failed: $outcome; canary=$($canaryResult.state); dashboard=$($dashboardResult.state); diagnostics run=$runId."
    }
    Write-Verbose 'Hosted dashboard DOM smoke assertions passed.'
}
catch {
    $failureClass = switch ($_.Exception.GetType().Name) {
        'ParameterBindingValidationException' { 'parameter-validation' }
        'ParameterBindingException' { 'parameter-binding' }
        'RuntimeException' { 'runtime' }
        'MethodInvocationException' { 'method-invocation' }
        default { 'other' }
    }
    $failureLine = $_.InvocationInfo.ScriptLineNumber
    throw "Hosted smoke outcome=$outcome; diagnostics run=$runId. See sanitized artifacts under the diagnostics root."
}
finally {
    $originalOutcome = $outcome
    $cleanupFailures = [Collections.Generic.List[string]]::new()
    foreach ($code in $priorCleanupFailures) { $cleanupFailures.Add($code) }
    $processCleanupConfirmed = $false
    try {
        $processCleanup = Stop-HostedSmokeProfileProcess -ProfilePath $profilePath
        $processCleanupConfirmed = $processCleanup.Confirmed
        foreach ($code in $processCleanup.Failures) { $cleanupFailures.Add($code) }
    }
    catch { $cleanupFailures.Add('process-cleanup-failure') }
    if ($serverJob) {
        Write-Verbose 'Removing local hosted dashboard server job.'
        try { Stop-Job -Job $serverJob -ErrorAction Stop } catch { $cleanupFailures.Add('server-stop-failure') }
        try { Wait-Job -Job $serverJob -Timeout 5 -ErrorAction Stop | Out-Null } catch { $cleanupFailures.Add('server-wait-failure') }
        try { Remove-Job -Job $serverJob -Force -ErrorAction Stop } catch { $cleanupFailures.Add('server-removal-failure') }
    }
    $profileRemoved = $false
    try {
        if (Test-Path -LiteralPath $profilePath -ErrorAction Stop) { Remove-Item -LiteralPath $profilePath -Recurse -Force -ErrorAction Stop }
        $profileRemoved = -not (Test-Path -LiteralPath $profilePath -ErrorAction Stop)
        if (-not $profileRemoved) { $cleanupFailures.Add('profile-remains') }
    }
    catch { $cleanupFailures.Add('profile-removal-failure') }
    $temporarySiteRemoved = $false
    try {
        if (Test-Path -LiteralPath $smokeRoot -ErrorAction Stop) { Remove-Item -LiteralPath $smokeRoot -Recurse -Force -ErrorAction Stop }
        $temporarySiteRemoved = -not (Test-Path -LiteralPath $smokeRoot -ErrorAction Stop)
        if (-not $temporarySiteRemoved) { $cleanupFailures.Add('site-remains') }
    }
    catch { $cleanupFailures.Add('site-removal-failure') }
    if (-not $processCleanupConfirmed -or $cleanupFailures.Count -gt 0) { $outcome = 'cleanup-failure' }
    try {
        [ordered]@{
            outcome = $outcome
            originalOutcome = $originalOutcome
            phase = $setupPhase
            failureClass = $failureClass
            failureLine = $failureLine
            controlFixture = [bool]$ControlFixture
            extensionSessionCount = $extensionSessionCount
            processCleanupConfirmed = $processCleanupConfirmed
            profileRemoved = $profileRemoved
            temporarySiteRemoved = $temporarySiteRemoved
            cleanupFailures = $cleanupFailures.ToArray()
        } | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $diagnosticRunPath 'run.json') -Encoding utf8 -ErrorAction Stop
    }
    catch {
        $cleanupFailures.Add('diagnostic-write-failure')
        Write-Warning 'Hosted smoke diagnostic-write-failure.'
    }
    foreach ($code in $cleanupFailures) { Write-Verbose $code }
}

if ($outcome -eq 'cleanup-failure' -or $cleanupFailures.Count -gt 0) {
    throw "Hosted smoke cleanup/diagnostic failure; diagnostics run=$runId. Temporary private files may remain; do not share them."
}

[PSCustomObject]@{
    Outcome = $outcome
    DiagnosticsRun = $runId
    DomBytes = $dashboardResult.stdoutBytes
    SmokeMode = 'edge-headless-dump-dom'
} | ConvertTo-Json -Depth 5
