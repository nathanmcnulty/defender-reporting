#Requires -Version 7.0

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateScript({
        if (-not (Test-Path -LiteralPath $_ -PathType Leaf)) {
            throw "Dashboard HTML path '$_' does not exist."
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
    [switch]$AllowSkip
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

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

        throw "Microsoft Edge executable was not found at '$RequestedPath'."
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

    $command = Get-Command -Name 'msedge.exe' -ErrorAction SilentlyContinue
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

$resolvedDashboardPath = [System.IO.Path]::GetFullPath($DashboardPath)
$dashboardRoot = Split-Path -Path $resolvedDashboardPath -Parent
$dashboardFileName = Split-Path -Path $resolvedDashboardPath -Leaf
$Port = if ($Port -gt 0) { $Port } else { Get-FreeTcpPort }
$edgeExecutablePath = Resolve-EdgeExecutablePath -RequestedPath $EdgePath
Write-Verbose "Resolved dashboard '$resolvedDashboardPath' and Edge '$edgeExecutablePath'."

if ([string]::IsNullOrWhiteSpace($edgeExecutablePath)) {
    if ($AllowSkip) {
        Write-Warning 'Microsoft Edge was not found; hosted dashboard runtime smoke skipped.'
        return
    }

    throw 'Microsoft Edge was not found. Provide -EdgePath or install Edge to run the hosted dashboard runtime smoke.'
}

$serverJob = $null
$edgeProcess = $null
$profilePath = Join-Path ([System.IO.Path]::GetTempPath()) ('edge-dashboard-smoke-' + [guid]::NewGuid().ToString('N'))
$smokeRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('hosted-dashboard-smoke-' + [guid]::NewGuid().ToString('N'))
$servedRoot = Join-Path $smokeRoot 'site'
$domOutputPath = Join-Path $smokeRoot 'dashboard.dom.html'
$edgeErrorPath = Join-Path $smokeRoot 'edge.stderr.log'

try {
    [void](New-Item -Path $smokeRoot -ItemType Directory -Force)
    [void](New-Item -Path $servedRoot -ItemType Directory -Force)
    Copy-Item -Path (Join-Path $dashboardRoot '*') -Destination $servedRoot -Recurse -Force

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

    function publishProbe(state, validation, message, payloadRows, runtimeChecks) {
        var existingProbe = document.getElementById(probeId);
        if (existingProbe && existingProbe.getAttribute('data-state') === 'ready') {
            return;
        }

        var probe = existingProbe || document.createElement('div');
        probe.id = probeId;
        probe.hidden = true;
        probe.setAttribute('data-state', state);
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
        var configElement = document.getElementById('dashboardConfig');
        if (!configElement || !configElement.textContent) {
            throw new Error('dashboardConfig was not available.');
        }

        return JSON.parse(configElement.textContent);
    }

    function assertRuntime(condition, message) {
        if (!condition) {
            throw new Error(message);
        }
    }

    function waitForCondition(description, predicate, timeoutMilliseconds) {
        var startedAt = Date.now();
        return new Promise(function (resolve, reject) {
            function poll() {
                try {
                    if (predicate()) {
                        resolve();
                        return;
                    }

                    if ((Date.now() - startedAt) > timeoutMilliseconds) {
                        reject(new Error('Timed out waiting for ' + description + '.'));
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
        await waitForCondition('dashboard readiness', function () {
            var validation = getValidation();
            return validation && validation.ready === true;
        }, probeTimeoutMilliseconds);

        return getValidation();
    }

    async function validateReportSwitching() {
        var selector = document.getElementById('reportSelector');
        assertRuntime(selector, 'Report selector was not available for runtime switching.');

        reportOptions.forEach(function (entry) {
            var option = Array.prototype.find.call(selector.options || [], function (candidate) {
                return candidate.value === entry[0];
            });
            assertRuntime(option, 'Missing report selector option for ' + entry[1] + '.');
        });

        for (var index = 0; index < reportOptions.length; index++) {
            var reportId = reportOptions[index][0];
            var reportLabel = reportOptions[index][1];
            var expectedSectionId = reportId + '-section';
            var section = document.getElementById(expectedSectionId);
            assertRuntime(section, 'Missing report section for ' + reportLabel + '.');

            selector.value = reportId;
            selector.dispatchEvent(new Event('change', { bubbles: true }));

            await waitForCondition(reportLabel + ' report activation', function () {
                return section.classList.contains('active') && !section.hasAttribute('aria-busy');
            }, Math.min(10000, probeTimeoutMilliseconds));

            var activeSections = Array.prototype.slice.call(document.querySelectorAll('.report-section.active'));
            assertRuntime(activeSections.length === 1, 'Expected exactly one active report section after selecting ' + reportLabel + '.');
            assertRuntime(activeSections[0].id === expectedSectionId, 'Unexpected active report section after selecting ' + reportLabel + '.');

            var validation = getValidation();
            assertRuntime(validation && validation.activeReportId === reportId, 'Dashboard validation did not track active report ' + reportLabel + '.');
        }
    }

    async function validateFilterPopover() {
        var severityPill = document.getElementById('filterPillSeverity');
        var popover = document.getElementById('filterPopover');
        assertRuntime(severityPill, 'Severity filter pill was not available.');
        assertRuntime(popover, 'Filter popover shell was not available.');

        severityPill.click();
        await waitForCondition('severity filter popover to open', function () {
            return popover.hidden === false
                && popover.getAttribute('aria-hidden') === 'false'
                && popover.getAttribute('data-filter-key') === 'filterSeverity';
        }, Math.min(5000, probeTimeoutMilliseconds));

        assertRuntime(document.getElementById('filterPopoverBody'), 'Filter popover body was not available.');
        assertRuntime(document.getElementById('filterPopoverApplyButton'), 'Filter popover apply button was not available.');

        var closeButton = document.getElementById('filterPopoverCloseButton');
        assertRuntime(closeButton, 'Filter popover close button was not available.');
        closeButton.click();

        await waitForCondition('severity filter popover to close', function () {
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
        if (!validation || validation.deliveryMode !== 'split-assets') {
            throw new Error('Dashboard validation snapshot did not report split-assets mode.');
        }
        if (!config.payloadUrl) {
            throw new Error('Split-assets dashboard config did not include a payloadUrl.');
        }
        if (!window.pako || typeof window.pako.inflate !== 'function') {
            throw new Error('pako did not load before the hosted asset probe.');
        }

        var response = await fetch(config.payloadUrl, { cache: 'no-cache' });
        if (!response.ok) {
            throw new Error('Hosted payload fetch failed: ' + response.status + ' ' + response.statusText);
        }

        var compressedBytes = new Uint8Array(await response.arrayBuffer());
        var payloadText = window.pako.inflate(compressedBytes, { to: 'string' });
        var payload = JSON.parse(payloadText);
        var payloadRows = getHostedPayloadRowCount(payload);
        if (payloadRows < 0) {
            throw new Error('Hosted payload shape was not recognized.');
        }

        var runtimeChecks = await validateRuntimeInteractions();

        probeCompleted = true;
        publishProbe('ready', getValidation() || validation, 'hosted-payload-ready', payloadRows, runtimeChecks);
    }

    window.addEventListener('dashboard-ready', function (event) {
        var validation = event.detail && event.detail.validation ? event.detail.validation : getValidation();
        latestDashboardReadyValidation = validation;
    });

    function startProbe() {
        runHostedAssetProbe().catch(function (error) {
            probeCompleted = true;
            publishProbe('error', getValidation(), error && error.message ? error.message : String(error));
        });
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', startProbe);
    } else {
        startProbe();
    }

    window.setTimeout(function () {
        if (!probeCompleted) {
            publishProbe('timeout', getValidation() || latestDashboardReadyValidation, 'Timed out waiting for dashboard readiness.');
        }
    }, probeTimeoutMilliseconds);
})();
</script>
'@.Replace('__PROBE_TIMEOUT_MS__', [string]$probeTimeoutMilliseconds)
    $dashboardHtml = $dashboardHtml.Insert($bodyCloseIndex, "`r`n$probeScript`r`n")
    Set-Content -LiteralPath $probeDashboardPath -Value $dashboardHtml -Encoding utf8 -NoNewline

    $serverJob = Start-StaticHttpServer -RootPath $servedRoot -IndexFileName $dashboardFileName -ListenPort $Port
    $dashboardUrl = 'http://127.0.0.1:{0}/{1}' -f $Port, [System.Uri]::EscapeDataString($dashboardFileName)
    Write-Verbose "Started local hosted dashboard server at $dashboardUrl."

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
        throw "Timed out waiting for local hosted dashboard server at $dashboardUrl."
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

    $edgeProcess = Start-Process `
        -FilePath $edgeExecutablePath `
        -ArgumentList $edgeArguments `
        -RedirectStandardOutput $domOutputPath `
        -RedirectStandardError $edgeErrorPath `
        -PassThru `
        -WindowStyle Hidden
    Write-Verbose "Started Microsoft Edge process $($edgeProcess.Id)."

    $waitMilliseconds = ($TimeoutSeconds * 1000) + 15000
    if (-not $edgeProcess.WaitForExit($waitMilliseconds)) {
        $edgeErrors = if (Test-Path -LiteralPath $edgeErrorPath -PathType Leaf) { Get-Content -LiteralPath $edgeErrorPath -Raw } else { '' }
        try { Stop-Process -Id $edgeProcess.Id -Force -ErrorAction SilentlyContinue } catch { Write-Verbose "Failed to stop timed-out Edge process $($edgeProcess.Id): $_" }
        throw "Timed out waiting for Microsoft Edge to complete the hosted dashboard runtime smoke after $([math]::Round($waitMilliseconds / 1000, 1)) seconds. $edgeErrors"
    }
    Write-Verbose "Microsoft Edge exited with code $($edgeProcess.ExitCode)."

    if ($edgeProcess.ExitCode -ne 0) {
        $edgeErrors = if (Test-Path -LiteralPath $edgeErrorPath -PathType Leaf) { Get-Content -LiteralPath $edgeErrorPath -Raw } else { '' }
        throw "Microsoft Edge exited with code $($edgeProcess.ExitCode). $edgeErrors"
    }

    if (-not (Test-Path -LiteralPath $domOutputPath -PathType Leaf)) {
        throw 'Microsoft Edge did not produce a DOM snapshot.'
    }

    $dom = Get-Content -LiteralPath $domOutputPath -Raw
    if ([string]::IsNullOrWhiteSpace($dom)) {
        throw 'Microsoft Edge produced an empty DOM snapshot.'
    }
    if ($dom -notmatch 'id="statsSummary"') {
        throw 'Hosted dashboard DOM snapshot did not contain the summary cards.'
    }
    if ($dom -notmatch 'id="reportSelector"') {
        throw 'Hosted dashboard DOM snapshot did not contain the report selector.'
    }
    if ($dom -match 'Failed to initialize the dashboard') {
        throw 'Hosted dashboard reported an initialization failure.'
    }
    if ($dom -notmatch 'id="hostedDashboardSmokeProbe"') {
        throw 'Hosted dashboard DOM snapshot did not contain the runtime readiness smoke probe.'
    }
    if ($dom -notmatch 'data-state="ready"') {
        $probeMatch = [regex]::Match($dom, '<div[^>]+id="hostedDashboardSmokeProbe"[^>]*>.*?</div>', [System.Text.RegularExpressions.RegexOptions]::Singleline)
        $probeDetails = if ($probeMatch.Success) { $probeMatch.Value } else { 'probe details unavailable' }
        throw "Hosted dashboard runtime readiness probe did not report ready. $probeDetails"
    }
    if ($dom -notmatch 'data-delivery-mode="split-assets"') {
        throw 'Hosted dashboard validation snapshot did not report split-assets delivery mode.'
    }
    if ($dom -notmatch 'data-runtime-checks="[^"]*report-switching[^"]*filter-popover[^"]*"') {
        throw 'Hosted dashboard smoke probe did not confirm report switching and filter popover runtime checks.'
    }
    $payloadRowsMatch = [regex]::Match($dom, 'data-payload-rows="(?<Rows>-?\d+)"')
    if (-not $payloadRowsMatch.Success -or [int]$payloadRowsMatch.Groups['Rows'].Value -le 0) {
        throw 'Hosted dashboard smoke probe did not confirm a readable hosted payload.'
    }
    Write-Verbose 'Hosted dashboard DOM smoke assertions passed.'

    [PSCustomObject]@{
        DashboardUrl = $dashboardUrl
        DomLength = $dom.Length
        EdgePath = $edgeExecutablePath
        SmokeMode = 'edge-headless-dump-dom'
    } | ConvertTo-Json -Depth 5
}
finally {
    if ($edgeProcess -and -not $edgeProcess.HasExited) {
        try { Stop-Process -Id $edgeProcess.Id -Force -ErrorAction SilentlyContinue } catch { Write-Verbose "Failed to stop Edge process $($edgeProcess.Id): $_" }
    }
    if ($serverJob) {
        Write-Verbose 'Removing local hosted dashboard server job.'
        try { Stop-Job -Job $serverJob -ErrorAction SilentlyContinue } catch { Write-Verbose "Failed to stop hosted dashboard server job: $_" }
        try { Wait-Job -Job $serverJob -Timeout 5 -ErrorAction SilentlyContinue | Out-Null } catch { Write-Verbose "Failed while waiting for hosted dashboard server job to stop: $_" }
        try { Remove-Job -Job $serverJob -Force -ErrorAction SilentlyContinue } catch { Write-Verbose "Failed to remove hosted dashboard server job: $_" }
    }
    if (Test-Path -LiteralPath $profilePath) {
        Remove-Item -LiteralPath $profilePath -Recurse -Force -ErrorAction SilentlyContinue
    }
    if (Test-Path -LiteralPath $smokeRoot) {
        Remove-Item -LiteralPath $smokeRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}
