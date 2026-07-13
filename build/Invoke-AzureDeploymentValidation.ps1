#Requires -Version 7.0

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$AutomationAccountName,

    [Parameter(Mandatory = $true)]
    [string]$FunctionAppName,

    [Parameter(Mandatory = $false)]
    [string]$ResourceGroupName,

    [Parameter(Mandatory = $false)]
    [ValidateSet('Auto', 'SelfContained', 'Hosted', 'Dual')]
    [string]$DashboardDeliveryMode,

    [Parameter(Mandatory = $false)]
    [switch]$SkipMdePermissions,

    [Parameter(Mandatory = $false)]
    [ValidateRange(60, 7200)]
    [int]$ValidationTimeoutSeconds = 3600,

    [Parameter(Mandatory = $false)]
    [ValidateRange(5, 60)]
    [int]$FunctionExecutionTimeoutMinutes = 25,

    [Parameter(Mandatory = $false)]
    [string]$FunctionExecutionDatasetPath,

    [Parameter(Mandatory = $false)]
    [switch]$SkipFunctionExecution,

    [Parameter(Mandatory = $false)]
    [switch]$SkipAutomationValidation
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$buildRoot = $PSScriptRoot
$repoRoot = Split-Path -Path $buildRoot -Parent
$setupScriptPath = Join-Path $repoRoot 'Setup-AzureResources.ps1'
$script:FunctionExecutionControlBlobName = '_diagnostics/ExportAndGenerate.control.json'
$script:FunctionExecutionStatusContainerName = 'dashboards'
$script:FunctionExecutionStatusBlobName = '_diagnostics/ExportAndGenerate.status.json'

function Get-ValidationTimestampText {
    [CmdletBinding()]
    [OutputType([string])]
    param()

    return (Get-Date).ToUniversalTime().ToString('u')
}

function Write-ValidationLogLine {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,

        [Parameter(Mandatory = $false)]
        [string]$ForegroundColor = 'Gray'
    )

    if ([string]::IsNullOrWhiteSpace($Message)) {
        return
    }

    foreach ($line in ($Message -split "`r?`n")) {
        if ([string]::IsNullOrWhiteSpace($line)) {
            continue
        }

        if ($line -match '^\[(?:\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}Z|\d{4}-\d{2}-\d{2}T[^\]]+)\]\s') {
            Write-Host $line -ForegroundColor $ForegroundColor
            continue
        }

        Write-Host ("[{0}] {1}" -f (Get-ValidationTimestampText), $line) -ForegroundColor $ForegroundColor
    }
}

function Get-ValidationStreamMessageText {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        $Record
    )

    if ($null -eq $Record) {
        return $null
    }

    if ($Record -is [System.Management.Automation.InformationRecord]) {
        return [string]$Record.MessageData
    }

    if ($Record -is [System.Management.Automation.WarningRecord]) {
        return ("WARNING: {0}" -f $Record.Message)
    }

    if ($Record -is [System.Management.Automation.VerboseRecord]) {
        return ("VERBOSE: {0}" -f $Record.Message)
    }

    if ($Record -is [System.Management.Automation.DebugRecord]) {
        return ("DEBUG: {0}" -f $Record.Message)
    }

    if ($Record -is [System.Management.Automation.ErrorRecord]) {
        if (-not [string]::IsNullOrWhiteSpace([string]$Record.Exception.Message)) {
            return ("ERROR: {0}" -f $Record.Exception.Message)
        }

        return ("ERROR: {0}" -f ($Record | Out-String).Trim())
    }

    return ($Record | Out-String).TrimEnd()
}

function Get-ValidationStreamForegroundColor {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        $Record
    )

    if ($Record -is [System.Management.Automation.WarningRecord]) {
        return 'Yellow'
    }

    if ($Record -is [System.Management.Automation.ErrorRecord]) {
        return 'Red'
    }

    if ($Record -is [System.Management.Automation.DebugRecord]) {
        return 'DarkGray'
    }

    return 'Gray'
}

function Invoke-TimestampedCommand {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [scriptblock]$ScriptBlock,

        [Parameter(Mandatory = $false)]
        [string]$FailureDescription = 'Command'
    )

    $previousLastExitCode = $global:LASTEXITCODE
    $commandExitCode = 0
    try {
        $global:LASTEXITCODE = 0

        foreach ($record in (& $ScriptBlock 6>&1 5>&1 4>&1 3>&1)) {
            $message = Get-ValidationStreamMessageText -Record $record
            if (-not [string]::IsNullOrWhiteSpace($message)) {
                Write-ValidationLogLine -Message $message -ForegroundColor (Get-ValidationStreamForegroundColor -Record $record)
            }
        }

        $commandExitCode = $global:LASTEXITCODE
    }
    finally {
        $global:LASTEXITCODE = $previousLastExitCode
    }

    if ($commandExitCode -ne 0) {
        throw ("{0} failed with exit code {1}." -f $FailureDescription, $commandExitCode)
    }
}

function Invoke-AzCliJson {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$Arguments
    )

    $output = & az @Arguments 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw ($output -join [Environment]::NewLine)
    }

    if ([string]::IsNullOrWhiteSpace(($output -join ''))) {
        return $null
    }

    return ($output -join [Environment]::NewLine) | ConvertFrom-Json
}

function Invoke-AzCliText {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$Arguments
    )

    $output = & az @Arguments 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw ($output -join [Environment]::NewLine)
    }

    return ($output -join [Environment]::NewLine).Trim()
}

function Assert-AzureSessionAvailable {
    [CmdletBinding()]
    [OutputType([object])]
    param()

    $azContext = Get-AzContext -ErrorAction Ignore
    if ($null -eq $azContext -or $null -eq $azContext.Account) {
        throw 'No Az PowerShell session is available. Authenticate first with Connect-AzAccount using browser or WAM sign-in.'
    }

    try {
        return Invoke-AzCliJson -Arguments @('account', 'show', '--output', 'json')
    }
    catch {
        throw 'Azure CLI is not authenticated. Run az login using browser or WAM sign-in before using this validation script.'
    }
}

function Resolve-ResourceGroupForResource {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,

        [Parameter(Mandatory = $true)]
        [string]$ResourceType
    )

    $resourceGroup = Invoke-AzCliText -Arguments @(
        'resource', 'list',
        '--name', $Name,
        '--resource-type', $ResourceType,
        '--query', '[0].resourceGroup',
        '-o', 'tsv'
    )

    if ([string]::IsNullOrWhiteSpace($resourceGroup)) {
        throw "Could not resolve resource group for resource '$Name' of type '$ResourceType'."
    }

    return $resourceGroup
}

function Get-FunctionAppSettingValue {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$FunctionAppName,

        [Parameter(Mandatory = $true)]
        [string]$FunctionResourceGroup,

        [Parameter(Mandatory = $true)]
        [string]$SettingName
    )

    $settings = @(Invoke-AzCliJson -Arguments @(
        'functionapp', 'config', 'appsettings', 'list',
        '--name', $FunctionAppName,
        '--resource-group', $FunctionResourceGroup,
        '-o', 'json'
    ))

    $setting = $settings | Where-Object { $_.name -eq $SettingName } | Select-Object -First 1
    if ($null -eq $setting) {
        return $null
    }

    return [string]$setting.value
}

function Get-AutomationVariableValue {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$AutomationAccountName,

        [Parameter(Mandatory = $true)]
        [string]$SubscriptionId,

        [Parameter(Mandatory = $true)]
        [string]$AutomationResourceGroup,

        [Parameter(Mandatory = $true)]
        [string]$VariableName
    )

    $uri = 'https://management.azure.com/subscriptions/{0}/resourceGroups/{1}/providers/Microsoft.Automation/automationAccounts/{2}/variables/{3}?api-version=2023-11-01' -f $SubscriptionId, $AutomationResourceGroup, $AutomationAccountName, $VariableName
    $variable = Invoke-AzCliJson -Arguments @('rest', '--method', 'get', '--uri', $uri, '--output', 'json')
    $rawValue = [string]$variable.properties.value

    if ([string]::IsNullOrWhiteSpace($rawValue)) {
        return $null
    }

    try {
        return [string]($rawValue | ConvertFrom-Json)
    }
    catch {
        return $rawValue.Trim('"')
    }
}

function Resolve-DashboardDeliveryMode {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$AutomationAccountName,

        [Parameter(Mandatory = $true)]
        [string]$FunctionAppName,

        [Parameter(Mandatory = $true)]
        [string]$SubscriptionId,

        [Parameter(Mandatory = $true)]
        [string]$AutomationResourceGroup,

        [Parameter(Mandatory = $true)]
        [string]$FunctionResourceGroup,

        [Parameter(Mandatory = $false)]
        [string]$RequestedDashboardDeliveryMode
    )

    if (-not [string]::IsNullOrWhiteSpace($RequestedDashboardDeliveryMode)) {
        return $RequestedDashboardDeliveryMode
    }

    $automationMode = Get-AutomationVariableValue -AutomationAccountName $AutomationAccountName -SubscriptionId $SubscriptionId -AutomationResourceGroup $AutomationResourceGroup -VariableName 'DashboardDeliveryMode'
    $functionMode = Get-FunctionAppSettingValue -FunctionAppName $FunctionAppName -FunctionResourceGroup $FunctionResourceGroup -SettingName 'DASHBOARD_DELIVERY_MODE'

    if (-not [string]::IsNullOrWhiteSpace($automationMode) -and -not [string]::IsNullOrWhiteSpace($functionMode) -and $automationMode -ne $functionMode) {
        throw "Detected conflicting dashboard delivery modes: AutomationAccount='$automationMode', FunctionApp='$functionMode'. Pass -DashboardDeliveryMode explicitly to choose the intended validation mode."
    }

    if (-not [string]::IsNullOrWhiteSpace($automationMode)) {
        return $automationMode
    }

    if (-not [string]::IsNullOrWhiteSpace($functionMode)) {
        return $functionMode
    }

    return 'Auto'
}

function Get-DatasetFiles {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '', Justification = 'Internal helper intentionally returns a collection of dataset files.')]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    return @(
        Get-ChildItem -LiteralPath $Path -File |
            Where-Object {
                $_.Name -match '\.json(\.gz)?$' -and
                $_.Name -notin @(
                    '.synthetic-progress.json',
                    '.synthetic-progress.json.gz',
                    'stress-validation-report.json',
                    'stress-validation-report.json.gz'
                )
            } |
            Sort-Object -Property Name
    )
}

function Resolve-FunctionExecutionDatasetPath {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $false)]
        [AllowEmptyString()]
        [string]$RequestedPath
    )

    $candidatePath = $RequestedPath
    if ([string]::IsNullOrWhiteSpace($candidatePath)) {
        $defaultPath = Join-Path $repoRoot 'exports'
        if (Test-Path -LiteralPath $defaultPath -PathType Container) {
            $candidatePath = $defaultPath
        }
    }

    if ([string]::IsNullOrWhiteSpace($candidatePath)) {
        return $null
    }

    $resolvedPath = if ([System.IO.Path]::IsPathRooted($candidatePath)) {
        [System.IO.Path]::GetFullPath($candidatePath)
    }
    else {
        [System.IO.Path]::GetFullPath((Join-Path -Path $repoRoot -ChildPath $candidatePath))
    }

    if (-not (Test-Path -LiteralPath $resolvedPath -PathType Container)) {
        throw "Function execution dataset path not found: $resolvedPath"
    }

    return $resolvedPath
}

function Get-StorageBlobRestHeaderSet {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param()

    $accessToken = Invoke-AzCliText -Arguments @('account', 'get-access-token', '--resource', 'https://storage.azure.com/', '--query', 'accessToken', '-o', 'tsv')
    if ([string]::IsNullOrWhiteSpace($accessToken)) {
        throw 'Failed to acquire an Azure Storage access token for blob REST operations.'
    }

    return @{
        Authorization = "Bearer $accessToken"
        'x-ms-version' = '2023-11-03'
    }
}

function Get-BlobNamesViaRest {
    [CmdletBinding()]
    [OutputType([string[]])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$AccountName,

        [Parameter(Mandatory = $true)]
        [string]$ContainerName
    )

    $headers = Get-StorageBlobRestHeaderSet
    $requestUri = "https://$AccountName.blob.core.windows.net/${ContainerName}?restype=container&comp=list"
    $response = Invoke-WebRequest -Method Get -Uri $requestUri -Headers $headers -UseBasicParsing
    if ([string]::IsNullOrWhiteSpace([string]$response.Content)) {
        return @()
    }

    $blobNameMatches = [System.Text.RegularExpressions.Regex]::Matches([string]$response.Content, '<Blob>\s*<Name>([^<]+)</Name>')
    return @($blobNameMatches | ForEach-Object { $_.Groups[1].Value } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
}

function Remove-BlobViaRest {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory = $true)]
        [string]$AccountName,

        [Parameter(Mandatory = $true)]
        [string]$ContainerName,

        [Parameter(Mandatory = $true)]
        [string]$BlobName
    )

    $headers = Get-StorageBlobRestHeaderSet
    $encodedBlobName = [System.Uri]::EscapeDataString($BlobName).Replace('%2F', '/')
    $requestUri = "https://$AccountName.blob.core.windows.net/${ContainerName}/$encodedBlobName"
    if ($PSCmdlet.ShouldProcess($requestUri, 'Delete blob via REST')) {
        Invoke-WebRequest -Method Delete -Uri $requestUri -Headers $headers -UseBasicParsing | Out-Null
    }
}

function Set-BlobViaRest {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory = $true)]
        [string]$AccountName,

        [Parameter(Mandatory = $true)]
        [string]$ContainerName,

        [Parameter(Mandatory = $true)]
        [string]$BlobName,

        [Parameter(Mandatory = $true)]
        [string]$FilePath,

        [Parameter(Mandatory = $true)]
        [string]$ContentType
    )

    $headers = Get-StorageBlobRestHeaderSet
    $headers['x-ms-blob-type'] = 'BlockBlob'
    $headers['Content-Type'] = $ContentType
    $encodedBlobName = [System.Uri]::EscapeDataString($BlobName).Replace('%2F', '/')
    $requestUri = "https://$AccountName.blob.core.windows.net/${ContainerName}/$encodedBlobName"
    if ($PSCmdlet.ShouldProcess($requestUri, 'Upload blob via REST')) {
        Invoke-WebRequest -Method Put -Uri $requestUri -Headers $headers -InFile $FilePath -UseBasicParsing | Out-Null
    }
}

function Get-BlobTextViaRest {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$AccountName,

        [Parameter(Mandatory = $true)]
        [string]$ContainerName,

        [Parameter(Mandatory = $true)]
        [string]$BlobName
    )

    $headers = Get-StorageBlobRestHeaderSet
    $encodedBlobName = [System.Uri]::EscapeDataString($BlobName).Replace('%2F', '/')
    $requestUri = "https://$AccountName.blob.core.windows.net/${ContainerName}/$encodedBlobName"

    try {
        $response = Invoke-WebRequest -Method Get -Uri $requestUri -Headers $headers -UseBasicParsing
        return [string]$response.Content
    }
    catch {
        if ($_.Exception.Response -and [int]$_.Exception.Response.StatusCode -eq 404) {
            return $null
        }

        throw
    }
}

function Get-BlobLastModifiedUtcViaRest {
    [CmdletBinding()]
    [OutputType([Nullable[datetime]])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$AccountName,

        [Parameter(Mandatory = $true)]
        [string]$ContainerName,

        [Parameter(Mandatory = $true)]
        [string]$BlobName
    )

    $headers = Get-StorageBlobRestHeaderSet
    $encodedBlobName = [System.Uri]::EscapeDataString($BlobName).Replace('%2F', '/')
    $requestUri = "https://$AccountName.blob.core.windows.net/${ContainerName}/$encodedBlobName"

    try {
        $response = Invoke-WebRequest -Method Head -Uri $requestUri -Headers $headers -UseBasicParsing
    }
    catch {
        if ($_.Exception.Response -and [int]$_.Exception.Response.StatusCode -eq 404) {
            return $null
        }

        throw
    }

    $lastModifiedHeader = [string]$response.Headers['Last-Modified']
    if ([string]::IsNullOrWhiteSpace($lastModifiedHeader)) {
        return $null
    }

    return ([datetimeoffset]$lastModifiedHeader).UtcDateTime
}

function Clear-BlobContainer {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$AccountName,

        [Parameter(Mandatory = $true)]
        [string]$ContainerName
    )

    try {
        $blobs = @(Invoke-AzCliJson -Arguments @(
        'storage', 'blob', 'list',
        '--account-name', $AccountName,
        '--container-name', $ContainerName,
        '--auth-mode', 'login',
        '-o', 'json'
        ))

        foreach ($blob in @($blobs)) {
            if ($null -eq $blob -or [string]::IsNullOrWhiteSpace([string]$blob.name)) {
                continue
            }

            & az storage blob delete --account-name $AccountName --container-name $ContainerName --name ([string]$blob.name) --auth-mode login --output none | Out-Null
            if ($LASTEXITCODE -ne 0) {
                throw "Failed to delete blob '$([string]$blob.name)' from container '$ContainerName'."
            }
        }

        return
    }
    catch {
        Write-ValidationLogLine -Message ("Azure CLI blob listing failed for container '{0}'. Falling back to blob REST: {1}" -f $ContainerName, $_.Exception.Message) -ForegroundColor Yellow
    }

    foreach ($blobName in @(Get-BlobNamesViaRest -AccountName $AccountName -ContainerName $ContainerName)) {
        Remove-BlobViaRest -AccountName $AccountName -ContainerName $ContainerName -BlobName $blobName
    }
}

function Set-FunctionAppAppSettings {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Internal helper updates a coordinated set of Function App settings during scripted validation.')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '', Justification = 'Internal helper accepts multiple settings by design.')]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$FunctionAppName,

        [Parameter(Mandatory = $true)]
        [string]$FunctionResourceGroup,

        [Parameter(Mandatory = $true)]
        [string[]]$Settings
    )

    if (@($Settings).Count -eq 0) {
        return
    }

    & az functionapp config appsettings set --name $FunctionAppName --resource-group $FunctionResourceGroup --settings @($Settings) --output none | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw ("Failed to update Function App app settings: {0}" -f (@($Settings) -join ', '))
    }
}

function Restore-FunctionAppSettingValue {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$FunctionAppName,

        [Parameter(Mandatory = $true)]
        [string]$FunctionResourceGroup,

        [Parameter(Mandatory = $true)]
        [string]$SettingName,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [string]$OriginalValue
    )

    if ($null -eq $OriginalValue) {
        & az functionapp config appsettings delete --name $FunctionAppName --resource-group $FunctionResourceGroup --setting-names $SettingName --output none | Out-Null
        if ($LASTEXITCODE -ne 0) {
            throw ("Failed to delete Function App app setting '{0}'." -f $SettingName)
        }

        return
    }

    Set-FunctionAppAppSettings -FunctionAppName $FunctionAppName -FunctionResourceGroup $FunctionResourceGroup -Settings @(("{0}={1}" -f $SettingName, $OriginalValue))
}

function Restart-FunctionAppInstance {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Internal helper restarts the Function App as part of scripted validation setup.')]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$FunctionAppName,

        [Parameter(Mandatory = $true)]
        [string]$FunctionResourceGroup,

        [Parameter(Mandatory = $false)]
        [string]$Reason = 'apply updated app settings'
    )

    Write-ValidationLogLine -Message ("Restarting Function App '{0}' to {1}..." -f $FunctionAppName, $Reason)
    & az functionapp restart --name $FunctionAppName --resource-group $FunctionResourceGroup --output none | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw ("Failed to restart Function App '{0}'." -f $FunctionAppName)
    }
}

function Refresh-FunctionExecutionTemplates {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseApprovedVerbs', '', Justification = 'Internal helper refreshes template blobs for validation without exposing a public command surface.')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '', Justification = 'Internal helper refreshes a set of template assets by design.')]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$StorageAccountName
    )

    $publishScriptPath = Join-Path $repoRoot 'build\Publish-DashboardTemplates.ps1'
    if (-not (Test-Path -LiteralPath $publishScriptPath -PathType Leaf)) {
        throw "Dashboard template publish script not found: $publishScriptPath"
    }

    Write-ValidationLogLine -Message ("Refreshing dashboard templates in storage account '{0}'..." -f $StorageAccountName)
    Invoke-TimestampedCommand -ScriptBlock { & $publishScriptPath -StorageAccountName $StorageAccountName }
}

function Seed-ExportsContainer {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseApprovedVerbs', '', Justification = 'Internal helper prepares the Function App exports container for execution validation.')]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$AccountName,

        [Parameter(Mandatory = $true)]
        [string]$DatasetPath
    )

    $datasetFiles = @(Get-DatasetFiles -Path $DatasetPath)
    if ($datasetFiles.Count -eq 0) {
        throw "Function execution dataset '$DatasetPath' does not contain any export files."
    }

    $missingFiles = [System.Collections.Generic.List[string]]::new()
    foreach ($requiredName in @('Machines_Current.json.gz', 'VulnContentDictionary.json.gz', 'VulnCurrentRefs.json.gz')) {
        if (-not (Test-Path -LiteralPath (Join-Path -Path $DatasetPath -ChildPath $requiredName) -PathType Leaf)) {
            $missingFiles.Add($requiredName) | Out-Null
        }
    }

    if (@(Get-ChildItem -LiteralPath $DatasetPath -Filter 'VulnHistoryRefs_*.json.gz' -File -ErrorAction SilentlyContinue).Count -eq 0) {
        $missingFiles.Add('VulnHistoryRefs_*.json.gz') | Out-Null
    }

    if ($missingFiles.Count -gt 0) {
        throw ("Function execution dataset is incomplete. Missing required file(s): {0}" -f ($missingFiles -join ', '))
    }

    Clear-BlobContainer -AccountName $AccountName -ContainerName 'exports'
    foreach ($file in $datasetFiles) {
        $contentType = if ($file.Name.EndsWith('.gz')) { 'application/gzip' } else { 'application/json' }
        & az storage blob upload --account-name $AccountName --container-name exports --name $file.Name --file $file.FullName --content-type $contentType --auth-mode login --overwrite --output none 2>$null | Out-Null
        if ($LASTEXITCODE -ne 0) {
            Write-ValidationLogLine -Message ("Azure CLI blob upload failed for '{0}' in container 'exports'. Falling back to blob REST." -f $file.Name) -ForegroundColor Yellow
            Set-BlobViaRest -AccountName $AccountName -ContainerName 'exports' -BlobName $file.Name -FilePath $file.FullName -ContentType $contentType
        }
    }
}

function Invoke-FunctionAdminRequest {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('Get', 'Post', 'Delete')]
        [string]$Method,

        [Parameter(Mandatory = $true)]
        [string]$HostName,

        [Parameter(Mandatory = $true)]
        [string]$MasterKey,

        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [string]$Body
    )

    $headers = @{ 'x-functions-key' = $MasterKey }
    if ($Method -eq 'Delete') {
        $headers['If-Match'] = '*'
    }

    $invokeParams = @{
        Method = $Method
        Uri = "https://$HostName/$Path"
        Headers = $headers
        ErrorAction = 'Stop'
    }

    if ($Method -eq 'Post') {
        $invokeParams.ContentType = 'application/json'
        $invokeParams.Body = if ([string]::IsNullOrWhiteSpace($Body)) { '{}' } else { $Body }
    }

    try {
        return Invoke-WebRequest @invokeParams
    }
    catch {
        $response = $_.Exception.Response
        if ($null -ne $response -and [int]$response.StatusCode -in @(403, 404)) {
            return $null
        }

        throw
    }
}

function Wait-FunctionHostReady {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$HostName,

        [Parameter(Mandatory = $true)]
        [string]$MasterKey,

        [Parameter(Mandatory = $false)]
        [int]$TimeoutMinutes = 10
    )

    Write-ValidationLogLine -Message ("Waiting for Function App host readiness on '{0}'..." -f $HostName)

    $deadline = [datetime]::UtcNow.AddMinutes($TimeoutMinutes)
    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    $lastHeartbeatSecond = -30
    while ([datetime]::UtcNow -lt $deadline) {
        try {
            $response = Invoke-FunctionAdminRequest -Method Get -HostName $HostName -MasterKey $MasterKey -Path 'admin/host/status'
            if ($null -ne $response -and $response.StatusCode -ge 200 -and $response.StatusCode -lt 300) {
                Write-ValidationLogLine -Message ("Function App host is ready after {0:N1}s." -f $stopwatch.Elapsed.TotalSeconds) -ForegroundColor Green
                return
            }
        }
        catch {
            Write-Verbose ("Function host not ready yet: {0}" -f $_.Exception.Message)
        }

        $elapsedWholeSeconds = [Math]::Floor($stopwatch.Elapsed.TotalSeconds)
        if (($lastHeartbeatSecond + 30) -le $elapsedWholeSeconds) {
            Write-ValidationLogLine -Message ("Still waiting for Function App host readiness ({0}s elapsed)." -f $elapsedWholeSeconds)
            $lastHeartbeatSecond = $elapsedWholeSeconds
        }

        Start-Sleep -Seconds 10
    }

    throw "Timed out waiting for Function App host '$HostName' to become ready."
}

function Wait-FunctionAdminFunctionReady {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$HostName,

        [Parameter(Mandatory = $true)]
        [string]$MasterKey,

        [Parameter(Mandatory = $false)]
        [string]$FunctionName = 'ExportAndGenerate',

        [Parameter(Mandatory = $false)]
        [int]$TimeoutMinutes = 5
    )

    Write-ValidationLogLine -Message ("Waiting for admin function definition '{0}' on '{1}'..." -f $FunctionName, $HostName)

    $deadline = [datetime]::UtcNow.AddMinutes($TimeoutMinutes)
    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    $lastHeartbeatSecond = -30
    while ([datetime]::UtcNow -lt $deadline) {
        try {
            $response = Invoke-FunctionAdminRequest -Method Get -HostName $HostName -MasterKey $MasterKey -Path 'admin/functions'
            if ($null -ne $response -and $response.StatusCode -ge 200 -and $response.StatusCode -lt 300) {
                $definitions = @([string]$response.Content | ConvertFrom-Json -Depth 20)
                $matchingDefinition = @(
                    $definitions | Where-Object {
                        $name = if ($_.PSObject.Properties['name']) { [string]$_.name } else { '' }
                        $configName = if ($_.PSObject.Properties['config'] -and $_.config -and $_.config.PSObject.Properties['name']) { [string]$_.config.name } else { '' }
                        ($name -eq $FunctionName) -or
                        ($name -like "*/$FunctionName") -or
                        ($configName -eq $FunctionName)
                    }
                ) | Select-Object -First 1

                if ($null -ne $matchingDefinition) {
                    Write-ValidationLogLine -Message ("Admin function definition '{0}' is ready after {1:N1}s." -f $FunctionName, $stopwatch.Elapsed.TotalSeconds) -ForegroundColor Green
                    return
                }
            }
        }
        catch {
            Write-Verbose ("Function definition not ready yet: {0}" -f $_.Exception.Message)
        }

        $elapsedWholeSeconds = [Math]::Floor($stopwatch.Elapsed.TotalSeconds)
        if (($lastHeartbeatSecond + 30) -le $elapsedWholeSeconds) {
            Write-ValidationLogLine -Message ("Still waiting for admin function definition '{0}' ({1}s elapsed)." -f $FunctionName, $elapsedWholeSeconds)
            $lastHeartbeatSecond = $elapsedWholeSeconds
        }

        Start-Sleep -Seconds 10
    }

    throw "Timed out waiting for Function App admin definition '$FunctionName' on host '$HostName'."
}

function Start-FunctionExecution {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Internal helper triggers a Function App execution as part of scripted validation.')]
    [CmdletBinding()]
    [OutputType([datetime])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$HostName,

        [Parameter(Mandatory = $true)]
        [string]$MasterKey,

        [Parameter(Mandatory = $false)]
        [int]$TimeoutMinutes = 5
    )

    Write-ValidationLogLine -Message 'Invoking Function App admin endpoint...'

    $deadline = [datetime]::UtcNow.AddMinutes($TimeoutMinutes)
    $lastFailure = $null
    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    $lastHeartbeatSecond = -30
    while ([datetime]::UtcNow -lt $deadline) {
        try {
            $response = Invoke-FunctionAdminRequest -Method Post -HostName $HostName -MasterKey $MasterKey -Path 'admin/functions/ExportAndGenerate' -Body '{}'
            if ($null -ne $response -and $response.StatusCode -ge 200 -and $response.StatusCode -lt 300) {
                $startedUtc = [datetime]::UtcNow
                Write-ValidationLogLine -Message ("Function App execution accepted at {0}." -f $startedUtc.ToString('o')) -ForegroundColor Green
                return $startedUtc
            }

            $lastFailure = 'Function admin invocation returned no response.'
        }
        catch {
            $lastFailure = $_.Exception.Message
        }

        $elapsedWholeSeconds = [Math]::Floor($stopwatch.Elapsed.TotalSeconds)
        if (($lastHeartbeatSecond + 30) -le $elapsedWholeSeconds) {
            $message = if ([string]::IsNullOrWhiteSpace($lastFailure)) {
                'Function admin invocation has not succeeded yet.'
            }
            else {
                "Function admin invocation still waiting: $lastFailure"
            }

            Write-ValidationLogLine -Message ("{0} ({1}s elapsed)." -f $message, $elapsedWholeSeconds)
            $lastHeartbeatSecond = $elapsedWholeSeconds
        }

        Start-Sleep -Seconds 10
        Wait-FunctionHostReady -HostName $HostName -MasterKey $MasterKey -TimeoutMinutes 2
        Wait-FunctionAdminFunctionReady -HostName $HostName -MasterKey $MasterKey -TimeoutMinutes 2
    }

    if (-not [string]::IsNullOrWhiteSpace($lastFailure)) {
        throw "Function App execution did not start successfully. $lastFailure"
    }

    throw 'Function App execution did not start successfully before timeout.'
}

function Invoke-FunctionTraceCleanup {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$HostName,

        [Parameter(Mandatory = $true)]
        [string]$MasterKey
    )

    foreach ($path in @(
        'admin/vfs/tmp/FunctionsData/ExportAndGenerate.trace.log',
        'admin/vfs/home/site/diagnostics/ExportAndGenerate.trace.log'
    )) {
        try {
            $null = Invoke-FunctionAdminRequest -Method Delete -HostName $HostName -MasterKey $MasterKey -Path $path
        }
        catch {
            Write-Verbose ("Ignoring trace cleanup failure for {0}: {1}" -f $path, $_.Exception.Message)
        }
    }
}

function Get-FunctionTraceContent {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$HostName,

        [Parameter(Mandatory = $true)]
        [string]$MasterKey
    )

    foreach ($path in @(
        'admin/vfs/tmp/FunctionsData/ExportAndGenerate.trace.log',
        'admin/vfs/home/site/diagnostics/ExportAndGenerate.trace.log'
    )) {
        try {
            $response = Invoke-FunctionAdminRequest -Method Get -HostName $HostName -MasterKey $MasterKey -Path $path
        }
        catch {
            $response = $null
        }

        if ($null -eq $response) {
            continue
        }

        $content = [string]$response.Content
        if (-not [string]::IsNullOrWhiteSpace($content)) {
            return $content
        }
    }

    return $null
}

function ConvertTo-FunctionTraceEvent {
    [CmdletBinding()]
    [OutputType([object[]])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Content,

        [Parameter(Mandatory = $true)]
        [datetime]$NotBeforeUtc
    )

    $events = [System.Collections.Generic.List[object]]::new()
    foreach ($line in ($Content -split "`r?`n")) {
        if ($line -notmatch '^\[(?<timestamp>[^\]]+)\]\s?(?<message>.*)$') {
            continue
        }

        try {
            $timestampUtc = ([datetimeoffset]$matches.timestamp).UtcDateTime
        }
        catch {
            continue
        }

        if ($timestampUtc -lt $NotBeforeUtc.AddSeconds(-5)) {
            continue
        }

        $events.Add([PSCustomObject]@{
            timestamp_utc = $timestampUtc
            message = $matches.message
        }) | Out-Null
    }

    return @($events | Sort-Object timestamp_utc, message -Unique)
}

function Get-FunctionTraceTerminalStatus {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [object[]]$Events
    )

    if (@($Events | Where-Object { [string]$_.message -match 'Pipeline Failed!|^Error:' }).Count -gt 0) {
        return 'Failed'
    }

    if (@($Events | Where-Object { [string]$_.message -match 'Pipeline Complete!' }).Count -gt 0) {
        return 'Completed'
    }

    return $null
}

function Get-BlobLastModifiedUtc {
    [CmdletBinding()]
    [OutputType([datetime])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$StorageAccountName,

        [Parameter(Mandatory = $false)]
        [string]$ContainerName = 'dashboards',

        [Parameter(Mandatory = $false)]
        [string]$BlobName = 'VulnerabilityDashboard.html'
    )

    $output = & az storage blob show --auth-mode login --account-name $StorageAccountName --container-name $ContainerName --name $BlobName --query properties.lastModified -o tsv 2>$null
    if ($LASTEXITCODE -ne 0) {
        return (Get-BlobLastModifiedUtcViaRest -AccountName $StorageAccountName -ContainerName $ContainerName -BlobName $BlobName)
    }

    $text = ($output -join [Environment]::NewLine).Trim()
    if ([string]::IsNullOrWhiteSpace($text)) {
        return $null
    }

    return ([datetimeoffset]$text).UtcDateTime
}

function Get-BlobTextContent {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$StorageAccountName,

        [Parameter(Mandatory = $true)]
        [string]$ContainerName,

        [Parameter(Mandatory = $true)]
        [string]$BlobName
    )

    $downloadPath = Join-Path ([System.IO.Path]::GetTempPath()) ("validation-blob-{0}.tmp" -f [guid]::NewGuid().ToString('N'))
    try {
        & az storage blob download --auth-mode login --account-name $StorageAccountName --container-name $ContainerName --name $BlobName --file $downloadPath --output none 2>$null | Out-Null
        if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $downloadPath -PathType Leaf)) {
            return (Get-BlobTextViaRest -AccountName $StorageAccountName -ContainerName $ContainerName -BlobName $BlobName)
        }

        return (Get-Content -LiteralPath $downloadPath -Raw)
    }
    finally {
        Remove-Item -LiteralPath $downloadPath -Force -ErrorAction SilentlyContinue
    }
}

function Get-FunctionExecutionStatus {
    [CmdletBinding()]
    [OutputType([object])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$StorageAccountName
    )

    $content = Get-BlobTextContent -StorageAccountName $StorageAccountName -ContainerName $script:FunctionExecutionStatusContainerName -BlobName $script:FunctionExecutionStatusBlobName
    if ([string]::IsNullOrWhiteSpace($content)) {
        return $null
    }

    try {
        return ($content | ConvertFrom-Json -Depth 20)
    }
    catch {
        return [PSCustomObject]@{
            rawContent = $content
        }
    }
}

function Get-FunctionExecutionStatusSummaryText {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        $StatusDocument
    )

    if ($null -eq $StatusDocument) {
        return 'none'
    }

    if ($StatusDocument.PSObject.Properties['rawContent']) {
        return 'unparsed-status-blob'
    }

    $statusText = if ($StatusDocument.PSObject.Properties['status']) { [string]$StatusDocument.status } else { 'unknown' }
    $stageText = if ($StatusDocument.PSObject.Properties['stage']) { [string]$StatusDocument.stage } else { 'unknown' }
    $messageText = if ($StatusDocument.PSObject.Properties['message']) { [string]$StatusDocument.message } else { '' }
    $summaryText = if ([string]::IsNullOrWhiteSpace($messageText)) {
        ("{0}/{1}" -f $statusText, $stageText)
    }
    else {
        ("{0}/{1}: {2}" -f $statusText, $stageText, $messageText)
    }

    $metadataParts = [System.Collections.Generic.List[string]]::new()
    $architectureVersionText = if ($StatusDocument.PSObject.Properties['pipelineArchitectureVersion']) { [string]$StatusDocument.pipelineArchitectureVersion } else { '' }
    if (-not [string]::IsNullOrWhiteSpace($architectureVersionText)) {
        $metadataParts.Add("arch=$architectureVersionText") | Out-Null
    }

    if ($StatusDocument.PSObject.Properties['normalizedPayloadCacheHit']) {
        $metadataParts.Add(("payloadCache={0}" -f $(if ([bool]$StatusDocument.normalizedPayloadCacheHit) { 'hit' } else { 'miss' }))) | Out-Null
    }

    if ($StatusDocument.PSObject.Properties['normalizedSubPhase']) {
        $subPhaseText = [string]$StatusDocument.normalizedSubPhase
        if (-not [string]::IsNullOrWhiteSpace($subPhaseText)) {
            $metadataParts.Add("subphase=$subPhaseText") | Out-Null
        }
    }

    if ($StatusDocument.PSObject.Properties['normalizedRowCount']) {
        $rowCountText = [string]$StatusDocument.normalizedRowCount
        [long]$rowCountValue = 0
        if ([long]::TryParse($rowCountText, [ref]$rowCountValue)) {
            $metadataParts.Add(("rows={0}" -f $rowCountValue.ToString('N0', [System.Globalization.CultureInfo]::InvariantCulture))) | Out-Null
        }
        elseif (-not [string]::IsNullOrWhiteSpace($rowCountText)) {
            $metadataParts.Add("rows=$rowCountText") | Out-Null
        }
    }

    if ($metadataParts.Count -eq 0) {
        return $summaryText
    }

    return ("{0} ({1})" -f $summaryText, ($metadataParts -join ', '))
}

function Set-FunctionExecutionControlBlob {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Internal helper writes a short-lived control blob for scripted Function App validation.')]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$StorageAccountName,

        [Parameter(Mandatory = $true)]
        [bool]$UseExistingExportsOnly,

        [Parameter(Mandatory = $false)]
        [int]$ExpiresInMinutes = 30
    )

    $controlDocument = [ordered]@{
        version = 1
        source = 'Invoke-AzureDeploymentValidation'
        createdOnUtc = ([datetime]::UtcNow).ToString('o')
        notAfterUtc = ([datetime]::UtcNow.AddMinutes($ExpiresInMinutes)).ToString('o')
        useExistingExportsOnly = $UseExistingExportsOnly
    }

    $controlFilePath = Join-Path ([System.IO.Path]::GetTempPath()) ("function-control-{0}.json" -f [guid]::NewGuid().ToString('N'))
    try {
        $controlDocument | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $controlFilePath -Encoding utf8
        & az storage blob upload --auth-mode login --account-name $StorageAccountName --container-name $script:FunctionExecutionStatusContainerName --name $script:FunctionExecutionControlBlobName --file $controlFilePath --content-type application/json --overwrite --output none 2>$null | Out-Null
        if ($LASTEXITCODE -ne 0) {
            Set-BlobViaRest -AccountName $StorageAccountName -ContainerName $script:FunctionExecutionStatusContainerName -BlobName $script:FunctionExecutionControlBlobName -FilePath $controlFilePath -ContentType 'application/json'
        }
    }
    finally {
        Remove-Item -LiteralPath $controlFilePath -Force -ErrorAction SilentlyContinue
    }
}

function Remove-FunctionExecutionControlBlob {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Internal helper removes a short-lived control blob created for scripted Function App validation.')]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$StorageAccountName
    )

    & az storage blob delete --auth-mode login --account-name $StorageAccountName --container-name $script:FunctionExecutionStatusContainerName --name $script:FunctionExecutionControlBlobName --output none 2>$null | Out-Null
    if ($LASTEXITCODE -ne 0) {
        Remove-BlobViaRest -AccountName $StorageAccountName -ContainerName $script:FunctionExecutionStatusContainerName -BlobName $script:FunctionExecutionControlBlobName
    }
}

function Get-FunctionExecutionActivity {
    [CmdletBinding()]
    [OutputType([object])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ResourceId,

        [Parameter(Mandatory = $true)]
        [datetime]$StartTimeUtc,

        [Parameter(Mandatory = $true)]
        [datetime]$EndTimeUtc
    )

    $metrics = Invoke-AzCliJson -Arguments @(
        'monitor', 'metrics', 'list',
        '--resource', $ResourceId,
        '--start-time', $StartTimeUtc.ToString('o'),
        '--end-time', $EndTimeUtc.ToString('o'),
        '--interval', 'PT1M',
        '--aggregation', 'Total',
        '--metrics', 'OnDemandFunctionExecutionCount',
        '-o', 'json'
    )

    $totalCount = 0.0
    $latestTimestampUtc = $null

    foreach ($metric in @($metrics.value)) {
        foreach ($series in @($metric.timeseries)) {
            foreach ($dataPoint in @($series.data)) {
                if ($null -eq $dataPoint.total) {
                    continue
                }

                $pointTotal = [double]$dataPoint.total
                if ($pointTotal -le 0) {
                    continue
                }

                $totalCount += $pointTotal
                $pointTimestampUtc = ([datetimeoffset]$dataPoint.timeStamp).UtcDateTime
                if ($null -eq $latestTimestampUtc -or $pointTimestampUtc -gt $latestTimestampUtc) {
                    $latestTimestampUtc = $pointTimestampUtc
                }
            }
        }
    }

    return [PSCustomObject]@{
        total_count = [int][math]::Round($totalCount, 0)
        latest_timestamp_utc = $latestTimestampUtc
    }
}

function Get-FunctionMetricSummary {
    [CmdletBinding()]
    [OutputType([object])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ResourceId,

        [Parameter(Mandatory = $true)]
        [datetime]$StartTimeUtc,

        [Parameter(Mandatory = $true)]
        [datetime]$EndTimeUtc
    )

    $metrics = Invoke-AzCliJson -Arguments @(
        'monitor', 'metrics', 'list',
        '--resource', $ResourceId,
        '--start-time', $StartTimeUtc.ToString('o'),
        '--end-time', $EndTimeUtc.ToString('o'),
        '--interval', 'PT1M',
        '--aggregation', 'Average', 'Maximum', 'Total',
        '--metrics', 'MemoryWorkingSet', 'AverageMemoryWorkingSet', 'CpuPercentage', 'OnDemandFunctionExecutionUnits',
        '-o', 'json'
    )

    $peakWorkingSetMb = 0.0
    $averageWorkingSetMb = 0.0
    $peakCpuPercentage = 0.0
    $executionUnits = 0.0

    foreach ($metric in @($metrics.value)) {
        $metricName = [string]$metric.name.value
        $dataPoints = @($metric.timeseries | ForEach-Object { $_.data })
        foreach ($dataPoint in $dataPoints) {
            switch ($metricName) {
                'MemoryWorkingSet' {
                    if ($null -ne $dataPoint.maximum) {
                        $peakWorkingSetMb = [math]::Max($peakWorkingSetMb, ([double]$dataPoint.maximum / 1MB))
                    }
                    elseif ($null -ne $dataPoint.average) {
                        $peakWorkingSetMb = [math]::Max($peakWorkingSetMb, ([double]$dataPoint.average / 1MB))
                    }
                }
                'AverageMemoryWorkingSet' {
                    if ($null -ne $dataPoint.average) {
                        $averageWorkingSetMb = [math]::Max($averageWorkingSetMb, ([double]$dataPoint.average / 1MB))
                    }
                }
                'CpuPercentage' {
                    if ($null -ne $dataPoint.maximum) {
                        $peakCpuPercentage = [math]::Max($peakCpuPercentage, [double]$dataPoint.maximum)
                    }
                    elseif ($null -ne $dataPoint.average) {
                        $peakCpuPercentage = [math]::Max($peakCpuPercentage, [double]$dataPoint.average)
                    }
                }
                'OnDemandFunctionExecutionUnits' {
                    if ($null -ne $dataPoint.total) {
                        $executionUnits += [double]$dataPoint.total
                    }
                }
            }
        }
    }

    return [PSCustomObject]@{
        peak_working_set_mb = [math]::Round($peakWorkingSetMb, 1)
        average_working_set_mb = [math]::Round($averageWorkingSetMb, 1)
        peak_cpu_percentage = [math]::Round($peakCpuPercentage, 1)
        execution_units = [math]::Round($executionUnits, 2)
    }
}

function Get-FunctionTraceAccessState {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$HostName,

        [Parameter(Mandatory = $true)]
        [string]$MasterKey
    )

    $headers = @{ 'x-functions-key' = $MasterKey }
    $sawMissing = $false
    foreach ($path in @(
        'admin/vfs/tmp/FunctionsData/ExportAndGenerate.trace.log',
        'admin/vfs/home/site/diagnostics/ExportAndGenerate.trace.log',
        'admin/vfs/tmp/FunctionsData/FunctionProfile.trace.log',
        'admin/vfs/home/site/diagnostics/FunctionProfile.trace.log'
    )) {
        try {
            $null = Invoke-WebRequest -Method Get -Uri "https://$HostName/$path" -Headers $headers -ErrorAction Stop
            return 'Accessible'
        }
        catch {
            $response = $_.Exception.Response
            if ($null -eq $response) {
                return 'Unavailable'
            }

            switch ([int]$response.StatusCode) {
                403 { return 'Forbidden' }
                404 { $sawMissing = $true; continue }
                default { return ("HTTP {0}" -f [int]$response.StatusCode) }
            }
        }
    }

    if ($sawMissing) {
        return 'Missing'
    }

    return 'Unavailable'
}

function Invoke-FunctionExecutionValidation {
    [CmdletBinding()]
    [OutputType([object])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$FunctionAppName,

        [Parameter(Mandatory = $true)]
        [string]$FunctionResourceGroup,

        [Parameter(Mandatory = $true)]
        [string]$StorageAccountName,

        [Parameter(Mandatory = $true)]
        [string]$DashboardDeliveryMode,

        [Parameter(Mandatory = $true)]
        [int]$TimeoutMinutes,

        [Parameter(Mandatory = $false)]
        [switch]$UseExistingExportsOnly,

        [Parameter(Mandatory = $false)]
        [AllowEmptyString()]
        [string]$DatasetPath
    )

    $hostName = Invoke-AzCliText -Arguments @(
        'functionapp', 'show',
        '--name', $FunctionAppName,
        '--resource-group', $FunctionResourceGroup,
        '--query', 'properties.defaultHostName',
        '-o', 'tsv'
    )
    $functionResourceId = Invoke-AzCliText -Arguments @(
        'functionapp', 'show',
        '--name', $FunctionAppName,
        '--resource-group', $FunctionResourceGroup,
        '--query', 'id',
        '-o', 'tsv'
    )

    $masterKey = [string](Invoke-AzCliJson -Arguments @(
        'functionapp', 'keys', 'list',
        '--name', $FunctionAppName,
        '--resource-group', $FunctionResourceGroup,
        '-o', 'json'
    )).masterKey

    $originalTraceSetting = Get-FunctionAppSettingValue -FunctionAppName $FunctionAppName -FunctionResourceGroup $FunctionResourceGroup -SettingName 'PIPELINE_FILE_TRACE_ENABLED'
    $originalUseExistingExportsOnlySetting = Get-FunctionAppSettingValue -FunctionAppName $FunctionAppName -FunctionResourceGroup $FunctionResourceGroup -SettingName 'USE_EXISTING_EXPORTS_ONLY'
    $originalStorageAccountNameSetting = Get-FunctionAppSettingValue -FunctionAppName $FunctionAppName -FunctionResourceGroup $FunctionResourceGroup -SettingName 'STORAGE_ACCOUNT_NAME'
    $originalDashboardDeliveryModeSetting = Get-FunctionAppSettingValue -FunctionAppName $FunctionAppName -FunctionResourceGroup $FunctionResourceGroup -SettingName 'DASHBOARD_DELIVERY_MODE'
    $originalIncludeAdvancedHuntingSetting = Get-FunctionAppSettingValue -FunctionAppName $FunctionAppName -FunctionResourceGroup $FunctionResourceGroup -SettingName 'INCLUDE_ADVANCED_HUNTING'
    $beforeBlobUtc = Get-BlobLastModifiedUtc -StorageAccountName $StorageAccountName

    try {
        $settingsToApply = [System.Collections.Generic.List[string]]::new()
        $settingsToApply.Add(("STORAGE_ACCOUNT_NAME={0}" -f $StorageAccountName)) | Out-Null
        $settingsToApply.Add(("DASHBOARD_DELIVERY_MODE={0}" -f $DashboardDeliveryMode)) | Out-Null
        $settingsToApply.Add('INCLUDE_ADVANCED_HUNTING=true') | Out-Null
        $settingsToApply.Add('PIPELINE_FILE_TRACE_ENABLED=true') | Out-Null
        if ($UseExistingExportsOnly) {
            $settingsToApply.Add('USE_EXISTING_EXPORTS_ONLY=true') | Out-Null
        }

        Write-ValidationLogLine -Message 'Applying Function App execution settings...'
        Set-FunctionAppAppSettings -FunctionAppName $FunctionAppName -FunctionResourceGroup $FunctionResourceGroup -Settings @($settingsToApply)
        Restart-FunctionAppInstance -FunctionAppName $FunctionAppName -FunctionResourceGroup $FunctionResourceGroup -Reason 'apply execution validation settings'

        Refresh-FunctionExecutionTemplates -StorageAccountName $StorageAccountName
        Write-ValidationLogLine -Message ("Clearing dashboard container in storage account '{0}'..." -f $StorageAccountName)
        Clear-BlobContainer -AccountName $StorageAccountName -ContainerName 'dashboards'
        $beforeBlobUtc = $null

        if ($UseExistingExportsOnly) {
            if (-not [string]::IsNullOrWhiteSpace($DatasetPath)) {
                Write-ValidationLogLine -Message ("Seeding Function App exports from local dataset: {0}" -f $DatasetPath)
                Seed-ExportsContainer -AccountName $StorageAccountName -DatasetPath $DatasetPath
            }
            else {
                Write-ValidationLogLine -Message 'USE_EXISTING_EXPORTS_ONLY execution validation is reusing whatever export blobs already exist in storage. Pass -FunctionExecutionDatasetPath for deterministic validation input.' -ForegroundColor Yellow
            }

            Write-ValidationLogLine -Message 'Uploading short-lived execution control blob to force seeded-export mode during validation...'
            Set-FunctionExecutionControlBlob -StorageAccountName $StorageAccountName -UseExistingExportsOnly $true
        }

        Wait-FunctionHostReady -HostName $hostName -MasterKey $masterKey -TimeoutMinutes 10
        Wait-FunctionAdminFunctionReady -HostName $hostName -MasterKey $masterKey -TimeoutMinutes 5
        Invoke-FunctionTraceCleanup -HostName $hostName -MasterKey $masterKey

        $traceAccessState = Get-FunctionTraceAccessState -HostName $hostName -MasterKey $masterKey
        if ($traceAccessState -ne 'Accessible') {
            Write-ValidationLogLine -Message ("Function trace files are not directly readable via admin VFS ({0}). Falling back to Azure Monitor execution metrics and dashboard blob polling." -f $traceAccessState) -ForegroundColor Yellow
        }

        $invokeStartedUtc = Start-FunctionExecution -HostName $hostName -MasterKey $masterKey -TimeoutMinutes 5
        Write-ValidationLogLine -Message ("Waiting for a fresh dashboard blob write until {0}." -f $invokeStartedUtc.AddMinutes($TimeoutMinutes).ToString('o'))

        $deadlineUtc = $invokeStartedUtc.AddMinutes($TimeoutMinutes)
        $events = @()
        $terminalStatus = $null
        $blobUpdated = $false
        $finalBlobUtc = $beforeBlobUtc
        $completionSource = $null
        $waitStopwatch = [System.Diagnostics.Stopwatch]::StartNew()
        $lastHeartbeatSecond = -60
        $executionActivity = $null
        $metricSummary = $null
        $lastExecutionMetricPollUtc = [datetime]::MinValue
        $latestPipelineStatus = $null
        $latestPipelineStatusBlobUtc = $null

        while ([datetime]::UtcNow -lt $deadlineUtc) {
            $nowUtc = [datetime]::UtcNow

            $content = Get-FunctionTraceContent -HostName $hostName -MasterKey $masterKey
            if (-not [string]::IsNullOrWhiteSpace($content)) {
                $events = @(ConvertTo-FunctionTraceEvent -Content $content -NotBeforeUtc $invokeStartedUtc)
                $terminalStatus = Get-FunctionTraceTerminalStatus -Events $events
            }

            if ($nowUtc -ge $lastExecutionMetricPollUtc.AddSeconds(60)) {
                $executionActivity = Get-FunctionExecutionActivity -ResourceId $functionResourceId -StartTimeUtc $invokeStartedUtc.AddMinutes(-1) -EndTimeUtc $nowUtc
                $metricSummary = Get-FunctionMetricSummary -ResourceId $functionResourceId -StartTimeUtc $invokeStartedUtc.AddMinutes(-1) -EndTimeUtc $nowUtc
                $lastExecutionMetricPollUtc = $nowUtc
            }

            $statusBlobUtc = Get-BlobLastModifiedUtc -StorageAccountName $StorageAccountName -ContainerName $script:FunctionExecutionStatusContainerName -BlobName $script:FunctionExecutionStatusBlobName
            if ($null -ne $statusBlobUtc -and ($null -eq $latestPipelineStatusBlobUtc -or $statusBlobUtc -gt $latestPipelineStatusBlobUtc)) {
                $statusDocument = Get-FunctionExecutionStatus -StorageAccountName $StorageAccountName
                if ($null -ne $statusDocument) {
                    $latestPipelineStatus = $statusDocument
                    $latestPipelineStatusBlobUtc = $statusBlobUtc
                }
            }

            $finalBlobUtc = Get-BlobLastModifiedUtc -StorageAccountName $StorageAccountName
            $blobUpdated = ($null -ne $finalBlobUtc -and $finalBlobUtc -ge $invokeStartedUtc.AddSeconds(-5))

            if ($terminalStatus -eq 'Failed') {
                Write-ValidationLogLine -Message 'Function App trace reported pipeline failure.' -ForegroundColor Red
                break
            }

            if ($blobUpdated) {
                Write-ValidationLogLine -Message ("Function App wrote dashboard blob at {0}." -f $finalBlobUtc.ToString('o')) -ForegroundColor Green
                $completionSource = if ($terminalStatus -eq 'Completed') { 'trace-and-blob' } else { 'blob-write' }
                break
            }

            if ($null -ne $latestPipelineStatus -and $latestPipelineStatus.PSObject.Properties['status'] -and [string]$latestPipelineStatus.status -eq 'failed') {
                Write-ValidationLogLine -Message ("Function execution status blob reported failure: {0}" -f (Get-FunctionExecutionStatusSummaryText -StatusDocument $latestPipelineStatus)) -ForegroundColor Red
                break
            }

            $elapsedWholeSeconds = [Math]::Floor($waitStopwatch.Elapsed.TotalSeconds)
            if (($lastHeartbeatSecond + 60) -le $elapsedWholeSeconds) {
                $lastTraceMessage = if ($events.Count -gt 0) {
                    [string]$events[-1].message
                }
                else {
                    'no trace events yet'
                }
                $blobText = if ($null -eq $finalBlobUtc) { 'none' } else { $finalBlobUtc.ToString('o') }
                $terminalText = if ([string]::IsNullOrWhiteSpace([string]$terminalStatus)) { 'Running' } else { $terminalStatus }
                $executionCount = if ($null -ne $executionActivity -and $executionActivity.PSObject.Properties['total_count']) { [int]$executionActivity.total_count } else { 0 }
                $executionTimestampText = if ($null -ne $executionActivity -and $executionActivity.PSObject.Properties['latest_timestamp_utc'] -and $null -ne $executionActivity.latest_timestamp_utc) {
                    ([datetime]$executionActivity.latest_timestamp_utc).ToString('o')
                }
                else {
                    'none'
                }
                $peakWorkingSetText = if ($null -ne $metricSummary -and $metricSummary.PSObject.Properties['peak_working_set_mb']) {
                    [string]([double]$metricSummary.peak_working_set_mb)
                }
                else {
                    'n/a'
                }
                $averageWorkingSetText = if ($null -ne $metricSummary -and $metricSummary.PSObject.Properties['average_working_set_mb']) {
                    [string]([double]$metricSummary.average_working_set_mb)
                }
                else {
                    'n/a'
                }
                $executionUnitsText = if ($null -ne $metricSummary -and $metricSummary.PSObject.Properties['execution_units']) {
                    [string]([double]$metricSummary.execution_units)
                }
                else {
                    'n/a'
                }
                $pipelineStatusText = Get-FunctionExecutionStatusSummaryText -StatusDocument $latestPipelineStatus

                Write-ValidationLogLine -Message ("Function execution heartbeat: {0}s elapsed; terminalStatus={1}; dashboardBlob={2}; executionCount={3}; latestExecutionMetric={4}; peakWorkingSetMb={5}; averageWorkingSetMb={6}; executionUnits={7}; traceAccess={8}; pipelineStatus={9}; lastTrace={10}" -f $elapsedWholeSeconds, $terminalText, $blobText, $executionCount, $executionTimestampText, $peakWorkingSetText, $averageWorkingSetText, $executionUnitsText, $traceAccessState, $pipelineStatusText, $lastTraceMessage)
                $lastHeartbeatSecond = $elapsedWholeSeconds
            }

            Start-Sleep -Seconds 15
        }

        $executionActivity = Get-FunctionExecutionActivity -ResourceId $functionResourceId -StartTimeUtc $invokeStartedUtc.AddMinutes(-1) -EndTimeUtc ([datetime]::UtcNow)
        $metricSummary = Get-FunctionMetricSummary -ResourceId $functionResourceId -StartTimeUtc $invokeStartedUtc.AddMinutes(-1) -EndTimeUtc ([datetime]::UtcNow)

        if ($terminalStatus -eq 'Failed') {
            throw 'Function App trace reported pipeline failure.'
        }

        if ($null -ne $latestPipelineStatus -and $latestPipelineStatus.PSObject.Properties['status'] -and [string]$latestPipelineStatus.status -eq 'failed') {
            $pipelineStatusText = Get-FunctionExecutionStatusSummaryText -StatusDocument $latestPipelineStatus
            $pipelineErrorText = if ($latestPipelineStatus.PSObject.Properties['error']) { [string]$latestPipelineStatus.error } else { $null }
            if ([string]::IsNullOrWhiteSpace($pipelineErrorText)) {
                throw ("Function App status blob reported failure. {0}" -f $pipelineStatusText)
            }

            throw ("Function App status blob reported failure. {0}. Error: {1}" -f $pipelineStatusText, $pipelineErrorText)
        }

        if (-not $blobUpdated) {
            $executionCount = if ($null -ne $executionActivity -and $executionActivity.PSObject.Properties['total_count']) { [int]$executionActivity.total_count } else { 0 }
            $executionTimestampText = if ($null -ne $executionActivity -and $executionActivity.PSObject.Properties['latest_timestamp_utc'] -and $null -ne $executionActivity.latest_timestamp_utc) {
                ([datetime]$executionActivity.latest_timestamp_utc).ToString('o')
            }
            else {
                $null
            }
            $pipelineStatusText = Get-FunctionExecutionStatusSummaryText -StatusDocument $latestPipelineStatus

            if ($terminalStatus -eq 'Completed') {
                throw 'Function App completed trace did not coincide with a fresh dashboard blob write.'
            }

            if ($executionCount -gt 0) {
                $executionDetail = if ([string]::IsNullOrWhiteSpace($executionTimestampText)) {
                    ("Function App executed {0} time(s) according to Azure Monitor" -f $executionCount)
                }
                else {
                    ("Function App executed {0} time(s) according to Azure Monitor (latest metric timestamp {1})" -f $executionCount, $executionTimestampText)
                }

                if ($traceAccessState -eq 'Forbidden') {
                    throw ("{0}, but no dashboard blob was written before timeout and admin VFS trace access is forbidden on this Flex app. Latest pipeline status: {1}" -f $executionDetail, $pipelineStatusText)
                }

                throw ("{0}, but no dashboard blob was written before timeout. Latest pipeline status: {1}" -f $executionDetail, $pipelineStatusText)
            }

            throw ("Function App did not write a fresh dashboard blob before timeout. Latest pipeline status: {0}" -f $pipelineStatusText)
        }

        return [PSCustomObject]@{
            hostName = $hostName
            invocationStartedUtc = $invokeStartedUtc.ToString('o')
            dashboardBlobLastModifiedUtc = $finalBlobUtc.ToString('o')
            executionMode = if ($UseExistingExportsOnly) { 'existing-exports-only' } else { 'live-export' }
            executionDatasetPath = if ([string]::IsNullOrWhiteSpace($DatasetPath)) { $null } else { $DatasetPath }
            terminalStatus = if ([string]::IsNullOrWhiteSpace([string]$terminalStatus)) { 'BlobUpdatedWithoutTerminalTrace' } else { $terminalStatus }
            completionSource = $completionSource
            traceAccessState = $traceAccessState
            executionCount = if ($null -ne $executionActivity -and $executionActivity.PSObject.Properties['total_count']) { [int]$executionActivity.total_count } else { 0 }
            latestExecutionMetricUtc = if ($null -ne $executionActivity -and $executionActivity.PSObject.Properties['latest_timestamp_utc'] -and $null -ne $executionActivity.latest_timestamp_utc) { ([datetime]$executionActivity.latest_timestamp_utc).ToString('o') } else { $null }
            hostedMetrics = $metricSummary
            pipelineStatus = $latestPipelineStatus
            recentTraceEvents = @($events | Select-Object -Last 12)
        }
    }
    finally {
        Restore-FunctionAppSettingValue -FunctionAppName $FunctionAppName -FunctionResourceGroup $FunctionResourceGroup -SettingName 'PIPELINE_FILE_TRACE_ENABLED' -OriginalValue $originalTraceSetting
        Restore-FunctionAppSettingValue -FunctionAppName $FunctionAppName -FunctionResourceGroup $FunctionResourceGroup -SettingName 'STORAGE_ACCOUNT_NAME' -OriginalValue $originalStorageAccountNameSetting
        Restore-FunctionAppSettingValue -FunctionAppName $FunctionAppName -FunctionResourceGroup $FunctionResourceGroup -SettingName 'DASHBOARD_DELIVERY_MODE' -OriginalValue $originalDashboardDeliveryModeSetting
        Restore-FunctionAppSettingValue -FunctionAppName $FunctionAppName -FunctionResourceGroup $FunctionResourceGroup -SettingName 'INCLUDE_ADVANCED_HUNTING' -OriginalValue $originalIncludeAdvancedHuntingSetting

        if ($UseExistingExportsOnly) {
            Remove-FunctionExecutionControlBlob -StorageAccountName $StorageAccountName
            Restore-FunctionAppSettingValue -FunctionAppName $FunctionAppName -FunctionResourceGroup $FunctionResourceGroup -SettingName 'USE_EXISTING_EXPORTS_ONLY' -OriginalValue $originalUseExistingExportsOnlySetting
        }
    }
}

if (-not (Test-Path -LiteralPath $setupScriptPath -PathType Leaf)) {
    throw "Setup script not found: $setupScriptPath"
}

$account = Assert-AzureSessionAvailable
$subscriptionId = [string]$account.id
$functionResourceGroup = if ($ResourceGroupName) {
    $ResourceGroupName
}
else {
    Resolve-ResourceGroupForResource -Name $FunctionAppName -ResourceType 'Microsoft.Web/sites'
}
$automationResourceGroup = if ($ResourceGroupName) {
    $ResourceGroupName
}
else {
    Resolve-ResourceGroupForResource -Name $AutomationAccountName -ResourceType 'Microsoft.Automation/automationAccounts'
}
$effectiveDashboardDeliveryMode = Resolve-DashboardDeliveryMode -AutomationAccountName $AutomationAccountName -FunctionAppName $FunctionAppName -SubscriptionId $subscriptionId -AutomationResourceGroup $automationResourceGroup -FunctionResourceGroup $functionResourceGroup -RequestedDashboardDeliveryMode $DashboardDeliveryMode
$resolvedValidationDatasetPath = $null
if ($SkipMdePermissions) {
    $resolvedValidationDatasetPath = Resolve-FunctionExecutionDatasetPath -RequestedPath $FunctionExecutionDatasetPath
}

Write-ValidationLogLine -Message 'Regenerating Azure deployment artifacts locally...' -ForegroundColor Cyan
Invoke-TimestampedCommand -FailureDescription 'Runbook build' -ScriptBlock { & (Join-Path $buildRoot 'azure\Build-Runbook.ps1') }
Invoke-TimestampedCommand -FailureDescription 'Function App build' -ScriptBlock { & (Join-Path $buildRoot 'azure\Build-FunctionApp.ps1') }

$setupCommonParameters = @{
    SkipMdePermissions = $SkipMdePermissions
    ValidationTimeoutSeconds = $ValidationTimeoutSeconds
    DashboardDeliveryMode = $effectiveDashboardDeliveryMode
}

if (-not [string]::IsNullOrWhiteSpace($resolvedValidationDatasetPath)) {
    $setupCommonParameters.ValidationDatasetPath = $resolvedValidationDatasetPath
}

if ($ResourceGroupName) {
    $setupCommonParameters.ResourceGroupName = $ResourceGroupName
}

if (-not $SkipAutomationValidation) {
    Write-ValidationLogLine -Message 'Validating Azure Automation deployment...' -ForegroundColor Cyan
    Invoke-TimestampedCommand -FailureDescription 'Azure Automation deployment validation' -ScriptBlock { & $setupScriptPath @setupCommonParameters -AutomationAccountName $AutomationAccountName }
}
else {
    Write-ValidationLogLine -Message 'Skipping Azure Automation deployment validation at the caller''s request.' -ForegroundColor Yellow
}

Write-ValidationLogLine -Message 'Validating Azure Function App deployment...' -ForegroundColor Cyan
Invoke-TimestampedCommand -FailureDescription 'Azure Function App deployment validation' -ScriptBlock { & $setupScriptPath @setupCommonParameters -ComputeType FunctionApp -FunctionAppName $FunctionAppName }

$functionExecutionResult = $null
if (-not $SkipFunctionExecution) {
    $storageAccountName = Get-FunctionAppSettingValue -FunctionAppName $FunctionAppName -FunctionResourceGroup $functionResourceGroup -SettingName 'STORAGE_ACCOUNT_NAME'
    if ([string]::IsNullOrWhiteSpace($storageAccountName)) {
        throw "STORAGE_ACCOUNT_NAME is not configured on Function App '$FunctionAppName'."
    }

    Write-ValidationLogLine -Message 'Validating Function App execution...' -ForegroundColor Cyan
    $functionExecutionResult = Invoke-FunctionExecutionValidation -FunctionAppName $FunctionAppName -FunctionResourceGroup $functionResourceGroup -StorageAccountName $storageAccountName -DashboardDeliveryMode $effectiveDashboardDeliveryMode -TimeoutMinutes $FunctionExecutionTimeoutMinutes -UseExistingExportsOnly:$SkipMdePermissions -DatasetPath $resolvedValidationDatasetPath
}

$result = [PSCustomObject]@{
    subscriptionId = $subscriptionId
    automationAccountName = $AutomationAccountName
    automationResourceGroup = $automationResourceGroup
    functionAppName = $FunctionAppName
    functionResourceGroup = $functionResourceGroup
    dashboardDeliveryMode = $effectiveDashboardDeliveryMode
    skipAutomationValidation = [bool]$SkipAutomationValidation
    functionExecution = $functionExecutionResult
}

Write-ValidationLogLine -Message 'Azure deployment validation completed successfully.' -ForegroundColor Green
$result
