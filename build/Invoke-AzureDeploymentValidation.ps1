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
    [ValidateSet('Auto', 'SelfContained', 'Hosted')]
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
    [switch]$SkipFunctionExecution
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$buildRoot = $PSScriptRoot
$repoRoot = Split-Path -Path $buildRoot -Parent
$setupScriptPath = Join-Path $repoRoot 'Setup-AzureResources.ps1'

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

    $deadline = [datetime]::UtcNow.AddMinutes($TimeoutMinutes)
    while ([datetime]::UtcNow -lt $deadline) {
        try {
            $response = Invoke-FunctionAdminRequest -Method Get -HostName $HostName -MasterKey $MasterKey -Path 'admin/host/status'
            if ($null -ne $response -and $response.StatusCode -ge 200 -and $response.StatusCode -lt 300) {
                return
            }
        }
        catch {
            Write-Verbose ("Function host not ready yet: {0}" -f $_.Exception.Message)
        }

        Start-Sleep -Seconds 10
    }

    throw "Timed out waiting for Function App host '$HostName' to become ready."
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
        [string]$StorageAccountName
    )

    $output = & az storage blob show --auth-mode login --account-name $StorageAccountName --container-name dashboards --name VulnerabilityDashboard.html --query properties.lastModified -o tsv 2>$null
    if ($LASTEXITCODE -ne 0) {
        return $null
    }

    $text = ($output -join [Environment]::NewLine).Trim()
    if ([string]::IsNullOrWhiteSpace($text)) {
        return $null
    }

    return ([datetimeoffset]$text).UtcDateTime
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
        [int]$TimeoutMinutes
    )

    $hostName = Invoke-AzCliText -Arguments @(
        'functionapp', 'show',
        '--name', $FunctionAppName,
        '--resource-group', $FunctionResourceGroup,
        '--query', 'properties.defaultHostName',
        '-o', 'tsv'
    )

    $masterKey = [string](Invoke-AzCliJson -Arguments @(
        'functionapp', 'keys', 'list',
        '--name', $FunctionAppName,
        '--resource-group', $FunctionResourceGroup,
        '-o', 'json'
    )).masterKey

    $originalTraceSetting = Get-FunctionAppSettingValue -FunctionAppName $FunctionAppName -FunctionResourceGroup $FunctionResourceGroup -SettingName 'PIPELINE_FILE_TRACE_ENABLED'
    $beforeBlobUtc = Get-BlobLastModifiedUtc -StorageAccountName $StorageAccountName

    try {
        & az functionapp config appsettings set --name $FunctionAppName --resource-group $FunctionResourceGroup --settings 'PIPELINE_FILE_TRACE_ENABLED=true' --output none | Out-Null
        if ($LASTEXITCODE -ne 0) {
            throw 'Failed to enable PIPELINE_FILE_TRACE_ENABLED for Function App execution validation.'
        }

        Wait-FunctionHostReady -HostName $hostName -MasterKey $masterKey -TimeoutMinutes 10
        Invoke-FunctionTraceCleanup -HostName $hostName -MasterKey $masterKey

        $invokeStartedUtc = [datetime]::UtcNow
        $null = Invoke-FunctionAdminRequest -Method Post -HostName $hostName -MasterKey $masterKey -Path 'admin/functions/ExportAndGenerate' -Body '{}'

        $deadlineUtc = $invokeStartedUtc.AddMinutes($TimeoutMinutes)
        $events = @()
        $terminalStatus = $null
        $blobUpdated = $false
        $finalBlobUtc = $beforeBlobUtc

        while ([datetime]::UtcNow -lt $deadlineUtc) {
            $content = Get-FunctionTraceContent -HostName $hostName -MasterKey $masterKey
            if (-not [string]::IsNullOrWhiteSpace($content)) {
                $events = @(ConvertTo-FunctionTraceEvent -Content $content -NotBeforeUtc $invokeStartedUtc)
                $terminalStatus = Get-FunctionTraceTerminalStatus -Events $events
            }

            $finalBlobUtc = Get-BlobLastModifiedUtc -StorageAccountName $StorageAccountName
            $blobUpdated = ($null -ne $finalBlobUtc -and $finalBlobUtc -ge $invokeStartedUtc.AddSeconds(-5))

            if ($terminalStatus -eq 'Failed') {
                break
            }

            if ($terminalStatus -eq 'Completed' -and $blobUpdated) {
                break
            }

            Start-Sleep -Seconds 15
        }

        if ($terminalStatus -eq 'Failed') {
            throw 'Function App trace reported pipeline failure.'
        }

        if ($terminalStatus -ne 'Completed') {
            throw 'Function App did not report Pipeline Complete! before timeout.'
        }

        if (-not $blobUpdated) {
            throw 'Function App completed trace did not coincide with a fresh dashboard blob write.'
        }

        return [PSCustomObject]@{
            hostName = $hostName
            invocationStartedUtc = $invokeStartedUtc.ToString('o')
            dashboardBlobLastModifiedUtc = $finalBlobUtc.ToString('o')
            terminalStatus = $terminalStatus
            recentTraceEvents = @($events | Select-Object -Last 12)
        }
    }
    finally {
        if ($null -eq $originalTraceSetting) {
            & az functionapp config appsettings delete --name $FunctionAppName --resource-group $FunctionResourceGroup --setting-names PIPELINE_FILE_TRACE_ENABLED --output none | Out-Null
        }
        else {
            & az functionapp config appsettings set --name $FunctionAppName --resource-group $FunctionResourceGroup --settings ("PIPELINE_FILE_TRACE_ENABLED={0}" -f $originalTraceSetting) --output none | Out-Null
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

Write-Output 'Regenerating Azure deployment artifacts locally...'
& (Join-Path $buildRoot 'azure\Build-Runbook.ps1')
& (Join-Path $buildRoot 'azure\Build-FunctionApp.ps1')

$setupCommonParameters = @{
    SkipMdePermissions = $SkipMdePermissions
    ValidationTimeoutSeconds = $ValidationTimeoutSeconds
    DashboardDeliveryMode = $effectiveDashboardDeliveryMode
}

if ($ResourceGroupName) {
    $setupCommonParameters.ResourceGroupName = $ResourceGroupName
}

Write-Output 'Validating Azure Automation deployment...'
& $setupScriptPath @setupCommonParameters -AutomationAccountName $AutomationAccountName

Write-Output 'Validating Azure Function App deployment...'
& $setupScriptPath @setupCommonParameters -ComputeType FunctionApp -FunctionAppName $FunctionAppName

$functionExecutionResult = $null
if (-not $SkipFunctionExecution) {
    $storageAccountName = Get-FunctionAppSettingValue -FunctionAppName $FunctionAppName -FunctionResourceGroup $functionResourceGroup -SettingName 'STORAGE_ACCOUNT_NAME'
    if ([string]::IsNullOrWhiteSpace($storageAccountName)) {
        throw "STORAGE_ACCOUNT_NAME is not configured on Function App '$FunctionAppName'."
    }

    Write-Output 'Validating Function App execution...'
    $functionExecutionResult = Invoke-FunctionExecutionValidation -FunctionAppName $FunctionAppName -FunctionResourceGroup $functionResourceGroup -StorageAccountName $storageAccountName -TimeoutMinutes $FunctionExecutionTimeoutMinutes
}

$result = [PSCustomObject]@{
    subscriptionId = $subscriptionId
    automationAccountName = $AutomationAccountName
    automationResourceGroup = $automationResourceGroup
    functionAppName = $FunctionAppName
    functionResourceGroup = $functionResourceGroup
    dashboardDeliveryMode = $effectiveDashboardDeliveryMode
    functionExecution = $functionExecutionResult
}

Write-Output 'Azure deployment validation completed successfully.'
$result