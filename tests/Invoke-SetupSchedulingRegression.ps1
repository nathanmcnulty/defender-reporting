#Requires -Version 7.0
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path $PSScriptRoot -Parent
$parseErrors = $null
$setupAst = [System.Management.Automation.Language.Parser]::ParseFile((Join-Path $repoRoot 'Setup-AzureResources.ps1'), [ref]$null, [ref]$parseErrors)
if ($parseErrors.Count) { throw ($parseErrors | Out-String) }
$scheduleAssignment = $setupAst.Find({ param($node) $node -is [System.Management.Automation.Language.AssignmentStatementAst] -and $node.Left.Extent.Text -eq '$scheduleName' }, $true)
$scheduleConditional = $setupAst.Find({ param($node) $node -is [System.Management.Automation.Language.IfStatementAst] -and $node.Clauses[0].Item1.Extent.Text -eq '$PSCmdlet.ShouldProcess($scheduleName, "Create schedule")' }, $true)
if (-not $scheduleAssignment -or -not $scheduleConditional) { throw 'Automation schedule setup block not found.' }
$scheduleStatements = $scheduleAssignment.Parent.Statements | Where-Object { $_.Extent.StartOffset -ge $scheduleAssignment.Extent.StartOffset -and $_.Extent.EndOffset -le $scheduleConditional.Extent.EndOffset }
$scheduleBlock = [scriptblock]::Create(($scheduleStatements.Extent.Text -join "`n"))

function Assert-True([bool]$Condition, [string]$Message) {
    if (-not $Condition) { throw $Message }
}

function Remove-AutomationJobSchedulesByScheduleName {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '', Justification = 'Mock accepts the production cleanup signature without modifying cloud resources.')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'No-op ARM cleanup mock has no side effects.')]
    param($SubscriptionPath, $ResourceGroupName, $AutomationAccountName, $ScheduleName)
}
function Invoke-ArmApi {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '', Justification = 'Mock accepts the production ARM signature.')]
    param($Path, $Method, $Payload, $Description)
    $script:Requests.Add(@{ Path = $Path; Method = $Method; Payload = $Payload })
    if ($Path -match '/Microsoft.Web/sites/') {
        if ($Method -eq 'POST') {
            if ($script:FailSettingsRead) { throw 'Injected settings read failure.' }
            return @{ properties = $script:FunctionSettings }
        }
        if ($Method -eq 'PUT') {
            $script:FunctionSettings = @{}
            foreach ($setting in ($Payload | ConvertFrom-Json).properties.siteConfig.appSettings) {
                $script:FunctionSettings[$setting.name] = $setting.value
            }
            if ($script:IgnoreFunctionDisable) { $script:FunctionSettings['AzureWebJobs.ExportAndGenerate.Disabled'] = 'false' }
        }
        return
    }
    if ($Path -match '/schedules/daily\?') {
        if ($Method -eq 'PUT') {
            $script:ScheduleState = ($Payload | ConvertFrom-Json).properties
            $script:ScheduleState.isEnabled = $true
        }
        elseif ($Method -eq 'PATCH') {
            if (-not $script:IgnoreSchedulePatch) { $script:ScheduleState.isEnabled = ($Payload | ConvertFrom-Json).properties.isEnabled }
        }
        elseif ($Method -eq 'GET') { return @{ properties = $script:ScheduleState } }
    }
}

function Invoke-ScheduleScenario {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '', Justification = 'Variables are consumed by the extracted production Setup script block in child scope.')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '', Justification = 'The extracted production Setup block invokes this command context ShouldProcess.')]
    [CmdletBinding(SupportsShouldProcess)]
    param([bool]$SkipMdePermissions, [bool]$IgnoreSchedulePatch = $false)
    $script:Requests = [System.Collections.Generic.List[object]]::new()
    $script:IgnoreSchedulePatch = $IgnoreSchedulePatch
    $script:AutomationDailyScheduleName = 'daily'
    $script:AutomationLegacyWeeklyScheduleName = 'weekly'
    $script:ArmApiVersions = @{ AutomationAccount = '2023-11-01' }
    $subPath = '/subscriptions/mock'
    $ResourceGroupName = 'rg-mock'
    $AutomationAccountName = 'aa-mock'
    $StorageAccountName = 'mockstorage'
    $effectiveDashboardDeliveryMode = 'Dual'
    $runbookName = 'pipeline'
    & $scheduleBlock
    Assert-True ($script:ScheduleState.isEnabled -eq (-not $SkipMdePermissions)) 'Schedule readback did not match requested state.'
    $schedulePut = $script:Requests | Where-Object { $_.Method -eq 'PUT' -and $_.Path -match '/schedules/daily\?' }
    Assert-True (($schedulePut.Payload | ConvertFrom-Json).properties.isEnabled -eq (-not $SkipMdePermissions)) 'Schedule creation used the wrong enabled state.'
    $link = $script:Requests | Where-Object { $_.Path -match '/jobSchedules/' }
    Assert-True (($link.Payload | ConvertFrom-Json).properties.parameters.DashboardDeliveryMode -eq 'Dual') 'Schedule link lost Dual delivery mode.'
}

Invoke-ScheduleScenario -SkipMdePermissions $true
Invoke-ScheduleScenario -SkipMdePermissions $false
$failureDetected = $false
try { Invoke-ScheduleScenario -SkipMdePermissions $true -IgnoreSchedulePatch $true }
catch {
    if ($_.Exception.Message -notlike '*did not reach the requested enabled state*') { throw }
    $failureDetected = $true
}
Assert-True $failureDetected 'Enabled schedule readback must fail closed when disabling does not take effect.'
Assert-True (-not ($script:Requests | Where-Object { $_.Path -match '/jobSchedules/' })) 'Failed schedule verification must not link the runbook.'

$functionAssignment = $setupAst.Find({ param($node) $node -is [System.Management.Automation.Language.AssignmentStatementAst] -and $node.Left.Extent.Text -eq '$functionAppPath' }, $true)
$functionConditional = $setupAst.Find({ param($node) $node -is [System.Management.Automation.Language.IfStatementAst] -and $node.Clauses[0].Item1.Extent.Text -eq '$PSCmdlet.ShouldProcess($FunctionAppName, "Create/update Function App")' }, $true)
if (-not $functionAssignment -or -not $functionConditional) { throw 'Function App setup block not found.' }
$functionStatements = $functionAssignment.Parent.Statements | Where-Object { $_.Extent.StartOffset -ge $functionAssignment.Extent.StartOffset -and $_.Extent.EndOffset -le $functionConditional.Extent.EndOffset }
$functionBlock = [scriptblock]::Create(($functionStatements.Extent.Text -join "`n"))
$payloadHelper = $setupAst.Find({ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Get-CreateOnlyProvisioningPayload' }, $true)
. ([scriptblock]::Create($payloadHelper.Extent.Text))
function Get-OptionalArmResource {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '', Justification = 'Mock accepts the production resource lookup signature.')]
    param($Path, $Description)
    return @{ Exists = $script:FunctionExists }
}

function Invoke-FunctionScenario {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '', Justification = 'Variables are consumed by the extracted production Setup script block in child scope.')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '', Justification = 'The extracted production Setup block invokes this command context ShouldProcess.')]
    [CmdletBinding(SupportsShouldProcess)]
    param([bool]$SkipMdePermissions, [bool]$Exists, [bool]$IgnoreFunctionDisable = $false, [bool]$FailSettingsRead = $false)
    $script:Requests = [System.Collections.Generic.List[object]]::new()
    $script:FunctionExists = $Exists
    $script:IgnoreFunctionDisable = $IgnoreFunctionDisable
    $script:FailSettingsRead = $FailSettingsRead
    $script:FunctionSettings = @{}
    if ($Exists) {
        $script:FunctionSettings = @{
            CUSTOM_SECRET = '@Microsoft.KeyVault(SecretUri=https://example.vault.azure.net/secrets/test)'
            APPLICATIONINSIGHTS_CONNECTION_STRING = 'InstrumentationKey=mock-secret'
            'AzureWebJobs.OtherFunction.Disabled' = 'true'
            'AzureWebJobs.ExportAndGenerate.Disabled' = 'true'
            STORAGE_ACCOUNT_NAME = 'oldstorage'
            DASHBOARD_DELIVERY_MODE = 'Hosted'
        }
    }
    $script:ArmApiVersions = @{ WebApp = '2024-04-01' }
    $script:ProvisioningTags = @{ workload = 'defender-reporting' }
    $script:FunctionAppDeploymentContainer = 'deployment'
    $subPath = '/subscriptions/mock'
    $subscriptionId = 'mock'
    $ResourceGroupName = 'rg-mock'
    $FunctionAppName = 'func-mock'
    $StorageAccountName = 'mockstorage'
    $effectiveDashboardDeliveryMode = 'Dual'
    $Location = 'westus'
    $planName = 'mockplan'
    & $functionBlock
    Assert-True ($script:FunctionSettings['AzureWebJobs.ExportAndGenerate.Disabled'] -ceq $SkipMdePermissions.ToString().ToLowerInvariant()) 'Timer setting did not match requested state.'
    Assert-True ($script:FunctionSettings.STORAGE_ACCOUNT_NAME -eq 'mockstorage') 'Setup-owned storage setting was not updated.'
    Assert-True ($script:FunctionSettings.DASHBOARD_DELIVERY_MODE -eq 'Dual') 'Setup-owned delivery setting was not updated.'
    if ($Exists) {
        Assert-True ($script:FunctionSettings.CUSTOM_SECRET -ceq '@Microsoft.KeyVault(SecretUri=https://example.vault.azure.net/secrets/test)') 'Existing Key Vault secret setting was lost.'
        Assert-True ($script:FunctionSettings.APPLICATIONINSIGHTS_CONNECTION_STRING -ceq 'InstrumentationKey=mock-secret') 'Existing secret setting was lost.'
        Assert-True ($script:FunctionSettings['AzureWebJobs.OtherFunction.Disabled'] -ceq 'true') 'Unrelated function setting was changed.'
    }
    $writes = @($script:Requests | Where-Object Method -eq 'PUT')
    Assert-True ($writes.Count -eq 1) 'Function setup must issue exactly one merged app write.'
    $readCount = @($script:Requests | Where-Object Method -eq 'POST').Count
    Assert-True ($readCount -eq $(if ($Exists) { 2 } else { 1 })) 'Settings read/verify requests were not made as expected.'
}

$bindingPath = Join-Path $repoRoot 'azure/function-app/ExportAndGenerate/function.json'
$bindings = (Get-Content -LiteralPath $bindingPath -Raw | ConvertFrom-Json).bindings
Assert-True (@($bindings | Where-Object type -eq 'timerTrigger').Count -eq 1) 'ExportAndGenerate must own the timer being disabled.'
foreach ($exists in @($false, $true)) {
    Invoke-FunctionScenario -SkipMdePermissions $true -Exists $exists
    Invoke-FunctionScenario -SkipMdePermissions $false -Exists $exists
}
$failureDetected = $false
try { Invoke-FunctionScenario -SkipMdePermissions $true -Exists $true -IgnoreFunctionDisable $true }
catch {
    if ($_.Exception.Message -notlike '*did not reach the requested timer disabled state*') { throw }
    $failureDetected = $true
}
Assert-True $failureDetected 'Function timer readback must fail closed when disabling does not take effect.'
$failureDetected = $false
try { Invoke-FunctionScenario -SkipMdePermissions $true -Exists $true -FailSettingsRead $true }
catch {
    if ($_.Exception.Message -ne 'Injected settings read failure.') { throw }
    $failureDetected = $true
}
Assert-True $failureDetected 'Settings read failure must abort setup.'
Assert-True (-not ($script:Requests | Where-Object Method -eq 'PUT')) 'Settings read failure must not overwrite app settings.'
Write-Host 'Setup scheduling regression passed.'