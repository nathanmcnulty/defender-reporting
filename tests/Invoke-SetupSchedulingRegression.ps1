#Requires -Version 7.0
[CmdletBinding()]
param(
    [string]$SetupRoot = (Split-Path $PSScriptRoot -Parent)
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$repoRoot = $SetupRoot
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

$provisioningPath = Join-Path $repoRoot 'src/powershell/Provisioning/Azure/AzureProvisioning.ps1'
if (-not (Test-Path -LiteralPath $provisioningPath)) {
    $provisioningPath = Join-Path $repoRoot 'azure/AzureProvisioning.ps1'
}
$provisioningAst = [System.Management.Automation.Language.Parser]::ParseFile($provisioningPath, [ref]$null, [ref]$parseErrors)
if ($parseErrors.Count) { throw ($parseErrors | Out-String) }
foreach ($helperName in @('Get-JwtPayload', 'Get-GraphApiTenantId')) {
    $helper = $provisioningAst.Find({ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $helperName }, $true)
    Assert-True ($null -ne $helper) 'Required production Graph tenant helper is missing.'
    . ([scriptblock]::Create($helper.Extent.Text))
}

$graphAssignment = $setupAst.Find({ param($node) $node -is [System.Management.Automation.Language.AssignmentStatementAst] -and $node.Left.Extent.Text -eq '$containerGraphContext' }, $true)
Assert-True ($null -ne $graphAssignment) 'Container Graph context selection is missing.'
$containerStatements = @($graphAssignment.Parent.Statements)
$graphIndex = [array]::IndexOf($containerStatements, $graphAssignment)
$tenantAssignment = $containerStatements[$graphIndex + 1]
Assert-True ($tenantAssignment -is [System.Management.Automation.Language.AssignmentStatementAst] -and $tenantAssignment.Left.Extent.Text -eq '$tenantId' -and $tenantAssignment.Right.Extent.Text -eq 'Get-GraphApiTenantId -Context $containerGraphContext') 'Tenant resolution must immediately follow Graph context selection, before Container App or identity operations.'
$tenantAssignments = @($graphAssignment.Parent.FindAll({ param($node) $node -is [System.Management.Automation.Language.AssignmentStatementAst] -and $node.Left.Extent.Text -eq '$tenantId' }, $true))
Assert-True ($tenantAssignments.Count -eq 1) 'Container App tenant must be resolved exactly once.'
$authAssignment = $setupAst.Find({ param($node) $node -is [System.Management.Automation.Language.AssignmentStatementAst] -and $node.Left.Extent.Text -eq '$authConfigPayload' }, $true)
$authConditional = $setupAst.Find({ param($node) $node -is [System.Management.Automation.Language.IfStatementAst] -and $node.Clauses[0].Item1.Extent.Text -eq '$PSCmdlet.ShouldProcess($ContainerAppName, "Configure Easy Auth")' }, $true)
$identityWrite = $setupAst.Find({ param($node) $node -is [System.Management.Automation.Language.CommandAst] -and $node.GetCommandName() -eq 'Invoke-GraphApi' -and $node.Extent.Text -like '*Require app role assignment*' }, $true)
Assert-True ($null -ne $authAssignment -and $null -ne $authConditional -and $null -ne $identityWrite) 'Production identity or Easy Auth configuration block is missing.'
$issuerBlock = [scriptblock]::Create((@($graphAssignment.Extent.Text, $tenantAssignment.Extent.Text, $identityWrite.Extent.Text, $authAssignment.Extent.Text, $authConditional.Extent.Text) -join "`n"))

function Get-GraphApiContext {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '', Justification = 'Mock accepts the production Graph context selection signature.')]
    param($Scenario, $RequiredAllScopes, $RequiredAnyScopeSets, $FallbackScopes)
    return $script:GraphContextFixture
}
function Get-MgContext {
    $script:SdkContextReads++
    return $script:SdkContextFixture
}
function Get-AzContext {
    $script:AzureContextReads++
    return [pscustomobject]@{ Tenant = [pscustomobject]@{ Id = $script:AzureTenantFixture } }
}
function Invoke-GraphApi {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '', Justification = 'Mock accepts the production identity write signature.')]
    param($Context, $Method, $Uri, $Body, $Description)
    if ($Method -eq 'GET') {
        $script:GraphReads++
        return @{ value = @() }
    }
    $script:GraphWrites++
}

function Invoke-GraphIssuerScenario {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '', Justification = 'Variables are consumed by the extracted production Setup script block.')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '', Justification = 'The extracted production Easy Auth block invokes this command context ShouldProcess.')]
    [CmdletBinding(SupportsShouldProcess)]
    param($Context, $SdkContext, [string]$ExpectedTenant, [switch]$ExpectFailure)
    $script:GraphContextFixture = $Context
    $script:SdkContextFixture = $SdkContext
    $script:Requests = [System.Collections.Generic.List[object]]::new()
    $script:GraphWrites = 0
    $script:GraphReads = 0
    $script:SdkContextReads = 0
    $script:AzureContextReads = 0
    $ContainerAppName = 'mock-container'
    $appClientId = 'cccccccc-cccc-cccc-cccc-cccccccccccc'
    $spObjectId = 'mock-service-principal'
    $spPatchBody = @{ appRoleAssignmentRequired = $true }
    $authConfigPath = '/mock/authConfigs/current'
    $securityGroupName = 'mock-group'
    $securityGroupId = 'mock-group-id'
    $failure = $null
    try { & $issuerBlock 6>$null }
    catch { $failure = $_ }
    if ($ExpectFailure) {
        Assert-True ($null -ne $failure) 'Invalid Graph tenant context must fail closed.'
        Assert-True ($script:Requests.Count -eq 0 -and $script:GraphWrites -eq 0) 'Invalid Graph tenant must fail before any ARM authentication or identity writes.'
    }
    else {
        if ($null -ne $failure) { throw $failure }
        Assert-True ($script:Requests.Count -eq 1 -and $script:GraphWrites -eq 1) 'Valid Graph tenant must reach the production write statements.'
        $config = $script:Requests[0].Payload | ConvertFrom-Json
        Assert-True ($config.properties.identityProviders.azureActiveDirectory.registration.openIdIssuer -ceq "https://login.microsoftonline.com/$ExpectedTenant/v2.0") 'Easy Auth issuer did not use the exact Graph tenant.'
        Assert-True ($config.properties.identityProviders.azureActiveDirectory.registration.clientId -ceq $appClientId) 'Issuer fix changed the configured client ID.'
        Assert-True ($script:SdkContextReads -eq $(if ($Context.Mode -eq 'MgGraph') { 1 } else { 0 })) 'Tenant resolution used the wrong authentication mode or repeated SDK lookup.'
    }
    Assert-True ($script:AzureContextReads -eq 0) 'Issuer resolution must never fall back to the Azure resource tenant.'
}

function Get-GraphTenantTestToken {
    param([string]$PayloadJson, [byte[]]$PayloadBytes)
    if ($null -eq $PayloadBytes) { $PayloadBytes = [Text.Encoding]::UTF8.GetBytes($PayloadJson) }
    $payloadSegment = [Convert]::ToBase64String($PayloadBytes).TrimEnd('=').Replace('+', '-').Replace('/', '_')
    return "header.$payloadSegment.signature"
}

$script:AzureTenantFixture = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'
$graphTenantFixture = 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb'
foreach ($expectedTenant in @($graphTenantFixture, $script:AzureTenantFixture)) {
    $context = [pscustomobject]@{ Mode = 'AzToken'; AccessToken = (Get-GraphTenantTestToken -PayloadJson ('{"tid":"' + $expectedTenant + '"}')); TenantId = $script:AzureTenantFixture }
    Invoke-GraphIssuerScenario -Context $context -ExpectedTenant $expectedTenant
    Invoke-GraphIssuerScenario -Context ([pscustomobject]@{ Mode = 'MgGraph'; TenantId = $script:AzureTenantFixture }) -SdkContext ([pscustomobject]@{ TenantId = $expectedTenant }) -ExpectedTenant $expectedTenant
}
foreach ($claimJson in @('{}', '{"tid":null}', '{"tid":""}', '{"tid":"not-a-guid"}', '{"tid":"00000000-0000-0000-0000-000000000000"}', '{"tid":["bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"]}', '{"tid":true}', '{"tid":1.5}', '{"tid":123}', '{invalid-json', '[]', '[{"tid":"bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"}]', '[{"tid":"bbbbbbbb-bbbb-bbbb-bbbbbbbbbbbb"},{"tid":"bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"}]', '"bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"', '123', 'true', 'null')) {
    Invoke-GraphIssuerScenario -Context ([pscustomobject]@{ Mode = 'AzToken'; AccessToken = (Get-GraphTenantTestToken -PayloadJson $claimJson) }) -ExpectFailure
}
foreach ($invalidToken in @($null, '', 'malformed', 'header.%%%%.signature', 'header.a.signature', [System.Security.SecureString]::new())) {
    Invoke-GraphIssuerScenario -Context ([pscustomobject]@{ Mode = 'AzToken'; AccessToken = $invalidToken }) -ExpectFailure
}
Invoke-GraphIssuerScenario -Context ([pscustomobject]@{ Mode = 'AzToken' }) -ExpectFailure
foreach ($sdkTenant in @($null, '', 'not-a-guid', [guid]::Empty.ToString(), @($graphTenantFixture), $true, 1.5, [guid]$graphTenantFixture)) {
    Invoke-GraphIssuerScenario -Context ([pscustomobject]@{ Mode = 'MgGraph'; TenantId = $graphTenantFixture }) -SdkContext ([pscustomobject]@{ TenantId = $sdkTenant }) -ExpectFailure
}
Invoke-GraphIssuerScenario -Context ([pscustomobject]@{ Mode = 'MgGraph'; TenantId = $graphTenantFixture }) -ExpectFailure
Invoke-GraphIssuerScenario -Context ([pscustomobject]@{ Mode = 'MgGraph' }) -SdkContext ([pscustomobject]@{}) -ExpectFailure
Invoke-GraphIssuerScenario -Context ([pscustomobject]@{ Mode = 'Unsupported'; TenantId = $graphTenantFixture }) -ExpectFailure
Invoke-GraphIssuerScenario -Context ([pscustomobject]@{}) -ExpectFailure
Write-Host 'Setup Graph tenant issuer regression passed (4 valid and 36 fail-closed scenarios).'

$containerBlock = [scriptblock]::Create(($containerStatements.Extent.Text -join "`n"))
foreach ($helperName in @('Get-OptionalObjectPropertyValue')) {
    $helper = $setupAst.Find({ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $helperName }, $true)
    . ([scriptblock]::Create($helper.Extent.Text))
}
$graphHelper = $provisioningAst.Find({ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Invoke-GraphApi' }, $true)
. ([scriptblock]::Create($graphHelper.Extent.Text))

function Get-GraphApiContext {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '', Justification = 'Mock accepts the production Graph context signature without connecting.')]
    param($Scenario, $RequiredAllScopes, $RequiredAnyScopeSets, $FallbackScopes)
    $script:ContainerEvents.Add('GraphContext')
    return $script:GraphContextFixture
}
function Get-MgContext {
    $script:ContainerEvents.Add('GraphTenant')
    $script:SdkContextReads++
    return $script:SdkContextFixture
}
function Get-ArmToken { throw 'Unexpected token acquisition.' }
function Connect-MgGraph { throw 'Unexpected SDK sign-in fallback.' }
function Get-MgApplication { throw 'Unexpected alternate application query.' }
function Start-Sleep {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '', Justification = 'No-op mock accepts the production sleep signature.')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'No-op mock never sleeps or changes state.')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidOverwritingBuiltInCmdlets', '', Justification = 'Test-local mock prevents production polling delays.')]
    param($Seconds)
}
function Get-DashboardContainerSyncScript {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '', Justification = 'Mock accepts the production startup script signature.')]
    param($AccountName, $HtmlBlobName)
    return 'mock startup'
}
function Wait-WithPolling {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '', Justification = 'Single-pass polling mock accepts production timeout parameters.')]
    param($Condition, $Description, $IntervalSeconds, $TimeoutSeconds)
    $ready = & $Condition
    if ($Description -eq 'Container Apps Environment provisioning') { Set-Variable -Name envDefaultDomain -Value $script:envDefaultDomain -Scope 1 }
    if ($Description -eq 'Container App provisioning') { Set-Variable -Name camiPrincipalId -Value $script:camiPrincipalId -Scope 1 }
    return $ready
}
function Get-OptionalArmResource {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '', Justification = 'Mock accepts the production resource lookup signature.')]
    param($Path, $Description)
    $script:ContainerEvents.Add('ARM:GET:optional')
    return @{ Exists = $false }
}
function Invoke-ArmApi {
    param($Path, $Method, $Payload, $Description)
    $script:ContainerEvents.Add("ARM:${Method}:$Description")
    $script:Requests.Add(@{ Path = $Path; Method = $Method; Payload = $Payload })
    if ($Method -ne 'GET') { return }
    if ($Path -match '/managedEnvironments/') { return @{ properties = @{ provisioningState = 'Succeeded'; defaultDomain = 'mock.example' } } }
    if ($Path -match '/roleAssignments') { return @{ value = @(@{ id = 'mock-role' }) } }
    if ($Path -match '/revisions\?') { return @{ value = @() } }
    return @{ properties = @{ provisioningState = 'Succeeded' }; identity = @{ principalId = 'mock-identity' } }
}
function Invoke-ContainerGraphFixture {
    param($Uri, $Method, $Body, $Mode)
    Assert-True ($Mode -eq $script:GraphContextFixture.Mode) 'Graph query used the wrong authentication mode.'
    $relativeUri = $Uri -replace '^https://graph.microsoft.com', ''
    $script:ContainerEvents.Add("Graph:${Method}:$relativeUri")
    $script:ContainerGraphRequests.Add(@{ Uri = $relativeUri; Method = $Method; Body = $Body })
    if ($Method -ne 'GET') {
        Assert-True (@($script:Requests | Where-Object Method -eq 'PUT').Count -ge 3) 'Graph mutations must remain after environment, app, and RBAC provisioning.'
        if ($relativeUri -eq '/v1.0/applications') { return $script:ApplicationFixture }
        return
    }
    if ($relativeUri -eq "/v1.0/applications?`$filter=appId eq '$script:AzureTenantFixture'") { return @{ value = @() } }
    if ($relativeUri -eq "/v1.0/applications?`$filter=appId eq '$script:ExplicitClientId'") {
        if ($script:ApplicationOutcome -eq 'Denied') { throw 'private-response-body TOKEN_SENTINEL' }
        if ($script:ApplicationOutcome -eq 'Missing') { return @{ value = @() } }
        if ($script:ApplicationOutcome -eq 'Duplicate') { return @{ value = @($script:ApplicationFixture, $script:ApplicationFixture) } }
        return @{ value = @($script:ApplicationFixture) }
    }
    if ($relativeUri -eq '/v1.0/applications/mock-app-object') { return $script:ApplicationFixture }
    if ($relativeUri -eq '/v1.0/groups/dddddddd-dddd-dddd-dddd-dddddddddddd') { return @{ id = 'mock-group'; displayName = 'mock-group' } }
    if ($relativeUri -like '/v1.0/servicePrincipals?*') { return @{ value = @(@{ id = 'mock-sp' }) } }
    if ($relativeUri -like '/v1.0/oauth2PermissionGrants?*') { return @{ value = @(@{ id = 'mock-consent'; scope = 'openid email profile' }) } }
    if ($relativeUri -eq '/v1.0/groups/mock-group/appRoleAssignments') { return @{ value = @() } }
    if ($relativeUri -eq "/v1.0/applications?`$filter=displayName eq 'mock-app'") { return @{ value = @() } }
    throw "Unexpected Graph query: $relativeUri"
}
function Invoke-RestMethod {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '', Justification = 'Mock accepts the production REST transport signature.')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidOverwritingBuiltInCmdlets', '', Justification = 'Test-local mock prevents any real REST requests.')]
    param($Uri, $Method, $Headers, $Body, $ContentType, $ErrorAction)
    Assert-True ($Headers.Authorization -ceq "Bearer $($script:GraphContextFixture.AccessToken)") 'REST app query did not use the selected Graph token.'
    return Invoke-ContainerGraphFixture -Uri $Uri -Method $Method -Body $Body -Mode 'AzToken'
}
function Invoke-MgGraphRequest {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '', Justification = 'Mock accepts the production SDK transport signature.')]
    param($Uri, $Method, $Body, $ErrorAction)
    return Invoke-ContainerGraphFixture -Uri $Uri -Method $Method -Body $Body -Mode 'MgGraph'
}

function Invoke-ContainerPreflightScenario {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '', Justification = 'Variables are consumed by the full extracted production Container App block.')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '', Justification = 'The extracted production block invokes this command context ShouldProcess.')]
    [CmdletBinding(SupportsShouldProcess)]
    param([string]$Mode, [string]$Outcome = 'Valid', [string]$ClientId = 'cccccccc-cccc-cccc-cccc-cccccccccccc', [string]$ClaimJson = ('{"tid":"' + $graphTenantFixture + '"}'), [byte[]]$PayloadBytes, [switch]$InvalidPayload, [switch]$ValidClaims, [switch]$InvalidSdkTenant)
    $script:ContainerEvents = [System.Collections.Generic.List[string]]::new()
    $script:ContainerGraphRequests = [System.Collections.Generic.List[object]]::new()
    $script:Requests = [System.Collections.Generic.List[object]]::new()
    $script:GraphContextFixture = [pscustomobject]@{ Mode = $Mode; AccessToken = (Get-GraphTenantTestToken -PayloadJson $ClaimJson -PayloadBytes $PayloadBytes) }
    $script:SdkContextFixture = [pscustomobject]@{ TenantId = $(if ($InvalidSdkTenant) { 'invalid' } else { $graphTenantFixture }) }
    $script:SdkContextReads = 0
    $script:AzureContextReads = 0
    $script:ExplicitClientId = 'cccccccc-cccc-cccc-cccc-cccccccccccc'
    $script:ApplicationOutcome = $Outcome
    $script:ApplicationFixture = [pscustomobject]@{ id = 'mock-app-object'; appId = $(if ($Outcome -eq 'WrongAppId') { $script:AzureTenantFixture } else { $script:ExplicitClientId }); displayName = $null; web = $null }
    if ($Mode -eq 'MgGraph') { $script:ApplicationFixture = @{ id = $script:ApplicationFixture.id; appId = $script:ApplicationFixture.appId; displayName = $null; web = $null } }
    $script:GraphApiBaseUrl = 'https://graph.microsoft.com'
    $script:ArmApiVersions = @{ ContainerAppEnvironment = '2024-03-01'; ContainerApp = '2024-03-01'; RoleAssignment = '2022-04-01' }
    $script:ProvisioningTags = @{}
    $script:DashboardBlobName = 'dashboard.html'
    $script:CaddyImage = 'mock-image'
    $script:StorageBlobDataReaderRoleId = 'mock-role'
    $subPath = '/subscriptions/mock'
    $ResourceGroupName = 'rg-mock'
    $StorageAccountName = 'mockstorage'
    $Location = 'westus'
    $ContainerAppName = 'mock-container'
    $ContainerAppEnvName = 'mock-environment'
    $SecurityGroup = 'dddddddd-dddd-dddd-dddd-dddddddddddd'
    $EasyAuthAppClientId = $ClientId
    $EasyAuthAppDisplayName = 'mock-app'
    $effectiveDashboardDeliveryMode = 'Hosted'
    $failure = $null
    try { & $containerBlock 6>$null } catch { $failure = $_ }
    $expectFailure = $Outcome -ne 'Valid' -or $InvalidSdkTenant -or $InvalidPayload -or (-not $ValidClaims -and $ClaimJson -ne ('{"tid":"' + $graphTenantFixture + '"}')) -or $ClientId -notin @('', $script:ExplicitClientId, $script:ExplicitClientId.ToUpperInvariant())
    if ($expectFailure) {
        Assert-True ($null -ne $failure) 'Invalid tenant or explicit application must reject the full Container App block.'
        Assert-True (@($script:Requests | Where-Object Method -ne 'GET').Count -eq 0) 'Preflight rejection must precede every Container App ARM mutation, including environment, app, and storage RBAC.'
        Assert-True (@($script:ContainerGraphRequests | Where-Object Method -ne 'GET').Count -eq 0) 'Preflight rejection must precede every Graph mutation.'
        Assert-True ($failure.Exception.Message -notmatch 'TOKEN_SENTINEL|private-response-body|header\..*\.signature') 'Preflight errors must not disclose tokens or response bodies.'
        if ($InvalidPayload) {
            Assert-True ($failure.Exception.Message -ceq 'Could not decode the Graph access token tenant claim.') 'Malformed UTF-8 must use the static claims error.'
            Assert-True ($script:Requests.Count -eq 0 -and $script:ContainerEvents.Count -eq 1) 'Malformed UTF-8 must reject before any ARM operation or Graph GET.'
        }
        if ($Outcome -eq 'Valid') { Assert-True ($script:ContainerGraphRequests.Count -eq 0) 'Invalid tenant or malformed client GUID must reject before any Graph lookup.' }
        else { Assert-True ($script:ContainerGraphRequests.Count -eq 1) 'Missing, mismatched, duplicate, or denied application must not trigger broad lookup or fallback.' }
    }
    else {
        if ($null -ne $failure) { throw $failure }
        $writes = @($script:Requests | Where-Object Method -ne 'GET')
        Assert-True ($writes.Count -eq 4) 'Valid fixture must execute environment, app, storage RBAC, and Easy Auth ARM writes.'
        Assert-True ($writes[0].Path -match '/managedEnvironments/' -and $writes[1].Path -match '/containerApps/' -and $writes[2].Path -match '/roleAssignments/') 'Normal Container App write order changed.'
        $config = $writes[3].Payload | ConvertFrom-Json
        Assert-True ($config.properties.identityProviders.azureActiveDirectory.registration.openIdIssuer -ceq "https://login.microsoftonline.com/$graphTenantFixture/v2.0") 'Full block issuer must use the Graph tenant, not the resource tenant.'
        Assert-True ($config.properties.identityProviders.azureActiveDirectory.registration.clientId -eq $script:ExplicitClientId) 'Full block must preserve the application client ID rather than the object ID.'
        $appQueries = @($script:ContainerGraphRequests | Where-Object { $_.Method -eq 'GET' -and $_.Uri -like '/v1.0/applications?*appId*' })
        Assert-True ($appQueries.Count -eq $(if ($ClientId) { 1 } else { 0 })) 'Prevalidated explicit app must not require a second filtered lookup.'
        if ($ClientId) {
            $appEvent = [array]::IndexOf($script:ContainerEvents.ToArray(), "Graph:GET:/v1.0/applications?`$filter=appId eq '$script:ExplicitClientId'")
            $firstArm = [array]::FindIndex($script:ContainerEvents.ToArray(), [Predicate[string]]{ param($entry) $entry.StartsWith('ARM:') })
            Assert-True ($appEvent -gt 0 -and $appEvent -lt $firstArm) 'Read-only explicit application validation must precede any Container App ARM operation.'
            if ($Mode -eq 'MgGraph') { Assert-True ($script:ContainerEvents[1] -eq 'GraphTenant' -and $appEvent -eq 2) 'Connected SDK tenant resolution must precede explicit app validation.' }
        }
        $appMutation = $script:ContainerGraphRequests | Where-Object { $_.Method -in @('POST', 'PATCH') -and $_.Uri -like '/v1.0/applications*' } | Select-Object -First 1
        $appBody = if ($appMutation.Body -is [string]) { $appMutation.Body | ConvertFrom-Json } else { $appMutation.Body }
        Assert-True (@($appBody.web.redirectUris) -contains 'https://mock-container.mock.example/.auth/login/aad/callback') 'App creation/update must retain the actual resolved FQDN redirect URI.'
    }
    Assert-True ($script:AzureContextReads -eq 0) 'Full block must not use the Azure tenant as a Graph fallback.'
    Assert-True ($script:SdkContextReads -eq $(if ($Mode -eq 'MgGraph') { 1 } else { 0 })) 'Selected Graph mode must not perform an SDK fallback or repeat tenant resolution.'
    if ($expectFailure) { $script:ContainerRejectedCount++ } else { $script:ContainerValidCount++ }
}

$script:ContainerRejectedCount = 0
$script:ContainerValidCount = 0
foreach ($mode in @('AzToken', 'MgGraph')) {
    Invoke-ContainerPreflightScenario -Mode $mode
    Invoke-ContainerPreflightScenario -Mode $mode -ClientId 'CCCCCCCC-CCCC-CCCC-CCCC-CCCCCCCCCCCC'
    Invoke-ContainerPreflightScenario -Mode $mode -ClientId ''
    foreach ($outcome in @('Missing', 'WrongAppId', 'Duplicate', 'Denied')) { Invoke-ContainerPreflightScenario -Mode $mode -Outcome $outcome }
    foreach ($clientId in @('not-a-guid', '00000000-0000-0000-0000-000000000000')) {
        Invoke-ContainerPreflightScenario -Mode $mode -ClientId $clientId
    }
    Invoke-ContainerPreflightScenario -Mode $mode -ClientId $script:AzureTenantFixture -Outcome 'Missing'
}
foreach ($claimJson in @('{}', '[]', '[{"tid":"bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"}]', '[{"tid":"bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"},{"tid":"bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"}]', '"tenant"', '123', 'true', 'null')) {
    Invoke-ContainerPreflightScenario -Mode 'AzToken' -ClaimJson $claimJson
}
Invoke-ContainerPreflightScenario -Mode 'MgGraph' -InvalidSdkTenant
$invalidUtf8Payload = [byte[]]([Text.Encoding]::UTF8.GetBytes('{"tid":"' + $graphTenantFixture + '","name":"') + [byte[]]@(0xC3, 0x28) + [Text.Encoding]::UTF8.GetBytes('"}'))
Invoke-ContainerPreflightScenario -Mode 'AzToken' -PayloadBytes $invalidUtf8Payload -InvalidPayload
Invoke-ContainerPreflightScenario -Mode 'AzToken' -PayloadBytes $invalidUtf8Payload -InvalidPayload -ClientId ''
Invoke-ContainerPreflightScenario -Mode 'MgGraph' -PayloadBytes $invalidUtf8Payload
$unicodeClaims = '{"tid":"' + $graphTenantFixture + '","name":"' + [char]0x00E9 + [char]::ConvertFromUtf32(0x1F600) + '"}'
Invoke-ContainerPreflightScenario -Mode 'AzToken' -ClaimJson $unicodeClaims -ValidClaims
Invoke-ContainerPreflightScenario -Mode 'AzToken' -ClaimJson $unicodeClaims -ValidClaims -ClientId ''
Invoke-ContainerPreflightScenario -Mode 'MgGraph' -ClaimJson $unicodeClaims -ValidClaims
$bomPayload = [byte[]]([byte[]]@(0xEF, 0xBB, 0xBF) + [Text.Encoding]::UTF8.GetBytes('{"tid":"' + $graphTenantFixture + '"}'))
Invoke-ContainerPreflightScenario -Mode 'AzToken' -PayloadBytes $bomPayload -InvalidPayload
Write-Host "Full Container App Graph preflight regression passed ($script:ContainerValidCount valid and $script:ContainerRejectedCount fail-closed scenarios; both auth modes, zero mutations on rejection)."