# Azure Functions profile - loaded on every cold start.
# Managed dependencies are not supported on Flex Consumption; Az.Accounts is
# bundled in the Modules/ directory by Build-FunctionApp.ps1.

if ($env:MSI_SECRET) {
    Disable-AzContextAutosave -Scope Process | Out-Null
}
