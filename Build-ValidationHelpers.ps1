#Requires -Version 7.0

[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repoRoot = $PSScriptRoot
$sourceRoot = Join-Path -Path $repoRoot -ChildPath 'validation\source'
$outputPath = Join-Path -Path $repoRoot -ChildPath 'validation-helpers.ps1'

if (-not (Test-Path -Path $sourceRoot -PathType Container)) {
    throw "Validation helper source directory not found: $sourceRoot"
}

$sourceFiles = @(
    Get-ChildItem -Path $sourceRoot -Filter '*.ps1' -File -ErrorAction Stop |
        Sort-Object Name
)

if ($sourceFiles.Count -eq 0) {
    throw "No validation helper source files found under '$sourceRoot'."
}

$combined = [System.Text.StringBuilder]::new()
for ($index = 0; $index -lt $sourceFiles.Count; $index++) {
    $content = Get-Content -Path $sourceFiles[$index].FullName -Raw
    [void]$combined.Append($content.TrimEnd())
    if ($index -lt ($sourceFiles.Count - 1)) {
        [void]$combined.AppendLine()
        [void]$combined.AppendLine()
    }
    else {
        [void]$combined.AppendLine()
    }
}

[System.IO.File]::WriteAllText($outputPath, $combined.ToString(), [System.Text.UTF8Encoding]::new($true))
Write-Host "Generated validation helpers: $outputPath" -ForegroundColor Green