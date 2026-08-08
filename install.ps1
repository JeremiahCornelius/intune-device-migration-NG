<#
.SYNOPSIS
    Safety-first Intune Win32 application entrypoint.

.DESCRIPTION
    Replaces direct execution of startMigrate.ps1 as the Intune install command.

    Sequence:
      1. Run non-destructive preflight.
      2. If and only if preflight returns 0, invoke the upstream migration
         controller.

    This first atomic commit intentionally doesn't rewrite startMigrate.ps1 yet.
    It establishes a mandatory safety gate before any upstream destructive
    operation can begin.

    Recommended Intune install command:
      powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\install.ps1

.NOTES
    Safety-first fork revision: 2026.08.07.1
#>

[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$preflight = Join-Path -Path $PSScriptRoot -ChildPath 'preflight.ps1'
$startMigration = Join-Path -Path $PSScriptRoot -ChildPath 'startMigrate.ps1'
$configPath = Join-Path -Path $PSScriptRoot -ChildPath 'config.json'

try {
    if (-not (Test-Path -LiteralPath $preflight)) {
        throw "Missing preflight script: $preflight"
    }

    if (-not (Test-Path -LiteralPath $startMigration)) {
        throw "Missing upstream migration controller: $startMigration"
    }

    if (-not (Test-Path -LiteralPath $configPath)) {
        throw "Missing migration configuration: $configPath"
    }

    & $preflight -ConfigPath $configPath
    $preflightExitCode = $LASTEXITCODE

    if ($preflightExitCode -ne 0) {
        Write-Error "Migration preflight failed with exit code $preflightExitCode. Destructive migration was NOT started."
        exit $preflightExitCode
    }

    Write-Output '[SAFETY] Preflight passed. Launching migration controller.'
    & $startMigration
    exit $LASTEXITCODE
}
catch {
    Write-Error "[SAFETY] Migration entrypoint failed before commit: $($_.Exception.Message)"
    exit 1
}
