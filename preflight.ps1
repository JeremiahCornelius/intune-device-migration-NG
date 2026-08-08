<#
.SYNOPSIS
    Non-destructive preflight for the safety-first same-tenant Hybrid Entra
    Joined -> Microsoft Entra Joined migration fork.

.DESCRIPTION
    Performs validation only.  It does NOT:
      - remove the Intune MDM certificate or enrollment;
      - leave Microsoft Entra ID;
      - unjoin the AD domain;
      - install a provisioning package;
      - alter a user profile owner;
      - reboot the device.

    A successful run writes a restricted local evidence record under:
      HKLM\SOFTWARE\IntuneMigration\Safety
    and:
      C:\ProgramData\IntuneMigration\preflight.json

    The identity mapping is deterministic for the same-tenant scenario:
      old AD SID -> Graph onPremisesSecurityIdentifier -> Entra securityIdentifier

    This prevents an operator or user from accidentally authenticating as a
    different Entra identity and having that SID applied to the existing profile.

.NOTES
    Safety-first fork revision: 2026.08.07.1
#>

[CmdletBinding()]
param(
    [Parameter()]
    [string]$ConfigPath = $(Join-Path -Path $PSScriptRoot -ChildPath 'config.json'),

    [Parameter()]
    [switch]$AllowAdministratorContext
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$commonPath = Join-Path -Path $PSScriptRoot -ChildPath 'Migration.Common.ps1'
if (-not (Test-Path -LiteralPath $commonPath)) {
    Write-Error "Required helper file is missing: $commonPath"
    exit 1
}

. $commonPath

$reportPath = $null

try {
    Write-MigrationLog INFO 'Starting non-destructive migration preflight.'

    $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    if (-not $identity.IsSystem) {
        if (-not $AllowAdministratorContext) {
            throw "Preflight must run as LocalSystem when deployed by Intune. Current identity: '$($identity.Name)'. Use -AllowAdministratorContext only for deliberate manual testing."
        }

        $principal = New-Object System.Security.Principal.WindowsPrincipal($identity)
        if (-not $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)) {
            throw "Manual preflight requires an elevated local Administrator token. Current identity: '$($identity.Name)'."
        }

        Write-MigrationLog WARN "Running preflight under elevated Administrator '$($identity.Name)' instead of LocalSystem because -AllowAdministratorContext was supplied."
    }
    else {
        Write-MigrationLog OK 'Execution context is LocalSystem.'
    }

    $config = Get-MigrationConfig -Path $ConfigPath
    $configHash = Get-ConfigFileSha256 -Path $ConfigPath
    $localPath = [string]$config.localPath

    if ([string]::IsNullOrWhiteSpace($localPath)) {
        $localPath = $script:MigrationLocalPathDefault
    }

    if (-not (Test-Path -LiteralPath $localPath)) {
        New-Item -Path $localPath -ItemType Directory -Force -ErrorAction Stop | Out-Null
    }

    $reportPath = Join-Path -Path $localPath -ChildPath 'preflight.json'

    $dsreg = Get-DsRegState
    Write-MigrationLog INFO "Join state: AzureAdJoined=$($dsreg.AzureAdJoined), DomainJoined=$($dsreg.DomainJoined), WorkplaceJoined=$($dsreg.WorkplaceJoined)."

    if ($dsreg.AzureAdJoined -ne 'YES') {
        throw "This fork's first migration path requires a Hybrid Entra Joined source device. AzureAdJoined must be YES."
    }

    if ($dsreg.DomainJoined -ne 'YES') {
        throw "This fork's first migration path requires a Hybrid Entra Joined source device. DomainJoined must be YES."
    }

    $mdmCertificates = @(Get-IntuneMdmCertificate)
    if ($mdmCertificates.Count -eq 0) {
        throw 'No Microsoft Intune MDM Device CA certificate is present.'
    }

    if ($mdmCertificates.Count -gt 1) {
        Write-MigrationLog WARN "More than one Intune MDM certificate is present ($($mdmCertificates.Count)); migration is allowed to stage, but this should be reviewed."
    }
    else {
        Write-MigrationLog OK 'Intune MDM certificate is present.'
    }

    $interactiveUser = Get-InteractiveUserIdentity
    Write-MigrationLog OK "Interactive source profile resolved: $($interactiveUser.UserName), SID=$($interactiveUser.Sid), Path=$($interactiveUser.ProfilePath)."

    if (-not $interactiveUser.ProfileLoaded) {
        throw 'The source user profile isn't currently loaded. Run staging while the intended user is signed in.'
    }

    # Authenticate using the existing upstream app-registration model, but keep
    # all credentials in SYSTEM context.  Nothing is copied to Public Documents.
    $sourceSession = New-GraphAppSession -TenantConfig $config.sourceTenant
    Write-MigrationLog OK "Source Graph application authenticated to tenant $($sourceSession.TenantId)."

    $targetTenantConfig = Get-OptionalPropertyValue -InputObject $config -Name 'targetTenant'
    $targetTenantName = [string](Get-OptionalPropertyValue -InputObject $targetTenantConfig -Name 'tenantName')

    if (-not [string]::IsNullOrWhiteSpace($targetTenantName)) {
        $targetSession = New-GraphAppSession -TenantConfig $targetTenantConfig
        Write-MigrationLog OK "Target Graph application authenticated to tenant $($targetSession.TenantId)."

        if ($targetSession.TenantId -ne $sourceSession.TenantId) {
            throw "This safety-first fork revision supports same-tenant Hybrid -> Entra migration only. Source tenant '$($sourceSession.TenantId)' and target tenant '$($targetSession.TenantId)' differ."
        }
    }
    else {
        $targetSession = $sourceSession
        Write-MigrationLog INFO 'No separate target tenant is configured; source tenant is the Entra-join target.'
    }

    if ($dsreg.TenantId -and $dsreg.TenantId -ne $sourceSession.TenantId) {
        throw "Hybrid device tenant '$($dsreg.TenantId)' doesn't match configured Graph tenant '$($sourceSession.TenantId)'."
    }

    $entraUser = Resolve-SameTenantEntraUserByOnPremSid `
        -OnPremSid $interactiveUser.Sid `
        -Headers $targetSession.Headers

    Write-MigrationLog OK "Deterministic Entra identity mapping succeeded: $($interactiveUser.Sid) -> $($entraUser.CloudSid) ($($entraUser.UserPrincipalName))."

    if ($interactiveUser.Sid -eq $entraUser.CloudSid) {
        throw 'Old AD SID and new Entra SID are unexpectedly identical.'
    }

    $recoveryAccount = Get-RecoveryLocalAccount -Config $config
    Write-MigrationLog OK "Local recovery account '$($recoveryAccount.Name)' is enabled and is a local Administrator."
    Write-MigrationLog WARN 'Preflight verifies recovery-account presence and privilege only; it cannot validate a password that is not supplied to the script.'

    $requireKfm = Get-SafetyBoolean -Config $config -Name 'requireOneDriveKfmReady' -Default $true
    $kfm = Get-OneDriveKfmReadiness

    if ($requireKfm) {
        if (-not $kfm.Ready) {
            throw "OneDrive KFM safety gate isn't ready. Expected Status=PolicyApplied and KfmState=DesktopDocumentsPicturesRedirected; observed Status='$($kfm.Status)', KfmState='$($kfm.KfmState)'."
        }

        Write-MigrationLog OK 'OneDrive KFM readiness verified for Desktop, Documents, and Pictures.'
    }
    else {
        Write-MigrationLog WARN "OneDrive KFM readiness is not enforced because config safety.requireOneDriveKfmReady=false. Observed KfmState='$($kfm.KfmState)'."
    }

    $allowPendingReboot = Get-SafetyBoolean -Config $config -Name 'allowPendingReboot' -Default $false
    $pendingReboot = Test-PendingReboot

    if ($pendingReboot -and -not $allowPendingReboot) {
        throw 'Windows reports a pending reboot. Complete the reboot before committing identity migration.'
    }

    if ($pendingReboot) {
        Write-MigrationLog WARN 'A pending reboot is present but explicitly permitted by configuration.'
    }
    else {
        Write-MigrationLog OK 'No standard pending-reboot indicators were found.'
    }

    $ppkg = Get-SingleProvisioningPackage -SearchRoot $PSScriptRoot
    $ppkgHash = (Get-FileHash -LiteralPath $ppkg.FullName -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
    Write-MigrationLog OK "Exactly one provisioning package is staged: $($ppkg.Name), SHA-256=$ppkgHash."

    $safety = Get-OptionalPropertyValue -InputObject $config -Name 'safety'
    $expectedPpkgHash = [string](Get-OptionalPropertyValue -InputObject $safety -Name 'ppkgSha256')
    if (-not [string]::IsNullOrWhiteSpace($expectedPpkgHash)) {
        if ($ppkgHash -ne $expectedPpkgHash.ToLowerInvariant()) {
            throw "Provisioning-package SHA-256 doesn't match config safety.ppkgSha256."
        }

        Write-MigrationLog OK 'Provisioning-package SHA-256 matches configured pin.'
    }
    else {
        Write-MigrationLog WARN 'No config safety.ppkgSha256 pin is configured. The observed package hash is recorded in preflight state and must remain unchanged through commit.'
    }

    foreach ($requiredFile in @('reboot.xml','postMigrate.xml','reboot.ps1','postMigrate.ps1','Migration.Common.ps1')) {
        $requiredPath = Join-Path -Path $PSScriptRoot -ChildPath $requiredFile
        if (-not (Test-Path -LiteralPath $requiredPath)) {
            throw "Required migration package file is missing: $requiredFile"
        }
    }
    Write-MigrationLog OK 'Required reboot/post-migration package files are present.'

    $systemDrive = Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DeviceID='$($env:SystemDrive)'" -ErrorAction Stop
    $freeGb = [math]::Round(([double]$systemDrive.FreeSpace / 1GB), 2)
    if ($freeGb -lt 5) {
        throw "System drive free space is only $freeGb GB; at least 5 GB is required by this fork's safety gate."
    }
    Write-MigrationLog OK "System drive free space: $freeGb GB."

    $preflightUtc = [DateTime]::UtcNow.ToString('o')
    $stateValues = @{
        State = 'PreflightPassed'
        PreflightUtc = $preflightUtc
        ConfigSha256 = $configHash
        ExpectedTenantId = $targetSession.TenantId
        OldSid = $interactiveUser.Sid
        ExpectedNewSid = $entraUser.CloudSid
        ExpectedUserObjectId = $entraUser.Id
        ExpectedUserPrincipalName = $entraUser.UserPrincipalName
        ExpectedProfilePath = $interactiveUser.ProfilePath
        RecoveryAccountName = $recoveryAccount.Name
        PpkgPath = $ppkg.FullName
        PpkgSha256 = $ppkgHash
        OneDriveKfmRequired = $requireKfm
        OneDriveKfmState = [string]$kfm.KfmState
        PendingRebootObserved = $pendingReboot
    }

    Set-MigrationSafetyState -Values $stateValues

    $report = [ordered]@{
        result = 'PreflightPassed'
        timestampUtc = $preflightUtc
        configSha256 = $configHash
        device = [ordered]@{
            computerName = $env:COMPUTERNAME
            azureAdJoined = $dsreg.AzureAdJoined
            domainJoined = $dsreg.DomainJoined
            tenantId = $dsreg.TenantId
            deviceId = $dsreg.DeviceId
            intuneMdmCertificates = $mdmCertificates.Count
        }
        sourceUser = [ordered]@{
            windowsName = $interactiveUser.UserName
            oldSid = $interactiveUser.Sid
            profilePath = $interactiveUser.ProfilePath
            profileLoaded = $interactiveUser.ProfileLoaded
        }
        targetUser = [ordered]@{
            objectId = $entraUser.Id
            upn = $entraUser.UserPrincipalName
            cloudSid = $entraUser.CloudSid
            tenantId = $targetSession.TenantId
        }
        recovery = [ordered]@{
            localAccount = $recoveryAccount.Name
            enabled = $true
            localAdministrator = $true
            passwordValidated = $false
        }
        backup = [ordered]@{
            required = $requireKfm
            status = $kfm.Status
            kfmState = $kfm.KfmState
            ready = $kfm.Ready
        }
        package = [ordered]@{
            ppkg = $ppkg.FullName
            sha256 = $ppkgHash
        }
        pendingReboot = $pendingReboot
        freeSystemDriveGb = $freeGb
    }

    $report | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $reportPath -Encoding UTF8 -Force
    Set-RestrictedFileAcl -Path $reportPath

    Write-MigrationLog OK "Preflight PASSED. Evidence: $reportPath"
    exit 0
}
catch {
    $message = $_.Exception.Message
    Write-MigrationLog ERROR "Preflight FAILED: $message"

    try {
        Set-MigrationSafetyState -Values @{
            State = 'PreflightFailed'
            PreflightUtc = [DateTime]::UtcNow.ToString('o')
            LastError = $message
        }
    }
    catch {
        Write-MigrationLog ERROR "Unable to persist PreflightFailed state: $($_.Exception.Message)"
    }

    if ($reportPath) {
        try {
            [ordered]@{
                result = 'PreflightFailed'
                timestampUtc = [DateTime]::UtcNow.ToString('o')
                error = $message
            } | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $reportPath -Encoding UTF8 -Force
            Set-RestrictedFileAcl -Path $reportPath
        }
        catch {
            Write-MigrationLog ERROR "Unable to write failure report: $($_.Exception.Message)"
        }
    }

    exit 1
}
