<#
.SYNOPSIS
    Read-only validation harness for the intune-device-migration-NG destructive lab workflow.

.DESCRIPTION
    Captures independently observable migration evidence before and after a
    same-tenant Hybrid Microsoft Entra joined -> Microsoft Entra joined
    migration and compares the resulting snapshots.

    This harness is deliberately separate from the migration state machine.
    It does not modify migration registry state, device registration, Intune
    enrollment, scheduled tasks, BitLocker configuration, profile ownership,
    Microsoft Entra objects, or Intune objects.

    The only local changes made by this script are creation of its validation
    output directory and report files.

    Supported modes:

      Before
        Capture source-state evidence and evaluate destructive-lab readiness.

      After
        Capture destination-state evidence and independently reconcile the
        migration result against endpoint, registry, certificate, profile,
        user-PRT, Microsoft Entra, and Intune observations.

      Compare
        Compare previously captured Before and After snapshots and report the
        preservation and transition properties that matter to this project.

    The harness intentionally does not trust migration process exit codes or
    marker files as proof of success.  They may be recorded as evidence, but
    completion is assessed from observable state.

    SECURITY
      - config.json is read when Graph access is requested, but clientSecret is
        never written to output.
      - OAuth access tokens are never written to output.
      - BitLocker recovery passwords are never collected.
      - Windows password material is never collected.
      - Output contains device/user identifiers and must be treated as
        sensitive administrative evidence.

.NOTES
    Project:
      JeremiahCornelius/intune-device-migration-NG

    Harness version:
      0.1.2

    Initial code baseline targeted by this harness:
      101902dc7c423036def6f206c322a50474bb1bae

    This migration technique remains outside Microsoft's supported
    Hybrid-to-Entra in-place conversion path.  The harness measures observed
    behavior; it does not change the support boundary.
#>

[CmdletBinding(DefaultParameterSetName = 'Snapshot')]
param(
    [Parameter(Mandatory, ParameterSetName = 'Snapshot')]
    [ValidateSet('Before', 'After')]
    [string]$Phase,

    [Parameter(ParameterSetName = 'Snapshot')]
    [string]$ConfigPath,

    [Parameter(ParameterSetName = 'Snapshot')]
    [string]$ManifestPath,

    [Parameter(ParameterSetName = 'Snapshot')]
    [switch]$SkipGraph,

    [Parameter(ParameterSetName = 'Snapshot')]
    [switch]$RecoveryCredentialManuallyValidated,

    [Parameter(ParameterSetName = 'Snapshot')]
    [switch]$FullDeviceRecoveryManuallyValidated,

    [Parameter(ParameterSetName = 'Snapshot')]
    [string]$OutputDirectory = 'C:\ProgramData\IntuneMigration\Validation',

    [Parameter(ParameterSetName = 'Snapshot')]
    [string]$OutputPath,

    [Parameter(Mandatory, ParameterSetName = 'Compare')]
    [switch]$Compare,

    [Parameter(Mandatory, ParameterSetName = 'Compare')]
    [string]$BeforeSnapshotPath,

    [Parameter(Mandatory, ParameterSetName = 'Compare')]
    [string]$AfterSnapshotPath,

    [Parameter(ParameterSetName = 'Compare')]
    [string]$ComparisonOutputPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:HarnessVersion = '0.1.2'
$script:SchemaVersion = '1.0'
$script:SnapshotSchemaUri = 'https://raw.githubusercontent.com/JeremiahCornelius/intune-device-migration-NG/main/validation/schemas/migration-validation-snapshot.schema.json'
$script:ComparisonSchemaUri = 'https://raw.githubusercontent.com/JeremiahCornelius/intune-device-migration-NG/main/validation/schemas/migration-validation-comparison.schema.json'
$script:MigrationRegistryRoot = 'HKLM:\SOFTWARE\IntuneMigration'
$script:MigrationSafetyPath = 'HKLM:\SOFTWARE\IntuneMigration\Safety'
$script:MigrationLocalPath = 'C:\ProgramData\IntuneMigration'
$script:UserProbeRoot = 'C:\ProgramData\IntuneMigrationUserProbe'
$script:KfmStatusPath = 'HKLM:\SOFTWARE\SBX\IntuneBaselines\WindowsBackupOneDrive'
$script:Checks = New-Object System.Collections.Generic.List[object]

function Get-OptionalPropertyValue {
    [CmdletBinding()]
    param(
        [Parameter()]
        [AllowNull()]
        $InputObject,

        [Parameter(Mandatory)]
        [string]$Name,

        [Parameter()]
        $Default = $null
    )

    if ($null -eq $InputObject) {
        return $Default
    }

    $property = $InputObject.PSObject.Properties[$Name]
    if ($null -eq $property) {
        return $Default
    }

    return $property.Value
}

function Add-ValidationCheck {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Id,

        [Parameter(Mandatory)]
        [ValidateSet('PASS', 'WARN', 'FAIL', 'INFO')]
        [string]$Status,

        [Parameter(Mandatory)]
        [string]$Message,

        [Parameter()]
        [AllowNull()]
        [string]$Evidence
    )

    $script:Checks.Add(
        [pscustomobject][ordered]@{
            id = $Id
            status = $Status
            message = $Message
            evidence = $Evidence
        }
    )
}

function Get-Sha256 {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        return $null
    }

    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
}

function Test-AdministrativeContext {
    [CmdletBinding()]
    param()

    $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object System.Security.Principal.WindowsPrincipal($identity)
    $isAdministrator = $principal.IsInRole(
        [System.Security.Principal.WindowsBuiltInRole]::Administrator
    )

    return [pscustomobject][ordered]@{
        identity = [string]$identity.Name
        sid = if ($identity.User) { [string]$identity.User.Value } else { $null }
        isSystem = [bool]$identity.IsSystem
        isAdministrator = [bool]$isAdministrator
    }
}

function Resolve-ValidationConfigPath {
    [CmdletBinding()]
    param(
        [Parameter()]
        [AllowNull()]
        [string]$RequestedPath
    )

    if (-not [string]::IsNullOrWhiteSpace($RequestedPath)) {
        return [IO.Path]::GetFullPath($RequestedPath)
    }

    $candidates = @(
        (Join-Path -Path $script:MigrationLocalPath -ChildPath 'config.json'),
        (Join-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -ChildPath 'config.json')
    )

    foreach ($candidate in $candidates) {
        if (Test-Path -LiteralPath $candidate -PathType Leaf) {
            return $candidate
        }
    }

    return $null
}

function Read-MigrationConfig {
    [CmdletBinding()]
    param(
        [Parameter()]
        [AllowNull()]
        [string]$Path
    )

    if ([string]::IsNullOrWhiteSpace($Path)) {
        return $null
    }

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        return $null
    }

    return Get-Content -LiteralPath $Path -Raw -ErrorAction Stop |
        ConvertFrom-Json -ErrorAction Stop
}

function Get-RedactedConfigEvidence {
    [CmdletBinding()]
    param(
        [Parameter()]
        [AllowNull()]
        [string]$Path,

        [Parameter()]
        [AllowNull()]
        $Config
    )

    if ([string]::IsNullOrWhiteSpace($Path) -or -not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        return [pscustomobject][ordered]@{
            present = $false
            path = $Path
            sha256 = $null
            tenantName = $null
            clientId = $null
            targetTenantConfigured = $false
            safety = $null
            secretsExported = $false
        }
    }

    $sourceTenant = Get-OptionalPropertyValue -InputObject $Config -Name 'sourceTenant'
    $targetTenant = Get-OptionalPropertyValue -InputObject $Config -Name 'targetTenant'
    $safety = Get-OptionalPropertyValue -InputObject $Config -Name 'safety'

    return [pscustomobject][ordered]@{
        present = $true
        path = $Path
        sha256 = Get-Sha256 -Path $Path
        tenantName = [string](Get-OptionalPropertyValue -InputObject $sourceTenant -Name 'tenantName')
        clientId = [string](Get-OptionalPropertyValue -InputObject $sourceTenant -Name 'clientId')
        targetTenantConfigured = -not [string]::IsNullOrWhiteSpace(
            [string](Get-OptionalPropertyValue -InputObject $targetTenant -Name 'tenantName')
        )
        safety = [pscustomobject][ordered]@{
            expectedSourceUserPrincipalName = [string](Get-OptionalPropertyValue -InputObject $safety -Name 'expectedSourceUserPrincipalName')
            intuneManagementNameSuffix = [string](Get-OptionalPropertyValue -InputObject $safety -Name 'intuneManagementNameSuffix')
            requireOneDriveKfmReady = Get-OptionalPropertyValue -InputObject $safety -Name 'requireOneDriveKfmReady'
            allowPendingReboot = Get-OptionalPropertyValue -InputObject $safety -Name 'allowPendingReboot'
            maxPreflightAgeMinutes = Get-OptionalPropertyValue -InputObject $safety -Name 'maxPreflightAgeMinutes'
            recoveryAccountName = [string](Get-OptionalPropertyValue -InputObject $safety -Name 'recoveryAccountName')
            ppkgSha256 = [string](Get-OptionalPropertyValue -InputObject $safety -Name 'ppkgSha256')
            allowBitLockerDecrypt = Get-OptionalPropertyValue -InputObject $safety -Name 'allowBitLockerDecrypt'
        }
        secretsExported = $false
    }
}

function ConvertFrom-Base64Url {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Text
    )

    $normalized = $Text.Replace('-', '+').Replace('_', '/')
    switch ($normalized.Length % 4) {
        2 { $normalized += '==' }
        3 { $normalized += '=' }
        0 { }
        default { throw 'Invalid base64url token component length.' }
    }

    return [Text.Encoding]::UTF8.GetString(
        [Convert]::FromBase64String($normalized)
    )
}

function Get-JwtTenantId {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$AccessToken
    )

    $parts = $AccessToken.Split('.')
    if ($parts.Count -lt 2) {
        throw 'OAuth access token is not a JWT.'
    }

    $payload = ConvertFrom-Base64Url -Text $parts[1] |
        ConvertFrom-Json -ErrorAction Stop

    $tenantId = [string](Get-OptionalPropertyValue -InputObject $payload -Name 'tid')
    if ([string]::IsNullOrWhiteSpace($tenantId)) {
        throw 'OAuth access token does not contain a tid claim.'
    }

    return $tenantId
}

function New-ReadOnlyGraphSession {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        $Config
    )

    $targetTenant = Get-OptionalPropertyValue -InputObject $Config -Name 'targetTenant'
    $targetTenantName = [string](Get-OptionalPropertyValue -InputObject $targetTenant -Name 'tenantName')

    if (-not [string]::IsNullOrWhiteSpace($targetTenantName)) {
        $tenantConfig = $targetTenant
        $configSource = 'targetTenant'
    }
    else {
        $tenantConfig = Get-OptionalPropertyValue -InputObject $Config -Name 'sourceTenant'
        $configSource = 'sourceTenant'
    }

    foreach ($required in @('tenantName', 'clientId', 'clientSecret')) {
        $value = [string](Get-OptionalPropertyValue -InputObject $tenantConfig -Name $required)
        if ([string]::IsNullOrWhiteSpace($value)) {
            throw "Graph configuration '$configSource.$required' is missing."
        }
    }

    $tenantName = [string]$tenantConfig.tenantName
    $clientId = [string]$tenantConfig.clientId
    $clientSecret = [string]$tenantConfig.clientSecret

    $tokenResponse = Invoke-RestMethod `
        -Method POST `
        -Uri "https://login.microsoftonline.com/$tenantName/oauth2/v2.0/token" `
        -ContentType 'application/x-www-form-urlencoded' `
        -Body @{
            grant_type = 'client_credentials'
            client_id = $clientId
            client_secret = $clientSecret
            scope = 'https://graph.microsoft.com/.default'
        } `
        -ErrorAction Stop

    $token = [string]$tokenResponse.access_token
    if ([string]::IsNullOrWhiteSpace($token)) {
        throw 'Microsoft identity platform did not return an access token.'
    }

    return [pscustomobject][ordered]@{
        tenantId = Get-JwtTenantId -AccessToken $token
        tenantName = $tenantName
        clientId = $clientId
        configSource = $configSource
        headers = @{
            Authorization = "Bearer $token"
            Accept = 'application/json'
        }
    }
}

function Get-DsRegValue {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string[]]$Raw,

        [Parameter(Mandatory)]
        [string]$Name
    )

    foreach ($line in $Raw) {
        if ($line -match ('^\s*' + [regex]::Escape($Name) + '\s*:\s*(.*?)\s*$')) {
            return $matches[1].Trim()
        }
    }

    return $null
}

function Get-DsRegEvidence {
    [CmdletBinding()]
    param()

    $raw = @(& "$env:SystemRoot\System32\dsregcmd.exe" /status 2>&1)
    $exitCode = $LASTEXITCODE

    if ($exitCode -ne 0) {
        return [pscustomobject][ordered]@{
            commandSucceeded = $false
            exitCode = $exitCode
            azureAdJoined = $null
            domainJoined = $null
            workplaceJoined = $null
            tenantId = $null
            tenantName = $null
            deviceId = $null
            azureAdPrt = $null
        }
    }

    return [pscustomobject][ordered]@{
        commandSucceeded = $true
        exitCode = 0
        azureAdJoined = Get-DsRegValue -Raw $raw -Name 'AzureAdJoined'
        domainJoined = Get-DsRegValue -Raw $raw -Name 'DomainJoined'
        workplaceJoined = Get-DsRegValue -Raw $raw -Name 'WorkplaceJoined'
        tenantId = Get-DsRegValue -Raw $raw -Name 'TenantId'
        tenantName = Get-DsRegValue -Raw $raw -Name 'TenantName'
        deviceId = Get-DsRegValue -Raw $raw -Name 'DeviceId'
        # This value is recorded for context only.  In an elevated/SYSTEM
        # harness process it is not accepted as authoritative user PRT evidence.
        azureAdPrt = Get-DsRegValue -Raw $raw -Name 'AzureAdPrt'
    }
}

function Get-InteractiveUserEvidence {
    [CmdletBinding()]
    param()

    try {
        $computerSystem = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
        $name = [string]$computerSystem.UserName

        if ([string]::IsNullOrWhiteSpace($name)) {
            return [pscustomobject][ordered]@{
                present = $false
                windowsName = $null
                sid = $null
                profilePath = $null
                profileLoaded = $false
                isLocalAccount = $null
                localAccountName = $null
            }
        }

        $sid = $null
        if ($name -match '\\') {
            try {
                $account = New-Object -TypeName System.Security.Principal.NTAccount -ArgumentList $name
                $sid = $account.Translate(
                    [System.Security.Principal.SecurityIdentifier]
                ).Value
            }
            catch {
                $sid = $null
            }
        }

        $profile = $null
        if (-not [string]::IsNullOrWhiteSpace($sid)) {
            $profile = Get-CimInstance -ClassName Win32_UserProfile -ErrorAction Stop |
                Where-Object { $_.SID -eq $sid } |
                Select-Object -First 1
        }

        $localAccount = $null
        if (-not [string]::IsNullOrWhiteSpace($sid)) {
            $localAccount = @(
                Get-LocalUser -ErrorAction Stop |
                    Where-Object {
                        $_.SID -and
                        [string]$_.SID.Value -eq [string]$sid
                    }
            ) | Select-Object -First 1
        }

        return [pscustomobject][ordered]@{
            present = $true
            windowsName = $name
            sid = $sid
            profilePath = if ($profile) { [string]$profile.LocalPath } else { $null }
            profileLoaded = if ($profile) { [bool]$profile.Loaded } else { $false }
            isLocalAccount = [bool]($null -ne $localAccount)
            localAccountName = if ($localAccount) { [string]$localAccount.Name } else { $null }
        }
    }
    catch {
        return [pscustomobject][ordered]@{
            present = $false
            windowsName = $null
            sid = $null
            profilePath = $null
            profileLoaded = $false
            isLocalAccount = $null
            localAccountName = $null
            error = $_.Exception.Message
        }
    }
}

function Get-ProfileEvidenceBySid {
    [CmdletBinding()]
    param(
        [Parameter()]
        [AllowNull()]
        [string]$Sid
    )

    if ([string]::IsNullOrWhiteSpace($Sid)) {
        return $null
    }

    try {
        $profile = Get-CimInstance -ClassName Win32_UserProfile -ErrorAction Stop |
            Where-Object { $_.SID -eq $Sid } |
            Select-Object -First 1

        if (-not $profile) {
            return [pscustomobject][ordered]@{
                present = $false
                sid = $Sid
                localPath = $null
                loaded = $false
                special = $false
                lastUseTime = $null
            }
        }

        return [pscustomobject][ordered]@{
            present = $true
            sid = [string]$profile.SID
            localPath = [string]$profile.LocalPath
            loaded = [bool]$profile.Loaded
            special = [bool]$profile.Special
            lastUseTime = if ($profile.LastUseTime) {
                ([DateTime]$profile.LastUseTime).ToUniversalTime().ToString('o')
            }
            else {
                $null
            }
        }
    }
    catch {
        return [pscustomobject][ordered]@{
            present = $false
            sid = $Sid
            error = $_.Exception.Message
        }
    }
}

function Get-IntuneMdmCertificateEvidence {
    [CmdletBinding()]
    param()

    try {
        return @(
            Get-ChildItem -Path 'Cert:\LocalMachine\My' -ErrorAction Stop |
                Where-Object { $_.Issuer -match 'Microsoft Intune MDM Device CA' } |
                Sort-Object NotBefore |
                ForEach-Object {
                    [pscustomobject][ordered]@{
                        isCertificate = $true
                        thumbprint = [string]$_.Thumbprint
                        subject = [string]$_.Subject
                        issuer = [string]$_.Issuer
                        notBeforeUtc = $_.NotBefore.ToUniversalTime().ToString('o')
                        notAfterUtc = $_.NotAfter.ToUniversalTime().ToString('o')
                        hasPrivateKey = [bool]$_.HasPrivateKey
                    }
                }
        )
    }
    catch {
        return @(
            [pscustomobject][ordered]@{
                isCertificate = $false
                thumbprint = $null
                subject = $null
                issuer = $null
                notBeforeUtc = $null
                notAfterUtc = $null
                hasPrivateKey = $false
                error = $_.Exception.Message
            }
        )
    }
}

function Get-ManagedDeviceIdFromCertificateSubject {
    [CmdletBinding()]
    param(
        [Parameter()]
        [AllowNull()]
        [string]$Subject
    )

    if ([string]::IsNullOrWhiteSpace($Subject)) {
        return $null
    }

    if ($Subject -match '(?i)^CN=([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?:,|$)') {
        return $matches[1].ToLowerInvariant()
    }

    return $null
}

function Get-IntuneEnrollmentIds {
    [CmdletBinding()]
    param()

    $root = 'HKLM:\SOFTWARE\Microsoft\Enrollments'
    if (-not (Test-Path -LiteralPath $root)) {
        return @()
    }

    $ids = New-Object System.Collections.Generic.List[string]

    foreach ($key in @(Get-ChildItem -LiteralPath $root -ErrorAction SilentlyContinue)) {
        try {
            $properties = Get-ItemProperty -LiteralPath $key.PSPath -ErrorAction Stop
            $urlProperty = $properties.PSObject.Properties['DiscoveryServiceFullURL']
            if (-not $urlProperty) {
                continue
            }

            $url = [string]$urlProperty.Value
            if ($url -match '(?i)manage\.microsoft\.com') {
                [void]$ids.Add([string]$key.PSChildName)
            }
        }
        catch {
            # Non-enrollment keys are expected beneath this registry root.
        }
    }

    return @($ids | Sort-Object -Unique)
}

function Test-PendingRebootEvidence {
    [CmdletBinding()]
    param()

    $reasons = New-Object System.Collections.Generic.List[string]

    foreach ($path in @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired'
    )) {
        if (Test-Path -LiteralPath $path) {
            [void]$reasons.Add($path)
        }
    }

    $sessionManager = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager'
    try {
        $pendingRename = (
            Get-ItemProperty `
                -LiteralPath $sessionManager `
                -Name PendingFileRenameOperations `
                -ErrorAction Stop
        ).PendingFileRenameOperations

        if ($pendingRename) {
            [void]$reasons.Add('PendingFileRenameOperations')
        }
    }
    catch {
        # Missing PendingFileRenameOperations is normal.
    }

    return [pscustomobject][ordered]@{
        pending = ($reasons.Count -gt 0)
        reasons = @($reasons)
    }
}

function Get-TimeSyncEvidence {
    [CmdletBinding()]
    param()

    $raw = @(& "$env:SystemRoot\System32\w32tm.exe" /query /status 2>&1)
    $exitCode = $LASTEXITCODE

    $source = $null
    $lastSync = $null
    $stratum = $null

    if ($exitCode -eq 0) {
        foreach ($line in $raw) {
            if ($line -match '^\s*Source:\s*(.*?)\s*$') {
                $source = $matches[1].Trim()
            }
            elseif ($line -match '^\s*Last Successful Sync Time:\s*(.*?)\s*$') {
                $lastSync = $matches[1].Trim()
            }
            elseif ($line -match '^\s*Stratum:\s*(.*?)\s*$') {
                $stratum = $matches[1].Trim()
            }
        }
    }

    return [pscustomobject][ordered]@{
        commandSucceeded = ($exitCode -eq 0)
        exitCode = $exitCode
        source = $source
        lastSuccessfulSyncTime = $lastSync
        stratum = $stratum
    }
}

function Get-DomainControllerEvidence {
    [CmdletBinding()]
    param(
        [Parameter()]
        [AllowNull()]
        [string]$DomainName,

        [Parameter()]
        [AllowNull()]
        [string]$DomainJoined
    )

    if ($DomainJoined -ne 'YES' -or [string]::IsNullOrWhiteSpace($DomainName)) {
        return [pscustomobject][ordered]@{
            applicable = $false
            domain = $DomainName
            reachable = $null
            exitCode = $null
        }
    }

    $raw = @(& "$env:SystemRoot\System32\nltest.exe" "/dsgetdc:$DomainName" 2>&1)
    $exitCode = $LASTEXITCODE

    return [pscustomobject][ordered]@{
        applicable = $true
        domain = $DomainName
        reachable = ($exitCode -eq 0)
        exitCode = $exitCode
    }
}

function Get-KfmEvidence {
    [CmdletBinding()]
    param()

    if (-not (Test-Path -LiteralPath $script:KfmStatusPath)) {
        return [pscustomobject][ordered]@{
            present = $false
            ready = $false
            status = $null
            kfmState = $null
            policyRevision = $null
        }
    }

    try {
        $value = Get-ItemProperty -LiteralPath $script:KfmStatusPath -ErrorAction Stop
        $status = [string](Get-OptionalPropertyValue -InputObject $value -Name 'Status')
        $kfmState = [string](Get-OptionalPropertyValue -InputObject $value -Name 'KfmState')

        return [pscustomobject][ordered]@{
            present = $true
            ready = (
                $status -eq 'PolicyApplied' -and
                $kfmState -eq 'DesktopDocumentsPicturesRedirected'
            )
            status = $status
            kfmState = $kfmState
            policyRevision = [string](Get-OptionalPropertyValue -InputObject $value -Name 'PolicyRevision')
        }
    }
    catch {
        return [pscustomobject][ordered]@{
            present = $true
            ready = $false
            error = $_.Exception.Message
        }
    }
}

function Get-SafetyEvidence {
    [CmdletBinding()]
    param()

    if (-not (Test-Path -LiteralPath $script:MigrationSafetyPath)) {
        return [pscustomobject][ordered]@{
            present = $false
            values = $null
        }
    }

    $property = Get-ItemProperty -LiteralPath $script:MigrationSafetyPath -ErrorAction Stop

    # Explicit allow-list prevents an unexpected future registry value from
    # being exported without review.
    $names = @(
        'State',
        'PreflightUtc',
        'ConfigSha256',
        'ExpectedTenantId',
        'OldSid',
        'ExpectedNewSid',
        'ExpectedUserObjectId',
        'ExpectedSourceUserPrincipalName',
        'ExpectedUserPrincipalName',
        'ExpectedProfilePath',
        'ExpectedComputerName',
        'IntuneManagementNameSuffix',
        'ExpectedIntuneManagementName',
        'RecoveryAccountName',
        'PpkgPath',
        'PpkgSha256',
        'OneDriveKfmRequired',
        'OneDriveKfmState',
        'PendingRebootObserved',
        'CommitStep',
        'CommitStartedUtc',
        'ControllerRevision',
        'OldManagedDeviceId',
        'OldMdmEnrollmentId',
        'OldDeviceId',
        'ProvisioningAppliedUtc',
        'RebootRequestedUtc',
        'ProfileReassociatedUtc',
        'PostMigrationAttemptCount',
        'PostMigrationAttemptUtc',
        'PostMigrationPendingUtc',
        'UserPrtVerifiedUtc',
        'UserPrtAuthority',
        'IntuneReenrollmentVerifiedUtc',
        'NewManagedDeviceId',
        'NewEntraDeviceId',
        'NewEntraObjectId',
        'NewMdmCertificateThumbprint',
        'NewMdmCertificateNotBeforeUtc',
        'NewManagedDeviceLastSyncUtc',
        'ManagedDeviceIdReused',
        'PrimaryUserAssignmentRequestedUtc',
        'BitLockerFinalization',
        'IntuneManagementNameStatus',
        'IntuneManagementNameRequestedUtc',
        'IntuneManagementNameVerifiedUtc',
        'ObservedIntuneDeviceName',
        'ObservedIntuneManagementName',
        'IntuneManagementNameWarning',
        'CompleteUtc',
        'RecoveryRequiredUtc',
        'CommitAbortedUtc',
        'LastError'
    )

    $values = [ordered]@{}
    foreach ($name in $names) {
        $candidate = Get-OptionalPropertyValue -InputObject $property -Name $name
        if ($null -ne $candidate) {
            $values[$name] = $candidate
        }
    }

    return [pscustomobject][ordered]@{
        present = $true
        values = [pscustomobject]$values
    }
}

function Get-RecoveryAccountEvidence {
    [CmdletBinding()]
    param(
        [Parameter()]
        [AllowNull()]
        [string]$ConfiguredName
    )

    try {
        if (-not [string]::IsNullOrWhiteSpace($ConfiguredName)) {
            $account = Get-LocalUser -Name $ConfiguredName -ErrorAction Stop
        }
        else {
            $account = Get-LocalUser -ErrorAction Stop |
                Where-Object { $_.SID.Value -match '-500$' } |
                Select-Object -First 1
        }

        if (-not $account) {
            return [pscustomobject][ordered]@{
                present = $false
                name = $ConfiguredName
                sid = $null
                enabled = $false
                localAdministrator = $false
                passwordValidatedByHarness = $false
            }
        }

        $administrators = Get-LocalGroup -SID 'S-1-5-32-544' -ErrorAction Stop
        $members = @(Get-LocalGroupMember -Group $administrators.Name -ErrorAction Stop)
        $isAdministrator = $false

        foreach ($member in $members) {
            if ($member.SID -and $member.SID.Value -eq $account.SID.Value) {
                $isAdministrator = $true
                break
            }
        }

        return [pscustomobject][ordered]@{
            present = $true
            name = [string]$account.Name
            sid = [string]$account.SID.Value
            enabled = [bool]$account.Enabled
            localAdministrator = $isAdministrator
            passwordValidatedByHarness = $false
        }
    }
    catch {
        return [pscustomobject][ordered]@{
            present = $false
            name = $ConfiguredName
            sid = $null
            enabled = $false
            localAdministrator = $false
            passwordValidatedByHarness = $false
            error = $_.Exception.Message
        }
    }
}

function Get-BitLockerEvidence {
    [CmdletBinding()]
    param()

    try {
        $volume = Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction Stop

        $protectors = @(
            foreach ($protector in @($volume.KeyProtector)) {
                [pscustomobject][ordered]@{
                    type = [string]$protector.KeyProtectorType
                    id = [string]$protector.KeyProtectorId
                }
            }
        )

        return [pscustomobject][ordered]@{
            available = $true
            mountPoint = [string]$volume.MountPoint
            volumeStatus = [string]$volume.VolumeStatus
            protectionStatus = [string]$volume.ProtectionStatus
            encryptionPercentage = [int]$volume.EncryptionPercentage
            keyProtectors = $protectors
            recoveryPasswordsExported = $false
        }
    }
    catch {
        return [pscustomobject][ordered]@{
            available = $false
            mountPoint = $env:SystemDrive
            error = $_.Exception.Message
            recoveryPasswordsExported = $false
        }
    }
}

function Get-MigrationTaskEvidence {
    [CmdletBinding()]
    param()

    $records = New-Object System.Collections.Generic.List[object]

    foreach ($name in @('Reboot', 'postMigrate', 'postMigrateUserVerify', 'GroupTag')) {
        try {
            $task = Get-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue
            if (-not $task) {
                $records.Add(
                    [pscustomobject][ordered]@{
                        name = $name
                        present = $false
                    }
                )
                continue
            }

            $info = Get-ScheduledTaskInfo -TaskName $name -ErrorAction SilentlyContinue
            $records.Add(
                [pscustomobject][ordered]@{
                    name = $name
                    present = $true
                    state = [string]$task.State
                    taskPath = [string]$task.TaskPath
                    lastRunTimeUtc = if ($info -and $info.LastRunTime) {
                        $info.LastRunTime.ToUniversalTime().ToString('o')
                    }
                    else {
                        $null
                    }
                    lastTaskResult = if ($info) { [int]$info.LastTaskResult } else { $null }
                    nextRunTimeUtc = if ($info -and $info.NextRunTime -and $info.NextRunTime.Year -gt 1900) {
                        $info.NextRunTime.ToUniversalTime().ToString('o')
                    }
                    else {
                        $null
                    }
                }
            )
        }
        catch {
            $records.Add(
                [pscustomobject][ordered]@{
                    name = $name
                    present = $null
                    error = $_.Exception.Message
                }
            )
        }
    }

    return @($records)
}

function Get-SensitiveResidueEvidence {
    [CmdletBinding()]
    param()

    $configPath = Join-Path -Path $script:MigrationLocalPath -ChildPath 'config.json'
    $detectionPath = Join-Path -Path $script:MigrationLocalPath -ChildPath 'IntuneDetectionRule.txt'

    $packages = @()
    if (Test-Path -LiteralPath $script:MigrationLocalPath) {
        $packages = @(
            Get-ChildItem `
                -LiteralPath $script:MigrationLocalPath `
                -Filter '*.ppkg' `
                -File `
                -Recurse `
                -ErrorAction SilentlyContinue |
                ForEach-Object {
                    [pscustomobject][ordered]@{
                        path = [string]$_.FullName
                        sha256 = Get-Sha256 -Path $_.FullName
                    }
                }
        )
    }

    return [pscustomobject][ordered]@{
        migrationConfigPresent = Test-Path -LiteralPath $configPath -PathType Leaf
        provisioningPackages = $packages
        provisioningPackageCount = $packages.Count
        userProbeDirectoryPresent = Test-Path -LiteralPath $script:UserProbeRoot -PathType Container
        detectionMarkerPresent = Test-Path -LiteralPath $detectionPath -PathType Leaf
    }
}

function Get-SourceProvisioningPackageEvidence {
    [CmdletBinding()]
    param(
        [Parameter()]
        [AllowNull()]
        [string]$ConfigFilePath
    )

    if ([string]::IsNullOrWhiteSpace($ConfigFilePath)) {
        return @()
    }

    $root = Split-Path -Path $ConfigFilePath -Parent
    if (-not (Test-Path -LiteralPath $root -PathType Container)) {
        return @()
    }

    return @(
        Get-ChildItem `
            -LiteralPath $root `
            -Filter '*.ppkg' `
            -File `
            -Recurse `
            -ErrorAction SilentlyContinue |
            ForEach-Object {
                [pscustomobject][ordered]@{
                    path = [string]$_.FullName
                    sha256 = Get-Sha256 -Path $_.FullName
                    size = [long]$_.Length
                }
            }
    )
}

function Get-ManifestEvidence {
    [CmdletBinding()]
    param(
        [Parameter()]
        [AllowNull()]
        [string]$Path
    )

    if ([string]::IsNullOrWhiteSpace($Path)) {
        return [pscustomobject][ordered]@{
            present = $false
            path = $null
            sha256 = $null
            gitCommit = $null
        }
    }

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        return [pscustomobject][ordered]@{
            present = $false
            path = $Path
            sha256 = $null
            gitCommit = $null
        }
    }

    $gitCommit = $null
    try {
        $manifest = Get-Content -LiteralPath $Path -Raw -ErrorAction Stop |
            ConvertFrom-Json -ErrorAction Stop
        $gitCommit = [string](Get-OptionalPropertyValue -InputObject $manifest -Name 'gitCommit')
    }
    catch {
        $gitCommit = $null
    }

    return [pscustomobject][ordered]@{
        present = $true
        path = [IO.Path]::GetFullPath($Path)
        sha256 = Get-Sha256 -Path $Path
        gitCommit = $gitCommit
    }
}

function Get-UserPrtEvidence {
    [CmdletBinding()]
    param(
        [Parameter()]
        [AllowNull()]
        [string]$ExpectedSid
    )

    if ([string]::IsNullOrWhiteSpace($ExpectedSid)) {
        return [pscustomobject][ordered]@{
            accessible = $false
            state = $null
            sid = $null
            userProfile = $null
            tenantId = $null
            azureAdPrt = $null
            verifiedUtc = $null
            authority = $null
        }
    }

    $path = "Registry::HKEY_USERS\$ExpectedSid\Software\IntuneMigration\PostMigrationUserVerification"

    if (-not (Test-Path -LiteralPath $path)) {
        return [pscustomobject][ordered]@{
            accessible = $false
            registryPath = $path
            state = $null
            sid = $ExpectedSid
            userProfile = $null
            tenantId = $null
            azureAdPrt = $null
            verifiedUtc = $null
            authority = $null
        }
    }

    try {
        $value = Get-ItemProperty -LiteralPath $path -ErrorAction Stop

        return [pscustomobject][ordered]@{
            accessible = $true
            registryPath = $path
            state = [string](Get-OptionalPropertyValue -InputObject $value -Name 'State')
            sid = [string](Get-OptionalPropertyValue -InputObject $value -Name 'Sid')
            expectedUpn = [string](Get-OptionalPropertyValue -InputObject $value -Name 'ExpectedUpn')
            userProfile = [string](Get-OptionalPropertyValue -InputObject $value -Name 'UserProfile')
            tenantId = [string](Get-OptionalPropertyValue -InputObject $value -Name 'TenantId')
            azureAdPrt = [string](Get-OptionalPropertyValue -InputObject $value -Name 'AzureAdPrt')
            verifiedUtc = [string](Get-OptionalPropertyValue -InputObject $value -Name 'VerifiedUtc')
            authority = [string](Get-OptionalPropertyValue -InputObject $value -Name 'AzureAdPrtAuthority')
            updateTime = [string](Get-OptionalPropertyValue -InputObject $value -Name 'AzureAdPrtUpdateTime')
        }
    }
    catch {
        return [pscustomobject][ordered]@{
            accessible = $false
            registryPath = $path
            state = $null
            sid = $ExpectedSid
            error = $_.Exception.Message
        }
    }
}

function Invoke-GraphGet {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Uri,

        [Parameter(Mandatory)]
        [hashtable]$Headers
    )

    return Invoke-RestMethod `
        -Method GET `
        -Uri $Uri `
        -Headers $Headers `
        -ErrorAction Stop
}

function Get-GraphEvidence {
    [CmdletBinding()]
    param(
        [Parameter()]
        [AllowNull()]
        $Config,

        [Parameter()]
        [AllowNull()]
        $Safety,

        [Parameter()]
        [AllowNull()]
        $InteractiveUser,

        [Parameter()]
        [AllowNull()]
        $DsReg,

        [Parameter(Mandatory)]
        [object[]]$MdmCertificates,

        [Parameter(Mandatory)]
        [bool]$GraphSkipped
    )

    if ($GraphSkipped) {
        return [pscustomobject][ordered]@{
            attempted = $false
            available = $false
            skipped = $true
            tenantId = $null
            user = $null
            entraDevices = @()
            managedDevices = @()
        }
    }

    if ($null -eq $Config) {
        return [pscustomobject][ordered]@{
            attempted = $false
            available = $false
            skipped = $false
            error = 'No readable migration config was supplied or discovered.'
            tenantId = $null
            user = $null
            entraDevices = @()
            managedDevices = @()
        }
    }

    try {
        $session = New-ReadOnlyGraphSession -Config $Config
    }
    catch {
        return [pscustomobject][ordered]@{
            attempted = $true
            available = $false
            skipped = $false
            error = $_.Exception.Message
            tenantId = $null
            user = $null
            entraDevices = @()
            managedDevices = @()
        }
    }

    $userEvidence = $null
    $expectedUserId = $null
    $oldSid = $null

    if ($Safety -and $Safety.present -and $Safety.values) {
        $expectedUserId = [string](Get-OptionalPropertyValue -InputObject $Safety.values -Name 'ExpectedUserObjectId')
        $oldSid = [string](Get-OptionalPropertyValue -InputObject $Safety.values -Name 'OldSid')
    }

    if ([string]::IsNullOrWhiteSpace($oldSid) -and $InteractiveUser) {
        $oldSid = [string](Get-OptionalPropertyValue -InputObject $InteractiveUser -Name 'sid')
    }

    try {
        if (-not [string]::IsNullOrWhiteSpace($expectedUserId)) {
            $uri = "https://graph.microsoft.com/v1.0/users/$expectedUserId?`$select=id,userPrincipalName,securityIdentifier,onPremisesSecurityIdentifier,onPremisesSyncEnabled,accountEnabled"
            $user = Invoke-GraphGet -Uri $uri -Headers $session.headers

            $userEvidence = [pscustomobject][ordered]@{
                count = 1
                id = [string]$user.id
                userPrincipalName = [string]$user.userPrincipalName
                securityIdentifier = [string]$user.securityIdentifier
                onPremisesSecurityIdentifier = [string]$user.onPremisesSecurityIdentifier
                onPremisesSyncEnabled = $user.onPremisesSyncEnabled
                accountEnabled = $user.accountEnabled
            }
        }
        elseif (-not [string]::IsNullOrWhiteSpace($oldSid)) {
            $filterText = "onPremisesSecurityIdentifier eq '$oldSid'"
            $filter = [Uri]::EscapeDataString($filterText)
            $select = 'id,userPrincipalName,securityIdentifier,onPremisesSecurityIdentifier,onPremisesSyncEnabled,accountEnabled'
            $uri = "https://graph.microsoft.com/v1.0/users?`$filter=$filter&`$select=$select"
            $response = Invoke-GraphGet -Uri $uri -Headers $session.headers
            $users = @($response.value)

            if ($users.Count -eq 1) {
                $user = $users[0]
                $userEvidence = [pscustomobject][ordered]@{
                    count = 1
                    id = [string]$user.id
                    userPrincipalName = [string]$user.userPrincipalName
                    securityIdentifier = [string]$user.securityIdentifier
                    onPremisesSecurityIdentifier = [string]$user.onPremisesSecurityIdentifier
                    onPremisesSyncEnabled = $user.onPremisesSyncEnabled
                    accountEnabled = $user.accountEnabled
                }
            }
            else {
                $userEvidence = [pscustomobject][ordered]@{
                    count = $users.Count
                    id = $null
                    userPrincipalName = $null
                    securityIdentifier = $null
                    onPremisesSecurityIdentifier = $oldSid
                    onPremisesSyncEnabled = $null
                    accountEnabled = $null
                }
            }
        }
    }
    catch {
        $userEvidence = [pscustomobject][ordered]@{
            count = $null
            error = $_.Exception.Message
        }
    }

    $deviceIds = New-Object System.Collections.Generic.List[string]

    if ($DsReg) {
        $currentDeviceId = [string](Get-OptionalPropertyValue -InputObject $DsReg -Name 'deviceId')
        if (-not [string]::IsNullOrWhiteSpace($currentDeviceId)) {
            [void]$deviceIds.Add($currentDeviceId)
        }
    }

    if ($Safety -and $Safety.present -and $Safety.values) {
        foreach ($name in @('OldDeviceId', 'NewEntraDeviceId')) {
            $candidate = [string](Get-OptionalPropertyValue -InputObject $Safety.values -Name $name)
            if (-not [string]::IsNullOrWhiteSpace($candidate) -and $candidate -notin $deviceIds) {
                [void]$deviceIds.Add($candidate)
            }
        }
    }

    $entraDevices = New-Object System.Collections.Generic.List[object]
    foreach ($deviceId in @($deviceIds)) {
        try {
            $filterText = "deviceId eq '$deviceId'"
            $filter = [Uri]::EscapeDataString($filterText)
            $select = 'id,deviceId,displayName,accountEnabled,trustType,profileType'
            $uri = "https://graph.microsoft.com/v1.0/devices?`$filter=$filter&`$select=$select"
            $response = Invoke-GraphGet -Uri $uri -Headers $session.headers
            $devices = @($response.value)

            if ($devices.Count -eq 0) {
                $entraDevices.Add(
                    [pscustomobject][ordered]@{
                        queriedDeviceId = $deviceId
                        count = 0
                        objects = @()
                    }
                )
            }
            else {
                $objects = @(
                    foreach ($device in $devices) {
                        [pscustomobject][ordered]@{
                            id = [string]$device.id
                            deviceId = [string]$device.deviceId
                            displayName = [string]$device.displayName
                            accountEnabled = $device.accountEnabled
                            trustType = [string]$device.trustType
                            profileType = [string]$device.profileType
                        }
                    }
                )

                $entraDevices.Add(
                    [pscustomobject][ordered]@{
                        queriedDeviceId = $deviceId
                        count = $devices.Count
                        objects = $objects
                    }
                )
            }
        }
        catch {
            $entraDevices.Add(
                [pscustomobject][ordered]@{
                    queriedDeviceId = $deviceId
                    count = $null
                    objects = @()
                    error = $_.Exception.Message
                }
            )
        }
    }

    $managedDeviceIds = New-Object System.Collections.Generic.List[string]

    foreach ($certificate in @($MdmCertificates)) {
        $subject = [string](Get-OptionalPropertyValue -InputObject $certificate -Name 'subject')
        $id = Get-ManagedDeviceIdFromCertificateSubject -Subject $subject
        if (-not [string]::IsNullOrWhiteSpace($id) -and $id -notin $managedDeviceIds) {
            [void]$managedDeviceIds.Add($id)
        }
    }

    if ($Safety -and $Safety.present -and $Safety.values) {
        foreach ($name in @('OldManagedDeviceId', 'NewManagedDeviceId')) {
            $candidate = [string](Get-OptionalPropertyValue -InputObject $Safety.values -Name $name)
            if (-not [string]::IsNullOrWhiteSpace($candidate) -and $candidate -notin $managedDeviceIds) {
                [void]$managedDeviceIds.Add($candidate)
            }
        }
    }

    $managedDevices = New-Object System.Collections.Generic.List[object]

    foreach ($id in @($managedDeviceIds)) {
        try {
            $uri = "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices/$id?`$select=id,deviceName,managedDeviceName,managementAgent,enrolledDateTime,lastSyncDateTime,operatingSystem,azureADDeviceId,serialNumber"
            $managed = Invoke-GraphGet -Uri $uri -Headers $session.headers

            $primaryUsers = @()
            try {
                $usersUri = "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices('$id')/users?`$select=id,userPrincipalName"
                $usersResponse = Invoke-GraphGet -Uri $usersUri -Headers $session.headers
                $primaryUsers = @(
                    foreach ($entry in @($usersResponse.value)) {
                        [pscustomobject][ordered]@{
                            id = [string]$entry.id
                            userPrincipalName = [string]$entry.userPrincipalName
                        }
                    }
                )
            }
            catch {
                $primaryUsers = @()
            }

            $managedDevices.Add(
                [pscustomobject][ordered]@{
                    queriedManagedDeviceId = $id
                    found = $true
                    id = [string]$managed.id
                    deviceName = [string]$managed.deviceName
                    managedDeviceName = [string]$managed.managedDeviceName
                    managementAgent = [string]$managed.managementAgent
                    enrolledDateTime = [string]$managed.enrolledDateTime
                    lastSyncDateTime = [string]$managed.lastSyncDateTime
                    operatingSystem = [string]$managed.operatingSystem
                    azureADDeviceId = [string]$managed.azureADDeviceId
                    serialNumber = [string]$managed.serialNumber
                    primaryUsers = $primaryUsers
                }
            )
        }
        catch {
            $managedDevices.Add(
                [pscustomobject][ordered]@{
                    queriedManagedDeviceId = $id
                    found = $false
                    error = $_.Exception.Message
                    primaryUsers = @()
                }
            )
        }
    }

    return [pscustomobject][ordered]@{
        attempted = $true
        available = $true
        skipped = $false
        tenantId = [string]$session.tenantId
        tenantName = [string]$session.tenantName
        clientId = [string]$session.clientId
        user = $userEvidence
        entraDevices = @($entraDevices)
        managedDevices = @($managedDevices)
        accessTokenExported = $false
    }
}

function ConvertTo-UtcDateTimeSafe {
    [CmdletBinding()]
    param(
        [Parameter()]
        [AllowNull()]
        [string]$Value
    )

    if ([string]::IsNullOrWhiteSpace($Value)) {
        return $null
    }

    try {
        return [DateTime]::Parse(
            $Value,
            [Globalization.CultureInfo]::InvariantCulture,
            [Globalization.DateTimeStyles]::RoundtripKind
        ).ToUniversalTime()
    }
    catch {
        return $null
    }
}

function Get-OverallStatus {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object[]]$Checks,

        [Parameter()]
        [AllowNull()]
        [string]$MigrationState
    )

    if ($MigrationState -eq 'RecoveryRequired') {
        return 'RECOVERY REQUIRED'
    }

    if (@($Checks | Where-Object { $_.status -eq 'FAIL' }).Count -gt 0) {
        return 'FAIL'
    }

    if ($MigrationState -in @(
        'ProfileReassociated',
        'PostMigrationVerifying',
        'PostMigrationPending',
        'UserPrtVerified',
        'IntuneReenrollmentVerified'
    )) {
        return 'PENDING'
    }

    if (@($Checks | Where-Object { $_.status -eq 'WARN' }).Count -gt 0) {
        return 'PASS WITH WARNINGS'
    }

    return 'PASS'
}

function Write-ValidationJson {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        $Object,

        [Parameter(Mandatory)]
        [string]$Path
    )

    $directory = Split-Path -Path $Path -Parent
    if ([string]::IsNullOrWhiteSpace($directory)) {
        $directory = (Get-Location).Path
        $Path = Join-Path -Path $directory -ChildPath $Path
    }

    if (-not (Test-Path -LiteralPath $directory -PathType Container)) {
        New-Item -Path $directory -ItemType Directory -Force -ErrorAction Stop | Out-Null
    }

    $json = $Object | ConvertTo-Json -Depth 15
    $temp = "$Path.tmp"

    $json | Set-Content -LiteralPath $temp -Encoding UTF8 -Force -ErrorAction Stop
    Move-Item -LiteralPath $temp -Destination $Path -Force -ErrorAction Stop
}

function Write-ConsoleSummary {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        $Result,

        [Parameter(Mandatory)]
        [string]$Path
    )

    Write-Host ''
    Write-Host '=== intune-device-migration-NG validation ==='
    Write-Host ("Mode:    {0}" -f [string](Get-OptionalPropertyValue -InputObject $Result -Name 'phase' -Default 'Compare'))
    Write-Host ("Status:  {0}" -f [string]$Result.overallStatus)
    Write-Host ("Output:  {0}" -f $Path)
    Write-Host ''

    foreach ($check in @($Result.checks)) {
        Write-Host ("[{0}] {1}: {2}" -f $check.status, $check.id, $check.message)
    }
}

function Add-BeforeChecks {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        $Context
    )

    if ($Context.execution.isAdministrator -or $Context.execution.isSystem) {
        Add-ValidationCheck -Id 'execution.admin' -Status PASS -Message 'Harness has administrative read access.' -Evidence $Context.execution.identity
    }
    else {
        Add-ValidationCheck -Id 'execution.admin' -Status FAIL -Message 'Harness must run elevated or as LocalSystem.' -Evidence $Context.execution.identity
    }

    if ($Context.join.commandSucceeded -and $Context.join.azureAdJoined -eq 'YES' -and $Context.join.domainJoined -eq 'YES') {
        Add-ValidationCheck -Id 'source.hybridJoin' -Status PASS -Message 'Source device is Hybrid Microsoft Entra joined.' -Evidence "DeviceId=$($Context.join.deviceId)"
    }
    else {
        Add-ValidationCheck -Id 'source.hybridJoin' -Status FAIL -Message 'Source must report AzureAdJoined=YES and DomainJoined=YES.' -Evidence "AzureAdJoined=$($Context.join.azureAdJoined); DomainJoined=$($Context.join.domainJoined)"
    }

    if ($Context.interactiveUser.present -and $Context.interactiveUser.profileLoaded -and -not [string]::IsNullOrWhiteSpace([string]$Context.interactiveUser.sid)) {
        Add-ValidationCheck -Id 'source.profileLoaded' -Status PASS -Message 'Intended source profile is loaded and has a resolvable SID.' -Evidence $Context.interactiveUser.profilePath
    }
    else {
        Add-ValidationCheck -Id 'source.profileLoaded' -Status FAIL -Message 'An intended DOMAIN\user profile must be loaded before staging.' -Evidence $Context.interactiveUser.windowsName
    }

    if ($Context.interactiveUser.isLocalAccount -eq $true) {
        Add-ValidationCheck -Id 'source.interactiveDomainIdentity' -Status FAIL -Message 'The active migration identity resolves to a local Windows account.' -Evidence "$($Context.interactiveUser.windowsName) / $($Context.interactiveUser.localAccountName)"
    }
    elseif ($Context.interactiveUser.isLocalAccount -eq $false) {
        Add-ValidationCheck -Id 'source.interactiveDomainIdentity' -Status PASS -Message 'The active migration identity does not resolve to a local Windows account.' -Evidence $Context.interactiveUser.windowsName
    }
    else {
        Add-ValidationCheck -Id 'source.interactiveDomainIdentity' -Status WARN -Message 'Local-versus-domain classification of the active migration identity was not available.' -Evidence $Context.interactiveUser.windowsName
    }

    $validSourceCertificates = @(
        $Context.intuneLocal.mdmCertificates |
            Where-Object { $_.isCertificate -eq $true }
    )
    if ($validSourceCertificates.Count -eq 1) {
        Add-ValidationCheck -Id 'source.mdmCertificate' -Status PASS -Message 'Exactly one Intune MDM Device CA certificate is present.' -Evidence $validSourceCertificates[0].thumbprint
    }
    else {
        Add-ValidationCheck -Id 'source.mdmCertificate' -Status FAIL -Message 'Exactly one Intune MDM Device CA certificate is required.' -Evidence "Count=$($validSourceCertificates.Count)"
    }

    if (@($Context.intuneLocal.enrollmentIds).Count -eq 1) {
        Add-ValidationCheck -Id 'source.enrollmentId' -Status PASS -Message 'Exactly one local Intune enrollment ID is present.' -Evidence $Context.intuneLocal.enrollmentIds[0]
    }
    else {
        Add-ValidationCheck -Id 'source.enrollmentId' -Status FAIL -Message 'Exactly one local Intune enrollment ID is required.' -Evidence "Count=$(@($Context.intuneLocal.enrollmentIds).Count)"
    }

    if ($Context.backup.ready) {
        Add-ValidationCheck -Id 'source.kfm' -Status PASS -Message 'OneDrive KFM reports Desktop, Documents, and Pictures redirected.' -Evidence $Context.backup.kfmState
    }
    else {
        Add-ValidationCheck -Id 'source.kfm' -Status FAIL -Message 'OneDrive KFM readiness gate is not satisfied.' -Evidence "Status=$($Context.backup.status); KfmState=$($Context.backup.kfmState)"
    }

    if (-not $Context.pendingReboot.pending) {
        Add-ValidationCheck -Id 'source.pendingReboot' -Status PASS -Message 'No standard pending-reboot indicators were found.' -Evidence $null
    }
    else {
        Add-ValidationCheck -Id 'source.pendingReboot' -Status FAIL -Message 'A pending reboot is present.' -Evidence ($Context.pendingReboot.reasons -join '; ')
    }

    if ($Context.recovery.present -and $Context.recovery.enabled -and $Context.recovery.localAdministrator) {
        Add-ValidationCheck -Id 'source.recoveryAccount' -Status PASS -Message 'Local recovery account is enabled and is a local Administrator.' -Evidence "$($Context.recovery.name) [$($Context.recovery.sid)]"
    }
    else {
        Add-ValidationCheck -Id 'source.recoveryAccount' -Status FAIL -Message 'Usable local recovery administrator was not verified.' -Evidence $Context.recovery.name
    }

    if ($Context.manualAssertions.recoveryCredentialValidated) {
        Add-ValidationCheck -Id 'source.recoveryPasswordManual' -Status PASS -Message 'Operator asserted that the local recovery credential was manually tested.' -Evidence $Context.recovery.name
    }
    else {
        Add-ValidationCheck -Id 'source.recoveryPasswordManual' -Status WARN -Message 'Harness cannot validate recovery-account password knowledge. Re-run with -RecoveryCredentialManuallyValidated only after testing it.' -Evidence $Context.recovery.name
    }

    if ($Context.manualAssertions.fullDeviceRecoveryValidated) {
        Add-ValidationCheck -Id 'source.fullDeviceRecovery' -Status PASS -Message 'Operator asserted that a full-device recovery/snapshot method was manually validated.' -Evidence 'Manual assertion'
    }
    else {
        Add-ValidationCheck -Id 'source.fullDeviceRecovery' -Status WARN -Message 'A destructive lab run should not proceed until a full-device recovery/snapshot method is validated.' -Evidence 'Use -FullDeviceRecoveryManuallyValidated after validation'
    }

    if ($Context.domainController.applicable -and $Context.domainController.reachable) {
        Add-ValidationCheck -Id 'source.domainController' -Status PASS -Message 'A domain controller was discoverable before migration.' -Evidence $Context.domainController.domain
    }
    elseif ($Context.domainController.applicable) {
        Add-ValidationCheck -Id 'source.domainController' -Status FAIL -Message 'No domain controller was discoverable.' -Evidence $Context.domainController.domain
    }

    if ($Context.timeSync.commandSucceeded) {
        Add-ValidationCheck -Id 'source.timeSync' -Status PASS -Message 'Windows Time service returned synchronization status.' -Evidence $Context.timeSync.source
    }
    else {
        Add-ValidationCheck -Id 'source.timeSync' -Status WARN -Message 'Unable to obtain Windows Time synchronization status.' -Evidence "ExitCode=$($Context.timeSync.exitCode)"
    }

    if ($Context.sourceArtifacts.config.present) {
        Add-ValidationCheck -Id 'source.config' -Status PASS -Message 'Migration config is readable; only its hash and non-secret metadata were exported.' -Evidence $Context.sourceArtifacts.config.sha256
    }
    else {
        Add-ValidationCheck -Id 'source.config' -Status FAIL -Message 'Migration config was not found.' -Evidence $Context.sourceArtifacts.config.path
    }

    $expectedSourceUpn = [string](
        Get-OptionalPropertyValue `
            -InputObject $Context.sourceArtifacts.config.safety `
            -Name 'expectedSourceUserPrincipalName'
    )

    if (
        -not [string]::IsNullOrWhiteSpace($expectedSourceUpn) -and
        $expectedSourceUpn -match '^[^@\s]+@[^@\s]+$'
    ) {
        Add-ValidationCheck -Id 'source.identityIntentConfigured' -Status PASS -Message 'An explicit expected source UPN is pinned in the execution configuration.' -Evidence $expectedSourceUpn
    }
    else {
        Add-ValidationCheck -Id 'source.identityIntentConfigured' -Status FAIL -Message 'config safety.expectedSourceUserPrincipalName must contain the intended synchronized user UPN.' -Evidence $expectedSourceUpn
    }

    $managementNameSuffix = [string](
        Get-OptionalPropertyValue `
            -InputObject $Context.sourceArtifacts.config.safety `
            -Name 'intuneManagementNameSuffix'
    )

    $normalizedSuffix = $managementNameSuffix.Trim().Trim('.').ToLowerInvariant()
    $suffixLabels = if ([string]::IsNullOrWhiteSpace($normalizedSuffix)) { @() } else { @($normalizedSuffix.Split('.')) }
    $suffixValid = $suffixLabels.Count -ge 2
    foreach ($label in $suffixLabels) {
        if (
            [string]::IsNullOrWhiteSpace($label) -or
            $label.Length -gt 63 -or
            $label -notmatch '^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$'
        ) {
            $suffixValid = $false
        }
    }

    if ($suffixValid) {
        $expectedManagementName = "$($Context.system.computerName).$normalizedSuffix"
        Add-ValidationCheck -Id 'source.intuneManagementNameConfigured' -Status PASS -Message 'A DNS-style Intune management-name suffix is explicitly configured.' -Evidence $expectedManagementName
    }
    else {
        Add-ValidationCheck -Id 'source.intuneManagementNameConfigured' -Status FAIL -Message 'config safety.intuneManagementNameSuffix must be a DNS-style suffix such as domain.tld.' -Evidence $managementNameSuffix
    }

    Add-ValidationCheck -Id 'source.ppkgComputerNameContract' -Status INFO -Message 'NG PPKG build contract requires ComputerName customization to be omitted; the binary PPKG is hash-pinned but this harness does not claim to introspect that customization.' -Evidence $Context.sourceArtifacts.config.safety.ppkgSha256

    $packages = @($Context.sourceArtifacts.provisioningPackages)
    if ($packages.Count -eq 1) {
        $expectedHash = [string](Get-OptionalPropertyValue -InputObject $Context.sourceArtifacts.config.safety -Name 'ppkgSha256')
        if (-not [string]::IsNullOrWhiteSpace($expectedHash)) {
            if ($packages[0].sha256 -eq $expectedHash.ToLowerInvariant()) {
                Add-ValidationCheck -Id 'source.ppkg' -Status PASS -Message 'Exactly one PPKG is present and matches the configured SHA-256 pin.' -Evidence $packages[0].sha256
            }
            else {
                Add-ValidationCheck -Id 'source.ppkg' -Status FAIL -Message 'PPKG SHA-256 does not match safety.ppkgSha256.' -Evidence "Observed=$($packages[0].sha256); Expected=$expectedHash"
            }
        }
        else {
            Add-ValidationCheck -Id 'source.ppkg' -Status WARN -Message 'Exactly one PPKG is present, but no configured SHA-256 pin was found.' -Evidence $packages[0].sha256
        }
    }
    else {
        Add-ValidationCheck -Id 'source.ppkg' -Status FAIL -Message 'Exactly one PPKG must be present beside/beneath the execution config.' -Evidence "Count=$($packages.Count)"
    }

    if ($Context.sourceArtifacts.manifest.present) {
        Add-ValidationCheck -Id 'source.manifest' -Status PASS -Message 'Execution manifest is present and hashed.' -Evidence "$($Context.sourceArtifacts.manifest.gitCommit) / $($Context.sourceArtifacts.manifest.sha256)"
    }
    else {
        Add-ValidationCheck -Id 'source.manifest' -Status WARN -Message 'No execution manifest was supplied. Use the lab bundle manifest for reproducibility.' -Evidence $null
    }

    if ($Context.graph.skipped) {
        Add-ValidationCheck -Id 'source.graph' -Status WARN -Message 'Graph collection was explicitly skipped.' -Evidence $null
    }
    elseif (-not $Context.graph.available) {
        Add-ValidationCheck -Id 'source.graph' -Status FAIL -Message 'Graph evidence could not be collected.' -Evidence $Context.graph.error
    }
    else {
        Add-ValidationCheck -Id 'source.graph' -Status PASS -Message 'Graph read-only evidence collection succeeded.' -Evidence "TenantId=$($Context.graph.tenantId)"

        if ([string]$Context.graph.tenantId -eq [string]$Context.join.tenantId) {
            Add-ValidationCheck -Id 'source.graphTenant' -Status PASS -Message 'Graph token tenant matches the source dsreg tenant.' -Evidence $Context.graph.tenantId
        }
        else {
            Add-ValidationCheck -Id 'source.graphTenant' -Status FAIL -Message 'Graph token tenant does not match the source dsreg tenant.' -Evidence "Graph=$($Context.graph.tenantId); Device=$($Context.join.tenantId)"
        }

        if (
            $Context.graph.user -and
            $Context.graph.user.count -eq 1 -and
            $Context.graph.user.accountEnabled -eq $true -and
            $Context.graph.user.onPremisesSyncEnabled -eq $true -and
            [string]$Context.graph.user.onPremisesSecurityIdentifier -eq [string]$Context.interactiveUser.sid -and
            [string]$Context.graph.user.securityIdentifier -match '^S-1-12-1-(\d+-){2,}\d+$'
        ) {
            Add-ValidationCheck -Id 'source.identityMapping' -Status PASS -Message 'Exactly one Entra user maps the source AD SID to an Entra cloud SID.' -Evidence "$($Context.graph.user.userPrincipalName) / $($Context.graph.user.securityIdentifier)"
        }
        else {
            Add-ValidationCheck -Id 'source.identityMapping' -Status FAIL -Message 'Deterministic Entra user SID mapping was not uniquely observable.' -Evidence $null
        }

        $resolvedSourceUpn = $null
        if ($Context.graph.user) {
            $resolvedSourceUpn = [string](
                Get-OptionalPropertyValue `
                    -InputObject $Context.graph.user `
                    -Name 'userPrincipalName'
            )
        }

        if (
            -not [string]::IsNullOrWhiteSpace($expectedSourceUpn) -and
            $Context.graph.user -and
            $Context.graph.user.count -eq 1 -and
            $resolvedSourceUpn -ieq $expectedSourceUpn
        ) {
            Add-ValidationCheck -Id 'source.identityIntentMatch' -Status PASS -Message 'The SID-resolved Entra user matches the configured expected source UPN.' -Evidence $expectedSourceUpn
        }
        else {
            Add-ValidationCheck -Id 'source.identityIntentMatch' -Status FAIL -Message 'The SID-resolved Entra user does not match the configured expected source UPN.' -Evidence "Configured=$expectedSourceUpn; Resolved=$resolvedSourceUpn"
        }

        $sourceDeviceRecords = @(
            $Context.graph.entraDevices |
                Where-Object { $_.queriedDeviceId -eq $Context.join.deviceId }
        )
        if (
            $sourceDeviceRecords.Count -eq 1 -and
            $sourceDeviceRecords[0].count -eq 1 -and
            $sourceDeviceRecords[0].objects[0].accountEnabled -eq $true
        ) {
            Add-ValidationCheck -Id 'source.entraDevice' -Status PASS -Message 'Exactly one enabled Entra device object matches the source dsreg DeviceId.' -Evidence $Context.join.deviceId
        }
        else {
            Add-ValidationCheck -Id 'source.entraDevice' -Status FAIL -Message 'Source dsreg DeviceId did not resolve to exactly one enabled Entra device object.' -Evidence $Context.join.deviceId
        }

        $sourceCertificateManagedId = $null
        if ($validSourceCertificates.Count -eq 1) {
            $sourceCertificateManagedId = Get-ManagedDeviceIdFromCertificateSubject -Subject ([string]$validSourceCertificates[0].subject)
        }

        $sourceManaged = @(
            $Context.graph.managedDevices |
                Where-Object {
                    $_.found -eq $true -and
                    ([string]$_.id -ieq [string]$sourceCertificateManagedId) -and
                    ([string]$_.azureADDeviceId -ieq [string]$Context.join.deviceId)
                }
        )
        if ($sourceManaged.Count -ge 1) {
            Add-ValidationCheck -Id 'source.intuneCorrelation' -Status PASS -Message 'An Intune managedDevice correlates to the source Entra DeviceId.' -Evidence $sourceManaged[0].id
        }
        else {
            Add-ValidationCheck -Id 'source.intuneCorrelation' -Status FAIL -Message 'No readable Intune managedDevice correlated to the source Entra DeviceId.' -Evidence $Context.join.deviceId
        }
    }
}

function Add-AfterChecks {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        $Context
    )

    $safetyValues = if ($Context.migrationSafety.present) { $Context.migrationSafety.values } else { $null }
    $state = [string](Get-OptionalPropertyValue -InputObject $safetyValues -Name 'State')
    $expectedTenantId = [string](Get-OptionalPropertyValue -InputObject $safetyValues -Name 'ExpectedTenantId')
    $oldSid = [string](Get-OptionalPropertyValue -InputObject $safetyValues -Name 'OldSid')
    $newSid = [string](Get-OptionalPropertyValue -InputObject $safetyValues -Name 'ExpectedNewSid')
    $expectedProfile = [string](Get-OptionalPropertyValue -InputObject $safetyValues -Name 'ExpectedProfilePath')
    $expectedUserId = [string](Get-OptionalPropertyValue -InputObject $safetyValues -Name 'ExpectedUserObjectId')
    $expectedSourceUpn = [string](Get-OptionalPropertyValue -InputObject $safetyValues -Name 'ExpectedSourceUserPrincipalName')
    $expectedUpn = [string](Get-OptionalPropertyValue -InputObject $safetyValues -Name 'ExpectedUserPrincipalName')
    $expectedComputerName = [string](Get-OptionalPropertyValue -InputObject $safetyValues -Name 'ExpectedComputerName')
    $expectedManagementName = [string](Get-OptionalPropertyValue -InputObject $safetyValues -Name 'ExpectedIntuneManagementName')
    $managementNameStatus = [string](Get-OptionalPropertyValue -InputObject $safetyValues -Name 'IntuneManagementNameStatus')

    if ($Context.execution.isAdministrator -or $Context.execution.isSystem) {
        Add-ValidationCheck -Id 'execution.admin' -Status PASS -Message 'Harness has administrative read access.' -Evidence $Context.execution.identity
    }
    else {
        Add-ValidationCheck -Id 'execution.admin' -Status FAIL -Message 'Harness must run elevated or as LocalSystem.' -Evidence $Context.execution.identity
    }

    if (
        -not [string]::IsNullOrWhiteSpace($expectedSourceUpn) -and
        -not [string]::IsNullOrWhiteSpace($expectedUpn) -and
        $expectedSourceUpn -ieq $expectedUpn
    ) {
        Add-ValidationCheck -Id 'after.identityIntentContinuity' -Status PASS -Message 'Persisted operator source-user intent matches the Entra UPN carried into post-migration verification.' -Evidence $expectedSourceUpn
    }
    else {
        Add-ValidationCheck -Id 'after.identityIntentContinuity' -Status FAIL -Message 'Persisted source-user intent and resolved expected Entra UPN are missing or inconsistent.' -Evidence "Intent=$expectedSourceUpn; Resolved=$expectedUpn"
    }

    if (
        -not [string]::IsNullOrWhiteSpace($expectedComputerName) -and
        [string]$Context.system.computerName -ieq $expectedComputerName
    ) {
        Add-ValidationCheck -Id 'after.physicalHostnamePreserved' -Status PASS -Message 'Physical Windows hostname matches the preflight-pinned value.' -Evidence $expectedComputerName
    }
    else {
        Add-ValidationCheck -Id 'after.physicalHostnamePreserved' -Status FAIL -Message 'Physical Windows hostname preservation could not be proven.' -Evidence "Expected=$expectedComputerName; Observed=$($Context.system.computerName)"
    }

    if (-not $Context.migrationSafety.present) {
        Add-ValidationCheck -Id 'after.safetyState' -Status FAIL -Message 'Migration Safety registry state is missing.' -Evidence $null
    }
    elseif ($state -eq 'Complete') {
        Add-ValidationCheck -Id 'after.safetyState' -Status PASS -Message 'Migration state machine reports Complete; independent checks continue below.' -Evidence $state
    }
    elseif ($state -eq 'RecoveryRequired') {
        Add-ValidationCheck -Id 'after.safetyState' -Status FAIL -Message 'Migration state machine reports RecoveryRequired.' -Evidence ([string](Get-OptionalPropertyValue -InputObject $safetyValues -Name 'LastError'))
    }
    else {
        Add-ValidationCheck -Id 'after.safetyState' -Status WARN -Message 'Migration has not reached Complete.' -Evidence $state
    }

    if (
        $Context.join.commandSucceeded -and
        $Context.join.azureAdJoined -eq 'YES' -and
        $Context.join.domainJoined -eq 'NO'
    ) {
        Add-ValidationCheck -Id 'after.joinState' -Status PASS -Message 'Device reports Entra joined and not AD-domain joined.' -Evidence "DeviceId=$($Context.join.deviceId)"
    }
    else {
        Add-ValidationCheck -Id 'after.joinState' -Status FAIL -Message 'Expected AzureAdJoined=YES and DomainJoined=NO.' -Evidence "AzureAdJoined=$($Context.join.azureAdJoined); DomainJoined=$($Context.join.domainJoined)"
    }

    if (
        -not [string]::IsNullOrWhiteSpace($expectedTenantId) -and
        [string]$Context.join.tenantId -eq $expectedTenantId
    ) {
        Add-ValidationCheck -Id 'after.tenant' -Status PASS -Message 'Current device tenant matches preflight target tenant.' -Evidence $expectedTenantId
    }
    else {
        Add-ValidationCheck -Id 'after.tenant' -Status FAIL -Message 'Current device tenant does not match the preflight target tenant.' -Evidence "Current=$($Context.join.tenantId); Expected=$expectedTenantId"
    }

    if (
        $Context.expectedProfiles.new -and
        $Context.expectedProfiles.new.present -and
        ([string]$Context.expectedProfiles.new.localPath).TrimEnd('\') -ieq $expectedProfile.TrimEnd('\')
    ) {
        Add-ValidationCheck -Id 'after.profileNewOwner' -Status PASS -Message 'Expected Entra SID owns the original profile path.' -Evidence "$newSid -> $expectedProfile"
    }
    else {
        Add-ValidationCheck -Id 'after.profileNewOwner' -Status FAIL -Message 'Expected Entra SID does not own the preserved profile path.' -Evidence "$newSid / $expectedProfile"
    }

    if ($Context.expectedProfiles.old -and -not $Context.expectedProfiles.old.present) {
        Add-ValidationCheck -Id 'after.profileOldOwnerGone' -Status PASS -Message 'Old AD SID no longer enumerates as a Win32_UserProfile.' -Evidence $oldSid
    }
    else {
        Add-ValidationCheck -Id 'after.profileOldOwnerGone' -Status FAIL -Message 'Old AD SID still enumerates as a Win32_UserProfile.' -Evidence $oldSid
    }

    if (
        $Context.userPrtEvidence.accessible -and
        $Context.userPrtEvidence.state -eq 'Verified' -and
        $Context.userPrtEvidence.azureAdPrt -eq 'YES' -and
        $Context.userPrtEvidence.sid -eq $newSid
    ) {
        Add-ValidationCheck -Id 'after.userPrt' -Status PASS -Message 'Independent HKU evidence confirms AzureAdPrt=YES for the expected Entra SID.' -Evidence $Context.userPrtEvidence.verifiedUtc
    }
    elseif ($state -eq 'Complete' -and -not [string]::IsNullOrWhiteSpace([string](Get-OptionalPropertyValue -InputObject $safetyValues -Name 'UserPrtVerifiedUtc'))) {
        Add-ValidationCheck -Id 'after.userPrt' -Status WARN -Message 'Raw HKU PRT evidence is not currently accessible; Safety state records that the finalizer previously verified it.' -Evidence ([string](Get-OptionalPropertyValue -InputObject $safetyValues -Name 'UserPrtVerifiedUtc'))
    }
    else {
        Add-ValidationCheck -Id 'after.userPrt' -Status FAIL -Message 'Expected user-context AzureAdPrt=YES evidence was not observed.' -Evidence $null
    }

    $validAfterCertificates = @(
        $Context.intuneLocal.mdmCertificates |
            Where-Object { $_.isCertificate -eq $true }
    )
    if ($validAfterCertificates.Count -eq 1) {
        Add-ValidationCheck -Id 'after.mdmCertificate' -Status PASS -Message 'Exactly one post-migration Intune MDM certificate is present.' -Evidence $validAfterCertificates[0].thumbprint

        $commitForCertificate = ConvertTo-UtcDateTimeSafe -Value ([string](Get-OptionalPropertyValue -InputObject $safetyValues -Name 'CommitStartedUtc'))
        $certificateNotBefore = ConvertTo-UtcDateTimeSafe -Value ([string]$validAfterCertificates[0].notBeforeUtc)
        if ($commitForCertificate -and $certificateNotBefore -and $certificateNotBefore -ge $commitForCertificate.AddMinutes(-5)) {
            Add-ValidationCheck -Id 'after.mdmCertificateFreshness' -Status PASS -Message 'MDM certificate NotBefore is consistent with a post-commit enrollment.' -Evidence $validAfterCertificates[0].notBeforeUtc
        }
        else {
            Add-ValidationCheck -Id 'after.mdmCertificateFreshness' -Status FAIL -Message 'MDM certificate freshness could not be tied to the post-commit enrollment window.' -Evidence $validAfterCertificates[0].notBeforeUtc
        }
    }
    else {
        Add-ValidationCheck -Id 'after.mdmCertificate' -Status FAIL -Message 'Expected exactly one post-migration Intune MDM certificate.' -Evidence "Count=$($validAfterCertificates.Count)"
    }

    if ($Context.graph.skipped) {
        Add-ValidationCheck -Id 'after.graph' -Status WARN -Message 'Graph collection was explicitly skipped; cloud reconciliation is incomplete.' -Evidence $null
    }
    elseif (-not $Context.graph.available) {
        Add-ValidationCheck -Id 'after.graph' -Status FAIL -Message 'Graph evidence could not be collected.' -Evidence $Context.graph.error
    }
    else {
        Add-ValidationCheck -Id 'after.graph' -Status PASS -Message 'Graph read-only evidence collection succeeded.' -Evidence "TenantId=$($Context.graph.tenantId)"

        if ([string]$Context.graph.tenantId -eq $expectedTenantId) {
            Add-ValidationCheck -Id 'after.graphTenant' -Status PASS -Message 'Graph token tenant matches the expected migration tenant.' -Evidence $Context.graph.tenantId
        }
        else {
            Add-ValidationCheck -Id 'after.graphTenant' -Status FAIL -Message 'Graph token tenant does not match the expected migration tenant.' -Evidence "Graph=$($Context.graph.tenantId); Expected=$expectedTenantId"
        }

        if (
            $Context.graph.user -and
            $Context.graph.user.count -eq 1 -and
            [string]$Context.graph.user.id -eq $expectedUserId -and
            [string]$Context.graph.user.userPrincipalName -ieq $expectedUpn -and
            [string]$Context.graph.user.securityIdentifier -eq $newSid
        ) {
            Add-ValidationCheck -Id 'after.identity' -Status PASS -Message 'Graph confirms the expected user object, UPN, and Entra cloud SID.' -Evidence "$expectedUpn / $newSid"
        }
        else {
            Add-ValidationCheck -Id 'after.identity' -Status FAIL -Message 'Expected post-migration Entra user identity could not be independently reconciled.' -Evidence "$expectedUserId / $expectedUpn / $newSid"
        }

        $currentDeviceRecords = @(
            $Context.graph.entraDevices |
                Where-Object { $_.queriedDeviceId -eq $Context.join.deviceId }
        )

        if (
            $currentDeviceRecords.Count -eq 1 -and
            $currentDeviceRecords[0].count -eq 1 -and
            $currentDeviceRecords[0].objects[0].accountEnabled -eq $true
        ) {
            Add-ValidationCheck -Id 'after.entraDevice' -Status PASS -Message 'Exactly one enabled/current Entra device record was observable for dsreg DeviceId.' -Evidence $Context.join.deviceId
        }
        else {
            Add-ValidationCheck -Id 'after.entraDevice' -Status FAIL -Message 'Current dsreg DeviceId did not resolve to exactly one Entra device record.' -Evidence $Context.join.deviceId
        }

        $currentCertificateManagedId = $null
        if ($validAfterCertificates.Count -eq 1) {
            $currentCertificateManagedId = Get-ManagedDeviceIdFromCertificateSubject -Subject ([string]$validAfterCertificates[0].subject)
        }

        $currentManaged = @(
            $Context.graph.managedDevices |
                Where-Object {
                    $_.found -eq $true -and
                    ([string]$_.id -ieq [string]$currentCertificateManagedId) -and
                    ([string]$_.azureADDeviceId -ieq [string]$Context.join.deviceId)
                }
        )

        if ($currentManaged.Count -ge 1) {
            Add-ValidationCheck -Id 'after.intuneCorrelation' -Status PASS -Message 'An Intune managedDevice correlates to the current Entra DeviceId.' -Evidence $currentManaged[0].id

            $commitStartedUtc = ConvertTo-UtcDateTimeSafe -Value ([string](Get-OptionalPropertyValue -InputObject $safetyValues -Name 'CommitStartedUtc'))
            $lastSyncUtc = ConvertTo-UtcDateTimeSafe -Value ([string]$currentManaged[0].lastSyncDateTime)
            if ($commitStartedUtc -and $lastSyncUtc -and $lastSyncUtc -ge $commitStartedUtc.AddMinutes(-5)) {
                Add-ValidationCheck -Id 'after.intunePostCommitSync' -Status PASS -Message 'Intune managedDevice has a sync timestamp attributable to the post-commit enrollment window.' -Evidence $lastSyncUtc.ToString('o')
            }
            else {
                Add-ValidationCheck -Id 'after.intunePostCommitSync' -Status FAIL -Message 'A post-commit Intune sync timestamp could not be proven.' -Evidence ([string]$currentManaged[0].lastSyncDateTime)
            }

            if (
                -not [string]::IsNullOrWhiteSpace($expectedManagementName) -and
                [string]$currentManaged[0].managedDeviceName -ieq $expectedManagementName
            ) {
                Add-ValidationCheck -Id 'after.intuneManagementName' -Status PASS -Message 'Intune managedDeviceName matches the configured post-migration administrative name.' -Evidence $expectedManagementName
            }
            else {
                Add-ValidationCheck -Id 'after.intuneManagementName' -Status WARN -Message 'Intune managedDeviceName does not match the configured administrative name.' -Evidence "Expected=$expectedManagementName; Observed=$([string]$currentManaged[0].managedDeviceName); FinalizerStatus=$managementNameStatus"
            }

            if ([string]$currentManaged[0].deviceName -ieq $expectedComputerName) {
                Add-ValidationCheck -Id 'after.intuneDeviceNamePreserved' -Status PASS -Message 'Intune deviceName agrees with the preserved physical Windows hostname.' -Evidence $expectedComputerName
            }
            else {
                Add-ValidationCheck -Id 'after.intuneDeviceNamePreserved' -Status WARN -Message 'Intune deviceName does not currently agree with the preserved physical Windows hostname.' -Evidence "Physical=$expectedComputerName; IntuneDeviceName=$([string]$currentManaged[0].deviceName)"
            }

            if ($managementNameStatus -eq 'Verified') {
                Add-ValidationCheck -Id 'after.intuneManagementNameFinalizerStatus' -Status PASS -Message 'Finalizer recorded verified Intune management-name read-back.' -Evidence ([string](Get-OptionalPropertyValue -InputObject $safetyValues -Name 'IntuneManagementNameVerifiedUtc'))
            }
            else {
                Add-ValidationCheck -Id 'after.intuneManagementNameFinalizerStatus' -Status WARN -Message 'Finalizer did not record verified Intune management-name classification; core migration may still be Complete.' -Evidence ([string](Get-OptionalPropertyValue -InputObject $safetyValues -Name 'IntuneManagementNameWarning'))
            }

            $expectedPrimary = @(
                $currentManaged[0].primaryUsers |
                    Where-Object {
                        ([string]$_.id -eq $expectedUserId) -or
                        ([string]$_.userPrincipalName -ieq $expectedUpn)
                    }
            )

            if ($expectedPrimary.Count -ge 1) {
                Add-ValidationCheck -Id 'after.primaryUser' -Status PASS -Message 'Expected Entra user is observable as an Intune primary user.' -Evidence $expectedUpn
            }
            else {
                Add-ValidationCheck -Id 'after.primaryUser' -Status WARN -Message 'Expected Intune primary user was not yet observable through the users relationship.' -Evidence $expectedUpn
            }
        }
        else {
            Add-ValidationCheck -Id 'after.intuneCorrelation' -Status FAIL -Message 'No observed managedDevice correlates to the current Entra DeviceId.' -Evidence $Context.join.deviceId
        }
    }

    $bitLockerFinalization = [string](Get-OptionalPropertyValue -InputObject $safetyValues -Name 'BitLockerFinalization')
    if ($Context.bitLocker.available) {
        $recoveryProtectorCount = @(
            $Context.bitLocker.keyProtectors |
                Where-Object { $_.type -eq 'RecoveryPassword' }
        ).Count

        if ($recoveryProtectorCount -gt 0) {
            Add-ValidationCheck -Id 'after.bitLocker' -Status PASS -Message 'System volume retains at least one RecoveryPassword protector.' -Evidence "Protectors=$recoveryProtectorCount; Finalizer=$bitLockerFinalization"
        }
        else {
            Add-ValidationCheck -Id 'after.bitLocker' -Status WARN -Message 'No RecoveryPassword protector was observed on the system volume.' -Evidence $bitLockerFinalization
        }

        if ($bitLockerFinalization -match '^EscrowRequested:') {
            Add-ValidationCheck -Id 'after.bitLockerCloudReadback' -Status INFO -Message 'Finalizer recorded a BitLocker escrow request. Harness does not claim cloud read-back without recovery-key read permission.' -Evidence $bitLockerFinalization
        }
    }
    else {
        Add-ValidationCheck -Id 'after.bitLocker' -Status WARN -Message 'BitLocker state could not be read.' -Evidence $Context.bitLocker.error
    }

    if ($state -eq 'Complete') {
        if (-not $Context.sensitiveResidue.migrationConfigPresent) {
            Add-ValidationCheck -Id 'after.cleanup.config' -Status PASS -Message 'Protected staged config.json was removed after completion.' -Evidence $null
        }
        else {
            Add-ValidationCheck -Id 'after.cleanup.config' -Status FAIL -Message 'Protected staged config.json remains after Complete.' -Evidence $script:MigrationLocalPath
        }

        if ($Context.sensitiveResidue.provisioningPackageCount -eq 0) {
            Add-ValidationCheck -Id 'after.cleanup.ppkg' -Status PASS -Message 'No staged PPKG remains after completion.' -Evidence $null
        }
        else {
            Add-ValidationCheck -Id 'after.cleanup.ppkg' -Status FAIL -Message 'One or more staged PPKG files remain after Complete.' -Evidence "Count=$($Context.sensitiveResidue.provisioningPackageCount)"
        }

        if (-not $Context.sensitiveResidue.userProbeDirectoryPresent) {
            Add-ValidationCheck -Id 'after.cleanup.userProbe' -Status PASS -Message 'Temporary user-probe staging directory was removed.' -Evidence $null
        }
        else {
            Add-ValidationCheck -Id 'after.cleanup.userProbe' -Status FAIL -Message 'Temporary user-probe staging directory remains after Complete.' -Evidence $script:UserProbeRoot
        }

        $remainingTasks = @($Context.tasks | Where-Object { $_.present -eq $true })
        if ($remainingTasks.Count -eq 0) {
            Add-ValidationCheck -Id 'after.cleanup.tasks' -Status PASS -Message 'No migration scheduled tasks remain.' -Evidence $null
        }
        else {
            Add-ValidationCheck -Id 'after.cleanup.tasks' -Status FAIL -Message 'One or more migration scheduled tasks remain after Complete.' -Evidence (($remainingTasks | ForEach-Object { $_.name }) -join ', ')
        }
    }
    else {
        Add-ValidationCheck -Id 'after.cleanup.deferred' -Status INFO -Message 'Sensitive-material/task cleanup is evaluated as a hard requirement only after Safety State=Complete.' -Evidence $state
    }

    if ($Context.sensitiveResidue.detectionMarkerPresent) {
        Add-ValidationCheck -Id 'after.detectionMarker' -Status INFO -Message 'Provisioning detection marker remains present by current design; it is not treated as proof of migration completion.' -Evidence (Join-Path -Path $script:MigrationLocalPath -ChildPath 'IntuneDetectionRule.txt')
    }

    Add-ValidationCheck -Id 'after.staleCloudObjects' -Status INFO -Message 'Old Entra/Intune object observations are reported but not failed in v0.1 because server-side stale-object cleanup is intentionally deferred.' -Evidence "OldDeviceId=$([string](Get-OptionalPropertyValue -InputObject $safetyValues -Name 'OldDeviceId')); OldManagedDeviceId=$([string](Get-OptionalPropertyValue -InputObject $safetyValues -Name 'OldManagedDeviceId'))"
}

function New-ValidationSnapshot {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('Before', 'After')]
        [string]$SnapshotPhase,

        [Parameter()]
        [AllowNull()]
        [string]$RequestedConfigPath,

        [Parameter()]
        [AllowNull()]
        [string]$RequestedManifestPath,

        [Parameter(Mandatory)]
        [bool]$GraphSkipped,

        [Parameter(Mandatory)]
        [bool]$RecoveryCredentialValidated,

        [Parameter(Mandatory)]
        [bool]$FullDeviceRecoveryValidated
    )

    $script:Checks.Clear()

    $execution = Test-AdministrativeContext
    if (-not ($execution.isAdministrator -or $execution.isSystem)) {
        throw 'Validation harness must run elevated or as LocalSystem.'
    }

    $resolvedConfigPath = Resolve-ValidationConfigPath -RequestedPath $RequestedConfigPath
    $config = Read-MigrationConfig -Path $resolvedConfigPath
    $configEvidence = Get-RedactedConfigEvidence -Path $resolvedConfigPath -Config $config

    $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
    $computer = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
    $join = Get-DsRegEvidence
    $interactive = Get-InteractiveUserEvidence
    $safety = Get-SafetyEvidence
    $mdmCertificates = @(Get-IntuneMdmCertificateEvidence)
    $enrollmentIds = @(Get-IntuneEnrollmentIds)
    $pendingReboot = Test-PendingRebootEvidence
    $timeSync = Get-TimeSyncEvidence
    $domainController = Get-DomainControllerEvidence `
        -DomainName ([string]$computer.Domain) `
        -DomainJoined ([string]$join.domainJoined)
    $kfm = Get-KfmEvidence

    $configuredRecoveryName = $null
    if ($safety.present -and $safety.values) {
        $configuredRecoveryName = [string](Get-OptionalPropertyValue -InputObject $safety.values -Name 'RecoveryAccountName')
    }
    if ([string]::IsNullOrWhiteSpace($configuredRecoveryName) -and $config) {
        $safetyConfig = Get-OptionalPropertyValue -InputObject $config -Name 'safety'
        $configuredRecoveryName = [string](Get-OptionalPropertyValue -InputObject $safetyConfig -Name 'recoveryAccountName')
    }

    $recovery = Get-RecoveryAccountEvidence -ConfiguredName $configuredRecoveryName
    $bitLocker = Get-BitLockerEvidence
    $tasks = @(Get-MigrationTaskEvidence)
    $residue = Get-SensitiveResidueEvidence
    $sourcePackages = @(Get-SourceProvisioningPackageEvidence -ConfigFilePath $resolvedConfigPath)
    $manifest = Get-ManifestEvidence -Path $RequestedManifestPath

    $oldSid = $null
    $newSid = $null
    if ($safety.present -and $safety.values) {
        $oldSid = [string](Get-OptionalPropertyValue -InputObject $safety.values -Name 'OldSid')
        $newSid = [string](Get-OptionalPropertyValue -InputObject $safety.values -Name 'ExpectedNewSid')
    }
    if ([string]::IsNullOrWhiteSpace($oldSid)) {
        $oldSid = [string]$interactive.sid
    }

    $expectedProfiles = [pscustomobject][ordered]@{
        old = Get-ProfileEvidenceBySid -Sid $oldSid
        new = Get-ProfileEvidenceBySid -Sid $newSid
    }

    $prtEvidence = Get-UserPrtEvidence -ExpectedSid $newSid

    $graph = Get-GraphEvidence `
        -Config $config `
        -Safety $safety `
        -InteractiveUser $interactive `
        -DsReg $join `
        -MdmCertificates $mdmCertificates `
        -GraphSkipped $GraphSkipped

    $context = [pscustomobject][ordered]@{
        execution = [pscustomobject][ordered]@{
            identity = $execution.identity
            sid = $execution.sid
            isSystem = $execution.isSystem
            isAdministrator = $execution.isAdministrator
            powershellEdition = [string]$PSVersionTable.PSEdition
            powershellVersion = [string]$PSVersionTable.PSVersion
        }
        manualAssertions = [pscustomobject][ordered]@{
            recoveryCredentialValidated = $RecoveryCredentialValidated
            fullDeviceRecoveryValidated = $FullDeviceRecoveryValidated
            assertionUtc = [DateTime]::UtcNow.ToString('o')
        }
        system = [pscustomobject][ordered]@{
            computerName = [string]$env:COMPUTERNAME
            manufacturer = [string]$computer.Manufacturer
            model = [string]$computer.Model
            windowsCaption = [string]$os.Caption
            windowsVersion = [string]$os.Version
            windowsBuild = [string]$os.BuildNumber
            lastBootUtc = if ($os.LastBootUpTime) {
                ([DateTime]$os.LastBootUpTime).ToUniversalTime().ToString('o')
            }
            else {
                $null
            }
            capturedUtc = [DateTime]::UtcNow.ToString('o')
        }
        join = $join
        interactiveUser = $interactive
        expectedProfiles = $expectedProfiles
        intuneLocal = [pscustomobject][ordered]@{
            mdmCertificates = $mdmCertificates
            enrollmentIds = $enrollmentIds
        }
        backup = $kfm
        pendingReboot = $pendingReboot
        timeSync = $timeSync
        domainController = $domainController
        recovery = $recovery
        bitLocker = $bitLocker
        migrationSafety = $safety
        userPrtEvidence = $prtEvidence
        tasks = $tasks
        sensitiveResidue = $residue
        sourceArtifacts = [pscustomobject][ordered]@{
            config = $configEvidence
            provisioningPackages = $sourcePackages
            manifest = $manifest
        }
        graph = $graph
    }

    if ($SnapshotPhase -eq 'Before') {
        Add-BeforeChecks -Context $context
    }
    else {
        Add-AfterChecks -Context $context
    }

    $migrationState = $null
    if ($safety.present -and $safety.values) {
        $migrationState = [string](Get-OptionalPropertyValue -InputObject $safety.values -Name 'State')
    }

    $overall = Get-OverallStatus -Checks @($script:Checks) -MigrationState $migrationState

    return [pscustomobject][ordered]@{
        '$schema' = $script:SnapshotSchemaUri
        schemaVersion = $script:SchemaVersion
        harnessVersion = $script:HarnessVersion
        phase = $SnapshotPhase
        capturedUtc = [DateTime]::UtcNow.ToString('o')
        overallStatus = $overall
        checks = @($script:Checks)
        evidence = $context
        security = [pscustomobject][ordered]@{
            reusableSecretsExported = $false
            accessTokensExported = $false
            bitLockerRecoveryPasswordsExported = $false
        }
    }
}

function Add-ComparisonCheck {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Id,

        [Parameter(Mandatory)]
        [ValidateSet('PASS', 'WARN', 'FAIL', 'INFO')]
        [string]$Status,

        [Parameter(Mandatory)]
        [string]$Message,

        [Parameter()]
        [AllowNull()]
        [string]$Evidence
    )

    Add-ValidationCheck -Id $Id -Status $Status -Message $Message -Evidence $Evidence
}

function New-ValidationComparison {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$BeforePath,

        [Parameter(Mandatory)]
        [string]$AfterPath
    )

    $script:Checks.Clear()

    if (-not (Test-Path -LiteralPath $BeforePath -PathType Leaf)) {
        throw "Before snapshot not found: $BeforePath"
    }
    if (-not (Test-Path -LiteralPath $AfterPath -PathType Leaf)) {
        throw "After snapshot not found: $AfterPath"
    }

    $before = Get-Content -LiteralPath $BeforePath -Raw -ErrorAction Stop |
        ConvertFrom-Json -ErrorAction Stop
    $after = Get-Content -LiteralPath $AfterPath -Raw -ErrorAction Stop |
        ConvertFrom-Json -ErrorAction Stop

    if ([string]$before.schemaVersion -ne $script:SchemaVersion) {
        throw "Unsupported Before snapshot schemaVersion '$($before.schemaVersion)'."
    }
    if ([string]$after.schemaVersion -ne $script:SchemaVersion) {
        throw "Unsupported After snapshot schemaVersion '$($after.schemaVersion)'."
    }
    if ([string]$before.phase -ne 'Before') {
        throw "BeforeSnapshotPath does not contain a Before snapshot."
    }
    if ([string]$after.phase -ne 'After') {
        throw "AfterSnapshotPath does not contain an After snapshot."
    }

    $beforeComputer = [string]$before.evidence.system.computerName
    $afterComputer = [string]$after.evidence.system.computerName

    if ($beforeComputer -eq $afterComputer) {
        Add-ComparisonCheck -Id 'compare.sameComputer' -Status PASS -Message 'Before and After snapshots identify the same computer name.' -Evidence $beforeComputer
    }
    else {
        Add-ComparisonCheck -Id 'compare.sameComputer' -Status FAIL -Message 'Before and After snapshots identify different computer names.' -Evidence "$beforeComputer -> $afterComputer"
    }

    $beforeProfile = [string]$before.evidence.interactiveUser.profilePath
    $afterSafety = $after.evidence.migrationSafety.values
    $afterExpectedProfile = [string](Get-OptionalPropertyValue -InputObject $afterSafety -Name 'ExpectedProfilePath')

    if (
        -not [string]::IsNullOrWhiteSpace($beforeProfile) -and
        -not [string]::IsNullOrWhiteSpace($afterExpectedProfile) -and
        $beforeProfile.TrimEnd('\') -ieq $afterExpectedProfile.TrimEnd('\')
    ) {
        Add-ComparisonCheck -Id 'compare.profilePathPreserved' -Status PASS -Message 'Original profile path is preserved across the migration.' -Evidence $beforeProfile
    }
    else {
        Add-ComparisonCheck -Id 'compare.profilePathPreserved' -Status FAIL -Message 'Profile path preservation could not be proven.' -Evidence "$beforeProfile -> $afterExpectedProfile"
    }

    $beforeSid = [string]$before.evidence.interactiveUser.sid
    $afterOldSid = [string](Get-OptionalPropertyValue -InputObject $afterSafety -Name 'OldSid')
    $afterNewSid = [string](Get-OptionalPropertyValue -InputObject $afterSafety -Name 'ExpectedNewSid')

    if (-not [string]::IsNullOrWhiteSpace($beforeSid) -and $beforeSid -eq $afterOldSid) {
        Add-ComparisonCheck -Id 'compare.oldSidContinuity' -Status PASS -Message 'Pre-migration interactive SID matches the recorded old SID.' -Evidence $beforeSid
    }
    else {
        Add-ComparisonCheck -Id 'compare.oldSidContinuity' -Status FAIL -Message 'Pre-migration SID does not match migration OldSid evidence.' -Evidence "$beforeSid / $afterOldSid"
    }

    if (
        -not [string]::IsNullOrWhiteSpace($afterNewSid) -and
        $after.evidence.expectedProfiles.new.present -eq $true -and
        $after.evidence.expectedProfiles.old.present -eq $false
    ) {
        Add-ComparisonCheck -Id 'compare.profileOwnershipTransition' -Status PASS -Message 'Profile ownership transitioned from the old AD SID to the expected Entra SID.' -Evidence "$afterOldSid -> $afterNewSid"
    }
    else {
        Add-ComparisonCheck -Id 'compare.profileOwnershipTransition' -Status FAIL -Message 'Expected profile-ownership transition was not proven.' -Evidence "$afterOldSid -> $afterNewSid"
    }

    $beforeDeviceId = [string]$before.evidence.join.deviceId
    $afterDeviceId = [string]$after.evidence.join.deviceId
    Add-ComparisonCheck `
        -Id 'compare.entraDeviceIdLifecycle' `
        -Status INFO `
        -Message 'Observed Entra DeviceId lifecycle is recorded for same-tenant behavior characterization.' `
        -Evidence "$beforeDeviceId -> $afterDeviceId"

    $beforeManagedId = $null
    $beforeCertificates = @(
        $before.evidence.intuneLocal.mdmCertificates |
            Where-Object { $_.isCertificate -eq $true }
    )
    if ($beforeCertificates.Count -eq 1) {
        $beforeManagedId = Get-ManagedDeviceIdFromCertificateSubject `
            -Subject ([string]$beforeCertificates[0].subject)
    }

    $afterManagedId = $null
    $afterCertificates = @(
        $after.evidence.intuneLocal.mdmCertificates |
            Where-Object { $_.isCertificate -eq $true }
    )
    if ($afterCertificates.Count -eq 1) {
        $afterManagedId = Get-ManagedDeviceIdFromCertificateSubject `
            -Subject ([string]$afterCertificates[0].subject)
    }

    Add-ComparisonCheck `
        -Id 'compare.managedDeviceLifecycle' `
        -Status INFO `
        -Message 'Observed Intune managedDevice identifier lifecycle is recorded for same-tenant behavior characterization.' `
        -Evidence "$beforeManagedId -> $afterManagedId"

    $afterExpectedManagementName = [string](Get-OptionalPropertyValue -InputObject $afterSafety -Name 'ExpectedIntuneManagementName')
    $afterManagedRecord = @(
        $after.evidence.graph.managedDevices |
            Where-Object {
                $_.found -eq $true -and
                ([string]$_.id -ieq [string]$afterManagedId)
            }
    ) | Select-Object -First 1

    $observedAfterManagementName = if ($afterManagedRecord) {
        [string]$afterManagedRecord.managedDeviceName
    }
    else {
        $null
    }

    if (
        $afterManagedRecord -and
        -not [string]::IsNullOrWhiteSpace($afterExpectedManagementName) -and
        $observedAfterManagementName -ieq $afterExpectedManagementName
    ) {
        Add-ComparisonCheck -Id 'compare.intuneManagementName' -Status PASS -Message 'After snapshot observes the expected Intune administrative management name.' -Evidence $afterExpectedManagementName
    }
    else {
        Add-ComparisonCheck -Id 'compare.intuneManagementName' -Status WARN -Message 'Expected Intune administrative management name was not independently observed in the After snapshot.' -Evidence "Expected=$afterExpectedManagementName; Observed=$observedAfterManagementName"
    }

    if ([string]$before.overallStatus -eq 'PASS') {
        Add-ComparisonCheck -Id 'compare.beforeStatus' -Status PASS -Message 'Before snapshot independently reports PASS.' -Evidence $before.capturedUtc
    }
    elseif ([string]$before.overallStatus -eq 'PASS WITH WARNINGS') {
        Add-ComparisonCheck -Id 'compare.beforeStatus' -Status WARN -Message 'Before snapshot passed with warnings; review them as part of the lab evidence.' -Evidence $before.capturedUtc
    }
    else {
        Add-ComparisonCheck -Id 'compare.beforeStatus' -Status FAIL -Message "Before snapshot status was '$($before.overallStatus)'." -Evidence $before.capturedUtc
    }

    if ([string]$after.overallStatus -eq 'PASS') {
        Add-ComparisonCheck -Id 'compare.afterStatus' -Status PASS -Message 'After snapshot independently reports PASS.' -Evidence $after.capturedUtc
    }
    elseif ([string]$after.overallStatus -eq 'PASS WITH WARNINGS') {
        Add-ComparisonCheck -Id 'compare.afterStatus' -Status WARN -Message 'After snapshot passed with warnings.' -Evidence $after.capturedUtc
    }
    elseif ([string]$after.overallStatus -eq 'PENDING') {
        Add-ComparisonCheck -Id 'compare.afterStatus' -Status WARN -Message 'After snapshot remains pending.' -Evidence $after.capturedUtc
    }
    else {
        Add-ComparisonCheck -Id 'compare.afterStatus' -Status FAIL -Message "After snapshot status is '$($after.overallStatus)'." -Evidence $after.capturedUtc
    }

    $overall = Get-OverallStatus -Checks @($script:Checks) -MigrationState $null
    if ([string]$after.overallStatus -eq 'RECOVERY REQUIRED') {
        $overall = 'RECOVERY REQUIRED'
    }
    elseif ([string]$after.overallStatus -eq 'PENDING' -and $overall -ne 'FAIL') {
        $overall = 'PENDING'
    }

    return [pscustomobject][ordered]@{
        '$schema' = $script:ComparisonSchemaUri
        schemaVersion = $script:SchemaVersion
        harnessVersion = $script:HarnessVersion
        phase = 'Compare'
        capturedUtc = [DateTime]::UtcNow.ToString('o')
        overallStatus = $overall
        checks = @($script:Checks)
        inputs = [pscustomobject][ordered]@{
            beforePath = [IO.Path]::GetFullPath($BeforePath)
            beforeSha256 = Get-Sha256 -Path $BeforePath
            afterPath = [IO.Path]::GetFullPath($AfterPath)
            afterSha256 = Get-Sha256 -Path $AfterPath
        }
        transition = [pscustomobject][ordered]@{
            computerName = $beforeComputer
            profilePath = [pscustomobject][ordered]@{
                before = $beforeProfile
                afterExpected = $afterExpectedProfile
                preserved = (
                    -not [string]::IsNullOrWhiteSpace($beforeProfile) -and
                    -not [string]::IsNullOrWhiteSpace($afterExpectedProfile) -and
                    $beforeProfile.TrimEnd('\') -ieq $afterExpectedProfile.TrimEnd('\')
                )
            }
            sid = [pscustomobject][ordered]@{
                before = $beforeSid
                recordedOld = $afterOldSid
                expectedNew = $afterNewSid
            }
            entraDeviceId = [pscustomobject][ordered]@{
                before = $beforeDeviceId
                after = $afterDeviceId
                reused = (
                    -not [string]::IsNullOrWhiteSpace($beforeDeviceId) -and
                    $beforeDeviceId -eq $afterDeviceId
                )
            }
            managedDeviceId = [pscustomobject][ordered]@{
                before = $beforeManagedId
                after = $afterManagedId
                reused = (
                    -not [string]::IsNullOrWhiteSpace($beforeManagedId) -and
                    $beforeManagedId -eq $afterManagedId
                )
            }
            afterMigrationState = [string](Get-OptionalPropertyValue -InputObject $afterSafety -Name 'State')
        }
        security = [pscustomobject][ordered]@{
            reusableSecretsExported = $false
            accessTokensExported = $false
            bitLockerRecoveryPasswordsExported = $false
        }
    }
}

try {
    if ($PSCmdlet.ParameterSetName -eq 'Compare') {
        $result = New-ValidationComparison `
            -BeforePath $BeforeSnapshotPath `
            -AfterPath $AfterSnapshotPath

        if ([string]::IsNullOrWhiteSpace($ComparisonOutputPath)) {
            $comparisonDirectory = Split-Path -Path ([IO.Path]::GetFullPath($AfterSnapshotPath)) -Parent
            $stamp = [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssZ')
            $ComparisonOutputPath = Join-Path `
                -Path $comparisonDirectory `
                -ChildPath "validation-comparison-$stamp.json"
        }

        Write-ValidationJson -Object $result -Path $ComparisonOutputPath
        Write-ConsoleSummary -Result $result -Path $ComparisonOutputPath

        if ($result.overallStatus -eq 'FAIL' -or $result.overallStatus -eq 'RECOVERY REQUIRED') {
            exit 1
        }

        exit 0
    }

    $snapshot = New-ValidationSnapshot `
        -SnapshotPhase $Phase `
        -RequestedConfigPath $ConfigPath `
        -RequestedManifestPath $ManifestPath `
        -GraphSkipped ([bool]$SkipGraph) `
        -RecoveryCredentialValidated ([bool]$RecoveryCredentialManuallyValidated) `
        -FullDeviceRecoveryValidated ([bool]$FullDeviceRecoveryManuallyValidated)

    if ([string]::IsNullOrWhiteSpace($OutputPath)) {
        if (-not (Test-Path -LiteralPath $OutputDirectory -PathType Container)) {
            New-Item -Path $OutputDirectory -ItemType Directory -Force -ErrorAction Stop | Out-Null
        }

        $stamp = [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssZ')
        $OutputPath = Join-Path `
            -Path $OutputDirectory `
            -ChildPath ("validation-{0}-{1}.json" -f $Phase.ToLowerInvariant(), $stamp)
    }

    Write-ValidationJson -Object $snapshot -Path $OutputPath
    Write-ConsoleSummary -Result $snapshot -Path $OutputPath

    switch ([string]$snapshot.overallStatus) {
        'FAIL' { exit 1 }
        'RECOVERY REQUIRED' { exit 2 }
        'PENDING' { exit 3 }
        default { exit 0 }
    }
}
catch {
    Write-Error "Validation harness failed: $($_.Exception.Message)"
    exit 10
}
