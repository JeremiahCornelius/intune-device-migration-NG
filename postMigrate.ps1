<#
.SYNOPSIS
    Safety-first post-migration verification and finalization controller.

.DESCRIPTION
    Runs as LocalSystem after profile reassociation and an interactive Entra
    sign-in.

    Completion is evidence-gated. Before Safety\State can become Complete, this
    finalizer requires:
      - ProfileReassociated state from the hardened reboot phase;
      - the expected Entra SID still owns the original profile;
      - the old AD SID no longer enumerates as a Win32_UserProfile;
      - user-context AzureAdPrt=YES evidence from postMigrateUser.ps1;
      - AzureAdJoined=YES, DomainJoined=NO, and the preflight TenantId;
      - exactly one enabled Entra device matching the current dsreg DeviceId;
      - a post-commit Intune MDM certificate;
      - a Graph managedDevice matching that certificate and current DeviceId;
      - a post-commit Intune lastSyncDateTime;
      - acceptance of the deterministic primary-user assignment;
      - successful configured BitLocker finalization;
      - preservation of the original physical Windows hostname.

    After the core migration is verified, the finalizer best-effort labels the
    verified Intune managedDevice with <original-hostname>.<configured-suffix>.
    Failure of that administrative label is recorded as a warning and does not
    convert an otherwise healthy migration into RecoveryRequired.

    This atomic phase deliberately does NOT:
      - delete the old server-side Intune managedDevice;
      - delete the old Entra device object;
      - create, delete, or import Windows Autopilot records;
      - mutate device physicalIds or group tags;
      - execute groupTag.ps1.

    Old/new identifiers are retained in Safety state for a later server-side
    lifecycle commit after same-tenant behavior is validated in the lab.

    Transient PRT/network/Graph/Intune propagation failures become
    PostMigrationPending and leave the logon tasks available for retry.
    Identity/profile/tenant invariant failures become RecoveryRequired and
    disable finalization tasks.

    A successful BackupToAAD-BitLockerKeyProtector call is recorded as an
    escrow request. This script does not claim independent cloud read-back,
    because the current endpoint application is not granted BitLocker recovery
    key read permissions.

.NOTES
    Derived from stevecapacity/intune-device-migration-8 (GPLv3).
    NG safety-first revision: 2026.08.08.1
#>

[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:LocalPath = 'C:\ProgramData\IntuneMigration'
$script:ConfigPath = Join-Path -Path $script:LocalPath -ChildPath 'config.json'
$script:CommonPath = Join-Path -Path $script:LocalPath -ChildPath 'Migration.Common.ps1'
$script:UserProbeRoot = 'C:\ProgramData\IntuneMigrationUserProbe'
$script:UserProbeTaskName = 'postMigrateUserVerify'
$script:TranscriptStarted = $false

if (-not (Test-Path -LiteralPath $script:CommonPath -PathType Leaf)) {
    Write-Error "Required helper file is missing: $($script:CommonPath)"
    exit 1
}

. $script:CommonPath

function Write-PostMigrationLog {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('INFO','OK','WARN','ERROR')]
        [string]$Level,

        [Parameter(Mandatory)]
        [string]$Message
    )

    Write-MigrationLog -Level $Level -Message "[POST] $Message"
}

function Stop-PostMigrationTranscript {
    [CmdletBinding()]
    param()

    if ($script:TranscriptStarted) {
        try {
            Stop-Transcript | Out-Null
        }
        catch {
            # Transcript cleanup must not replace the primary finalizer result.
        }

        $script:TranscriptStarted = $false
    }
}

function Test-SystemContext {
    [CmdletBinding()]
    param()

    return [System.Security.Principal.WindowsIdentity]::GetCurrent().IsSystem
}

function Disable-FinalizationTasksBestEffort {
    [CmdletBinding()]
    param()

    foreach ($taskName in @('postMigrate',$script:UserProbeTaskName)) {
        try {
            $task = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
            if ($task) {
                Disable-ScheduledTask `
                    -TaskName $taskName `
                    -ErrorAction SilentlyContinue | Out-Null
            }
        }
        catch {
            # Recovery safeguard only.
        }
    }
}

function Remove-FinalizationTasksBestEffort {
    [CmdletBinding()]
    param()

    foreach ($taskName in @('Reboot','postMigrate',$script:UserProbeTaskName,'GroupTag')) {
        try {
            $task = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
            if ($task) {
                Unregister-ScheduledTask `
                    -TaskName $taskName `
                    -Confirm:$false `
                    -ErrorAction SilentlyContinue
            }
        }
        catch {
            Write-PostMigrationLog WARN "Unable to remove scheduled task '$taskName': $($_.Exception.Message)"
        }
    }
}

function Set-NormalLoginSurface {
    [CmdletBinding()]
    param()

    $policyPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
    if (-not (Test-Path -LiteralPath $policyPath)) {
        New-Item -Path $policyPath -Force -ErrorAction Stop | Out-Null
    }

    New-ItemProperty `
        -Path $policyPath `
        -Name 'DontDisplayLastUserName' `
        -Value 0 `
        -PropertyType DWord `
        -Force `
        -ErrorAction Stop | Out-Null

    foreach ($name in @('legalnoticecaption','legalnoticetext')) {
        Remove-ItemProperty `
            -Path $policyPath `
            -Name $name `
            -Force `
            -ErrorAction SilentlyContinue
    }
}

function Set-RecoveryNotice {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Message
    )

    $policyPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
    if (-not (Test-Path -LiteralPath $policyPath)) {
        New-Item -Path $policyPath -Force -ErrorAction Stop | Out-Null
    }

    New-ItemProperty `
        -Path $policyPath `
        -Name 'legalnoticecaption' `
        -Value 'Device migration recovery required' `
        -PropertyType String `
        -Force `
        -ErrorAction Stop | Out-Null

    New-ItemProperty `
        -Path $policyPath `
        -Name 'legalnoticetext' `
        -Value $Message `
        -PropertyType String `
        -Force `
        -ErrorAction Stop | Out-Null
}

function Stop-WithRecoveryRequired {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Message
    )

    Write-PostMigrationLog ERROR $Message

    try {
        Set-MigrationSafetyState -Values @{
            State = 'RecoveryRequired'
            RecoveryRequiredUtc = [DateTime]::UtcNow.ToString('o')
            LastError = $Message
        }
    }
    catch {
        Write-PostMigrationLog ERROR "Unable to persist RecoveryRequired state: $($_.Exception.Message)"
    }

    Disable-FinalizationTasksBestEffort

    try {
        Set-RecoveryNotice `
            -Message 'Post-migration verification found an identity, profile, or tenant invariant mismatch. Use the approved local recovery administrator account and review the migration logs before making further changes.'
    }
    catch {
        Write-PostMigrationLog ERROR "Unable to set recovery notice: $($_.Exception.Message)"
    }

    Stop-PostMigrationTranscript
    exit 1
}

function Stop-WithPendingVerification {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Message
    )

    Write-PostMigrationLog WARN $Message

    try {
        Set-MigrationSafetyState -Values @{
            State = 'PostMigrationPending'
            PostMigrationPendingUtc = [DateTime]::UtcNow.ToString('o')
            LastError = $Message
        }
    }
    catch {
        Write-PostMigrationLog ERROR "Unable to persist PostMigrationPending state: $($_.Exception.Message)"
    }

    # Tasks remain enabled. A later expected-user logon can retry after PRT,
    # network, Graph, or Intune eventual-consistency conditions recover.
    Stop-PostMigrationTranscript
    exit 2
}

function ConvertTo-UtcDateTime {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Value,

        [Parameter(Mandatory)]
        [string]$Name
    )

    try {
        return [DateTime]::Parse(
            $Value,
            [Globalization.CultureInfo]::InvariantCulture,
            [Globalization.DateTimeStyles]::RoundtripKind
        ).ToUniversalTime()
    }
    catch {
        throw "Unable to parse '$Name' timestamp '$Value'."
    }
}

function Get-RequiredSafetyString {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        $SafetyState,

        [Parameter(Mandatory)]
        [string]$Name
    )

    $value = [string](Get-OptionalPropertyValue -InputObject $SafetyState -Name $Name)
    if ([string]::IsNullOrWhiteSpace($value)) {
        throw "Migration safety state is missing required value '$Name'."
    }

    return $value
}

function Get-UserVerificationEvidence {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$ExpectedSid,

        [Parameter(Mandatory)]
        [string]$ExpectedUpn,

        [Parameter(Mandatory)]
        [string]$ExpectedProfilePath,

        [Parameter(Mandatory)]
        [DateTime]$ProfileReassociatedUtc
    )

    $evidencePath = "Registry::HKEY_USERS\$ExpectedSid\Software\IntuneMigration\PostMigrationUserVerification"

    # postMigrate.xml delays SYSTEM finalization by one minute. Continue polling
    # for up to three more minutes so the user probe can finish PRT acquisition.
    for ($attempt = 1; $attempt -le 18; $attempt++) {
        $task = Get-ScheduledTask `
            -TaskName $script:UserProbeTaskName `
            -ErrorAction SilentlyContinue

        $taskInfo = Get-ScheduledTaskInfo `
            -TaskName $script:UserProbeTaskName `
            -ErrorAction SilentlyContinue

        if ($task -and $taskInfo -and (Test-Path -LiteralPath $evidencePath)) {
            $evidence = Get-ItemProperty -LiteralPath $evidencePath -ErrorAction Stop
            $state = [string](Get-OptionalPropertyValue -InputObject $evidence -Name 'State')
            $verifiedUtcText = [string](Get-OptionalPropertyValue -InputObject $evidence -Name 'VerifiedUtc')
            $sid = [string](Get-OptionalPropertyValue -InputObject $evidence -Name 'Sid')
            $upn = [string](Get-OptionalPropertyValue -InputObject $evidence -Name 'ExpectedUpn')
            $profilePath = [string](Get-OptionalPropertyValue -InputObject $evidence -Name 'UserProfile')
            $prt = [string](Get-OptionalPropertyValue -InputObject $evidence -Name 'AzureAdPrt')

            if (
                $state -eq 'Verified' -and
                $taskInfo.LastTaskResult -eq 0 -and
                -not [string]::IsNullOrWhiteSpace($verifiedUtcText)
            ) {
                $verifiedUtc = ConvertTo-UtcDateTime `
                    -Value $verifiedUtcText `
                    -Name 'VerifiedUtc'

                $taskRunUtc = $taskInfo.LastRunTime.ToUniversalTime()

                if ($sid -ne $ExpectedSid) {
                    throw "User-context evidence SID '$sid' does not match expected SID '$ExpectedSid'."
                }

                if ($upn -ne $ExpectedUpn) {
                    throw "User-context evidence UPN '$upn' does not match expected UPN '$ExpectedUpn'."
                }

                if ($profilePath.TrimEnd('\') -ine $ExpectedProfilePath.TrimEnd('\')) {
                    throw 'User-context evidence profile path does not match the preserved profile.'
                }

                if ($prt -ne 'YES') {
                    throw "User-context evidence unexpectedly reports AzureAdPrt='$prt'."
                }

                if ($verifiedUtc -lt $ProfileReassociatedUtc.AddMinutes(-1)) {
                    throw 'User-context PRT evidence predates profile reassociation.'
                }

                if ($taskRunUtc -lt $ProfileReassociatedUtc.AddMinutes(-1)) {
                    throw 'User-context verification task result predates profile reassociation.'
                }

                return $evidence
            }
        }

        if ($attempt -lt 18) {
            Start-Sleep -Seconds 10
        }
    }

    return $null
}

function Get-EntraDeviceByDeviceId {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$DeviceId,

        [Parameter(Mandatory)]
        [hashtable]$Headers
    )

    $filterText = "deviceId eq '$DeviceId'"
    $filter = [Uri]::EscapeDataString($filterText)
    $select = 'id,deviceId,displayName,accountEnabled,trustType,profileType'
    $uri = "https://graph.microsoft.com/v1.0/devices?`$filter=$filter&`$select=$select"

    $response = Invoke-RestMethod `
        -Method GET `
        -Uri $uri `
        -Headers $Headers `
        -ErrorAction Stop

    $devices = @($response.value)
    if ($devices.Count -ne 1) {
        throw "Expected exactly one Entra device for DeviceId '$DeviceId'; observed $($devices.Count)."
    }

    $device = $devices[0]

    if ([string]$device.deviceId -ne $DeviceId) {
        throw 'Microsoft Graph returned an Entra device whose deviceId does not exactly match dsregcmd.'
    }

    if ($device.accountEnabled -ne $true) {
        throw "Current Entra device object '$($device.id)' is disabled."
    }

    return $device
}

function Get-ManagedDeviceIdFromMdmCertificate {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        $Certificate
    )

    $subject = [string]$Certificate.Subject

    if ($subject -notmatch '(?i)^CN=([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?:,|$)') {
        return $null
    }

    return $matches[1].ToLowerInvariant()
}

function Wait-ForVerifiedIntuneEnrollment {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Headers,

        [Parameter(Mandatory)]
        [string]$CurrentEntraDeviceId,

        [Parameter(Mandatory)]
        [DateTime]$CommitStartedUtc
    )

    $lastReason = 'No post-commit Intune enrollment candidate was observed.'

    # Intune enrollment and Microsoft Graph propagation are asynchronous.
    # Poll for up to ten minutes before leaving the finalizer Pending.
    for ($attempt = 1; $attempt -le 30; $attempt++) {
        $certificates = @(
            Get-IntuneMdmCertificate |
                Where-Object {
                    $_.NotAfter.ToUniversalTime() -gt [DateTime]::UtcNow -and
                    $_.NotBefore.ToUniversalTime() -ge $CommitStartedUtc.AddMinutes(-5)
                } |
                Sort-Object NotBefore -Descending
        )

        foreach ($certificate in $certificates) {
            $managedDeviceId = Get-ManagedDeviceIdFromMdmCertificate -Certificate $certificate

            if ([string]::IsNullOrWhiteSpace($managedDeviceId)) {
                $lastReason = "Intune MDM certificate Subject '$($certificate.Subject)' did not contain an expected managed-device GUID."
                continue
            }

            try {
                $uri = "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices/$managedDeviceId?`$select=id,deviceName,managedDeviceName,managementAgent,enrolledDateTime,lastSyncDateTime,operatingSystem,azureADDeviceId,serialNumber"

                $managedDevice = Invoke-RestMethod `
                    -Method GET `
                    -Uri $uri `
                    -Headers $Headers `
                    -ErrorAction Stop

                if ([string]$managedDevice.id -ne $managedDeviceId) {
                    $lastReason = "Graph managedDevice.id did not match MDM certificate ID '$managedDeviceId'."
                    continue
                }

                if ([string]$managedDevice.azureADDeviceId -ne $CurrentEntraDeviceId) {
                    $lastReason = "managedDevice.azureADDeviceId '$($managedDevice.azureADDeviceId)' does not yet match current Entra DeviceId '$CurrentEntraDeviceId'."
                    continue
                }

                if ([string]$managedDevice.operatingSystem -notmatch '(?i)^Windows$') {
                    $lastReason = "managedDevice operatingSystem is '$($managedDevice.operatingSystem)', not Windows."
                    continue
                }

                if ([string]$managedDevice.managementAgent -notmatch '(?i)mdm') {
                    $lastReason = "managedDevice managementAgent '$($managedDevice.managementAgent)' does not indicate MDM management."
                    continue
                }

                $lastSyncText = [string]$managedDevice.lastSyncDateTime
                if ([string]::IsNullOrWhiteSpace($lastSyncText)) {
                    $lastReason = 'managedDevice lastSyncDateTime is empty.'
                    continue
                }

                $lastSyncUtc = ConvertTo-UtcDateTime `
                    -Value $lastSyncText `
                    -Name 'lastSyncDateTime'

                if ($lastSyncUtc -lt $CommitStartedUtc.AddMinutes(-5)) {
                    $lastReason = "managedDevice lastSyncDateTime '$lastSyncText' predates the migration commit."
                    continue
                }

                return [pscustomobject]@{
                    Certificate = $certificate
                    ManagedDevice = $managedDevice
                    ManagedDeviceId = $managedDeviceId
                    LastSyncUtc = $lastSyncUtc
                }
            }
            catch {
                $lastReason = "Graph managed-device verification is not ready for '$managedDeviceId': $($_.Exception.Message)"
            }
        }

        Write-PostMigrationLog INFO "Intune verification attempt $attempt/30 pending: $lastReason"

        if ($attempt -lt 30) {
            Start-Sleep -Seconds 20
        }
    }

    return [pscustomobject]@{
        Certificate = $null
        ManagedDevice = $null
        ManagedDeviceId = $null
        LastSyncUtc = $null
        LastReason = $lastReason
    }
}

function Set-ExpectedIntunePrimaryUser {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$ManagedDeviceId,

        [Parameter(Mandatory)]
        [string]$UserObjectId,

        [Parameter(Mandatory)]
        [hashtable]$Headers
    )

    $uri = "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices('$ManagedDeviceId')/users/`$ref"

    $body = @{
        '@odata.id' = "https://graph.microsoft.com/v1.0/users/$UserObjectId"
    } | ConvertTo-Json -Compress

    Invoke-RestMethod `
        -Method POST `
        -Uri $uri `
        -Headers $Headers `
        -Body $body `
        -ContentType 'application/json' `
        -ErrorAction Stop | Out-Null
}

function Set-VerifiedIntuneManagementName {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$ManagedDeviceId,

        [Parameter(Mandatory)]
        [string]$CurrentEntraDeviceId,

        [Parameter(Mandatory)]
        [string]$ExpectedComputerName,

        [Parameter(Mandatory)]
        [string]$ExpectedManagementName,

        [Parameter(Mandatory)]
        [hashtable]$Headers
    )

    $requestedUtc = [DateTime]::UtcNow.ToString('o')
    $uri = "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices/$ManagedDeviceId"
    $body = @{
        managedDeviceName = $ExpectedManagementName
    } | ConvertTo-Json -Compress

    Invoke-RestMethod `
        -Method PATCH `
        -Uri $uri `
        -Headers $Headers `
        -Body $body `
        -ContentType 'application/json' `
        -ErrorAction Stop | Out-Null

    # Always perform a fresh read-back.  Do not trust the PATCH response as
    # evidence that Intune persisted the administrative name on the intended
    # managedDevice record.
    $readbackUri = "${uri}?`$select=id,deviceName,managedDeviceName,azureADDeviceId,lastSyncDateTime"
    $observed = Invoke-RestMethod `
        -Method GET `
        -Uri $readbackUri `
        -Headers $Headers `
        -ErrorAction Stop

    if ([string]$observed.id -ne $ManagedDeviceId) {
        throw "Intune management-name read-back returned managedDevice.id '$($observed.id)' instead of '$ManagedDeviceId'."
    }

    if ([string]$observed.azureADDeviceId -ne $CurrentEntraDeviceId) {
        throw "Intune management-name read-back returned azureADDeviceId '$($observed.azureADDeviceId)' instead of current DeviceId '$CurrentEntraDeviceId'."
    }

    if ([string]$observed.managedDeviceName -ine $ExpectedManagementName) {
        throw "Intune managedDeviceName read-back '$($observed.managedDeviceName)' does not exactly match requested '$ExpectedManagementName'."
    }

    return [pscustomobject]@{
        RequestedUtc = $requestedUtc
        VerifiedUtc = [DateTime]::UtcNow.ToString('o')
        ObservedDeviceName = [string]$observed.deviceName
        ObservedManagedDeviceName = [string]$observed.managedDeviceName
        ObservedAzureAdDeviceId = [string]$observed.azureADDeviceId
        PhysicalNameMatchesIntuneDeviceName = ([string]$observed.deviceName -ieq $ExpectedComputerName)
    }
}

function Invoke-BitLockerFinalization {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        $Config
    )

    $mode = [string](Get-OptionalPropertyValue -InputObject $Config -Name 'bitlocker')

    if ([string]::IsNullOrWhiteSpace($mode)) {
        return 'NotConfigured'
    }

    switch ($mode.ToUpperInvariant()) {
        'MIGRATE' {
            $volume = Get-BitLockerVolume `
                -MountPoint $env:SystemDrive `
                -ErrorAction Stop

            $recoveryProtectors = @(
                $volume.KeyProtector |
                    Where-Object { $_.KeyProtectorType -eq 'RecoveryPassword' }
            )

            if ($recoveryProtectors.Count -eq 0) {
                throw "BitLocker MIGRATE is configured but '$env:SystemDrive' has no RecoveryPassword protector."
            }

            foreach ($protector in $recoveryProtectors) {
                BackupToAAD-BitLockerKeyProtector `
                    -MountPoint $env:SystemDrive `
                    -KeyProtectorId ([string]$protector.KeyProtectorId) `
                    -ErrorAction Stop | Out-Null
            }

            return "EscrowRequested:$($recoveryProtectors.Count)"
        }

        'DECRYPT' {
            $allowDecrypt = Get-SafetyBoolean `
                -Config $Config `
                -Name 'allowBitLockerDecrypt' `
                -Default $false

            if (-not $allowDecrypt) {
                throw 'BitLocker DECRYPT requires safety.allowBitLockerDecrypt=true.'
            }

            Disable-BitLocker `
                -MountPoint $env:SystemDrive `
                -ErrorAction Stop | Out-Null

            return 'DecryptionRequested'
        }

        default {
            throw "Unsupported config bitlocker value '$mode'."
        }
    }
}

function Remove-SensitiveStagedMaterialBestEffort {
    [CmdletBinding()]
    param()

    $errors = New-Object System.Collections.Generic.List[string]

    if (Test-Path -LiteralPath $script:ConfigPath) {
        try {
            Remove-Item `
                -LiteralPath $script:ConfigPath `
                -Force `
                -ErrorAction Stop
        }
        catch {
            [void]$errors.Add("config.json: $($_.Exception.Message)")
        }
    }

    try {
        $packages = @(
            Get-ChildItem `
                -LiteralPath $script:LocalPath `
                -Filter '*.ppkg' `
                -File `
                -Recurse `
                -ErrorAction Stop
        )

        foreach ($package in $packages) {
            try {
                Remove-Item `
                    -LiteralPath $package.FullName `
                    -Force `
                    -ErrorAction Stop
            }
            catch {
                [void]$errors.Add("$($package.FullName): $($_.Exception.Message)")
            }
        }
    }
    catch {
        [void]$errors.Add("PPKG enumeration: $($_.Exception.Message)")
    }

    try {
        if (Test-Path -LiteralPath $script:UserProbeRoot) {
            Remove-Item `
                -LiteralPath $script:UserProbeRoot `
                -Recurse `
                -Force `
                -ErrorAction Stop
        }
    }
    catch {
        [void]$errors.Add("User probe staging: $($_.Exception.Message)")
    }

    return @($errors)
}

try {
    if (-not (Test-SystemContext)) {
        Write-Error 'postMigrate.ps1 must run as LocalSystem.'
        exit 1
    }

    $initialSafetyState = Get-MigrationSafetyState
    if ($null -eq $initialSafetyState) {
        Write-Error 'Migration safety state is missing.'
        exit 1
    }

    $initialState = [string](Get-OptionalPropertyValue `
        -InputObject $initialSafetyState `
        -Name 'State')

    if ($initialState -eq 'Complete') {
        Remove-FinalizationTasksBestEffort
        exit 0
    }

    if ($initialState -eq 'RecoveryRequired') {
        exit 1
    }

    if (-not (Test-Path -LiteralPath $script:ConfigPath -PathType Leaf)) {
        Stop-WithRecoveryRequired "Required protected migration configuration is missing: '$($script:ConfigPath)'."
    }

    $config = Get-MigrationConfig -Path $script:ConfigPath

    $logDirectory = [string]$config.logPath
    if ([string]::IsNullOrWhiteSpace($logDirectory)) {
        throw 'config logPath is empty.'
    }

    if (-not (Test-Path -LiteralPath $logDirectory)) {
        New-Item `
            -Path $logDirectory `
            -ItemType Directory `
            -Force `
            -ErrorAction Stop | Out-Null
    }

    Start-Transcript `
        -Path (Join-Path -Path $logDirectory -ChildPath 'postMigrate.log') `
        -Append `
        -ErrorAction Stop | Out-Null

    $script:TranscriptStarted = $true

    Write-PostMigrationLog INFO 'Starting NG verified post-migration finalizer revision 2026.08.08.1.'

    $safetyState = Get-MigrationSafetyState
    $state = [string](Get-OptionalPropertyValue -InputObject $safetyState -Name 'State')

    $allowedStates = @(
        'ProfileReassociated',
        'PostMigrationVerifying',
        'PostMigrationPending',
        'UserPrtVerified',
        'IntuneReenrollmentVerified'
    )

    if ($state -notin $allowedStates) {
        Stop-WithRecoveryRequired "Unexpected Safety\State '$state' at post-migration entry."
    }

    $attemptCount = [int](Get-OptionalPropertyValue `
        -InputObject $safetyState `
        -Name 'PostMigrationAttemptCount' `
        -Default 0)

    $attemptCount++

    Set-MigrationSafetyState -Values @{
        State = 'PostMigrationVerifying'
        PostMigrationAttemptCount = $attemptCount
        PostMigrationAttemptUtc = [DateTime]::UtcNow.ToString('o')
        LastError = ''
    }

    $expectedTenantId = Get-RequiredSafetyString `
        -SafetyState $safetyState `
        -Name 'ExpectedTenantId'

    $expectedNewSid = Get-RequiredSafetyString `
        -SafetyState $safetyState `
        -Name 'ExpectedNewSid'

    $expectedOldSid = Get-RequiredSafetyString `
        -SafetyState $safetyState `
        -Name 'OldSid'

    $expectedUpn = Get-RequiredSafetyString `
        -SafetyState $safetyState `
        -Name 'ExpectedUserPrincipalName'

    $expectedUserObjectId = Get-RequiredSafetyString `
        -SafetyState $safetyState `
        -Name 'ExpectedUserObjectId'

    $expectedProfilePath = Get-RequiredSafetyString `
        -SafetyState $safetyState `
        -Name 'ExpectedProfilePath'

    $expectedComputerName = Get-RequiredSafetyString `
        -SafetyState $safetyState `
        -Name 'ExpectedComputerName'

    $expectedManagementName = Get-RequiredSafetyString `
        -SafetyState $safetyState `
        -Name 'ExpectedIntuneManagementName'

    if ([string]$env:COMPUTERNAME -ine $expectedComputerName) {
        Stop-WithRecoveryRequired "Physical Windows hostname changed during migration. Expected '$expectedComputerName'; observed '$env:COMPUTERNAME'."
    }

    Write-PostMigrationLog OK "Physical Windows hostname preserved as '$env:COMPUTERNAME'."

    $profileReassociatedUtc = ConvertTo-UtcDateTime `
        -Value (Get-RequiredSafetyString -SafetyState $safetyState -Name 'ProfileReassociatedUtc') `
        -Name 'ProfileReassociatedUtc'

    $commitStartedUtc = ConvertTo-UtcDateTime `
        -Value (Get-RequiredSafetyString -SafetyState $safetyState -Name 'CommitStartedUtc') `
        -Name 'CommitStartedUtc'

    if ($expectedNewSid -notmatch '^S-1-12-1-(\d+-){2,}\d+$') {
        Stop-WithRecoveryRequired "ExpectedNewSid '$expectedNewSid' is not an Entra cloud SID."
    }

    $registryNewSid = Get-MigrationRegistryString -Name 'NEW_SID' -Required
    if ($registryNewSid -ne $expectedNewSid) {
        Stop-WithRecoveryRequired "NEW_SID registry handoff '$registryNewSid' does not match preflight SID '$expectedNewSid'."
    }

    $newProfile = Get-CimInstance -ClassName Win32_UserProfile -ErrorAction Stop |
        Where-Object { $_.SID -eq $expectedNewSid } |
        Select-Object -First 1

    if ($null -eq $newProfile) {
        Stop-WithRecoveryRequired "Expected Entra SID '$expectedNewSid' no longer owns a Win32_UserProfile."
    }

    if (([string]$newProfile.LocalPath).TrimEnd('\') -ine $expectedProfilePath.TrimEnd('\')) {
        Stop-WithRecoveryRequired "Expected Entra SID now maps to '$($newProfile.LocalPath)' instead of '$expectedProfilePath'."
    }

    if (-not [bool]$newProfile.Loaded) {
        Stop-WithPendingVerification 'The expected Entra profile is not currently loaded. Finalization will retry on the next expected-user logon.'
    }

    $oldProfile = Get-CimInstance -ClassName Win32_UserProfile -ErrorAction Stop |
        Where-Object { $_.SID -eq $expectedOldSid } |
        Select-Object -First 1

    if ($oldProfile) {
        Stop-WithRecoveryRequired "Old AD SID '$expectedOldSid' unexpectedly enumerates after verified ChangeOwner."
    }

    $dsreg = Get-DsRegState

    if ($dsreg.AzureAdJoined -ne 'YES') {
        Stop-WithRecoveryRequired "AzureAdJoined must be YES; observed '$($dsreg.AzureAdJoined)'."
    }

    if ($dsreg.DomainJoined -ne 'NO') {
        Stop-WithRecoveryRequired "DomainJoined must be NO; observed '$($dsreg.DomainJoined)'."
    }

    if ([string]$dsreg.TenantId -ne $expectedTenantId) {
        Stop-WithRecoveryRequired "Current TenantId '$($dsreg.TenantId)' does not match expected tenant '$expectedTenantId'."
    }

    if ([string]::IsNullOrWhiteSpace([string]$dsreg.DeviceId)) {
        Stop-WithRecoveryRequired 'dsregcmd did not return the current Microsoft Entra DeviceId.'
    }

    try {
        $userEvidence = Get-UserVerificationEvidence `
            -ExpectedSid $expectedNewSid `
            -ExpectedUpn $expectedUpn `
            -ExpectedProfilePath $expectedProfilePath `
            -ProfileReassociatedUtc $profileReassociatedUtc
    }
    catch {
        Stop-WithRecoveryRequired "User-context verification evidence failed an identity/profile freshness invariant: $($_.Exception.Message)"
    }

    if ($null -eq $userEvidence) {
        Stop-WithPendingVerification 'Expected user-context AzureAdPrt=YES evidence is not yet available. Finalization remains armed for a later logon.'
    }

    Write-PostMigrationLog OK "User-context PRT verified for expected SID '$expectedNewSid'."

    Set-MigrationSafetyState -Values @{
        State = 'UserPrtVerified'
        UserPrtVerifiedUtc = [string](Get-OptionalPropertyValue -InputObject $userEvidence -Name 'VerifiedUtc')
        UserPrtAuthority = [string](Get-OptionalPropertyValue -InputObject $userEvidence -Name 'AzureAdPrtAuthority')
        LastError = ''
    }

    $targetTenantConfig = Get-OptionalPropertyValue -InputObject $config -Name 'targetTenant'
    $targetTenantName = [string](Get-OptionalPropertyValue -InputObject $targetTenantConfig -Name 'tenantName')

    try {
        if (-not [string]::IsNullOrWhiteSpace($targetTenantName)) {
            $graphSession = New-GraphAppSession -TenantConfig $targetTenantConfig
        }
        else {
            $graphSession = New-GraphAppSession -TenantConfig $config.sourceTenant
        }
    }
    catch {
        Stop-WithPendingVerification "Graph authentication is not currently available: $($_.Exception.Message)"
    }

    if ([string]$graphSession.TenantId -ne $expectedTenantId) {
        Stop-WithRecoveryRequired "Graph token tenant '$($graphSession.TenantId)' does not match expected tenant '$expectedTenantId'."
    }

    try {
        $entraDevice = Get-EntraDeviceByDeviceId `
            -DeviceId ([string]$dsreg.DeviceId) `
            -Headers $graphSession.Headers
    }
    catch {
        Stop-WithPendingVerification "Current Entra device object is not yet verifiable in Graph: $($_.Exception.Message)"
    }

    Write-PostMigrationLog OK "Current Entra device verified: DeviceId=$($dsreg.DeviceId), ObjectId=$($entraDevice.id)."

    $intuneVerification = Wait-ForVerifiedIntuneEnrollment `
        -Headers $graphSession.Headers `
        -CurrentEntraDeviceId ([string]$dsreg.DeviceId) `
        -CommitStartedUtc $commitStartedUtc

    if ($null -eq $intuneVerification.ManagedDevice) {
        Stop-WithPendingVerification "Intune re-enrollment was not verified within the polling window. $($intuneVerification.LastReason)"
    }

    $newManagedDeviceId = [string]$intuneVerification.ManagedDeviceId
    $oldManagedDeviceId = [string](Get-OptionalPropertyValue `
        -InputObject $safetyState `
        -Name 'OldManagedDeviceId')

    $oldDeviceId = [string](Get-OptionalPropertyValue `
        -InputObject $safetyState `
        -Name 'OldDeviceId')

    Write-PostMigrationLog OK "Verified Intune managed device '$newManagedDeviceId' maps to current Entra DeviceId '$($dsreg.DeviceId)'."

    try {
        Set-ExpectedIntunePrimaryUser `
            -ManagedDeviceId $newManagedDeviceId `
            -UserObjectId $expectedUserObjectId `
            -Headers $graphSession.Headers
    }
    catch {
        Stop-WithPendingVerification "Intune primary-user assignment was not accepted: $($_.Exception.Message)"
    }

    Write-PostMigrationLog OK "Intune primary-user assignment accepted for '$expectedUpn'."

    try {
        $bitLockerAction = Invoke-BitLockerFinalization -Config $config
    }
    catch {
        Stop-WithPendingVerification "BitLocker finalization did not complete: $($_.Exception.Message)"
    }

    Write-PostMigrationLog OK "BitLocker post-migration action: $bitLockerAction."

    $managementNameStatus = 'Warning'
    $managementNameRequestedUtc = [DateTime]::UtcNow.ToString('o')
    $managementNameVerifiedUtc = ''
    $observedIntuneDeviceName = ''
    $observedIntuneManagementName = ''
    $managementNameWarning = ''

    try {
        $managementNameEvidence = Set-VerifiedIntuneManagementName `
            -ManagedDeviceId $newManagedDeviceId `
            -CurrentEntraDeviceId ([string]$dsreg.DeviceId) `
            -ExpectedComputerName $expectedComputerName `
            -ExpectedManagementName $expectedManagementName `
            -Headers $graphSession.Headers

        $managementNameStatus = 'Verified'
        $managementNameRequestedUtc = [string]$managementNameEvidence.RequestedUtc
        $managementNameVerifiedUtc = [string]$managementNameEvidence.VerifiedUtc
        $observedIntuneDeviceName = [string]$managementNameEvidence.ObservedDeviceName
        $observedIntuneManagementName = [string]$managementNameEvidence.ObservedManagedDeviceName

        if (-not [bool]$managementNameEvidence.PhysicalNameMatchesIntuneDeviceName) {
            $managementNameWarning = "Intune deviceName '$observedIntuneDeviceName' does not yet match preserved physical hostname '$expectedComputerName'."
            Write-PostMigrationLog WARN $managementNameWarning
        }

        Write-PostMigrationLog OK "Intune managedDeviceName verified as '$observedIntuneManagementName'."
    }
    catch {
        $managementNameWarning = $_.Exception.Message
        Write-PostMigrationLog WARN "Migration core verification succeeded, but Intune managedDeviceName classification was not verified: $managementNameWarning"
    }

    Set-MigrationSafetyState -Values @{
        State = 'IntuneReenrollmentVerified'
        IntuneReenrollmentVerifiedUtc = [DateTime]::UtcNow.ToString('o')
        NewManagedDeviceId = $newManagedDeviceId
        NewEntraDeviceId = [string]$dsreg.DeviceId
        NewEntraObjectId = [string]$entraDevice.id
        NewMdmCertificateThumbprint = [string]$intuneVerification.Certificate.Thumbprint
        NewMdmCertificateNotBeforeUtc = $intuneVerification.Certificate.NotBefore.ToUniversalTime().ToString('o')
        NewManagedDeviceLastSyncUtc = $intuneVerification.LastSyncUtc.ToString('o')
        ManagedDeviceIdReused = ($newManagedDeviceId -eq $oldManagedDeviceId)
        PrimaryUserAssignmentRequestedUtc = [DateTime]::UtcNow.ToString('o')
        BitLockerFinalization = $bitLockerAction
        ExpectedComputerName = $expectedComputerName
        ExpectedIntuneManagementName = $expectedManagementName
        IntuneManagementNameStatus = $managementNameStatus
        IntuneManagementNameRequestedUtc = $managementNameRequestedUtc
        IntuneManagementNameVerifiedUtc = $managementNameVerifiedUtc
        ObservedIntuneDeviceName = $observedIntuneDeviceName
        ObservedIntuneManagementName = $observedIntuneManagementName
        IntuneManagementNameWarning = $managementNameWarning
        ServerCleanupDeferred = $true
        AutopilotRegistrationDeferred = $true
        GroupTagMutationDeferred = $true
        LastError = ''
    }

    Set-NormalLoginSurface

    Set-MigrationSafetyState -Values @{
        State = 'Complete'
        CompletedUtc = [DateTime]::UtcNow.ToString('o')
        OldManagedDeviceId = $oldManagedDeviceId
        OldDeviceId = $oldDeviceId
        LastError = ''
    }

    Write-PostMigrationLog OK 'Migration finalization verified. Safety\State=Complete.'

    Remove-FinalizationTasksBestEffort
    Stop-PostMigrationTranscript

    $cleanupErrors = @(Remove-SensitiveStagedMaterialBestEffort)

    if ($cleanupErrors.Count -gt 0) {
        Set-MigrationSafetyState -Values @{
            State = 'Complete'
            StagingCleanupStatus = 'Warning'
            StagingCleanupWarning = ($cleanupErrors -join ' | ')
        }
    }
    else {
        Set-MigrationSafetyState -Values @{
            State = 'Complete'
            StagingCleanupStatus = 'SensitiveMaterialRemoved'
        }
    }

    exit 0
}
catch {
    if ($script:TranscriptStarted) {
        Write-PostMigrationLog ERROR "Unhandled post-migration finalizer error: $($_.Exception.Message)"
    }

    try {
        Set-MigrationSafetyState -Values @{
            State = 'PostMigrationPending'
            PostMigrationPendingUtc = [DateTime]::UtcNow.ToString('o')
            LastError = "Unhandled post-migration finalizer error: $($_.Exception.Message)"
        }
    }
    catch {
        # Preserve the original result.
    }

    Stop-PostMigrationTranscript
    exit 2
}
