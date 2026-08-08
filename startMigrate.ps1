<#
.SYNOPSIS
    Safety-first same-tenant Hybrid Entra Joined -> Microsoft Entra Joined
    migration commit controller.

.DESCRIPTION
    This is a full replacement for the upstream startMigrate.ps1.

    It runs only after preflight.ps1 has written a successful safety record.
    The controller deliberately narrows the supported migration path to:

        Microsoft Entra hybrid joined + Intune managed
            ->
        Microsoft Entra joined + Intune managed
        in the SAME Microsoft Entra tenant.

    The controller consumes the user, profile, tenant, and package identities
    resolved by preflight. It does NOT ask the interactive user to authenticate
    to Azure/Graph and does NOT install Az.Accounts or RunAsUser.

    The controller performs these phases:

      1. Revalidate preflight evidence and source state.
      2. Copy the full migration payload to the protected ProgramData staging
         directory and verify the staged provisioning-package hash.
      3. Persist OLD_* and NEW_* compatibility values expected by reboot.ps1
         and postMigrate.ps1.
      4. Register only the first-boot SYSTEM verification task. The
         post-migration logon task remains unarmed until reboot.ps1 verifies
         successful profile reassociation.
      5. Cross the irreversible boundary only after all prior checks succeed.
      6. Request AD-domain unjoin using the LocalSystem caller context, without
         changing DNS and without embedding domain credentials.
      7. Leave the existing Hybrid Entra device registration.
      8. Remove only LOCAL Intune enrollment artifacts needed to permit the new
         enrollment. Server-side Intune and Autopilot objects are retained.
      9. Apply the pinned provisioning package using Install-ProvisioningPackage.
     10. Write the Intune detection marker only after provisioning succeeds.
     11. Request the first reboot. reboot.ps1 performs the separately hardened
         and verified Win32_UserProfile.ChangeOwner transition.

    IMPORTANT
    This remains an unsupported migration technique. Safety checks are designed
    to fail closed and preserve a local recovery path; they do not turn this
    workflow into a Microsoft-supported conversion method.

    Post-migration verification is delegated to the hardened postMigrate.ps1
    finalizer and its secret-free user-context PRT probe. Server-side stale-object
    cleanup, group-tag mutation, and Autopilot lifecycle changes remain deferred
    to later atomic commits after lab evidence confirms same-tenant behavior.

    Derived conceptually from:
      stevecapacity/intune-device-migration-8 (GPLv3)
      upstream main and selected review of branch 8.1

    Branch 8.1 was reviewed for this phase. Its interactive Az.Accounts /
    RunAsUser target-user discovery and Public Documents config copy are
    intentionally NOT carried forward because deterministic same-tenant
    identity resolution now occurs in preflight.ps1.

.OWNER
    Steve Weiner (upstream project)
.MODIFICATIONS
    Safety-first NG fork, 2026-08-07.
#>

[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:ControllerRevision = '2026.08.07.3'
$script:IrreversibleBoundaryCrossed = $false
$script:TranscriptStarted = $false
$script:RegisteredTaskNames = @()
$script:DetectionMarkerName = 'IntuneDetectionRule.txt'

$configPath = Join-Path -Path $PSScriptRoot -ChildPath 'config.json'
$commonPath = Join-Path -Path $PSScriptRoot -ChildPath 'Migration.Common.ps1'

if (-not (Test-Path -LiteralPath $commonPath)) {
    Write-Error "Required helper file is missing: $commonPath"
    exit 1
}

. $commonPath

function Write-ControllerLog {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('INFO','OK','WARN','ERROR')]
        [string]$Level,

        [Parameter(Mandatory)]
        [string]$Message
    )

    Write-MigrationLog -Level $Level -Message "[COMMIT] $Message"
}

function Stop-ControllerTranscript {
    [CmdletBinding()]
    param()

    if ($script:TranscriptStarted) {
        try {
            Stop-Transcript | Out-Null
        }
        catch {
            # Transcript cleanup must not hide the original failure.
        }

        $script:TranscriptStarted = $false
    }
}

function Set-NormalInteractiveLogon {
    [CmdletBinding()]
    param()

    $winlogonPath = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
    if (-not (Test-Path -LiteralPath $winlogonPath)) {
        New-Item -Path $winlogonPath -Force -ErrorAction Stop | Out-Null
    }

    New-ItemProperty `
        -Path $winlogonPath `
        -Name 'AutoAdminLogon' `
        -Value '0' `
        -PropertyType String `
        -Force `
        -ErrorAction Stop | Out-Null

    foreach ($name in @('DefaultPassword','DefaultUserName','DefaultDomainName')) {
        Remove-ItemProperty `
            -Path $winlogonPath `
            -Name $name `
            -Force `
            -ErrorAction SilentlyContinue
    }

    $passwordProvider = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\{60b78e88-ead8-445c-9cfd-0b87f74ea6cd}'
    if (-not (Test-Path -LiteralPath $passwordProvider)) {
        New-Item -Path $passwordProvider -Force -ErrorAction Stop | Out-Null
    }

    New-ItemProperty `
        -Path $passwordProvider `
        -Name 'Disabled' `
        -Value 0 `
        -PropertyType DWord `
        -Force `
        -ErrorAction Stop | Out-Null
}

function Set-MigrationLoginNotice {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Caption,

        [Parameter(Mandatory)]
        [string]$Text
    )

    $path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
    if (-not (Test-Path -LiteralPath $path)) {
        New-Item -Path $path -Force -ErrorAction Stop | Out-Null
    }

    New-ItemProperty -Path $path -Name 'legalnoticecaption' -Value $Caption -PropertyType String -Force -ErrorAction Stop | Out-Null
    New-ItemProperty -Path $path -Name 'legalnoticetext' -Value $Text -PropertyType String -Force -ErrorAction Stop | Out-Null
}

function Disable-MigrationTasksBestEffort {
    [CmdletBinding()]
    param()

    foreach ($taskName in @('Reboot','postMigrate')) {
        try {
            $task = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
            if ($task) {
                Disable-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue | Out-Null
            }
        }
        catch {
            # Best-effort recovery action only.
        }
    }
}

function Remove-StagedMigrationTasksBestEffort {
    [CmdletBinding()]
    param()

    foreach ($taskName in @($script:RegisteredTaskNames)) {
        try {
            Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
        }
        catch {
            # Best-effort cleanup before the irreversible boundary.
        }
    }
}

function Stop-MigrationCommit {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Message
    )

    Write-ControllerLog ERROR $Message

    try {
        Set-NormalInteractiveLogon
    }
    catch {
        Write-ControllerLog ERROR "Unable to fully restore the normal Windows sign-in surface: $($_.Exception.Message)"
    }

    if ($script:IrreversibleBoundaryCrossed) {
        Disable-MigrationTasksBestEffort

        try {
            Set-MigrationLoginNotice `
                -Caption 'Device migration recovery required' `
                -Text 'The migration stopped after an identity-changing operation began. Do not reboot unless instructed by the administrator. Use the approved local recovery administrator account if sign-in recovery is required.'
        }
        catch {
            Write-ControllerLog ERROR "Unable to set the recovery notice: $($_.Exception.Message)"
        }

        try {
            Set-MigrationSafetyState -Values @{
                State = 'RecoveryRequired'
                CommitStep = 'FailedAfterIrreversibleBoundary'
                RecoveryRequiredUtc = [DateTime]::UtcNow.ToString('o')
                LastError = $Message
            }
        }
        catch {
            Write-ControllerLog ERROR "Unable to persist RecoveryRequired state: $($_.Exception.Message)"
        }
    }
    else {
        Remove-StagedMigrationTasksBestEffort

        try {
            Set-MigrationSafetyState -Values @{
                State = 'CommitAborted'
                CommitStep = 'FailedBeforeIrreversibleBoundary'
                CommitAbortedUtc = [DateTime]::UtcNow.ToString('o')
                LastError = $Message
            }
        }
        catch {
            Write-ControllerLog ERROR "Unable to persist CommitAborted state: $($_.Exception.Message)"
        }
    }

    Stop-ControllerTranscript
    exit 1
}

function Assert-SystemContext {
    [CmdletBinding()]
    param()

    $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    if (-not $identity.IsSystem) {
        throw "Migration commit controller must run as LocalSystem. Current identity: '$($identity.Name)'."
    }

    Write-ControllerLog OK 'Execution context is LocalSystem.'
}

function Get-SafetyStateRequired {
    [CmdletBinding()]
    param()

    $state = Get-MigrationSafetyState
    if ($null -eq $state) {
        throw 'Migration safety state is missing. Run through install.ps1/preflight.ps1.'
    }

    if ([string](Get-OptionalPropertyValue -InputObject $state -Name 'State') -ne 'PreflightPassed') {
        throw "Migration Safety\State must be PreflightPassed before commit. Observed '$([string](Get-OptionalPropertyValue -InputObject $state -Name 'State'))'."
    }

    foreach ($name in @(
        'PreflightUtc',
        'ConfigSha256',
        'ExpectedTenantId',
        'OldSid',
        'ExpectedNewSid',
        'ExpectedUserObjectId',
        'ExpectedUserPrincipalName',
        'ExpectedProfilePath',
        'RecoveryAccountName',
        'PpkgSha256'
    )) {
        $value = [string](Get-OptionalPropertyValue -InputObject $state -Name $name)
        if ([string]::IsNullOrWhiteSpace($value)) {
            throw "Migration safety state is missing required value '$name'."
        }
    }

    return $state
}

function Assert-PreflightFreshness {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        $SafetyState,

        [Parameter(Mandatory)]
        $Config
    )

    $safetyConfig = Get-OptionalPropertyValue -InputObject $Config -Name 'safety'
    $maxAgeValue = Get-OptionalPropertyValue -InputObject $safetyConfig -Name 'maxPreflightAgeMinutes' -Default 60

    try {
        $maxAgeMinutes = [int]$maxAgeValue
    }
    catch {
        throw "config safety.maxPreflightAgeMinutes must be an integer. Observed '$maxAgeValue'."
    }

    if ($maxAgeMinutes -lt 5 -or $maxAgeMinutes -gt 1440) {
        throw 'config safety.maxPreflightAgeMinutes must be between 5 and 1440.'
    }

    try {
        $preflightUtc = [DateTime]::Parse(
            [string]$SafetyState.PreflightUtc,
            [Globalization.CultureInfo]::InvariantCulture,
            [Globalization.DateTimeStyles]::RoundtripKind
        ).ToUniversalTime()
    }
    catch {
        throw "Unable to parse preflight timestamp '$($SafetyState.PreflightUtc)'."
    }

    $age = [DateTime]::UtcNow - $preflightUtc
    if ($age.TotalMinutes -gt $maxAgeMinutes) {
        throw ('Preflight is stale ({0:N1} minutes old; maximum {1}). Run preflight again.' -f $age.TotalMinutes, $maxAgeMinutes)
    }

    if ($age.TotalMinutes -lt -5) {
        throw 'Preflight timestamp is unexpectedly in the future; verify system clock synchronization.'
    }

    Write-ControllerLog OK ('Preflight freshness verified: {0:N1} minutes old.' -f [math]::Max(0, $age.TotalMinutes))
}

function Assert-RegistryLayout {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        $Config
    )

    $configured = [string]$Config.regPath
    $normalized = $configured.Replace('/', '\').TrimEnd('\').Replace('HKLM:\', 'HKLM\')

    if ($normalized -ine 'HKLM\SOFTWARE\IntuneMigration') {
        throw "This NG fork revision requires regPath 'HKLM\SOFTWARE\IntuneMigration' because reboot.ps1 consumes the same fixed state root. Observed '$configured'."
    }
}

function Set-MigrationRegistryValue {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Name,

        [Parameter()]
        [AllowNull()]
        $Value
    )

    if (-not (Test-Path -LiteralPath $script:MigrationRegistryRoot)) {
        New-Item -Path $script:MigrationRegistryRoot -Force -ErrorAction Stop | Out-Null
    }

    if ($null -eq $Value -or [string]::IsNullOrWhiteSpace([string]$Value)) {
        Remove-ItemProperty `
            -Path $script:MigrationRegistryRoot `
            -Name $Name `
            -Force `
            -ErrorAction SilentlyContinue
        return
    }

    New-ItemProperty `
        -Path $script:MigrationRegistryRoot `
        -Name $Name `
        -Value ([string]$Value) `
        -PropertyType String `
        -Force `
        -ErrorAction Stop | Out-Null
}

function Set-ProtectedDirectoryAcl {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )

    & "$env:SystemRoot\System32\icacls.exe" `
        $Path `
        '/inheritance:r' `
        '/grant:r' `
        '*S-1-5-18:(OI)(CI)F' `
        '*S-1-5-32-544:(OI)(CI)F' `
        '/T' `
        '/C' | Out-Null

    if ($LASTEXITCODE -ne 0) {
        throw "icacls failed while restricting '$Path' (exit code $LASTEXITCODE)."
    }
}

function Copy-MigrationPayload {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$SourcePath,

        [Parameter(Mandatory)]
        [string]$DestinationPath
    )

    if (-not (Test-Path -LiteralPath $DestinationPath)) {
        New-Item -Path $DestinationPath -ItemType Directory -Force -ErrorAction Stop | Out-Null
    }

    $sourceFull = [IO.Path]::GetFullPath($SourcePath).TrimEnd('\')
    $destinationFull = [IO.Path]::GetFullPath($DestinationPath).TrimEnd('\')

    if ($sourceFull -ine $destinationFull) {
        foreach ($item in @(Get-ChildItem -LiteralPath $SourcePath -Force -ErrorAction Stop)) {
            Copy-Item `
                -LiteralPath $item.FullName `
                -Destination $DestinationPath `
                -Recurse `
                -Force `
                -ErrorAction Stop
        }
    }
    else {
        Write-ControllerLog WARN 'Package source and ProgramData staging directory are the same path; payload copy skipped.'
    }

    Set-ProtectedDirectoryAcl -Path $DestinationPath
}

function Assert-RequiredPayloadFiles {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Root
    )

    $required = @(
        'config.json',
        'Migration.Common.ps1',
        'startMigrate.ps1',
        'reboot.ps1',
        'reboot.xml',
        'postMigrate.ps1',
        'postMigrateUser.ps1',
        'postMigrate.xml'
    )

    foreach ($name in $required) {
        $path = Join-Path -Path $Root -ChildPath $name
        if (-not (Test-Path -LiteralPath $path)) {
            throw "Required migration payload file is missing after staging: '$name'."
        }
    }
}

function Get-IntuneEnrollmentRegistryIds {
    [CmdletBinding()]
    param()

    $root = 'HKLM:\SOFTWARE\Microsoft\Enrollments'
    if (-not (Test-Path -LiteralPath $root)) {
        return @()
    }

    $ids = New-Object System.Collections.Generic.List[string]

    foreach ($key in @(Get-ChildItem -LiteralPath $root -ErrorAction Stop)) {
        try {
            $properties = Get-ItemProperty -LiteralPath $key.PSPath -ErrorAction Stop
            $urlProperty = $properties.PSObject.Properties['DiscoveryServiceFullURL']
            if (-not $urlProperty) {
                continue
            }

            $url = [string]$urlProperty.Value
            if ($url -match '(?i)manage\.microsoft\.com') {
                [void]$ids.Add($key.PSChildName)
            }
        }
        catch {
            # Enrollment root contains non-enrollment keys; skip those.
        }
    }

    return @($ids | Sort-Object -Unique)
}

function Get-OldAutopilotRegistrationId {
    [CmdletBinding()]
    param()

    $path = 'HKLM:\SOFTWARE\Microsoft\Provisioning\Diagnostics\Autopilot\EstablishedCorrelations'
    if (-not (Test-Path -LiteralPath $path)) {
        return $null
    }

    try {
        return [string](Get-ItemPropertyValue -LiteralPath $path -Name 'ZtdRegistrationId' -ErrorAction Stop)
    }
    catch {
        return $null
    }
}

function Get-ManagedDeviceIdFromMdmCertificate {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        $Certificate
    )

    $subject = [string]$Certificate.Subject
    if ($subject -notmatch '^CN=(.+)$') {
        throw "Intune MDM certificate Subject isn't in expected CN=<managedDeviceId> form: '$subject'."
    }

    $id = $matches[1].Trim()
    if ([string]::IsNullOrWhiteSpace($id)) {
        throw 'Intune MDM certificate CN is empty.'
    }

    return $id
}

function Register-MigrationTaskFromXml {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$TaskName,

        [Parameter(Mandatory)]
        [string]$XmlPath
    )

    if (-not (Test-Path -LiteralPath $XmlPath)) {
        throw "Scheduled-task XML file is missing: '$XmlPath'."
    }

    $xml = Get-Content -LiteralPath $XmlPath -Raw -ErrorAction Stop
    Register-ScheduledTask `
        -TaskName $TaskName `
        -Xml $xml `
        -Force `
        -ErrorAction Stop | Out-Null

    $registered = Get-ScheduledTask -TaskName $TaskName -ErrorAction Stop
    if (-not $registered) {
        throw "Task '$TaskName' wasn't observable after registration."
    }

    if ($TaskName -notin $script:RegisteredTaskNames) {
        $script:RegisteredTaskNames += $TaskName
    }

    Write-ControllerLog OK "Scheduled task '$TaskName' registered."
}

function Remove-LocalIntuneEnrollment {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$EnrollmentId,

        [Parameter(Mandatory)]
        [array]$MdmCertificates
    )

    Write-ControllerLog WARN "Removing local Intune enrollment '$EnrollmentId'. Server-side Intune and Autopilot objects are intentionally retained."

    $taskPath = "\Microsoft\Windows\EnterpriseMgmt\$EnrollmentId\"
    foreach ($task in @(Get-ScheduledTask -TaskPath $taskPath -ErrorAction SilentlyContinue)) {
        try {
            Unregister-ScheduledTask `
                -TaskName $task.TaskName `
                -TaskPath $task.TaskPath `
                -Confirm:$false `
                -ErrorAction Stop
            Write-ControllerLog INFO "Removed old EnterpriseMgmt task '$($task.TaskPath)$($task.TaskName)'."
        }
        catch {
            throw "Failed to remove EnterpriseMgmt task '$($task.TaskPath)$($task.TaskName)': $($_.Exception.Message)"
        }
    }

    $paths = @(
        "HKLM:\SOFTWARE\Microsoft\EnterpriseResourceManager\Tracked\$EnrollmentId",
        "HKLM:\SOFTWARE\Microsoft\PolicyManager\AdmxInstalled\$EnrollmentId",
        "HKLM:\SOFTWARE\Microsoft\PolicyManager\Providers\$EnrollmentId",
        "HKLM:\SOFTWARE\Microsoft\Provisioning\OMADM\Accounts\$EnrollmentId",
        "HKLM:\SOFTWARE\Microsoft\Provisioning\OMADM\Logger\$EnrollmentId",
        "HKLM:\SOFTWARE\Microsoft\Provisioning\OMADM\Sessions\$EnrollmentId",
        "HKLM:\SOFTWARE\Microsoft\Enrollments\Status\$EnrollmentId",
        "HKLM:\SOFTWARE\Microsoft\Enrollments\$EnrollmentId"
    )

    foreach ($path in $paths) {
        if (Test-Path -LiteralPath $path) {
            Remove-Item -LiteralPath $path -Recurse -Force -ErrorAction Stop
            Write-ControllerLog INFO "Removed local enrollment registry path '$path'."
        }
    }

    foreach ($certificate in @($MdmCertificates)) {
        Remove-Item -LiteralPath $certificate.PSPath -Force -ErrorAction Stop
        Write-ControllerLog INFO "Removed old Intune MDM certificate thumbprint '$($certificate.Thumbprint)'."
    }

    if (Test-Path -LiteralPath "HKLM:\SOFTWARE\Microsoft\Enrollments\$EnrollmentId") {
        throw "Local Intune enrollment registry key '$EnrollmentId' remains after cleanup."
    }

    $remainingCertificates = @(Get-IntuneMdmCertificate)
    if ($remainingCertificates.Count -gt 0) {
        throw "One or more Microsoft Intune MDM Device CA certificates remain after cleanup."
    }

    Write-ControllerLog OK 'Local Intune enrollment artifacts required for re-enrollment have been removed.'
}

function Request-DomainUnjoin {
    [CmdletBinding()]
    param()

    $computerSystem = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
    if (-not [bool]$computerSystem.PartOfDomain) {
        throw 'The device no longer reports PartOfDomain=True immediately before the domain-unjoin request.'
    }

    # Microsoft documents that when UserName is NULL the caller context is used.
    # LocalSystem is intentionally used here so no reusable domain or local
    # account password is embedded in the migration package.
    $result = $computerSystem | Invoke-CimMethod `
        -MethodName 'UnjoinDomainOrWorkgroup' `
        -Arguments @{
            FUnjoinOptions = [uint32]0
            UserName = $null
            Password = $null
        } `
        -ErrorAction Stop

    if ($null -eq $result -or [uint32]$result.ReturnValue -ne 0) {
        $returnValue = if ($result) { [string]$result.ReturnValue } else { '<null>' }
        throw "Win32_ComputerSystem.UnjoinDomainOrWorkgroup returned '$returnValue' instead of 0."
    }

    Write-ControllerLog OK 'AD-domain unjoin request returned success. The change is finalized by reboot.'
}

function Leave-CurrentEntraRegistration {
    [CmdletBinding()]
    param()

    $process = Start-Process `
        -FilePath "$env:SystemRoot\System32\dsregcmd.exe" `
        -ArgumentList '/leave' `
        -Wait `
        -PassThru `
        -WindowStyle Hidden `
        -ErrorAction Stop

    if ($process.ExitCode -ne 0) {
        throw "dsregcmd /leave returned exit code $($process.ExitCode)."
    }

    $left = $false
    for ($attempt = 1; $attempt -le 10; $attempt++) {
        Start-Sleep -Seconds 2
        $state = Get-DsRegState
        if ($state.AzureAdJoined -eq 'NO') {
            $left = $true
            break
        }
    }

    if (-not $left) {
        throw 'AzureAdJoined did not become NO after dsregcmd /leave verification retries.'
    }

    Write-ControllerLog OK 'Existing Hybrid Entra device registration left successfully.'
}

function Install-PinnedProvisioningPackage {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$PackagePath,

        [Parameter(Mandatory)]
        [string]$ExpectedSha256,

        [Parameter(Mandatory)]
        [string]$LogDirectory
    )

    $actualHash = (Get-FileHash -LiteralPath $PackagePath -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
    if ($actualHash -ne $ExpectedSha256.ToLowerInvariant()) {
        throw "Staged provisioning-package SHA-256 '$actualHash' doesn't match preflight hash '$ExpectedSha256'."
    }

    if (-not (Get-Command Install-ProvisioningPackage -ErrorAction SilentlyContinue)) {
        Import-Module Provisioning -ErrorAction Stop
    }

    if (-not (Get-Command Install-ProvisioningPackage -ErrorAction SilentlyContinue)) {
        throw "Install-ProvisioningPackage is not available on this Windows installation."
    }

    if (-not (Test-Path -LiteralPath $LogDirectory)) {
        New-Item -Path $LogDirectory -ItemType Directory -Force -ErrorAction Stop | Out-Null
    }

    Write-ControllerLog WARN "Applying provisioning package '$PackagePath'."

    $result = Install-ProvisioningPackage `
        -PackagePath $PackagePath `
        -QuietInstall `
        -ForceInstall `
        -LogsDirectoryPath $LogDirectory `
        -ErrorAction Stop

    if ($null -ne $result) {
        Write-ControllerLog INFO "Provisioning cmdlet returned: $([string]$result)"
    }

    Write-ControllerLog OK 'Provisioning package application completed without a PowerShell error.'
}

function Write-CompatibilityState {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        $SafetyState,

        [Parameter(Mandatory)]
        $DsRegState,

        [Parameter(Mandatory)]
        $InteractiveUser,

        [Parameter(Mandatory)]
        [string]$ManagedDeviceId,

        [Parameter(Mandatory)]
        [string]$LocalDomain,

        [Parameter()]
        [AllowNull()]
        [string]$OldAutopilotId
    )

    $expectedUpn = [string]$SafetyState.ExpectedUserPrincipalName
    $expectedUserId = [string]$SafetyState.ExpectedUserObjectId
    $expectedNewSid = [string]$SafetyState.ExpectedNewSid
    $newSamName = $expectedUpn.Split('@')[0]

    if ([string]::IsNullOrWhiteSpace($newSamName)) {
        throw "Unable to derive NEW_SAMName from expected UPN '$expectedUpn'."
    }

    $values = [ordered]@{
        OLD_hostname = $env:COMPUTERNAME
        OLD_intuneId = $ManagedDeviceId
        OLD_azureAdId = [string]$DsRegState.DeviceId
        OLD_localDomain = $LocalDomain
        OLD_autopilotId = $OldAutopilotId
        OLD_domainJoined = 'YES'
        OLD_azureAdJoined = 'YES'
        OLD_mdm = 'True'

        OLD_userName = [string]$InteractiveUser.UserName
        OLD_UPN = $expectedUpn
        OLD_entraUserID = $expectedUserId
        OLD_profilePath = [string]$InteractiveUser.ProfilePath
        OLD_SAMName = [string]$InteractiveUser.SamName
        OLD_SID = [string]$InteractiveUser.Sid

        NEW_entraUserID = $expectedUserId
        NEW_SID = $expectedNewSid
        NEW_SAMName = $newSamName
        NEW_UPN = $expectedUpn
    }

    foreach ($entry in $values.GetEnumerator()) {
        Set-MigrationRegistryValue -Name $entry.Key -Value $entry.Value
    }

    # Read back the values consumed by the separately hardened reboot.ps1.
    foreach ($name in @('OLD_SID','OLD_profilePath','NEW_SID','NEW_SAMName','NEW_UPN','NEW_entraUserID')) {
        $readBack = Get-MigrationRegistryString -Name $name -Required
        $expected = [string]$values[$name]
        if ($readBack -ne $expected) {
            throw "Migration registry read-back mismatch for '$name'. Expected '$expected'; observed '$readBack'."
        }
    }

    Write-ControllerLog OK 'OLD_* and NEW_* compatibility state written and verified.'
}

function Write-DetectionMarker {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$LocalPath
    )

    $path = Join-Path -Path $LocalPath -ChildPath $script:DetectionMarkerName
    @(
        "ControllerRevision=$($script:ControllerRevision)"
        "State=ProvisioningApplied"
        "TimestampUtc=$([DateTime]::UtcNow.ToString('o'))"
    ) | Set-Content -LiteralPath $path -Encoding ASCII -Force -ErrorAction Stop

    Set-RestrictedFileAcl -Path $path
    Write-ControllerLog OK "Intune detection marker written only after provisioning success: '$path'."
}

try {
    $config = Get-MigrationConfig -Path $configPath
    Assert-RegistryLayout -Config $config

    $logDirectory = [string]$config.logPath
    if ([string]::IsNullOrWhiteSpace($logDirectory)) {
        throw 'config logPath is empty.'
    }

    if (-not (Test-Path -LiteralPath $logDirectory)) {
        New-Item -Path $logDirectory -ItemType Directory -Force -ErrorAction Stop | Out-Null
    }

    $transcriptPath = Join-Path -Path $logDirectory -ChildPath 'startMigrate.log'
    Start-Transcript -Path $transcriptPath -Append -ErrorAction Stop | Out-Null
    $script:TranscriptStarted = $true

    Write-ControllerLog INFO "Starting NG same-tenant migration commit controller revision $($script:ControllerRevision)."

    Assert-SystemContext
    Set-NormalInteractiveLogon

    $safetyState = Get-SafetyStateRequired
    Assert-PreflightFreshness -SafetyState $safetyState -Config $config

    $currentConfigHash = Get-ConfigFileSha256 -Path $configPath
    if ($currentConfigHash -ne ([string]$safetyState.ConfigSha256).ToLowerInvariant()) {
        throw "config.json changed after preflight. Expected SHA-256 '$($safetyState.ConfigSha256)'; observed '$currentConfigHash'."
    }
    Write-ControllerLog OK 'config.json SHA-256 still matches preflight evidence.'

    $dsreg = Get-DsRegState
    if ($dsreg.AzureAdJoined -ne 'YES' -or $dsreg.DomainJoined -ne 'YES') {
        throw "Source join state changed after preflight. Expected AzureAdJoined=YES and DomainJoined=YES; observed AzureAdJoined=$($dsreg.AzureAdJoined), DomainJoined=$($dsreg.DomainJoined)."
    }

    if ([string]$dsreg.TenantId -ne [string]$safetyState.ExpectedTenantId) {
        throw "Current device TenantId '$($dsreg.TenantId)' doesn't match preflight tenant '$($safetyState.ExpectedTenantId)'."
    }

    $interactiveUser = Get-InteractiveUserIdentity
    if ([string]$interactiveUser.Sid -ne [string]$safetyState.OldSid) {
        throw "Interactive user's SID changed after preflight. Expected '$($safetyState.OldSid)'; observed '$($interactiveUser.Sid)'."
    }

    if (([string]$interactiveUser.ProfilePath).TrimEnd('\') -ine ([string]$safetyState.ExpectedProfilePath).TrimEnd('\')) {
        throw "Interactive user's profile path changed after preflight."
    }

    if (-not $interactiveUser.ProfileLoaded) {
        throw 'The intended source profile is no longer loaded.'
    }

    $recoveryAccount = Get-RecoveryLocalAccount -Config $config
    if ([string]$recoveryAccount.Name -ine [string]$safetyState.RecoveryAccountName) {
        throw "Recovery account changed after preflight. Expected '$($safetyState.RecoveryAccountName)'; observed '$($recoveryAccount.Name)'."
    }
    Write-ControllerLog OK "Recovery account '$($recoveryAccount.Name)' revalidated."

    $requireKfm = Get-SafetyBoolean -Config $config -Name 'requireOneDriveKfmReady' -Default $true
    if ($requireKfm) {
        $kfm = Get-OneDriveKfmReadiness
        if (-not $kfm.Ready) {
            throw "OneDrive KFM safety gate is no longer ready. Status='$($kfm.Status)', KfmState='$($kfm.KfmState)'."
        }
        Write-ControllerLog OK 'OneDrive KFM readiness revalidated.'
    }

    $allowPendingReboot = Get-SafetyBoolean -Config $config -Name 'allowPendingReboot' -Default $false
    if ((Test-PendingReboot) -and -not $allowPendingReboot) {
        throw 'A pending reboot appeared after preflight. Commit refused.'
    }

    $sccmEnabled = [bool](Get-OptionalPropertyValue -InputObject $config -Name 'SCCM' -Default $false)
    if ($sccmEnabled) {
        throw 'config SCCM=true is not supported by this NG same-tenant commit controller revision. Remove Configuration Manager/co-management in a separately reviewed operation before migration.'
    }

    $mdmCertificates = @(Get-IntuneMdmCertificate)
    if ($mdmCertificates.Count -ne 1) {
        throw "Exactly one Microsoft Intune MDM Device CA certificate is required at commit. Observed $($mdmCertificates.Count)."
    }

    $managedDeviceId = Get-ManagedDeviceIdFromMdmCertificate -Certificate $mdmCertificates[0]
    $enrollmentIds = @(Get-IntuneEnrollmentRegistryIds)
    if ($enrollmentIds.Count -ne 1) {
        throw "Exactly one local Intune enrollment registry ID is required at commit. Observed $($enrollmentIds.Count): $($enrollmentIds -join ', ')."
    }

    $localDomain = [string](Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop).Domain
    if ([string]::IsNullOrWhiteSpace($localDomain)) {
        throw 'Unable to determine the current AD domain.'
    }

    $sourcePpkg = Get-SingleProvisioningPackage -SearchRoot $PSScriptRoot
    $sourcePpkgHash = (Get-FileHash -LiteralPath $sourcePpkg.FullName -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
    if ($sourcePpkgHash -ne ([string]$safetyState.PpkgSha256).ToLowerInvariant()) {
        throw "Provisioning package changed after preflight. Expected '$($safetyState.PpkgSha256)'; observed '$sourcePpkgHash'."
    }

    $localPath = [string]$config.localPath
    if ([string]::IsNullOrWhiteSpace($localPath)) {
        $localPath = $script:MigrationLocalPathDefault
    }

    Write-ControllerLog INFO "Staging migration payload to '$localPath'."
    Copy-MigrationPayload -SourcePath $PSScriptRoot -DestinationPath $localPath
    Assert-RequiredPayloadFiles -Root $localPath

    $stagedConfigPath = Join-Path -Path $localPath -ChildPath 'config.json'
    $stagedConfigHash = Get-ConfigFileSha256 -Path $stagedConfigPath
    if ($stagedConfigHash -ne $currentConfigHash) {
        throw 'Staged config.json hash differs from the preflight-validated package config.'
    }

    $stagedPpkg = Get-SingleProvisioningPackage -SearchRoot $localPath
    $stagedPpkgHash = (Get-FileHash -LiteralPath $stagedPpkg.FullName -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
    if ($stagedPpkgHash -ne $sourcePpkgHash) {
        throw 'Staged provisioning-package hash differs from the preflight-validated package.'
    }

    Write-ControllerLog OK "Payload staged and protected. PPKG SHA-256=$stagedPpkgHash."

    Write-CompatibilityState `
        -SafetyState $safetyState `
        -DsRegState $dsreg `
        -InteractiveUser $interactiveUser `
        -ManagedDeviceId $managedDeviceId `
        -LocalDomain $localDomain `
        -OldAutopilotId (Get-OldAutopilotRegistrationId)

    # A stale postMigrate task from an earlier/upstream attempt must not be able
    # to run during the first boot. The post-migration task is armed only by
    # reboot.ps1 after profile reassociation succeeds and is verified.
    $stalePostMigrate = Get-ScheduledTask -TaskName 'postMigrate' -ErrorAction SilentlyContinue
    if ($stalePostMigrate) {
        Unregister-ScheduledTask -TaskName 'postMigrate' -Confirm:$false -ErrorAction Stop
        Write-ControllerLog WARN 'Removed a pre-existing postMigrate task before the commit boundary.'
    }

    Register-MigrationTaskFromXml `
        -TaskName 'Reboot' `
        -XmlPath (Join-Path -Path $localPath -ChildPath 'reboot.xml')

    Set-MigrationSafetyState -Values @{
        State = 'CommitStarted'
        CommitStep = 'ReadyForIrreversibleBoundary'
        CommitStartedUtc = [DateTime]::UtcNow.ToString('o')
        ControllerRevision = $script:ControllerRevision
        OldManagedDeviceId = $managedDeviceId
        OldMdmEnrollmentId = $enrollmentIds[0]
        OldDeviceId = [string]$dsreg.DeviceId
    }

    Write-ControllerLog WARN 'All reversible staging checks passed. Crossing the irreversible migration boundary now.'
    $script:IrreversibleBoundaryCrossed = $true

    Set-MigrationSafetyState -Values @{
        State = 'CommitStarted'
        CommitStep = 'DomainUnjoinRequested'
    }
    Request-DomainUnjoin

    Set-MigrationSafetyState -Values @{
        State = 'CommitStarted'
        CommitStep = 'LeavingHybridEntraRegistration'
    }
    Leave-CurrentEntraRegistration

    Set-MigrationSafetyState -Values @{
        State = 'CommitStarted'
        CommitStep = 'RemovingLocalMdmEnrollment'
    }
    Remove-LocalIntuneEnrollment `
        -EnrollmentId $enrollmentIds[0] `
        -MdmCertificates $mdmCertificates

    Set-MigrationSafetyState -Values @{
        State = 'CommitStarted'
        CommitStep = 'ApplyingProvisioningPackage'
    }

    $provisioningLogs = Join-Path -Path $localPath -ChildPath 'ProvisioningLogs'
    Install-PinnedProvisioningPackage `
        -PackagePath $stagedPpkg.FullName `
        -ExpectedSha256 $stagedPpkgHash `
        -LogDirectory $provisioningLogs

    Set-MigrationSafetyState -Values @{
        State = 'CommitStarted'
        CommitStep = 'ProvisioningApplied'
        ProvisioningAppliedUtc = [DateTime]::UtcNow.ToString('o')
    }

    # A runtime bulk-Entra provisioning package may not expose the final join
    # state synchronously. Log current state, but leave authoritative verification
    # to the hardened boot-phase reboot.ps1 after Windows restarts.
    try {
        $postProvisionState = Get-DsRegState
        Write-ControllerLog INFO "Immediate post-provision state: AzureAdJoined=$($postProvisionState.AzureAdJoined), DomainJoined=$($postProvisionState.DomainJoined), TenantId=$($postProvisionState.TenantId)."
    }
    catch {
        Write-ControllerLog WARN "Unable to query immediate post-provision dsregcmd state: $($_.Exception.Message)"
    }

    Write-DetectionMarker -LocalPath $localPath

    Set-MigrationLoginNotice `
        -Caption 'Device migration in progress' `
        -Text 'The device is completing its Microsoft Entra migration. Do not sign in during the first restart. The system will restart again automatically when profile reassociation has been verified.'

    Set-MigrationSafetyState -Values @{
        State = 'CommitStarted'
        CommitStep = 'RebootRequested'
        RebootRequestedUtc = [DateTime]::UtcNow.ToString('o')
        LastError = ''
    }

    Write-ControllerLog OK 'Commit controller completed its phase successfully. Requesting first reboot in 15 seconds.'

    Stop-ControllerTranscript

    & "$env:SystemRoot\System32\shutdown.exe" /r /t 15 /c "Microsoft Entra migration commit phase completed."
    if ($LASTEXITCODE -ne 0) {
        throw "shutdown.exe returned exit code $LASTEXITCODE."
    }

    exit 0
}
catch {
    Stop-MigrationCommit -Message "Unhandled commit-controller error: $($_.Exception.Message)"
}
