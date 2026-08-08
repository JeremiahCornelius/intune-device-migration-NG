<#
.SYNOPSIS
    Safety-hardened reboot/profile-owner phase for the Intune device migration
    fork.

.DESCRIPTION
    This replacement keeps the upstream Win32_UserProfile.ChangeOwner technique
    but makes it fail closed.

    Before the original profile can be reassigned, it requires:
      - a successful preflight safety record;
      - AzureAdJoined = YES after provisioning;
      - DomainJoined = NO after domain removal;
      - the joined tenant ID to equal the preflight target tenant;
      - NEW_SID to exactly equal the preflight-resolved Entra cloud SID;
      - OLD_SID and the source profile path to equal preflight evidence;
      - the source profile to be unloaded;
      - any temporary new-owner profile to be unloaded and distinct.

    It incorporates the useful 8.1 idea of waiting for CreateProfile materialization
    but deliberately removes the 8.1 runas.exe fallback.

    On any safety failure:
      - the password credential provider is restored;
      - auto-logon plaintext is removed;
      - the reboot task remains disabled to prevent loops;
      - Safety\State is set to RecoveryRequired;
      - the machine does NOT automatically reboot.

    Derived from stevecapacity/intune-device-migration-8 reboot.ps1 (GPLv3).
    Original authors/contributors retained below.

.OWNER
    Steve Weiner
.CONTRIBUTORS
    Logan Lautt
.MODIFICATIONS
    Safety-first fork, 2026-08-07.
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$configPath = 'C:\ProgramData\IntuneMigration\config.json'
$commonPath = 'C:\ProgramData\IntuneMigration\Migration.Common.ps1'

if (-not (Test-Path -LiteralPath $commonPath)) {
    Write-Error "Required safety helper is missing: $commonPath"
    exit 1
}

. $commonPath

$config = Get-MigrationConfig -Path $configPath
$logPath = Join-Path -Path ([string]$config.logPath) -ChildPath 'reboot.log'
$script:transcriptStarted = $false

function Restore-InteractiveLogonSafety {
    [CmdletBinding()]
    param()

    $winlogonPath = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
    if (-not (Test-Path -LiteralPath $winlogonPath)) {
        New-Item -Path $winlogonPath -Force | Out-Null
    }

    New-ItemProperty -Path $winlogonPath -Name 'AutoAdminLogon' -Value '0' -PropertyType String -Force | Out-Null
    Remove-ItemProperty -Path $winlogonPath -Name 'DefaultPassword' -Force -ErrorAction SilentlyContinue
    Remove-ItemProperty -Path $winlogonPath -Name 'DefaultUserName' -Force -ErrorAction SilentlyContinue
    Remove-ItemProperty -Path $winlogonPath -Name 'DefaultDomainName' -Force -ErrorAction SilentlyContinue

    $credentialProvider = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\{60b78e88-ead8-445c-9cfd-0b87f74ea6cd}'
    if (-not (Test-Path -LiteralPath $credentialProvider)) {
        New-Item -Path $credentialProvider -Force | Out-Null
    }
    New-ItemProperty -Path $credentialProvider -Name 'Disabled' -Value 0 -PropertyType DWord -Force | Out-Null
}

function Set-LoginNotice {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Caption,
        [Parameter(Mandatory)][string]$Text
    )

    $policyPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
    New-ItemProperty -Path $policyPath -Name 'legalnoticecaption' -Value $Caption -PropertyType String -Force | Out-Null
    New-ItemProperty -Path $policyPath -Name 'legalnoticetext' -Value $Text -PropertyType String -Force | Out-Null
}

function Fail-ProfileTransition {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Message
    )

    Write-MigrationLog ERROR $Message

    try {
        Restore-InteractiveLogonSafety
        New-ItemProperty `
            -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' `
            -Name 'DontDisplayLastUserName' `
            -Value 0 `
            -PropertyType DWord `
            -Force | Out-Null

        Set-LoginNotice `
            -Caption 'Device migration recovery required' `
            -Text 'The automated profile transition was stopped by a safety check. Sign in with the approved local recovery administrator account and contact the administrator.'
    }
    catch {
        Write-MigrationLog ERROR "Unable to fully restore interactive logon safety: $($_.Exception.Message)"
    }

    try {
        Set-MigrationSafetyState -Values @{
            State = 'RecoveryRequired'
            RecoveryRequiredUtc = [DateTime]::UtcNow.ToString('o')
            LastError = $Message
        }
    }
    catch {
        Write-MigrationLog ERROR "Unable to persist RecoveryRequired state: $($_.Exception.Message)"
    }

    if ($script:transcriptStarted) {
        try { Stop-Transcript | Out-Null } catch {}
    }

    exit 1
}

function Get-ProfileBySid {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Sid
    )

    return Get-CimInstance -ClassName Win32_UserProfile -ErrorAction Stop |
        Where-Object { $_.SID -eq $Sid } |
        Select-Object -First 1
}

function Remove-OldSidIdentityCacheEntries {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$OldSid
    )

    # Same-tenant migration retains the same UPN.  Do NOT delete cache entries by
    # UPN, because that can remove freshly provisioned cloud identity state.
    # Only remove entries that explicitly point at the old on-premises SID.
    $roots = @(
        'HKLM:\SOFTWARE\Microsoft\IdentityStore\LogonCache',
        'HKLM:\SOFTWARE\Microsoft\IdentityStore\Cache'
    )

    foreach ($root in $roots) {
        if (-not (Test-Path -LiteralPath $root)) {
            continue
        }

        foreach ($key in @(Get-ChildItem -LiteralPath $root -Recurse -ErrorAction SilentlyContinue | Sort-Object PSPath -Descending)) {
            $remove = $false

            if ($key.PSChildName -eq $OldSid) {
                $remove = $true
            }
            else {
                try {
                    $properties = Get-ItemProperty -LiteralPath $key.PSPath -ErrorAction Stop
                    foreach ($propertyName in @('Sid','SID','SecurityIdentifier')) {
                        $property = $properties.PSObject.Properties[$propertyName]
                        if ($property -and [string]$property.Value -eq $OldSid) {
                            $remove = $true
                            break
                        }
                    }
                }
                catch {
                    # Not every IdentityStore key is readable as a property bag.
                }
            }

            if ($remove) {
                Write-MigrationLog INFO "Removing stale IdentityStore key tied to old SID: $($key.PSPath)"
                Remove-Item -LiteralPath $key.PSPath -Recurse -Force -ErrorAction SilentlyContinue
            }
        }
    }
}

try {
    Start-Transcript -Path $logPath -Append -ErrorAction Stop | Out-Null
    $script:transcriptStarted = $true

    Write-MigrationLog INFO 'Starting safety-hardened reboot/profile-owner phase.'

    # Prevent a boot loop before doing anything else.
    try {
        Disable-ScheduledTask -TaskName 'Reboot' -ErrorAction Stop | Out-Null
        Write-MigrationLog OK 'Reboot scheduled task disabled.'
    }
    catch {
        Write-MigrationLog WARN "Unable to disable Reboot task: $($_.Exception.Message)"
    }

    # Upstream startMigrate enables auto-logon and disables the password provider.
    # Restore a normal recovery-capable sign-in surface immediately.
    Restore-InteractiveLogonSafety
    Write-MigrationLog OK 'Auto-logon disabled, any Winlogon DefaultPassword removed, and password credential provider enabled.'

    $safety = Get-MigrationSafetyState
    if ($null -eq $safety) {
        Fail-ProfileTransition 'No migration Safety state exists. This replacement reboot.ps1 must be reached through install.ps1/preflight.ps1.'
    }

    $preflightState = [string](Get-OptionalPropertyValue -InputObject $safety -Name 'State')
    if ($preflightState -ne 'PreflightPassed' -and $preflightState -ne 'CommitStarted') {
        Fail-ProfileTransition "Profile transition refused because Safety\State='$preflightState', not PreflightPassed/CommitStarted."
    }

    $expectedTenantId = [string](Get-OptionalPropertyValue -InputObject $safety -Name 'ExpectedTenantId')
    $expectedOldSid = [string](Get-OptionalPropertyValue -InputObject $safety -Name 'OldSid')
    $expectedNewSid = [string](Get-OptionalPropertyValue -InputObject $safety -Name 'ExpectedNewSid')
    $expectedProfilePath = [string](Get-OptionalPropertyValue -InputObject $safety -Name 'ExpectedProfilePath')
    $expectedUpn = [string](Get-OptionalPropertyValue -InputObject $safety -Name 'ExpectedUserPrincipalName')

    foreach ($requiredPair in @(
        @{ Name='ExpectedTenantId'; Value=$expectedTenantId },
        @{ Name='OldSid'; Value=$expectedOldSid },
        @{ Name='ExpectedNewSid'; Value=$expectedNewSid },
        @{ Name='ExpectedProfilePath'; Value=$expectedProfilePath }
    )) {
        if ([string]::IsNullOrWhiteSpace([string]$requiredPair.Value)) {
            Fail-ProfileTransition "Safety state is missing required value '$($requiredPair.Name)'."
        }
    }

    $oldSid = Get-MigrationRegistryString -Name 'OLD_SID' -Required
    $newSid = Get-MigrationRegistryString -Name 'NEW_SID' -Required
    $oldProfilePath = Get-MigrationRegistryString -Name 'OLD_profilePath' -Required
    $newSamName = Get-MigrationRegistryString -Name 'NEW_SAMName' -Required
    $newUpn = Get-MigrationRegistryString -Name 'NEW_UPN'

    if ($oldSid -ne $expectedOldSid) {
        Fail-ProfileTransition "OLD_SID '$oldSid' doesn't match preflight SID '$expectedOldSid'."
    }

    if ($newSid -ne $expectedNewSid) {
        Fail-ProfileTransition "NEW_SID '$newSid' doesn't match the deterministic preflight cloud SID '$expectedNewSid'. Refusing to transfer the profile to the wrong identity."
    }

    if ($oldProfilePath.TrimEnd('\') -ine $expectedProfilePath.TrimEnd('\')) {
        Fail-ProfileTransition "OLD_profilePath '$oldProfilePath' doesn't match preflight profile path '$expectedProfilePath'."
    }

    if ($newUpn -and $expectedUpn -and $newUpn -ine $expectedUpn) {
        Fail-ProfileTransition "NEW_UPN '$newUpn' doesn't match preflight UPN '$expectedUpn'."
    }

    if ($oldSid -eq $newSid) {
        Fail-ProfileTransition 'OLD_SID and NEW_SID are identical; same-tenant hybrid migration expects distinct AD and Entra Windows SIDs.'
    }

    if ($newSid -notmatch '^S-1-12-1-') {
        Fail-ProfileTransition "NEW_SID '$newSid' isn't an expected Entra Windows SID."
    }

    $dsreg = Get-DsRegState
    Write-MigrationLog INFO "Post-provisioning join state: AzureAdJoined=$($dsreg.AzureAdJoined), DomainJoined=$($dsreg.DomainJoined), TenantId=$($dsreg.TenantId)."

    if ($dsreg.AzureAdJoined -ne 'YES') {
        Fail-ProfileTransition 'Profile transfer refused because the device is not Microsoft Entra joined after provisioning.'
    }

    if ($dsreg.DomainJoined -ne 'NO') {
        Fail-ProfileTransition 'Profile transfer refused because DomainJoined is not NO after provisioning.'
    }

    if ([string]::IsNullOrWhiteSpace([string]$dsreg.TenantId) -or $dsreg.TenantId -ne $expectedTenantId) {
        Fail-ProfileTransition "Profile transfer refused because joined tenant '$($dsreg.TenantId)' doesn't match expected tenant '$expectedTenantId'."
    }

    $sourceProfile = Get-ProfileBySid -Sid $oldSid
    $alreadyTransferred = $false

    if ($null -eq $sourceProfile) {
        $newOwnerProfile = Get-ProfileBySid -Sid $newSid
        if ($newOwnerProfile -and ([string]$newOwnerProfile.LocalPath).TrimEnd('\') -ieq $oldProfilePath.TrimEnd('\')) {
            Write-MigrationLog WARN 'OLD_SID profile no longer exists and NEW_SID already owns the original profile path; treating this as an idempotent rerun after successful ChangeOwner.'
            $alreadyTransferred = $true
        }
        else {
            Fail-ProfileTransition "Original profile for OLD_SID '$oldSid' can't be found and NEW_SID doesn't own the expected profile path."
        }
    }

    if (-not $alreadyTransferred) {
        if (([string]$sourceProfile.LocalPath).TrimEnd('\') -ine $oldProfilePath.TrimEnd('\')) {
            Fail-ProfileTransition "Win32_UserProfile path '$($sourceProfile.LocalPath)' doesn't match recorded source path '$oldProfilePath'."
        }

        if ([bool]$sourceProfile.Loaded) {
            Fail-ProfileTransition 'Original source profile is still loaded. ChangeOwner will not run against a loaded profile.'
        }

        # Remove stale AAD BrokerPlugin package state from the old profile only.
        $packagesPath = Join-Path -Path $oldProfilePath -ChildPath 'AppData\Local\Packages'
        if (Test-Path -LiteralPath $packagesPath) {
            foreach ($brokerPath in @(Get-ChildItem -LiteralPath $packagesPath -Directory -Filter 'Microsoft.AAD.BrokerPlugin_*' -ErrorAction SilentlyContinue)) {
                try {
                    Remove-Item -LiteralPath $brokerPath.FullName -Recurse -Force -ErrorAction Stop
                    Write-MigrationLog OK "Removed stale AAD BrokerPlugin directory '$($brokerPath.FullName)'."
                }
                catch {
                    Fail-ProfileTransition "Unable to remove stale AAD BrokerPlugin directory '$($brokerPath.FullName)': $($_.Exception.Message)"
                }
            }
        }

        # CreateProfile causes Windows to materialize the NEW_SID profile record.
        # The record is then removed so ChangeOwner can associate NEW_SID with the
        # original profile.  This is the core upstream technique.
        Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
namespace UserProfile {
    public static class NativeMethods {
        [DllImport("userenv.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern int CreateProfile(
            string pszUserSid,
            string pszUserName,
            System.Text.StringBuilder pszProfilePath,
            uint cchProfilePath
        );
    }
}
"@ -ErrorAction Stop

        $builder = New-Object System.Text.StringBuilder 260
        $createResult = [UserProfile.NativeMethods]::CreateProfile(
            $newSid,
            $newSamName,
            $builder,
            [uint32]$builder.Capacity
        )

        # 0 = success.  0x800700B7 represented as signed Int32 is -2147024713:
        # ERROR_ALREADY_EXISTS.  Both are acceptable before read-back.
        if ($createResult -ne 0 -and $createResult -ne -2147024713) {
            Fail-ProfileTransition "CreateProfile failed with return value $createResult."
        }

        Write-MigrationLog INFO "CreateProfile return value=$createResult, proposed path='$($builder.ToString())'."

        $temporaryProfile = $null
        for ($attempt = 1; $attempt -le 5; $attempt++) {
            $temporaryProfile = Get-ProfileBySid -Sid $newSid
            if ($temporaryProfile) {
                break
            }

            Write-MigrationLog INFO "NEW_SID profile record isn't visible yet; retry $attempt/5 in 10 seconds."
            Start-Sleep -Seconds 10
        }

        if ($null -eq $temporaryProfile) {
            Fail-ProfileTransition 'NEW_SID profile record never materialized after CreateProfile. The unsafe runas.exe fallback from branch 8.1 is intentionally not used.'
        }

        if (([string]$temporaryProfile.LocalPath).TrimEnd('\') -ieq $oldProfilePath.TrimEnd('\')) {
            Write-MigrationLog WARN 'NEW_SID already owns the original profile path after CreateProfile; treating transition as already complete.'
            $alreadyTransferred = $true
        }
        else {
            if ([bool]$temporaryProfile.Loaded) {
                Fail-ProfileTransition "Temporary NEW_SID profile '$($temporaryProfile.LocalPath)' is loaded; it will not be deleted."
            }

            Write-MigrationLog INFO "Removing temporary NEW_SID profile '$($temporaryProfile.LocalPath)' before ChangeOwner."
            Remove-CimInstance -InputObject $temporaryProfile -ErrorAction Stop

            # Confirm the temporary target profile is actually gone.
            Start-Sleep -Seconds 2
            if (Get-ProfileBySid -Sid $newSid) {
                Fail-ProfileTransition 'Temporary NEW_SID profile still exists after Remove-CimInstance.'
            }

            $sourceProfile = Get-ProfileBySid -Sid $oldSid
            if ($null -eq $sourceProfile) {
                Fail-ProfileTransition 'Source profile disappeared before ChangeOwner.'
            }

            $changeResult = $sourceProfile | Invoke-CimMethod `
                -MethodName ChangeOwner `
                -Arguments @{ NewOwnerSID = $newSid; Flags = 0 } `
                -ErrorAction Stop

            if ($null -eq $changeResult -or [uint32]$changeResult.ReturnValue -ne 0) {
                $returnValue = if ($changeResult) { [string]$changeResult.ReturnValue } else { '<null>' }
                Fail-ProfileTransition "Win32_UserProfile.ChangeOwner returned '$returnValue' instead of 0."
            }

            Write-MigrationLog OK 'Win32_UserProfile.ChangeOwner returned success.'

            $verifiedNewProfile = $null
            $verifiedOldProfile = $null
            for ($verifyAttempt = 1; $verifyAttempt -le 5; $verifyAttempt++) {
                Start-Sleep -Seconds 2
                $verifiedNewProfile = Get-ProfileBySid -Sid $newSid
                $verifiedOldProfile = Get-ProfileBySid -Sid $oldSid

                if ($verifiedNewProfile -and -not $verifiedOldProfile) {
                    break
                }
            }

            if ($verifiedOldProfile) {
                Fail-ProfileTransition 'OLD_SID profile still enumerates after ChangeOwner verification retries.'
            }

            if ($null -eq $verifiedNewProfile) {
                Fail-ProfileTransition 'NEW_SID profile doesn't enumerate after ChangeOwner verification retries.'
            }

            if (([string]$verifiedNewProfile.LocalPath).TrimEnd('\') -ine $oldProfilePath.TrimEnd('\')) {
                Fail-ProfileTransition "NEW_SID owns '$($verifiedNewProfile.LocalPath)' rather than expected original profile '$oldProfilePath'."
            }

            Write-MigrationLog OK "Profile owner transition verified: $oldSid -> $newSid at '$oldProfilePath'."
            $alreadyTransferred = $true
        }
    }

    if (-not $alreadyTransferred) {
        Fail-ProfileTransition 'Internal safety invariant failed: profile transfer wasn't verified.'
    }

    # Remove only registry identity records that explicitly reference OLD_SID.
    # Same-tenant UPN is preserved, so broad UPN-based cache deletion is unsafe.
    Remove-OldSidIdentityCacheEntries -OldSid $oldSid
    Write-MigrationLog OK 'Targeted old-SID IdentityStore cleanup completed.'

    Restore-InteractiveLogonSafety

    New-ItemProperty `
        -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' `
        -Name 'DontDisplayLastUserName' `
        -Value 0 `
        -PropertyType DWord `
        -Force | Out-Null

    $targetTenantConfig = Get-OptionalPropertyValue -InputObject $config -Name 'targetTenant'
    $targetTenantName = [string](Get-OptionalPropertyValue -InputObject $targetTenantConfig -Name 'tenantName')
    $tenantLabel = if (-not [string]::IsNullOrWhiteSpace($targetTenantName)) {
        $targetTenantName
    }
    else {
        [string]$config.sourceTenant.tenantName
    }

    Set-LoginNotice `
        -Caption "Welcome to $tenantLabel" `
        -Text "Sign in with your Microsoft Entra account: $expectedUpn"

    Set-MigrationSafetyState -Values @{
        State = 'ProfileReassociated'
        ProfileReassociatedUtc = [DateTime]::UtcNow.ToString('o')
        VerifiedNewSid = $newSid
        VerifiedProfilePath = $oldProfilePath
        LastError = ''
    }

    Write-MigrationLog OK 'Profile reassociation completed and verified. Rebooting to the normal Entra sign-in surface.'

    if ($script:transcriptStarted) {
        Stop-Transcript | Out-Null
        $script:transcriptStarted = $false
    }

    shutdown.exe /r /t 10 /c "Microsoft Entra migration profile transition completed."
    exit 0
}
catch {
    Fail-ProfileTransition "Unhandled profile-transition error: $($_.Exception.Message)"
}
