<#
.SYNOPSIS
    One-time LocalSystem handoff worker for the atomic 0011 destructive lab.

.DESCRIPTION
    Runs only under LocalSystem from the no-trigger NG-DestructiveLab-Start task.
    It independently re-verifies the control package, execution bundle, endpoint
    gate, and LAUNCH-INTENT chain in the task context; refuses replay; writes an
    immutable SYSTEM-LAUNCH record; performs one final startMigrate.ps1 hash
    check; and then invokes the verified bundle migration controller.

    This worker is the final machine-context enforcement point between a human
    launch request and startMigrate.ps1.

.NOTES
    Atomic 0011. Windows PowerShell 5.1 compatible.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$ControlPackagePath,
    [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$BundlePath,
    [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$GateEvidencePath,
    [Parameter(Mandatory)][ValidatePattern('^[0-9a-fA-F]{64}$')][string]$LaunchIntentSha256
)

Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
if($PSVersionTable.PSEdition -ne 'Desktop' -or $PSVersionTable.PSVersion.Major -ne 5){ throw 'Atomic 0011 worker requires Windows PowerShell 5.1.' }
$commonPath=Join-Path $PSScriptRoot 'NG.DestructiveLab.Common.ps1'; if(-not (Test-Path -LiteralPath $commonPath -PathType Leaf)){ throw "Atomic 0011 common helper missing: '$commonPath'." }; . $commonPath

$identity=[Security.Principal.WindowsIdentity]::GetCurrent()
if(-not $identity.IsSystem){ throw "Atomic 0011 launch worker must run as LocalSystem. Observed '$($identity.Name)'." }

$control=Test-NG0011ControlPackage -ControlPackagePath $ControlPackagePath -RequireFreshAuthorization
$bundle=Get-NG0011BundleEvidence -BundlePath $BundlePath -BundleVerifierPath (Join-Path $control.payload 'Test-NGLabExecutionBundle.ps1')
Assert-NG0011BundleAuthorizationBinding -BundleEvidence $bundle -RunAuthorization $control.authorization
$gateRoot=Get-NG0011ResolvedDirectory -Path $GateEvidencePath -Purpose 'Gate evidence'

# Re-run the full read-only endpoint gate verifier in this LocalSystem task
# context immediately before the final handoff to the migration engine.
Invoke-NG0011ChildPowerShell -ScriptPath (Join-Path $control.payload 'Test-NGDestructiveLabGateEvidence.ps1') -Arguments @('-ControlPackagePath',$control.root,'-BundlePath',$bundle.path,'-GateEvidencePath',$gateRoot)
$gateResult=Read-NG0011Record -Directory $gateRoot -RecordName $script:NG0011GateRecordName
$intentResult=Read-NG0011Record -Directory $gateRoot -RecordName $script:NG0011LaunchIntentName
$intent=$intentResult.Record
if($intentResult.Sha256 -ne $LaunchIntentSha256.ToLowerInvariant()){ throw 'Scheduled-task LaunchIntentSha256 does not match LAUNCH-INTENT.json.' }
if([string]$intent.previousRecordSha256 -ine $gateResult.Sha256){ throw 'LAUNCH-INTENT.json does not hash-bind the current Gate record.' }
if([string]$intent.confirmations.bundleId -ine $bundle.bundleId -or [string]$intent.confirmations.deviceId -ine [string]$control.authorization.authorization0010.device.deviceId -or [string]$intent.confirmations.computerName -cne [string]$gateResult.Record.endpoint.computerName){ throw 'LAUNCH-INTENT confirmations no longer match current verified authorization.' }

$live=$intent.liveLifecycleAuthorization
if($null -eq $live -or -not [bool]$live.verified -or -not [bool]$live.stage.directMember -or -not [bool]$live.commit.directMember -or [bool]$live.success.directMember -or [bool]$live.graphWritePerformed){ throw 'LAUNCH-INTENT does not contain an acceptable final live lifecycle authorization proof.' }
if([string]$live.deviceObjectId -ine [string]$control.authorization.authorization0010.device.objectId -or [string]$live.stage.groupId -ine [string]$control.authorization.authorization0010.groups.stage.objectId -or [string]$live.commit.groupId -ine [string]$control.authorization.authorization0010.groups.commit.objectId -or [string]$live.success.groupId -ine $script:NG0011SuccessGroupId){ throw 'LAUNCH-INTENT live lifecycle proof is bound to unexpected device/group identities.' }
$liveUtc=ConvertTo-NG0011Utc -Value ([string]$live.verifiedUtc) -Purpose 'live lifecycle verification'
$liveAge=[DateTime]::UtcNow-$liveUtc
if($liveAge.TotalSeconds -lt -60 -or $liveAge.TotalMinutes -gt 5){ throw "Live Graph lifecycle proof is not fresh enough for LocalSystem handoff. Age minutes=$([Math]::Round($liveAge.TotalMinutes,2))." }

$systemRecordPath=Join-Path $gateRoot $script:NG0011SystemLaunchName
if(Test-Path -LiteralPath $systemRecordPath){ throw 'SYSTEM-LAUNCH.json already exists. Refusing replay of the destructive task.' }

$startMigrate=Join-Path (Join-Path $bundle.path 'payload') 'startMigrate.ps1'
$manifestRecord=@($bundle.manifest.payload.files | Where-Object { [string]$_.name -ceq 'startMigrate.ps1' })
if($manifestRecord.Count -ne 1){ throw 'Execution manifest does not contain exactly one startMigrate.ps1 record.' }
$startSha=Get-NG0011Sha256 $startMigrate
if($startSha -ne ([string]$manifestRecord[0].sha256).ToLowerInvariant()){ throw 'startMigrate.ps1 changed after bundle verification.' }

$systemRecord=[ordered]@{
    schemaVersion='1.0';atomic='0011';recordType='SystemLaunch';generatedUtc=[DateTime]::UtcNow.ToString('o');previousRecordSha256=$intentResult.Sha256
    principal=[ordered]@{windowsAccount=[string]$identity.Name;windowsSid=[string]$identity.User.Value;localSystem=$true}
    binding=[ordered]@{controlId=[string]$control.manifest.controlId;runAuthorizationSha256=$control.authorizationSha256;gateRecordSha256=$gateResult.Sha256;launchIntentSha256=$intentResult.Sha256;bundleId=$bundle.bundleId;bundleManifestSha256=$bundle.manifestSha256;repositoryCommit=$bundle.repositoryCommit;repositoryTree=$bundle.repositoryTree;deviceId=[string]$control.authorization.authorization0010.device.deviceId;computerName=[string]$gateResult.Record.endpoint.computerName}
    liveLifecycleAuthorization=[ordered]@{verifiedUtc=[string]$live.verifiedUtc;ageSeconds=[Math]::Round($liveAge.TotalSeconds,1);stageDirectMember=[bool]$live.stage.directMember;commitDirectMember=[bool]$live.commit.directMember;successDirectMember=[bool]$live.success.directMember;graphAccount=[string]$live.graph.account;graphWritePerformed=[bool]$live.graphWritePerformed}
    migrationController=[ordered]@{path=$startMigrate;sha256=$startSha;manifestSha256=[string]$manifestRecord[0].sha256}
    policy=[ordered]@{controlReverified=$true;bundleReverified=$true;gateReverified=$true;launchIntentVerified=$true;liveLifecycleProofUnderFiveMinutes=$true;replayRefused=$true;migrationInvocationRequested=$true;migrationOutcomeInferred=$false;successGroupTouched=$false}
}
$systemSha=Write-NG0011ImmutableRecord -Directory $gateRoot -RecordName $script:NG0011SystemLaunchName -Record $systemRecord
Write-Host "Atomic 0011 LocalSystem handoff verified. SYSTEM-LAUNCH SHA-256: $systemSha"
Write-Host "Invoking verified startMigrate.ps1 for BundleId $($bundle.bundleId)."

& $startMigrate
exit 0
