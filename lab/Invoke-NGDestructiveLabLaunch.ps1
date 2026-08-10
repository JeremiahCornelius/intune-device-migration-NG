<#
.SYNOPSIS
    Explicitly launches the first destructive NG lab after a verified 0011 gate.

.DESCRIPTION
    This is the atomic 0011 destructive boundary. It independently reruns the
    gate verifier, requires exact human confirmations for Gate SHA, BundleId,
    DeviceId, and computer name, writes immutable LAUNCH-INTENT evidence, then
    creates and manually starts a one-shot/no-trigger LocalSystem scheduled task
    whose only action is the atomic 0011 LocalSystem launch worker. The worker
    independently re-verifies the gate/bundle and then invokes startMigrate.ps1.

    The script does not change Entra/Intune group membership and does not infer
    success from task creation. The existing startMigrate.ps1 still performs its
    own safety checks before its internal irreversible identity boundary.

.NOTES
    Atomic 0011. Windows PowerShell 5.1 compatible.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$ControlPackagePath,
    [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$BundlePath,
    [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$GateEvidencePath,
    [Parameter(Mandatory)][ValidatePattern('^[0-9a-fA-F]{64}$')][string]$GateRecordSha256,
    [Parameter(Mandatory)][ValidatePattern('^[0-9a-fA-F]{64}$')][string]$ConfirmBundleId,
    [Parameter(Mandatory)][ValidatePattern('^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')][string]$ConfirmDeviceId,
    [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$ConfirmComputerName,
    [Parameter()][switch]$UseDeviceCode,
    [Parameter()][switch]$Execute
)

Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
if($PSVersionTable.PSEdition -ne 'Desktop' -or $PSVersionTable.PSVersion.Major -ne 5){ throw "Atomic 0011 requires Windows PowerShell 5.1. Observed $($PSVersionTable.PSEdition) $($PSVersionTable.PSVersion)." }
if(-not $Execute){ throw 'Destructive launch refused. Supply -Execute only after reviewing the complete gate output and independent verifier PASS.' }

$commonPath=Join-Path $PSScriptRoot 'NG.DestructiveLab.Common.ps1'; if(-not (Test-Path -LiteralPath $commonPath -PathType Leaf)){ throw "Atomic 0011 common helper missing: '$commonPath'." }; . $commonPath
$identity=[Security.Principal.WindowsIdentity]::GetCurrent(); if($identity.IsSystem){ throw 'Launch must be initiated by an elevated human Administrator, not directly as LocalSystem.' }
$principal=New-Object Security.Principal.WindowsPrincipal($identity); if(-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){ throw 'Launch requires an elevated local Administrator token.' }

$control=Test-NG0011ControlPackage -ControlPackagePath $ControlPackagePath -RequireFreshAuthorization
$bundle=Get-NG0011BundleEvidence -BundlePath $BundlePath -BundleVerifierPath (Join-Path $control.payload 'Test-NGLabExecutionBundle.ps1')
Assert-NG0011BundleAuthorizationBinding -BundleEvidence $bundle -RunAuthorization $control.authorization
$gateRoot=Get-NG0011ResolvedDirectory -Path $GateEvidencePath -Purpose 'Gate evidence'

# Independent pre-launch verification occurs in a fresh Windows PowerShell process.
$gateVerifier=Join-Path $control.payload 'Test-NGDestructiveLabGateEvidence.ps1'
Invoke-NG0011ChildPowerShell -ScriptPath $gateVerifier -Arguments @('-ControlPackagePath',$control.root,'-BundlePath',$bundle.path,'-GateEvidencePath',$gateRoot)
$gateResult=Read-NG0011Record -Directory $gateRoot -RecordName $script:NG0011GateRecordName
$gate=$gateResult.Record

if($gateResult.Sha256 -ne $GateRecordSha256.ToLowerInvariant()){ throw "GateRecordSha256 confirmation does not match verified gate record '$($gateResult.Sha256)'." }
if($bundle.bundleId -ne $ConfirmBundleId.ToLowerInvariant()){ throw "ConfirmBundleId does not match '$($bundle.bundleId)'." }
$deviceId=ConvertTo-NG0011GuidString -Value ([string]$control.authorization.authorization0010.device.deviceId) -Purpose 'authorized DeviceId'
$confirmedDeviceId=ConvertTo-NG0011GuidString -Value $ConfirmDeviceId -Purpose 'ConfirmDeviceId'
if($confirmedDeviceId -ne $deviceId){ throw "ConfirmDeviceId '$confirmedDeviceId' does not match '$deviceId'." }
if($ConfirmComputerName -cne [string]$gate.endpoint.computerName){ throw "ConfirmComputerName '$ConfirmComputerName' does not exactly match gate computer '$($gate.endpoint.computerName)'." }
$expires=ConvertTo-NG0011Utc -Value ([string]$gate.expiresUtc) -Purpose 'gate expiresUtc'; if([DateTime]::UtcNow -gt $expires){ throw 'Gate expired after independent verification. Refusing launch.' }

# Immediately before any task/intent mutation, perform a fresh delegated, read-only
# Graph query of the authorized pre-migration device object's DIRECT memberships.
# This closes the operational gap between the immutable 0010 Commit record and
# the destructive launch: STAGE and COMMIT must still be present, and SUCCESS
# must still be absent. Only Device.Read.All is requested; no Graph write occurs.
$liveLifecycle=Get-NG0011LiveLifecycleMembership -RunAuthorization $control.authorization -UseDeviceCode:$UseDeviceCode

$intentPath=Join-Path $gateRoot $script:NG0011LaunchIntentName; $observationPath=Join-Path $gateRoot $script:NG0011LaunchObservationName
if((Test-Path -LiteralPath $intentPath) -or (Test-Path -LiteralPath $observationPath)){ throw 'Launch evidence already exists. Atomic 0011 permits only one launch attempt per gate evidence directory.' }
$taskName='NG-DestructiveLab-Start'
if(Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue){ throw "Scheduled task '$taskName' already exists. Reconcile prior state before another launch." }

$startMigrate=Join-Path (Join-Path $bundle.path 'payload') 'startMigrate.ps1'
if(-not (Test-Path -LiteralPath $startMigrate -PathType Leaf)){ throw "Verified bundle startMigrate.ps1 is missing: '$startMigrate'." }
$worker=Join-Path $control.payload 'Invoke-NGDestructiveLabLaunchWorker.ps1'
if(-not (Test-Path -LiteralPath $worker -PathType Leaf)){ throw "Atomic 0011 LocalSystem launch worker is missing: '$worker'." }
$intent=[ordered]@{
    schemaVersion='1.0';atomic='0011';recordType='LaunchIntent';generatedUtc=[DateTime]::UtcNow.ToString('o');previousRecordSha256=$gateResult.Sha256
    operator=[ordered]@{windowsAccount=[string]$identity.Name;windowsSid=[string]$identity.User.Value;elevatedAdministrator=$true}
    confirmations=[ordered]@{gateRecordSha256=$GateRecordSha256.ToLowerInvariant();bundleId=$ConfirmBundleId.ToLowerInvariant();deviceId=$confirmedDeviceId;computerName=$ConfirmComputerName;executeSwitch=$true}
    binding=[ordered]@{controlId=[string]$control.manifest.controlId;runAuthorizationSha256=$control.authorizationSha256;authorizationCommitRecordSha256=[string]$control.authorization.authorization0010.commitRecordSha256;bundleManifestSha256=$bundle.manifestSha256;repositoryCommit=$bundle.repositoryCommit;repositoryTree=$bundle.repositoryTree}
    liveLifecycleAuthorization=$liveLifecycle
    plannedExecution=[ordered]@{taskName=$taskName;principal='NT AUTHORITY\SYSTEM';runLevel='Highest';powerShell='Windows PowerShell 5.1';worker=$worker;verifiedMigrationController=$startMigrate;trigger='None; explicit Start-ScheduledTask only'}
    policy=[ordered]@{liveDirectStageCommitReverified=$true;successConfirmedAbsent=$true;graphWritePerformed=$false;migrationStarted=$false;successGroupTouched=$false;serverCleanupRequested=$false}
}
$intentSha=Write-NG0011ImmutableRecord -Directory $gateRoot -RecordName $script:NG0011LaunchIntentName -Record $intent

try {
    $powerShell="$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
    if(-not (Test-Path -LiteralPath $powerShell -PathType Leaf)){ throw "Native Windows PowerShell missing: '$powerShell'." }
    $argument='-NoProfile -ExecutionPolicy Bypass -File "{0}" -ControlPackagePath "{1}" -BundlePath "{2}" -GateEvidencePath "{3}" -LaunchIntentSha256 {4}' -f $worker,$control.root,$bundle.path,$gateRoot,$intentSha
    $action=New-ScheduledTaskAction -Execute $powerShell -Argument $argument
    $taskPrincipal=New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    Register-ScheduledTask -TaskName $taskName -Action $action -Principal $taskPrincipal -Description 'Atomic 0011 one-shot LocalSystem gate worker for verified NG destructive lab.' -ErrorAction Stop | Out-Null
    $registered=Get-ScheduledTask -TaskName $taskName -ErrorAction Stop
    if(-not $registered){ throw "Scheduled task '$taskName' was not observable after registration." }
    $startRequestedUtc=[DateTime]::UtcNow
    Start-ScheduledTask -TaskName $taskName -ErrorAction Stop

    # Observe only; do not delay or interfere with startMigrate. Its earliest
    # meaningful persisted transition is Safety State=CommitStarted or an abort.
    $observedState='';$observedStep='';$observedUtc=''
    for($attempt=1;$attempt -le 60;$attempt++){
        Start-Sleep -Seconds 2
        try {
            $safetyPath='HKLM:\SOFTWARE\IntuneMigration\Safety'
            if(Test-Path -LiteralPath $safetyPath){
                $safety=Get-ItemProperty -LiteralPath $safetyPath -ErrorAction Stop
                $state=[string](Get-NG0011ObjectProperty -Object $safety -Name 'State')
                if($state -and $state -ne 'PreflightPassed'){
                    $observedState=$state;$observedStep=[string](Get-NG0011ObjectProperty -Object $safety -Name 'CommitStep');$observedUtc=[DateTime]::UtcNow.ToString('o');break
                }
            }
        } catch {}
    }
    if($observedState){
        $taskInfo=Get-ScheduledTaskInfo -TaskName $taskName -ErrorAction SilentlyContinue
        $observation=[ordered]@{
            schemaVersion='1.0';atomic='0011';recordType='LaunchObservation';generatedUtc=[DateTime]::UtcNow.ToString('o');previousRecordSha256=$intentSha
            task=[ordered]@{taskName=$taskName;registered=$true;startRequestedUtc=$startRequestedUtc.ToString('o');state=[string]$registered.State;lastRunTime=if($taskInfo){$taskInfo.LastRunTime.ToString('o')}else{''};lastTaskResult=if($taskInfo){[int]$taskInfo.LastTaskResult}else{$null}}
            migrationSafety=[ordered]@{state=$observedState;commitStep=$observedStep;observedUtc=$observedUtc}
            policy=[ordered]@{taskStartRequested=$true;migrationOutcomeInferred=$false;successGroupTouched=$false}
        }
        $observationSha=Write-NG0011ImmutableRecord -Directory $gateRoot -RecordName $script:NG0011LaunchObservationName -Record $observation
        Write-Host "Launch observation SHA-256: $observationSha"
        Write-Host "Observed migration Safety state: $observedState / $observedStep"
    } else {
        Write-Warning 'No Safety-state transition was observed before the launch observer timed out. LAUNCH-INTENT remains the authoritative proof that task start was requested; do not infer migration success.'
    }

    Write-Host ''
    Write-Host 'ATOMIC 0011 DESTRUCTIVE LAUNCH REQUESTED.'
    Write-Host "Launch intent SHA-256: $intentSha"
    Write-Host "Live Graph operator:      $($liveLifecycle.graph.account)"
    Write-Host 'Live lifecycle state:     STAGE=True COMMIT=True SUCCESS=False'
    Write-Host "Task:                    $taskName (LocalSystem worker, no trigger)"
    Write-Host "BundleId:                $($bundle.bundleId)"
    Write-Host 'The task worker will re-verify the gate and refuse replay before invoking startMigrate.ps1.'
    Write-Host 'Do not manually rerun the task, worker, or startMigrate.ps1.'
}
catch {
    throw "Destructive launch failed after LAUNCH-INTENT was recorded. Preserve the gate evidence directory and reconcile before any retry. $($_.Exception.Message)"
}
