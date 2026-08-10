<#
.SYNOPSIS
    Independently verifies atomic 0011 endpoint gate evidence immediately before launch.

.DESCRIPTION
    Read-only verification of control-package integrity, final execution-bundle
    integrity, short-lived run authorization, endpoint gate hash chain, exact
    Hybrid source identity, preflight binding, recovery-account availability,
    BitLocker recovery evidence, AC/time/network readiness, and evidence ACL.

    It does not validate the recovery password a second time, query or modify
    Microsoft Graph, start migration, change join state, or modify profile data.

.NOTES
    Atomic 0011. Windows PowerShell 5.1 compatible.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$ControlPackagePath,
    [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$BundlePath,
    [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$GateEvidencePath
)

Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
if($PSVersionTable.PSEdition -ne 'Desktop' -or $PSVersionTable.PSVersion.Major -ne 5){ throw "Atomic 0011 requires Windows PowerShell 5.1. Observed $($PSVersionTable.PSEdition) $($PSVersionTable.PSVersion)." }
$commonPath=Join-Path $PSScriptRoot 'NG.DestructiveLab.Common.ps1'; if(-not (Test-Path -LiteralPath $commonPath -PathType Leaf)){ throw "Atomic 0011 common helper missing: '$commonPath'." }; . $commonPath

$control=Test-NG0011ControlPackage -ControlPackagePath $ControlPackagePath -RequireFreshAuthorization
$bundle=Get-NG0011BundleEvidence -BundlePath $BundlePath -BundleVerifierPath (Join-Path $control.payload 'Test-NGLabExecutionBundle.ps1')
Assert-NG0011BundleAuthorizationBinding -BundleEvidence $bundle -RunAuthorization $control.authorization
Import-NG0011BundleCommon -BundleEvidence $bundle

$gateRoot=Get-NG0011ResolvedDirectory -Path $GateEvidencePath -Purpose 'Gate evidence'
$gateAuthorization=Read-NG0011Record -Directory $gateRoot -RecordName $script:NG0011RunAuthorizationName
if($gateAuthorization.Sha256 -ne $control.authorizationSha256){ throw 'Gate evidence RUN-AUTHORIZATION.json differs from the verified control package authorization.' }
$gateResult=Read-NG0011Record -Directory $gateRoot -RecordName $script:NG0011GateRecordName
$gate=$gateResult.Record
if([string]$gate.schemaVersion -ne '1.0' -or [string]$gate.atomic -ne '0011' -or [string]$gate.recordType -ne 'DestructiveLabGate'){ throw 'Unsupported DESTRUCTIVE-LAB-GATE.json.' }
if([string]$gate.previousRecordSha256 -ine $control.authorizationSha256){ throw 'Gate record does not hash-bind the current RUN-AUTHORIZATION.json.' }
if([string]$gate.control.controlId -ine [string]$control.manifest.controlId -or [string]$gate.control.manifestSha256 -ine $control.manifestSha256){ throw 'Gate record does not match the control package.' }
$expires=ConvertTo-NG0011Utc -Value ([string]$gate.expiresUtc) -Purpose 'gate expiresUtc'; if([DateTime]::UtcNow -gt $expires){ throw "Destructive-lab gate expired at $($expires.ToString('o')). Run the gate again with a new evidence directory." }

$pairs=@(
 @('bundleId',$gate.bundle.bundleId,$bundle.bundleId),@('bundle manifest',$gate.bundle.manifestSha256,$bundle.manifestSha256),@('config SHA',$gate.bundle.configSha256,$bundle.configSha256),@('PPKG SHA',$gate.bundle.ppkgSha256,$bundle.ppkgSha256),
 @('0010 Commit SHA',$gate.authorization0010.commitRecordSha256,$control.authorization.authorization0010.commitRecordSha256),@('DeviceId',$gate.authorization0010.device.deviceId,$control.authorization.authorization0010.device.deviceId),@('device object ID',$gate.authorization0010.device.objectId,$control.authorization.authorization0010.device.objectId)
)
foreach($p in $pairs){ if([string]$p[1] -ine [string]$p[2]){ throw "Gate field '$($p[0])' does not match current authorization/bundle." } }
if(-not [bool]$gate.policy.recoveryCredentialUsable -or -not [bool]$gate.recovery.credential.validated -or [bool]$gate.recovery.credential.passwordStored -or [bool]$gate.recovery.credential.passwordDerivedVerifierStored){ throw 'Gate does not contain acceptable recovery-credential proof.' }

Assert-NG0011RestrictedDirectoryAcl -Path $gateRoot -OperatorSid ([string]$gate.endpoint.operator.windowsSid)
$source=Assert-NG0011HybridSourceBinding -RunAuthorization $control.authorization -RequireInteractiveUser
$safety=Get-MigrationSafetyState; if($null -eq $safety){ throw 'Migration Safety state is missing.' }
Assert-NG0011PreflightBinding -SafetyState $safety -RunAuthorization $control.authorization -BundleEvidence $bundle
if([string]$source.interactiveUser.Sid -ne [string]$gate.preflight.oldSid){ throw 'Current interactive source SID differs from gate evidence.' }
if(([string]$source.interactiveUser.ProfilePath).TrimEnd('\') -ine ([string]$gate.preflight.expectedProfilePath).TrimEnd('\')){ throw 'Current interactive profile path differs from gate evidence.' }

$preflightPath=[string]$gate.preflight.preflightEvidencePath
if(-not (Test-Path -LiteralPath $preflightPath -PathType Leaf)){ throw "Gate-bound preflight evidence file is missing: '$preflightPath'." }
if((Get-NG0011Sha256 $preflightPath) -ne ([string]$gate.preflight.preflightEvidenceSha256).ToLowerInvariant()){ throw 'Gate-bound preflight evidence file changed after gate creation.' }

$recoveryAccount=Get-RecoveryLocalAccount -Config $bundle.config
if([string]$recoveryAccount.Name -ine [string]$gate.recovery.credential.accountName -or [string]$recoveryAccount.SID.Value -ine [string]$gate.recovery.credential.accountSid){ throw 'Configured recovery account identity changed after gate creation.' }
$bitLocker=Get-NG0011BitLockerRecoveryEvidence
if([bool]$bitLocker.protectionOn -ne [bool]$gate.recovery.bitLocker.protectionOn){ throw 'BitLocker protection status changed after gate creation.' }
if([bool]$bitLocker.protectionOn -and [int]$bitLocker.recoveryPasswordProtectorCount -lt 1){ throw 'BitLocker recovery protector is no longer available.' }
$power=Get-NG0011PowerEvidence
$time=Get-NG0011TimeEvidence
$connectivity=@(Get-NG0011ConnectivityEvidence)

Write-Host ''
Write-Host 'NG atomic 0011 destructive-lab gate evidence verification: PASS'
Write-Host "Computer:             $env:COMPUTERNAME"
Write-Host "DeviceId:             $($source.dsreg.DeviceId)"
Write-Host "TenantId:             $($source.dsreg.TenantId)"
Write-Host "Source user:          $($bundle.expectedSourceUserPrincipalName)"
Write-Host "BundleId:             $($bundle.bundleId)"
Write-Host "0010 Commit SHA-256:  $($control.authorization.authorization0010.commitRecordSha256)"
Write-Host "Gate SHA-256:         $($gateResult.Sha256)"
Write-Host "Gate expires:         $($gate.expiresUtc)"
Write-Host "Recovery account:     $($recoveryAccount.Name)"
Write-Host "BitLocker protection: $($bitLocker.protectionStatus)"
Write-Host "AC status:            $($power.powerLineStatus)"
Write-Host "Time source:          $($time.source)"
Write-Host "Connectivity probes:  $($connectivity.Count) passed"
Write-Host ''
Write-Host 'This verifier was read-only and did not start migration or modify Microsoft Graph.'
exit 0
