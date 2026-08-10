<#
.SYNOPSIS
    Establishes the final non-destructive endpoint gate before the first NG destructive lab.

.DESCRIPTION
    Verifies one exact atomic 0011 control package and its bound atomic 0009
    execution bundle, then proves endpoint recovery/readiness conditions and
    runs a fresh non-destructive preflight. A successful gate writes immutable,
    short-lived evidence. It does not start migration.

    Recovery credential validation uses LogonUser against the local SAM with an
    interactive logon type. The password exists in plaintext only transiently
    in process memory for the API call, is immediately released/zeroed, and is
    never written, logged, hashed, or stored in gate evidence.

.NOTES
    Atomic 0011. Run in elevated Windows PowerShell 5.1 as a local Administrator.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$ControlPackagePath,
    [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$BundlePath,
    [Parameter()][ValidateNotNullOrEmpty()][string]$GateEvidencePath='C:\ProgramData\IntuneMigrationGate',
    [Parameter()][Management.Automation.PSCredential]$RecoveryCredential,
    [Parameter()][ValidateRange(5,60)][int]$GateLifetimeMinutes=30
)

Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
if($PSVersionTable.PSEdition -ne 'Desktop' -or $PSVersionTable.PSVersion.Major -ne 5){ throw "Atomic 0011 requires Windows PowerShell 5.1. Observed $($PSVersionTable.PSEdition) $($PSVersionTable.PSVersion)." }

$commonPath=Join-Path $PSScriptRoot 'NG.DestructiveLab.Common.ps1'
if(-not (Test-Path -LiteralPath $commonPath -PathType Leaf)){ throw "Atomic 0011 common helper missing: '$commonPath'." }
. $commonPath

$identity=[Security.Principal.WindowsIdentity]::GetCurrent()
if($identity.IsSystem){ throw 'Run the endpoint gate as an elevated human local Administrator, not LocalSystem.' }
$principal=New-Object Security.Principal.WindowsPrincipal($identity)
if(-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){ throw "Endpoint gate requires an elevated local Administrator token. Current identity: '$($identity.Name)'." }

$control=Test-NG0011ControlPackage -ControlPackagePath $ControlPackagePath -RequireFreshAuthorization
$bundleVerifier=Join-Path $control.payload 'Test-NGLabExecutionBundle.ps1'
$bundle=Get-NG0011BundleEvidence -BundlePath $BundlePath -BundleVerifierPath $bundleVerifier
Assert-NG0011BundleAuthorizationBinding -BundleEvidence $bundle -RunAuthorization $control.authorization
Import-NG0011BundleCommon -BundleEvidence $bundle

$source=Assert-NG0011HybridSourceBinding -RunAuthorization $control.authorization -RequireInteractiveUser
$recoveryAccount=Get-RecoveryLocalAccount -Config $bundle.config
if($null -eq $RecoveryCredential){
    $RecoveryCredential=Get-Credential -UserName ".\$($recoveryAccount.Name)" -Message 'Enter the verified local recovery-account password. It will not be stored.'
}
if($null -eq $RecoveryCredential){ throw 'Recovery credential entry was cancelled.' }
$credentialEvidence=Test-NG0011RecoveryCredential -RecoveryAccount $recoveryAccount -Credential $RecoveryCredential
$RecoveryCredential=$null

$bitLockerEvidence=Get-NG0011BitLockerRecoveryEvidence
$powerEvidence=Get-NG0011PowerEvidence
$timeEvidence=Get-NG0011TimeEvidence
$connectivityEvidence=@(Get-NG0011ConnectivityEvidence)

$payloadRoot=Join-Path $bundle.path 'payload'
$preflight=Join-Path $payloadRoot 'preflight.ps1'
if(-not (Test-Path -LiteralPath $preflight -PathType Leaf)){ throw 'Bundled preflight.ps1 is missing.' }
& $preflight -ConfigPath $bundle.configPath -AllowAdministratorContext
$preflightExit=$LASTEXITCODE
if($preflightExit -ne 0){ throw "Fresh non-destructive preflight failed with exit code $preflightExit. Migration was not started." }

$safety=Get-MigrationSafetyState
if($null -eq $safety){ throw 'Fresh preflight returned success but migration Safety state is missing.' }
Assert-NG0011PreflightBinding -SafetyState $safety -RunAuthorization $control.authorization -BundleEvidence $bundle

# Reassert exact source state after preflight because preflight performs network
# and Graph work and is intentionally the last substantial read-only operation.
$sourceAfter=Assert-NG0011HybridSourceBinding -RunAuthorization $control.authorization -RequireInteractiveUser
if([string]$sourceAfter.interactiveUser.Sid -ne [string](Get-OptionalPropertyValue -InputObject $safety -Name 'OldSid')){ throw 'Interactive source SID changed during the gate.' }
if(([string]$sourceAfter.interactiveUser.ProfilePath).TrimEnd('\') -ine ([string](Get-OptionalPropertyValue -InputObject $safety -Name 'ExpectedProfilePath')).TrimEnd('\')){ throw 'Interactive source profile path changed during the gate.' }

$preflightPath=Join-Path ([string]$bundle.config.localPath) 'preflight.json'
if(-not (Test-Path -LiteralPath $preflightPath -PathType Leaf)){ throw "Fresh preflight evidence file is missing: '$preflightPath'." }
$preflightSha=Get-NG0011Sha256 $preflightPath

$gateFull=[IO.Path]::GetFullPath($GateEvidencePath).TrimEnd([char[]]@('\','/'))
if([string]::IsNullOrWhiteSpace($gateFull) -or $gateFull -eq [IO.Path]::GetPathRoot($gateFull).TrimEnd([char[]]@('\','/'))){ throw "Invalid GateEvidencePath '$GateEvidencePath'." }
if(Test-Path -LiteralPath $gateFull){ throw "GateEvidencePath already exists. Refusing to merge evidence: '$gateFull'." }
if(Test-NG0011PathInsideDirectory -ChildPath $gateFull -ParentPath $control.root){ throw 'Gate evidence must not be inside control package.' }
if(Test-NG0011PathInsideDirectory -ChildPath $gateFull -ParentPath $bundle.path){ throw 'Gate evidence must not be inside execution bundle.' }

New-Item -Path $gateFull -ItemType Directory -ErrorAction Stop | Out-Null
$operatorSid=Set-NG0011RestrictedDirectoryAcl -Path $gateFull
try {
    # Preserve exact authorization bytes in the endpoint evidence directory.
    Copy-Item -LiteralPath (Join-Path $control.root $script:NG0011RunAuthorizationName) -Destination $gateFull -ErrorAction Stop
    Copy-Item -LiteralPath (Join-Path $control.root $script:NG0011RunAuthorizationHashName) -Destination $gateFull -ErrorAction Stop

    $now=[DateTime]::UtcNow
    $gate=[ordered]@{
        schemaVersion='1.0';atomic='0011';recordType='DestructiveLabGate';generatedUtc=$now.ToString('o');expiresUtc=$now.AddMinutes($GateLifetimeMinutes).ToString('o')
        previousRecordSha256=$control.authorizationSha256
        control=[ordered]@{controlId=[string]$control.manifest.controlId;manifestSha256=$control.manifestSha256;runAuthorizationSha256=$control.authorizationSha256}
        repository=[ordered]@{commit=$bundle.repositoryCommit;tree=$bundle.repositoryTree}
        bundle=[ordered]@{bundleId=$bundle.bundleId;manifestSha256=$bundle.manifestSha256;configSha256=$bundle.configSha256;ppkgSha256=$bundle.ppkgSha256}
        authorization0010=$control.authorization.authorization0010
        endpoint=[ordered]@{
            operator=[ordered]@{windowsAccount=[string]$identity.Name;windowsSid=[string]$identity.User.Value;elevatedAdministrator=$true;localSystem=$false}
            computerName=[string]$env:COMPUTERNAME;tenantId=[string]$sourceAfter.dsreg.TenantId;deviceId=[string]$sourceAfter.dsreg.DeviceId;azureAdJoined=[string]$sourceAfter.dsreg.AzureAdJoined;domainJoined=[string]$sourceAfter.dsreg.DomainJoined
            sourceUser=[ordered]@{windowsName=[string]$sourceAfter.interactiveUser.UserName;oldSid=[string]$sourceAfter.interactiveUser.Sid;profilePath=[string]$sourceAfter.interactiveUser.ProfilePath;profileLoaded=[bool]$sourceAfter.interactiveUser.ProfileLoaded}
        }
        recovery=[ordered]@{credential=$credentialEvidence;bitLocker=$bitLockerEvidence}
        readiness=[ordered]@{power=$powerEvidence;time=$timeEvidence;connectivity=$connectivityEvidence}
        preflight=[ordered]@{
            state=[string](Get-OptionalPropertyValue $safety 'State');preflightUtc=[string](Get-OptionalPropertyValue $safety 'PreflightUtc');preflightEvidencePath=$preflightPath;preflightEvidenceSha256=$preflightSha
            oldSid=[string](Get-OptionalPropertyValue $safety 'OldSid');expectedNewSid=[string](Get-OptionalPropertyValue $safety 'ExpectedNewSid');expectedUserObjectId=[string](Get-OptionalPropertyValue $safety 'ExpectedUserObjectId');expectedUserPrincipalName=[string](Get-OptionalPropertyValue $safety 'ExpectedUserPrincipalName');expectedProfilePath=[string](Get-OptionalPropertyValue $safety 'ExpectedProfilePath');expectedComputerName=[string](Get-OptionalPropertyValue $safety 'ExpectedComputerName')
        }
        policy=[ordered]@{bundleReverified=$true;authorizationFresh=$true;recoveryCredentialUsable=$true;bitLockerRecoveryEvidenceVerified=$true;sourceHybridInvariantVerified=$true;freshPreflightPassed=$true;migrationStarted=$false;successGroupTouched=$false}
    }
    $gateSha=Write-NG0011ImmutableRecord -Directory $gateFull -RecordName $script:NG0011GateRecordName -Record $gate
    Assert-NG0011RestrictedDirectoryAcl -Path $gateFull -OperatorSid $operatorSid

    Write-Host ''
    Write-Host 'NG atomic 0011 destructive-lab gate: PASS'
    Write-Host "Computer:               $env:COMPUTERNAME"
    Write-Host "DeviceId:               $($sourceAfter.dsreg.DeviceId)"
    Write-Host "TenantId:               $($sourceAfter.dsreg.TenantId)"
    Write-Host "Source user:            $($bundle.expectedSourceUserPrincipalName)"
    Write-Host "BundleId:               $($bundle.bundleId)"
    Write-Host "0010 Commit SHA-256:    $($control.authorization.authorization0010.commitRecordSha256)"
    Write-Host "Recovery account:       $($recoveryAccount.Name) (credential usable)"
    Write-Host "BitLocker protector count: $($bitLockerEvidence.recoveryPasswordProtectorCount)"
    Write-Host "BitLocker protector IDs:   $(@($bitLockerEvidence.recoveryPasswordProtectorIds) -join ', ')"
    Write-Host "Gate record SHA-256:    $gateSha"
    Write-Host "Gate expires:           $($gate.expiresUtc)"
    Write-Host "Gate evidence:          $gateFull"
    Write-Host ''
    Write-Host 'No migration was started.'
    Write-Host 'Independent gate verification command:'
    Write-Host "  & '$PSScriptRoot\Test-NGDestructiveLabGateEvidence.ps1' -ControlPackagePath '$($control.root)' -BundlePath '$($bundle.path)' -GateEvidencePath '$gateFull'"
    Write-Host ''
    Write-Host 'If every value remains correct, the explicit destructive launcher command is:'
    Write-Host "  & '$PSScriptRoot\Invoke-NGDestructiveLabLaunch.ps1' -ControlPackagePath '$($control.root)' -BundlePath '$($bundle.path)' -GateEvidencePath '$gateFull' -GateRecordSha256 $gateSha -ConfirmBundleId $($bundle.bundleId) -ConfirmDeviceId $($sourceAfter.dsreg.DeviceId) -ConfirmComputerName '$env:COMPUTERNAME' -Execute"
}
catch {
    try { Remove-Item -LiteralPath $gateFull -Recurse -Force -ErrorAction Stop } catch {}
    throw
}
