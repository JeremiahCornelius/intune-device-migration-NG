<#
.SYNOPSIS
    Builds the atomic 0011 destructive-lab control package.

.DESCRIPTION
    Creates a protected, non-secret control package bound to one exact final
    execution bundle and one complete atomic 0010 Stage -> Review -> Commit
    authorization chain. The package contains only atomic 0011 endpoint control
    tooling plus the atomic 0009 bundle verifier.

    This builder never starts migration.

.NOTES
    Atomic 0011. Windows PowerShell 5.1 compatible.
#>

[CmdletBinding()]
param(
    [Parameter()][AllowEmptyString()][string]$RepositoryRoot='',
    [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$BundlePath,
    [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$AuthorizationEvidencePath,
    [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$OutputPath,
    [Parameter()][ValidateRange(30,1440)][int]$AuthorizationLifetimeMinutes=480
)

Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'

if($PSVersionTable.PSEdition -ne 'Desktop' -or $PSVersionTable.PSVersion.Major -ne 5){ throw "Atomic 0011 requires Windows PowerShell 5.1. Observed $($PSVersionTable.PSEdition) $($PSVersionTable.PSVersion)." }

if([string]::IsNullOrWhiteSpace($RepositoryRoot)){
    if([string]::IsNullOrWhiteSpace($PSScriptRoot)){ throw 'RepositoryRoot omitted and PSScriptRoot unavailable.' }
    $RepositoryRoot=Split-Path -Path $PSScriptRoot -Parent
}
$commonPath=Join-Path $RepositoryRoot 'lab\NG.DestructiveLab.Common.ps1'
if(-not (Test-Path -LiteralPath $commonPath -PathType Leaf)){ throw "Atomic 0011 common helper missing: '$commonPath'." }
. $commonPath

$repo=Get-NG0011RepositoryProvenance -RepositoryRoot $RepositoryRoot
$bundleVerifier=Join-Path $repo.root 'lab\Test-NGLabExecutionBundle.ps1'
$authorizationVerifier=Join-Path $repo.root 'lab\Test-NGMigrationAuthorizationEvidence.ps1'
$bundle=Get-NG0011BundleEvidence -BundlePath $BundlePath -BundleVerifierPath $bundleVerifier
$authEvidence=Get-NG0011ResolvedDirectory -Path $AuthorizationEvidencePath -Purpose 'Authorization evidence'

if(Test-NG0011PathInsideDirectory -ChildPath $bundle.path -ParentPath $repo.root){ throw 'Execution bundle must be outside the repository.' }
if(Test-NG0011PathInsideDirectory -ChildPath $authEvidence -ParentPath $repo.root){ throw 'Authorization evidence must be outside the repository.' }
if($bundle.repositoryCommit -ne $repo.commit -or $bundle.repositoryTree -ne $repo.tree){ throw "Final execution bundle was not built from the current clean main HEAD/tree. Bundle=$($bundle.repositoryCommit)/$($bundle.repositoryTree); repo=$($repo.commit)/$($repo.tree)." }

Invoke-NG0011ChildPowerShell -ScriptPath $authorizationVerifier -Arguments @('-BundlePath',$bundle.path,'-EvidencePath',$authEvidence,'-RequireCommit')
$stage=Read-NG0011Record -Directory $authEvidence -RecordName 'STAGE-RECORD.json'
$review=Read-NG0011Record -Directory $authEvidence -RecordName 'REVIEW-RECORD.json'
$commit=Read-NG0011Record -Directory $authEvidence -RecordName 'COMMIT-RECORD.json'

if([string]$commit.Record.bundle.bundleId -ine $bundle.bundleId -or [string]$commit.Record.bundle.manifestSha256 -ine $bundle.manifestSha256){ throw 'Atomic 0010 Commit evidence is not bound to the supplied execution bundle.' }
if([string]$commit.Record.controller.repositoryCommit -ine $repo.commit -or [string]$commit.Record.controller.repositoryTree -ine $repo.tree){ throw 'Atomic 0010 Commit evidence is not bound to the current final repository state.' }
if(-not [bool]$commit.Record.membershipAfter.stage -or -not [bool]$commit.Record.membershipAfter.commit){ throw 'Atomic 0010 Commit evidence does not end with Stage=True, Commit=True.' }

$outputFull=[IO.Path]::GetFullPath($OutputPath).TrimEnd([char[]]@('\','/'))
if([string]::IsNullOrWhiteSpace($outputFull) -or $outputFull -eq [IO.Path]::GetPathRoot($outputFull).TrimEnd([char[]]@('\','/'))){ throw "Invalid OutputPath '$OutputPath'." }
if(Test-Path -LiteralPath $outputFull){ throw "OutputPath already exists: '$outputFull'." }
if(Test-NG0011PathInsideDirectory -ChildPath $outputFull -ParentPath $repo.root){ throw 'Control package output must be outside repository.' }
if(Test-NG0011PathInsideDirectory -ChildPath $outputFull -ParentPath $bundle.path){ throw 'Control package output must not be inside execution bundle.' }
if(Test-NG0011PathInsideDirectory -ChildPath $outputFull -ParentPath $authEvidence){ throw 'Control package output must not be inside authorization evidence.' }

$created=$false
try {
    New-Item -Path $outputFull -ItemType Directory -ErrorAction Stop | Out-Null; $created=$true
    $operatorSid=Set-NG0011RestrictedDirectoryAcl -Path $outputFull
    $payloadPath=Join-Path $outputFull 'payload'; New-Item -Path $payloadPath -ItemType Directory -ErrorAction Stop | Out-Null

    $payloadRepoPaths=@(
        'lab/NG.DestructiveLab.Common.ps1',
        'lab/Invoke-NGDestructiveLabGate.ps1',
        'lab/Test-NGDestructiveLabGateEvidence.ps1',
        'lab/Invoke-NGDestructiveLabLaunch.ps1',
        'lab/Invoke-NGDestructiveLabLaunchWorker.ps1',
        'lab/Export-NGDestructiveLabEvidence.ps1',
        'lab/Test-NGLabExecutionBundle.ps1'
    )
    $records=[System.Collections.Generic.List[object]]::new()
    foreach($relative in $payloadRepoPaths){
        [void](Invoke-NG0011Git -Repository $repo.root -Arguments @('ls-files','--error-unmatch','--',$relative))
        $source=Join-Path $repo.root $relative; if(-not (Test-Path -LiteralPath $source -PathType Leaf)){ throw "Control runtime file missing: '$relative'." }
        $name=Split-Path $relative -Leaf; $dest=Join-Path $payloadPath $name; Copy-Item -LiteralPath $source -Destination $dest -Force -ErrorAction Stop
        $sha=Get-NG0011Sha256 $dest; $blob=Invoke-NG0011Git -Repository $repo.root -Arguments @('rev-parse',"HEAD:$relative")
        $records.Add([pscustomobject][ordered]@{name=$name;repositoryPath=$relative;gitBlobId=$blob.ToLowerInvariant();sizeBytes=[Int64](Get-Item $dest).Length;sha256=$sha})
    }

    $now=[DateTime]::UtcNow
    $windowsIdentity=[Security.Principal.WindowsIdentity]::GetCurrent()
    $runAuthorization=[ordered]@{
        schemaVersion='1.0'; atomic='0011'; recordType='RunAuthorization'; generatedUtc=$now.ToString('o'); notBeforeUtc=$now.AddMinutes(-5).ToString('o'); expiresUtc=$now.AddMinutes($AuthorizationLifetimeMinutes).ToString('o')
        builderOperator=[ordered]@{windowsAccount=[string]$windowsIdentity.Name;windowsSid=[string]$windowsIdentity.User.Value}
        repository=[ordered]@{expectedRepository=$script:NG0011ExpectedRepository;commit=$repo.commit;tree=$repo.tree}
        bundle=[ordered]@{bundleId=$bundle.bundleId;manifestSha256=$bundle.manifestSha256;configSha256=$bundle.configSha256;ppkgSha256=$bundle.ppkgSha256;expectedSourceUserPrincipalName=$bundle.expectedSourceUserPrincipalName;sourceTenantName=$bundle.sourceTenantName}
        authorization0010=[ordered]@{
            stageRecordSha256=$stage.Sha256;reviewRecordSha256=$review.Sha256;commitRecordSha256=$commit.Sha256
            tenantId=[string]$commit.Record.tenantId
            device=[ordered]@{objectId=[string]$commit.Record.device.objectId;deviceId=[string]$commit.Record.device.deviceId;displayName=[string]$commit.Record.device.displayName;operatingSystem=[string]$commit.Record.device.operatingSystem;trustType=[string]$commit.Record.device.trustType}
            groups=[ordered]@{stage=[ordered]@{objectId=[string]$commit.Record.groups.stage.objectId;displayName=[string]$commit.Record.groups.stage.displayName};commit=[ordered]@{objectId=[string]$commit.Record.groups.commit.objectId;displayName=[string]$commit.Record.groups.commit.displayName}}
            commitOperator=[ordered]@{account=[string]$commit.Record.operator.account;stageOperatorSid=[string]$stage.Record.operator.stageOperatorSid}
            committedMembership=[ordered]@{stage=[bool]$commit.Record.membershipAfter.stage;commit=[bool]$commit.Record.membershipAfter.commit}
        }
        policy=[ordered]@{migrationStarted=$false;successGroupTouched=$false;endpointGraphWriteAuthority=$false;recoveryPasswordStored=$false}
        nonce=[Guid]::NewGuid().ToString()
    }
    $authSha=Write-NG0011ImmutableRecord -Directory $outputFull -RecordName $script:NG0011RunAuthorizationName -Record $runAuthorization

    $ordered=@($records | Sort-Object name)
    $identity=[System.Collections.Generic.List[string]]::new(); $identity.Add("repositoryCommit=$($repo.commit)");$identity.Add("repositoryTree=$($repo.tree)");$identity.Add("bundleId=$($bundle.bundleId)");$identity.Add("authorizationCommitRecordSha256=$($commit.Sha256)")
    foreach($r in $ordered){$identity.Add("$($r.name)|$($r.sizeBytes)|$($r.sha256)")}
    $controlId=Get-NG0011StringSha256 -Value ($identity -join "`n")
    $manifest=[ordered]@{
        schemaVersion='1.0';atomic='0011';artifact='NGDestructiveLabControlPackage';generatedUtc=[DateTime]::UtcNow.ToString('o');controlIdAlgorithm='SHA-256';controlId=$controlId
        repository=[ordered]@{expectedRepository=$script:NG0011ExpectedRepository;originUrl=$repo.originUrl;branch=$repo.branch;commit=$repo.commit;tree=$repo.tree;trackedWorktreeClean=$true}
        binding=[ordered]@{bundleId=$bundle.bundleId;bundleManifestSha256=$bundle.manifestSha256;authorizationCommitRecordSha256=$commit.Sha256}
        runAuthorization=[ordered]@{name=$script:NG0011RunAuthorizationName;sha256=$authSha}
        payload=[ordered]@{root='payload';fileCount=$ordered.Count;files=$ordered}
        policy=[ordered]@{containsReusableSecrets=$false;containsRecoveryPassword=$false;startsMigration=$false;successGroupTouched=$false}
    }
    $manifestSha=Write-NG0011ImmutableRecord -Directory $outputFull -RecordName $script:NG0011ControlManifestName -Record $manifest
    Assert-NG0011RestrictedDirectoryAcl -Path $outputFull -OperatorSid $operatorSid
    [void](Test-NG0011ControlPackage -ControlPackagePath $outputFull -RequireFreshAuthorization)

    Write-Host ''
    Write-Host 'NG atomic 0011 destructive-lab control package created.'
    Write-Host "Control package:       $outputFull"
    Write-Host "Repository commit:     $($repo.commit)"
    Write-Host "Repository tree:       $($repo.tree)"
    Write-Host "BundleId:              $($bundle.bundleId)"
    Write-Host "0010 Commit SHA-256:   $($commit.Sha256)"
    Write-Host "ControlId:             $controlId"
    Write-Host "Control manifest SHA:  $manifestSha"
    Write-Host "Authorization expires: $($runAuthorization.expiresUtc)"
    Write-Host ''
    Write-Host 'No migration was started.'
}
catch {
    if($created -and (Test-Path -LiteralPath $outputFull -PathType Container)){ try{Remove-Item -LiteralPath $outputFull -Recurse -Force -ErrorAction Stop}catch{} }
    throw
}
