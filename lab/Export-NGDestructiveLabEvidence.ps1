<#
.SYNOPSIS
    Exports a bounded evidence package that excludes known sensitive runtime inputs for one atomic 0011 lab attempt.

.DESCRIPTION
    Collects local migration state, join state, profile mappings, task metadata,
    MDM certificate metadata, selected migration/provisioning logs, selected
    Windows event logs, and the 0011 control/gate/launch records. It never copies
    config.json, provisioning packages, private keys, recovery passwords, or
    reusable Graph credentials and performs no Graph calls or migration writes.

.NOTES
    Atomic 0011. Windows PowerShell 5.1 compatible.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$ControlPackagePath,
    [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$BundlePath,
    [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$GateEvidencePath,
    [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$OutputPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
if($PSVersionTable.PSEdition -ne 'Desktop' -or $PSVersionTable.PSVersion.Major -ne 5){ throw "Atomic 0011 evidence export requires Windows PowerShell 5.1." }
$commonPath=Join-Path $PSScriptRoot 'NG.DestructiveLab.Common.ps1'; if(-not (Test-Path -LiteralPath $commonPath -PathType Leaf)){ throw "Atomic 0011 common helper missing: '$commonPath'." }; . $commonPath

$control=Test-NG0011ControlPackage -ControlPackagePath $ControlPackagePath
$bundle=Get-NG0011BundleEvidence -BundlePath $BundlePath -BundleVerifierPath (Join-Path $control.payload 'Test-NGLabExecutionBundle.ps1')
Assert-NG0011BundleAuthorizationBinding -BundleEvidence $bundle -RunAuthorization $control.authorization
$gateRoot=Get-NG0011ResolvedDirectory -Path $GateEvidencePath -Purpose 'Gate evidence'
$output=[IO.Path]::GetFullPath($OutputPath).TrimEnd([char[]]@('\','/'))
if(Test-Path -LiteralPath $output){ throw "Evidence OutputPath already exists: '$output'." }
if((Test-NG0011PathInsideDirectory -ChildPath $output -ParentPath $bundle.path) -or (Test-NG0011PathInsideDirectory -ChildPath $output -ParentPath $control.root) -or (Test-NG0011PathInsideDirectory -ChildPath $output -ParentPath $gateRoot)){ throw 'Evidence output must be separate from bundle/control/gate directories.' }

New-Item -Path $output -ItemType Directory -ErrorAction Stop | Out-Null
$operatorSid=Set-NG0011RestrictedDirectoryAcl -Path $output
$files=[System.Collections.Generic.List[object]]::new()

function Add-EvidenceFile {
    param([Parameter(Mandatory)][string]$Source,[Parameter(Mandatory)][string]$RelativeName)
    if(-not (Test-Path -LiteralPath $Source -PathType Leaf)){ return }
    if([IO.Path]::GetFileName($Source) -ieq 'config.json' -or [IO.Path]::GetExtension($Source) -ieq '.ppkg'){ throw "Secret/sensitive runtime input was selected for export and was blocked: '$Source'." }
    $dest=Join-Path $output $RelativeName; $parent=Split-Path $dest -Parent; if(-not (Test-Path -LiteralPath $parent)){ New-Item -Path $parent -ItemType Directory -Force | Out-Null }
    Copy-Item -LiteralPath $Source -Destination $dest -Force -ErrorAction Stop
}
function Write-EvidenceJson {
    param([Parameter(Mandatory)][string]$RelativeName,[Parameter(Mandatory)]$Object)
    $dest=Join-Path $output $RelativeName; $parent=Split-Path $dest -Parent; if(-not (Test-Path -LiteralPath $parent)){New-Item -Path $parent -ItemType Directory -Force|Out-Null}
    Write-NG0011Utf8NoBom -Path $dest -Content (($Object|ConvertTo-Json -Depth 16)+"`n")
}
function Write-EvidenceText {
    param([Parameter(Mandatory)][string]$RelativeName,[Parameter(Mandatory)][string[]]$Lines)
    $dest=Join-Path $output $RelativeName; $parent=Split-Path $dest -Parent; if(-not (Test-Path -LiteralPath $parent)){New-Item -Path $parent -ItemType Directory -Force|Out-Null}
    Write-NG0011Utf8NoBom -Path $dest -Content (($Lines -join "`r`n")+"`r`n")
}

try {
    foreach($name in @($script:NG0011RunAuthorizationName,$script:NG0011RunAuthorizationHashName,$script:NG0011GateRecordName,$script:NG0011GateRecordHashName,$script:NG0011LaunchIntentName,$script:NG0011LaunchIntentHashName,$script:NG0011LaunchObservationName,$script:NG0011LaunchObservationHashName,$script:NG0011SystemLaunchName,$script:NG0011SystemLaunchHashName)){
        Add-EvidenceFile -Source (Join-Path $gateRoot $name) -RelativeName ("authorization\"+$name)
    }
    foreach($name in @($script:NG0011ControlManifestName,$script:NG0011ControlManifestHashName)){
        Add-EvidenceFile -Source (Join-Path $control.root $name) -RelativeName ("control\"+$name)
    }
    Add-EvidenceFile -Source $bundle.manifestPath -RelativeName 'bundle\EXECUTION-MANIFEST.json'
    Add-EvidenceFile -Source (Join-Path $bundle.path 'EXECUTION-MANIFEST.sha256') -RelativeName 'bundle\EXECUTION-MANIFEST.sha256'

    $dsreg=@(& "$env:SystemRoot\System32\dsregcmd.exe" /status 2>&1); Write-EvidenceText -RelativeName 'endpoint\dsregcmd-status.txt' -Lines @($dsreg|ForEach-Object{[string]$_})
    $safetyPath='HKLM:\SOFTWARE\IntuneMigration\Safety'; if(Test-Path -LiteralPath $safetyPath){
        $s=Get-ItemProperty -LiteralPath $safetyPath -ErrorAction Stop
        $clean=[ordered]@{}; foreach($p in $s.PSObject.Properties){ if($p.Name -notmatch '^PS(Path|ParentPath|ChildName|Drive|Provider)$'){ $clean[$p.Name]=$p.Value } }
        Write-EvidenceJson -RelativeName 'endpoint\migration-safety-state.json' -Object $clean
    }
    $migrationRoot='HKLM:\SOFTWARE\IntuneMigration'; if(Test-Path -LiteralPath $migrationRoot){
        $m=Get-ItemProperty -LiteralPath $migrationRoot -ErrorAction Stop; $handoff=[ordered]@{}
        foreach($p in $m.PSObject.Properties){ if($p.Name -match '^(OLD_|NEW_)'){ $handoff[$p.Name]=$p.Value } }
        Write-EvidenceJson -RelativeName 'endpoint\migration-handoff.json' -Object $handoff
    }

    $profiles=@(Get-CimInstance Win32_UserProfile -ErrorAction Stop | Select-Object SID,LocalPath,Loaded,Special); Write-EvidenceJson -RelativeName 'endpoint\user-profiles.json' -Object $profiles
    $certs=@(Get-ChildItem Cert:\LocalMachine\My -ErrorAction Stop | Where-Object{$_.Issuer -match 'Microsoft Intune MDM Device CA'} | ForEach-Object{[pscustomobject]@{Subject=$_.Subject;Issuer=$_.Issuer;Thumbprint=$_.Thumbprint;NotBefore=$_.NotBefore.ToUniversalTime().ToString('o');NotAfter=$_.NotAfter.ToUniversalTime().ToString('o');HasPrivateKey=[bool]$_.HasPrivateKey}}); Write-EvidenceJson -RelativeName 'endpoint\intune-mdm-certificates-metadata.json' -Object $certs

    $taskRecords=[System.Collections.Generic.List[object]]::new(); foreach($taskName in @('NG-DestructiveLab-Start','Reboot','postMigrate','postMigrateUserVerify','GroupTag')){
        $task=Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue; $info=Get-ScheduledTaskInfo -TaskName $taskName -ErrorAction SilentlyContinue
        if($task){$taskRecords.Add([pscustomobject]@{TaskName=$taskName;State=[string]$task.State;PrincipalUserId=[string]$task.Principal.UserId;PrincipalLogonType=[string]$task.Principal.LogonType;PrincipalRunLevel=[string]$task.Principal.RunLevel;LastRunTime=if($info){$info.LastRunTime.ToString('o')}else{''};LastTaskResult=if($info){[int]$info.LastTaskResult}else{$null};NextRunTime=if($info){$info.NextRunTime.ToString('o')}else{''}})}
    }; Write-EvidenceJson -RelativeName 'endpoint\scheduled-tasks.json' -Object @($taskRecords)

    $logPath=[string]$bundle.config.logPath
    if(-not [string]::IsNullOrWhiteSpace($logPath) -and (Test-Path -LiteralPath $logPath -PathType Container)){
        foreach($name in @('preflight.log','startMigrate.log','reboot.log','postMigrate.log')){Add-EvidenceFile -Source (Join-Path $logPath $name) -RelativeName ("logs\"+$name)}
    }
    $preflightPath=Join-Path ([string]$bundle.config.localPath) 'preflight.json'; Add-EvidenceFile -Source $preflightPath -RelativeName 'logs\preflight.json'
    $prov=Join-Path ([string]$bundle.config.localPath) 'ProvisioningLogs'; if(Test-Path -LiteralPath $prov -PathType Container){
        foreach($item in @(Get-ChildItem -LiteralPath $prov -File -Recurse -ErrorAction SilentlyContinue)){
            if($item.Name -ine 'config.json' -and $item.Extension -ine '.ppkg'){ $relative=$item.FullName.Substring($prov.Length).TrimStart('\'); Add-EvidenceFile -Source $item.FullName -RelativeName (Join-Path 'provisioning-logs' $relative) }
        }
    }

    $eventRoot=Join-Path $output 'event-logs'; New-Item -Path $eventRoot -ItemType Directory -Force|Out-Null
    foreach($logName in @('Microsoft-Windows-User Device Registration/Admin','Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Admin','Microsoft-Windows-Provisioning-Diagnostics-Provider/Admin')){
        try{ $safe=($logName -replace '[\\/:*?"<>| ]','_')+'.evtx'; & "$env:SystemRoot\System32\wevtutil.exe" epl $logName (Join-Path $eventRoot $safe) /ow:true 2>$null }catch{}
    }

    $all=@(Get-ChildItem -LiteralPath $output -File -Recurse -ErrorAction Stop | Where-Object{$_.Name -notin @('EVIDENCE-MANIFEST.json','EVIDENCE-MANIFEST.sha256')})
    foreach($item in $all){$relative=$item.FullName.Substring($output.Length).TrimStart('\');$files.Add([pscustomobject][ordered]@{path=$relative;sizeBytes=[Int64]$item.Length;sha256=Get-NG0011Sha256 $item.FullName})}
    $manifest=[ordered]@{schemaVersion='1.0';atomic='0011';artifact='NGDestructiveLabEvidenceExport';generatedUtc=[DateTime]::UtcNow.ToString('o');repository=[ordered]@{commit=$bundle.repositoryCommit;tree=$bundle.repositoryTree};binding=[ordered]@{controlId=[string]$control.manifest.controlId;bundleId=$bundle.bundleId;authorizationCommitRecordSha256=[string]$control.authorization.authorization0010.commitRecordSha256};policy=[ordered]@{configCopied=$false;ppkgCopied=$false;privateKeysCopied=$false;recoveryPasswordsCopied=$false;graphCalled=$false;migrationStateModified=$false};files=@($files|Sort-Object path)}
    $manifestSha=Write-NG0011ImmutableRecord -Directory $output -RecordName 'EVIDENCE-MANIFEST.json' -Record $manifest
    Assert-NG0011RestrictedDirectoryAcl -Path $output -OperatorSid $operatorSid
    Write-Host ''
    Write-Host 'NG atomic 0011 evidence export: PASS'
    Write-Host "Output:                $output"
    Write-Host "BundleId:              $($bundle.bundleId)"
    Write-Host "Evidence files:        $($files.Count)"
    Write-Host "Manifest SHA-256:      $manifestSha"
    Write-Host 'config.json / PPKG / private keys / recovery passwords were not copied.'
    Write-Warning 'The exported logs and event logs still contain sensitive tenant, user, device, and operational metadata. Protect the complete evidence directory.'
}
catch{ throw "Evidence export failed. Preserve the partial output for manual inspection; do not treat it as a complete evidence package. $($_.Exception.Message)" }
