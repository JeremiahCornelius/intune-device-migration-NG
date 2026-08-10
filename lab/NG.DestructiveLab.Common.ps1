<#
.SYNOPSIS
    Shared non-migration helpers for atomic 0011 destructive-lab control tooling.

.DESCRIPTION
    Centralizes cryptographic record verification, ACL checks, repository and
    execution-bundle provenance, endpoint source-state checks, recovery
    credential validation, BitLocker recovery evidence, power/time/network
    readiness, and immutable JSON evidence handling.

    This helper does not start migration, change Entra/Intune group membership,
    alter device join state, install provisioning packages, or change profile
    ownership.

.NOTES
    Atomic 0011. Windows PowerShell 5.1 compatible.
#>

Set-StrictMode -Version Latest

$script:NG0011SchemaVersion = '1.0'
$script:NG0011ExpectedRepository = 'JeremiahCornelius/intune-device-migration-NG'
$script:NG0011ControlManifestName = 'CONTROL-MANIFEST.json'
$script:NG0011ControlManifestHashName = 'CONTROL-MANIFEST.sha256'
$script:NG0011RunAuthorizationName = 'RUN-AUTHORIZATION.json'
$script:NG0011RunAuthorizationHashName = 'RUN-AUTHORIZATION.sha256'
$script:NG0011GateRecordName = 'DESTRUCTIVE-LAB-GATE.json'
$script:NG0011GateRecordHashName = 'DESTRUCTIVE-LAB-GATE.sha256'
$script:NG0011LaunchIntentName = 'LAUNCH-INTENT.json'
$script:NG0011LaunchIntentHashName = 'LAUNCH-INTENT.sha256'
$script:NG0011LaunchObservationName = 'LAUNCH-OBSERVATION.json'
$script:NG0011LaunchObservationHashName = 'LAUNCH-OBSERVATION.sha256'
$script:NG0011SystemLaunchName = 'SYSTEM-LAUNCH.json'
$script:NG0011SystemLaunchHashName = 'SYSTEM-LAUNCH.sha256'
$script:NG0011SuccessGroupId = '093f5a96-eeb0-48bd-b9b7-05b975d8c287'
$script:NG0011SuccessGroupName = 'PROD-EN-ENTRA-MIGRATION-SUCCESS'

function Get-NG0011Sha256 {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
}

function Get-NG0011StringSha256 {
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Value)
    $bytes = [Text.Encoding]::UTF8.GetBytes($Value)
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        return (($sha.ComputeHash($bytes) | ForEach-Object { $_.ToString('x2') }) -join '')
    }
    finally { $sha.Dispose() }
}

function Write-NG0011Utf8NoBom {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][AllowEmptyString()][string]$Content
    )
    $encoding = New-Object Text.UTF8Encoding($false)
    [IO.File]::WriteAllText($Path, $Content, $encoding)
}

function Get-NG0011ResolvedDirectory {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path,[Parameter(Mandatory)][string]$Purpose)
    if (-not (Test-Path -LiteralPath $Path -PathType Container)) { throw "$Purpose directory does not exist: '$Path'." }
    return [IO.Path]::GetFullPath((Resolve-Path -LiteralPath $Path -ErrorAction Stop).ProviderPath).TrimEnd([char[]]@('\','/'))
}

function Get-NG0011ResolvedFile {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path,[Parameter(Mandatory)][string]$Purpose)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { throw "$Purpose file does not exist: '$Path'." }
    return [IO.Path]::GetFullPath((Resolve-Path -LiteralPath $Path -ErrorAction Stop).ProviderPath)
}

function Test-NG0011PathInsideDirectory {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$ChildPath,[Parameter(Mandatory)][string]$ParentPath)
    $child = [IO.Path]::GetFullPath($ChildPath).TrimEnd([char[]]@('\','/'))
    $parent = [IO.Path]::GetFullPath($ParentPath).TrimEnd([char[]]@('\','/'))
    if ($child -ieq $parent) { return $true }
    return $child.StartsWith($parent + [IO.Path]::DirectorySeparatorChar,[StringComparison]::OrdinalIgnoreCase)
}

function Get-NG0011ObjectProperty {
    [CmdletBinding()]
    param([Parameter()][AllowNull()]$Object,[Parameter(Mandatory)][string]$Name,[Parameter()]$Default=$null)
    if ($null -eq $Object) { return $Default }
    if ($Object -is [System.Collections.IDictionary]) {
        if ($Object.Contains($Name)) { return $Object[$Name] }
        return $Default
    }
    $property = $Object.PSObject.Properties[$Name]
    if ($null -eq $property) { return $Default }
    return $property.Value
}

function ConvertTo-NG0011GuidString {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Value,[Parameter(Mandatory)][string]$Purpose)
    $guid = [Guid]::Empty
    if (-not [Guid]::TryParse($Value,[ref]$guid)) { throw "$Purpose is not a valid GUID: '$Value'." }
    return $guid.ToString().ToLowerInvariant()
}

function ConvertTo-NG0011Utc {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Value,[Parameter(Mandatory)][string]$Purpose)
    try {
        return [DateTime]::Parse($Value,[Globalization.CultureInfo]::InvariantCulture,[Globalization.DateTimeStyles]::RoundtripKind).ToUniversalTime()
    }
    catch { throw "Unable to parse $Purpose timestamp '$Value'." }
}

function Invoke-NG0011Git {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Repository,[Parameter(Mandatory)][string[]]$Arguments)
    $output = @(& git -C $Repository @Arguments 2>&1)
    if ($LASTEXITCODE -ne 0) {
        $detail = ($output | ForEach-Object { [string]$_ }) -join [Environment]::NewLine
        throw "git $($Arguments -join ' ') failed with exit code $LASTEXITCODE. $detail"
    }
    return (($output | ForEach-Object { [string]$_ }) -join "`n").Trim()
}

function Get-NG0011RepositoryProvenance {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$RepositoryRoot)
    if (-not (Get-Command git -ErrorAction SilentlyContinue)) { throw 'git is required and was not found in PATH.' }
    $repo = Get-NG0011ResolvedDirectory -Path $RepositoryRoot -Purpose 'Repository'
    $top = [IO.Path]::GetFullPath((Invoke-NG0011Git -Repository $repo -Arguments @('rev-parse','--show-toplevel'))).TrimEnd([char[]]@('\','/'))
    if ($top -ine $repo) { throw "RepositoryRoot '$repo' is not Git top-level '$top'." }
    $origin = Invoke-NG0011Git -Repository $repo -Arguments @('remote','get-url','origin')
    if ($origin -notmatch '(?i)(?:[:/])JeremiahCornelius/intune-device-migration-NG(?:\.git)?$') { throw "Unexpected repository origin '$origin'." }
    $branch = Invoke-NG0011Git -Repository $repo -Arguments @('rev-parse','--abbrev-ref','HEAD')
    if ($branch -ne 'main') { throw "Atomic 0011 tooling requires branch main; observed '$branch'." }
    $status = Invoke-NG0011Git -Repository $repo -Arguments @('status','--porcelain=v1','--untracked-files=no')
    if (-not [string]::IsNullOrWhiteSpace($status)) { throw "Tracked repository files are modified.`n$status" }
    return [pscustomobject][ordered]@{
        root=$repo; originUrl=$origin; branch=$branch
        commit=(Invoke-NG0011Git -Repository $repo -Arguments @('rev-parse','HEAD')).ToLowerInvariant()
        tree=(Invoke-NG0011Git -Repository $repo -Arguments @('rev-parse','HEAD^{tree}')).ToLowerInvariant()
    }
}

function Set-NG0011RestrictedDirectoryAcl {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)
    $identity=[Security.Principal.WindowsIdentity]::GetCurrent()
    if (-not $identity -or -not $identity.User) { throw 'Unable to resolve current Windows SID.' }
    $sid=[string]$identity.User.Value
    $grants=@("*$($sid):(OI)(CI)F",'*S-1-5-18:(OI)(CI)F','*S-1-5-32-544:(OI)(CI)F') | Select-Object -Unique
    $icaclsArgs=@($Path,'/inheritance:r','/grant:r')+$grants+@('/T','/C')
    & "$env:SystemRoot\System32\icacls.exe" @icaclsArgs | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "icacls failed for '$Path' with exit code $LASTEXITCODE." }
    return $sid
}

function Assert-NG0011RestrictedDirectoryAcl {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path,[Parameter(Mandatory)][string]$OperatorSid)
    $acl=Get-Acl -LiteralPath $Path -ErrorAction Stop
    if (-not $acl.AreAccessRulesProtected) { throw "Directory inherits access rules: '$Path'." }
    $expected=@($OperatorSid,'S-1-5-18','S-1-5-32-544') | ForEach-Object { $_.ToUpperInvariant() } | Select-Object -Unique
    $rules=@($acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]))
    foreach($rule in $rules){
        $sid=([string]$rule.IdentityReference.Value).ToUpperInvariant()
        if($expected -notcontains $sid){ throw "ACL contains unexpected principal SID '$sid'." }
        if([string]$rule.AccessControlType -ne 'Allow'){ throw "ACL contains non-Allow rule for '$sid'." }
        $full=[Security.AccessControl.FileSystemRights]::FullControl
        if(($rule.FileSystemRights -band $full) -ne $full){ throw "ACL does not grant FullControl to '$sid'." }
    }
    foreach($sid in $expected){ if(@($rules | Where-Object { ([string]$_.IdentityReference.Value).ToUpperInvariant() -eq $sid }).Count -eq 0){ throw "ACL missing required SID '$sid'." } }
}

function Write-NG0011ImmutableRecord {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Directory,[Parameter(Mandatory)][string]$RecordName,[Parameter(Mandatory)]$Record)
    $recordPath=Join-Path $Directory $RecordName
    $sidecarName=[IO.Path]::GetFileNameWithoutExtension($RecordName)+'.sha256'
    $sidecarPath=Join-Path $Directory $sidecarName
    if((Test-Path -LiteralPath $recordPath) -or (Test-Path -LiteralPath $sidecarPath)){ throw "Refusing to overwrite existing evidence '$RecordName'." }
    $json=$Record | ConvertTo-Json -Depth 16
    Write-NG0011Utf8NoBom -Path $recordPath -Content ($json+"`n")
    $sha=Get-NG0011Sha256 -Path $recordPath
    Write-NG0011Utf8NoBom -Path $sidecarPath -Content ("$sha  $RecordName`n")
    return $sha
}

function Read-NG0011Record {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Directory,[Parameter(Mandatory)][string]$RecordName)
    $recordPath=Join-Path $Directory $RecordName
    $sidecarName=[IO.Path]::GetFileNameWithoutExtension($RecordName)+'.sha256'
    $sidecarPath=Join-Path $Directory $sidecarName
    if(-not (Test-Path -LiteralPath $recordPath -PathType Leaf)){ throw "Record missing: '$recordPath'." }
    if(-not (Test-Path -LiteralPath $sidecarPath -PathType Leaf)){ throw "Sidecar missing: '$sidecarPath'." }
    $text=(Get-Content -LiteralPath $sidecarPath -Raw -ErrorAction Stop).Trim()
    $escaped=[Regex]::Escape($RecordName)
    if($text -notmatch "^([0-9a-fA-F]{64})  $escaped$"){ throw "Invalid sidecar format: '$sidecarPath'." }
    $expected=$Matches[1].ToLowerInvariant(); $actual=Get-NG0011Sha256 -Path $recordPath
    if($actual -ne $expected){ throw "SHA-256 mismatch for '$RecordName'." }
    try { $record=Get-Content -LiteralPath $recordPath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop }
    catch { throw "Invalid JSON in '$RecordName': $($_.Exception.Message)" }
    return [pscustomobject]@{Record=$record;Sha256=$actual;Path=$recordPath;SidecarPath=$sidecarPath}
}

function Invoke-NG0011ChildPowerShell {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$ScriptPath,[Parameter(Mandatory)][string[]]$Arguments)
    $ps=Join-Path $PSHOME 'powershell.exe'
    if(-not (Test-Path -LiteralPath $ps -PathType Leaf)){ throw "Windows PowerShell executable not found at '$ps'." }
    & $ps -NoProfile -ExecutionPolicy Bypass -File $ScriptPath @Arguments
    $code=$LASTEXITCODE
    if($code -ne 0){ throw "Child verifier '$ScriptPath' failed with exit code $code." }
}

function Get-NG0011BundleEvidence {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$BundlePath,[Parameter(Mandatory)][string]$BundleVerifierPath)
    $bundle=Get-NG0011ResolvedDirectory -Path $BundlePath -Purpose 'Execution bundle'
    Invoke-NG0011ChildPowerShell -ScriptPath $BundleVerifierPath -Arguments @('-BundlePath',$bundle)
    $manifestPath=Join-Path $bundle 'EXECUTION-MANIFEST.json'
    $manifest=Get-Content -LiteralPath $manifestPath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
    $configName=[string]$manifest.inputs.config.payloadName
    $configPath=Join-Path (Join-Path $bundle 'payload') $configName
    $config=Get-Content -LiteralPath $configPath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
    return [pscustomobject][ordered]@{
        path=$bundle; manifest=$manifest; manifestPath=$manifestPath; manifestSha256=(Get-NG0011Sha256 $manifestPath)
        bundleId=([string]$manifest.bundleId).ToLowerInvariant(); repositoryCommit=([string]$manifest.repository.commit).ToLowerInvariant(); repositoryTree=([string]$manifest.repository.tree).ToLowerInvariant()
        configPath=$configPath; configSha256=(Get-NG0011Sha256 $configPath); config=$config
        ppkgSha256=([string]$manifest.inputs.provisioningPackage.sha256).ToLowerInvariant()
        expectedSourceUserPrincipalName=[string]$config.safety.expectedSourceUserPrincipalName
        sourceTenantName=[string]$config.sourceTenant.tenantName
    }
}

function Test-NG0011ControlPackage {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$ControlPackagePath,[switch]$RequireFreshAuthorization)
    $root=Get-NG0011ResolvedDirectory -Path $ControlPackagePath -Purpose 'Control package'
    $manifestResult=Read-NG0011Record -Directory $root -RecordName $script:NG0011ControlManifestName
    $manifest=$manifestResult.Record
    if([string]$manifest.schemaVersion -ne '1.0' -or [string]$manifest.atomic -ne '0011' -or [string]$manifest.artifact -ne 'NGDestructiveLabControlPackage'){ throw 'Unsupported CONTROL-MANIFEST.json.' }
    if([string]$manifest.payload.root -ne 'payload'){ throw "Control payload root must be 'payload'." }
    $payload=Join-Path $root 'payload'; if(-not (Test-Path -LiteralPath $payload -PathType Container)){ throw 'Control payload directory is missing.' }
    $records=@($manifest.payload.files); $items=@(Get-ChildItem -LiteralPath $payload -Force -ErrorAction Stop)
    if(@($items | Where-Object {$_.PSIsContainer}).Count -gt 0){ throw 'Control payload contains an unexpected subdirectory.' }
    if($items.Count -ne $records.Count){ throw 'Control payload file count differs from manifest.' }
    $actualNames=@($items | ForEach-Object {$_.Name} | Sort-Object); $expectedNames=@($records | ForEach-Object {[string]$_.name} | Sort-Object)
    if(($actualNames -join "`n") -cne ($expectedNames -join "`n")){ throw 'Control payload file set differs from manifest.' }
    foreach($record in $records){
        $path=Join-Path $payload ([string]$record.name); if((Get-NG0011Sha256 $path) -ne ([string]$record.sha256).ToLowerInvariant()){ throw "Control payload hash mismatch: '$($record.name)'." }
        if([Int64](Get-Item -LiteralPath $path).Length -ne [Int64]$record.sizeBytes){ throw "Control payload size mismatch: '$($record.name)'." }
    }
    $authResult=Read-NG0011Record -Directory $root -RecordName $script:NG0011RunAuthorizationName
    $auth=$authResult.Record
    if([string]$auth.schemaVersion -ne '1.0' -or [string]$auth.atomic -ne '0011' -or [string]$auth.recordType -ne 'RunAuthorization'){ throw 'Unsupported RUN-AUTHORIZATION.json.' }
    if($authResult.Sha256 -ne ([string]$manifest.runAuthorization.sha256).ToLowerInvariant()){ throw 'Run authorization hash does not match control manifest.' }
    $identity=[System.Collections.Generic.List[string]]::new(); $identity.Add("repositoryCommit=$($manifest.repository.commit)"); $identity.Add("repositoryTree=$($manifest.repository.tree)"); $identity.Add("bundleId=$($manifest.binding.bundleId)"); $identity.Add("authorizationCommitRecordSha256=$($manifest.binding.authorizationCommitRecordSha256)")
    foreach($r in @($records | Sort-Object name)){ $identity.Add("$($r.name)|$($r.sizeBytes)|$($r.sha256)") }
    $calculated=Get-NG0011StringSha256 -Value ($identity -join "`n")
    if($calculated -ne ([string]$manifest.controlId).ToLowerInvariant()){ throw 'ControlId deterministic recomputation failed.' }
    if($RequireFreshAuthorization){
        $now=[DateTime]::UtcNow; $nb=ConvertTo-NG0011Utc -Value ([string]$auth.notBeforeUtc) -Purpose 'RunAuthorization notBeforeUtc'; $exp=ConvertTo-NG0011Utc -Value ([string]$auth.expiresUtc) -Purpose 'RunAuthorization expiresUtc'
        if($now -lt $nb -or $now -gt $exp){ throw "Run authorization is outside its validity window ($($nb.ToString('o')) - $($exp.ToString('o')))." }
    }
    return [pscustomobject]@{root=$root;payload=$payload;manifest=$manifest;manifestSha256=$manifestResult.Sha256;authorization=$auth;authorizationSha256=$authResult.Sha256}
}

function Assert-NG0011BundleAuthorizationBinding {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$BundleEvidence,[Parameter(Mandatory)]$RunAuthorization)
    $pairs=@(
        @('BundleId',$BundleEvidence.bundleId,$RunAuthorization.bundle.bundleId),
        @('manifest SHA-256',$BundleEvidence.manifestSha256,$RunAuthorization.bundle.manifestSha256),
        @('repository commit',$BundleEvidence.repositoryCommit,$RunAuthorization.repository.commit),
        @('repository tree',$BundleEvidence.repositoryTree,$RunAuthorization.repository.tree),
        @('config SHA-256',$BundleEvidence.configSha256,$RunAuthorization.bundle.configSha256),
        @('PPKG SHA-256',$BundleEvidence.ppkgSha256,$RunAuthorization.bundle.ppkgSha256),
        @('expected source UPN',$BundleEvidence.expectedSourceUserPrincipalName,$RunAuthorization.bundle.expectedSourceUserPrincipalName)
    )
    foreach($p in $pairs){ if([string]$p[1] -ine [string]$p[2]){ throw "Execution bundle $($p[0]) does not match run authorization." } }
}

function Import-NG0011BundleCommon {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$BundleEvidence)
    $common=Join-Path (Join-Path $BundleEvidence.path 'payload') 'Migration.Common.ps1'
    if(-not (Test-Path -LiteralPath $common -PathType Leaf)){ throw "Bundled Migration.Common.ps1 is missing." }
    . $common
}

function Assert-NG0011HybridSourceBinding {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$RunAuthorization,[switch]$RequireInteractiveUser)
    $dsreg=Get-DsRegState
    if($dsreg.AzureAdJoined -ne 'YES' -or $dsreg.DomainJoined -ne 'YES'){ throw "Source device is not Hybrid Entra joined. AzureAdJoined=$($dsreg.AzureAdJoined), DomainJoined=$($dsreg.DomainJoined)." }
    if([string]$dsreg.TenantId -ine [string]$RunAuthorization.authorization0010.tenantId){ throw "Current TenantId '$($dsreg.TenantId)' differs from authorized tenant '$($RunAuthorization.authorization0010.tenantId)'." }
    if([string]$dsreg.DeviceId -ine [string]$RunAuthorization.authorization0010.device.deviceId){ throw "Current DeviceId '$($dsreg.DeviceId)' differs from authorized DeviceId '$($RunAuthorization.authorization0010.device.deviceId)'." }
    if([string]$env:COMPUTERNAME -ine [string]$RunAuthorization.authorization0010.device.displayName){ throw "Current computer name '$env:COMPUTERNAME' differs from authorized display name '$($RunAuthorization.authorization0010.device.displayName)'." }
    $interactive=$null
    if($RequireInteractiveUser){ $interactive=Get-InteractiveUserIdentity; if(-not $interactive.ProfileLoaded){ throw 'Intended source profile is not loaded.' } }
    return [pscustomobject]@{dsreg=$dsreg;interactiveUser=$interactive}
}


function Get-NG0011LiveLifecycleMembership {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$RunAuthorization,
        [Parameter()][switch]$UseDeviceCode
    )

    $identity=[Security.Principal.WindowsIdentity]::GetCurrent()
    if($identity.IsSystem){ throw 'Live lifecycle membership verification requires an interactive delegated operator and cannot run as LocalSystem.' }

    $module=Get-Module -ListAvailable -Name Microsoft.Graph.Authentication | Sort-Object Version -Descending | Select-Object -First 1
    if($null -eq $module){ throw 'Microsoft.Graph.Authentication is required for the final delegated live-membership check. Install it before the destructive-lab window; the launcher will not install modules automatically.' }
    Import-Module Microsoft.Graph.Authentication -RequiredVersion $module.Version -Force -ErrorAction Stop

    $tenantId=ConvertTo-NG0011GuidString -Value ([string]$RunAuthorization.authorization0010.tenantId) -Purpose 'authorized tenantId'
    $deviceObjectId=ConvertTo-NG0011GuidString -Value ([string]$RunAuthorization.authorization0010.device.objectId) -Purpose 'authorized Entra device object ID'
    $stageGroupId=ConvertTo-NG0011GuidString -Value ([string]$RunAuthorization.authorization0010.groups.stage.objectId) -Purpose 'authorized STAGE group ID'
    $commitGroupId=ConvertTo-NG0011GuidString -Value ([string]$RunAuthorization.authorization0010.groups.commit.objectId) -Purpose 'authorized COMMIT group ID'
    $successGroupId=ConvertTo-NG0011GuidString -Value $script:NG0011SuccessGroupId -Purpose '0011 SUCCESS group ID'

    try { Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null } catch {}
    try {
        $connect=@{TenantId=$tenantId;Scopes=@('Device.Read.All');ContextScope='Process';NoWelcome=$true;ErrorAction='Stop'}
        if($UseDeviceCode){$connect['UseDeviceCode']=$true}
        Connect-MgGraph @connect | Out-Null
        $context=Get-MgContext -ErrorAction Stop
        if($null -eq $context){ throw 'Microsoft Graph delegated context was not created.' }
        if([string]$context.AuthType -ne 'Delegated'){ throw "Final membership check requires delegated Graph authentication; observed AuthType '$($context.AuthType)'." }
        if([string]$context.TenantId -ine $tenantId){ throw "Graph context TenantId '$($context.TenantId)' does not match authorized tenant '$tenantId'." }
        if(@($context.Scopes) -notcontains 'Device.Read.All'){ throw 'Graph context is missing required delegated scope Device.Read.All.' }
        if([string]::IsNullOrWhiteSpace([string]$context.Account)){ throw 'Graph delegated context does not expose the signed-in operator account.' }

        $ids=[System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        $uri="https://graph.microsoft.com/v1.0/devices/$deviceObjectId/memberOf?`$select=id"
        while(-not [string]::IsNullOrWhiteSpace($uri)){
            $response=Invoke-MgGraphRequest -Method GET -Uri $uri -OutputType PSObject -ErrorAction Stop
            foreach($entry in @(Get-NG0011ObjectProperty -Object $response -Name 'value' -Default @())){
                $id=[string](Get-NG0011ObjectProperty -Object $entry -Name 'id' -Default '')
                if(-not [string]::IsNullOrWhiteSpace($id)){[void]$ids.Add($id)}
            }
            $next=[string](Get-NG0011ObjectProperty -Object $response -Name '@odata.nextLink' -Default '')
            $uri=$next
        }

        $stage=$ids.Contains($stageGroupId)
        $commit=$ids.Contains($commitGroupId)
        $success=$ids.Contains($successGroupId)
        if(-not $stage -or -not $commit -or $success){ throw "Final direct lifecycle membership is not authorized for destructive launch. STAGE=$stage COMMIT=$commit SUCCESS=$success." }

        return [pscustomobject][ordered]@{
            verified=$true
            verifiedUtc=[DateTime]::UtcNow.ToString('o')
            graph=[ordered]@{account=[string]$context.Account;tenantId=$tenantId;authType=[string]$context.AuthType;delegatedScopes=@($context.Scopes)}
            deviceObjectId=$deviceObjectId
            stage=[ordered]@{groupId=$stageGroupId;directMember=$stage}
            commit=[ordered]@{groupId=$commitGroupId;directMember=$commit}
            success=[ordered]@{groupId=$successGroupId;displayName=$script:NG0011SuccessGroupName;directMember=$success}
            querySemantics='devices/{id}/memberOf direct membership; not transitive'
            graphWritePerformed=$false
        }
    }
    finally {
        try { Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null } catch {}
    }
}

function Get-NG0011TimeEvidence {
    [CmdletBinding()]
    param()
    $output=@(& "$env:SystemRoot\System32\w32tm.exe" /query /status 2>&1); if($LASTEXITCODE -ne 0){ throw "w32tm /query /status failed with exit code $LASTEXITCODE." }
    $source=''; foreach($line in $output){ if([string]$line -match '^\s*Source:\s*(.+?)\s*$'){ $source=$Matches[1]; break } }
    return [ordered]@{verified=$true;source=$source;verifiedUtc=[DateTime]::UtcNow.ToString('o')}
}

function Get-NG0011PowerEvidence {
    [CmdletBinding()]
    param()
    $batteries=@(Get-CimInstance -ClassName Win32_Battery -ErrorAction SilentlyContinue)
    if($batteries.Count -eq 0){ return [ordered]@{batteryPresent=$false;acRequired=$false;powerLineStatus='NotApplicable';verified=$true} }
    Add-Type -AssemblyName System.Windows.Forms -ErrorAction Stop
    $status=[string][System.Windows.Forms.SystemInformation]::PowerStatus.PowerLineStatus
    if($status -ne 'Online'){ throw "A battery is present and AC power is not positively Online (observed '$status')." }
    return [ordered]@{batteryPresent=$true;acRequired=$true;powerLineStatus=$status;verified=$true}
}

function Get-NG0011ConnectivityEvidence {
    [CmdletBinding()]
    param()
    $uris=@('https://login.microsoftonline.com/common/v2.0/.well-known/openid-configuration','https://graph.microsoft.com/v1.0/$metadata','https://enterpriseregistration.windows.net/')
    $results=[System.Collections.Generic.List[object]]::new()
    foreach($uri in $uris){
        $reachable=$false; $status=''; $connectivityError=''
        try {
            $request=[Net.HttpWebRequest]::Create($uri); $request.Method='GET'; $request.Timeout=15000; $request.AllowAutoRedirect=$true; $request.UserAgent='NG-Atomic-0011-Gate'
            $response=$request.GetResponse(); try { $status=[string][int]$response.StatusCode; $reachable=$true } finally { $response.Close() }
        }
        catch [Net.WebException] {
            if($_.Exception.Response){ $response=$_.Exception.Response; try { $status=[string][int]$response.StatusCode; $reachable=$true } finally { $response.Close() } }
            else { $connectivityError=$_.Exception.Message }
        }
        if(-not $reachable){ throw "Required HTTPS endpoint is not reachable: '$uri'. $connectivityError" }
        $results.Add([pscustomobject][ordered]@{uri=$uri;reachable=$true;httpStatus=$status})
    }
    return @($results)
}

function Get-NG0011BitLockerRecoveryEvidence {
    [CmdletBinding()]
    param()
    if(-not (Get-Command Get-BitLockerVolume -ErrorAction SilentlyContinue)){ Import-Module BitLocker -ErrorAction Stop }
    if(-not (Get-Command Get-BitLockerVolume -ErrorAction SilentlyContinue)){ throw 'Get-BitLockerVolume is unavailable; recovery evidence cannot be established.' }
    $volume=Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction Stop
    $protection=[string]$volume.ProtectionStatus
    $protectionOn=($protection -eq 'On')
    try { if([int]$volume.ProtectionStatus -eq 1){ $protectionOn=$true } } catch {}
    $protectors=@($volume.KeyProtector | Where-Object {$_.KeyProtectorType -eq 'RecoveryPassword'})
    if($protectionOn -and $protectors.Count -lt 1){ throw "BitLocker protection is On for '$env:SystemDrive' but no RecoveryPassword protector exists." }
    return [ordered]@{mountPoint=$env:SystemDrive;volumeStatus=[string]$volume.VolumeStatus;protectionStatus=$protection;protectionOn=$protectionOn;recoveryPasswordProtectorCount=$protectors.Count;recoveryPasswordProtectorIds=@($protectors | ForEach-Object {[string]$_.KeyProtectorId});recoveryPasswordsCaptured=$false;verified=$true}
}

function Test-NG0011RecoveryCredential {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$RecoveryAccount,[Parameter(Mandatory)][Management.Automation.PSCredential]$Credential)
    $provided=[string]$Credential.UserName
    if($provided -match '@'){ throw 'Recovery credential must be a local Windows account, not a UPN.' }
    $leaf=($provided -split '\\')[-1]
    if($leaf -ine [string]$RecoveryAccount.Name){ throw "Credential username '$provided' does not match configured recovery account '$($RecoveryAccount.Name)'." }
    if(-not ('NG0011.NativeMethods' -as [type])){
        $typeDefinition = @"
using System;
using System.Runtime.InteropServices;
namespace NG0011 {
    public static class NativeMethods {
        [DllImport("advapi32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
        public static extern bool LogonUser(string user, string domain, IntPtr password, int logonType, int logonProvider, out IntPtr token);
        [DllImport("kernel32.dll", SetLastError=true)]
        public static extern bool CloseHandle(IntPtr handle);
    }
}
"@
        Add-Type -TypeDefinition $typeDefinition -ErrorAction Stop
    }
    $passwordPtr=[IntPtr]::Zero; $token=[IntPtr]::Zero
    try {
        $passwordPtr=[Runtime.InteropServices.Marshal]::SecureStringToGlobalAllocUnicode($Credential.Password)
        $ok=[NG0011.NativeMethods]::LogonUser([string]$RecoveryAccount.Name,'.',$passwordPtr,2,0,[ref]$token)
        if(-not $ok){ $code=[Runtime.InteropServices.Marshal]::GetLastWin32Error(); $message=(New-Object ComponentModel.Win32Exception($code)).Message; throw "Local recovery credential interactive-logon validation failed (Win32 $($code): $message)." }
    }
    finally {
        if($token -ne [IntPtr]::Zero){ [void][NG0011.NativeMethods]::CloseHandle($token) }
        if($passwordPtr -ne [IntPtr]::Zero){ [Runtime.InteropServices.Marshal]::ZeroFreeGlobalAllocUnicode($passwordPtr) }
    }
    return [ordered]@{accountName=[string]$RecoveryAccount.Name;accountSid=[string]$RecoveryAccount.SID.Value;localSamDomain='.';logonType='LOGON32_LOGON_INTERACTIVE';validated=$true;validatedUtc=[DateTime]::UtcNow.ToString('o');passwordStored=$false;passwordDerivedVerifierStored=$false}
}

function Assert-NG0011PreflightBinding {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$SafetyState,[Parameter(Mandatory)]$RunAuthorization,[Parameter(Mandatory)]$BundleEvidence)
    if([string](Get-OptionalPropertyValue -InputObject $SafetyState -Name 'State') -ne 'PreflightPassed'){ throw "Safety State is not PreflightPassed." }
    $pairs=@(
      @('ConfigSha256',(Get-OptionalPropertyValue $SafetyState 'ConfigSha256'),$BundleEvidence.configSha256),
      @('ExpectedTenantId',(Get-OptionalPropertyValue $SafetyState 'ExpectedTenantId'),$RunAuthorization.authorization0010.tenantId),
      @('ExpectedSourceUserPrincipalName',(Get-OptionalPropertyValue $SafetyState 'ExpectedSourceUserPrincipalName'),$RunAuthorization.bundle.expectedSourceUserPrincipalName),
      @('ExpectedComputerName',(Get-OptionalPropertyValue $SafetyState 'ExpectedComputerName'),$RunAuthorization.authorization0010.device.displayName),
      @('PpkgSha256',(Get-OptionalPropertyValue $SafetyState 'PpkgSha256'),$BundleEvidence.ppkgSha256)
    )
    foreach($p in $pairs){ if([string]$p[1] -ine [string]$p[2]){ throw "Preflight field '$($p[0])' does not match authorization/bundle binding." } }
    if([string]::IsNullOrWhiteSpace([string](Get-OptionalPropertyValue $SafetyState 'OldSid')) -or [string]::IsNullOrWhiteSpace([string](Get-OptionalPropertyValue $SafetyState 'ExpectedNewSid')) -or [string]::IsNullOrWhiteSpace([string](Get-OptionalPropertyValue $SafetyState 'ExpectedProfilePath'))){ throw 'Preflight safety state is missing required profile/SID evidence.' }
}
