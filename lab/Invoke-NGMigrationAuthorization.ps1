<#
.SYNOPSIS
    Manual Stage -> Review -> Commit authorization controller for the first
    intune-device-migration-NG destructive lab.

.DESCRIPTION
    Atomic 0010. This operator-side controller binds an independently verified
    atomic 0009 execution bundle to one exact Microsoft Entra device object and
    advances only the migration authorization group lifecycle:

        STAGE  ->  REVIEW  ->  COMMIT

    STAGE and COMMIT are direct Entra security-group memberships. REVIEW is a
    local, read-only evidence step that produces an explicit approval token.

    The controller does NOT run preflight.ps1, startMigrate.ps1, install a PPKG,
    mutate Intune objects, rename a device, alter profile ownership, modify
    BitLocker, add SUCCESS membership, or otherwise start migration.

    Required delegated Microsoft Graph scopes:
      - Device.Read.All
      - GroupMember.ReadWrite.All

    The signed-in operator must also hold a Microsoft Entra role permitted to
    update membership of the target security groups. Intune Administrator is a
    supported role for security-group membership updates.

.NOTES
    Atomic 0010.
    Windows PowerShell 5.1 compatible.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateSet('Stage', 'Review', 'Commit')]
    [string]$Action,

    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$BundlePath,

    [Parameter(Mandatory)]
    [guid]$DeviceId,

    [Parameter()]
    [string]$EvidencePath,

    [Parameter()]
    [string]$ApprovalToken,

    [Parameter()]
    [string]$EvidenceRoot,

    [Parameter()]
    [guid]$TenantId = 'a49b0b38-9873-445a-91c2-3ccbbe216d69',

    [Parameter()]
    [guid]$StageGroupId = 'c3b4a23d-2d81-424c-a0b2-4e5add86a7a8',

    [Parameter()]
    [guid]$CommitGroupId = '7eeb1496-bdf4-4cf6-b5ac-2494cbb4c462',

    [Parameter()]
    [guid]$SuccessGroupId = '093f5a96-eeb0-48bd-b9b7-05b975d8c287',

    [Parameter()]
    [switch]$DisconnectAfter
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:ControllerVersion = '0.1.0'
$script:EvidenceSchemaVersion = '1.0'
$script:ExpectedRepository = 'JeremiahCornelius/intune-device-migration-NG'
$script:ControllerRepositoryPath = 'lab/Invoke-NGMigrationAuthorization.ps1'
$script:ExpectedStageGroupName = 'PROD-EN-ENTRA-MIGRATION-STAGE'
$script:ExpectedCommitGroupName = 'PROD-EN-ENTRA-MIGRATION-COMMIT'
$script:ExpectedSuccessGroupName = 'PROD-EN-ENTRA-MIGRATION-SUCCESS'
$script:RequiredScopes = @('Device.Read.All', 'GroupMember.ReadWrite.All')

function Get-NGSha256 {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Get-NGStringSha256 {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Value)

    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($Value)
        return ([BitConverter]::ToString($sha.ComputeHash($bytes))).Replace('-', '').ToLowerInvariant()
    }
    finally {
        $sha.Dispose()
    }
}

function Write-NGUtf8NoBom {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Content
    )

    $encoding = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($Path, $Content, $encoding)
}

function Write-NGJsonEvidence {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)]$Object
    )

    $json = $Object | ConvertTo-Json -Depth 16
    Write-NGUtf8NoBom -Path $Path -Content ($json + [Environment]::NewLine)

    $hash = Get-NGSha256 -Path $Path
    $sidecar = "$Path.sha256"
    Write-NGUtf8NoBom -Path $sidecar -Content ("{0} *{1}{2}" -f $hash, [IO.Path]::GetFileName($Path), [Environment]::NewLine)

    return $hash
}

function Read-NGVerifiedEvidence {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "Required evidence file is missing: '$Path'."
    }

    $sidecar = "$Path.sha256"
    if (-not (Test-Path -LiteralPath $sidecar -PathType Leaf)) {
        throw "Required evidence SHA-256 sidecar is missing: '$sidecar'."
    }

    $sidecarText = (Get-Content -LiteralPath $sidecar -Raw).Trim()
    if ($sidecarText -notmatch '^([0-9A-Fa-f]{64})\s+\*?(.+)$') {
        throw "Evidence SHA-256 sidecar is malformed: '$sidecar'."
    }

    $expectedHash = $Matches[1].ToLowerInvariant()
    $expectedName = $Matches[2]
    if ($expectedName -cne [IO.Path]::GetFileName($Path)) {
        throw "Evidence SHA-256 sidecar names '$expectedName' but expected '$([IO.Path]::GetFileName($Path))'."
    }

    $actualHash = Get-NGSha256 -Path $Path
    if ($actualHash -cne $expectedHash) {
        throw "Evidence SHA-256 mismatch for '$Path'. Expected '$expectedHash'; observed '$actualHash'."
    }

    try {
        $object = Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json
    }
    catch {
        throw "Evidence JSON is invalid: '$Path'. $($_.Exception.Message)"
    }

    return [pscustomobject]@{
        Object = $object
        Sha256 = $actualHash
    }
}

function Set-NGDirectoryAcl {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    if (-not $identity -or -not $identity.User) {
        throw 'Unable to resolve the current Windows identity SID for evidence ACL protection.'
    }

    $acl = New-Object System.Security.AccessControl.DirectorySecurity
    $acl.SetAccessRuleProtection($true, $false)

    $inheritance = [System.Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit'
    $propagation = [System.Security.AccessControl.PropagationFlags]::None
    $allow = [System.Security.AccessControl.AccessControlType]::Allow
    $full = [System.Security.AccessControl.FileSystemRights]::FullControl

    $principals = @(
        $identity.User,
        (New-Object System.Security.Principal.SecurityIdentifier('S-1-5-18')),
        (New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-544'))
    )

    foreach ($principal in $principals) {
        $rule = New-Object System.Security.AccessControl.FileSystemAccessRule($principal, $full, $inheritance, $propagation, $allow)
        [void]$acl.AddAccessRule($rule)
    }

    Set-Acl -LiteralPath $Path -AclObject $acl
}

function Get-NGControllerProvenance {
    [CmdletBinding()]
    param()

    $repoCandidate = Split-Path -Path $PSScriptRoot -Parent
    $repoRoot = (& git -C $repoCandidate rev-parse --show-toplevel 2>$null)
    if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($repoRoot)) {
        throw 'The authorization controller must be executed from a Git checkout of intune-device-migration-NG.'
    }

    $repoRoot = $repoRoot.Trim()
    $branch = (& git -C $repoRoot branch --show-current).Trim()
    if ($LASTEXITCODE -ne 0 -or $branch -cne 'main') {
        throw "Controller repository must be on branch 'main'. Observed '$branch'."
    }

    $status = @(& git -C $repoRoot status --porcelain=v1 --untracked-files=no)
    if ($LASTEXITCODE -ne 0) {
        throw 'Unable to determine tracked repository status.'
    }
    if ($status.Count -gt 0) {
        throw 'Controller repository contains modified tracked files. Refusing authorization from a dirty checkout.'
    }

    $origin = (& git -C $repoRoot remote get-url origin).Trim()
    if ($LASTEXITCODE -ne 0) {
        throw 'Unable to resolve Git origin.'
    }

    $normalizedOrigin = $origin.ToLowerInvariant().Replace('git@github.com:', 'https://github.com/').TrimEnd('/')
    if ($normalizedOrigin.EndsWith('.git')) {
        $normalizedOrigin = $normalizedOrigin.Substring(0, $normalizedOrigin.Length - 4)
    }
    if ($normalizedOrigin -cne 'https://github.com/jeremiahcornelius/intune-device-migration-ng') {
        throw "Unexpected Git origin '$origin'. Expected $($script:ExpectedRepository)."
    }

    $commit = (& git -C $repoRoot rev-parse HEAD).Trim()
    $tree = (& git -C $repoRoot rev-parse 'HEAD^{tree}').Trim()
    $blob = (& git -C $repoRoot rev-parse "HEAD:$($script:ControllerRepositoryPath)" 2>$null).Trim()
    if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($blob)) {
        throw 'The authorization controller is not tracked at repository HEAD.'
    }

    $controllerPath = Join-Path -Path $repoRoot -ChildPath ($script:ControllerRepositoryPath -replace '/', '\')
    $verifierPath = Join-Path -Path $repoRoot -ChildPath 'lab\Test-NGLabExecutionBundle.ps1'
    if (-not (Test-Path -LiteralPath $verifierPath -PathType Leaf)) {
        throw "Atomic 0009 bundle verifier is missing: '$verifierPath'."
    }

    return [pscustomobject]@{
        RepoRoot = $repoRoot
        Origin = $origin
        Branch = $branch
        Commit = $commit
        Tree = $tree
        ControllerBlob = $blob
        ControllerSha256 = Get-NGSha256 -Path $controllerPath
        BundleVerifierPath = $verifierPath
        BundleVerifierSha256 = Get-NGSha256 -Path $verifierPath
    }
}

function Get-NGVerifiedBundle {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)]$ControllerProvenance
    )

    $resolved = (Resolve-Path -LiteralPath $Path -ErrorAction Stop).ProviderPath
    $manifestPath = Join-Path -Path $resolved -ChildPath 'EXECUTION-MANIFEST.json'
    $configPath = Join-Path -Path $resolved -ChildPath 'payload\config.json'

    $powershellPath = Join-Path -Path $env:SystemRoot -ChildPath 'System32\WindowsPowerShell\v1.0\powershell.exe'
    if (-not (Test-Path -LiteralPath $powershellPath -PathType Leaf)) {
        throw "Windows PowerShell 5.1 executable is missing: '$powershellPath'."
    }

    Write-Host 'Verifying atomic 0009 execution bundle...'
    & $powershellPath -NoProfile -ExecutionPolicy Bypass -File $ControllerProvenance.BundleVerifierPath -BundlePath $resolved
    $verifyExit = $LASTEXITCODE
    if ($verifyExit -ne 0) {
        throw "Atomic 0009 bundle verifier failed with exit code $verifyExit."
    }

    $manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
    $config = Get-Content -LiteralPath $configPath -Raw | ConvertFrom-Json

    if ($config.PSObject.Properties.Name -contains 'functionalTestOnly' -and [bool]$config.functionalTestOnly) {
        throw 'Bundle config is marked functionalTestOnly=true. Synthetic 0009 validation bundles cannot be staged or committed.'
    }

    if ($config.sourceTenant.tenantName -match '(?i)\.invalid$') {
        throw "Bundle source tenant '$($config.sourceTenant.tenantName)' uses the reserved .invalid namespace. Refusing operational authorization."
    }

    if ($config.safety.expectedSourceUserPrincipalName -match '(?i)@.+\.invalid$') {
        throw "Bundle expected source UPN '$($config.safety.expectedSourceUserPrincipalName)' uses the reserved .invalid namespace."
    }

    return [pscustomobject]@{
        Path = $resolved
        ManifestPath = $manifestPath
        ManifestSha256 = Get-NGSha256 -Path $manifestPath
        BundleId = [string]$manifest.bundleId
        RepositoryCommit = [string]$manifest.repository.commit
        RepositoryTree = [string]$manifest.repository.tree
        ConfigSha256 = Get-NGSha256 -Path $configPath
        ExpectedSourceUserPrincipalName = [string]$config.safety.expectedSourceUserPrincipalName
        SourceTenantName = [string]$config.sourceTenant.tenantName
    }
}

function Connect-NGGraph {
    [CmdletBinding()]
    param([Parameter(Mandatory)][guid]$ExpectedTenantId)

    $module = Get-Module -ListAvailable -Name Microsoft.Graph.Authentication | Sort-Object Version -Descending | Select-Object -First 1
    if (-not $module) {
        throw "Microsoft.Graph.Authentication is required. Install it before running 0010."
    }

    Import-Module Microsoft.Graph.Authentication -ErrorAction Stop
    Connect-MgGraph -TenantId $ExpectedTenantId.Guid -Scopes $script:RequiredScopes -NoWelcome -ErrorAction Stop | Out-Null

    $context = Get-MgContext
    if (-not $context) {
        throw 'Microsoft Graph context was not established.'
    }
    if ([string]$context.TenantId -ine $ExpectedTenantId.Guid) {
        throw "Connected Graph tenant '$($context.TenantId)' does not match expected tenant '$($ExpectedTenantId.Guid)'."
    }

    $grantedScopes = @($context.Scopes)
    foreach ($scope in $script:RequiredScopes) {
        if ($grantedScopes -notcontains $scope) {
            throw "Required delegated Graph scope '$scope' is not present in the active context."
        }
    }

    return $context
}

function Get-NGDevice {
    [CmdletBinding()]
    param([Parameter(Mandatory)][guid]$ExpectedDeviceId)

    $select = 'id,deviceId,displayName,accountEnabled,operatingSystem,operatingSystemVersion,trustType,approximateLastSignInDateTime'
    $uri = "https://graph.microsoft.com/v1.0/devices(deviceId='$($ExpectedDeviceId.Guid)')?" + '$select=' + $select
    $device = Invoke-MgGraphRequest -Method GET -Uri $uri -OutputType PSObject -ErrorAction Stop

    if (-not $device.id) {
        throw "Microsoft Graph did not return an Entra device object for deviceId '$($ExpectedDeviceId.Guid)'."
    }
    if ([string]$device.deviceId -ine $ExpectedDeviceId.Guid) {
        throw "Resolved Entra device returned deviceId '$($device.deviceId)' rather than expected '$($ExpectedDeviceId.Guid)'."
    }
    if ([string]$device.trustType -cne 'ServerAd') {
        throw "Expected a Hybrid Entra source device with trustType 'ServerAd'; observed '$($device.trustType)'."
    }
    if ($device.accountEnabled -ne $true) {
        throw "Entra source device '$($device.id)' is not enabled."
    }

    return $device
}

function Get-NGValidatedGroup {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][guid]$GroupId,
        [Parameter(Mandatory)][string]$ExpectedDisplayName
    )

    $uri = "https://graph.microsoft.com/v1.0/groups/$($GroupId.Guid)?" + '$select=id,displayName,securityEnabled,mailEnabled,groupTypes,isAssignableToRole'
    $group = Invoke-MgGraphRequest -Method GET -Uri $uri -OutputType PSObject -ErrorAction Stop

    if ([string]$group.id -ine $GroupId.Guid) {
        throw "Group lookup returned unexpected object ID '$($group.id)' for expected '$($GroupId.Guid)'."
    }
    if ([string]$group.displayName -cne $ExpectedDisplayName) {
        throw "Group '$($GroupId.Guid)' displayName is '$($group.displayName)'; expected '$ExpectedDisplayName'."
    }
    if ($group.securityEnabled -ne $true -or $group.mailEnabled -eq $true) {
        throw "Group '$ExpectedDisplayName' is not the expected non-mail-enabled security group."
    }
    if (@($group.groupTypes) -contains 'DynamicMembership') {
        throw "Group '$ExpectedDisplayName' is dynamic. 0010 requires direct static membership."
    }
    if ($group.isAssignableToRole -eq $true) {
        throw "Group '$ExpectedDisplayName' is role-assignable. Refusing migration authorization use."
    }

    return $group
}

function Get-NGDirectMembershipIds {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$DeviceObjectId)

    $ids = New-Object System.Collections.Generic.List[string]
    $uri = "https://graph.microsoft.com/v1.0/devices/$DeviceObjectId/memberOf?" + '$select=id,displayName'

    while ($uri) {
        $page = Invoke-MgGraphRequest -Method GET -Uri $uri -OutputType PSObject -ErrorAction Stop
        foreach ($entry in @($page.value)) {
            if ($entry.id) {
                $ids.Add([string]$entry.id)
            }
        }
        $next = $page.PSObject.Properties['@odata.nextLink']
        if ($next -and $next.Value) {
            $uri = [string]$next.Value
        }
        else {
            $uri = $null
        }
    }

    return @($ids)
}

function Add-NGDeviceToGroup {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][guid]$GroupId,
        [Parameter(Mandatory)][string]$DeviceObjectId
    )

    $uri = "https://graph.microsoft.com/v1.0/groups/$($GroupId.Guid)/members/`$ref"
    $body = @{ '@odata.id' = "https://graph.microsoft.com/v1.0/directoryObjects/$DeviceObjectId" } | ConvertTo-Json -Compress
    Invoke-MgGraphRequest -Method POST -Uri $uri -Body $body -ContentType 'application/json' -ErrorAction Stop | Out-Null
}

function Get-NGMembershipState {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$DeviceObjectId,
        [Parameter(Mandatory)][guid]$StageId,
        [Parameter(Mandatory)][guid]$CommitId,
        [Parameter(Mandatory)][guid]$SuccessId
    )

    $ids = @(Get-NGDirectMembershipIds -DeviceObjectId $DeviceObjectId)
    return [pscustomobject]@{
        Stage = $ids -contains $StageId.Guid
        Commit = $ids -contains $CommitId.Guid
        Success = $ids -contains $SuccessId.Guid
        DirectMembershipIds = $ids
    }
}

function Assert-NGEvidenceBinding {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Evidence,
        [Parameter(Mandatory)]$Bundle,
        [Parameter(Mandatory)]$Device,
        [Parameter(Mandatory)][guid]$ExpectedTenantId,
        [Parameter(Mandatory)][guid]$ExpectedStageGroupId,
        [Parameter(Mandatory)][guid]$ExpectedCommitGroupId,
        [Parameter(Mandatory)][guid]$ExpectedSuccessGroupId
    )

    if ([string]$Evidence.schemaVersion -cne $script:EvidenceSchemaVersion) { throw 'Unsupported 0010 evidence schemaVersion.' }
    if ([string]$Evidence.tenantId -ine $ExpectedTenantId.Guid) { throw 'Evidence tenantId does not match the requested tenant.' }
    if ([string]$Evidence.device.deviceId -ine $Device.deviceId) { throw 'Evidence deviceId does not match the current Entra device.' }
    if ([string]$Evidence.device.objectId -ine $Device.id) { throw 'Evidence Entra objectId does not match the current Entra device.' }
    if ([string]$Evidence.bundle.bundleId -cne $Bundle.BundleId) { throw 'Evidence BundleId does not match the currently verified bundle.' }
    if ([string]$Evidence.groups.stage.id -ine $ExpectedStageGroupId.Guid) { throw 'Evidence STAGE group ID mismatch.' }
    if ([string]$Evidence.groups.commit.id -ine $ExpectedCommitGroupId.Guid) { throw 'Evidence COMMIT group ID mismatch.' }
    if ([string]$Evidence.groups.success.id -ine $ExpectedSuccessGroupId.Guid) { throw 'Evidence SUCCESS group ID mismatch.' }
}

function New-NGCommonEvidence {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$EventType,
        [Parameter(Mandatory)][string]$AuthorizationId,
        [Parameter(Mandatory)]$Controller,
        [Parameter(Mandatory)]$Bundle,
        [Parameter(Mandatory)]$GraphContext,
        [Parameter(Mandatory)]$Device,
        [Parameter(Mandatory)]$StageGroup,
        [Parameter(Mandatory)]$CommitGroup,
        [Parameter(Mandatory)]$SuccessGroup,
        [Parameter(Mandatory)]$Membership
    )

    return [ordered]@{
        schemaVersion = $script:EvidenceSchemaVersion
        eventType = $EventType
        authorizationId = $AuthorizationId
        recordedUtc = [DateTime]::UtcNow.ToString('o')
        tenantId = [string]$GraphContext.TenantId
        operator = [ordered]@{
            account = [string]$GraphContext.Account
            authType = [string]$GraphContext.AuthType
            scopes = @($GraphContext.Scopes | Sort-Object)
        }
        controller = [ordered]@{
            version = $script:ControllerVersion
            repositoryCommit = $Controller.Commit
            repositoryTree = $Controller.Tree
            controllerBlob = $Controller.ControllerBlob
            controllerSha256 = $Controller.ControllerSha256
            bundleVerifierSha256 = $Controller.BundleVerifierSha256
        }
        bundle = [ordered]@{
            bundleId = $Bundle.BundleId
            manifestSha256 = $Bundle.ManifestSha256
            repositoryCommit = $Bundle.RepositoryCommit
            repositoryTree = $Bundle.RepositoryTree
            configSha256 = $Bundle.ConfigSha256
            expectedSourceUserPrincipalName = $Bundle.ExpectedSourceUserPrincipalName
            sourceTenantName = $Bundle.SourceTenantName
        }
        device = [ordered]@{
            objectId = [string]$Device.id
            deviceId = [string]$Device.deviceId
            displayName = [string]$Device.displayName
            accountEnabled = [bool]$Device.accountEnabled
            trustType = [string]$Device.trustType
            operatingSystem = [string]$Device.operatingSystem
            operatingSystemVersion = [string]$Device.operatingSystemVersion
            approximateLastSignInDateTime = [string]$Device.approximateLastSignInDateTime
        }
        groups = [ordered]@{
            stage = [ordered]@{ id = [string]$StageGroup.id; displayName = [string]$StageGroup.displayName }
            commit = [ordered]@{ id = [string]$CommitGroup.id; displayName = [string]$CommitGroup.displayName }
            success = [ordered]@{ id = [string]$SuccessGroup.id; displayName = [string]$SuccessGroup.displayName }
        }
        directMembership = [ordered]@{
            stage = [bool]$Membership.Stage
            commit = [bool]$Membership.Commit
            success = [bool]$Membership.Success
        }
    }
}

function Get-NGApprovalToken {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$StageEvidence,
        [Parameter(Mandatory)][string]$StageEvidenceSha256,
        [Parameter(Mandatory)]$Bundle
    )

    $canonical = @(
        'NG0010-COMMIT'
        [string]$StageEvidence.tenantId
        [string]$StageEvidence.authorizationId
        [string]$StageEvidence.device.deviceId
        [string]$StageEvidence.device.objectId
        [string]$Bundle.BundleId
        $StageEvidenceSha256
        [string]$StageEvidence.groups.stage.id
        [string]$StageEvidence.groups.commit.id
        [string]$StageEvidence.groups.success.id
    ) -join '|'

    return Get-NGStringSha256 -Value $canonical
}

$controller = $null
$graphContext = $null

try {
    $controller = Get-NGControllerProvenance
    $bundle = Get-NGVerifiedBundle -Path $BundlePath -ControllerProvenance $controller

    if ([string]::IsNullOrWhiteSpace($EvidenceRoot)) {
        $EvidenceRoot = Join-Path -Path $env:USERPROFILE -ChildPath 'NG-Migration-Authorization'
    }

    $graphContext = Connect-NGGraph -ExpectedTenantId $TenantId
    $device = Get-NGDevice -ExpectedDeviceId $DeviceId
    $stageGroup = Get-NGValidatedGroup -GroupId $StageGroupId -ExpectedDisplayName $script:ExpectedStageGroupName
    $commitGroup = Get-NGValidatedGroup -GroupId $CommitGroupId -ExpectedDisplayName $script:ExpectedCommitGroupName
    $successGroup = Get-NGValidatedGroup -GroupId $SuccessGroupId -ExpectedDisplayName $script:ExpectedSuccessGroupName
    $membership = Get-NGMembershipState -DeviceObjectId ([string]$device.id) -StageId $StageGroupId -CommitId $CommitGroupId -SuccessId $SuccessGroupId

    switch ($Action) {
        'Stage' {
            if ($membership.Success) { throw 'Device is already a direct member of MIGRATION-SUCCESS. Refusing to stage an already successful device object.' }
            if ($membership.Commit) { throw 'Device is already a direct member of MIGRATION-COMMIT. Refusing to create a new Stage authorization over an existing Commit state.' }

            if (-not (Test-Path -LiteralPath $EvidenceRoot -PathType Container)) {
                New-Item -ItemType Directory -Path $EvidenceRoot -Force | Out-Null
                Set-NGDirectoryAcl -Path $EvidenceRoot
            }

            $authorizationId = [guid]::NewGuid().Guid
            $folderName = '{0}-{1}-{2}' -f ([DateTime]::UtcNow.ToString('yyyyMMddTHHmmssZ')), $DeviceId.Guid, $authorizationId.Substring(0, 8)
            $EvidencePath = Join-Path -Path $EvidenceRoot -ChildPath $folderName
            New-Item -ItemType Directory -Path $EvidencePath -ErrorAction Stop | Out-Null
            Set-NGDirectoryAcl -Path $EvidencePath

            $intent = New-NGCommonEvidence -EventType 'StageIntent' -AuthorizationId $authorizationId -Controller $controller -Bundle $bundle -GraphContext $graphContext -Device $device -StageGroup $stageGroup -CommitGroup $commitGroup -SuccessGroup $successGroup -Membership $membership
            $intent['membershipMutation'] = if ($membership.Stage) { 'AlreadyDirectMember' } else { 'AddDirectMember' }
            $intentHash = Write-NGJsonEvidence -Path (Join-Path $EvidencePath 'STAGE-INTENT.json') -Object $intent

            if (-not $membership.Stage) {
                Add-NGDeviceToGroup -GroupId $StageGroupId -DeviceObjectId ([string]$device.id)
            }

            $postMembership = Get-NGMembershipState -DeviceObjectId ([string]$device.id) -StageId $StageGroupId -CommitId $CommitGroupId -SuccessId $SuccessGroupId
            if (-not $postMembership.Stage) { throw 'STAGE membership read-back failed after attempted authorization mutation.' }
            if ($postMembership.Commit -or $postMembership.Success) { throw 'Unexpected COMMIT or SUCCESS membership appeared during Stage. Stop and investigate.' }

            $stageEvidence = New-NGCommonEvidence -EventType 'Stage' -AuthorizationId $authorizationId -Controller $controller -Bundle $bundle -GraphContext $graphContext -Device $device -StageGroup $stageGroup -CommitGroup $commitGroup -SuccessGroup $successGroup -Membership $postMembership
            $stageEvidence['stageIntentSha256'] = $intentHash
            $stageEvidence['membershipMutation'] = if ($membership.Stage) { 'AlreadyDirectMember' } else { 'AddedDirectMember' }
            $stageHash = Write-NGJsonEvidence -Path (Join-Path $EvidencePath 'STAGE.json') -Object $stageEvidence

            Write-Host ''
            Write-Host 'NG migration authorization STAGE: PASS'
            Write-Host "Evidence path: $EvidencePath"
            Write-Host "DeviceId:      $($DeviceId.Guid)"
            Write-Host "ObjectId:      $($device.id)"
            Write-Host "BundleId:      $($bundle.BundleId)"
            Write-Host "STAGE SHA-256: $stageHash"
            Write-Host ''
            Write-Host 'NEXT STEP — REVIEW (read-only):'
            Write-Host (".\lab\Invoke-NGMigrationAuthorization.ps1 -Action Review -BundlePath '{0}' -DeviceId '{1}' -EvidencePath '{2}'" -f $bundle.Path, $DeviceId.Guid, $EvidencePath)
        }

        'Review' {
            if ([string]::IsNullOrWhiteSpace($EvidencePath)) { throw '-EvidencePath is mandatory for Review.' }
            $resolvedEvidencePath = (Resolve-Path -LiteralPath $EvidencePath -ErrorAction Stop).ProviderPath
            $stageRecord = Read-NGVerifiedEvidence -Path (Join-Path $resolvedEvidencePath 'STAGE.json')
            Assert-NGEvidenceBinding -Evidence $stageRecord.Object -Bundle $bundle -Device $device -ExpectedTenantId $TenantId -ExpectedStageGroupId $StageGroupId -ExpectedCommitGroupId $CommitGroupId -ExpectedSuccessGroupId $SuccessGroupId

            if (-not $membership.Stage) { throw 'Review requires current direct STAGE membership.' }
            if ($membership.Commit) { throw 'Review requires the device to be absent from COMMIT.' }
            if ($membership.Success) { throw 'Review requires the device to be absent from SUCCESS.' }

            $approvalToken = Get-NGApprovalToken -StageEvidence $stageRecord.Object -StageEvidenceSha256 $stageRecord.Sha256 -Bundle $bundle
            $review = New-NGCommonEvidence -EventType 'Review' -AuthorizationId ([string]$stageRecord.Object.authorizationId) -Controller $controller -Bundle $bundle -GraphContext $graphContext -Device $device -StageGroup $stageGroup -CommitGroup $commitGroup -SuccessGroup $successGroup -Membership $membership
            $review['stageEvidenceSha256'] = $stageRecord.Sha256
            $review['approvalTokenSha256'] = $approvalToken
            $review['reviewDecision'] = 'EligibleForExplicitCommit'
            $reviewHash = Write-NGJsonEvidence -Path (Join-Path $resolvedEvidencePath 'REVIEW.json') -Object $review

            Write-Host ''
            Write-Host 'NG migration authorization REVIEW: PASS'
            Write-Host 'No group membership was changed by Review.'
            Write-Host "Evidence path:   $resolvedEvidencePath"
            Write-Host "DeviceId:        $($DeviceId.Guid)"
            Write-Host "ObjectId:        $($device.id)"
            Write-Host "BundleId:        $($bundle.BundleId)"
            Write-Host "REVIEW SHA-256:  $reviewHash"
            Write-Host "APPROVAL TOKEN:  $approvalToken"
            Write-Host ''
            Write-Host 'STOP HERE AND MANUALLY REVIEW THE EVIDENCE ABOVE.'
            Write-Host 'Only if the device, bundle, tenant, and groups are correct, run the exact Commit command:'
            Write-Host (".\lab\Invoke-NGMigrationAuthorization.ps1 -Action Commit -BundlePath '{0}' -DeviceId '{1}' -EvidencePath '{2}' -ApprovalToken '{3}'" -f $bundle.Path, $DeviceId.Guid, $resolvedEvidencePath, $approvalToken)
        }

        'Commit' {
            if ([string]::IsNullOrWhiteSpace($EvidencePath)) { throw '-EvidencePath is mandatory for Commit.' }
            if ([string]::IsNullOrWhiteSpace($ApprovalToken)) { throw '-ApprovalToken is mandatory for Commit.' }

            $resolvedEvidencePath = (Resolve-Path -LiteralPath $EvidencePath -ErrorAction Stop).ProviderPath
            $stageRecord = Read-NGVerifiedEvidence -Path (Join-Path $resolvedEvidencePath 'STAGE.json')
            $reviewRecord = Read-NGVerifiedEvidence -Path (Join-Path $resolvedEvidencePath 'REVIEW.json')
            Assert-NGEvidenceBinding -Evidence $stageRecord.Object -Bundle $bundle -Device $device -ExpectedTenantId $TenantId -ExpectedStageGroupId $StageGroupId -ExpectedCommitGroupId $CommitGroupId -ExpectedSuccessGroupId $SuccessGroupId
            Assert-NGEvidenceBinding -Evidence $reviewRecord.Object -Bundle $bundle -Device $device -ExpectedTenantId $TenantId -ExpectedStageGroupId $StageGroupId -ExpectedCommitGroupId $CommitGroupId -ExpectedSuccessGroupId $SuccessGroupId

            if ([string]$reviewRecord.Object.stageEvidenceSha256 -cne $stageRecord.Sha256) { throw 'REVIEW evidence does not bind to the current STAGE evidence SHA-256.' }
            $expectedToken = Get-NGApprovalToken -StageEvidence $stageRecord.Object -StageEvidenceSha256 $stageRecord.Sha256 -Bundle $bundle
            if ($ApprovalToken -cne $expectedToken) { throw 'ApprovalToken does not match the cryptographically bound Review authorization.' }
            if ([string]$reviewRecord.Object.approvalTokenSha256 -cne $expectedToken) { throw 'REVIEW evidence approval token does not match the recomputed authorization token.' }

            if (-not $membership.Stage) { throw 'Commit requires current direct STAGE membership.' }
            if ($membership.Commit) { throw 'Device is already a direct member of COMMIT. Refusing ambiguous duplicate Commit; inspect evidence and group history manually.' }
            if ($membership.Success) { throw 'Commit requires the device to be absent from SUCCESS.' }

            $intent = New-NGCommonEvidence -EventType 'CommitIntent' -AuthorizationId ([string]$stageRecord.Object.authorizationId) -Controller $controller -Bundle $bundle -GraphContext $graphContext -Device $device -StageGroup $stageGroup -CommitGroup $commitGroup -SuccessGroup $successGroup -Membership $membership
            $intent['stageEvidenceSha256'] = $stageRecord.Sha256
            $intent['reviewEvidenceSha256'] = $reviewRecord.Sha256
            $intent['approvalTokenSha256'] = $expectedToken
            $intentHash = Write-NGJsonEvidence -Path (Join-Path $resolvedEvidencePath 'COMMIT-INTENT.json') -Object $intent

            Add-NGDeviceToGroup -GroupId $CommitGroupId -DeviceObjectId ([string]$device.id)
            $postMembership = Get-NGMembershipState -DeviceObjectId ([string]$device.id) -StageId $StageGroupId -CommitId $CommitGroupId -SuccessId $SuccessGroupId
            if (-not $postMembership.Stage -or -not $postMembership.Commit) { throw 'Commit membership read-back failed. STAGE and COMMIT must both be directly present.' }
            if ($postMembership.Success) { throw 'Unexpected SUCCESS membership appeared during Commit. Stop and investigate.' }

            $commitEvidence = New-NGCommonEvidence -EventType 'Commit' -AuthorizationId ([string]$stageRecord.Object.authorizationId) -Controller $controller -Bundle $bundle -GraphContext $graphContext -Device $device -StageGroup $stageGroup -CommitGroup $commitGroup -SuccessGroup $successGroup -Membership $postMembership
            $commitEvidence['stageEvidenceSha256'] = $stageRecord.Sha256
            $commitEvidence['reviewEvidenceSha256'] = $reviewRecord.Sha256
            $commitEvidence['commitIntentSha256'] = $intentHash
            $commitEvidence['approvalTokenSha256'] = $expectedToken
            $commitEvidence['membershipMutation'] = 'AddedDirectMember'
            $commitHash = Write-NGJsonEvidence -Path (Join-Path $resolvedEvidencePath 'COMMIT.json') -Object $commitEvidence

            Write-Host ''
            Write-Host 'NG migration authorization COMMIT: PASS'
            Write-Host "Evidence path:  $resolvedEvidencePath"
            Write-Host "DeviceId:       $($DeviceId.Guid)"
            Write-Host "ObjectId:       $($device.id)"
            Write-Host "BundleId:       $($bundle.BundleId)"
            Write-Host "COMMIT SHA-256: $commitHash"
            Write-Host ''
            Write-Host 'AUTHORIZATION ONLY: migration has NOT been started.'
            Write-Host 'Do not run startMigrate.ps1 until the atomic 0011 destructive-lab runbook explicitly instructs you to cross that boundary.'
        }
    }
}
finally {
    if ($DisconnectAfter -and (Get-Command Disconnect-MgGraph -ErrorAction SilentlyContinue)) {
        Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
    }
}
