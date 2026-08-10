<#
.SYNOPSIS
    Implements the manual Stage -> Review -> Commit authorization controller
    for intune-device-migration-NG destructive-lab execution.

.DESCRIPTION
    Atomic 0010 creates an operator-side authorization boundary around the
    deterministic execution bundle introduced by atomic 0009.

    The controller has three actions:

      Stage  - verifies the exact 0009 bundle, resolves one Entra device by its
               deviceId, validates the configured STAGE and COMMIT groups, and
               adds the exact device object to STAGE if required.

      Review - re-verifies the bundle and live Entra identity/membership state,
               performs no cloud write, records the reviewed state, and emits
               an exact one-line Commit command bound to the review-record hash,
               BundleId, and Entra device object ID.

      Commit - re-verifies the bundle immediately before authorization, verifies
               the complete Stage/Review evidence chain and explicit operator
               confirmations, then adds the same device object to COMMIT while
               preserving STAGE membership.

    Commit is an authorization event only. This controller does NOT invoke
    preflight.ps1, startMigrate.ps1, reboot, domain unjoin, dsregcmd /leave,
    provisioning-package installation, profile reassociation, Intune cleanup,
    BitLocker changes, SUCCESS membership, or any migration-engine operation.

    Evidence is stored outside the repository and outside the execution bundle.
    Stage, Review, and Commit each write an immutable JSON record plus SHA-256
    sidecar. Each later record cryptographically references the prior record.

    Microsoft Graph authentication is delegated and operator-interactive. The
    controller does not use the reusable Graph client secret carried inside the
    migration bundle.

.REQUIREMENTS
    - Windows PowerShell 5.1 (Desktop edition).
    - Git available in PATH.
    - Microsoft.Graph.Authentication PowerShell module.
    - Delegated Microsoft Graph scopes:
        Device.Read.All
        GroupMember.ReadWrite.All
    - A signed-in Entra operator with a role permitted to update security-group
      membership. Microsoft currently documents Intune Administrator as one of
      the supported delegated roles for security groups.

.PARAMETER Action
    Stage, Review, or Commit.

.PARAMETER BundlePath
    Existing 0009 deterministic execution bundle. It is verified before every
    action and must have been built from the exact current clean main checkout.

.PARAMETER EvidencePath
    External evidence directory. Stage requires a previously nonexistent path.
    Review and Commit require the Stage-created directory.

.PARAMETER TenantId
    Required for Stage. Exact Entra tenant GUID. Review and Commit recover and
    verify it from the Stage record.

.PARAMETER DeviceId
    Required for Stage. The Entra device registration deviceId GUID, not the
    directory object ID and not the display name. For a Windows source device,
    this is the DeviceId reported by dsregcmd /status.

.PARAMETER ExpectedDeviceDisplayName
    Required for Stage. Exact expected Entra device display name, normally the
    current physical Windows computer name. This provides a second human-readable
    identity check in addition to the authoritative deviceId GUID.

.PARAMETER StageGroupId
    Required for Stage. Object ID of the static security group representing
    prepared/qualified devices.

.PARAMETER CommitGroupId
    Required for Stage. Object ID of the static security group representing
    explicitly authorized devices.

.PARAMETER ExpectedStageGroupName
    Expected display name read back from StageGroupId.

.PARAMETER ExpectedCommitGroupName
    Expected display name read back from CommitGroupId.

.PARAMETER ReviewRecordSha256
    Required for Commit. Exact SHA-256 emitted by Review for REVIEW-RECORD.json.

.PARAMETER ConfirmBundleId
    Required for Commit. Exact 64-hex BundleId printed during Review.

.PARAMETER ConfirmDeviceObjectId
    Required for Commit. Exact Entra directory object ID printed during Review.

.PARAMETER RepositoryRoot
    Optional explicit repository root. If omitted, it is resolved inside the
    script body from $PSScriptRoot. This intentionally avoids using PSScriptRoot
    in a parameter-default expression.

.PARAMETER UseDeviceCode
    Use Microsoft Graph device-code authentication rather than the default
    interactive browser flow when a new delegated Graph context is required.

.EXAMPLE
    .\lab\Invoke-NGMigrationAuthorization.ps1 -Action Stage -BundlePath 'C:\NG-Lab-Run\Bundle-001' -EvidencePath 'C:\NG-Lab-Run\Authorization-001' -TenantId '00000000-0000-0000-0000-000000000000' -DeviceId '11111111-1111-1111-1111-111111111111' -ExpectedDeviceDisplayName 'LAB-PC-01' -StageGroupId '22222222-2222-2222-2222-222222222222' -CommitGroupId '33333333-3333-3333-3333-333333333333'

.EXAMPLE
    .\lab\Invoke-NGMigrationAuthorization.ps1 -Action Review -BundlePath 'C:\NG-Lab-Run\Bundle-001' -EvidencePath 'C:\NG-Lab-Run\Authorization-001'

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
    [ValidateNotNullOrEmpty()]
    [string]$EvidencePath,

    [Parameter()]
    [ValidatePattern('^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')]
    [string]$TenantId,

    [Parameter()]
    [ValidatePattern('^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')]
    [string]$DeviceId,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$ExpectedDeviceDisplayName,

    [Parameter()]
    [ValidatePattern('^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')]
    [string]$StageGroupId,

    [Parameter()]
    [ValidatePattern('^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')]
    [string]$CommitGroupId,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$ExpectedStageGroupName = 'PROD-EN-ENTRA-MIGRATION-STAGE',

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$ExpectedCommitGroupName = 'PROD-EN-ENTRA-MIGRATION-COMMIT',

    [Parameter()]
    [ValidatePattern('^[0-9a-fA-F]{64}$')]
    [string]$ReviewRecordSha256,

    [Parameter()]
    [ValidatePattern('^[0-9a-fA-F]{64}$')]
    [string]$ConfirmBundleId,

    [Parameter()]
    [ValidatePattern('^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')]
    [string]$ConfirmDeviceObjectId,

    [Parameter()]
    [AllowEmptyString()]
    [string]$RepositoryRoot = '',

    [Parameter()]
    [switch]$UseDeviceCode
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:ControllerVersion = '0.1.0'
$script:ExpectedRepository = 'JeremiahCornelius/intune-device-migration-NG'
$script:ControllerRepositoryPath = 'lab/Invoke-NGMigrationAuthorization.ps1'
$script:BundleVerifierRepositoryPath = 'lab/Test-NGLabExecutionBundle.ps1'
$script:StageRecordName = 'STAGE-RECORD.json'
$script:ReviewRecordName = 'REVIEW-RECORD.json'
$script:CommitRecordName = 'COMMIT-RECORD.json'
$script:RequiredScopes = @('Device.Read.All', 'GroupMember.ReadWrite.All')

function Get-NGResolvedDirectoryPath {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Path,

        [Parameter(Mandatory)]
        [string]$Purpose
    )

    if (-not (Test-Path -LiteralPath $Path -PathType Container)) {
        throw "$Purpose directory does not exist: '$Path'."
    }

    return [IO.Path]::GetFullPath(
        (Resolve-Path -LiteralPath $Path -ErrorAction Stop).ProviderPath
    ).TrimEnd([char[]]@('\', '/'))
}

function Test-NGPathInsideDirectory {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$ChildPath,

        [Parameter(Mandatory)]
        [string]$ParentPath
    )

    $childFull = [IO.Path]::GetFullPath($ChildPath).TrimEnd([char[]]@('\', '/'))
    $parentFull = [IO.Path]::GetFullPath($ParentPath).TrimEnd([char[]]@('\', '/'))

    if ($childFull -ieq $parentFull) {
        return $true
    }

    $prefix = $parentFull + [IO.Path]::DirectorySeparatorChar
    return $childFull.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)
}

function Invoke-NGGit {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Repository,

        [Parameter(Mandatory)]
        [string[]]$Arguments
    )

    $output = @(& git -C $Repository @Arguments 2>&1)
    $exitCode = $LASTEXITCODE

    if ($exitCode -ne 0) {
        $detail = ($output | ForEach-Object { [string]$_ }) -join [Environment]::NewLine
        throw "git $($Arguments -join ' ') failed with exit code $exitCode. $detail"
    }

    return (($output | ForEach-Object { [string]$_ }) -join "`n").Trim()
}

function Get-NGSha256 {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )

    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
}

function Write-NGUtf8NoBom {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Path,

        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$Content
    )

    $encoding = New-Object Text.UTF8Encoding($false)
    [IO.File]::WriteAllText($Path, $Content, $encoding)
}

function Get-NGObjectProperty {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        $Object,

        [Parameter(Mandatory)]
        [string]$Name
    )

    if ($Object -is [System.Collections.IDictionary]) {
        if ($Object.Contains($Name)) {
            return $Object[$Name]
        }
        return $null
    }

    $property = $Object.PSObject.Properties[$Name]
    if ($property) {
        return $property.Value
    }

    return $null
}

function ConvertTo-NGGuidString {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Value,

        [Parameter(Mandatory)]
        [string]$Purpose
    )

    $guid = [Guid]::Empty
    if (-not [Guid]::TryParse($Value, [ref]$guid)) {
        throw "$Purpose is not a valid GUID: '$Value'."
    }

    return $guid.ToString().ToLowerInvariant()
}

function Get-NGRepositoryProvenance {
    [CmdletBinding()]
    param(
        [Parameter()]
        [AllowEmptyString()]
        [string]$ExplicitRepositoryRoot = ''
    )

    if (-not (Get-Command git -ErrorAction SilentlyContinue)) {
        throw 'git is required and was not found in PATH.'
    }

    $candidate = $ExplicitRepositoryRoot
    if ([string]::IsNullOrWhiteSpace($candidate)) {
        if ([string]::IsNullOrWhiteSpace($PSScriptRoot)) {
            throw 'RepositoryRoot was not supplied and PSScriptRoot is unavailable.'
        }
        $candidate = Split-Path -Path $PSScriptRoot -Parent
    }

    $repository = Get-NGResolvedDirectoryPath -Path $candidate -Purpose 'Repository'
    $gitTop = Invoke-NGGit -Repository $repository -Arguments @('rev-parse', '--show-toplevel')
    $gitTop = [IO.Path]::GetFullPath($gitTop).TrimEnd([char[]]@('\', '/'))

    if ($gitTop -ine $repository) {
        throw "RepositoryRoot '$repository' is not the Git top-level directory '$gitTop'."
    }

    $originUrl = Invoke-NGGit -Repository $repository -Arguments @('remote', 'get-url', 'origin')
    if ($originUrl -notmatch '(?i)(?:[:/])JeremiahCornelius/intune-device-migration-NG(?:\.git)?$') {
        throw "Repository origin '$originUrl' is not the expected '$script:ExpectedRepository' repository."
    }

    $branch = Invoke-NGGit -Repository $repository -Arguments @('rev-parse', '--abbrev-ref', 'HEAD')
    if ($branch -ne 'main') {
        throw "Authorization must run from branch 'main'. Observed '$branch'."
    }

    $trackedStatus = Invoke-NGGit -Repository $repository -Arguments @('status', '--porcelain=v1', '--untracked-files=no')
    if (-not [string]::IsNullOrWhiteSpace($trackedStatus)) {
        throw "Tracked repository files are modified. Commit or revert them before authorization.`n$trackedStatus"
    }

    foreach ($relativePath in @($script:ControllerRepositoryPath, $script:BundleVerifierRepositoryPath)) {
        $fullPath = Join-Path -Path $repository -ChildPath $relativePath
        if (-not (Test-Path -LiteralPath $fullPath -PathType Leaf)) {
            throw "Required tracked authorization file is missing: '$relativePath'."
        }
        [void](Invoke-NGGit -Repository $repository -Arguments @('ls-files', '--error-unmatch', '--', $relativePath))
    }

    $commit = Invoke-NGGit -Repository $repository -Arguments @('rev-parse', 'HEAD')
    $tree = Invoke-NGGit -Repository $repository -Arguments @('rev-parse', 'HEAD^{tree}')
    $controllerPath = Join-Path -Path $repository -ChildPath $script:ControllerRepositoryPath
    $controllerBlob = Invoke-NGGit -Repository $repository -Arguments @('rev-parse', "HEAD:$script:ControllerRepositoryPath")

    return [pscustomobject][ordered]@{
        repositoryRoot = $repository
        originUrl = $originUrl
        branch = $branch
        commit = $commit.ToLowerInvariant()
        tree = $tree.ToLowerInvariant()
        controllerRepositoryPath = $script:ControllerRepositoryPath
        controllerGitBlobId = $controllerBlob.ToLowerInvariant()
        controllerSha256 = Get-NGSha256 -Path $controllerPath
    }
}

function Get-NGSidecarHash {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$RecordPath,

        [Parameter(Mandatory)]
        [string]$SidecarPath
    )

    if (-not (Test-Path -LiteralPath $RecordPath -PathType Leaf)) {
        throw "Evidence record is missing: '$RecordPath'."
    }
    if (-not (Test-Path -LiteralPath $SidecarPath -PathType Leaf)) {
        throw "Evidence hash sidecar is missing: '$SidecarPath'."
    }

    $sidecar = (Get-Content -LiteralPath $SidecarPath -Raw -ErrorAction Stop).Trim()
    $recordName = Split-Path -Path $RecordPath -Leaf
    $escapedName = [Regex]::Escape($recordName)
    if ($sidecar -notmatch "^([0-9a-fA-F]{64})  $escapedName$") {
        throw "Evidence hash sidecar has an invalid format: '$SidecarPath'."
    }

    $expected = $Matches[1].ToLowerInvariant()
    $actual = Get-NGSha256 -Path $RecordPath
    if ($actual -ne $expected) {
        throw "Evidence record SHA-256 mismatch for '$recordName'. Expected '$expected'; observed '$actual'."
    }

    return $actual
}

function Read-NGEvidenceRecord {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$EvidenceRoot,

        [Parameter(Mandatory)]
        [string]$RecordName
    )

    $recordPath = Join-Path -Path $EvidenceRoot -ChildPath $RecordName
    $sidecarName = [IO.Path]::GetFileNameWithoutExtension($RecordName) + '.sha256'
    $sidecarPath = Join-Path -Path $EvidenceRoot -ChildPath $sidecarName
    $sha256 = Get-NGSidecarHash -RecordPath $recordPath -SidecarPath $sidecarPath

    try {
        $record = Get-Content -LiteralPath $recordPath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
    }
    catch {
        throw "Evidence record '$RecordName' is not valid JSON: $($_.Exception.Message)"
    }

    return [pscustomobject]@{
        Record = $record
        Sha256 = $sha256
        Path = $recordPath
    }
}

function Write-NGEvidenceRecord {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$EvidenceRoot,

        [Parameter(Mandatory)]
        [string]$RecordName,

        [Parameter(Mandatory)]
        $Record
    )

    $recordPath = Join-Path -Path $EvidenceRoot -ChildPath $RecordName
    $sidecarName = [IO.Path]::GetFileNameWithoutExtension($RecordName) + '.sha256'
    $sidecarPath = Join-Path -Path $EvidenceRoot -ChildPath $sidecarName

    if ((Test-Path -LiteralPath $recordPath) -or (Test-Path -LiteralPath $sidecarPath)) {
        throw "Refusing to overwrite existing authorization evidence for '$RecordName'."
    }

    $json = $Record | ConvertTo-Json -Depth 16
    Write-NGUtf8NoBom -Path $recordPath -Content ($json + "`n")
    $sha256 = Get-NGSha256 -Path $recordPath
    Write-NGUtf8NoBom -Path $sidecarPath -Content ("$sha256  $RecordName`n")

    $verified = Get-NGSidecarHash -RecordPath $recordPath -SidecarPath $sidecarPath
    if ($verified -ne $sha256) {
        throw "Evidence self-verification failed for '$RecordName'."
    }

    return $sha256
}

function Set-NGEvidenceDirectoryAcl {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )

    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    if (-not $identity -or -not $identity.User) {
        throw 'Unable to determine the current Windows identity SID for authorization-evidence ACL protection.'
    }

    $currentSid = [string]$identity.User.Value
    $grants = @(
        "*$($currentSid):(OI)(CI)F",
        '*S-1-5-18:(OI)(CI)F',
        '*S-1-5-32-544:(OI)(CI)F'
    ) | Select-Object -Unique

    $arguments = @($Path, '/inheritance:r', '/grant:r') + $grants + @('/T', '/C')
    & "$env:SystemRoot\System32\icacls.exe" @arguments | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "Unable to apply restrictive ACLs to authorization evidence '$Path' (icacls exit $LASTEXITCODE)."
    }

    return $currentSid
}

function Assert-NGEvidenceDirectoryAcl {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Path,

        [Parameter(Mandatory)]
        [string]$StageOperatorSid
    )

    $acl = Get-Acl -LiteralPath $Path -ErrorAction Stop
    if (-not $acl.AreAccessRulesProtected) {
        throw "Authorization evidence directory inherits access rules: '$Path'."
    }

    $expectedSids = @(
        $StageOperatorSid,
        'S-1-5-18',
        'S-1-5-32-544'
    ) | ForEach-Object { $_.ToUpperInvariant() } | Select-Object -Unique

    $rules = @($acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]))
    foreach ($rule in $rules) {
        $sid = ([string]$rule.IdentityReference.Value).ToUpperInvariant()
        if ($expectedSids -notcontains $sid) {
            throw "Authorization evidence ACL contains unexpected principal SID '$sid'."
        }
        if ([string]$rule.AccessControlType -ne 'Allow') {
            throw "Authorization evidence ACL contains a non-Allow rule for SID '$sid'."
        }
        $fullControl = [Security.AccessControl.FileSystemRights]::FullControl
        if (($rule.FileSystemRights -band $fullControl) -ne $fullControl) {
            throw "Authorization evidence ACL does not grant FullControl to required SID '$sid'."
        }
        $requiredInheritance = [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [Security.AccessControl.InheritanceFlags]::ObjectInherit
        if (($rule.InheritanceFlags -band $requiredInheritance) -ne $requiredInheritance) {
            throw "Authorization evidence ACL does not propagate to files and subdirectories for required SID '$sid'."
        }
    }

    foreach ($sid in $expectedSids) {
        if (@($rules | Where-Object { ([string]$_.IdentityReference.Value).ToUpperInvariant() -eq $sid }).Count -eq 0) {
            throw "Authorization evidence ACL is missing required SID '$sid'."
        }
    }
}

function Test-NGBundleWithIndependentVerifier {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        $RepositoryProvenance,

        [Parameter(Mandatory)]
        [string]$InputBundlePath
    )

    $bundle = Get-NGResolvedDirectoryPath -Path $InputBundlePath -Purpose 'Execution bundle'
    $verifierPath = Join-Path -Path $RepositoryProvenance.repositoryRoot -ChildPath $script:BundleVerifierRepositoryPath
    $windowsPowerShell = Join-Path -Path $PSHOME -ChildPath 'powershell.exe'

    if (-not (Test-Path -LiteralPath $windowsPowerShell -PathType Leaf)) {
        throw "Windows PowerShell executable was not found at '$windowsPowerShell'."
    }

    & $windowsPowerShell -NoProfile -ExecutionPolicy Bypass -File $verifierPath -BundlePath $bundle
    $verificationExitCode = $LASTEXITCODE
    if ($verificationExitCode -ne 0) {
        throw "Independent 0009 bundle verification failed with exit code $verificationExitCode."
    }

    $manifestPath = Join-Path -Path $bundle -ChildPath 'EXECUTION-MANIFEST.json'
    $manifestSidecarPath = Join-Path -Path $bundle -ChildPath 'EXECUTION-MANIFEST.sha256'
    if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) {
        throw 'Verified bundle is missing EXECUTION-MANIFEST.json.'
    }
    if (-not (Test-Path -LiteralPath $manifestSidecarPath -PathType Leaf)) {
        throw 'Verified bundle is missing EXECUTION-MANIFEST.sha256.'
    }

    try {
        $manifest = Get-Content -LiteralPath $manifestPath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
    }
    catch {
        throw "Unable to parse verified execution manifest: $($_.Exception.Message)"
    }

    $manifestSha256 = Get-NGSha256 -Path $manifestPath
    $sidecarText = (Get-Content -LiteralPath $manifestSidecarPath -Raw -ErrorAction Stop).Trim()
    if ($sidecarText -notmatch '^([0-9a-fA-F]{64})  EXECUTION-MANIFEST\.json$') {
        throw 'Execution-manifest SHA-256 sidecar format is invalid.'
    }
    if ($manifestSha256 -ne $Matches[1].ToLowerInvariant()) {
        throw 'Execution-manifest SHA-256 changed after independent verification.'
    }

    $bundleCommit = ([string]$manifest.repository.commit).ToLowerInvariant()
    $bundleTree = ([string]$manifest.repository.tree).ToLowerInvariant()
    if ($bundleCommit -ne [string]$RepositoryProvenance.commit) {
        throw "Bundle repository commit '$bundleCommit' does not match current controller checkout '$($RepositoryProvenance.commit)'. Rebuild the bundle from the current clean main checkout."
    }
    if ($bundleTree -ne [string]$RepositoryProvenance.tree) {
        throw "Bundle repository tree '$bundleTree' does not match current controller checkout '$($RepositoryProvenance.tree)'."
    }

    $bundleId = ([string]$manifest.bundleId).ToLowerInvariant()
    if ($bundleId -notmatch '^[0-9a-f]{64}$') {
        throw 'Execution manifest BundleId is not a 64-character SHA-256 value.'
    }

    # Read only the non-secret configuration fields required for human review.
    # The full config remains inside the ACL-protected execution bundle and is
    # never copied into authorization evidence.
    $configPayloadName = [string]$manifest.inputs.config.payloadName
    if ([string]::IsNullOrWhiteSpace($configPayloadName)) {
        throw 'Execution manifest does not identify the external config payload.'
    }
    $configPath = Join-Path -Path (Join-Path -Path $bundle -ChildPath 'payload') -ChildPath $configPayloadName
    if (-not (Test-Path -LiteralPath $configPath -PathType Leaf)) {
        throw "Verified execution bundle is missing config payload '$configPayloadName'."
    }
    try {
        $config = Get-Content -LiteralPath $configPath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
    }
    catch {
        throw "Verified execution config is not valid JSON: $($_.Exception.Message)"
    }

    $expectedSourceUpn = [string]$config.safety.expectedSourceUserPrincipalName
    $managementSuffix = [string]$config.safety.intuneManagementNameSuffix
    $pinnedPpkgSha256 = ([string]$config.safety.ppkgSha256).ToLowerInvariant()
    $sourceTenantName = [string]$config.sourceTenant.tenantName
    if ([string]::IsNullOrWhiteSpace($expectedSourceUpn) -or [string]::IsNullOrWhiteSpace($managementSuffix) -or [string]::IsNullOrWhiteSpace($sourceTenantName) -or $pinnedPpkgSha256 -notmatch '^[0-9a-f]{64}$') {
        throw 'Verified execution config is missing required non-secret review fields.'
    }

    return [pscustomobject][ordered]@{
        path = $bundle
        bundleId = $bundleId
        manifestSha256 = $manifestSha256
        repositoryCommit = $bundleCommit
        repositoryTree = $bundleTree
        sourceTenantName = $sourceTenantName
        expectedSourceUserPrincipalName = $expectedSourceUpn
        intuneManagementNameSuffix = $managementSuffix
        ppkgSha256 = $pinnedPpkgSha256
    }
}

function Connect-NGDelegatedGraph {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$RequiredTenantId,

        [Parameter()]
        [switch]$DeviceCode
    )

    if (-not (Get-Module -ListAvailable -Name Microsoft.Graph.Authentication)) {
        throw 'Microsoft.Graph.Authentication is required but is not installed.'
    }

    Import-Module Microsoft.Graph.Authentication -ErrorAction Stop
    $normalizedTenantId = ConvertTo-NGGuidString -Value $RequiredTenantId -Purpose 'TenantId'

    # Establish a fresh process-scoped delegated context for every Stage,
    # Review, and Commit action. Do not silently inherit a CurrentUser context
    # from unrelated Graph administration performed in the same profile.
    $connectParameters = @{
        TenantId = $normalizedTenantId
        Scopes = $script:RequiredScopes
        ContextScope = 'Process'
        NoWelcome = $true
        ErrorAction = 'Stop'
    }
    if ($DeviceCode) {
        $connectParameters['UseDeviceCode'] = $true
    }

    Connect-MgGraph @connectParameters | Out-Null
    $context = Get-MgContext -ErrorAction Stop

    if (-not $context) {
        throw 'Microsoft Graph authentication completed without a readable context.'
    }
    if ([string]$context.TenantId -ine $normalizedTenantId) {
        throw "Connected Graph tenant '$($context.TenantId)' does not match required tenant '$normalizedTenantId'."
    }
    if ([string]$context.AuthType -ine 'Delegated') {
        throw "Authorization controller requires delegated Graph authentication. Observed '$($context.AuthType)'."
    }
    if ([string]::IsNullOrWhiteSpace([string]$context.Account)) {
        throw 'Delegated Graph context does not expose the signed-in operator account.'
    }

    $scopeNames = @($context.Scopes | ForEach-Object { ([string]$_).ToLowerInvariant() })
    $missingScopes = @($script:RequiredScopes | Where-Object { $scopeNames -notcontains $_.ToLowerInvariant() })
    if ($missingScopes.Count -gt 0) {
        throw "Graph context is missing required delegated scope(s): $($missingScopes -join ', ')."
    }

    $loadedModule = Get-Module -Name Microsoft.Graph.Authentication -ErrorAction Stop | Select-Object -First 1
    return [pscustomobject][ordered]@{
        Account = [string]$context.Account
        AuthType = [string]$context.AuthType
        TenantId = [string]$context.TenantId
        Scopes = @($context.Scopes)
        ModuleVersion = [string]$loadedModule.Version
    }
}

function Get-NGGraphDeviceByDeviceId {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$ExactDeviceId
    )

    $normalized = ConvertTo-NGGuidString -Value $ExactDeviceId -Purpose 'DeviceId'
    $uri = "https://graph.microsoft.com/v1.0/devices(deviceId='$normalized')?`$select=id,deviceId,displayName,accountEnabled,operatingSystem,operatingSystemVersion,trustType,profileType,registrationDateTime,approximateLastSignInDateTime"
    $device = Invoke-MgGraphRequest -Method GET -Uri $uri -ErrorAction Stop
    $objectId = [string](Get-NGObjectProperty -Object $device -Name 'id')
    if ([string]::IsNullOrWhiteSpace($objectId)) {
        throw "Graph did not return a directory object ID for deviceId '$normalized'."
    }

    return $device
}

function Get-NGGraphDeviceByObjectId {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$ObjectId
    )

    $normalized = ConvertTo-NGGuidString -Value $ObjectId -Purpose 'Device object ID'
    $uri = "https://graph.microsoft.com/v1.0/devices/$normalized?`$select=id,deviceId,displayName,accountEnabled,operatingSystem,operatingSystemVersion,trustType,profileType,registrationDateTime,approximateLastSignInDateTime"
    return Invoke-MgGraphRequest -Method GET -Uri $uri -ErrorAction Stop
}

function Get-NGGraphGroup {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$GroupId
    )

    $normalized = ConvertTo-NGGuidString -Value $GroupId -Purpose 'Group object ID'
    $uri = "https://graph.microsoft.com/v1.0/groups/$normalized?`$select=id,displayName,securityEnabled,mailEnabled,groupTypes,isAssignableToRole"
    return Invoke-MgGraphRequest -Method GET -Uri $uri -ErrorAction Stop
}

function Assert-NGStaticSecurityGroup {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        $Group,

        [Parameter(Mandatory)]
        [string]$ExpectedId,

        [Parameter(Mandatory)]
        [string]$ExpectedDisplayName,

        [Parameter(Mandatory)]
        [string]$Purpose
    )

    $id = [string](Get-NGObjectProperty -Object $Group -Name 'id')
    $displayName = [string](Get-NGObjectProperty -Object $Group -Name 'displayName')
    $securityEnabled = [bool](Get-NGObjectProperty -Object $Group -Name 'securityEnabled')
    $mailEnabled = [bool](Get-NGObjectProperty -Object $Group -Name 'mailEnabled')
    $groupTypes = @(Get-NGObjectProperty -Object $Group -Name 'groupTypes')
    $isAssignableToRoleValue = Get-NGObjectProperty -Object $Group -Name 'isAssignableToRole'

    if ($id -ine (ConvertTo-NGGuidString -Value $ExpectedId -Purpose "$Purpose group ID")) {
        throw "$Purpose group read-back object ID '$id' does not match expected '$ExpectedId'."
    }
    if ($displayName -cne $ExpectedDisplayName) {
        throw "$Purpose group display name '$displayName' does not exactly match expected '$ExpectedDisplayName'."
    }
    if (-not $securityEnabled -or $mailEnabled) {
        throw "$Purpose group '$displayName' is not a normal non-mail-enabled security group."
    }
    if ($groupTypes.Count -gt 0) {
        throw "$Purpose group '$displayName' has unsupported groupTypes '$($groupTypes -join ',')'; atomic 0010 requires a normal static security group with an empty groupTypes collection."
    }
    if ($null -eq $isAssignableToRoleValue) {
        throw "$Purpose group '$displayName' did not expose isAssignableToRole; atomic 0010 cannot prove that the group is non-role-assignable."
    }
    if ([bool]$isAssignableToRoleValue) {
        throw "$Purpose group '$displayName' is role-assignable; atomic 0010 refuses role-assignable groups."
    }
}

function Get-NGDeviceDirectGroupMembership {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$DeviceObjectId
    )

    $normalized = ConvertTo-NGGuidString -Value $DeviceObjectId -Purpose 'Device object ID'
    $uri = "https://graph.microsoft.com/v1.0/devices/$normalized/memberOf"
    $groups = [System.Collections.Generic.List[object]]::new()

    while (-not [string]::IsNullOrWhiteSpace($uri)) {
        $response = Invoke-MgGraphRequest -Method GET -Uri $uri -ErrorAction Stop
        foreach ($item in @(Get-NGObjectProperty -Object $response -Name 'value')) {
            $groups.Add($item)
        }
        $nextLink = Get-NGObjectProperty -Object $response -Name '@odata.nextLink'
        $uri = [string]$nextLink
    }

    return @($groups | ForEach-Object { $_ })
}

function Get-NGMembershipSnapshot {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$DeviceObjectId,

        [Parameter(Mandatory)]
        [string]$ExactStageGroupId,

        [Parameter(Mandatory)]
        [string]$ExactCommitGroupId
    )

    $stageId = ConvertTo-NGGuidString -Value $ExactStageGroupId -Purpose 'Stage group ID'
    $commitId = ConvertTo-NGGuidString -Value $ExactCommitGroupId -Purpose 'Commit group ID'
    $memberships = @(Get-NGDeviceDirectGroupMembership -DeviceObjectId $DeviceObjectId)

    return [pscustomobject][ordered]@{
        stage = @($memberships | Where-Object { [string](Get-NGObjectProperty -Object $_ -Name 'id') -ieq $stageId }).Count -gt 0
        commit = @($memberships | Where-Object { [string](Get-NGObjectProperty -Object $_ -Name 'id') -ieq $commitId }).Count -gt 0
    }
}

function Add-NGDeviceToGroup {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$ExactGroupId,

        [Parameter(Mandatory)]
        [string]$DeviceObjectId
    )

    $groupId = ConvertTo-NGGuidString -Value $ExactGroupId -Purpose 'Group ID'
    $objectId = ConvertTo-NGGuidString -Value $DeviceObjectId -Purpose 'Device object ID'
    $uri = "https://graph.microsoft.com/v1.0/groups/$groupId/members/`$ref"
    $body = @{ '@odata.id' = "https://graph.microsoft.com/v1.0/directoryObjects/$objectId" } | ConvertTo-Json -Compress
    [void](Invoke-MgGraphRequest -Method POST -Uri $uri -Body $body -ContentType 'application/json' -ErrorAction Stop)
}

function Wait-NGMembershipSnapshot {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$DeviceObjectId,

        [Parameter(Mandatory)]
        [string]$ExactStageGroupId,

        [Parameter(Mandatory)]
        [string]$ExactCommitGroupId,

        [Parameter(Mandatory)]
        [bool]$ExpectedStage,

        [Parameter(Mandatory)]
        [bool]$ExpectedCommit
    )

    $last = $null
    for ($attempt = 1; $attempt -le 12; $attempt++) {
        $last = Get-NGMembershipSnapshot -DeviceObjectId $DeviceObjectId -ExactStageGroupId $ExactStageGroupId -ExactCommitGroupId $ExactCommitGroupId
        if ([bool]$last.stage -eq $ExpectedStage -and [bool]$last.commit -eq $ExpectedCommit) {
            return $last
        }
        if ($attempt -lt 12) {
            Start-Sleep -Seconds 5
        }
    }

    throw "Graph membership read-back did not reach expected state after retries. Expected Stage=$ExpectedStage Commit=$ExpectedCommit; observed Stage=$($last.stage) Commit=$($last.commit)."
}

function ConvertTo-NGDeviceEvidence {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        $Device
    )

    return [ordered]@{
        objectId = ([string](Get-NGObjectProperty -Object $Device -Name 'id')).ToLowerInvariant()
        deviceId = ([string](Get-NGObjectProperty -Object $Device -Name 'deviceId')).ToLowerInvariant()
        displayName = [string](Get-NGObjectProperty -Object $Device -Name 'displayName')
        accountEnabled = Get-NGObjectProperty -Object $Device -Name 'accountEnabled'
        operatingSystem = [string](Get-NGObjectProperty -Object $Device -Name 'operatingSystem')
        operatingSystemVersion = [string](Get-NGObjectProperty -Object $Device -Name 'operatingSystemVersion')
        trustType = [string](Get-NGObjectProperty -Object $Device -Name 'trustType')
        profileType = [string](Get-NGObjectProperty -Object $Device -Name 'profileType')
        registrationDateTime = [string](Get-NGObjectProperty -Object $Device -Name 'registrationDateTime')
        approximateLastSignInDateTime = [string](Get-NGObjectProperty -Object $Device -Name 'approximateLastSignInDateTime')
    }
}

function Assert-NGSourceDeviceInvariant {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        $DeviceEvidence,

        [Parameter(Mandatory)]
        [string]$ExpectedDeviceId,

        [Parameter(Mandatory)]
        [string]$ExpectedDisplayName,

        [Parameter()]
        [AllowEmptyString()]
        [string]$ExpectedObjectId = ''
    )

    $expectedDeviceIdNormalized = ConvertTo-NGGuidString -Value $ExpectedDeviceId -Purpose 'Expected deviceId'
    $observedDeviceId = ConvertTo-NGGuidString -Value ([string]$DeviceEvidence.deviceId) -Purpose 'Observed deviceId'
    if ($observedDeviceId -ne $expectedDeviceIdNormalized) {
        throw "Resolved deviceId '$observedDeviceId' does not match expected '$expectedDeviceIdNormalized'."
    }

    $observedObjectId = ConvertTo-NGGuidString -Value ([string]$DeviceEvidence.objectId) -Purpose 'Observed device object ID'
    if (-not [string]::IsNullOrWhiteSpace($ExpectedObjectId)) {
        $expectedObjectIdNormalized = ConvertTo-NGGuidString -Value $ExpectedObjectId -Purpose 'Expected device object ID'
        if ($observedObjectId -ne $expectedObjectIdNormalized) {
            throw "Resolved device object ID '$observedObjectId' does not match expected '$expectedObjectIdNormalized'."
        }
    }

    if ([string]$DeviceEvidence.displayName -cne $ExpectedDisplayName) {
        throw "Resolved device display name '$($DeviceEvidence.displayName)' does not exactly match expected '$ExpectedDisplayName'."
    }
    if ([string]$DeviceEvidence.operatingSystem -ine 'Windows') {
        throw "Resolved device operatingSystem '$($DeviceEvidence.operatingSystem)' is not Windows."
    }
    if ([string]$DeviceEvidence.trustType -ine 'ServerAd') {
        throw "Resolved device trustType '$($DeviceEvidence.trustType)' is not ServerAd (Microsoft Entra hybrid joined)."
    }
    if ($null -eq $DeviceEvidence.accountEnabled) {
        throw 'Resolved Entra device object did not expose accountEnabled.'
    }
    if (-not [bool]$DeviceEvidence.accountEnabled) {
        throw 'Resolved Entra device object is disabled.'
    }
}

function ConvertTo-NGGroupEvidence {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        $Group
    )

    return [ordered]@{
        objectId = ([string](Get-NGObjectProperty -Object $Group -Name 'id')).ToLowerInvariant()
        displayName = [string](Get-NGObjectProperty -Object $Group -Name 'displayName')
        securityEnabled = [bool](Get-NGObjectProperty -Object $Group -Name 'securityEnabled')
        mailEnabled = [bool](Get-NGObjectProperty -Object $Group -Name 'mailEnabled')
        groupTypes = @(Get-NGObjectProperty -Object $Group -Name 'groupTypes')
        isAssignableToRole = Get-NGObjectProperty -Object $Group -Name 'isAssignableToRole'
    }
}

function Assert-NGStageRecord {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        $StageRecord,

        [Parameter(Mandatory)]
        $RepositoryProvenance,

        [Parameter(Mandatory)]
        $BundleEvidence
    )

    if ([string]$StageRecord.schemaVersion -ne '1.0' -or [string]$StageRecord.recordType -ne 'Stage') {
        throw 'STAGE-RECORD.json is not a supported atomic 0010 Stage record.'
    }
    if ([string]$StageRecord.atomic -ne '0010') {
        throw "Stage record atomic '$($StageRecord.atomic)' is not 0010."
    }
    if ([string]$StageRecord.controller.repositoryCommit -ine [string]$RepositoryProvenance.commit -or [string]$StageRecord.controller.repositoryTree -ine [string]$RepositoryProvenance.tree) {
        throw 'Current controller repository provenance does not match the Stage record. Complete one authorization chain without changing repository HEAD.'
    }
    if ([string]$StageRecord.controller.controllerSha256 -ine [string]$RepositoryProvenance.controllerSha256) {
        throw 'Current controller bytes do not match the Stage record controller SHA-256.'
    }
    if ([string]$StageRecord.bundle.bundleId -ine [string]$BundleEvidence.bundleId -or [string]$StageRecord.bundle.manifestSha256 -ine [string]$BundleEvidence.manifestSha256) {
        throw 'Current execution bundle does not match the Stage record.'
    }
    foreach ($bundleField in @('sourceTenantName', 'expectedSourceUserPrincipalName', 'intuneManagementNameSuffix', 'ppkgSha256')) {
        if ([string]$StageRecord.bundle.$bundleField -ine [string]$BundleEvidence.$bundleField) {
            throw "Current execution bundle review field '$bundleField' does not match the Stage record."
        }
    }
}

function Assert-NGReviewRecord {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        $ReviewRecord,

        [Parameter(Mandatory)]
        [string]$StageRecordSha256,

        [Parameter(Mandatory)]
        $StageRecord
    )

    if ([string]$ReviewRecord.schemaVersion -ne '1.0' -or [string]$ReviewRecord.recordType -ne 'Review') {
        throw 'REVIEW-RECORD.json is not a supported atomic 0010 Review record.'
    }
    if ([string]$ReviewRecord.atomic -ne '0010') {
        throw "Review record atomic '$($ReviewRecord.atomic)' is not 0010."
    }
    if ([string]$ReviewRecord.previousRecordSha256 -ine $StageRecordSha256) {
        throw 'Review record does not cryptographically reference the current Stage record.'
    }

    foreach ($comparison in @(
        @('bundle.bundleId', [string]$ReviewRecord.bundle.bundleId, [string]$StageRecord.bundle.bundleId),
        @('bundle.manifestSha256', [string]$ReviewRecord.bundle.manifestSha256, [string]$StageRecord.bundle.manifestSha256),
        @('bundle.sourceTenantName', [string]$ReviewRecord.bundle.sourceTenantName, [string]$StageRecord.bundle.sourceTenantName),
        @('bundle.expectedSourceUserPrincipalName', [string]$ReviewRecord.bundle.expectedSourceUserPrincipalName, [string]$StageRecord.bundle.expectedSourceUserPrincipalName),
        @('bundle.intuneManagementNameSuffix', [string]$ReviewRecord.bundle.intuneManagementNameSuffix, [string]$StageRecord.bundle.intuneManagementNameSuffix),
        @('bundle.ppkgSha256', [string]$ReviewRecord.bundle.ppkgSha256, [string]$StageRecord.bundle.ppkgSha256),
        @('tenantId', [string]$ReviewRecord.tenantId, [string]$StageRecord.tenantId),
        @('device.objectId', [string]$ReviewRecord.device.objectId, [string]$StageRecord.device.objectId),
        @('device.deviceId', [string]$ReviewRecord.device.deviceId, [string]$StageRecord.device.deviceId),
        @('device.displayName', [string]$ReviewRecord.device.displayName, [string]$StageRecord.device.displayName),
        @('device.operatingSystem', [string]$ReviewRecord.device.operatingSystem, [string]$StageRecord.device.operatingSystem),
        @('device.trustType', [string]$ReviewRecord.device.trustType, [string]$StageRecord.device.trustType),
        @('device.accountEnabled', [string]$ReviewRecord.device.accountEnabled, [string]$StageRecord.device.accountEnabled),
        @('groups.stage.objectId', [string]$ReviewRecord.groups.stage.objectId, [string]$StageRecord.groups.stage.objectId),
        @('groups.stage.displayName', [string]$ReviewRecord.groups.stage.displayName, [string]$StageRecord.groups.stage.displayName),
        @('groups.commit.objectId', [string]$ReviewRecord.groups.commit.objectId, [string]$StageRecord.groups.commit.objectId),
        @('groups.commit.displayName', [string]$ReviewRecord.groups.commit.displayName, [string]$StageRecord.groups.commit.displayName),
        @('controller.repositoryCommit', [string]$ReviewRecord.controller.repositoryCommit, [string]$StageRecord.controller.repositoryCommit),
        @('controller.repositoryTree', [string]$ReviewRecord.controller.repositoryTree, [string]$StageRecord.controller.repositoryTree),
        @('controller.gitBlobId', [string]$ReviewRecord.controller.gitBlobId, [string]$StageRecord.controller.gitBlobId),
        @('controller.controllerSha256', [string]$ReviewRecord.controller.controllerSha256, [string]$StageRecord.controller.controllerSha256)
    )) {
        if ([string]$comparison[1] -ine [string]$comparison[2]) {
            throw "Review record field '$($comparison[0])' does not match the Stage record."
        }
    }
}

function Quote-NGPowerShellLiteral {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$Value
    )

    return "'" + $Value.Replace("'", "''") + "'"
}

if ($PSVersionTable.PSEdition -ne 'Desktop' -or $PSVersionTable.PSVersion.Major -ne 5) {
    throw "Atomic 0010 requires Windows PowerShell 5.1. Observed $($PSVersionTable.PSEdition) $($PSVersionTable.PSVersion)."
}

$repo = Get-NGRepositoryProvenance -ExplicitRepositoryRoot $RepositoryRoot
$bundle = Test-NGBundleWithIndependentVerifier -RepositoryProvenance $repo -InputBundlePath $BundlePath
$evidenceFull = [IO.Path]::GetFullPath($EvidencePath).TrimEnd([char[]]@('\', '/'))

if ([string]::IsNullOrWhiteSpace($evidenceFull)) {
    throw 'EvidencePath resolved to an empty path.'
}
if ($evidenceFull -eq [IO.Path]::GetPathRoot($evidenceFull).TrimEnd([char[]]@('\', '/'))) {
    throw "EvidencePath cannot be a filesystem root: '$evidenceFull'."
}
if (Test-NGPathInsideDirectory -ChildPath $evidenceFull -ParentPath $repo.repositoryRoot) {
    throw 'Authorization evidence must be outside the Git repository.'
}
if (Test-NGPathInsideDirectory -ChildPath $evidenceFull -ParentPath $bundle.path) {
    throw 'Authorization evidence must not be created inside the cryptographically verified execution bundle.'
}

switch ($Action) {
    'Stage' {
        foreach ($required in @(
            @('TenantId', $TenantId),
            @('DeviceId', $DeviceId),
            @('ExpectedDeviceDisplayName', $ExpectedDeviceDisplayName),
            @('StageGroupId', $StageGroupId),
            @('CommitGroupId', $CommitGroupId)
        )) {
            if ([string]::IsNullOrWhiteSpace([string]$required[1])) {
                throw "Stage requires -$($required[0])."
            }
        }

        if (Test-Path -LiteralPath $evidenceFull) {
            throw "Stage requires a previously nonexistent EvidencePath. Refusing to merge with '$evidenceFull'."
        }

        $normalizedTenantId = ConvertTo-NGGuidString -Value $TenantId -Purpose 'TenantId'
        $normalizedDeviceId = ConvertTo-NGGuidString -Value $DeviceId -Purpose 'DeviceId'
        $normalizedStageGroupId = ConvertTo-NGGuidString -Value $StageGroupId -Purpose 'Stage group ID'
        $normalizedCommitGroupId = ConvertTo-NGGuidString -Value $CommitGroupId -Purpose 'Commit group ID'
        if ($normalizedStageGroupId -eq $normalizedCommitGroupId) {
            throw 'StageGroupId and CommitGroupId must identify different groups.'
        }

        $graph = Connect-NGDelegatedGraph -RequiredTenantId $normalizedTenantId -DeviceCode:$UseDeviceCode
        $stageGroup = Get-NGGraphGroup -GroupId $normalizedStageGroupId
        $commitGroup = Get-NGGraphGroup -GroupId $normalizedCommitGroupId
        Assert-NGStaticSecurityGroup -Group $stageGroup -ExpectedId $normalizedStageGroupId -ExpectedDisplayName $ExpectedStageGroupName -Purpose 'STAGE'
        Assert-NGStaticSecurityGroup -Group $commitGroup -ExpectedId $normalizedCommitGroupId -ExpectedDisplayName $ExpectedCommitGroupName -Purpose 'COMMIT'

        $device = Get-NGGraphDeviceByDeviceId -ExactDeviceId $normalizedDeviceId
        $deviceEvidence = ConvertTo-NGDeviceEvidence -Device $device
        Assert-NGSourceDeviceInvariant -DeviceEvidence $deviceEvidence -ExpectedDeviceId $normalizedDeviceId -ExpectedDisplayName $ExpectedDeviceDisplayName

        $before = Get-NGMembershipSnapshot -DeviceObjectId $deviceEvidence.objectId -ExactStageGroupId $normalizedStageGroupId -ExactCommitGroupId $normalizedCommitGroupId
        if ([bool]$before.commit) {
            throw 'Device is already a direct member of COMMIT. Stage refuses to back-fill evidence for a previously authorized object.'
        }

        # Create protected evidence only after every read-only Stage gate has
        # passed, but before any possible cloud membership mutation.
        New-Item -Path $evidenceFull -ItemType Directory -ErrorAction Stop | Out-Null
        $stageOperatorSid = Set-NGEvidenceDirectoryAcl -Path $evidenceFull
        Assert-NGEvidenceDirectoryAcl -Path $evidenceFull -StageOperatorSid $stageOperatorSid

        $mutation = 'AlreadyPresent'
        if (-not [bool]$before.stage) {
            Add-NGDeviceToGroup -ExactGroupId $normalizedStageGroupId -DeviceObjectId $deviceEvidence.objectId
            $mutation = 'Added'
        }

        $after = Wait-NGMembershipSnapshot -DeviceObjectId $deviceEvidence.objectId -ExactStageGroupId $normalizedStageGroupId -ExactCommitGroupId $normalizedCommitGroupId -ExpectedStage $true -ExpectedCommit $false

        $record = [ordered]@{
            schemaVersion = '1.0'
            atomic = '0010'
            recordType = 'Stage'
            controllerVersion = $script:ControllerVersion
            generatedUtc = [DateTime]::UtcNow.ToString('o')
            previousRecordSha256 = $null
            tenantId = $normalizedTenantId
            operator = [ordered]@{
                account = [string]$graph.Account
                authType = [string]$graph.AuthType
                microsoftGraphAuthenticationVersion = [string]$graph.ModuleVersion
                delegatedScopes = @($graph.Scopes)
                stageOperatorSid = $stageOperatorSid
            }
            controller = [ordered]@{
                repositoryCommit = $repo.commit
                repositoryTree = $repo.tree
                repositoryPath = $repo.controllerRepositoryPath
                gitBlobId = $repo.controllerGitBlobId
                controllerSha256 = $repo.controllerSha256
            }
            bundle = [ordered]@{
                bundlePath = $bundle.path
                bundleId = $bundle.bundleId
                manifestSha256 = $bundle.manifestSha256
                repositoryCommit = $bundle.repositoryCommit
                repositoryTree = $bundle.repositoryTree
                sourceTenantName = $bundle.sourceTenantName
                expectedSourceUserPrincipalName = $bundle.expectedSourceUserPrincipalName
                intuneManagementNameSuffix = $bundle.intuneManagementNameSuffix
                ppkgSha256 = $bundle.ppkgSha256
            }
            device = $deviceEvidence
            groups = [ordered]@{
                stage = ConvertTo-NGGroupEvidence -Group $stageGroup
                commit = ConvertTo-NGGroupEvidence -Group $commitGroup
            }
            membershipBefore = [ordered]@{ stage = [bool]$before.stage; commit = [bool]$before.commit }
            operation = [ordered]@{
                cloudWrite = ($mutation -eq 'Added')
                stageMembership = $mutation
                commitMembership = 'NotModified'
            }
            membershipAfter = [ordered]@{ stage = [bool]$after.stage; commit = [bool]$after.commit }
            policy = [ordered]@{
                bundleReverified = $true
                exactDeviceIdResolution = $true
                expectedDisplayNameMatched = $true
                sourceDeviceWindows = $true
                sourceDeviceHybridTrustTypeServerAd = $true
                stagePreservedThroughCommit = $true
                successGroupTouched = $false
                migrationStarted = $false
            }
        }

        $stageSha = Write-NGEvidenceRecord -EvidenceRoot $evidenceFull -RecordName $script:StageRecordName -Record $record

        Write-Host ''
        Write-Host 'NG migration authorization - STAGE: PASS'
        Write-Host "Tenant:                  $normalizedTenantId"
        Write-Host "Operator:                $($graph.Account)"
        Write-Host "Device display name:     $($deviceEvidence.displayName)"
        Write-Host "DeviceId:                $($deviceEvidence.deviceId)"
        Write-Host "Device object ID:        $($deviceEvidence.objectId)"
        Write-Host "BundleId:                $($bundle.bundleId)"
        Write-Host "STAGE membership:        $($after.stage) ($mutation)"
        Write-Host "COMMIT membership:       $($after.commit)"
        Write-Host "Stage record SHA-256:    $stageSha"
        Write-Host "Evidence path:           $evidenceFull"
        Write-Host ''
        Write-Host 'No migration was started. Run Review only after inspecting this Stage result.'
    }

    'Review' {
        if (-not (Test-Path -LiteralPath $evidenceFull -PathType Container)) {
            throw "Review requires an existing Stage evidence directory: '$evidenceFull'."
        }
        if (Test-Path -LiteralPath (Join-Path $evidenceFull $script:ReviewRecordName)) {
            throw 'REVIEW-RECORD.json already exists. Refusing to overwrite prior review evidence.'
        }
        if (Test-Path -LiteralPath (Join-Path $evidenceFull $script:CommitRecordName)) {
            throw 'COMMIT-RECORD.json already exists. Review cannot run after a recorded Commit.'
        }

        $stageResult = Read-NGEvidenceRecord -EvidenceRoot $evidenceFull -RecordName $script:StageRecordName
        $stageRecord = $stageResult.Record
        Assert-NGEvidenceDirectoryAcl -Path $evidenceFull -StageOperatorSid ([string]$stageRecord.operator.stageOperatorSid)
        Assert-NGStageRecord -StageRecord $stageRecord -RepositoryProvenance $repo -BundleEvidence $bundle

        $normalizedTenantId = ConvertTo-NGGuidString -Value ([string]$stageRecord.tenantId) -Purpose 'Stage record tenantId'
        $stageGroupIdFromRecord = ConvertTo-NGGuidString -Value ([string]$stageRecord.groups.stage.objectId) -Purpose 'Stage record STAGE group ID'
        $commitGroupIdFromRecord = ConvertTo-NGGuidString -Value ([string]$stageRecord.groups.commit.objectId) -Purpose 'Stage record COMMIT group ID'
        $deviceObjectIdFromRecord = ConvertTo-NGGuidString -Value ([string]$stageRecord.device.objectId) -Purpose 'Stage record device object ID'
        $deviceIdFromRecord = ConvertTo-NGGuidString -Value ([string]$stageRecord.device.deviceId) -Purpose 'Stage record deviceId'

        $graph = Connect-NGDelegatedGraph -RequiredTenantId $normalizedTenantId -DeviceCode:$UseDeviceCode
        $stageGroup = Get-NGGraphGroup -GroupId $stageGroupIdFromRecord
        $commitGroup = Get-NGGraphGroup -GroupId $commitGroupIdFromRecord
        Assert-NGStaticSecurityGroup -Group $stageGroup -ExpectedId $stageGroupIdFromRecord -ExpectedDisplayName ([string]$stageRecord.groups.stage.displayName) -Purpose 'STAGE'
        Assert-NGStaticSecurityGroup -Group $commitGroup -ExpectedId $commitGroupIdFromRecord -ExpectedDisplayName ([string]$stageRecord.groups.commit.displayName) -Purpose 'COMMIT'

        $device = Get-NGGraphDeviceByObjectId -ObjectId $deviceObjectIdFromRecord
        $deviceEvidence = ConvertTo-NGDeviceEvidence -Device $device
        Assert-NGSourceDeviceInvariant -DeviceEvidence $deviceEvidence -ExpectedDeviceId $deviceIdFromRecord -ExpectedDisplayName ([string]$stageRecord.device.displayName) -ExpectedObjectId $deviceObjectIdFromRecord

        $membership = Get-NGMembershipSnapshot -DeviceObjectId $deviceObjectIdFromRecord -ExactStageGroupId $stageGroupIdFromRecord -ExactCommitGroupId $commitGroupIdFromRecord
        if (-not [bool]$membership.stage) {
            throw 'Review requires the exact device object to remain a direct STAGE member.'
        }
        if ([bool]$membership.commit) {
            throw 'Review requires COMMIT membership to be absent. The authorization boundary has already been crossed outside this evidence chain.'
        }

        $reviewRecord = [ordered]@{
            schemaVersion = '1.0'
            atomic = '0010'
            recordType = 'Review'
            controllerVersion = $script:ControllerVersion
            generatedUtc = [DateTime]::UtcNow.ToString('o')
            previousRecordSha256 = $stageResult.Sha256
            tenantId = $normalizedTenantId
            operator = [ordered]@{ account = [string]$graph.Account; authType = [string]$graph.AuthType; microsoftGraphAuthenticationVersion = [string]$graph.ModuleVersion; delegatedScopes = @($graph.Scopes) }
            controller = [ordered]@{
                repositoryCommit = $repo.commit
                repositoryTree = $repo.tree
                repositoryPath = $repo.controllerRepositoryPath
                gitBlobId = $repo.controllerGitBlobId
                controllerSha256 = $repo.controllerSha256
            }
            bundle = [ordered]@{
                bundlePath = $bundle.path
                bundleId = $bundle.bundleId
                manifestSha256 = $bundle.manifestSha256
                repositoryCommit = $bundle.repositoryCommit
                repositoryTree = $bundle.repositoryTree
                sourceTenantName = $bundle.sourceTenantName
                expectedSourceUserPrincipalName = $bundle.expectedSourceUserPrincipalName
                intuneManagementNameSuffix = $bundle.intuneManagementNameSuffix
                ppkgSha256 = $bundle.ppkgSha256
            }
            device = $deviceEvidence
            groups = [ordered]@{
                stage = ConvertTo-NGGroupEvidence -Group $stageGroup
                commit = ConvertTo-NGGroupEvidence -Group $commitGroup
            }
            membershipObserved = [ordered]@{ stage = [bool]$membership.stage; commit = [bool]$membership.commit }
            operation = [ordered]@{ cloudWrite = $false; reviewOnly = $true }
            policy = [ordered]@{
                bundleReverified = $true
                stageRecordVerified = $true
                liveDeviceIdentityVerified = $true
                sourceDeviceInvariantReverified = $true
                commitMembershipAbsent = $true
                successGroupTouched = $false
                migrationStarted = $false
            }
        }

        $reviewSha = Write-NGEvidenceRecord -EvidenceRoot $evidenceFull -RecordName $script:ReviewRecordName -Record $reviewRecord

        Write-Host ''
        Write-Host 'NG migration authorization - REVIEW: PASS'
        Write-Host 'Review the following values before authorizing Commit:'
        Write-Host "Tenant:                  $normalizedTenantId"
        Write-Host "Operator:                $($graph.Account)"
        Write-Host "Device display name:     $($deviceEvidence.displayName)"
        Write-Host "DeviceId:                $($deviceEvidence.deviceId)"
        Write-Host "Device object ID:        $($deviceEvidence.objectId)"
        Write-Host "BundleId:                $($bundle.bundleId)"
        Write-Host "Manifest SHA-256:        $($bundle.manifestSha256)"
        Write-Host "Expected source user:    $($bundle.expectedSourceUserPrincipalName)"
        Write-Host "Source tenant name:      $($bundle.sourceTenantName)"
        Write-Host "PPKG SHA-256:            $($bundle.ppkgSha256)"
        Write-Host "Intune name suffix:      $($bundle.intuneManagementNameSuffix)"
        Write-Host "STAGE group:             $($reviewRecord.groups.stage.displayName) [$stageGroupIdFromRecord]"
        Write-Host "COMMIT group:            $($reviewRecord.groups.commit.displayName) [$commitGroupIdFromRecord]"
        Write-Host "STAGE membership:        $($membership.stage)"
        Write-Host "COMMIT membership:       $($membership.commit)"
        Write-Host "Review record SHA-256:   $reviewSha"
        Write-Host ''
        Write-Host 'No cloud write occurred during Review.'
        Write-Host 'If and only if every value above is correct, use this exact one-line Commit command:'
        $controllerFull = Join-Path -Path $repo.repositoryRoot -ChildPath $script:ControllerRepositoryPath
        $commitCommand = "& " + (Quote-NGPowerShellLiteral $controllerFull) + " -Action Commit -RepositoryRoot " + (Quote-NGPowerShellLiteral $repo.repositoryRoot) + " -BundlePath " + (Quote-NGPowerShellLiteral $bundle.path) + " -EvidencePath " + (Quote-NGPowerShellLiteral $evidenceFull) + " -ReviewRecordSha256 $reviewSha -ConfirmBundleId $($bundle.bundleId) -ConfirmDeviceObjectId $($deviceEvidence.objectId)"
        if ($UseDeviceCode) {
            $commitCommand += ' -UseDeviceCode'
        }
        Write-Host $commitCommand
    }

    'Commit' {
        foreach ($required in @(
            @('ReviewRecordSha256', $ReviewRecordSha256),
            @('ConfirmBundleId', $ConfirmBundleId),
            @('ConfirmDeviceObjectId', $ConfirmDeviceObjectId)
        )) {
            if ([string]::IsNullOrWhiteSpace([string]$required[1])) {
                throw "Commit requires -$($required[0])."
            }
        }

        if (-not (Test-Path -LiteralPath $evidenceFull -PathType Container)) {
            throw "Commit requires an existing reviewed evidence directory: '$evidenceFull'."
        }
        if (Test-Path -LiteralPath (Join-Path $evidenceFull $script:CommitRecordName)) {
            throw 'COMMIT-RECORD.json already exists. Refusing to create a second Commit record.'
        }

        $stageResult = Read-NGEvidenceRecord -EvidenceRoot $evidenceFull -RecordName $script:StageRecordName
        $reviewResult = Read-NGEvidenceRecord -EvidenceRoot $evidenceFull -RecordName $script:ReviewRecordName
        $stageRecord = $stageResult.Record
        $reviewRecord = $reviewResult.Record

        Assert-NGEvidenceDirectoryAcl -Path $evidenceFull -StageOperatorSid ([string]$stageRecord.operator.stageOperatorSid)
        Assert-NGStageRecord -StageRecord $stageRecord -RepositoryProvenance $repo -BundleEvidence $bundle
        Assert-NGReviewRecord -ReviewRecord $reviewRecord -StageRecordSha256 $stageResult.Sha256 -StageRecord $stageRecord

        if ($reviewResult.Sha256 -ine $ReviewRecordSha256.ToLowerInvariant()) {
            throw "Provided ReviewRecordSha256 does not match REVIEW-RECORD.json. Expected '$($reviewResult.Sha256)'."
        }
        if ([string]$bundle.bundleId -ine $ConfirmBundleId.ToLowerInvariant()) {
            throw "ConfirmBundleId '$ConfirmBundleId' does not match verified BundleId '$($bundle.bundleId)'."
        }

        $deviceObjectIdFromRecord = ConvertTo-NGGuidString -Value ([string]$stageRecord.device.objectId) -Purpose 'Stage record device object ID'
        $confirmedObjectId = ConvertTo-NGGuidString -Value $ConfirmDeviceObjectId -Purpose 'ConfirmDeviceObjectId'
        if ($confirmedObjectId -ne $deviceObjectIdFromRecord) {
            throw "ConfirmDeviceObjectId '$confirmedObjectId' does not match reviewed device object '$deviceObjectIdFromRecord'."
        }

        $normalizedTenantId = ConvertTo-NGGuidString -Value ([string]$stageRecord.tenantId) -Purpose 'Stage record tenantId'
        $stageGroupIdFromRecord = ConvertTo-NGGuidString -Value ([string]$stageRecord.groups.stage.objectId) -Purpose 'Stage record STAGE group ID'
        $commitGroupIdFromRecord = ConvertTo-NGGuidString -Value ([string]$stageRecord.groups.commit.objectId) -Purpose 'Stage record COMMIT group ID'
        $deviceIdFromRecord = ConvertTo-NGGuidString -Value ([string]$stageRecord.device.deviceId) -Purpose 'Stage record deviceId'

        $graph = Connect-NGDelegatedGraph -RequiredTenantId $normalizedTenantId -DeviceCode:$UseDeviceCode
        $stageGroup = Get-NGGraphGroup -GroupId $stageGroupIdFromRecord
        $commitGroup = Get-NGGraphGroup -GroupId $commitGroupIdFromRecord
        Assert-NGStaticSecurityGroup -Group $stageGroup -ExpectedId $stageGroupIdFromRecord -ExpectedDisplayName ([string]$stageRecord.groups.stage.displayName) -Purpose 'STAGE'
        Assert-NGStaticSecurityGroup -Group $commitGroup -ExpectedId $commitGroupIdFromRecord -ExpectedDisplayName ([string]$stageRecord.groups.commit.displayName) -Purpose 'COMMIT'

        $device = Get-NGGraphDeviceByObjectId -ObjectId $deviceObjectIdFromRecord
        $deviceEvidence = ConvertTo-NGDeviceEvidence -Device $device
        Assert-NGSourceDeviceInvariant -DeviceEvidence $deviceEvidence -ExpectedDeviceId $deviceIdFromRecord -ExpectedDisplayName ([string]$stageRecord.device.displayName) -ExpectedObjectId $deviceObjectIdFromRecord

        $before = Get-NGMembershipSnapshot -DeviceObjectId $deviceObjectIdFromRecord -ExactStageGroupId $stageGroupIdFromRecord -ExactCommitGroupId $commitGroupIdFromRecord
        if (-not [bool]$before.stage) {
            throw 'Commit requires the reviewed device object to remain a direct STAGE member.'
        }
        if ([bool]$before.commit) {
            throw 'Device is already a direct COMMIT member but no COMMIT-RECORD.json exists. Refusing to bless an out-of-band or partially recorded authorization; investigate manually.'
        }

        Add-NGDeviceToGroup -ExactGroupId $commitGroupIdFromRecord -DeviceObjectId $deviceObjectIdFromRecord
        $after = Wait-NGMembershipSnapshot -DeviceObjectId $deviceObjectIdFromRecord -ExactStageGroupId $stageGroupIdFromRecord -ExactCommitGroupId $commitGroupIdFromRecord -ExpectedStage $true -ExpectedCommit $true

        $commitRecord = [ordered]@{
            schemaVersion = '1.0'
            atomic = '0010'
            recordType = 'Commit'
            controllerVersion = $script:ControllerVersion
            generatedUtc = [DateTime]::UtcNow.ToString('o')
            previousRecordSha256 = $reviewResult.Sha256
            stageRecordSha256 = $stageResult.Sha256
            tenantId = $normalizedTenantId
            operator = [ordered]@{ account = [string]$graph.Account; authType = [string]$graph.AuthType; microsoftGraphAuthenticationVersion = [string]$graph.ModuleVersion; delegatedScopes = @($graph.Scopes) }
            controller = [ordered]@{
                repositoryCommit = $repo.commit
                repositoryTree = $repo.tree
                repositoryPath = $repo.controllerRepositoryPath
                gitBlobId = $repo.controllerGitBlobId
                controllerSha256 = $repo.controllerSha256
            }
            bundle = [ordered]@{
                bundlePath = $bundle.path
                bundleId = $bundle.bundleId
                manifestSha256 = $bundle.manifestSha256
                repositoryCommit = $bundle.repositoryCommit
                repositoryTree = $bundle.repositoryTree
                sourceTenantName = $bundle.sourceTenantName
                expectedSourceUserPrincipalName = $bundle.expectedSourceUserPrincipalName
                intuneManagementNameSuffix = $bundle.intuneManagementNameSuffix
                ppkgSha256 = $bundle.ppkgSha256
            }
            device = $deviceEvidence
            groups = [ordered]@{
                stage = ConvertTo-NGGroupEvidence -Group $stageGroup
                commit = ConvertTo-NGGroupEvidence -Group $commitGroup
            }
            explicitConfirmations = [ordered]@{
                reviewRecordSha256 = $ReviewRecordSha256.ToLowerInvariant()
                bundleId = $ConfirmBundleId.ToLowerInvariant()
                deviceObjectId = $confirmedObjectId
            }
            membershipBefore = [ordered]@{ stage = [bool]$before.stage; commit = [bool]$before.commit }
            operation = [ordered]@{
                cloudWrite = $true
                stageMembership = 'Preserved'
                commitMembership = 'Added'
            }
            membershipAfter = [ordered]@{ stage = [bool]$after.stage; commit = [bool]$after.commit }
            policy = [ordered]@{
                bundleReverifiedImmediatelyBeforeCommit = $true
                stageRecordVerified = $true
                reviewRecordVerified = $true
                liveDeviceIdentityVerified = $true
                sourceDeviceInvariantReverified = $true
                explicitHumanConfirmationBound = $true
                successGroupTouched = $false
                migrationStarted = $false
            }
        }

        $commitSha = Write-NGEvidenceRecord -EvidenceRoot $evidenceFull -RecordName $script:CommitRecordName -Record $commitRecord

        Write-Host ''
        Write-Host 'NG migration authorization - COMMIT: PASS'
        Write-Host "Tenant:                  $normalizedTenantId"
        Write-Host "Operator:                $($graph.Account)"
        Write-Host "Device display name:     $($deviceEvidence.displayName)"
        Write-Host "DeviceId:                $($deviceEvidence.deviceId)"
        Write-Host "Device object ID:        $($deviceEvidence.objectId)"
        Write-Host "BundleId:                $($bundle.bundleId)"
        Write-Host "STAGE membership:        $($after.stage) (preserved)"
        Write-Host "COMMIT membership:       $($after.commit) (added)"
        Write-Host "Commit record SHA-256:   $commitSha"
        Write-Host "Evidence path:           $evidenceFull"
        Write-Host ''
        Write-Host 'AUTHORIZATION RECORDED. No migration was started by atomic 0010.'
        Write-Host 'Do not invoke migration until the atomic 0011 destructive-lab runbook and recovery/evidence gate are satisfied.'
    }
}
