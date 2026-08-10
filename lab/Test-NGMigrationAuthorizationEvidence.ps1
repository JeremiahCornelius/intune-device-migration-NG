<#
.SYNOPSIS
    Independently verifies atomic 0010 Stage/Review/Commit evidence against an
    atomic 0009 execution bundle.

.DESCRIPTION
    Read-only verifier for the local authorization evidence chain produced by
    Invoke-NGMigrationAuthorization.ps1.

    The verifier:
      - independently runs Test-NGLabExecutionBundle.ps1 against BundlePath;
      - verifies SHA-256 sidecars for Stage, Review, and Commit records;
      - verifies the Stage -> Review -> Commit hash chain;
      - verifies BundleId, manifest SHA-256, repository commit/tree, tenant,
        device IDs, and STAGE/COMMIT group IDs remain consistent;
      - verifies the Stage evidence directory retains the restricted ACL created
        by the controller;
      - verifies recorded membership transitions are internally consistent;
      - optionally requires a complete Commit record.

    It performs no Microsoft Graph calls and no cloud or endpoint writes. Live
    Entra membership was read back by the controller at each transition; atomic
    0011 will define the final pre-migration operational evidence gate.

.PARAMETER BundlePath
    Existing atomic 0009 deterministic execution bundle.

.PARAMETER EvidencePath
    Existing atomic 0010 authorization evidence directory.

.PARAMETER RequireCommit
    Fail unless a complete and internally consistent Commit record is present.

.NOTES
    Atomic 0010.
    Windows PowerShell 5.1 compatible.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$BundlePath,

    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$EvidencePath,

    [Parameter()]
    [switch]$RequireCommit
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

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

function Get-NGSha256 {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )

    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
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

    if (-not (Test-Path -LiteralPath $recordPath -PathType Leaf)) {
        throw "Required evidence record is missing: '$recordPath'."
    }
    if (-not (Test-Path -LiteralPath $sidecarPath -PathType Leaf)) {
        throw "Required evidence sidecar is missing: '$sidecarPath'."
    }

    $sidecar = (Get-Content -LiteralPath $sidecarPath -Raw -ErrorAction Stop).Trim()
    $escapedName = [Regex]::Escape($RecordName)
    if ($sidecar -notmatch "^([0-9a-fA-F]{64})  $escapedName$") {
        throw "Evidence sidecar has invalid format: '$sidecarPath'."
    }

    $expected = $Matches[1].ToLowerInvariant()
    $actual = Get-NGSha256 -Path $recordPath
    if ($actual -ne $expected) {
        throw "Evidence record SHA-256 mismatch for '$RecordName'. Expected '$expected'; observed '$actual'."
    }

    try {
        $record = Get-Content -LiteralPath $recordPath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
    }
    catch {
        throw "Evidence record '$RecordName' is not valid JSON: $($_.Exception.Message)"
    }

    return [pscustomobject]@{
        Record = $record
        Sha256 = $actual
        Path = $recordPath
    }
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

    $expectedSids = @($StageOperatorSid, 'S-1-5-18', 'S-1-5-32-544') | ForEach-Object { $_.ToUpperInvariant() } | Select-Object -Unique
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

function Assert-NGOperatorEvidence {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        $Operator,

        [Parameter(Mandatory)]
        [string]$Purpose
    )

    if ([string]::IsNullOrWhiteSpace([string]$Operator.account)) {
        throw "$Purpose evidence does not identify the delegated Graph operator account."
    }
    if ([string]$Operator.authType -ine 'Delegated') {
        throw "$Purpose evidence authType '$($Operator.authType)' is not Delegated."
    }
    if ([string]::IsNullOrWhiteSpace([string]$Operator.microsoftGraphAuthenticationVersion)) {
        throw "$Purpose evidence does not record the Microsoft.Graph.Authentication module version."
    }
    $scopeNames = @($Operator.delegatedScopes | ForEach-Object { ([string]$_).ToLowerInvariant() })
    $missing = @($script:RequiredScopes | Where-Object { $scopeNames -notcontains $_.ToLowerInvariant() })
    if ($missing.Count -gt 0) {
        throw "$Purpose evidence is missing required delegated scope(s): $($missing -join ', ')."
    }
}

function Assert-NGEqualField {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Name,

        [Parameter()]
        [AllowNull()]
        $Left,

        [Parameter()]
        [AllowNull()]
        $Right
    )

    if ([string]$Left -ine [string]$Right) {
        throw "Authorization evidence field '$Name' is inconsistent. Left='$Left' Right='$Right'."
    }
}

if ($PSVersionTable.PSEdition -ne 'Desktop' -or $PSVersionTable.PSVersion.Major -ne 5) {
    throw "Atomic 0010 evidence verification requires Windows PowerShell 5.1. Observed $($PSVersionTable.PSEdition) $($PSVersionTable.PSVersion)."
}

$bundle = Get-NGResolvedDirectoryPath -Path $BundlePath -Purpose 'Execution bundle'
$evidence = Get-NGResolvedDirectoryPath -Path $EvidencePath -Purpose 'Authorization evidence'

if ([string]::IsNullOrWhiteSpace($PSScriptRoot)) {
    throw 'PSScriptRoot is unavailable; unable to locate the atomic 0009 bundle verifier.'
}

$bundleVerifier = Join-Path -Path $PSScriptRoot -ChildPath 'Test-NGLabExecutionBundle.ps1'
if (-not (Test-Path -LiteralPath $bundleVerifier -PathType Leaf)) {
    throw "Atomic 0009 bundle verifier is missing: '$bundleVerifier'."
}

$windowsPowerShell = Join-Path -Path $PSHOME -ChildPath 'powershell.exe'
if (-not (Test-Path -LiteralPath $windowsPowerShell -PathType Leaf)) {
    throw "Windows PowerShell executable was not found at '$windowsPowerShell'."
}

& $windowsPowerShell -NoProfile -ExecutionPolicy Bypass -File $bundleVerifier -BundlePath $bundle
if ($LASTEXITCODE -ne 0) {
    throw "Atomic 0009 bundle verification failed with exit code $LASTEXITCODE."
}

$manifestPath = Join-Path -Path $bundle -ChildPath 'EXECUTION-MANIFEST.json'
$manifest = Get-Content -LiteralPath $manifestPath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
$manifestSha256 = Get-NGSha256 -Path $manifestPath
$configPayloadName = [string]$manifest.inputs.config.payloadName
$configPath = Join-Path -Path (Join-Path -Path $bundle -ChildPath 'payload') -ChildPath $configPayloadName
$config = Get-Content -LiteralPath $configPath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop

$stageResult = Read-NGEvidenceRecord -EvidenceRoot $evidence -RecordName $script:StageRecordName
$stage = $stageResult.Record

if ([string]$stage.schemaVersion -ne '1.0' -or [string]$stage.atomic -ne '0010' -or [string]$stage.recordType -ne 'Stage') {
    throw 'STAGE-RECORD.json is not a supported atomic 0010 Stage record.'
}
if ($null -ne $stage.previousRecordSha256) {
    throw 'Stage record unexpectedly references a previous authorization record.'
}
if (-not [bool]$stage.membershipAfter.stage -or [bool]$stage.membershipAfter.commit) {
    throw 'Stage record does not end in the required Stage=True, Commit=False state.'
}
if ([bool]$stage.membershipBefore.commit) {
    throw 'Stage record unexpectedly began with Commit=True.'
}
if ([bool]$stage.membershipBefore.stage) {
    if ([bool]$stage.operation.cloudWrite -or [string]$stage.operation.stageMembership -ne 'AlreadyPresent') { throw 'Stage record is inconsistent for an already-present STAGE membership.' }
}
else {
    if (-not [bool]$stage.operation.cloudWrite -or [string]$stage.operation.stageMembership -ne 'Added') { throw 'Stage record is inconsistent for an added STAGE membership.' }
}
if ([string]$stage.operation.commitMembership -ne 'NotModified') { throw 'Stage record claims an unexpected COMMIT operation.' }
if ([bool]$stage.policy.migrationStarted -or [bool]$stage.policy.successGroupTouched) {
    throw 'Stage record claims a prohibited migration or SUCCESS-group operation.'
}
if ([string]$stage.device.operatingSystem -ine 'Windows' -or [string]$stage.device.trustType -ine 'ServerAd' -or -not [bool]$stage.device.accountEnabled) {
    throw 'Stage record does not describe an enabled Windows ServerAd (Hybrid Entra joined) device.'
}
foreach ($groupRecord in @($stage.groups.stage, $stage.groups.commit)) {
    if (-not [bool]$groupRecord.securityEnabled -or [bool]$groupRecord.mailEnabled -or @($groupRecord.groupTypes).Count -ne 0) {
        throw "Stage record group '$($groupRecord.displayName)' is not a normal static security group."
    }
    if ($null -eq $groupRecord.isAssignableToRole -or [bool]$groupRecord.isAssignableToRole) {
        throw "Stage record group '$($groupRecord.displayName)' is not positively verified as non-role-assignable."
    }
}

Assert-NGEvidenceDirectoryAcl -Path $evidence -StageOperatorSid ([string]$stage.operator.stageOperatorSid)
Assert-NGEqualField -Name 'bundle.bundleId' -Left $stage.bundle.bundleId -Right $manifest.bundleId
Assert-NGEqualField -Name 'bundle.manifestSha256' -Left $stage.bundle.manifestSha256 -Right $manifestSha256
Assert-NGEqualField -Name 'bundle.repositoryCommit' -Left $stage.bundle.repositoryCommit -Right $manifest.repository.commit
Assert-NGEqualField -Name 'bundle.repositoryTree' -Left $stage.bundle.repositoryTree -Right $manifest.repository.tree
Assert-NGEqualField -Name 'controller.repositoryCommit' -Left $stage.controller.repositoryCommit -Right $manifest.repository.commit
Assert-NGEqualField -Name 'controller.repositoryTree' -Left $stage.controller.repositoryTree -Right $manifest.repository.tree
if ([string]$stage.controller.controllerSha256 -notmatch '^[0-9a-fA-F]{64}$') { throw 'Stage record controller SHA-256 is invalid.' }
Assert-NGOperatorEvidence -Operator $stage.operator -Purpose 'Stage'
if ([string]::IsNullOrWhiteSpace([string]$stage.operator.stageOperatorSid)) { throw 'Stage record does not identify the Windows SID used to protect authorization evidence.' }
if ([string]::IsNullOrWhiteSpace([string]$stage.bundle.sourceTenantName) -or [string]::IsNullOrWhiteSpace([string]$stage.bundle.expectedSourceUserPrincipalName) -or [string]::IsNullOrWhiteSpace([string]$stage.bundle.intuneManagementNameSuffix) -or [string]$stage.bundle.ppkgSha256 -notmatch '^[0-9a-fA-F]{64}$') {
    throw 'Stage record is missing required non-secret execution-bundle review fields.'
}
Assert-NGEqualField -Name 'bundle.sourceTenantName' -Left $stage.bundle.sourceTenantName -Right $config.sourceTenant.tenantName
Assert-NGEqualField -Name 'bundle.expectedSourceUserPrincipalName' -Left $stage.bundle.expectedSourceUserPrincipalName -Right $config.safety.expectedSourceUserPrincipalName
Assert-NGEqualField -Name 'bundle.intuneManagementNameSuffix' -Left $stage.bundle.intuneManagementNameSuffix -Right $config.safety.intuneManagementNameSuffix
Assert-NGEqualField -Name 'bundle.ppkgSha256' -Left $stage.bundle.ppkgSha256 -Right $config.safety.ppkgSha256

$reviewPath = Join-Path -Path $evidence -ChildPath $script:ReviewRecordName
$commitPath = Join-Path -Path $evidence -ChildPath $script:CommitRecordName
$hasReview = Test-Path -LiteralPath $reviewPath -PathType Leaf
$hasCommit = Test-Path -LiteralPath $commitPath -PathType Leaf

if ($hasCommit -and -not $hasReview) {
    throw 'Commit evidence exists without Review evidence.'
}

$state = 'Staged'
$reviewResult = $null

if ($hasReview) {
    $reviewResult = Read-NGEvidenceRecord -EvidenceRoot $evidence -RecordName $script:ReviewRecordName
    $review = $reviewResult.Record

    if ([string]$review.schemaVersion -ne '1.0' -or [string]$review.atomic -ne '0010' -or [string]$review.recordType -ne 'Review') {
        throw 'REVIEW-RECORD.json is not a supported atomic 0010 Review record.'
    }
    Assert-NGEqualField -Name 'review.previousRecordSha256' -Left $review.previousRecordSha256 -Right $stageResult.Sha256
    Assert-NGEqualField -Name 'review.bundle.bundleId' -Left $review.bundle.bundleId -Right $stage.bundle.bundleId
    Assert-NGEqualField -Name 'review.bundle.manifestSha256' -Left $review.bundle.manifestSha256 -Right $stage.bundle.manifestSha256
    Assert-NGEqualField -Name 'review.bundle.sourceTenantName' -Left $review.bundle.sourceTenantName -Right $stage.bundle.sourceTenantName
    Assert-NGEqualField -Name 'review.bundle.expectedSourceUserPrincipalName' -Left $review.bundle.expectedSourceUserPrincipalName -Right $stage.bundle.expectedSourceUserPrincipalName
    Assert-NGEqualField -Name 'review.bundle.intuneManagementNameSuffix' -Left $review.bundle.intuneManagementNameSuffix -Right $stage.bundle.intuneManagementNameSuffix
    Assert-NGEqualField -Name 'review.bundle.ppkgSha256' -Left $review.bundle.ppkgSha256 -Right $stage.bundle.ppkgSha256
    Assert-NGEqualField -Name 'review.tenantId' -Left $review.tenantId -Right $stage.tenantId
    Assert-NGEqualField -Name 'review.device.objectId' -Left $review.device.objectId -Right $stage.device.objectId
    Assert-NGEqualField -Name 'review.device.deviceId' -Left $review.device.deviceId -Right $stage.device.deviceId
    Assert-NGEqualField -Name 'review.device.displayName' -Left $review.device.displayName -Right $stage.device.displayName
    Assert-NGEqualField -Name 'review.device.operatingSystem' -Left $review.device.operatingSystem -Right $stage.device.operatingSystem
    Assert-NGEqualField -Name 'review.device.trustType' -Left $review.device.trustType -Right $stage.device.trustType
    Assert-NGEqualField -Name 'review.device.accountEnabled' -Left $review.device.accountEnabled -Right $stage.device.accountEnabled
    Assert-NGEqualField -Name 'review.groups.stage.objectId' -Left $review.groups.stage.objectId -Right $stage.groups.stage.objectId
    Assert-NGEqualField -Name 'review.groups.stage.displayName' -Left $review.groups.stage.displayName -Right $stage.groups.stage.displayName
    Assert-NGEqualField -Name 'review.groups.commit.objectId' -Left $review.groups.commit.objectId -Right $stage.groups.commit.objectId
    Assert-NGEqualField -Name 'review.groups.commit.displayName' -Left $review.groups.commit.displayName -Right $stage.groups.commit.displayName
    Assert-NGEqualField -Name 'review.controller.repositoryCommit' -Left $review.controller.repositoryCommit -Right $stage.controller.repositoryCommit
    Assert-NGEqualField -Name 'review.controller.repositoryTree' -Left $review.controller.repositoryTree -Right $stage.controller.repositoryTree
    Assert-NGEqualField -Name 'review.controller.controllerSha256' -Left $review.controller.controllerSha256 -Right $stage.controller.controllerSha256
    Assert-NGOperatorEvidence -Operator $review.operator -Purpose 'Review'

    if (-not [bool]$review.membershipObserved.stage -or [bool]$review.membershipObserved.commit) {
        throw 'Review record does not capture the required Stage=True, Commit=False state.'
    }
    if ([bool]$review.operation.cloudWrite -or -not [bool]$review.operation.reviewOnly) {
        throw 'Review record does not represent a read-only review.'
    }
    if (-not [bool]$review.policy.sourceDeviceInvariantReverified) {
        throw 'Review record does not attest that the full source-device invariant was reverified.'
    }
    if ([bool]$review.policy.migrationStarted -or [bool]$review.policy.successGroupTouched) {
        throw 'Review record claims a prohibited migration or SUCCESS-group operation.'
    }

    $state = 'Reviewed'
}

$commitResult = $null
if ($hasCommit) {
    $commitResult = Read-NGEvidenceRecord -EvidenceRoot $evidence -RecordName $script:CommitRecordName
    $commit = $commitResult.Record

    if ([string]$commit.schemaVersion -ne '1.0' -or [string]$commit.atomic -ne '0010' -or [string]$commit.recordType -ne 'Commit') {
        throw 'COMMIT-RECORD.json is not a supported atomic 0010 Commit record.'
    }
    Assert-NGEqualField -Name 'commit.previousRecordSha256' -Left $commit.previousRecordSha256 -Right $reviewResult.Sha256
    Assert-NGEqualField -Name 'commit.stageRecordSha256' -Left $commit.stageRecordSha256 -Right $stageResult.Sha256
    Assert-NGEqualField -Name 'commit.bundle.bundleId' -Left $commit.bundle.bundleId -Right $stage.bundle.bundleId
    Assert-NGEqualField -Name 'commit.bundle.manifestSha256' -Left $commit.bundle.manifestSha256 -Right $stage.bundle.manifestSha256
    Assert-NGEqualField -Name 'commit.bundle.sourceTenantName' -Left $commit.bundle.sourceTenantName -Right $stage.bundle.sourceTenantName
    Assert-NGEqualField -Name 'commit.bundle.expectedSourceUserPrincipalName' -Left $commit.bundle.expectedSourceUserPrincipalName -Right $stage.bundle.expectedSourceUserPrincipalName
    Assert-NGEqualField -Name 'commit.bundle.intuneManagementNameSuffix' -Left $commit.bundle.intuneManagementNameSuffix -Right $stage.bundle.intuneManagementNameSuffix
    Assert-NGEqualField -Name 'commit.bundle.ppkgSha256' -Left $commit.bundle.ppkgSha256 -Right $stage.bundle.ppkgSha256
    Assert-NGEqualField -Name 'commit.tenantId' -Left $commit.tenantId -Right $stage.tenantId
    Assert-NGEqualField -Name 'commit.device.objectId' -Left $commit.device.objectId -Right $stage.device.objectId
    Assert-NGEqualField -Name 'commit.device.deviceId' -Left $commit.device.deviceId -Right $stage.device.deviceId
    Assert-NGEqualField -Name 'commit.device.displayName' -Left $commit.device.displayName -Right $stage.device.displayName
    Assert-NGEqualField -Name 'commit.device.operatingSystem' -Left $commit.device.operatingSystem -Right $stage.device.operatingSystem
    Assert-NGEqualField -Name 'commit.device.trustType' -Left $commit.device.trustType -Right $stage.device.trustType
    Assert-NGEqualField -Name 'commit.device.accountEnabled' -Left $commit.device.accountEnabled -Right $stage.device.accountEnabled
    Assert-NGEqualField -Name 'commit.groups.stage.objectId' -Left $commit.groups.stage.objectId -Right $stage.groups.stage.objectId
    Assert-NGEqualField -Name 'commit.groups.stage.displayName' -Left $commit.groups.stage.displayName -Right $stage.groups.stage.displayName
    Assert-NGEqualField -Name 'commit.groups.commit.objectId' -Left $commit.groups.commit.objectId -Right $stage.groups.commit.objectId
    Assert-NGEqualField -Name 'commit.groups.commit.displayName' -Left $commit.groups.commit.displayName -Right $stage.groups.commit.displayName
    Assert-NGEqualField -Name 'commit.explicitConfirmations.reviewRecordSha256' -Left $commit.explicitConfirmations.reviewRecordSha256 -Right $reviewResult.Sha256
    Assert-NGEqualField -Name 'commit.explicitConfirmations.bundleId' -Left $commit.explicitConfirmations.bundleId -Right $stage.bundle.bundleId
    Assert-NGEqualField -Name 'commit.explicitConfirmations.deviceObjectId' -Left $commit.explicitConfirmations.deviceObjectId -Right $stage.device.objectId
    Assert-NGEqualField -Name 'commit.controller.repositoryCommit' -Left $commit.controller.repositoryCommit -Right $stage.controller.repositoryCommit
    Assert-NGEqualField -Name 'commit.controller.repositoryTree' -Left $commit.controller.repositoryTree -Right $stage.controller.repositoryTree
    Assert-NGEqualField -Name 'commit.controller.controllerSha256' -Left $commit.controller.controllerSha256 -Right $stage.controller.controllerSha256
    Assert-NGOperatorEvidence -Operator $commit.operator -Purpose 'Commit'

    if (-not [bool]$commit.membershipBefore.stage -or [bool]$commit.membershipBefore.commit) {
        throw 'Commit record pre-state is not Stage=True, Commit=False.'
    }
    if (-not [bool]$commit.membershipAfter.stage -or -not [bool]$commit.membershipAfter.commit) {
        throw 'Commit record post-state is not Stage=True, Commit=True.'
    }
    if (-not [bool]$commit.operation.cloudWrite -or [string]$commit.operation.stageMembership -ne 'Preserved' -or [string]$commit.operation.commitMembership -ne 'Added') {
        throw 'Commit record does not describe the required preserved-STAGE/add-COMMIT operation.'
    }
    if (-not [bool]$commit.policy.sourceDeviceInvariantReverified) {
        throw 'Commit record does not attest that the full source-device invariant was reverified immediately before authorization.'
    }
    if ([bool]$commit.policy.migrationStarted -or [bool]$commit.policy.successGroupTouched) {
        throw 'Commit record claims a prohibited migration or SUCCESS-group operation.'
    }

    $state = 'Committed'
}

if ($RequireCommit -and $state -ne 'Committed') {
    throw "Authorization evidence is '$state'; -RequireCommit requires a complete Commit record."
}

Write-Host ''
Write-Host 'NG migration authorization evidence verification: PASS'
Write-Host "Authorization state:     $state"
Write-Host "BundleId:                $($stage.bundle.bundleId)"
Write-Host "Manifest SHA-256:        $manifestSha256"
Write-Host "Expected source user:    $($stage.bundle.expectedSourceUserPrincipalName)"
Write-Host "Source tenant name:      $($stage.bundle.sourceTenantName)"
Write-Host "PPKG SHA-256:            $($stage.bundle.ppkgSha256)"
Write-Host "Tenant:                  $($stage.tenantId)"
Write-Host "Device display name:     $($stage.device.displayName)"
Write-Host "DeviceId:                $($stage.device.deviceId)"
Write-Host "Device object ID:        $($stage.device.objectId)"
Write-Host "STAGE group:             $($stage.groups.stage.displayName) [$($stage.groups.stage.objectId)]"
Write-Host "COMMIT group:            $($stage.groups.commit.displayName) [$($stage.groups.commit.objectId)]"
Write-Host "Stage record SHA-256:    $($stageResult.Sha256)"
if ($reviewResult) {
    Write-Host "Review record SHA-256:   $($reviewResult.Sha256)"
}
if ($commitResult) {
    Write-Host "Commit record SHA-256:   $($commitResult.Sha256)"
}
Write-Host ''
Write-Host 'This verifier is read-only and did not query or modify Microsoft Graph.'
exit 0
