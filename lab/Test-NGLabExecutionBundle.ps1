<#
.SYNOPSIS
    Independently verifies a generated intune-device-migration-NG destructive
    lab execution bundle.

.DESCRIPTION
    Performs read-only verification of:
      - EXECUTION-MANIFEST.json SHA-256 sidecar;
      - manifest schema/version fields required by atomic 0009;
      - deterministic BundleId;
      - exact payload file set;
      - every payload file size and SHA-256;
      - exactly one config.json and one .ppkg;
      - config safety.ppkgSha256 against the actual PPKG hash.

    It does not read or print reusable credentials from config.json and does not
    run any migration scripts.

.PARAMETER BundlePath
    Root directory produced by Build-NGLabExecutionBundle.ps1.

.EXAMPLE
    .\lab\Test-NGLabExecutionBundle.ps1 `
        -BundlePath 'C:\NG-Lab-Run\Bundle-001'

.NOTES
    Atomic 0009.
    Windows PowerShell 5.1 compatible.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$BundlePath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-NGSha256 {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )

    return (
        Get-FileHash -LiteralPath $Path -Algorithm SHA256 -ErrorAction Stop
    ).Hash.ToLowerInvariant()
}

function Get-NGStringSha256 {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$Value
    )

    $bytes = [Text.Encoding]::UTF8.GetBytes($Value)
    $sha256 = [Security.Cryptography.SHA256]::Create()

    try {
        return (
            ($sha256.ComputeHash($bytes) | ForEach-Object { $_.ToString('x2') }) -join ''
        )
    }
    finally {
        $sha256.Dispose()
    }
}

$bundleFull = [IO.Path]::GetFullPath(
    (Resolve-Path -LiteralPath $BundlePath -ErrorAction Stop).ProviderPath
).TrimEnd([char[]]@('\', '/'))

$manifestPath = Join-Path -Path $bundleFull -ChildPath 'EXECUTION-MANIFEST.json'
$manifestHashPath = Join-Path -Path $bundleFull -ChildPath 'EXECUTION-MANIFEST.sha256'
$payloadPath = Join-Path -Path $bundleFull -ChildPath 'payload'

foreach ($requiredPath in @($manifestPath, $manifestHashPath)) {
    if (-not (Test-Path -LiteralPath $requiredPath -PathType Leaf)) {
        throw "Required bundle metadata file is missing: '$requiredPath'."
    }
}

if (-not (Test-Path -LiteralPath $payloadPath -PathType Container)) {
    throw "Payload directory is missing: '$payloadPath'."
}

$sidecar = (
    Get-Content -LiteralPath $manifestHashPath -Raw -ErrorAction Stop
).Trim()

if ($sidecar -notmatch '^(?<Hash>[0-9A-Fa-f]{64})\s+EXECUTION-MANIFEST\.json$') {
    throw 'EXECUTION-MANIFEST.sha256 is not in the expected format.'
}

$expectedManifestSha256 = $Matches['Hash'].ToLowerInvariant()
$actualManifestSha256 = Get-NGSha256 -Path $manifestPath

if ($actualManifestSha256 -ne $expectedManifestSha256) {
    throw "Execution manifest SHA-256 mismatch. Expected '$expectedManifestSha256'; observed '$actualManifestSha256'."
}

try {
    $manifest = (
        Get-Content -LiteralPath $manifestPath -Raw -ErrorAction Stop |
            ConvertFrom-Json -ErrorAction Stop
    )
}
catch {
    throw "Execution manifest JSON is invalid: $($_.Exception.Message)"
}

if ([string]$manifest.schemaVersion -ne '1.0') {
    throw "Unsupported execution-manifest schemaVersion '$($manifest.schemaVersion)'."
}

if ([string]$manifest.bundleIdAlgorithm -ne 'SHA-256') {
    throw "Unsupported BundleId algorithm '$($manifest.bundleIdAlgorithm)'."
}

if ([string]$manifest.payload.root -ne 'payload') {
    throw "Manifest payload root must be 'payload'."
}

$records = @($manifest.payload.files)
if ($records.Count -lt 1) {
    throw 'Execution manifest contains no payload file records.'
}

if ([int]$manifest.payload.fileCount -ne $records.Count) {
    throw "Manifest payload.fileCount '$($manifest.payload.fileCount)' does not equal the number of file records '$($records.Count)'."
}

$duplicateNames = @(
    $records |
        Group-Object -Property name |
        Where-Object { $_.Count -gt 1 }
)

if ($duplicateNames.Count -gt 0) {
    throw "Manifest contains duplicate payload file names: $($duplicateNames.Name -join ', ')."
}

$configRecords = @(
    $records |
        Where-Object {
            [string]$_.name -ieq 'config.json' -and
            [string]$_.sourceKind -eq 'ExternalConfig'
        }
)

if ($configRecords.Count -ne 1) {
    throw 'Manifest must contain exactly one ExternalConfig record named config.json.'
}

$ppkgRecords = @(
    $records |
        Where-Object {
            [string]$_.sourceKind -eq 'ExternalProvisioningPackage'
        }
)

if ($ppkgRecords.Count -ne 1) {
    throw 'Manifest must contain exactly one ExternalProvisioningPackage record.'
}

if ([IO.Path]::GetExtension([string]$ppkgRecords[0].name) -ine '.ppkg') {
    throw 'ExternalProvisioningPackage record does not name a .ppkg file.'
}

$actualItems = @(
    Get-ChildItem -LiteralPath $payloadPath -Force -ErrorAction Stop
)

$directories = @(
    $actualItems |
        Where-Object { $_.PSIsContainer }
)

if ($directories.Count -gt 0) {
    throw "Payload contains unexpected subdirectories: $($directories.Name -join ', ')."
}

$actualFiles = @(
    $actualItems |
        Where-Object { -not $_.PSIsContainer }
)

if ($actualFiles.Count -ne $records.Count) {
    throw "Payload contains $($actualFiles.Count) files; manifest declares $($records.Count)."
}

$actualNames = @(
    $actualFiles |
        ForEach-Object { [string]$_.Name } |
        Sort-Object
)

$manifestNames = @(
    $records |
        ForEach-Object { [string]$_.name } |
        Sort-Object
)

if (($actualNames -join "`n") -cne ($manifestNames -join "`n")) {
    throw 'Actual payload file set does not exactly match the manifest file set.'
}

$verificationResults = [System.Collections.Generic.List[object]]::new()

foreach ($record in $records) {
    $filePath = Join-Path -Path $payloadPath -ChildPath ([string]$record.name)

    if (-not (Test-Path -LiteralPath $filePath -PathType Leaf)) {
        throw "Manifest-listed payload file is missing: '$($record.name)'."
    }

    $item = Get-Item -LiteralPath $filePath -ErrorAction Stop
    $actualSha256 = Get-NGSha256 -Path $filePath
    $expectedSha256 = ([string]$record.sha256).ToLowerInvariant()

    if ([Int64]$item.Length -ne [Int64]$record.sizeBytes) {
        throw "Payload size mismatch for '$($record.name)'."
    }

    if ($actualSha256 -ne $expectedSha256) {
        throw "Payload SHA-256 mismatch for '$($record.name)'."
    }

    $verificationResults.Add(
        [pscustomobject][ordered]@{
            Name = [string]$record.name
            SourceKind = [string]$record.sourceKind
            SizeBytes = [Int64]$item.Length
            Sha256 = $actualSha256
            Status = 'Verified'
        }
    )
}

$identityLines = [System.Collections.Generic.List[string]]::new()
$identityLines.Add("repositoryCommit=$([string]$manifest.repository.commit)")
$identityLines.Add("repositoryTree=$([string]$manifest.repository.tree)")

foreach ($record in @($records | Sort-Object -Property name)) {
    $identityLines.Add(
        "$([string]$record.name)|$([Int64]$record.sizeBytes)|$([string]$record.sha256)"
    )
}

$calculatedBundleId = Get-NGStringSha256 `
    -Value ($identityLines -join "`n")

if ($calculatedBundleId -ne ([string]$manifest.bundleId).ToLowerInvariant()) {
    throw "BundleId mismatch. Manifest='$($manifest.bundleId)'; calculated='$calculatedBundleId'."
}

$configPath = Join-Path -Path $payloadPath -ChildPath 'config.json'
try {
    $config = (
        Get-Content -LiteralPath $configPath -Raw -ErrorAction Stop |
            ConvertFrom-Json -ErrorAction Stop
    )
}
catch {
    throw "Bundled config.json is invalid JSON: $($_.Exception.Message)"
}

if (-not $config.PSObject.Properties['safety']) {
    throw 'Bundled config.json is missing safety.'
}

$ppkgPinProperty = $config.safety.PSObject.Properties['ppkgSha256']
if (-not $ppkgPinProperty) {
    throw 'Bundled config.json is missing safety.ppkgSha256.'
}

$configPpkgPin = ([string]$ppkgPinProperty.Value).Trim().ToLowerInvariant()
if ($configPpkgPin -notmatch '^[0-9a-f]{64}$') {
    throw 'Bundled config safety.ppkgSha256 is not a 64-character hexadecimal SHA-256.'
}

$ppkgPath = Join-Path -Path $payloadPath -ChildPath ([string]$ppkgRecords[0].name)
$actualPpkgSha256 = Get-NGSha256 -Path $ppkgPath

if ($actualPpkgSha256 -ne $configPpkgPin) {
    throw "Bundled PPKG SHA-256 does not match config safety.ppkgSha256."
}

if (
    [string]$manifest.inputs.provisioningPackage.sha256 -ne $actualPpkgSha256 -or
    [string]$manifest.inputs.provisioningPackage.configPinnedSha256 -ne $configPpkgPin -or
    [bool]$manifest.inputs.provisioningPackage.pinMatched -ne $true
) {
    throw 'Manifest provisioning-package pin evidence does not match the verified bundle.'
}

Write-Host ''
Write-Host 'NG destructive-lab execution bundle verification: PASS'
Write-Host "Bundle path:        $bundleFull"
Write-Host "Repository commit:  $($manifest.repository.commit)"
Write-Host "Repository tree:    $($manifest.repository.tree)"
Write-Host "BundleId:           $($manifest.bundleId)"
Write-Host "Manifest SHA-256:   $actualManifestSha256"
Write-Host "PPKG SHA-256:       $actualPpkgSha256"
Write-Host ''

$verificationResults |
    Sort-Object -Property Name |
    Format-Table -AutoSize

exit 0
