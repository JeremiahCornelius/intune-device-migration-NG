<#
.SYNOPSIS
    Builds a deterministic, allow-list-driven destructive-lab execution bundle
    for intune-device-migration-NG.

.DESCRIPTION
    Packages only the migration runtime files required for the first destructive
    lab, plus an externally supplied untracked config.json and exactly one
    externally supplied provisioning package.

    The builder records:
      - repository identity, branch, commit, and tree;
      - the Git blob ID and SHA-256 of every tracked runtime file;
      - SHA-256 and size of the external config and provisioning package;
      - a deterministic BundleId derived from repository commit/tree and payload
        file names, sizes, and SHA-256 values;
      - a SHA-256 sidecar for EXECUTION-MANIFEST.json.

    Safety properties:
      - refuses a repository other than JeremiahCornelius/intune-device-migration-NG;
      - requires branch main;
      - refuses modified tracked files;
      - requires config and PPKG inputs to be outside the repository;
      - requires output to be outside the repository and not already exist;
      - requires config safety.ppkgSha256 and verifies it against the PPKG;
      - refuses obvious template placeholders in required config values;
      - copies only an explicit runtime allow-list;
      - creates the output directory with restrictive ACLs for the current
        identity, LocalSystem, and local Administrators;
      - removes a partially created output directory if the build fails.

    This script does NOT run preflight, cross the migration commit boundary,
    inspect the binary PPKG for ComputerName customization, or perform migration.

.PARAMETER RepositoryRoot
    Root of the checked-out NG repository. Defaults to the parent directory of
    this script's lab directory.

.PARAMETER ConfigPath
    Path to the real lab config JSON. The file must be outside the repository.

.PARAMETER PpkgPath
    Path to the dedicated lab .ppkg. The file must be outside the repository.

.PARAMETER OutputPath
    New directory to create for the execution bundle. It must be outside the
    repository and must not already exist.

.EXAMPLE
    .\lab\Build-NGLabExecutionBundle.ps1 `
        -ConfigPath 'C:\NG-Lab-Private\config.json' `
        -PpkgPath 'C:\NG-Lab-Private\NG-Lab-EntraJoin.ppkg' `
        -OutputPath 'C:\NG-Lab-Run\Bundle-001'

.NOTES
    Atomic 0009.
    Windows PowerShell 5.1 compatible.
#>

[CmdletBinding()]
param(
    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$RepositoryRoot = $(Split-Path -Path $PSScriptRoot -Parent),

    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$ConfigPath,

    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$PpkgPath,

    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$OutputPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:BuilderVersion = '0.1.0'
$script:ExpectedRepository = 'JeremiahCornelius/intune-device-migration-NG'
$script:BuilderRepositoryPath = 'lab/Build-NGLabExecutionBundle.ps1'
$script:ManifestFileName = 'EXECUTION-MANIFEST.json'
$script:ManifestHashFileName = 'EXECUTION-MANIFEST.sha256'

# This list is intentionally narrow.  preflight.ps1 is required to stage the
# first lab; the remaining files are the exact post-staging runtime required by
# current startMigrate.ps1.  Do not replace this with recursive repository copy.
$script:TrackedPayloadAllowList = @(
    'Migration.Common.ps1',
    'preflight.ps1',
    'startMigrate.ps1',
    'reboot.ps1',
    'reboot.xml',
    'postMigrate.ps1',
    'postMigrateUser.ps1',
    'postMigrate.xml'
)

function Get-NGResolvedFilePath {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Path,

        [Parameter(Mandatory)]
        [string]$Purpose
    )

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "$Purpose file does not exist: '$Path'."
    }

    return [IO.Path]::GetFullPath(
        (Resolve-Path -LiteralPath $Path -ErrorAction Stop).ProviderPath
    )
}

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
    return $childFull.StartsWith(
        $prefix,
        [StringComparison]::OrdinalIgnoreCase
    )
}

function Invoke-NGGit {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Repository,

        [Parameter(Mandatory)]
        [string[]]$Arguments
    )

    $output = @(
        & git -C $Repository @Arguments 2>&1
    )
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

function Test-NGTemplateValue {
    [CmdletBinding()]
    param(
        [Parameter()]
        [AllowNull()]
        $Value
    )

    if ($null -eq $Value) {
        return $true
    }

    $text = [string]$Value
    if ([string]::IsNullOrWhiteSpace($text)) {
        return $true
    }

    return $text.Trim() -match '^<[^>]+>$'
}

function Get-NGRequiredConfigString {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        $Object,

        [Parameter(Mandatory)]
        [string]$PropertyName,

        [Parameter(Mandatory)]
        [string]$DisplayName
    )

    $property = $Object.PSObject.Properties[$PropertyName]
    if (-not $property) {
        throw "Config is missing required value '$DisplayName'."
    }

    $value = $property.Value
    if (Test-NGTemplateValue -Value $value) {
        throw "Config value '$DisplayName' is empty or still contains a template placeholder."
    }

    return ([string]$value).Trim()
}

function Set-NGBundleDirectoryAcl {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )

    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    if (-not $identity -or -not $identity.User) {
        throw 'Unable to determine the current Windows identity SID for bundle ACL protection.'
    }

    $currentSid = [string]$identity.User.Value
    $grants = @(
        "*$($currentSid):(OI)(CI)F",
        '*S-1-5-18:(OI)(CI)F',
        '*S-1-5-32-544:(OI)(CI)F'
    ) | Select-Object -Unique

    $arguments = @(
        $Path,
        '/inheritance:r',
        '/grant:r'
    ) + $grants + @(
        '/T',
        '/C'
    )

    & "$env:SystemRoot\System32\icacls.exe" @arguments | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "Unable to apply restrictive ACLs to lab bundle '$Path' (icacls exit $LASTEXITCODE)."
    }
}

function Get-NGPayloadRecord {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Name,

        [Parameter(Mandatory)]
        [string]$Path,

        [Parameter(Mandatory)]
        [ValidateSet('TrackedRuntime', 'ExternalConfig', 'ExternalProvisioningPackage')]
        [string]$SourceKind,

        [Parameter()]
        [AllowEmptyString()]
        [string]$RepositoryPath = '',

        [Parameter()]
        [AllowEmptyString()]
        [string]$GitBlobId = ''
    )

    $item = Get-Item -LiteralPath $Path -ErrorAction Stop

    return [pscustomobject][ordered]@{
        name = $Name
        sourceKind = $SourceKind
        repositoryPath = $RepositoryPath
        gitBlobId = $GitBlobId
        sizeBytes = [Int64]$item.Length
        sha256 = Get-NGSha256 -Path $Path
    }
}

$createdOutput = $false

try {
    if (-not (Get-Command git -ErrorAction SilentlyContinue)) {
        throw 'git is required and was not found in PATH.'
    }

    $repository = Get-NGResolvedDirectoryPath `
        -Path $RepositoryRoot `
        -Purpose 'Repository'

    $gitTop = Invoke-NGGit `
        -Repository $repository `
        -Arguments @('rev-parse', '--show-toplevel')

    $gitTop = [IO.Path]::GetFullPath($gitTop).TrimEnd([char[]]@('\', '/'))
    if ($gitTop -ine $repository) {
        throw "RepositoryRoot '$repository' is not the Git top-level directory '$gitTop'."
    }

    $originUrl = Invoke-NGGit `
        -Repository $repository `
        -Arguments @('remote', 'get-url', 'origin')

    if ($originUrl -notmatch '(?i)(?:[:/])JeremiahCornelius/intune-device-migration-NG(?:\.git)?$') {
        throw "Repository origin '$originUrl' is not the expected '$script:ExpectedRepository' repository."
    }

    $branch = Invoke-NGGit `
        -Repository $repository `
        -Arguments @('rev-parse', '--abbrev-ref', 'HEAD')

    if ($branch -ne 'main') {
        throw "Lab bundles must be built from branch 'main'. Observed '$branch'."
    }

    $trackedStatus = Invoke-NGGit `
        -Repository $repository `
        -Arguments @('status', '--porcelain=v1', '--untracked-files=no')

    if (-not [string]::IsNullOrWhiteSpace($trackedStatus)) {
        throw "Tracked repository files are modified. Commit or revert them before building a lab bundle.`n$trackedStatus"
    }

    $repositoryCommit = Invoke-NGGit `
        -Repository $repository `
        -Arguments @('rev-parse', 'HEAD')

    $repositoryTree = Invoke-NGGit `
        -Repository $repository `
        -Arguments @('rev-parse', 'HEAD^{tree}')

    $configFull = Get-NGResolvedFilePath `
        -Path $ConfigPath `
        -Purpose 'Config'

    $ppkgFull = Get-NGResolvedFilePath `
        -Path $PpkgPath `
        -Purpose 'Provisioning package'

    if ([IO.Path]::GetExtension($ppkgFull) -ine '.ppkg') {
        throw "Provisioning package must use the .ppkg extension. Observed '$ppkgFull'."
    }

    if (Test-NGPathInsideDirectory -ChildPath $configFull -ParentPath $repository) {
        throw 'The real lab config must be external to the Git repository.'
    }

    if (Test-NGPathInsideDirectory -ChildPath $ppkgFull -ParentPath $repository) {
        throw 'The lab provisioning package must be external to the Git repository.'
    }

    $outputFull = [IO.Path]::GetFullPath($OutputPath).TrimEnd([char[]]@('\', '/'))
    if ([string]::IsNullOrWhiteSpace($outputFull)) {
        throw 'OutputPath resolved to an empty path.'
    }

    if ($outputFull -eq [IO.Path]::GetPathRoot($outputFull).TrimEnd([char[]]@('\', '/'))) {
        throw "OutputPath cannot be a filesystem root: '$outputFull'."
    }

    if (Test-NGPathInsideDirectory -ChildPath $outputFull -ParentPath $repository) {
        throw 'The generated execution bundle must be outside the Git repository.'
    }

    if (Test-Path -LiteralPath $outputFull) {
        throw "OutputPath already exists. Refusing to merge or overwrite an earlier lab bundle: '$outputFull'."
    }

    $configRaw = Get-Content -LiteralPath $configFull -Raw -ErrorAction Stop
    try {
        $config = $configRaw | ConvertFrom-Json -ErrorAction Stop
    }
    catch {
        throw "Config JSON is invalid: $($_.Exception.Message)"
    }

    if (-not $config.PSObject.Properties['sourceTenant']) {
        throw 'Config is missing sourceTenant.'
    }
    if (-not $config.PSObject.Properties['safety']) {
        throw 'Config is missing safety.'
    }

    [void](Get-NGRequiredConfigString `
        -Object $config.sourceTenant `
        -PropertyName 'clientId' `
        -DisplayName 'sourceTenant.clientId')

    [void](Get-NGRequiredConfigString `
        -Object $config.sourceTenant `
        -PropertyName 'clientSecret' `
        -DisplayName 'sourceTenant.clientSecret')

    [void](Get-NGRequiredConfigString `
        -Object $config.sourceTenant `
        -PropertyName 'tenantName' `
        -DisplayName 'sourceTenant.tenantName')

    [void](Get-NGRequiredConfigString `
        -Object $config.safety `
        -PropertyName 'expectedSourceUserPrincipalName' `
        -DisplayName 'safety.expectedSourceUserPrincipalName')

    [void](Get-NGRequiredConfigString `
        -Object $config.safety `
        -PropertyName 'intuneManagementNameSuffix' `
        -DisplayName 'safety.intuneManagementNameSuffix')

    $configuredPpkgSha256 = Get-NGRequiredConfigString `
        -Object $config.safety `
        -PropertyName 'ppkgSha256' `
        -DisplayName 'safety.ppkgSha256'

    if ($configuredPpkgSha256 -notmatch '^[0-9A-Fa-f]{64}$') {
        throw 'Config safety.ppkgSha256 must contain exactly 64 hexadecimal characters.'
    }

    $configuredPpkgSha256 = $configuredPpkgSha256.ToLowerInvariant()
    $actualPpkgSha256 = Get-NGSha256 -Path $ppkgFull

    if ($actualPpkgSha256 -ne $configuredPpkgSha256) {
        throw "PPKG SHA-256 '$actualPpkgSha256' does not match config safety.ppkgSha256 '$configuredPpkgSha256'."
    }

    # If targetTenant is configured for the same-tenant path, reject obvious
    # placeholders before sensitive material is copied to the execution bundle.
    if ($config.PSObject.Properties['targetTenant'] -and $config.targetTenant) {
        $targetTenantNameProperty = $config.targetTenant.PSObject.Properties['tenantName']
        if ($targetTenantNameProperty) {
            $targetTenantName = [string]$targetTenantNameProperty.Value

            if (-not [string]::IsNullOrWhiteSpace($targetTenantName)) {
                if (Test-NGTemplateValue -Value $targetTenantName) {
                    throw 'Config targetTenant.tenantName still contains a template placeholder.'
                }

                [void](Get-NGRequiredConfigString `
                    -Object $config.targetTenant `
                    -PropertyName 'clientId' `
                    -DisplayName 'targetTenant.clientId')

                [void](Get-NGRequiredConfigString `
                    -Object $config.targetTenant `
                    -PropertyName 'clientSecret' `
                    -DisplayName 'targetTenant.clientSecret')
            }
        }
    }

    foreach ($relativePath in $script:TrackedPayloadAllowList) {
        $sourcePath = Join-Path -Path $repository -ChildPath $relativePath

        if (-not (Test-Path -LiteralPath $sourcePath -PathType Leaf)) {
            throw "Allow-listed tracked runtime file is missing: '$relativePath'."
        }

        [void](Invoke-NGGit `
            -Repository $repository `
            -Arguments @('ls-files', '--error-unmatch', '--', $relativePath))
    }

    $builderSourcePath = Join-Path `
        -Path $repository `
        -ChildPath $script:BuilderRepositoryPath

    if (-not (Test-Path -LiteralPath $builderSourcePath -PathType Leaf)) {
        throw "Tracked bundle builder is missing: '$script:BuilderRepositoryPath'."
    }

    $builderBlobId = Invoke-NGGit `
        -Repository $repository `
        -Arguments @('rev-parse', "HEAD:$script:BuilderRepositoryPath")

    $builderSha256 = Get-NGSha256 -Path $builderSourcePath

    New-Item -Path $outputFull -ItemType Directory -ErrorAction Stop | Out-Null
    $createdOutput = $true

    Set-NGBundleDirectoryAcl -Path $outputFull

    $payloadPath = Join-Path -Path $outputFull -ChildPath 'payload'
    New-Item -Path $payloadPath -ItemType Directory -ErrorAction Stop | Out-Null

    $payloadRecords = [System.Collections.Generic.List[object]]::new()

    foreach ($relativePath in $script:TrackedPayloadAllowList) {
        $sourcePath = Join-Path -Path $repository -ChildPath $relativePath
        $destinationName = Split-Path -Path $relativePath -Leaf
        $destinationPath = Join-Path -Path $payloadPath -ChildPath $destinationName

        Copy-Item `
            -LiteralPath $sourcePath `
            -Destination $destinationPath `
            -Force `
            -ErrorAction Stop

        $sourceSha256 = Get-NGSha256 -Path $sourcePath
        $destinationSha256 = Get-NGSha256 -Path $destinationPath
        if ($sourceSha256 -ne $destinationSha256) {
            throw "Copied runtime file '$relativePath' failed SHA-256 verification."
        }

        $blobId = Invoke-NGGit `
            -Repository $repository `
            -Arguments @('rev-parse', "HEAD:$relativePath")

        $payloadRecords.Add(
            (Get-NGPayloadRecord `
                -Name $destinationName `
                -Path $destinationPath `
                -SourceKind 'TrackedRuntime' `
                -RepositoryPath $relativePath `
                -GitBlobId $blobId)
        )
    }

    $configDestination = Join-Path -Path $payloadPath -ChildPath 'config.json'
    Copy-Item `
        -LiteralPath $configFull `
        -Destination $configDestination `
        -Force `
        -ErrorAction Stop

    if ((Get-NGSha256 -Path $configDestination) -ne (Get-NGSha256 -Path $configFull)) {
        throw 'Copied config.json failed SHA-256 verification.'
    }

    $payloadRecords.Add(
        (Get-NGPayloadRecord `
            -Name 'config.json' `
            -Path $configDestination `
            -SourceKind 'ExternalConfig')
    )

    $ppkgName = Split-Path -Path $ppkgFull -Leaf
    if ($script:TrackedPayloadAllowList -contains $ppkgName -or $ppkgName -ieq 'config.json') {
        throw "Provisioning-package file name '$ppkgName' collides with a required payload file."
    }

    $ppkgDestination = Join-Path -Path $payloadPath -ChildPath $ppkgName
    Copy-Item `
        -LiteralPath $ppkgFull `
        -Destination $ppkgDestination `
        -Force `
        -ErrorAction Stop

    if ((Get-NGSha256 -Path $ppkgDestination) -ne $actualPpkgSha256) {
        throw 'Copied provisioning package failed SHA-256 verification.'
    }

    $payloadRecords.Add(
        (Get-NGPayloadRecord `
            -Name $ppkgName `
            -Path $ppkgDestination `
            -SourceKind 'ExternalProvisioningPackage')
    )

    $orderedRecords = @(
        $payloadRecords |
            Sort-Object -Property name
    )

    $identityLines = [System.Collections.Generic.List[string]]::new()
    $identityLines.Add("repositoryCommit=$repositoryCommit")
    $identityLines.Add("repositoryTree=$repositoryTree")

    foreach ($record in $orderedRecords) {
        $identityLines.Add(
            "$($record.name)|$($record.sizeBytes)|$($record.sha256)"
        )
    }

    $bundleId = Get-NGStringSha256 `
        -Value ($identityLines -join "`n")

    $manifest = [ordered]@{
        schemaVersion = '1.0'
        artifact = 'intune-device-migration-NG destructive-lab execution bundle'
        builderVersion = $script:BuilderVersion
        generatedUtc = [DateTime]::UtcNow.ToString('o')
        bundleIdAlgorithm = 'SHA-256'
        bundleId = $bundleId
        repository = [ordered]@{
            expectedRepository = $script:ExpectedRepository
            originUrl = $originUrl
            branch = $branch
            commit = $repositoryCommit
            tree = $repositoryTree
            trackedWorktreeClean = $true
        }
        builder = [ordered]@{
            repositoryPath = $script:BuilderRepositoryPath
            gitBlobId = $builderBlobId
            sha256 = $builderSha256
        }
        inputs = [ordered]@{
            config = [ordered]@{
                payloadName = 'config.json'
                sha256 = Get-NGSha256 -Path $configDestination
            }
            provisioningPackage = [ordered]@{
                payloadName = $ppkgName
                sha256 = $actualPpkgSha256
                configPinnedSha256 = $configuredPpkgSha256
                pinMatched = $true
            }
        }
        payload = [ordered]@{
            root = 'payload'
            allowListDriven = $true
            fileCount = $orderedRecords.Count
            files = $orderedRecords
        }
        policy = [ordered]@{
            realConfigTrackedInGit = $false
            provisioningPackageTrackedInGit = $false
            outputInsideRepository = $false
            manifestContainsReusableSecrets = $false
            ppkgComputerNameCustomization = 'MUST_BE_OMITTED_PER_DESIGN_HISTORY_0008_NOT_BINARY_INSPECTED'
        }
    }

    $manifestPath = Join-Path -Path $outputFull -ChildPath $script:ManifestFileName
    $manifestJson = $manifest | ConvertTo-Json -Depth 12
    Write-NGUtf8NoBom `
        -Path $manifestPath `
        -Content ($manifestJson + "`n")

    $manifestSha256 = Get-NGSha256 -Path $manifestPath
    $manifestHashPath = Join-Path -Path $outputFull -ChildPath $script:ManifestHashFileName

    Write-NGUtf8NoBom `
        -Path $manifestHashPath `
        -Content ("$manifestSha256  $script:ManifestFileName`n")

    # Final self-audit of the generated payload: exactly the manifest-listed
    # files, exactly one PPKG, and all hashes still matching.
    $actualPayloadItems = @(
        Get-ChildItem -LiteralPath $payloadPath -Force -ErrorAction Stop
    )

    if (@($actualPayloadItems | Where-Object { $_.PSIsContainer }).Count -gt 0) {
        throw 'Generated payload unexpectedly contains a subdirectory.'
    }

    if ($actualPayloadItems.Count -ne $orderedRecords.Count) {
        throw "Generated payload contains $($actualPayloadItems.Count) files; manifest expects $($orderedRecords.Count)."
    }

    if (@($actualPayloadItems | Where-Object { $_.Extension -ieq '.ppkg' }).Count -ne 1) {
        throw 'Generated payload must contain exactly one provisioning package.'
    }

    foreach ($record in $orderedRecords) {
        $generatedPath = Join-Path -Path $payloadPath -ChildPath $record.name
        if (-not (Test-Path -LiteralPath $generatedPath -PathType Leaf)) {
            throw "Generated payload is missing manifest-listed file '$($record.name)'."
        }

        if ((Get-NGSha256 -Path $generatedPath) -ne [string]$record.sha256) {
            throw "Generated payload file '$($record.name)' no longer matches its manifest SHA-256."
        }
    }

    Write-Host ''
    Write-Host 'NG destructive-lab execution bundle created.'
    Write-Host "Bundle path:          $outputFull"
    Write-Host "Repository commit:    $repositoryCommit"
    Write-Host "Repository tree:      $repositoryTree"
    Write-Host "BundleId:             $bundleId"
    Write-Host "Manifest SHA-256:     $manifestSha256"
    Write-Host "PPKG SHA-256:         $actualPpkgSha256"
    Write-Host "Payload file count:   $($orderedRecords.Count)"
    Write-Host ''
    Write-Host 'Verify before use with:'
    Write-Host "  .\lab\Test-NGLabExecutionBundle.ps1 -BundlePath '$outputFull'"
}
catch {
    if ($createdOutput -and (Test-Path -LiteralPath $outputFull -PathType Container)) {
        try {
            Remove-Item -LiteralPath $outputFull -Recurse -Force -ErrorAction Stop
        }
        catch {
            Write-Warning "Unable to remove partial output '$outputFull': $($_.Exception.Message)"
        }
    }

    throw
}
