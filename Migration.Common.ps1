<#
.SYNOPSIS
    Shared safety and validation functions for the safety-first Intune device
    migration fork.

.DESCRIPTION
    This file is intentionally non-destructive.  It centralizes:
      - configuration validation;
      - Microsoft Entra/Windows join-state discovery;
      - app-only Graph authentication using the upstream config model;
      - deterministic same-tenant user resolution by on-premises SID;
      - local profile, MDM, recovery-account, backup and package checks;
      - persisted migration safety state.

    The upstream project is GPLv3.  This derivative helper is intended to be
    distributed with the corresponding fork under GPLv3-compatible terms.

.NOTES
    Fork lineage:
      stevecapacity/intune-device-migration-8
      base: current main reviewed 2026-08-07
      selected 8.1 concepts: explicit tenant targeting and profile retry logic

    Safety-first fork revision: 2026.08.07.1
#>

Set-StrictMode -Version Latest

$script:MigrationRegistryRoot = 'HKLM:\SOFTWARE\IntuneMigration'
$script:MigrationSafetyRegistryPath = 'HKLM:\SOFTWARE\IntuneMigration\Safety'
$script:MigrationLocalPathDefault = 'C:\ProgramData\IntuneMigration'
$script:OneDriveBackupStatusPath = 'HKLM:\SOFTWARE\SBX\IntuneBaselines\WindowsBackupOneDrive'

function Write-MigrationLog {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('INFO','OK','WARN','ERROR')]
        [string]$Level,

        [Parameter(Mandatory)]
        [string]$Message
    )

    $line = '[{0}] [{1}] {2}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level, $Message
    Write-Output $line
}

function Get-OptionalPropertyValue {
    [CmdletBinding()]
    param(
        [Parameter()]
        [AllowNull()]
        $InputObject,

        [Parameter(Mandatory)]
        [string]$Name,

        [Parameter()]
        $Default = $null
    )

    if ($null -eq $InputObject) {
        return $Default
    }

    $property = $InputObject.PSObject.Properties[$Name]
    if ($null -eq $property) {
        return $Default
    }

    return $property.Value
}

function Get-MigrationConfig {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        throw "Migration configuration file not found: $Path"
    }

    $config = Get-Content -LiteralPath $Path -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop

    foreach ($required in @('localPath','logPath','regPath','sourceTenant')) {
        if ($null -eq $config.PSObject.Properties[$required]) {
            throw "config.json is missing required property '$required'."
        }
    }

    foreach ($required in @('tenantName','clientId','clientSecret')) {
        $value = [string](Get-OptionalPropertyValue -InputObject $config.sourceTenant -Name $required)
        if ([string]::IsNullOrWhiteSpace($value)) {
            throw "config.json sourceTenant.$required is required."
        }
    }

    return $config
}

function Get-ConfigFileSha256 {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )

    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
}

function Get-DsRegState {
    [CmdletBinding()]
    param()

    $raw = & "$env:SystemRoot\System32\dsregcmd.exe" /status 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "dsregcmd /status failed with exit code $LASTEXITCODE."
    }

    $state = [ordered]@{
        AzureAdJoined = $null
        DomainJoined = $null
        WorkplaceJoined = $null
        DeviceId = $null
        TenantId = $null
        TenantName = $null
        AzureAdPrt = $null
        Raw = @($raw)
    }

    foreach ($line in @($raw)) {
        if ($line -notmatch '^\s*([^:]+?)\s*:\s*(.*?)\s*$') {
            continue
        }

        $key = $matches[1].Trim()
        $value = $matches[2].Trim()

        switch -Regex ($key) {
            '^AzureAdJoined$'   { if (-not $state.AzureAdJoined)   { $state.AzureAdJoined = $value } }
            '^DomainJoined$'    { if (-not $state.DomainJoined)    { $state.DomainJoined = $value } }
            '^WorkplaceJoined$' { if (-not $state.WorkplaceJoined) { $state.WorkplaceJoined = $value } }
            '^DeviceId$'        { if (-not $state.DeviceId)        { $state.DeviceId = $value } }
            '^TenantId$'        { if (-not $state.TenantId)        { $state.TenantId = $value } }
            '^TenantName$'      { if (-not $state.TenantName)      { $state.TenantName = $value } }
            '^AzureAdPrt$'      { if (-not $state.AzureAdPrt)      { $state.AzureAdPrt = $value } }
        }
    }

    return [pscustomobject]$state
}

function Get-IntuneMdmCertificate {
    [CmdletBinding()]
    param()

    return @(
        Get-ChildItem -Path 'Cert:\LocalMachine\My' -ErrorAction Stop |
            Where-Object { $_.Issuer -match 'Microsoft Intune MDM Device CA' }
    )
}

function Get-InteractiveUserIdentity {
    [CmdletBinding()]
    param()

    $computerSystem = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
    $userName = [string]$computerSystem.UserName

    if ([string]::IsNullOrWhiteSpace($userName)) {
        throw 'No interactive Windows user is signed in.'
    }

    if ($userName -notmatch '\\') {
        throw "Interactive user '$userName' isn't in DOMAIN\user form."
    }

    $account = New-Object -TypeName System.Security.Principal.NTAccount -ArgumentList $userName
    $sid = $account.Translate([System.Security.Principal.SecurityIdentifier]).Value
    $samName = $userName.Split('\')[-1]

    $profile = Get-CimInstance -ClassName Win32_UserProfile -ErrorAction Stop |
        Where-Object { $_.SID -eq $sid } |
        Select-Object -First 1

    if ($null -eq $profile) {
        throw "No Win32_UserProfile object exists for interactive user SID '$sid'."
    }

    $profilePath = [string]$profile.LocalPath
    if ([string]::IsNullOrWhiteSpace($profilePath) -or -not (Test-Path -LiteralPath $profilePath)) {
        throw "Profile path for '$userName' is missing or inaccessible: '$profilePath'."
    }

    return [pscustomobject]@{
        UserName = $userName
        SamName = $samName
        Sid = $sid
        ProfilePath = $profilePath
        ProfileLoaded = [bool]$profile.Loaded
    }
}

function ConvertFrom-Base64Url {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Text
    )

    $normalized = $Text.Replace('-', '+').Replace('_', '/')
    switch ($normalized.Length % 4) {
        2 { $normalized += '==' }
        3 { $normalized += '=' }
        0 { }
        default { throw 'Invalid base64url length.' }
    }

    return [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($normalized))
}

function Get-JwtTenantId {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$AccessToken
    )

    $parts = $AccessToken.Split('.')
    if ($parts.Count -lt 2) {
        throw "Access token isn't a JWT."
    }

    $payload = ConvertFrom-Base64Url -Text $parts[1] | ConvertFrom-Json -ErrorAction Stop
    $tenantId = [string](Get-OptionalPropertyValue -InputObject $payload -Name 'tid')

    if ([string]::IsNullOrWhiteSpace($tenantId)) {
        throw "Access token doesn't contain a tid claim."
    }

    return $tenantId
}

function New-GraphAppSession {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        $TenantConfig
    )

    foreach ($required in @('tenantName','clientId','clientSecret')) {
        $value = [string](Get-OptionalPropertyValue -InputObject $TenantConfig -Name $required)
        if ([string]::IsNullOrWhiteSpace($value)) {
            throw "Tenant configuration is missing '$required'."
        }
    }

    $tenantName = [string]$TenantConfig.tenantName
    $clientId = [string]$TenantConfig.clientId
    $clientSecret = [string]$TenantConfig.clientSecret

    # Hashtable form encoding avoids corrupting secrets containing reserved URL
    # characters; no secret is written to logs or user-readable files.
    $tokenResponse = Invoke-RestMethod `
        -Method POST `
        -Uri "https://login.microsoftonline.com/$tenantName/oauth2/v2.0/token" `
        -ContentType 'application/x-www-form-urlencoded' `
        -Body @{
            grant_type = 'client_credentials'
            client_id = $clientId
            client_secret = $clientSecret
            scope = 'https://graph.microsoft.com/.default'
        } `
        -ErrorAction Stop

    $accessToken = [string]$tokenResponse.access_token
    if ([string]::IsNullOrWhiteSpace($accessToken)) {
        throw "Microsoft identity platform didn't return an access token for tenant '$tenantName'."
    }

    $tenantId = Get-JwtTenantId -AccessToken $accessToken

    return [pscustomobject]@{
        TenantId = $tenantId
        TenantName = $tenantName
        Headers = @{
            Authorization = "Bearer $accessToken"
            'Content-Type' = 'application/json'
        }
    }
}

function Resolve-SameTenantEntraUserByOnPremSid {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$OnPremSid,

        [Parameter(Mandatory)]
        [hashtable]$Headers
    )

    $filterText = "onPremisesSecurityIdentifier eq '$OnPremSid'"
    $filter = [Uri]::EscapeDataString($filterText)
    $select = 'id,userPrincipalName,securityIdentifier,onPremisesSecurityIdentifier,onPremisesSyncEnabled,accountEnabled'
    $uri = "https://graph.microsoft.com/v1.0/users?`$filter=$filter&`$select=$select"

    $result = Invoke-RestMethod -Method GET -Uri $uri -Headers $Headers -ErrorAction Stop
    $users = @($result.value)

    if ($users.Count -eq 0) {
        throw "No Microsoft Entra user matches onPremisesSecurityIdentifier '$OnPremSid'."
    }

    if ($users.Count -gt 1) {
        throw "More than one Microsoft Entra user matches onPremisesSecurityIdentifier '$OnPremSid'."
    }

    $user = $users[0]

    if ([string]$user.onPremisesSecurityIdentifier -ne $OnPremSid) {
        throw "Graph returned a user whose on-premises SID doesn't exactly match the requested SID."
    }

    if ($user.onPremisesSyncEnabled -ne $true) {
        throw "User '$($user.userPrincipalName)' isn't currently synchronized from on-premises AD."
    }

    if ($user.accountEnabled -ne $true) {
        throw "User '$($user.userPrincipalName)' is disabled in Microsoft Entra ID."
    }

    $cloudSid = [string]$user.securityIdentifier
    if ($cloudSid -notmatch '^S-1-12-1-(\d+-){2,}\d+$') {
        throw "User '$($user.userPrincipalName)' doesn't expose an expected Entra Windows securityIdentifier. Value: '$cloudSid'."
    }

    return [pscustomobject]@{
        Id = [string]$user.id
        UserPrincipalName = [string]$user.userPrincipalName
        CloudSid = $cloudSid
        OnPremSid = [string]$user.onPremisesSecurityIdentifier
    }
}

function Get-RecoveryLocalAccount {
    [CmdletBinding()]
    param(
        [Parameter()]
        [AllowNull()]
        $Config
    )

    $safety = Get-OptionalPropertyValue -InputObject $Config -Name 'safety'
    $configuredName = [string](Get-OptionalPropertyValue -InputObject $safety -Name 'recoveryAccountName')

    if (-not [string]::IsNullOrWhiteSpace($configuredName)) {
        $account = Get-LocalUser -Name $configuredName -ErrorAction Stop
    }
    else {
        # Resolve the built-in Administrator account by RID -500 so localized or
        # renamed systems don't depend on the literal name "Administrator".
        $account = Get-LocalUser -ErrorAction Stop |
            Where-Object { $_.SID.Value -match '-500$' } |
            Select-Object -First 1
    }

    if ($null -eq $account) {
        throw 'No configured recovery account or local RID-500 Administrator account was found.'
    }

    if (-not $account.Enabled) {
        throw "Recovery account '$($account.Name)' is disabled."
    }

    $administrators = Get-LocalGroup -SID 'S-1-5-32-544' -ErrorAction Stop
    $members = @(Get-LocalGroupMember -Group $administrators.Name -ErrorAction Stop)
    $isMember = $false

    foreach ($member in $members) {
        if ($member.SID -and $member.SID.Value -eq $account.SID.Value) {
            $isMember = $true
            break
        }
    }

    if (-not $isMember) {
        throw "Recovery account '$($account.Name)' isn't a member of the local Administrators group."
    }

    return $account
}

function Get-OneDriveKfmReadiness {
    [CmdletBinding()]
    param()

    if (-not (Test-Path -LiteralPath $script:OneDriveBackupStatusPath)) {
        return [pscustomobject]@{
            Present = $false
            Ready = $false
            Status = $null
            KfmState = $null
            PolicyRevision = $null
        }
    }

    $value = Get-ItemProperty -LiteralPath $script:OneDriveBackupStatusPath -ErrorAction Stop
    $status = [string](Get-OptionalPropertyValue -InputObject $value -Name 'Status')
    $kfmState = [string](Get-OptionalPropertyValue -InputObject $value -Name 'KfmState')
    $revision = [string](Get-OptionalPropertyValue -InputObject $value -Name 'PolicyRevision')

    return [pscustomobject]@{
        Present = $true
        Ready = ($status -eq 'PolicyApplied' -and $kfmState -eq 'DesktopDocumentsPicturesRedirected')
        Status = $status
        KfmState = $kfmState
        PolicyRevision = $revision
    }
}

function Test-PendingReboot {
    [CmdletBinding()]
    param()

    $indicators = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired'
    )

    foreach ($path in $indicators) {
        if (Test-Path -LiteralPath $path) {
            return $true
        }
    }

    $sessionManager = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager'
    try {
        $pendingRename = (Get-ItemProperty -LiteralPath $sessionManager -Name PendingFileRenameOperations -ErrorAction Stop).PendingFileRenameOperations
        if ($pendingRename) {
            return $true
        }
    }
    catch {
        # Missing PendingFileRenameOperations is the normal state.
    }

    return $false
}

function Get-SingleProvisioningPackage {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$SearchRoot
    )

    $packages = @(
        Get-ChildItem -LiteralPath $SearchRoot -Filter '*.ppkg' -File -Recurse -ErrorAction Stop
    )

    if ($packages.Count -eq 0) {
        throw "No .ppkg file was found beneath '$SearchRoot'."
    }

    if ($packages.Count -gt 1) {
        throw "More than one .ppkg file was found beneath '$SearchRoot'. Exactly one is required."
    }

    return $packages[0]
}

function Get-SafetyBoolean {
    [CmdletBinding()]
    param(
        [Parameter()]
        [AllowNull()]
        $Config,

        [Parameter(Mandatory)]
        [string]$Name,

        [Parameter(Mandatory)]
        [bool]$Default
    )

    $safety = Get-OptionalPropertyValue -InputObject $Config -Name 'safety'
    $value = Get-OptionalPropertyValue -InputObject $safety -Name $Name -Default $Default
    return [bool]$value
}

function Set-MigrationSafetyState {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Values
    )

    if (-not (Test-Path -LiteralPath $script:MigrationSafetyRegistryPath)) {
        New-Item -Path $script:MigrationSafetyRegistryPath -Force -ErrorAction Stop | Out-Null
    }

    foreach ($key in $Values.Keys) {
        $value = $Values[$key]
        if ($null -eq $value) {
            continue
        }

        if ($value -is [bool]) {
            New-ItemProperty -Path $script:MigrationSafetyRegistryPath -Name $key -Value ([int]$value) -PropertyType DWord -Force -ErrorAction Stop | Out-Null
        }
        elseif ($value -is [int] -or $value -is [long]) {
            New-ItemProperty -Path $script:MigrationSafetyRegistryPath -Name $key -Value ([int]$value) -PropertyType DWord -Force -ErrorAction Stop | Out-Null
        }
        else {
            New-ItemProperty -Path $script:MigrationSafetyRegistryPath -Name $key -Value ([string]$value) -PropertyType String -Force -ErrorAction Stop | Out-Null
        }
    }
}

function Get-MigrationSafetyState {
    [CmdletBinding()]
    param()

    if (-not (Test-Path -LiteralPath $script:MigrationSafetyRegistryPath)) {
        return $null
    }

    return Get-ItemProperty -LiteralPath $script:MigrationSafetyRegistryPath -ErrorAction Stop
}

function Get-MigrationRegistryString {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Name,

        [Parameter()]
        [switch]$Required
    )

    if (-not (Test-Path -LiteralPath $script:MigrationRegistryRoot)) {
        if ($Required) {
            throw "Migration registry root doesn't exist: $($script:MigrationRegistryRoot)"
        }
        return $null
    }

    try {
        $value = [string](Get-ItemPropertyValue -LiteralPath $script:MigrationRegistryRoot -Name $Name -ErrorAction Stop)
    }
    catch {
        if ($Required) {
            throw "Required migration registry value '$Name' isn't present."
        }
        return $null
    }

    if ($Required -and [string]::IsNullOrWhiteSpace($value)) {
        throw "Required migration registry value '$Name' is empty."
    }

    return $value
}

function Set-RestrictedFileAcl {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )

    # The migration data includes user/device identifiers.  Keep it readable by
    # LocalSystem and local Administrators, not ordinary users.
    & "$env:SystemRoot\System32\icacls.exe" $Path /inheritance:r /grant:r '*S-1-5-18:(F)' '*S-1-5-32-544:(F)' | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "icacls failed while restricting '$Path'."
    }
}
