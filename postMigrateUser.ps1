<#
.SYNOPSIS
    Secret-free user-context Microsoft Entra PRT verification probe.

.DESCRIPTION
    Runs only for the deterministic Entra SID selected during preflight. The
    script contains no Graph credential and does not read config.json.

    It verifies:
      - the current Windows token SID equals Safety\ExpectedNewSid;
      - USERPROFILE equals the original preserved profile path;
      - AzureAdJoined=YES;
      - DomainJoined=NO;
      - TenantId equals Safety\ExpectedTenantId;
      - AzureAdPrt becomes YES in the real user context.

    Microsoft documents that dsregcmd user/SSO state, including AzureAdPrt, is
    valid only when dsregcmd runs in the logged-in user's context. The SYSTEM
    finalizer therefore consumes evidence written by this probe rather than
    treating SYSTEM-context AzureAdPrt output as authoritative.

    Verified evidence is written beneath the expected user's HKCU hive. The
    privileged finalizer independently checks the task result, task timestamp,
    SID, UPN, profile path, and evidence timestamp before accepting it.

.NOTES
    NG safety-first revision: 2026.08.07.3
#>

[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:SafetyPath = 'HKLM:\SOFTWARE\IntuneMigration\Safety'
$script:EvidencePath = 'HKCU:\Software\IntuneMigration\PostMigrationUserVerification'

function Get-RequiredSafetyValue {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Name
    )

    if (-not (Test-Path -LiteralPath $script:SafetyPath)) {
        throw 'Migration safety state is missing.'
    }

    $value = [string](Get-ItemPropertyValue `
        -LiteralPath $script:SafetyPath `
        -Name $Name `
        -ErrorAction Stop)

    if ([string]::IsNullOrWhiteSpace($value)) {
        throw "Required migration safety value '$Name' is empty."
    }

    return $value
}

function Get-DsRegValue {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string[]]$Raw,

        [Parameter(Mandatory)]
        [string]$Name
    )

    foreach ($line in $Raw) {
        if ($line -match ('^\s*' + [regex]::Escape($Name) + '\s*:\s*(.*?)\s*$')) {
            return $matches[1].Trim()
        }
    }

    return $null
}

function Set-ProbeEvidence {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Values
    )

    if (-not (Test-Path -LiteralPath $script:EvidencePath)) {
        New-Item -Path $script:EvidencePath -Force -ErrorAction Stop | Out-Null
    }

    foreach ($name in $Values.Keys) {
        $value = $Values[$name]
        if ($null -eq $value) {
            continue
        }

        New-ItemProperty `
            -Path $script:EvidencePath `
            -Name $name `
            -Value ([string]$value) `
            -PropertyType String `
            -Force `
            -ErrorAction Stop | Out-Null
    }
}

try {
    $expectedSid = Get-RequiredSafetyValue -Name 'ExpectedNewSid'
    $expectedTenantId = Get-RequiredSafetyValue -Name 'ExpectedTenantId'
    $expectedProfilePath = Get-RequiredSafetyValue -Name 'ExpectedProfilePath'
    $expectedUpn = Get-RequiredSafetyValue -Name 'ExpectedUserPrincipalName'

    $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $currentSid = [string]$identity.User.Value

    if ($currentSid -ne $expectedSid) {
        # Defense in depth: task registration already targets ExpectedNewSid.
        # Do not write evidence into an unexpected user's HKCU hive.
        exit 10
    }

    if ([string]::IsNullOrWhiteSpace($env:USERPROFILE)) {
        throw 'USERPROFILE is empty in the expected user context.'
    }

    if ($env:USERPROFILE.TrimEnd('\') -ine $expectedProfilePath.TrimEnd('\')) {
        throw "Expected profile '$expectedProfilePath' but current USERPROFILE is '$env:USERPROFILE'."
    }

    $lastPrt = $null
    $lastPrtAuthority = $null
    $lastPrtUpdate = $null

    # PRT acquisition can complete shortly after the shell starts. Poll for up
    # to two minutes rather than treating the first instant as a hard failure.
    for ($attempt = 1; $attempt -le 12; $attempt++) {
        $raw = @(& "$env:SystemRoot\System32\dsregcmd.exe" /status 2>&1)

        if ($LASTEXITCODE -ne 0) {
            throw "dsregcmd /status returned exit code $LASTEXITCODE."
        }

        $azureAdJoined = Get-DsRegValue -Raw $raw -Name 'AzureAdJoined'
        $domainJoined = Get-DsRegValue -Raw $raw -Name 'DomainJoined'
        $tenantId = Get-DsRegValue -Raw $raw -Name 'TenantId'
        $lastPrt = Get-DsRegValue -Raw $raw -Name 'AzureAdPrt'
        $lastPrtAuthority = Get-DsRegValue -Raw $raw -Name 'AzureAdPrtAuthority'
        $lastPrtUpdate = Get-DsRegValue -Raw $raw -Name 'AzureAdPrtUpdateTime'

        if ($azureAdJoined -ne 'YES') {
            throw "AzureAdJoined must be YES in the expected user session; observed '$azureAdJoined'."
        }

        if ($domainJoined -ne 'NO') {
            throw "DomainJoined must be NO in the expected user session; observed '$domainJoined'."
        }

        if ($tenantId -ne $expectedTenantId) {
            throw "Joined TenantId '$tenantId' does not match expected tenant '$expectedTenantId'."
        }

        if ($lastPrt -eq 'YES') {
            Set-ProbeEvidence -Values @{
                State = 'Verified'
                VerifiedUtc = [DateTime]::UtcNow.ToString('o')
                Sid = $currentSid
                ExpectedUpn = $expectedUpn
                UserProfile = $env:USERPROFILE
                TenantId = $tenantId
                AzureAdPrt = $lastPrt
                AzureAdPrtAuthority = $lastPrtAuthority
                AzureAdPrtUpdateTime = $lastPrtUpdate
                LastError = ''
            }

            exit 0
        }

        if ($attempt -lt 12) {
            Start-Sleep -Seconds 10
        }
    }

    Set-ProbeEvidence -Values @{
        State = 'Pending'
        ObservedUtc = [DateTime]::UtcNow.ToString('o')
        Sid = $currentSid
        ExpectedUpn = $expectedUpn
        UserProfile = $env:USERPROFILE
        TenantId = $expectedTenantId
        AzureAdPrt = $lastPrt
        AzureAdPrtAuthority = $lastPrtAuthority
        AzureAdPrtUpdateTime = $lastPrtUpdate
        LastError = 'AzureAdPrt did not become YES during the two-minute user-context verification window.'
    }

    exit 20
}
catch {
    $errorSid = ''
    try {
        $errorIdentity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        if ($errorIdentity.User) {
            $errorSid = [string]$errorIdentity.User.Value
        }
    }
    catch {
        $errorSid = ''
    }

    try {
        Set-ProbeEvidence -Values @{
            State = 'Failed'
            ObservedUtc = [DateTime]::UtcNow.ToString('o')
            Sid = $errorSid
            UserProfile = [string]$env:USERPROFILE
            LastError = [string]$_.Exception.Message
        }
    }
    catch {
        # The task still returns failure if evidence persistence is unavailable.
    }

    exit 1
}
