# Lab validation harness v0.1.1

`Invoke-MigrationValidation.ps1` is the read-only evidence harness for destructive lab qualification of `intune-device-migration-NG`.

It is intentionally independent of the migration state machine. It does **not** modify device registration, Intune enrollment, profile ownership, BitLocker, migration registry state, scheduled tasks, Microsoft Entra objects, or Intune objects. Its only writes are its own JSON report files.

## Modes

### Before

Capture source-state evidence and evaluate lab readiness:

```powershell
.\validation\Invoke-MigrationValidation.ps1 `
    -Phase Before `
    -ConfigPath C:\NGLabBundle\config.json `
    -ManifestPath C:\NGLabBundle\manifest.json `
    -RecoveryCredentialManuallyValidated `
    -FullDeviceRecoveryManuallyValidated `
    -OutputPath C:\NGLabEvidence\validation-before.json
```

Run this from an elevated **64-bit Windows PowerShell 5.1** session while the intended synchronized AD domain user is signed in and its profile is loaded. The execution config must pin that identity with `safety.expectedSourceUserPrincipalName`; the harness fails if the active identity is local or if SID-based Graph resolution returns a different Entra UPN.

The two manual-validation switches are assertions, not automated tests. Supply them only after actually testing the local recovery credential and the full-device recovery/snapshot method. If omitted, the harness records explicit warnings.

The output should be copied off-host before destructive commit.

### After

After the migrated Entra user has signed in and the migration finalizer has had an opportunity to complete:

```powershell
.\validation\Invoke-MigrationValidation.ps1 `
    -Phase After `
    -ConfigPath C:\ProgramData\IntuneMigration\config.json `
    -OutputPath C:\NGLabEvidence\validation-after.json
```

If the finalizer has already reached `Complete`, it may already have removed its protected `config.json`. In that case provide an execution-only copy of the same lab config from secure operator storage:

```powershell
.\validation\Invoke-MigrationValidation.ps1 `
    -Phase After `
    -ConfigPath D:\SecureLabEvidence\config.json `
    -OutputPath C:\NGLabEvidence\validation-after.json
```

The harness reads the secret only to acquire a Graph token. It never exports `clientSecret` or the access token.

If Graph access is intentionally unavailable, `-SkipGraph` permits endpoint-only collection. Cloud reconciliation will be reported as incomplete.

### Compare

```powershell
.\validation\Invoke-MigrationValidation.ps1 `
    -Compare `
    -BeforeSnapshotPath C:\NGLabEvidence\validation-before.json `
    -AfterSnapshotPath C:\NGLabEvidence\validation-after.json `
    -ComparisonOutputPath C:\NGLabEvidence\validation-comparison.json
```

`Compare` proves or reports:

- same lab endpoint;
- original profile-path preservation;
- continuity of the pre-migration AD SID;
- transition to the expected Entra cloud SID;
- old AD profile ownership no longer enumerating;
- observed Entra DeviceId lifecycle;
- observed Intune managedDevice ID lifecycle;
- the independent result of the After snapshot.

## Exit codes

| Exit | Meaning |
| ---: | --- |
| `0` | PASS or PASS WITH WARNINGS |
| `1` | FAIL |
| `2` | RECOVERY REQUIRED |
| `3` | PENDING |
| `10` | Harness execution failure |

`Before` warnings include manual controls that software cannot prove, notably actual knowledge/testing of the local recovery-account password.

## Evidence collected

The harness records:

- Windows build and execution context;
- `dsregcmd /status` device state;
- interactive source identity, local/domain classification, and profile path;
- configured `safety.expectedSourceUserPrincipalName` operator intent and its match to SID-resolved Entra UPN;
- relevant old/new `Win32_UserProfile` ownership;
- Intune MDM certificate metadata;
- local Intune enrollment IDs;
- OneDrive KFM readiness;
- pending reboot evidence;
- Windows Time status;
- domain-controller discovery before migration;
- local recovery-account status and Administrators membership;
- BitLocker status and protector IDs/types, **never recovery passwords**;
- allow-listed `HKLM\SOFTWARE\IntuneMigration\Safety` evidence;
- authoritative user-context PRT evidence when its HKU hive is accessible;
- migration scheduled-task residue;
- staged `config.json`, PPKG and user-probe residue;
- config/PPKG/manifest SHA-256 evidence;
- Microsoft Entra user/device observations;
- Intune managedDevice correlation, sync metadata, and observable primary users.

Old cloud objects are reported rather than failed in v0.1 because server-side cleanup is intentionally deferred until same-tenant lifecycle behavior is established by lab evidence.

## Security

Validation JSON contains administrative identifiers and must be protected accordingly.

The harness is explicitly designed not to emit:

- `clientSecret`;
- OAuth access tokens;
- passwords;
- BitLocker recovery passwords.

The JSON includes a `security` assertion block that must remain `false` for all reusable-secret export fields.

## Schemas

- `schemas/migration-validation-snapshot.schema.json`
- `schemas/migration-validation-comparison.schema.json`

The schemas use JSON Schema Draft 2020-12.

## CI integration

The accompanying `.github/workflows/powershell-validation.yml` replacement adds:

`validation/Invoke-MigrationValidation.ps1`

to the native Windows PowerShell 5.1 parser and pinned PSScriptAnalyzer 1.25.0 target arrays, and triggers the workflow for changes under `validation/**`.

Schema files in this bundle have been validated against the Draft 2020-12 metaschema before delivery.
