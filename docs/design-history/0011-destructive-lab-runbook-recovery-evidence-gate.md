# 0011 — Destructive-lab runbook and recovery/evidence gate

**Status:** Proposed atomic implementation  
**Target baseline commit:** `b42127181da282d0a5c2736b542f4b3a8d62f632`  
**Target baseline tree:** `c8d66549ef9ad6f2eff77cf0b866f623e65afabc`  
**Date:** 2026-08-09

## Decision

Atomic 0011 adds the final operator and endpoint safety boundary required before the first destructive same-tenant Hybrid Entra Joined → Microsoft Entra Joined lab migration.

Atomic 0011 does **not** rewrite the already reviewed migration engine. `startMigrate.ps1`, `reboot.ps1`, `postMigrate.ps1`, `postMigrateUser.ps1`, `preflight.ps1`, and `Migration.Common.ps1` remain unchanged.

Instead, 0011 adds a separate control plane:

```text
final reviewed repository HEAD
        ↓
fresh deterministic 0009 execution bundle
        ↓
0010 Stage → Review → Commit
        ↓
0011 control package
        ↓
endpoint recovery/readiness gate
        ↓
independent gate verification
        ↓
explicit human-confirmed launch
        ↓
existing startMigrate → reboot → postMigrate engine
        ↓
bounded evidence export
        ↓
STOP and analyze first destructive lab
```

The destructive launch path is intentionally manual. No Intune assignment, COMMIT group membership, scheduled trigger, or SUCCESS classification automatically starts migration.

## Why 0011 is required

Atomics 0009 and 0010 answer two different questions:

1. **0009:** Which exact runtime bytes, config, and provisioning package are eligible to execute?
2. **0010:** Which exact pre-migration Entra device object has a human operator reviewed and explicitly authorized for that exact bundle?

They do not prove that the endpoint is still recoverable immediately before destruction.

The promoted preflight already verifies that the configured local recovery account exists, is enabled, and is a local Administrator. It explicitly does **not** validate the account password. Atomic 0011 closes that gap by performing an actual Windows interactive-logon credential validation against the local SAM immediately before the destructive lab.

The first destructive run must also leave useful evidence if the system stops between domain unjoin, Entra leave, MDM removal, provisioning, reboot, profile reassociation, PRT acquisition, and Intune re-enrollment. Upstream reports continue to demonstrate failures in precisely these identity-transition and resume windows.

## Repository scope

Atomic 0011 changes only lab/control-plane artifacts and CI coverage:

```text
.github/workflows/powershell-validation.yml

docs/design-history/0011-destructive-lab-runbook-recovery-evidence-gate.md

lab/NG.DestructiveLab.Common.ps1
lab/Build-NGDestructiveLabControlPackage.ps1
lab/Invoke-NGDestructiveLabGate.ps1
lab/Test-NGDestructiveLabGateEvidence.ps1
lab/Invoke-NGDestructiveLabLaunch.ps1
lab/Invoke-NGDestructiveLabLaunchWorker.ps1
lab/Export-NGDestructiveLabEvidence.ps1
lab/README.md
```

No migration-engine file is modified.

## Control package

`Build-NGDestructiveLabControlPackage.ps1` runs from a clean `main` checkout after atomic 0011 itself is committed and promoted.

It requires:

- the exact NG repository and branch `main`;
- a clean tracked worktree;
- a fresh atomic 0009 execution bundle built from the same current repository commit/tree;
- successful independent 0009 bundle verification;
- a complete atomic 0010 Stage → Review → Commit evidence chain for that same bundle;
- successful independent 0010 evidence verification with `-RequireCommit`;
- a new output directory outside the Git checkout, execution bundle, and authorization-evidence directory.

The generated control package contains no reusable Graph secret, provisioning package, recovery password, or BitLocker recovery password.

Control payload:

```text
NG.DestructiveLab.Common.ps1
Invoke-NGDestructiveLabGate.ps1
Test-NGDestructiveLabGateEvidence.ps1
Invoke-NGDestructiveLabLaunch.ps1
Invoke-NGDestructiveLabLaunchWorker.ps1
Export-NGDestructiveLabEvidence.ps1
Test-NGLabExecutionBundle.ps1
```

Metadata:

```text
CONTROL-MANIFEST.json
CONTROL-MANIFEST.sha256
RUN-AUTHORIZATION.json
RUN-AUTHORIZATION.sha256
```

The output ACL is restricted to the builder operator, LocalSystem, and local Administrators.

### Run authorization

`RUN-AUTHORIZATION.json` binds:

- final repository commit/tree;
- BundleId;
- execution-manifest SHA-256;
- config SHA-256;
- PPKG SHA-256;
- expected source UPN;
- atomic 0010 Stage/Review/Commit record hashes;
- exact tenant GUID;
- exact pre-migration Entra device object ID;
- exact Entra `deviceId`;
- exact device display name;
- exact STAGE and COMMIT group identities;
- the recorded Stage=True / Commit=True authorization state;
- builder operator identity;
- a random nonce;
- a bounded validity interval.

The default validity interval is eight hours and is operator-configurable from 30 to 1440 minutes.

### ControlId

`ControlId` is deterministic for the stable execution inputs. It is SHA-256 over:

```text
repository commit
repository tree
BundleId
atomic 0010 Commit-record SHA-256
sorted control payload name | size | SHA-256 records
```

Timestamps and the authorization nonce are deliberately excluded from `ControlId`; the serialized run-authorization record is protected separately by its own SHA-256 sidecar and is referenced by the control manifest.

## Endpoint recovery/readiness gate

`Invoke-NGDestructiveLabGate.ps1` runs in an elevated **human Administrator** Windows PowerShell 5.1 session on the source endpoint. It refuses LocalSystem execution.

A successful gate performs all of the following without starting migration:

1. independently verifies the complete atomic 0011 control package;
2. independently verifies the bound atomic 0009 execution bundle;
3. requires the current source to remain Hybrid Entra Joined (`AzureAdJoined=YES`, `DomainJoined=YES`);
4. requires exact tenant GUID and exact authorized `deviceId`;
5. requires the physical computer name to match the authorized device display name;
6. requires the intended domain source profile to remain loaded;
7. resolves the configured local recovery account and reasserts enabled/local-Administrator status;
8. validates the actual local recovery password through Windows `LogonUser` using local SAM domain `.` and `LOGON32_LOGON_INTERACTIVE`;
9. if BitLocker protection is On, requires at least one RecoveryPassword protector and records only protector IDs/count, never recovery passwords; the operator must separately confirm actual recovery material is retrievable from authorized escrow before launch;
10. if a battery is present, positively requires AC power;
11. requires `w32tm /query /status` to succeed;
12. requires HTTPS reachability to Microsoft identity, Graph, and enterprise-registration endpoints;
13. runs the bundle's existing `preflight.ps1` with `-AllowAdministratorContext`;
14. requires fresh `PreflightPassed` state and exact config/tenant/user/computer/PPKG binding;
15. reasserts source identity again after preflight;
16. writes a new immutable short-lived gate record and SHA-256 sidecar.

Default gate lifetime is 30 minutes and is configurable only from 5 to 60 minutes.

### Recovery credential treatment

The recovery credential is used only to call the Windows logon API.

The gate:

- accepts or interactively prompts for a `PSCredential`;
- requires the supplied username to resolve to the configured local recovery account;
- validates against the local SAM by using domain `.`;
- uses interactive logon semantics;
- closes the returned token handle;
- releases and zeroes the unmanaged Unicode buffer containing the temporary plaintext password;
- sets the credential variable to null after validation;
- never prints the password;
- never writes the password;
- never stores a password hash or other password-derived verifier.

Gate evidence records only that credential usability was verified, the local account name/SID, logon type, and verification timestamp.

## Gate evidence

Default endpoint evidence directory:

```text
C:\ProgramData\IntuneMigrationGate
```

The path must not already exist. It is ACL-restricted to the gate operator SID, LocalSystem, and local Administrators.

Contents after successful Gate:

```text
RUN-AUTHORIZATION.json
RUN-AUTHORIZATION.sha256
DESTRUCTIVE-LAB-GATE.json
DESTRUCTIVE-LAB-GATE.sha256
```

The gate record binds the exact control package, run authorization, execution bundle, 0010 authorization, endpoint identity, recovery proof, readiness proof, and fresh preflight evidence.

## Independent pre-launch verifier

`Test-NGDestructiveLabGateEvidence.ps1` is the final endpoint-local read-only checkpoint before the human launcher.

It re-verifies:

- control-package hashes and deterministic ControlId;
- run-authorization freshness;
- execution bundle and BundleId;
- gate sidecar and hash chain;
- gate freshness;
- exact authorized device and Hybrid source state;
- intended interactive source profile;
- current `PreflightPassed` state;
- preflight evidence file SHA-256;
- configured recovery account identity and local-Administrator status;
- BitLocker recovery protector availability;
- AC-power requirement;
- Windows time status;
- required network reachability;
- gate evidence ACL.

It does not repeat the password check because the password is deliberately not retained. It verifies the immutable proof that the gate performed that check within the gate's short lifetime.

It performs no Microsoft Graph write and does not start migration.

The launcher then adds one cloud-state check that cannot be delegated to the LocalSystem worker: immediately before it records Launch Intent or creates a task, it establishes a fresh **delegated** Microsoft Graph process context scoped only to `Device.Read.All` and queries `GET /devices/{id}/memberOf`. That API reports direct device memberships. Launch requires the exact authorized device object to remain a direct member of STAGE and COMMIT and to remain absent from the production SUCCESS group. No Graph write is performed. The live membership proof is embedded in `LAUNCH-INTENT.json`; the LocalSystem worker refuses handoff unless that proof is less than five minutes old.

The source endpoint therefore requires the `Microsoft.Graph.Authentication` module to be installed before the destructive window. The launcher does not install modules automatically. Interactive browser authentication is the default; `-UseDeviceCode` is available when device-code authentication is operationally preferable.

## Explicit destructive launch

`Invoke-NGDestructiveLabLaunch.ps1` is the atomic 0011 destructive boundary.

It requires the operator to supply:

```text
Gate record SHA-256
BundleId
DeviceId
ComputerName
-Execute

Optional:
UseDeviceCode
```

The launcher first runs the independent gate verifier in a fresh Windows PowerShell process, compares every explicit confirmation to the verified evidence, and performs the fresh delegated direct-membership Graph check described above. STAGE=True, COMMIT=True, SUCCESS=False is required at the actual launch boundary.

Before starting any migration process, it writes:

```text
LAUNCH-INTENT.json
LAUNCH-INTENT.sha256
```

The intent record cryptographically references the Gate record, records the fresh live lifecycle-membership proof and delegated Graph account, and records `migrationStarted=false` because it is written before task creation/start.

The launcher then registers a task named:

```text
NG-DestructiveLab-Start
```

The task:

- has no trigger;
- runs as LocalSystem;
- runs at highest privilege;
- invokes native Windows PowerShell 5.1;
- invokes only `Invoke-NGDestructiveLabLaunchWorker.ps1` from the verified control package;
- is started explicitly with `Start-ScheduledTask` by the launcher.

The LocalSystem worker independently re-verifies the control package, bundle, short-lived Gate and `LAUNCH-INTENT.json` in the task context. It additionally requires the launcher's live lifecycle proof to be less than five minutes old and bound to the exact authorized device/STAGE/COMMIT/SUCCESS IDs. It writes immutable `SYSTEM-LAUNCH.json` before the final handoff, refuses replay if that record already exists, rechecks the `startMigrate.ps1` manifest hash, and only then invokes the verified migration controller.

The launcher refuses an existing task or existing Launch evidence so a single gate cannot silently authorize multiple attempts.

After the worker handoff, if the human launcher observes the existing migration Safety state transition away from `PreflightPassed`, it writes:

```text
LAUNCH-OBSERVATION.json
LAUNCH-OBSERVATION.sha256
```

Absence of a Launch Observation does **not** mean failure or success; a reboot or timing window can interrupt observation. `LAUNCH-INTENT.json` remains proof that task start was requested.

The launcher never labels a device SUCCESS.

## Existing migration-engine recovery states

Atomic 0011 relies on, rather than replaces, the existing migration-engine fail-closed states.

### `PreflightPassed`

The destructive engine has not started. It is safe to stop. A later attempt requires a fresh 0011 gate and new evidence directory.

### `CommitAborted`

`startMigrate.ps1` failed before its own irreversible boundary. Capture evidence. Do not reuse the old gate for an automatic retry.

### `CommitStarted`

The migration engine crossed its execution boundary or is approaching an identity-changing step. Do not assume rollback is safe. Inspect `CommitStep` and preserve evidence.

Known Commit steps include:

```text
ReadyForIrreversibleBoundary
DomainUnjoinRequested
LeavingHybridEntraRegistration
RemovingLocalMdmEnrollment
ApplyingProvisioningPackage
ProvisioningApplied
RebootRequested
```

### `RecoveryRequired`

An identity/profile/tenant safety check failed after an identity-changing path began or during profile/finalization processing.

Required operator posture:

- do not manually rerun `startMigrate.ps1`;
- do not force another reboot unless the exact recovery state has been analyzed;
- use the 0011-validated local recovery Administrator if normal sign-in is unavailable;
- capture evidence before making repairs;
- preserve `HKLM\SOFTWARE\IntuneMigration` and ProgramData logs;
- do not improvise `Win32_UserProfile.ChangeOwner`, SID registry edits, Entra leave/join, Intune enrollment deletion, or PPKG reapplication.

### `ProfileReassociated`

The hardened reboot phase has verified the profile owner transition. Do not manually reverse profile ownership. Continue with the expected Entra sign-in and normal post-migration finalization.

### `PostMigrationPending`

The core profile transition is not declared failed. PRT/network/Graph/Intune eventual-consistency conditions are pending and the finalization tasks remain available for retry. Do not start a new migration attempt.

### `Complete`

The existing post-migration finalizer has verified its core invariants and written `State=Complete`. Atomic 0011 still does not add the device to MIGRATION-SUCCESS. First export and review the full lab evidence.

## Evidence export

`Export-NGDestructiveLabEvidence.ps1` is read-only with respect to migration state.

It creates a new ACL-protected output directory and captures a bounded evidence set including:

- control manifest and run authorization;
- Gate, Launch Intent, and Launch Observation records when present;
- execution manifest and sidecar;
- `dsregcmd /status` output;
- migration Safety registry values;
- non-secret OLD_/NEW_ registry handoff values;
- `Win32_UserProfile` SID/path/Loaded/Special mapping;
- migration scheduled-task metadata;
- Intune MDM certificate metadata only;
- preflight/startMigrate/reboot/postMigrate logs when present;
- preflight evidence;
- provisioning diagnostic logs when present;
- selected User Device Registration, MDM diagnostics, and Provisioning event logs;
- SHA-256 and size for every exported file;
- an evidence-manifest SHA-256 sidecar.

Explicit exclusions:

```text
config.json
*.ppkg
certificate private keys
BitLocker recovery passwords
recovery-account passwords
Graph access tokens/client secrets
```

## First destructive lab stop rule

Atomic 0011 authorizes **one** first destructive lab device.

Whether the migration succeeds or fails:

1. export the evidence;
2. preserve the original 0009 execution bundle, 0010 authorization evidence, 0011 control package, gate evidence, and exported evidence package;
3. do not migrate another device;
4. compare the observed transitions to the expected state machine;
5. correct any defect as a new atomic before additional destructive testing.

## SUCCESS classification remains deferred

Atomic 0011 does not add or remove membership in:

```text
PROD-EN-ENTRA-MIGRATION-SUCCESS
093f5a96-eeb0-48bd-b9b7-05b975d8c287
```

SUCCESS remains a later, independently reviewed classification derived from completed post-migration evidence. It is not a launch signal and is not required for first-lab recovery.

## Upstream provenance review

Refreshed for atomic 0011:

- NG promoted 0010 baseline: `b42127181da282d0a5c2736b542f4b3a8d62f632`
- upstream `main`: `9effda8bd5ae042f1d837981eb07fd0b35af7c2c`
- upstream `8.1`: `798ce006dae9ea1ac0c06e12c0345f898c102a7c`

Upstream issues reviewed for the lab/recovery boundary include #6, #13, #16, #17, and #18. They continue to demonstrate device-ID, target-user SID, sign-in, and first-reboot/resume failure modes. Atomic 0011 ports no upstream recovery/authorization code.

## Promotion requirements

After commit, atomic 0011 is promotable only if all of the following pass:

1. exact parent/current baseline ancestry is established;
2. net changed-file scope is exactly the intended 0011 repository artifacts;
3. all committed Git blobs match the delivery manifest;
4. resulting root tree matches the expected delivery tree;
5. native Windows PowerShell 5.1 parses every existing migration script plus all seven 0011 PowerShell files;
6. PSScriptAnalyzer 1.25.0 reports zero Error findings and zero `PSUseCompatibleSyntax` blockers;
7. GitHub Actions succeeds for the exact commit;
8. static review confirms no 0011 script mutates SUCCESS membership or performs server-side object cleanup;
9. the builder/gate/verifier/exporter do not invoke migration; only the explicit human launcher starts the no-trigger LocalSystem task, and only the one-time verified LocalSystem worker invokes `startMigrate.ps1`;
10. the launcher contains only a delegated `Device.Read.All` live Graph read path and no Graph mutation path; the worker requires the resulting STAGE=True / COMMIT=True / SUCCESS=False proof to be under five minutes old.

Promotion is source/static/CI proof only. The first destructive run itself remains the runtime proof.
