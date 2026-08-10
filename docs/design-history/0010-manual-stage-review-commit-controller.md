# 0010 — Manual Stage → Review → Commit authorization controller

**Status:** Proposed atomic implementation  
**Target baseline:** `0a408c8c72087628f6d33aff1cfa668f30af080c`  
**Target baseline tree:** `7db0b24f5ce1f3559013cf2640925fb5c986f13b`  
**Date:** 2026-08-09

## Decision

Atomic 0010 introduces an explicit operator-controlled authorization boundary between a cryptographically verified atomic 0009 execution bundle and the later destructive migration runbook.

The controller implements three deliberately separate actions:

```text
Stage  →  Review  →  Commit
```

None of these actions starts migration.

- **Stage** classifies one exact pre-migration Entra device object as prepared/qualified.
- **Review** performs a read-only revalidation of bundle, device, group, and membership identity and produces a hash-bound one-line Commit command.
- **Commit** records explicit operator authorization by adding the exact same pre-migration Entra device object to the COMMIT security group while preserving STAGE membership.

`MIGRATION-SUCCESS` remains outside atomic 0010. SUCCESS means a later, separately verified post-migration outcome; it must not be confused with authorization to attempt migration.

## Why this boundary is required

Atomic 0009 proves which bytes are eligible to execute. It does not answer a different control question:

> Which exact device has a human operator reviewed and explicitly authorized to cross the destructive migration boundary using this exact bundle?

A migration controller that automatically infers authorization from configuration, device name, a broad Intune assignment, or mere STAGE membership would collapse preparation and destructive intent into one state.

Atomic 0010 instead makes the authorization transition explicit, attributable, reviewable, and independently verifiable.

## Lifecycle groups

The production authorization groups are:

```text
PROD-EN-ENTRA-MIGRATION-STAGE
  c3b4a23d-2d81-424c-a0b2-4e5add86a7a8

PROD-EN-ENTRA-MIGRATION-COMMIT
  7eeb1496-bdf4-4cf6-b5ac-2494cbb4c462

PROD-EN-ENTRA-MIGRATION-SUCCESS
  093f5a96-eeb0-48bd-b9b7-05b975d8c287
```

Atomic 0010 reads and writes only STAGE and COMMIT. It never reads SUCCESS as authorization and never changes SUCCESS membership.

The authorized object is the **pre-migration Entra device directory object**. The controller does not predict which post-migration Entra or Intune objects will later exist.

STAGE membership is intentionally preserved after Commit. It remains historical evidence that the object passed the preparation boundary; COMMIT is an additional explicit authorization classification rather than a move operation.

## Exact target-device identity

Stage requires all of the following:

1. exact tenant GUID;
2. exact Entra `deviceId` GUID, normally obtained from `dsregcmd /status` on the source host;
3. exact expected device display name, normally the physical Windows computer name;
4. exact STAGE group object ID and expected display name;
5. exact COMMIT group object ID and expected display name.

The controller resolves the device through the Graph `deviceId` alternate-key route and records the returned directory object ID. It then requires:

- returned `deviceId` equals the requested GUID;
- returned display name exactly equals the operator-supplied expected display name;
- `operatingSystem` is Windows;
- `trustType` is `ServerAd`, the Graph value representing an on-premises domain-joined device joined to Microsoft Entra ID;
- the device object is enabled.

Review and Commit subsequently resolve by the recorded **directory object ID** and reassert the complete source-device invariant immediately before proceeding: object ID, `deviceId`, exact display name, Windows operating system, `trustType = ServerAd`, and enabled state must all still match the Stage authorization context.

This avoids using display name as the primary identity key while retaining it as an independent human-readable check and prevents authorization from continuing after a meaningful source-device state change.

## Group safety contract

Both STAGE and COMMIT must read back as:

- the exact requested object ID;
- the exact expected display name;
- `securityEnabled = true`;
- `mailEnabled = false`;
- empty `groupTypes` collection;
- `isAssignableToRole = false`.

If the controller cannot positively read `isAssignableToRole`, it fails closed.

This deliberately excludes dynamic groups, Microsoft 365 groups, mail-enabled groups, and role-assignable groups from the authorization workflow.

## Graph permission model

The controller uses delegated, operator-interactive Microsoft Graph authentication through `Microsoft.Graph.Authentication`.

Required delegated scopes:

```text
Device.Read.All
GroupMember.ReadWrite.All
```

The controller requests a fresh process-scoped context for every Stage, Review, and Commit action and validates the tenant, delegated auth type, signed-in operator account, and required scopes.

No Graph application client secret from the migration bundle is used by atomic 0010.

For a device member, Microsoft documents `GroupMember.ReadWrite.All` plus `Device.Read.All` as the least-privileged delegated Graph permissions for adding the device to a group. The signed-in user must also hold a supported Entra role or custom role permission for membership updates; Microsoft documents Intune Administrator as supported for security groups.

Atomic 0010 therefore does not require `Group.ReadWrite.All`, `Directory.ReadWrite.All`, `Device.ReadWrite.All`, or role-management permissions.

## 0009 bundle binding

Before **every** action the controller independently invokes:

```text
lab/Test-NGLabExecutionBundle.ps1
```

The verified bundle must have been built from the exact commit and tree of the controller's current clean `main` checkout.

The controller records:

- BundleId;
- manifest SHA-256;
- repository commit/tree;
- source tenant name from the bundled config;
- expected source-user UPN from the bundled config;
- Intune management-name suffix;
- pinned PPKG SHA-256.

Only those non-secret review fields are copied into authorization evidence. The config itself, Graph client secret, and provisioning-package material remain in the protected 0009 bundle.

Because atomic 0011 will change repository HEAD after 0010, the real destructive-lab execution bundle must be built **after the final prerequisite commit** and before Stage. An older 0009 functional-test bundle is not acceptable operational input.

## Repository provenance

The controller fails closed unless:

1. Git is available;
2. `RepositoryRoot` is the Git top level;
3. origin is `JeremiahCornelius/intune-device-migration-NG`;
4. branch is `main`;
5. tracked files are clean;
6. the controller and atomic 0009 verifier are tracked at HEAD.

Atomic 0009 functional observation `0009-F01` showed that using `$PSScriptRoot` in a parameter-default expression can be unreliable under a child `powershell.exe -File` invocation. Atomic 0010 therefore does not use that pattern: an omitted repository root is resolved in the script body, and the Review-generated Commit command supplies `-RepositoryRoot` explicitly.

## Evidence chain

Authorization evidence lives outside both Git and the execution bundle.

After all read-only Stage gates pass, but before any possible membership write, Stage creates a previously nonexistent evidence directory and ACL-restricts it to:

```text
Stage operator SID
NT AUTHORITY\SYSTEM
BUILTIN\Administrators
```

The controller creates:

```text
STAGE-RECORD.json
STAGE-RECORD.sha256

REVIEW-RECORD.json
REVIEW-RECORD.sha256

COMMIT-RECORD.json
COMMIT-RECORD.sha256
```

Each JSON record is UTF-8 without BOM. Each sidecar protects the complete serialized record.

The hash chain is:

```text
STAGE-RECORD.json
      ↓ SHA-256 recorded by Review
REVIEW-RECORD.json
      ↓ SHA-256 recorded by Commit
COMMIT-RECORD.json
```

Commit additionally records the Stage record SHA-256 and the three explicit operator confirmations:

```text
Review record SHA-256
BundleId
Entra device object ID
```

Evidence files are never overwritten by the controller.

## Stage semantics

Required pre-state:

```text
COMMIT = false
```

STAGE may be either false or true:

- if false, the controller adds direct STAGE membership;
- if already true, Stage records `AlreadyPresent` after all other identity gates succeed.

Required post-state:

```text
STAGE  = true
COMMIT = false
```

A device already in COMMIT is rejected. Stage will not back-fill authorization evidence for an object that has previously crossed the boundary.

Stage does not run preflight and does not modify endpoint state.

## Review semantics

Review requires valid Stage evidence and a live state of:

```text
STAGE  = true
COMMIT = false
```

Review performs no Graph write.

It prints the exact values the human operator must inspect, including:

- tenant;
- operator;
- device display name;
- deviceId;
- Entra directory object ID;
- BundleId;
- manifest SHA-256;
- expected source-user UPN;
- source tenant name;
- PPKG SHA-256;
- Intune naming suffix;
- STAGE and COMMIT group identities;
- live membership state;
- Review record SHA-256.

Only after writing and self-verifying REVIEW-RECORD.json does the controller emit an exact one-line Commit command containing the Review record SHA-256, BundleId, and device object ID.

## Commit semantics

Commit requires:

- a valid Stage → Review hash chain;
- exact current bundle re-verification immediately before authorization;
- explicit Review record SHA-256 match;
- explicit BundleId match;
- explicit device object ID match;
- current live device object ID and `deviceId` match;
- exact Stage-recorded display name still matches;
- device remains enabled Windows with `trustType = ServerAd`;
- current STAGE membership present;
- current COMMIT membership absent.

Commit then adds direct COMMIT membership and reads membership back until it observes:

```text
STAGE  = true
COMMIT = true
```

Only then does it write COMMIT-RECORD.json.

Commit is an **authorization event only**. It does not call `preflight.ps1`, `startMigrate.ps1`, or any migration-engine script.

## Partial-failure semantics

The controller deliberately prefers manual reconciliation over guessing after a cloud mutation.

Examples:

- If Stage membership is added but local evidence cannot be completed, a later Stage attempt will encounter existing state/evidence and require inspection rather than silently reconstructing history.
- If COMMIT membership is added but COMMIT-RECORD.json cannot be completed, a later Commit sees COMMIT membership without a Commit record and fails closed with an explicit out-of-band/partial-record warning.
- An existing Review or Commit record is never overwritten.

Atomic 0011 will define the operator recovery/evidence runbook around these states.

## Independent evidence verifier

`lab/Test-NGMigrationAuthorizationEvidence.ps1` is read-only.

It:

- independently reruns the atomic 0009 bundle verifier;
- verifies Stage/Review/Commit sidecars;
- verifies the cryptographic record chain;
- verifies bundle identity and non-secret config review fields;
- verifies tenant, device, and group identities remain consistent across records;
- verifies recorded state transitions;
- verifies the evidence-directory ACL;
- refuses evidence claiming migration or SUCCESS-group activity;
- supports `-RequireCommit` for the final authorization gate.

It does not query or modify Graph. Live Graph membership remains the controller's responsibility at each action; atomic 0011 will define the immediate pre-migration operational gate.

## Explicit exclusions

Atomic 0010 does **not**:

- run migration preflight;
- unjoin AD;
- run `dsregcmd /leave`;
- install a PPKG;
- change a Windows profile owner;
- change physical computer name;
- modify Intune `managedDeviceName`;
- alter BitLocker;
- delete Entra, Intune, or Autopilot objects;
- add or remove SUCCESS membership;
- remove STAGE membership at Commit;
- automatically start migration because COMMIT membership exists;
- grant Graph permissions to the endpoint migration payload.

## CI contract

Atomic 0010 adds these scripts to both Windows PowerShell 5.1 parser validation and PSScriptAnalyzer:

```text
lab/Invoke-NGMigrationAuthorization.ps1
lab/Test-NGMigrationAuthorizationEvidence.ps1
```

The existing `lab/**` workflow path filter already covers the new files.

## Roadmap position

```text
0009  deterministic execution bundle + cryptographic manifest
      source/static/CI PASS
      non-destructive functional PASS
  ↓
0010  manual Stage → Review → Commit authorization controller
  ↓
0011  destructive-lab runbook + recovery/evidence gate
  ↓
real external config + ephemeral Graph credential + ComputerName-free PPKG
  ↓
build fresh deterministic bundle from final prerequisite HEAD
  ↓
Stage → Review → explicit Commit
  ↓
first destructive migration
  ↓
post-migration validation → compare → stop and analyze runtime evidence
```

## Upstream provenance review

Refreshed before atomic 0010:

- NG `main`: `0a408c8c72087628f6d33aff1cfa668f30af080c`
- upstream `main`: `9effda8bd5ae042f1d837981eb07fd0b35af7c2c`
- upstream `8.1`: `798ce006dae9ea1ac0c06e12c0345f898c102a7c`

Relevant upstream issues continue to demonstrate identity-transition and resume hazards, including #13, #16, #17, and #18. Issue #6 documents unreliable device-ID derivation from the organization-access certificate. Open PRs #10 and #11 address unrelated RunAsUser import and reboot-log issues.

No upstream Stage/Review/Commit authorization controller was identified for selective porting. Atomic 0010 is NG-specific and ports no upstream code.
