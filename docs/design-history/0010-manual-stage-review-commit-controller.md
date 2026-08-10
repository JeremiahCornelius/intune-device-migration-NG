# 0010 — Manual Stage → Review → Commit authorization controller

**Status:** Proposed atomic implementation  
**Target baseline:** `0a408c8c72087628f6d33aff1cfa668f30af080c`  
**Target baseline tree:** `7db0b24f5ce1f3559013cf2640925fb5c986f13b`  
**Date:** 2026-08-09

## Decision

The first destructive migration must not be authorized merely because a device received a payload or passed preflight. Authorization is a separate operator-controlled transaction with three explicit states:

```text
STAGE  →  REVIEW  →  COMMIT
```

Atomic 0010 adds an operator-side Windows PowerShell controller that binds one independently verified atomic 0009 execution bundle to one exact Microsoft Entra device object and advances only the migration authorization group lifecycle.

It does **not** start migration.

## Group lifecycle

The production lifecycle groups are fixed for this atomic:

| State | Group | Object ID |
| --- | --- | --- |
| STAGE | `PROD-EN-ENTRA-MIGRATION-STAGE` | `c3b4a23d-2d81-424c-a0b2-4e5add86a7a8` |
| COMMIT | `PROD-EN-ENTRA-MIGRATION-COMMIT` | `7eeb1496-bdf4-4cf6-b5ac-2494cbb4c462` |
| SUCCESS | `PROD-EN-ENTRA-MIGRATION-SUCCESS` | `093f5a96-eeb0-48bd-b9b7-05b975d8c287` |

The controller requires all three objects to be static, non-mail-enabled security groups with the exact expected names. Role-assignable or dynamic groups are rejected.

SUCCESS remains read-only in 0010. No endpoint or operator-side automatic SUCCESS mutation is introduced.

## Exact device identity

The operator supplies the Microsoft Entra **DeviceId** GUID, normally recorded from source-device `dsregcmd /status` output.

The controller does not authorize by hostname, display name, Intune managed-device name, user principal name, or fuzzy search.

It resolves:

```text
GET /v1.0/devices(deviceId='{deviceId}')
```

and records both:

- `deviceId` — the Entra device registration identifier;
- `id` — the Entra directory object identifier used for group membership.

Before Stage, Review, and Commit, the object must still be enabled and have `trustType = ServerAd`, the Entra representation of an on-premises domain-joined device joined to Entra.

## Microsoft Graph permission boundary

0010 uses delegated operator authentication only.

Required delegated scopes:

```text
Device.Read.All
GroupMember.ReadWrite.All
```

For a **device** member, current Microsoft Graph documentation identifies those as the least-privileged delegated permissions for `POST /groups/{group-id}/members/$ref`.

The signed-in user must also have a supported Entra role for the group membership update. For security groups, Microsoft documents Intune Administrator as a supported role.

The controller does not use application credentials, client secrets, `Directory.ReadWrite.All`, or endpoint-resident group-write authority.

## Bundle trust boundary

Before every action, the controller invokes atomic 0009's independent verifier in a separate Windows PowerShell 5.1 process.

Authorization stops if the bundle no longer verifies.

The controller additionally rejects the deliberately synthetic 0009 functional-test form when:

```text
functionalTestOnly = true
```

or the source tenant / expected source UPN uses the reserved `.invalid` namespace.

This prevents the inert 0009 functional-validation bundle from becoming an operational migration authorization input.

## Controller provenance

The controller itself fails closed unless it is executed from:

- the NG repository;
- branch `main`;
- a clean tracked worktree;
- the expected GitHub origin;
- a version of the controller tracked at `HEAD`.

Evidence records controller repository commit/tree, controller Git blob ID and SHA-256, and the SHA-256 of the 0009 bundle verifier used for that action.

## STAGE

STAGE is the first mutation boundary.

Before mutation the controller:

1. verifies controller provenance;
2. verifies the atomic 0009 bundle;
3. rejects synthetic functional-test input;
4. authenticates to the exact tenant;
5. resolves the exact Entra device by `deviceId`;
6. requires `ServerAd` and enabled state;
7. validates STAGE, COMMIT, and SUCCESS group identity/type;
8. reads current **direct** group membership;
9. refuses devices already in COMMIT or SUCCESS;
10. creates a protected evidence directory;
11. writes and hashes `STAGE-INTENT.json` before group mutation.

It then adds the exact Entra device directory object to STAGE if it is not already a direct member and requires read-back confirmation.

A successful Stage writes:

```text
STAGE-INTENT.json
STAGE-INTENT.json.sha256
STAGE.json
STAGE.json.sha256
```

An already-direct STAGE member may be captured as `AlreadyDirectMember`; COMMIT and SUCCESS still cause hard failure.

## REVIEW

REVIEW is deliberately read-only.

The controller:

1. re-verifies the 0009 bundle;
2. verifies the `STAGE.json` sidecar and JSON;
3. re-resolves the same Entra device;
4. revalidates tenant, device object ID, DeviceId, BundleId, and group IDs;
5. requires direct STAGE membership;
6. requires absence from COMMIT and SUCCESS;
7. writes and hashes `REVIEW.json`;
8. computes a SHA-256 approval token bound to the Stage evidence, exact device, bundle, tenant, and group IDs;
9. prints the exact Commit command.

No Graph mutation occurs during Review.

The operator must manually inspect the displayed identity and evidence before running Commit.

## COMMIT

COMMIT is the explicit authorization mutation.

The controller repeats all material trust checks and additionally requires:

- valid Stage evidence;
- valid Review evidence;
- Review bound to the current Stage evidence SHA-256;
- the exact approval token printed by Review;
- direct STAGE membership;
- absence from COMMIT and SUCCESS.

Before Graph mutation it writes and hashes:

```text
COMMIT-INTENT.json
COMMIT-INTENT.json.sha256
```

It then adds the exact same Entra device directory object to COMMIT and requires fresh membership read-back proving both STAGE and COMMIT remain directly present and SUCCESS is absent.

A successful Commit writes:

```text
COMMIT.json
COMMIT.json.sha256
```

COMMIT means **authorized to cross the migration boundary under the atomic 0011 runbook**. It does not itself cross that boundary.

## Fail-closed duplicate Commit behavior

If the device is already a direct COMMIT member when the controller enters the Commit action, 0010 refuses to infer why.

This can mean:

- a previous Commit succeeded but local evidence writing failed;
- an operator manually added membership;
- another controller instance acted;
- the device is in an unexpected lifecycle state.

0010 stops for manual reconciliation rather than hiding that ambiguity with automatic idempotence.

## Evidence and ACLs

Default evidence root:

```text
%USERPROFILE%\NG-Migration-Authorization
```

Each Stage creates a unique child directory based on UTC time, DeviceId, and a new authorization GUID.

The directory ACL is restricted to:

- current Windows identity;
- `NT AUTHORITY\SYSTEM`;
- local Administrators.

Every JSON evidence file has a SHA-256 sidecar. Later states verify earlier sidecars and embed earlier hashes, providing a simple evidence chain.

Evidence intentionally contains identifiers, hashes, group state, Graph operator identity, and controller provenance. It does not contain Graph access tokens, client secrets, BPRTs, BitLocker recovery passwords, or bundled configuration contents.

## Explicit exclusions

Atomic 0010 does not:

- run `preflight.ps1`;
- run `startMigrate.ps1`;
- install the PPKG;
- unjoin AD;
- call `dsregcmd /leave`;
- delete or modify Intune managed-device objects;
- delete or rename Entra devices;
- alter Windows hostname;
- alter profile ownership;
- modify BitLocker;
- add SUCCESS membership;
- clean stale cloud objects;
- implement rollback or rerun automation;
- create Win32 app packaging.

## 0009 functional-test observation

The non-destructive 0009 functional test found that a child `powershell.exe -File` invocation of the bundle **builder** required explicit `-RepositoryRoot` because its default `$PSScriptRoot` expression failed during parameter binding in that launch mode.

0010 does not invoke the builder. It invokes the 0009 **verifier**, which was successfully exercised through `powershell.exe -File` during the 0009 functional test.

No 0009 migration-runtime modification is introduced by 0010.

## Upstream provenance review

Refreshed before atomic 0010:

- NG `main`: `0a408c8c72087628f6d33aff1cfa668f30af080c`
- upstream `main`: `9effda8bd5ae042f1d837981eb07fd0b35af7c2c`
- upstream `8.1`: `798ce006dae9ea1ac0c06e12c0345f898c102a7c`

Current upstream issues continue to report identity/profile ambiguity and migrations that remove the source state but fail to complete the destination join. Those reports reinforce the NG design requirement for a separate, inspectable authorization boundary.

No upstream main/8.1 implementation or PR supplies an equivalent deterministic Stage → Review → Commit authorization controller to port.

## Roadmap position

```text
0009  deterministic execution bundle + cryptographic manifest
       + non-destructive functional validation PASS
  ↓
0010  manual Stage → Review → Commit authorization controller
  ↓
0011  destructive-lab runbook + recovery/evidence gate
  ↓
real operational config + dedicated credential + real PPKG
  ↓
build and verify execution bundle
  ↓
Stage
  ↓
Review
  ↓
explicit Commit
  ↓
0011 destructive migration boundary
```
