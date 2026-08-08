# 0008 — Preserve Windows hostname; classify migrated devices with Intune management name

**Status:** Proposed atomic implementation  
**Target baseline:** `101902dc7c423036def6f206c322a50474bb1bae`  
**Date:** 2026-08-08

## Decision

NG preserves the existing physical Windows computer name across the Hybrid Entra Joined to Microsoft Entra Joined migration. The provisioning package must not contain a `ComputerName` customization.

After the current Intune re-enrollment has been uniquely correlated to the current `dsregcmd` DeviceId, NG may set only the Intune administrative `managedDeviceName` to:

```text
<original-hostname>.<safety.intuneManagementNameSuffix>
```

Example:

```text
Physical Windows hostname: W11-LAPTOP07
Configured suffix:          domain.tld
Intune deviceName:          W11-LAPTOP07
Intune managedDeviceName:   W11-LAPTOP07.domain.tld
```

The dotted value is an Intune administrative label; it is not a Windows `ComputerName` and is not an Entra device `displayName` mutation.

## Rationale

The original/upstream deployment model can embed a device-naming template in Windows Configuration Designer. That is unnecessary for same-tenant NG and conflicts with the preservation objective. A physical rename creates avoidable endpoint state, reboot implications, Windows naming restrictions, and ambiguity over whether an observed name is the original endpoint identity or a migration side effect.

Intune exposes `managedDeviceName` independently from the read-only `deviceName`. The former can be overwritten with a user-friendly administrative value using the existing `DeviceManagementManagedDevices.ReadWrite.All` permission class. This provides a useful visual distinction between migrated and non-migrated records without adding `DeviceManagementManagedDevices.PrivilegedOperations.All` or invoking the privileged `setDeviceName` action.

## Required behavior

1. `safety.intuneManagementNameSuffix` is mandatory for the lab configuration and must be a DNS-style suffix such as `domain.tld`.
2. Preflight pins:
   - `ExpectedComputerName`;
   - `IntuneManagementNameSuffix`;
   - `ExpectedIntuneManagementName`.
3. `startMigrate.ps1` refuses commit if the physical hostname differs from the preflight-pinned value.
4. The NG PPKG build process must omit `ComputerName` customization.
5. `postMigrate.ps1` treats a changed post-reboot physical hostname as a preservation invariant failure.
6. Only after verified Intune re-enrollment, primary-user assignment, and BitLocker finalization does the finalizer attempt the Intune management-name PATCH.
7. The finalizer performs a fresh GET and verifies the returned managedDevice ID, current Entra DeviceId correlation, and exact `managedDeviceName`.
8. The finalizer records observed Intune `deviceName` separately to demonstrate that the administrative label did not intentionally rename Windows.
9. Failure to set/read back `managedDeviceName` is administrative classification failure only. Core migration may still reach `Complete`; naming status is recorded as `Warning`.
10. The validation harness independently verifies physical hostname preservation and Intune management-name observation.

## Explicit non-goals for this atomic

- Do not change Entra device `displayName`.
- Do not invoke Intune `setDeviceName`.
- Do not call `Rename-Computer`.
- Do not add `DeviceManagementManagedDevices.PrivilegedOperations.All`.
- Do not automate Entra migration-success security-group membership yet.
- Do not delete/reconcile stale Entra, Intune, or Autopilot objects.

## PPKG build requirement

Windows Configuration Designer's desktop wizard requires a device-name field. For NG, acquire the bulk Microsoft Entra enrollment token using the applicable WCD workflow, then use/switch to Advanced provisioning and ensure the final package customization set contains no computer-name setting. The final `.ppkg` remains hash-pinned by `safety.ppkgSha256`.

The validation harness records this as a build-contract requirement; it does not claim to reverse-engineer or introspect the binary PPKG for `ComputerName` customization.

## Failure semantics

| Condition | Migration classification |
| --- | --- |
| Physical hostname differs from preflight value | Hard preservation/invariant failure; do not declare normal completion |
| Verified managedDevice cannot be correlated | Existing `PostMigrationPending` behavior |
| Intune `managedDeviceName` PATCH/read-back succeeds | `IntuneManagementNameStatus=Verified` |
| Intune `managedDeviceName` PATCH/read-back fails after core gates succeed | `Complete` permitted with `IntuneManagementNameStatus=Warning` |
| Intune `deviceName` temporarily disagrees with preserved physical hostname | Record warning; endpoint hostname remains authoritative |

## Roadmap relationship

This atomic belongs **before the first destructive lab PPKG/execution bundle** so the lab characterizes the intended production naming behavior rather than an inherited WCD rename side effect.

After the first destructive lab, use Before/After/Compare evidence to characterize whether Entra DeviceId/ObjectId and Intune managedDevice IDs are reused or recreated. Only after that lifecycle is known should NG automate a separate Entra `MIGRATION-SUCCESS` security-group classification. That future operation should be performed by controlled/server-side automation rather than by broadening the endpoint credential.

The rollout/authorization group and future success group have different semantics:

```text
MIGRATION-COMMIT   = authorized / potentially migrated population
MIGRATION-SUCCESS  = current Entra device object whose NG migration passed all core verification gates
```

Intune `managedDeviceName` is an operator-friendly visual indicator; security-group membership is the stronger authoritative classification mechanism.

## Provenance and current references

Upstream references were refreshed before this atomic:

- upstream `main`: `9effda8bd5ae042f1d837981eb07fd0b35af7c2c`
- upstream `8.1`: `798ce006dae9ea1ac0c06e12c0345f898c102a7c`

No upstream naming implementation is ported by this atomic. The design is NG-specific and follows the existing preservation, deterministic correlation, least-privilege, and evidence-first principles.

## Microsoft references checked for this decision

Checked 2026-08-08:

- Microsoft Graph v1.0 `managedDevice` resource: `managedDeviceName` is an automatically generated identifier that can be overwritten with a user-friendly name; `deviceName` is read-only.
  - https://learn.microsoft.com/en-us/graph/api/resources/intune-devices-manageddevice?view=graph-rest-1.0
- Microsoft Graph v1.0 managedDevice update: `PATCH /deviceManagement/managedDevices/{managedDeviceId}` uses `DeviceManagementManagedDevices.ReadWrite.All` for application access.
  - https://learn.microsoft.com/en-us/graph/api/intune-devices-manageddevice-update?view=graph-rest-1.0
- Windows Configuration Designer advanced provisioning.
  - https://learn.microsoft.com/en-us/windows/configuration/provisioning-packages/provisioning-create-package
- Windows Configuration Designer Accounts reference: bulk Microsoft Entra BPRT settings are acquired through a provisioning wizard and the project can then be switched to the advanced editor.
  - https://learn.microsoft.com/en-us/windows/configuration/wcd/wcd-accounts
