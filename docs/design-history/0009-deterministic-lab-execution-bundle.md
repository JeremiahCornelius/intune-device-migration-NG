# 0009 — Deterministic destructive-lab execution bundle and cryptographic manifest

**Status:** Proposed atomic implementation  
**Target baseline:** `abbd91b317c2d4185dfc3bede2372705e61b9389`  
**Target baseline tree:** `10b1a48a596ed4c6480985c561d52873c5ab3b0a`  
**Date:** 2026-08-08

## Decision

The first destructive migration must execute from a deterministic, allow-list-driven bundle whose repository provenance and every payload byte can be independently verified.

Atomic 0009 adds only the bundle builder, independent verifier, documentation, design history, and CI coverage for those tools. It makes no migration-engine behavior changes.

## Why this is required

Static/CI validation has established Windows PowerShell 5.1 syntax compatibility and nonblocking analyzer status for the migration components, but it cannot prove the runtime identity transition.

The first destructive test must therefore answer a different evidentiary question:

> What exact code, configuration, and provisioning package were used for this migration attempt?

Recursive packaging of the repository is unsuitable because it can silently carry repository-only artifacts, inherited content, development tools, or accidental files into the endpoint staging directory.

The execution payload is instead built from a fixed allow-list and two explicitly supplied operational inputs.

## Runtime payload contract

Tracked runtime allow-list:

```text
Migration.Common.ps1
preflight.ps1
startMigrate.ps1
reboot.ps1
reboot.xml
postMigrate.ps1
postMigrateUser.ps1
postMigrate.xml
```

External operational inputs:

```text
config.json
<exactly one>.ppkg
```

The current `startMigrate.ps1` post-staging requirement is:

```text
config.json
Migration.Common.ps1
startMigrate.ps1
reboot.ps1
reboot.xml
postMigrate.ps1
postMigrateUser.ps1
postMigrate.xml
```

`preflight.ps1` is additionally carried because it is the non-destructive lab staging entry point.

## Explicit exclusions

The execution bundle does not include repository content merely because it exists. In particular:

```text
install.ps1
groupTag.ps1
groupTag.xml
Autopilot.jpg
Autopilot.theme
IntuneWinAppUtil.exe
validation/**
.github/**
README.md
development/review artifacts
```

The exclusion of `Autopilot.jpg` reflects its current non-runtime role, not legacy status.

## Repository provenance gates

The builder fails closed unless:

1. Git is available.
2. the selected path is the Git top-level directory;
3. `origin` resolves to `JeremiahCornelius/intune-device-migration-NG`;
4. the checkout is on `main`;
5. tracked files are clean;
6. every runtime allow-list file is tracked;
7. the builder itself is tracked at `HEAD`.

The generated manifest records the repository commit SHA, tree SHA, branch, origin, builder Git blob ID, and builder SHA-256.

This permits a later lab report to bind the runtime evidence to the exact reviewed repository state.

## Operational-input gates

The real lab config and dedicated PPKG are not repository artifacts.

The builder requires both to be outside the Git checkout and refuses output inside the checkout.

The builder also requires:

- real, non-placeholder source Graph application values;
- `safety.expectedSourceUserPrincipalName`;
- `safety.intuneManagementNameSuffix`;
- a 64-character `safety.ppkgSha256`;
- actual PPKG SHA-256 exactly matching that pin.

If `targetTenant.tenantName` is populated, its app values must also not be placeholders.

This does not replace `preflight.ps1`; it prevents obvious packaging errors before sensitive material is copied.

## PPKG naming contract

Design history 0008 remains authoritative:

> the NG provisioning package must omit `ComputerName` customization.

Atomic 0009 deliberately does not parse or reverse-engineer the binary PPKG. The build manifest records the policy as a required external build contract and cryptographically pins the exact PPKG used.

## Sensitive material

The current first-lab credential model still places a reusable Graph application client secret in the real config, and the PPKG contains sensitive bulk-enrollment material.

Therefore the generated bundle:

- must live outside Git;
- is created only at a previously nonexistent path;
- receives restrictive Windows ACLs for the current identity, LocalSystem, and local Administrators;
- is deleted if the build fails after output creation.

The manifest itself contains hashes and provenance but not reusable credentials, access tokens, BPRTs, or BitLocker recovery passwords.

## Cryptographic manifest

`EXECUTION-MANIFEST.json` records every payload file.

Tracked files include:

- payload name;
- source kind;
- repository path;
- Git blob ID;
- size;
- SHA-256.

External inputs include size and SHA-256 without recording the private source path.

The manifest also records a deterministic `BundleId`.

`BundleId` is SHA-256 over:

```text
repositoryCommit
repositoryTree
sorted(payloadName | sizeBytes | sha256)
```

The generation timestamp is intentionally excluded, so identical execution inputs generate the same BundleId.

The serialized manifest is independently protected by:

```text
EXECUTION-MANIFEST.sha256
```

## Independent verifier

`Test-NGLabExecutionBundle.ps1` requires no Git repository and performs read-only verification of a built bundle.

It verifies:

- manifest SHA-256 sidecar;
- schema version;
- exact payload file set;
- no payload subdirectories;
- every file size and SHA-256;
- exactly one `ExternalConfig`;
- exactly one `ExternalProvisioningPackage`;
- deterministic BundleId;
- bundled config PPKG pin against the actual PPKG;
- manifest PPKG evidence against the same observed hash.

This verifier is the cryptographic gate that atomic 0010 can invoke before Stage and again immediately before Commit.

## Failure semantics

Any packaging or verification discrepancy is a **build failure**, not a migration recovery state. Atomic 0009 runs before migration state is changed.

The builder removes its newly created output directory if it fails after output creation. It never overwrites an existing bundle directory.

## CI contract

The existing PowerShell validation workflow is extended to include:

```text
lab/Build-NGLabExecutionBundle.ps1
lab/Test-NGLabExecutionBundle.ps1
```

in both Windows PowerShell 5.1 parser validation and PSScriptAnalyzer.

No migration script is modified by atomic 0009.

## Roadmap position

```text
0008  hostname preservation + Intune management naming
  ↓
0009  deterministic execution bundle + cryptographic manifest
  ↓
0010  manual Stage → Review → Commit controller
  ↓
0011  destructive-lab runbook + recovery/evidence gate
  ↓
real external config + dedicated hash-pinned PPKG
  ↓
first destructive test
```

Do not add migration-engine feature work between 0009 and the first destructive test unless a prerequisite atomic reveals an actual safety defect.

## Upstream provenance review

Refreshed before atomic 0009:

- NG `main`: `abbd91b317c2d4185dfc3bede2372705e61b9389`
- upstream `main`: `9effda8bd5ae042f1d837981eb07fd0b35af7c2c`
- upstream `8.1`: `798ce006dae9ea1ac0c06e12c0345f898c102a7c`

No upstream PR or open issue matching payload/PPKG/config packaging supplied a competing deterministic-bundle implementation to port. Atomic 0009 is therefore NG-specific.
