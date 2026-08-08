# Deterministic destructive-lab execution bundle

Atomic 0009 adds the packaging/provenance layer for the first destructive `intune-device-migration-NG` test. It does **not** add migration logic and does not cross the migration commit boundary.

## Purpose

The first destructive test must be attributable to an exact repository state, an exact runtime file set, an exact real configuration, and an exact provisioning package. The lab bundle therefore uses a fixed allow-list instead of recursively packaging the repository.

The bundle builder records cryptographic provenance in `EXECUTION-MANIFEST.json` and writes a SHA-256 sidecar for the manifest itself.

## Committed tooling

- `Build-NGLabExecutionBundle.ps1` — builds a new protected execution directory from a clean `main` checkout and external lab inputs.
- `Test-NGLabExecutionBundle.ps1` — independently verifies the manifest, deterministic `BundleId`, exact payload file set, file sizes/hashes, and PPKG hash pin.

Both scripts are covered by the repository's Windows PowerShell 5.1 parser and PSScriptAnalyzer workflow.

## Runtime allow-list

The generated `payload` directory contains only:

```text
Migration.Common.ps1
preflight.ps1
startMigrate.ps1
reboot.ps1
reboot.xml
postMigrate.ps1
postMigrateUser.ps1
postMigrate.xml
config.json
<one externally supplied>.ppkg
```

`preflight.ps1` is the lab staging entry point. The remaining tracked runtime files correspond to the files required by the current migration controller after staging.

The builder intentionally excludes `install.ps1`, `groupTag.ps1`, `groupTag.xml`, validation tooling, GitHub workflow files, repository documentation, `Autopilot.jpg`, `Autopilot.theme`, `IntuneWinAppUtil.exe`, and other development/repository content.

## Inputs are operational artifacts, not Git artifacts

The real lab configuration and PPKG must remain outside the repository:

```text
<external-private-path>\config.json
<external-private-path>\<lab-package>.ppkg
```

The builder refuses to package either input from within the repository. It also refuses to place its output inside the repository.

The config must contain real values rather than the tracked template placeholders and must contain a 64-character `safety.ppkgSha256`. The actual `.ppkg` SHA-256 must match that pin before any bundle is created.

The provisioning package remains governed by design history 0008: **the PPKG must omit `ComputerName` customization**. Atomic 0009 does not claim to reverse-engineer or inspect the binary PPKG for that setting.

## Build procedure

From a clean `main` checkout:

```powershell
.\lab\Build-NGLabExecutionBundle.ps1 `
    -ConfigPath 'C:\NG-Lab-Private\config.json' `
    -PpkgPath 'C:\NG-Lab-Private\NG-Lab-EntraJoin.ppkg' `
    -OutputPath 'C:\NG-Lab-Run\Bundle-001'
```

The output path must not already exist. This prevents accidental merging of evidence from separate lab attempts.

The builder requires:

- Git available in `PATH`;
- repository origin matching `JeremiahCornelius/intune-device-migration-NG`;
- branch `main`;
- no modified tracked files;
- every allow-listed runtime file tracked at `HEAD`;
- external config and PPKG;
- a valid config PPKG hash pin;
- an output location external to the Git checkout.

The generated directory is ACL-restricted to:

- the current Windows identity;
- `NT AUTHORITY\SYSTEM`;
- local Administrators.

This is required because the bundle contains a reusable Graph client secret in the current lab credential model and a sensitive bulk-enrollment provisioning package.

## Output structure

```text
Bundle-001\
    EXECUTION-MANIFEST.json
    EXECUTION-MANIFEST.sha256
    payload\
        Migration.Common.ps1
        preflight.ps1
        startMigrate.ps1
        reboot.ps1
        reboot.xml
        postMigrate.ps1
        postMigrateUser.ps1
        postMigrate.xml
        config.json
        NG-Lab-EntraJoin.ppkg
```

The manifest does **not** contain the config contents, client secret, access token, BPRT, or BitLocker recovery material.

## Cryptographic evidence

For every tracked runtime file, the manifest records:

- repository-relative path;
- Git blob ID at `HEAD`;
- size;
- SHA-256.

For the external config and PPKG it records size and SHA-256 without recording the original private filesystem path.

The manifest additionally records:

- repository origin;
- branch;
- commit SHA;
- tree SHA;
- builder Git blob ID and SHA-256;
- config SHA-256;
- PPKG SHA-256;
- configured PPKG SHA-256 pin and match result;
- a deterministic `BundleId`.

`BundleId` is SHA-256 over the repository commit/tree and the sorted payload names, sizes, and SHA-256 values. It therefore remains stable for identical execution inputs even though `generatedUtc` and the manifest's own SHA-256 vary between builds.

`EXECUTION-MANIFEST.sha256` protects the complete serialized manifest.

## Independent verification

Before preflight or any future Stage/Commit controller uses a bundle:

```powershell
.\lab\Test-NGLabExecutionBundle.ps1 `
    -BundlePath 'C:\NG-Lab-Run\Bundle-001'
```

The verifier is read-only. It fails if:

- the manifest sidecar does not match;
- the manifest is malformed or unsupported;
- the deterministic `BundleId` does not recompute;
- a payload file is missing, extra, resized, or rehashed;
- the payload contains a subdirectory;
- there is not exactly one external config and one external PPKG;
- the PPKG no longer matches `config.safety.ppkgSha256`.

The verifier does not print reusable secrets.

## Boundary with atomics 0010 and 0011

Atomic 0009 ends after producing and independently verifying a deterministic execution bundle.

It does **not**:

- run `preflight.ps1`;
- create a Stage/Review/Commit controller;
- validate the local recovery credential;
- invoke `startMigrate.ps1`;
- alter Entra, Intune, AD, profile, BitLocker, or enrollment state;
- add the device to `MIGRATION-SUCCESS`.

Atomic 0010 will consume this bundle as the input to the explicit Stage → Review → Commit workflow. Atomic 0011 will define the destructive-lab runbook and recovery/evidence contract.
