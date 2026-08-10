# Atomic 0010 Lab Manual — Manual Stage → Review → Commit Authorization

**Project:** `JeremiahCornelius/intune-device-migration-NG`  
**Atomic:** 0010  
**Operator shell:** Windows PowerShell 5.1  
**Migration behavior:** This procedure authorizes a device; it does **not** execute migration.

---

# 1. Purpose

This procedure places one exact Hybrid Entra device through an operator-controlled authorization lifecycle:

```text
STAGE → REVIEW → COMMIT
```

The controller uses a previously built and independently verifiable atomic 0009 execution bundle. The operator explicitly identifies the source device by its Entra `DeviceId` GUID.

Successful COMMIT means only:

> this exact source Entra device object, using this exact verified bundle, has been explicitly authorized for the later atomic 0011 destructive-lab procedure.

It does **not** execute `startMigrate.ps1`.

---

# 2. Important safety boundary

During this 0010 procedure, do **not** manually run any script from the bundle `payload` directory.

Do not run:

```text
preflight.ps1
startMigrate.ps1
reboot.ps1
postMigrate.ps1
postMigrateUser.ps1
```

Atomic 0011 will define when and how the destructive migration boundary may be crossed.

0010 may make only these Entra changes:

```text
STAGE:  add the exact source Entra device object to PROD-EN-ENTRA-MIGRATION-STAGE
COMMIT: add the exact same object to PROD-EN-ENTRA-MIGRATION-COMMIT
```

REVIEW is read-only.

SUCCESS is read-only throughout 0010.

---

# 3. Production lifecycle groups

The controller is pinned to these groups:

```text
STAGE
PROD-EN-ENTRA-MIGRATION-STAGE
c3b4a23d-2d81-424c-a0b2-4e5add86a7a8

COMMIT
PROD-EN-ENTRA-MIGRATION-COMMIT
7eeb1496-bdf4-4cf6-b5ac-2494cbb4c462

SUCCESS
PROD-EN-ENTRA-MIGRATION-SUCCESS
093f5a96-eeb0-48bd-b9b7-05b975d8c287
```

Tenant:

```text
a49b0b38-9873-445a-91c2-3ccbbe216d69
```

Do not substitute other groups for the first destructive lab without a separate design review.

---

# 4. Prerequisites

Before beginning, confirm all of the following:

```text
[ ] 0010 has been committed to NG main and its Windows PowerShell 5.1 CI validation passed.
[ ] The Windows PowerShell checkout is clean and on main.
[ ] Atomic 0009 non-destructive functional validation has passed.
[ ] A REAL operational 0009 bundle has been built from the intended lab configuration and PPKG.
[ ] The bundle is not the synthetic 0009 functional-test bundle.
[ ] The real PPKG was built without ComputerName customization.
[ ] The source Windows device is still Hybrid Entra joined.
[ ] You know the source device's dsregcmd DeviceId.
[ ] Microsoft.Graph.Authentication is installed for Windows PowerShell 5.1.
[ ] Your operator account can consent/use Device.Read.All and GroupMember.ReadWrite.All.
[ ] Your operator account has a supported Entra role for security-group membership changes.
```

For the current environment, Intune Administrator is a supported role for adding device members to security groups.

---

# 5. Open the correct PowerShell

Open **Windows PowerShell** as the operator account.

Run:

```powershell
$PSVersionTable.PSEdition; $PSVersionTable.PSVersion
```

Expected:

```text
Desktop
Major = 5
Minor = 1
```

Do not use PowerShell 7 for the first 0010 lab execution.

---

# 6. Enter the NG repository directory

Change into the repository directory used by Windows PowerShell.

Example:

```powershell
Set-Location 'C:\Users\<USER>\<COMPANY>\build\intune-device-migration-NG'
```

Set the repository variable from the current directory:

```powershell
$Repo=(Get-Location).ProviderPath
```

Confirm the controller exists:

```powershell
Test-Path -LiteralPath (Join-Path $Repo 'lab\Invoke-NGMigrationAuthorization.ps1')
```

Expected:

```text
True
```

---

# 7. Verify repository state

These Git commands may be performed in your normal Git terminal if desired. The controller itself will independently refuse a dirty tracked checkout.

Verify the current HEAD and status:

```powershell
git -C $Repo rev-parse HEAD; git -C $Repo status --porcelain=v1 --untracked-files=no
```

Expected:

```text
<the validated 0010 commit SHA>
<no tracked-status output>
```

The 0010 commit SHA will be recorded after you commit this atomic and validate CI. Do not use the controller operationally before that validation.

---

# 8. Confirm Microsoft Graph Authentication module

Run:

```powershell
Get-Module -ListAvailable Microsoft.Graph.Authentication | Sort-Object Version -Descending | Select-Object -First 1 Name,Version,Path
```

You must receive a module record.

If none is returned, install the Microsoft Graph PowerShell Authentication module according to your normal administrator procedure before continuing.

0010 deliberately does not auto-install modules.

---

# 9. Obtain the exact source DeviceId

On the **source Hybrid Windows 11 device**, open a command prompt or Windows PowerShell in the signed-in domain-user context and run:

```powershell
dsregcmd /status
```

Under **Device State**, verify:

```text
AzureAdJoined : YES
DomainJoined  : YES
```

Under **Device Details**, record:

```text
DeviceId : xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
```

This GUID is the authorization identity.

Do not use:

- the Windows hostname;
- the Intune managed-device ID;
- the Entra directory object ID;
- an Autopilot ID;
- a user object ID.

Set it in the operator PowerShell window:

```powershell
$DeviceId='xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx'
```

---

# 10. Set the real 0009 bundle path

Set the path to the **real operational execution bundle**, not the synthetic functional-test bundle.

Example:

```powershell
$Bundle='C:\NG-Lab-Run\Bundle-001'
```

Confirm it exists:

```powershell
Test-Path -LiteralPath $Bundle
```

Expected:

```text
True
```

Confirm its manifest is present:

```powershell
Test-Path -LiteralPath (Join-Path $Bundle 'EXECUTION-MANIFEST.json')
```

Expected:

```text
True
```

---

# 11. Independently verify the bundle before Stage

Run the atomic 0009 verifier directly:

```powershell
& (Join-Path $Repo 'lab\Test-NGLabExecutionBundle.ps1') -BundlePath $Bundle
```

Expected final result:

```text
NG destructive-lab execution bundle verification: PASS
```

Stop if the verifier reports any discrepancy.

---

# 12. STAGE — understand what will happen

STAGE will:

1. verify the controller repository provenance;
2. independently verify the 0009 bundle again;
3. reject synthetic `functionalTestOnly` / `.invalid` bundle data;
4. open delegated Graph authentication;
5. resolve exactly one Entra object using the supplied DeviceId;
6. require the device to be enabled and `trustType=ServerAd`;
7. validate the three lifecycle group objects;
8. inspect current direct membership;
9. write protected Stage-intent evidence;
10. add the exact device object to STAGE if needed;
11. read back membership;
12. write protected Stage evidence.

STAGE does not add COMMIT or SUCCESS membership.

---

# 13. Execute STAGE

Run this as one PowerShell command:

```powershell
.\lab\Invoke-NGMigrationAuthorization.ps1 -Action Stage -BundlePath $Bundle -DeviceId $DeviceId
```

A browser authentication flow may appear for Microsoft Graph.

Authenticate using the intended operator account in tenant:

```text
a49b0b38-9873-445a-91c2-3ccbbe216d69
```

The requested delegated scopes are:

```text
Device.Read.All
GroupMember.ReadWrite.All
```

---

# 14. Expected STAGE result

A successful run ends with:

```text
NG migration authorization STAGE: PASS
Evidence path: <path>
DeviceId:      <source DeviceId>
ObjectId:      <Entra directory object ID>
BundleId:      <0009 BundleId>
STAGE SHA-256: <hash>
```

It also prints the exact Review command.

**Copy the Evidence path.**

Set it in your PowerShell session, for example:

```powershell
$Evidence='C:\Users\<USER>\NG-Migration-Authorization\<generated-folder>'
```

---

# 15. Inspect Stage evidence

List the evidence directory:

```powershell
Get-ChildItem -LiteralPath $Evidence -File | Select-Object Name,Length
```

Expected at this stage:

```text
STAGE-INTENT.json
STAGE-INTENT.json.sha256
STAGE.json
STAGE.json.sha256
```

Inspect the ACL:

```powershell
icacls $Evidence
```

Expected effective principals:

```text
current Windows identity
NT AUTHORITY\SYSTEM
BUILTIN\Administrators
```

Broad inherited read access such as `Users`, `Authenticated Users`, or `Everyone` is a failure.

---

# 16. Inspect the Stage record

Run:

```powershell
Get-Content -LiteralPath (Join-Path $Evidence 'STAGE.json') -Raw | ConvertFrom-Json | Format-List schemaVersion,eventType,authorizationId,tenantId,bundle,device,groups,directMembership
```

Manually verify:

```text
[ ] eventType is Stage
[ ] tenantId is a49b0b38-9873-445a-91c2-3ccbbe216d69
[ ] device.deviceId equals the dsregcmd DeviceId
[ ] device.trustType is ServerAd
[ ] device.objectId is populated
[ ] device.displayName is the expected source device
[ ] bundle.bundleId is the intended real bundle
[ ] bundle.expectedSourceUserPrincipalName is the intended migrating user
[ ] groups.stage is PROD-EN-ENTRA-MIGRATION-STAGE
[ ] groups.commit is PROD-EN-ENTRA-MIGRATION-COMMIT
[ ] groups.success is PROD-EN-ENTRA-MIGRATION-SUCCESS
[ ] directMembership.stage is True
[ ] directMembership.commit is False
[ ] directMembership.success is False
```

Stop if any value is unexpected.

---

# 17. Optional portal cross-check after Stage

In Microsoft Entra admin center, inspect:

```text
Groups → PROD-EN-ENTRA-MIGRATION-STAGE → Members
```

Confirm the expected device is present.

Then inspect COMMIT and SUCCESS and confirm the device is absent from both.

The Graph evidence remains authoritative for the controller transaction; the portal check is an operator sanity check.

---

# 18. REVIEW — read-only gate

Run the exact Review command printed by Stage, or use:

```powershell
.\lab\Invoke-NGMigrationAuthorization.ps1 -Action Review -BundlePath $Bundle -DeviceId $DeviceId -EvidencePath $Evidence
```

Review performs no group mutation.

It re-verifies:

- repository provenance;
- the 0009 bundle;
- Stage evidence hash;
- exact tenant;
- exact DeviceId and Entra object ID;
- `ServerAd` state;
- direct STAGE membership;
- absence from COMMIT;
- absence from SUCCESS.

---

# 19. Expected REVIEW result

Successful output includes:

```text
NG migration authorization REVIEW: PASS
No group membership was changed by Review.
Evidence path:  <path>
DeviceId:       <DeviceId>
ObjectId:       <ObjectId>
BundleId:       <BundleId>
REVIEW SHA-256: <hash>
APPROVAL TOKEN: <64-character SHA-256>
```

It then prints an exact Commit command.

Do **not** run Commit immediately without reviewing the values.

---

# 20. Inspect Review evidence

List the evidence directory again:

```powershell
Get-ChildItem -LiteralPath $Evidence -File | Select-Object Name,Length
```

You should now additionally have:

```text
REVIEW.json
REVIEW.json.sha256
```

Inspect:

```powershell
Get-Content -LiteralPath (Join-Path $Evidence 'REVIEW.json') -Raw | ConvertFrom-Json | Format-List eventType,authorizationId,tenantId,bundle,device,groups,directMembership,stageEvidenceSha256,approvalTokenSha256,reviewDecision
```

Verify:

```text
[ ] eventType is Review
[ ] authorizationId matches STAGE.json
[ ] Stage evidence SHA-256 is populated
[ ] reviewDecision is EligibleForExplicitCommit
[ ] Stage=True, Commit=False, Success=False
[ ] DeviceId/ObjectId/BundleId still match
```

---

# 21. Manual authorization decision

Before Commit, explicitly answer all of these:

```text
[ ] Is this the intended physical lab VM?
[ ] Does dsregcmd still show Hybrid Entra join?
[ ] Is the DeviceId exact?
[ ] Is the Entra display name plausible for that VM?
[ ] Is trustType ServerAd?
[ ] Is this the intended real 0009 bundle?
[ ] Is the expected source UPN correct?
[ ] Is STAGE present?
[ ] Are COMMIT and SUCCESS absent?
[ ] Is local recovery access known and tested under the separate recovery prerequisite?
[ ] Are you intentionally authorizing this device for the later 0011 destructive test?
```

If any answer is **No** or uncertain, do not Commit.

---

# 22. COMMIT — explicit authorization

Use the **exact Commit command printed by Review**. It will contain the cryptographically bound approval token.

The form is:

```powershell
.\lab\Invoke-NGMigrationAuthorization.ps1 -Action Commit -BundlePath $Bundle -DeviceId $DeviceId -EvidencePath $Evidence -ApprovalToken '<token-from-Review>'
```

The token is specific to:

- tenant;
- authorization transaction;
- DeviceId;
- Entra object ID;
- BundleId;
- Stage evidence SHA-256;
- STAGE group ID;
- COMMIT group ID;
- SUCCESS group ID.

Do not hand-edit the token.

---

# 23. COMMIT checks before mutation

Before changing COMMIT membership, the controller again:

1. verifies the 0009 bundle;
2. verifies Stage evidence and sidecar;
3. verifies Review evidence and sidecar;
4. confirms Review points to the current Stage hash;
5. recomputes and validates the approval token;
6. resolves the exact Entra device again;
7. requires `ServerAd` and enabled state;
8. requires direct STAGE membership;
9. requires absence from COMMIT;
10. requires absence from SUCCESS;
11. writes `COMMIT-INTENT.json` and its hash sidecar.

Only then is COMMIT membership added.

---

# 24. Expected COMMIT result

Successful output ends with:

```text
NG migration authorization COMMIT: PASS
Evidence path:  <path>
DeviceId:       <DeviceId>
ObjectId:       <ObjectId>
BundleId:       <BundleId>
COMMIT SHA-256: <hash>

AUTHORIZATION ONLY: migration has NOT been started.
```

That final line is important.

Do not run `startMigrate.ps1` yet.

---

# 25. Inspect final 0010 evidence

The directory should now contain:

```text
STAGE-INTENT.json
STAGE-INTENT.json.sha256
STAGE.json
STAGE.json.sha256
REVIEW.json
REVIEW.json.sha256
COMMIT-INTENT.json
COMMIT-INTENT.json.sha256
COMMIT.json
COMMIT.json.sha256
```

List it:

```powershell
Get-ChildItem -LiteralPath $Evidence -File | Sort-Object Name | Select-Object Name,Length
```

---

# 26. Verify final membership state

Inspect the Commit evidence:

```powershell
Get-Content -LiteralPath (Join-Path $Evidence 'COMMIT.json') -Raw | ConvertFrom-Json | Format-List eventType,authorizationId,tenantId,bundle,device,groups,directMembership,membershipMutation
```

Required state:

```text
Stage   = True
Commit  = True
Success = False
```

Any other state is a stop condition.

---

# 27. Portal cross-check after Commit

In Entra admin center verify the same device appears as a direct member of:

```text
PROD-EN-ENTRA-MIGRATION-STAGE
PROD-EN-ENTRA-MIGRATION-COMMIT
```

and does **not** appear in:

```text
PROD-EN-ENTRA-MIGRATION-SUCCESS
```

Do not manually add SUCCESS.

---

# 28. Stop point after 0010

After a clean Commit, stop.

The machine remains unmigrated.

The required state is:

```text
Verified real 0009 bundle
        +
exact Hybrid Entra device identity
        +
STAGE evidence
        +
REVIEW evidence
        +
explicit approval token
        +
COMMIT evidence
        ↓
AUTHORIZED — NOT YET MIGRATING
```

Atomic 0011 will define the destructive-lab execution and recovery/evidence sequence.

---

# 29. Failure handling

If Stage, Review, or Commit throws an error:

1. Do not retry blindly.
2. Do not manually force group membership to make the script pass.
3. Record the full console error.
4. Preserve the evidence directory exactly as it exists.
5. Record current STAGE/COMMIT/SUCCESS membership from Entra.
6. Do not run migration scripts.
7. Reconcile the observed state before continuing.

If an error occurs after `COMMIT-INTENT.json` exists, treat that evidence as particularly important: Graph mutation might have been attempted even if final `COMMIT.json` was not written.

---

# 30. Duplicate Commit behavior

If Commit reports that the device is already a COMMIT member, the controller intentionally fails closed.

Do not remove/re-add membership merely to make the controller pass.

Investigate whether:

- a previous Commit mutation succeeded;
- the final evidence write failed;
- someone manually altered membership;
- another authorization transaction exists.

This ambiguity is evidence, not an idempotence problem to hide.

---

# 31. Evidence retention

Retain the entire authorization directory for the first destructive test.

Also record externally in the test notes:

```text
0010 commit SHA
0010 tree SHA
0009 BundleId
0009 manifest SHA-256
source DeviceId
source Entra ObjectId
STAGE evidence SHA-256
REVIEW evidence SHA-256
COMMIT evidence SHA-256
operator account
UTC timestamps
```

Do not place the evidence directory in Git.

---

# 32. 0010 PASS criteria

```text
[ ] Controller ran from validated clean NG main
[ ] Real 0009 bundle independently verified
[ ] Synthetic functional-test bundle rejected/not used
[ ] Exact DeviceId resolved
[ ] Device trustType == ServerAd
[ ] Correct lifecycle groups validated
[ ] STAGE-INTENT written before Stage mutation
[ ] Direct STAGE membership read back
[ ] STAGE evidence hash verified
[ ] Review performed no mutation
[ ] Review revalidated STAGE=True / COMMIT=False / SUCCESS=False
[ ] Approval token generated
[ ] Operator manually reviewed the transaction
[ ] COMMIT-INTENT written before Commit mutation
[ ] Direct COMMIT membership read back
[ ] Final membership STAGE=True / COMMIT=True / SUCCESS=False
[ ] COMMIT evidence written and hash-protected
[ ] No migration script executed
```

Only after all items pass is atomic 0010 operationally complete for that device/bundle authorization transaction.
