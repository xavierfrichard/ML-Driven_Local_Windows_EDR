# Warden Phase 0 Spike â€” WDAC / App Control policy artifacts

This folder holds the hand-authored App Control for Business (WDAC) policy that
Warden ships, plus the notes needed to understand it. The **base** policy is not
hand-authored â€” it is derived at deploy time from a Microsoft-shipped example.
Only the small **supplemental** lives here as source.

> **Safety:** every policy here is designed to be deployed **only inside an
> isolated Windows 11 Hyper-V VM**. The deploy script refuses to run without an
> explicit `-IUnderstandVmOnly` switch, and prints the exact rollback command.
> A wrong policy can lock a machine out of running code. Treat this as
> load-bearing.

---

## Files

| File | What it is |
|---|---|
| `WardenSpike.Supplemental.xml` | Hand-authored **supplemental** policy (multiple-policy format). Adds an allow-by-hash for the lab exe (and, at deploy time, the unsigned reader tool). Ships a **deliberately invalid** placeholder hash and an all-zeros `BasePolicyID` so a hand-deploy fails loud / stays inert; both are regenerated at deploy time. |
| `README.md` | This document. |

The base policy XML, the compiled `.cip` binaries, and the working copies of
these files are produced by `scripts/Deploy-WardenSpikePolicy.ps1` into a
working directory (default `%ProgramData%\WardenSpikeLab\policy`); they are not
checked in.

The work folder is **admin-only**: the script creates `%ProgramData%\WardenSpikeLab`,
owns it as Administrators, gives it a protected SYSTEM + Administrators ACL, and
empties `policy\` at the start of every run. It refuses a lab folder that someone
else pre-created, a junction, or a `-WorkDir` outside the lab folder. Nothing it
compiles or deploys is read back from a user-writable place: the base is
regenerated from the Microsoft template on every run, and the lab binaries
(which do live in the user's profile) are copied into the admin-only folder and
checked against a SHA-256 pin (`-LabExeSha256`, `-WardenSpikeToolSha256`) before
they are hashed into the supplemental.

---

## The base-from-Microsoft-template approach (and why we do NOT hand-author it)

A WDAC **base** policy that enforces zero-trust has to allow *all of Windows* â€”
thousands of signed components â€” or the machine cannot boot or log in. Writing
that allowlist by hand is enormous and a single mistake bricks the box.

So Warden does **not** hand-author the base. The deploy script instead:

1. Copies Microsoft's shipped example
   `C:\Windows\schemas\CodeIntegrity\ExamplePolicies\DefaultWindows_Audit.xml`
   (which already safely allows Windows OS components, Store/MSIX-signed apps,
   WHQL drivers, and core Microsoft apps) to a working file.
2. Converts it to multiple-policy format with `Set-CIPolicyIdInfo -ResetPolicyID`,
   then sets both `PolicyID` and `BasePolicyID` to the spike's fixed base ID
   `{77EEF7EE-839E-49F6-ADF1-3BD853A234B1}` - that self-reference is what makes it
   a base, and the fixed ID makes every run update the same deployed base. This
   happens on **every run**; a base XML left from an earlier run is never reused.
   `VersionEx` is set above the version CiTool reports for the deployed base.
3. Guarantees the rule options Warden needs:
   - `3  Enabled:Audit Mode` â€” **present on first run (audit-first)**.
   - `6  Enabled:Unsigned System Integrity Policy` â€” unsigned â‡’ rebootless.
   - `0  Enabled:UMCI` â€” user-mode enforcement (exe/dll/scripts), not just drivers.
   - `16 Enabled:Update Policy No Reboot` â€” updates apply without reboot.
   - `17 Enabled:Allow Supplemental Policies` â€” lets the supplemental attach.
   - During the **audit phase** it also **removes `19 Enabled:Dynamic Code
     Security`**, which the template inherits. Option 19 has **no audit mode** â€”
     it enforces even while the policy is in Audit Mode â€” so leaving it in would
     make the "audit" run partly enforcing for dynamically-generated/JIT code.
     Removing it keeps the first run a true observe-only pass.
   - On **enforce** it asserts `9 Enabled:Advanced Boot Options Menu` (keeps the
     F8 recovery menu) and `10 Enabled:Boot Audit on Failure` so a bad first
     enforced ring stays recoverable rather than blocking boot-critical code.
4. Compiles it with `ConvertFrom-CIPolicy` and deploys it with
   `CiTool --update-policy`.

`DefaultWindows_Audit.xml` is chosen over `AllowMicrosoft.xml` because it has a
smaller trust surface (Windows + a short list of Microsoft apps, rather than
*all* Microsoft-signed software), and over `DenyAllAudit.xml` because a pure
default-deny base would would-block Windows itself.

---

## Why audit-first

The **very first** deployment must be **audit mode** (rule option 3 present).

- In audit mode WDAC **does not actually block** anything â€” it only logs a
  `CodeIntegrity/Operational` event **3076** ("would have been blocked").
- This means a mistaken or overly-strict policy cannot lock the VM out of
  running code on first contact. You observe the 3076 events, confirm the
  policy blocks exactly what you expect and nothing else, and only then flip to
  enforce.
- Enforce mode (option 3 removed) actually blocks and logs event **3077**.

The deploy script's default path is audit. Enforce is opt-in via `-Enforce`,
which redeploys the **same base** GUID with option 3 removed and the version
bumped. Warden always crosses the auditâ†’enforce line deliberately, on the base.

`-Enforce` is **gated so it can never run on a first, unobserved deployment**. It
is refused unless **both**:

- the spike **audit base** is already deployed (CiTool reports its PolicyID), and
- the operator passes a second explicit switch, **`-IHaveReviewedAuditEvents`**.

Without this, `-Enforce` on a fresh machine would create the base and strip Audit
Mode in one step â€” blocking every non-Microsoft binary (including the unsigned
`Warden.Spike` reader) before a single 3076 event was ever seen. The gate keeps
the observe-then-enforce ordering mandatory.

### Keeping the unsigned reader tool runnable under enforce

An enforce base allows only Windows/Store/Microsoft-signed code, so it would
block the **user-built, unsigned `Warden.Spike` reader** the spike depends on
(goal #3). To prevent that self-lockout, the deploy script folds
the reader's hash (`-WardenSpikeToolPath`, default
`%USERPROFILE%\WardenSpikeLab\Warden.Spike.exe`) into the supplemental allow-set
whenever the exe exists and `-WardenSpikeToolSha256` pins it (an unpinned reader
is not allowed, with a warning) â€” so flipping to enforce never blocks the reader. If the
exe is not present at enforce time the script warns that it must be re-run once
the reader is built.

---

## The precedence subtlety: block by *absence of allow*, not by `<Deny>`

WDAC evaluates rules in a fixed order:

> **First** all explicit **Deny** rules, **then** all explicit **Allow** rules
> (then Managed Installer, then ISG).

Two consequences drive this spike's design:

1. **A Deny always wins.** A supplemental Allow can *never* un-block something
   the base explicitly Denies. Base + supplemental is a **union of allows**.
2. Therefore the lab exe must be blocked by the **absence of any matching
   allow**, not by an explicit `<Deny>`.

That is exactly what `DefaultWindows_Audit` gives us: it allows Windows via
**signer** rules, but an **unsigned binary in a user folder matches no allow**,
so it is would-be-blocked (3076 in audit / 3077 in enforce) **with no Deny rule
needed**. Because the block is absence-of-allow, the Warden supplemental can
add an Allow-by-hash for that exe and â€” via the union â€” the file now runs. Had
we blocked it with a `<Deny>`, no supplemental could rescue it. This is the core
mechanic the "user clicks Allow" loop rehearses.

---

## PolicyID / BasePolicyID relationship

Multiple-policy format links a supplemental to its base purely through these two
GUIDs:

```
BASE policy (WardenBase, from DefaultWindows_Audit):
    PolicyType   = "Base Policy"
    PolicyID     = {B}   <-- the spike's fixed base GUID
                            ({77EEF7EE-839E-49F6-ADF1-3BD853A234B1})
    BasePolicyID = {B}   <-- equals its own PolicyID (self-reference == "I am a base")
    Rules        include option 17 (Allow Supplemental Policies)

SUPPLEMENTAL policy (WardenSpike.Supplemental.xml):
    PolicyType   = "Supplemental Policy"
    PolicyID     = {S}   <-- this supplemental's OWN fixed GUID
                            ({591A5539-3983-4C77-92B7-583045489C23})
    BasePolicyID = {B}   <-- points at the BASE's PolicyID  ==  the linkage
```

The Warden **service** deploys its own allow-list supplemental under a different
fixed ID, `{7A4D1C0A-5B2E-4F6A-9C3D-000000000001}`. The spike supplemental must
never reuse it (two policies with one PolicyID overwrite each other); the deploy
script refuses to run if `WardenSpike.Supplemental.xml` carries that ID. Older
spike runs did use it: run `Remove-WardenSpikePolicy.ps1` once before deploying
with this version.

Rules of thumb:

- **Base:** `PolicyID == BasePolicyID`.
- **Supplemental:** `PolicyID` is unique to itself; `BasePolicyID` equals the
  **base's** `PolicyID`. The deploy script fills `{B}` into the supplemental via
  `Set-CIPolicyIdInfo -SupplementsBasePolicyID {B}` (the checked-in file carries
  an all-zeros placeholder, and the deploy script **refuses to deploy** a
  supplemental whose `BasePolicyID` is still all-zeros after linkage).
- A supplemental expands **exactly one** base; a base must set option 17 to
  accept any supplemental.
- Each compiled `.cip` **must be named `{PolicyID}.cip`** â€” `{B}.cip` for the
  base, `{S}.cip` for the supplemental.
- Rollback removes **by `PolicyID`**: `CiTool --remove-policy "{S}"` then
  `CiTool --remove-policy "{B}"` (remove the supplemental first).

---

## Reboot / rollback facts (unsigned, multiple-policy, HVCI-off)

Because every Warden spike policy is **unsigned**, **multiple-policy format**,
and **HVCI-off**, all deploys and removals are reboot-free:

- `CiTool --update-policy "{GUID}.cip"` applies immediately (it refreshes CI).
- `CiTool --remove-policy "{GUID}"` removes it; rebootless on Windows 11 **24H2+**
  (earlier builds fully drop it on the next refresh/reboot). Verify the VM is
  24H2+ so rollback is also rebootless.
- **Always remove the supplemental before the base.**

The deploy script prints the exact `CiTool --remove-policy {GUID}` commands for
whatever it deployed; `scripts/Remove-WardenSpikePolicy.ps1` finds and removes
the spike's policies (its fixed IDs, or a "Warden Spike" friendly name). It does
not remove the Warden service's supplemental by name; if that supplemental still
expands the spike base, the script stops and names it (`-IncludeDependentSupplementals`
removes it too).

---

## Typical VM run sequence

```powershell
# In an elevated PowerShell, inside the isolated Windows 11 VM:

# 1. Create a harmless lab exe that will be blocked. It prints the SHA-256 pin.
.\scripts\New-WardenLabExe.ps1
$pin = '<the SHA-256 it printed>'

# 2. Deploy the AUDIT base. The lab exe is now would-be-blocked -> event 3076.
.\scripts\Deploy-WardenSpikePolicy.ps1 -IUnderstandVmOnly
#    ...run %USERPROFILE%\WardenSpikeLab\hello.exe, observe 3076 in
#    Microsoft-Windows-CodeIntegrity/Operational...

# 3. (Warden loop) Deploy the supplemental that allows the exe by hash.
.\scripts\Deploy-WardenSpikePolicy.ps1 -IUnderstandVmOnly -DeploySupplemental -LabExeSha256 $pin
#    ...hello.exe now runs (union of allows)...

# 4. (Optional) Flip the base to ENFORCE. Requires a prior audit base AND the
#    reviewed-events switch. Now the block is real -> event 3077.
.\scripts\Deploy-WardenSpikePolicy.ps1 -IUnderstandVmOnly -Enforce -IHaveReviewedAuditEvents -LabExeSha256 $pin

# 5. Roll everything back to a clean machine.
.\scripts\Remove-WardenSpikePolicy.ps1 -IUnderstandVmOnly
```
