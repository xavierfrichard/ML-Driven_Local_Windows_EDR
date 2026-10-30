# Warden install + hardening (Phase 6)

Phase 6 makes the agent **survivable, installable, and signable** without PPL/ELAM (which require a
Microsoft AV-vendor agreement and are explicitly **out of scope** — see below). Self-protection is
achieved with a hardened service security descriptor, restart-on-kill recovery, and ACL-locked on-disk
state.

> ⚠️ These scripts make **real, machine-wide changes** (a Windows service, service ACLs, a locked data
> directory, registry configuration). Run them **only** on the target machine or inside the Win11
> Hyper-V test VM, elevated, from **64-bit Windows PowerShell started with `-NoProfile`** — never casually
> on a dev box.

## Build

```powershell
dotnet publish src\Warden.Service\Warden.Service.csproj -c Release -o out\service
dotnet publish src\Warden.Ui\Warden.Ui.csproj           -c Release -o out\ui
```

## Sign and/or write a manifest (so the installer can verify what it copies)

Anything that can write to `out\` between the build and the install gets its code run as SYSTEM. The
installer can check the binaries **before and after** it copies them into Program Files, in two ways.
Use one or both; without either it installs but warns that nothing was verified.

**Authenticode (recommended; needs a code-signing certificate).** Warden's managed binaries are **not**
signed by the build — no certificate is committed. Sign the published output, then pass the
certificate's thumbprint to the installer:

```powershell
.\installer\sign.ps1 -Path out\service -Thumbprint <thumbprint>
.\installer\sign.ps1 -Path out\ui      -Thumbprint <thumbprint>
.\installer\install.ps1 -BinDir out\service -UiDir out\ui -SignerThumbprint <thumbprint>
```

Every `Warden*.dll` / `Warden*.exe` must then carry a valid signature from exactly that certificate. A
self-signed certificate is fine for personal test use (its root must be trusted on the target);
distribution needs an OV/EV cert. Third-party DLLs are not signed by `sign.ps1`, so add a manifest to
cover them.

**SHA-256 manifest (covers every file).** Right after a trusted build, write the manifest, keep it in a
folder only administrators can write, and pass it to the install:

```powershell
.\installer\install.ps1 -BinDir out\service -UiDir out\ui -WriteManifest C:\WardenRelease\warden.sha256
.\installer\install.ps1 -BinDir out\service -UiDir out\ui -ManifestPath C:\WardenRelease\warden.sha256
```

`-WriteManifest` only writes the file (one `<sha256>  service\…` / `ui\…` line per file) and exits. The
install refuses a manifest that non-administrators can edit, and any missing, extra or different file.

## Install (elevated, on the target / VM)

```powershell
.\installer\install.ps1 -BinDir out\service -UiDir out\ui [-SignerThumbprint …] [-ManifestPath …] [-WdacBasePolicyGuid '{...}']
```

This:

0. **Resolves its trust roots** from HKLM and the known-folder API, never from `$env:ProgramFiles` /
   `$env:ProgramData` (a user's `HKCU\Environment` can override those in an elevated session). System
   tools run by full System32 path, and modules load only from `$PSHOME` and Program Files.
1. **Checks the .NET host** (`<Program Files>\dotnet\dotnet.exe`): it must carry a valid Authenticode
   signature from Microsoft (chaining to a Microsoft root), and it, its folder, every parent folder,
   `host\fxr` and `shared\Microsoft.NETCore.App` must be owned and writable only by SYSTEM, Administrators
   or TrustedInstaller.
2. **Verifies the binaries** (signature and/or manifest, see above), then **copies** them to
   `<Program Files>\Warden\{service,ui}` through a staging folder inside the locked install directory,
   verifies the copy again, and only then swaps it in. The tree is locked (owner Administrators;
   SYSTEM/Administrators full, Users read+execute). A LocalSystem service must never load code from a
   user-writable directory — anyone could swap the DLL and be SYSTEM on the next restart.
3. Creates `<ProgramData>\Warden` owned by Administrators and locked to **SYSTEM + Administrators** only
   (protected DACL, set atomically when the folder is created). **A pre-existing directory** (standard
   users can create folders under `C:\ProgramData`) that is, or contains, a junction, symlink or hard link,
   or that anyone else owns or can write, is **renamed aside** to `<dir>.untrusted-<timestamp>` without
   following anything inside it, and a fresh one is created. Inspect and delete the renamed folder. A
   directory that only administrators control (an earlier install) keeps its contents; its owners are
   normalised to Administrators and its DACL is replaced, not merged. The install directory gets the same
   treatment.
4. Registers the **WardenAgent** service as `LocalSystem`, auto-start, launched via the **pinned**
   `dotnet.exe` host (`binPath = "…\dotnet.exe" "<Program Files>\Warden\service\Warden.Service.dll"`).
5. Applies the hardened **service SDDL** (`sc sdset`) — standard users may query the service but cannot
   **stop, change, or delete** it. Mirrors `Warden.Hardening.HardeningSddl.ServiceDacl`. Configures
   **restart-on-kill** recovery (`sc failure … actions= restart/…`, `sc failureflag 1`). Every `sc.exe`
   call's exit code is checked.
6. Writes the service's settings into its own registry value
   `HKLM\SYSTEM\CurrentControlSet\Services\WardenAgent\Environment` (REG_MULTI_SZ): `WARDEN_DATA_DIR`,
   `WARDEN_ENFORCE_HARDENING=1` and, if given, `WARDEN_WDAC_BASE_POLICY_GUID`. New machine environment
   variables only reach services after a reboot; this value is read at every service start, so the first
   start already has them. Other entries in that value are kept. `WARDEN_DATA_DIR` (and the GUID) are also
   set machine-wide for tools; `WARDEN_ENFORCE_HARDENING` is service-only (and removed machine-wide if an
   older install set it), so a dev/console run never re-ACLs the data directory.
7. Optionally registers the tray UI to launch **elevated** at logon (a scheduled task with
   `-RunLevel Highest`; the UI's manifest is `requireAdministrator` because the service's pipes admit only
   elevated callers and an "Allow" is honoured only from an Administrators token). Standard-user accounts
   do not get the tray and cannot approve launches.
8. API keys (`WARDEN_VT_API_KEY`, `WARDEN_ANTHROPIC_API_KEY`): set them with `installer\Set-WardenSecret.ps1`,
   not as machine environment variables (every user can read those).

On every start, the service (with `WARDEN_ENFORCE_HARDENING=1`) refuses to use the data directory if it,
a parent folder or anything inside it is a junction, symlink, mount point or hard link; otherwise it resets
the owner (Administrators) and access lists of the whole tree, verifies them, and stops with exit code 1
(so recovery retries) if it cannot. It also checks that only SYSTEM, Administrators or TrustedInstaller own
or can write its binaries, `dotnet.exe`, `hostfxr`, the shared runtime and their parent folders, and records
a critical tamper event for each problem.

Verify:

```powershell
sc.exe qc WardenAgent          # config, start type, binPath
sc.exe sdshow WardenAgent      # the applied security descriptor
sc.exe qfailure WardenAgent    # recovery actions
(Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Services\WardenAgent).Environment
```

## Uninstall

```powershell
.\installer\uninstall.ps1              # stop + delete service, remove config vars + UI task + <Program Files>\Warden
.\installer\uninstall.ps1 -RemoveData  # also remove the data directory (confirmed; -Force to skip)
```

Right before each directory is removed — after the confirmation prompt — the whole tree is checked again.
If anything in it is a junction, symlink, mount point or hard link, or is owned or writable by anyone other
than SYSTEM / Administrators / TrustedInstaller, nothing is removed and the script says why. The removal
walks the tree without following links and deletes one entry at a time (no recursive `takeown`, `icacls`
or `Remove-Item` that could follow a planted junction).

**What uninstall leaves in place** (remove these by hand if you want them gone):

| Left behind | Why it matters | How to remove |
|---|---|---|
| The **WDAC supplemental policy** `{7A4D1C0A-5B2E-4F6A-9C3D-000000000001}` | Every hash Warden allow-listed stays allowed by the OS | `CiTool.exe --remove-policy "{7A4D1C0A-5B2E-4F6A-9C3D-000000000001}"` (check `CiTool.exe -lp` first) |
| **Firewall rules** named `Warden Block …` | Blocked apps stay blocked | `Get-NetFirewallRule -DisplayName 'Warden Block*' \| Remove-NetFirewallRule` |
| **Exploit-protection / IFEO** `MitigationOptions` set from the Advanced panel | Per-app mitigations stay on | `Set-ProcessMitigation -Name <exe> -Remove`, or delete the value under `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\<exe>` |
| **ASR rules** added from the Advanced panel | They stay in Defender's configuration | `Remove-MpPreference -AttackSurfaceReductionRules_Ids <id>` |
| The data directory (without `-RemoveData`) and any `<dir>.untrusted-<timestamp>` folder the installer renamed aside | Database, quarantine, logs | Re-run with `-RemoveData`; inspect and delete renamed folders by hand |

## What self-protection does (and does not) cover

| Threat | Mitigation |
|---|---|
| Standard user stops/deletes the service | Hardened service SDDL (only SYSTEM/Admins can stop/delete) |
| Service is killed / crashes | SCM restart-on-kill recovery (`sc failure` + `failureflag`) |
| Standard user reads/edits the database or quarantine | Data directory + DB locked to SYSTEM + Administrators |
| Standard user pre-creates `C:\ProgramData\Warden` to stay its owner | Installer renames it aside; service resets owner + ACLs of the whole tree at every start |
| Junction / hard link redirects SYSTEM's writes, ACL changes or deletes | Installer, service and uninstaller refuse any link in the tree before changing anything |
| Tampered binaries in `out\` before install | `-SignerThumbprint` / `-ManifestPath`, checked before and after the copy |
| User-writable .NET host or runtime | Installer checks owner/ACL + Microsoft signature; service re-checks owner/ACL at every start |
| Tampering leaves no trace | Every failed lockdown / recovery event is written to `tamper_log` and the Serilog file (control, line-separator and bidi characters escaped; the file rolls at 50 MB so flooding cannot silence it) |

**Residual risk — the elevated tray UI and the user's environment.** The `WardenUi` logon task runs
`Warden.Ui.exe` elevated (RunLevel Highest) **with the logged-on user's environment**. Anything running as
that user, even unelevated, can write `HKCU\Environment` and set .NET loader variables
(`DOTNET_STARTUP_HOOKS`, `DOTNET_ROOT`, `CORECLR_ENABLE_PROFILING` / `CORECLR_PROFILER_PATH`,
`DOTNET_DiagnosticPorts`, …) that take effect at the next elevated start, i.e. elevated code execution with
the UI's admin authority on the management pipe.
- `StartupHookSupport=false` in the UI build (`Directory.Build.props`, PR #7) disables startup hooks.
- The installer does **not** wrap the task in a launcher that clears these variables: `cmd.exe` keeps a
  console window open for the tray's lifetime; `start`/ShellExecute, PowerShell (`COR_PROFILER`) and WSH
  (per-user COM) each have their own per-user hijack path; and a blocklist misses new variables.
- Still open: `DOTNET_ROOT` (a framework-dependent apphost resolves the runtime through it) and profiler
  variables. Publishing the UI self-contained removes the `DOTNET_ROOT` path. The full fix is for the tray
  to run unelevated and the service to authorise the user another way.

**Out of scope (documented limitation):** PPL (Protected Process Light) and ELAM anti-tamper require a
Microsoft AV-vendor agreement and code-signing under that program. An **Administrator** can always stop
or remove the agent — this is by design for a personal tool and is the ceiling of non-PPL
self-protection.

## Productionizing the installer (WiX / MSIX)

The PowerShell scripts here are the immediately-runnable install path and the reference for exactly what
must happen. For a distributable package, wrap the same steps in **WiX** (a `ServiceInstall` +
`ServiceControl` + `util:PermissionEx` for the SDDL + a custom action for `sc failure`) or **MSIX** (with
a service extension). The C# `Warden.Hardening.ServiceHardener` already emits the exact `sc.exe`
arguments, and `HardeningSddl` the exact descriptors, so a WiX/MSIX author has a single source of truth.
