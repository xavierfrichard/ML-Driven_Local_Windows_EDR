# Warden install + hardening (Phase 6)

Phase 6 makes the agent **survivable, installable, and signable** without PPL/ELAM (which require a
Microsoft AV-vendor agreement and are explicitly **out of scope** — see below). Self-protection is
achieved with a hardened service security descriptor, restart-on-kill recovery, and ACL-locked on-disk
state.

> ⚠️ These scripts make **real, machine-wide changes** (a Windows service, service ACLs, a locked data
> directory, a machine environment variable). Run them **only** on the target machine or inside the
> Win11 Hyper-V test VM, elevated — never casually on a dev box.

## Build

```powershell
dotnet publish src\Warden.Service\Warden.Service.csproj -c Release -o out\service
dotnet publish src\Warden.Ui\Warden.Ui.csproj           -c Release -o out\ui
```

## Sign (release step; requires a code-signing certificate)

Warden's managed binaries are **not** signed by the build — no certificate is committed. Sign the
published output before installing/distributing:

```powershell
.\installer\sign.ps1 -Path out\service -Thumbprint <your-cert-thumbprint>
.\installer\sign.ps1 -Path out\ui      -Thumbprint <your-cert-thumbprint>
```

A self-signed certificate is fine for personal test use; distribution needs an OV/EV cert.

## Install (elevated, on the target / VM)

```powershell
.\installer\install.ps1 -BinDir out\service -UiExe out\ui\Warden.Ui.exe
```

This:

1. Creates `%ProgramData%\Warden` locked to **SYSTEM + Administrators** only (`icacls /inheritance:r`).
2. Registers the **WardenAgent** service as `LocalSystem`, auto-start, launched via the trusted `dotnet`
   host (`binPath = "dotnet" "…\Warden.Service.dll"`).
3. Applies the hardened **service SDDL** (`sc sdset`) — standard users may query the service but cannot
   **stop, change, or delete** it. Mirrors `Warden.Hardening.HardeningSddl.ServiceDacl`.
4. Configures **restart-on-kill** recovery (`sc failure … actions= restart/…`, `sc failureflag 1`).
5. Sets `WARDEN_ENFORCE_HARDENING=1` (machine) so the service re-applies the data-dir/DB ACL on every
   start (maintains lockdown even if it drifts).
6. Optionally registers the tray UI to launch at logon (a scheduled task; the UI runs in the user
   session, not session 0).

Verify:

```powershell
sc.exe qc WardenAgent          # config, start type, binPath
sc.exe sdshow WardenAgent      # the applied security descriptor
sc.exe qfailure WardenAgent    # recovery actions
```

## Uninstall

```powershell
.\installer\uninstall.ps1              # stop + delete service, remove flag + UI task
.\installer\uninstall.ps1 -RemoveData  # also take ownership of and remove %ProgramData%\Warden
```

## What self-protection does (and does not) cover

| Threat | Mitigation |
|---|---|
| Standard user stops/deletes the service | Hardened service SDDL (only SYSTEM/Admins can stop/delete) |
| Service is killed / crashes | SCM restart-on-kill recovery (`sc failure` + `failureflag`) |
| Standard user reads/edits the database or quarantine | Data directory + DB locked to SYSTEM + Administrators |
| Tampering leaves no trace | Every failed lockdown / recovery event is written to `tamper_log` and the Serilog file |

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
