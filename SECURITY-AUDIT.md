# Warden security audit

- **Repo:** `xavierfrichard/ML-Driven_Local_Windows_EDR` @ `e0737e2`
- **Date:** 2026-10-30
- **Method:** read-only code review. Nothing was built or run.
- **Threat model:** standard-user (or medium-integrity) malware on the same machine. Its goals are to get its own binary allowed, to tamper with or disable Warden, to escalate to SYSTEM through the service, or to stall enforcement.

Confidence labels:
- **Confirmed:** traced end to end in the code.
- **Plausible:** the code path is confirmed, but exploiting it depends on Windows behaviour that wasn't tested here.

## Fix status (2026-10-30)

H1 and H2 are fixed in the working tree. The fix is not committed yet. All changes are on the service side: the service enforces them for every rule, including rules already stored, whatever the UI sends.

**H1: Signature rules** (`RulesEngine.SignatureAllowMatches`)
- A Signature **allow** now matches only a signature that verified (`IsTrustedSignature`), and only by the exact Common Name or the leaf certificate's thumbprint. The `RequireSignature` checkbox no longer matters for these rules.
- Signature **block** rules still match loosely. A wider block only blocks more, so this is safe.
- New allow rules are stored trimmed and with `RequireSignature = true`. A pasted subject DN (`CN=…`) is rejected with a message.
- When the rule comes with a picked file:
  - The service copies the file to a SYSTEM-only snapshot and verifies the signature and publisher on that copy.
  - It then pins the copy's SHA-256 for the WDAC step, so the bytes allow-listed are the bytes verified.
  - An unsigned, self-signed or mismatched file is not allow-listed.

**H2: Folder rules** (`RulesEngine.IsUnderFolder`, new `Warden.Hardening.FolderWriteAccess`)
- Folder rules now match on a directory boundary, including rules stored before the fix. `C:\Tools` no longer covers `C:\ToolsX`.
- New folder rules are stored canonical, with a trailing `\`.
- A Folder **allow** is refused unless the folder exists and all of these hold:
  - the folder and everything under it (up to 5,000 entries) are owned by SYSTEM, Administrators or TrustedInstaller, and only those accounts can write to them;
  - no entry is a link or junction;
  - no parent folder lets anyone else delete, rename or re-permission it.
- The refusal message names the offending path and account.
- The "allow folder now" bulk step also has a 2 GB total-size cap.

**Tests:** 36 new tests (19 in `RulesEngineTests`, 17 in `FolderWriteAccessTests`), all passing.
- Run against the old matching code, 8 of the new rule tests fail. They pass with the fix.
- The handler-level paths (`ValidateRule`, `VerifySignedSource`) still have no tests, because `MgmtRequestHandler` has no test harness.

**Not done**
- **UI hints:** the UI was being edited in parallel (an MVVM migration), so it was left alone. Its "Require a valid signature" checkbox and hint text should be updated to say signature allows always require one.
- **M2 for other paths:** "Allow file…" and the Hash-rule picker still allow-list whatever bytes are on disk at copy time.

## Summary

The core design is sound:
- WDAC blocks by default.
- The decision pipeline fails closed (first decisive answer wins).
- Process launches and named pipes are hardened.
- The automated tiers (VirusTotal, ML, LLM) cannot produce an Allow in the default configuration.

The 8c47763 remediation holds up for what it targeted.

The weak spots are the paths a human creates:
- **Signature** and **Folder** allow rules match far more loosely than the UI suggests. Commits f49b993 and e0737e2 made both easier to create and added "allow now" shortcuts.
- **File-system races and ownership** around SYSTEM operations: quarantine, the data directory, and the WDAC work files.

| # | Severity | Finding | Confidence |
|---|---|---|---|
| H1 | High | A Signature allow rule matches forged or self-signed certificates by substring (**fixed, uncommitted**) | Confirmed |
| H2 | High | A Folder allow rule is a raw prefix match and accepts user-writable folders (**fixed, uncommitted**) | Confirmed |
| H3 | High | Quarantine follows junctions, giving an arbitrary file move as SYSTEM | Confirmed (code) / Plausible (race) |
| H4 | High | A pre-created data directory keeps the attacker as owner, so they can edit the DB, WDAC XML and ML model | Plausible |
| H5 | High (if enabled) | The Claude CLI path runs as SYSTEM with no check on who can write it | Confirmed (code) |
| M1 | Medium | WDAC changes are saved before deploy, so failed allows go live later; Revoke can report success while the allow stays | Confirmed / Plausible |
| M2 | Medium | "Allow file…" and the rule picker allow-list whatever bytes are on disk when the copy happens | Confirmed |
| M3 | Medium | The UI accepts a squatted pipe owned by the same user | Confirmed (code) / Plausible (window) |
| M4 | Medium | API keys are stored in machine environment variables that every user can read | Confirmed |
| M5 | Medium | The ML model's hash pin cannot be configured | Confirmed |
| M6 | Medium | Unbounded reads and parsing on the single decision thread can exhaust memory or stall the service | Confirmed / Plausible |
| M7 | Medium | When the snapshot fails, the bytes judged are not the bytes allow-listed | Plausible |
| M8 | Medium | The installer trusts environment-variable roots and doesn't verify binaries; the elevated logon task can be hijacked through env vars | Plausible |
| M9 | Medium | Uninstall's recursive take-ownership and delete can be redirected by a junction | Plausible (chained with H4) |
| M10 | Medium | The lab script deploys policy from a user-writable folder and shares the service's PolicyID | Confirmed |
| L* | Low | See the Low and Info section | |

---

## High

### H1. A Signature allow rule matches forged or self-signed certificates by substring

**Where**
- `src/Warden.Rules/RulesEngine.cs:128-130`:
  ```csharp
  context.Signer?.SubjectName is { } subject && subject.Contains(value, StringComparison.OrdinalIgnoreCase)
  ```
- `src/Warden.Trust/FileInspector.cs:135-138` fills in `SubjectName = leaf.Subject` even when `IsValid == false`.
- `RequireSignature` is the only check on validity (`RulesEngine.cs:152`), and its checkbox is off by default (`src/Warden.Ui/AddRuleWindow.xaml:24`).
- Since e0737e2, Browse… fills in the CN with `X509Certificate.CreateFromSignedFile`, which does not verify the signature.
- `MgmtRequestHandler.cs:229-236` allow-lists the picked file outright (`expected = null` for Signature rules), without checking its signature.

**Exploit:** an admin adds `Signature "Google LLC" → Allow`. Malware self-signs with `CN=Google LLC`, or `O=Not Google LLC Ltd`, or grafts on a copied certificate, then launches:
- The rules tier returns Allow.
- `ApplyAllowAsync` deploys a permanent WDAC hash allow.
- Because Rules runs before Whitelist and is recorded as authoritative, this also overrides an earlier human Block of that hash.

Even with RequireSignature on, any public-CA certificate whose DN merely *contains* the string still matches.

**Fix**
- Always require `IsTrustedSignature` for Signature rules.
- Match the CN exactly, and pin the leaf or issuer thumbprint captured by the picker.
- Verify with WinVerifyTrust in the picker.
- Hash-pin the picked file before allowing it.

### H2. A Folder allow rule is a raw prefix match and accepts user-writable folders

**Where**
- `RulesEngine.cs:132-134`: `context.ImagePath.StartsWith(value, OrdinalIgnoreCase)`, with no directory boundary.
- `MgmtRequestHandler.cs:186-188` validates the path but stores the raw value, which has no trailing `\`.
- `IsAcceptableLocalPath` only rejects drive roots.
- f49b993's `AllowFolderNowAsync` (`MgmtRequestHandler.cs:283-337`) also hash-allows up to 500 PE files currently under the folder, recursively, with no hash pin. It does this while holding the WDAC lock.

**Exploit**
- An allow on `C:\Tools` also matches `C:\Tools2\evil.exe`, and Authenticated Users can create folders at `C:\` by default.
- An allow on `C:\Users\bob\App` also matches `C:\Users\bob\AppData\...`.
- Allows on Downloads or `%LOCALAPPDATA%\...` are accepted, so every future drop into those folders is auto-allowed.
- Anything malware has already planted in the folder is allowed the moment the admin clicks.

**Fix**
- Canonicalize the path, store it with a trailing separator, and match on a directory boundary. `AuthenticodeTrustGate.StartsWithDirectory` already does this.
- Refuse Folder→Allow when non-admins can write to the folder or any ancestor.
- Before a bulk allow, show the admin the list of files and hashes to confirm, and put a total-bytes budget on it.

### H3. Quarantine follows junctions, giving an arbitrary file move as SYSTEM

**Where:** `EnforcementController.cs:289-291` passes `ctx.ImagePath` to `QuarantineStore.cs:40-53`. That code checks `File.Exists`, hashes the file, then calls `File.Move(filePath, dest)` and locks the file's DACL. Along the way:
- No path component is checked for reparse points.
- The bytes are never compared with `ctx.Sha256`.

**Exploit:**
1. Malware at `C:\Users\me\d\x.exe` is blocked, and the user is prompted.
2. The user clicks **Quarantine**, which looks like the safe answer.
3. During the prompt window (about 20 s), the attacker swaps `d` for a mount-point junction pointing into a privileged directory.
4. SYSTEM moves the victim file there into quarantine and locks it down.

The result is an arbitrary file move or delete as SYSTEM. That is enough to tamper with Warden's or WDAC's own files, and it is a known route to privilege escalation.

**Fix:**
- Open the file with `FILE_FLAG_OPEN_REPARSE_POINT`.
- Verify that `GetFinalPathNameByHandle` returns the blocked path and that the hash equals `ctx.Sha256`.
- Rename through that same handle.
- Refuse if any ancestor is a reparse point.

`RestoreAsync` (`:182-223`) has the same class of bug. It isn't wired to IPC yet, so fix it before exposing it.

### H4. A pre-created data directory keeps the attacker as owner

**Where:** `installer/install.ps1:94-105,169` (`Lock-Directory`) and `src/Warden.Hardening/DataDirectoryHardener.cs:24-38`.

**What happens:** by default, standard users can create folders under `C:\ProgramData`. The installer never checks whether `%ProgramData%\Warden` already exists, is a junction, or who owns it.
- `icacls /inheritance:r /grant:r` keeps any other explicit entries in the directory's access list and never resets the owner. It is also not recursive.
- The startup re-hardening replaces the access list (`AccessControlSections.Access` only) but also leaves the owner alone.

**Exploit:**
1. Before install, malware creates `C:\ProgramData\Warden`, plus `ml\`, `wdac\` and so on.
2. After install it is still the owner, which gives it WRITE_DAC. It grants itself write access again.
3. With write access it can:
   - edit `warden.db` and insert whitelist or rule Allow rows
   - plant `wdac\WardenAllowlist.Supplemental.xml`, which is merged and deployed as-is (`WdacAllowlistManager.cs:397-403`, with no PolicyID or rule-type check)
   - replace `ml\model.onnx`

A junction variant redirects SYSTEM's ACL changes and file writes to a target the attacker chooses.

**Made worse by:** new machine environment variables don't reach services.exe until a reboot (`install.ps1:194-197` sets them, then `sc start` runs at `:214`). So on the first run after install, `WARDEN_ENFORCE_HARDENING` and a custom `WARDEN_DATA_DIR` are ignored.

**Fix**
- At install, refuse a pre-existing directory that is a reparse point or has a foreign owner. Otherwise run `takeown` plus `icacls /setowner *S-1-5-32-544 /reset /T`.
- At start, use `AccessControlSections.Owner | Access`, recurse, and check for reparse points.
- Before every compile, check that the supplemental policy has the fixed PolicyID, is of Supplemental type, and holds only hash Allow rules.
- Put the service's settings in its own `HKLM\SYSTEM\CurrentControlSet\Services\WardenAgent\Environment` value.

### H5. The Claude CLI path runs as SYSTEM with no check on who can write it (only when enabled)

**Where:** `ClaudeCliProvider.cs:51-55`. The only checks are `Path.IsPathRooted` and "doesn't start with `\\`". Problems with that:
- It accepts `C:claude.exe`, `\claude.exe` and `//host/share/...`.
- It never checks who owns or can write the file or its folders.

**Exploit:** the documented setup points `WARDEN_CLAUDE_CLI_PATH` at `claude`, which normally lives somewhere the user can write:
- `%USERPROFILE%\.local\bin\claude.exe`
- `%APPDATA%\npm\claude.cmd`, which runs `cli.js`

Malware edits the file, then launches any blocked binary, and the LLM tier runs the attacker's code as LocalSystem.

**Fix**
- Use `Path.IsPathFullyQualified`.
- Require the file and every parent folder to be owned by, and writable only by, SYSTEM or Administrators.
- Refuse `.cmd` and `.bat` paths.

**Side note:** `--bare` combined with the env scrub probably leaves the CLI unable to log in under the service anyway, but that is luck, not a control.

---

## Medium

### M1. WDAC changes are saved before deploy, and Revoke can report success while the allow stays

- **Failed allows go live later.** `WdacAllowlistManager.cs:189-192` saves the merged XML and the ledger *before* `CompileAndDeployAsync`, and nothing is rolled back on failure. The backups are written but never restored.
  - A "failed" allow, for which no whitelist row is recorded, goes live at the next successful deploy.
  - It is then invisible in the UI and cannot be revoked from it.
- **Revoke reports success regardless.** In `:262-276`, Revoke deploys and returns `revoked:` even when `RemoveAllowRules` removed 0 rules.
  - The ledger stores ConfigCI rule *IDs*, and the policy is rebuilt with `Merge-CIPolicy` on every allow. If merging renumbers IDs (plausible), the recorded IDs go stale.
  - "Set Block" then tells the admin that the WDAC allow was removed while it stays active.
- **Fix**
  - Build in a temp file, and promote the XML and ledger only after CiTool succeeds; restore from backup on failure.
  - Revoke by the `Hash=` values instead of IDs, and fail when the ledger had entries but `removed == 0`.

### M2. "Allow file…" and the rule picker allow-list whatever bytes are on disk when the copy happens

- `MainWindow.xaml.cs:324-341` sends only a path, and `MgmtRequestHandler.cs:407` calls `new WdacAllowFile(canonical, null)` with no hash pin. The Signature-rule `SourcePath` path behaves the same way (see H1).
- **Exploit:** same-user malware swaps the file's bytes between the admin picking it and the service copying it, using an oplock to time the swap. The malware's bytes get the WDAC allow and an "Admin" whitelist row.
- **Fix:** have the UI hash the file, show the hash and signer, and send them as `ExpectedSha256`. Warn on files in user-writable folders.

### M3. The UI accepts a squatted pipe owned by the same user

- `PipeGuard.cs:257-258` accepts a pipe whose owner equals the current user. This "dev run" exception is active in production.
- Standard or medium-integrity malware in the admin's session has the same user SID, so it can grab both pipe names whenever they are free:
  - while the service is down (recovery waits 60 s before restarting it)
  - after a prompt-pipe error (`PromptPipeServer.cs:216-239` drops its only instance for 1 s)
  - mgmt pipe instances after the first are created without `FirstPipeInstance` (`MgmtPipeServer.cs:184-186`)
- **Impact once squatted:**
  - Real prompts are lost; they time out, so the block still holds.
  - The attacker can show fake prompts and fake management data.
  - Admin "Set Block" or revoke requests are silently swallowed.
  - The service's retry loop writes a tamper-log row every second.
- **Fix**
  - Require the pipe owner to be SYSTEM.
  - Compare `GetNamedPipeServerProcessId` with the WardenAgent service PID.
  - Always keep one listening instance.
  - Rate-limit the tamper events.

### M4. API keys are stored in machine environment variables that every user can read

- `Program.cs:68,81` read `WARDEN_VT_API_KEY` and `WARDEN_ANTHROPIC_API_KEY` from machine environment variables.
- Those live in `HKLM\...\Session Manager\Environment`, which every user can read, and they are inherited by every process.
- **Fix:** store the keys with DPAPI LocalMachine protection under the locked data directory, or in the service's own registry `Environment` value.

### M5. The ML model's hash pin cannot be configured

- `AddWardenMl()` is called with no configuration (`Program.cs:74`), so `ModelSha256` is always null and any `model.onnx` gets loaded.
- Combined with H4:
  - a planted model can Block any app (DoS)
  - if `AllowOnLowScore` is ever turned on, it can Allow anything
- **Fix:** read the pin from protected configuration and require it whenever a model is present.

### M6. Unbounded reads and parsing on the single decision thread

All blocks are decided one at a time on a single thread, and the pipeline has no per-tier timeout. These code paths can exhaust memory or stall that thread:

- **WebApps import scan (confirmed).** `WebAppCollectors.cs:48` calls `File.ReadAllBytes(appPath)` on the *original* image with no size cap, and it runs for every block. A 2 GB padded executable causes about 2 GB of allocation per launch.
- **Mark-of-the-Web read (confirmed).** `FileInspector.cs:157-181` calls `ReadLine()` on the attacker's `Zone.Identifier` alternate data stream with no limit. A multi-GB stream with no newline causes an OutOfMemoryException.
- **In-place hashing (plausible).** When the snapshot is skipped (file over 256 MB, or a reparse point), hashing and WinVerifyTrust run on the live file with no cap.
- **PeNet parsing (plausible).** PeNet 4.1.3 parses hostile PEs synchronously with no timeout. A recursive resource tree could cause a StackOverflowException, which can't be caught, so the service would crash on every launch of that file.

**Fix**
- Cap every read, and read through one file handle.
- Use the snapshot everywhere.
- Add per-tier timeouts.
- Run PE parsing in a separate worker process with time and memory limits.

### M7. When the snapshot fails, the bytes judged are not the bytes allow-listed

- If `TrySnapshot` returns null (`EnforcementController.cs:346-353, 391-421`), the hash, signer check and lazily-read PE features each reopen the mutable original file.
- WDAC (`WdacAllowlistManager.cs:110-131`) only checks the hash, not that the bytes match what the ML or LLM tiers looked at.
- The attacker could therefore show benign bytes to the scorers and malicious bytes to the hash. This matters only if an auto-allow tier is enabled.
- **Fix:** with no snapshot, mark the context as Prompt-only.

### M8. Installer and logon-task trust (plausible)

- **Environment-variable roots.** `install.ps1:54-59,127-131` derive the trust roots, including the pinned `dotnet.exe`, from `$env:ProgramFiles` and `$env:ProgramData`, which a user's `HKCU\Environment` can override in an elevated session.
- **No binary verification.** `BinDir` is mirrored into Program Files without any signature or hash check.
- **Logon-task hijack.** The `WardenUi` task runs at Highest with the user's environment. Setting `DOTNET_STARTUP_HOOKS`, `DOTNET_ROOT` or `CORECLR_PROFILER_PATH` there gives elevated code execution and the UI's admin authority on the management pipe.
- **Fix**
  - Resolve the roots from HKLM or `GetFolderPath`.
  - Verify the owner and access list of `dotnet.exe`.
  - Verify signatures or a hash manifest before and after copying.
  - Publish the UI self-contained with `StartupHookSupport=false`.

### M9. Uninstall can be redirected by a junction (chained with H4)

- `uninstall.ps1:55-70` checks only the top-level folder for a reparse point, and does so before the confirmation prompt.
- `takeown /R`, `icacls /reset /T` and `Remove-Item -Recurse` can follow junctions planted inside the tree. That makes them a recursive take-ownership, ACL reset or delete of an arbitrary target.
- **Fix:** re-check right before acting, and refuse if any reparse point exists in the tree.

### M10. The lab script deploys from a user-writable folder

- `scripts/Deploy-WardenSpikePolicy.ps1` defaults its work folder to `%USERPROFILE%\WardenSpikeLab\policy`. It reuses whatever `WardenBase.xml` is already there and compiles the policy in that folder before deploying it.
- Any same-user process can tamper with the base policy before the next elevated run.
- The spike supplemental also shares the PolicyID `{7A4D1C0A-…-000000000001}` with the service's supplemental, so each one overwrites the other.
- **Fix:** use an admin-only work folder, and give the spike supplemental its own GUID.

---

## Low and Info

### Low

- **Extension allow rules.** `.exe → Allow` is accepted by `ValidateRule` and is effectively a global allow. Refuse Extension allows, or limit them to block rules.
- **Prompt display spoofing.** The prompt shows attacker text raw (`PromptWindow.xaml.cs:51-58`), so bidi characters (U+202E) and padding can disguise the file. Strip bidi and control characters, and show the canonical path and hash.
- **Pipe peer check is name-only.** The peer image check compares only the file name (`PipeGuard.cs:279-287`), so a renamed binary passes. The pipe's access list still limits callers to admins.
- **Flooding and prompt fatigue.** The block queue holds 512 entries and drops the oldest when full, and an unanswered prompt isn't persisted. Flooding distinct binaries pushes out real blocks (this fails closed), and repeated prompts wear the user down. Coalesce by hash and rate-limit prompts.
- **VirusTotal.** "Suspicious" votes are ignored when deciding "clean". A 404 is cached for 24 h. The 480-requests-per-day quota can be burned with fresh hashes.
- **Local LLM endpoint.** The default `http://localhost:11434` can be taken over by any local user when Ollama isn't running. This only matters if `EnableLocal` is on.
- **Prompt injection.** If `AllowOnBenign` is turned on, a confident "benign" answer from the LLM alone can Allow. Attacker-controlled strings, file name, signer and command line all reach the model, and a local 8B model's tool call counts the same as Anthropic's. Never let the LLM Allow without corroboration.
- **Log sanitizer gaps.** The sanitizer misses nested values, exception text, U+2028/2029 and bidi characters. Tamper rows in the DB are not sanitized.
- **Log file can be silenced.** The Serilog file has a 1 GB daily cap without `rollOnFileSizeLimit`, so flooding it silences the file log for the rest of the day.
- **Installer error checks.** The results of `sc sdset`, `failure` and `failureflag` are never checked.
- **Startup self-check is weak.** It checks only the service folder's access list. It ignores parent folders, the `dotnet` folder, the owner and arbitrary user SIDs, and it only logs.
- **Supply chain.**
  - No `packages.lock.json` and no NuGet source mapping.
  - `ml-training/requirements.txt` uses unpinned `>=` versions.
  - Third-party DLLs are not signed or verified.
  - `Microsoft.Data.Sqlite 8.0.10` bundles an older SQLite; bumping `SQLitePCLRaw.bundle_e_sqlite3` is advisable (low impact).
- **Quote escaping.** `PowerShellRunner.PsQuote` and `WdacAllowlistManager.Ps` don't escape Unicode single quotes (U+2018 to U+201B). Not exploitable today, because every interpolated value is validated ASCII.
- **AMSI DLL search order.** `[DllImport("amsi.dll")]` has no `DefaultDllImportSearchPaths(System32)`. This is safe only while the install folder stays locked.

### Info

- `CLAUDE.md` says the UI reads `warden.db` directly. It no longer does; everything goes through the management pipe.
- Uninstall leaves the WDAC supplemental policy and the firewall, IFEO and ASR changes in place.
- The `AsrRuleManager`, `ProcessMitigationManager` and `IfeoWriter` modules can't be reached from the management pipe.
- `tools/Warden.Spike` prints attacker strings raw to an elevated console and uses substring "IsMicrosoft" checks. It is display-only and must not be reused for decisions.
- `.gitignore` is missing `*.snk`, `*.p12`, `*.pem`, `*.key`, `*.pvk` and `*.db`.
- **Secrets sweep:** none found in the git history. The only hits are test placeholders.

---

## What holds up

- **Pipeline:** first decisive answer wins and fails closed. A tier that throws is skipped, the fallback is Prompt, and an unanswered prompt keeps the block.
- **Default configuration:** VirusTotal, ML and LLM cannot Allow (`AllowKnownClean`, `AllowOnLowScore` and `AllowOnBenign` default to false and have no env switch).
- **Trust gate:** requires WinVerifyTrust, identifies Microsoft by pinned roots, matches publishers exactly, checks paths on directory boundaries, checks the owner, and leaves catalog-only files undecided.
- **WDAC:** generates hash rules only. It requires the judged hash, re-hashes the copy, refuses reparse points, caps file size, edits XML with XDocument, and serializes all changes.
- **Process launches:** use absolute System32 paths, `-EncodedCommand` and `ArgumentList`, and never interpolate file names, publishers or process names into scripts.
- **Pipes:** the access list admits only SYSTEM and Administrators. The admin check runs after the first read under impersonation, authorization is default-deny, frames are capped at 1 MiB, payloads are typed JSON, and clients connect at Identification level.
- **SQL:** fully parameterized through Dapper.
- **LLM:** forced tool-call verdict, capped dossier, constant system prompt, no raw bytes sent, and the CLI gets its input on stdin with `--tools ""`.
- **HTTP:** certificate validation is never disabled, and responses are capped.
- **Installer:** copies to Program Files and locks it. The binPath is quoted with a pinned `dotnet.exe`. The service access list denies stop and config changes to users. Recovery restarts the service on kill.

## Suggested fix order

1. **H1 and H2.** Tighten Signature and Folder matching, and hash-pin every "allow now" path (M2). These are the easiest ways for malware to get permanently allowed.
2. **H4.** Make the installer and startup take ownership of the data directory recursively and refuse reparse points. Validate the supplemental XML before deploying it.
3. **H3.** Quarantine through a verified handle.
4. **M1.** Make WDAC changes transactional, and make Revoke fail when it removes nothing.
5. **M3.** Pin the pipe server to SYSTEM and the service PID.
6. **H5, M4, M5.** Check who can write the CLI path, move the API keys out of environment variables, and make the model hash pin configurable and required.
7. **M6.** Cap all reads, add per-tier timeouts, and isolate PE parsing in a worker process.
8. **Tests to add:** `MgmtRequestHandler`, `EnforcementController`, Signature and Folder edge cases, quarantine through a junction, and pipe squatting. None of these currently have tests.
