# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

Warden is a **CyberLock-class, zero-trust Windows EDR**: WDAC (Windows Defender Application Control) blocks every launch by default at the OS layer ("the floor"), and a chain of increasingly expensive **verdict tiers** decides whether a blocked launch should be allowed, blocked, quarantined, or escalated to the user. It ships as a .NET 8 **Windows Service** (`Warden.Service`) plus a **WPF tray UI** (`Warden.Ui`) that communicate over a named pipe. Development happened in Phases 0–6; the phase numbers are annotated in `src/Warden.Service/Program.cs` and appear in file names (`Phase2Entities.cs`, etc.).

**Windows-only.** Most projects target `net8.0-windows` (WPF, ETW, WDAC, service, COM). `dotnet build`/`test` will not work for those on Linux/macOS.

## Build, test, run

Requires the **.NET SDK 8.0.4xx** (pinned to `8.0.422`, `rollForward: latestFeature` in `global.json`) on Windows.

```powershell
# Build
dotnet build Warden.sln -c Release        # or -c Debug (only Debug/Release | Any CPU exist)

# Test (xUnit)
dotnet test                                            # whole solution
dotnet test tests\Warden.Tests\Warden.Tests.csproj     # one project
dotnet test --filter "FullyQualifiedName~DecisionPipelineTests"   # one class
dotnet test --filter "DisplayName~First_decisive_source_wins"     # one test
```

Two test projects: `tests\Warden.Tests` (net8.0 — pipeline, storage, ML, LLM, reputation) and `tests\Warden.Tests.Windows` (net8.0-windows — ETW, quarantine, hardening ACLs, Phase 5/6).

**Run the agent / UI / spike (dev):**

```powershell
dotnet run --project src\Warden.Service\Warden.Service.csproj   # the EDR agent (console in dev, Windows Service in prod)
dotnet run --project src\Warden.Ui\Warden.Ui.csproj            # WPF tray + management window
dotnet run --project tools\Warden.Spike\Warden.Spike.csproj -- --selftest   # Phase 0 smoke test (non-admin)
dotnet run --project tools\Warden.Spike\Warden.Spike.csproj -- --watch       # live ETW/WDAC correlation (REQUIRES ADMIN, VM only)
```

**Runtime environment variables** (behavior is configured in code + env vars, *not* `appsettings.json`, which only holds log levels):
- `WARDEN_ENFORCE_HARDENING=1` — re-applies the data-dir/DB ACL lockdown on startup. The **installer** sets this (Machine scope); a plain dev run must **not** set it, or it will re-ACL `%ProgramData%\Warden`.
- `WARDEN_ANTHROPIC_API_KEY` — enables the LLM analyst tier (otherwise that tier stays silent).
- The ML tier stays dormant until an ONNX model exists at `%ProgramData%\Warden\ml\model.onnx`.

**Install as a service** (Phase 6, elevated): publish then run the installer — see `installer\README.md`.

```powershell
dotnet publish src\Warden.Service\Warden.Service.csproj -c Release -o out\service
dotnet publish src\Warden.Ui\Warden.Ui.csproj           -c Release -o out\ui
.\installer\install.ps1 -BinDir out\service -UiExe out\ui\Warden.Ui.exe
```

`install.ps1` creates an ACL-locked `%ProgramData%\Warden`, registers the `WardenAgent` service as LocalSystem, applies a hardened service SDDL (`sc sdset`), sets restart-on-kill recovery, and sets `WARDEN_ENFORCE_HARDENING=1`. `uninstall.ps1` reverses it; `sign.ps1` Authenticode-signs binaries (the build does **not** sign them).

## Architecture

### The spine: WDAC floor + first-decisive-wins pipeline

WDAC enforces default-deny *before* Warden runs. A base policy (`policy/WardenSpike.Supplemental.xml`, deployed by `scripts/Deploy-WardenSpikePolicy.ps1` in a test VM) blocks any launch that isn't already allowed; each block surfaces as a CodeIntegrity ETW event. **The pipeline only ever decides whether to _lift_ a block** — this is why `Verdict`/`VerdictContext` doc-comments say "the OS has already blocked the launch."

Everything hinges on `src/Warden.Core/` (the domain vocabulary + engine; no dependencies on other Warden projects):
- `IVerdictSource` — one tier: `VerdictSourceKind Kind` + `EvaluateAsync(VerdictContext, ct)`. A tier with no opinion returns `VerdictResult.Undecided`.
- `Verdict` enum — `Unknown` (defer), `Allow`, `Block`, `Quarantine`, `Prompt`.
- `DecisionPipeline` — holds tiers ordered by `(int)Kind` and returns the **first decisive** result. A tier that throws is caught, logged, and skipped. If all decline, it returns `VerdictResult.PromptFallthrough`.

There is **no score fusion** — cheap/deterministic gates run first, expensive probabilistic tiers last, first decisive wins. **Registration order in `Program.cs` _is_ the policy.**

| Kind | Class | Project | Behavior |
|---|---|---|---|
| 0 Rules | `RulesEngine` | Warden.Rules | User allow/block rules, **deny-wins** |
| 1 TrustGate | `AuthenticodeTrustGate` | Warden.Trust | Fast-allow trusted-signed/trusted-path; **never blocks** |
| 2 Whitelist | `WhitelistVerdictSource` | Warden.Rules | Replay a prior recorded decision for this SHA-256 |
| 3 VirusTotal | `VirusTotalClient` | Warden.Reputation | Cached hash reputation; decisive only at extremes |
| 4 Ml | `OnnxScorer` | Warden.Ml | EMBER→ONNX score; block high / allow low; mid-band defers |
| 5 Llm | `LlmVerdictSource` | Warden.Llm | LLM analyst on a structured dossier |
| 6 UserPrompt / 7 Fallthrough | — | — | Keep blocked + ask the user |

**The load-bearing invariant: fail-safe, never a silent allow.** Any tier that errors or abstains falls through toward `Verdict.Prompt`, whose terminal state keeps the launch blocked and asks the user. Tests assert "a broken final source never produces a silent allow."

### Runtime flow — `src/Warden.Service/EnforcementController.cs` (read this first for behavior)

1. `Warden.Etw.KernelProcessSession` fires on process starts → buffered in a ring buffer (also feeds `ProcessTreeBuilder`).
2. `Warden.Etw.CodeIntegritySession` fires on WDAC block events (3076 audit / 3077 enforce) → written to a `Channel<CiBlockEvent>`.
3. `RunAsync` drains the channel **single-threaded** so prompts never interleave and WDAC is never regenerated concurrently.
4. `BuildContext` correlates the block with a recent process start (5s window, by image path) into an immutable `VerdictContext`.
5. `_pipeline.EvaluateAsync(ctx)` → switch on the verdict: `Allow` → `IWdacAllowlistManager.AllowAsync` (so it runs on relaunch) + record; `Quarantine` → `IQuarantineStore`; `Prompt` → `IPromptPresenter` (non-modal, 20s auto-dismiss defaulting to keep-blocked, over the named pipe).
6. Every block also runs `WebAppClassifier.ClassifyAsync` best-effort (read-only, cannot change the outcome).

`WardenWorker` (`BackgroundService`) is the host loop wrapper: DB init, optional startup hardening, seeds vulnerable-apps, subscribes ETW → controller, degrades gracefully if not elevated.

### The WDAC allow path — `Warden.Wdac`

`WdacAllowlistManager.AllowAsync` maintains a single **supplemental** policy (fixed PolicyID) linked to the active base: `New-CIPolicy -Level Hash` (or publisher rule), `Merge-CIPolicy`, `ConvertFrom-CIPolicy` to `.cip`, deploy via `CiTool --update-policy` — **no reboot**. Safety invariants: refuses an unset/all-zeros `BasePolicyID`, always keeps a backup, never touches the base policy's audit/enforce state.

### ML tier — `Warden.Ml`

`Microsoft.ML.OnnxRuntime` + `PeNet`. Approach: **EMBER v2** feature vector scored by a LightGBM model exported to **ONNX**. Training is a *separate* Python pipeline in `ml-training/` (`train.py`, `ember_features.py`); the C# `EmberFeatureExtractor` must stay byte-parity with it (parity fixtures under `tests\Warden.Tests\parity\`). `OnnxScorer` is `Undecided` until a model file exists, so the pipeline ships unchanged without one.

### LLM analyst tier — `Warden.Llm` (most defensively designed; input derives from a possibly-malicious file)

- `IVerdictLlmProvider` — `Name`, `Priority` (lower tried first), `IsEnabled`, `AnalyzeAsync(Dossier, ...)`. Returns **null on any failure** so it can never become a silent allow. Providers: `AnthropicApiProvider` (0), `LocalLlmProvider` (10), `ClaudeCodeOAuthProvider` (20, off by default). First enabled provider returning non-null wins.
- **Forced-JSON verdict:** `LlmAnalystPrompt` defines a single `submit_verdict` tool with a strict schema and sets `tool_choice` to force it. Enforcement reads *only* the tool-call input, never free-form prose. A benign label scraped from prose (`FromToolCall=false`) can never auto-allow.
- `Dossier`/`DossierBuilder` build a typed, **capped** summary (hashes, signer facts, MOTW, PE structure, suspicious imports, bounded strings) — raw bytes are never sent. See `src/Warden.Llm/README.md`.

### Advanced + Web Apps engines (Phase 5) — NOT pipeline tiers

Registered but apply **nothing** on startup; they are panel-driven side capabilities.
- `Warden.AntiExploit` — `AsrRuleManager` (Attack Surface Reduction), `ExploitProtection`/`ProcessMitigationManager` (per-app DEP/ASLR/CFG/CET…), `IfeoWriter`, `VulnerableApps` (LOLBAS/EP-reset seed). Appliers make real machine-wide changes only when invoked from the UI.
- `Warden.Firewall` — `FirewallRuleManager`: per-app block rules via the Windows Firewall COM API.
- `Warden.WebApps` — always-on, read-only classifier that recognizes modern JS/WebView apps (Electron/WebView2/CEF/Tauri) by *engine*, not by browser name. Runs on every block, out of band.

### Storage — `Warden.Storage`

SQLite via **`Microsoft.Data.Sqlite` + Dapper** (no EF Core, no migration framework). DB at `%ProgramData%\Warden\warden.db` (WAL). **The entire schema is one inline `const string Schema` in `WardenDb.cs` (`CREATE TABLE IF NOT EXISTS ...`) — edit DDL there.** Column names match entity property names so Dapper maps with no config; `DapperConfig.cs` adds one `DateTimeOffset` ↔ ISO-8601 handler. Entities and repositories are **split by phase**: `Entities.cs`, `Phase2Entities.cs`, `Phase5Entities.cs`, `Phase6Entities.cs`, and matching `*Repositories.cs` / `*Repositories.Impl.cs`. `AddWardenStorage()` registers all repos as singletons.

### UI — `Warden.Ui` (WPF tray, no MVVM)

Tray app (`Hardcodet.NotifyIcon.Wpf`) in the interactive session. `MainWindow` is a `TabControl` with 9 management panels (Advanced, Web Apps, Attack Chains, Protected Folders, Whitelist, User Log, Command Lines, Quarantine, Rules) plus a Tamper Log tab. There are **no ViewModels** — code-behind reads the **shared `warden.db`** directly via the storage repositories (this is the testing/inspection surface; enforcement stays service-driven). The one thing over the pipe is prompt approval (`App.xaml.cs` + `PromptPipeClient`), which fails safe to keep-blocked.

### Hardening — `Warden.Hardening` (Phase 6, no PPL/ELAM)

Self-protection via ACLs + service SDDL + recovery config (PPL/ELAM need a Microsoft AV-vendor agreement, out of scope). `HardeningSddl` holds the reviewed SDDL constants; `DataDirectoryHardener` locks the data dir/DB to SYSTEM+Admins; `ServiceHardener` builds the `sc.exe` argument strings; `TamperLog` writes each event to **both** Serilog and the `tamper_log` table. `AddWardenLogging()` configures Serilog to a daily rolling file `%ProgramData%\Warden\logs\warden-<date>.log` (14-day retention, `shared: true`) plus console. Startup ACL lockdown only runs when `WARDEN_ENFORCE_HARDENING=1`.

## Conventions & gotchas

- **`Directory.Build.props` applies to every project:** `Nullable` enabled, `ImplicitUsings` enabled, .NET analyzers on (`AnalysisLevel=latest-recommended`). Solution-wide `NoWarn`: `CA1848`, `CA1305` (intentional noise suppression).
- **Test naming is underscored `Given_When_Then` sentences** (`First_decisive_source_wins_and_later_sources_are_not_consulted`); `CA1707` is suppressed for that. xUnit only; **no mocking library** — hand-written fakes (`StubSource`/`ThrowingSource` in `TestData.cs`, `FakeLlmProvider`/`RecordingHandler` in `LlmTestHelpers.cs`).
- **Each module owns an `AddWardenXxx()` DI extension**; `Program.cs` is the single composition root and the best top-level map (phase-annotated). The pipeline is assembled generically from every registered `IVerdictSource` ordered by `Kind`.
- **All runtime state lives under `%ProgramData%\Warden\`** — `warden.db` (+ `-wal`/`-shm`), the quarantine store, `ml\model.onnx`, and `logs\`.
- WDAC/malware operations are **VM-only** (`scripts/*.ps1` are gated behind `-IUnderstandVmOnly`); handle live samples only in an isolated Hyper-V VM.

## Fastest path in

`src/Warden.Service/Program.cs` (wiring + phase map) → `EnforcementController.cs` (the runtime loop) → `DecisionPipeline` + `IVerdictSource`/`Verdict`/`VerdictContext` in `Warden.Core` (the contract) → the specific tier you care about.
