# Build Plan: ML-Driven Local Windows EDR (CyberLock-class)

## Context

**Goal:** Build your own local, ML-driven Endpoint Detection & Response agent for Windows, modeled on VoodooSoft's **CyberLock** (formerly VoodooShield) — an application-whitelisting / "anti-executable" tool with on-device ML classification of unknown executables and context-aware protection.

**What CyberLock does** (the thing we're cloning), three pillars:
1. **Default-deny application whitelisting** — only whitelisted code runs; everything else is blocked at process-creation time (via a kernel driver).
2. **Context-aware dynamic toggling** — the "lock" tightens when the machine is at-risk (browser/email running), relaxes when idle, snapshotting running processes per activation.
3. **On-device ML** — an ML.NET model over ~224 PE features classifies unknown executables Safe/Not-Safe, backed by VirusTotal + a proprietary reputation cloud. Non-modal, ~20-second auto-dismissing prompts fight alert fatigue.

**Scope decisions made for this build (locked):**
| Decision | Choice | Consequence |
|---|---|---|
| Intent | **Personal / learning** | No EV cert urgency, no PPL/ELAM, no commercial distribution or GPL-license hygiene. Driver runs under **test-signing** on your own machines. |
| Blocking ambition | **Phased — detection beta first** | Ship a pure-.NET user-mode agent first; kernel true-prevention is a later, optional learning phase. |
| OS targets | **Windows 10/11 x64 only** | Single test matrix; no Server/ARM64 driver builds. |
| Reputation/cloud | **VirusTotal + offline-first** | Use VirusTotal hash lookups with local caching; agent stays fully functional offline via local ML + whitelist. **No backend to build or host.** |

**Honest framing — the load-bearing constraint:** True pre-execution default-deny **requires a kernel-mode C++ driver** (the .NET CLR cannot run in the kernel). A pure-.NET user-mode agent can only *observe* (via ETW) and *react* (kill/suspend) — there is a millisecond race window where the process already ran before you kill it. So **Phases 0–2 produce a credible detection + soft-response agent (~70% of CyberLock's value)**; **Phase 3 (optional) adds real blocking** via a thin kernel shim. The plan isolates the unavoidable C++ into one well-bounded phase you can take on once the managed agent works.

**Outcome:** A working personal EDR that detects process launches, classifies unknown executables with a local LightGBM/ONNX model, enriches with VirusTotal reputation, enforces a context-aware whitelist with soft-blocking + quarantine, and (optionally, later) hard-blocks via a kernel driver.

---

## Architecture

A **managed user-mode plane** (90% of the work, where your C#/.NET strength lives) plus a **minimal native/kernel plane** added only in the optional Phase 3. The kernel driver holds **no decision logic and no ML** — it caches verdicts and forwards unknowns to the user-mode service.

```
                       +----------------------------------------------+
                       |            USER MODE  (.NET 8)                |
  +-----------+ named  |  +--------------+    +--------------------+   |
  |  Tray UI  |<-pipe->|  | Core Engine  |<-->|   ML Subsystem      |  |
  | (WPF)     | (JSON) |  |  Windows Svc |    | PeNet + EMBER feats |  |
  +-----------+        |  +------+-------+    | ONNX Runtime infer. |  |
   prompts/alerts      |         |            +--------------------+   |
                       |  +------+-----+ +------------+ +----------+    |
                       |  | Policy /   | | Reputation | |   ETW    |    |
                       |  | Whitelist  | | VirusTotal | | Consumer |    |
                       |  | (SQLite)   | | + cache    | |(TraceEvent)|  |
                       |  +------------+ +------------+ +----------+    |
                       |     ^ context engine (browser/email/idle)     |
                       +-----+--------------------------+--------------+
                             | FilterReplyMessage        | ETW (observe-only)
       =================================================================
                             |  Filter Comm Port  (Phase 3 only)
                       +-----+------------------------------------------+
                       |     KERNEL MODE  (C++/WDK) — OPTIONAL Phase 3  |
                       |  Minifilter (file I/O)  +  PsSetCreateProcess  |
                       |  FltRegisterFilter         NotifyRoutineEx2    |
                       +------------------------------------------------+
```

**Communication:** Service<->UI via `System.IO.Pipes` (JSON DTOs). Service<->VirusTotal via `HttpClient`. (Phase 3) Kernel<->Service via `FltCreateCommunicationPort` <-> P/Invoke `FltLib.dll` (`FilterConnectCommunicationPort` / `FilterGetMessage` / `FilterReplyMessage`), with a hash-keyed verdict cache and a hard decision timeout + fail-safe default.

---

## ML Subsystem (Phase 2)

- **Features:** Adopt the **EMBER v2 schema** (industry baseline): ByteHistogram (256), ByteEntropyHistogram (256), HeaderFileInfo (62), SectionInfo (~255), ImportsInfo (1280), ExportsInfo (128), Strings (104), GeneralFileInfo (10) = **2,381 features**. Ship full EMBER v2 first (proven ~0.999 AUC); a reduced ~224-feature set (CyberLock-style) is a later latency optimization.
- **Model:** **LightGBM** (gradient-boosted trees) — beats MalConv on EMBER (0.99911 vs 0.99821 AUC), ~2.4 MB, <15 ms inference, exports cleanly to ONNX. Defer raw-byte deep nets and any LLM layer.
- **Dataset:** **EMBER 2018/2024** (1.1M/3.2M labeled PEs) baseline; **BODMAS** (134K, family labels) and **SOREL-20M** for augmentation/eval. 1:1 class balance.
- **Offline training pipeline (Python, separate from the product):** extract with **LIEF** + EMBER's `PEFeatureExtractor` -> train LightGBM, tune threshold at **~1% FPR** -> export to **ONNX** (optionally INT8-quantized, <1 MB, validate <=0.5% AUC loss) -> version the artifact.
- **On-device inference (.NET):** `Microsoft.ML.OnnxRuntime` loads the model; `PeNet` parses PE headers/imports; **you re-implement the EMBER feature vector in C#** — this is the load-bearing, error-prone part, so keep an EMBER-parity unit-test corpus comparing C# output to the Python extractor byte-for-byte.
- **False-positive strategy (3-tier, cheap->expensive):**
  1. **Trust gate** — Authenticode-signed by Microsoft/known vendor + trusted path (System32, Program Files) => allow, skip ML.
  2. **Reputation gate** — VirusTotal hash lookup (cached, offline-tolerant); known-good => allow, known-bad => block.
  3. **ML gate** — score >= T_block => block/prompt; mid-band => log + prompt; low => allow. Optional YARA sidecar to confirm low-confidence hits + add explainability.
- **Drift:** retrain every 2-4 weeks (cumulative); trigger early on KL-divergence drift over recent feature distributions; keep N-1 model for rollback.

---

## Phased Roadmap

> Effort assumes one strong C#/.NET engineer working solo part-time. Phase 3 carries the most uncertainty (new kernel skills).

### Phase 0 — Spike & scaffolding (1-2 wks)
- Create repo + .NET 8 solution; provision a **Hyper-V test VM** (`bcdedit /set testsigning on` for later driver work — fine for personal use).
- Prove ETW capture with `TraceEvent` (see a real process start); prove `PeNet` PE parse + SHA-256.
- Run an EMBER LightGBM baseline in Python; export **one** ONNX model; load + run it from a C# console via `Microsoft.ML.OnnxRuntime`.
- **Deliverable:** end-to-end smoke test — "process starts -> hash it -> score a (dummy) ONNX model."

### Phase 1 — User-mode MVP, no ML yet (4-6 wks)
- **Windows Service** (Core Engine) + **ETW consumer** (`Microsoft-Windows-Kernel-Process`, Event ID 1) + **named-pipe IPC** + **WPF tray UI** with non-modal, ~20s auto-dismiss prompts.
- **SQLite** policy/whitelist store; **context engine** (detect browser/email processes, idle timer, per-activation process snapshot — CyberLock's key UX differentiator).
- **Soft default-deny:** kill/suspend non-whitelisted processes; **file quarantine** (move to ACL-restricted `%ProgramData%\<Product>\Quarantine` with restore metadata).
- **AMSI provider** (P/Invoke `AmsiScanBuffer`, or a NativeAOT COM `IAntimalwareProvider`) for PowerShell/JS/VBA script scanning.
- **Deliverable:** installable agent that detects, prompts, soft-blocks, quarantines, and toggles by context. **No kernel, no ML yet.**

### Phase 2 — ML classifier integrated (3-5 wks)
- Implement the **EMBER-parity feature extractor in C#** (unit-tested against Python); wire ONNX Runtime into the decision pipeline.
- Add the **3-tier FP strategy**: Authenticode trust gate -> VirusTotal client + cache (offline-first) -> ML gate with tuned threshold; optional YARA sidecar.
- Stand up the **offline training pipeline** + model versioning in the repo.
- **Deliverable:** unknown PEs classified locally in <15 ms with reputation enrichment and a managed false-positive rate. **This is the shippable personal beta.**

### Phase 3 — Kernel driver / true blocking (OPTIONAL learning stretch, 8-12+ wks, highest risk)
- WDK setup; **minifilter** (`FltRegisterFilter`, `PRE_CREATE`/`PRE_WRITE`) for file block/quarantine + **`PsSetCreateProcessNotifyRoutineEx2`** for synchronous pre-execution process deny (set `CreationStatus` to `STATUS_ACCESS_DENIED`).
- `FltCreateCommunicationPort` <-> C# service via P/Invoke `FltLib`; hash-keyed verdict cache; <10 ms decision path with watchdog + fail-safe default.
- Test exclusively in the Hyper-V VM with **WinDbg**; validate against isolated malware samples. **Test-signing only** (no EV cert needed for personal machines).
- **References to fork, not write from scratch:** `microsoft/Windows-driver-samples` (minispy/minifilter, MS-PL), plus `kanitsharma/sniper` and `RafWu/RansomWatch` as process/ransomware-deny references.
- **Deliverable:** real pre-execution default-deny on your own test machine.

### Phase 4 — Response & hardening (OPTIONAL, 3-5 wks)
- Ransomware safeguards: detect `vssadmin delete shadows` (MITRE T1490) + mass file-modification via canary folders; suspend offender.
- Windows Firewall network isolation (`INetFwPolicy2`); MITRE ATT&CK technique tagging on alerts; full quarantine/restore UI.
- Interim self-protection: service ACLs + watchdog; (deeper `ObRegisterCallbacks`/`CmRegisterCallbackEx` tamper-protection optional). PPL/ELAM is **explicitly out** (requires a Microsoft vendor agreement; not needed for personal use).

**Rough timeline:** a usable personal beta (Phases 0-2) ~= **2.5-3.5 months part-time**. Optional kernel blocking + hardening (Phases 3-4) adds several months and is where the deep Windows-internals learning happens.

---

## Recommended Tech Stack & Repo Layout

**Stack:** .NET 8 / C# (user-mode); Python (LightGBM + LIEF + EMBER + onnxmltools) for offline training; SQLite storage; WPF tray UI; C++/WDK (Phase 3 only).

**NuGet:** `Microsoft.Diagnostics.Tracing.TraceEvent`, `PeNet`, `Microsoft.ML.OnnxRuntime`, `Microsoft.Data.Sqlite`, `Hardcodet.NotifyIcon.Wpf`; `System.IO.Pipes` (built-in). Optional: `dnYara` (YARA sidecar).

```
/edr
  /src
    /Edr.Service     (.NET 8 Windows Service — core engine, IPC host)   <- CoreEngine.cs (decision pipeline)
    /Edr.Etw         (TraceEvent consumers)                             <- ProcessStartConsumer.cs
    /Edr.Ml          (EMBER feature extractor + ONNX inference)         <- EmberFeatureExtractor.cs (load-bearing)
    /Edr.Policy      (whitelist, context engine, SQLite store)
    /Edr.Reputation  (VirusTotal client + cache, offline-first)
    /Edr.Response    (quarantine, kill, isolation, MITRE tagging)
    /Edr.Amsi        (AMSI provider, NativeAOT)
    /Edr.Ui          (WPF tray app, non-modal auto-dismiss prompts)
    /Edr.Ipc         (shared named-pipe contracts/DTOs)
  /kernel            (Phase 3 only)
    /EdrProcGuard    (C++ PsSetCreateProcessNotifyRoutineEx2 + Filter port)  <- fork Windows-driver-samples
    /EdrMinifilter   (C++ WDK minifilter)
  /ml-training       (Python: EMBER, LightGBM, ONNX export, drift)      <- train_lightgbm_ember.py
  /test
    /vm-lab          (Hyper-V provisioning, test-signing scripts)
    /ember-parity    (C#<->Python feature-vector parity corpus)
  /docs
```

**First files to create** (greenfield): `Edr.Etw/ProcessStartConsumer.cs` (MVP detection core), `Edr.Service/CoreEngine.cs` (trust->reputation->ML pipeline + context toggling), `Edr.Ml/EmberFeatureExtractor.cs` (+ ONNX session), `ml-training/train_lightgbm_ember.py` (defines the model the C# side must match).

---

## Key Risks & De-risking

| Risk | Mitigation |
|---|---|
| **MVP race window** (ETW is async; process runs before kill) | Be explicit it's *detection + soft-response*, not prevention. Gate "true blocking" claims behind Phase 3. |
| **EMBER C# parity bugs** (feature vector mismatch silently wrecks accuracy) | `ember-parity` test corpus comparing C# vector to Python extractor on a fixed PE set; CI gate. |
| **False positives** | 3-tier trust->reputation->ML gating; Authenticode + trusted-path allowlist; tune at ~1% FPR; YARA confirmation; staged model rollout. |
| **Prompt fatigue** | Non-modal ~20s auto-dismiss prompts; AutoPilot mode auto-allows ML-Safe; aggressive reputation-based auto-whitelisting. |
| **BSOD (Phase 3)** | Keep driver logic minimal (no ML/IO in kernel); WinDbg + Hyper-V; drain in-flight callbacks before unload; strict IRQL/locking; fork vetted MS samples. |
| **Concept drift / evasion** | 2-4 wk cumulative retraining; KL-divergence trigger; track EMBER2024 adversarial set; consider behavioral ensemble later. |
| **VirusTotal availability/rate limits** | Offline-first: local ML + whitelist must work with no network; cache all hash verdicts in SQLite. |

---

## Verification

- **Phase 0:** From a C# console, launch Notepad and confirm the ETW consumer logs the process-start event (PID/PPID/ImagePath); confirm `PeNet` hashes a known EXE and ONNX Runtime loads the exported model and returns a score.
- **Phase 1:** Install the service on the Hyper-V VM; launch a non-whitelisted EXE -> confirm a non-modal prompt appears and "Continue blocking" kills/quarantines it; confirm the file lands in the ACL-restricted quarantine with restore metadata; confirm context toggling (lock engages when a browser opens). Drop a test EICAR-style script -> confirm AMSI scan fires.
- **Phase 2:** Run the `ember-parity` corpus -> C# and Python feature vectors match. Score a labeled holdout set of benign + malicious PEs -> measure detection rate at the chosen threshold and false positives on a clean Program Files sweep. Confirm VirusTotal enrichment works and that pulling the network still leaves the agent functional (offline-first).
- **Phase 3 (if pursued):** In the isolated VM, attempt to launch a known-bad sample -> confirm the kernel callback denies execution *before* any payload runs (verify via Process Monitor that the process never reaches `main`). Stress-test for BSODs under rapid process churn; verify clean driver unload.

---

## Legal / safety note

EDR development is legitimate defensive security work. Two cautions for the build: (1) handle live malware samples **only inside the isolated Hyper-V VM** (no network bridge to your host); (2) CyberLock's snapshot-whitelisting is patented (US 9,197,656) — fine to replicate the *concept* for personal use, but relevant if you ever reconsider commercializing.
