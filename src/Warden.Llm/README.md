# Warden.Llm — LLM analyst tier (pipeline tier 6)

The last tier before the user prompt. It turns a **typed dossier** of a blocked launch into a
**structured verdict** (`benign` / `suspicious` / `malicious` + confidence + evidence + MITRE) via a
**forced tool call**, and maps that verdict to a pipeline `Verdict`.

- `Dossier` / `DossierBuilder` — capped, typed facts (hash, signer, MOTW, PE structure, suspicious
  imports, command line, parent, attack chain, extracted printable strings). **The model never sees
  raw bytes**; every free-text field is length- and count-capped.
- `LlmAnalystPrompt` — the **fixed** (cacheable) system prompt and the `submit_verdict` JSON schema,
  shared by all providers, plus response parsers for the Anthropic, OpenAI, and Claude-CLI wire
  formats. The shared analysis/injection-defense body is defined once; a tool-calling tail
  (`SystemPrompt`) and a raw-JSON tail (`CliSystemPrompt`) differ only in the output instruction.
- `IVerdictLlmProvider` — provider abstraction. `LlmVerdictSource` consults enabled providers in
  priority order and uses the first non-null verdict.
- `LlmVerdictSource` — maps the verdict to `Block` (confident malicious), optionally `Allow`
  (confident benign, off by default), else `Undecided` → prompt.

## Prompt-injection defense (three layers)

1. **Data boundary** — the dossier is serialized to JSON and placed in the *user* turn. The *system*
   prompt is constant and never contains any sample-derived text.
2. **Instruction** — the system prompt forbids the model from following any instruction found inside
   the dossier and tells it to treat such text as a suspicious indicator.
3. **Output boundary** — the enforcement action is read **only** from the forced `submit_verdict`
   tool call. Free-form model prose can never change what the agent does. Verdicts scraped from
   free-text output (the local content fallback and the Claude CLI) are marked `FromToolCall = false`
   and **can only block or defer — never auto-allow** (see `LlmVerdictSource.Map`).
4. **Only the Anthropic API may auto-allow.** Even with `AllowOnBenign` on, an Allow needs a provider
   whose `MayAutoAllow` is true — only `AnthropicApiProvider`. The local endpoint can be squatted by any
   local user, and the CLI and OAuth paths are personal-use, so their verdicts can only block or defer.
5. **Evidence is capped.** Each evidence / MITRE item is clipped to `LlmVerdict.MaxItemLength` characters and
   stripped of control and formatting characters (newlines, bidi overrides) before it reaches logs or the UI.

## Providers

| Provider | Auth | Default? | Notes |
|---|---|---|---|
| `AnthropicApiProvider` | `x-api-key` | **yes**, when a key is set | The supported backend for any distributed build. Default model `claude-haiku-4-5`; escalates internet-origin samples to `claude-sonnet-5`. Prompt-caches the system prompt + tool schema. |
| `ClaudeCliProvider` | the installed `claude` CLI's own login | when `EnableClaudeCli` | **Subscription-backed**, personal machine. Shells out to `claude -p --output-format json` — running Claude Code *as the product*, so it draws on a Pro/Max subscription instead of API billing. Priority 5 (preferred over local, yields to an API key). See the CLI section below. |
| `LocalLlmProvider` | bearer (required for http) | when `EnableLocal` | Offline, free. OpenAI-compatible endpoint (Ollama / llama.cpp). Reads the verdict from the tool call, or from a JSON object in the message content. `https` is accepted; plain `http` only to loopback **and** only with `LocalAllowLoopbackHttp = true` and a `LocalApiKey` (any local user can bind a free loopback port). The token stops other local users from using the endpoint; it does not prove the server is genuine, which is why this provider can never auto-allow. |
| `ClaudeCodeOAuthProvider` | `Authorization: Bearer` + `anthropic-beta: oauth-2025-04-20` | **NO — disabled by default** | Personal machine only. See the warning below. |

## ClaudeCliProvider — subscription-backed, personal machine

Shells out to the installed **`claude` CLI** in headless mode
(`claude -p --output-format json`). This runs Claude Code **as the product**, under your own login, so
it draws on a **Claude Pro/Max subscription** rather than API-key billing — the sanctioned way to use a
subscription headlessly (`claude setup-token`), and distinct from `ClaudeCodeOAuthProvider`, which lifts
the session token and posts to the raw API (against terms — see below).

How it is invoked, and why it stays safe:

- **Trusted executable only (runs as SYSTEM).** `WARDEN_CLAUDE_CLI_PATH` must be a canonical,
  fully-qualified local path to an **`.exe`** — no bare name, drive-relative, UNC or device path, and no
  `.cmd`/`.bat`/`.ps1`. Before **every** launch the file and each parent folder must be owned by SYSTEM,
  Administrators or TrustedInstaller, with nobody else able to write to the file or its folder or to move a
  parent aside (`LlmOptions.ClaudeCliTrustCheck`, injected by the service from
  `Warden.Hardening.FolderWriteAccess`; no check configured = no launch). The per-user installs
  (`%USERPROFILE%\.local\bin\claude.exe`, `%APPDATA%\npm\claude.cmd`) are refused: copy `claude.exe` into a
  folder under `%ProgramFiles%` first.
- **Allow-listed environment.** The child gets only a short list of Windows variables (`SystemRoot`,
  `TEMP`, `USERPROFILE`, …) and a `PATH` reset to the system folders. Every other variable — the service's
  keys, `CLAUDE_CODE_*`, `NODE_OPTIONS`, anything added later — stays out.
- **No tools.** The CLI is called with `--tools ""` and `--bare`, so a prompt-injection smuggled into a
  dossier string can never make the agent run `Bash`, `Write`, or any tool, and no hooks, MCP servers or
  `CLAUDE.md` are discovered. `--permission-mode dontAsk` auto-denies anything that would still ask.
- **JSON output.** The CLI has no `submit_verdict` tool, so it uses `CliSystemPrompt` (same analysis and
  injection defense, but asks for a bare JSON object). The verdict is parsed from the CLI's free-text
  `result` field, so it is `FromToolCall = false` → **block/prompt only, never auto-allow.**
- **Model / cost.** Uses the same `Model` / `EscalationModel` as the other providers (Haiku for volume,
  Sonnet for internet-origin escalations). **Do not leave the model unset to the CLI default** — the CLI
  defaults to your session's (Opus-class) model and loads its full harness prompt, which measured ~$0.43
  per classification in testing vs ~$0.03–0.08 on Haiku. As a *last* pipeline tier this fires rarely, so
  even the notional cost is negligible, and under a subscription it is not billed — but keep it on Haiku.

### ⚠️ Auth caveat — LocalSystem vs the user session

The CLI reads its subscription login from the **invoking user's profile**. `WardenAgent` runs as
**LocalSystem**, which has no Claude login — under the service this provider fails auth and returns null
(fail-safe: the tier stays silent and the pipeline falls through to the prompt). To use it under the
service you would need to give the service account a login; the allow-listed environment deliberately does
not pass `CLAUDE_CODE_OAUTH_TOKEN` through, so this is not wired up. Drive classification from the
user-session tray UI instead. It works out of the box
when the agent itself runs in your user session (e.g. `dotnet run` during development).

Enable with `WARDEN_ENABLE_CLAUDE_CLI=1` (see `Program.cs`).

## ⚠️ ClaudeCodeOAuthProvider — personal use only, against Anthropic's terms

`ClaudeCodeOAuthProvider` authenticates with a **Claude Pro/Max subscription OAuth token**
(`CLAUDE_CODE_OAUTH_TOKEN`, obtained via `claude setup-token`). Using a subscription OAuth token as an
application/product backend is **not permitted by Anthropic**:

> OAuth authentication is intended exclusively for … ordinary use of Claude Code and other native
> Anthropic applications. Developers building products … should use API key authentication.
> — <https://code.claude.com/docs/en/legal-and-compliance>

Therefore this provider:

- is **disabled by default** (`LlmOptions.EnableClaudeCodeOAuth = false`);
- must be turned on explicitly and only on your **own personal machine**;
- is given the **lowest priority** so it is never preferred over the API key or local model;
- **must never** be the default — or even enabled — in a distributed/shipped build. Distributed
  builds use an API key (or BYOK) or a local model.

## Configuration

Everything is off until configured (the tier stays silent, matching the ML tier's model-absent
behavior). Wire it up in `Program.cs`:

```csharp
builder.Services.AddWardenLlm(o =>
{
    o.AnthropicApiKey = ReadSecret(WardenSecretStore.AnthropicApiKey, "WARDEN_ANTHROPIC_API_KEY");
    // o.EnableClaudeCli = true;  // subscription-backed via the `claude` CLI (personal machine; see above)
    // o.EnableLocal = true; o.LocalAllowLoopbackHttp = true; o.LocalApiKey = "<token>"; o.LocalModel = "foundation-sec-8b";
    // o.AllowOnBenign = true;   // opt in to let a confident-benign Anthropic API verdict auto-allow
});
```

The Anthropic API key comes from the service's protected secret store
(`<data dir>\secrets\AnthropicApiKey.bin`, DPAPI machine scope, SYSTEM + Administrators only), written with
`installer\Set-WardenSecret.ps1 -Name AnthropicApiKey`. The old `WARDEN_ANTHROPIC_API_KEY` machine environment
variable is still read as a deprecated fallback, with a warning: every user can read machine environment
variables. Never commit secrets (see the repo `.gitignore`).
