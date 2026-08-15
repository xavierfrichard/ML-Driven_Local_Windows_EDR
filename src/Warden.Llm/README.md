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

## Providers

| Provider | Auth | Default? | Notes |
|---|---|---|---|
| `AnthropicApiProvider` | `x-api-key` | **yes**, when a key is set | The supported backend for any distributed build. Default model `claude-haiku-4-5`; escalates internet-origin samples to `claude-sonnet-5`. Prompt-caches the system prompt + tool schema. |
| `ClaudeCliProvider` | the installed `claude` CLI's own login | when `EnableClaudeCli` | **Subscription-backed**, personal machine. Shells out to `claude -p --output-format json` — running Claude Code *as the product*, so it draws on a Pro/Max subscription instead of API billing. Priority 5 (preferred over local, yields to an API key). See the CLI section below. |
| `LocalLlmProvider` | optional bearer | when `EnableLocal` | Offline, free. OpenAI-compatible endpoint (Ollama / llama.cpp). Reads the verdict from the tool call, or from a JSON object in the message content. |
| `ClaudeCodeOAuthProvider` | `Authorization: Bearer` + `anthropic-beta: oauth-2025-04-20` | **NO — disabled by default** | Personal machine only. See the warning below. |

## ClaudeCliProvider — subscription-backed, personal machine

Shells out to the installed **`claude` CLI** in headless mode
(`claude -p --output-format json`). This runs Claude Code **as the product**, under your own login, so
it draws on a **Claude Pro/Max subscription** rather than API-key billing — the sanctioned way to use a
subscription headlessly (`claude setup-token`), and distinct from `ClaudeCodeOAuthProvider`, which lifts
the session token and posts to the raw API (against terms — see below).

How it is invoked, and why it stays safe:

- **No tools.** The CLI is called with `--allowed-tools __none__` (a single non-existent tool name — the
  flag is variadic and rejects an empty value), so a prompt-injection smuggled into a dossier string can
  never make the agent run `Bash`, `Write`, or any tool. `--exclude-dynamic-system-prompt-sections`
  trims the harness prompt.
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
service, run `claude setup-token` and expose the resulting token to the service account (e.g. a machine
env var the CLI honors), or drive classification from the user-session tray UI. It works out of the box
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
    o.AnthropicApiKey = Environment.GetEnvironmentVariable("WARDEN_ANTHROPIC_API_KEY");
    // o.EnableClaudeCli = true;  // subscription-backed via the `claude` CLI (personal machine; see above)
    // o.EnableLocal = true; o.LocalBaseAddress = new("http://localhost:11434/"); o.LocalModel = "foundation-sec-8b";
    // o.AllowOnBenign = true;   // opt in to let a confident-benign verdict auto-allow (default: defer to prompt)
});
```

Secrets (`AnthropicApiKey`, `ClaudeCodeOAuthToken`, `LocalApiKey`) must come from the environment or a
local, git-ignored config — never commit them (see the repo `.gitignore`).
