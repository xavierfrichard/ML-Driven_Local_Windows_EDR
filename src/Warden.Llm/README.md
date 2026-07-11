# Warden.Llm — LLM analyst tier (pipeline tier 6)

The last tier before the user prompt. It turns a **typed dossier** of a blocked launch into a
**structured verdict** (`benign` / `suspicious` / `malicious` + confidence + evidence + MITRE) via a
**forced tool call**, and maps that verdict to a pipeline `Verdict`.

- `Dossier` / `DossierBuilder` — capped, typed facts (hash, signer, MOTW, PE structure, suspicious
  imports, command line, parent, attack chain, extracted printable strings). **The model never sees
  raw bytes**; every free-text field is length- and count-capped.
- `LlmAnalystPrompt` — the **fixed** (cacheable) system prompt and the `submit_verdict` JSON schema,
  shared by all providers, plus response parsers for the Anthropic and OpenAI wire formats.
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
   tool call. Free-form model prose can never change what the agent does.

## Providers

| Provider | Auth | Default? | Notes |
|---|---|---|---|
| `AnthropicApiProvider` | `x-api-key` | **yes**, when a key is set | The supported backend for any distributed build. Default model `claude-haiku-4-5`; escalates internet-origin samples to `claude-sonnet-5`. Prompt-caches the system prompt + tool schema. |
| `LocalLlmProvider` | optional bearer | when `EnableLocal` | Offline, free. OpenAI-compatible endpoint (Ollama / llama.cpp). Reads the verdict from the tool call, or from a JSON object in the message content. |
| `ClaudeCodeOAuthProvider` | `Authorization: Bearer` + `anthropic-beta: oauth-2025-04-20` | **NO — disabled by default** | Personal machine only. See the warning below. |

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
    // o.EnableLocal = true; o.LocalBaseAddress = new("http://localhost:11434/"); o.LocalModel = "foundation-sec-8b";
    // o.AllowOnBenign = true;   // opt in to let a confident-benign verdict auto-allow (default: defer to prompt)
});
```

Secrets (`AnthropicApiKey`, `ClaudeCodeOAuthToken`, `LocalApiKey`) must come from the environment or a
local, git-ignored config — never commit them (see the repo `.gitignore`).
