using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Warden.Amsi;
using Warden.AttackChain;
using Warden.Core;
using Warden.Etw;
using Warden.Ipc;
using Warden.Llm;
using Warden.Ml;
using Warden.Monitoring;
using Warden.Quarantine;
using Warden.Reputation;
using Warden.Rules;
using Warden.Service;
using Warden.AntiExploit;
using Warden.Firewall;
using Warden.Hardening;
using Warden.Storage;
using Warden.Trust;
using Warden.Wdac;
using Warden.WebApps;

var builder = Host.CreateApplicationBuilder(args);

// Run as a Windows Service in production; also runs as a console app for dev.
builder.Services.AddWindowsService(options => options.ServiceName = "WardenAgent");

// Phase 6 — structured rolling-file logging (Serilog) and the self-protection layer. The data-directory
// ACL lockdown is applied on startup ONLY when the installer sets WARDEN_ENFORCE_HARDENING=1, so a plain
// dev/console run never re-ACLs %ProgramData%\Warden. The service SDDL + recovery are installer-only.
builder.Services.AddWardenLogging();
builder.Services.AddWardenHardening(options =>
{
    options.EnforceOnStartup =
        string.Equals(Environment.GetEnvironmentVariable("WARDEN_ENFORCE_HARDENING"), "1", StringComparison.Ordinal);
});

// Module registrations (each module owns its own DI wiring).
builder.Services.AddWardenStorage();
builder.Services.AddWardenEtw();
builder.Services.AddWardenTrust();
builder.Services.AddWardenRules();
// The WDAC base policy the supplemental attaches to comes from configuration (the installer sets the
// machine-scoped WARDEN_WDAC_BASE_POLICY_GUID); a machine's GUID must never be hard-coded in source, and an
// unset/invalid value falls back to run-time discovery from CiTool.
builder.Services.AddWardenWdac(options =>
{
    string? configured = Environment.GetEnvironmentVariable("WARDEN_WDAC_BASE_POLICY_GUID");
    options.BasePolicyGuid = configured is not null && Guid.TryParse(configured.Trim().Trim('{', '}'), out Guid g) && g != Guid.Empty
        ? "{" + g.ToString().ToUpperInvariant() + "}"
        : null;
});
// IPC security refusals (rejected peer, non-admin Allow, squatted pipe, oversized frame) go to the tamper log.
builder.Services.AddSingleton<IPipeSecurityEventSink, PipeSecurityTamperSink>();
builder.Services.AddWardenIpcServer();

// The management channel: the tray UI reads every panel and applies policy edits through the service,
// because %ProgramData%\Warden is ACL-locked to SYSTEM + Administrators and a user-session UI cannot
// open the SQLite file. The pipe DACL admits only elevated callers; mutations are additionally refused
// unless the impersonated calling token is an Administrators member.
builder.Services.AddSingleton<IMgmtHandler, MgmtRequestHandler>();
builder.Services.AddWardenMgmtServer();

// Phase 2 telemetry + reputation. The VirusTotal tier stays silent until a key is configured.
builder.Services.AddWardenReputation(options =>
{
    options.ApiKey = Environment.GetEnvironmentVariable("WARDEN_VT_API_KEY");
});   // adds the VirusTotal IVerdictSource (pipeline tier 3)
builder.Services.AddWardenAttackChain();
builder.Services.AddWardenQuarantine();
builder.Services.AddWardenAmsi();
builder.Services.AddWardenMonitoring();
builder.Services.AddWardenMl();          // adds the ONNX ML IVerdictSource (pipeline tier 5; disabled until a model exists)

// Phase 4: LLM analyst tier (pipeline tier 6, the last before the user prompt). Disabled until a
// provider is configured. The Claude Code OAuth provider stays off unless explicitly enabled (personal
// machines only — see src/Warden.Llm/README.md). Configure the Anthropic API key from the environment.
builder.Services.AddWardenLlm(options =>
{
    options.AnthropicApiKey = Environment.GetEnvironmentVariable("WARDEN_ANTHROPIC_API_KEY");

    // Subscription-backed analyst via the installed `claude` CLI (personal machine). Preferred when no
    // API key is set. NOTE: the CLI reads its login from the invoking user's profile — under the
    // LocalSystem service it fails auth and stays silent (fail-safe). To use it under the service, run
    // `claude setup-token` and expose the token to the service account; otherwise it is live when the
    // agent runs in the user session. Opt in explicitly with WARDEN_ENABLE_CLAUDE_CLI=1 and point
    // WARDEN_CLAUDE_CLI_PATH at the executable (an absolute path — a SYSTEM service never resolves through PATH).
    options.EnableClaudeCli =
        string.Equals(Environment.GetEnvironmentVariable("WARDEN_ENABLE_CLAUDE_CLI"), "1", StringComparison.Ordinal);
    if (Environment.GetEnvironmentVariable("WARDEN_CLAUDE_CLI_PATH") is { Length: > 0 } cliPath)
    {
        options.ClaudeCliPath = cliPath;
    }
});

// Phase 5 — Advanced + Web Apps panels. The Web Apps classifier is always-ON (no toggle) and read-only.
// The anti-exploit and firewall managers are registered but apply NOTHING on startup: their appliers
// make real, machine-wide changes only when invoked panel-driven (audit-first, VM-validated).
builder.Services.AddWardenWebApps();
builder.Services.AddWardenAntiExploit();
builder.Services.AddWardenFirewall();

// The decision pipeline is composed from every registered IVerdictSource, ordered cheap->expensive by
// VerdictSourceKind (Rules -> Whitelist -> TrustGate -> ...). A source that throws is logged and skipped;
// the pipeline still falls through to Prompt, so a broken tier can never become a silent allow.
builder.Services.AddSingleton(sp =>
{
    var sources = sp.GetServices<IVerdictSource>()
        .OrderBy(s => (int)s.Kind)
        .ToList();
    var logger = sp.GetRequiredService<ILogger<DecisionPipeline>>();
    return new DecisionPipeline(
        sources,
        (kind, ex) => logger.LogError(ex, "Verdict source {Kind} threw; skipping it", kind));
});

builder.Services.AddSingleton<EnforcementController>();
builder.Services.AddHostedService<WardenWorker>();

var host = builder.Build();
host.Run();
