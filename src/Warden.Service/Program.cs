using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Warden.Amsi;
using Warden.AttackChain;
using Warden.Core;
using Warden.Etw;
using Warden.Ipc;
using Warden.Ml;
using Warden.Monitoring;
using Warden.Quarantine;
using Warden.Reputation;
using Warden.Rules;
using Warden.Service;
using Warden.Storage;
using Warden.Trust;
using Warden.Wdac;

var builder = Host.CreateApplicationBuilder(args);

// Run as a Windows Service in production; also runs as a console app for dev.
builder.Services.AddWindowsService(options => options.ServiceName = "WardenAgent");

// Module registrations (each module owns its own DI wiring).
builder.Services.AddWardenStorage();
builder.Services.AddWardenEtw();
builder.Services.AddWardenTrust();
builder.Services.AddWardenRules();
builder.Services.AddWardenWdac();
builder.Services.AddWardenIpcServer();

// Phase 2 telemetry + reputation.
builder.Services.AddWardenReputation();   // adds the VirusTotal IVerdictSource (pipeline tier 4)
builder.Services.AddWardenAttackChain();
builder.Services.AddWardenQuarantine();
builder.Services.AddWardenAmsi();
builder.Services.AddWardenMonitoring();
builder.Services.AddWardenMl();          // adds the ONNX ML IVerdictSource (pipeline tier 5; disabled until a model exists)

// The decision pipeline is composed from every registered IVerdictSource, ordered cheap->expensive by
// VerdictSourceKind (Rules -> TrustGate -> Whitelist -> ...). A source that throws is logged and skipped;
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
