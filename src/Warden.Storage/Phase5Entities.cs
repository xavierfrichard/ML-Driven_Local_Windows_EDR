namespace Warden.Storage;

/// <summary>
/// One row of the Advanced panel's vulnerable-app list: an app tagged as an exploit entry point or a
/// post-exploitation LOLBin, with its per-app anti-exploit + firewall state.
/// </summary>
public sealed record VulnerableAppRecord
{
    public long Id { get; init; }

    /// <summary>Exe name (for a seeded entry, e.g. "winword.exe") or full path (once resolved).</summary>
    public required string AppPath { get; init; }

    public string? Publisher { get; init; }

    /// <summary>Why it is vulnerable: "internet-facing" (exploit entry point) or "lolbin".</summary>
    public required string Reason { get; init; }

    /// <summary>The mitigation profile applied to this app, if any.</summary>
    public long? MitigationProfileId { get; init; }

    public bool FwInBlocked { get; init; }
    public bool FwOutBlocked { get; init; }
}

/// <summary>One row of the Advanced panel's mitigation profiles: the anti-exploit posture applied to an app.</summary>
public sealed record MitigationProfileRecord
{
    public long Id { get; init; }
    public required string AppPath { get; init; }

    /// <summary>Path of the Exploit Protection XML applied via Set-ProcessMitigation, if any.</summary>
    public string? XmlPath { get; init; }

    /// <summary>Comma-separated ASR rule GUIDs enabled for this app.</summary>
    public string? AsrGuidsCsv { get; init; }

    public bool NoChildProcesses { get; init; }
    public bool CetUsermode { get; init; }
    public DateTimeOffset AppliedTs { get; init; }
}

/// <summary>One row of the per-app firewall rules (two per blocked app: one inbound, one outbound).</summary>
public sealed record FirewallRuleRecord
{
    public long Id { get; init; }
    public required string AppPath { get; init; }

    /// <summary>"inbound" or "outbound".</summary>
    public required string Direction { get; init; }

    /// <summary>The Windows Firewall rule name Warden created.</summary>
    public required string FwRuleName { get; init; }

    public bool Enabled { get; init; } = true;
    public DateTimeOffset CreatedTs { get; init; }
}

/// <summary>One row of the Web Apps panel: an app's web-engine classification, cached by path.</summary>
public sealed record WebAppClassificationRecord
{
    public long Id { get; init; }
    public required string AppPath { get; init; }

    /// <summary>Detected engine: "electron" | "webview2" | "cef" | "tauri" | "mshtml" | "none".</summary>
    public required string Engine { get; init; }

    public int StaticScore { get; init; }

    /// <summary>True once runtime signals have upgraded the verdict.</summary>
    public bool RuntimeConfirmed { get; init; }

    /// <summary>JSON array of the matched signals (name/weight/engine), for display and audit.</summary>
    public string? SignalsJson { get; init; }

    public DateTimeOffset Ts { get; init; }
}
