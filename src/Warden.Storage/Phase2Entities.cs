namespace Warden.Storage;

/// <summary>One node of a reconstructed process ancestry chain (Attack Chains panel).</summary>
public sealed record AttackChainRecord
{
    public long Id { get; init; }
    public required string SessionGuid { get; init; }
    public int NodePid { get; init; }
    public int ParentPid { get; init; }
    public required string ImagePath { get; init; }
    public string? Sha256 { get; init; }
    public string CommandLine { get; init; } = string.Empty;
    public DateTimeOffset Timestamp { get; init; }
    public int Depth { get; init; }
    public double SuspicionScore { get; init; }
    public string? LlmRationale { get; init; }
}

/// <summary>One row of the Command Lines panel: a process launch and its (optional) verdict.</summary>
public sealed record CommandLineRecord
{
    public long Id { get; init; }
    public DateTimeOffset Timestamp { get; init; }
    public int Pid { get; init; }
    public int ParentPid { get; init; }
    public required string ImagePath { get; init; }
    public string? Sha256 { get; init; }
    public required string CommandLine { get; init; }
    public bool IsScript { get; init; }
    public PolicyAction? Verdict { get; init; }
    public string? VerdictSource { get; init; }
}

/// <summary>One row of the Quarantine panel: a file moved to the restricted store, with restore metadata.</summary>
public sealed record QuarantineRecord
{
    public long Id { get; init; }
    public required string OriginalPath { get; init; }
    public required string QuarantinePath { get; init; }
    public string? Sha256 { get; init; }
    public long Size { get; init; }
    public DateTimeOffset Timestamp { get; init; }
    public string? Reason { get; init; }
    public string? RestoreAclSddl { get; init; }
    public string? VerdictSource { get; init; }
    public bool Restored { get; init; }
}

/// <summary>One row of the Protected Folders panel: a folder Warden monitors.</summary>
public sealed record ProtectedFolder
{
    public long Id { get; init; }
    public required string Path { get; init; }
    public bool Recursive { get; init; } = true;

    /// <summary>Monitoring intent, e.g. "monitor" (log changes) — extended in later phases.</summary>
    public string MonitorMode { get; init; } = "monitor";

    public DateTimeOffset AddedTs { get; init; }
}

/// <summary>Cached VirusTotal reputation for a file hash (offline-tolerant reputation tier).</summary>
public sealed record ReputationRecord
{
    public required string Sha256 { get; init; }

    /// <summary>Number of VirusTotal engines flagging the file as malicious.</summary>
    public int VtPositives { get; init; }

    /// <summary>Total engines that reported.</summary>
    public int VtTotal { get; init; }

    /// <summary>VirusTotal first-submission time, if known.</summary>
    public DateTimeOffset? VtFirstSeen { get; init; }

    public DateTimeOffset CachedTs { get; init; }
    public long TtlSecs { get; init; }

    /// <summary>True while the cache entry is within its TTL.</summary>
    public bool IsFresh(DateTimeOffset now) => (now - CachedTs).TotalSeconds < TtlSecs;
}
