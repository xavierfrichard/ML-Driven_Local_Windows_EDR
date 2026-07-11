namespace Warden.Storage;

/// <summary>
/// One security-relevant tamper/self-protection event: a failed lockdown, a detected ACL mismatch, a
/// service-recovery restart, etc. Recorded so tampering with the agent leaves an audit trail.
/// </summary>
public sealed record TamperEventRecord
{
    public long Id { get; init; }
    public DateTimeOffset Timestamp { get; init; }

    /// <summary>Short category, e.g. "data-dir-lockdown-failed", "db-acl-applied", "service-recovery".</summary>
    public required string Category { get; init; }

    public string? Detail { get; init; }

    /// <summary>"info" | "warning" | "critical".</summary>
    public string Severity { get; init; } = "warning";
}
