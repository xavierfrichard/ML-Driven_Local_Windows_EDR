namespace Warden.Storage;

/// <summary>Allow or block — used by both whitelist rows and rules.</summary>
public enum PolicyAction
{
    Allow = 0,
    Block,
}

/// <summary>What a <see cref="RuleEntry"/> matches on.</summary>
public enum RuleKind
{
    /// <summary>SHA-256 (uppercase hex) of the image.</summary>
    Hash = 0,

    /// <summary>Authenticode signer subject (substring match).</summary>
    Signature,

    /// <summary>Folder path prefix (case-insensitive).</summary>
    Folder,

    /// <summary>File extension including the dot, e.g. ".exe".</summary>
    Extension,
}

/// <summary>
/// One row of the Whitelist panel: the full record of an allow/block decision for a file. Mirrors the
/// CyberLock whitelist columns plus the ML/LLM verdicts and the verdict source.
/// </summary>
public sealed record WhitelistEntry
{
    public long Id { get; init; }
    public DateTimeOffset Timestamp { get; init; }
    public PolicyAction Action { get; init; }
    public required string ProcessName { get; init; }
    public required string ProcessPath { get; init; }
    public required string Sha256 { get; init; }
    public string? SignerSubject { get; init; }
    public string? SignerIssuer { get; init; }
    public string? CertThumbprint { get; init; }
    public string? LlmVerdict { get; init; }
    public double? MlScore { get; init; }
    public string CommandLine { get; init; } = string.Empty;
    public long FileSize { get; init; } = -1;
    public string? ParentName { get; init; }
    public string? ParentPath { get; init; }

    /// <summary>Which tier produced this decision, e.g. "UserPrompt", "Rules", "TrustGate".</summary>
    public required string Source { get; init; }

    /// <summary>Rule that produced this decision, if any.</summary>
    public long? RuleId { get; init; }
}

/// <summary>One row of the Rules panel: a user allow/block by hash / signature / folder / extension.</summary>
public sealed record RuleEntry
{
    public long Id { get; init; }
    public RuleKind Kind { get; init; }
    public required string MatchValue { get; init; }
    public PolicyAction Action { get; init; }

    /// <summary>When true, an allow rule only applies if the file is validly Authenticode-signed.</summary>
    public bool RequireSignature { get; init; }

    /// <summary>When true, an allow rule only applies if the file already has whitelist status.</summary>
    public bool RequireWhitelist { get; init; }

    public bool Enabled { get; init; } = true;
    public DateTimeOffset CreatedTs { get; init; }
    public string? Note { get; init; }
}
