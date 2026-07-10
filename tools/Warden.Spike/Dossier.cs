using System.Text;
using Warden.Core;

namespace Warden.Spike;

/// <summary>How the dossier's process context (command line / parent) was obtained.</summary>
internal enum CorrelationSource
{
    /// <summary>3076 audit block matched to a live process-start event: full command line + parent.</summary>
    AuditCorrelated,

    /// <summary>3076 audit block with no matching start found in the window (process ran too early/late).</summary>
    AuditUncorrelated,

    /// <summary>3077 enforce block: the process never ran, so context is CI-event + file inspection only.</summary>
    EnforceCiOnly,

    /// <summary>Fabricated from sample data by <c>--selftest</c>.</summary>
    SelfTestSample,
}

/// <summary>
/// The correlated dossier for one blocked launch: file identity + provenance (from disk) joined with
/// process context (from ETW, when available). Backed by a real <see cref="VerdictContext"/> so the
/// spike exercises the Warden.Core contracts the enforcement controller will populate for real.
/// </summary>
internal sealed class Dossier
{
    public required int BlockEventId { get; init; }
    public required string Mode { get; init; }                 // "audit" | "enforce"
    public required CorrelationSource Source { get; init; }

    public required string ImagePath { get; init; }
    public string FileName => string.IsNullOrEmpty(ImagePath) ? string.Empty : Path.GetFileName(ImagePath);
    public string? Sha256FlatHex { get; init; }
    public long FileSize { get; init; } = -1;
    public required SignerInfo Signer { get; init; }
    public int MotwZone { get; init; } = VerdictContext.NoMotw;

    public string CommandLine { get; init; } = string.Empty;
    public int Pid { get; init; }
    public int ParentPid { get; init; }
    public string ParentPath { get; init; } = string.Empty;

    public string PolicyName { get; init; } = string.Empty;
    public string PolicyGuid { get; init; } = string.Empty;
    public string Sha256Authenticode { get; init; } = string.Empty;
    public ulong CorrelationId { get; init; }
    public required DateTimeOffset Timestamp { get; init; }

    /// <summary>True when the process context could not be recovered (enforce block or no match).</summary>
    public bool ProcessContextUnavailable =>
        Source is CorrelationSource.EnforceCiOnly or CorrelationSource.AuditUncorrelated;

    /// <summary>
    /// Projects the dossier onto the Warden.Core <see cref="VerdictContext"/> the decision pipeline
    /// consumes â€” validating that the spike's fields line up with the shipped contract.
    /// </summary>
    public VerdictContext ToVerdictContext() => new(
        Sha256: Sha256FlatHex ?? string.Empty,
        ImagePath: ImagePath,
        CommandLine: CommandLine,
        Pid: Pid,
        ParentPid: ParentPid,
        ParentPath: ParentPath,
        ParentSha256: null,
        Signer: Signer,
        MotwZone: MotwZone,
        Pe: new Lazy<PeFeatures>(() => PeFeatures.NotPortableExecutable),
        Chain: AttackChainNode.None,
        Timestamp: Timestamp,
        CorrelationId: CorrelationId);

    /// <summary>Renders the dossier as a human-readable block to the given writer.</summary>
    public void Print(TextWriter w)
    {
        string modeTag = BlockEventId switch
        {
            3076 => "3076 AUDIT (would-block)",
            3077 => "3077 ENFORCE (blocked)",
            _ => $"{BlockEventId} {Mode}",
        };

        string sourceTag = Source switch
        {
            CorrelationSource.AuditCorrelated => "audit-correlated (ETW process-start matched)",
            CorrelationSource.AuditUncorrelated => "audit-ci-only (no matching process-start in window)",
            CorrelationSource.EnforceCiOnly => "enforce-ci-only (process never ran)",
            CorrelationSource.SelfTestSample => "self-test sample data",
            _ => Source.ToString(),
        };

        var sb = new StringBuilder();
        sb.AppendLine("â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€");
        sb.AppendLine($"â”‚ WARDEN DOSSIER  â€”  {modeTag}");
        sb.AppendLine($"â”‚ observed : {Timestamp:yyyy-MM-dd HH:mm:ss.fff zzz}");
        sb.AppendLine($"â”‚ source   : {sourceTag}");
        sb.AppendLine($"â”‚ corr-id  : 0x{CorrelationId:X16}");
        sb.AppendLine("â”œâ”€ FILE â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€");
        sb.AppendLine($"â”‚ name     : {FileName}");
        sb.AppendLine($"â”‚ path     : {ImagePath}");
        sb.AppendLine($"â”‚ size     : {(FileSize >= 0 ? FileSize.ToString("N0") + " bytes" : "(unavailable)")}");
        sb.AppendLine($"â”‚ SHA-256  : {Sha256FlatHex ?? "(unavailable)"}  [flat file hash]");
        if (!string.IsNullOrEmpty(Sha256Authenticode))
        {
            sb.AppendLine($"â”‚ SHA-256  : {Sha256Authenticode}  [Authenticode, from CI event]");
        }
        sb.AppendLine($"â”‚ MOTW     : {DescribeMotw(MotwZone)}");
        sb.AppendLine("â”œâ”€ SIGNER â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€");
        if (!Signer.IsSigned)
        {
            sb.AppendLine("â”‚ signed   : NO (unsigned, or catalog-signed â€” not visible to embedded-sig read)");
        }
        else
        {
            sb.AppendLine($"â”‚ signed   : YES  valid={Signer.IsValid}  microsoft={Signer.IsMicrosoft}");
            sb.AppendLine($"â”‚ subject  : {Signer.SubjectName}");
            sb.AppendLine($"â”‚ issuer   : {Signer.IssuerName}");
            sb.AppendLine($"â”‚ thumb    : {Signer.Thumbprint}");
        }
        sb.AppendLine("â”œâ”€ PROCESS â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€");
        if (ProcessContextUnavailable)
        {
            sb.AppendLine("â”‚ cmdline  : (unavailable â€” enforce block: process never ran)");
            sb.AppendLine($"â”‚ requestor: {(string.IsNullOrEmpty(ParentPath) ? "(unknown)" : ParentPath)}  [loader per CI event]");
            sb.AppendLine("â”‚ pid/ppid : (unavailable)");
        }
        else
        {
            sb.AppendLine($"â”‚ cmdline  : {CommandLine}");
            sb.AppendLine($"â”‚ pid      : {Pid}");
            sb.AppendLine($"â”‚ parent   : {(string.IsNullOrEmpty(ParentPath) ? "(unknown)" : ParentPath)}  (ppid {ParentPid})");
        }
        sb.AppendLine("â”œâ”€ POLICY â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€");
        sb.AppendLine($"â”‚ name     : {(string.IsNullOrEmpty(PolicyName) ? "(n/a)" : PolicyName)}");
        sb.AppendLine($"â”‚ guid     : {(string.IsNullOrEmpty(PolicyGuid) ? "(n/a)" : PolicyGuid)}");
        sb.AppendLine("â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€");

        w.Write(sb.ToString());
        w.Flush();
    }

    private static string DescribeMotw(int zone) => zone switch
    {
        VerdictContext.NoMotw => "none (no Mark-of-the-Web stream)",
        >= 4 => $"Restricted (ZoneId={zone}) â€” untrusted origin",
        3 => "Internet (ZoneId=3) â€” downloaded, untrusted",
        _ => $"Local/Trusted (ZoneId={zone})",
    };

    /// <summary>
    /// Builds a fully-populated sample dossier for <c>--selftest</c> â€” no file, event-log, or ETW
    /// access, so it runs fine as a non-admin smoke test on the host.
    /// </summary>
    public static Dossier CreateSample() => new()
    {
        BlockEventId = 3076,
        Mode = "audit",
        Source = CorrelationSource.SelfTestSample,
        ImagePath = @"C:\Users\test\Desktop\evil-demo.exe",
        Sha256FlatHex = "9F86D081884C7D659A2FEAA0C55AD015A3BF4F1B2B0B822CD15D6C15B0F00A08",
        FileSize = 73_802,
        Signer = SignerInfo.Unsigned,
        MotwZone = 3, // Internet
        CommandLine = @"""C:\Users\test\Desktop\evil-demo.exe"" --do-bad-things",
        Pid = 4242,
        ParentPid = 1337,
        ParentPath = @"C:\Windows\explorer.exe",
        PolicyName = "Warden Phase 0 Audit Base",
        PolicyGuid = "{A7F1C0DE-0000-4000-8000-DEADBEEF0000}",
        Sha256Authenticode = "(unsigned file â€” flat hash used by CI event)",
        CorrelationId = 0xC0FFEE0000BADF00,
        Timestamp = DateTimeOffset.Now,
    };
}
