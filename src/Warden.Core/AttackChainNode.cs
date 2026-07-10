using System.Collections.Immutable;

namespace Warden.Core;

/// <summary>
/// One node in a reconstructed process ancestry chain (parent → child → grandchild …). The
/// attack-chain subsystem builds these from ETW process-start events; the chain is handed to the
/// LLM analyst for suspicion scoring and shown in the Attack Chains panel.
/// </summary>
/// <param name="Pid">Process id of this node.</param>
/// <param name="ParentPid">Process id of the creator.</param>
/// <param name="ImagePath">Full path to the node's image.</param>
/// <param name="Sha256">SHA-256 of the image, uppercase hex (may be null if not yet hashed).</param>
/// <param name="CommandLine">Full command line the process was launched with.</param>
/// <param name="Timestamp">When the process started.</param>
/// <param name="Depth">Distance from the chain root (root = 0).</param>
/// <param name="Ancestors">
/// The chain from the root down to (but not including) this node, nearest-parent last.
/// Empty for a root node.
/// </param>
public sealed record AttackChainNode(
    int Pid,
    int ParentPid,
    string ImagePath,
    string? Sha256,
    string CommandLine,
    DateTimeOffset Timestamp,
    int Depth,
    ImmutableArray<AttackChainNode> Ancestors)
{
    /// <summary>An empty placeholder chain for contexts where ancestry has not been reconstructed.</summary>
    public static readonly AttackChainNode None = new(
        Pid: 0,
        ParentPid: 0,
        ImagePath: string.Empty,
        Sha256: null,
        CommandLine: string.Empty,
        Timestamp: default,
        Depth: 0,
        Ancestors: ImmutableArray<AttackChainNode>.Empty);

    /// <summary>The image file name (no directory), lower-cased; empty for <see cref="None"/>.</summary>
    public string ImageName =>
        string.IsNullOrEmpty(ImagePath) ? string.Empty : Path.GetFileName(ImagePath).ToLowerInvariant();
}
