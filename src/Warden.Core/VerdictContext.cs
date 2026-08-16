namespace Warden.Core;

/// <summary>
/// Everything a <see cref="IVerdictSource"/> needs to judge a single blocked launch. Built by the
/// enforcement controller by correlating a WDAC block event with the matching process-start event.
/// Immutable; sources must not mutate it.
/// </summary>
/// <param name="Sha256">SHA-256 of the image being launched, uppercase hex.</param>
/// <param name="ImagePath">Full path to the image being launched.</param>
/// <param name="CommandLine">Full command line of the launch.</param>
/// <param name="Pid">Process id assigned to the (blocked) launch, if known; otherwise 0.</param>
/// <param name="ParentPid">Process id of the creator.</param>
/// <param name="ParentPath">Full path to the parent image.</param>
/// <param name="ParentSha256">SHA-256 of the parent image, uppercase hex (may be null).</param>
/// <param name="Signer">Authenticode facts about the image.</param>
/// <param name="MotwZone">
/// Mark-of-the-Web zone id from the file's <c>Zone.Identifier</c> stream. -1 = no MOTW,
/// 3 = Internet, 4 = Restricted. Values ≥ 3 indicate an untrusted origin.
/// </param>
/// <param name="Pe">Lazily-parsed PE features. Only forced by tiers that need them (ML, web-app, LLM).</param>
/// <param name="Chain">Reconstructed process ancestry for the launch.</param>
/// <param name="Timestamp">When the launch was observed.</param>
/// <param name="CorrelationId">Links the WDAC block event to the process-start event that produced this context.</param>
public sealed record VerdictContext(
    string Sha256,
    string ImagePath,
    string CommandLine,
    int Pid,
    int ParentPid,
    string ParentPath,
    string? ParentSha256,
    SignerInfo Signer,
    int MotwZone,
    Lazy<PeFeatures> Pe,
    AttackChainNode Chain,
    DateTimeOffset Timestamp,
    ulong CorrelationId)
{
    /// <summary>Mark-of-the-Web zone id meaning "no MOTW stream present".</summary>
    public const int NoMotw = -1;

    /// <summary>
    /// Path of the immutable snapshot the controller took of the image <i>before</i> inspection (in the
    /// SYSTEM-only data directory), or null when no snapshot could be taken (oversized/unreadable). Every
    /// byte-level fact in this context — <see cref="Sha256"/>, <see cref="Signer"/>, <see cref="Pe"/> — was
    /// derived from the snapshot, and the WDAC allow rule is built from it, so the bytes judged are the bytes
    /// allow-listed. Tiers that need the original location (path trust, MOTW, owner) use <see cref="ImagePath"/>.
    /// </summary>
    public string? SnapshotPath { get; init; }

    /// <summary>The file to read bytes from: the snapshot when present, else the original path.</summary>
    public string BytesPath => SnapshotPath ?? ImagePath;

    /// <summary>True when the file carries a Mark-of-the-Web indicating an internet/restricted origin.</summary>
    public bool IsFromInternet => MotwZone >= 3;

    /// <summary>The image file name (no directory), lower-cased.</summary>
    public string ImageName =>
        string.IsNullOrEmpty(ImagePath) ? string.Empty : Path.GetFileName(ImagePath).ToLowerInvariant();
}
