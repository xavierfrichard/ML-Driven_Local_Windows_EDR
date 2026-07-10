namespace Warden.Core;

/// <summary>
/// The outcome a verdict source can assign to a launch. The decision pipeline stops at the first
/// source that returns anything other than <see cref="Unknown"/>.
/// </summary>
/// <remarks>
/// Warden is default-deny: the OS (WDAC) has already blocked the launch before the pipeline runs,
/// so a non-decisive pipeline result never means "the process is running unchecked" — it means
/// "fall through to <see cref="Prompt"/>", which keeps the launch blocked and asks the user.
/// </remarks>
public enum Verdict
{
    /// <summary>The source has no opinion; continue to the next source in the pipeline.</summary>
    Unknown = 0,

    /// <summary>Allow the launch (whitelist it so WDAC lets it run).</summary>
    Allow,

    /// <summary>Keep the launch blocked.</summary>
    Block,

    /// <summary>Keep the launch blocked and move the file to quarantine.</summary>
    Quarantine,

    /// <summary>No source was decisive; show a non-modal prompt. Default action keeps it blocked.</summary>
    Prompt,
}
