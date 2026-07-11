using Warden.Core;
using Warden.Storage;

namespace Warden.Rules;

/// <summary>
/// Resolves a blocked launch against prior decisions recorded in the whitelist: if the same image
/// (by SHA-256) was previously allowed or blocked, that decision is replayed decisively.
/// </summary>
/// <remarks>
/// Fail-safe by construction: with no prior record — or if the whitelist store cannot be read — the
/// source declines with <see cref="VerdictResult.Undecided"/> so the pipeline continues rather than
/// silently allowing the launch.
/// </remarks>
public sealed class WhitelistVerdictSource : IVerdictSource
{
    private readonly IWhitelistRepository _whitelist;

    /// <summary>Creates a whitelist verdict source over the given store.</summary>
    /// <param name="whitelist">The whitelist / verdict-history store.</param>
    /// <exception cref="ArgumentNullException"><paramref name="whitelist"/> is null.</exception>
    public WhitelistVerdictSource(IWhitelistRepository whitelist)
    {
        ArgumentNullException.ThrowIfNull(whitelist);
        _whitelist = whitelist;
    }

    /// <inheritdoc />
    public VerdictSourceKind Kind => VerdictSourceKind.Whitelist;

    /// <inheritdoc />
    public async ValueTask<VerdictResult> EvaluateAsync(VerdictContext context, CancellationToken cancellationToken)
    {
        if (context is null || string.IsNullOrEmpty(context.Sha256))
        {
            return VerdictResult.Undecided(Kind, "No hash to look up.");
        }

        WhitelistEntry? latest;
        try
        {
            latest = await _whitelist.FindLatestBySha256Async(context.Sha256, cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch
        {
            // Fail safe: an unreadable whitelist must never short-circuit into an allow.
            return VerdictResult.Undecided(Kind, "Whitelist store unavailable; deferring.");
        }

        if (latest is null)
        {
            return VerdictResult.Undecided(Kind, "No prior whitelist decision for this hash.");
        }

        return latest.Action switch
        {
            PolicyAction.Allow => new VerdictResult(
                Verdict.Allow,
                Kind,
                1d,
                $"Previously allowed on {latest.Timestamp:u}."),

            PolicyAction.Block => new VerdictResult(
                Verdict.Block,
                Kind,
                1d,
                $"Previously blocked on {latest.Timestamp:u}."),

            _ => VerdictResult.Undecided(Kind, "Unrecognized prior decision; deferring."),
        };
    }
}
