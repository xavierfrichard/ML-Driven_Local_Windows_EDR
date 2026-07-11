using Warden.Core;
using Warden.Storage;

namespace Warden.Rules;

/// <summary>
/// Evaluates a blocked launch against the user-defined rules from the Rules panel. This is the first,
/// cheapest tier of the decision pipeline: deterministic allow/block rules keyed on hash, signer
/// subject, folder prefix or file extension.
/// </summary>
/// <remarks>
/// <para>All enabled rules are matched against the context and combined <em>deny-wins</em>: any rule
/// whose action is <see cref="PolicyAction.Block"/> and whose match predicate holds is decisive and
/// keeps the launch blocked, regardless of any allow rules. Only when no block rule matches is an
/// allow rule considered, and then only if its <see cref="RuleEntry.RequireSignature"/> and
/// <see cref="RuleEntry.RequireWhitelist"/> guards are satisfied. The first satisfied allow rule wins.</para>
/// <para>Fail-safe by construction: if the rule store cannot be read, or anything else goes wrong, the
/// source declines with <see cref="VerdictResult.Undecided"/> so the pipeline continues toward the
/// deny-and-ask fallthrough rather than silently allowing the launch.</para>
/// </remarks>
public sealed class RulesEngine : IVerdictSource
{
    private readonly IRulesRepository _rules;
    private readonly IWhitelistRepository _whitelist;

    /// <summary>Creates a rules engine over the given rule and whitelist stores.</summary>
    /// <param name="rules">Source of the enabled allow/block rules.</param>
    /// <param name="whitelist">Whitelist store, consulted for <see cref="RuleEntry.RequireWhitelist"/> guards.</param>
    /// <exception cref="ArgumentNullException">A dependency is null.</exception>
    public RulesEngine(IRulesRepository rules, IWhitelistRepository whitelist)
    {
        ArgumentNullException.ThrowIfNull(rules);
        ArgumentNullException.ThrowIfNull(whitelist);
        _rules = rules;
        _whitelist = whitelist;
    }

    /// <inheritdoc />
    public VerdictSourceKind Kind => VerdictSourceKind.Rules;

    /// <inheritdoc />
    public async ValueTask<VerdictResult> EvaluateAsync(VerdictContext context, CancellationToken cancellationToken)
    {
        if (context is null)
        {
            return VerdictResult.Undecided(Kind, "No context to evaluate.");
        }

        IReadOnlyList<RuleEntry> enabled;
        try
        {
            enabled = await _rules.GetEnabledAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch
        {
            // Fail safe: an unreadable rule store must never short-circuit into an allow.
            return VerdictResult.Undecided(Kind, "Rule store unavailable; deferring.");
        }

        if (enabled is null || enabled.Count == 0)
        {
            return VerdictResult.Undecided(Kind, "No enabled rules matched.");
        }

        // Deny wins: a single matching block rule is decisive, so scan for one before considering allows.
        RuleEntry? firstAllow = null;
        foreach (var rule in enabled)
        {
            if (rule is null || !Matches(rule, context))
            {
                continue;
            }

            if (rule.Action == PolicyAction.Block)
            {
                return new VerdictResult(
                    Verdict.Block,
                    Kind,
                    1d,
                    $"Blocked by {Describe(rule)}.");
            }

            firstAllow ??= rule;
        }

        // No block rule matched. Consider matching allow rules in order; the first whose guards hold wins.
        if (firstAllow is not null)
        {
            foreach (var rule in enabled)
            {
                if (rule is null || rule.Action != PolicyAction.Allow || !Matches(rule, context))
                {
                    continue;
                }

                if (await AllowSatisfiedAsync(rule, context, cancellationToken).ConfigureAwait(false))
                {
                    return new VerdictResult(
                        Verdict.Allow,
                        Kind,
                        1d,
                        $"Allowed by {Describe(rule)}.");
                }
            }
        }

        return VerdictResult.Undecided(Kind, "No decisive rule matched.");
    }

    /// <summary>Determines whether a rule's match predicate holds for the launch context.</summary>
    private static bool Matches(RuleEntry rule, VerdictContext context)
    {
        var value = rule.MatchValue;
        if (string.IsNullOrEmpty(value))
        {
            return false;
        }

        return rule.Kind switch
        {
            RuleKind.Hash =>
                string.Equals(context.Sha256, value, StringComparison.OrdinalIgnoreCase),

            RuleKind.Signature =>
                context.Signer?.SubjectName is { } subject &&
                subject.Contains(value, StringComparison.OrdinalIgnoreCase),

            RuleKind.Folder =>
                !string.IsNullOrEmpty(context.ImagePath) &&
                context.ImagePath.StartsWith(value, StringComparison.OrdinalIgnoreCase),

            RuleKind.Extension =>
                string.Equals(GetExtension(context.ImagePath), value, StringComparison.OrdinalIgnoreCase),

            _ => false,
        };
    }

    /// <summary>
    /// Evaluates the guards on a matching allow rule: a signature requirement is met by a trusted
    /// Authenticode signature, a whitelist requirement by an existing allow row for the same hash.
    /// </summary>
    private async ValueTask<bool> AllowSatisfiedAsync(
        RuleEntry rule,
        VerdictContext context,
        CancellationToken cancellationToken)
    {
        if (rule.RequireSignature && !(context.Signer?.IsTrustedSignature ?? false))
        {
            return false;
        }

        if (rule.RequireWhitelist)
        {
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
                // Fail safe: if we cannot confirm whitelist status, the allow guard is not satisfied.
                return false;
            }

            if (latest is null || latest.Action != PolicyAction.Allow)
            {
                return false;
            }
        }

        return true;
    }

    /// <summary>File extension including the dot, or empty when the path has none.</summary>
    private static string GetExtension(string? imagePath) =>
        string.IsNullOrEmpty(imagePath) ? string.Empty : Path.GetExtension(imagePath);

    /// <summary>Short human-readable description of a rule for verdict reasons.</summary>
    private static string Describe(RuleEntry rule) =>
        $"rule #{rule.Id} ({rule.Kind} '{rule.MatchValue}')";
}
