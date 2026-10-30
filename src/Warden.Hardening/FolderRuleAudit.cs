using Microsoft.Extensions.Logging;
using Warden.Storage;

namespace Warden.Hardening;

/// <summary>
/// Startup check of the stored Folder → Allow rules. New rules are refused when non-administrators can
/// change the folder (see <see cref="FolderWriteAccess"/>), but rules saved before that check existed, or
/// written to the database some other way, were never checked. Any that fail now are disabled, not deleted,
/// and each one is recorded in the tamper log so an administrator can see why it stopped applying.
/// </summary>
public static class FolderRuleAudit
{
    /// <summary>Tamper-log category for a folder allow rule that was disabled.</summary>
    public const string Category = "unsafe-folder-allow-rule-disabled";

    /// <summary>
    /// Disables every enabled Folder → Allow rule whose folder fails <paramref name="check"/>. Returns how many
    /// were disabled. Fail-safe: if the check itself throws, the rule is disabled.
    /// </summary>
    /// <param name="rules">The rule store.</param>
    /// <param name="tamperLog">Where each disabled rule is recorded.</param>
    /// <param name="logger">Diagnostic logger.</param>
    /// <param name="check">Returns null when the folder is safe, else a reason. Defaults to <see cref="FolderWriteAccess.FindProblem"/>.</param>
    /// <param name="cancellationToken">Cancellation.</param>
    public static async Task<int> DisableUnsafeFolderAllowsAsync(
        IRulesRepository rules,
        ITamperLog tamperLog,
        ILogger logger,
        Func<string, string?>? check = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(rules);
        ArgumentNullException.ThrowIfNull(tamperLog);
        ArgumentNullException.ThrowIfNull(logger);
        check ??= folder => FolderWriteAccess.FindProblem(folder);

        IReadOnlyList<RuleEntry> enabled = await rules.GetEnabledAsync(cancellationToken).ConfigureAwait(false);
        int disabled = 0;

        foreach (RuleEntry rule in enabled.Where(r => r.Kind == RuleKind.Folder && r.Action == PolicyAction.Allow))
        {
            string? problem;
            try
            {
                problem = check(rule.MatchValue);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                problem = "its permissions could not be checked (" + ex.GetType().Name + ").";
            }

            if (problem is null)
            {
                continue;
            }

            try
            {
                await rules.SetEnabledAsync(rule.Id, enabled: false, cancellationToken).ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                logger.LogError(ex, "Could not disable unsafe folder allow rule {Id} ({Folder}).", rule.Id, rule.MatchValue);
                await tamperLog.LogAsync(Category,
                    $"Folder allow rule #{rule.Id} ({rule.MatchValue}) is unsafe but could not be disabled: {problem}",
                    "critical", cancellationToken).ConfigureAwait(false);
                continue;
            }

            disabled++;
            await tamperLog.LogAsync(Category,
                $"Folder allow rule #{rule.Id} ({rule.MatchValue}) was disabled: {problem} "
                + "Lock the folder down and re-add the rule, or use Hash or Signature rules instead.",
                "warning", cancellationToken).ConfigureAwait(false);
        }

        return disabled;
    }
}
