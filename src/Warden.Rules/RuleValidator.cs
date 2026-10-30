using System.Text.RegularExpressions;
using Warden.Core;
using Warden.Storage;

namespace Warden.Rules;

/// <summary>
/// Validation of a rule an administrator submits from the Rules panel, before it is stored. Kept here (rather
/// than in the service's management handler) so it can be tested without the service host.
/// </summary>
public static partial class RuleValidator
{
    [GeneratedRegex("^[0-9A-Fa-f]{64}$")]
    private static partial Regex Sha256Hex();

    /// <summary>True when <paramref name="value"/> is a 64-hex-character SHA-256.</summary>
    public static bool IsSha256(string? value) => value is not null && Sha256Hex().IsMatch(value);

    /// <summary>A rooted, canonical local path that is not a bare drive root (so "C:\" cannot become a rule).</summary>
    public static bool IsAcceptableLocalPath(string? value, bool allowDriveRoot, out string canonical, out string? error)
    {
        canonical = string.Empty;
        error = null;
        if (string.IsNullOrWhiteSpace(value))
        {
            error = "Path is empty.";
            return false;
        }

        try
        {
            canonical = Path.GetFullPath(value);
        }
        catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException)
        {
            error = "Path is not a valid local path.";
            return false;
        }

        if (!Path.IsPathRooted(canonical) || canonical.StartsWith(@"\\", StringComparison.Ordinal))
        {
            error = "Path must be a rooted local path (no UNC/device paths).";
            return false;
        }

        if (!allowDriveRoot && Path.GetPathRoot(canonical) is { } root
            && string.Equals(root, canonical.TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase))
        {
            error = "A drive root is not accepted here (it would apply to everything on the volume).";
            return false;
        }

        return true;
    }

    /// <summary>Message returned for an Extension allow rule.</summary>
    public const string ExtensionAllowRefused =
        "An extension rule can only block. \".exe → Allow\" would allow every program with that extension "
        + "(even with \"require signature\", anything signed by any public certificate authority). "
        + "Use a Hash rule for one file, or a Signature rule for one publisher.";

    /// <summary>
    /// Returns why <paramref name="rule"/> cannot be stored, or null when it can.
    /// </summary>
    /// <param name="rule">The submitted rule.</param>
    /// <param name="folderWriteProblem">
    /// For a folder allow: describes who other than SYSTEM and Administrators can change what is in the folder,
    /// or returns null when nobody can (the service passes <c>FolderWriteAccess.FindProblem</c>).
    /// </param>
    public static string? Validate(RuleEntry rule, Func<string, string?> folderWriteProblem)
    {
        ArgumentNullException.ThrowIfNull(rule);
        ArgumentNullException.ThrowIfNull(folderWriteProblem);

        if (string.IsNullOrWhiteSpace(rule.MatchValue))
        {
            return "Rule value is empty.";
        }

        if (!Enum.IsDefined(rule.Kind) || !Enum.IsDefined(rule.Action))
        {
            return "Rule kind/action is invalid.";
        }

        switch (rule.Kind)
        {
            case RuleKind.Hash:
                return IsSha256(rule.MatchValue) ? null : "A hash rule needs a 64-hex-character SHA-256.";
            case RuleKind.Signature:
                if (rule.MatchValue.Trim().Length < 3)
                {
                    return "A signature rule needs at least 3 characters of publisher name.";
                }
                // Allow rules match the certificate's Common Name exactly (or its thumbprint), so a pasted
                // subject DN would never match: say so now rather than store a rule that silently does nothing.
                return rule.Action == PolicyAction.Allow && rule.MatchValue.Contains('=', StringComparison.Ordinal)
                    ? "For an allow rule, enter the publisher's Common Name (for example \"Contoso Ltd\") or the signing certificate's thumbprint, not a subject string."
                    : null;
            case RuleKind.Folder:
            {
                // A folder ALLOW on a drive root is a global allow; a BLOCK on a drive root is fine.
                if (!IsAcceptableLocalPath(rule.MatchValue, allowDriveRoot: rule.Action == PolicyAction.Block, out string canonical, out string? err))
                {
                    return err;
                }
                if (rule.Action != PolicyAction.Allow)
                {
                    return null;
                }
                // An ALLOW auto-allows (and permanently hash-allows in WDAC) anything launched from the folder,
                // so only a folder that standard users cannot write to, or swap out, may carry one.
                if (!Directory.Exists(canonical))
                {
                    return "A folder allow rule needs an existing folder, so its permissions can be checked.";
                }
                return folderWriteProblem(canonical) is { } problem
                    ? "This folder cannot carry an allow rule, because accounts other than SYSTEM and Administrators can change what is in it: "
                      + problem + " Use a Hash or Signature rule instead, or lock the folder down first."
                    : null;
            }
            case RuleKind.Extension:
                if (rule.Action == PolicyAction.Allow)
                {
                    return ExtensionAllowRefused;
                }
                return rule.MatchValue.StartsWith('.') && rule.MatchValue.Length >= 2 && !rule.MatchValue.Any(char.IsWhiteSpace)
                    ? null
                    : "An extension rule looks like \".exe\".";
            default:
                return "Rule kind is invalid.";
        }
    }
}
