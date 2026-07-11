using Warden.Core;

namespace Warden.AttackChain;

/// <summary>
/// A cheap heuristic suspicion score in [0,1] for a process chain, pending the LLM analyst (Phase 4).
/// Rewards classic living-off-the-land patterns: a document/browser/mail app spawning a script host or
/// shell, LOLBins in the chain, execution from user-writable temp/download folders, and unusual depth.
/// </summary>
public sealed class ChainSuspicionScorer
{
    private static readonly HashSet<string> ScriptHostsAndShells = new(StringComparer.OrdinalIgnoreCase)
    {
        "powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe",
    };

    private static readonly HashSet<string> LolBins = new(StringComparer.OrdinalIgnoreCase)
    {
        "rundll32.exe", "regsvr32.exe", "mshta.exe", "certutil.exe", "bitsadmin.exe", "wmic.exe",
        "msbuild.exe", "installutil.exe", "regasm.exe", "regsvcs.exe", "cscript.exe", "wscript.exe",
        "hh.exe", "ieexec.exe", "presentationhost.exe", "msdt.exe",
    };

    private static readonly HashSet<string> RiskyParents = new(StringComparer.OrdinalIgnoreCase)
    {
        "winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "acrord32.exe", "acrobat.exe",
        "chrome.exe", "msedge.exe", "firefox.exe", "iexplore.exe",
    };

    /// <summary>Scores the given node in the context of its reconstructed ancestry.</summary>
    public double Score(AttackChainNode node)
    {
        if (ReferenceEquals(node, AttackChainNode.None) || string.IsNullOrEmpty(node.ImagePath))
        {
            return 0d;
        }

        double score = 0d;
        string image = node.ImageName;

        if (LolBins.Contains(image))
        {
            score += 0.35;
        }

        string? parentImage = node.Ancestors.IsDefaultOrEmpty
            ? null
            : node.Ancestors[^1].ImageName;
        if (parentImage is not null && RiskyParents.Contains(parentImage) && ScriptHostsAndShells.Contains(image))
        {
            score += 0.45; // office/browser -> shell/script host is a strong signal
        }

        if (IsUserWritable(node.ImagePath))
        {
            score += 0.25;
        }

        if (node.Depth >= 4)
        {
            score += 0.15;
        }

        return Math.Clamp(score, 0d, 1d);
    }

    private static bool IsUserWritable(string path)
    {
        string p = path.ToLowerInvariant();
        return p.Contains(@"\appdata\local\temp\")
            || p.Contains(@"\downloads\")
            || p.Contains(@"\windows\temp\")
            || p.Contains(@"\users\public\");
    }
}
