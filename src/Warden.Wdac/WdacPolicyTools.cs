using System.Text;

namespace Warden.Wdac;

/// <summary>
/// The external ConfigCI / CiTool steps the allow-list manager needs, behind one seam so the transaction
/// logic around them (staging, validation, rollback) can be tested without admin rights or ConfigCI.
/// Every method writes only the output paths it is given.
/// </summary>
public interface IWdacPolicyTools
{
    /// <summary>
    /// Hashes the PE files under <paramref name="scanDir"/> into <paramref name="hashPolicyXml"/>
    /// (New-CIPolicy -Level Hash), merges <paramref name="currentXml"/> with it into
    /// <paramref name="mergedXml"/> and links the result to <paramref name="baseGuid"/>. Must not modify
    /// <paramref name="currentXml"/>.
    /// </summary>
    Task<ProcessResult> BuildMergedAsync(string currentXml, string scanDir, string hashPolicyXml, string mergedXml, string baseGuid, CancellationToken cancellationToken);

    /// <summary>Compiles <paramref name="xmlPath"/> to the binary policy <paramref name="cipPath"/>.</summary>
    Task<ProcessResult> CompileAsync(string xmlPath, string cipPath, CancellationToken cancellationToken);

    /// <summary>Deploys a compiled policy (CiTool --update-policy).</summary>
    Task<ProcessResult> DeployAsync(string cipPath, CancellationToken cancellationToken);

    /// <summary>Lists deployed policies (CiTool --list-policies --json).</summary>
    Task<ProcessResult> ListPoliciesAsync(CancellationToken cancellationToken);
}

/// <summary>The real <see cref="IWdacPolicyTools"/>: ConfigCI cmdlets in Windows PowerShell, and CiTool.</summary>
public sealed class ConfigCiPolicyTools : IWdacPolicyTools
{
    private readonly WdacOptions _options;
    private readonly ProcessRunner _runner;

    public ConfigCiPolicyTools(WdacOptions options, ProcessRunner runner)
    {
        _options = options;
        _runner = runner;
    }

    public Task<ProcessResult> BuildMergedAsync(string currentXml, string scanDir, string hashPolicyXml, string mergedXml, string baseGuid, CancellationToken cancellationToken)
    {
        var sb = new StringBuilder();
        sb.AppendLine("$ErrorActionPreference='Stop'");
        sb.AppendLine("Import-Module ConfigCI -ErrorAction Stop");
        sb.AppendLine($"$cur = {WdacAllowlistManager.Ps(currentXml)}");
        sb.AppendLine($"$scan = {WdacAllowlistManager.Ps(scanDir)}");
        sb.AppendLine($"$tmp = {WdacAllowlistManager.Ps(hashPolicyXml)}");
        sb.AppendLine($"$merged = {WdacAllowlistManager.Ps(mergedXml)}");
        sb.AppendLine("New-CIPolicy -Level Hash -ScanPath $scan -FilePath $tmp -MultiplePolicyFormat -UserPEs | Out-Null");
        sb.AppendLine("Merge-CIPolicy -PolicyPaths $cur,$tmp -OutputFilePath $merged | Out-Null");
        sb.AppendLine($"Set-CIPolicyIdInfo -FilePath $merged -SupplementsBasePolicyID {WdacAllowlistManager.Ps(baseGuid)} | Out-Null");
        return _runner.RunPowerShellAsync(sb.ToString(), _options.Timeout, cancellationToken);
    }

    public Task<ProcessResult> CompileAsync(string xmlPath, string cipPath, CancellationToken cancellationToken)
    {
        var sb = new StringBuilder();
        sb.AppendLine("$ErrorActionPreference='Stop'");
        sb.AppendLine("Import-Module ConfigCI -ErrorAction Stop");
        sb.AppendLine($"ConvertFrom-CIPolicy -XmlFilePath {WdacAllowlistManager.Ps(xmlPath)} -BinaryFilePath {WdacAllowlistManager.Ps(cipPath)} | Out-Null");
        return _runner.RunPowerShellAsync(sb.ToString(), _options.Timeout, cancellationToken);
    }

    public Task<ProcessResult> DeployAsync(string cipPath, CancellationToken cancellationToken)
    {
        if (cipPath.Contains('"', StringComparison.Ordinal))
        {
            throw new ArgumentException("A .cip path may not contain a double quote.", nameof(cipPath));
        }
        return _runner.RunAsync(_options.CiToolPath, $"--update-policy \"{cipPath}\" --json", _options.Timeout, cancellationToken);
    }

    public Task<ProcessResult> ListPoliciesAsync(CancellationToken cancellationToken) =>
        _runner.RunAsync(_options.CiToolPath, "--list-policies --json", _options.Timeout, cancellationToken);
}
