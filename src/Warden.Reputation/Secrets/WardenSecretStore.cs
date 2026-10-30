using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;

namespace Warden.Secrets;

/// <summary>Where a secret value came from.</summary>
public enum SecretOrigin
{
    /// <summary>Not configured anywhere.</summary>
    None,

    /// <summary>Read from the protected store.</summary>
    Store,

    /// <summary>Read from the deprecated, world-readable machine environment variable.</summary>
    LegacyEnvironment,

    /// <summary>A store entry exists but was refused (unsafe permissions, link, corrupt, wrong name). No value.</summary>
    Refused,
}

/// <summary>The result of one secret lookup. <see cref="Message"/> is for the service log, never the value.</summary>
public sealed record SecretLookup(string? Value, SecretOrigin Origin, string? Message)
{
    /// <summary>True when the lookup must be logged as an error (a store entry was refused).</summary>
    public bool IsCritical => Origin == SecretOrigin.Refused;
}

/// <summary>
/// The service's protected secret store: one DPAPI (machine scope) blob per secret in
/// <c>&lt;data dir&gt;\secrets\&lt;Name&gt;.bin</c>, written by <c>installer\Set-WardenSecret.ps1</c>.
/// </summary>
/// <remarks>
/// <para>Why a file under the data directory rather than the service's registry <c>Parameters</c> key:
/// the data directory is already the folder the installer locks to SYSTEM + Administrators, and the service
/// re-applies that lock on startup; a <c>Services\WardenAgent\Parameters</c> key inherits <c>Users: Read</c> from
/// the <c>Services</c> key unless someone remembers to break inheritance, and nothing would re-check it. The
/// file is also DPAPI-encrypted, so a backup or an offline disk image does not reveal the key.</para>
/// <para>Before a value is used, the file, the <c>secrets</c> folder and the data directory must be owned by
/// SYSTEM, Administrators or TrustedInstaller, must not be links or junctions, and no other account may read or
/// change them. A store entry that fails any check is <see cref="SecretOrigin.Refused"/>: no value, and no fallback
/// to the environment (an administrator has to fix it).</para>
/// <para>Each blob is bound to its name through DPAPI entropy (<see cref="EntropyFor"/>), so a blob copied to
/// another name does not decrypt.</para>
/// </remarks>
public sealed class WardenSecretStore
{
    /// <summary>The VirusTotal API key.</summary>
    public const string VirusTotalApiKey = "VirusTotalApiKey";

    /// <summary>The Anthropic API key.</summary>
    public const string AnthropicApiKey = "AnthropicApiKey";

    /// <summary>The SHA-256 (hex) the ML model file must match.</summary>
    public const string MlModelSha256 = "MlModelSha256";

    /// <summary>Largest blob read from disk.</summary>
    public const int MaxBlobBytes = 64 * 1024;

    private const string TrustedInstallerSid = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464";

    // Any right that reads the secret, changes it, or changes who can: refused for every untrusted account.
    private const int GenericAll = 0x10000000;
    private const int GenericExecute = 0x20000000;
    private const int GenericWrite = 0x40000000;
    private const int GenericRead = unchecked((int)0x80000000);
    // ReadData 0x1 | WriteData 0x2 | AppendData 0x4 | ReadEA 0x8 | WriteEA 0x10 | DeleteChild 0x40
    // | WriteAttributes 0x100 | Delete 0x10000 | WriteDAC 0x40000 | WriteOwner 0x80000.
    private const int SensitiveMask = 0x1 | 0x2 | 0x4 | 0x8 | 0x10 | 0x40 | 0x100 | 0x10000 | 0x40000 | 0x80000
        | GenericAll | GenericExecute | GenericWrite | GenericRead;

    private readonly string _dataDirectory;
    private readonly ISecretUnprotector _unprotector;
    private readonly TrustedFileChain.SddlReader? _readSddl;

    /// <param name="dataDirectory">The Warden data directory (the top of the permission walk).</param>
    /// <param name="unprotector">DPAPI by default; tests inject a fake.</param>
    /// <param name="readSddl">File-system reader by default; tests inject SDDL.</param>
    public WardenSecretStore(string dataDirectory, ISecretUnprotector? unprotector = null, TrustedFileChain.SddlReader? readSddl = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(dataDirectory);
        _dataDirectory = dataDirectory;
        _unprotector = unprotector ?? new DpapiMachineProtector();
        _readSddl = readSddl;
        SecretsDirectory = Path.Combine(dataDirectory, "secrets");
    }

    /// <summary><c>&lt;data dir&gt;\secrets</c>.</summary>
    public string SecretsDirectory { get; }

    /// <summary>The file a secret is stored in.</summary>
    public string PathFor(string name)
    {
        ValidateName(name);
        return Path.Combine(SecretsDirectory, name + ".bin");
    }

    /// <summary>DPAPI entropy binding a blob to its secret name (the script uses the same string).</summary>
    public static byte[] EntropyFor(string name)
    {
        ValidateName(name);
        return Encoding.UTF8.GetBytes("Warden.Secret.v1:" + name);
    }

    /// <summary>Reads a secret from the store only.</summary>
    public SecretLookup Get(string name)
    {
        string path = PathFor(name);
        if (!OperatingSystem.IsWindows() || !File.Exists(path))
        {
            return new SecretLookup(null, SecretOrigin.None, null);
        }

        string? problem = TrustedFileChain.FindProblem(path, DescribeStrict, _dataDirectory, _readSddl);
        if (problem is not null)
        {
            return Refused(name, problem);
        }

        byte[] blob;
        try
        {
            using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
            if (fs.Length is 0 or > MaxBlobBytes)
            {
                return Refused(name, $"the file is {fs.Length} bytes");
            }
            blob = new byte[fs.Length];
            fs.ReadExactly(blob);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return Refused(name, $"it could not be read ({ex.GetType().Name})");
        }

        string value;
        try
        {
            byte[] plain = _unprotector.Unprotect(blob, EntropyFor(name));
            value = Encoding.UTF8.GetString(plain).Trim();
            Array.Clear(plain);
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            return Refused(name, $"it could not be decrypted on this machine ({ex.GetType().Name})");
        }
        if (value.Length == 0)
        {
            return Refused(name, "it is empty");
        }
        return new SecretLookup(value, SecretOrigin.Store, null);
    }

    /// <summary>
    /// Reads a secret from the store; when the store has no entry, falls back to the deprecated machine
    /// environment variable <paramref name="legacyVariable"/> and returns a warning saying it is world-readable.
    /// A <see cref="SecretOrigin.Refused"/> store entry never falls back.
    /// </summary>
    public SecretLookup GetWithLegacyFallback(string name, string legacyVariable, Func<string, string?> readEnvironment)
    {
        ArgumentNullException.ThrowIfNull(readEnvironment);
        SecretLookup stored = Get(name);
        if (stored.Origin != SecretOrigin.None)
        {
            return stored;
        }

        string? legacy = readEnvironment(legacyVariable);
        if (string.IsNullOrWhiteSpace(legacy))
        {
            return stored;
        }
        return new SecretLookup(legacy.Trim(), SecretOrigin.LegacyEnvironment,
            $"{legacyVariable} is set as an environment variable. Machine environment variables are stored in "
            + "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment, which every user can read, and are "
            + $"inherited by every process. This fallback is deprecated: store the value with "
            + $"'installer\\Set-WardenSecret.ps1 -Name {name}' and remove the variable.");
    }

    /// <summary>
    /// Strict policy for every object on the secret's path (file, <c>secrets</c>, data directory): a trusted
    /// owner and no read, write or permission rights for anyone else. Exposed for tests.
    /// </summary>
    public static string? DescribeStrict(string path, string? sddl, ChainRole role)
    {
        if (!OperatingSystem.IsWindows())
        {
            return "permissions can only be verified on Windows";
        }
        if (string.IsNullOrEmpty(sddl))
        {
            return $"the permissions of {path} could not be read";
        }

        RawSecurityDescriptor sd;
        try
        {
            sd = new RawSecurityDescriptor(sddl);
        }
        catch (ArgumentException)
        {
            return $"the permissions of {path} could not be parsed";
        }

        if (sd.Owner is null || !IsTrusted(sd.Owner))
        {
            return $"{path} is owned by {sd.Owner?.Value ?? "nobody"}, not SYSTEM or Administrators";
        }
        if (sd.DiscretionaryAcl is null)
        {
            return $"{path} has no access list (everyone has full access)";
        }
        foreach (GenericAce ace in sd.DiscretionaryAcl)
        {
            if (ace is not QualifiedAce known
                || known.AceQualifier != AceQualifier.AccessAllowed
                || (ace.AceFlags & AceFlags.InheritOnly) != 0
                || (known.AccessMask & SensitiveMask) == 0
                || IsTrusted(known.SecurityIdentifier))
            {
                continue;
            }
            return $"{known.SecurityIdentifier.Value} can read or change {path}";
        }
        return null;
    }

    private static SecretLookup Refused(string name, string reason) =>
        new(null, SecretOrigin.Refused,
            $"The stored secret '{name}' was NOT used because {reason}. Re-run installer\\Set-WardenSecret.ps1 -Name {name} "
            + "as an administrator to rewrite it with the right permissions.");

    [SupportedOSPlatform("windows")]
    private static bool IsTrusted(SecurityIdentifier sid) =>
        sid.IsWellKnown(WellKnownSidType.LocalSystemSid)
        || sid.IsWellKnown(WellKnownSidType.BuiltinAdministratorsSid)
        || string.Equals(sid.Value, TrustedInstallerSid, StringComparison.OrdinalIgnoreCase);

    private static void ValidateName(string name)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(name);
        foreach (char c in name)
        {
            if (!char.IsAsciiLetterOrDigit(c))
            {
                throw new ArgumentException("A secret name is ASCII letters and digits only.", nameof(name));
            }
        }
    }
}
