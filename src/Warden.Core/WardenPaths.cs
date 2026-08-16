namespace Warden.Core;

/// <summary>
/// The single source of truth for where Warden keeps its runtime state. Every module derives its files
/// from <see cref="DataDirectory"/> so the installer's <c>-DataDir</c> (published as the machine-scoped
/// <c>WARDEN_DATA_DIR</c> environment variable) moves <i>everything</i> — database, quarantine, WDAC work
/// dir, snapshots, ML model, logs — and the hardener locks the directory that is actually in use.
/// </summary>
public static class WardenPaths
{
    /// <summary>Machine-scoped environment variable naming the data directory (set by the installer).</summary>
    public const string DataDirectoryEnvironmentVariable = "WARDEN_DATA_DIR";

    /// <summary>Default: <c>%ProgramData%\Warden</c>.</summary>
    public static string DefaultDataDirectory { get; } =
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "Warden");

    /// <summary>
    /// The data directory: <c>WARDEN_DATA_DIR</c> when it is a rooted local path, else the default. The
    /// variable is Machine-scoped (only administrators can set it), so honouring it does not widen the
    /// trust boundary; a relative/UNC/malformed value is ignored rather than trusted.
    /// </summary>
    public static string DataDirectory => Resolve(Environment.GetEnvironmentVariable(DataDirectoryEnvironmentVariable));

    /// <summary>A path under the data directory.</summary>
    public static string Under(params string[] parts)
    {
        ArgumentNullException.ThrowIfNull(parts);
        return Path.Combine(new[] { DataDirectory }.Concat(parts).ToArray());
    }

    /// <summary>Pure resolution used by <see cref="DataDirectory"/> (exposed for tests).</summary>
    public static string Resolve(string? configured)
    {
        if (string.IsNullOrWhiteSpace(configured))
        {
            return DefaultDataDirectory;
        }

        try
        {
            string trimmed = configured.Trim();
            // Must be fully qualified (drive + root) BEFORE canonicalization: a relative or drive-less value
            // would silently resolve against the service's working directory/drive — never what anyone meant.
            if (!Path.IsPathFullyQualified(trimmed) || trimmed.StartsWith(@"\\", StringComparison.Ordinal))
            {
                return DefaultDataDirectory;
            }

            string full = Path.GetFullPath(trimmed);
            if (!Path.IsPathRooted(full) || full.StartsWith(@"\\", StringComparison.Ordinal))
            {
                return DefaultDataDirectory;
            }

            // A bare drive root would be locked down by the hardener — never accept that.
            string? root = Path.GetPathRoot(full);
            if (root is not null && string.Equals(root.TrimEnd(Path.DirectorySeparatorChar), full.TrimEnd(Path.DirectorySeparatorChar), StringComparison.OrdinalIgnoreCase))
            {
                return DefaultDataDirectory;
            }

            return full.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        }
        catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException)
        {
            return DefaultDataDirectory;
        }
    }
}
