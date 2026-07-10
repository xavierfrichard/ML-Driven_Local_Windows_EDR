using System.Runtime.InteropServices;
using System.Text;

namespace Warden.Spike;

/// <summary>
/// Path-normalization helpers shared by the CodeIntegrity and Kernel-Process sessions. WDAC block
/// events (and, depending on the OS build, the NT Kernel Logger) report NT device paths
/// (<c>\Device\HarddiskVolumeN\...</c>) rather than DOS paths (<c>C:\...</c>); these map device
/// prefixes to drive letters and compare two image paths robustly.
/// </summary>
internal static class PathUtil
{
    /// <summary>
    /// Converts an NT device path (<c>\Device\HarddiskVolume3\Users\x\a.exe</c>) to a DOS path
    /// (<c>C:\Users\x\a.exe</c>). Already-DOS paths and <c>\??\</c> / <c>\\?\</c>-prefixed paths are
    /// handled. Unmappable paths (network <c>\Device\Mup\...</c>, unknown volumes) are returned unchanged.
    /// </summary>
    public static string DevicePathToDosPath(string path)
    {
        if (string.IsNullOrEmpty(path))
        {
            return path ?? string.Empty;
        }

        // Strip NT object-manager prefixes.
        if (path.StartsWith(@"\??\", StringComparison.Ordinal) ||
            path.StartsWith(@"\\?\", StringComparison.Ordinal))
        {
            path = path.Substring(4);
        }

        // Already a DOS path (X:\...).
        if (path.Length >= 2 && char.IsLetter(path[0]) && path[1] == ':')
        {
            return path;
        }

        // Map \Device\HarddiskVolumeN\... via the drive -> device table (longest device first).
        foreach ((string dos, string device) in DriveMap.Value)
        {
            if (path.StartsWith(device, StringComparison.OrdinalIgnoreCase) &&
                (path.Length == device.Length || path[device.Length] == '\\'))
            {
                return dos + path.Substring(device.Length);
            }
        }

        return path; // unmapped (network share, unknown volume) — leave as-is
    }

    /// <summary>
    /// True if two image paths refer to the same file. Both sides are device-normalized first; if the
    /// full paths still differ (normalization edge cases), falls back to a non-empty file-name match.
    /// </summary>
    public static bool PathsEqual(string a, string b)
    {
        if (string.IsNullOrEmpty(a) || string.IsNullOrEmpty(b))
        {
            return false;
        }

        string na = DevicePathToDosPath(a);
        string nb = DevicePathToDosPath(b);
        if (string.Equals(na, nb, StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        string fa = SafeFileName(na);
        string fb = SafeFileName(nb);
        return fa.Length > 0 && string.Equals(fa, fb, StringComparison.OrdinalIgnoreCase);
    }

    private static string SafeFileName(string path)
    {
        try { return Path.GetFileName(path); }
        catch (ArgumentException) { return string.Empty; }
    }

    // Drive-letter -> NT device path (e.g. "C:" -> "\Device\HarddiskVolume3"), longest device first so
    // a longer prefix wins over a shorter collision. Built once; volume topology is stable per boot.
    private static readonly Lazy<IReadOnlyList<(string Dos, string Device)>> DriveMap = new(BuildDriveMap);

    private static List<(string Dos, string Device)> BuildDriveMap()
    {
        var map = new List<(string, string)>();
        var buffer = new StringBuilder(1024);

        for (char letter = 'A'; letter <= 'Z'; letter++)
        {
            string dos = letter + ":";
            buffer.Clear();
            if (QueryDosDevice(dos, buffer, buffer.Capacity) == 0)
            {
                continue; // no such drive
            }

            // QueryDosDevice returns a double-null-terminated list; take the first entry.
            string device = buffer.ToString();
            int nul = device.IndexOf('\0');
            if (nul >= 0)
            {
                device = device.Substring(0, nul);
            }

            if (device.Length > 0)
            {
                map.Add((dos, device));
            }
        }

        map.Sort((x, y) => y.Item2.Length.CompareTo(x.Item2.Length));
        return map;
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern int QueryDosDevice(string lpDeviceName, StringBuilder lpTargetPath, int ucchMax);
}
