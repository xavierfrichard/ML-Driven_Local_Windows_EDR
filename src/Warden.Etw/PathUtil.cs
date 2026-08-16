using System.Runtime.InteropServices;
using System.Text;

namespace Warden.Etw;

/// <summary>
/// Path-normalization helpers. WDAC block events (and, depending on the OS build, the NT Kernel
/// Logger) report NT device paths (<c>\Device\HarddiskVolumeN\...</c>) rather than DOS paths
/// (<c>C:\...</c>); these map device prefixes to drive letters and compare two image paths robustly.
/// </summary>
public static class PathUtil
{
    /// <summary>
    /// Converts an NT device path (<c>\Device\HarddiskVolume3\Users\x\a.exe</c>) to a DOS path
    /// (<c>C:\Users\x\a.exe</c>). Already-DOS and <c>\??\</c> / <c>\\?\</c>-prefixed paths are handled;
    /// unmappable paths (network <c>\Device\Mup\...</c>, unknown volumes) are returned unchanged.
    /// </summary>
    public static string DevicePathToDosPath(string path)
    {
        if (string.IsNullOrEmpty(path))
        {
            return path ?? string.Empty;
        }

        if (path.StartsWith(@"\??\", StringComparison.Ordinal) ||
            path.StartsWith(@"\\?\", StringComparison.Ordinal))
        {
            path = path.Substring(4);
        }

        if (path.Length >= 2 && char.IsLetter(path[0]) && path[1] == ':')
        {
            return path;
        }

        string? mapped = TryMap(path, Volatile.Read(ref _driveMap) ?? RefreshDriveMap());
        if (mapped is not null)
        {
            return mapped;
        }

        // Unknown device: a volume mounted after the map was built (USB, VHD, BitLocker unlock). Rebuild
        // once (rate-limited) and retry, otherwise return the path unchanged.
        if (ShouldRefresh())
        {
            mapped = TryMap(path, RefreshDriveMap());
            if (mapped is not null)
            {
                return mapped;
            }
        }

        return path;
    }

    private static string? TryMap(string path, IReadOnlyList<(string Dos, string Device)> map)
    {
        foreach ((string dos, string device) in map)
        {
            if (path.StartsWith(device, StringComparison.OrdinalIgnoreCase) &&
                (path.Length == device.Length || path[device.Length] == '\\'))
            {
                return dos + path.Substring(device.Length);
            }
        }
        return null;
    }

    private static readonly TimeSpan RefreshInterval = TimeSpan.FromSeconds(30);
    private static long _lastRefreshTicks;
    private static List<(string Dos, string Device)>? _driveMap;

    private static bool ShouldRefresh()
    {
        long now = Environment.TickCount64;
        long last = Volatile.Read(ref _lastRefreshTicks);
        return now - last >= (long)RefreshInterval.TotalMilliseconds;
    }

    private static List<(string Dos, string Device)> RefreshDriveMap()
    {
        Volatile.Write(ref _lastRefreshTicks, Environment.TickCount64);
        List<(string Dos, string Device)> map = BuildDriveMap();
        Volatile.Write(ref _driveMap, map);
        return map;
    }

    /// <summary>
    /// True only if two image paths are the same <b>full path</b> after device normalization. This is the
    /// predicate to use for block↔process correlation: a file-name-only match would let a same-named decoy
    /// started elsewhere lend its command line / parent / ancestry to the blocked file.
    /// </summary>
    public static bool PathsEqualStrict(string a, string b)
    {
        if (string.IsNullOrEmpty(a) || string.IsNullOrEmpty(b))
        {
            return false;
        }

        return string.Equals(DevicePathToDosPath(a), DevicePathToDosPath(b), StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// True if two image paths <i>probably</i> refer to the same file: same normalized full path, or —
    /// as a display-oriented fallback — the same non-empty file name. Do NOT use this for correlation
    /// (see <see cref="PathsEqualStrict"/>).
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
                continue;
            }

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
