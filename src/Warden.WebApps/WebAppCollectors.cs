using System.Collections.Immutable;
using System.Diagnostics;
using System.Runtime.Versioning;
using Microsoft.Win32;

namespace Warden.WebApps;

/// <summary>Collects the static (on-file) inputs the scorer needs for an app.</summary>
public interface IWebAppInputCollector
{
    /// <summary>Read the PE imports, directory siblings, version resources, and URL-handler registration.</summary>
    WebAppStaticInput CollectStatic(string appPath);

    /// <summary>
    /// Same as <see cref="CollectStatic(string)"/>, but reads file content (PE imports, version resources)
    /// from <paramref name="bytesPath"/> — the immutable snapshot of <paramref name="appPath"/> when one
    /// exists — while location facts (siblings, URL handler) still come from <paramref name="appPath"/>.
    /// </summary>
    WebAppStaticInput CollectStatic(string appPath, string? bytesPath) => CollectStatic(appPath);
}

/// <summary>Collects the runtime inputs the scorer needs for a running app.</summary>
public interface IWebAppRuntimeCollector
{
    /// <summary>
    /// Build runtime input for a running app. Child-process facts are supplied by the caller (the
    /// enforcement path already has them from the ETW attack chain); this collector adds the cheap
    /// filesystem/module checks.
    /// </summary>
    WebAppRuntimeInput CollectRuntime(int pid, string appPath, IEnumerable<string> childImageNames, bool hasRendererChild);
}

/// <summary>Windows implementation: PE parsing (PeNet), directory listing, version resources, registry.</summary>
[SupportedOSPlatform("windows")]
public sealed class WebAppInputCollector : IWebAppInputCollector
{
    private const int MaxSiblingFiles = 512;

    /// <summary>
    /// Largest image whose imports are parsed (the same cap the ML tier uses). The scan runs for every
    /// block on the single decision thread, so an attacker-padded multi-GB image must not be read whole.
    /// </summary>
    public const long MaxImportScanBytes = 64L * 1024 * 1024;

    public WebAppStaticInput CollectStatic(string appPath) => CollectStatic(appPath, bytesPath: null);

    public WebAppStaticInput CollectStatic(string appPath, string? bytesPath)
    {
        string contentPath = string.IsNullOrEmpty(bytesPath) ? appPath : bytesPath;
        string imageName = string.IsNullOrEmpty(appPath) ? string.Empty : Path.GetFileName(appPath).ToLowerInvariant();
        ImmutableArray<string> modules = ImportedModules(contentPath);
        ImmutableArray<string> siblings = Siblings(appPath);
        (string? originalFilename, string? productName) = VersionInfo(contentPath);
        bool isUrlHandler = IsHttpHandler(appPath);

        return new WebAppStaticInput(
            imageName, modules, siblings, originalFilename, productName, isUrlHandler, OtherSchemeHandlerCount: 0);
    }

    private static ImmutableArray<string> ImportedModules(string appPath)
    {
        try
        {
            byte[]? bytes = ReadCapped(appPath, MaxImportScanBytes);
            if (bytes is null || !PeNet.PeFile.IsPeFile(bytes))
            {
                return ImmutableArray<string>.Empty;
            }
            var pe = new PeNet.PeFile(bytes);
            IEnumerable<string> normal = pe.ImportedFunctions?.Select(f => f.DLL) ?? Enumerable.Empty<string>();
            return normal
                .Where(d => !string.IsNullOrEmpty(d))
                .Select(d => d!.ToLowerInvariant())
                .Distinct(StringComparer.Ordinal)
                .ToImmutableArray();
        }
        catch
        {
            return ImmutableArray<string>.Empty;
        }
    }

    /// <summary>
    /// Reads the whole file through one handle when it is at most <paramref name="maxBytes"/>, else null.
    /// The length is taken from the open handle and the read never goes past it, so a file that grows
    /// after the check cannot push the allocation over the cap.
    /// </summary>
    public static byte[]? ReadCapped(string path, long maxBytes)
    {
        using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, bufferSize: 1);
        long length = fs.Length;
        if (length <= 0 || length > maxBytes)
        {
            return null;
        }

        byte[] bytes = new byte[length];
        int total = 0;
        int read;
        while (total < bytes.Length && (read = fs.Read(bytes, total, bytes.Length - total)) > 0)
        {
            total += read;
        }
        return total == bytes.Length ? bytes : null;
    }

    private static ImmutableArray<string> Siblings(string appPath)
    {
        try
        {
            string? dir = Path.GetDirectoryName(appPath);
            if (string.IsNullOrEmpty(dir) || !Directory.Exists(dir))
            {
                return ImmutableArray<string>.Empty;
            }

            var names = new List<string>();
            void Add(string folder)
            {
                if (names.Count >= MaxSiblingFiles || !Directory.Exists(folder))
                {
                    return;
                }
                foreach (string f in Directory.EnumerateFiles(folder))
                {
                    names.Add(Path.GetFileName(f).ToLowerInvariant());
                    if (names.Count >= MaxSiblingFiles)
                    {
                        break;
                    }
                }
            }

            Add(dir);
            Add(Path.Combine(dir, "resources")); // where Electron places app.asar
            return names.Distinct(StringComparer.Ordinal).ToImmutableArray();
        }
        catch
        {
            return ImmutableArray<string>.Empty;
        }
    }

    private static (string? OriginalFilename, string? ProductName) VersionInfo(string appPath)
    {
        try
        {
            FileVersionInfo v = FileVersionInfo.GetVersionInfo(appPath);
            return (v.OriginalFilename, v.ProductName);
        }
        catch
        {
            return (null, null);
        }
    }

    /// <summary>
    /// True if this exe is the registered handler for http/https. Checks the classic
    /// <c>HKCR\http\shell\open\command</c> (and https) default value for a reference to the exe.
    /// Best-effort — a false result never blocks anything; it only lowers the web-facing score.
    /// </summary>
    private static bool IsHttpHandler(string appPath)
    {
        string imageName = Path.GetFileName(appPath);
        foreach (string scheme in new[] { "http", "https" })
        {
            try
            {
                using RegistryKey? cmd = Registry.ClassesRoot.OpenSubKey($@"{scheme}\shell\open\command");
                if (cmd?.GetValue(null) is string command && !string.IsNullOrEmpty(command)
                    && (command.Contains(appPath, StringComparison.OrdinalIgnoreCase)
                        || command.Contains(imageName, StringComparison.OrdinalIgnoreCase)))
                {
                    return true;
                }
            }
            catch
            {
                // registry unreadable — ignore this scheme
            }
        }
        return false;
    }
}

/// <summary>Windows implementation of the runtime collector (EBWebView folder + loaded modules).</summary>
[SupportedOSPlatform("windows")]
public sealed class WebAppRuntimeCollector : IWebAppRuntimeCollector
{
    public WebAppRuntimeInput CollectRuntime(int pid, string appPath, IEnumerable<string> childImageNames, bool hasRendererChild)
    {
        ImmutableArray<string> children = childImageNames is null
            ? ImmutableArray<string>.Empty
            : childImageNames.Where(c => !string.IsNullOrEmpty(c)).Select(c => c.ToLowerInvariant()).ToImmutableArray();

        return new WebAppRuntimeInput(
            children,
            hasRendererChild,
            HasEbWebViewFolder(appPath),
            LoadedModules(pid));
    }

    private static bool HasEbWebViewFolder(string appPath)
    {
        try
        {
            string? dir = Path.GetDirectoryName(appPath);
            return dir is not null && (Directory.Exists(Path.Combine(dir, "EBWebView"))
                || Directory.Exists(Path.Combine(dir, "WebView2", "EBWebView")));
        }
        catch
        {
            return false;
        }
    }

    private static ImmutableArray<string> LoadedModules(int pid)
    {
        if (pid <= 0)
        {
            return ImmutableArray<string>.Empty;
        }
        try
        {
            using Process p = Process.GetProcessById(pid);
            var names = new List<string>();
            foreach (ProcessModule m in p.Modules)
            {
                names.Add(m.ModuleName.ToLowerInvariant());
            }
            return names.Distinct(StringComparer.Ordinal).ToImmutableArray();
        }
        catch
        {
            // process gone / access denied / bitness mismatch — modules unavailable
            return ImmutableArray<string>.Empty;
        }
    }
}
