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

    public WebAppStaticInput CollectStatic(string appPath)
    {
        string imageName = string.IsNullOrEmpty(appPath) ? string.Empty : Path.GetFileName(appPath).ToLowerInvariant();
        ImmutableArray<string> modules = ImportedModules(appPath);
        ImmutableArray<string> siblings = Siblings(appPath);
        (string? originalFilename, string? productName) = VersionInfo(appPath);
        bool isUrlHandler = IsHttpHandler(appPath);

        return new WebAppStaticInput(
            imageName, modules, siblings, originalFilename, productName, isUrlHandler, OtherSchemeHandlerCount: 0);
    }

    private static ImmutableArray<string> ImportedModules(string appPath)
    {
        try
        {
            byte[] bytes = File.ReadAllBytes(appPath);
            if (!PeNet.PeFile.IsPeFile(bytes))
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
