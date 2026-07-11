using System.Collections.Immutable;

namespace Warden.WebApps;

/// <summary>
/// Pure, multi-signal, static-first / runtime-confirmed web-app scorer. No I/O — it operates only on
/// the collected <see cref="WebAppStaticInput"/> / <see cref="WebAppRuntimeInput"/>, which makes the
/// (load-bearing) scoring logic fully unit-testable. An app is web-facing when the combined score
/// reaches <see cref="WebFacingThreshold"/>.
/// </summary>
public static class WebAppScorer
{
    /// <summary>Combined static + runtime score at/above which the app is classified web-facing.</summary>
    public const int WebFacingThreshold = 90;

    // Lower-case module names by engine family.
    private static readonly string[] Webview2Modules = { "webview2loader.dll", "microsoft.web.webview2.core.dll" };
    private static readonly string[] MshtmlModules = { "mshtml.dll", "ieframe.dll", "urlmon.dll", "shdocvw.dll" };
    private static readonly string[] ChromiumRuntimeModules =
        { "chrome_elf.dll", "ffmpeg.dll", "libegl.dll", "libglesv2.dll", "vk_swiftshader.dll" };

    /// <summary>Classify from static signals only.</summary>
    public static WebAppClassification ClassifyStatic(string appPath, WebAppStaticInput input, DateTimeOffset now)
    {
        ImmutableArray<WebAppSignal> signals = ScoreStatic(input);
        return Build(appPath, signals, ImmutableArray<WebAppSignal>.Empty, now);
    }

    /// <summary>Classify from static + runtime signals (the upgraded verdict once the app is running).</summary>
    public static WebAppClassification ClassifyWithRuntime(
        string appPath, WebAppStaticInput staticInput, WebAppRuntimeInput runtimeInput, DateTimeOffset now)
    {
        ImmutableArray<WebAppSignal> staticSignals = ScoreStatic(staticInput);
        ImmutableArray<WebAppSignal> runtimeSignals = ScoreRuntime(runtimeInput);
        return Build(appPath, staticSignals, runtimeSignals, now);
    }

    /// <summary>Compute the static signals for an input (public for testing).</summary>
    public static ImmutableArray<WebAppSignal> ScoreStatic(WebAppStaticInput input)
    {
        ImmutableArray<WebAppSignal>.Builder s = ImmutableArray.CreateBuilder<WebAppSignal>();

        // --- PE import table references a webview DLL -------------------------------------------------
        if (HasModule(input.ImportedModules, "libcef.dll"))
        {
            s.Add(new WebAppSignal("Imports libcef.dll (CEF)", 100, WebAppEngine.Cef));
        }
        if (HasAny(input.ImportedModules, Webview2Modules))
        {
            s.Add(new WebAppSignal("Imports the WebView2 loader", 100, WebAppEngine.WebView2));
        }
        if (HasAny(input.ImportedModules, MshtmlModules))
        {
            // Legacy Trident. urlmon/shdocvw are used by non-browsers too, so this is a weaker signal.
            s.Add(new WebAppSignal("Imports a legacy Trident/MSHTML DLL", 60, WebAppEngine.Mshtml));
        }

        // --- Directory-sibling scan ------------------------------------------------------------------
        bool hasAsar = Has(input.SiblingFileNames, "app.asar");
        bool hasPak = input.SiblingFileNames.Any(f => f.EndsWith(".pak", StringComparison.Ordinal));
        bool hasIcu = Has(input.SiblingFileNames, "icudtl.dat");
        if (hasAsar && hasPak && hasIcu)
        {
            // app.asar + a .pak + icudtl.dat is near-definitive Electron.
            s.Add(new WebAppSignal("Ships app.asar + *.pak + icudtl.dat (Electron)", 100, WebAppEngine.Electron));
        }
        else if (hasIcu && hasPak)
        {
            // Chromium runtime without the Electron archive — CEF or an embedded Chromium.
            s.Add(new WebAppSignal("Ships a Chromium runtime (*.pak + icudtl.dat)", 60, WebAppEngine.Cef));
        }
        if (Has(input.SiblingFileNames, "libcef.dll") || Has(input.SiblingFileNames, "cef.pak"))
        {
            s.Add(new WebAppSignal("Ships libcef.dll / cef.pak (CEF)", 100, WebAppEngine.Cef));
        }

        // --- PE version resources --------------------------------------------------------------------
        if (string.Equals(input.VersionOriginalFilename, "electron.exe", StringComparison.OrdinalIgnoreCase))
        {
            s.Add(new WebAppSignal("Version resource OriginalFilename = electron.exe", 70, WebAppEngine.Electron));
        }
        if (input.VersionProductName is not null)
        {
            if (input.VersionProductName.Contains("Chromium", StringComparison.OrdinalIgnoreCase))
            {
                s.Add(new WebAppSignal("Version resource ProductName mentions Chromium", 70, WebAppEngine.Electron));
            }
            else if (input.VersionProductName.Contains("WebView2", StringComparison.OrdinalIgnoreCase))
            {
                s.Add(new WebAppSignal("Version resource ProductName mentions WebView2", 70, WebAppEngine.WebView2));
            }
        }

        // --- Registry URL-scheme handlers ------------------------------------------------------------
        if (input.IsRegisteredUrlHandler)
        {
            s.Add(new WebAppSignal("Registered http/https protocol handler", 90, WebAppEngine.None));
        }
        else if (input.OtherSchemeHandlerCount > 0)
        {
            s.Add(new WebAppSignal($"Registered handler for {input.OtherSchemeHandlerCount} URL scheme(s)", 40, WebAppEngine.None));
        }

        return s.ToImmutable();
    }

    /// <summary>Compute the runtime signals for an input (public for testing).</summary>
    public static ImmutableArray<WebAppSignal> ScoreRuntime(WebAppRuntimeInput input)
    {
        ImmutableArray<WebAppSignal>.Builder s = ImmutableArray.CreateBuilder<WebAppSignal>();

        bool hasWebView2Child = !input.ChildImageNames.IsDefaultOrEmpty
            && input.ChildImageNames.Any(c => string.Equals(c, "msedgewebview2.exe", StringComparison.OrdinalIgnoreCase));
        if (hasWebView2Child)
        {
            s.Add(new WebAppSignal("Spawns msedgewebview2.exe", 80, WebAppEngine.WebView2));
        }
        else if (input.HasRendererChild)
        {
            s.Add(new WebAppSignal("Spawns a --type=renderer child", 80, WebAppEngine.None));
        }

        if (input.HasEbWebViewFolder)
        {
            s.Add(new WebAppSignal("Has an EBWebView user-data folder", 60, WebAppEngine.WebView2));
        }

        if (!input.LoadedModuleNames.IsDefaultOrEmpty && HasAny(input.LoadedModuleNames, ChromiumRuntimeModules))
        {
            s.Add(new WebAppSignal("Loaded Chromium runtime modules", 40, WebAppEngine.None));
        }

        return s.ToImmutable();
    }

    private static WebAppClassification Build(
        string appPath,
        ImmutableArray<WebAppSignal> staticSignals,
        ImmutableArray<WebAppSignal> runtimeSignals,
        DateTimeOffset now)
    {
        int staticScore = staticSignals.Sum(x => x.Weight);
        int runtimeScore = runtimeSignals.Sum(x => x.Weight);
        ImmutableArray<WebAppSignal> all = staticSignals.AddRange(runtimeSignals);
        WebAppEngine engine = DominantEngine(all);
        int total = staticScore + runtimeScore;

        return new WebAppClassification(
            appPath, engine, staticScore, runtimeScore, total >= WebFacingThreshold, all, now);
    }

    /// <summary>The engine of the single highest-weight engine-attributed signal (None if none).</summary>
    private static WebAppEngine DominantEngine(ImmutableArray<WebAppSignal> signals)
    {
        WebAppEngine engine = WebAppEngine.None;
        int best = -1;
        foreach (WebAppSignal sig in signals)
        {
            if (sig.Engine != WebAppEngine.None && sig.Weight > best)
            {
                best = sig.Weight;
                engine = sig.Engine;
            }
        }
        return engine;
    }

    private static bool Has(ImmutableArray<string> items, string value) =>
        !items.IsDefaultOrEmpty && items.Any(i => string.Equals(i, value, StringComparison.OrdinalIgnoreCase));

    private static bool HasModule(ImmutableArray<string> modules, string value) => Has(modules, value);

    private static bool HasAny(ImmutableArray<string> items, string[] values) =>
        !items.IsDefaultOrEmpty && items.Any(i => values.Contains(i, StringComparer.OrdinalIgnoreCase));
}
