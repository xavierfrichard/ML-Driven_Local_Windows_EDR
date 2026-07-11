using System.Collections.Immutable;

namespace Warden.WebApps;

/// <summary>
/// The web-rendering engine a classified app is built on. This is the "Web Apps" panel's key
/// improvement over CyberLock, which only recognizes classic browsers — here we identify modern
/// JavaScript/WebView apps (Claude.exe, Slack, Discord, VS Code) by their engine.
/// </summary>
public enum WebAppEngine
{
    /// <summary>No web-rendering engine detected.</summary>
    None = 0,

    /// <summary>Electron (Chromium + Node, ships app.asar + Chromium runtime).</summary>
    Electron,

    /// <summary>Microsoft Edge WebView2 (also the host for many Tauri / WinUI apps).</summary>
    WebView2,

    /// <summary>Chromium Embedded Framework (libcef.dll + cef.pak).</summary>
    Cef,

    /// <summary>Tauri (Rust shell over the system WebView; on Windows that is WebView2).</summary>
    Tauri,

    /// <summary>Legacy Trident / MSHTML (Internet Explorer engine).</summary>
    Mshtml,
}

/// <summary>One matched web-facing indicator and the weight it contributes to the score.</summary>
/// <param name="Name">Short human-readable indicator, shown in the panel's signals list.</param>
/// <param name="Weight">Points this signal contributes.</param>
/// <param name="Engine">The engine this signal points at (<see cref="WebAppEngine.None"/> if generic).</param>
public sealed record WebAppSignal(string Name, int Weight, WebAppEngine Engine);

/// <summary>
/// Static (pre-execution, on-the-file) inputs to the classifier. Collected by
/// <see cref="IWebAppInputCollector"/>; the scoring over them (<see cref="WebAppScorer"/>) is pure.
/// </summary>
/// <param name="ImageName">The exe file name, lower-cased.</param>
/// <param name="ImportedModules">Lower-cased DLL names from the PE import (and delay-import) table.</param>
/// <param name="SiblingFileNames">
/// Lower-cased file names in the exe's directory <b>and</b> its <c>resources</c> subfolder (where
/// Electron places <c>app.asar</c>).
/// </param>
/// <param name="VersionOriginalFilename">PE version resource OriginalFilename, if any.</param>
/// <param name="VersionProductName">PE version resource ProductName, if any.</param>
/// <param name="IsRegisteredUrlHandler">True if the exe is a registered http/https shell-open handler.</param>
/// <param name="OtherSchemeHandlerCount">Count of other URL scheme handlers the exe is registered for.</param>
public sealed record WebAppStaticInput(
    string ImageName,
    ImmutableArray<string> ImportedModules,
    ImmutableArray<string> SiblingFileNames,
    string? VersionOriginalFilename,
    string? VersionProductName,
    bool IsRegisteredUrlHandler,
    int OtherSchemeHandlerCount);

/// <summary>
/// Runtime (once-running) inputs that upgrade a verdict. Collected by
/// <see cref="IWebAppRuntimeCollector"/>; the scoring is pure.
/// </summary>
/// <param name="ChildImageNames">Lower-cased image names of child processes.</param>
/// <param name="HasRendererChild">True if any child was launched with a <c>--type=renderer</c> flag.</param>
/// <param name="HasEbWebViewFolder">True if an <c>EBWebView</c> WebView2 user-data folder exists near the app.</param>
/// <param name="LoadedModuleNames">Lower-cased names of modules loaded into the running process.</param>
public sealed record WebAppRuntimeInput(
    ImmutableArray<string> ChildImageNames,
    bool HasRendererChild,
    bool HasEbWebViewFolder,
    ImmutableArray<string> LoadedModuleNames);

/// <summary>The classifier's verdict for an app, persisted to the Web Apps panel and cached by path.</summary>
/// <param name="AppPath">Full path to the classified exe.</param>
/// <param name="Engine">The dominant detected engine.</param>
/// <param name="StaticScore">Points from static (on-file) signals.</param>
/// <param name="RuntimeScore">Points from runtime signals (0 until confirmed at runtime).</param>
/// <param name="IsWebFacing">True when <see cref="TotalScore"/> ≥ <see cref="WebAppScorer.WebFacingThreshold"/>.</param>
/// <param name="Signals">The individual matched signals (for display and audit).</param>
/// <param name="Timestamp">When the classification was produced.</param>
public sealed record WebAppClassification(
    string AppPath,
    WebAppEngine Engine,
    int StaticScore,
    int RuntimeScore,
    bool IsWebFacing,
    ImmutableArray<WebAppSignal> Signals,
    DateTimeOffset Timestamp)
{
    /// <summary>Combined static + runtime score.</summary>
    public int TotalScore => StaticScore + RuntimeScore;
}
