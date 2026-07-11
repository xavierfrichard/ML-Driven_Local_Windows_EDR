using System.Threading;
using System.Windows;
using System.Windows.Controls;
using Hardcodet.Wpf.TaskbarNotification;
using Warden.Ipc;

namespace Warden.Ui;

/// <summary>
/// Interaction logic for the Warden tray application.
/// </summary>
/// <remarks>
/// This process runs in the interactive user session. The Warden service lives in session 0 and
/// cannot show UI, so it hands blocked-launch prompts to this process over a named pipe. The app is
/// headless at startup: it owns only a tray icon and the <see cref="PromptPipeClient"/>. Windows are
/// created on demand when the service asks for a decision.
/// </remarks>
public partial class App : Application
{
    /// <summary>Name of the single-instance guard mutex. Global-scoped so it also blocks other sessions.</summary>
    private const string SingleInstanceMutexName = "Global\\WardenAgent.Ui.SingleInstance.v1";

    private Mutex? _singleInstanceMutex;
    private TaskbarIcon? _trayIcon;
    private PromptPipeClient? _pipeClient;

    /// <inheritdoc />
    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);

        // Single-instance guard: if another tray is already running, quietly exit.
        _singleInstanceMutex = new Mutex(initiallyOwned: true, SingleInstanceMutexName, out bool createdNew);
        if (!createdNew)
        {
            _singleInstanceMutex.Dispose();
            _singleInstanceMutex = null;
            Shutdown();
            return;
        }

        _trayIcon = CreateTrayIcon();

        // The pipe client runs on a background loop; each prompt is marshalled to the UI thread here.
        _pipeClient = new PromptPipeClient
        {
            PromptHandler = ShowPromptAsync,
        };
        _pipeClient.Start();
    }

    /// <summary>Builds the tray icon and its context menu.</summary>
    private TaskbarIcon CreateTrayIcon()
    {
        var menu = new ContextMenu();

        var showWhitelist = new MenuItem { Header = "Show Whitelist" };
        showWhitelist.Click += OnShowWhitelist;
        menu.Items.Add(showWhitelist);

        menu.Items.Add(new Separator());

        var exit = new MenuItem { Header = "Exit" };
        exit.Click += OnExitClicked;
        menu.Items.Add(exit);

        return new TaskbarIcon
        {
            ToolTipText = "Warden — zero-trust application control",
            Icon = System.Drawing.SystemIcons.Shield,
            ContextMenu = menu,
        };
    }

    /// <summary>
    /// Marshals a prompt request onto the WPF dispatcher, shows a <see cref="PromptWindow"/>, and
    /// returns the task that completes with the user's (or the timeout's) decision. Any failure
    /// resolves to <see cref="PromptDecision.KeepBlocked"/> so the service fails safe.
    /// </summary>
    private Task<PromptDecision> ShowPromptAsync(PromptRequest request, CancellationToken cancellationToken)
    {
        try
        {
            return Dispatcher.InvokeAsync(() =>
            {
                var window = new PromptWindow(request);
                window.Show();
                return window.Completion;
            }).Task.Unwrap();
        }
        catch
        {
            // Dispatcher shutting down, or window creation failed: fail safe.
            return Task.FromResult(PromptDecision.KeepBlocked);
        }
    }

    private void OnShowWhitelist(object sender, RoutedEventArgs e)
    {
        // Stub for Phase 1: the whitelist management window is not implemented yet.
        MessageBox.Show(
            "Whitelist management is not available in this build.",
            "Warden",
            MessageBoxButton.OK,
            MessageBoxImage.Information);
    }

    private void OnExitClicked(object sender, RoutedEventArgs e) => Shutdown();

    /// <inheritdoc />
    protected override void OnExit(ExitEventArgs e)
    {
        // Best-effort teardown; never throw out of shutdown.
        try
        {
            _pipeClient?.DisposeAsync().AsTask().GetAwaiter().GetResult();
        }
        catch
        {
            // ignored
        }

        _trayIcon?.Dispose();
        _trayIcon = null;

        _singleInstanceMutex?.Dispose();
        _singleInstanceMutex = null;

        base.OnExit(e);
    }
}
