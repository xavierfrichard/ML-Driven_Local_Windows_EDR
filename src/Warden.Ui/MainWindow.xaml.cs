using System.Windows;
using System.Windows.Controls;
using Warden.Ipc;
using Warden.Storage;
using Warden.Ui.Services;
using Warden.Ui.ViewModels;

namespace Warden.Ui;

/// <summary>
/// The Warden management window: a tab per CyberLock panel. Every read and every edit goes to the
/// service over the management pipe (<see cref="MgmtPipeClient"/>) — the UI never opens the SQLite file,
/// which is ACL-locked to SYSTEM + Administrators by the hardened install. Types from
/// <see cref="Warden.Storage"/> are used only as the wire shape for display.
/// </summary>
/// <remarks>
/// Policy edits require an elevated UI: the service refuses mutations whose caller is not an
/// Administrators member, and says so in the status bar. Reads work either way.
/// </remarks>
public partial class MainWindow : Window
{
    private readonly MainWindowViewModel _viewModel;

    public MainWindow()
    {
        InitializeComponent();

        // Create services
        var dialogService = new DialogService();
        var fileDialogService = new FileDialogService();

        // Create and set the ViewModel as DataContext with injected services
        _viewModel = new MainWindowViewModel(dialogService, fileDialogService);
        DataContext = _viewModel;

        // Set the owner for dialog operations
        _viewModel.SetOwner(this);

        // Set database path text
        DbPathText.Text = @"via WardenAgent (pipe: " + MgmtProtocol.PipeName + ")";

        // Load all data on startup
        Loaded += async (_, _) => await _viewModel.LoadAllAsync();
        Closed += (_, _) => _viewModel.Dispose();

        // Handle mutation button enablement based on admin status
        _viewModel.PropertyChanged += (sender, e) =>
        {
            if (e.PropertyName == nameof(_viewModel.IsAdministrator))
            {
                UpdateMutationButtonEnablement();
            }
        };
    }

    /// <summary>
    /// Updates the enabled state of all mutation buttons based on admin status.
    /// This is called when IsAdministrator changes.
    /// </summary>
    private void UpdateMutationButtonEnablement()
    {
        foreach (Button b in FindMutationButtons(this))
        {
            b.IsEnabled = _viewModel.IsAdministrator;
            b.ToolTip ??= _viewModel.IsAdministrator ? null : MgmtProtocol.ElevationRequired;
        }

        if (!_viewModel.IsAdministrator)
        {
            _viewModel.Status = MgmtProtocol.ElevationRequired;
        }
    }

    // Logical (not visual) tree walk: a TabControl only realizes the selected tab's visuals, but every
    // tab's content is a logical child, so this finds the buttons on unselected tabs too.
    private static IEnumerable<Button> FindMutationButtons(DependencyObject root)
    {
        foreach (object child in LogicalTreeHelper.GetChildren(root))
        {
            if (child is not DependencyObject dep)
            {
                continue;
            }
            if (dep is Button { Tag: "mutation" } b)
            {
                yield return b;
            }
            foreach (Button nested in FindMutationButtons(dep))
            {
                yield return nested;
            }
        }
    }

    // ---- Firewall checkbox handlers (still using events for now, will migrate to commands) ----

    /// <summary>
    /// Applies an inbound/outbound firewall block for the row's app. The grid is reloaded afterwards so
    /// the checkbox always shows the state the service actually persisted — if the change is refused
    /// (for example a seeded exe name that has no full path yet) the box snaps back.
    /// </summary>
    private async void FirewallCheck_Click(object sender, RoutedEventArgs e)
    {
        if (sender is not CheckBox box || box.DataContext is not VulnerableAppRecord app)
        {
            return;
        }

        bool inBlocked = app.FwInBlocked;
        bool outBlocked = app.FwOutBlocked;
        bool value = box.IsChecked == true;

        if (string.Equals(box.Tag as string, "in", StringComparison.Ordinal))
        {
            inBlocked = value;
        }
        else
        {
            outBlocked = value;
        }

        try
        {
            await _viewModel._client.InvokeAsync(
                MgmtOperations.VulnAppSetFirewall,
                new SetFirewallPayload(app.Id, app.AppPath, inBlocked, outBlocked));
            _viewModel.Status = $"Firewall for {app.AppPath}: inbound={inBlocked}, outbound={outBlocked}.";
        }
        catch (Exception ex)
        {
            _viewModel.Status = "Firewall change failed: " + ex.Message;
        }

        await _viewModel.LoadAdvancedAsync();
    }

    // Note: All Click handlers for buttons have been migrated to ViewModel commands.
    // The FirewallCheck_Click handler is still used in XAML for checkbox events.
}
