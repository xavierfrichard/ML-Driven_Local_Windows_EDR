using System.Windows;
using System.Windows.Controls;
using Microsoft.Win32;
using Warden.Ipc;
using Warden.Storage;
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

        // Create and set the ViewModel as DataContext
        _viewModel = new MainWindowViewModel();
        DataContext = _viewModel;

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

    // ---- Dialog-based mutation actions ----

    /// <summary>
    /// Opens the Add Rule dialog.
    /// </summary>
    private async void AddRule_Click(object sender, RoutedEventArgs e)
    {
        var dlg = new AddRuleWindow { Owner = this };
        if (dlg.ShowDialog() == true && dlg.Result is { } rule)
        {
            // Envelope: the rule plus the file its hash/publisher came from, so the service can allow-list
            // that file immediately (see RuleAddPayload).
            await _viewModel.MutateAndReloadAsync(
                MgmtOperations.RulesAdd,
                new { Rule = rule, SourcePath = dlg.SourcePath },
                "Rule added.",
                ct => _viewModel.LoadRulesAsync(ct));
            await _viewModel.LoadWhitelistAsync();
        }
    }

    /// <summary>
    /// Deletes the selected rule.
    /// </summary>
    private async void DeleteRule_Click(object sender, RoutedEventArgs e)
    {
        if (_viewModel.SelectedRuleEntry is RuleEntry rule)
        {
            await _viewModel.MutateAndReloadAsync(
                MgmtOperations.RulesDelete,
                new IdPayload(rule.Id),
                "Rule deleted.",
                ct => _viewModel.LoadRulesAsync(ct));
        }
        else
        {
            _viewModel.Status = "Select a rule row to delete.";
        }
    }

    /// <summary>
    /// "Allow file…": pick a blocked executable/DLL and allow it now — the service hash-allow-lists it in
    /// WDAC immediately and records an Allow row, so no fail-then-relaunch cycle is needed.
    /// </summary>
    private async void AllowFile_Click(object sender, RoutedEventArgs e)
    {
        var dlg = new OpenFileDialog
        {
            Title = "Choose a file to allow",
            Filter = "Executables and libraries (*.exe;*.dll;*.ocx;*.cpl;*.scr;*.arx;*.dbx)|*.exe;*.dll;*.ocx;*.cpl;*.scr;*.arx;*.dbx|All files (*.*)|*.*",
            CheckFileExists = true,
            Multiselect = true,
        };
        if (dlg.ShowDialog(this) != true)
        {
            return;
        }

        foreach (string file in dlg.FileNames)
        {
            await _viewModel.MutateAndReloadAsync(
                MgmtOperations.WhitelistAllowFile,
                new AllowFilePayload(file),
                $"{System.IO.Path.GetFileName(file)} allowed.",
                ct => _viewModel.LoadWhitelistAsync(ct));
        }
    }

    /// <summary>
    /// Opens the Add Folder dialog.
    /// </summary>
    private async void AddFolder_Click(object sender, RoutedEventArgs e)
    {
        var dlg = new OpenFolderDialog { Title = "Choose a folder to protect" };
        if (dlg.ShowDialog(this) == true)
        {
            var folder = new ProtectedFolder
            {
                Path = dlg.FolderName,
                Recursive = true,
                MonitorMode = "monitor",
                AddedTs = DateTimeOffset.UtcNow,
            };
            await _viewModel.MutateAndReloadAsync(
                MgmtOperations.FoldersAdd,
                folder,
                "Protected folder added.",
                ct => _viewModel.LoadFoldersAsync(ct));
        }
    }

    /// <summary>
    /// Deletes the selected folder.
    /// </summary>
    private async void DeleteFolder_Click(object sender, RoutedEventArgs e)
    {
        if (_viewModel.SelectedFolderEntry is ProtectedFolder folder)
        {
            await _viewModel.MutateAndReloadAsync(
                MgmtOperations.FoldersDelete,
                new IdPayload(folder.Id),
                "Protected folder removed.",
                ct => _viewModel.LoadFoldersAsync(ct));
        }
        else
        {
            _viewModel.Status = "Select a folder row to delete.";
        }
    }

    /// <summary>
    /// Opens the Add Whitelist dialog.
    /// </summary>
    private async void AddWhitelist_Click(object sender, RoutedEventArgs e)
    {
        var dlg = new AddWhitelistWindow { Owner = this };
        if (dlg.ShowDialog() == true && dlg.Result is { } entry)
        {
            await _viewModel.MutateAndReloadAsync(
                MgmtOperations.WhitelistAdd,
                entry,
                "Whitelist entry saved.",
                ct => _viewModel.LoadWhitelistAsync(ct));
        }
    }

    /// <summary>
    /// Sets the action for the selected whitelist entry.
    /// </summary>
    private async void WhitelistAllow_Click(object sender, RoutedEventArgs e)
    {
        if (_viewModel.SelectedWhitelistEntry is WhitelistEntry entry)
        {
            await _viewModel.MutateAndReloadAsync(
                MgmtOperations.WhitelistSetAction,
                new SetActionPayload(entry.Id, (int)PolicyAction.Allow),
                $"{entry.ProcessName} set to Allow.",
                ct => _viewModel.LoadWhitelistAsync(ct));
        }
        else
        {
            _viewModel.Status = "Select a row first.";
        }
    }

    /// <summary>
    /// Sets the action for the selected whitelist entry to Block.
    /// </summary>
    private async void WhitelistBlock_Click(object sender, RoutedEventArgs e)
    {
        if (_viewModel.SelectedWhitelistEntry is WhitelistEntry entry)
        {
            await _viewModel.MutateAndReloadAsync(
                MgmtOperations.WhitelistSetAction,
                new SetActionPayload(entry.Id, (int)PolicyAction.Block),
                $"{entry.ProcessName} set to Block.",
                ct => _viewModel.LoadWhitelistAsync(ct));
        }
        else
        {
            _viewModel.Status = "Select a row first.";
        }
    }

    /// <summary>
    /// Sets the action for the selected user log entry.
    /// </summary>
    private async void UserLogAllow_Click(object sender, RoutedEventArgs e)
    {
        if (_viewModel.SelectedUserLogEntry is WhitelistEntry entry)
        {
            await _viewModel.MutateAndReloadAsync(
                MgmtOperations.WhitelistSetAction,
                new SetActionPayload(entry.Id, (int)PolicyAction.Allow),
                $"{entry.ProcessName} set to Allow.",
                ct => _viewModel.LoadUserLogAsync(ct));
        }
        else
        {
            _viewModel.Status = "Select a row first.";
        }
    }

    /// <summary>
    /// Sets the action for the selected user log entry to Block.
    /// </summary>
    private async void UserLogBlock_Click(object sender, RoutedEventArgs e)
    {
        if (_viewModel.SelectedUserLogEntry is WhitelistEntry entry)
        {
            await _viewModel.MutateAndReloadAsync(
                MgmtOperations.WhitelistSetAction,
                new SetActionPayload(entry.Id, (int)PolicyAction.Block),
                $"{entry.ProcessName} set to Block.",
                ct => _viewModel.LoadUserLogAsync(ct));
        }
        else
        {
            _viewModel.Status = "Select a row first.";
        }
    }

    // ---- Refresh handlers for each tab ----

    private async void RefreshWhitelist_Click(object sender, RoutedEventArgs e) =>
        await _viewModel.LoadWhitelistAsync();

    private async void RefreshUserLog_Click(object sender, RoutedEventArgs e) =>
        await _viewModel.LoadUserLogAsync();

    private async void RefreshRules_Click(object sender, RoutedEventArgs e) =>
        await _viewModel.LoadRulesAsync();

    private async void RefreshCommandLines_Click(object sender, RoutedEventArgs e) =>
        await _viewModel.LoadCommandLinesAsync();

    private async void RefreshQuarantine_Click(object sender, RoutedEventArgs e) =>
        await _viewModel.LoadQuarantineAsync();

    private async void RefreshChains_Click(object sender, RoutedEventArgs e) =>
        await _viewModel.LoadChainsAsync();

    private async void RefreshFolders_Click(object sender, RoutedEventArgs e) =>
        await _viewModel.LoadFoldersAsync();

    private async void RefreshAdvanced_Click(object sender, RoutedEventArgs e) =>
        await _viewModel.LoadAdvancedAsync();

    private async void RefreshWebApps_Click(object sender, RoutedEventArgs e) =>
        await _viewModel.LoadWebAppsAsync();

    private async void RefreshTamper_Click(object sender, RoutedEventArgs e) =>
        await _viewModel.LoadTamperAsync();
}
