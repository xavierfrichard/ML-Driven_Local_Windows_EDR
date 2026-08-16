using System.Windows;
using System.Windows.Controls;
using Microsoft.Win32;
using Warden.Ipc;
using Warden.Storage;

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
    private readonly MgmtPipeClient _client = new();

    public MainWindow()
    {
        InitializeComponent();

        DbPathText.Text = @"via WardenAgent (pipe: " + MgmtProtocol.PipeName + ")";
        Loaded += async (_, _) => await LoadAllAsync();
        Closed += (_, _) => _client.Dispose();
    }

    private async Task LoadAllAsync()
    {
        await RefreshPrivilegeAsync();
        await LoadWhitelistAsync();
        await LoadUserLogAsync();
        await LoadRulesAsync();
        await LoadCommandLinesAsync();
        await LoadQuarantineAsync();
        await LoadChainsAsync();
        await LoadFoldersAsync();
        await LoadAdvancedAsync();
        await LoadWebAppsAsync();
        await LoadTamperAsync();
        Status("Loaded. Right-click the tray icon and choose Open Warden any time.");
    }

    /// <summary>
    /// Asks the service whether this connection is elevated and greys out every mutating control when it is
    /// not, so the answer is visible up front instead of as a refusal after each click.
    /// </summary>
    private async Task RefreshPrivilegeAsync()
    {
        bool isAdmin;
        try
        {
            isAdmin = await _client.IsAdministratorAsync();
        }
        catch (Exception ex)
        {
            Status(ex.Message);
            isAdmin = false;
        }

        foreach (Button b in FindMutationButtons(this))
        {
            b.IsEnabled = isAdmin;
            b.ToolTip ??= isAdmin ? null : MgmtProtocol.ElevationRequired;
        }

        if (!isAdmin)
        {
            Status(MgmtProtocol.ElevationRequired);
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

    // ---- per-panel loads --------------------------------------------------------------------------

    private Task LoadWhitelistAsync() =>
        SafeLoad<WhitelistEntry>(WhitelistGrid, MgmtOperations.WhitelistList, "Whitelist");

    private Task LoadUserLogAsync() =>
        SafeLoad<WhitelistEntry>(UserLogGrid, MgmtOperations.UserLogList, "User Log");

    private Task LoadRulesAsync() =>
        SafeLoad<RuleEntry>(RulesGrid, MgmtOperations.RulesList, "Rules");

    private Task LoadCommandLinesAsync() =>
        SafeLoad<CommandLineRecord>(CommandLinesGrid, MgmtOperations.CommandLinesList, "Command Lines");

    private Task LoadQuarantineAsync() =>
        SafeLoad<QuarantineRecord>(QuarantineGrid, MgmtOperations.QuarantineList, "Quarantine");

    private Task LoadChainsAsync() =>
        SafeLoad<AttackChainRecord>(ChainsGrid, MgmtOperations.ChainsList, "Attack Chains");

    private Task LoadFoldersAsync() =>
        SafeLoad<ProtectedFolder>(FoldersGrid, MgmtOperations.FoldersList, "Protected Folders");

    private async Task LoadAdvancedAsync()
    {
        await SafeLoad<VulnerableAppRecord>(VulnAppsGrid, MgmtOperations.VulnAppsList, "Vulnerable apps");
        await SafeLoad<MitigationProfileRecord>(MitigationGrid, MgmtOperations.MitigationsList, "Mitigation profiles");
        await SafeLoad<FirewallRuleRecord>(FirewallGrid, MgmtOperations.FirewallList, "Firewall rules");
    }

    private Task LoadWebAppsAsync() =>
        SafeLoad<WebAppClassificationRecord>(WebAppsGrid, MgmtOperations.WebAppsList, "Web Apps");

    private Task LoadTamperAsync() =>
        SafeLoad<TamperEventRecord>(TamperGrid, MgmtOperations.TamperList, "Tamper Log");

    private async Task SafeLoad<T>(DataGrid grid, string operation, string name)
    {
        try
        {
            IReadOnlyList<T> rows = await _client.ListAsync<T>(operation);
            grid.ItemsSource = rows;
            Status($"{name}: {rows.Count} row(s).");
        }
        catch (Exception ex)
        {
            grid.ItemsSource = null;
            Status($"{name} load failed: {ex.Message}");
        }
    }

    // ---- refresh handlers -------------------------------------------------------------------------

    private async void RefreshWhitelist_Click(object sender, RoutedEventArgs e) => await LoadWhitelistAsync();
    private async void RefreshUserLog_Click(object sender, RoutedEventArgs e) => await LoadUserLogAsync();
    private async void RefreshRules_Click(object sender, RoutedEventArgs e) => await LoadRulesAsync();
    private async void RefreshCommandLines_Click(object sender, RoutedEventArgs e) => await LoadCommandLinesAsync();
    private async void RefreshQuarantine_Click(object sender, RoutedEventArgs e) => await LoadQuarantineAsync();
    private async void RefreshChains_Click(object sender, RoutedEventArgs e) => await LoadChainsAsync();
    private async void RefreshFolders_Click(object sender, RoutedEventArgs e) => await LoadFoldersAsync();
    private async void RefreshAdvanced_Click(object sender, RoutedEventArgs e) => await LoadAdvancedAsync();
    private async void RefreshWebApps_Click(object sender, RoutedEventArgs e) => await LoadWebAppsAsync();
    private async void RefreshTamper_Click(object sender, RoutedEventArgs e) => await LoadTamperAsync();

    // ---- edit actions (all applied by the service) ------------------------------------------------

    private async void AddRule_Click(object sender, RoutedEventArgs e)
    {
        var dlg = new AddRuleWindow { Owner = this };
        if (dlg.ShowDialog() == true && dlg.Result is { } rule)
        {
            // Envelope: the rule plus the file its hash/publisher came from, so the service can allow-list
            // that file immediately (see RuleAddPayload).
            await MutateAsync(MgmtOperations.RulesAdd, new { Rule = rule, SourcePath = dlg.SourcePath }, "Rule added.", LoadRulesAsync);
            await LoadWhitelistAsync();
        }
    }

    private async void DeleteRule_Click(object sender, RoutedEventArgs e)
    {
        if (RulesGrid.SelectedItem is RuleEntry rule)
        {
            await MutateAsync(MgmtOperations.RulesDelete, new IdPayload(rule.Id), "Rule deleted.", LoadRulesAsync);
        }
        else
        {
            Status("Select a rule row to delete.");
        }
    }

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
            await MutateAsync(MgmtOperations.FoldersAdd, folder, "Protected folder added.", LoadFoldersAsync);
        }
    }

    private async void DeleteFolder_Click(object sender, RoutedEventArgs e)
    {
        if (FoldersGrid.SelectedItem is ProtectedFolder folder)
        {
            await MutateAsync(
                MgmtOperations.FoldersDelete, new IdPayload(folder.Id), "Protected folder removed.", LoadFoldersAsync);
        }
        else
        {
            Status("Select a folder row to remove.");
        }
    }

    private async void AddWhitelist_Click(object sender, RoutedEventArgs e)
    {
        var dlg = new AddWhitelistWindow { Owner = this };
        if (dlg.ShowDialog() == true && dlg.Result is { } entry)
        {
            await MutateAsync(
                MgmtOperations.WhitelistAdd, entry, "Whitelist entry saved.", LoadWhitelistAsync);
        }
    }

    // ---- whitelist / user-log action toggles ------------------------------------------------------

    private async void WhitelistAllow_Click(object sender, RoutedEventArgs e) =>
        await SetWhitelistActionAsync(WhitelistGrid, PolicyAction.Allow, LoadWhitelistAsync);

    private async void WhitelistBlock_Click(object sender, RoutedEventArgs e) =>
        await SetWhitelistActionAsync(WhitelistGrid, PolicyAction.Block, LoadWhitelistAsync);

    private async void UserLogAllow_Click(object sender, RoutedEventArgs e) =>
        await SetWhitelistActionAsync(UserLogGrid, PolicyAction.Allow, LoadUserLogAsync);

    private async void UserLogBlock_Click(object sender, RoutedEventArgs e) =>
        await SetWhitelistActionAsync(UserLogGrid, PolicyAction.Block, LoadUserLogAsync);

    /// <summary>
    /// Flips the selected entry between Allow and Block. Setting Block revokes a previously-allowed
    /// file: the service removes the WDAC allow rule for the hash first (so the OS blocks the next launch
    /// again) and only then records the Block, which the whitelist tier replays.
    /// </summary>
    private async Task SetWhitelistActionAsync(DataGrid grid, PolicyAction action, Func<Task> reload)
    {
        if (grid.SelectedItem is not WhitelistEntry entry)
        {
            Status("Select a row first.");
            return;
        }

        await MutateAsync(
            MgmtOperations.WhitelistSetAction,
            new SetActionPayload(entry.Id, (int)action),
            $"{entry.ProcessName} set to {action}.",
            reload);
    }

    // ---- Advanced panel: per-app firewall checkboxes ----------------------------------------------

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
            await _client.InvokeAsync(
                MgmtOperations.VulnAppSetFirewall,
                new SetFirewallPayload(app.Id, app.AppPath, inBlocked, outBlocked));
            Status($"Firewall for {app.AppPath}: inbound={inBlocked}, outbound={outBlocked}.");
        }
        catch (Exception ex)
        {
            Status("Firewall change failed: " + ex.Message);
        }

        await LoadAdvancedAsync();
    }

    /// <summary>Runs a mutating call, reporting success or the service's refusal in the status bar.</summary>
    private async Task MutateAsync(string operation, object payload, string success, Func<Task> reload)
    {
        try
        {
            // The service may report what it actually did (e.g. "WDAC rule deployed; relaunch the app");
            // prefer that over the generic caption so the user knows whether a relaunch is enough.
            string? outcome = await _client.InvokeAsync(operation, payload);
            await reload();
            Status(string.IsNullOrWhiteSpace(outcome) ? success : outcome);
        }
        catch (Exception ex)
        {
            Status(ex.Message);
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
            await MutateAsync(MgmtOperations.WhitelistAllowFile, new AllowFilePayload(file), $"{System.IO.Path.GetFileName(file)} allowed.", LoadWhitelistAsync);
        }
    }

    private void Status(string message)
    {
        if (StatusText is not null)
        {
            StatusText.Text = message;
        }
    }
}
