using System.Windows;
using System.Windows.Controls;
using Microsoft.Win32;
using Warden.Storage;

namespace Warden.Ui;

/// <summary>
/// The Warden management window: a tab per CyberLock panel, each browsing the agent's SQLite database
/// directly (via <see cref="Warden.Storage"/>). This is the testing/inspection surface — the service
/// owns enforcement, so applying an allow (WDAC), a mitigation, or a firewall rule stays service-driven;
/// the panels here read all state and support the pure-database edits (rules, protected folders, manual
/// whitelist) that help exercise the pipeline.
/// </summary>
public partial class MainWindow : Window
{
    private readonly IWardenDatabase _db;
    private readonly IWhitelistRepository _whitelist;
    private readonly IRulesRepository _rules;
    private readonly ICommandLineRepository _commandLines;
    private readonly IQuarantineRepository _quarantine;
    private readonly IAttackChainRepository _chains;
    private readonly IProtectedFolderRepository _folders;
    private readonly IVulnerableAppRepository _vulnApps;
    private readonly IMitigationProfileRepository _mitigations;
    private readonly IFirewallRuleRepository _firewall;
    private readonly IWebAppClassificationRepository _webApps;
    private readonly ITamperLogRepository _tamper;

    public MainWindow()
    {
        InitializeComponent();

        _db = new WardenDb();
        try
        {
            _db.Initialize();
        }
        catch (Exception ex)
        {
            Status("Database unavailable (is it locked to SYSTEM/Admins by a hardened install?): " + ex.Message);
        }

        _whitelist = new WhitelistRepository(_db);
        _rules = new RulesRepository(_db);
        _commandLines = new CommandLineRepository(_db);
        _quarantine = new QuarantineRepository(_db);
        _chains = new AttackChainRepository(_db);
        _folders = new ProtectedFolderRepository(_db);
        _vulnApps = new VulnerableAppRepository(_db);
        _mitigations = new MitigationProfileRepository(_db);
        _firewall = new FirewallRuleRepository(_db);
        _webApps = new WebAppClassificationRepository(_db);
        _tamper = new TamperLogRepository(_db);

        DbPathText.Text = _db.DatabasePath;
        Loaded += async (_, _) => await LoadAllAsync();
    }

    private async Task LoadAllAsync()
    {
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

    // ---- per-panel loads --------------------------------------------------------------------------

    private Task LoadWhitelistAsync() => SafeLoad(WhitelistGrid, () => _whitelist.GetAllAsync(), "Whitelist");

    private Task LoadUserLogAsync() => SafeLoad(UserLogGrid, async () =>
        (IReadOnlyList<WhitelistEntry>)(await _whitelist.GetAllAsync())
            .Where(w => string.Equals(w.Source, "UserPrompt", StringComparison.OrdinalIgnoreCase))
            .ToList(),
        "User Log");

    private Task LoadRulesAsync() => SafeLoad(RulesGrid, () => _rules.GetAllAsync(), "Rules");

    private Task LoadCommandLinesAsync() => SafeLoad(CommandLinesGrid, () => _commandLines.GetAllAsync(), "Command Lines");

    private Task LoadQuarantineAsync() => SafeLoad(QuarantineGrid, () => _quarantine.GetAllAsync(), "Quarantine");

    private Task LoadChainsAsync() => SafeLoad(ChainsGrid, () => _chains.GetRecentAsync(), "Attack Chains");

    private Task LoadFoldersAsync() => SafeLoad(FoldersGrid, () => _folders.GetAllAsync(), "Protected Folders");

    private async Task LoadAdvancedAsync()
    {
        await SafeLoad(VulnAppsGrid, () => _vulnApps.GetAllAsync(), "Vulnerable apps");
        await SafeLoad(MitigationGrid, () => _mitigations.GetAllAsync(), "Mitigation profiles");
        await SafeLoad(FirewallGrid, () => _firewall.GetAllAsync(), "Firewall rules");
    }

    private Task LoadWebAppsAsync() => SafeLoad(WebAppsGrid, () => _webApps.GetAllAsync(), "Web Apps");

    private Task LoadTamperAsync() => SafeLoad(TamperGrid, () => _tamper.GetRecentAsync(), "Tamper Log");

    private async Task SafeLoad<T>(DataGrid grid, Func<Task<IReadOnlyList<T>>> loader, string name)
    {
        try
        {
            IReadOnlyList<T> rows = await loader();
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

    // ---- edit actions (pure database writes) ------------------------------------------------------

    private async void AddRule_Click(object sender, RoutedEventArgs e)
    {
        var dlg = new AddRuleWindow { Owner = this };
        if (dlg.ShowDialog() == true && dlg.Result is { } rule)
        {
            try
            {
                await _rules.AddAsync(rule);
                await LoadRulesAsync();
                Status("Rule added.");
            }
            catch (Exception ex)
            {
                Status("Add rule failed: " + ex.Message);
            }
        }
    }

    private async void DeleteRule_Click(object sender, RoutedEventArgs e)
    {
        if (RulesGrid.SelectedItem is RuleEntry rule)
        {
            try
            {
                await _rules.DeleteAsync(rule.Id);
                await LoadRulesAsync();
                Status("Rule deleted.");
            }
            catch (Exception ex)
            {
                Status("Delete rule failed: " + ex.Message);
            }
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
            try
            {
                await _folders.AddAsync(new ProtectedFolder
                {
                    Path = dlg.FolderName,
                    Recursive = true,
                    MonitorMode = "monitor",
                    AddedTs = DateTimeOffset.UtcNow,
                });
                await LoadFoldersAsync();
                Status("Protected folder added.");
            }
            catch (Exception ex)
            {
                Status("Add folder failed: " + ex.Message);
            }
        }
    }

    private async void DeleteFolder_Click(object sender, RoutedEventArgs e)
    {
        if (FoldersGrid.SelectedItem is ProtectedFolder folder)
        {
            try
            {
                await _folders.DeleteAsync(folder.Id);
                await LoadFoldersAsync();
                Status("Protected folder removed.");
            }
            catch (Exception ex)
            {
                Status("Remove folder failed: " + ex.Message);
            }
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
            try
            {
                await _whitelist.AddAsync(entry);
                await LoadWhitelistAsync();
                Status("Whitelist entry added.");
            }
            catch (Exception ex)
            {
                Status("Add whitelist entry failed: " + ex.Message);
            }
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
