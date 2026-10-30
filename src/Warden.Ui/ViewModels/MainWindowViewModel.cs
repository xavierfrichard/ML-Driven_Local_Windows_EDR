using System.Collections.ObjectModel;
using System.Windows;
using System.Windows.Input;
using Microsoft.Win32;
using Warden.Ipc;
using Warden.Storage;

namespace Warden.Ui.ViewModels;

/// <summary>
/// ViewModel for the MainWindow. Handles all data loading, commands, and state management.
/// </summary>
public sealed class MainWindowViewModel : ViewModelBase, IDisposable
{
    internal readonly MgmtPipeClient _client = new();
    private string _status = "Ready.";
    private string _dbPathText = string.Empty;
    private bool _isAdministrator;
    private bool _isLoading;
    
    // Tab data collections
    private ObservableCollection<WhitelistEntry> _whitelistEntries = new();
    private ObservableCollection<WhitelistEntry> _userLogEntries = new();
    private ObservableCollection<RuleEntry> _ruleEntries = new();
    private ObservableCollection<CommandLineRecord> _commandLineEntries = new();
    private ObservableCollection<QuarantineRecord> _quarantineEntries = new();
    private ObservableCollection<AttackChainRecord> _attackChainEntries = new();
    private ObservableCollection<ProtectedFolder> _protectedFolders = new();
    private ObservableCollection<VulnerableAppRecord> _vulnerableAppRecords = new();
    private ObservableCollection<MitigationProfileRecord> _mitigationProfiles = new();
    private ObservableCollection<FirewallRuleRecord> _firewallRules = new();
    private ObservableCollection<WebAppClassificationRecord> _webAppClassifications = new();
    private ObservableCollection<TamperEventRecord> _tamperEvents = new();

    // Selected items for mutation operations
    private WhitelistEntry? _selectedWhitelistEntry;
    private WhitelistEntry? _selectedUserLogEntry;
    private RuleEntry? _selectedRuleEntry;
    private ProtectedFolder? _selectedFolderEntry;

    /// <summary>
    /// Gets the status text displayed in the status bar.
    /// </summary>
    public string Status
    {
        get => _status;
        set => SetField(ref _status, value);
    }

    /// <summary>
    /// Gets the database path text displayed in the status bar.
    /// </summary>
    public string DbPathText
    {
        get => _dbPathText;
        set => SetField(ref _dbPathText, value);
    }

    /// <summary>
    /// Gets a value indicating whether the current user is an administrator.
    /// </summary>
    public bool IsAdministrator
    {
        get => _isAdministrator;
        set
        {
            if (SetField(ref _isAdministrator, value))
            {
                // Re-evaluate all mutation command CanExecute
                (AddRuleCommand as AsyncRelayCommand)?.RaiseCanExecuteChanged();
                (DeleteRuleCommand as AsyncRelayCommand)?.RaiseCanExecuteChanged();
                (AddFolderCommand as AsyncRelayCommand)?.RaiseCanExecuteChanged();
                (DeleteFolderCommand as AsyncRelayCommand)?.RaiseCanExecuteChanged();
                (AllowFileCommand as AsyncRelayCommand)?.RaiseCanExecuteChanged();
                (AddWhitelistCommand as AsyncRelayCommand)?.RaiseCanExecuteChanged();
                (WhitelistAllowCommand as AsyncRelayCommand)?.RaiseCanExecuteChanged();
                (WhitelistBlockCommand as AsyncRelayCommand)?.RaiseCanExecuteChanged();
                (UserLogAllowCommand as AsyncRelayCommand)?.RaiseCanExecuteChanged();
                (UserLogBlockCommand as AsyncRelayCommand)?.RaiseCanExecuteChanged();
            }
        }
    }

    /// <summary>
    /// Gets a value indicating whether data is currently being loaded.
    /// </summary>
    public bool IsLoading
    {
        get => _isLoading;
        set => SetField(ref _isLoading, value);
    }

    // Whitelist tab
    public ObservableCollection<WhitelistEntry> WhitelistEntries
    {
        get => _whitelistEntries;
        set => SetField(ref _whitelistEntries, value);
    }

    public WhitelistEntry? SelectedWhitelistEntry
    {
        get => _selectedWhitelistEntry;
        set => SetField(ref _selectedWhitelistEntry, value);
    }

    // User Log tab
    public ObservableCollection<WhitelistEntry> UserLogEntries
    {
        get => _userLogEntries;
        set => SetField(ref _userLogEntries, value);
    }

    public WhitelistEntry? SelectedUserLogEntry
    {
        get => _selectedUserLogEntry;
        set => SetField(ref _selectedUserLogEntry, value);
    }

    // Rules tab
    public ObservableCollection<RuleEntry> RuleEntries
    {
        get => _ruleEntries;
        set => SetField(ref _ruleEntries, value);
    }

    public RuleEntry? SelectedRuleEntry
    {
        get => _selectedRuleEntry;
        set => SetField(ref _selectedRuleEntry, value);
    }

    // Command Lines tab
    public ObservableCollection<CommandLineRecord> CommandLineEntries
    {
        get => _commandLineEntries;
        set => SetField(ref _commandLineEntries, value);
    }

    // Quarantine tab
    public ObservableCollection<QuarantineRecord> QuarantineEntries
    {
        get => _quarantineEntries;
        set => SetField(ref _quarantineEntries, value);
    }

    // Attack Chains tab
    public ObservableCollection<AttackChainRecord> AttackChainEntries
    {
        get => _attackChainEntries;
        set => SetField(ref _attackChainEntries, value);
    }

    // Protected Folders tab
    public ObservableCollection<ProtectedFolder> ProtectedFolders
    {
        get => _protectedFolders;
        set => SetField(ref _protectedFolders, value);
    }

    public ProtectedFolder? SelectedFolderEntry
    {
        get => _selectedFolderEntry;
        set => SetField(ref _selectedFolderEntry, value);
    }

    // Advanced tab
    public ObservableCollection<VulnerableAppRecord> VulnerableAppRecords
    {
        get => _vulnerableAppRecords;
        set => SetField(ref _vulnerableAppRecords, value);
    }

    public ObservableCollection<MitigationProfileRecord> MitigationProfiles
    {
        get => _mitigationProfiles;
        set => SetField(ref _mitigationProfiles, value);
    }

    public ObservableCollection<FirewallRuleRecord> FirewallRules
    {
        get => _firewallRules;
        set => SetField(ref _firewallRules, value);
    }

    // Web Apps tab
    public ObservableCollection<WebAppClassificationRecord> WebAppClassifications
    {
        get => _webAppClassifications;
        set => SetField(ref _webAppClassifications, value);
    }

    // Tamper Log tab
    public ObservableCollection<TamperEventRecord> TamperEvents
    {
        get => _tamperEvents;
        set => SetField(ref _tamperEvents, value);
    }

    // Commands - Refresh
    public ICommand RefreshWhitelistCommand { get; }
    public ICommand RefreshUserLogCommand { get; }
    public ICommand RefreshRulesCommand { get; }
    public ICommand RefreshCommandLinesCommand { get; }
    public ICommand RefreshQuarantineCommand { get; }
    public ICommand RefreshChainsCommand { get; }
    public ICommand RefreshFoldersCommand { get; }
    public ICommand RefreshAdvancedCommand { get; }
    public ICommand RefreshWebAppsCommand { get; }
    public ICommand RefreshTamperCommand { get; }

    // Commands - Mutations
    public ICommand AddRuleCommand { get; }
    public ICommand DeleteRuleCommand { get; }
    public ICommand AddFolderCommand { get; }
    public ICommand DeleteFolderCommand { get; }
    public ICommand AllowFileCommand { get; }
    public ICommand AddWhitelistCommand { get; }
    public ICommand WhitelistAllowCommand { get; }
    public ICommand WhitelistBlockCommand { get; }
    public ICommand UserLogAllowCommand { get; }
    public ICommand UserLogBlockCommand { get; }

    // Commands - Firewall (handled in XAML event for now, will migrate)

    /// <summary>
    /// Initializes a new instance of the MainWindowViewModel class.
    /// </summary>
    public MainWindowViewModel()
    {
        // Initialize commands
        RefreshWhitelistCommand = new AsyncRelayCommand(LoadWhitelistAsync);
        RefreshUserLogCommand = new AsyncRelayCommand(LoadUserLogAsync);
        RefreshRulesCommand = new AsyncRelayCommand(LoadRulesAsync);
        RefreshCommandLinesCommand = new AsyncRelayCommand(LoadCommandLinesAsync);
        RefreshQuarantineCommand = new AsyncRelayCommand(LoadQuarantineAsync);
        RefreshChainsCommand = new AsyncRelayCommand(LoadChainsAsync);
        RefreshFoldersCommand = new AsyncRelayCommand(LoadFoldersAsync);
        RefreshAdvancedCommand = new AsyncRelayCommand(LoadAdvancedAsync);
        RefreshWebAppsCommand = new AsyncRelayCommand(LoadWebAppsAsync);
        RefreshTamperCommand = new AsyncRelayCommand(LoadTamperAsync);

        AddRuleCommand = new AsyncRelayCommand(AddRuleAsync, () => IsAdministrator);
        DeleteRuleCommand = new AsyncRelayCommand(DeleteRuleAsync, () => IsAdministrator && SelectedRuleEntry is not null);
        AddFolderCommand = new AsyncRelayCommand(AddFolderAsync, () => IsAdministrator);
        DeleteFolderCommand = new AsyncRelayCommand(DeleteFolderAsync, () => IsAdministrator && SelectedFolderEntry is not null);
        AllowFileCommand = new AsyncRelayCommand(AllowFileAsync, () => IsAdministrator);
        AddWhitelistCommand = new AsyncRelayCommand(AddWhitelistAsync, () => IsAdministrator);
        WhitelistAllowCommand = new AsyncRelayCommand(() => SetWhitelistActionAsync(WhitelistEntries, PolicyAction.Allow, LoadWhitelistAsync), () => IsAdministrator && SelectedWhitelistEntry is not null);
        WhitelistBlockCommand = new AsyncRelayCommand(() => SetWhitelistActionAsync(WhitelistEntries, PolicyAction.Block, LoadWhitelistAsync), () => IsAdministrator && SelectedWhitelistEntry is not null);
        UserLogAllowCommand = new AsyncRelayCommand(() => SetWhitelistActionAsync(UserLogEntries, PolicyAction.Allow, LoadUserLogAsync), () => IsAdministrator && SelectedUserLogEntry is not null);
        UserLogBlockCommand = new AsyncRelayCommand(() => SetWhitelistActionAsync(UserLogEntries, PolicyAction.Block, LoadUserLogAsync), () => IsAdministrator && SelectedUserLogEntry is not null);

        // Set initial database path text
        DbPathText = "via WardenAgent (pipe: " + MgmtProtocol.PipeName + ")";
    }

    /// <summary>
    /// Loads all data on startup.
    /// </summary>
    public async Task LoadAllAsync()
    {
        try
        {
            IsLoading = true;
            Status = "Loading...";

            // Load privilege status first
            await RefreshPrivilegeAsync();

            // Load all tabs in parallel
            var tasks = new Task[]
            {
                LoadWhitelistAsync(CancellationToken.None),
                LoadUserLogAsync(CancellationToken.None),
                LoadRulesAsync(CancellationToken.None),
                LoadCommandLinesAsync(CancellationToken.None),
                LoadQuarantineAsync(CancellationToken.None),
                LoadChainsAsync(CancellationToken.None),
                LoadFoldersAsync(CancellationToken.None),
                LoadAdvancedAsync(CancellationToken.None),
                LoadWebAppsAsync(CancellationToken.None),
                LoadTamperAsync(CancellationToken.None),
            };

            await Task.WhenAll(tasks);

            Status = "Loaded. Right-click the tray icon and choose Open Warden any time.";
        }
        catch (Exception ex)
        {
            Status = "Load failed: " + ex.Message;
        }
        finally
        {
            IsLoading = false;
        }
    }

    /// <summary>
    /// Refreshes the administrator privilege status.
    /// </summary>
    public async Task RefreshPrivilegeAsync()
    {
        try
        {
            IsAdministrator = await _client.IsAdministratorAsync();
        }
        catch (Exception ex)
        {
            Status = ex.Message;
            IsAdministrator = false;
        }
    }

    // Load methods for each tab
    public async Task LoadWhitelistAsync(CancellationToken ct = default)
    {
        try
        {
            var entries = await _client.ListAsync<WhitelistEntry>(MgmtOperations.WhitelistList, ct);
            WhitelistEntries = new ObservableCollection<WhitelistEntry>(entries);
            Status = $"Whitelist: {entries.Count} row(s).";
        }
        catch (Exception ex)
        {
            WhitelistEntries.Clear();
            Status = "Whitelist load failed: " + ex.Message;
        }
    }

    public async Task LoadUserLogAsync(CancellationToken ct = default)
    {
        try
        {
            var entries = await _client.ListAsync<WhitelistEntry>(MgmtOperations.UserLogList, ct);
            UserLogEntries = new ObservableCollection<WhitelistEntry>(entries);
            Status = $"User Log: {entries.Count} row(s).";
        }
        catch (Exception ex)
        {
            UserLogEntries.Clear();
            Status = "User Log load failed: " + ex.Message;
        }
    }

    public async Task LoadRulesAsync(CancellationToken ct = default)
    {
        try
        {
            var entries = await _client.ListAsync<RuleEntry>(MgmtOperations.RulesList, ct);
            RuleEntries = new ObservableCollection<RuleEntry>(entries);
            Status = $"Rules: {entries.Count} row(s).";
        }
        catch (Exception ex)
        {
            RuleEntries.Clear();
            Status = "Rules load failed: " + ex.Message;
        }
    }

    public async Task LoadCommandLinesAsync(CancellationToken ct = default)
    {
        try
        {
            var entries = await _client.ListAsync<CommandLineRecord>(MgmtOperations.CommandLinesList, ct);
            CommandLineEntries = new ObservableCollection<CommandLineRecord>(entries);
            Status = $"Command Lines: {entries.Count} row(s).";
        }
        catch (Exception ex)
        {
            CommandLineEntries.Clear();
            Status = "Command Lines load failed: " + ex.Message;
        }
    }

    public async Task LoadQuarantineAsync(CancellationToken ct = default)
    {
        try
        {
            var entries = await _client.ListAsync<QuarantineRecord>(MgmtOperations.QuarantineList, ct);
            QuarantineEntries = new ObservableCollection<QuarantineRecord>(entries);
            Status = $"Quarantine: {entries.Count} row(s).";
        }
        catch (Exception ex)
        {
            QuarantineEntries.Clear();
            Status = "Quarantine load failed: " + ex.Message;
        }
    }

    public async Task LoadChainsAsync(CancellationToken ct = default)
    {
        try
        {
            var entries = await _client.ListAsync<AttackChainRecord>(MgmtOperations.ChainsList, ct);
            AttackChainEntries = new ObservableCollection<AttackChainRecord>(entries);
            Status = $"Attack Chains: {entries.Count} row(s).";
        }
        catch (Exception ex)
        {
            AttackChainEntries.Clear();
            Status = "Attack Chains load failed: " + ex.Message;
        }
    }

    public async Task LoadFoldersAsync(CancellationToken ct = default)
    {
        try
        {
            var entries = await _client.ListAsync<ProtectedFolder>(MgmtOperations.FoldersList, ct);
            ProtectedFolders = new ObservableCollection<ProtectedFolder>(entries);
            Status = $"Protected Folders: {entries.Count} row(s).";
        }
        catch (Exception ex)
        {
            ProtectedFolders.Clear();
            Status = "Protected Folders load failed: " + ex.Message;
        }
    }

    public async Task LoadAdvancedAsync(CancellationToken ct = default)
    {
        try
        {
            var vulnAppsTask = _client.ListAsync<VulnerableAppRecord>(MgmtOperations.VulnAppsList, ct);
            var mitigationsTask = _client.ListAsync<MitigationProfileRecord>(MgmtOperations.MitigationsList, ct);
            var firewallTask = _client.ListAsync<FirewallRuleRecord>(MgmtOperations.FirewallList, ct);

            await Task.WhenAll(vulnAppsTask, mitigationsTask, firewallTask);

            VulnerableAppRecords = new ObservableCollection<VulnerableAppRecord>(await vulnAppsTask);
            MitigationProfiles = new ObservableCollection<MitigationProfileRecord>(await mitigationsTask);
            FirewallRules = new ObservableCollection<FirewallRuleRecord>(await firewallTask);

            Status = $"Advanced: {VulnerableAppRecords.Count} vulnerable apps, {MitigationProfiles.Count} mitigation profiles, {FirewallRules.Count} firewall rules.";
        }
        catch (Exception ex)
        {
            Status = "Advanced load failed: " + ex.Message;
        }
    }

    public async Task LoadWebAppsAsync(CancellationToken ct = default)
    {
        try
        {
            var entries = await _client.ListAsync<WebAppClassificationRecord>(MgmtOperations.WebAppsList, ct);
            WebAppClassifications = new ObservableCollection<WebAppClassificationRecord>(entries);
            Status = $"Web Apps: {entries.Count} row(s).";
        }
        catch (Exception ex)
        {
            WebAppClassifications.Clear();
            Status = "Web Apps load failed: " + ex.Message;
        }
    }

    public async Task LoadTamperAsync(CancellationToken ct = default)
    {
        try
        {
            var entries = await _client.ListAsync<TamperEventRecord>(MgmtOperations.TamperList, ct);
            TamperEvents = new ObservableCollection<TamperEventRecord>(entries);
            Status = $"Tamper Log: {entries.Count} row(s).";
        }
        catch (Exception ex)
        {
            TamperEvents.Clear();
            Status = "Tamper Log load failed: " + ex.Message;
        }
    }

    // Mutation methods
    private async Task AddRuleAsync(CancellationToken ct = default)
    {
        // This will be handled by showing AddRuleWindow
        // The actual addition is done in the dialog's OK handler
        // For now, we'll keep this as a placeholder
        Status = "Use the Add button in the Rules tab to add a rule.";
    }

    private async Task DeleteRuleAsync(CancellationToken ct = default)
    {
        if (SelectedRuleEntry is null)
        {
            Status = "Select a rule row to delete.";
            return;
        }

        try
        {
            await _client.InvokeAsync(MgmtOperations.RulesDelete, new IdPayload(SelectedRuleEntry.Id), ct);
            Status = "Rule deleted.";
            await LoadRulesAsync(ct);
        }
        catch (Exception ex)
        {
            Status = ex.Message;
        }
    }

    private async Task AddFolderAsync(CancellationToken ct = default)
    {
        // This will be handled by showing folder picker dialog
        Status = "Use the Add folder button in the Protected Folders tab.";
    }

    private async Task DeleteFolderAsync(CancellationToken ct = default)
    {
        if (SelectedFolderEntry is null)
        {
            Status = "Select a folder row to delete.";
            return;
        }

        try
        {
            await _client.InvokeAsync(MgmtOperations.FoldersDelete, new IdPayload(SelectedFolderEntry.Id), ct);
            Status = "Protected folder removed.";
            await LoadFoldersAsync(ct);
        }
        catch (Exception ex)
        {
            Status = ex.Message;
        }
    }

    private async Task AllowFileAsync(CancellationToken ct = default)
    {
        // This will be handled by showing file picker dialog
        Status = "Use the Allow file button in the Whitelist tab.";
    }

    private async Task AddWhitelistAsync(CancellationToken ct = default)
    {
        // This will be handled by showing AddWhitelistWindow
        Status = "Use the Manual Add button in the Whitelist tab.";
    }

    /// <summary>
    /// Sets the action for a whitelist or user log entry.
    /// </summary>
    private async Task SetWhitelistActionAsync(ObservableCollection<WhitelistEntry> collection, PolicyAction action, Func<CancellationToken, Task> reload, CancellationToken ct = default)
    {
        WhitelistEntry? entry = default;
        
        if (collection == WhitelistEntries)
        {
            entry = SelectedWhitelistEntry;
        }
        else if (collection == UserLogEntries)
        {
            entry = SelectedUserLogEntry;
        }

        if (entry is null)
        {
            Status = "Select a row first.";
            return;
        }

        try
        {
            await _client.InvokeAsync(
                MgmtOperations.WhitelistSetAction,
                new SetActionPayload(entry.Id, (int)action),
                ct);
            
            Status = $"{entry.ProcessName} set to {action}.";
            await reload(ct);
        }
        catch (Exception ex)
        {
            Status = ex.Message;
        }
    }

    /// <summary>
    /// Mutates data via the service and reloads the specified tab.
    /// </summary>
    public async Task MutateAndReloadAsync(string operation, object payload, string successMessage, Func<CancellationToken, Task> reload, CancellationToken ct = default)
    {
        try
        {
            string? outcome = await _client.InvokeAsync(operation, payload, ct);
            await reload(ct);
            Status = string.IsNullOrWhiteSpace(outcome) ? successMessage : outcome;
        }
        catch (Exception ex)
        {
            Status = ex.Message;
        }
    }

    /// <summary>
    /// Disposes the management pipe client.
    /// </summary>
    public void Dispose()
    {
        _client.Dispose();
    }
}
