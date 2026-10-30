using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Windows.Input;
using Warden.Storage;
using Warden.Ui.Services;
using Warden.Ui.ViewModels.Validation;

namespace Warden.Ui.ViewModels;

/// <summary>
/// ViewModel for the AddRuleWindow. Handles rule creation with browse support and validation.
/// </summary>
public sealed class AddRuleWindowViewModel : ValidatableViewModelBase
{
    private readonly IFileDialogService _fileDialogService;
    private RuleKind _selectedKind = RuleKind.Hash;
    private PolicyAction _selectedAction = PolicyAction.Allow;
    private string _matchValue = string.Empty;
    private string _matchHint = "SHA-256 of the file (Browse… picks a file and computes it)";
    private string _sourceHint = string.Empty;
    private bool _requireSignature;
    private bool _requireWhitelist;
    private string _note = string.Empty;
    private bool _browseButtonEnabled = true;
    
    // Properties for owner window (needed for dialogs)
    private object? _owner;

    /// <summary>
    /// Gets or sets the selected rule kind.
    /// </summary>
    public RuleKind SelectedKind
    {
        get => _selectedKind;
        set
        {
            if (SetField(ref _selectedKind, value))
            {
                UpdateHints();
                UpdateBrowseEnabled();
            }
        }
    }

    /// <summary>
    /// Gets or sets the selected action.
    /// </summary>
    public PolicyAction SelectedAction
    {
        get => _selectedAction;
        set => SetField(ref _selectedAction, value);
    }

    /// <summary>
    /// Gets or sets the match value (hash, signature, folder, or extension).
    /// </summary>
    public string MatchValue
    {
        get => _matchValue;
        set => SetField(ref _matchValue, value);
    }

    /// <summary>
    /// Gets the match hint text.
    /// </summary>
    public string MatchHint
    {
        get => _matchHint;
        set => SetField(ref _matchHint, value, validate: false);
    }

    /// <summary>
    /// Gets the source hint text.
    /// </summary>
    public string SourceHint
    {
        get => _sourceHint;
        set => SetField(ref _sourceHint, value, validate: false);
    }

    /// <summary>
    /// Gets or sets a value indicating whether a valid signature is required.
    /// </summary>
    public bool RequireSignature
    {
        get => _requireSignature;
        set => SetField(ref _requireSignature, value);
    }

    /// <summary>
    /// Gets or sets a value indicating whether existing whitelist status is required.
    /// </summary>
    public bool RequireWhitelist
    {
        get => _requireWhitelist;
        set => SetField(ref _requireWhitelist, value);
    }

    /// <summary>
    /// Gets or sets the note.
    /// </summary>
    public string Note
    {
        get => _note;
        set => SetField(ref _note, value);
    }

    /// <summary>
    /// Gets a value indicating whether the browse button is enabled.
    /// </summary>
    public bool BrowseButtonEnabled
    {
        get => _browseButtonEnabled;
        set => SetField(ref _browseButtonEnabled, value, validate: false);
    }

    /// <summary>
    /// Gets the list of rule kinds for the combo box.
    /// </summary>
    public Array RuleKinds => Enum.GetValues(typeof(RuleKind));

    /// <summary>
    /// Gets the list of actions for the combo box.
    /// </summary>
    public Array Actions => Enum.GetValues(typeof(PolicyAction));

    // Commands
    public ICommand BrowseCommand { get; }
    public ICommand OkCommand { get; }

    /// <summary>
    /// Gets the result rule entry, or null if not yet created or cancelled.
    /// </summary>
    public RuleEntry? Result { get; private set; }

    /// <summary>
    /// Gets the source path for the rule (used for immediate allow-listing), or null if not applicable.
    /// </summary>
    public string? SourcePath { get; set; }

    /// <summary>
    /// Initializes a new instance of the AddRuleWindowViewModel class.
    /// </summary>
    /// <param name="fileDialogService">The file dialog service for browsing files/folders.</param>
    public AddRuleWindowViewModel(IFileDialogService? fileDialogService = null)
    {
        _fileDialogService = fileDialogService ?? new FileDialogService();
        BrowseCommand = new RelayCommand(Browse);
        OkCommand = new RelayCommand(Ok, CanOk);
        
        // Initialize hints for default kind (Hash)
        UpdateHints();
        UpdateBrowseEnabled();
    }
    
    /// <summary>
    /// Sets the owner window for dialogs.
    /// </summary>
    /// <param name="owner">The owner window.</param>
    public void SetOwner(object? owner)
    {
        _owner = owner;
    }

    /// <summary>
    /// Updates the match and source hints based on the selected kind.
    /// </summary>
    private void UpdateHints()
    {
        switch (SelectedKind)
        {
            case RuleKind.Hash:
                MatchHint = "SHA-256 of the file (Browse… picks a file and computes it)";
                SourceHint = string.Empty;
                break;
            case RuleKind.Signature:
                MatchHint = "Publisher name as it appears in the signing certificate (Browse… reads it from a signed file)";
                SourceHint = string.Empty;
                break;
            case RuleKind.Folder:
                MatchHint = "Folder — applies to everything under it (Browse… picks a folder)";
                SourceHint = string.Empty;
                break;
            default:
                MatchHint = "File extension including the dot, e.g. .exe";
                SourceHint = string.Empty;
                break;
        }
    }

    /// <summary>
    /// Updates whether the browse button should be enabled based on the selected kind.
    /// </summary>
    private void UpdateBrowseEnabled()
    {
        BrowseButtonEnabled = SelectedKind != RuleKind.Extension;
    }

    /// <summary>
    /// Determines whether the OK command can execute.
    /// </summary>
    private bool CanOk() => !string.IsNullOrWhiteSpace(MatchValue) && IsValid;

    /// <summary>
    /// Handles the Browse command to select a file or folder based on the selected kind.
    /// </summary>
    private void Browse()
    {
        switch (SelectedKind)
        {
            case RuleKind.Folder:
            {
                string? folder = _fileDialogService.ShowOpenFolderDialog("Choose the folder this rule applies to", _owner);
                if (folder != null)
                {
                    MatchValue = folder;
                    SourcePath = null;
                    SourceHint = string.Empty;
                }
                break;
            }
            case RuleKind.Hash:
            {
                string? file = _fileDialogService.ShowOpenFileDialog(
                    "Choose the file to compute the SHA-256 of",
                    FileDialogService.ExecutableFilter,
                    _owner);
                if (file != null)
                {
                    try
                    {
                        using FileStream fs = File.OpenRead(file);
                        MatchValue = Convert.ToHexString(SHA256.HashData(fs));
                        SourcePath = file;
                        SourceHint = $"From {file}";
                    }
                    catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
                    {
                        // Error will be shown by caller if needed
                    }
                }
                break;
            }
            case RuleKind.Signature:
            {
                string? file = _fileDialogService.ShowOpenFileDialog(
                    "Choose a signed file to read the publisher from",
                    FileDialogService.ExecutableFilter,
                    _owner);
                if (file != null)
                {
                    string? publisher = ReadPublisher(file);
                    if (publisher != null)
                    {
                        MatchValue = publisher;
                        SourcePath = file;
                        SourceHint = $"From {file}";
                    }
                }
                break;
            }
        }
    }
    
    /// <summary>
    /// Reads the publisher name from a signed file.
    /// </summary>
    private static string? ReadPublisher(string file)
    {
        try
        {
            using var cert = new X509Certificate2(X509Certificate.CreateFromSignedFile(file));
            string cn = cert.GetNameInfo(X509NameType.SimpleName, forIssuer: false);
            return string.IsNullOrWhiteSpace(cn) ? cert.Subject : cn;
        }
        catch (CryptographicException)
        {
            return null;
        }
        catch (IOException)
        {
            return null;
        }
        catch (UnauthorizedAccessException)
        {
            return null;
        }
    }

    /// <summary>
    /// Handles the OK command to create the rule.
    /// </summary>
    private void Ok()
    {
        if (!IsValid)
        {
            // Validate will have already been called by CanOk
            return;
        }

        Result = new RuleEntry
        {
            Kind = SelectedKind,
            MatchValue = MatchValue.Trim(),
            Action = SelectedAction,
            RequireSignature = RequireSignature,
            RequireWhitelist = RequireWhitelist,
            Enabled = true,
            CreatedTs = DateTimeOffset.UtcNow,
            Note = string.IsNullOrWhiteSpace(Note) ? null : Note.Trim(),
        };
    }

    /// <summary>
    /// Validates the MatchValue property.
    /// </summary>
    protected override ValidationResult ValidatePropertyCore(string propertyName)
    {
        if (propertyName == nameof(MatchValue))
        {
            return ValidateMatchValue();
        }
        return ValidationResult.Success();
    }

    private ValidationResult ValidateMatchValue()
    {
        if (string.IsNullOrWhiteSpace(MatchValue))
        {
            return ValidationResult.Fail("Match value is required");
        }

        // Validate based on kind
        switch (SelectedKind)
        {
            case RuleKind.Hash:
                // SHA-256 should be 64 hex characters
                if (MatchValue.Length != 64 || !IsHexString(MatchValue))
                {
                    return ValidationResult.Fail("Hash must be a 64-character hexadecimal string");
                }
                break;
            
            case RuleKind.Signature:
                // Signature should not be empty
                if (string.IsNullOrWhiteSpace(MatchValue))
                {
                    return ValidationResult.Fail("Signature is required");
                }
                break;
                
            case RuleKind.Folder:
                // Folder path should be valid
                if (string.IsNullOrWhiteSpace(MatchValue) || 
                    MatchValue.IndexOfAny(System.IO.Path.GetInvalidPathChars()) >= 0)
                {
                    return ValidationResult.Fail("Invalid folder path");
                }
                break;
                
            case RuleKind.Extension:
                // Extension should start with dot
                if (!MatchValue.StartsWith(".", StringComparison.Ordinal))
                {
                    return ValidationResult.Fail("Extension must start with a dot (.)");
                }
                break;
        }

        return ValidationResult.Success();
    }

    private static bool IsHexString(string input)
    {
        foreach (char c in input)
        {
            if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')))
            {
                return false;
            }
        }
        return true;
    }

    /// <summary>
    /// Computes the SHA-256 hash of a file.
    /// </summary>
    public static string ComputeSha256(string filePath)
    {
        using FileStream fs = File.OpenRead(filePath);
        return Convert.ToHexString(SHA256.HashData(fs));
    }

}
