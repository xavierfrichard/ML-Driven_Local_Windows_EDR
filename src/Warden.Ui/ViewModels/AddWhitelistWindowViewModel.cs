using System.IO;
using System.Security.Cryptography;
using System.Windows.Input;
using Warden.Storage;
using Warden.Ui.Services;
using Warden.Ui.ViewModels.Validation;

namespace Warden.Ui.ViewModels;

/// <summary>
/// ViewModel for the AddWhitelistWindow. Handles manual whitelist entry creation with validation.
/// </summary>
public sealed class AddWhitelistWindowViewModel : ValidatableViewModelBase
{
    private readonly IFileDialogService _fileDialogService;
    private string _path = string.Empty;
    private string _sha256 = string.Empty;
    private PolicyAction _selectedAction = PolicyAction.Allow;
    private object? _owner;

    /// <summary>
    /// Gets or sets the file path.
    /// </summary>
    public string Path
    {
        get => _path;
        set => SetField(ref _path, value);
    }

    /// <summary>
    /// Gets or sets the SHA-256 hash (uppercase hex).
    /// </summary>
    public string Sha256
    {
        get => _sha256;
        set => SetField(ref _sha256, value);
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
    /// Gets the list of actions for the combo box.
    /// </summary>
    public Array Actions => Enum.GetValues(typeof(PolicyAction));

    // Commands
    public ICommand BrowseCommand { get; }
    public ICommand OkCommand { get; }

    /// <summary>
    /// Gets the result whitelist entry, or null if not yet created or cancelled.
    /// </summary>
    public WhitelistEntry? Result { get; private set; }

    /// <summary>
    /// Initializes a new instance of the AddWhitelistWindowViewModel class.
    /// </summary>
    /// <param name="fileDialogService">The file dialog service for browsing files.</param>
    public AddWhitelistWindowViewModel(IFileDialogService? fileDialogService = null)
    {
        _fileDialogService = fileDialogService ?? new FileDialogService();
        BrowseCommand = new RelayCommand(Browse);
        OkCommand = new RelayCommand(Ok, CanOk);
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
    /// Determines whether the OK command can execute.
    /// </summary>
    private bool CanOk() => !string.IsNullOrWhiteSpace(Path) && IsValid;

    /// <summary>
    /// Handles the Browse command to select a file and compute its SHA-256.
    /// </summary>
    private void Browse()
    {
        string? file = _fileDialogService.ShowOpenFileDialog(
            "Choose the file",
            FileDialogService.ExecutableFilter,
            _owner);
        
        if (file != null)
        {
            try
            {
                using FileStream fs = File.OpenRead(file);
                Sha256 = Convert.ToHexString(SHA256.HashData(fs));
                Path = file;
            }
            catch (IOException)
            {
                // Error will be shown by caller if needed
            }
            catch (UnauthorizedAccessException)
            {
                // Error will be shown by caller if needed
            }
        }
    }

    /// <summary>
    /// Handles the OK command to create the whitelist entry.
    /// </summary>
    private void Ok()
    {
        if (!IsValid)
        {
            // Validate will have already been called by CanOk
            return;
        }

        Result = new WhitelistEntry
        {
            Timestamp = DateTimeOffset.UtcNow,
            Action = SelectedAction,
            ProcessName = System.IO.Path.GetFileName(Path),
            ProcessPath = Path,
            Sha256 = Sha256.Trim(),
            CommandLine = string.Empty,
            FileSize = -1,
            Source = "Admin",
        };
    }

    /// <summary>
    /// Validates the Path property.
    /// </summary>
    protected override ValidationResult ValidatePropertyCore(string propertyName)
    {
        if (propertyName == nameof(Path))
        {
            return ValidatePath();
        }
        else if (propertyName == nameof(Sha256))
        {
            return ValidateSha256();
        }
        return ValidationResult.Success();
    }

    private ValidationResult ValidatePath()
    {
        if (string.IsNullOrWhiteSpace(Path))
        {
            return ValidationResult.Fail("File path is required");
        }
        
        if (Path.IndexOfAny(System.IO.Path.GetInvalidPathChars()) >= 0)
        {
            return ValidationResult.Fail("Invalid file path");
        }
        
        return ValidationResult.Success();
    }

    private ValidationResult ValidateSha256()
    {
        if (string.IsNullOrWhiteSpace(Sha256))
        {
            return ValidationResult.Fail("SHA-256 hash is required");
        }
        
        if (Sha256.Length != 64 || !IsHexString(Sha256))
        {
            return ValidationResult.Fail("SHA-256 must be a 64-character hexadecimal string");
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
