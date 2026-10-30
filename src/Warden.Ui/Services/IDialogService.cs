using System.Windows;
using Warden.Storage;

namespace Warden.Ui.Services;

/// <summary>
/// Service for showing dialogs and getting user input.
/// This allows ViewModels to request user interaction without direct references to Windows.
/// </summary>
public interface IDialogService
{
    /// <summary>
    /// Shows an open file dialog and returns the selected file path.
    /// </summary>
    /// <param name="owner">The owner window.</param>
    /// <param name="title">The dialog title.</param>
    /// <param name="filter">The file filter.</param>
    /// <param name="multiselect">Whether to allow multiple selections.</param>
    /// <returns>The selected file path(s), or null if cancelled.</returns>
    string[]? ShowOpenFileDialog(Window owner, string title, string filter, bool multiselect = false);

    /// <summary>
    /// Shows an open folder dialog and returns the selected folder path.
    /// </summary>
    /// <param name="owner">The owner window.</param>
    /// <param name="title">The dialog title.</param>
    /// <returns>The selected folder path, or null if cancelled.</returns>
    string? ShowOpenFolderDialog(Window owner, string title);

    /// <summary>
    /// Shows a message box.
    /// </summary>
    /// <param name="owner">The owner window.</param>
    /// <param name="message">The message text.</param>
    /// <param name="caption">The caption.</param>
    /// <param name="button">The button configuration.</param>
    /// <param name="icon">The icon.</param>
    /// <returns>The result.</returns>
    MessageBoxResult ShowMessageBox(Window owner, string message, string caption, MessageBoxButton button, MessageBoxImage icon);

    /// <summary>
    /// Shows the Add Rule dialog and returns the result.
    /// </summary>
    /// <param name="owner">The owner window.</param>
    /// <returns>The rule entry and source path, or null if cancelled.</returns>
    (RuleEntry Rule, string? SourcePath)? ShowAddRuleDialog(Window owner);

    /// <summary>
    /// Shows the Add Whitelist dialog and returns the result.
    /// </summary>
    /// <param name="owner">The owner window.</param>
    /// <returns>The whitelist entry, or null if cancelled.</returns>
    WhitelistEntry? ShowAddWhitelistDialog(Window owner);
}
