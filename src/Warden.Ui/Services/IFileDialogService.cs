using System.Threading.Tasks;

namespace Warden.Ui.Services;

/// <summary>
/// Service interface for file dialog operations.
/// This allows ViewModels to request file/folder selection without direct UI dependencies.
/// </summary>
public interface IFileDialogService
{
    /// <summary>
    /// Shows an open file dialog and returns the selected file path.
    /// </summary>
    /// <param name="title">The dialog title.</param>
    /// <param name="filter">The file filter (e.g., "Executables (*.exe)|*.exe").</param>
    /// <param name="owner">The owner window (optional).</param>
    /// <returns>The selected file path, or null if cancelled.</returns>
    string? ShowOpenFileDialog(string title, string? filter = null, object? owner = null);

    /// <summary>
    /// Shows an open folder dialog and returns the selected folder path.
    /// </summary>
    /// <param name="title">The dialog title.</param>
    /// <param name="owner">The owner window (optional).</param>
    /// <returns>The selected folder path, or null if cancelled.</returns>
    string? ShowOpenFolderDialog(string title, object? owner = null);

    /// <summary>
    /// Shows a save file dialog and returns the selected file path.
    /// </summary>
    /// <param name="title">The dialog title.</param>
    /// <param name="filter">The file filter.</param>
    /// <param name="defaultFileName">The default file name.</param>
    /// <param name="owner">The owner window (optional).</param>
    /// <returns>The selected file path, or null if cancelled.</returns>
    string? ShowSaveFileDialog(string title, string? filter = null, string? defaultFileName = null, object? owner = null);
}
