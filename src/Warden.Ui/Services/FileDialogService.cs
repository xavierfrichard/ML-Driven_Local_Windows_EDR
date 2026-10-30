using System.Windows;
using Microsoft.Win32;

namespace Warden.Ui.Services;

/// <summary>
/// WPF implementation of IFileDialogService.
/// Uses standard WPF dialogs for file/folder selection.
/// </summary>
public sealed class FileDialogService : IFileDialogService
{
    /// <summary>
    /// Default filter for executable files.
    /// </summary>
    public const string ExecutableFilter = "Executables and libraries (*.exe;*.dll;*.ocx;*.cpl;*.scr;*.arx;*.dbx)|*.exe;*.dll;*.ocx;*.cpl;*.scr;*.arx;*.dbx|All files (*.*)|*.*";

    /// <summary>
    /// Shows an open file dialog and returns the selected file path.
    /// </summary>
    public string? ShowOpenFileDialog(string title, string? filter = null, object? owner = null)
    {
        var dialog = new OpenFileDialog
        {
            Title = title,
            Filter = filter ?? "All files (*.*)|*.*",
            CheckFileExists = true,
        };

        if (owner is Window window)
        {
            return dialog.ShowDialog(window) == true ? dialog.FileName : null;
        }
        return dialog.ShowDialog() == true ? dialog.FileName : null;
    }

    /// <summary>
    /// Shows an open folder dialog and returns the selected folder path.
    /// </summary>
    public string? ShowOpenFolderDialog(string title, object? owner = null)
    {
        var dialog = new OpenFolderDialog { Title = title };

        if (owner is Window window)
        {
            return dialog.ShowDialog(window) == true ? dialog.FolderName : null;
        }
        return dialog.ShowDialog() == true ? dialog.FolderName : null;
    }

    /// <summary>
    /// Shows a save file dialog and returns the selected file path.
    /// </summary>
    public string? ShowSaveFileDialog(string title, string? filter = null, string? defaultFileName = null, object? owner = null)
    {
        var dialog = new SaveFileDialog
        {
            Title = title,
            Filter = filter ?? "All files (*.*)|*.*",
            FileName = defaultFileName ?? string.Empty,
        };

        if (owner is Window window)
        {
            return dialog.ShowDialog(window) == true ? dialog.FileName : null;
        }
        return dialog.ShowDialog() == true ? dialog.FileName : null;
    }
}
