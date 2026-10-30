using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Windows;
using Microsoft.Win32;
using Warden.Storage;

namespace Warden.Ui.Services;

/// <summary>
/// Default implementation of IDialogService using WPF dialogs.
/// </summary>
public sealed class DialogService : IDialogService
{
    /// <summary>
    /// Shows an open file dialog and returns the selected file path.
    /// </summary>
    public string[]? ShowOpenFileDialog(Window owner, string title, string filter, bool multiselect = false)
    {
        var dlg = new OpenFileDialog
        {
            Title = title,
            Filter = filter,
            CheckFileExists = true,
            Multiselect = multiselect,
        };
        
        return dlg.ShowDialog(owner) == true ? dlg.FileNames : null;
    }

    /// <summary>
    /// Shows an open folder dialog and returns the selected folder path.
    /// </summary>
    public string? ShowOpenFolderDialog(Window owner, string title)
    {
        var dlg = new OpenFolderDialog { Title = title };
        return dlg.ShowDialog(owner) == true ? dlg.FolderName : null;
    }

    /// <summary>
    /// Shows a message box.
    /// </summary>
    public MessageBoxResult ShowMessageBox(Window owner, string message, string caption, MessageBoxButton button, MessageBoxImage icon)
    {
        return MessageBox.Show(owner, message, caption, button, icon);
    }

    /// <summary>
    /// Shows the Add Rule dialog and returns the result.
    /// </summary>
    public (RuleEntry Rule, string? SourcePath)? ShowAddRuleDialog(Window owner)
    {
        var dlg = new AddRuleWindow { Owner = owner };
        if (dlg.ShowDialog() == true && dlg.Result is { } rule)
        {
            return (rule, dlg.SourcePath);
        }
        return null;
    }

    /// <summary>
    /// Shows the Add Whitelist dialog and returns the result.
    /// </summary>
    public WhitelistEntry? ShowAddWhitelistDialog(Window owner)
    {
        var dlg = new AddWhitelistWindow { Owner = owner };
        return dlg.ShowDialog() == true ? dlg.Result : null;
    }
}
