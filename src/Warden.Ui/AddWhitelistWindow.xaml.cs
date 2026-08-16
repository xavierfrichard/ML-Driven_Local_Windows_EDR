using System.IO;
using System.Security.Cryptography;
using System.Windows;
using Microsoft.Win32;
using Warden.Storage;

namespace Warden.Ui;

/// <summary>A small dialog for adding a manual Whitelist-panel entry (allow/block by path + optional hash).</summary>
public partial class AddWhitelistWindow : Window
{
    /// <summary>The whitelist entry the user built, or null if cancelled.</summary>
    public WhitelistEntry? Result { get; private set; }

    public AddWhitelistWindow()
    {
        InitializeComponent();
        ActionBox.ItemsSource = Enum.GetValues<PolicyAction>();
        ActionBox.SelectedIndex = 0;
    }

    private void Browse_Click(object sender, RoutedEventArgs e)
    {
        var dlg = new OpenFileDialog
        {
            Title = "Choose the file",
            Filter = "Executables and libraries (*.exe;*.dll;*.ocx;*.cpl;*.scr;*.arx;*.dbx)|*.exe;*.dll;*.ocx;*.cpl;*.scr;*.arx;*.dbx|All files (*.*)|*.*",
            CheckFileExists = true,
        };
        if (dlg.ShowDialog(this) != true)
        {
            return;
        }

        try
        {
            using FileStream fs = File.OpenRead(dlg.FileName);
            ShaBox.Text = Convert.ToHexString(SHA256.HashData(fs));
            PathBox.Text = dlg.FileName;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            MessageBox.Show(this, "Could not read the file: " + ex.Message, "Manual Whitelist Entry", MessageBoxButton.OK, MessageBoxImage.Warning);
        }
    }

    private void Ok_Click(object sender, RoutedEventArgs e)
    {
        string path = PathBox.Text?.Trim() ?? string.Empty;
        if (string.IsNullOrEmpty(path))
        {
            MessageBox.Show(this, "Enter a file path or use Browse….", "Manual Whitelist Entry", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }
        if ((ShaBox.Text?.Trim().Length ?? 0) != 64)
        {
            MessageBox.Show(this, "A 64-character SHA-256 is required (use Browse… to compute it).", "Manual Whitelist Entry", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        Result = new WhitelistEntry
        {
            Timestamp = DateTimeOffset.UtcNow,
            Action = (PolicyAction)ActionBox.SelectedItem,
            ProcessName = Path.GetFileName(path),
            ProcessPath = path,
            Sha256 = ShaBox.Text?.Trim() ?? string.Empty,
            CommandLine = string.Empty,
            FileSize = -1,
            Source = "Admin",
        };
        DialogResult = true;
    }
}
