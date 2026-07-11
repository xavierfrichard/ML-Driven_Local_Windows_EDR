using System.IO;
using System.Windows;
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

    private void Ok_Click(object sender, RoutedEventArgs e)
    {
        string path = PathBox.Text?.Trim() ?? string.Empty;
        if (string.IsNullOrEmpty(path))
        {
            MessageBox.Show(this, "Enter a process path.", "Manual Whitelist Entry", MessageBoxButton.OK, MessageBoxImage.Warning);
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
            Source = "ManualUi",
        };
        DialogResult = true;
    }
}
