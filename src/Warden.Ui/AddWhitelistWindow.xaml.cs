using System.IO;
using System.Security.Cryptography;
using System.Windows;
using Microsoft.Win32;
using Warden.Storage;
using Warden.Ui.ViewModels;

namespace Warden.Ui;

/// <summary>A small dialog for adding a manual Whitelist-panel entry (allow/block by path + optional hash).</summary>
public partial class AddWhitelistWindow : Window
{
    private readonly AddWhitelistWindowViewModel _viewModel;

    /// <summary>The whitelist entry the user built, or null if cancelled.</summary>
    public WhitelistEntry? Result => _viewModel.Result;

    public AddWhitelistWindow()
    {
        InitializeComponent();
        
        // Create and set the ViewModel
        _viewModel = new AddWhitelistWindowViewModel();
        DataContext = _viewModel;
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
            _viewModel.Sha256 = Convert.ToHexString(SHA256.HashData(fs));
            _viewModel.Path = dlg.FileName;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            MessageBox.Show(this, "Could not read the file: " + ex.Message, "Manual Whitelist Entry", MessageBoxButton.OK, MessageBoxImage.Warning);
        }
    }

    private void Ok_Click(object sender, RoutedEventArgs e)
    {
        string path = _viewModel.Path?.Trim() ?? string.Empty;
        if (string.IsNullOrEmpty(path))
        {
            MessageBox.Show(this, "Enter a file path or use Browse….", "Manual Whitelist Entry", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }
        if ((_viewModel.Sha256?.Trim().Length ?? 0) != 64)
        {
            MessageBox.Show(this, "A 64-character SHA-256 is required (use Browse… to compute it).", "Manual Whitelist Entry", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        // Create the result via ViewModel
        _viewModel.OkCommand.Execute(null);
        
        if (_viewModel.Result is not null)
        {
            DialogResult = true;
        }
    }
}
