using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Windows;
using System.Windows.Controls;
using Microsoft.Win32;
using Warden.Storage;
using Warden.Ui.ViewModels;

namespace Warden.Ui;

/// <summary>
/// A small dialog for adding a Rules-panel entry (hash / signature / folder / extension). The Browse…
/// button fills the match value from a picker: a folder for Folder rules, a file whose SHA-256 is
/// computed for Hash rules, a file whose signer name is read for Signature rules — so nobody has to type
/// a hash or a publisher name by hand.
/// </summary>
public partial class AddRuleWindow : Window
{
    private readonly AddRuleWindowViewModel _viewModel;

    /// <summary>The rule the user built, or null if cancelled.</summary>
    public RuleEntry? Result => _viewModel.Result;

    /// <summary>
    /// The file the match value was derived from (Hash / Signature rules picked through Browse…), so the
    /// service can allow-list that very file immediately instead of waiting for its next block.
    /// </summary>
    public string? SourcePath => _viewModel.SourcePath;

    public AddRuleWindow()
    {
        InitializeComponent();
        
        // Create and set the ViewModel
        _viewModel = new AddRuleWindowViewModel();
        DataContext = _viewModel;
    }

    private RuleKind Kind => _viewModel.SelectedKind;

    private void KindBox_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        _viewModel.SourcePath = null;
        _viewModel.SourceHint = string.Empty;
    }

    private void Browse_Click(object sender, RoutedEventArgs e)
    {
        switch (Kind)
        {
            case RuleKind.Folder:
            {
                var dlg = new OpenFolderDialog { Title = "Choose the folder this rule applies to" };
                if (dlg.ShowDialog(this) == true)
                {
                    _viewModel.MatchValue = dlg.FolderName;
                }
                break;
            }
            case RuleKind.Hash:
            {
                string? file = PickFile("Choose the file to compute the SHA-256 of");
                if (file is null) { break; }
                try
                {
                    using FileStream fs = File.OpenRead(file);
                    _viewModel.MatchValue = Convert.ToHexString(SHA256.HashData(fs));
                    _viewModel.SourcePath = file;
                    _viewModel.SourceHint = $"From {file}";
                }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
                {
                    MessageBox.Show(this, "Could not read the file: " + ex.Message, "Add Rule", MessageBoxButton.OK, MessageBoxImage.Warning);
                }
                break;
            }
            case RuleKind.Signature:
            {
                string? file = PickFile("Choose a signed file to read the publisher from");
                if (file is null) { break; }
                string? publisher = ReadPublisher(file, out string? error);
                if (publisher is null)
                {
                    MessageBox.Show(this, error ?? "The file has no embedded signature.", "Add Rule", MessageBoxButton.OK, MessageBoxImage.Warning);
                    break;
                }
                _viewModel.MatchValue = publisher;
                _viewModel.SourcePath = file;
                _viewModel.SourceHint = $"From {file}";
                break;
            }
        }
    }

    private string? PickFile(string title)
    {
        var dlg = new OpenFileDialog
        {
            Title = title,
            Filter = "Executables and libraries (*.exe;*.dll;*.ocx;*.cpl;*.scr;*.arx;*.dbx)|*.exe;*.dll;*.ocx;*.cpl;*.scr;*.arx;*.dbx|All files (*.*)|*.*",
            CheckFileExists = true,
        };
        return dlg.ShowDialog(this) == true ? dlg.FileName : null;
    }

    /// <summary>The leaf certificate's Common Name (what a Signature rule matches as a substring of the subject).</summary>
    private static string? ReadPublisher(string file, out string? error)
    {
        error = null;
        try
        {
            using var cert = new X509Certificate2(X509Certificate.CreateFromSignedFile(file));
            string cn = cert.GetNameInfo(X509NameType.SimpleName, forIssuer: false);
            return string.IsNullOrWhiteSpace(cn) ? cert.Subject : cn;
        }
        catch (CryptographicException)
        {
            error = "The file has no embedded Authenticode signature (catalog-signed Windows files show up as unsigned).";
            return null;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            error = "Could not read the file: " + ex.Message;
            return null;
        }
    }

    private void Ok_Click(object sender, RoutedEventArgs e)
    {
        string match = _viewModel.MatchValue?.Trim() ?? string.Empty;
        if (string.IsNullOrEmpty(match))
        {
            MessageBox.Show(this, "Enter a match value or use Browse….", "Add Rule", MessageBoxButton.OK, MessageBoxImage.Warning);
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
