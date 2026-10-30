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
        
        // Set the owner for dialogs
        _viewModel.SetOwner(this);
    }

    private void KindBox_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        _viewModel.SourcePath = null;
        _viewModel.SourceHint = string.Empty;
    }
}
