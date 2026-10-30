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
        
        // Set the owner for dialogs
        _viewModel.SetOwner(this);
    }
}
