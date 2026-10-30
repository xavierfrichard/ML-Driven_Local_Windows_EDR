using System;
using Warden.Storage;
using Xunit;

namespace Warden.Ui.ViewModels;

public class AddWhitelistWindowViewModelTests
{
    [Fact]
    public void Constructor_ShouldInitialize_WithDefaultValues()
    {
        // Arrange & Act
        var viewModel = new AddWhitelistWindowViewModel();

        // Assert
        Assert.Empty(viewModel.Path);
        Assert.Empty(viewModel.Sha256);
        Assert.Equal(PolicyAction.Allow, viewModel.SelectedAction);
    }

    [Fact]
    public void Path_ShouldBeEmpty_Initially()
    {
        // Arrange
        var viewModel = new AddWhitelistWindowViewModel();

        // Assert
        Assert.Empty(viewModel.Path);
    }

    [Fact]
    public void SetPath_ShouldRaisePropertyChanged()
    {
        // Arrange
        var viewModel = new AddWhitelistWindowViewModel();
        bool propertyChanged = false;
        
        viewModel.PropertyChanged += (sender, e) =>
        {
            if (e.PropertyName == nameof(viewModel.Path))
                propertyChanged = true;
        };

        // Act
        viewModel.Path = "C:\\test.exe";

        // Assert
        Assert.True(propertyChanged);
        Assert.Equal("C:\\test.exe", viewModel.Path);
    }

    [Fact]
    public void SetSha256_ShouldRaisePropertyChanged()
    {
        // Arrange
        var viewModel = new AddWhitelistWindowViewModel();
        bool propertyChanged = false;
        
        viewModel.PropertyChanged += (sender, e) =>
        {
            if (e.PropertyName == nameof(viewModel.Sha256))
                propertyChanged = true;
        };

        // Act
        viewModel.Sha256 = new string('A', 64);

        // Assert
        Assert.True(propertyChanged);
        Assert.Equal(64, viewModel.Sha256.Length);
    }

    [Fact]
    public void CanOk_ShouldReturnFalse_WhenPathIsEmpty()
    {
        // Arrange
        var viewModel = new AddWhitelistWindowViewModel();

        // Act & Assert
        Assert.False(viewModel.OkCommand.CanExecute(null));
    }

    [Fact]
    public void CanOk_ShouldReturnFalse_WhenSha256IsInvalid()
    {
        // Arrange
        var viewModel = new AddWhitelistWindowViewModel();
        viewModel.Path = "C:\\test.exe";
        viewModel.Sha256 = "Invalid";

        // Act & Assert
        Assert.False(viewModel.OkCommand.CanExecute(null));
    }

    [Fact]
    public void Validate_EmptyPath_ShouldFail()
    {
        // Arrange
        var viewModel = new AddWhitelistWindowViewModel();

        // Act
        var result = viewModel.Validate();

        // Assert
        Assert.False(result.IsValid);
        Assert.Contains("required", result.FirstError ?? string.Empty, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Validate_InvalidSha256_ShouldFail()
    {
        // Arrange
        var viewModel = new AddWhitelistWindowViewModel();
        viewModel.Path = "C:\\test.exe";
        viewModel.Sha256 = "InvalidHash";

        // Act
        var result = viewModel.Validate();

        // Assert
        Assert.False(result.IsValid);
        Assert.Contains("hexadecimal", result.FirstError ?? string.Empty, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Validate_ValidData_ShouldPass()
    {
        // Arrange
        var viewModel = new AddWhitelistWindowViewModel();
        viewModel.Path = "C:\\test.exe";
        viewModel.Sha256 = new string('A', 64);

        // Act
        var result = viewModel.Validate();

        // Assert
        Assert.True(result.IsValid);
    }

    [Fact]
    public void Ok_ShouldCreate_WhitelistEntry_WhenValid()
    {
        // Arrange
        var viewModel = new AddWhitelistWindowViewModel();
        viewModel.Path = "C:\\test\\app.exe";
        viewModel.Sha256 = new string('A', 64);
        viewModel.SelectedAction = PolicyAction.Allow;

        // Act
        viewModel.OkCommand.Execute(null);

        // Assert
        Assert.NotNull(viewModel.Result);
        Assert.Equal("app.exe", viewModel.Result.ProcessName);
        Assert.Equal("C:\\test\\app.exe", viewModel.Result.ProcessPath);
        Assert.Equal(new string('A', 64), viewModel.Result.Sha256);
        Assert.Equal(PolicyAction.Allow, viewModel.Result.Action);
        Assert.Equal("Admin", viewModel.Result.Source);
    }

    [Fact]
    public void ComputeSha256_ShouldReturn_ValidHash()
    {
        // Arrange
        // Create a temporary file with known content
        var tempPath = System.IO.Path.GetTempFileName();
        System.IO.File.WriteAllText(tempPath, "Test content");

        try
        {
            // Act
            var hash = AddWhitelistWindowViewModel.ComputeSha256(tempPath);

            // Assert
            Assert.NotNull(hash);
            Assert.Equal(64, hash.Length);
            Assert.Matches("^[0-9A-Fa-f]{64}$", hash);
        }
        finally
        {
            System.IO.File.Delete(tempPath);
        }
    }

    [Fact]
    public void Actions_ShouldReturn_AllPolicyActions()
    {
        // Arrange
        var viewModel = new AddWhitelistWindowViewModel();

        // Act
        var actions = viewModel.Actions;

        // Assert
        Assert.Equal(2, actions.Length); // Allow, Block
        Assert.Contains(PolicyAction.Allow, (IEnumerable<PolicyAction>)actions);
        Assert.Contains(PolicyAction.Block, (IEnumerable<PolicyAction>)actions);
    }

    [Fact]
    public void SelectedAction_ShouldDefault_ToAllow()
    {
        // Arrange
        var viewModel = new AddWhitelistWindowViewModel();

        // Assert
        Assert.Equal(PolicyAction.Allow, viewModel.SelectedAction);
    }

    [Fact]
    public void SetSelectedAction_ShouldRaisePropertyChanged()
    {
        // Arrange
        var viewModel = new AddWhitelistWindowViewModel();
        bool propertyChanged = false;
        
        viewModel.PropertyChanged += (sender, e) =>
        {
            if (e.PropertyName == nameof(viewModel.SelectedAction))
                propertyChanged = true;
        };

        // Act
        viewModel.SelectedAction = PolicyAction.Block;

        // Assert
        Assert.True(propertyChanged);
        Assert.Equal(PolicyAction.Block, viewModel.SelectedAction);
    }
}
