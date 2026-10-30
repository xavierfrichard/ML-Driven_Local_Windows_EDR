using System;
using Warden.Storage;
using Xunit;

namespace Warden.Ui.ViewModels;

public class AddRuleWindowViewModelTests
{
    [Fact]
    public void Constructor_ShouldInitialize_WithDefaultValues()
    {
        // Arrange & Act
        var viewModel = new AddRuleWindowViewModel();

        // Assert
        Assert.Equal(RuleKind.Hash, viewModel.SelectedKind);
        Assert.Equal(PolicyAction.Allow, viewModel.SelectedAction);
        Assert.Empty(viewModel.MatchValue);
        Assert.False(viewModel.RequireSignature);
        Assert.False(viewModel.RequireWhitelist);
        Assert.Empty(viewModel.Note);
        Assert.True(viewModel.BrowseButtonEnabled);
    }

    [Fact]
    public void SelectedKind_ShouldUpdate_Hints_WhenChanged()
    {
        // Arrange
        var viewModel = new AddRuleWindowViewModel();

        // Act - Change to Signature
        viewModel.SelectedKind = RuleKind.Signature;

        // Assert
        Assert.Contains("Publisher name", viewModel.MatchHint);
    }

    [Fact]
    public void SelectedKind_Extension_ShouldDisable_BrowseButton()
    {
        // Arrange
        var viewModel = new AddRuleWindowViewModel();

        // Act - Change to Extension
        viewModel.SelectedKind = RuleKind.Extension;

        // Assert
        Assert.False(viewModel.BrowseButtonEnabled);
    }

    [Fact]
    public void MatchValue_ShouldBeEmpty_Initially()
    {
        // Arrange
        var viewModel = new AddRuleWindowViewModel();

        // Assert
        Assert.Empty(viewModel.MatchValue);
    }

    [Fact]
    public void SetMatchValue_ShouldRaisePropertyChanged()
    {
        // Arrange
        var viewModel = new AddRuleWindowViewModel();
        bool propertyChanged = false;
        
        viewModel.PropertyChanged += (sender, e) =>
        {
            if (e.PropertyName == nameof(viewModel.MatchValue))
                propertyChanged = true;
        };

        // Act
        viewModel.MatchValue = "TestHash";

        // Assert
        Assert.True(propertyChanged);
        Assert.Equal("TestHash", viewModel.MatchValue);
    }

    [Fact]
    public void CanOk_ShouldReturnFalse_WhenMatchValueIsEmpty()
    {
        // Arrange
        var viewModel = new AddRuleWindowViewModel();

        // Act & Assert
        Assert.False(viewModel.OkCommand.CanExecute(null));
    }

    [Fact]
    public void Validate_EmptyMatchValue_ShouldFail()
    {
        // Arrange
        var viewModel = new AddRuleWindowViewModel();

        // Act
        var result = viewModel.Validate();

        // Assert
        Assert.False(result.IsValid);
        Assert.Contains("required", result.FirstError ?? string.Empty, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Validate_InvalidHash_ShouldFail()
    {
        // Arrange
        var viewModel = new AddRuleWindowViewModel();
        viewModel.MatchValue = "InvalidHash";

        // Act
        var result = viewModel.Validate();

        // Assert
        Assert.False(result.IsValid);
        Assert.Contains("hexadecimal", result.FirstError ?? string.Empty, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Validate_ValidHash_ShouldPass()
    {
        // Arrange
        var viewModel = new AddRuleWindowViewModel();
        viewModel.MatchValue = new string('A', 64); // 64-character hex string

        // Act
        var result = viewModel.Validate();

        // Assert
        Assert.True(result.IsValid);
    }

    [Fact]
    public void Validate_ExtensionWithoutDot_ShouldFail()
    {
        // Arrange
        var viewModel = new AddRuleWindowViewModel();
        viewModel.SelectedKind = RuleKind.Extension;
        viewModel.MatchValue = "exe";

        // Act
        var result = viewModel.Validate();

        // Assert
        Assert.False(result.IsValid);
        Assert.Contains("dot", result.FirstError ?? string.Empty, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Validate_ValidExtension_ShouldPass()
    {
        // Arrange
        var viewModel = new AddRuleWindowViewModel();
        viewModel.SelectedKind = RuleKind.Extension;
        viewModel.MatchValue = ".exe";

        // Act
        var result = viewModel.Validate();

        // Assert
        Assert.True(result.IsValid);
    }

    [Fact]
    public void Ok_ShouldCreate_RuleEntry_WhenValid()
    {
        // Arrange
        var viewModel = new AddRuleWindowViewModel();
        viewModel.MatchValue = new string('A', 64);
        viewModel.SelectedKind = RuleKind.Hash;
        viewModel.SelectedAction = PolicyAction.Allow;
        viewModel.RequireSignature = true;
        viewModel.Note = "Test note";

        // Act
        viewModel.OkCommand.Execute(null);

        // Assert
        Assert.NotNull(viewModel.Result);
        Assert.Equal(RuleKind.Hash, viewModel.Result.Kind);
        Assert.Equal(PolicyAction.Allow, viewModel.Result.Action);
        Assert.True(viewModel.Result.RequireSignature);
        Assert.Equal("Test note", viewModel.Result.Note);
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
            var hash = AddRuleWindowViewModel.ComputeSha256(tempPath);

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
    public void RuleKinds_ShouldReturn_AllRuleKinds()
    {
        // Arrange
        var viewModel = new AddRuleWindowViewModel();

        // Act
        var kinds = viewModel.RuleKinds;

        // Assert
        Assert.Equal(4, kinds.Length); // Hash, Signature, Folder, Extension
        Assert.Contains(RuleKind.Hash, (IEnumerable<RuleKind>)kinds);
        Assert.Contains(RuleKind.Signature, (IEnumerable<RuleKind>)kinds);
        Assert.Contains(RuleKind.Folder, (IEnumerable<RuleKind>)kinds);
        Assert.Contains(RuleKind.Extension, (IEnumerable<RuleKind>)kinds);
    }

    [Fact]
    public void Actions_ShouldReturn_AllPolicyActions()
    {
        // Arrange
        var viewModel = new AddRuleWindowViewModel();

        // Act
        var actions = viewModel.Actions;

        // Assert
        Assert.Equal(2, actions.Length); // Allow, Block
        Assert.Contains(PolicyAction.Allow, (IEnumerable<PolicyAction>)actions);
        Assert.Contains(PolicyAction.Block, (IEnumerable<PolicyAction>)actions);
    }
}
