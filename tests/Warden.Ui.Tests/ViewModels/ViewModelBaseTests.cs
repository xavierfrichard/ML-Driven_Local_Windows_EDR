using System.ComponentModel;
using Xunit;

namespace Warden.Ui.ViewModels;

public class ViewModelBaseTests
{
    [Fact]
    public void SetField_ShouldRaisePropertyChanged_WhenValueChanges()
    {
        // Arrange
        var viewModel = new TestViewModel();
        bool propertyChanged = false;
        string? propertyName = null;
        
        viewModel.PropertyChanged += (sender, e) =>
        {
            propertyChanged = true;
            propertyName = e.PropertyName;
        };

        // Act
        viewModel.TestProperty = "NewValue";

        // Assert
        Assert.True(propertyChanged);
        Assert.Equal(nameof(TestViewModel.TestProperty), propertyName);
        Assert.Equal("NewValue", viewModel.TestProperty);
    }

    [Fact]
    public void SetField_ShouldNotRaisePropertyChanged_WhenValueDoesNotChange()
    {
        // Arrange
        var viewModel = new TestViewModel { TestProperty = "Initial" };
        bool propertyChanged = false;
        
        viewModel.PropertyChanged += (sender, e) => propertyChanged = true;

        // Act
        viewModel.TestProperty = "Initial";

        // Assert
        Assert.False(propertyChanged);
    }

    [Fact]
    public void SetField_WithCallback_ShouldInvokeCallback()
    {
        // Arrange
        var viewModel = new TestViewModel();
        bool callbackInvoked = false;

        // Act
        viewModel.SetFieldWithCallback("NewValue", () => callbackInvoked = true);

        // Assert
        Assert.True(callbackInvoked);
        Assert.Equal("NewValue", viewModel.TestProperty);
    }

    [Fact]
    public void PropertyChanged_ShouldBeRaised_WhenPropertyChanges()
    {
        // Arrange
        var viewModel = new TestViewModel();
        string? propertyName = null;
        viewModel.PropertyChanged += (s, e) => propertyName = e.PropertyName;

        // Act
        viewModel.TestProperty = "NewValue";

        // Assert
        Assert.Equal(nameof(TestViewModel.TestProperty), propertyName);
    }

    [Fact]
    public void PropertyChanged_ShouldNotBeRaised_WhenValueDoesNotChange()
    {
        // Arrange
        var viewModel = new TestViewModel { TestProperty = "Initial" };
        int eventCount = 0;
        viewModel.PropertyChanged += (s, e) => eventCount++;

        // Act
        viewModel.TestProperty = "Initial";

        // Assert
        Assert.Equal(0, eventCount);
    }

    private sealed class TestViewModel : ViewModelBase
    {
        private string _testProperty = string.Empty;

        public string TestProperty
        {
            get => _testProperty;
            set => SetField(ref _testProperty, value);
        }

        public void SetFieldWithCallback(string value, Action? callback)
        {
            SetField(ref _testProperty, value, callback);
        }
    }
}
