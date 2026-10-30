using System;
using System.Threading;
using System.Threading.Tasks;
using Xunit;

namespace Warden.Ui.ViewModels;

public class RelayCommandTests
{
    [Fact]
    public void RelayCommand_ShouldExecute_WhenCanExecuteIsTrue()
    {
        // Arrange
        bool executed = false;
        var command = new RelayCommand(() => executed = true);

        // Act
        command.Execute(null);

        // Assert
        Assert.True(executed);
    }

    [Fact]
    public void RelayCommand_ShouldNotExecute_WhenCanExecuteReturnsFalse()
    {
        // Arrange
        var command = new RelayCommand(
            () => { },
            () => false);

        // Act & Assert
        Assert.False(command.CanExecute(null));
    }

    [Fact]
    public void RelayCommand_CanExecute_ShouldReturnTrue_WhenNoPredicate()
    {
        // Arrange
        var command = new RelayCommand(() => { });

        // Act & Assert
        Assert.True(command.CanExecute(null));
    }

    [Fact]
    public void RelayCommand_CanExecute_ShouldReturnPredicateResult()
    {
        // Arrange
        var command = new RelayCommand(() => { }, () => false);

        // Act & Assert
        Assert.False(command.CanExecute(null));
    }

    [Fact]
    public void RelayCommand_ShouldRaiseCanExecuteChanged()
    {
        // Arrange
        var command = new RelayCommand(() => { });
        bool canExecuteChanged = false;
        
        command.CanExecuteChanged += (sender, e) => canExecuteChanged = true;

        // Act
        command.RaiseCanExecuteChanged();

        // Assert
        Assert.True(canExecuteChanged);
    }

    [Fact]
    public void RelayCommand_ShouldThrow_WhenExecuteIsNull()
    {
        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => new RelayCommand(null!));
    }

    [Fact]
    public void RelayCommand_Generic_ShouldExecuteWithParameter()
    {
        // Arrange
        string? parameter = null;
        var command = new RelayCommand<string>(p => parameter = p);

        // Act
        command.Execute("Test");

        // Assert
        Assert.Equal("Test", parameter);
    }

    [Fact]
    public void RelayCommand_Generic_ShouldCastParameter()
    {
        // Arrange
        string? parameter = null;
        var command = new RelayCommand<string>(p => parameter = p);

        // Act
        command.Execute("Test" as object);

        // Assert
        Assert.Equal("Test", parameter);
    }

    [Fact]
    public void RelayCommand_Generic_CanExecute_ShouldUsePredicate()
    {
        // Arrange
        var command = new RelayCommand<string>(
            p => { },
            p => p == "Valid");

        // Act & Assert
        Assert.True(command.CanExecute("Valid"));
        Assert.False(command.CanExecute("Invalid"));
    }

    [Fact]
    public async Task AsyncRelayCommand_ShouldExecuteAsync()
    {
        // Arrange
        bool executed = false;
        var command = new AsyncRelayCommand(async ct =>
        {
            await Task.Delay(10);
            executed = true;
        });

        // Act
        command.Execute(null);
        await Task.Delay(50); // Wait for async execution

        // Assert
        Assert.True(executed);
    }

    [Fact]
    public async Task AsyncRelayCommand_ShouldSetIsExecuting()
    {
        // Arrange
        var command = new AsyncRelayCommand(async ct =>
        {
            await Task.Delay(50);
        });

        // Act
        command.Execute(null);
        
        // Assert - should be executing
        Assert.False(command.CanExecute(null));
        
        // Wait for completion
        await Task.Delay(100);
        
        // Assert - should be able to execute again
        Assert.True(command.CanExecute(null));
    }

    [Fact]
    public async Task AsyncRelayCommand_ShouldNotExecute_WhenAlreadyExecuting()
    {
        // Arrange
        int executeCount = 0;
        var command = new AsyncRelayCommand(async ct =>
        {
            executeCount++;
            await Task.Delay(50);
        });

        // Act - execute twice quickly
        command.Execute(null);
        command.Execute(null);
        
        // Wait for completion
        await Task.Delay(100);

        // Assert - should only execute once
        Assert.Equal(1, executeCount);
    }

    [Fact]
    public async Task AsyncRelayCommand_WithParameter_ShouldExecuteAsync()
    {
        // Arrange
        string? parameter = null;
        var command = new AsyncRelayCommand<string>(async (p, ct) =>
        {
            await Task.Delay(10);
            parameter = p;
        });

        // Act
        command.Execute("Test");
        await Task.Delay(50);

        // Assert
        Assert.Equal("Test", parameter);
    }

    [Fact]
    public void AsyncRelayCommand_ShouldThrow_WhenExecuteIsNull()
    {
        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => new AsyncRelayCommand((Func<CancellationToken, Task>)null!));
    }
}
