using System.Linq;
using Warden.Ui.ViewModels.Validation;
using Xunit;

namespace Warden.Ui.ViewModels.Validation;

public class ValidationResultTests
{
    [Fact]
    public void Success_ShouldCreate_ValidResult()
    {
        // Arrange & Act
        var result = ValidationResult.Success();

        // Assert
        Assert.True(result.IsValid);
        Assert.Empty(result.Errors);
        Assert.Empty(result.Warnings);
        Assert.Null(result.FirstError);
    }

    [Fact]
    public void Fail_WithSingleError_ShouldCreate_InvalidResult()
    {
        // Arrange & Act
        var result = ValidationResult.Fail("Error message");

        // Assert
        Assert.False(result.IsValid);
        Assert.Single(result.Errors);
        Assert.Equal("Error message", result.Errors[0]);
        Assert.Equal("Error message", result.FirstError);
    }

    [Fact]
    public void Fail_WithMultipleErrors_ShouldCreate_InvalidResult()
    {
        // Arrange
        var errors = new[] { "Error 1", "Error 2", "Error 3" };

        // Act
        var result = ValidationResult.Fail(errors);

        // Assert
        Assert.False(result.IsValid);
        Assert.Equal(3, result.Errors.Count);
        Assert.Equal("Error 1", result.FirstError);
    }

    [Fact]
    public void Warn_ShouldCreate_ValidResultWithWarning()
    {
        // Arrange & Act
        var result = ValidationResult.Warn("Warning message");

        // Assert
        Assert.True(result.IsValid);
        Assert.Empty(result.Errors);
        Assert.Single(result.Warnings);
        Assert.Equal("Warning message", result.Warnings[0]);
    }

    [Fact]
    public void AddError_ShouldAdd_ToErrors()
    {
        // Arrange
        var result = ValidationResult.Success();

        // Act
        result.AddError("Error 1");
        result.AddError("Error 2");

        // Assert
        Assert.False(result.IsValid);
        Assert.Equal(2, result.Errors.Count);
    }

    [Fact]
    public void AddWarning_ShouldAdd_ToWarnings()
    {
        // Arrange
        var result = ValidationResult.Success();

        // Act
        result.AddWarning("Warning 1");
        result.AddWarning("Warning 2");

        // Assert
        Assert.True(result.IsValid);
        Assert.Equal(2, result.Warnings.Count);
    }

    [Fact]
    public void Combine_ShouldMerge_Results()
    {
        // Arrange
        var result1 = ValidationResult.Fail("Error 1");
        var result2 = ValidationResult.Fail("Error 2").AddWarning("Warning 1");

        // Act
        var combined = result1.Combine(result2);

        // Assert
        Assert.False(combined.IsValid);
        Assert.Equal(2, combined.Errors.Count);
        Assert.Single(combined.Warnings);
    }

    [Fact]
    public void Combine_WithSuccess_ShouldPreserve_Errors()
    {
        // Arrange
        var result1 = ValidationResult.Fail("Error 1");
        var result2 = ValidationResult.Success();

        // Act
        var combined = result1.Combine(result2);

        // Assert
        Assert.False(combined.IsValid);
        Assert.Single(combined.Errors);
    }

    [Fact]
    public void ImplicitConversion_FromBool_ShouldWork()
    {
        // Arrange & Act
        ValidationResult success = true;
        ValidationResult fail = false;

        // Assert
        Assert.True(success.IsValid);
        Assert.False(fail.IsValid);
    }

    [Fact]
    public void AddErrors_ShouldAdd_MultipleErrors()
    {
        // Arrange
        var result = ValidationResult.Success();
        var errors = new[] { "Error 1", "Error 2" };

        // Act
        result.AddErrors(errors);

        // Assert
        Assert.False(result.IsValid);
        Assert.Equal(2, result.Errors.Count);
    }

    [Fact]
    public void AddWarnings_ShouldAdd_MultipleWarnings()
    {
        // Arrange
        var result = ValidationResult.Success();
        var warnings = new[] { "Warning 1", "Warning 2" };

        // Act
        result.AddWarnings(warnings);

        // Assert
        Assert.True(result.IsValid);
        Assert.Equal(2, result.Warnings.Count);
    }
}
