using System.ComponentModel;

namespace Warden.Ui.ViewModels.Validation;

/// <summary>
/// Interface for ViewModels that support validation.
/// </summary>
public interface IValidatableViewModel : INotifyPropertyChanged
{
    /// <summary>
    /// Gets a value indicating whether the ViewModel is currently valid.
    /// </summary>
    bool IsValid { get; }

    /// <summary>
    /// Gets the current validation errors.
    /// </summary>
    IReadOnlyList<string> ValidationErrors { get; }

    /// <summary>
    /// Gets the first validation error, or null if valid.
    /// </summary>
    string? FirstValidationError { get; }

    /// <summary>
    /// Validates the ViewModel and returns the validation result.
    /// </summary>
    ValidationResult Validate();

    /// <summary>
    /// Validates a specific property and returns the validation result.
    /// </summary>
    /// <param name="propertyName">The name of the property to validate.</param>
    ValidationResult ValidateProperty(string propertyName);
}
