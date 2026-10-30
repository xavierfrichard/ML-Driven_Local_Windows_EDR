using System.Collections.Generic;
using System.Linq;

namespace Warden.Ui.ViewModels.Validation;

/// <summary>
/// Represents the result of a validation operation.
/// </summary>
public sealed class ValidationResult
{
    private readonly List<string> _errors = new();
    private readonly List<string> _warnings = new();

    /// <summary>
    /// Gets a value indicating whether the validation passed (no errors).
    /// </summary>
    public bool IsValid => !_errors.Any();

    /// <summary>
    /// Gets the list of error messages.
    /// </summary>
    public IReadOnlyList<string> Errors => _errors.AsReadOnly();

    /// <summary>
    /// Gets the list of warning messages.
    /// </summary>
    public IReadOnlyList<string> Warnings => _warnings.AsReadOnly();

    /// <summary>
    /// Gets the first error message, or null if there are no errors.
    /// </summary>
    public string? FirstError => _errors.FirstOrDefault();

    /// <summary>
    /// Adds an error message.
    /// </summary>
    public void AddError(string error) => _errors.Add(error);

    /// <summary>
    /// Adds a warning message.
    /// </summary>
    public ValidationResult AddWarning(string warning)
    {
        _warnings.Add(warning);
        return this;
    }

    /// <summary>
    /// Adds multiple error messages.
    /// </summary>
    public void AddErrors(IEnumerable<string> errors) => _errors.AddRange(errors);

    /// <summary>
    /// Adds multiple warning messages.
    /// </summary>
    public void AddWarnings(IEnumerable<string> warnings) => _warnings.AddRange(warnings);

    /// <summary>
    /// Combines this result with another result.
    /// </summary>
    public ValidationResult Combine(ValidationResult other)
    {
        var result = new ValidationResult();
        result.AddErrors(_errors);
        result.AddErrors(other.Errors);
        result.AddWarnings(_warnings);
        result.AddWarnings(other.Warnings);
        return result;
    }

    /// <summary>
    /// Creates a successful validation result.
    /// </summary>
    public static ValidationResult Success() => new();

    /// <summary>
    /// Creates a failed validation result with the specified error.
    /// </summary>
    public static ValidationResult Fail(string error)
    {
        var result = new ValidationResult();
        result.AddError(error);
        return result;
    }

    /// <summary>
    /// Creates a validation result with the specified errors.
    /// </summary>
    public static ValidationResult Fail(IEnumerable<string> errors)
    {
        var result = new ValidationResult();
        result.AddErrors(errors);
        return result;
    }

    /// <summary>
    /// Creates a validation result with the specified warning.
    /// </summary>
    public static ValidationResult Warn(string warning)
    {
        var result = new ValidationResult();
        result.AddWarning(warning);
        return result;
    }

    /// <summary>
    /// Implicit conversion from bool to ValidationResult.
    /// </summary>
    public static implicit operator ValidationResult(bool success) => success ? Success() : Fail("Validation failed");
}
