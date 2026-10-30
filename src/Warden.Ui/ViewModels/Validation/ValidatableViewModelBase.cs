using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Runtime.CompilerServices;

namespace Warden.Ui.ViewModels.Validation;

/// <summary>
/// Base class for ViewModels that support validation.
/// </summary>
public abstract class ValidatableViewModelBase : ViewModelBase, IValidatableViewModel
{
    private readonly Dictionary<string, List<string>> _propertyErrors = new();
    private ValidationResult? _lastValidationResult;

    /// <summary>
    /// Gets a value indicating whether the ViewModel is currently valid.
    /// </summary>
    public bool IsValid => Validate().IsValid;

    /// <summary>
    /// Gets the current validation errors for all properties.
    /// </summary>
    public IReadOnlyList<string> ValidationErrors => _propertyErrors.Values.SelectMany(e => e).ToList().AsReadOnly();

    /// <summary>
    /// Gets the first validation error, or null if valid.
    /// </summary>
    public string? FirstValidationError => ValidationErrors.FirstOrDefault();

    /// <summary>
    /// Gets the validation errors for a specific property.
    /// </summary>
    /// <param name="propertyName">The name of the property.</param>
    public IReadOnlyList<string> GetErrors(string propertyName)
    {
        return _propertyErrors.TryGetValue(propertyName, out var errors) 
            ? errors.AsReadOnly() 
            : new List<string>().AsReadOnly();
    }

    /// <summary>
    /// Validates the entire ViewModel.
    /// </summary>
    public ValidationResult Validate()
    {
        _propertyErrors.Clear();
        
        var result = new ValidationResult();
        var properties = GetType().GetProperties()
            .Where(p => p.CanRead && p.GetIndexParameters().Length == 0);
        
        foreach (var property in properties)
        {
            var propertyResult = ValidatePropertyCore(property.Name);
            result = result.Combine(propertyResult);
            
            if (!propertyResult.IsValid)
            {
                if (!_propertyErrors.TryGetValue(property.Name, out var errors))
                {
                    errors = new List<string>();
                    _propertyErrors[property.Name] = errors;
                }
                errors.AddRange(propertyResult.Errors);
            }
        }
        
        _lastValidationResult = result;
        OnPropertyChanged(nameof(IsValid));
        OnPropertyChanged(nameof(ValidationErrors));
        OnPropertyChanged(nameof(FirstValidationError));
        
        return result;
    }

    /// <summary>
    /// Validates a specific property.
    /// </summary>
    /// <param name="propertyName">The name of the property to validate.</param>
    public ValidationResult ValidateProperty(string propertyName)
    {
        var result = ValidatePropertyCore(propertyName);
        
        if (!_propertyErrors.TryGetValue(propertyName, out var errors))
        {
            errors = new List<string>();
            _propertyErrors[propertyName] = errors;
        }
        else
        {
            errors.Clear();
        }
        
        if (!result.IsValid)
        {
            errors.AddRange(result.Errors);
        }
        
        OnPropertyChanged(nameof(IsValid));
        OnPropertyChanged(nameof(ValidationErrors));
        OnPropertyChanged(nameof(FirstValidationError));
        OnPropertyChanged($"Errors[{propertyName}]");
        
        return result;
    }

    /// <summary>
    /// Validates a specific property. Override this in derived classes to provide custom validation.
    /// </summary>
    /// <param name="propertyName">The name of the property to validate.</param>
    protected virtual ValidationResult ValidatePropertyCore(string propertyName)
    {
        return ValidationResult.Success();
    }

    /// <summary>
    /// Sets the value of a property and validates it if validation is enabled.
    /// </summary>
    /// <typeparam name="T">The type of the property.</typeparam>
    /// <param name="field">Reference to the backing field.</param>
    /// <param name="value">The new value.</param>
    /// <param name="propertyName">The name of the property.</param>
    /// <param name="validate">Whether to validate the property after setting.</param>
    /// <returns>True if the value was changed; false otherwise.</returns>
    protected bool SetField<T>(ref T field, T value, [CallerMemberName] string? propertyName = null, bool validate = true)
    {
        if (EqualityComparer<T>.Default.Equals(field, value))
        {
            return false;
        }

        field = value;
        OnPropertyChanged(propertyName);
        
        if (validate && propertyName is not null)
        {
            ValidateProperty(propertyName);
        }
        
        return true;
    }

    /// <summary>
    /// Sets the value of a property and validates it if validation is enabled.
    /// </summary>
    /// <typeparam name="T">The type of the property.</typeparam>
    /// <param name="field">Reference to the backing field.</param>
    /// <param name="value">The new value.</param>
    /// <param name="onChanged">Callback to invoke when the value changes.</param>
    /// <param name="propertyName">The name of the property.</param>
    /// <param name="validate">Whether to validate the property after setting.</param>
    /// <returns>True if the value was changed; false otherwise.</returns>
    protected bool SetField<T>(ref T field, T value, Action? onChanged, [CallerMemberName] string? propertyName = null, bool validate = true)
    {
        if (EqualityComparer<T>.Default.Equals(field, value))
        {
            return false;
        }

        field = value;
        OnPropertyChanged(propertyName);
        onChanged?.Invoke();
        
        if (validate && propertyName is not null)
        {
            ValidateProperty(propertyName);
        }
        
        return true;
    }
}
