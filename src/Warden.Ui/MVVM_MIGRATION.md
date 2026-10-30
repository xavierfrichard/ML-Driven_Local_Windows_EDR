# MVVM Migration Documentation

## Overview

This document describes the migration of the Warden UI from code-behind to MVVM (Model-View-ViewModel) pattern. This migration aims to improve separation of concerns, testability, and maintainability.

## Migration Strategy

### Hybrid Approach
- **ViewModels**: Handle data, business logic, validation, and commands
- **Code-behind**: Handle dialogs, navigation, and view-specific behavior
- **XAML**: Contains bindings to ViewModel properties and commands

### Key Principles
1. **Data Binding**: Two-way binding with `UpdateSourceTrigger=PropertyChanged` for real-time validation
2. **Command Pattern**: Use `RelayCommand` for all user actions
3. **Validation**: Property-level validation through `IValidatableViewModel`
4. **Separation of Concerns**: ViewModels contain no UI-specific code

## Created Files

### Base Classes
- `ViewModels/ViewModelBase.cs` - Base ViewModel with INotifyPropertyChanged and SetField helper
- `ViewModels/RelayCommand.cs` - Command implementations (sync and async)

### View Models
- `ViewModels/MainWindowViewModel.cs` - Main window ViewModel with all tabs and commands
- `ViewModels/PromptWindowViewModel.cs` - ViewModel for prompt dialog
- `ViewModels/AddRuleWindowViewModel.cs` - ViewModel with validation for rule creation
- `ViewModels/AddWhitelistWindowViewModel.cs` - ViewModel with validation for whitelist entries

### Validation Infrastructure
- `ViewModels/Validation/ValidationResult.cs` - Validation result container
- `ViewModels/Validation/IValidatableViewModel.cs` - Validation interface
- `ViewModels/Validation/ValidatableViewModelBase.cs` - Validatable base class

### Services
- `Services/IDialogService.cs` - Dialog service interface
- `Services/DialogService.cs` - Dialog service implementation

### Converters
- `Converters/BoolToVisibilityConverter.cs` - Common value converter

### Tests
- `tests/Warden.Ui.Tests/ViewModels/ViewModelBaseTests.cs`
- `tests/Warden.Ui.Tests/ViewModels/RelayCommandTests.cs`
- `tests/Warden.Ui.Tests/ViewModels/PromptWindowViewModelTests.cs`
- `tests/Warden.Ui.Tests/ViewModels/AddRuleWindowViewModelTests.cs`
- `tests/Warden.Ui.Tests/ViewModels/AddWhitelistWindowViewModelTests.cs`
- `tests/Warden.Ui.Tests/ViewModels/Validation/ValidationResultTests.cs`

## Modified Files

### XAML Files
- `MainWindow.xaml` - Added DataContext and data bindings for all DataGrids
- `PromptWindow.xaml` - Full MVVM with command bindings
- `AddRuleWindow.xaml` - Added data bindings to ViewModel
- `AddWhitelistWindow.xaml` - Added data bindings to ViewModel

### Code-behind Files
- `MainWindow.xaml.cs` - Uses MainWindowViewModel for data, keeps dialog handlers
- `PromptWindow.xaml.cs` - Simplified, uses ViewModel
- `AddRuleWindow.xaml.cs` - Uses ViewModel, keeps file browse handlers
- `AddWhitelistWindow.xaml.cs` - Uses ViewModel, keeps file browse handler

### Resources
- `App.xaml` - Added BoolToVisibilityConverter resource

## Validation Implementation

### ValidationResult
- Contains `Errors` and `Warnings` collections
- `IsValid` property returns true when no errors exist
- `FirstError` returns the first error message or null
- Supports chaining with `Combine()` method
- Implicit conversion from bool for convenience

### ValidatableViewModelBase
- Abstract base class implementing `IValidatableViewModel`
- Provides `ValidationResult` property
- Abstract `Validate()` method to be implemented by derived classes
- `ValidateAllProperties()` method for bulk validation
- `OnPropertyChangedValidation()` for property-level validation

### Usage Pattern
```csharp
public override ValidationResult Validate()
{
    var result = ValidationResult.Success();
    
    if (string.IsNullOrEmpty(Name))
        result.AddError("Name is required");
    
    if (Name?.Length > 100)
        result.AddError("Name must be less than 100 characters");
    
    return result;
}
```

## Command Implementation

### RelayCommand
- Implements `ICommand` interface
- Supports both synchronous and asynchronous execution
- Automatic `CanExecute` based on predicate function
- `RaiseCanExecuteChanged()` for manual refresh

### Usage Pattern
```csharp
private RelayCommand _saveCommand;
public ICommand SaveCommand => _saveCommand ??= new RelayCommand(
    execute: Save,
    canExecute: () => IsValid
);
```

## Dialog Service

### IDialogService
- `ShowMessage()` - Shows information message
- `ShowWarning()` - Shows warning message
- `ShowError()` - Shows error message
- `ShowConfirm()` - Shows confirmation dialog
- `ShowPrompt()` - Shows prompt dialog with text input

### DialogService
- WPF implementation using MessageBox and custom dialogs
- Can be mocked for testing

## Data Binding Patterns

### Two-way Binding with Validation
```xml
<TextBox Text="{Binding Name, UpdateSourceTrigger=PropertyChanged, ValidatesOnDataErrors=True}"/>
```

### Command Binding
```xml
<Button Command="{Binding SaveCommand}" Content="Save"/>
```

### Visibility Binding
```xml
<StackPanel Visibility="{Binding HasErrors, Converter={StaticResource BoolToVisibility}}">
    <!-- Error content -->
</StackPanel>
```

## Testing Strategy

### Unit Tests
- Test ViewModel logic independently of UI
- Test command execution and CanExecute conditions
- Test validation rules
- Mock dependencies using interfaces

### Integration Tests
- Test View-ViewModel binding behavior
- Test dialog service integration
- Test navigation flows

## Migration Checklist

- [x] Create base ViewModel classes
- [x] Create command implementations
- [x] Create validation infrastructure
- [x] Create dialog service
- [x] Create ViewModels for all windows
- [x] Update XAML with bindings
- [x] Update code-behind to use ViewModels
- [x] Create unit tests
- [x] Update solution file
- [ ] Verify all bindings work correctly
- [ ] Run all tests and fix failures
- [ ] Update file browse handlers to use ViewModel commands
- [ ] Integrate dialog service throughout

## Next Steps

1. **Verify Build**: Fix .NET SDK version in global.json to enable building
2. **Test Integration**: Run the application and verify all ViewModels work correctly with the updated XAML
3. **Complete Dialog Integration**: Fully integrate the dialog service throughout the application
4. **Enhance Validation**: Add more comprehensive validation rules
5. **Performance Optimization**: Review and optimize data binding performance

## Best Practices

1. **Keep ViewModels Thin**: Business logic should be in services, not ViewModels
2. **Use Dependency Injection**: Inject services into ViewModels for better testability
3. **Minimize Code-behind**: Only use code-behind for view-specific behavior
4. **Validate Early**: Implement validation at the property level for immediate feedback
5. **Use Async**: Use async commands for long-running operations

## Troubleshooting

### Common Issues
1. **Binding Not Working**: Check DataContext is set, verify property names match, ensure INotifyPropertyChanged is implemented
2. **Validation Not Triggering**: Ensure UpdateSourceTrigger=PropertyChanged is set, check ValidatesOnDataErrors=True
3. **Commands Not Executing**: Verify CanExecute returns true, check for exceptions in command handlers

### Debugging Tips
- Use Output window to see binding errors
- Use Snoop or WPF Inspector to inspect visual tree and bindings
- Check DataContext in debugger

## References

- MVVM Pattern: https://docs.microsoft.com/en-us/dotnet/architecture/maui/mvvm
- ICommand: https://docs.microsoft.com/en-us/dotnet/api/system.windows.input.icommand
- INotifyPropertyChanged: https://docs.microsoft.com/en-us/dotnet/api/system.componentmodel.inotifypropertychanged
- Data Binding: https://docs.microsoft.com/en-us/dotnet/desktop/wpf/data/data-binding-overview