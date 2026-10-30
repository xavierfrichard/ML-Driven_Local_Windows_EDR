using System;
using System.Windows.Input;

namespace Warden.Ui.ViewModels;

/// <summary>
/// A command that relays its execution to a delegate.
/// </summary>
public sealed class RelayCommand : ICommand
{
    private readonly Action _execute;
    private readonly Func<bool>? _canExecute;

    /// <summary>
    /// Creates a new command that can always execute.
    /// </summary>
    /// <param name="execute">The action to execute.</param>
    /// <exception cref="ArgumentNullException">Thrown when execute is null.</exception>
    public RelayCommand(Action execute) : this(execute, null)
    {
    }

    /// <summary>
    /// Creates a new command with a can-execute condition.
    /// </summary>
    /// <param name="execute">The action to execute.</param>
    /// <param name="canExecute">A function that determines if the command can execute.</param>
    /// <exception cref="ArgumentNullException">Thrown when execute is null.</exception>
    public RelayCommand(Action execute, Func<bool>? canExecute)
    {
        _execute = execute ?? throw new ArgumentNullException(nameof(execute));
        _canExecute = canExecute;
    }

    /// <summary>
    /// Defines the method that determines whether the command can execute in its current state.
    /// </summary>
    /// <param name="parameter">Data used by the command.</param>
    /// <returns>True if this command can be executed; otherwise, false.</returns>
    public bool CanExecute(object? parameter) => _canExecute?.Invoke() ?? true;

    /// <summary>
    /// Defines the method to be called when the command is invoked.
    /// </summary>
    /// <param name="parameter">Data used by the command.</param>
    public void Execute(object? parameter) => _execute();

    /// <summary>
    /// Raises the CanExecuteChanged event.
    /// </summary>
    public void RaiseCanExecuteChanged() => CanExecuteChanged?.Invoke(this, EventArgs.Empty);

    /// <summary>
    /// Occurs when changes occur that affect whether or not the command should execute.
    /// </summary>
    public event EventHandler? CanExecuteChanged;
}

/// <summary>
/// A generic command that relays its execution to a delegate with a parameter.
/// </summary>
/// <typeparam name="T">The type of the command parameter.</typeparam>
public sealed class RelayCommand<T> : ICommand
{
    private readonly Action<T?> _execute;
    private readonly Predicate<T?>? _canExecute;

    /// <summary>
    /// Creates a new command that can always execute.
    /// </summary>
    /// <param name="execute">The action to execute.</param>
    /// <exception cref="ArgumentNullException">Thrown when execute is null.</exception>
    public RelayCommand(Action<T?> execute) : this(execute, null)
    {
    }

    /// <summary>
    /// Creates a new command with a can-execute condition.
    /// </summary>
    /// <param name="execute">The action to execute.</param>
    /// <param name="canExecute">A function that determines if the command can execute.</param>
    /// <exception cref="ArgumentNullException">Thrown when execute is null.</exception>
    public RelayCommand(Action<T?> execute, Predicate<T?>? canExecute)
    {
        _execute = execute ?? throw new ArgumentNullException(nameof(execute));
        _canExecute = canExecute;
    }

    /// <summary>
    /// Defines the method that determines whether the command can execute in its current state.
    /// </summary>
    /// <param name="parameter">Data used by the command.</param>
    /// <returns>True if this command can be executed; otherwise, false.</returns>
    public bool CanExecute(object? parameter) => _canExecute?.Invoke((T?)parameter) ?? true;

    /// <summary>
    /// Defines the method to be called when the command is invoked.
    /// </summary>
    /// <param name="parameter">Data used by the command.</param>
    public void Execute(object? parameter) => _execute((T?)parameter);

    /// <summary>
    /// Raises the CanExecuteChanged event.
    /// </summary>
    public void RaiseCanExecuteChanged() => CanExecuteChanged?.Invoke(this, EventArgs.Empty);

    /// <summary>
    /// Occurs when changes occur that affect whether or not the command should execute.
    /// </summary>
    public event EventHandler? CanExecuteChanged;
}

/// <summary>
/// A command that relays its execution to an async delegate.
/// </summary>
public sealed class AsyncRelayCommand : ICommand
{
    private readonly Func<CancellationToken, Task> _execute;
    private readonly Func<bool>? _canExecute;
    private bool _isExecuting;

    /// <summary>
    /// Creates a new async command that can always execute.
    /// </summary>
    /// <param name="execute">The async action to execute (with no parameters).</param>
    /// <exception cref="ArgumentNullException">Thrown when execute is null.</exception>
    public AsyncRelayCommand(Func<Task> execute) : this(execute, null)
    {
    }

    /// <summary>
    /// Creates a new async command with a can-execute condition.
    /// </summary>
    /// <param name="execute">The async action to execute (with no parameters).</param>
    /// <param name="canExecute">A function that determines if the command can execute.</param>
    /// <exception cref="ArgumentNullException">Thrown when execute is null.</exception>
    public AsyncRelayCommand(Func<Task> execute, Func<bool>? canExecute)
        : this(_ => execute(), canExecute)
    {
    }

    /// <summary>
    /// Creates a new async command that can always execute.
    /// </summary>
    /// <param name="execute">The async action to execute.</param>
    /// <exception cref="ArgumentNullException">Thrown when execute is null.</exception>
    public AsyncRelayCommand(Func<CancellationToken, Task> execute) : this(execute, null)
    {
    }

    /// <summary>
    /// Creates a new async command with a can-execute condition.
    /// </summary>
    /// <param name="execute">The async action to execute.</param>
    /// <param name="canExecute">A function that determines if the command can execute.</param>
    /// <exception cref="ArgumentNullException">Thrown when execute is null.</exception>
    public AsyncRelayCommand(Func<CancellationToken, Task> execute, Func<bool>? canExecute)
    {
        _execute = execute ?? throw new ArgumentNullException(nameof(execute));
        _canExecute = canExecute;
    }

    /// <summary>
    /// Defines the method that determines whether the command can execute in its current state.
    /// </summary>
    /// <param name="parameter">Data used by the command.</param>
    /// <returns>True if this command can be executed; otherwise, false.</returns>
    public bool CanExecute(object? parameter) => !_isExecuting && (_canExecute?.Invoke() ?? true);

    /// <summary>
    /// Defines the method to be called when the command is invoked.
    /// </summary>
    /// <param name="parameter">Data used by the command.</param>
    public async void Execute(object? parameter)
    {
        if (_isExecuting)
        {
            return;
        }

        _isExecuting = true;
        RaiseCanExecuteChanged();

        try
        {
            await _execute(CancellationToken.None);
        }
        finally
        {
            _isExecuting = false;
            RaiseCanExecuteChanged();
        }
    }

    /// <summary>
    /// Raises the CanExecuteChanged event.
    /// </summary>
    public void RaiseCanExecuteChanged() => CanExecuteChanged?.Invoke(this, EventArgs.Empty);

    /// <summary>
    /// Occurs when changes occur that affect whether or not the command should execute.
    /// </summary>
    public event EventHandler? CanExecuteChanged;
}

/// <summary>
/// A generic async command that relays its execution to a delegate with a parameter.
/// </summary>
/// <typeparam name="T">The type of the command parameter.</typeparam>
public sealed class AsyncRelayCommand<T> : ICommand
{
    private readonly Func<T?, CancellationToken, Task> _execute;
    private readonly Predicate<T?>? _canExecute;
    private bool _isExecuting;

    /// <summary>
    /// Creates a new async command that can always execute.
    /// </summary>
    /// <param name="execute">The async action to execute.</param>
    /// <exception cref="ArgumentNullException">Thrown when execute is null.</exception>
    public AsyncRelayCommand(Func<T?, CancellationToken, Task> execute) : this(execute, null)
    {
    }

    /// <summary>
    /// Creates a new async command with a can-execute condition.
    /// </summary>
    /// <param name="execute">The async action to execute.</param>
    /// <param name="canExecute">A function that determines if the command can execute.</param>
    /// <exception cref="ArgumentNullException">Thrown when execute is null.</exception>
    public AsyncRelayCommand(Func<T?, CancellationToken, Task> execute, Predicate<T?>? canExecute)
    {
        _execute = execute ?? throw new ArgumentNullException(nameof(execute));
        _canExecute = canExecute;
    }

    /// <summary>
    /// Defines the method that determines whether the command can execute in its current state.
    /// </summary>
    /// <param name="parameter">Data used by the command.</param>
    /// <returns>True if this command can be executed; otherwise, false.</returns>
    public bool CanExecute(object? parameter) => !_isExecuting && (_canExecute?.Invoke((T?)parameter) ?? true);

    /// <summary>
    /// Defines the method to be called when the command is invoked.
    /// </summary>
    /// <param name="parameter">Data used by the command.</param>
    public async void Execute(object? parameter)
    {
        if (_isExecuting)
        {
            return;
        }

        _isExecuting = true;
        RaiseCanExecuteChanged();

        try
        {
            await _execute((T?)parameter, CancellationToken.None);
        }
        finally
        {
            _isExecuting = false;
            RaiseCanExecuteChanged();
        }
    }

    /// <summary>
    /// Raises the CanExecuteChanged event.
    /// </summary>
    public void RaiseCanExecuteChanged() => CanExecuteChanged?.Invoke(this, EventArgs.Empty);

    /// <summary>
    /// Occurs when changes occur that affect whether or not the command should execute.
    /// </summary>
    public event EventHandler? CanExecuteChanged;
}
