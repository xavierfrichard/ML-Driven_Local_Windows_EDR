using System.Windows;
using System.Windows.Threading;
using Warden.Ipc;
using Warden.Ui.ViewModels;

namespace Warden.Ui;

/// <summary>
/// A non-modal, always-on-top prompt shown when the service blocks a launch. It renders the
/// <see cref="PromptRequest"/> and exposes the user's choice (or the auto-dismiss timeout) through
/// <see cref="Completion"/>. The window deliberately does not steal focus.
/// </summary>
public partial class PromptWindow : Window
{
    private readonly PromptWindowViewModel _viewModel;
    private readonly DispatcherTimer _timer;
    private bool _resolved;

    /// <summary>Completes with the chosen decision. Never faults; times out to <see cref="PromptDecision.Timeout"/>.</summary>
    public Task<PromptDecision> Completion => _viewModel.Completion;

    /// <summary>Creates the prompt for the supplied request and starts the auto-dismiss countdown.</summary>
    public PromptWindow(PromptRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        InitializeComponent();

        // Create and set the ViewModel
        _viewModel = new PromptWindowViewModel(request);
        DataContext = _viewModel;

        // Initialize and start the timer
        _timer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(1) };
        _timer.Tick += OnTick;

        Loaded += OnLoaded;
    }

    private void OnLoaded(object sender, RoutedEventArgs e)
    {
        PositionBottomRight();
        _timer.Start();
    }

    /// <summary>Anchors the window to the bottom-right of the working area (above the taskbar).</summary>
    private void PositionBottomRight()
    {
        var area = SystemParameters.WorkArea;
        const double margin = 12;
        Left = area.Right - ActualWidth - margin;
        Top = area.Bottom - ActualHeight - margin;
    }

    private void OnTick(object? sender, EventArgs e)
    {
        _viewModel.Tick();
        
        if (_viewModel.RemainingSeconds <= 0)
        {
            // The ViewModel has already resolved, just close the window
            Close();
            return;
        }
    }

    /// <summary>
    /// Resolves the completion exactly once and closes the window.
    /// </summary>
    private void Resolve(PromptDecision decision)
    {
        if (_resolved)
        {
            return;
        }

        _resolved = true;
        _timer.Stop();
        _viewModel.ResolveFromCodeBehind(decision);
        Close();
    }

    /// <inheritdoc />
    protected override void OnClosed(EventArgs e)
    {
        // If the window is dismissed by any other means, fail safe (unanswered → blocked, not persisted).
        _timer.Stop();
        _timer.Tick -= OnTick;
        
        if (!_resolved)
        {
            _viewModel.ResolveFromCodeBehind(PromptDecision.Timeout);
        }
        
        base.OnClosed(e);
    }
}
