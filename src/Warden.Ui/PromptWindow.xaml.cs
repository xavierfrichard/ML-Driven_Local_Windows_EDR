using System.Windows;
using System.Windows.Threading;
using Warden.Ipc;

namespace Warden.Ui;

/// <summary>
/// A non-modal, always-on-top prompt shown when the service blocks a launch. It renders the
/// <see cref="PromptRequest"/> and exposes the user's choice (or the auto-dismiss timeout) through
/// <see cref="Completion"/>. The window deliberately does not steal focus.
/// </summary>
public partial class PromptWindow : Window
{
    private readonly TaskCompletionSource<PromptDecision> _completion =
        new(TaskCreationOptions.RunContinuationsAsynchronously);

    private readonly DispatcherTimer _timer;
    private int _remainingSeconds;
    private bool _resolved;

    /// <summary>Completes with the chosen decision. Never faults; times out to <see cref="PromptDecision.Timeout"/>.</summary>
    public Task<PromptDecision> Completion => _completion.Task;

    /// <summary>Creates the prompt for the supplied request and starts the auto-dismiss countdown.</summary>
    public PromptWindow(PromptRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        InitializeComponent();

        PopulateFields(request);

        // Honor the service-supplied budget as the single source of truth so the client countdown and
        // the server-side wait agree. The server waits max(0, AutoDismissSeconds) + grace, so counting
        // down max(1, AutoDismissSeconds) is always <= the server budget: the window never stays live
        // after the service has resolved the prompt, so a late click can never be silently ignored.
        // A non-positive value (misconfiguration) is floored to 1s rather than invented as 20s.
        _remainingSeconds = Math.Max(1, request.AutoDismissSeconds);

        _timer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(1) };
        _timer.Tick += OnTick;

        Loaded += OnLoaded;
    }

    private void PopulateFields(PromptRequest request)
    {
        ModeText.Text = string.IsNullOrWhiteSpace(request.BlockMode)
            ? "Awaiting your decision"
            : $"Block mode: {request.BlockMode}";

        FileNameText.Text = Fallback(request.FileName);
        PathText.Text = Fallback(request.ImagePath);
        ShaText.Text = Fallback(request.Sha256);
        CommandLineText.Text = Fallback(request.CommandLine);
        ParentText.Text = Fallback(request.ParentPath);
        SignerText.Text = Fallback(request.SignerSummary);
        MotwText.Text = DescribeMotw(request.MotwZone);
        ReasonText.Text = Fallback(request.Reason);

        bool hasMl = request.MlScore is not null;
        bool hasLlm = !string.IsNullOrWhiteSpace(request.LlmVerdict);

        if (hasMl)
        {
            MlText.Text = $"ML risk score: {request.MlScore!.Value:0.000}";
            MlText.Visibility = Visibility.Visible;
        }
        else
        {
            MlText.Visibility = Visibility.Collapsed;
        }

        if (hasLlm)
        {
            LlmText.Text = $"LLM verdict: {request.LlmVerdict}";
            LlmText.Visibility = Visibility.Visible;
        }
        else
        {
            LlmText.Visibility = Visibility.Collapsed;
        }

        AssessmentPanel.Visibility = hasMl || hasLlm ? Visibility.Visible : Visibility.Collapsed;
    }

    private static string Fallback(string? value) =>
        string.IsNullOrWhiteSpace(value) ? "(unknown)" : value;

    private static string DescribeMotw(int zone) => zone switch
    {
        <= 0 => "None (local)",
        1 => "Zone 1 — local intranet",
        2 => "Zone 2 — trusted sites",
        3 => "Zone 3 — internet",
        4 => "Zone 4 — restricted",
        _ => $"Zone {zone}",
    };

    private void OnLoaded(object sender, RoutedEventArgs e)
    {
        PositionBottomRight();
        UpdateCountdownText();
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
        _remainingSeconds--;
        if (_remainingSeconds <= 0)
        {
            // Timeout is the zero-trust safe default: the block stands, but nobody decided, so the service
            // does not persist it and will ask again next time.
            Resolve(PromptDecision.Timeout);
            return;
        }

        UpdateCountdownText();
    }

    private void UpdateCountdownText() => CountdownText.Text = $"{_remainingSeconds}s";

    private void OnAllow(object sender, RoutedEventArgs e) => Resolve(PromptDecision.Allow);

    private void OnKeepBlocked(object sender, RoutedEventArgs e) => Resolve(PromptDecision.KeepBlocked);

    private void OnQuarantine(object sender, RoutedEventArgs e) => Resolve(PromptDecision.Quarantine);

    /// <summary>Resolves the completion exactly once and closes the window.</summary>
    private void Resolve(PromptDecision decision)
    {
        if (_resolved)
        {
            return;
        }

        _resolved = true;
        _timer.Stop();
        _completion.TrySetResult(decision);
        Close();
    }

    /// <inheritdoc />
    protected override void OnClosed(EventArgs e)
    {
        // If the window is dismissed by any other means, fail safe (unanswered → blocked, not persisted).
        _timer.Stop();
        _timer.Tick -= OnTick;
        _completion.TrySetResult(PromptDecision.Timeout);
        base.OnClosed(e);
    }
}
