using System.Windows.Input;
using Warden.Ipc;

namespace Warden.Ui.ViewModels;

/// <summary>
/// ViewModel for the PromptWindow. Handles the prompt display and user decision.
/// </summary>
public sealed class PromptWindowViewModel : ViewModelBase
{
    private readonly TaskCompletionSource<PromptDecision> _completion =
        new(TaskCreationOptions.RunContinuationsAsynchronously);

    private int _remainingSeconds;
    private string _modeText = string.Empty;
    private string _fileNameText = "(unknown)";
    private string _pathText = "(unknown)";
    private string _shaText = "(unknown)";
    private string _commandLineText = "(unknown)";
    private string _parentText = "(unknown)";
    private string _signerText = "(unknown)";
    private string _motwText = "None (local)";
    private string _reasonText = "(unknown)";
    private string _mlText = string.Empty;
    private string _llmText = string.Empty;
    private string _countdownText = "20s";
    private bool _assessmentPanelVisible;

    /// <summary>
    /// Gets the completion task for the user's decision.
    /// </summary>
    public Task<PromptDecision> Completion => _completion.Task;

    /// <summary>
    /// Gets the mode text (e.g., "Block mode: enforce").
    /// </summary>
    public string ModeText
    {
        get => _modeText;
        set => SetField(ref _modeText, value);
    }

    /// <summary>
    /// Gets the file name.
    /// </summary>
    public string FileNameText
    {
        get => _fileNameText;
        set => SetField(ref _fileNameText, value);
    }

    /// <summary>
    /// Gets the file path.
    /// </summary>
    public string PathText
    {
        get => _pathText;
        set => SetField(ref _pathText, value);
    }

    /// <summary>
    /// Gets the SHA-256 hash.
    /// </summary>
    public string ShaText
    {
        get => _shaText;
        set => SetField(ref _shaText, value);
    }

    /// <summary>
    /// Gets the command line.
    /// </summary>
    public string CommandLineText
    {
        get => _commandLineText;
        set => SetField(ref _commandLineText, value);
    }

    /// <summary>
    /// Gets the parent process path.
    /// </summary>
    public string ParentText
    {
        get => _parentText;
        set => SetField(ref _parentText, value);
    }

    /// <summary>
    /// Gets the signer summary.
    /// </summary>
    public string SignerText
    {
        get => _signerText;
        set => SetField(ref _signerText, value);
    }

    /// <summary>
    /// Gets the MOTW zone description.
    /// </summary>
    public string MotwText
    {
        get => _motwText;
        set => SetField(ref _motwText, value);
    }

    /// <summary>
    /// Gets the reason text.
    /// </summary>
    public string ReasonText
    {
        get => _reasonText;
        set => SetField(ref _reasonText, value);
    }

    /// <summary>
    /// Gets the ML score text.
    /// </summary>
    public string MlText
    {
        get => _mlText;
        set => SetField(ref _mlText, value);
    }

    /// <summary>
    /// Gets the LLM verdict text.
    /// </summary>
    public string LlmText
    {
        get => _llmText;
        set => SetField(ref _llmText, value);
    }

    /// <summary>
    /// Gets the countdown text.
    /// </summary>
    public string CountdownText
    {
        get => _countdownText;
        set => SetField(ref _countdownText, value);
    }

    /// <summary>
    /// Gets a value indicating whether the assessment panel (ML/LLM) is visible.
    /// </summary>
    public bool AssessmentPanelVisible
    {
        get => _assessmentPanelVisible;
        set => SetField(ref _assessmentPanelVisible, value);
    }

    // Commands
    public ICommand AllowCommand { get; }
    public ICommand KeepBlockedCommand { get; }
    public ICommand QuarantineCommand { get; }

    /// <summary>
    /// Initializes a new instance of the PromptWindowViewModel class.
    /// </summary>
    /// <param name="request">The prompt request.</param>
    public PromptWindowViewModel(PromptRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);

        // Initialize commands
        AllowCommand = new RelayCommand(() => Resolve(PromptDecision.Allow));
        KeepBlockedCommand = new RelayCommand(() => Resolve(PromptDecision.KeepBlocked));
        QuarantineCommand = new RelayCommand(() => Resolve(PromptDecision.Quarantine));

        // Populate fields from the request
        PopulateFields(request);

        // Initialize countdown
        _remainingSeconds = Math.Max(1, request.AutoDismissSeconds);
        UpdateCountdownText();
    }

    /// <summary>
    /// Populates the fields from the prompt request.
    /// </summary>
    private void PopulateFields(PromptRequest request)
    {
        ModeText = string.IsNullOrWhiteSpace(request.BlockMode)
            ? "Awaiting your decision"
            : $"Block mode: {request.BlockMode}";

        FileNameText = Fallback(request.FileName);
        PathText = Fallback(request.ImagePath);
        ShaText = Fallback(request.Sha256);
        CommandLineText = Fallback(request.CommandLine);
        ParentText = Fallback(request.ParentPath);
        SignerText = Fallback(request.SignerSummary);
        MotwText = DescribeMotw(request.MotwZone);
        ReasonText = Fallback(request.Reason);

        bool hasMl = request.MlScore is not null;
        bool hasLlm = !string.IsNullOrWhiteSpace(request.LlmVerdict);

        if (hasMl)
        {
            MlText = $"ML risk score: {request.MlScore!.Value:0.000}";
        }

        if (hasLlm)
        {
            LlmText = $"LLM verdict: {request.LlmVerdict}";
        }

        AssessmentPanelVisible = hasMl || hasLlm;
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

    /// <summary>
    /// Updates the countdown text.
    /// </summary>
    public void UpdateCountdownText() => CountdownText = $"{_remainingSeconds}s";

    /// <summary>
    /// Ticks the countdown timer.
    /// </summary>
    public void Tick()
    {
        _remainingSeconds--;
        if (_remainingSeconds <= 0)
        {
            Resolve(PromptDecision.Timeout);
            return;
        }

        UpdateCountdownText();
    }

    /// <summary>
    /// Resolves the completion with the specified decision.
    /// </summary>
    /// <param name="decision">The user's decision.</param>
    private void Resolve(PromptDecision decision)
    {
        _completion.TrySetResult(decision);
    }

    /// <summary>
    /// Public method for code-behind to resolve the completion.
    /// This maintains MVVM separation while allowing code-behind to trigger resolution.
    /// </summary>
    /// <param name="decision">The user's decision.</param>
    public void ResolveFromCodeBehind(PromptDecision decision)
    {
        Resolve(decision);
    }

    /// <summary>
    /// Gets the current countdown value.
    /// </summary>
    public int RemainingSeconds => _remainingSeconds;
}
