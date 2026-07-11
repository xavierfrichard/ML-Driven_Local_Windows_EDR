using System.Windows;
using Warden.Storage;

namespace Warden.Ui;

/// <summary>A small dialog for adding a Rules-panel entry (hash / signature / folder / extension).</summary>
public partial class AddRuleWindow : Window
{
    /// <summary>The rule the user built, or null if cancelled.</summary>
    public RuleEntry? Result { get; private set; }

    public AddRuleWindow()
    {
        InitializeComponent();
        KindBox.ItemsSource = Enum.GetValues<RuleKind>();
        KindBox.SelectedIndex = 0;
        ActionBox.ItemsSource = Enum.GetValues<PolicyAction>();
        ActionBox.SelectedIndex = 0;
    }

    private void Ok_Click(object sender, RoutedEventArgs e)
    {
        string match = MatchBox.Text?.Trim() ?? string.Empty;
        if (string.IsNullOrEmpty(match))
        {
            MessageBox.Show(this, "Enter a match value.", "Add Rule", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        Result = new RuleEntry
        {
            Kind = (RuleKind)KindBox.SelectedItem,
            MatchValue = match,
            Action = (PolicyAction)ActionBox.SelectedItem,
            RequireSignature = RequireSigBox.IsChecked == true,
            RequireWhitelist = RequireWlBox.IsChecked == true,
            Enabled = true,
            CreatedTs = DateTimeOffset.UtcNow,
            Note = string.IsNullOrWhiteSpace(NoteBox.Text) ? null : NoteBox.Text.Trim(),
        };
        DialogResult = true;
    }
}
