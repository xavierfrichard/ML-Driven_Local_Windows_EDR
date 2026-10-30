using Warden.Core;
using Warden.Rules;
using Warden.Storage;

namespace Warden.Tests;

/// <summary>
/// The Rules panel's validation (what <c>MgmtRequestHandler</c> runs on <c>rules.add</c> before storing a rule).
/// The folder-permission check is a hand-written fake here; the live ACL check has its own tests.
/// </summary>
public sealed class RuleValidatorTests : IDisposable
{
    private const string Sha = "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF";

    private readonly string _dir = Path.Combine(Path.GetTempPath(), "warden-rulevalidator-" + Guid.NewGuid().ToString("N"));

    public RuleValidatorTests() => Directory.CreateDirectory(_dir);

    public void Dispose()
    {
        try { Directory.Delete(_dir, recursive: true); } catch (IOException) { } catch (UnauthorizedAccessException) { }
    }

    // ---- Extension rules -----------------------------------------------------------------------

    [Theory]
    [InlineData(".exe", false)]
    [InlineData(".exe", true)]
    [InlineData(".dll", false)]
    public void Given_an_extension_allow_rule_When_validated_Then_it_is_refused_with_a_clear_message(string ext, bool requireSignature)
    {
        string? error = RuleValidator.Validate(Rule(RuleKind.Extension, ext, PolicyAction.Allow, requireSignature), SafeFolder);

        Assert.Equal(RuleValidator.ExtensionAllowRefused, error);
        Assert.Contains("can only block", error, StringComparison.Ordinal);
    }

    [Fact]
    public void Given_an_extension_block_rule_When_validated_Then_it_is_accepted()
    {
        Assert.Null(RuleValidator.Validate(Rule(RuleKind.Extension, ".scr", PolicyAction.Block), SafeFolder));
    }

    [Theory]
    [InlineData("exe")]
    [InlineData(".")]
    [InlineData(". exe")]
    public void Given_a_malformed_extension_block_rule_When_validated_Then_it_is_refused(string ext)
    {
        Assert.Equal("An extension rule looks like \".exe\".", RuleValidator.Validate(Rule(RuleKind.Extension, ext, PolicyAction.Block), SafeFolder));
    }

    // ---- Folder rules --------------------------------------------------------------------------

    [Fact]
    public void Given_a_folder_allow_on_a_folder_others_can_write_When_validated_Then_it_is_refused_with_the_reason()
    {
        string? error = RuleValidator.Validate(
            Rule(RuleKind.Folder, _dir, PolicyAction.Allow),
            _ => "Users can write to it.");

        Assert.NotNull(error);
        Assert.Contains("cannot carry an allow rule", error, StringComparison.Ordinal);
        Assert.Contains("Users can write to it.", error, StringComparison.Ordinal);
    }

    [Fact]
    public void Given_a_folder_allow_on_a_locked_down_folder_When_validated_Then_it_is_accepted_and_the_check_saw_the_canonical_path()
    {
        string? checkedFolder = null;
        string? error = RuleValidator.Validate(
            Rule(RuleKind.Folder, _dir + Path.DirectorySeparatorChar + ".", PolicyAction.Allow),
            f => { checkedFolder = f; return null; });

        Assert.Null(error);
        Assert.Equal(Path.GetFullPath(_dir), checkedFolder);
    }

    [Fact]
    public void Given_a_folder_allow_on_a_missing_folder_When_validated_Then_it_is_refused_without_asking_the_permission_check()
    {
        bool asked = false;
        string? error = RuleValidator.Validate(
            Rule(RuleKind.Folder, Path.Combine(_dir, "missing"), PolicyAction.Allow),
            _ => { asked = true; return null; });

        Assert.Equal("A folder allow rule needs an existing folder, so its permissions can be checked.", error);
        Assert.False(asked);
    }

    [Fact]
    public void Given_a_folder_allow_on_a_drive_root_When_validated_Then_it_is_refused_but_a_block_is_accepted()
    {
        string root = Path.GetPathRoot(Path.GetTempPath())!;

        Assert.NotNull(RuleValidator.Validate(Rule(RuleKind.Folder, root, PolicyAction.Allow), SafeFolder));
        Assert.Null(RuleValidator.Validate(Rule(RuleKind.Folder, root, PolicyAction.Block), SafeFolder));
    }

    [Fact]
    public void Given_a_folder_block_on_a_folder_others_can_write_When_validated_Then_the_permission_check_does_not_apply()
    {
        Assert.Null(RuleValidator.Validate(Rule(RuleKind.Folder, _dir, PolicyAction.Block), _ => "Users can write to it."));
    }

    // ---- Signature rules -----------------------------------------------------------------------

    [Fact]
    public void Given_a_signature_allow_with_a_subject_DN_When_validated_Then_it_is_refused()
    {
        string? error = RuleValidator.Validate(Rule(RuleKind.Signature, "CN=Contoso Ltd, O=Contoso", PolicyAction.Allow), SafeFolder);

        Assert.NotNull(error);
        Assert.Contains("Common Name", error, StringComparison.Ordinal);
    }

    [Fact]
    public void Given_a_signature_allow_with_a_common_name_or_a_block_with_a_DN_When_validated_Then_both_are_accepted()
    {
        Assert.Null(RuleValidator.Validate(Rule(RuleKind.Signature, "Contoso Ltd", PolicyAction.Allow), SafeFolder));
        Assert.Null(RuleValidator.Validate(Rule(RuleKind.Signature, "CN=Contoso Ltd", PolicyAction.Block), SafeFolder));
    }

    // ---- Hash rules ----------------------------------------------------------------------------

    [Theory]
    [InlineData("ABC")]
    [InlineData("0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEG")]
    public void Given_a_hash_rule_that_is_not_a_SHA256_When_validated_Then_it_is_refused(string value)
    {
        Assert.NotNull(RuleValidator.Validate(Rule(RuleKind.Hash, value, PolicyAction.Allow), SafeFolder));
    }

    [Fact]
    public void Given_a_hash_rule_with_a_SHA256_When_validated_Then_it_is_accepted()
    {
        Assert.Null(RuleValidator.Validate(Rule(RuleKind.Hash, Sha.ToLowerInvariant(), PolicyAction.Allow), SafeFolder));
    }

    private static string? SafeFolder(string folder) => null;

    private static RuleEntry Rule(RuleKind kind, string value, PolicyAction action, bool requireSignature = false) => new()
    {
        Kind = kind,
        MatchValue = value,
        Action = action,
        RequireSignature = requireSignature,
        Enabled = true,
        CreatedTs = DateTimeOffset.UtcNow,
    };
}
