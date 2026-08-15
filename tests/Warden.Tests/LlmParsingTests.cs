using System.Text.Json;
using Warden.Llm;

namespace Warden.Tests;

/// <summary>
/// Direct tests of the verdict/response parsers — the fail-safe boundary. The verdict-source tests use
/// a fake provider and never exercise these paths, so a regression here (e.g. an unknown label mapping
/// to benign, or a hostile body parsing to a usable allow) would otherwise pass unnoticed.
/// </summary>
public sealed class LlmParsingTests
{
    private static JsonElement Element(string json) => JsonDocument.Parse(json).RootElement;

    // ---- LlmVerdict.FromInput ---------------------------------------------------------------------

    [Theory]
    [InlineData("safe")]
    [InlineData("clean")]
    [InlineData("unknown")]
    [InlineData("evil")]
    [InlineData("")]
    public void Unknown_verdict_label_maps_to_suspicious_never_benign(string label)
    {
        LlmVerdict? v = LlmVerdict.FromInput(Element($"{{\"verdict\":\"{label}\",\"confidence\":0.9}}"), 20);

        Assert.NotNull(v);
        Assert.Equal(LlmDisposition.Suspicious, v!.Disposition); // the single most important fail-safe assertion
        Assert.NotEqual(LlmDisposition.Benign, v.Disposition);
    }

    [Fact]
    public void Missing_verdict_property_yields_null()
    {
        Assert.Null(LlmVerdict.FromInput(Element("{\"confidence\":0.99}"), 20));
    }

    [Fact]
    public void Non_object_input_yields_null()
    {
        Assert.Null(LlmVerdict.FromInput(Element("\"just a string\""), 20));
        Assert.Null(LlmVerdict.FromInput(Element("[1,2,3]"), 20));
    }

    [Fact]
    public void Missing_confidence_defaults_below_all_thresholds()
    {
        LlmVerdict? v = LlmVerdict.FromInput(Element("{\"verdict\":\"malicious\"}"), 20);
        Assert.Equal(0.5, v!.Confidence, 3); // below the 0.70 block and 0.85 allow thresholds
    }

    [Fact]
    public void Wrong_type_confidence_is_ignored()
    {
        LlmVerdict? v = LlmVerdict.FromInput(Element("{\"verdict\":\"benign\",\"confidence\":\"high\"}"), 20);
        Assert.Equal(0.5, v!.Confidence, 3);
    }

    [Theory]
    [InlineData("1.5", 1.0)]
    [InlineData("-0.3", 0.0)]
    [InlineData("2000000", 1.0)]
    public void Confidence_is_clamped(string raw, double expected)
    {
        LlmVerdict? v = LlmVerdict.FromInput(Element($"{{\"verdict\":\"malicious\",\"confidence\":{raw}}}"), 20);
        Assert.Equal(expected, v!.Confidence, 3);
    }

    [Fact]
    public void Array_fields_keep_only_strings_and_respect_the_cap()
    {
        LlmVerdict? v = LlmVerdict.FromInput(
            Element("{\"verdict\":\"malicious\",\"confidence\":0.8,\"evidence\":[\"a\",1,\"b\",null,\"c\"],\"mitre_attack\":[\"T1\",\"T2\",\"T3\"]}"),
            2);

        Assert.Equal(new[] { "a", "b" }, v!.Evidence);       // non-strings skipped, capped to 2
        Assert.Equal(new[] { "T1", "T2" }, v.MitreAttack);   // capped to 2
    }

    [Fact]
    public void FromInput_defaults_to_a_tool_call_provenance()
    {
        LlmVerdict? v = LlmVerdict.FromInput(Element("{\"verdict\":\"malicious\",\"confidence\":0.9}"), 20);
        Assert.True(v!.FromToolCall);
    }

    // ---- Anthropic response parser ----------------------------------------------------------------

    [Fact]
    public void Anthropic_parses_valid_tool_use()
    {
        LlmVerdict? v = LlmAnalystPrompt.ParseAnthropicResponse(LlmTest.AnthropicToolUse("malicious", 0.9), 20);
        Assert.Equal(LlmDisposition.Malicious, v!.Disposition);
        Assert.True(v.FromToolCall);
    }

    [Fact]
    public void Anthropic_error_envelope_yields_null()
    {
        const string err = "{\"type\":\"error\",\"error\":{\"type\":\"overloaded_error\",\"message\":\"x\"}}";
        Assert.Null(LlmAnalystPrompt.ParseAnthropicResponse(err, 20));
    }

    [Fact]
    public void Anthropic_refusal_yields_null()
    {
        Assert.Null(LlmAnalystPrompt.ParseAnthropicResponse(LlmTest.AnthropicRefusal(), 20));
    }

    [Fact]
    public void Anthropic_wrong_tool_name_yields_null()
    {
        const string json = "{\"content\":[{\"type\":\"tool_use\",\"name\":\"something_else\","
            + "\"input\":{\"verdict\":\"benign\",\"confidence\":0.99}}]}";
        Assert.Null(LlmAnalystPrompt.ParseAnthropicResponse(json, 20));
    }

    [Fact]
    public void Anthropic_garbage_yields_null()
    {
        Assert.Null(LlmAnalystPrompt.ParseAnthropicResponse("not json", 20));
        Assert.Null(LlmAnalystPrompt.ParseAnthropicResponse("{}", 20));
        Assert.Null(LlmAnalystPrompt.ParseAnthropicResponse("{\"content\":[]}", 20));
    }

    // ---- OpenAI response parser -------------------------------------------------------------------

    [Fact]
    public void OpenAi_parses_string_arguments_as_tool_call()
    {
        LlmVerdict? v = LlmAnalystPrompt.ParseOpenAiResponse(LlmTest.OpenAiToolCall("malicious", 0.88), 20);
        Assert.Equal(LlmDisposition.Malicious, v!.Disposition);
        Assert.True(v.FromToolCall);
    }

    [Fact]
    public void OpenAi_parses_object_arguments_as_tool_call()
    {
        // Some OpenAI-compatible servers emit `arguments` as a JSON object, not a string.
        var body = new
        {
            choices = new object[]
            {
                new
                {
                    message = new
                    {
                        tool_calls = new object[]
                        {
                            new
                            {
                                function = new
                                {
                                    name = "submit_verdict",
                                    arguments = new
                                    {
                                        verdict = "malicious",
                                        confidence = 0.8,
                                        evidence = Array.Empty<string>(),
                                        mitre_attack = Array.Empty<string>(),
                                        suggested_action = "block",
                                    },
                                },
                            },
                        },
                    },
                },
            },
        };

        LlmVerdict? v = LlmAnalystPrompt.ParseOpenAiResponse(JsonSerializer.Serialize(body), 20);

        Assert.Equal(LlmDisposition.Malicious, v!.Disposition);
        Assert.True(v.FromToolCall);
    }

    [Fact]
    public void OpenAi_content_fallback_is_marked_not_from_a_tool_call()
    {
        LlmVerdict? v = LlmAnalystPrompt.ParseOpenAiResponse(LlmTest.OpenAiContentJson("benign", 0.99), 20);

        Assert.Equal(LlmDisposition.Benign, v!.Disposition);
        Assert.False(v.FromToolCall); // scraped from prose — must never be trusted to auto-allow
    }

    [Fact]
    public void OpenAi_garbage_yields_null()
    {
        Assert.Null(LlmAnalystPrompt.ParseOpenAiResponse("{\"choices\":[]}", 20));
        Assert.Null(LlmAnalystPrompt.ParseOpenAiResponse("{\"choices\":[{\"message\":{\"content\":\"no json here\"}}]}", 20));
        Assert.Null(LlmAnalystPrompt.ParseOpenAiResponse("not json", 20));
    }

    // ---- ParseClaudeCliResult (CLI --output-format json envelope) ----------------------------------

    [Theory]
    [InlineData(true)]   // real CLI wraps the JSON in ```json fences
    [InlineData(false)]  // bare JSON in the result field
    public void Cli_extracts_verdict_from_result_and_marks_it_not_a_tool_call(bool fenced)
    {
        LlmVerdict? v = LlmAnalystPrompt.ParseClaudeCliResult(
            LlmTest.CliEnvelope("malicious", 0.91, "quarantine", fenced), 20);

        Assert.NotNull(v);
        Assert.Equal(LlmDisposition.Malicious, v!.Disposition);
        Assert.Equal(0.91, v.Confidence, 3);
        Assert.False(v.FromToolCall); // from result text → can never auto-allow
    }

    [Fact]
    public void Cli_error_or_nonsuccess_envelope_yields_null()
    {
        Assert.Null(LlmAnalystPrompt.ParseClaudeCliResult(LlmTest.CliErrorEnvelope(), 20));
        // success-shaped but result carries no JSON object
        Assert.Null(LlmAnalystPrompt.ParseClaudeCliResult(
            "{\"is_error\":false,\"subtype\":\"success\",\"result\":\"I refuse.\"}", 20));
        // a non-success subtype is rejected even with is_error absent
        Assert.Null(LlmAnalystPrompt.ParseClaudeCliResult(
            "{\"subtype\":\"error_max_turns\",\"result\":\"{\\\"verdict\\\":\\\"benign\\\",\\\"confidence\\\":0.9}\"}", 20));
    }

    [Fact]
    public void Cli_garbage_yields_null()
    {
        Assert.Null(LlmAnalystPrompt.ParseClaudeCliResult("not json", 20));
        Assert.Null(LlmAnalystPrompt.ParseClaudeCliResult("{}", 20));
        Assert.Null(LlmAnalystPrompt.ParseClaudeCliResult("[1,2,3]", 20));
    }

    [Fact]
    public void Cli_and_tool_system_prompts_share_analysis_but_differ_on_output_instruction()
    {
        // Same role/analysis and — critically — the same injection defense in both variants.
        Assert.Contains("senior Windows malware and threat analyst", LlmAnalystPrompt.CliSystemPrompt, StringComparison.Ordinal);
        Assert.Contains("UNTRUSTED DATA", LlmAnalystPrompt.CliSystemPrompt, StringComparison.Ordinal);
        // The tool variant demands submit_verdict; the CLI variant forbids tools and asks for raw JSON.
        Assert.Contains("submit_verdict tool", LlmAnalystPrompt.SystemPrompt, StringComparison.Ordinal);
        Assert.DoesNotContain("submit_verdict tool", LlmAnalystPrompt.CliSystemPrompt, StringComparison.Ordinal);
        Assert.Contains("ONLY a single JSON object", LlmAnalystPrompt.CliSystemPrompt, StringComparison.Ordinal);
    }
}
