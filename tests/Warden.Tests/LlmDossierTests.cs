using System.Collections.Immutable;
using System.Text;
using System.Text.Json;
using Warden.Core;
using Warden.Llm;

namespace Warden.Tests;

public sealed class LlmDossierTests
{
    [Fact]
    public void Command_line_is_capped()
    {
        var options = new LlmOptions { MaxCommandLineLength = 64 };
        string longCmd = new('x', 5000);
        var context = LlmTest.Context(commandLine: longCmd);

        Dossier dossier = new DossierBuilder(options).Build(context);

        Assert.Equal(64, dossier.CommandLine.Length);
    }

    [Fact]
    public void Extracted_strings_are_capped_in_count_and_length_and_carry_only_text()
    {
        var options = new LlmOptions { MaxDossierStrings = 3, MaxStringLength = 8 };
        string tmp = Path.GetTempFileName();
        try
        {
            // Interleave printable runs with non-printable bytes; include one very long run.
            var bytes = new List<byte>();
            void Run(string s) { bytes.AddRange(Encoding.ASCII.GetBytes(s)); bytes.Add(0x00); }
            Run("MARKER_ONE_LONGRUN_XXXXXXXX");   // long printable run
            Run("second_string");
            Run("third_string");
            Run("fourth_string_should_be_dropped");
            File.WriteAllBytes(tmp, bytes.ToArray());

            Dossier dossier = new DossierBuilder(options).Build(LlmTest.Context(imagePath: tmp));

            Assert.True(dossier.NotableStrings.Length <= 3, "count cap");
            Assert.All(dossier.NotableStrings, s => Assert.True(s.Length <= 8, "length cap"));
            // The first run is captured (truncated) — proving printable text extraction works.
            Assert.Contains(dossier.NotableStrings, s => s.StartsWith("MARKER_O", StringComparison.Ordinal));

            // Serialization is pure text/JSON — no raw NUL bytes leak into the payload.
            string json = dossier.ToJson();
            Assert.DoesNotContain('\0', json);
        }
        finally
        {
            File.Delete(tmp);
        }
    }

    [Fact]
    public void Suspicious_imports_are_surfaced_but_benign_ones_are_not()
    {
        var pe = new PeFeatures(
            IsPortableExecutable: true,
            Is64Bit: true,
            IsDotNet: false,
            ImportedModules: ImmutableArray.Create("kernel32.dll", "ws2_32.dll"),
            ImportedFunctions: ImmutableArray.Create("WriteProcessMemory", "CreateRemoteThread", "printf", "malloc"),
            SectionNames: ImmutableArray.Create(".text", ".data"),
            MaxSectionEntropy: 7.9);

        Dossier dossier = new DossierBuilder(new LlmOptions()).Build(LlmTest.Context(pe: pe));

        Assert.Contains("WriteProcessMemory", dossier.SuspiciousImports);
        Assert.Contains("CreateRemoteThread", dossier.SuspiciousImports);
        Assert.DoesNotContain("printf", dossier.SuspiciousImports);
        Assert.Equal(7.9, dossier.MaxSectionEntropy);
        Assert.True(dossier.IsPortableExecutable);
    }

    [Fact]
    public void Derived_name_fields_are_capped()
    {
        var options = new LlmOptions { MaxStringLength = 16 };
        var context = LlmTest.Context(imagePath: @"C:\Temp\" + new string('n', 300) + ".exe");

        Dossier dossier = new DossierBuilder(options).Build(context);

        Assert.True(dossier.ImageName.Length <= 16, "image name should be capped");
    }

    [Fact]
    public void Missing_file_degrades_to_empty_strings_without_throwing()
    {
        Dossier dossier = new DossierBuilder(new LlmOptions())
            .Build(LlmTest.Context(imagePath: @"C:\does\not\exist_zzz.exe"));

        Assert.Empty(dossier.NotableStrings);
        Assert.Equal(0, dossier.FileSize);
    }

    [Fact]
    public void ToJson_uses_snake_case_and_is_valid_json()
    {
        Dossier dossier = new DossierBuilder(new LlmOptions()).Build(LlmTest.Context());

        string json = dossier.ToJson();
        using JsonDocument doc = JsonDocument.Parse(json); // must parse
        Assert.True(doc.RootElement.TryGetProperty("command_line", out _));
        Assert.True(doc.RootElement.TryGetProperty("suspicious_imports", out _));
    }
}
