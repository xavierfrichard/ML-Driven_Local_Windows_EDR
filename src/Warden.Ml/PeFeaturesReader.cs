using System.Collections.Immutable;
using Microsoft.Extensions.Logging;
using PeNet;
using Warden.Core;

namespace Warden.Ml;

/// <summary>Produces the lightweight <see cref="PeFeatures"/> summary shared by the LLM dossier, the web-app classifier and the ML tier.</summary>
public interface IPeFeaturesReader
{
    /// <summary>
    /// Parses the file at <paramref name="path"/>. Never throws: a non-PE, oversized, unreadable or
    /// malformed input yields <see cref="PeFeatures.NotPortableExecutable"/>.
    /// </summary>
    PeFeatures Read(string path);
}

/// <summary>
/// PeNet-backed <see cref="IPeFeaturesReader"/>. Reads at most <see cref="MlOptions.MaxImageBytes"/> (an
/// attacker-controlled file must not be able to make the SYSTEM service allocate gigabytes) and caps the
/// number and length of the names it reports, so a hostile import table cannot flood the LLM prompt.
/// </summary>
public sealed class PeFeaturesReader : IPeFeaturesReader
{
    private const int MaxNames = 256;
    private const int MaxNameLength = 128;

    private readonly MlOptions _options;
    private readonly ILogger<PeFeaturesReader> _logger;

    public PeFeaturesReader(MlOptions options, ILogger<PeFeaturesReader> logger)
    {
        _options = options;
        _logger = logger;
    }

    public PeFeatures Read(string path)
    {
        try
        {
            if (string.IsNullOrEmpty(path) || !File.Exists(path))
            {
                return PeFeatures.NotPortableExecutable;
            }

            long length = new FileInfo(path).Length;
            if (length > _options.MaxImageBytes)
            {
                _logger.LogInformation("Not parsing {File}: {Size} bytes exceeds the PE parsing cap.", Path.GetFileName(path), length);
                return PeFeatures.NotPortableExecutable;
            }

            byte[] bytes = File.ReadAllBytes(path);
            if (!PeFile.IsPeFile(bytes))
            {
                return PeFeatures.NotPortableExecutable;
            }

            var pe = new PeFile(bytes);

            ImmutableArray<string> modules = (pe.ImportedFunctions ?? Array.Empty<PeNet.Header.Pe.ImportFunction>())
                .Select(f => f.DLL)
                .Where(d => !string.IsNullOrEmpty(d))
                .Select(d => Clip(d!.ToLowerInvariant()))
                .Distinct(StringComparer.Ordinal)
                .Take(MaxNames)
                .ToImmutableArray();

            ImmutableArray<string> functions = (pe.ImportedFunctions ?? Array.Empty<PeNet.Header.Pe.ImportFunction>())
                .Select(f => f.Name)
                .Where(n => !string.IsNullOrEmpty(n))
                .Select(n => Clip(n!))
                .Distinct(StringComparer.Ordinal)
                .Take(MaxNames)
                .ToImmutableArray();

            ImmutableArray<string> sections = (pe.ImageSectionHeaders ?? Array.Empty<PeNet.Header.Pe.ImageSectionHeader>())
                .Select(s => Clip(s.Name ?? string.Empty))
                .Take(64)
                .ToImmutableArray();

            double maxEntropy = 0d;
            foreach (var section in pe.ImageSectionHeaders ?? Array.Empty<PeNet.Header.Pe.ImageSectionHeader>())
            {
                long start = section.PointerToRawData;
                long size = section.SizeOfRawData;
                if (start < 0 || size <= 0 || start >= bytes.Length)
                {
                    continue;
                }
                int len = (int)Math.Min(size, bytes.Length - start);
                maxEntropy = Math.Max(maxEntropy, Entropy(bytes.AsSpan((int)start, len)));
            }

            return new PeFeatures(
                IsPortableExecutable: true,
                Is64Bit: pe.Is64Bit,
                IsDotNet: pe.IsDotNet,
                ImportedModules: modules,
                ImportedFunctions: functions,
                SectionNames: sections,
                MaxSectionEntropy: maxEntropy);
        }
        catch (Exception ex)
        {
            // Malformed PE, I/O race, PeNet parser exception: report "not a PE" so every consumer degrades.
            _logger.LogDebug(ex, "PE parse failed for {File}.", Path.GetFileName(path));
            return PeFeatures.NotPortableExecutable;
        }
    }

    private static string Clip(string s) => s.Length <= MaxNameLength ? s : s[..MaxNameLength];

    private static double Entropy(ReadOnlySpan<byte> data)
    {
        if (data.IsEmpty)
        {
            return 0d;
        }
        Span<int> counts = stackalloc int[256];
        foreach (byte b in data)
        {
            counts[b]++;
        }
        double entropy = 0d;
        double n = data.Length;
        for (int i = 0; i < 256; i++)
        {
            if (counts[i] == 0) { continue; }
            double p = counts[i] / n;
            entropy -= p * Math.Log2(p);
        }
        return entropy;
    }
}
