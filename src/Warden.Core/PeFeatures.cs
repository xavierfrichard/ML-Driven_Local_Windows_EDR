using System.Collections.Immutable;

namespace Warden.Core;

/// <summary>
/// Static features parsed from a PE image, shared by the ML tier (EMBER feature extraction), the
/// web-app classifier (import-table signals), and the LLM dossier builder. This is a lightweight
/// summary; the full EMBER v2 feature vector is produced separately in the ML subsystem.
/// </summary>
/// <remarks>
/// Parsing a PE is not free, so <see cref="VerdictContext.Pe"/> exposes this behind a
/// <see cref="System.Lazy{T}"/> — only tiers that need it (ML, web-app classification, LLM) force it.
/// </remarks>
/// <param name="IsPortableExecutable">False if the file is not a PE (e.g. a script).</param>
/// <param name="Is64Bit">True for PE32+.</param>
/// <param name="IsDotNet">True if the image has a CLR header (managed assembly).</param>
/// <param name="ImportedModules">Lower-cased DLL names referenced by the import (and delay-import) table.</param>
/// <param name="ImportedFunctions">Notable imported API names (used for suspicious-API and web-facing signals).</param>
/// <param name="SectionNames">PE section names in order.</param>
/// <param name="MaxSectionEntropy">Highest Shannon entropy across sections (packing/encryption signal).</param>
public sealed record PeFeatures(
    bool IsPortableExecutable,
    bool Is64Bit,
    bool IsDotNet,
    ImmutableArray<string> ImportedModules,
    ImmutableArray<string> ImportedFunctions,
    ImmutableArray<string> SectionNames,
    double MaxSectionEntropy)
{
    /// <summary>Represents a non-PE input (e.g. a script file) with no parsable PE structure.</summary>
    public static readonly PeFeatures NotPortableExecutable = new(
        IsPortableExecutable: false,
        Is64Bit: false,
        IsDotNet: false,
        ImportedModules: ImmutableArray<string>.Empty,
        ImportedFunctions: ImmutableArray<string>.Empty,
        SectionNames: ImmutableArray<string>.Empty,
        MaxSectionEntropy: 0d);

    /// <summary>True if the import (or delay-import) table references the given module (case-insensitive).</summary>
    public bool ImportsModule(string moduleName) =>
        ImportedModules.Any(m => string.Equals(m, moduleName, StringComparison.OrdinalIgnoreCase));
}
