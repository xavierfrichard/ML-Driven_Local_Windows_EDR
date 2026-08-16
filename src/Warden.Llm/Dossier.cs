using System.Collections.Immutable;
using System.Text.Json;
using Warden.Core;

namespace Warden.Llm;

/// <summary>
/// A typed, capped summary of a blocked launch, handed to the LLM analyst as <b>data</b>. The analyst
/// never sees raw file bytes — only these extracted, length- and count-bounded facts. Everything here
/// is untrusted (it may originate from a malicious file), so the system prompt forbids the model from
/// following any instruction found within it, and the enforcement action comes only from the tool
/// schema — see <see cref="LlmAnalystPrompt"/>.
/// </summary>
public sealed record Dossier(
    string Sha256,
    string ImageName,
    string ImagePath,
    long FileSize,
    bool IsSigned,
    bool SignatureValid,
    bool IsMicrosoftSigner,
    string? SignerSubject,
    string? SignerIssuer,
    int MotwZone,
    bool FromInternet,
    bool IsPortableExecutable,
    bool Is64Bit,
    bool IsDotNet,
    double MaxSectionEntropy,
    ImmutableArray<string> SectionNames,
    ImmutableArray<string> ImportedModules,
    ImmutableArray<string> SuspiciousImports,
    string CommandLine,
    string ParentName,
    string ParentPath,
    ImmutableArray<string> AttackChain,
    ImmutableArray<string> NotableStrings)
{
    /// <summary>
    /// Serialize to compact JSON for the model. This is the <i>data</i> payload placed in the user
    /// turn — never in the (fixed, cached) system prompt. <see cref="System.Text.Json"/> escapes every
    /// value, so no dossier content can break out of its JSON string and become a model instruction.
    /// </summary>
    public string ToJson() => JsonSerializer.Serialize(this, DossierJsonContext.Options);
}

internal static class DossierJsonContext
{
    public static readonly JsonSerializerOptions Options = new()
    {
        WriteIndented = false,
        // Property names are lower-case with underscores so they read naturally to the model.
        PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower,
    };
}

/// <summary>
/// Builds a <see cref="Dossier"/> from a <see cref="VerdictContext"/>. Reads the image (bounded) to
/// extract printable strings, projects the lazily-parsed PE features, and caps every field so the
/// prompt size — and the injection surface — stays bounded regardless of the sample.
/// </summary>
public sealed class DossierBuilder
{
    // APIs that, when imported, are worth surfacing to the analyst (process injection, code download,
    // crypto/ransomware, persistence, evasion). Matched case-insensitively against imported function names.
    private static readonly HashSet<string> SuspiciousApiNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "VirtualAllocEx", "VirtualProtect", "VirtualProtectEx", "WriteProcessMemory", "ReadProcessMemory",
        "CreateRemoteThread", "CreateRemoteThreadEx", "NtCreateThreadEx", "RtlCreateUserThread",
        "QueueUserApc", "NtQueueApcThread", "SetWindowsHookEx", "SetThreadContext", "GetThreadContext",
        "OpenProcess", "NtUnmapViewOfSection", "MapViewOfSection", "NtMapViewOfSection", "LoadLibraryA",
        "LoadLibraryW", "LoadLibraryExA", "LoadLibraryExW", "GetProcAddress", "WinExec", "ShellExecuteA",
        "ShellExecuteW", "ShellExecuteExW", "CreateProcessA", "CreateProcessW", "CreateProcessInternalW",
        "InternetOpenA", "InternetOpenW", "InternetOpenUrlA", "InternetOpenUrlW", "InternetReadFile",
        "URLDownloadToFileA", "URLDownloadToFileW", "WinHttpOpen", "WinHttpConnect", "WinHttpSendRequest",
        "HttpSendRequestA", "HttpSendRequestW", "WSAStartup", "connect", "send", "recv",
        "CryptEncrypt", "CryptDecrypt", "CryptAcquireContextA", "CryptAcquireContextW", "BCryptEncrypt",
        "CryptGenKey", "CryptDeriveKey", "AdjustTokenPrivileges", "LookupPrivilegeValueA",
        "LookupPrivilegeValueW", "OpenProcessToken", "DuplicateTokenEx", "ImpersonateLoggedOnUser",
        "RegSetValueExA", "RegSetValueExW", "RegCreateKeyExA", "RegCreateKeyExW", "IsDebuggerPresent",
        "CheckRemoteDebuggerPresent", "NtQueryInformationProcess", "GetTickCount", "CreateServiceA",
        "CreateServiceW", "CreateToolhelp32Snapshot", "Process32First", "Process32Next", "EnumProcesses",
        "CreateMutexA", "CreateMutexW", "FindResourceA", "FindResourceW", "SetFileAttributesW",
    };

    private readonly LlmOptions _options;

    public DossierBuilder(LlmOptions options) => _options = options;

    public Dossier Build(VerdictContext context)
    {
        PeFeatures pe = SafePe(context);
        long fileSize = SafeFileSize(context.BytesPath);

        // Every list item is length-capped as well as count-capped: PE import/section names are
        // attacker-controlled bytes and must not be able to flood the prompt.
        ImmutableArray<string> suspicious = pe.ImportedFunctions.IsDefaultOrEmpty
            ? ImmutableArray<string>.Empty
            : pe.ImportedFunctions
                .Where(f => SuspiciousApiNames.Contains(f))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .Take(_options.MaxSuspiciousFunctions)
                .Select(f => Cap(f, _options.MaxStringLength) ?? string.Empty)
                .ToImmutableArray();

        ImmutableArray<string> modules = pe.ImportedModules.IsDefaultOrEmpty
            ? ImmutableArray<string>.Empty
            : pe.ImportedModules
                .Take(_options.MaxImportedModules)
                .Select(m => Cap(m, _options.MaxStringLength) ?? string.Empty)
                .ToImmutableArray();

        ImmutableArray<string> sections = pe.SectionNames.IsDefaultOrEmpty
            ? ImmutableArray<string>.Empty
            : pe.SectionNames
                .Take(32)
                .Select(n => Cap(n, 32) ?? string.Empty)
                .ToImmutableArray();

        return new Dossier(
            Sha256: context.Sha256 ?? string.Empty,
            ImageName: Cap(context.ImageName, _options.MaxStringLength) ?? string.Empty,
            ImagePath: Cap(context.ImagePath, _options.MaxStringLength * 4) ?? string.Empty,
            FileSize: fileSize,
            IsSigned: context.Signer.IsSigned,
            SignatureValid: context.Signer.IsValid,
            IsMicrosoftSigner: context.Signer.IsMicrosoft,
            SignerSubject: Cap(context.Signer.SubjectName, _options.MaxStringLength),
            SignerIssuer: Cap(context.Signer.IssuerName, _options.MaxStringLength),
            MotwZone: context.MotwZone,
            FromInternet: context.IsFromInternet,
            IsPortableExecutable: pe.IsPortableExecutable,
            Is64Bit: pe.Is64Bit,
            IsDotNet: pe.IsDotNet,
            MaxSectionEntropy: Math.Round(pe.MaxSectionEntropy, 3),
            SectionNames: sections,
            ImportedModules: modules,
            SuspiciousImports: suspicious,
            CommandLine: Cap(context.CommandLine, _options.MaxCommandLineLength) ?? string.Empty,
            ParentName: Cap(ImageNameOf(context.ParentPath), _options.MaxStringLength) ?? string.Empty,
            ParentPath: Cap(context.ParentPath, _options.MaxStringLength * 4) ?? string.Empty,
            AttackChain: BuildChain(context.Chain),
            NotableStrings: ExtractStrings(context.BytesPath));
    }

    private ImmutableArray<string> BuildChain(AttackChainNode chain)
    {
        if (chain is null || chain.Ancestors.IsDefaultOrEmpty)
        {
            // No reconstructed ancestry; still record the node itself if it carries anything useful.
            return string.IsNullOrEmpty(chain?.ImageName)
                ? ImmutableArray<string>.Empty
                : ImmutableArray.Create(DescribeNode(chain));
        }

        ImmutableArray<string>.Builder builder = ImmutableArray.CreateBuilder<string>();
        foreach (AttackChainNode ancestor in chain.Ancestors.Take(_options.MaxChainDepth))
        {
            builder.Add(DescribeNode(ancestor));
        }
        builder.Add(DescribeNode(chain));
        return builder.ToImmutable();
    }

    private string DescribeNode(AttackChainNode node)
    {
        string name = string.IsNullOrEmpty(node.ImageName) ? "?" : Cap(node.ImageName, _options.MaxStringLength)!;
        string cmd = Cap(node.CommandLine, _options.MaxStringLength) ?? string.Empty;
        return string.IsNullOrEmpty(cmd) ? name : $"{name}: {cmd}";
    }

    private static PeFeatures SafePe(VerdictContext context)
    {
        try
        {
            return context.Pe?.Value ?? PeFeatures.NotPortableExecutable;
        }
        catch
        {
            return PeFeatures.NotPortableExecutable;
        }
    }

    private static long SafeFileSize(string path)
    {
        try
        {
            return string.IsNullOrEmpty(path) ? 0 : new FileInfo(path).Length;
        }
        catch
        {
            return 0;
        }
    }

    private static string ImageNameOf(string? path) =>
        string.IsNullOrEmpty(path) ? string.Empty : Path.GetFileName(path).ToLowerInvariant();

    private static string? Cap(string? value, int max)
    {
        if (string.IsNullOrEmpty(value))
        {
            return value;
        }
        return value.Length <= max ? value : value[..max];
    }

    /// <summary>
    /// Extract printable ASCII runs from a bounded prefix of the file. This is the only place the file
    /// bytes are touched, and no bytes are ever forwarded — only decoded printable runs, capped in both
    /// count and per-string length. Failures degrade to an empty list.
    /// </summary>
    private ImmutableArray<string> ExtractStrings(string path)
    {
        if (string.IsNullOrEmpty(path))
        {
            return ImmutableArray<string>.Empty;
        }

        byte[] buffer;
        try
        {
            using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
            int toRead = (int)Math.Min(fs.Length, _options.MaxStringScanBytes);
            buffer = new byte[toRead];
            int read = 0;
            while (read < toRead)
            {
                int n = fs.Read(buffer, read, toRead - read);
                if (n <= 0)
                {
                    break;
                }
                read += n;
            }
            if (read != toRead)
            {
                Array.Resize(ref buffer, read);
            }
        }
        catch
        {
            return ImmutableArray<string>.Empty;
        }

        const int minRun = 6;
        ImmutableArray<string>.Builder result = ImmutableArray.CreateBuilder<string>();
        int runStart = -1;
        for (int i = 0; i < buffer.Length && result.Count < _options.MaxDossierStrings; i++)
        {
            byte b = buffer[i];
            bool printable = b >= 0x20 && b <= 0x7E;
            if (printable)
            {
                if (runStart < 0)
                {
                    runStart = i;
                }
            }
            else
            {
                AddRun(buffer, runStart, i, minRun, result);
                runStart = -1;
            }
        }
        if (runStart >= 0 && result.Count < _options.MaxDossierStrings)
        {
            AddRun(buffer, runStart, buffer.Length, minRun, result);
        }
        return result.ToImmutable();
    }

    private void AddRun(byte[] buffer, int start, int endExclusive, int minRun, ImmutableArray<string>.Builder result)
    {
        if (start < 0 || endExclusive - start < minRun)
        {
            return;
        }
        int len = Math.Min(endExclusive - start, _options.MaxStringLength);
        string s = System.Text.Encoding.ASCII.GetString(buffer, start, len);
        result.Add(s);
    }
}
