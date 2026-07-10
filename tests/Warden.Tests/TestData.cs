using System.Collections.Immutable;
using Warden.Core;

namespace Warden.Tests;

/// <summary>Test helpers for building pipeline inputs and stub sources.</summary>
internal static class TestData
{
    /// <summary>A minimal, valid <see cref="VerdictContext"/> for pipeline tests.</summary>
    public static VerdictContext Context(string imagePath = @"C:\Temp\unknown.exe") => new(
        Sha256: "0000000000000000000000000000000000000000000000000000000000000000",
        ImagePath: imagePath,
        CommandLine: $"\"{imagePath}\"",
        Pid: 4321,
        ParentPid: 1234,
        ParentPath: @"C:\Windows\explorer.exe",
        ParentSha256: null,
        Signer: SignerInfo.Unsigned,
        MotwZone: VerdictContext.NoMotw,
        Pe: new Lazy<PeFeatures>(() => PeFeatures.NotPortableExecutable),
        Chain: AttackChainNode.None,
        Timestamp: DateTimeOffset.UnixEpoch,
        CorrelationId: 1);
}

/// <summary>A stub source returning a fixed result, recording whether it was consulted.</summary>
internal sealed class StubSource : IVerdictSource
{
    private readonly VerdictResult _result;

    public StubSource(VerdictSourceKind kind, VerdictResult result)
    {
        Kind = kind;
        _result = result;
    }

    public VerdictSourceKind Kind { get; }

    public bool WasEvaluated { get; private set; }

    public ValueTask<VerdictResult> EvaluateAsync(VerdictContext context, CancellationToken cancellationToken)
    {
        WasEvaluated = true;
        return ValueTask.FromResult(_result);
    }

    /// <summary>Builds a decisive stub for the given verdict.</summary>
    public static StubSource Deciding(VerdictSourceKind kind, Verdict verdict) =>
        new(kind, new VerdictResult(verdict, kind, 1d, $"{kind} decided {verdict}"));

    /// <summary>Builds a non-decisive (Unknown) stub.</summary>
    public static StubSource Undecided(VerdictSourceKind kind) =>
        new(kind, VerdictResult.Undecided(kind, $"{kind} has no opinion"));
}

/// <summary>A source that always throws, to exercise the pipeline's fail-safe path.</summary>
internal sealed class ThrowingSource : IVerdictSource
{
    public ThrowingSource(VerdictSourceKind kind) => Kind = kind;

    public VerdictSourceKind Kind { get; }

    public ValueTask<VerdictResult> EvaluateAsync(VerdictContext context, CancellationToken cancellationToken) =>
        throw new InvalidOperationException($"{Kind} blew up");
}

/// <summary>A source that observes cancellation.</summary>
internal sealed class CancelObservingSource : IVerdictSource
{
    public VerdictSourceKind Kind => VerdictSourceKind.Ml;

    public ValueTask<VerdictResult> EvaluateAsync(VerdictContext context, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return ValueTask.FromResult(VerdictResult.Undecided(Kind, "unreached"));
    }
}
