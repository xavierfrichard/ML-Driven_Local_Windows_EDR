using System.Collections.Concurrent;
using System.Collections.Immutable;
using System.Threading.Channels;
using Microsoft.Extensions.Logging;
using Warden.Core;
using Warden.Etw;
using Warden.Storage;

namespace Warden.AttackChain;

/// <summary>
/// Maintains a live process tree from ETW process starts, reconstructs ancestry chains, and persists
/// each node to the Attack Chains store on a background writer (so the ETW thread never blocks on I/O).
/// </summary>
public sealed class ProcessTreeBuilder : IProcessTreeBuilder, IDisposable
{
    private const int MaxNodes = 8192;
    private const int MaxDepth = 64;

    private sealed record Node(int Pid, int ParentPid, string ImagePath, string CommandLine, DateTimeOffset Timestamp);

    private readonly ConcurrentDictionary<int, Node> _byPid = new();
    private readonly ConcurrentDictionary<int, string> _sessionByPid = new();
    private readonly IAttackChainRepository _repo;
    private readonly ChainSuspicionScorer _scorer;
    private readonly ILogger<ProcessTreeBuilder> _logger;
    private readonly Channel<AttackChainRecord> _persist =
        Channel.CreateBounded<AttackChainRecord>(new BoundedChannelOptions(8192)
        {
            FullMode = BoundedChannelFullMode.DropOldest,
            SingleReader = true,
        });
    private readonly Task _writerTask;
    private bool _disposed;

    public ProcessTreeBuilder(IAttackChainRepository repo, ChainSuspicionScorer scorer, ILogger<ProcessTreeBuilder> logger)
    {
        _repo = repo;
        _scorer = scorer;
        _logger = logger;
        _writerTask = Task.Run(WriteLoopAsync);
    }

    public void RecordStart(ProcessStartRecord start)
    {
        var node = new Node(start.Pid, start.ParentPid, start.ImagePath, start.CommandLine, start.Timestamp);
        _byPid[start.Pid] = node;

        // Session id groups a whole tree: inherit the parent's, or mint a new one for a root.
        string session = _sessionByPid.TryGetValue(start.ParentPid, out string? parentSession)
            ? parentSession
            : Guid.NewGuid().ToString("N");
        _sessionByPid[start.Pid] = session;

        if (_byPid.Count > MaxNodes)
        {
            Trim();
        }

        AttackChainNode chain = BuildChainFor(start.Pid);
        double suspicion = _scorer.Score(chain);

        _persist.Writer.TryWrite(new AttackChainRecord
        {
            SessionGuid = session,
            NodePid = start.Pid,
            ParentPid = start.ParentPid,
            ImagePath = start.ImagePath,
            CommandLine = start.CommandLine,
            Timestamp = start.Timestamp,
            Depth = chain.Depth,
            SuspicionScore = suspicion,
        });
    }

    public AttackChainNode BuildChainFor(int pid)
    {
        if (!_byPid.TryGetValue(pid, out Node? node))
        {
            return AttackChainNode.None;
        }

        // Collect parents from nearest up to root.
        var parents = new List<Node>();
        int current = node.ParentPid;
        int guard = 0;
        while (guard++ < MaxDepth && _byPid.TryGetValue(current, out Node? parent))
        {
            parents.Add(parent);
            if (parent.ParentPid == 0 || parent.ParentPid == parent.Pid)
            {
                break;
            }
            current = parent.ParentPid;
        }

        parents.Reverse(); // root-first, nearest-parent last

        var ancestors = ImmutableArray.CreateBuilder<AttackChainNode>(parents.Count);
        for (int i = 0; i < parents.Count; i++)
        {
            ancestors.Add(ToNode(parents[i], depth: i, ImmutableArray<AttackChainNode>.Empty));
        }

        return ToNode(node, depth: parents.Count, ancestors.ToImmutable());
    }

    private static AttackChainNode ToNode(Node n, int depth, ImmutableArray<AttackChainNode> ancestors) =>
        new(n.Pid, n.ParentPid, n.ImagePath, null, n.CommandLine, n.Timestamp, depth, ancestors);

    private void Trim()
    {
        // Drop roughly the oldest quarter to keep memory bounded.
        var oldest = _byPid.Values.OrderBy(n => n.Timestamp).Take(_byPid.Count / 4).Select(n => n.Pid).ToList();
        foreach (int pid in oldest)
        {
            _byPid.TryRemove(pid, out _);
            _sessionByPid.TryRemove(pid, out _);
        }
    }

    private async Task WriteLoopAsync()
    {
        try
        {
            await foreach (AttackChainRecord record in _persist.Reader.ReadAllAsync().ConfigureAwait(false))
            {
                try
                {
                    await _repo.AddNodeAsync(record).ConfigureAwait(false);
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "Failed persisting attack-chain node for pid {Pid}.", record.NodePid);
                }
            }
        }
        catch (OperationCanceledException)
        {
            // shutting down
        }
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }
        _disposed = true;
        _persist.Writer.TryComplete();
        try { _writerTask.Wait(TimeSpan.FromSeconds(3)); } catch { /* best effort */ }
    }
}
