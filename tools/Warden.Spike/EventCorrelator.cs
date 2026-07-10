using Warden.Core;

namespace Warden.Spike;

/// <summary>
/// Joins a CodeIntegrity block event with a recent Kernel-Process start by normalized image path
/// within a short time window, and produces a <see cref="Dossier"/>.
/// <para>
/// Per the research finding on enforce-vs-audit: a <b>3076 audit</b> block lets the process actually
/// run, so a matching start event carrying command line + parent SHOULD exist and is used. A
/// <b>3077 enforce</b> block fails at section-creation time — the process never runs and NO start
/// event is emitted — so the correlator must NOT wait for one (that would hang forever); it builds
/// the dossier from the CI event plus on-disk file inspection and marks the process context
/// unavailable.
/// </para>
/// Thread-safe: starts arrive on the ETW thread, blocks on the EventLogWatcher thread.
/// </summary>
internal sealed class EventCorrelator
{
    private readonly TimeSpan _window;
    private readonly int _capacity;
    private readonly object _gate = new();
    private readonly LinkedList<ProcessStartRecord> _recentStarts = new();
    private long _correlationCounter;

    /// <summary>Raised with a finished dossier for each block event.</summary>
    public event Action<Dossier>? DossierReady;

    /// <param name="window">Max |CI.time − start.time| to accept as a match (a few seconds).</param>
    /// <param name="capacity">Max process-start records retained in the ring buffer.</param>
    public EventCorrelator(TimeSpan? window = null, int capacity = 1024)
    {
        _window = window ?? TimeSpan.FromSeconds(5);
        _capacity = capacity;
    }

    /// <summary>Records a process start into the ring buffer (called from the ETW thread).</summary>
    public void RecordProcessStart(ProcessStartRecord start)
    {
        lock (_gate)
        {
            _recentStarts.AddLast(start);
            while (_recentStarts.Count > _capacity)
            {
                _recentStarts.RemoveFirst();
            }
        }
    }

    /// <summary>Handles a CI block event: correlates (audit) or falls back (enforce), then emits.</summary>
    public void OnBlock(CiBlockEvent block)
    {
        string path = block.BlockedFilePath;

        // File-side provenance is always gathered from disk (degrades gracefully if moved/deleted).
        string? sha = FileInspector.Sha256FlatHex(path);
        long size = FileInspector.FileSize(path);
        SignerInfo signer = FileInspector.ReadSigner(path);
        int motw = FileInspector.ReadMotwZone(path);
        ulong corrId = NextCorrelationId(block);

        // Only audit blocks (3076) can have a correlating start; never wait on one for enforce (3077).
        ProcessStartRecord? match = block.EventId == 3076 ? FindMatchingStart(block) : null;

        Dossier dossier;
        if (match is not null)
        {
            // Audit path: enrich with real ETW process context; resolve parent image from the buffer.
            dossier = new Dossier
            {
                BlockEventId = block.EventId,
                Mode = block.Mode,
                Source = CorrelationSource.AuditCorrelated,
                ImagePath = string.IsNullOrEmpty(path) ? match.ImagePath : path,
                Sha256FlatHex = sha,
                FileSize = size,
                Signer = signer,
                MotwZone = motw,
                CommandLine = match.CommandLine,
                Pid = match.Pid,
                ParentPid = match.ParentPid,
                ParentPath = ResolveParentPath(match.ParentPid, match.Timestamp),
                PolicyName = block.PolicyName,
                PolicyGuid = block.PolicyGuid,
                Sha256Authenticode = block.Sha256Authenticode,
                CorrelationId = corrId,
                Timestamp = block.TimeCreated,
            };
        }
        else
        {
            // Enforce block (no start ever fires) OR audit block with no start in the window.
            CorrelationSource src = block.EventId == 3077
                ? CorrelationSource.EnforceCiOnly
                : CorrelationSource.AuditUncorrelated;

            dossier = new Dossier
            {
                BlockEventId = block.EventId,
                Mode = block.Mode,
                Source = src,
                ImagePath = path,
                Sha256FlatHex = sha,
                FileSize = size,
                Signer = signer,
                MotwZone = motw,
                CommandLine = string.Empty,
                Pid = 0,
                ParentPid = 0,
                ParentPath = block.ProcessName, // the loader/requestor per the CI event
                PolicyName = block.PolicyName,
                PolicyGuid = block.PolicyGuid,
                Sha256Authenticode = block.Sha256Authenticode,
                CorrelationId = corrId,
                Timestamp = block.TimeCreated,
            };
        }

        DossierReady?.Invoke(dossier);
    }

    /// <summary>Finds the newest start whose image path matches and falls within the time window.</summary>
    private ProcessStartRecord? FindMatchingStart(CiBlockEvent block)
    {
        lock (_gate)
        {
            for (LinkedListNode<ProcessStartRecord>? node = _recentStarts.Last; node is not null; node = node.Previous)
            {
                ProcessStartRecord s = node.Value;
                if (!PathUtil.PathsEqual(s.ImagePath, block.BlockedFilePath))
                {
                    continue;
                }
                if ((block.TimeCreated - s.Timestamp).Duration() <= _window)
                {
                    return s;
                }
            }
        }
        return null;
    }

    /// <summary>Best-effort lookup of the parent image path from a recent start with the given pid.</summary>
    private string ResolveParentPath(int parentPid, DateTimeOffset childStart)
    {
        lock (_gate)
        {
            for (LinkedListNode<ProcessStartRecord>? node = _recentStarts.Last; node is not null; node = node.Previous)
            {
                if (node.Value.Pid == parentPid && node.Value.Timestamp <= childStart)
                {
                    return node.Value.ImagePath;
                }
            }
        }
        return string.Empty;
    }

    /// <summary>A readable, monotonically-unique correlation id blending block time with a sequence.</summary>
    private ulong NextCorrelationId(CiBlockEvent block)
    {
        ulong seq = (ulong)Interlocked.Increment(ref _correlationCounter);
        return ((ulong)block.TimeCreated.ToUnixTimeSeconds() << 20) ^ seq;
    }
}
