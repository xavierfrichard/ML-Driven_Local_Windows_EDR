namespace Warden.Ipc;

/// <summary>
/// Tracks the pipe instances a server holds, so it knows when to create with
/// <c>FILE_FLAG_FIRST_PIPE_INSTANCE</c>: whenever it holds zero instances. While at least one of its own
/// instances exists the name cannot belong to anyone else, so a later instance may join it; once all are
/// gone, the next create must prove the name is free again (otherwise it would silently join a squatter's
/// pipe).
/// </summary>
/// <remarks>
/// The "do we hold any?" decision and every release run under one lock. That way a concurrent release
/// cannot drop the count to zero between the decision and the create (which would turn a free name into a
/// non-first create), and a create never sees "zero" while a just-released handle still exists (which would
/// look like squatting).
/// </remarks>
/// <typeparam name="T">The instance type (a <see cref="System.IO.Pipes.NamedPipeServerStream"/> in production).</typeparam>
public sealed class PipeInstanceSet<T> where T : class, IDisposable
{
    private readonly object _gate = new();
    private readonly HashSet<T> _live = new(ReferenceEqualityComparer.Instance);
    private bool _closed;

    /// <summary>Number of instances currently held.</summary>
    public int Count
    {
        get
        {
            lock (_gate)
            {
                return _live.Count;
            }
        }
    }

    /// <summary>
    /// Creates and tracks a new instance. <paramref name="factory"/> receives <c>true</c> when no instance
    /// is held, meaning it must create with <c>FILE_FLAG_FIRST_PIPE_INSTANCE</c>. Throws
    /// <see cref="ObjectDisposedException"/> after <see cref="Close"/>; factory exceptions propagate.
    /// </summary>
    public T Create(Func<bool, T> factory)
    {
        ArgumentNullException.ThrowIfNull(factory);
        lock (_gate)
        {
            ObjectDisposedException.ThrowIf(_closed, this);
            T instance = factory(_live.Count == 0);
            _live.Add(instance);
            return instance;
        }
    }

    /// <summary>Disposes and forgets an instance. Null and already-released instances are fine.</summary>
    public void Release(T? instance)
    {
        if (instance is null)
        {
            return;
        }

        lock (_gate)
        {
            _live.Remove(instance);
            instance.Dispose();
        }
    }

    /// <summary>Disposes every held instance and refuses further creates.</summary>
    public void Close()
    {
        lock (_gate)
        {
            _closed = true;
            foreach (T instance in _live)
            {
                instance.Dispose();
            }
            _live.Clear();
        }
    }
}

/// <summary>
/// Limits security events to one per category per interval, so a retry loop (for example a squatted pipe
/// name retried every second) cannot write a tamper-log row every second. The first event of a category
/// after a quiet interval goes through and says how many were suppressed since the last one reported.
/// </summary>
public sealed class SecurityEventThrottle
{
    private readonly object _gate = new();
    private readonly Dictionary<string, (DateTimeOffset LastReported, int Suppressed)> _state = new(StringComparer.Ordinal);
    private readonly TimeSpan _interval;
    private readonly TimeProvider _time;

    /// <param name="interval">Minimum time between two reports of one category. Zero or less: no limit.</param>
    /// <param name="time">Clock (tests pass a fake). Defaults to the system clock.</param>
    public SecurityEventThrottle(TimeSpan interval, TimeProvider? time = null)
    {
        _interval = interval;
        _time = time ?? TimeProvider.System;
    }

    /// <summary>
    /// Returns the text to report, or null when this event is suppressed. The returned text is
    /// <paramref name="message"/>, plus a note with the suppressed count when earlier events were dropped.
    /// </summary>
    public string? Filter(string category, string message)
    {
        ArgumentNullException.ThrowIfNull(category);
        ArgumentNullException.ThrowIfNull(message);

        if (_interval <= TimeSpan.Zero)
        {
            return message;
        }

        DateTimeOffset now = _time.GetUtcNow();
        lock (_gate)
        {
            if (_state.TryGetValue(category, out var entry))
            {
                if (now - entry.LastReported < _interval)
                {
                    _state[category] = (entry.LastReported, entry.Suppressed + 1);
                    return null;
                }

                _state[category] = (now, 0);
                return entry.Suppressed == 0
                    ? message
                    : $"{message} ({entry.Suppressed} more '{category}' event(s) suppressed since {entry.LastReported:u}.)";
            }

            _state[category] = (now, 0);
            return message;
        }
    }
}

/// <summary>Categories for <see cref="SecurityEventThrottle"/> used by the pipe servers.</summary>
internal static class PipeSecurityCategory
{
    public const string Squat = "pipe-squat";
    public const string PeerRejected = "peer-rejected";
    public const string NonAdminAllow = "non-admin-allow";
    public const string OversizedFrame = "oversized-frame";
}
