namespace Warden.Etw;

/// <summary>
/// Tracks which blocks are queued but not yet handled, so a burst of block events for the same file
/// (relaunch loops, an attacker spamming one binary) occupies one queue slot instead of hundreds and
/// cannot push other files' blocks out of the bounded queue. Thread-safe.
/// </summary>
public sealed class PendingBlockSet
{
    private readonly object _gate = new();
    private readonly HashSet<string> _pending = new(StringComparer.Ordinal);

    /// <summary>
    /// The coalescing key of a block: the blocked path (case-insensitive) plus the CI event's Authenticode
    /// hash when it has one, so a file replaced in place between two events is still handled twice.
    /// </summary>
    public static string KeyOf(CiBlockEvent block)
    {
        ArgumentNullException.ThrowIfNull(block);
        string path = (block.BlockedFilePath ?? string.Empty).Trim().ToUpperInvariant();
        string hash = (block.Sha256Authenticode ?? string.Empty).Trim().ToUpperInvariant();
        return hash.Length == 0 ? path : path + "|" + hash;
    }

    /// <summary>Number of distinct blocks currently pending.</summary>
    public int Count
    {
        get
        {
            lock (_gate)
            {
                return _pending.Count;
            }
        }
    }

    /// <summary>
    /// Marks <paramref name="block"/> pending. Returns false when an identical block is already pending,
    /// meaning the caller should drop this one (the queued one will be handled; the OS block stands).
    /// </summary>
    public bool TryAdd(CiBlockEvent block)
    {
        string key = KeyOf(block);
        lock (_gate)
        {
            return _pending.Add(key);
        }
    }

    /// <summary>Clears the pending mark (when the block is dequeued for handling, or dropped by the queue).</summary>
    public void Remove(CiBlockEvent block)
    {
        string key = KeyOf(block);
        lock (_gate)
        {
            _pending.Remove(key);
        }
    }
}

/// <summary>Why <see cref="PromptThrottle.TryAcquire"/> refused a prompt.</summary>
public enum PromptSuppression
{
    /// <summary>Not suppressed: show the prompt.</summary>
    None = 0,

    /// <summary>The same file was prompted for within the per-file cooldown.</summary>
    Cooldown,

    /// <summary>Too many prompts (for any files) within the rolling window.</summary>
    RateLimited,
}

/// <summary>
/// Limits how often the user is prompted, to blunt prompt-fatigue attacks: at most one prompt per file
/// within <see cref="Cooldown"/>, and at most <see cref="MaxPromptsPerWindow"/> prompts in any
/// <see cref="Window"/>. A suppressed prompt only means the launch stays blocked without asking; nothing is
/// recorded, and in particular nothing is ever allowed because of it. Thread-safe.
/// </summary>
public sealed class PromptThrottle
{
    private readonly object _gate = new();
    private readonly Dictionary<string, DateTimeOffset> _lastPromptByKey = new(StringComparer.OrdinalIgnoreCase);
    private readonly Queue<DateTimeOffset> _recentPrompts = new();
    private readonly TimeProvider _time;

    public PromptThrottle(
        TimeSpan? cooldown = null,
        int maxPromptsPerWindow = 10,
        TimeSpan? window = null,
        TimeProvider? timeProvider = null)
    {
        Cooldown = cooldown ?? TimeSpan.FromSeconds(60);
        Window = window ?? TimeSpan.FromSeconds(60);
        MaxPromptsPerWindow = maxPromptsPerWindow > 0 ? maxPromptsPerWindow : 1;
        _time = timeProvider ?? TimeProvider.System;
    }

    /// <summary>Minimum time between two prompts for the same file.</summary>
    public TimeSpan Cooldown { get; }

    /// <summary>The rolling window for the global prompt cap.</summary>
    public TimeSpan Window { get; }

    /// <summary>Most prompts shown in any <see cref="Window"/>.</summary>
    public int MaxPromptsPerWindow { get; }

    /// <summary>The throttle key for a file: its hash when known, else its path.</summary>
    public static string KeyOf(string? sha256, string? path) =>
        !string.IsNullOrWhiteSpace(sha256)
            ? "sha:" + sha256.Trim().ToUpperInvariant()
            : "path:" + (path ?? string.Empty).Trim().ToUpperInvariant();

    /// <summary>
    /// Asks to show a prompt for <paramref name="key"/>. On <see cref="PromptSuppression.None"/> the prompt
    /// is counted and the caller should show it; otherwise the caller keeps the launch blocked silently.
    /// </summary>
    public PromptSuppression TryAcquire(string key)
    {
        ArgumentNullException.ThrowIfNull(key);
        DateTimeOffset now = _time.GetUtcNow();
        lock (_gate)
        {
            while (_recentPrompts.Count > 0 && now - _recentPrompts.Peek() >= Window)
            {
                _recentPrompts.Dequeue();
            }
            PruneCooldowns(now);

            if (_lastPromptByKey.TryGetValue(key, out DateTimeOffset last) && now - last < Cooldown)
            {
                return PromptSuppression.Cooldown;
            }
            if (_recentPrompts.Count >= MaxPromptsPerWindow)
            {
                return PromptSuppression.RateLimited;
            }

            _lastPromptByKey[key] = now;
            _recentPrompts.Enqueue(now);
            return PromptSuppression.None;
        }
    }

    /// <summary>
    /// Restarts the per-file cooldown for <paramref name="key"/> from now (call when the prompt closes, so
    /// a prompt left open for its full auto-dismiss time still gets the whole cooldown afterwards).
    /// </summary>
    public void MarkCompleted(string key)
    {
        ArgumentNullException.ThrowIfNull(key);
        DateTimeOffset now = _time.GetUtcNow();
        lock (_gate)
        {
            _lastPromptByKey[key] = now;
        }
    }

    /// <summary>Bounds memory: forget keys whose cooldown has expired.</summary>
    private void PruneCooldowns(DateTimeOffset now)
    {
        if (_lastPromptByKey.Count < 256)
        {
            return;
        }
        foreach (string stale in _lastPromptByKey.Where(kv => now - kv.Value >= Cooldown).Select(kv => kv.Key).ToList())
        {
            _lastPromptByKey.Remove(stale);
        }
    }
}
