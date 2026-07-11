using Microsoft.Extensions.Logging;
using Warden.Storage;

namespace Warden.Hardening;

/// <summary>Records security-relevant tamper / self-protection events (to the log and the tamper_log table).</summary>
public interface ITamperLog
{
    Task LogAsync(string category, string? detail = null, string severity = "warning", CancellationToken cancellationToken = default);
}

/// <summary>
/// Writes tamper events to both the structured log and the <c>tamper_log</c> table so tampering with the
/// agent leaves an audit trail. Best-effort — a persistence failure never propagates.
/// </summary>
public sealed class TamperLog : ITamperLog
{
    private readonly ITamperLogRepository _repo;
    private readonly ILogger<TamperLog> _logger;

    public TamperLog(ITamperLogRepository repo, ILogger<TamperLog> logger)
    {
        _repo = repo;
        _logger = logger;
    }

    public async Task LogAsync(
        string category, string? detail = null, string severity = "warning", CancellationToken cancellationToken = default)
    {
        // Structured log first (always), regardless of whether the DB write succeeds.
        if (string.Equals(severity, "critical", StringComparison.OrdinalIgnoreCase))
        {
            _logger.LogError("TAMPER [{Category}] {Detail}", category, detail);
        }
        else
        {
            _logger.LogWarning("TAMPER [{Category}] {Detail}", category, detail);
        }

        try
        {
            await _repo.AddAsync(new TamperEventRecord
            {
                Timestamp = DateTimeOffset.UtcNow,
                Category = category,
                Detail = detail,
                Severity = severity,
            }, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to persist tamper event {Category}.", category);
        }
    }
}
