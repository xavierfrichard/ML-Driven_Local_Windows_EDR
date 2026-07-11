using System.Security.AccessControl;
using System.Security.Cryptography;
using Microsoft.Extensions.Logging;
using Warden.Storage;

namespace Warden.Quarantine;

/// <summary>Configuration for the quarantine store.</summary>
public sealed class QuarantineOptions
{
    public string QuarantineDir { get; set; } = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "Warden", "Quarantine");
}

/// <summary>
/// Moves a file into an ACL-restricted quarantine folder and records restore metadata. The quarantined
/// copy is locked down to SYSTEM + Administrators only (no read/execute for normal users), and the
/// file's original ACL is captured as SDDL so a restore reinstates it. Fail-safe: never throws out of
/// the enforcement path.
/// </summary>
public sealed class QuarantineStore : IQuarantineStore
{
    // Protected (no inheritance), full access to Local System (SY) and Builtin Administrators (BA) only.
    private const string LockedDownDacl = "D:PAI(A;;FA;;;SY)(A;;FA;;;BA)";

    private readonly QuarantineOptions _options;
    private readonly IQuarantineRepository _repo;
    private readonly ILogger<QuarantineStore> _logger;

    public QuarantineStore(QuarantineOptions options, IQuarantineRepository repo, ILogger<QuarantineStore> logger)
    {
        _options = options;
        _repo = repo;
        _logger = logger;
    }

    public async Task<QuarantineResult> QuarantineAsync(
        string filePath, string reason, string verdictSource, CancellationToken cancellationToken = default)
    {
        try
        {
            if (!File.Exists(filePath))
            {
                return QuarantineResult.Fail($"File not found: {filePath}");
            }

            Directory.CreateDirectory(_options.QuarantineDir);

            var info = new FileInfo(filePath);
            long size = info.Length;
            string? sha = TryComputeSha256(filePath);
            string? originalSddl = TryCaptureSddl(info);

            string dest = Path.Combine(_options.QuarantineDir, Guid.NewGuid().ToString("N") + ".quar");
            File.Move(filePath, dest);

            // Securing the quarantined copy is mandatory. If we cannot lock it down, do NOT leave an
            // accessible-yet-recorded malware file lying in a predictable folder — delete it and fail.
            try
            {
                LockDown(dest);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Could not secure quarantined file {Dest}; deleting it.", dest);
                TryDelete(dest);
                return QuarantineResult.Fail($"Failed to secure quarantined file: {ex.Message}");
            }

            long id = await _repo.AddAsync(new QuarantineRecord
            {
                OriginalPath = filePath,
                QuarantinePath = dest,
                Sha256 = sha,
                Size = size,
                Timestamp = DateTimeOffset.UtcNow,
                Reason = reason,
                RestoreAclSddl = originalSddl,
                VerdictSource = verdictSource,
                Restored = false,
            }, cancellationToken).ConfigureAwait(false);

            _logger.LogInformation("Quarantined {File} -> {Dest} (reason: {Reason})", filePath, dest, reason);
            return new QuarantineResult(true, id, dest, null);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Quarantine failed for {File}", filePath);
            return QuarantineResult.Fail(ex.Message);
        }
    }

    public async Task<bool> RestoreAsync(long recordId, CancellationToken cancellationToken = default)
    {
        try
        {
            QuarantineRecord? record = await _repo.GetAsync(recordId, cancellationToken).ConfigureAwait(false);
            if (record is null || record.Restored || !File.Exists(record.QuarantinePath))
            {
                return false;
            }

            // The quarantined file is locked to SYSTEM+Administrators. Re-grant access by restoring the
            // original ACL onto it BEFORE moving it back — otherwise the move fails for lack of DELETE on
            // the source. The store runs as SYSTEM (or is the owner), so it has WRITE_DAC to do this.
            if (!string.IsNullOrEmpty(record.RestoreAclSddl))
            {
                TryApplySddl(new FileInfo(record.QuarantinePath), record.RestoreAclSddl);
            }

            File.Move(record.QuarantinePath, record.OriginalPath);

            await _repo.MarkRestoredAsync(recordId, cancellationToken).ConfigureAwait(false);
            _logger.LogInformation("Restored quarantined file to {Path}", record.OriginalPath);
            return true;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Restore failed for quarantine record {Id}", recordId);
            return false;
        }
    }

    private void LockDown(string path)
    {
        var info = new FileInfo(path);

        // 1) The restrictive DACL is mandatory. The creator/owner still has WRITE_DAC, so this alone is
        //    not sufficient (see step 2), but a failure here means the file is unprotected -> throw.
        var dacl = new FileSecurity();
        // Access-only: the single-arg overload defaults to AccessControlSections.All, which makes
        // SetAccessControl try to write the SACL (needs SeSecurityPrivilege) and fail.
        dacl.SetSecurityDescriptorSddlForm(LockedDownDacl, AccessControlSections.Access);
        info.SetAccessControl(dacl);

        // 2) Take ownership away from the low-privilege creator (who otherwise has implicit
        //    WRITE_DAC/READ_CONTROL and could simply re-grant themselves access). Setting the owner to
        //    a different principal needs SeRestorePrivilege, which the service has as LocalSystem;
        //    best-effort so a non-elevated dev/test run still succeeds with the DACL applied.
        try
        {
            var owner = new FileSecurity();
            owner.SetSecurityDescriptorSddlForm("O:BA", AccessControlSections.Owner);
            info.SetAccessControl(owner);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex,
                "Could not set Administrators as owner of {Path} (requires SYSTEM); DACL applied but the "
                + "original owner retains WRITE_DAC.", path);
        }
    }

    private static void TryDelete(string path)
    {
        try { File.Delete(path); }
        catch { /* best effort */ }
    }

    private static string? TryCaptureSddl(FileInfo info)
    {
        try
        {
            return info.GetAccessControl().GetSecurityDescriptorSddlForm(AccessControlSections.Access);
        }
        catch
        {
            return null;
        }
    }

    private void TryApplySddl(FileInfo info, string sddl)
    {
        try
        {
            var security = new FileSecurity();
            security.SetSecurityDescriptorSddlForm(sddl, AccessControlSections.Access);
            info.SetAccessControl(security);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Could not restore original ACL on {Path}.", info.FullName);
        }
    }

    private static string? TryComputeSha256(string path)
    {
        try
        {
            using FileStream stream = File.OpenRead(path);
            using var sha = SHA256.Create();
            return Convert.ToHexString(sha.ComputeHash(stream));
        }
        catch
        {
            return null;
        }
    }
}
