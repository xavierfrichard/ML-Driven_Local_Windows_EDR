using System.Security.AccessControl;
using Microsoft.Extensions.Logging;
using Microsoft.Win32.SafeHandles;
using Warden.Storage;

namespace Warden.Quarantine;

/// <summary>Configuration for the quarantine store.</summary>
public sealed class QuarantineOptions
{
    public string QuarantineDir { get; set; } = Warden.Core.WardenPaths.Under("Quarantine");

    /// <summary>
    /// Largest file that is quarantined (it is hashed through its handle on the decision thread). Matches
    /// the snapshot cap: a bigger file was never hashed, so it has no expected hash to verify anyway.
    /// </summary>
    public long MaxFileBytes { get; set; } = 256L * 1024 * 1024;
}

/// <summary>
/// Moves a file into an ACL-restricted quarantine folder and records restore metadata. The quarantined
/// copy is locked down to SYSTEM + Administrators only (no read/execute for normal users), and the
/// file's original ACL is captured as SDDL so a restore reinstates it. Fail-safe: never throws out of
/// the enforcement path.
/// </summary>
/// <remarks>
/// <b>Junction-safe.</b> Both directions refuse reparse points on every ancestor, open the file itself by
/// handle (never through a final reparse point, denying other writers), check through that handle where
/// it really lives and that its bytes hash to the expected value, and rename that same handle into a
/// directory that is also held by handle (see <see cref="SafeFileOps"/>). Swapping a path component during
/// the prompt can no longer make SYSTEM move some other file. Any mismatch fails and leaves the file, and
/// the WDAC block, where they are.
/// </remarks>
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
        string filePath, string expectedSha256, string reason, string verdictSource, CancellationToken cancellationToken = default)
    {
        try
        {
            if (string.IsNullOrWhiteSpace(expectedSha256))
            {
                // Without the hash the decision was made on, nothing proves the file about to be moved is
                // the one that was judged. Keep the block; never move an unverified file as SYSTEM.
                return QuarantineResult.Fail("No expected hash for the blocked file; refusing to quarantine.");
            }

            string? canonical = SafeFileOps.CanonicalLocalPath(filePath);
            if (canonical is null)
            {
                return QuarantineResult.Fail("Not a rooted local path; refusing to quarantine.");
            }

            if (SafeFileOps.FindUnsafeAncestor(canonical) is { } badAncestor)
            {
                _logger.LogError("Refusing to quarantine {File}: ancestor {Dir} is a reparse point or unreadable.", canonical, badAncestor);
                return QuarantineResult.Fail($"Ancestor directory is a reparse point (junction/symlink) or unreadable: {badAncestor}");
            }

            string quarantineDir = SafeFileOps.CanonicalLocalPath(_options.QuarantineDir)
                ?? throw new InvalidOperationException("The quarantine directory is not a rooted local path.");
            Directory.CreateDirectory(quarantineDir);

            string leaf = Guid.NewGuid().ToString("N") + ".quar";
            string dest = Path.Combine(quarantineDir, leaf);
            string sha;
            long size;
            string? originalSddl;

            using (SafeFileHandle file = SafeFileOps.OpenFileForMove(canonical))
            {
                // From here on every check is on the open object, not on the path.
                (uint attrs, uint links, long length) = SafeFileOps.Describe(file);
                if (SafeFileOps.IsReparsePoint(attrs) || SafeFileOps.IsDirectory(attrs))
                {
                    return QuarantineResult.Fail("The target is a reparse point or directory, not a regular file.");
                }
                if (links != 1)
                {
                    // Moving one name of a hard-linked file would leave (or steal) the other names.
                    return QuarantineResult.Fail($"The target has {links} hard links; refusing to quarantine.");
                }
                if (length > _options.MaxFileBytes)
                {
                    return QuarantineResult.Fail($"The target is {length} bytes, over the {_options.MaxFileBytes}-byte quarantine cap.");
                }

                string? finalPath = SafeFileOps.FinalPath(file);
                if (finalPath is null || !SafeFileOps.SamePath(finalPath, canonical))
                {
                    _logger.LogError("Refusing to quarantine {File}: the opened file resolves to {Final}.", canonical, finalPath ?? "(unknown)");
                    return QuarantineResult.Fail("The opened file is not at the blocked path (redirected).");
                }

                using SafeFileHandle dir = SafeFileOps.OpenDirectory(quarantineDir);
                (uint dirAttrs, _, _) = SafeFileOps.Describe(dir);
                if (SafeFileOps.IsReparsePoint(dirAttrs) || !SafeFileOps.IsDirectory(dirAttrs))
                {
                    return QuarantineResult.Fail("The quarantine directory is a reparse point; refusing.");
                }

                // The share mode on our handle denies writers, so these are the bytes that will be moved.
                sha = SafeFileOps.HashHandle(file);
                if (!string.Equals(sha, expectedSha256.Trim(), StringComparison.OrdinalIgnoreCase))
                {
                    _logger.LogError("Refusing to quarantine {File}: its bytes no longer match the judged hash.", canonical);
                    return QuarantineResult.Fail("The file's hash does not match the hash that was judged; refusing to quarantine.");
                }

                size = length;
                originalSddl = TryReadSddl(file);

                int status = SafeFileOps.RenameInto(file, dir, leaf);
                if (status == SafeFileOps.StatusNotSameDevice)
                {
                    // Different volume: copy the verified bytes out of the same handle, then delete the
                    // original through that handle. No path is re-resolved on the source side.
                    CopyThenDelete(file, dest, expectedSha256);
                }
                else if (status != 0)
                {
                    return QuarantineResult.Fail($"Moving the file into quarantine failed (NTSTATUS 0x{status:X8}).");
                }
            }

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
                OriginalPath = canonical,
                QuarantinePath = dest,
                Sha256 = sha,
                Size = size,
                Timestamp = DateTimeOffset.UtcNow,
                Reason = reason,
                RestoreAclSddl = originalSddl,
                VerdictSource = verdictSource,
                Restored = false,
            }, cancellationToken).ConfigureAwait(false);

            _logger.LogInformation("Quarantined {File} -> {Dest} (reason: {Reason})", canonical, dest, reason);
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
            if (record is null || record.Restored)
            {
                return false;
            }
            if (string.IsNullOrWhiteSpace(record.Sha256))
            {
                _logger.LogError("Refusing to restore quarantine record {Id}: no recorded hash to verify.", recordId);
                return false;
            }

            string? quarantineDir = SafeFileOps.CanonicalLocalPath(_options.QuarantineDir);
            string? source = SafeFileOps.CanonicalLocalPath(record.QuarantinePath);
            if (quarantineDir is null || source is null
                || !SafeFileOps.SamePath(Path.GetDirectoryName(source) ?? string.Empty, quarantineDir)
                || !File.Exists(source))
            {
                _logger.LogError("Refusing to restore quarantine record {Id}: the stored file is not in the quarantine directory.", recordId);
                return false;
            }

            // The destination comes from the database (ultimately from the path the sample was found at):
            // SYSTEM must not be steerable into writing a file wherever that string says.
            if (!IsSafeRestoreTarget(record.OriginalPath, out string canonical, out string? why))
            {
                _logger.LogError("Refusing to restore quarantine record {Id} to {Path}: {Why}", recordId, record.OriginalPath, why);
                return false;
            }
            string parent = Path.GetDirectoryName(canonical)!;
            string leaf = Path.GetFileName(canonical);

            // Hold the target directory by handle and judge it by where the handle really points.
            using SafeFileHandle parentDir = SafeFileOps.OpenDirectory(parent);
            (uint parentAttrs, _, _) = SafeFileOps.Describe(parentDir);
            string? parentFinal = SafeFileOps.FinalPath(parentDir);
            if (SafeFileOps.IsReparsePoint(parentAttrs) || !SafeFileOps.IsDirectory(parentAttrs)
                || parentFinal is null || !SafeFileOps.SamePath(parentFinal, parent))
            {
                _logger.LogError("Refusing to restore quarantine record {Id}: {Dir} resolves to {Final}.", recordId, parent, parentFinal ?? "(unknown)");
                return false;
            }
            if (IsPrivilegedLocation(parentFinal, out string? root))
            {
                _logger.LogError("Refusing to restore quarantine record {Id} into privileged location {Root}.", recordId, root);
                return false;
            }

            // The quarantined file is locked to SYSTEM+Administrators. Re-grant access by restoring the
            // original ACL onto it BEFORE opening it — otherwise the open fails for lack of DELETE/read.
            // The store runs as SYSTEM (or is the owner), so it has WRITE_DAC to do this.
            bool aclReopened = false;
            if (!string.IsNullOrEmpty(record.RestoreAclSddl))
            {
                aclReopened = TryApplySddl(new FileInfo(source), record.RestoreAclSddl);
            }

            bool restored = false;
            try
            {
                using SafeFileHandle file = SafeFileOps.OpenFileForMove(source);
                (uint attrs, uint links, _) = SafeFileOps.Describe(file);
                string? fileFinal = SafeFileOps.FinalPath(file);
                if (SafeFileOps.IsReparsePoint(attrs) || SafeFileOps.IsDirectory(attrs) || links != 1
                    || fileFinal is null || !SafeFileOps.SamePath(fileFinal, source))
                {
                    _logger.LogError("Refusing to restore quarantine record {Id}: the stored file is not a plain file at {Path}.", recordId, source);
                    return false;
                }

                // Verify the bytes are what was quarantined before putting them back on disk.
                string actual = SafeFileOps.HashHandle(file);
                if (!string.Equals(actual, record.Sha256, StringComparison.OrdinalIgnoreCase))
                {
                    _logger.LogError("Refusing to restore quarantine record {Id}: stored bytes do not match the recorded hash.", recordId);
                    return false;
                }

                int status = SafeFileOps.RenameInto(file, parentDir, leaf);
                if (status != 0)
                {
                    // Includes a cross-volume restore: a copy would have to create the target by path, which
                    // is exactly what this code avoids. Restore by hand in that (rare) case.
                    _logger.LogError("Restore of quarantine record {Id} failed (NTSTATUS 0x{Status:X8}).", recordId, status);
                    return false;
                }
                restored = true;
            }
            finally
            {
                if (!restored && aclReopened)
                {
                    try { LockDown(source); } catch (Exception ex) { _logger.LogWarning(ex, "Could not re-lock {Path}.", source); }
                }
            }

            await _repo.MarkRestoredAsync(recordId, cancellationToken).ConfigureAwait(false);
            _logger.LogInformation("Restored quarantined file to {Path}", canonical);
            return true;
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Restore failed for quarantine record {Id}", recordId);
            return false;
        }
    }

    /// <summary>
    /// A restore target is acceptable when it is a rooted, canonical local path (no UNC/device form), its
    /// parent directory exists, no ancestor is a reparse point, nothing already occupies it, and it is not in
    /// the Windows or Program Files trees or Warden's own data directory (SYSTEM must not be used to plant
    /// files in privileged locations). This is the path-level filter; <see cref="RestoreAsync"/> repeats
    /// the location checks on the directory handle it renames into.
    /// </summary>
    public static bool IsSafeRestoreTarget(string? original, out string canonical, out string? reason)
    {
        canonical = string.Empty;
        reason = null;
        if (string.IsNullOrWhiteSpace(original))
        {
            reason = "no original path recorded";
            return false;
        }

        string? full = SafeFileOps.CanonicalLocalPath(original);
        if (full is null)
        {
            reason = "original path is not a rooted local path";
            return false;
        }
        canonical = full;

        string? parent = Path.GetDirectoryName(canonical);
        if (string.IsNullOrEmpty(parent) || !Directory.Exists(parent))
        {
            reason = "original directory no longer exists";
            return false;
        }

        if (SafeFileOps.FindUnsafeAncestor(canonical) is { } bad)
        {
            reason = $"ancestor directory {bad} is a reparse point (junction/symlink) or could not be inspected";
            return false;
        }

        if (File.Exists(canonical) || Directory.Exists(canonical))
        {
            reason = "something already exists at the original path";
            return false;
        }

        if (IsPrivilegedLocation(parent, out string? root))
        {
            reason = $"refusing to restore into a privileged system location ({root})";
            return false;
        }

        return true;
    }

    /// <summary>
    /// True when <paramref name="directory"/> is, or lies under, a privileged root. Each root is compared both
    /// as configured and as its own final path, so a junctioned or short-name root still matches.
    /// </summary>
    private static bool IsPrivilegedLocation(string directory, out string? matchedRoot)
    {
        foreach (string root in PrivilegedRoots())
        {
            if (SafeFileOps.IsAtOrUnder(directory, root))
            {
                matchedRoot = root;
                return true;
            }
        }
        matchedRoot = null;
        return false;
    }

    private static IEnumerable<string> PrivilegedRoots()
    {
        string[] configured =
        {
            Environment.GetFolderPath(Environment.SpecialFolder.Windows),
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
            Warden.Core.WardenPaths.DataDirectory,
        };
        foreach (string root in configured)
        {
            string? canonical = SafeFileOps.CanonicalLocalPath(root);
            if (canonical is null)
            {
                continue;
            }
            yield return canonical;

            string? final = null;
            if (Directory.Exists(canonical))
            {
                try
                {
                    using SafeFileHandle h = SafeFileOps.OpenDirectory(canonical);
                    final = SafeFileOps.FinalPath(h);
                }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.ComponentModel.Win32Exception)
                {
                    // Unreadable root: the configured spelling above still applies.
                }
            }
            if (final is not null)
            {
                yield return final;
            }
        }
    }

    /// <summary>Cross-volume quarantine: copy from the verified handle into a new file, then delete through the handle.</summary>
    private static void CopyThenDelete(SafeFileHandle source, string dest, string expectedSha256)
    {
        try
        {
            using (var output = new FileStream(dest, FileMode.CreateNew, FileAccess.Write, FileShare.None))
            {
                string copiedSha = SafeFileOps.HashHandle(source, output);
                output.Flush(flushToDisk: true);
                if (!string.Equals(copiedSha, expectedSha256.Trim(), StringComparison.OrdinalIgnoreCase))
                {
                    throw new IOException("The bytes copied into quarantine do not match the judged hash.");
                }
            }
            SafeFileOps.DeleteOnClose(source);
        }
        catch
        {
            TryDelete(dest);
            throw;
        }
    }

    private string? TryReadSddl(SafeFileHandle file)
    {
        try
        {
            return SafeFileOps.ReadDaclSddl(file);
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Could not read the original ACL; a restore will keep the quarantine ACL.");
            return null;
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

    private bool TryApplySddl(FileInfo info, string sddl)
    {
        try
        {
            var security = new FileSecurity();
            security.SetSecurityDescriptorSddlForm(sddl, AccessControlSections.Access);
            info.SetAccessControl(security);
            return true;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Could not restore original ACL on {Path}.", info.FullName);
            return false;
        }
    }
}
