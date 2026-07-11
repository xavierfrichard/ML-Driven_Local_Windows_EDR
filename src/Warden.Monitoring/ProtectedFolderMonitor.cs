using Microsoft.Extensions.Logging;
using Warden.Storage;

namespace Warden.Monitoring;

/// <summary>
/// Watches the user-configured protected folders for created/modified executables and logs them,
/// flagging any that carry a Mark-of-the-Web (downloaded-from-internet) tag. A lightweight Phase 2
/// telemetry feed; deeper response (canary files, ransomware detection) lands in later phases.
/// </summary>
public sealed class ProtectedFolderMonitor : IProtectedFolderMonitor, IDisposable
{
    private static readonly HashSet<string> ExecutableExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".exe", ".dll", ".scr", ".com", ".ps1", ".bat", ".cmd", ".vbs", ".js", ".jar", ".msi",
    };

    private readonly IProtectedFolderRepository _repo;
    private readonly ILogger<ProtectedFolderMonitor> _logger;
    private readonly List<FileSystemWatcher> _watchers = new();
    private bool _started;
    private bool _disposed;

    public ProtectedFolderMonitor(IProtectedFolderRepository repo, ILogger<ProtectedFolderMonitor> logger)
    {
        _repo = repo;
        _logger = logger;
    }

    public void Start()
    {
        if (_started || _disposed)
        {
            return;
        }
        _started = true;

        IReadOnlyList<ProtectedFolder> folders;
        try
        {
            folders = _repo.GetAllAsync().GetAwaiter().GetResult();
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Could not load protected folders.");
            return;
        }

        foreach (ProtectedFolder folder in folders)
        {
            if (!Directory.Exists(folder.Path))
            {
                _logger.LogWarning("Protected folder does not exist: {Path}", folder.Path);
                continue;
            }
            try
            {
                var watcher = new FileSystemWatcher(folder.Path)
                {
                    IncludeSubdirectories = folder.Recursive,
                    NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite,
                    EnableRaisingEvents = true,
                };
                watcher.Created += OnChanged;
                watcher.Changed += OnChanged;
                _watchers.Add(watcher);
                _logger.LogInformation("Monitoring protected folder {Path} (recursive={Recursive}).", folder.Path, folder.Recursive);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Could not watch protected folder {Path}.", folder.Path);
            }
        }
    }

    public void Stop()
    {
        if (!_started)
        {
            return;
        }
        _started = false;
        foreach (FileSystemWatcher watcher in _watchers)
        {
            try
            {
                watcher.EnableRaisingEvents = false;
                watcher.Dispose();
            }
            catch { /* best effort */ }
        }
        _watchers.Clear();
    }

    private void OnChanged(object sender, FileSystemEventArgs e)
    {
        try
        {
            if (!ExecutableExtensions.Contains(Path.GetExtension(e.FullPath)))
            {
                return;
            }

            int zone = ReadMotwZone(e.FullPath);
            if (zone >= 3)
            {
                _logger.LogWarning(
                    "Protected folder: internet-tagged executable {Change} at {Path} (ZoneId={Zone}).",
                    e.ChangeType, e.FullPath, zone);
            }
            else
            {
                _logger.LogInformation("Protected folder: executable {Change} at {Path}.", e.ChangeType, e.FullPath);
            }
        }
        catch
        {
            // watcher callbacks must never throw
        }
    }

    private static int ReadMotwZone(string path)
    {
        try
        {
            using var stream = new FileStream(path + ":Zone.Identifier", FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            using var reader = new StreamReader(stream);
            bool inZoneTransfer = false;
            string? line;
            while ((line = reader.ReadLine()) is not null)
            {
                line = line.Trim();
                if (line.StartsWith('['))
                {
                    inZoneTransfer = line.Equals("[ZoneTransfer]", StringComparison.OrdinalIgnoreCase);
                }
                else if (inZoneTransfer && line.StartsWith("ZoneId", StringComparison.OrdinalIgnoreCase))
                {
                    int eq = line.IndexOf('=');
                    if (eq > 0 && int.TryParse(line[(eq + 1)..].Trim(), out int zone))
                    {
                        return zone;
                    }
                }
            }
        }
        catch { /* no ADS / unreadable */ }
        return -1;
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }
        _disposed = true;
        Stop();
    }
}
