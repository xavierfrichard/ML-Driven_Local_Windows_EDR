using System.ComponentModel;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace Warden.Ipc;

/// <summary>Thrown by <see cref="BoundedLineReader"/> when a peer sends a frame larger than the cap.</summary>
public sealed class IpcFrameTooLargeException : IOException
{
    public IpcFrameTooLargeException(int limit)
        : base($"IPC frame exceeded the {limit:N0}-byte limit; connection dropped.")
    {
    }

    public IpcFrameTooLargeException()
    {
    }

    public IpcFrameTooLargeException(string message) : base(message)
    {
    }

    public IpcFrameTooLargeException(string message, Exception innerException) : base(message, innerException)
    {
    }
}

/// <summary>Facts about the process on the other end of a server pipe instance.</summary>
/// <param name="ProcessId">Client PID (0 if it could not be resolved).</param>
/// <param name="ImagePath">Full image path of the client process, or null if unavailable.</param>
public readonly record struct PipePeer(int ProcessId, string? ImagePath)
{
    /// <summary>The client's image file name (no directory), or null.</summary>
    public string? ImageName => ImagePath is null ? null : Path.GetFileName(ImagePath);
}

/// <summary>
/// Reads newline-delimited UTF-8 frames from a stream with a hard size cap, so a peer that streams bytes
/// without ever sending <c>\n</c> cannot grow the reader's buffer without bound (the SYSTEM service must
/// not be OOM-able by any local client). Frames longer than <see cref="Limit"/> throw
/// <see cref="IpcFrameTooLargeException"/>; callers drop the connection.
/// </summary>
public sealed class BoundedLineReader
{
    /// <summary>Default per-frame cap for both IPC channels (1 MiB is far above any legitimate frame).</summary>
    public const int DefaultLimit = 1024 * 1024;

    private readonly Stream _stream;
    private readonly byte[] _chunk = new byte[16 * 1024];
    private readonly MemoryStream _pending = new();
    private int _pendingRead; // read cursor into _pending

    public BoundedLineReader(Stream stream, int limit = DefaultLimit)
    {
        _stream = stream ?? throw new ArgumentNullException(nameof(stream));
        if (limit <= 0) { throw new ArgumentOutOfRangeException(nameof(limit)); }
        Limit = limit;
    }

    /// <summary>Maximum accepted frame length in bytes (excluding the terminating newline).</summary>
    public int Limit { get; }

    /// <summary>
    /// Returns the next line without its terminator (a trailing <c>\r</c> is stripped), or null when the
    /// stream ends. Throws <see cref="IpcFrameTooLargeException"/> once a partial line exceeds the cap.
    /// </summary>
    public async Task<string?> ReadLineAsync(CancellationToken cancellationToken)
    {
        var line = new MemoryStream();

        while (true)
        {
            // Drain buffered bytes first.
            byte[] buf = _pending.GetBuffer();
            int end = (int)_pending.Length;
            while (_pendingRead < end)
            {
                byte b = buf[_pendingRead++];
                if (b == (byte)'\n')
                {
                    CompactPending();
                    return Decode(line);
                }

                if (line.Length >= Limit)
                {
                    throw new IpcFrameTooLargeException(Limit);
                }
                line.WriteByte(b);
            }

            // Buffer empty: pull more from the stream.
            _pending.SetLength(0);
            _pendingRead = 0;
            int n = await _stream.ReadAsync(_chunk, cancellationToken).ConfigureAwait(false);
            if (n <= 0)
            {
                // EOF: a final unterminated line is returned once, then null.
                return line.Length == 0 ? null : Decode(line);
            }
            _pending.Write(_chunk, 0, n);
        }
    }

    private void CompactPending()
    {
        if (_pendingRead >= _pending.Length)
        {
            _pending.SetLength(0);
            _pendingRead = 0;
        }
    }

    private static string Decode(MemoryStream line)
    {
        int len = (int)line.Length;
        byte[] data = line.GetBuffer();
        if (len > 0 && data[len - 1] == (byte)'\r')
        {
            len--;
        }
        return Encoding.UTF8.GetString(data, 0, len);
    }
}

/// <summary>
/// Shared security primitives for both named-pipe channels: the server DACL, peer identification, the
/// admin-membership check, and the client-side server-owner check.
/// </summary>
public static class PipeGuard
{
    /// <summary>Name of the Windows service that hosts both pipes.</summary>
    public const string ServiceName = "WardenAgent";

    /// <summary>The tray UI's image file name.</summary>
    public const string UiImageName = "Warden.Ui.exe";

    /// <summary>
    /// Environment variable that turns on the dev-run pipe exceptions. Only Debug builds read it; a Release
    /// build ignores it, so same-user malware cannot turn it on in production by setting a user
    /// environment variable.
    /// </summary>
    public const string DevModeVariable = "WARDEN_DEV_PIPES";

    /// <summary>
    /// True only in a Debug build started with <c>WARDEN_DEV_PIPES=1</c>. It allows the dev-run setup
    /// (service started in a console as the signed-in user, UI started from its own bin folder):
    /// <list type="bullet">
    /// <item>clients accept a server pipe owned by the current user (see <see cref="ServerLooksLegitimate(PipeStream)"/>);</item>
    /// <item>servers accept a client whose image is named <c>Warden.Ui.exe</c> in any folder
    /// (see <see cref="PipeServerOptions.DevUiImageName"/>).</item>
    /// </list>
    /// Release builds always return false.
    /// </summary>
    public static bool DevModeEnabled { get; } = ComputeDevMode();

    private static bool ComputeDevMode()
    {
#if DEBUG
        return string.Equals(Environment.GetEnvironmentVariable(DevModeVariable), "1", StringComparison.Ordinal);
#else
        return false;
#endif
    }

    /// <summary>
    /// The DACL every Warden server pipe is created with: SYSTEM and BUILTIN\Administrators get full
    /// control; the account the server itself runs as is added so a dev run (service in a console as the
    /// user) still works. Nothing else — a non-elevated process cannot even connect. This is what makes
    /// "whoever answers the prompt is trusted" safe: only an elevated caller can answer.
    /// The owner is set explicitly to the server's own account (SYSTEM for the installed service) instead
    /// of the token's default owner, so clients can require a SYSTEM owner. A medium-integrity process
    /// cannot create a pipe owned by SYSTEM.
    /// </summary>
    [SupportedOSPlatform("windows")]
    public static PipeSecurity BuildServerSecurity()
    {
        var security = new PipeSecurity();
        security.AddAccessRule(new PipeAccessRule(
            new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null),
            PipeAccessRights.FullControl,
            AccessControlType.Allow));
        security.AddAccessRule(new PipeAccessRule(
            new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null),
            PipeAccessRights.FullControl,
            AccessControlType.Allow));

        using WindowsIdentity self = WindowsIdentity.GetCurrent();
        if (self.User is { } me)
        {
            security.SetOwner(me);
            if (!me.IsWellKnown(WellKnownSidType.LocalSystemSid))
            {
                security.AddAccessRule(new PipeAccessRule(me, PipeAccessRights.FullControl, AccessControlType.Allow));
            }
        }

        return security;
    }

    /// <summary>
    /// Creates a server instance with the Warden DACL. <paramref name="firstInstance"/> maps to
    /// <c>FILE_FLAG_FIRST_PIPE_INSTANCE</c>: creation fails (rather than silently joining a pre-created
    /// pipe with someone else's DACL) if the name already exists — the defence against pipe squatting.
    /// Servers pass true whenever they hold no instance of the name (see <see cref="PipeInstanceSet{T}"/>).
    /// </summary>
    [SupportedOSPlatform("windows")]
    public static NamedPipeServerStream CreateServer(string pipeName, int maxInstances, bool firstInstance)
    {
        PipeOptions options = PipeOptions.Asynchronous | (firstInstance ? PipeOptions.FirstPipeInstance : PipeOptions.None);
        return NamedPipeServerStreamAcl.Create(
            pipeName,
            PipeDirection.InOut,
            maxInstances,
            PipeTransmissionMode.Byte,
            options,
            inBufferSize: 0,
            outBufferSize: 0,
            BuildServerSecurity());
    }

    /// <summary>Identifies the connected client process (PID + image path). Never throws; fields are null/0 on failure.</summary>
    [SupportedOSPlatform("windows")]
    public static PipePeer ResolvePeer(NamedPipeServerStream pipe)
    {
        ArgumentNullException.ThrowIfNull(pipe);
        try
        {
            if (!GetNamedPipeClientProcessId(pipe.SafePipeHandle, out uint pid) || pid == 0)
            {
                return new PipePeer(0, null);
            }

            return new PipePeer((int)pid, QueryImagePath(pid));
        }
        catch (Exception ex) when (ex is Win32Exception or IOException or ObjectDisposedException or InvalidOperationException)
        {
            return new PipePeer(0, null);
        }
    }

    /// <summary>
    /// Impersonates the connected client and reports whether its token is a member of BUILTIN\Administrators.
    /// MUST be called only after at least one frame has been read from the client — Windows attaches the
    /// client's security context to the first message read (<c>ERROR_CANNOT_IMPERSONATE</c> otherwise).
    /// Any failure resolves to false (fail closed). Under UAC a filtered admin token reports false, which
    /// is exactly the intent: only an elevated process counts.
    /// </summary>
    [SupportedOSPlatform("windows")]
    public static bool ClientIsAdministrator(NamedPipeServerStream pipe, Action<Exception>? onError = null)
    {
        ArgumentNullException.ThrowIfNull(pipe);
        bool isAdmin = false;
        try
        {
            pipe.RunAsClient(() =>
            {
                using WindowsIdentity identity = WindowsIdentity.GetCurrent();
                isAdmin = new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
            });
        }
        catch (Exception ex) when (ex is IOException or InvalidOperationException or ObjectDisposedException
                                   or UnauthorizedAccessException or System.Security.SecurityException)
        {
            onError?.Invoke(ex);
            return false;
        }
        return isAdmin;
    }

    /// <summary>
    /// Client-side check that the pipe we connected to is hosted by the Warden service, under the default
    /// policy (<see cref="PipeServerTrust.Default"/>): the owner must be SYSTEM and, when the WardenAgent
    /// service is installed, the server process must be the service's process. A pipe owned by the current
    /// user is accepted only in dev mode (<see cref="DevModeEnabled"/>). Never throws; false on any error.
    /// </summary>
    [SupportedOSPlatform("windows")]
    public static bool ServerLooksLegitimate(PipeStream pipe) => ServerLooksLegitimate(pipe, PipeServerTrust.Default);

    /// <summary>
    /// Client-side check that the pipe we connected to is hosted by the Warden service under the given
    /// policy. See <see cref="EvaluateServer"/> for the rules. Never throws; false on any error.
    /// </summary>
    [SupportedOSPlatform("windows")]
    public static bool ServerLooksLegitimate(PipeStream pipe, PipeServerTrust trust)
    {
        ArgumentNullException.ThrowIfNull(pipe);
        ArgumentNullException.ThrowIfNull(trust);
        try
        {
            PipeSecurity security = pipe.GetAccessControl();
            if (security.GetOwner(typeof(SecurityIdentifier)) is not SecurityIdentifier owner)
            {
                return false;
            }

            int serverPid = GetNamedPipeServerProcessId(pipe.SafePipeHandle, out uint pid) ? (int)pid : 0;

            using WindowsIdentity self = WindowsIdentity.GetCurrent();
            return EvaluateServer(owner, self.User, serverPid, trust);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidOperationException
                                   or ObjectDisposedException or IdentityNotMappedException or Win32Exception)
        {
            return false;
        }
    }

    /// <summary>
    /// The server-legitimacy rules, kept apart from the Win32 lookups so they can be tested:
    /// <list type="number">
    /// <item>Owner SYSTEM: accepted when the WardenAgent service is not installed, or when it has a process
    /// and <paramref name="serverProcessId"/> is that process. A stopped service, a different or unknown
    /// server PID, or a failed SCM query is rejected (fail closed): some other process holds the name.</item>
    /// <item>Owner equal to <paramref name="currentUser"/>: accepted only when
    /// <see cref="PipeServerTrust.AllowCurrentUserOwner"/> is set (dev run). The service PID is not checked
    /// then, because a dev-run server is not the service.</item>
    /// <item>Any other owner (BUILTIN\Administrators, other users, ...): rejected.</item>
    /// </list>
    /// </summary>
    [SupportedOSPlatform("windows")]
    public static bool EvaluateServer(SecurityIdentifier owner, SecurityIdentifier? currentUser, int serverProcessId, PipeServerTrust trust)
    {
        ArgumentNullException.ThrowIfNull(owner);
        ArgumentNullException.ThrowIfNull(trust);

        if (owner.IsWellKnown(WellKnownSidType.LocalSystemSid))
        {
            ServiceProcessInfo service;
            try
            {
                service = trust.QueryServiceProcess();
            }
            catch (Exception ex) when (ex is Win32Exception or InvalidOperationException or UnauthorizedAccessException)
            {
                return false;
            }

            return service.State switch
            {
                ServiceProcessState.NotInstalled => true,
                ServiceProcessState.Running => serverProcessId != 0 && serverProcessId == service.ProcessId,
                _ => false,
            };
        }

        return trust.AllowCurrentUserOwner && currentUser is not null && owner.Equals(currentUser);
    }

    /// <summary>
    /// Asks the Service Control Manager for the process of <paramref name="serviceName"/>. Needs only
    /// <c>SERVICE_QUERY_STATUS</c>, which the installer's service DACL grants to Authenticated Users.
    /// Never throws: failures are reported as <see cref="ServiceProcessState.QueryFailed"/>.
    /// </summary>
    [SupportedOSPlatform("windows")]
    public static ServiceProcessInfo QueryServiceProcess(string serviceName)
    {
        ArgumentException.ThrowIfNullOrEmpty(serviceName);

        IntPtr scm = OpenSCManagerW(null, null, SC_MANAGER_CONNECT);
        if (scm == IntPtr.Zero)
        {
            return new ServiceProcessInfo(ServiceProcessState.QueryFailed, 0);
        }

        try
        {
            IntPtr service = OpenServiceW(scm, serviceName, SERVICE_QUERY_STATUS);
            if (service == IntPtr.Zero)
            {
                return Marshal.GetLastWin32Error() == ERROR_SERVICE_DOES_NOT_EXIST
                    ? new ServiceProcessInfo(ServiceProcessState.NotInstalled, 0)
                    : new ServiceProcessInfo(ServiceProcessState.QueryFailed, 0);
            }

            try
            {
                var status = default(SERVICE_STATUS_PROCESS);
                if (!QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO, ref status, Marshal.SizeOf<SERVICE_STATUS_PROCESS>(), out _))
                {
                    return new ServiceProcessInfo(ServiceProcessState.QueryFailed, 0);
                }

                return status.dwProcessId == 0
                    ? new ServiceProcessInfo(ServiceProcessState.NotRunning, 0)
                    : new ServiceProcessInfo(ServiceProcessState.Running, (int)status.dwProcessId);
            }
            finally
            {
                CloseServiceHandle(service);
            }
        }
        finally
        {
            CloseServiceHandle(scm);
        }
    }

    /// <summary>
    /// The UI image paths the servers accept by default: <c>Warden.Ui.exe</c> in the installer's
    /// <c>InstallDir\ui</c> folder (next to the service's <c>InstallDir\service</c> folder), or in the
    /// service folder itself. Both are inside the ACL-locked install directory in production, so a renamed
    /// or copied binary anywhere else does not match.
    /// </summary>
    /// <param name="serviceDirectory">The service's binary folder; defaults to <see cref="AppContext.BaseDirectory"/>.</param>
    public static IReadOnlyList<string> DefaultUiImagePaths(string? serviceDirectory = null)
    {
        string dir = serviceDirectory ?? AppContext.BaseDirectory;
        return new[]
        {
            Path.GetFullPath(Path.Combine(dir, "..", "ui", UiImageName)),
            Path.GetFullPath(Path.Combine(dir, UiImageName)),
        };
    }

    /// <summary>
    /// True when the peer's full image path equals one of <paramref name="allowedImagePaths"/>
    /// (normalized, case-insensitive). Only the full path counts: a renamed or copied binary in another
    /// folder is rejected. An empty list accepts any image (tests); an unresolvable peer, a relative peer
    /// path, or a relative allow-list entry never matches.
    /// </summary>
    public static bool PeerImageAllowed(PipePeer peer, IReadOnlyCollection<string> allowedImagePaths)
    {
        ArgumentNullException.ThrowIfNull(allowedImagePaths);
        if (allowedImagePaths.Count == 0)
        {
            return true;
        }

        string? actual = NormalizeFullPath(peer.ImagePath);
        if (actual is null)
        {
            return false;
        }

        foreach (string allowed in allowedImagePaths)
        {
            string? expected = NormalizeFullPath(allowed);
            if (expected is not null && string.Equals(expected, actual, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }
        return false;
    }

    /// <summary>
    /// The servers' peer check: the full image path must be allowed (<see cref="PeerImageAllowed"/>), or,
    /// in dev mode only, the image file name must equal <see cref="PipeServerOptions.DevUiImageName"/>.
    /// </summary>
    public static bool PeerAllowed(PipePeer peer, PipeServerOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        if (PeerImageAllowed(peer, (IReadOnlyCollection<string>)options.AllowedClientImagePaths))
        {
            return true;
        }

        return options.DevUiImageName is { Length: > 0 } devName
            && string.Equals(peer.ImageName, devName, StringComparison.OrdinalIgnoreCase);
    }

    private static string? NormalizeFullPath(string? path)
    {
        if (string.IsNullOrWhiteSpace(path) || !Path.IsPathFullyQualified(path))
        {
            return null;
        }

        try
        {
            return Path.GetFullPath(path);
        }
        catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException)
        {
            return null;
        }
    }

    // ---- P/Invoke ---------------------------------------------------------------------------------

    private const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;
    private const uint SC_MANAGER_CONNECT = 0x0001;
    private const uint SERVICE_QUERY_STATUS = 0x0004;
    private const int SC_STATUS_PROCESS_INFO = 0;
    private const int ERROR_SERVICE_DOES_NOT_EXIST = 1060;

    [StructLayout(LayoutKind.Sequential)]
    private struct SERVICE_STATUS_PROCESS
    {
        public uint dwServiceType;
        public uint dwCurrentState;
        public uint dwControlsAccepted;
        public uint dwWin32ExitCode;
        public uint dwServiceSpecificExitCode;
        public uint dwCheckPoint;
        public uint dwWaitHint;
        public uint dwProcessId;
        public uint dwServiceFlags;
    }

    [SupportedOSPlatform("windows")]
    private static string? QueryImagePath(uint pid)
    {
        IntPtr handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
        if (handle == IntPtr.Zero)
        {
            return null;
        }

        try
        {
            var sb = new StringBuilder(1024);
            int size = sb.Capacity;
            return QueryFullProcessImageName(handle, 0, sb, ref size) ? sb.ToString(0, size) : null;
        }
        finally
        {
            CloseHandle(handle);
        }
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetNamedPipeClientProcessId(SafePipeHandle hNamedPipe, out uint clientProcessId);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetNamedPipeServerProcessId(SafePipeHandle hNamedPipe, out uint serverProcessId);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint desiredAccess, [MarshalAs(UnmanagedType.Bool)] bool inheritHandle, uint processId);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool QueryFullProcessImageName(IntPtr hProcess, uint flags, StringBuilder exeName, ref int size);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseHandle(IntPtr handle);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern IntPtr OpenSCManagerW(string? machineName, string? databaseName, uint desiredAccess);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern IntPtr OpenServiceW(IntPtr scManager, string serviceName, uint desiredAccess);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool QueryServiceStatusEx(IntPtr service, int infoLevel, ref SERVICE_STATUS_PROCESS buffer, int bufferSize, out int bytesNeeded);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseServiceHandle(IntPtr handle);
}

/// <summary>What <see cref="PipeGuard.QueryServiceProcess"/> found out about the service.</summary>
public enum ServiceProcessState
{
    /// <summary>The service is not installed on this machine.</summary>
    NotInstalled,

    /// <summary>The service has a process (running, starting or stopping).</summary>
    Running,

    /// <summary>The service is installed but has no process.</summary>
    NotRunning,

    /// <summary>The SCM could not be asked; callers fail closed.</summary>
    QueryFailed,
}

/// <summary>The service's state and process id (0 unless <see cref="ServiceProcessState.Running"/>).</summary>
public readonly record struct ServiceProcessInfo(ServiceProcessState State, int ProcessId);

/// <summary>Client-side policy for <see cref="PipeGuard.ServerLooksLegitimate(PipeStream, PipeServerTrust)"/>.</summary>
public sealed class PipeServerTrust
{
    /// <summary>
    /// Accept a server pipe owned by the current user (dev run: the service started in a console as the
    /// user). Off in production, where same-user malware could otherwise squat the pipe names.
    /// </summary>
    public bool AllowCurrentUserOwner { get; init; }

    /// <summary>Looks up the WardenAgent service process. Replaceable for tests.</summary>
    public Func<ServiceProcessInfo> QueryServiceProcess { get; init; } = QueryWardenService;

    /// <summary>Production policy: SYSTEM owner and the service's PID only.</summary>
    public static PipeServerTrust Production { get; } = new();

    /// <summary>What the clients use: production, plus the current-user owner in dev mode (<see cref="PipeGuard.DevModeEnabled"/>).</summary>
    public static PipeServerTrust Default { get; } = new() { AllowCurrentUserOwner = PipeGuard.DevModeEnabled };

    private static ServiceProcessInfo QueryWardenService() =>
        OperatingSystem.IsWindows()
            ? PipeGuard.QueryServiceProcess(PipeGuard.ServiceName)
            : new ServiceProcessInfo(ServiceProcessState.QueryFailed, 0);
}

/// <summary>Policy knobs shared by both pipe servers. Production defaults are the strict ones.</summary>
public sealed class PipeServerOptions
{
    /// <summary>Name of the prompt pipe (overridable so tests do not collide with an installed agent).</summary>
    public string PromptPipeName { get; set; } = IpcProtocol.PipeName;

    /// <summary>Name of the management pipe (overridable so tests do not collide with an installed agent).</summary>
    public string MgmtPipeName { get; set; } = MgmtProtocol.PipeName;

    /// <summary>
    /// Full image paths a client process may have. Default: the installed tray UI
    /// (<see cref="PipeGuard.DefaultUiImagePaths"/>). Only the full path counts, so a renamed or copied
    /// binary elsewhere is rejected. Empty = accept any image (unit tests). The DACL already limits
    /// callers to elevated processes; this is defence in depth.
    /// </summary>
    public IList<string> AllowedClientImagePaths { get; } = new List<string>(PipeGuard.DefaultUiImagePaths());

    /// <summary>
    /// Dev run only: a client whose image file name equals this is accepted from any folder. Defaults to
    /// <c>Warden.Ui.exe</c> when <see cref="PipeGuard.DevModeEnabled"/>, otherwise null (off).
    /// </summary>
    public string? DevUiImageName { get; set; } = PipeGuard.DevModeEnabled ? PipeGuard.UiImageName : null;

    /// <summary>
    /// Prompt channel: an <c>Allow</c> answer is honoured only from a client whose token is a member of
    /// Administrators; anything else is downgraded to KeepBlocked. Default true.
    /// </summary>
    public bool RequireAdministratorForAllow { get; set; } = true;

    /// <summary>Per-frame byte cap for both channels.</summary>
    public int MaxFrameBytes { get; set; } = BoundedLineReader.DefaultLimit;

    /// <summary>Management channel: a connection with no request for this long is dropped.</summary>
    public TimeSpan IdleTimeout { get; set; } = TimeSpan.FromMinutes(10);

    /// <summary>Delay before re-creating a listener after a failed create/accept (prevents a hot spin).</summary>
    public TimeSpan RetryBackoff { get; set; } = TimeSpan.FromSeconds(1);

    /// <summary>
    /// Security events (tamper-log rows) of one category are reported at most once per this interval; the
    /// next report carries the number suppressed meanwhile. Zero or less turns the limit off.
    /// </summary>
    public TimeSpan SecurityEventInterval { get; set; } = TimeSpan.FromMinutes(1);

    /// <summary>A permissive instance for in-process tests: any client image, no admin requirement.</summary>
    public static PipeServerOptions ForTests()
    {
        var o = new PipeServerOptions { RequireAdministratorForAllow = false, DevUiImageName = null };
        o.AllowedClientImagePaths.Clear();
        return o;
    }
}
