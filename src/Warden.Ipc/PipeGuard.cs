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
    /// <summary>
    /// The DACL every Warden server pipe is created with: SYSTEM and BUILTIN\Administrators get full
    /// control; the account the server itself runs as is added so a dev run (service in a console as the
    /// user) still works. Nothing else — a non-elevated process cannot even connect. This is what makes
    /// "whoever answers the prompt is trusted" safe: only an elevated caller can answer.
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
        if (self.User is { } me
            && !me.IsWellKnown(WellKnownSidType.LocalSystemSid))
        {
            security.AddAccessRule(new PipeAccessRule(me, PipeAccessRights.FullControl, AccessControlType.Allow));
        }

        return security;
    }

    /// <summary>
    /// Creates a server instance with the Warden DACL. <paramref name="firstInstance"/> maps to
    /// <c>FILE_FLAG_FIRST_PIPE_INSTANCE</c>: creation fails (rather than silently joining a pre-created
    /// pipe with someone else's DACL) if the name already exists — the defence against pipe squatting.
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
    /// Client-side check that the pipe we connected to is hosted by a legitimate server: its owner must be
    /// SYSTEM, BUILTIN\Administrators, or the current user (dev run). A rogue pre-created pipe owned by
    /// another standard user fails this. Never throws; false on any error.
    /// </summary>
    [SupportedOSPlatform("windows")]
    public static bool ServerLooksLegitimate(PipeStream pipe)
    {
        ArgumentNullException.ThrowIfNull(pipe);
        try
        {
            PipeSecurity security = pipe.GetAccessControl();
            if (security.GetOwner(typeof(SecurityIdentifier)) is not SecurityIdentifier owner)
            {
                return false;
            }

            if (owner.IsWellKnown(WellKnownSidType.LocalSystemSid) || owner.IsWellKnown(WellKnownSidType.BuiltinAdministratorsSid))
            {
                return true;
            }

            using WindowsIdentity self = WindowsIdentity.GetCurrent();
            return self.User is { } me && owner.Equals(me);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidOperationException
                                   or ObjectDisposedException or IdentityNotMappedException)
        {
            return false;
        }
    }

    /// <summary>
    /// True when the peer's image name is on the allow-list (case-insensitive). An empty allow-list accepts
    /// any image (tests / dev); an unresolvable peer is rejected when a list is configured.
    /// </summary>
    public static bool PeerImageAllowed(PipePeer peer, IReadOnlyCollection<string> allowedImageNames)
    {
        ArgumentNullException.ThrowIfNull(allowedImageNames);
        if (allowedImageNames.Count == 0)
        {
            return true;
        }

        string? name = peer.ImageName;
        if (string.IsNullOrEmpty(name))
        {
            return false;
        }

        foreach (string allowed in allowedImageNames)
        {
            if (string.Equals(allowed, name, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }
        return false;
    }

    // ---- P/Invoke ---------------------------------------------------------------------------------

    private const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;

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
    private static extern IntPtr OpenProcess(uint desiredAccess, [MarshalAs(UnmanagedType.Bool)] bool inheritHandle, uint processId);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool QueryFullProcessImageName(IntPtr hProcess, uint flags, StringBuilder exeName, ref int size);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseHandle(IntPtr handle);
}

/// <summary>Policy knobs shared by both pipe servers. Production defaults are the strict ones.</summary>
public sealed class PipeServerOptions
{
    /// <summary>Name of the prompt pipe (overridable so tests do not collide with an installed agent).</summary>
    public string PromptPipeName { get; set; } = IpcProtocol.PipeName;

    /// <summary>Name of the management pipe (overridable so tests do not collide with an installed agent).</summary>
    public string MgmtPipeName { get; set; } = MgmtProtocol.PipeName;

    /// <summary>
    /// Image file names a client process may have. Default: the tray UI only. Empty = accept any image
    /// (unit tests). The DACL already limits callers to elevated processes; this is defence in depth.
    /// </summary>
    public IList<string> AllowedClientImageNames { get; } = new List<string> { "Warden.Ui.exe" };

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

    /// <summary>A permissive instance for in-process tests: any client image, no admin requirement.</summary>
    public static PipeServerOptions ForTests()
    {
        var o = new PipeServerOptions { RequireAdministratorForAllow = false };
        o.AllowedClientImageNames.Clear();
        return o;
    }
}
