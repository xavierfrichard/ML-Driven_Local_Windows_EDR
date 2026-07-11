using System.Runtime.InteropServices;
using Microsoft.Extensions.Logging;

namespace Warden.Amsi;

/// <summary>
/// AMSI content scanner over amsi.dll. Lazily initializes a shared AMSI context; if amsi.dll or
/// initialization is unavailable, every scan degrades to <see cref="AmsiScanOutcome.NotChecked"/>.
/// Scans and disposal are serialized against a single gate so a scan can never run against a context
/// that <see cref="Dispose"/> has already freed.
/// </summary>
public sealed class AmsiScanner : IAmsiScanner, IDisposable
{
    // AMSI_RESULT_DETECTED = 32768; values >= this are malware (AmsiResultIsMalware).
    private const int AmsiResultDetected = 32768;

    // AMSI_RESULT_BLOCKED_BY_ADMIN_START..END (0x4000..0x4FFF): blocked by administrator policy — NOT clean.
    private const int AmsiBlockedByAdminStart = 0x4000;
    private const int AmsiBlockedByAdminEnd = 0x4FFF;

    private readonly ILogger<AmsiScanner> _logger;
    private readonly object _gate = new();
    private IntPtr _context;
    private bool _initTried;
    private bool _disposed;

    public AmsiScanner(ILogger<AmsiScanner> logger) => _logger = logger;

    public AmsiScanOutcome Scan(ReadOnlySpan<byte> content, string contentName)
    {
        byte[] buffer = content.ToArray();
        lock (_gate)
        {
            if (_disposed)
            {
                return AmsiScanOutcome.NotChecked;
            }
            IntPtr context = EnsureContextLocked();
            if (context == IntPtr.Zero)
            {
                return AmsiScanOutcome.NotChecked;
            }
            try
            {
                int hr = AmsiScanBuffer(context, buffer, (uint)buffer.Length, contentName, IntPtr.Zero, out int result);
                return FromHr(hr, result);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "AMSI buffer scan failed.");
                return AmsiScanOutcome.NotChecked;
            }
        }
    }

    public AmsiScanOutcome Scan(string content, string contentName)
    {
        lock (_gate)
        {
            if (_disposed)
            {
                return AmsiScanOutcome.NotChecked;
            }
            IntPtr context = EnsureContextLocked();
            if (context == IntPtr.Zero)
            {
                return AmsiScanOutcome.NotChecked;
            }
            try
            {
                int hr = AmsiScanString(context, content, contentName, IntPtr.Zero, out int result);
                return FromHr(hr, result);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "AMSI string scan failed.");
                return AmsiScanOutcome.NotChecked;
            }
        }
    }

    private static AmsiScanOutcome FromHr(int hr, int result)
    {
        if (hr != 0)
        {
            return AmsiScanOutcome.NotChecked;
        }
        bool detected = result >= AmsiResultDetected
            || (result >= AmsiBlockedByAdminStart && result <= AmsiBlockedByAdminEnd);
        return new AmsiScanOutcome(detected ? AmsiVerdict.Detected : AmsiVerdict.Clean, result);
    }

    // Must be called under _gate.
    private IntPtr EnsureContextLocked()
    {
        if (_context != IntPtr.Zero || _initTried)
        {
            return _context;
        }
        _initTried = true;
        try
        {
            int hr = AmsiInitialize("Warden", out IntPtr context);
            if (hr == 0)
            {
                _context = context;
            }
            else
            {
                _logger.LogWarning("AmsiInitialize failed (hr=0x{Hr:X8}); AMSI scanning disabled.", hr);
            }
        }
        catch (DllNotFoundException)
        {
            _logger.LogInformation("amsi.dll not available; AMSI scanning disabled.");
        }
        return _context;
    }

    public void Dispose()
    {
        lock (_gate)
        {
            if (_disposed)
            {
                return;
            }
            _disposed = true;
            if (_context != IntPtr.Zero)
            {
                try { AmsiUninitialize(_context); }
                catch { /* best effort */ }
                _context = IntPtr.Zero;
            }
        }
    }

    [DllImport("amsi.dll", CharSet = CharSet.Unicode)]
    private static extern int AmsiInitialize(string appName, out IntPtr amsiContext);

    [DllImport("amsi.dll")]
    private static extern void AmsiUninitialize(IntPtr amsiContext);

    [DllImport("amsi.dll", CharSet = CharSet.Unicode)]
    private static extern int AmsiScanBuffer(
        IntPtr amsiContext, byte[] buffer, uint length, string contentName, IntPtr amsiSession, out int result);

    [DllImport("amsi.dll", CharSet = CharSet.Unicode)]
    private static extern int AmsiScanString(
        IntPtr amsiContext, string content, string contentName, IntPtr amsiSession, out int result);
}
