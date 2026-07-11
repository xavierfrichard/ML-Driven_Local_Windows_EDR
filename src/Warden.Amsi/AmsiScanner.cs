using System.Runtime.InteropServices;
using Microsoft.Extensions.Logging;

namespace Warden.Amsi;

/// <summary>
/// AMSI content scanner over amsi.dll. Lazily initializes a shared AMSI context; if amsi.dll or
/// initialization is unavailable, every scan degrades to <see cref="AmsiScanOutcome.NotChecked"/>.
/// </summary>
public sealed class AmsiScanner : IAmsiScanner, IDisposable
{
    // AMSI_RESULT_DETECTED = 32768; values >= this are malware (AmsiResultIsMalware).
    private const int AmsiResultDetected = 32768;

    private readonly ILogger<AmsiScanner> _logger;
    private readonly object _gate = new();
    private IntPtr _context;
    private bool _initTried;
    private bool _disposed;

    public AmsiScanner(ILogger<AmsiScanner> logger) => _logger = logger;

    public AmsiScanOutcome Scan(ReadOnlySpan<byte> content, string contentName)
    {
        IntPtr context = EnsureContext();
        if (context == IntPtr.Zero)
        {
            return AmsiScanOutcome.NotChecked;
        }

        byte[] buffer = content.ToArray();
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

    public AmsiScanOutcome Scan(string content, string contentName)
    {
        IntPtr context = EnsureContext();
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

    private static AmsiScanOutcome FromHr(int hr, int result) =>
        hr != 0
            ? AmsiScanOutcome.NotChecked
            : new AmsiScanOutcome(result >= AmsiResultDetected ? AmsiVerdict.Detected : AmsiVerdict.Clean, result);

    private IntPtr EnsureContext()
    {
        if (_context != IntPtr.Zero)
        {
            return _context;
        }
        lock (_gate)
        {
            if (_context != IntPtr.Zero || _disposed || _initTried)
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
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }
        _disposed = true;
        lock (_gate)
        {
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
