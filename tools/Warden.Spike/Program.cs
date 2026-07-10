using System.Text;
using Warden.Core;

namespace Warden.Spike;

/// <summary>
/// Phase 0 spike entry point. Three modes:
/// <list type="bullet">
///   <item><c>--selftest</c> — non-privileged smoke test: prints a sample dossier built from in-memory
///     data. Runs fine as a normal user on the host.</item>
///   <item><c>--watch</c> — the real loop: opens the Kernel-Process ETW session + the CodeIntegrity
///     EventLogWatcher, correlates blocks with process starts, and prints dossiers. Requires admin.</item>
///   <item><c>--help</c> — usage.</item>
/// </list>
/// </summary>
internal static class Program
{
    private static int Main(string[] args)
    {
        TrySetUtf8Console();

        string mode = args.Length > 0 ? args[0].ToLowerInvariant() : "--help";
        return mode switch
        {
            "--selftest" => RunSelfTest(),
            "--watch" => RunWatch(),
            _ => PrintHelp(),
        };
    }

    /// <summary>Builds a fake VerdictContext/dossier from sample data and prints it. No privileged calls.</summary>
    private static int RunSelfTest()
    {
        Console.WriteLine("Warden.Spike --selftest  (no ETW / event-log / file access; runs as non-admin)");
        Console.WriteLine();

        Dossier sample = Dossier.CreateSample();
        sample.Print(Console.Out);

        // Exercise the Warden.Core contract projection so the spike validates the shipped signatures.
        VerdictContext ctx = sample.ToVerdictContext();
        Console.WriteLine();
        Console.WriteLine("Warden.Core.VerdictContext projection (contract check):");
        Console.WriteLine($"  ImageName        = {ctx.ImageName}");
        Console.WriteLine($"  IsFromInternet   = {ctx.IsFromInternet}  (MotwZone={ctx.MotwZone})");
        Console.WriteLine($"  Signer.IsTrusted = {ctx.Signer.IsTrustedSignature}");
        Console.WriteLine($"  Pe (forced)      = IsPE:{ctx.Pe.Value.IsPortableExecutable}");
        Console.WriteLine($"  Chain            = {(ReferenceEquals(ctx.Chain, AttackChainNode.None) ? "None" : ctx.Chain.ImageName)}");
        Console.WriteLine();
        Console.WriteLine("Self-test OK.");
        return 0;
    }

    /// <summary>Live correlation loop. Requires elevation for both the kernel session and the CI channel.</summary>
    private static int RunWatch()
    {
        if (!KernelProcessSession.IsElevated())
        {
            Console.Error.WriteLine("--watch requires Administrator elevation.");
            Console.Error.WriteLine("  * The NT Kernel Logger ETW session needs elevation.");
            Console.Error.WriteLine("  * Reading Microsoft-Windows-CodeIntegrity/Operational needs elevation.");
            Console.Error.WriteLine("Re-launch this console 'As administrator', then run: Warden.Spike --watch");
            Console.Error.WriteLine("(Use --selftest for a non-privileged smoke test.)");
            return 2;
        }

        Console.WriteLine("Warden.Spike --watch : correlating WDAC blocks with process-start telemetry.");
        Console.WriteLine("Channel : Microsoft-Windows-CodeIntegrity/Operational (EventID 3076/3077)");
        Console.WriteLine("ETW     : NT Kernel Logger (process) + Microsoft-Windows-Kernel-Process");
        Console.WriteLine("Press Ctrl+C to stop.");
        Console.WriteLine();

        var correlator = new EventCorrelator(window: TimeSpan.FromSeconds(5));
        correlator.DossierReady += d =>
        {
            Console.WriteLine();
            d.Print(Console.Out);
            Console.WriteLine();
        };

        // Own both sessions in one scope so Ctrl+C tears everything down cleanly.
        using var kernel = new KernelProcessSession();
        using var codeIntegrity = new CodeIntegritySession(replayExisting: true);

        kernel.ProcessStarted += correlator.RecordProcessStart;
        codeIntegrity.BlockObserved += correlator.OnBlock;

        using var stopped = new ManualResetEventSlim(false);
        Console.CancelKeyPress += (_, e) =>
        {
            e.Cancel = true;          // don't hard-kill; unwind gracefully
            Console.WriteLine("Stopping…");
            kernel.Stop();            // unblocks the kernel Process() loop
            stopped.Set();
        };

        try
        {
            codeIntegrity.Start();    // async delivery on watcher threads
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"Failed to start CodeIntegrity watcher: {ex.Message}");
            return 3;
        }

        // Run the (blocking) kernel ETW pump on a dedicated thread; main thread waits for Ctrl+C.
        var pump = new Thread(() =>
        {
            try
            {
                kernel.Process();
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"Kernel ETW session error: {ex.Message}");
                stopped.Set();
            }
        })
        {
            IsBackground = true,
            Name = "warden-etw-pump",
        };
        pump.Start();

        stopped.Wait();
        pump.Join(TimeSpan.FromSeconds(3));
        Console.WriteLine("Stopped.");
        return 0;
    }

    private static int PrintHelp()
    {
        Console.WriteLine(
            """
            Warden.Spike — Phase 0 WDAC block ⇄ process-start correlation spike

            USAGE:
              Warden.Spike --selftest    Print a sample dossier from in-memory data.
                                         No ETW / event-log / file access; runs as a
                                         normal (non-admin) user. Use to smoke-test the host.

              Warden.Spike --watch       Live mode. Opens the NT Kernel Logger process
                                         ETW session and an EventLogWatcher on
                                         Microsoft-Windows-CodeIntegrity/Operational,
                                         correlates 3076/3077 blocks with process starts,
                                         and prints a dossier per block. REQUIRES ADMIN.
                                         Intended to run only inside the isolated VM.

              Warden.Spike --help        This message.

            NOTES:
              * 3076 = audit (would-block): the process runs, so command line + parent are
                recovered from ETW and shown.
              * 3077 = enforce (blocked): the process never runs, so no start event exists;
                the dossier is built from the CI event + on-disk file inspection and the
                process context is marked unavailable.
            """);
        return 0;
    }

    /// <summary>Best-effort switch to UTF-8 so the dossier's box-drawing characters render.</summary>
    private static void TrySetUtf8Console()
    {
        try { Console.OutputEncoding = Encoding.UTF8; }
        catch (IOException) { /* redirected / headless console: ignore */ }
    }
}
