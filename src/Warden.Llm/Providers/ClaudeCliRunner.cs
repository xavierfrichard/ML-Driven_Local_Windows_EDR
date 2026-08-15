using System.Diagnostics;
using System.Text;

namespace Warden.Llm.Providers;

/// <summary>The captured outcome of one <c>claude</c> CLI invocation.</summary>
/// <param name="Started">False when the process could not be launched (e.g. the CLI is not installed).</param>
/// <param name="ExitCode">Process exit code, or -1 when it never started or was killed on timeout.</param>
/// <param name="Stdout">Full standard output (the JSON envelope, on success).</param>
/// <param name="Stderr">Full standard error (diagnostics / auth failures).</param>
public readonly record struct ClaudeCliResult(bool Started, int ExitCode, string Stdout, string Stderr);

/// <summary>
/// Runs the headless <c>claude</c> CLI. Abstracted behind an interface so the provider can be unit-tested
/// with a fake that returns a canned envelope, without spawning a real process.
/// </summary>
public interface IClaudeCliRunner
{
    /// <summary>
    /// Launch the CLI with <paramref name="arguments"/>, write <paramref name="stdin"/> to its standard
    /// input, and return the captured result. Never throws for an ordinary process failure — a launch
    /// failure surfaces as <see cref="ClaudeCliResult.Started"/> = false so the provider fails safe.
    /// </summary>
    Task<ClaudeCliResult> RunAsync(
        string executablePath,
        IReadOnlyList<string> arguments,
        string stdin,
        TimeSpan timeout,
        CancellationToken cancellationToken);
}

/// <summary>Process-backed <see cref="IClaudeCliRunner"/>. Passes arguments via the argument list (no shell),
/// so a dossier value can never be interpreted as a command.</summary>
public sealed class ClaudeCliRunner : IClaudeCliRunner
{
    public async Task<ClaudeCliResult> RunAsync(
        string executablePath,
        IReadOnlyList<string> arguments,
        string stdin,
        TimeSpan timeout,
        CancellationToken cancellationToken)
    {
        var psi = new ProcessStartInfo
        {
            FileName = executablePath,
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true,
            StandardOutputEncoding = Encoding.UTF8,
            StandardErrorEncoding = Encoding.UTF8,
        };
        foreach (string arg in arguments)
        {
            psi.ArgumentList.Add(arg);
        }

        using var process = new Process { StartInfo = psi };
        var stdout = new StringBuilder();
        var stderr = new StringBuilder();
        using var outDone = new SemaphoreSlim(0, 1);
        using var errDone = new SemaphoreSlim(0, 1);

        process.OutputDataReceived += (_, e) =>
        {
            if (e.Data is null) { outDone.Release(); } else { stdout.AppendLine(e.Data); }
        };
        process.ErrorDataReceived += (_, e) =>
        {
            if (e.Data is null) { errDone.Release(); } else { stderr.AppendLine(e.Data); }
        };

        try
        {
            if (!process.Start())
            {
                return new ClaudeCliResult(false, -1, string.Empty, "Process.Start returned false.");
            }
        }
        catch (Exception ex)
        {
            // File-not-found (CLI not installed), access denied, etc. Fail safe, not throw.
            return new ClaudeCliResult(false, -1, string.Empty, ex.Message);
        }

        process.BeginOutputReadLine();
        process.BeginErrorReadLine();

        using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        cts.CancelAfter(timeout);

        try
        {
            await process.StandardInput.WriteAsync(stdin.AsMemory(), cts.Token).ConfigureAwait(false);
            process.StandardInput.Close();

            await process.WaitForExitAsync(cts.Token).ConfigureAwait(false);
            // Drain the async readers so buffered output is not lost after exit.
            await outDone.WaitAsync(TimeSpan.FromSeconds(2), CancellationToken.None).ConfigureAwait(false);
            await errDone.WaitAsync(TimeSpan.FromSeconds(2), CancellationToken.None).ConfigureAwait(false);

            return new ClaudeCliResult(true, process.ExitCode, stdout.ToString(), stderr.ToString());
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            TryKill(process);
            throw; // caller asked to cancel — propagate
        }
        catch (OperationCanceledException)
        {
            // Our own timeout fired.
            TryKill(process);
            return new ClaudeCliResult(false, -1, stdout.ToString(), "claude CLI timed out.");
        }
        catch (Exception ex)
        {
            TryKill(process);
            return new ClaudeCliResult(false, -1, stdout.ToString(), ex.Message);
        }
    }

    private static void TryKill(Process process)
    {
        try
        {
            if (!process.HasExited)
            {
                process.Kill(entireProcessTree: true);
            }
        }
        catch
        {
            // best-effort cleanup
        }
    }
}
