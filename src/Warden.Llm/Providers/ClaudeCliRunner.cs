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
/// <remarks>
/// <para><b>Absolute path only.</b> The executable is never resolved through PATH (a LocalSystem service with
/// a user-writable PATH entry would be SYSTEM code execution).</para>
/// <para><b>Contained child.</b> The service's own secrets (<c>WARDEN_*</c>, <c>ANTHROPIC_*</c>,
/// <c>CLAUDE_CODE_*</c>) are removed from the child environment, the working directory is a fixed
/// SYSTEM-owned location (Claude Code treats the CWD as its project root — it must never be an
/// attacker-influenced folder), and captured output is capped.</para>
/// </remarks>
public sealed class ClaudeCliRunner : IClaudeCliRunner
{
    /// <summary>Per-stream capture cap.</summary>
    public const int MaxCapturedChars = 1024 * 1024;

    private static readonly string[] ScrubbedEnvironmentPrefixes = { "WARDEN_", "ANTHROPIC_", "CLAUDE_CODE_" };

    public async Task<ClaudeCliResult> RunAsync(
        string executablePath,
        IReadOnlyList<string> arguments,
        string stdin,
        TimeSpan timeout,
        CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(executablePath) || !Path.IsPathRooted(executablePath))
        {
            return new ClaudeCliResult(false, -1, string.Empty, "The claude CLI must be configured with an absolute path.");
        }

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
            WorkingDirectory = Environment.SystemDirectory,
        };
        foreach (string arg in arguments)
        {
            psi.ArgumentList.Add(arg);
        }
        foreach (string key in psi.Environment.Keys.ToList())
        {
            if (ScrubbedEnvironmentPrefixes.Any(p => key.StartsWith(p, StringComparison.OrdinalIgnoreCase)))
            {
                psi.Environment.Remove(key);
            }
        }

        using var process = new Process { StartInfo = psi };
        var stdout = new StringBuilder();
        var stderr = new StringBuilder();
        using var outDone = new SemaphoreSlim(0, 1);
        using var errDone = new SemaphoreSlim(0, 1);

        process.OutputDataReceived += (_, e) =>
        {
            if (e.Data is null) { outDone.Release(); } else { Append(stdout, e.Data); }
        };
        process.ErrorDataReceived += (_, e) =>
        {
            if (e.Data is null) { errDone.Release(); } else { Append(stderr, e.Data); }
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

    private static void Append(StringBuilder sb, string line)
    {
        lock (sb)
        {
            if (sb.Length >= MaxCapturedChars)
            {
                return;
            }
            int room = MaxCapturedChars - sb.Length;
            sb.AppendLine(line.Length > room ? line[..room] : line);
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
