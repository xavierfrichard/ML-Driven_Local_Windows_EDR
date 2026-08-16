using System.Diagnostics;
using System.Text;

namespace Warden.Wdac;

/// <summary>Result of running a child process.</summary>
public sealed record ProcessResult(int ExitCode, string StdOut, string StdErr)
{
    public bool Ok => ExitCode == 0;
}

/// <summary>
/// Runs child processes (CiTool.exe, powershell.exe) and captures their output. PowerShell is invoked
/// via <c>-EncodedCommand</c> (base64 UTF-16LE): this avoids all shell-quoting issues AND the machine's
/// GPO block on running <c>.ps1</c> files, since an encoded command is not a script file.
/// </summary>
/// <remarks>
/// <para><b>No PATH resolution.</b> This runs as LocalSystem, so executables are launched by absolute
/// path only (<see cref="PowerShellPath"/> is the System32 Windows PowerShell). A bare name would be
/// resolved through the PATH search order, where a user-writable directory means SYSTEM code execution.</para>
/// <para><b>Bounded output.</b> stdout/stderr capture is capped (<see cref="MaxCapturedChars"/>) so a chatty
/// or hostile child cannot grow the service's memory without limit.</para>
/// </remarks>
public sealed class ProcessRunner
{
    /// <summary>Windows PowerShell 5.1, pinned to the System32 copy (not on the System32 root, so PATH would otherwise be consulted).</summary>
    public static readonly string PowerShellPath =
        Path.Combine(Environment.SystemDirectory, "WindowsPowerShell", "v1.0", "powershell.exe");

    /// <summary>Per-stream capture cap.</summary>
    public const int MaxCapturedChars = 1024 * 1024;

    public async Task<ProcessResult> RunAsync(
        string fileName,
        string arguments,
        TimeSpan timeout,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(fileName);
        if (!Path.IsPathRooted(fileName))
        {
            throw new ArgumentException($"Executables must be launched by absolute path (got '{fileName}').", nameof(fileName));
        }

        var psi = new ProcessStartInfo(fileName, arguments)
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true,
            WorkingDirectory = Environment.SystemDirectory,
        };

        using var process = new Process { StartInfo = psi };
        var stdout = new StringBuilder();
        var stderr = new StringBuilder();
        process.OutputDataReceived += (_, e) => Append(stdout, e.Data);
        process.ErrorDataReceived += (_, e) => Append(stderr, e.Data);

        process.Start();
        process.BeginOutputReadLine();
        process.BeginErrorReadLine();

        using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        cts.CancelAfter(timeout);
        try
        {
            await process.WaitForExitAsync(cts.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            TryKill(process);
            return new ProcessResult(-1, stdout.ToString(), $"Timed out after {timeout}.");
        }
        catch (OperationCanceledException)
        {
            TryKill(process);
            throw;
        }

        return new ProcessResult(process.ExitCode, stdout.ToString(), stderr.ToString());
    }

    /// <summary>Runs a PowerShell script via -EncodedCommand (no script file, no quoting, no exec-policy block).</summary>
    public Task<ProcessResult> RunPowerShellAsync(string script, TimeSpan timeout, CancellationToken cancellationToken = default)
    {
        string encoded = Convert.ToBase64String(Encoding.Unicode.GetBytes(script));
        return RunAsync(
            PowerShellPath,
            $"-NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand {encoded}",
            timeout,
            cancellationToken);
    }

    private static void Append(StringBuilder sb, string? line)
    {
        if (line is null)
        {
            return;
        }
        lock (sb)
        {
            if (sb.Length >= MaxCapturedChars)
            {
                return; // cap reached: drop further output
            }
            int room = MaxCapturedChars - sb.Length;
            sb.AppendLine(line.Length > room ? line[..room] : line);
        }
    }

    private static void TryKill(Process process)
    {
        try { process.Kill(entireProcessTree: true); }
        catch { /* already gone */ }
    }
}
