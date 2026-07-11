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
public sealed class ProcessRunner
{
    public async Task<ProcessResult> RunAsync(
        string fileName,
        string arguments,
        TimeSpan timeout,
        CancellationToken cancellationToken = default)
    {
        var psi = new ProcessStartInfo(fileName, arguments)
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true,
        };

        using var process = new Process { StartInfo = psi };
        var stdout = new StringBuilder();
        var stderr = new StringBuilder();
        process.OutputDataReceived += (_, e) => { if (e.Data is not null) stdout.AppendLine(e.Data); };
        process.ErrorDataReceived += (_, e) => { if (e.Data is not null) stderr.AppendLine(e.Data); };

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
            "powershell.exe",
            $"-NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand {encoded}",
            timeout,
            cancellationToken);
    }

    private static void TryKill(Process process)
    {
        try { process.Kill(entireProcessTree: true); }
        catch { /* already gone */ }
    }
}
