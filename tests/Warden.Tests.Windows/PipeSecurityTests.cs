using System.IO.Pipes;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using Warden.Ipc;

namespace Warden.Tests.Windows;

/// <summary>
/// The two named pipes are the trust boundary between the LocalSystem service and the user session. These
/// tests pin the properties that keep that boundary honest: bounded frames, default-deny authorization,
/// the Administrators check resolved <b>after</b> the first read (so it actually works), a non-admin
/// <c>Allow</c> being downgraded, and the server DACL admitting the creating user.
/// </summary>
public sealed class PipeSecurityTests
{
    private static bool ThisProcessIsElevated()
    {
        using var id = WindowsIdentity.GetCurrent();
        return new WindowsPrincipal(id).IsInRole(WindowsBuiltInRole.Administrator);
    }

    private static PipeServerOptions TestOptions()
    {
        var o = new PipeServerOptions
        {
            PromptPipeName = "WardenTest.Prompt." + Guid.NewGuid().ToString("N"),
            MgmtPipeName = "WardenTest.Mgmt." + Guid.NewGuid().ToString("N"),
            RetryBackoff = TimeSpan.FromMilliseconds(50),
            IdleTimeout = TimeSpan.FromSeconds(30),
        };
        o.AllowedClientImageNames.Clear(); // the test host is not Warden.Ui.exe
        return o;
    }

    // ---- BoundedLineReader --------------------------------------------------------------------------

    [Fact]
    public async Task Bounded_reader_returns_lines_and_strips_cr()
    {
        var ms = new MemoryStream(Encoding.UTF8.GetBytes("one\r\ntwo\nthree"));
        var reader = new BoundedLineReader(ms, 1024);
        Assert.Equal("one", await reader.ReadLineAsync(CancellationToken.None));
        Assert.Equal("two", await reader.ReadLineAsync(CancellationToken.None));
        Assert.Equal("three", await reader.ReadLineAsync(CancellationToken.None));
        Assert.Null(await reader.ReadLineAsync(CancellationToken.None));
    }

    [Fact]
    public async Task Bounded_reader_throws_on_oversized_frame_instead_of_growing()
    {
        var ms = new MemoryStream(Encoding.UTF8.GetBytes(new string('x', 5000) + "\n"));
        var reader = new BoundedLineReader(ms, 1024);
        await Assert.ThrowsAsync<IpcFrameTooLargeException>(() => reader.ReadLineAsync(CancellationToken.None));
    }

    [Fact]
    public async Task Bounded_reader_handles_lines_split_across_chunks()
    {
        // 40 KiB line crosses several 16 KiB read chunks; must reassemble exactly.
        string big = new string('y', 40_000);
        var ms = new MemoryStream(Encoding.UTF8.GetBytes(big + "\nz\n"));
        var reader = new BoundedLineReader(ms, 64 * 1024);
        Assert.Equal(big, await reader.ReadLineAsync(CancellationToken.None));
        Assert.Equal("z", await reader.ReadLineAsync(CancellationToken.None));
    }

    // ---- authorization model ------------------------------------------------------------------------

    [Fact]
    public void Authorization_is_default_deny_for_unknown_operations()
    {
        Assert.True(MgmtOperations.IsMutation("quarantine.restore"));   // not listed anywhere → mutation
        Assert.True(MgmtOperations.IsMutation("Whitelist.List"));       // case-sensitive: not a read
        Assert.False(MgmtOperations.IsMutation(MgmtOperations.WhitelistList));
        Assert.False(MgmtOperations.IsMutation(MgmtOperations.WhoAmI));
        foreach (string m in MgmtOperations.Mutations)
        {
            Assert.True(MgmtOperations.IsMutation(m));
            Assert.False(MgmtOperations.IsRead(m));
        }
    }

    // ---- management pipe end-to-end -----------------------------------------------------------------

    private sealed class RecordingHandler : IMgmtHandler
    {
        public List<(string Op, bool Admin)> Calls { get; } = new();

        public Task<MgmtResponse> HandleAsync(MgmtRequest request, bool callerIsAdmin, CancellationToken cancellationToken)
        {
            Calls.Add((request.Operation, callerIsAdmin));
            return Task.FromResult(request.Operation == "boom"
                ? throw new InvalidOperationException("SQLite Error 5: 'database is locked' at C:\\secret\\path")
                : MgmtResponse.Success(request.RequestId, "[]"));
        }
    }

    [Fact]
    public async Task Whoami_reflects_the_impersonated_token_and_the_check_works_after_first_read()
    {
        PipeServerOptions options = TestOptions();
        var handler = new RecordingHandler();
        var errors = new List<Exception>();
        using var server = new MgmtPipeServer(handler, errors.Add, options);
        server.Start();

        using var client = new MgmtPipeClient(options.MgmtPipeName);
        bool isAdmin = await client.IsAdministratorAsync();

        // The server impersonates the client AFTER reading the first frame; that is what makes this
        // equal to the process's own elevation state instead of a spurious "false" from
        // ERROR_CANNOT_IMPERSONATE. If impersonation had failed, an elevated test run would see false here.
        Assert.Equal(ThisProcessIsElevated(), isAdmin);
        Assert.DoesNotContain(errors, e => e.Message.Contains("impersonate", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task Mutation_is_refused_for_non_admin_and_never_reaches_the_handler()
    {
        if (ThisProcessIsElevated())
        {
            return; // this scenario needs a filtered token; covered by the elevated variant below
        }

        PipeServerOptions options = TestOptions();
        var handler = new RecordingHandler();
        using var server = new MgmtPipeServer(handler, null, options);
        server.Start();

        using var client = new MgmtPipeClient(options.MgmtPipeName);
        var ex = await Assert.ThrowsAsync<MgmtException>(() => client.InvokeAsync(MgmtOperations.WhitelistAdd, new { Sha256 = "AA" }));
        Assert.Equal(MgmtProtocol.ElevationRequired, ex.Message);
        Assert.DoesNotContain(handler.Calls, c => c.Op == MgmtOperations.WhitelistAdd);

        // Reads still work for the same (non-elevated, same-user) connection.
        IReadOnlyList<object> rows = await client.ListAsync<object>(MgmtOperations.RulesList);
        Assert.Empty(rows);
        Assert.Contains(handler.Calls, c => c.Op == MgmtOperations.RulesList && !c.Admin);
    }

    [Fact]
    public async Task Mutation_reaches_the_handler_when_the_caller_is_elevated()
    {
        if (!ThisProcessIsElevated())
        {
            return; // covered by the non-elevated variant above
        }

        PipeServerOptions options = TestOptions();
        var handler = new RecordingHandler();
        using var server = new MgmtPipeServer(handler, null, options);
        server.Start();

        using var client = new MgmtPipeClient(options.MgmtPipeName);
        await client.InvokeAsync(MgmtOperations.RulesDelete, new IdPayload(1));
        Assert.Contains(handler.Calls, c => c.Op == MgmtOperations.RulesDelete && c.Admin);
    }

    [Fact]
    public async Task Handler_exceptions_are_not_leaked_to_the_client()
    {
        PipeServerOptions options = TestOptions();
        var handler = new RecordingHandler();
        var errors = new List<Exception>();
        using var server = new MgmtPipeServer(handler, errors.Add, options);
        server.Start();

        using var client = new MgmtPipeClient(options.MgmtPipeName);
        // "boom" is not a read → needs admin; if we're not elevated we get ElevationRequired (fine).
        // If we are elevated the handler throws and the client must see a generic message only.
        MgmtException ex = await Assert.ThrowsAsync<MgmtException>(() => client.InvokeAsync("boom", null));
        Assert.DoesNotContain("secret", ex.Message, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("SQLite", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Oversized_frame_drops_the_connection_and_the_server_survives()
    {
        PipeServerOptions options = TestOptions();
        options.MaxFrameBytes = 2048;
        var handler = new RecordingHandler();
        var security = new List<string>();
        using var server = new MgmtPipeServer(handler, null, options, security.Add);
        server.Start();

        // Raw client that streams 10 KB with no newline.
        using (var raw = new NamedPipeClientStream(".", options.MgmtPipeName, PipeDirection.InOut, PipeOptions.Asynchronous, TokenImpersonationLevel.Identification))
        {
            await raw.ConnectAsync(5000);
            byte[] junk = Encoding.ASCII.GetBytes(new string('j', 10_000));
            try
            {
                await raw.WriteAsync(junk);
                await raw.FlushAsync();
                // Server should close on us; a subsequent read returns 0 or throws.
                var buf = new byte[16];
                using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
                int n = await raw.ReadAsync(buf, cts.Token);
                Assert.Equal(0, n);
            }
            catch (IOException)
            {
                // pipe broken by the server: expected
            }
        }

        // The server is still alive for a well-behaved client.
        using var client = new MgmtPipeClient(options.MgmtPipeName);
        Assert.Empty(await client.ListAsync<object>(MgmtOperations.RulesList));
        Assert.Contains(security, s => s.Contains("oversized", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task Peer_image_allow_list_rejects_this_test_host_when_configured()
    {
        PipeServerOptions options = TestOptions();
        options.AllowedClientImageNames.Add("Warden.Ui.exe"); // we are testhost.exe / dotnet.exe
        var handler = new RecordingHandler();
        var security = new List<string>();
        using var server = new MgmtPipeServer(handler, null, options, security.Add);
        server.Start();

        using var client = new MgmtPipeClient(options.MgmtPipeName);
        await Assert.ThrowsAsync<MgmtException>(() => client.ListAsync<object>(MgmtOperations.RulesList));
        Assert.Contains(security, s => s.Contains("Rejected management-pipe client", StringComparison.Ordinal));
        Assert.Empty(handler.Calls);
    }

    // ---- prompt pipe end-to-end ---------------------------------------------------------------------

    private static PromptRequest Prompt(int autoDismissSeconds = 5) => new(
        RequestId: Guid.NewGuid(),
        Sha256: new string('A', 64),
        ImagePath: @"C:\x\evil.exe",
        FileName: "evil.exe",
        CommandLine: "evil.exe",
        ParentPath: @"C:\Windows\explorer.exe",
        SignerSummary: "unsigned",
        MotwZone: 3,
        Reason: "test",
        BlockMode: "enforce",
        MlScore: null,
        LlmVerdict: null,
        Timestamp: DateTimeOffset.UtcNow,
        AutoDismissSeconds: autoDismissSeconds);

    /// <summary>Connects as a raw client and answers every request with the given decision.</summary>
    private static async Task<NamedPipeClientStream> AnsweringClientAsync(string pipeName, PromptDecision decision, CancellationToken ct)
    {
        var pipe = new NamedPipeClientStream(".", pipeName, PipeDirection.InOut, PipeOptions.Asynchronous, TokenImpersonationLevel.Identification);
        await pipe.ConnectAsync(5000, ct);
        _ = Task.Run(async () =>
        {
            var reader = new BoundedLineReader(pipe);
            while (!ct.IsCancellationRequested)
            {
                string? line = await reader.ReadLineAsync(ct);
                if (line is null) { return; }
                PromptRequest? req = JsonSerializer.Deserialize<PromptRequest>(line, IpcProtocol.Json);
                if (req is null) { continue; }
                byte[] reply = JsonSerializer.SerializeToUtf8Bytes(new PromptResponse(req.RequestId, decision), IpcProtocol.Json);
                await pipe.WriteAsync(reply, ct);
                await pipe.WriteAsync(new[] { (byte)'\n' }, ct);
                await pipe.FlushAsync(ct);
            }
        }, ct);
        return pipe;
    }

    [Fact]
    public async Task Allow_from_a_client_is_honoured_only_when_the_client_is_an_administrator()
    {
        PipeServerOptions options = TestOptions();
        options.RequireAdministratorForAllow = true;      // the property under test
        var security = new List<string>();
        using var server = new PromptPipeServer(null, options, security.Add);
        server.Start();

        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        using NamedPipeClientStream client = await AnsweringClientAsync(options.PromptPipeName, PromptDecision.Allow, cts.Token);
        await WaitUntil(() => server.IsClientConnected, cts.Token);

        PromptResponse r = await server.PromptAsync(Prompt(), cts.Token);

        if (ThisProcessIsElevated())
        {
            Assert.Equal(PromptDecision.Allow, r.Decision);
        }
        else
        {
            // Downgraded: the block stands and, being "unanswered", is not persisted as a permanent Block.
            Assert.Equal(PromptDecision.Timeout, r.Decision);
            Assert.Contains(security, s => s.Contains("non-Administrator", StringComparison.Ordinal));
        }
    }

    [Fact]
    public async Task Quarantine_and_keep_blocked_answers_do_not_need_elevation()
    {
        PipeServerOptions options = TestOptions();
        using var server = new PromptPipeServer(null, options);
        server.Start();

        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        using NamedPipeClientStream client = await AnsweringClientAsync(options.PromptPipeName, PromptDecision.Quarantine, cts.Token);
        await WaitUntil(() => server.IsClientConnected, cts.Token);

        PromptResponse r = await server.PromptAsync(Prompt(), cts.Token);
        Assert.Equal(PromptDecision.Quarantine, r.Decision);
    }

    [Fact]
    public async Task No_client_means_unanswered_immediately_which_keeps_the_block_without_persisting_it()
    {
        PipeServerOptions options = TestOptions();
        using var server = new PromptPipeServer(null, options);
        server.Start();

        PromptResponse r = await server.PromptAsync(Prompt(), CancellationToken.None);
        Assert.Equal(PromptDecision.Timeout, r.Decision);
    }

    [Fact]
    public async Task Server_pipe_owner_passes_the_client_side_legitimacy_check()
    {
        PipeServerOptions options = TestOptions();
        using var server = new PromptPipeServer(null, options);
        server.Start();

        using var pipe = new NamedPipeClientStream(".", options.PromptPipeName, PipeDirection.InOut, PipeOptions.Asynchronous, TokenImpersonationLevel.Identification);
        await pipe.ConnectAsync(5000);
        Assert.True(PipeGuard.ServerLooksLegitimate(pipe));
    }

    private static async Task WaitUntil(Func<bool> condition, CancellationToken ct)
    {
        while (!condition())
        {
            ct.ThrowIfCancellationRequested();
            await Task.Delay(20, ct);
        }
    }
}
