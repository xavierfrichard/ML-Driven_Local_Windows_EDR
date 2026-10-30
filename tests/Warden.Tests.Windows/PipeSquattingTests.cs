using System.ComponentModel;
using System.IO.Pipes;
using System.Security.Principal;
using Warden.Ipc;

namespace Warden.Tests.Windows;

/// <summary>
/// Audit finding M3 (pipe squatting) and the IPC lows: the client only trusts a SYSTEM-owned pipe hosted by
/// the service process, the servers never leave the pipe names free, the peer check uses the full image
/// path, and security events are rate-limited.
/// </summary>
public sealed class PipeSquattingTests
{
    private static readonly SecurityIdentifier SystemSid = new(WellKnownSidType.LocalSystemSid, null);
    private static readonly SecurityIdentifier AdministratorsSid = new(WellKnownSidType.BuiltinAdministratorsSid, null);
    private static readonly SecurityIdentifier OtherUserSid = new("S-1-5-21-1111111111-2222222222-3333333333-1001");

    /// <summary>The servers here run in the test process as this user, so clients use the dev-run trust.</summary>
    private static readonly PipeServerTrust DevTrust = new() { AllowCurrentUserOwner = true };

    private static SecurityIdentifier CurrentUser()
    {
        using WindowsIdentity self = WindowsIdentity.GetCurrent();
        return self.User!;
    }

    private static PipeServerOptions TestOptions(TimeSpan? retryBackoff = null)
    {
        var o = new PipeServerOptions
        {
            PromptPipeName = "WardenTest.Prompt." + Guid.NewGuid().ToString("N"),
            MgmtPipeName = "WardenTest.Mgmt." + Guid.NewGuid().ToString("N"),
            RetryBackoff = retryBackoff ?? TimeSpan.FromMilliseconds(50),
            IdleTimeout = TimeSpan.FromSeconds(30),
            DevUiImageName = null,
        };
        o.AllowedClientImagePaths.Clear(); // the test host is not the installed UI
        return o;
    }

    private static NamedPipeClientStream Client(string pipeName) =>
        new(".", pipeName, PipeDirection.InOut, PipeOptions.Asynchronous, TokenImpersonationLevel.Identification);

    /// <summary>A same-user process trying to grab the name: succeeds only if no instance of it exists.</summary>
    private static bool SquatSucceeds(string pipeName)
    {
        try
        {
            using var squatter = new NamedPipeServerStream(
                pipeName, PipeDirection.InOut, 1, PipeTransmissionMode.Byte,
                PipeOptions.Asynchronous | PipeOptions.FirstPipeInstance);
            return true;
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or IOException)
        {
            return false;
        }
    }

    private static async Task WaitUntil(Func<bool> condition, CancellationToken ct)
    {
        while (!condition())
        {
            ct.ThrowIfCancellationRequested();
            await Task.Delay(20, ct);
        }
    }

    private sealed class ListHandler : IMgmtHandler
    {
        public Task<MgmtResponse> HandleAsync(MgmtRequest request, bool callerIsAdmin, CancellationToken cancellationToken) =>
            Task.FromResult(MgmtResponse.Success(request.RequestId, "[]"));
    }

    private sealed class ConcurrentLog
    {
        private readonly List<string> _items = new();

        public void Add(string s)
        {
            lock (_items) { _items.Add(s); }
        }

        public List<string> Snapshot()
        {
            lock (_items) { return new List<string>(_items); }
        }
    }

    // ---- client side: who may host the pipe --------------------------------------------------------

    [Fact]
    public async Task Given_a_pipe_owned_by_the_current_user_When_checked_in_production_mode_Then_it_is_rejected()
    {
        PipeServerOptions options = TestOptions();
        using var server = new PromptPipeServer(null, options);
        server.Start();

        using NamedPipeClientStream pipe = Client(options.PromptPipeName);
        await pipe.ConnectAsync(5000);

        // The server set its own account as owner explicitly; for the test host that is this user.
        Assert.Equal(CurrentUser(), pipe.GetAccessControl().GetOwner(typeof(SecurityIdentifier)));

        Assert.False(PipeGuard.ServerLooksLegitimate(pipe, PipeServerTrust.Production));
        if (!PipeGuard.DevModeEnabled)
        {
            // The default policy the UI uses is production unless a Debug build runs with WARDEN_DEV_PIPES=1.
            Assert.False(PipeGuard.ServerLooksLegitimate(pipe));
        }
    }

    [Fact]
    public async Task Given_a_management_pipe_owned_by_the_current_user_When_the_default_client_connects_Then_it_refuses_to_talk()
    {
        if (PipeGuard.DevModeEnabled)
        {
            return; // a Debug dev run with WARDEN_DEV_PIPES=1 trusts this user's pipes on purpose
        }

        PipeServerOptions options = TestOptions();
        var handler = new CountingHandler();
        using var server = new MgmtPipeServer(handler, null, options);
        server.Start();

        using var client = new MgmtPipeClient(options.MgmtPipeName);
        MgmtException ex = await Assert.ThrowsAsync<MgmtException>(() => client.ListAsync<object>(MgmtOperations.RulesList));
        Assert.Contains("not owned by the Warden service", ex.Message, StringComparison.Ordinal);
        Assert.Equal(0, handler.Calls);
    }

    private sealed class CountingHandler : IMgmtHandler
    {
        public int Calls { get; private set; }

        public Task<MgmtResponse> HandleAsync(MgmtRequest request, bool callerIsAdmin, CancellationToken cancellationToken)
        {
            Calls++;
            return Task.FromResult(MgmtResponse.Success(request.RequestId, "[]"));
        }
    }

    [Fact]
    public async Task Given_a_pipe_owned_by_the_current_user_When_checked_with_the_dev_switch_Then_it_passes()
    {
        PipeServerOptions options = TestOptions();
        using var server = new PromptPipeServer(null, options);
        server.Start();

        using NamedPipeClientStream pipe = Client(options.PromptPipeName);
        await pipe.ConnectAsync(5000);

        Assert.True(PipeGuard.ServerLooksLegitimate(pipe, new PipeServerTrust { AllowCurrentUserOwner = true }));
    }

    [Theory]
    [InlineData(ServiceProcessState.NotInstalled, 0, 1234, true)]
    [InlineData(ServiceProcessState.Running, 1234, 1234, true)]
    [InlineData(ServiceProcessState.Running, 1234, 5678, false)]
    [InlineData(ServiceProcessState.Running, 1234, 0, false)]
    [InlineData(ServiceProcessState.NotRunning, 0, 1234, false)]
    [InlineData(ServiceProcessState.QueryFailed, 0, 1234, false)]
    public void Given_a_system_owned_pipe_When_the_server_pid_is_compared_with_the_service_Then_only_the_service_process_passes(
        ServiceProcessState state, int servicePid, int serverPid, bool expected)
    {
        var trust = new PipeServerTrust { QueryServiceProcess = () => new ServiceProcessInfo(state, servicePid) };
        Assert.Equal(expected, PipeGuard.EvaluateServer(SystemSid, CurrentUser(), serverPid, trust));
    }

    [Fact]
    public void Given_the_service_lookup_throws_When_a_system_owned_pipe_is_checked_Then_it_fails_closed()
    {
        var trust = new PipeServerTrust { QueryServiceProcess = () => throw new Win32Exception(5) };
        Assert.False(PipeGuard.EvaluateServer(SystemSid, CurrentUser(), 1234, trust));
    }

    [Fact]
    public void Given_an_owner_other_than_system_When_checked_in_production_mode_Then_it_is_rejected()
    {
        int lookups = 0;
        var production = new PipeServerTrust
        {
            QueryServiceProcess = () => { lookups++; return new ServiceProcessInfo(ServiceProcessState.NotInstalled, 0); },
        };

        Assert.False(PipeGuard.EvaluateServer(CurrentUser(), CurrentUser(), 1234, production));
        Assert.False(PipeGuard.EvaluateServer(AdministratorsSid, CurrentUser(), 1234, production));
        Assert.False(PipeGuard.EvaluateServer(OtherUserSid, CurrentUser(), 1234, production));
        Assert.Equal(0, lookups);
    }

    [Fact]
    public void Given_the_dev_switch_When_another_users_pipe_is_checked_Then_it_is_still_rejected()
    {
        var dev = new PipeServerTrust { AllowCurrentUserOwner = true };
        Assert.True(PipeGuard.EvaluateServer(CurrentUser(), CurrentUser(), 1234, dev));
        Assert.False(PipeGuard.EvaluateServer(OtherUserSid, CurrentUser(), 1234, dev));
        Assert.False(PipeGuard.EvaluateServer(AdministratorsSid, CurrentUser(), 1234, dev));
        Assert.False(PipeGuard.EvaluateServer(CurrentUser(), null, 1234, dev));
    }

    [Fact]
    public void Given_a_service_name_that_does_not_exist_When_the_scm_is_queried_Then_it_reports_not_installed()
    {
        ServiceProcessInfo info = PipeGuard.QueryServiceProcess("WardenTest.NoSuchService." + Guid.NewGuid().ToString("N"));
        Assert.Equal(ServiceProcessState.NotInstalled, info.State);
        Assert.Equal(0, info.ProcessId);
    }

    [Fact]
    public void Given_a_release_build_or_no_switch_When_the_default_policy_is_read_Then_it_matches_dev_mode()
    {
        Assert.Equal(PipeGuard.DevModeEnabled, PipeServerTrust.Default.AllowCurrentUserOwner);
        Assert.False(PipeServerTrust.Production.AllowCurrentUserOwner);
        Assert.Equal(PipeGuard.DevModeEnabled, new PipeServerOptions().DevUiImageName is not null);
    }

    // ---- servers: the name is never free ------------------------------------------------------------

    [Fact]
    public async Task Given_a_connected_prompt_client_When_clients_reconnect_Then_a_listening_instance_always_holds_the_name()
    {
        PipeServerOptions options = TestOptions();
        using var server = new PromptPipeServer(null, options);
        server.Start();
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));

        await WaitUntil(() => !SquatSucceeds(options.PromptPipeName), cts.Token);

        for (int i = 0; i < 4; i++)
        {
            using (NamedPipeClientStream ui = Client(options.PromptPipeName))
            {
                await ui.ConnectAsync(5000, cts.Token);
                await WaitUntil(() => server.IsClientConnected, cts.Token);

                // While the UI is being served, a second instance is listening: another client gets in at
                // once, and the name cannot be squatted.
                using (NamedPipeClientStream probe = Client(options.PromptPipeName))
                {
                    await probe.ConnectAsync(2000, cts.Token);
                }

                Assert.False(SquatSucceeds(options.PromptPipeName));
            }

            // Right after the disconnect the listener still holds the name.
            Assert.False(SquatSucceeds(options.PromptPipeName));
            await WaitUntil(() => !server.IsClientConnected, cts.Token);
            Assert.False(SquatSucceeds(options.PromptPipeName));
        }

        // The server still serves a UI after all that churn.
        using NamedPipeClientStream last = Client(options.PromptPipeName);
        await last.ConnectAsync(5000, cts.Token);
        await WaitUntil(() => server.IsClientConnected, cts.Token);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task Given_a_rejected_peer_When_the_server_backs_off_Then_the_name_cannot_be_squatted(bool promptChannel)
    {
        // A long back-off: before the fix the name was free for this whole window.
        PipeServerOptions options = TestOptions(retryBackoff: TimeSpan.FromSeconds(3));
        options.AllowedClientImagePaths.Add(@"C:\Program Files\Warden\ui\Warden.Ui.exe"); // not this test host
        var security = new ConcurrentLog();
        string pipeName = promptChannel ? options.PromptPipeName : options.MgmtPipeName;

        using var prompt = promptChannel ? new PromptPipeServer(null, options, security.Add) : null;
        using var mgmt = promptChannel ? null : new MgmtPipeServer(new ListHandler(), null, options, security.Add);
        prompt?.Start();
        mgmt?.Start();

        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        using (NamedPipeClientStream rejected = Client(pipeName))
        {
            await rejected.ConnectAsync(5000, cts.Token);
            await WaitUntil(() => security.Snapshot().Exists(s => s.Contains("Rejected", StringComparison.Ordinal)), cts.Token);
        }

        // The server is now inside its back-off.
        Assert.False(SquatSucceeds(pipeName));
        await Task.Delay(300, cts.Token);
        Assert.False(SquatSucceeds(pipeName));
    }

    [Fact]
    public async Task Given_a_management_client_When_it_reconnects_Then_the_name_stays_held_and_it_is_served_again()
    {
        PipeServerOptions options = TestOptions();
        using var server = new MgmtPipeServer(new ListHandler(), null, options);
        server.Start();

        for (int i = 0; i < 3; i++)
        {
            using (var client = new MgmtPipeClient(options.MgmtPipeName, DevTrust))
            {
                Assert.Empty(await client.ListAsync<object>(MgmtOperations.RulesList));
                Assert.False(SquatSucceeds(options.MgmtPipeName));
            }

            Assert.False(SquatSucceeds(options.MgmtPipeName));
        }
    }

    // ---- rate limit ----------------------------------------------------------------------------------

    [Theory]
    [InlineData(1)]                                                   // our create fails with PIPE_BUSY
    [InlineData(NamedPipeServerStream.MaxAllowedServerInstances)]     // our create fails with ACCESS_DENIED
    public async Task Given_a_squatted_name_When_the_server_retries_Then_one_event_per_interval_is_reported_and_it_recovers(int squatterMaxInstances)
    {
        PipeServerOptions options = TestOptions(retryBackoff: TimeSpan.FromMilliseconds(20));
        var security = new ConcurrentLog();
        var errors = new ConcurrentLog();

        var squatter = new NamedPipeServerStream(
            options.MgmtPipeName, PipeDirection.InOut, squatterMaxInstances, PipeTransmissionMode.Byte,
            PipeOptions.Asynchronous | PipeOptions.FirstPipeInstance);

        using var server = new MgmtPipeServer(new ListHandler(), ex => errors.Add(ex.GetType().Name), options, security.Add);
        server.Start();

        // ~30 retries at 20 ms. Before the fix each one wrote a tamper row (and a capped squatter none).
        await Task.Delay(700);
        List<string> squatEvents = security.Snapshot().FindAll(s => s.Contains("already exists", StringComparison.Ordinal));
        Assert.Single(squatEvents);
        Assert.Single(errors.Snapshot());

        // Once the squatter is gone the server takes the name (first-instance create) and serves clients.
        squatter.Dispose();
        using var client = new MgmtPipeClient(options.MgmtPipeName, DevTrust);
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        while (true)
        {
            try
            {
                Assert.Empty(await client.ListAsync<object>(MgmtOperations.RulesList, cts.Token));
                break;
            }
            catch (MgmtException) when (!cts.IsCancellationRequested)
            {
                await Task.Delay(50, cts.Token);
            }
        }
    }

    private sealed class ManualTime : TimeProvider
    {
        public DateTimeOffset Now { get; set; } = new(2026, 10, 30, 12, 0, 0, TimeSpan.Zero);

        public override DateTimeOffset GetUtcNow() => Now;
    }

    [Fact]
    public void Given_repeated_events_of_one_category_When_filtered_Then_one_per_interval_passes_with_the_suppressed_count()
    {
        var time = new ManualTime();
        var throttle = new SecurityEventThrottle(TimeSpan.FromMinutes(1), time);

        Assert.Equal("squat 1", throttle.Filter("squat", "squat 1"));
        time.Now += TimeSpan.FromSeconds(1);
        Assert.Null(throttle.Filter("squat", "squat 2"));
        time.Now += TimeSpan.FromSeconds(1);
        Assert.Null(throttle.Filter("squat", "squat 3"));

        // Another category has its own budget.
        Assert.Equal("peer 1", throttle.Filter("peer", "peer 1"));

        time.Now += TimeSpan.FromMinutes(1);
        string? next = throttle.Filter("squat", "squat 4");
        Assert.NotNull(next);
        Assert.StartsWith("squat 4", next, StringComparison.Ordinal);
        Assert.Contains("2 more 'squat' event(s) suppressed", next, StringComparison.Ordinal);

        // The count resets after it has been reported.
        time.Now += TimeSpan.FromMinutes(1);
        Assert.Equal("squat 5", throttle.Filter("squat", "squat 5"));
    }

    [Fact]
    public void Given_a_zero_interval_When_filtered_Then_nothing_is_suppressed()
    {
        var throttle = new SecurityEventThrottle(TimeSpan.Zero, new ManualTime());
        Assert.Equal("a", throttle.Filter("c", "a"));
        Assert.Equal("b", throttle.Filter("c", "b"));
    }

    // ---- instance tracking ---------------------------------------------------------------------------

    private sealed class FakeInstance : IDisposable
    {
        public FakeInstance(bool first) => First = first;

        public bool First { get; }

        public int DisposeCount { get; private set; }

        public void Dispose() => DisposeCount++;
    }

    [Fact]
    public void Given_no_instance_held_When_one_is_created_Then_it_must_be_a_first_instance()
    {
        var set = new PipeInstanceSet<FakeInstance>();

        FakeInstance a = set.Create(first => new FakeInstance(first));
        FakeInstance b = set.Create(first => new FakeInstance(first));
        Assert.True(a.First);
        Assert.False(b.First); // a still holds the name

        set.Release(a);
        FakeInstance c = set.Create(first => new FakeInstance(first));
        Assert.False(c.First); // b still holds the name

        set.Release(b);
        set.Release(c);
        Assert.Equal(0, set.Count);

        // Every instance gone: the next one must prove the name is free (the old mgmt server did not).
        FakeInstance d = set.Create(first => new FakeInstance(first));
        Assert.True(d.First);
        Assert.Equal(1, a.DisposeCount);
    }

    [Fact]
    public void Given_a_closed_set_When_creating_Then_it_refuses_and_held_instances_are_disposed()
    {
        var set = new PipeInstanceSet<FakeInstance>();
        FakeInstance a = set.Create(first => new FakeInstance(first));

        set.Close();

        Assert.Equal(1, a.DisposeCount);
        Assert.Throws<ObjectDisposedException>(() => set.Create(first => new FakeInstance(first)));
        set.Release(a); // releasing after close is harmless
    }

    [Fact]
    public void Given_a_factory_that_throws_When_creating_Then_nothing_is_tracked()
    {
        var set = new PipeInstanceSet<FakeInstance>();
        Assert.Throws<UnauthorizedAccessException>(() => set.Create(_ => throw new UnauthorizedAccessException()));
        Assert.Equal(0, set.Count);
        Assert.True(set.Create(first => new FakeInstance(first)).First);
    }

    // ---- peer image check by full path ---------------------------------------------------------------

    private const string InstalledUi = @"C:\Program Files\Warden\ui\Warden.Ui.exe";

    [Theory]
    [InlineData(@"C:\Users\Public\Downloads\Warden.Ui.exe")]   // copy with the right name, wrong folder
    [InlineData(@"C:\Users\Public\evil.exe")]                  // renamed binary
    [InlineData(@"C:\Program Files\Warden\ui\Warden.Ui.exe.bak")]
    [InlineData(@"Warden.Ui.exe")]                             // relative path
    [InlineData(@"\\?\C:\Users\Public\Warden.Ui.exe")]
    public void Given_a_ui_image_outside_the_install_folder_When_the_peer_is_checked_Then_it_is_rejected(string imagePath)
    {
        Assert.False(PipeGuard.PeerImageAllowed(new PipePeer(42, imagePath), new[] { InstalledUi }));
    }

    [Theory]
    [InlineData(@"C:\Program Files\Warden\ui\Warden.Ui.exe")]
    [InlineData(@"c:\program files\warden\UI\WARDEN.UI.EXE")]
    [InlineData(@"C:\Program Files\Warden\service\..\ui\Warden.Ui.exe")]
    public void Given_the_installed_ui_When_the_peer_is_checked_Then_it_is_accepted(string imagePath)
    {
        Assert.True(PipeGuard.PeerImageAllowed(new PipePeer(42, imagePath), new[] { InstalledUi }));
    }

    [Fact]
    public void Given_an_unresolved_peer_When_a_path_list_is_configured_Then_it_is_rejected()
    {
        Assert.False(PipeGuard.PeerImageAllowed(new PipePeer(0, null), new[] { InstalledUi }));
        Assert.False(PipeGuard.PeerImageAllowed(new PipePeer(42, @"C:\x\Warden.Ui.exe"), new[] { "Warden.Ui.exe" }));
    }

    [Fact]
    public void Given_the_service_folder_When_default_ui_paths_are_built_Then_they_point_into_the_install_dir()
    {
        IReadOnlyList<string> paths = PipeGuard.DefaultUiImagePaths(@"C:\Program Files\Warden\service\");
        Assert.Contains(InstalledUi, paths, StringComparer.OrdinalIgnoreCase);
        Assert.Contains(@"C:\Program Files\Warden\service\Warden.Ui.exe", paths, StringComparer.OrdinalIgnoreCase);
        Assert.Equal(2, paths.Count);
    }

    [Fact]
    public void Given_production_options_When_a_renamed_copy_has_the_ui_file_name_Then_only_the_dev_switch_accepts_it()
    {
        var options = new PipeServerOptions { DevUiImageName = null };
        options.AllowedClientImagePaths.Clear();
        options.AllowedClientImagePaths.Add(InstalledUi);
        var copy = new PipePeer(42, @"C:\Users\Public\Downloads\Warden.Ui.exe");

        Assert.False(PipeGuard.PeerAllowed(copy, options));
        Assert.True(PipeGuard.PeerAllowed(new PipePeer(42, InstalledUi), options));

        options.DevUiImageName = PipeGuard.UiImageName; // only ever set by default in a Debug dev run
        Assert.True(PipeGuard.PeerAllowed(copy, options));
    }
}
