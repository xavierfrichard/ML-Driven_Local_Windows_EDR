using Warden.Core;
using Warden.Trust;
using Warden.WebApps;

namespace Warden.Tests.Windows;

/// <summary>M6: reads of attacker-controlled data on the decision thread are bounded.</summary>
public sealed class BoundedReadTests : IDisposable
{
    private readonly string _dir;

    public BoundedReadTests()
    {
        _dir = Path.Combine(Path.GetTempPath(), "warden-br-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_dir);
    }

    public void Dispose()
    {
        try { Directory.Delete(_dir, recursive: true); } catch { /* best effort */ }
    }

    private string WithZoneIdentifier(string content)
    {
        string file = Path.Combine(_dir, Guid.NewGuid().ToString("N") + ".exe");
        File.WriteAllText(file, "MZ");
        File.WriteAllText(file + ":Zone.Identifier", content);
        return file;
    }

    [Fact]
    public void Given_a_normal_zone_identifier_When_read_Then_the_zone_is_returned()
    {
        string file = WithZoneIdentifier("[ZoneTransfer]\r\nZoneId=3\r\nReferrerUrl=https://example.invalid/\r\n");

        Assert.Equal(3, new FileInspector().ReadMotwZone(file));
    }

    [Fact]
    public void Given_no_zone_identifier_When_read_Then_no_motw()
    {
        string file = Path.Combine(_dir, "plain.exe");
        File.WriteAllText(file, "MZ");

        Assert.Equal(VerdictContext.NoMotw, new FileInspector().ReadMotwZone(file));
    }

    [Fact]
    public void Given_a_huge_zone_identifier_without_newlines_When_read_Then_it_returns_quickly_as_internet()
    {
        string file = Path.Combine(_dir, "padded.exe");
        File.WriteAllText(file, "MZ");
        using (var ads = new FileStream(file + ":Zone.Identifier", FileMode.Create, FileAccess.Write))
        {
            ads.Write("[ZoneTransfer]\r\n"u8);
            byte[] pad = new byte[1024 * 1024];
            Array.Fill(pad, (byte)'A');
            for (int i = 0; i < 64; i++)
            {
                ads.Write(pad); // 64 MB on one line
            }
            ads.Write("\r\nZoneId=3\r\n"u8);
        }

        long before = GC.GetAllocatedBytesForCurrentThread();
        int zone = new FileInspector().ReadMotwZone(file);
        long allocated = GC.GetAllocatedBytesForCurrentThread() - before;

        Assert.Equal(3, zone);                        // padding cannot hide the download
        Assert.True(allocated < 1024 * 1024, $"allocated {allocated} bytes");
    }

    [Fact]
    public void Given_a_zone_identifier_at_the_limit_When_parsed_Then_only_the_prefix_is_used()
    {
        Assert.Equal(4096, FileInspector.MaxZoneIdentifierBytes);
        Assert.Equal(4, FileInspector.ParseZoneId("[ZoneTransfer]\nZoneId=4\n"));
        Assert.Equal(VerdictContext.NoMotw, FileInspector.ParseZoneId("[Other]\nZoneId=3\n"));
    }

    [Fact]
    public void Given_a_file_over_the_cap_When_read_capped_Then_nothing_is_read()
    {
        string file = Path.Combine(_dir, "big.bin");
        using (var fs = new FileStream(file, FileMode.Create))
        {
            fs.SetLength(WebAppInputCollector.MaxImportScanBytes + 1);
        }

        Assert.Null(WebAppInputCollector.ReadCapped(file, WebAppInputCollector.MaxImportScanBytes));
    }

    [Fact]
    public void Given_a_file_under_the_cap_When_read_capped_Then_all_bytes_are_returned()
    {
        string file = Path.Combine(_dir, "small.bin");
        File.WriteAllBytes(file, new byte[] { 1, 2, 3 });

        Assert.Equal(new byte[] { 1, 2, 3 }, WebAppInputCollector.ReadCapped(file, 3));
        Assert.Null(WebAppInputCollector.ReadCapped(file, 2));
    }

    [Fact]
    public void Given_a_snapshot_When_collecting_web_app_inputs_Then_imports_come_from_the_snapshot()
    {
        string realPe = Path.Combine(Environment.SystemDirectory, "cmd.exe");
        if (!File.Exists(realPe))
        {
            return;
        }
        string snapshot = Path.Combine(_dir, "snapshot.bin");
        File.Copy(realPe, snapshot);
        string appPath = Path.Combine(_dir, "app.exe");
        File.WriteAllText(appPath, "swapped: not a PE any more");

        var collector = new WebAppInputCollector();
        WebAppStaticInput fromOriginal = collector.CollectStatic(appPath);
        WebAppStaticInput fromSnapshot = collector.CollectStatic(appPath, snapshot);

        Assert.Empty(fromOriginal.ImportedModules);
        Assert.NotEmpty(fromSnapshot.ImportedModules);
        Assert.Equal("app.exe", fromSnapshot.ImageName);
    }
}
