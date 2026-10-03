using Microsoft.Extensions.Configuration;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging.Abstractions;
using PrivacyLink.Api;
using PrivacyLink.Contracts;

public sealed class StatisticsPrivacyTests
{
    [Fact]
    public void VisitorTokenIsStableForSameIpAndKeyAcrossUtcDays()
    {
        var now = DateTimeOffset.UtcNow;
        var key = Convert.ToBase64String(Enumerable.Range(0, 32).Select(i => (byte)i).ToArray());
        var configuration = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["Analytics:Key"] = key
        }).Build();
        var recorder = new StatisticsRecorder(configuration, new FixedTimeProvider(now), NullLogger<StatisticsRecorder>.Instance);
        var context = new DefaultHttpContext();
        context.Connection.RemoteIpAddress = System.Net.IPAddress.Parse("::ffff:203.0.113.4");

        var entry = recorder.Event(context, "secret_open");
        var nextDayEntry = new StatisticsRecorder(configuration, new FixedTimeProvider(now.AddDays(1)), NullLogger<StatisticsRecorder>.Instance)
            .Event(context, "secret_open");

        Assert.NotNull(entry.VisitorHash);
        Assert.Equal(32, entry.VisitorHash!.Length);
        Assert.Equal(entry.VisitorHash, nextDayEntry.VisitorHash);
        Assert.NotEqual(entry.Day, nextDayEntry.Day);
        Assert.DoesNotContain("203.0.113.4", Convert.ToHexString(entry.VisitorHash), StringComparison.Ordinal);
    }

    [Fact]
    public void AddressNormalizationCollapsesIpv4MappedIpv6()
    {
        Assert.Equal("203.0.113.4", StatisticsRecorder.Normalize(System.Net.IPAddress.Parse("::ffff:203.0.113.4")));
        Assert.Equal("203.0.113.4", StatisticsRecorder.Normalize(System.Net.IPAddress.Parse("203.0.113.4")));
    }

    [Fact]
    public void VisitorTokenIsDisabledWhenConfiguredAsPasswordPepper()
    {
        var key = Convert.ToBase64String(Enumerable.Range(0, 32).Select(i => (byte)i).ToArray());
        var configuration = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["Analytics:Key"] = key,
            ["Security:PasswordPepper"] = Convert.ToBase64String(Convert.FromBase64String(key).Reverse().ToArray())
        }).Build();
        // A distinct pepper remains valid; only byte-for-byte key reuse is rejected.
        Assert.NotNull(new StatisticsRecorder(configuration, TimeProvider.System, NullLogger<StatisticsRecorder>.Instance)
            .Event(new DefaultHttpContext { Connection = { RemoteIpAddress = System.Net.IPAddress.Parse("203.0.113.4") } }, "secret_open").VisitorHash);

        configuration = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["Analytics:Key"] = key,
            ["Security:PasswordPepper"] = " " + key + " "
        }).Build();
        Assert.Null(new StatisticsRecorder(configuration, TimeProvider.System, NullLogger<StatisticsRecorder>.Instance)
            .Event(new DefaultHttpContext { Connection = { RemoteIpAddress = System.Net.IPAddress.Parse("203.0.113.4") } }, "secret_open").VisitorHash);
    }

    [Theory]
    [InlineData("unique_ips", "", "", true)]
    [InlineData("creation_content_type", "content_type", "both", true)]
    [InlineData("creation_content_type", "content_type", "secret-id", false)]
    [InlineData("unknown_metric", "", "", false)]
    [InlineData("visitor_hmac", "", "", false)]
    public void PublicStatisticsAllowlistExposesOnlyKnownAggregateRows(string metric, string dimension, string value, bool expected)
    {
        var row = new DailyStatisticResponse(new DateOnly(2026, 9, 30), metric, dimension, value, 1, 0);
        Assert.Equal(expected, StatisticsRecorder.IsPublicStatistic(row));
    }

    private sealed class FixedTimeProvider(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => now;
    }
}
