using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using PrivacyLink.Api;
using System.Security.Cryptography;
using System.Text;

public sealed class PrivacyAuditTests
{
    [Fact]
    public void AuditLogContainsOnlyOperationalIdentifiers()
    {
        var provider = new CapturingProvider();
        var key = RandomNumberGenerator.GetBytes(32);
        var configuration = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["Security:AuditHashKey"] = Convert.ToBase64String(key)
        }).Build();
        using var services = new ServiceCollection()
            .AddSingleton<IConfiguration>(configuration)
            .AddLogging(logging => logging.AddProvider(provider))
            .BuildServiceProvider();
        var context = new DefaultHttpContext { RequestServices = services };
        context.Request.Path = "/api/v1/secrets/secret-id/unlock";
        context.Connection.RemoteIpAddress = System.Net.IPAddress.Parse("203.0.113.4");
        context.Response.StatusCode = 403;

        PrivacyAudit.Log(context, "unlock");

        Assert.Contains("unlock", provider.Message, StringComparison.Ordinal);
        Assert.DoesNotContain("secret-id", provider.Message, StringComparison.Ordinal);
        Assert.DoesNotContain("203.0.113.4", provider.Message, StringComparison.Ordinal);
        Assert.DoesNotContain("correct horse", provider.Message, StringComparison.Ordinal);
        var expected = Convert.ToHexString(HMACSHA256.HashData(key, Encoding.UTF8.GetBytes("203.0.113.4")))[..16];
        var unkeyed = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes("203.0.113.4")))[..16];
        Assert.Contains($"client={expected}", provider.Message, StringComparison.Ordinal);
        Assert.DoesNotContain(unkeyed, provider.Message, StringComparison.Ordinal);
    }

    private sealed class CapturingProvider : ILoggerProvider
    {
        public string Message { get; private set; } = string.Empty;
        public ILogger CreateLogger(string categoryName) => new CapturingLogger(this);
        public void Dispose() { }
        private sealed class CapturingLogger(CapturingProvider owner) : ILogger
        {
            public IDisposable? BeginScope<TState>(TState state) where TState : notnull => NullScope.Instance;
            public bool IsEnabled(LogLevel logLevel) => true;
            public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter) => owner.Message = formatter(state, exception);
            private sealed class NullScope : IDisposable { public static readonly NullScope Instance = new(); public void Dispose() { } }
        }
    }
}
