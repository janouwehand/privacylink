using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using PrivacyLink.Api;
using PrivacyLink.Infrastructure;
using PrivacyLink.Services;

public sealed class SecretRequestAuditTests
{
    [Fact]
    public async Task MiddlewareFlushesSecretResponseToOriginalResponseBody()
    {
        var responseBody = new MemoryStream();
        var context = new DefaultHttpContext();
        context.Request.Path = "/api/v1/secrets/AAAAAAAAAAAAAAAAAAAAAA";
        context.Response.Body = responseBody;
        var middleware = new SecretRequestAuditMiddleware(new ConfigurationBuilder().Build(), new NoopAuditWriter());

        await middleware.InvokeAsync(context, async _ =>
        {
            context.Response.StatusCode = StatusCodes.Status200OK;
            await context.Response.WriteAsync("secret-response");
        });

        Assert.Equal("secret-response", System.Text.Encoding.UTF8.GetString(responseBody.ToArray()));
    }

    [Fact]
    public async Task MiddlewareReplacesPartialSecretResponseWhenEndpointThrows()
    {
        var responseBody = new MemoryStream();
        var context = new DefaultHttpContext();
        context.Request.Path = "/api/v1/secrets/AAAAAAAAAAAAAAAAAAAAAA";
        context.Response.Body = responseBody;
        var middleware = new SecretRequestAuditMiddleware(new ConfigurationBuilder().Build(), new NoopAuditWriter());

        await middleware.InvokeAsync(context, async _ =>
        {
            await context.Response.WriteAsync("partial-response");
            throw new InvalidOperationException("simulated endpoint failure");
        });

        Assert.Equal(StatusCodes.Status500InternalServerError, context.Response.StatusCode);
        Assert.DoesNotContain("partial-response", System.Text.Encoding.UTF8.GetString(responseBody.ToArray()));
        Assert.Contains("server_error", System.Text.Encoding.UTF8.GetString(responseBody.ToArray()));
    }

    [Fact]
    public void FailureMappingPreservesHttpAndAuditStatuses()
    {
        Assert.Equal((413, "payload_too_large"), PrivacyAudit.Failure(new BadHttpRequestException("too large", 413)));
        Assert.Equal((503, "audit_unavailable"), PrivacyAudit.Failure(new SecretAuditUnavailableException()));
        Assert.Equal("audit_unavailable", PrivacyAudit.AuditErrorCode(503, "audit_unavailable"));
    }

    [Fact]
    public async Task InMemoryWriterRetainsCompletedAuditRows()
    {
        var writer = new InMemorySecretRequestAuditWriter();
        var requestId = Guid.NewGuid();
        var started = new SecretRequestAuditStart(requestId, "trace", "AAAAAAAAAAAAAAAAAAAAAA", "reserved", null,
            "metadata", "GET", "/api/v1/secrets/{id}", DateTimeOffset.UtcNow, null, null);
        var finish = new SecretRequestAuditFinish(DateTimeOffset.UtcNow, 3, "completed", "success", 200, null);

        await writer.StartAsync(started);
        await writer.FinishAsync(requestId, finish);

        var row = Assert.Single(writer.Snapshot());
        Assert.Equal(started, row.Start);
        Assert.Equal(finish, row.Finish);
    }

    [Fact]
    public async Task RevokeCommitsBeforeBlobCleanupAndKeepsSuccessOutcomeOnCleanupFailure()
    {
        var repository = new InMemorySecretRepository(new ConfigurationBuilder().Build());
        var now = DateTimeOffset.UtcNow;
        var secret = new StoredSecret("secret-id", now.AddDays(1), null, "blob-id", 1, [], RevokeTokenHash: "token-hash");
        await repository.CreateAsync(secret);
        var blobs = new ObservingBlobStorage(() => repository.GetAsync(secret.Id, now).GetAwaiter().GetResult() is null);
        var service = new SecretApplicationService(repository, blobs, new PasswordEnvelopeService(new PasswordEnvelopeOptions(null)), TimeProvider.System);
        var loggedFailures = 0;

        var revoked = await service.RevokeAsync(secret.Id, "token-hash", Guid.NewGuid(), blobDeleteFailure: _ => loggedFailures++);

        Assert.True(revoked);
        Assert.True(blobs.SawSecretAlreadyRemoved);
        Assert.Equal(1, loggedFailures);
        Assert.Null(await repository.GetAsync(secret.Id, now));
    }

    private sealed class ObservingBlobStorage(Func<bool> secretWasRemoved) : IBlobStorage
    {
        public bool SawSecretAlreadyRemoved { get; private set; }
        public Task PutAsync(string secretId, string blobId, ReadOnlyMemory<byte> contents, CancellationToken cancellationToken = default) => Task.CompletedTask;
        public Task<byte[]> ReadAsync(string secretId, string blobId, CancellationToken cancellationToken = default) => Task.FromResult(Array.Empty<byte>());
        public Task DeleteAsync(string secretId, string blobId, CancellationToken cancellationToken = default)
        {
            SawSecretAlreadyRemoved = secretWasRemoved();
            throw new IOException("simulated blob deletion failure");
        }
    }

    private sealed class NoopAuditWriter : ISecretRequestAuditWriter
    {
        public Task StartAsync(SecretRequestAuditStart audit, CancellationToken cancellationToken = default) => Task.CompletedTask;
        public Task FinishAsync(Guid requestId, SecretRequestAuditFinish finish, CancellationToken cancellationToken = default) => Task.CompletedTask;
    }
}
