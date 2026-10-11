using System.Net;
using System.Net.Http.Json;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using PrivacyLink.Services;

public sealed class SecretAuditTests
{
    [Fact]
    public async Task CreateUsesPreGeneratedSecretIdAndCompletesItsAudit()
    {
        var audit = new CapturingAuditWriter();
        await using var factory = new TestApiFactory().WithWebHostBuilder(builder =>
            builder.ConfigureTestServices(services =>
            {
                services.RemoveAll<ISecretRequestAuditWriter>();
                services.AddSingleton<ISecretRequestAuditWriter>(audit);
            }));
        using var client = factory.CreateClient();
        var payload = new { protocolVersion = 1, expiry = "1d", message = new { nonce = "AAAAAAAAAAAAAAAA", ciphertext = "AAAAAAAAAAAAAAAAAAAAAAA" }, files = Array.Empty<object>() };

        using var response = await CreateProofTestHelper.CreateAsync(client, payload);
        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        var created = await response.Content.ReadFromJsonAsync<System.Text.Json.JsonElement>();
        Assert.Single(audit.Starts);
        Assert.Single(audit.Finishes);
        Assert.Equal(created.GetProperty("id").GetString(), audit.Starts[0].SecretId);
        Assert.Equal("create", audit.Starts[0].Action);
        Assert.Equal(201, audit.Finishes[0].HttpStatus);
        Assert.Equal("success", audit.Finishes[0].Outcome);
    }

    [Fact]
    public async Task OriginRejectionIsAuditedBeforeTheEndpointRuns()
    {
        var audit = new CapturingAuditWriter();
        await using var factory = new TestApiFactory().WithWebHostBuilder(builder =>
            builder.ConfigureTestServices(services =>
            {
                services.RemoveAll<ISecretRequestAuditWriter>();
                services.AddSingleton<ISecretRequestAuditWriter>(audit);
            }));
        using var client = factory.CreateClient();
        using var request = new HttpRequestMessage(HttpMethod.Post, "/api/v1/secrets");
        request.Headers.Add("Origin", "https://evil.example");

        using var response = await client.SendAsync(request);
        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        Assert.Single(audit.Starts);
        Assert.Single(audit.Finishes);
        Assert.Equal("rejected", audit.Finishes[0].Outcome);
    }

    private sealed class CapturingAuditWriter : ISecretRequestAuditWriter
    {
        public List<SecretRequestAuditStart> Starts { get; } = [];
        public List<SecretRequestAuditFinish> Finishes { get; } = [];
        public Task StartAsync(SecretRequestAuditStart audit, CancellationToken cancellationToken = default)
        {
            lock (Starts) Starts.Add(audit);
            return Task.CompletedTask;
        }
        public Task FinishAsync(Guid requestId, SecretRequestAuditFinish finish, CancellationToken cancellationToken = default)
        {
            lock (Finishes) Finishes.Add(finish);
            return Task.CompletedTask;
        }
    }
}
