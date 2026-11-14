using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using PrivacyLink.Services;

public sealed class SecretFlowTests : IClassFixture<TestApiFactory>
{
    private const string TestChromeExtensionOrigin = "chrome-extension://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    private readonly HttpClient _client;
    public SecretFlowTests(TestApiFactory factory) => _client = factory.CreateClient();

    [Fact]
    public async Task SameOriginWebsiteCanUseTheCreateChallengeAndCreateFlow()
    {
        var websiteOrigin = _client.BaseAddress!.GetLeftPart(UriPartial.Authority);
        void SetWebsiteOrigin(HttpRequestMessage request) => request.Headers.Add("Origin", websiteOrigin);
        var payload = new { protocolVersion = 1, expiry = "1d", message = new { nonce = "AAAAAAAAAAAAAAAA", ciphertext = "AAAAAAAAAAAAAAAAAAAAAAA" }, files = Array.Empty<object>() };

        using var created = await CreateProofTestHelper.CreateAsync(_client, payload, SetWebsiteOrigin, SetWebsiteOrigin);

        Assert.Equal(HttpStatusCode.Created, created.StatusCode);
    }

    [Fact]
    public async Task ConfiguredChromeExtensionCanUseCreateChallengeAndCreateWithProof()
    {
        using var factory = new TestApiFactory().WithWebHostBuilder(builder => builder.ConfigureAppConfiguration((_, config) => config.AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["Security:ChromeExtensionOrigin"] = TestChromeExtensionOrigin
        })));
        using var client = factory.CreateClient();
        void SetExtensionOrigin(HttpRequestMessage request)
        {
            request.Headers.Add("Origin", TestChromeExtensionOrigin);
            request.Headers.Add("Sec-Fetch-Site", "cross-site");
        }

        using var challengeRequest = new HttpRequestMessage(HttpMethod.Get, "/api/v1/secrets/create-challenge");
        SetExtensionOrigin(challengeRequest);
        using var challenge = await client.SendAsync(challengeRequest);
        Assert.Equal(HttpStatusCode.OK, challenge.StatusCode);

        using var capabilitiesRequest = new HttpRequestMessage(HttpMethod.Get, "/api/v1/capabilities");
        SetExtensionOrigin(capabilitiesRequest);
        using var capabilities = await client.SendAsync(capabilitiesRequest);
        Assert.Equal(HttpStatusCode.OK, capabilities.StatusCode);
        using var capabilitiesBody = JsonDocument.Parse(await capabilities.Content.ReadAsStringAsync());
        Assert.Equal(15, capabilitiesBody.RootElement.GetProperty("maxFiles").GetInt32());

        using var missingProofRequest = new HttpRequestMessage(HttpMethod.Post, "/api/v1/secrets")
        {
            Content = new StringContent("not json", System.Text.Encoding.UTF8, "application/json")
        };
        SetExtensionOrigin(missingProofRequest);
        using var missingProof = await client.SendAsync(missingProofRequest);
        Assert.Equal(HttpStatusCode.Forbidden, missingProof.StatusCode);
        Assert.Equal("{\"code\":\"proof_required\"}", await missingProof.Content.ReadAsStringAsync());

        var payload = new { protocolVersion = 1, expiry = "1d", message = new { nonce = "AAAAAAAAAAAAAAAA", ciphertext = "AAAAAAAAAAAAAAAAAAAAAAA" }, files = Array.Empty<object>() };
        using var created = await CreateProofTestHelper.CreateAsync(client, payload, SetExtensionOrigin, SetExtensionOrigin);
        Assert.Equal(HttpStatusCode.Created, created.StatusCode);
    }

    [Fact]
    public async Task ChromeExtensionOriginIsAcceptedWithoutAnIdAllowlist()
    {
        using var client = new TestApiFactory().CreateClient();
        foreach (var origin in new[] { TestChromeExtensionOrigin, "chrome-extension://bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" })
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, "/api/v1/secrets/create-challenge");
            request.Headers.Add("Origin", origin);
            request.Headers.Add("Sec-Fetch-Site", "cross-site");
            using var response = await client.SendAsync(request);
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        }
    }

    [Fact]
    public async Task ChromeExtensionOriginIsNotBlockedByOriginFilterOnOtherRoutesOrMethods()
    {
        using var factory = new TestApiFactory().WithWebHostBuilder(builder => builder.ConfigureAppConfiguration((_, config) => config.AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["Security:ChromeExtensionOrigin"] = TestChromeExtensionOrigin
        })));
        using var client = factory.CreateClient();

        using var otherRoute = new HttpRequestMessage(HttpMethod.Get, "/api/v1/capabilities");
        otherRoute.Headers.Add("Origin", TestChromeExtensionOrigin);
        using var allowedCapabilities = await client.SendAsync(otherRoute);
        Assert.Equal(HttpStatusCode.OK, allowedCapabilities.StatusCode);

        using var unrelatedRoute = new HttpRequestMessage(HttpMethod.Get, "/api/v1/stats");
        unrelatedRoute.Headers.Add("Origin", TestChromeExtensionOrigin);
        using var unrelatedResponse = await client.SendAsync(unrelatedRoute);
        Assert.Equal(HttpStatusCode.Gone, unrelatedResponse.StatusCode);

        using var otherMethod = new HttpRequestMessage(HttpMethod.Put, "/api/v1/capabilities");
        otherMethod.Headers.Add("Origin", TestChromeExtensionOrigin);
        using var otherMethodResponse = await client.SendAsync(otherMethod);
        Assert.Equal(HttpStatusCode.MethodNotAllowed, otherMethodResponse.StatusCode);
    }

    [Fact]
    public async Task CreateMetadataAndOpenReturnSameCiphertext()
    {
        var payload = new { protocolVersion = 1, expiry = "1d", message = new { nonce = "AAAAAAAAAAAAAAAA", ciphertext = "AAAAAAAAAAAAAAAAAAAAAAA" }, files = Array.Empty<object>() };
        var created = await CreateProofTestHelper.CreateAsync(_client, payload);
        Assert.Equal(HttpStatusCode.Created, created.StatusCode);
        using var body = JsonDocument.Parse(await created.Content.ReadAsStringAsync());
        var id = body.RootElement.GetProperty("id").GetString();
        var metadata = await _client.GetAsync($"/api/v1/secrets/{id}");
        Assert.Equal(HttpStatusCode.OK, metadata.StatusCode);
        var opened = await _client.PostAsync($"/api/v1/secrets/{id}/open", null);
        Assert.Equal(HttpStatusCode.OK, opened.StatusCode);
        Assert.Contains("AAAAAAAAAAAAAAAAAAAAAAA", await opened.Content.ReadAsStringAsync());
        Assert.Equal("no-store", opened.Headers.CacheControl?.ToString());
    }

    [Fact]
    public async Task UnknownFieldsAndForeignOriginAreRejected()
    {
        var invalid = await CreateProofTestHelper.CreateAsync(_client, new { protocolVersion = 1, expiry = "1d", message = new { nonce = "AAAAAAAAAAAAAAAA", ciphertext = "AAAAAAAAAAAAAAAAAAAAAAA" }, files = Array.Empty<object>(), password = "1234", unexpected = true });
        Assert.Equal(HttpStatusCode.BadRequest, invalid.StatusCode);
        using var request = new HttpRequestMessage(HttpMethod.Post, "/api/v1/secrets");
        request.Headers.Add("Origin", "https://evil.example");
        var foreign = await _client.SendAsync(request);
        Assert.Equal(HttpStatusCode.Forbidden, foreign.StatusCode);

        using var foreignChallenge = new HttpRequestMessage(HttpMethod.Get, "/api/v1/secrets/create-challenge");
        foreignChallenge.Headers.Add("Origin", "https://evil.example");
        foreignChallenge.Headers.Add("Sec-Fetch-Site", "cross-site");
        using var rejectedChallenge = await _client.SendAsync(foreignChallenge);
        Assert.Equal(HttpStatusCode.Forbidden, rejectedChallenge.StatusCode);
    }

    [Fact]
    public async Task CreateRequiresProofBeforeBodyValidationAndConsumesItOnce()
    {
        using var noProof = await _client.PostAsync("/api/v1/secrets", new StringContent("not json", System.Text.Encoding.UTF8, "application/json"));
        Assert.Equal(HttpStatusCode.Forbidden, noProof.StatusCode);
        Assert.Equal("{\"code\":\"proof_required\"}", await noProof.Content.ReadAsStringAsync());

        var proof = await CreateProofTestHelper.GetProofAsync(_client);
        var payload = new { protocolVersion = 1, expiry = "1d", message = new { nonce = "AAAAAAAAAAAAAAAA", ciphertext = "AAAAAAAAAAAAAAAAAAAAAAA" }, files = Array.Empty<object>() };
        using var firstRequest = new HttpRequestMessage(HttpMethod.Post, "/api/v1/secrets") { Content = JsonContent.Create(payload) };
        firstRequest.Headers.Add("X-PrivacyLink-Proof", proof);
        using var first = await _client.SendAsync(firstRequest);
        Assert.Equal(HttpStatusCode.Created, first.StatusCode);

        using var replayRequest = new HttpRequestMessage(HttpMethod.Post, "/api/v1/secrets") { Content = JsonContent.Create(payload) };
        replayRequest.Headers.Add("X-PrivacyLink-Proof", proof);
        using var replay = await _client.SendAsync(replayRequest);
        Assert.Equal(HttpStatusCode.Forbidden, replay.StatusCode);
        Assert.Equal("{\"code\":\"proof_required\"}", await replay.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task ChallengeIsNotCachedAndExpiredOrMalformedProofIsRejected()
    {
        using var challenge = await _client.GetAsync("/api/v1/secrets/create-challenge");
        Assert.Equal(HttpStatusCode.OK, challenge.StatusCode);
        Assert.Equal("no-store", challenge.Headers.CacheControl?.ToString());

        var payload = new { protocolVersion = 1, expiry = "1d", message = new { nonce = "AAAAAAAAAAAAAAAA", ciphertext = "AAAAAAAAAAAAAAAAAAAAAAA" }, files = Array.Empty<object>() };
        var expiredProof = await CreateProofTestHelper.GetExpiredProofAsync(_client);
        using var expiredRequest = new HttpRequestMessage(HttpMethod.Post, "/api/v1/secrets") { Content = JsonContent.Create(payload) };
        expiredRequest.Headers.Add("X-PrivacyLink-Proof", expiredProof);
        using var expired = await _client.SendAsync(expiredRequest);
        Assert.Equal(HttpStatusCode.Forbidden, expired.StatusCode);
        Assert.Equal("{\"code\":\"proof_required\"}", await expired.Content.ReadAsStringAsync());

        using var malformedRequest = new HttpRequestMessage(HttpMethod.Post, "/api/v1/secrets") { Content = JsonContent.Create(payload) };
        malformedRequest.Headers.Add("X-PrivacyLink-Proof", "malformed");
        using var malformed = await _client.SendAsync(malformedRequest);
        Assert.Equal(HttpStatusCode.Forbidden, malformed.StatusCode);
        Assert.Equal("{\"code\":\"proof_required\"}", await malformed.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task FullReplayStoreReturnsRetryAfterBeforeReadingCreateBody()
    {
        using var factory = new TestApiFactory().WithWebHostBuilder(builder => builder.ConfigureAppConfiguration((_, config) => config.AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["Tests:CreateProofReplayFull"] = "true"
        })));
        using var client = factory.CreateClient();
        var proof = await CreateProofTestHelper.GetProofAsync(client);
        using var request = new HttpRequestMessage(HttpMethod.Post, "/api/v1/secrets") { Content = new StringContent("not json", System.Text.Encoding.UTF8, "application/json") };
        request.Headers.Add("X-PrivacyLink-Proof", proof);
        using var response = await client.SendAsync(request);

        Assert.Equal(HttpStatusCode.ServiceUnavailable, response.StatusCode);
        Assert.Equal("5", response.Headers.GetValues("Retry-After").Single());
        Assert.Equal("{\"code\":\"temporarily_unavailable\"}", await response.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task InvalidProtocolAndUnknownIdsAreRejected()
    {
        var invalid = await CreateProofTestHelper.CreateAsync(_client, new { protocolVersion = 2, expiry = "1d", message = new { nonce = "AAAAAAAAAAAAAAAA", ciphertext = "AAAAAAAAAAAAAAAAAAAAAAA" }, files = Array.Empty<object>() });
        Assert.Equal(HttpStatusCode.BadRequest, invalid.StatusCode);
        var unknown = await _client.GetAsync("/api/v1/secrets/AAAAAAAAAAAAAAAAAAAAAA");
        Assert.Equal(HttpStatusCode.NotFound, unknown.StatusCode);
        Assert.Contains("not_found", await unknown.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task UnknownExpiredAndRevokedSecretsHaveIdenticalMetadataAndOpenResponses()
    {
        var clock = new MutableTimeProvider(DateTimeOffset.UtcNow);
        using var factory = new TestApiFactory().WithWebHostBuilder(builder => builder.ConfigureTestServices(services =>
        {
            services.RemoveAll<TimeProvider>();
            services.AddSingleton<TimeProvider>(clock);
        }));
        using var client = factory.CreateClient();
        var payload = new { protocolVersion = 1, expiry = "1d", message = new { nonce = "AAAAAAAAAAAAAAAA", ciphertext = "AAAAAAAAAAAAAAAAAAAAAAA" }, files = Array.Empty<object>() };

        async Task<(string Id, string RevokeToken)> CreateSecretAsync()
        {
            using var created = await CreateProofTestHelper.CreateAsync(client, payload);
            Assert.Equal(HttpStatusCode.Created, created.StatusCode);
            using var body = await created.Content.ReadFromJsonAsync<JsonDocument>();
            return (body!.RootElement.GetProperty("id").GetString()!, body.RootElement.GetProperty("revokeToken").GetString()!);
        }

        var expired = await CreateSecretAsync();
        var revoked = await CreateSecretAsync();
        Assert.Equal(HttpStatusCode.OK, (await client.GetAsync($"/api/v1/secrets/{expired.Id}")).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await client.GetAsync($"/api/v1/secrets/{revoked.Id}")).StatusCode);

        using (var revoke = await client.PostAsJsonAsync($"/api/v1/secrets/{revoked.Id}/revoke", new { revokeToken = revoked.RevokeToken }))
            Assert.Equal(HttpStatusCode.NoContent, revoke.StatusCode);
        clock.Advance(TimeSpan.FromDays(2));

        const string unknownId = "AAAAAAAAAAAAAAAAAAAAAA";
        using var unknownMetadata = await client.GetAsync($"/api/v1/secrets/{unknownId}");
        using var expiredMetadata = await client.GetAsync($"/api/v1/secrets/{expired.Id}");
        using var revokedMetadata = await client.GetAsync($"/api/v1/secrets/{revoked.Id}");
        var metadataResults = new[]
        {
            (unknownMetadata.StatusCode, await unknownMetadata.Content.ReadAsStringAsync()),
            (expiredMetadata.StatusCode, await expiredMetadata.Content.ReadAsStringAsync()),
            (revokedMetadata.StatusCode, await revokedMetadata.Content.ReadAsStringAsync())
        };
        Assert.All(metadataResults, result =>
        {
            Assert.Equal(HttpStatusCode.NotFound, result.Item1);
            Assert.Equal("{\"code\":\"not_found\"}", result.Item2);
        });
        Assert.Equal(metadataResults[0], metadataResults[1]);
        Assert.Equal(metadataResults[0], metadataResults[2]);

        using var unknownOpen = await client.PostAsync($"/api/v1/secrets/{unknownId}/open", null);
        using var expiredOpen = await client.PostAsync($"/api/v1/secrets/{expired.Id}/open", null);
        using var revokedOpen = await client.PostAsync($"/api/v1/secrets/{revoked.Id}/open", null);
        var openResults = new[]
        {
            (unknownOpen.StatusCode, await unknownOpen.Content.ReadAsStringAsync()),
            (expiredOpen.StatusCode, await expiredOpen.Content.ReadAsStringAsync()),
            (revokedOpen.StatusCode, await revokedOpen.Content.ReadAsStringAsync())
        };
        Assert.All(openResults, result =>
        {
            Assert.Equal(HttpStatusCode.NotFound, result.Item1);
            Assert.Equal("{\"code\":\"not_found\"}", result.Item2);
        });
        Assert.Equal(openResults[0], openResults[1]);
        Assert.Equal(openResults[0], openResults[2]);
    }

    [Fact]
    public async Task RetiredStatisticsEndpointReturnsGone()
    {
        var response = await _client.GetAsync("/api/v1/stats");
        var body = await response.Content.ReadAsStringAsync();

        Assert.Equal(HttpStatusCode.Gone, response.StatusCode);
        Assert.Equal("no-store", response.Headers.CacheControl?.ToString());
        Assert.Contains("statistics_retired", body, StringComparison.Ordinal);
    }

    [Fact]
    public async Task CrossSiteFetchAndOversizeCiphertextAreRejected()
    {
        using var foreign = new HttpRequestMessage(HttpMethod.Post, "/api/v1/secrets");
        foreign.Headers.Add("Sec-Fetch-Site", "cross-site");
        Assert.Equal(HttpStatusCode.Forbidden, (await _client.SendAsync(foreign)).StatusCode);

        var largeCiphertext = Convert.ToBase64String(new byte[262161]).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        var oversized = await CreateProofTestHelper.CreateAsync(_client, new { protocolVersion = 1, expiry = "1d", message = new { nonce = "AAAAAAAAAAAAAAAA", ciphertext = largeCiphertext }, files = Array.Empty<object>() });
        Assert.Equal(HttpStatusCode.RequestEntityTooLarge, oversized.StatusCode);
    }

    [Fact]
    public async Task UnprotectedOpenReturnsEveryFileAndLegacyFileRouteRemainsAvailable()
    {
        var fileId = Convert.ToBase64String(new byte[16]).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        var payload = new { protocolVersion = 1, expiry = "1d", files = new[] { new { id = fileId, extension = ".txt", nameNonce = "AAAAAAAAAAAAAAAA", nameCiphertext = "AAAAAAAAAAAAAAAAAAAAAA", mimeType = "text/plain", size = 1L, nonce = "AAAAAAAAAAAAAAAA", ciphertext = "AAAAAAAAAAAAAAAAAAAAAAA" } } };
        var created = await CreateProofTestHelper.CreateAsync(_client, payload);
        Assert.Equal(HttpStatusCode.Created, created.StatusCode);
        var id = (await created.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("id").GetString();
        var metadata = await _client.GetFromJsonAsync<JsonElement>($"/api/v1/secrets/{id}");
        Assert.Equal(".txt", metadata.GetProperty("files")[0].GetProperty("extension").GetString());
        Assert.Equal("AAAAAAAAAAAAAAAAAAAAAA", metadata.GetProperty("files")[0].GetProperty("nameCiphertext").GetString());
        Assert.False(metadata.GetProperty("files")[0].TryGetProperty("name", out _));
        var open = await _client.PostAsync($"/api/v1/secrets/{id}/open", null);
        Assert.Equal(HttpStatusCode.OK, open.StatusCode);
        var openBody = await open.Content.ReadFromJsonAsync<JsonElement>();
        Assert.Single(openBody.GetProperty("files").EnumerateArray());
        Assert.Equal(fileId, openBody.GetProperty("files")[0].GetProperty("id").GetString());
        var opened = await _client.PostAsync($"/api/v1/secrets/{id}/files/{fileId}/open", null);
        Assert.Equal(HttpStatusCode.OK, opened.StatusCode);
        var openedBody = JsonDocument.Parse(await opened.Content.ReadAsStringAsync()).RootElement;
        Assert.Equal(".txt", openedBody.GetProperty("file").GetProperty("extension").GetString());
        Assert.Equal("AAAAAAAAAAAAAAAAAAAAAA", openedBody.GetProperty("file").GetProperty("nameCiphertext").GetString());
        Assert.Contains("AAAAAAAAAAAAAAAAAAAAAAA", openedBody.GetProperty("file").GetProperty("ciphertext").GetString());
        Assert.Equal(fileId, openedBody.GetProperty("file").GetProperty("id").GetString());
    }

    [Fact]
    public async Task OneTimeOpenReturnsAllContentOnceAndLegacyFileRouteCannotConsumeOrBypass()
    {
        var fileId = Convert.ToBase64String(Enumerable.Repeat((byte)3, 16).ToArray()).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        var payload = new
        {
            protocolVersion = 1,
            expiry = "1d",
            oneTimeOpen = true,
            message = new { nonce = "AAAAAAAAAAAAAAAA", ciphertext = "AAAAAAAAAAAAAAAAAAAAAAA" },
            files = new[] { new { id = fileId, extension = ".txt", nameNonce = "AAAAAAAAAAAAAAAA", nameCiphertext = "AAAAAAAAAAAAAAAAAAAAAA", mimeType = "text/plain", size = 1L, nonce = "AAAAAAAAAAAAAAAA", ciphertext = "AAAAAAAAAAAAAAAAAAAAAAA" } }
        };
        using var created = await CreateProofTestHelper.CreateAsync(_client, payload);
        Assert.Equal(HttpStatusCode.Created, created.StatusCode);
        var id = (await created.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("id").GetString()!;

        var metadata = await _client.GetFromJsonAsync<JsonElement>($"/api/v1/secrets/{id}");
        Assert.True(metadata.GetProperty("oneTimeOpen").GetBoolean());
        Assert.False(metadata.GetProperty("oneTimeOpened").GetBoolean());

        using var directFileBeforeOpen = await _client.PostAsync($"/api/v1/secrets/{id}/files/{fileId}/open", null);
        Assert.Equal(HttpStatusCode.NotFound, directFileBeforeOpen.StatusCode);
        metadata = await _client.GetFromJsonAsync<JsonElement>($"/api/v1/secrets/{id}");
        Assert.False(metadata.GetProperty("oneTimeOpened").GetBoolean());

        using var opened = await _client.PostAsync($"/api/v1/secrets/{id}/open", null);
        Assert.Equal(HttpStatusCode.OK, opened.StatusCode);
        var body = await opened.Content.ReadFromJsonAsync<JsonElement>();
        Assert.Contains("AAAAAAAAAAAAAAAAAAAAAAA", body.GetProperty("message").GetProperty("ciphertext").GetString());
        Assert.Single(body.GetProperty("files").EnumerateArray());
        Assert.Equal(fileId, body.GetProperty("files")[0].GetProperty("id").GetString());

        using var deletedMetadata = await _client.GetAsync($"/api/v1/secrets/{id}");
        Assert.Equal(HttpStatusCode.NotFound, deletedMetadata.StatusCode);
        using var repeatedOpen = await _client.PostAsync($"/api/v1/secrets/{id}/open", null);
        using var directFileAfterOpen = await _client.PostAsync($"/api/v1/secrets/{id}/files/{fileId}/open", null);
        Assert.Equal(HttpStatusCode.NotFound, repeatedOpen.StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, directFileAfterOpen.StatusCode);
    }

    [Fact]
    public async Task SuccessfulOneTimeResponseDeletesBlobsAndSecretMetadata()
    {
        var blobStorage = new FailOnceBlobStorage();
        var auditWriter = new CapturingSecretAuditWriter();
        using var factory = new TestApiFactory().WithWebHostBuilder(builder => builder.ConfigureTestServices(services =>
        {
            services.RemoveAll<IBlobStorage>();
            services.AddSingleton<IBlobStorage>(blobStorage);
            services.RemoveAll<ISecretRequestAuditWriter>();
            services.AddSingleton<ISecretRequestAuditWriter>(auditWriter);
        }));
        using var client = factory.CreateClient();
        var fileId = Convert.ToBase64String(Enumerable.Repeat((byte)5, 16).ToArray()).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        using var created = await CreateProofTestHelper.CreateAsync(client, new
        {
            protocolVersion = 1,
            expiry = "1d",
            oneTimeOpen = true,
            message = new { nonce = "AAAAAAAAAAAAAAAA", ciphertext = "AAAAAAAAAAAAAAAAAAAAAAA" },
            files = new[] { new { id = fileId, extension = ".txt", nameNonce = "AAAAAAAAAAAAAAAA", nameCiphertext = "AAAAAAAAAAAAAAAAAAAAAA", mimeType = "text/plain", size = 1L, nonce = "AAAAAAAAAAAAAAAA", ciphertext = "AAAAAAAAAAAAAAAAAAAAAAA" } }
        });
        Assert.Equal(HttpStatusCode.Created, created.StatusCode);
        var id = (await created.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("id").GetString()!;
        Assert.Equal(2, blobStorage.BlobCount);

        using var opened = await client.PostAsync($"/api/v1/secrets/{id}/open", null);
        Assert.Equal(HttpStatusCode.OK, opened.StatusCode);
        var content = await opened.Content.ReadFromJsonAsync<JsonElement>();
        Assert.Single(content.GetProperty("files").EnumerateArray());
        var completedAudit = auditWriter.GetCompleted(id, "open");
        Assert.Equal(200, completedAudit.Finish.HttpStatus);
        Assert.Equal("success", completedAudit.Finish.Outcome);
        Assert.Equal(0, blobStorage.BlobCount);
        using var metadata = await client.GetAsync($"/api/v1/secrets/{id}");
        using var replay = await client.PostAsync($"/api/v1/secrets/{id}/open", null);
        Assert.Equal(HttpStatusCode.NotFound, metadata.StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, replay.StatusCode);
    }

    [Fact]
    public async Task FailedResponseWriteKeepsConsumedOneTimeSecretAndBlobsForLaterCleanup()
    {
        var blobStorage = new FailOnceBlobStorage();
        var auditWriter = new CapturingSecretAuditWriter();
        using var factory = new TestApiFactory().WithWebHostBuilder(builder => builder.ConfigureTestServices(services =>
        {
            services.RemoveAll<IBlobStorage>();
            services.AddSingleton<IBlobStorage>(blobStorage);
            services.RemoveAll<ISecretRequestAuditWriter>();
            services.AddSingleton<ISecretRequestAuditWriter>(auditWriter);
            services.AddSingleton<IStartupFilter, FailOpenResponseWriteStartupFilter>();
        }));
        using var client = factory.CreateClient();
        using var created = await CreateProofTestHelper.CreateAsync(client, new
        {
            protocolVersion = 1,
            expiry = "1d",
            oneTimeOpen = true,
            message = new { nonce = "AAAAAAAAAAAAAAAA", ciphertext = "AAAAAAAAAAAAAAAAAAAAAAA" },
            files = Array.Empty<object>()
        });
        Assert.Equal(HttpStatusCode.Created, created.StatusCode);
        var id = (await created.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("id").GetString()!;
        Assert.Equal(1, blobStorage.BlobCount);

        using var failedResponse = await client.PostAsync($"/api/v1/secrets/{id}/open", null);
        Assert.Equal(HttpStatusCode.InternalServerError, failedResponse.StatusCode);
        var failedAudit = auditWriter.GetCompleted(id, "open");
        Assert.Equal(500, failedAudit.Finish.HttpStatus);
        Assert.Equal("error", failedAudit.Finish.Outcome);
        using var metadataResponse = await client.GetAsync($"/api/v1/secrets/{id}");
        Assert.Equal(HttpStatusCode.OK, metadataResponse.StatusCode);
        var metadata = await metadataResponse.Content.ReadFromJsonAsync<JsonElement>();
        Assert.True(metadata.GetProperty("oneTimeOpened").GetBoolean());
        Assert.Equal(1, blobStorage.BlobCount);

        using var replay = await client.PostAsync($"/api/v1/secrets/{id}/open", null);
        Assert.Equal(HttpStatusCode.NotFound, replay.StatusCode);
        Assert.Equal(1, blobStorage.BlobCount);
    }

    [Fact]
    public async Task ConcurrentOneTimeOpenRequestsReleaseContentToAtMostOneCaller()
    {
        using var created = await CreateProofTestHelper.CreateAsync(_client, new
        {
            protocolVersion = 1,
            expiry = "1d",
            oneTimeOpen = true,
            message = new { nonce = "AAAAAAAAAAAAAAAA", ciphertext = "AAAAAAAAAAAAAAAAAAAAAAA" },
            files = Array.Empty<object>()
        });
        Assert.Equal(HttpStatusCode.Created, created.StatusCode);
        var id = (await created.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("id").GetString()!;

        var attempts = await Task.WhenAll(Enumerable.Range(0, 12).Select(_ => _client.PostAsync($"/api/v1/secrets/{id}/open", null)));

        Assert.Single(attempts.Where(response => response.StatusCode == HttpStatusCode.OK));
        Assert.Equal(11, attempts.Count(response => response.StatusCode == HttpStatusCode.NotFound));
        foreach (var response in attempts) response.Dispose();
    }

    [Fact]
    public async Task OneTimeOpenRemainsConsumedWhenBlobDeliveryFailsAfterTheClaim()
    {
        var blobStorage = new FailOnceBlobStorage();
        using var factory = new TestApiFactory().WithWebHostBuilder(builder => builder.ConfigureTestServices(services =>
        {
            services.RemoveAll<IBlobStorage>();
            services.AddSingleton<IBlobStorage>(blobStorage);
        }));
        using var client = factory.CreateClient();
        using var created = await CreateProofTestHelper.CreateAsync(client, new
        {
            protocolVersion = 1,
            expiry = "1d",
            oneTimeOpen = true,
            message = new { nonce = "AAAAAAAAAAAAAAAA", ciphertext = "AAAAAAAAAAAAAAAAAAAAAAA" },
            files = Array.Empty<object>()
        });
        Assert.Equal(HttpStatusCode.Created, created.StatusCode);
        var id = (await created.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("id").GetString()!;

        blobStorage.FailNextRead();
        using var failedDelivery = await client.PostAsync($"/api/v1/secrets/{id}/open", null);
        Assert.Equal(HttpStatusCode.InternalServerError, failedDelivery.StatusCode);
        var metadata = await client.GetFromJsonAsync<JsonElement>($"/api/v1/secrets/{id}");
        Assert.True(metadata.GetProperty("oneTimeOpened").GetBoolean());

        using var retry = await client.PostAsync($"/api/v1/secrets/{id}/open", null);
        Assert.Equal(HttpStatusCode.NotFound, retry.StatusCode);
    }

    [Fact]
    public async Task UnsupportedFileAndMoreThanTenFilesAreRejected()
    {
        var fileId = Convert.ToBase64String(new byte[16]).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        var invalid = new { protocolVersion = 1, expiry = "1d", files = new[] { new { id = fileId, extension = ".exe", nameNonce = "AAAAAAAAAAAAAAAA", nameCiphertext = "AAAAAAAAAAAAAAAAAAAAAA", mimeType = "application/octet-stream", size = 1L, nonce = "AAAAAAAAAAAAAAAA", ciphertext = "AAAAAAAAAAAAAAAAAAAAAAA" } } };
        Assert.Equal(HttpStatusCode.BadRequest, (await CreateProofTestHelper.CreateAsync(_client, invalid)).StatusCode);
        var files = Enumerable.Range(0, 11).Select(i => new { id = Convert.ToBase64String(BitConverter.GetBytes(i).Concat(new byte[8]).ToArray()).TrimEnd('=').Replace('+', '-').Replace('/', '_'), extension = ".txt", nameNonce = "AAAAAAAAAAAAAAAA", nameCiphertext = "AAAAAAAAAAAAAAAAAAAAAA", mimeType = "text/plain", size = 1L, nonce = "AAAAAAAAAAAAAAAA", ciphertext = "AAAAAAAAAAAAAAAAAAAAAAA" }).ToArray();
        Assert.Equal(HttpStatusCode.BadRequest, (await CreateProofTestHelper.CreateAsync(_client, new { protocolVersion = 1, expiry = "1d", files })).StatusCode);
    }

    [Fact]
    public async Task ProtectedSecretRequiresPasswordAndUnlockReturnsClientCiphertext()
    {
        using var factory = new TestApiFactory().WithWebHostBuilder(builder => builder.ConfigureAppConfiguration((_, config) => config.AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["Security:PasswordPepper"] = "integration-test-pepper",
            ["Security:Argon2:MemorySizeKb"] = "8192",
            ["Security:Argon2:Iterations"] = "1",
            ["Security:Argon2:DegreeOfParallelism"] = "1"
        })));
        using var client = factory.CreateClient();
        var payload = new { protocolVersion = 1, expiry = "1d", password = "correct horse", message = new { nonce = "AAAAAAAAAAAAAAAA", ciphertext = "AAAAAAAAAAAAAAAAAAAAAAA" }, files = Array.Empty<object>() };
        var created = await CreateProofTestHelper.CreateAsync(client, payload);
        Assert.Equal(HttpStatusCode.Created, created.StatusCode);
        var createdBody = await created.Content.ReadFromJsonAsync<JsonElement>();
        var id = createdBody.GetProperty("id").GetString();
        Assert.True(createdBody.GetProperty("passwordProtected").GetBoolean());
        var metadata = await client.GetFromJsonAsync<JsonElement>($"/api/v1/secrets/{id}");
        Assert.True(metadata.GetProperty("passwordProtected").GetBoolean());
        Assert.Equal(HttpStatusCode.Forbidden, (await client.PostAsync($"/api/v1/secrets/{id}/open", null)).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await client.PostAsJsonAsync($"/api/v1/secrets/{id}/unlock", new { password = "wrong horse" })).StatusCode);
        var unlocked = await client.PostAsJsonAsync($"/api/v1/secrets/{id}/unlock", new { password = "correct horse" });
        Assert.Equal(HttpStatusCode.OK, unlocked.StatusCode);
        Assert.Contains("AAAAAAAAAAAAAAAAAAAAAAA", await unlocked.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task OneTimeProtectedOpenDoesNotConsumeOnWrongPasswordAndUnlockReturnsCombinedAndMessageOnlyContent()
    {
        using var factory = new TestApiFactory().WithWebHostBuilder(builder => builder.ConfigureAppConfiguration((_, config) => config.AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["Security:PasswordPepper"] = "integration-test-pepper",
            ["Security:Argon2:MemorySizeKb"] = "8192",
            ["Security:Argon2:Iterations"] = "1",
            ["Security:Argon2:DegreeOfParallelism"] = "1"
        })));
        using var client = factory.CreateClient();
        var fileId = Convert.ToBase64String(Enumerable.Repeat((byte)4, 16).ToArray()).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        using var created = await CreateProofTestHelper.CreateAsync(client, new
        {
            protocolVersion = 1,
            expiry = "1d",
            oneTimeOpen = true,
            password = "correct horse",
            message = new { nonce = "AAAAAAAAAAAAAAAA", ciphertext = "AAAAAAAAAAAAAAAAAAAAAAA" },
            files = new[] { new { id = fileId, extension = ".txt", nameNonce = "AAAAAAAAAAAAAAAA", nameCiphertext = "AAAAAAAAAAAAAAAAAAAAAA", mimeType = "text/plain", size = 1L, nonce = "AAAAAAAAAAAAAAAA", ciphertext = "AAAAAAAAAAAAAAAAAAAAAAA" } }
        });
        Assert.Equal(HttpStatusCode.Created, created.StatusCode);
        var id = (await created.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("id").GetString()!;

        using var wrongPassword = await client.PostAsJsonAsync($"/api/v1/secrets/{id}/unlock", new { password = "wrong horse" });
        Assert.Equal(HttpStatusCode.Forbidden, wrongPassword.StatusCode);
        var stillAvailable = await client.GetFromJsonAsync<JsonElement>($"/api/v1/secrets/{id}");
        Assert.False(stillAvailable.GetProperty("oneTimeOpened").GetBoolean());

        using var unlocked = await client.PostAsJsonAsync($"/api/v1/secrets/{id}/unlock", new { password = "correct horse" });
        Assert.Equal(HttpStatusCode.OK, unlocked.StatusCode);
        var body = await unlocked.Content.ReadFromJsonAsync<JsonElement>();
        Assert.Single(body.GetProperty("files").EnumerateArray());
        Assert.Equal(fileId, body.GetProperty("files")[0].GetProperty("id").GetString());

        using var replay = await client.PostAsJsonAsync($"/api/v1/secrets/{id}/unlock", new { password = "correct horse" });
        Assert.Equal(HttpStatusCode.NotFound, replay.StatusCode);

        using var messageOnlyCreated = await CreateProofTestHelper.CreateAsync(client, new
        {
            protocolVersion = 1,
            expiry = "1d",
            oneTimeOpen = true,
            password = "correct horse",
            message = new { nonce = "AAAAAAAAAAAAAAAA", ciphertext = "AAAAAAAAAAAAAAAAAAAAAAA" },
            files = Array.Empty<object>()
        });
        Assert.Equal(HttpStatusCode.Created, messageOnlyCreated.StatusCode);
        var messageOnlyId = (await messageOnlyCreated.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("id").GetString()!;
        using var messageOnlyOpen = await client.PostAsJsonAsync($"/api/v1/secrets/{messageOnlyId}/unlock", new { password = "correct horse" });
        Assert.Equal(HttpStatusCode.OK, messageOnlyOpen.StatusCode);
        var messageOnlyBody = await messageOnlyOpen.Content.ReadFromJsonAsync<JsonElement>();
        Assert.NotEqual(JsonValueKind.Null, messageOnlyBody.GetProperty("message").ValueKind);
        Assert.Empty(messageOnlyBody.GetProperty("files").EnumerateArray());
    }

    [Fact]
    public async Task ProtectedSecretCooldownReturnsRateLimitAfterConfiguredAttempts()
    {
        using var factory = new TestApiFactory().WithWebHostBuilder(builder => builder.ConfigureAppConfiguration((_, config) => config.AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["Security:PasswordPepper"] = "integration-test-pepper",
            ["Security:Argon2:MemorySizeKb"] = "8192",
            ["Security:Argon2:Iterations"] = "1",
            ["Security:Argon2:DegreeOfParallelism"] = "1",
            ["Security:UnlockAttempts:MaxPerWindow"] = "1"
        })));
        using var client = factory.CreateClient();
        var payload = new { protocolVersion = 1, expiry = "1d", password = "correct horse", message = new { nonce = "AAAAAAAAAAAAAAAA", ciphertext = "AAAAAAAAAAAAAAAAAAAAAAA" }, files = Array.Empty<object>() };
        var created = await CreateProofTestHelper.CreateAsync(client, payload);
        Assert.Equal(HttpStatusCode.Created, created.StatusCode);
        var id = (await created.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("id").GetString();

        var firstWrongPassword = await client.PostAsJsonAsync($"/api/v1/secrets/{id}/unlock", new { password = "wrong horse" });
        Assert.Equal(HttpStatusCode.Forbidden, firstWrongPassword.StatusCode);
        var secondWrongPassword = await client.PostAsJsonAsync($"/api/v1/secrets/{id}/unlock", new { password = "wrong horse" });

        Assert.Equal(HttpStatusCode.TooManyRequests, secondWrongPassword.StatusCode);
        Assert.True(secondWrongPassword.Headers.RetryAfter?.Delta > TimeSpan.Zero);
        Assert.Contains("rate_limited", await secondWrongPassword.Content.ReadAsStringAsync());
        Assert.Equal(HttpStatusCode.TooManyRequests, (await client.PostAsJsonAsync($"/api/v1/secrets/{id}/unlock", new { password = "correct horse" })).StatusCode);
    }

    [Fact]
    public async Task ProtectedFileOnlySecretExposesFileCountBeforeUnlock()
    {
        using var factory = new TestApiFactory().WithWebHostBuilder(builder => builder.ConfigureAppConfiguration((_, config) => config.AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["Security:PasswordPepper"] = "integration-test-pepper",
            ["Security:Argon2:MemorySizeKb"] = "8192",
            ["Security:Argon2:Iterations"] = "1",
            ["Security:Argon2:DegreeOfParallelism"] = "1"
        })));
        using var client = factory.CreateClient();
        var fileId = Convert.ToBase64String(new byte[16]).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        var payload = new { protocolVersion = 1, expiry = "1d", password = "1234", files = new[] { new { id = fileId, extension = ".txt", nameNonce = "AAAAAAAAAAAAAAAA", nameCiphertext = "AAAAAAAAAAAAAAAAAAAAAA", mimeType = "text/plain", size = 1L, nonce = "AAAAAAAAAAAAAAAA", ciphertext = "AAAAAAAAAAAAAAAAAAAAAAA" } } };

        var created = await CreateProofTestHelper.CreateAsync(client, payload);
        var id = (await created.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("id").GetString();
        var metadata = await client.GetFromJsonAsync<JsonElement>($"/api/v1/secrets/{id}");

        Assert.True(metadata.GetProperty("passwordProtected").GetBoolean());
        Assert.False(metadata.GetProperty("hasMessage").GetBoolean());
        Assert.Equal(1, metadata.GetProperty("fileCount").GetInt32());
        Assert.Empty(metadata.GetProperty("files").EnumerateArray());

        var unlocked = await client.PostAsJsonAsync($"/api/v1/secrets/{id}/unlock", new { password = "1234" });
        Assert.Equal(HttpStatusCode.OK, unlocked.StatusCode);
        var unlockedBody = JsonDocument.Parse(await unlocked.Content.ReadAsStringAsync()).RootElement;
        Assert.Equal(".txt", unlockedBody.GetProperty("files")[0].GetProperty("extension").GetString());
        Assert.Equal("AAAAAAAAAAAAAAAAAAAAAA", unlockedBody.GetProperty("files")[0].GetProperty("nameCiphertext").GetString());
        Assert.True(unlockedBody.GetProperty("files")[0].TryGetProperty("ciphertext", out _));
    }

    [Fact]
    public async Task DevelopmentConfigurationCanCreatePasswordProtectedSecret()
    {
        var payload = new { protocolVersion = 1, expiry = "1d", password = "correct horse", message = new { nonce = "AAAAAAAAAAAAAAAA", ciphertext = "AAAAAAAAAAAAAAAAAAAAAAA" }, files = Array.Empty<object>() };

        var created = await CreateProofTestHelper.CreateAsync(_client, payload);

        Assert.Equal(HttpStatusCode.Created, created.StatusCode);
        Assert.True((await created.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("passwordProtected").GetBoolean());
    }

    [Fact]
    public async Task SecurityHeadersArePresentAndResponsesDoNotExposeSensitiveServerDetails()
    {
        using var response = await _client.GetAsync("/health");

        var contentSecurityPolicy = response.Headers.GetValues("Content-Security-Policy").Single();
        Assert.Contains("default-src 'self'", contentSecurityPolicy);
        Assert.Contains("base-uri 'self'", contentSecurityPolicy);
        Assert.Contains("frame-ancestors 'none'", contentSecurityPolicy);
        Assert.Contains("object-src 'none'", contentSecurityPolicy);
        Assert.Contains("script-src 'self' 'wasm-unsafe-eval'", contentSecurityPolicy);
        Assert.DoesNotContain("'unsafe-eval'", contentSecurityPolicy);
        Assert.Equal("DENY", response.Headers.GetValues("X-Frame-Options").Single());
        Assert.Equal("same-origin", response.Headers.GetValues("Cross-Origin-Resource-Policy").Single());
        Assert.Equal("no-referrer", response.Headers.GetValues("Referrer-Policy").Single());
        Assert.Equal("nosniff", response.Headers.GetValues("X-Content-Type-Options").Single());
        Assert.DoesNotContain("Server", response.Headers.Select(header => header.Key), StringComparer.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task ReadinessIsHealthyAfterStorageInitializationWithoutExposingDependencies()
    {
        using var response = await _client.GetAsync("/health/ready");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("{\"status\":\"ready\"}", await response.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task TrustedForwardedForAddressesUseTheConfiguredClientIdentity()
    {
        using var factory = new TestApiFactory().WithWebHostBuilder(builder => builder.ConfigureAppConfiguration((_, config) => config.AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["Security:TrustedProxies:0"] = "127.0.0.1",
            ["RateLimiting:CreatePerIpPerHour"] = "1",
            ["RateLimiting:CreatePerIpPerDay"] = "10"
        })));
        using var client = factory.CreateClient();

        static object Payload() => new { protocolVersion = 1, expiry = "1d", message = new { nonce = "AAAAAAAAAAAAAAAA", ciphertext = Convert.ToBase64String(new byte[17]).TrimEnd('=').Replace('+', '-').Replace('/', '_') }, files = Array.Empty<object>() };
        using var first = await CreateProofTestHelper.CreateAsync(client, Payload(), request => request.Headers.Add("X-Forwarded-For", "198.51.100.10"));
        using var second = await CreateProofTestHelper.CreateAsync(client, Payload(), request => request.Headers.Add("X-Forwarded-For", "198.51.100.11"));

        Assert.Equal(HttpStatusCode.Created, first.StatusCode);
        Assert.Equal(HttpStatusCode.Created, second.StatusCode);
    }

    [Fact]
    public async Task ConfiguredChromeExtensionCreatesRemainSubjectToExistingRateLimits()
    {
        using var factory = new TestApiFactory().WithWebHostBuilder(builder => builder.ConfigureAppConfiguration((_, config) => config.AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["Security:ChromeExtensionOrigin"] = TestChromeExtensionOrigin,
            ["RateLimiting:CreatePerIpPerHour"] = "1",
            ["RateLimiting:CreatePerIpPerDay"] = "10"
        })));
        using var client = factory.CreateClient();
        void SetExtensionOrigin(HttpRequestMessage request)
        {
            request.Headers.Add("Origin", TestChromeExtensionOrigin);
            request.Headers.Add("Sec-Fetch-Site", "cross-site");
        }
        static object Payload() => new { protocolVersion = 1, expiry = "1d", message = new { nonce = "AAAAAAAAAAAAAAAA", ciphertext = Convert.ToBase64String(new byte[17]).TrimEnd('=').Replace('+', '-').Replace('/', '_') }, files = Array.Empty<object>() };

        using var first = await CreateProofTestHelper.CreateAsync(client, Payload(), SetExtensionOrigin, SetExtensionOrigin);
        using var limited = await CreateProofTestHelper.CreateAsync(client, Payload(), SetExtensionOrigin, SetExtensionOrigin);

        Assert.Equal(HttpStatusCode.Created, first.StatusCode);
        Assert.Equal(HttpStatusCode.TooManyRequests, limited.StatusCode);
        Assert.Equal("{\"code\":\"rate_limited\"}", await limited.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task MalformedMimeTypesAreRejectedWithoutEchoingInput()
    {
        var fileId = Convert.ToBase64String(new byte[16]).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        var payload = new { protocolVersion = 1, expiry = "1d", files = new[] { new { id = fileId, extension = ".txt", nameNonce = "AAAAAAAAAAAAAAAA", nameCiphertext = "AAAAAAAAAAAAAAAAAAAAAA", mimeType = "text/plain\r\nX-Leak: secret-password", size = 1L, nonce = "AAAAAAAAAAAAAAAA", ciphertext = "AAAAAAAAAAAAAAAAAAAAAAA" } } };
        using var response = await CreateProofTestHelper.CreateAsync(_client, payload);
        var content = await response.Content.ReadAsStringAsync();

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal("{\"code\":\"invalid_request\"}", content);
        Assert.DoesNotContain("secret-password", content, StringComparison.Ordinal);
    }

    [Fact]
    public async Task UnlockRateLimitAppliesBeforeRepeatedPasswordAttempts()
    {
        using var factory = new TestApiFactory().WithWebHostBuilder(builder => builder.ConfigureAppConfiguration((_, config) => config.AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["Security:PasswordPepper"] = "integration-test-pepper",
            ["Security:Argon2:MemorySizeKb"] = "8192",
            ["Security:Argon2:Iterations"] = "1",
            ["Security:Argon2:DegreeOfParallelism"] = "1",
            ["RateLimiting:UnlockPerIpPerSecretPerMinute"] = "1",
            ["RateLimiting:UnlockPerIpPerSecretPerHour"] = "1"
        })));
        using var client = factory.CreateClient();
        var payload = new { protocolVersion = 1, expiry = "1d", password = "correct horse", message = new { nonce = "AAAAAAAAAAAAAAAA", ciphertext = "AAAAAAAAAAAAAAAAAAAAAAA" }, files = Array.Empty<object>() };
        var created = await CreateProofTestHelper.CreateAsync(client, payload);
        var id = (await created.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("id").GetString();

        Assert.Equal(HttpStatusCode.Forbidden, (await client.PostAsJsonAsync($"/api/v1/secrets/{id}/unlock", new { password = "wrong horse" })).StatusCode);
        var limited = await client.PostAsJsonAsync($"/api/v1/secrets/{id}/unlock", new { password = "wrong horse" });
        Assert.Equal(HttpStatusCode.TooManyRequests, limited.StatusCode);
        Assert.Equal("{\"code\":\"rate_limited\"}", await limited.Content.ReadAsStringAsync());
    }

    private sealed class MutableTimeProvider(DateTimeOffset utcNow) : TimeProvider
    {
        private DateTimeOffset _utcNow = utcNow;
        public override DateTimeOffset GetUtcNow() => _utcNow;
        public void Advance(TimeSpan duration) => _utcNow += duration;
    }

    private sealed class FailOnceBlobStorage : IBlobStorage
    {
        private readonly Dictionary<(string SecretId, string BlobId), byte[]> _blobs = new();
        private int _failNextRead;
        public int BlobCount => _blobs.Count;

        public void FailNextRead() => Interlocked.Exchange(ref _failNextRead, 1);

        public Task PutAsync(string secretId, string blobId, ReadOnlyMemory<byte> contents, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            _blobs[(secretId, blobId)] = contents.ToArray();
            return Task.CompletedTask;
        }

        public Task<byte[]> ReadAsync(string secretId, string blobId, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (Interlocked.Exchange(ref _failNextRead, 0) == 1)
                return Task.FromException<byte[]>(new IOException("Injected blob read failure after one-time claim."));
            return _blobs.TryGetValue((secretId, blobId), out var contents)
                ? Task.FromResult(contents.ToArray())
                : Task.FromException<byte[]>(new FileNotFoundException());
        }

        public Task DeleteAsync(string secretId, string blobId, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            _blobs.Remove((secretId, blobId));
            return Task.CompletedTask;
        }
    }

    private sealed class CapturingSecretAuditWriter : ISecretRequestAuditWriter
    {
        private readonly object _gate = new();
        private readonly List<SecretRequestAuditStart> _starts = [];
        private readonly Dictionary<Guid, SecretRequestAuditFinish> _finishes = [];

        public Task StartAsync(SecretRequestAuditStart audit, CancellationToken cancellationToken = default)
        {
            lock (_gate) _starts.Add(audit);
            return Task.CompletedTask;
        }

        public Task FinishAsync(Guid requestId, SecretRequestAuditFinish finish, CancellationToken cancellationToken = default)
        {
            lock (_gate) _finishes[requestId] = finish;
            return Task.CompletedTask;
        }

        public (SecretRequestAuditStart Start, SecretRequestAuditFinish Finish) GetCompleted(string secretId, string action)
        {
            lock (_gate)
            {
                var start = _starts.Single(item => item.SecretId == secretId && item.Action == action);
                return (start, _finishes[start.RequestId]);
            }
        }
    }

    private sealed class FailOpenResponseWriteStartupFilter : IStartupFilter
    {
        private int _failNextOpen = 1;

        public FailOpenResponseWriteStartupFilter() { }

        public Action<IApplicationBuilder> Configure(Action<IApplicationBuilder> next) => app =>
        {
            app.Use(async (context, nextMiddleware) =>
            {
                var originalBody = context.Response.Body;
                if (HttpMethods.IsPost(context.Request.Method) && context.Request.Path.Value?.EndsWith("/open", StringComparison.Ordinal) == true &&
                    Interlocked.Exchange(ref _failNextOpen, 0) == 1)
                    context.Response.Body = new FailFirstWriteStream(originalBody);
                try { await nextMiddleware(); }
                finally { context.Response.Body = originalBody; }
            });
            next(app);
        };
    }

    private sealed class FailFirstWriteStream(Stream inner) : Stream
    {
        private int _failNextWrite = 1;

        public override bool CanRead => false;
        public override bool CanSeek => false;
        public override bool CanWrite => true;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override void Flush() => inner.Flush();
        public override Task FlushAsync(CancellationToken cancellationToken) => inner.FlushAsync(cancellationToken);
        public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();

        public override void Write(byte[] buffer, int offset, int count)
        {
            ThrowOnFirstWrite();
            inner.Write(buffer, offset, count);
        }

        public override void Write(ReadOnlySpan<byte> buffer)
        {
            ThrowOnFirstWrite();
            inner.Write(buffer);
        }

        public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        {
            if (Interlocked.Exchange(ref _failNextWrite, 0) == 1)
                return Task.FromException(new IOException("Injected response write failure."));
            return inner.WriteAsync(buffer, offset, count, cancellationToken);
        }

        public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
        {
            if (Interlocked.Exchange(ref _failNextWrite, 0) == 1)
                return ValueTask.FromException(new IOException("Injected response write failure."));
            return inner.WriteAsync(buffer, cancellationToken);
        }

        private void ThrowOnFirstWrite()
        {
            if (Interlocked.Exchange(ref _failNextWrite, 0) == 1)
                throw new IOException("Injected response write failure.");
        }
    }
}
