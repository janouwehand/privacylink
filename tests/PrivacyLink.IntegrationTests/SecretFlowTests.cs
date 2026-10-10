using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.Configuration;

public sealed class SecretFlowTests : IClassFixture<WebApplicationFactory<Program>>
{
    private readonly HttpClient _client;
    public SecretFlowTests(WebApplicationFactory<Program> factory) => _client = factory.CreateClient();

    [Fact]
    public async Task CreateMetadataAndOpenReturnSameCiphertext()
    {
        var payload = new { protocolVersion = 1, expiry = "1d", message = new { nonce = "AAAAAAAAAAAAAAAA", ciphertext = "AAAAAAAAAAAAAAAAAAAAAAA" }, files = Array.Empty<object>() };
        var created = await _client.PostAsJsonAsync("/api/v1/secrets", payload);
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
        var invalid = await _client.PostAsJsonAsync("/api/v1/secrets", new { protocolVersion = 1, expiry = "1d", message = new { nonce = "AAAAAAAAAAAAAAAA", ciphertext = "AAAAAAAAAAAAAAAAAAAAAAA" }, files = Array.Empty<object>(), password = "1234", unexpected = true });
        Assert.Equal(HttpStatusCode.BadRequest, invalid.StatusCode);
        using var request = new HttpRequestMessage(HttpMethod.Post, "/api/v1/secrets");
        request.Headers.Add("Origin", "https://evil.example");
        var foreign = await _client.SendAsync(request);
        Assert.Equal(HttpStatusCode.Forbidden, foreign.StatusCode);
    }

    [Fact]
    public async Task InvalidProtocolAndUnknownIdsAreRejected()
    {
        var invalid = await _client.PostAsJsonAsync("/api/v1/secrets", new { protocolVersion = 2, expiry = "1d", message = new { nonce = "AAAAAAAAAAAAAAAA", ciphertext = "AAAAAAAAAAAAAAAAAAAAAAA" }, files = Array.Empty<object>() });
        Assert.Equal(HttpStatusCode.BadRequest, invalid.StatusCode);
        var unknown = await _client.GetAsync("/api/v1/secrets/AAAAAAAAAAAAAAAAAAAAAA");
        Assert.Equal(HttpStatusCode.NotFound, unknown.StatusCode);
        Assert.Contains("not_found", await unknown.Content.ReadAsStringAsync());
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
        var oversized = await _client.PostAsJsonAsync("/api/v1/secrets", new { protocolVersion = 1, expiry = "1d", message = new { nonce = "AAAAAAAAAAAAAAAA", ciphertext = largeCiphertext }, files = Array.Empty<object>() });
        Assert.Equal(HttpStatusCode.RequestEntityTooLarge, oversized.StatusCode);
    }

    [Fact]
    public async Task UnprotectedOpenReturnsNoFileBlobsAndFileOpenReturnsCombinedFile()
    {
        var fileId = Convert.ToBase64String(new byte[16]).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        var payload = new { protocolVersion = 1, expiry = "1d", files = new[] { new { id = fileId, extension = ".txt", nameNonce = "AAAAAAAAAAAAAAAA", nameCiphertext = "AAAAAAAAAAAAAAAAAAAAAA", mimeType = "text/plain", size = 1L, nonce = "AAAAAAAAAAAAAAAA", ciphertext = "AAAAAAAAAAAAAAAAAAAAAAA" } } };
        var created = await _client.PostAsJsonAsync("/api/v1/secrets", payload);
        Assert.Equal(HttpStatusCode.Created, created.StatusCode);
        var id = (await created.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("id").GetString();
        var metadata = await _client.GetFromJsonAsync<JsonElement>($"/api/v1/secrets/{id}");
        Assert.Equal(".txt", metadata.GetProperty("files")[0].GetProperty("extension").GetString());
        Assert.Equal("AAAAAAAAAAAAAAAAAAAAAA", metadata.GetProperty("files")[0].GetProperty("nameCiphertext").GetString());
        Assert.False(metadata.GetProperty("files")[0].TryGetProperty("name", out _));
        var open = await _client.PostAsync($"/api/v1/secrets/{id}/open", null);
        Assert.Equal(HttpStatusCode.OK, open.StatusCode);
        Assert.Empty((await open.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("files").EnumerateArray());
        var opened = await _client.PostAsync($"/api/v1/secrets/{id}/files/{fileId}/open", null);
        Assert.Equal(HttpStatusCode.OK, opened.StatusCode);
        var openedBody = JsonDocument.Parse(await opened.Content.ReadAsStringAsync()).RootElement;
        Assert.Equal(".txt", openedBody.GetProperty("file").GetProperty("extension").GetString());
        Assert.Equal("AAAAAAAAAAAAAAAAAAAAAA", openedBody.GetProperty("file").GetProperty("nameCiphertext").GetString());
        Assert.Contains("AAAAAAAAAAAAAAAAAAAAAAA", openedBody.GetProperty("file").GetProperty("ciphertext").GetString());
        Assert.Equal(fileId, openedBody.GetProperty("file").GetProperty("id").GetString());
    }

    [Fact]
    public async Task UnsupportedFileAndMoreThanTenFilesAreRejected()
    {
        var fileId = Convert.ToBase64String(new byte[16]).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        var invalid = new { protocolVersion = 1, expiry = "1d", files = new[] { new { id = fileId, extension = ".exe", nameNonce = "AAAAAAAAAAAAAAAA", nameCiphertext = "AAAAAAAAAAAAAAAAAAAAAA", mimeType = "application/octet-stream", size = 1L, nonce = "AAAAAAAAAAAAAAAA", ciphertext = "AAAAAAAAAAAAAAAAAAAAAAA" } } };
        Assert.Equal(HttpStatusCode.BadRequest, (await _client.PostAsJsonAsync("/api/v1/secrets", invalid)).StatusCode);
        var files = Enumerable.Range(0, 11).Select(i => new { id = Convert.ToBase64String(BitConverter.GetBytes(i).Concat(new byte[8]).ToArray()).TrimEnd('=').Replace('+', '-').Replace('/', '_'), extension = ".txt", nameNonce = "AAAAAAAAAAAAAAAA", nameCiphertext = "AAAAAAAAAAAAAAAAAAAAAA", mimeType = "text/plain", size = 1L, nonce = "AAAAAAAAAAAAAAAA", ciphertext = "AAAAAAAAAAAAAAAAAAAAAAA" }).ToArray();
        Assert.Equal(HttpStatusCode.BadRequest, (await _client.PostAsJsonAsync("/api/v1/secrets", new { protocolVersion = 1, expiry = "1d", files })).StatusCode);
    }

    [Fact]
    public async Task ProtectedSecretRequiresPasswordAndUnlockReturnsClientCiphertext()
    {
        using var factory = new WebApplicationFactory<Program>().WithWebHostBuilder(builder => builder.ConfigureAppConfiguration((_, config) => config.AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["Security:PasswordPepper"] = "integration-test-pepper",
            ["Security:Argon2:MemorySizeKb"] = "8192",
            ["Security:Argon2:Iterations"] = "1",
            ["Security:Argon2:DegreeOfParallelism"] = "1"
        })));
        using var client = factory.CreateClient();
        var payload = new { protocolVersion = 1, expiry = "1d", password = "correct horse", message = new { nonce = "AAAAAAAAAAAAAAAA", ciphertext = "AAAAAAAAAAAAAAAAAAAAAAA" }, files = Array.Empty<object>() };
        var created = await client.PostAsJsonAsync("/api/v1/secrets", payload);
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
    public async Task ProtectedSecretCooldownReturnsRateLimitAfterConfiguredAttempts()
    {
        using var factory = new WebApplicationFactory<Program>().WithWebHostBuilder(builder => builder.ConfigureAppConfiguration((_, config) => config.AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["Security:PasswordPepper"] = "integration-test-pepper",
            ["Security:Argon2:MemorySizeKb"] = "8192",
            ["Security:Argon2:Iterations"] = "1",
            ["Security:Argon2:DegreeOfParallelism"] = "1",
            ["Security:UnlockAttempts:MaxPerWindow"] = "1"
        })));
        using var client = factory.CreateClient();
        var payload = new { protocolVersion = 1, expiry = "1d", password = "correct horse", message = new { nonce = "AAAAAAAAAAAAAAAA", ciphertext = "AAAAAAAAAAAAAAAAAAAAAAA" }, files = Array.Empty<object>() };
        var created = await client.PostAsJsonAsync("/api/v1/secrets", payload);
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
        using var factory = new WebApplicationFactory<Program>().WithWebHostBuilder(builder => builder.ConfigureAppConfiguration((_, config) => config.AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["Security:PasswordPepper"] = "integration-test-pepper",
            ["Security:Argon2:MemorySizeKb"] = "8192",
            ["Security:Argon2:Iterations"] = "1",
            ["Security:Argon2:DegreeOfParallelism"] = "1"
        })));
        using var client = factory.CreateClient();
        var fileId = Convert.ToBase64String(new byte[16]).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        var payload = new { protocolVersion = 1, expiry = "1d", password = "1234", files = new[] { new { id = fileId, extension = ".txt", nameNonce = "AAAAAAAAAAAAAAAA", nameCiphertext = "AAAAAAAAAAAAAAAAAAAAAA", mimeType = "text/plain", size = 1L, nonce = "AAAAAAAAAAAAAAAA", ciphertext = "AAAAAAAAAAAAAAAAAAAAAAA" } } };

        var created = await client.PostAsJsonAsync("/api/v1/secrets", payload);
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

        var created = await _client.PostAsJsonAsync("/api/v1/secrets", payload);

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
        using var factory = new WebApplicationFactory<Program>().WithWebHostBuilder(builder => builder.ConfigureAppConfiguration((_, config) => config.AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["Security:TrustedProxies:0"] = "127.0.0.1",
            ["RateLimiting:CreatePerIpPerHour"] = "1",
            ["RateLimiting:CreatePerIpPerDay"] = "10"
        })));
        using var client = factory.CreateClient();

        static object Payload() => new { protocolVersion = 1, expiry = "1d", message = new { nonce = "AAAAAAAAAAAAAAAA", ciphertext = Convert.ToBase64String(new byte[17]).TrimEnd('=').Replace('+', '-').Replace('/', '_') }, files = Array.Empty<object>() };
        using var first = new HttpRequestMessage(HttpMethod.Post, "/api/v1/secrets");
        first.Headers.Add("X-Forwarded-For", "198.51.100.10");
        first.Content = JsonContent.Create(Payload());
        using var second = new HttpRequestMessage(HttpMethod.Post, "/api/v1/secrets");
        second.Headers.Add("X-Forwarded-For", "198.51.100.11");
        second.Content = JsonContent.Create(Payload());

        Assert.Equal(HttpStatusCode.Created, (await client.SendAsync(first)).StatusCode);
        Assert.Equal(HttpStatusCode.Created, (await client.SendAsync(second)).StatusCode);
    }

    [Fact]
    public async Task MalformedMimeTypesAreRejectedWithoutEchoingInput()
    {
        var fileId = Convert.ToBase64String(new byte[16]).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        var payload = new { protocolVersion = 1, expiry = "1d", files = new[] { new { id = fileId, extension = ".txt", nameNonce = "AAAAAAAAAAAAAAAA", nameCiphertext = "AAAAAAAAAAAAAAAAAAAAAA", mimeType = "text/plain\r\nX-Leak: secret-password", size = 1L, nonce = "AAAAAAAAAAAAAAAA", ciphertext = "AAAAAAAAAAAAAAAAAAAAAAA" } } };
        using var response = await _client.PostAsJsonAsync("/api/v1/secrets", payload);
        var content = await response.Content.ReadAsStringAsync();

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal("{\"code\":\"invalid_request\"}", content);
        Assert.DoesNotContain("secret-password", content, StringComparison.Ordinal);
    }

    [Fact]
    public async Task UnlockRateLimitAppliesBeforeRepeatedPasswordAttempts()
    {
        using var factory = new WebApplicationFactory<Program>().WithWebHostBuilder(builder => builder.ConfigureAppConfiguration((_, config) => config.AddInMemoryCollection(new Dictionary<string, string?>
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
        var created = await client.PostAsJsonAsync("/api/v1/secrets", payload);
        var id = (await created.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("id").GetString();

        Assert.Equal(HttpStatusCode.Forbidden, (await client.PostAsJsonAsync($"/api/v1/secrets/{id}/unlock", new { password = "wrong horse" })).StatusCode);
        var limited = await client.PostAsJsonAsync($"/api/v1/secrets/{id}/unlock", new { password = "wrong horse" });
        Assert.Equal(HttpStatusCode.TooManyRequests, limited.StatusCode);
        Assert.Equal("{\"code\":\"rate_limited\"}", await limited.Content.ReadAsStringAsync());
    }
}
