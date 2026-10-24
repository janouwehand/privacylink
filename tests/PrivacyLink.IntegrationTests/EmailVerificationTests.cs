using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using PrivacyLink.Services;

public sealed class EmailVerificationTests
{
    private const string Email = "recipient.name+tag@example.com";
    private const string FileId = "AAAAAAAAAAAAAAAAAAAAAA";

    [Fact]
    public async Task OrdinarySecretCreationStillWorksWithoutPostgres()
    {
        using var host = EmailVerificationTestHost.Create(storeAvailable: false, senderConfigured: false);

        using var response = await CreateAsync(host);

        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
    }

    [Fact]
    public async Task EmailProtectedCreationRequiresPostgresEvenWhenResendIsConfigured()
    {
        using var host = EmailVerificationTestHost.Create(storeAvailable: false, senderConfigured: true);

        using var response = await CreateAsync(host, Email);

        Assert.Equal(HttpStatusCode.ServiceUnavailable, response.StatusCode);
        Assert.Equal("{\"code\":\"temporarily_unavailable\"}", await response.Content.ReadAsStringAsync());
        Assert.Empty(host.Sender.Messages);
    }

    [Fact]
    public async Task EmailProtectedCreationRequiresSenderConfigurationWhenStoreIsAvailable()
    {
        using var host = EmailVerificationTestHost.Create(storeAvailable: true, senderConfigured: false);

        using var response = await CreateAsync(host, Email);

        Assert.Equal(HttpStatusCode.ServiceUnavailable, response.StatusCode);
        Assert.Equal("{\"code\":\"temporarily_unavailable\"}", await response.Content.ReadAsStringAsync());
        Assert.Empty(host.Sender.Messages);
    }

    [Fact]
    public async Task EmailAddressIsNormalizedAndOnlyMaskedMetadataIsExposed()
    {
        using var host = EmailVerificationTestHost.Create(storeAvailable: true);

        using var invalid = await CreateAsync(host, "not-an-email");
        Assert.Equal(HttpStatusCode.BadRequest, invalid.StatusCode);

        using var created = await CreateAsync(host, "Recipient.Name+Tag@Example.COM");
        var configuration = host.Factory.Services.GetRequiredService<IConfiguration>();
        Assert.True(created.StatusCode == HttpStatusCode.Created,
            $"status={created.StatusCode}; body={await created.Content.ReadAsStringAsync()}; canCreate={host.CanCreateEmailProtectedSecrets}; store={host.Store.IsAvailable}; hmacOption={host.Options.HasHmacKey}; senderOption={host.Options.HasSenderConfiguration}; hmacConfigured={!string.IsNullOrWhiteSpace(configuration["Security:EmailVerificationHmacKey"])}; resendKeyConfigured={!string.IsNullOrWhiteSpace(configuration["Resend:ApiKey"])}; fromConfigured={!string.IsNullOrWhiteSpace(configuration["Resend:FromAddress"])}");
        Assert.Empty(host.Sender.Messages);
        var id = (await created.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("id").GetString()!;
        host.Store.RegisterSecret(id, Email);

        using var metadata = await host.Client.GetAsync($"/api/v1/secrets/{id}");
        Assert.Equal(HttpStatusCode.OK, metadata.StatusCode);
        var body = await metadata.Content.ReadAsStringAsync();
        using var json = JsonDocument.Parse(body);
        Assert.True(json.RootElement.GetProperty("emailVerificationRequired").GetBoolean());
        Assert.Equal("r***@example.com", json.RootElement.GetProperty("maskedEmailAddress").GetString());
        Assert.DoesNotContain("Recipient.Name+Tag@Example.COM", body, StringComparison.Ordinal);
        Assert.DoesNotContain("recipient.name+tag@example.com", body, StringComparison.Ordinal);
        Assert.False(json.RootElement.TryGetProperty("emailAddress", out _));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task ProviderOrTransportFailureInvalidatesTheCodeAndClearsTheOutbox(bool transportFailure)
    {
        Exception failure = transportFailure
            ? new HttpRequestException("Simulated transport failure.")
            : new InvalidOperationException("Simulated provider rejection.");
        using var host = EmailVerificationTestHost.Create(storeAvailable: true, senderFailure: failure);
        using var created = await CreateAsync(host, Email);
        Assert.Equal(HttpStatusCode.Created, created.StatusCode);
        var id = (await created.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("id").GetString()!;
        host.Store.RegisterSecret(id, Email);

        using var known = await host.Client.PostAsync($"/api/v1/secrets/{id}/email-verification/request", null);
        using var unknown = await host.Client.PostAsync("/api/v1/secrets/AAAAAAAAAAAAAAAAAAAAAA/email-verification/request", null);

        Assert.Equal(HttpStatusCode.Accepted, known.StatusCode);
        Assert.Equal(HttpStatusCode.Accepted, unknown.StatusCode);
        Assert.Equal(await unknown.Content.ReadAsStringAsync(), await known.Content.ReadAsStringAsync());
        Assert.Equal("{\"code\":\"verification_requested\"}", await known.Content.ReadAsStringAsync());
        await host.Store.WaitForInvalidationAsync(id).WaitAsync(TimeSpan.FromSeconds(5));
        Assert.Single(host.Sender.Messages);
        Assert.Equal(Email, host.Sender.Messages[0].Recipient);
        Assert.Equal(0, host.Store.OutboxCount);
        Assert.False(host.Store.HasChallenge(id));

        using var verification = await host.Client.PostAsJsonAsync($"/api/v1/secrets/{id}/email-verification/verify", new { code = host.Sender.LastCode });
        Assert.Equal(HttpStatusCode.BadRequest, verification.StatusCode);
        Assert.Equal("{\"code\":\"invalid_code\"}", await verification.Content.ReadAsStringAsync());
        Assert.DoesNotContain("provider", await verification.Content.ReadAsStringAsync(), StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task BodyBearingUnknownCodeRequestIsGenericAndCountsWithoutSending()
    {
        using var host = EmailVerificationTestHost.Create(storeAvailable: true);

        using var response = await host.Client.PostAsync(
            "/api/v1/secrets/AAAAAAAAAAAAAAAAAAAAAA/email-verification/request",
            new StringContent("request-body-must-not-trigger-email"));

        Assert.Equal(HttpStatusCode.Accepted, response.StatusCode);
        Assert.Equal("{\"code\":\"verification_requested\"}", await response.Content.ReadAsStringAsync());
        Assert.Equal(1, host.Store.RecordedRequests);
        Assert.Empty(host.Sender.Messages);
    }

    [Fact]
    public async Task MissingSenderRequestIsGenericAndCountsWithoutSending()
    {
        using var host = EmailVerificationTestHost.Create(storeAvailable: true, senderConfigured: false);
        const string id = "AAAAAAAAAAAAAAAAAAAAAA";
        host.Store.RegisterSecret(id, Email);

        using var response = await host.Client.PostAsync($"/api/v1/secrets/{id}/email-verification/request", null);

        Assert.Equal(HttpStatusCode.Accepted, response.StatusCode);
        Assert.Equal("{\"code\":\"verification_requested\"}", await response.Content.ReadAsStringAsync());
        Assert.Equal(1, host.Store.RecordedRequests);
        Assert.Equal(0, host.Store.RecordedFailedCodeInputsFor(IPAddress.Loopback));
        await host.Store.WaitForInvalidationAsync(id).WaitAsync(TimeSpan.FromSeconds(5));
        Assert.Equal(0, host.Store.OutboxCount);
        Assert.False(host.Store.HasChallenge(id));
        Assert.Empty(host.Sender.Messages);
    }

    [Fact]
    public async Task CodeRequestReturnsBeforeQueuedDeliveryCompletes()
    {
        using var host = EmailVerificationTestHost.Create(storeAvailable: true, blockSending: true);
        using var created = await CreateAsync(host, Email);
        Assert.Equal(HttpStatusCode.Created, created.StatusCode);
        var id = (await created.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("id").GetString()!;
        host.Store.RegisterSecret(id, Email);

        try
        {
            using var response = await host.Client.PostAsync($"/api/v1/secrets/{id}/email-verification/request", null)
                .WaitAsync(TimeSpan.FromSeconds(5));

            Assert.Equal(HttpStatusCode.Accepted, response.StatusCode);
            Assert.Equal("{\"code\":\"verification_requested\"}", await response.Content.ReadAsStringAsync());
            await host.Sender.WaitForSendStartedAsync().WaitAsync(TimeSpan.FromSeconds(5));
            Assert.False(host.Sender.IsReleased);
            var code = Assert.IsType<string>(host.Sender.LastCode);
            var stored = Assert.IsType<TestOutboxSnapshot>(host.Store.GetOutboxSnapshot(id));
            Assert.Equal(12, stored.Nonce.Length);
            Assert.Equal(6, stored.Ciphertext.Length);
            Assert.Equal(16, stored.Tag.Length);
            Assert.False(Encoding.ASCII.GetBytes(code).SequenceEqual(stored.Ciphertext));
            var delivery = new ClaimedEmailDelivery(stored.OutboxId, Assert.IsType<Guid>(stored.LeaseToken), stored.SecretId,
                stored.CodeMac, stored.Nonce, stored.Ciphertext, stored.Tag, Email);
            Assert.Equal(code, host.Options.DecryptCode(delivery));
        }
        finally
        {
            host.Sender.ReleaseDelivery();
        }

        await host.Store.WaitForActivationAsync(id).WaitAsync(TimeSpan.FromSeconds(5));
    }

    [Fact]
    public async Task ReplacedChallengeIsSkippedBeforeTheStaleDeliveryIsSent()
    {
        using var host = EmailVerificationTestHost.Create(storeAvailable: true, blockSending: true);
        using var created = await CreateAsync(host, Email);
        Assert.Equal(HttpStatusCode.Created, created.StatusCode);
        var id = (await created.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("id").GetString()!;
        host.Store.RegisterSecret(id, Email);
        var gate = host.Store.HoldNextDeliveryCheck();

        using var firstRequest = await host.Client.PostAsync($"/api/v1/secrets/{id}/email-verification/request", null);
        Assert.Equal(HttpStatusCode.Accepted, firstRequest.StatusCode);
        await gate.WaitForStartedAsync().WaitAsync(TimeSpan.FromSeconds(5));
        var stale = Assert.IsType<TestOutboxSnapshot>(host.Store.GetOutboxSnapshot(id));

        using var replacementRequest = await host.Client.PostAsync($"/api/v1/secrets/{id}/email-verification/request", null);
        Assert.Equal(HttpStatusCode.Accepted, replacementRequest.StatusCode);
        var replacement = Assert.IsType<TestOutboxSnapshot>(host.Store.GetOutboxSnapshot(id));
        Assert.NotEqual(stale.OutboxId, replacement.OutboxId);
        Assert.False(stale.CodeMac.SequenceEqual(replacement.CodeMac));
        Assert.Empty(host.Sender.Messages);

        try
        {
            gate.Release();
            await host.Store.WaitForDiscardAsync(id).WaitAsync(TimeSpan.FromSeconds(5));
            await host.Sender.WaitForSendStartedAsync().WaitAsync(TimeSpan.FromSeconds(5));
        }
        finally
        {
            host.Sender.ReleaseDelivery();
        }

        await host.Store.WaitForActivationAsync(id).WaitAsync(TimeSpan.FromSeconds(5));
        Assert.Single(host.Sender.Messages);
        Assert.Equal(0, host.Store.OutboxCount);
    }

    [Fact]
    public async Task AbandonedOutboxLeaseCanBeReclaimedAfterExpiry()
    {
        var key = Convert.ToBase64String(Enumerable.Repeat((byte)7, 32).ToArray());
        var options = EmailVerificationOptions.FromConfiguration(new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?> { ["Security:EmailVerificationHmacKey"] = key })
            .Build());
        var store = new TestEmailVerificationStore(isAvailable: true);
        var id = "AAAAAAAAAAAAAAAAAAAAAA";
        var now = DateTimeOffset.UtcNow;
        var codeMac = SHA256.HashData(Encoding.UTF8.GetBytes("fake challenge mac"));
        store.RegisterSecret(id, Email);
        var encryptedCode = options.EncryptCode(id, codeMac, "123456");
        await store.RequestCodeAsync(id, IPAddress.Loopback, codeMac, encryptedCode, now);

        var firstLease = Assert.IsType<ClaimedEmailDelivery>(await store.ClaimDeliveryAsync(now, TimeSpan.FromSeconds(30)));
        Assert.Null(await store.ClaimDeliveryAsync(now.AddSeconds(29), TimeSpan.FromSeconds(30)));
        Assert.False(await store.IsDeliveryCurrentAsync(firstLease, now.AddSeconds(30)));

        var reclaimed = Assert.IsType<ClaimedEmailDelivery>(await store.ClaimDeliveryAsync(now.AddSeconds(30), TimeSpan.FromSeconds(30)));
        Assert.Equal(firstLease.OutboxId, reclaimed.OutboxId);
        Assert.NotEqual(firstLease.LeaseToken, reclaimed.LeaseToken);
        Assert.True(await store.IsDeliveryCurrentAsync(reclaimed, now.AddSeconds(31)));
        Assert.Equal(1, store.OutboxCount);
    }

    [Fact]
    public async Task MalformedVerifyInputsAreCountedWithoutConsumingTheChallenge()
    {
        using var host = EmailVerificationTestHost.Create(storeAvailable: true);
        using var created = await CreateAsync(host, Email);
        Assert.Equal(HttpStatusCode.Created, created.StatusCode);
        var id = (await created.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("id").GetString()!;
        host.Store.RegisterSecret(id, Email);

        using var requested = await host.Client.PostAsync($"/api/v1/secrets/{id}/email-verification/request", null);
        Assert.Equal(HttpStatusCode.Accepted, requested.StatusCode);
        await host.Store.WaitForActivationAsync(id).WaitAsync(TimeSpan.FromSeconds(5));
        var realCode = host.Sender.LastCode!;

        foreach (var malformedCode in new[] { "12345", "12x456", "1234567" })
        {
            using var malformed = await host.Client.PostAsJsonAsync($"/api/v1/secrets/{id}/email-verification/verify", new { code = malformedCode });
            Assert.Equal(HttpStatusCode.BadRequest, malformed.StatusCode);
            Assert.Equal("{\"code\":\"invalid_code\"}", await malformed.Content.ReadAsStringAsync());
        }

        Assert.Equal(3, host.Store.RecordedFailedCodeInputsFor(IPAddress.Loopback));

        using var verified = await host.Client.PostAsJsonAsync($"/api/v1/secrets/{id}/email-verification/verify", new { code = realCode });
        Assert.Equal(HttpStatusCode.NoContent, verified.StatusCode);
        Assert.Equal(3, host.Store.RecordedFailedCodeInputsFor(IPAddress.Loopback));
    }

    [Fact]
    public async Task ThreeWrongCodesInvalidateChallengeAndCorrectCodeCanOnlyBeUsedOnce()
    {
        using var host = EmailVerificationTestHost.Create(storeAvailable: true);
        using var created = await CreateAsync(host, Email);
        Assert.Equal(HttpStatusCode.Created, created.StatusCode);
        var id = (await created.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("id").GetString()!;
        host.Store.RegisterSecret(id, Email);

        using var firstRequest = await host.Client.PostAsync($"/api/v1/secrets/{id}/email-verification/request", null);
        Assert.Equal(HttpStatusCode.Accepted, firstRequest.StatusCode);
        await host.Store.WaitForActivationAsync(id).WaitAsync(TimeSpan.FromSeconds(5));
        var firstCode = host.Sender.LastCode!;
        var wrongCode = firstCode == "000000" ? "000001" : "000000";

        for (var attempt = 0; attempt < 3; attempt++)
        {
            using var wrong = await host.Client.PostAsJsonAsync($"/api/v1/secrets/{id}/email-verification/verify", new { code = wrongCode });
            Assert.Equal(HttpStatusCode.BadRequest, wrong.StatusCode);
            Assert.Equal("{\"code\":\"invalid_code\"}", await wrong.Content.ReadAsStringAsync());
        }

        using var invalidated = await host.Client.PostAsJsonAsync($"/api/v1/secrets/{id}/email-verification/verify", new { code = firstCode });
        Assert.Equal(HttpStatusCode.BadRequest, invalidated.StatusCode);

        using var secondRequest = await host.Client.PostAsync($"/api/v1/secrets/{id}/email-verification/request", null);
        Assert.Equal(HttpStatusCode.Accepted, secondRequest.StatusCode);
        await host.Store.WaitForActivationAsync(id).WaitAsync(TimeSpan.FromSeconds(5));
        var secondCode = host.Sender.LastCode!;
        using var verified = await host.Client.PostAsJsonAsync($"/api/v1/secrets/{id}/email-verification/verify", new { code = secondCode });
        Assert.Equal(HttpStatusCode.NoContent, verified.StatusCode);
        using var replay = await host.Client.PostAsJsonAsync($"/api/v1/secrets/{id}/email-verification/verify", new { code = secondCode });
        Assert.Equal(HttpStatusCode.BadRequest, replay.StatusCode);
    }

    [Fact]
    public async Task EmailVerificationGatesOpenAndFileRoutesAndIssuesSecureSessionCookie()
    {
        using var host = EmailVerificationTestHost.Create(storeAvailable: true);
        using var created = await CreateAsync(host, Email, includeFile: true);
        Assert.Equal(HttpStatusCode.Created, created.StatusCode);
        var id = (await created.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("id").GetString()!;
        host.Store.RegisterSecret(id, Email);

        using var blockedOpen = await host.Client.PostAsync($"/api/v1/secrets/{id}/open", null);
        using var blockedFile = await host.Client.PostAsync($"/api/v1/secrets/{id}/files/{FileId}/open", null);
        await AssertEmailVerificationRequiredAsync(blockedOpen);
        await AssertEmailVerificationRequiredAsync(blockedFile);

        using var requested = await host.Client.PostAsync($"/api/v1/secrets/{id}/email-verification/request", null);
        Assert.Equal(HttpStatusCode.Accepted, requested.StatusCode);
        await host.Store.WaitForActivationAsync(id).WaitAsync(TimeSpan.FromSeconds(5));
        var code = host.Sender.LastCode;
        Assert.NotNull(code);
        using var verified = await host.Client.PostAsJsonAsync($"/api/v1/secrets/{id}/email-verification/verify", new { code });
        Assert.Equal(HttpStatusCode.NoContent, verified.StatusCode);
        var setCookie = verified.Headers.GetValues("Set-Cookie").Single();
        Assert.Contains("httponly", setCookie, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("secure", setCookie, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("samesite=strict", setCookie, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("max-age=1800", setCookie, StringComparison.OrdinalIgnoreCase);
        var cookie = setCookie.Split(';', 2)[0];

        using var stillBlocked = await host.Client.PostAsync($"/api/v1/secrets/{id}/open", null);
        await AssertEmailVerificationRequiredAsync(stillBlocked);
        using var open = await PostWithCookieAsync(host.Client, $"/api/v1/secrets/{id}/open", cookie);
        Assert.Equal(HttpStatusCode.OK, open.StatusCode);
        Assert.Contains("AAAAAAAAAAAAAAAAAAAAAAA", await open.Content.ReadAsStringAsync(), StringComparison.Ordinal);
        using var openFile = await PostWithCookieAsync(host.Client, $"/api/v1/secrets/{id}/files/{FileId}/open", cookie);
        Assert.Equal(HttpStatusCode.OK, openFile.StatusCode);
        Assert.Contains("AAAAAAAAAAAAAAAAAAAAAAA", await openFile.Content.ReadAsStringAsync(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task EmailVerificationMustPrecedePasswordUnlockAndPasswordRemainsRequired()
    {
        using var host = EmailVerificationTestHost.Create(storeAvailable: true);
        using var created = await CreateAsync(host, Email, password: "1234");
        Assert.Equal(HttpStatusCode.Created, created.StatusCode);
        var id = (await created.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("id").GetString()!;
        host.Store.RegisterSecret(id, Email);

        using var blockedUnlock = await host.Client.PostAsJsonAsync($"/api/v1/secrets/{id}/unlock", new { password = "1234" });
        await AssertEmailVerificationRequiredAsync(blockedUnlock);

        using var requested = await host.Client.PostAsync($"/api/v1/secrets/{id}/email-verification/request", null);
        Assert.Equal(HttpStatusCode.Accepted, requested.StatusCode);
        await host.Store.WaitForActivationAsync(id).WaitAsync(TimeSpan.FromSeconds(5));
        using var verified = await host.Client.PostAsJsonAsync($"/api/v1/secrets/{id}/email-verification/verify", new { code = host.Sender.LastCode });
        Assert.Equal(HttpStatusCode.NoContent, verified.StatusCode);
        var cookie = verified.Headers.GetValues("Set-Cookie").Single().Split(';', 2)[0];

        using var wrongPassword = await PostWithCookieAsync(host.Client, $"/api/v1/secrets/{id}/unlock", cookie, new { password = "wrong" });
        Assert.Equal(HttpStatusCode.Forbidden, wrongPassword.StatusCode);
        Assert.Equal("{\"code\":\"forbidden\"}", await wrongPassword.Content.ReadAsStringAsync());
        using var correctPassword = await PostWithCookieAsync(host.Client, $"/api/v1/secrets/{id}/unlock", cookie, new { password = "1234" });
        Assert.Equal(HttpStatusCode.OK, correctPassword.StatusCode);
        Assert.Contains("AAAAAAAAAAAAAAAAAAAAAAA", await correctPassword.Content.ReadAsStringAsync(), StringComparison.Ordinal);
    }

    private static Task<HttpResponseMessage> CreateAsync(EmailVerificationTestHost host, string? emailAddress = null, string? password = null, bool includeFile = false)
    {
        var payload = new Dictionary<string, object?>
        {
            ["protocolVersion"] = 1,
            ["expiry"] = "1d",
            ["message"] = new { nonce = "AAAAAAAAAAAAAAAA", ciphertext = "AAAAAAAAAAAAAAAAAAAAAAA" },
            ["files"] = includeFile
                ? new object[] { new { id = FileId, extension = ".txt", nameNonce = "AAAAAAAAAAAAAAAA", nameCiphertext = "AAAAAAAAAAAAAAAAAAAAAA", mimeType = "text/plain", size = 1L, nonce = "AAAAAAAAAAAAAAAA", ciphertext = "AAAAAAAAAAAAAAAAAAAAAAA" } }
                : Array.Empty<object>()
        };
        if (emailAddress is not null) payload["emailAddress"] = emailAddress;
        if (password is not null) payload["password"] = password;
        return CreateProofTestHelper.CreateAsync(host.Client, payload);
    }

    private static async Task<HttpResponseMessage> PostWithCookieAsync(HttpClient client, string path, string cookie, object? body = null)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, path);
        request.Headers.TryAddWithoutValidation("Cookie", cookie);
        if (body is not null) request.Content = JsonContent.Create(body);
        return await client.SendAsync(request);
    }

    private static async Task AssertEmailVerificationRequiredAsync(HttpResponseMessage response)
    {
        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        Assert.Equal("{\"code\":\"email_verification_required\"}", await response.Content.ReadAsStringAsync());
    }
}
