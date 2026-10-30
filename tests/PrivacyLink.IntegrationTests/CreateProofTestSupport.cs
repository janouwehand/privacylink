using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using PrivacyLink.Services;

public sealed class TestApiFactory : WebApplicationFactory<Program>
{
    internal const string HmacKey = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=";

    static TestApiFactory()
    {
        // Minimal hosting reads these before WebApplicationFactory's late app-config callbacks run.
        Environment.SetEnvironmentVariable("Security__CreateProofHmacKey", HmacKey);
        Environment.SetEnvironmentVariable("Security__CreateProofDifficultyBits", "1");
        Environment.SetEnvironmentVariable("ConnectionStrings__PrivacyLink", string.Empty);
    }

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.ConfigureAppConfiguration((_, configuration) => configuration.AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["Security:CreateProofHmacKey"] = HmacKey,
            ["Security:CreateProofDifficultyBits"] = "1"
        }));
        builder.ConfigureTestServices(services =>
        {
            services.RemoveAll<ICreateProofReplayStore>();
            services.AddSingleton<ICreateProofReplayStore, TestCreateProofReplayStore>();
        });
    }
}

internal sealed class TestCreateProofReplayStore : ICreateProofReplayStore
{
    private readonly object _gate = new();
    private readonly Dictionary<string, DateTimeOffset> _entries = new(StringComparer.Ordinal);
    private readonly bool _full;

    public TestCreateProofReplayStore(IConfiguration configuration) => _full = configuration["Tests:CreateProofReplayFull"] == "true";

    public Task<CreateProofConsumeResult> TryConsumeAsync(string challengeId, DateTimeOffset expiresAt, DateTimeOffset now, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (_full) return Task.FromResult(CreateProofConsumeResult.Full);
        lock (_gate)
        {
            foreach (var expired in _entries.Where(entry => entry.Value <= now).Select(entry => entry.Key).ToArray()) _entries.Remove(expired);
            if (_entries.ContainsKey(challengeId)) return Task.FromResult(CreateProofConsumeResult.Replay);
            if (_entries.Count >= 10_000) return Task.FromResult(CreateProofConsumeResult.Full);
            _entries.Add(challengeId, expiresAt);
            return Task.FromResult(CreateProofConsumeResult.Consumed);
        }
    }
}

internal static class CreateProofTestHelper
{
    public static async Task<HttpResponseMessage> CreateAsync(
        HttpClient client,
        object payload,
        Action<HttpRequestMessage>? customize = null,
        Action<HttpRequestMessage>? customizeChallenge = null)
    {
        var proof = await GetProofAsync(client, customizeChallenge);
        using var request = new HttpRequestMessage(HttpMethod.Post, "/api/v1/secrets") { Content = JsonContent.Create(payload) };
        request.Headers.Add("X-PrivacyLink-Proof", proof);
        customize?.Invoke(request);
        return await client.SendAsync(request);
    }

    public static async Task<string> GetProofAsync(HttpClient client, Action<HttpRequestMessage>? customize = null)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, "/api/v1/secrets/create-challenge");
        customize?.Invoke(request);
        using var challengeResponse = await client.SendAsync(request);
        challengeResponse.EnsureSuccessStatusCode();
        using var challenge = System.Text.Json.JsonDocument.Parse(await challengeResponse.Content.ReadAsStringAsync());
        var root = challenge.RootElement;
        var id = root.GetProperty("challengeId").GetString()!;
        var nonce = root.GetProperty("nonce").GetString()!;
        var bits = root.GetProperty("difficultyBits").GetInt32();
        var expires = root.GetProperty("expiresAt").GetInt64();
        var signature = root.GetProperty("signature").GetString()!;
        for (ulong counter = 0; ; counter++)
        {
            var text = $"PrivacyLink-Create-PoW-v1:{id}:{nonce}:{counter}";
            var hash = SHA256.HashData(Encoding.UTF8.GetBytes(text));
            var zeros = 0;
            foreach (var value in hash)
            {
                if (value == 0) { zeros += 8; continue; }
                zeros += System.Numerics.BitOperations.LeadingZeroCount((uint)value) - 24;
                break;
            }
            if (zeros >= bits) return $"{id}.{nonce}.{bits}.{expires}.{signature}.{counter}";
        }
    }

    public static async Task<string> GetExpiredProofAsync(HttpClient client)
    {
        var proof = await GetProofAsync(client);
        var fields = proof.Split('.');
        var expiredAt = long.Parse(fields[3], System.Globalization.CultureInfo.InvariantCulture) - 301;
        var message = $"PrivacyLink-Create-Challenge-v1\n{fields[0]}\n{fields[1]}\n{fields[2]}\n{expiredAt}";
        var signature = Convert.ToBase64String(HMACSHA256.HashData(Convert.FromBase64String(TestApiFactory.HmacKey), Encoding.UTF8.GetBytes(message)))
            .TrimEnd('=').Replace('+', '-').Replace('/', '_');
        fields[3] = expiredAt.ToString(System.Globalization.CultureInfo.InvariantCulture);
        fields[4] = signature;
        return string.Join('.', fields);
    }
}
