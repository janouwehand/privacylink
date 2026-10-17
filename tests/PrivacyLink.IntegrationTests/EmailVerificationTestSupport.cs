using System.Net;
using System.Security.Cryptography;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using PrivacyLink.Services;

internal sealed class EmailVerificationTestHost : IDisposable
{
    private EmailVerificationTestHost(WebApplicationFactory<Program> factory, TestEmailVerificationStore store, TestEmailSender sender)
    {
        Factory = factory;
        Store = store;
        Sender = sender;
        Client = factory.CreateClient(new WebApplicationFactoryClientOptions { BaseAddress = new Uri("https://localhost"), HandleCookies = false });
    }

    public WebApplicationFactory<Program> Factory { get; }
    public HttpClient Client { get; }
    public TestEmailVerificationStore Store { get; }
    public TestEmailSender Sender { get; }
    public EmailVerificationOptions Options => Factory.Services.GetRequiredService<EmailVerificationOptions>();
    public bool CanCreateEmailProtectedSecrets => Factory.Services.GetRequiredService<EmailVerificationService>().CanCreateEmailProtectedSecrets;

    public static EmailVerificationTestHost Create(bool storeAvailable, bool senderConfigured = true, Exception? senderFailure = null, bool blockSending = false)
    {
        var store = new TestEmailVerificationStore(storeAvailable);
        var sender = new TestEmailSender(senderFailure, blockSending);
        var key = Convert.ToBase64String(Enumerable.Repeat((byte)2, 32).ToArray());
        var values = new Dictionary<string, string?>
        {
            ["Security:EmailVerificationHmacKey"] = key,
            ["Resend:ApiKey"] = senderConfigured ? "integration-test-resend-key" : null,
            ["Resend:FromAddress"] = senderConfigured ? "noreply@example.com" : null
        };

        var factory = new TestApiFactory().WithWebHostBuilder(builder =>
        {
            builder.ConfigureAppConfiguration((_, configuration) => configuration.AddInMemoryCollection(values));
            builder.ConfigureTestServices(services =>
            {
                services.RemoveAll<EmailVerificationOptions>();
                services.AddSingleton(EmailVerificationOptions.FromConfiguration(new ConfigurationBuilder().AddInMemoryCollection(values).Build()));
                services.RemoveAll<IEmailVerificationStore>();
                services.AddSingleton<IEmailVerificationStore>(store);
                services.RemoveAll<IEmailSender>();
                services.AddSingleton<IEmailSender>(sender);
                services.AddSingleton<IStartupFilter, TestRemoteIpStartupFilter>();
            });
        });
        return new EmailVerificationTestHost(factory, store, sender);
    }

    public void Dispose()
    {
        Client.Dispose();
        Factory.Dispose();
    }
}

internal sealed class TestRemoteIpStartupFilter : IStartupFilter
{
    public Action<IApplicationBuilder> Configure(Action<IApplicationBuilder> next) => app =>
    {
        app.Use(async (context, nextMiddleware) =>
        {
            context.Connection.RemoteIpAddress ??= IPAddress.Loopback;
            await nextMiddleware();
        });
        next(app);
    };
}

internal sealed class TestEmailVerificationStore(bool isAvailable) : IEmailVerificationStore
{
    private readonly object _gate = new();
    private readonly Dictionary<string, string> _emailSecrets = new(StringComparer.Ordinal);
    private readonly Dictionary<string, Challenge> _challenges = new(StringComparer.Ordinal);
    private readonly Dictionary<string, Session> _sessions = new(StringComparer.Ordinal);
    private readonly Dictionary<string, DeliverySignal> _deliverySignals = new(StringComparer.Ordinal);
    private readonly Dictionary<long, OutboxItem> _outbox = [];
    private readonly Dictionary<string, long> _failedCodeInputsByIp = new(StringComparer.Ordinal);
    private long _recordedRequests;
    private long _nextOutboxId;
    private DeliveryCheckGate? _nextDeliveryCheckGate;

    public bool IsAvailable => isAvailable;
    public long RecordedRequests { get { lock (_gate) return _recordedRequests; } }
    public int OutboxCount { get { lock (_gate) return _outbox.Count; } }

    public long RecordedFailedCodeInputsFor(IPAddress clientIp)
    {
        var key = (clientIp.IsIPv4MappedToIPv6 ? clientIp.MapToIPv4() : clientIp).ToString();
        lock (_gate) return _failedCodeInputsByIp.TryGetValue(key, out var count) ? count : 0;
    }

    public Task RecordRequestAsync(IPAddress clientIp, DateTimeOffset now, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        lock (_gate) _recordedRequests++;
        return Task.CompletedTask;
    }

    public Task<EmailCodeVerificationStatus> RecordFailedCodeInputAsync(IPAddress clientIp, DateTimeOffset now, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        lock (_gate)
        {
            if (!isAvailable) return Task.FromResult(EmailCodeVerificationStatus.Invalid);
            var key = (clientIp.IsIPv4MappedToIPv6 ? clientIp.MapToIPv4() : clientIp).ToString();
            var count = _failedCodeInputsByIp.GetValueOrDefault(key);
            if (count >= 30) return Task.FromResult(EmailCodeVerificationStatus.RateLimited);
            _failedCodeInputsByIp[key] = count + 1;
            return Task.FromResult(EmailCodeVerificationStatus.Invalid);
        }
    }

    public void RegisterSecret(string secretId, string normalizedAddress)
    {
        lock (_gate) _emailSecrets[secretId] = normalizedAddress;
    }

    public Task WaitForActivationAsync(string secretId, CancellationToken cancellationToken = default) =>
        GetDeliverySignal(secretId).Activated.Task.WaitAsync(cancellationToken);

    public Task WaitForInvalidationAsync(string secretId, CancellationToken cancellationToken = default) =>
        GetDeliverySignal(secretId).Invalidated.Task.WaitAsync(cancellationToken);

    public Task WaitForDiscardAsync(string secretId, CancellationToken cancellationToken = default) =>
        GetDeliverySignal(secretId).Discarded.Task.WaitAsync(cancellationToken);

    public DeliveryCheckGate HoldNextDeliveryCheck()
    {
        lock (_gate)
        {
            if (_nextDeliveryCheckGate is not null) throw new InvalidOperationException("A delivery check is already held.");
            return _nextDeliveryCheckGate = new DeliveryCheckGate();
        }
    }

    public TestOutboxSnapshot? GetOutboxSnapshot(string secretId)
    {
        lock (_gate)
        {
            var item = _outbox.Values.SingleOrDefault(candidate => candidate.SecretId == secretId);
            return item is null ? null : ToSnapshot(item);
        }
    }

    public bool HasChallenge(string secretId)
    {
        lock (_gate) return _challenges.ContainsKey(secretId);
    }

    public Task RequestCodeAsync(string secretId, IPAddress clientIp, byte[] codeMac, EncryptedEmailCode encryptedCode, DateTimeOffset now, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        lock (_gate)
        {
            _recordedRequests++;
            if (!isAvailable || !_emailSecrets.TryGetValue(secretId, out var address))
                return Task.CompletedTask;

            if (_challenges.TryGetValue(secretId, out var previous)) previous.Delivery.Invalidated.TrySetResult(true);
            foreach (var oldOutboxId in _outbox.Values.Where(item => item.SecretId == secretId).Select(item => item.Id).ToArray())
                _outbox.Remove(oldOutboxId);

            var delivery = new DeliverySignal();
            _deliverySignals[secretId] = delivery;
            _challenges[secretId] = new Challenge(codeMac.ToArray(), address, now.AddMinutes(5), false, 0, delivery);
            var outboxId = ++_nextOutboxId;
            _outbox[outboxId] = new OutboxItem(
                outboxId, secretId, codeMac.ToArray(),
                new EncryptedEmailCode(encryptedCode.Nonce.ToArray(), encryptedCode.Ciphertext.ToArray(), encryptedCode.Tag.ToArray()),
                address, now.AddMinutes(5), now);
            return Task.CompletedTask;
        }
    }

    public Task<ClaimedEmailDelivery?> ClaimDeliveryAsync(DateTimeOffset now, TimeSpan leaseDuration, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        lock (_gate)
        {
            foreach (var candidate in _outbox.Values.OrderBy(item => item.Id).ToArray())
            {
                if (candidate.ExpiresAt <= now || candidate.LeaseUntil > now ||
                    !_challenges.TryGetValue(candidate.SecretId, out var challenge) || challenge.Active || challenge.ExpiresAt <= now ||
                    !CryptographicOperations.FixedTimeEquals(challenge.CodeMac, candidate.CodeMac) ||
                    !_emailSecrets.TryGetValue(candidate.SecretId, out var recipient)) continue;

                var leased = candidate with { LeaseUntil = now.Add(leaseDuration), LeaseToken = Guid.NewGuid(), Attempts = candidate.Attempts + 1 };
                _outbox[candidate.Id] = leased;
                return Task.FromResult<ClaimedEmailDelivery?>(ToClaimedDelivery(leased, recipient));
            }
            return Task.FromResult<ClaimedEmailDelivery?>(null);
        }
    }

    public async Task<bool> IsDeliveryCurrentAsync(ClaimedEmailDelivery delivery, DateTimeOffset now, CancellationToken cancellationToken = default)
    {
        DeliveryCheckGate? gate;
        lock (_gate)
        {
            gate = _nextDeliveryCheckGate;
            _nextDeliveryCheckGate = null;
        }
        if (gate is not null)
        {
            gate.SignalStarted();
            await gate.WaitForReleaseAsync(cancellationToken);
        }

        cancellationToken.ThrowIfCancellationRequested();
        lock (_gate)
        {
            if (_deliverySignals.TryGetValue(delivery.SecretId, out var signal)) signal.Checked.TrySetResult(true);
            return _outbox.TryGetValue(delivery.OutboxId, out var item) &&
                item.LeaseToken == delivery.LeaseToken && item.LeaseUntil > now && item.ExpiresAt > now &&
                item.SecretId == delivery.SecretId && CryptographicOperations.FixedTimeEquals(item.CodeMac, delivery.CodeMac) &&
                _challenges.TryGetValue(delivery.SecretId, out var challenge) && !challenge.Active && challenge.ExpiresAt > now &&
                CryptographicOperations.FixedTimeEquals(challenge.CodeMac, delivery.CodeMac) && _emailSecrets.ContainsKey(delivery.SecretId);
        }
    }

    public Task CompleteDeliveryAsync(ClaimedEmailDelivery delivery, DateTimeOffset now, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        lock (_gate)
        {
            if (_outbox.TryGetValue(delivery.OutboxId, out var item) && MatchesLease(item, delivery))
            {
                _outbox.Remove(item.Id);
                if (_challenges.TryGetValue(delivery.SecretId, out var challenge) && !challenge.Active && challenge.ExpiresAt > now &&
                    CryptographicOperations.FixedTimeEquals(challenge.CodeMac, delivery.CodeMac))
                {
                    _challenges[delivery.SecretId] = challenge with { Active = true };
                    challenge.Delivery.Activated.TrySetResult(true);
                }
            }
        }
        return Task.CompletedTask;
    }

    public Task FailDeliveryAsync(ClaimedEmailDelivery delivery, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        lock (_gate)
        {
            if (_outbox.TryGetValue(delivery.OutboxId, out var item) && MatchesLease(item, delivery))
            {
                _outbox.Remove(item.Id);
                if (_challenges.TryGetValue(delivery.SecretId, out var challenge) && !challenge.Active &&
                    CryptographicOperations.FixedTimeEquals(challenge.CodeMac, delivery.CodeMac))
                {
                    _challenges.Remove(delivery.SecretId);
                    challenge.Delivery.Invalidated.TrySetResult(true);
                }
            }
        }
        return Task.CompletedTask;
    }

    public Task DiscardDeliveryAsync(ClaimedEmailDelivery delivery, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        lock (_gate)
        {
            if (_outbox.TryGetValue(delivery.OutboxId, out var item) && MatchesLease(item, delivery)) _outbox.Remove(item.Id);
            if (_deliverySignals.TryGetValue(delivery.SecretId, out var signal)) signal.Discarded.TrySetResult(true);
        }
        return Task.CompletedTask;
    }

    public Task<EmailCodeVerificationStatus> VerifyCodeAsync(string secretId, IPAddress clientIp, byte[] codeMac, byte[] sessionMac, DateTimeOffset now, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        lock (_gate)
        {
            if (!_emailSecrets.ContainsKey(secretId) || !_challenges.TryGetValue(secretId, out var challenge) || !challenge.Active || challenge.ExpiresAt <= now)
                return Task.FromResult(EmailCodeVerificationStatus.Invalid);

            if (!CryptographicOperations.FixedTimeEquals(challenge.CodeMac, codeMac))
            {
                var attempts = challenge.Attempts + 1;
                if (attempts >= 3)
                {
                    _challenges.Remove(secretId);
                    challenge.Delivery.Invalidated.TrySetResult(true);
                }
                else _challenges[secretId] = challenge with { Attempts = attempts };
                return Task.FromResult(EmailCodeVerificationStatus.Invalid);
            }

            _challenges.Remove(secretId);
            _sessions[secretId] = new Session(sessionMac.ToArray(), now.AddMinutes(30));
            return Task.FromResult(EmailCodeVerificationStatus.Verified);
        }
    }

    public Task<EmailSecretAccessStatus> CheckAccessAsync(string secretId, byte[] sessionMac, DateTimeOffset now, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        lock (_gate)
        {
            if (!_emailSecrets.ContainsKey(secretId)) return Task.FromResult(EmailSecretAccessStatus.NotFound);
            if (_sessions.TryGetValue(secretId, out var session) && session.ExpiresAt > now && CryptographicOperations.FixedTimeEquals(session.SessionMac, sessionMac))
                return Task.FromResult(EmailSecretAccessStatus.Authorized);
            return Task.FromResult(EmailSecretAccessStatus.VerificationRequired);
        }
    }

    public Task CleanupAsync(DateTimeOffset now, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        lock (_gate)
        {
            foreach (var secretId in _challenges.Where(pair => pair.Value.Active && pair.Value.ExpiresAt <= now).Select(pair => pair.Key).ToArray()) _challenges.Remove(secretId);
            foreach (var secretId in _sessions.Where(pair => pair.Value.ExpiresAt <= now).Select(pair => pair.Key).ToArray()) _sessions.Remove(secretId);
        }
        return Task.CompletedTask;
    }

    private DeliverySignal GetDeliverySignal(string secretId)
    {
        lock (_gate)
            return _deliverySignals.TryGetValue(secretId, out var signal)
                ? signal
                : throw new InvalidOperationException($"No delivery signal exists for secret {secretId}.");
    }

    private static bool MatchesLease(OutboxItem item, ClaimedEmailDelivery delivery) =>
        item.Id == delivery.OutboxId && item.LeaseToken == delivery.LeaseToken && item.SecretId == delivery.SecretId &&
        CryptographicOperations.FixedTimeEquals(item.CodeMac, delivery.CodeMac);

    private static ClaimedEmailDelivery ToClaimedDelivery(OutboxItem item, string recipient) => new(
        item.Id, item.LeaseToken!.Value, item.SecretId, item.CodeMac.ToArray(), item.Payload.Nonce.ToArray(),
        item.Payload.Ciphertext.ToArray(), item.Payload.Tag.ToArray(), recipient);

    private static TestOutboxSnapshot ToSnapshot(OutboxItem item) => new(
        item.Id, item.SecretId, item.CodeMac.ToArray(), item.Payload.Nonce.ToArray(), item.Payload.Ciphertext.ToArray(),
        item.Payload.Tag.ToArray(), item.ExpiresAt, item.LeaseUntil, item.LeaseToken, item.Attempts);

    private sealed record Challenge(byte[] CodeMac, string Recipient, DateTimeOffset ExpiresAt, bool Active, int Attempts, DeliverySignal Delivery);
    private sealed record Session(byte[] SessionMac, DateTimeOffset ExpiresAt);
    private sealed record OutboxItem(long Id, string SecretId, byte[] CodeMac, EncryptedEmailCode Payload, string Recipient,
        DateTimeOffset ExpiresAt, DateTimeOffset CreatedAt, DateTimeOffset? LeaseUntil = null, Guid? LeaseToken = null, int Attempts = 0);

    private sealed class DeliverySignal
    {
        public TaskCompletionSource<bool> Activated { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public TaskCompletionSource<bool> Invalidated { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public TaskCompletionSource<bool> Checked { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public TaskCompletionSource<bool> Discarded { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
    }

    internal sealed class DeliveryCheckGate
    {
        private readonly TaskCompletionSource<bool> _started = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private readonly TaskCompletionSource<bool> _release = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public Task WaitForStartedAsync(CancellationToken cancellationToken = default) => _started.Task.WaitAsync(cancellationToken);
        public void Release() => _release.TrySetResult(true);
        internal void SignalStarted() => _started.TrySetResult(true);
        internal Task WaitForReleaseAsync(CancellationToken cancellationToken) => _release.Task.WaitAsync(cancellationToken);
    }
}

internal sealed record TestOutboxSnapshot(long OutboxId, string SecretId, byte[] CodeMac, byte[] Nonce, byte[] Ciphertext,
    byte[] Tag, DateTimeOffset ExpiresAt, DateTimeOffset? LeaseUntil, Guid? LeaseToken, int Attempts);

internal sealed class TestEmailSender : IEmailSender
{
    private readonly object _gate = new();
    private readonly List<EmailMessage> _messages = [];
    private readonly Exception? _sendFailure;
    private readonly TaskCompletionSource<bool> _started = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly TaskCompletionSource<bool> _release = new(TaskCreationOptions.RunContinuationsAsynchronously);

    public TestEmailSender(Exception? sendFailure = null, bool blockSending = false)
    {
        _sendFailure = sendFailure;
        IsReleased = !blockSending;
        if (!blockSending) _release.TrySetResult(true);
    }

    public bool IsReleased { get; private set; }

    public IReadOnlyList<EmailMessage> Messages
    {
        get { lock (_gate) return _messages.ToArray(); }
    }

    public Task WaitForSendStartedAsync(CancellationToken cancellationToken = default) => _started.Task.WaitAsync(cancellationToken);

    public void ReleaseDelivery()
    {
        IsReleased = true;
        _release.TrySetResult(true);
    }

    public async Task SendAsync(EmailMessage message, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        lock (_gate) _messages.Add(message);
        _started.TrySetResult(true);
        await _release.Task.WaitAsync(cancellationToken);
        if (_sendFailure is not null) throw _sendFailure;
    }

    public string? LastCode => Messages.LastOrDefault() is { } message
        ? Regex.Match(message.TextBody, @"\b\d{6}\b").Value is { Length: 6 } code ? code : null
        : null;
}
