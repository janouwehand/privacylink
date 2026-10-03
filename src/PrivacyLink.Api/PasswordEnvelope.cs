using System.Security.Cryptography;
using System.Text;
using Konscious.Security.Cryptography;

namespace PrivacyLink.Api;

internal sealed record PasswordEnvelope(byte[] Salt, byte[] Nonce, byte[] Ciphertext);

internal sealed class PasswordEnvelopeService(IConfiguration configuration)
{
    private readonly byte[]? _pepper = ReadPepper(configuration);
    private readonly int _memorySizeKb = ReadBounded(configuration, "Security:Argon2:MemorySizeKb", 65536, 8192, 1024 * 1024);
    private readonly int _iterations = ReadBounded(configuration, "Security:Argon2:Iterations", 3, 1, 20);
    private readonly int _degreeOfParallelism = ReadBounded(configuration, "Security:Argon2:DegreeOfParallelism", 2, 1, 16);
    // The service is a singleton, so this is a process-wide limit shared by protected create and unlock.
    private readonly Argon2ConcurrencyGate _argon2Gate = new(
        ReadBounded(configuration, "Security:Argon2:MaxConcurrentOperations", 2, 1, 8),
        ReadBounded(configuration, "Security:Argon2:MaxQueuedUnlocks", 8, 0, 64),
        TimeSpan.FromSeconds(ReadBounded(configuration, "Security:Argon2:UnlockQueueTimeoutSeconds", 30, 1, 120)));

    public async Task<PasswordEnvelope> EncryptAsync(string password, ReadOnlyMemory<byte> plaintext, CancellationToken cancellationToken = default)
    {
        var salt = RandomNumberGenerator.GetBytes(16);
        var key = await DeriveKeyAsync(password, salt, cancellationToken);
        return EncryptWithKey(key, salt, plaintext);
    }

    public async Task<PasswordEnvelopeSession> CreateSessionAsync(string password, CancellationToken cancellationToken = default)
    {
        var salt = RandomNumberGenerator.GetBytes(16);
        var key = await DeriveKeyAsync(password, salt, cancellationToken);
        return new PasswordEnvelopeSession(salt, key);
    }

    public async Task<PasswordEnvelopeSession> OpenSessionAsync(string password, byte[] salt, CancellationToken cancellationToken = default, Func<CancellationToken, Task>? beforeKdf = null) =>
        new(salt, await DeriveKeyAsync(password, salt, cancellationToken, queueWhenBusy: true, beforeKdf));

    internal static PasswordEnvelope EncryptWithKey(byte[] key, byte[] salt, ReadOnlyMemory<byte> plaintext)
    {
        var nonce = RandomNumberGenerator.GetBytes(12);
        var ciphertext = new byte[plaintext.Length + 16];
        using var aes = new AesGcm(key, 16);
        aes.Encrypt(nonce, plaintext.Span, ciphertext.AsSpan(0, plaintext.Length), ciphertext.AsSpan(plaintext.Length));
        return new PasswordEnvelope(salt, nonce, ciphertext);
    }

    public async Task<byte[]> DecryptAsync(string password, PasswordEnvelope envelope, CancellationToken cancellationToken = default)
    {
        if (envelope.Salt.Length != 16 || envelope.Nonce.Length != 12 || envelope.Ciphertext.Length < 17) throw new CryptographicException();
        var key = await DeriveKeyAsync(password, envelope.Salt, cancellationToken);
        var plaintext = new byte[envelope.Ciphertext.Length - 16];
        try
        {
            using var aes = new AesGcm(key, 16);
            aes.Decrypt(envelope.Nonce, envelope.Ciphertext.AsSpan(0, plaintext.Length), envelope.Ciphertext.AsSpan(plaintext.Length), plaintext);
            return plaintext;
        }
        finally { CryptographicOperations.ZeroMemory(key); }
    }

    private async Task<byte[]> DeriveKeyAsync(string password, byte[] salt, CancellationToken cancellationToken, bool queueWhenBusy = false, Func<CancellationToken, Task>? beforeKdf = null)
    {
        cancellationToken.ThrowIfCancellationRequested();
        using var slot = await _argon2Gate.AcquireAsync(queueWhenBusy, cancellationToken);

        byte[]? passwordBytes = null;
        byte[]? pepperedPassword = null;
        byte[]? key = null;
        try
        {
            cancellationToken.ThrowIfCancellationRequested();
            passwordBytes = Encoding.UTF8.GetBytes(password);
            var pepper = _pepper ?? throw new InvalidOperationException("Security:PasswordPepper is required for password protection.");
            pepperedPassword = HMACSHA256.HashData(pepper, passwordBytes);
            CryptographicOperations.ZeroMemory(passwordBytes);
            passwordBytes = null;

            var argon = new Argon2id(pepperedPassword)
            {
                Salt = salt,
                MemorySize = _memorySizeKb,
                Iterations = _iterations,
                DegreeOfParallelism = _degreeOfParallelism
            };
            if (beforeKdf is not null) await beforeKdf(cancellationToken).ConfigureAwait(false);
            cancellationToken.ThrowIfCancellationRequested();
            // Konscious does not expose a cancellation token. Await its actual task so the
            // permit remains held until native/managed KDF work has really stopped.
            key = await argon.GetBytesAsync(32).ConfigureAwait(false);
            cancellationToken.ThrowIfCancellationRequested();
            var result = key;
            key = null;
            return result;
        }
        finally
        {
            if (passwordBytes is not null) CryptographicOperations.ZeroMemory(passwordBytes);
            if (pepperedPassword is not null) CryptographicOperations.ZeroMemory(pepperedPassword);
            if (key is not null) CryptographicOperations.ZeroMemory(key);
        }
    }

    private static byte[]? ReadPepper(IConfiguration configuration)
    {
        var value = SecretStoreConfiguration.ReadPasswordPepper(configuration, isProduction: false);
        return string.IsNullOrWhiteSpace(value) ? null : Encoding.UTF8.GetBytes(value);
    }

    private static int ReadBounded(IConfiguration configuration, string key, int fallback, int minimum, int maximum) =>
        int.TryParse(configuration[key], out var value) && value >= minimum && value <= maximum ? value : fallback;
}

internal sealed class PasswordEnvelopeCapacityException : Exception { }

internal sealed class Argon2ConcurrencyGate(int maxConcurrent, int maxQueuedUnlocks, TimeSpan unlockQueueTimeout)
{
    private readonly SemaphoreSlim _slots = new(maxConcurrent);
    private int _queuedUnlocks;
    internal int QueuedUnlocks => Volatile.Read(ref _queuedUnlocks);

    internal async Task<IDisposable> AcquireAsync(bool queueWhenBusy, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (Volatile.Read(ref _queuedUnlocks) == 0 && _slots.Wait(0)) return new Slot(_slots);
        if (!queueWhenBusy || maxQueuedUnlocks == 0) throw new PasswordEnvelopeCapacityException();

        var queued = Interlocked.Increment(ref _queuedUnlocks);
        if (queued > maxQueuedUnlocks)
        {
            Interlocked.Decrement(ref _queuedUnlocks);
            if (_slots.Wait(0)) return new Slot(_slots);
            cancellationToken.ThrowIfCancellationRequested();
            throw new PasswordEnvelopeCapacityException();
        }

        using var timeout = new CancellationTokenSource(unlockQueueTimeout);
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, timeout.Token);
        try
        {
            await _slots.WaitAsync(linked.Token).ConfigureAwait(false);
            return new Slot(_slots);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested && timeout.IsCancellationRequested)
        {
            throw new PasswordEnvelopeCapacityException();
        }
        finally
        {
            Interlocked.Decrement(ref _queuedUnlocks);
        }
    }

    private sealed class Slot(SemaphoreSlim slots) : IDisposable
    {
        private SemaphoreSlim? _slots = slots;
        public void Dispose() => Interlocked.Exchange(ref _slots, null)?.Release();
    }
}

internal sealed class PasswordEnvelopeSession(byte[] salt, byte[] key) : IDisposable
{
    public PasswordEnvelope Encrypt(ReadOnlyMemory<byte> plaintext) => PasswordEnvelopeService.EncryptWithKey(key, salt, plaintext);
    public byte[] Decrypt(PasswordEnvelope envelope)
    {
        var plaintext = new byte[envelope.Ciphertext.Length - 16];
        using var aes = new AesGcm(key, 16);
        aes.Decrypt(envelope.Nonce, envelope.Ciphertext.AsSpan(0, plaintext.Length), envelope.Ciphertext.AsSpan(plaintext.Length), plaintext);
        return plaintext;
    }
    public byte[] Salt => salt;
    public void Dispose() => CryptographicOperations.ZeroMemory(key);
}
