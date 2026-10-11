using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using PrivacyLink.Contracts;
using PrivacyLink.Services;

namespace PrivacyLink.Api;

internal sealed class CreateProofOfWork
{
    private const string ChallengeDomain = "PrivacyLink-Create-Challenge-v1\n";
    private const string ProofDomain = "PrivacyLink-Create-PoW-v1:";
    private readonly byte[] _key;
    private readonly int _difficultyBits;
    private readonly ICreateProofReplayStore _replayStore;
    private readonly TimeProvider _clock;

    public CreateProofOfWork(IConfiguration configuration, ICreateProofReplayStore replayStore, TimeProvider clock)
    {
        _key = SecurityKeyUtilities.RequireExactKey(configuration["Security:CreateProofHmacKey"], "Security:CreateProofHmacKey", 32);
        if (!int.TryParse(configuration["Security:CreateProofDifficultyBits"], NumberStyles.None, CultureInfo.InvariantCulture, out var difficultyBits) || difficultyBits is < 1 or > 24)
            throw new InvalidOperationException("Security:CreateProofDifficultyBits must be an integer from 1 through 24.");
        _difficultyBits = difficultyBits;
        _replayStore = replayStore;
        _clock = clock;
    }

    public CreateChallengeResponse Issue()
    {
        var id = Encode(RandomNumberGenerator.GetBytes(16));
        var nonce = Encode(RandomNumberGenerator.GetBytes(16));
        var expiresAt = _clock.GetUtcNow().AddMinutes(5).ToUnixTimeSeconds();
        var signature = Sign(id, nonce, _difficultyBits, expiresAt);
        return new CreateChallengeResponse(1, id, nonce, _difficultyBits, expiresAt, signature);
    }

    public async Task<ProofCheckResult> ValidateAndConsumeAsync(string? header, CancellationToken cancellationToken)
    {
        if (!TryParse(header, out var id, out var nonce, out var bits, out var expiresAt, out var signature, out var counter))
            return ProofCheckResult.Invalid;
        var expected = Decode(Sign(id, nonce, bits, expiresAt), 32);
        if (!CryptographicOperations.FixedTimeEquals(signature, expected)) return ProofCheckResult.Invalid;
        var now = _clock.GetUtcNow();
        var nowSeconds = now.ToUnixTimeSeconds();
        if (expiresAt <= nowSeconds || expiresAt > nowSeconds + 300) return ProofCheckResult.Invalid;
        if (!HasLeadingZeroBits(SHA256.HashData(Encoding.UTF8.GetBytes($"{ProofDomain}{id}:{nonce}:{counter}")), bits))
            return ProofCheckResult.Invalid;
        try
        {
            var consumed = await _replayStore.TryConsumeAsync(id, DateTimeOffset.FromUnixTimeSeconds(expiresAt), now, cancellationToken);
            return consumed switch
            {
                CreateProofConsumeResult.Consumed => ProofCheckResult.Valid,
                CreateProofConsumeResult.Full => ProofCheckResult.Unavailable,
                _ => ProofCheckResult.Invalid
            };
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
        catch { return ProofCheckResult.Unavailable; }
    }

    private string Sign(string id, string nonce, int bits, long expiresAt)
    {
        var message = string.Concat(ChallengeDomain, id, "\n", nonce, "\n", bits.ToString(CultureInfo.InvariantCulture), "\n", expiresAt.ToString(CultureInfo.InvariantCulture));
        return Encode(HMACSHA256.HashData(_key, Encoding.UTF8.GetBytes(message)));
    }

    private static bool TryParse(string? header, out string id, out string nonce, out int bits, out long expiresAt, out byte[] signature, out string counter)
    {
        id = nonce = counter = string.Empty;
        bits = 0;
        expiresAt = 0;
        signature = [];
        if (string.IsNullOrEmpty(header) || header.Length > 160 || header.Any(c => c > 0x7f)) return false;
        var fields = header.Split('.');
        if (fields.Length != 6) return false;
        id = fields[0]; nonce = fields[1];
        if (!TryDecode(fields[0], 16, out _) || !TryDecode(fields[1], 16, out _)) return false;
        if (!int.TryParse(fields[2], NumberStyles.None, CultureInfo.InvariantCulture, out bits) || bits is < 1 or > 24 || bits.ToString(CultureInfo.InvariantCulture) != fields[2]) return false;
        if (!long.TryParse(fields[3], NumberStyles.None, CultureInfo.InvariantCulture, out expiresAt) || expiresAt.ToString(CultureInfo.InvariantCulture) != fields[3]) return false;
        if (!TryDecode(fields[4], 32, out signature)) return false;
        if (fields[5].Length is < 1 or > 20 || fields[5].Length > 1 && fields[5][0] == '0' || fields[5].Any(c => c is < '0' or > '9') || !ulong.TryParse(fields[5], NumberStyles.None, CultureInfo.InvariantCulture, out _)) return false;
        counter = fields[5];
        return true;
    }

    private static bool HasLeadingZeroBits(ReadOnlySpan<byte> hash, int bits)
    {
        var fullBytes = bits / 8;
        for (var i = 0; i < fullBytes; i++) if (hash[i] != 0) return false;
        var remaining = bits % 8;
        return remaining == 0 || (hash[fullBytes] & (0xff << (8 - remaining))) == 0;
    }

    private static bool TryDecode(string value, int expectedLength, out byte[] bytes)
    {
        bytes = [];
        if (value.Length != (expectedLength * 8 + 5) / 6) return false;
        try
        {
            var decoded = Convert.FromBase64String(value.Replace('-', '+').Replace('_', '/') + ((value.Length % 4) switch { 2 => "==", 3 => "=", _ => string.Empty }));
            if (decoded.Length != expectedLength || Encode(decoded) != value) return false;
            bytes = decoded;
            return true;
        }
        catch (FormatException) { return false; }
    }

    private static byte[] Decode(string value, int expectedLength) => TryDecode(value, expectedLength, out var bytes) ? bytes : [];
    private static string Encode(byte[] bytes) => Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
}

internal enum ProofCheckResult { Valid, Invalid, Unavailable }
