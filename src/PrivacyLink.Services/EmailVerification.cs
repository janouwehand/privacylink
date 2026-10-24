using System.Globalization;
using System.Net;
using System.Net.Mail;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Configuration;

namespace PrivacyLink.Services;

public sealed record EmailMessage(string Recipient, string Subject, string TextBody, string HtmlBody);

public interface IEmailSender
{
    Task SendAsync(EmailMessage message, CancellationToken cancellationToken = default);
}

public sealed class EmailVerificationOptions
{
    private static readonly byte[] OutboxKeyPurpose = Encoding.UTF8.GetBytes("PrivacyLink:EmailVerification:outbox-encryption:v1");

    private EmailVerificationOptions(byte[]? hmacKey, string? resendApiKey, string? fromAddress)
    {
        HmacKey = hmacKey;
        OutboxEncryptionKey = hmacKey is { Length: >= 32 } ? HMACSHA256.HashData(hmacKey, OutboxKeyPurpose) : null;
        ResendApiKey = resendApiKey;
        FromAddress = fromAddress;
        HasSenderConfiguration = !string.IsNullOrWhiteSpace(resendApiKey) && EmailAddress.TryNormalize(fromAddress, out _);
    }

    public byte[]? HmacKey { get; }
    public byte[]? OutboxEncryptionKey { get; }
    public string? ResendApiKey { get; }
    public string? FromAddress { get; }
    public bool HasHmacKey => HmacKey is { Length: >= 32 };
    public bool HasSenderConfiguration { get; }
    public bool IsConfigured => HasHmacKey && HasSenderConfiguration;

    public EncryptedEmailCode EncryptCode(string secretId, byte[] codeMac, string code)
    {
        var key = OutboxEncryptionKey ?? throw new InvalidOperationException("Email verification encryption key is unavailable.");
        var nonce = RandomNumberGenerator.GetBytes(12);
        var plaintext = Encoding.ASCII.GetBytes(code);
        var ciphertext = new byte[plaintext.Length];
        var tag = new byte[16];
        using var aes = new AesGcm(key, tag.Length);
        aes.Encrypt(nonce, plaintext, ciphertext, tag, OutboxAssociatedData(secretId, codeMac));
        CryptographicOperations.ZeroMemory(plaintext);
        return new EncryptedEmailCode(nonce, ciphertext, tag);
    }

    public string DecryptCode(ClaimedEmailDelivery delivery)
    {
        var key = OutboxEncryptionKey ?? throw new InvalidOperationException("Email verification encryption key is unavailable.");
        var plaintext = new byte[delivery.Ciphertext.Length];
        using var aes = new AesGcm(key, delivery.Tag.Length);
        aes.Decrypt(delivery.Nonce, delivery.Ciphertext, delivery.Tag, plaintext, OutboxAssociatedData(delivery.SecretId, delivery.CodeMac));
        try
        {
            var code = Encoding.ASCII.GetString(plaintext);
            if (code.Length != 6 || code.Any(character => character is < '0' or > '9'))
                throw new CryptographicException("Stored email verification code is invalid.");
            return code;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plaintext);
        }
    }

    private static byte[] OutboxAssociatedData(string secretId, byte[] codeMac) =>
        [.. Encoding.UTF8.GetBytes($"PrivacyLink:EmailVerification:outbox:v1\0{secretId}\0"), .. codeMac];

    public static EmailVerificationOptions FromConfiguration(IConfiguration configuration)
    {
        byte[]? key = null;
        var keyText = configuration["Security:EmailVerificationHmacKey"];
        if (!string.IsNullOrWhiteSpace(keyText))
        {
            try
            {
                var decoded = Convert.FromBase64String(keyText);
                if (decoded.Length >= 32 && Convert.ToBase64String(decoded) == keyText &&
                    !MatchesKey(decoded, configuration["Security:PasswordPepper"]) &&
                    !MatchesKey(decoded, configuration["Security:AuditHashKey"]) &&
                    !MatchesKey(decoded, configuration["Security:CreateProofHmacKey"])) key = decoded;
            }
            catch (FormatException) { }
        }
        return new EmailVerificationOptions(key, configuration["Resend:ApiKey"], configuration["Resend:FromAddress"]);
    }

    private static bool MatchesKey(byte[] key, string? other)
    {
        if (string.IsNullOrWhiteSpace(other)) return false;
        var raw = Encoding.UTF8.GetBytes(other);
        if (raw.Length == key.Length && CryptographicOperations.FixedTimeEquals(key, raw)) return true;
        try
        {
            var decoded = Convert.FromBase64String(other);
            return decoded.Length == key.Length && CryptographicOperations.FixedTimeEquals(key, decoded);
        }
        catch (FormatException) { return false; }
    }
}

public static class EmailAddress
{
    public static bool TryNormalize(string? supplied, out string normalized)
    {
        normalized = string.Empty;
        if (string.IsNullOrWhiteSpace(supplied) || supplied.Length > 254 || supplied.Any(char.IsControl) || supplied.Any(char.IsWhiteSpace)) return false;
        if (!MailAddress.TryCreate(supplied, out var parsed) || !string.Equals(parsed.Address, supplied, StringComparison.OrdinalIgnoreCase)) return false;
        var separator = supplied.LastIndexOf('@');
        if (separator is < 1 or > 64 || separator == supplied.Length - 1) return false;
        var domain = supplied[(separator + 1)..];
        if (domain.Length > 253 || !domain.Contains('.')) return false;
        var labels = domain.Split('.');
        if (labels.Any(label => label.Length is < 1 or > 63 || label[0] == '-' || label[^1] == '-' ||
            label.Any(character => !char.IsAsciiLetterOrDigit(character) && character != '-'))) return false;
        normalized = parsed.Address.ToLowerInvariant();
        return true;
    }
}

public sealed record EmailCodeVerificationOutcome(EmailCodeVerificationStatus Status, string? SessionToken = null);

public sealed class EmailVerificationService(
    ISecretRepository secrets,
    IEmailVerificationStore store,
    EmailVerificationOptions options,
    TimeProvider clock)
{
    public bool CanCreateEmailProtectedSecrets => store.IsAvailable && options.IsConfigured;

    public Task RecordRequestAsync(IPAddress? clientIp, CancellationToken cancellationToken = default)
    {
        if (clientIp is null || !store.IsAvailable || !options.HasHmacKey) return Task.CompletedTask;
        return store.RecordRequestAsync(NormalizeIp(clientIp), clock.GetUtcNow(), cancellationToken);
    }

    public async Task RequestCodeAsync(string secretId, IPAddress? clientIp, CancellationToken cancellationToken = default)
    {
        if (clientIp is null || !store.IsAvailable || !options.HasHmacKey) return;

        var normalizedIp = NormalizeIp(clientIp);
        var code = RandomNumberGenerator.GetInt32(0, 1_000_000).ToString("D6", CultureInfo.InvariantCulture);
        var codeMac = ComputeMac("challenge", secretId, code);
        var encryptedCode = options.EncryptCode(secretId, codeMac, code);
        await store.RequestCodeAsync(secretId, normalizedIp, codeMac, encryptedCode, clock.GetUtcNow(), cancellationToken);
    }

    public async Task<EmailCodeVerificationStatus> RecordFailedCodeInputAsync(IPAddress? clientIp, CancellationToken cancellationToken = default)
    {
        if (clientIp is null || !store.IsAvailable || !options.HasHmacKey) return EmailCodeVerificationStatus.Invalid;
        return await store.RecordFailedCodeInputAsync(NormalizeIp(clientIp), clock.GetUtcNow(), cancellationToken);
    }

    public async Task<EmailCodeVerificationOutcome> VerifyCodeAsync(string secretId, IPAddress? clientIp, string code, CancellationToken cancellationToken = default)
    {
        if (clientIp is null || !store.IsAvailable || !options.HasHmacKey)
            return new EmailCodeVerificationOutcome(EmailCodeVerificationStatus.Invalid);

        var tokenBytes = RandomNumberGenerator.GetBytes(32);
        var token = Encode(tokenBytes);
        var codeMac = ComputeMac("challenge", secretId, code);
        var sessionMac = ComputeMac("session", secretId, token);
        var status = await store.VerifyCodeAsync(secretId, NormalizeIp(clientIp), codeMac, sessionMac, clock.GetUtcNow(), cancellationToken);
        return new EmailCodeVerificationOutcome(status, status == EmailCodeVerificationStatus.Verified ? token : null);
    }

    public async Task<EmailSecretAccessStatus> CheckAccessAsync(string secretId, string? sessionToken, CancellationToken cancellationToken = default)
    {
        var now = clock.GetUtcNow();
        var secret = await secrets.GetAsync(secretId, now, cancellationToken);
        if (secret is null) return EmailSecretAccessStatus.NotFound;
        if (secret.EmailAddress is null) return EmailSecretAccessStatus.NotRequired;
        if (!store.IsAvailable || !options.HasHmacKey) return EmailSecretAccessStatus.VerificationRequired;
        byte[] sessionMac = [];
        if (!string.IsNullOrEmpty(sessionToken)) sessionMac = ComputeMac("session", secretId, sessionToken);
        return await store.CheckAccessAsync(secretId, sessionMac, now, cancellationToken);
    }

    public static string MaskAddress(string address)
    {
        var separator = address.LastIndexOf('@');
        if (separator <= 0) return "***";
        var local = address[..separator];
        var visible = local.Length <= 1 ? "*" : string.Concat(local[0], "***");
        return $"{visible}{address[separator..]}";
    }

    public static EmailMessage CreateMessage(string recipient, string code) => new(
        recipient,
        "Your PrivacyLink verification code",
        $"Your PrivacyLink verification code is {code}. It expires in five minutes. If you did not request this code, you can ignore this email.",
        $"<p>Your PrivacyLink verification code is:</p><p style=\"font-size:24px;font-weight:700;letter-spacing:0.2em\">{code}</p><p>It expires in five minutes. If you did not request this code, you can ignore this email.</p>");

    private byte[] ComputeMac(string purpose, string secretId, string value)
    {
        var key = options.HmacKey ?? throw new InvalidOperationException("Email verification key is unavailable.");
        var input = Encoding.UTF8.GetBytes($"PrivacyLink:EmailVerification:{purpose}\0{secretId}\0{value}");
        return HMACSHA256.HashData(key, input);
    }

    private static IPAddress NormalizeIp(IPAddress address) => address.IsIPv4MappedToIPv6 ? address.MapToIPv4() : address;

    private static string Encode(byte[] bytes) => Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
}
