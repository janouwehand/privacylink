using System.Security.Cryptography;
using Microsoft.Extensions.Configuration;
using PrivacyLink.Api;
using PrivacyLink.Contracts;

public sealed class SecretStoreTests
{
    [Fact]
    public void ProductionConfigurationRequiresPersistentHttpsBackedSecrets()
    {
        var configuration = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["Security:PasswordPepper"] = "pepper",
            ["Security:SecretStore:Provider"] = "Environment",
            ["Security:RequirePasswordPepper"] = "true",
            ["Security:RequireHttps"] = "true",
            ["Storage:BlobPath"] = "C:\\privacylink\\blobs"
        }).Build();

        var error = Assert.Throws<InvalidOperationException>(() => ProductionConfiguration.Validate(configuration, isProduction: true));

        Assert.Contains("ConnectionStrings:PrivacyLink", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void ProductionConfigurationRequiresAnEnvironmentSecretBinding()
    {
        var configuration = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["Security:PasswordPepper"] = "pepper",
            ["Security:RequirePasswordPepper"] = "true",
            ["Security:RequireHttps"] = "true",
            ["Storage:BlobPath"] = "C:\\privacylink\\blobs",
            ["ConnectionStrings:PrivacyLink"] = "Host=localhost;Database=privacy"
        }).Build();

        var error = Assert.Throws<InvalidOperationException>(() => ProductionConfiguration.Validate(configuration, isProduction: true));

        Assert.Contains("SecretStore:Provider", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void EnvironmentBindingAcceptsHostInjectedSecrets()
    {
        var configuration = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["Security:SecretStore:Provider"] = "Environment",
            ["Security:PasswordPepper"] = "pepper"
        }).Build();

        Assert.Equal("pepper", SecretStoreConfiguration.ReadPasswordPepper(configuration, isProduction: true));
    }

    [Fact]
    public void BlobReconciliationReportsOnlyUnreferencedRelativePaths()
    {
        var orphans = BlobReconciliation.FindOrphans(
            ["secret-a/blob-1", "secret-a/blob-orphan", "secret-b/blob-2"],
            [new BlobReference("secret-a", "blob-1"), new BlobReference("secret-b", "blob-2")]);

        Assert.Equal(["secret-a/blob-orphan"], orphans);
    }

    [Fact]
    public async Task FileBlobStorageRemovesInterruptedTemporaryWritesOnStartup()
    {
        var root = Path.Combine(Path.GetTempPath(), "privacylink-test-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(Path.Combine(root, "secret"));
        await File.WriteAllBytesAsync(Path.Combine(root, "secret", "blob.tmp-ABCD"), [1, 2, 3]);
        await File.WriteAllBytesAsync(Path.Combine(root, "secret", "blob"), [4, 5, 6]);

        try
        {
            var configuration = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Storage:BlobPath"] = root
            }).Build();
            var storage = new FileBlobStorage(configuration);

            await storage.CleanupTemporaryFilesAsync();

            Assert.False(File.Exists(Path.Combine(root, "secret", "blob.tmp-ABCD")));
            Assert.Equal([4, 5, 6], await File.ReadAllBytesAsync(Path.Combine(root, "secret", "blob")));
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task PasswordEnvelopeRoundTripsWithoutStoringThePassword()
    {
        var configuration = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["Security:PasswordPepper"] = "test-only-pepper",
            ["Security:Argon2:MemorySizeKb"] = "8192",
            ["Security:Argon2:Iterations"] = "1",
            ["Security:Argon2:DegreeOfParallelism"] = "1"
        }).Build();
        var service = new PasswordEnvelopeService(configuration);
        var plaintext = new byte[] { 1, 2, 3, 4 };
        var envelope = await service.EncryptAsync("correct horse", plaintext);

        Assert.Equal(16, envelope.Salt.Length);
        Assert.Equal(12, envelope.Nonce.Length);
        Assert.NotEqual(plaintext, envelope.Ciphertext);
        Assert.Equal(plaintext, await service.DecryptAsync("correct horse", envelope, CancellationToken.None));
        await Assert.ThrowsAnyAsync<CryptographicException>(() => service.DecryptAsync("wrong horse", envelope, CancellationToken.None));
    }

    [Fact]
    public async Task ExpiredSecretsCannotBeReadAndAreRemoved()
    {
        var store = new InMemorySecretRepository(new ConfigurationBuilder().Build());
        var now = DateTimeOffset.UtcNow;
        var secret = new StoredSecret("id", now.AddMinutes(1), "nonce", "blob", 1, []);
        Assert.NotNull(await store.CreateAsync(secret));
        Assert.NotNull(await store.GetAsync(secret.Id, now));
        Assert.Null(await store.GetAsync(secret.Id, now.AddMinutes(1)));
        var expired = await store.GetExpiredAsync(now.AddMinutes(1), 100);
        Assert.Single(expired);
        await store.DeleteAsync(secret.Id);
        Assert.Null(await store.GetAsync(secret.Id, now));
    }

    [Fact]
    public async Task ActiveSecretCountIsBounded()
    {
        var config = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["Storage:MaxActiveSecrets"] = "1"
        }).Build();
        var store = new InMemorySecretRepository(config);
        var now = DateTimeOffset.UtcNow.AddDays(1);
        Assert.NotNull(await store.CreateAsync(new StoredSecret("one", now, "n", "blob1", 1, [])));
        Assert.Null(await store.CreateAsync(new StoredSecret("two", now, "n", "blob2", 1, [])));
    }
}
