using Microsoft.Extensions.Configuration;
using PrivacyLink.Api;

public sealed class UnlockAttemptTests
{
    [Fact]
    public async Task AttemptLimitIsAtomicAcrossConcurrentCallersAndCooldownDoesNotExtend()
    {
        var repository = new InMemorySecretRepository(new ConfigurationBuilder().Build());
        var now = DateTimeOffset.Parse("2026-09-27T10:00:00Z");
        await repository.CreateAsync(new StoredSecret("secret", now.AddDays(1), null, null, 1, [], PasswordSalt: "salt"));

        var admissions = await Task.WhenAll(Enumerable.Range(0, 20).Select(_ => repository.ReserveUnlockAttemptAsync(
            "secret", now, maxAttempts: 5, TimeSpan.FromMinutes(15), TimeSpan.FromMinutes(15))));

        Assert.Equal(5, admissions.Count(admission => admission.Allowed));
        Assert.All(admissions.Where(admission => !admission.Allowed), admission => Assert.Equal(now.AddMinutes(15), admission.RetryAt));

        var laterBlocked = await repository.ReserveUnlockAttemptAsync("secret", now.AddMinutes(5), 5, TimeSpan.FromMinutes(15), TimeSpan.FromMinutes(15));
        Assert.False(laterBlocked.Allowed);
        Assert.Equal(now.AddMinutes(15), laterBlocked.RetryAt);

        var afterCooldown = await repository.ReserveUnlockAttemptAsync("secret", now.AddMinutes(16), 5, TimeSpan.FromMinutes(15), TimeSpan.FromMinutes(15));
        Assert.True(afterCooldown.Allowed);
    }

    [Fact]
    public async Task SuccessfulUnlockCanResetAttemptState()
    {
        var repository = new InMemorySecretRepository(new ConfigurationBuilder().Build());
        var now = DateTimeOffset.UtcNow;
        await repository.CreateAsync(new StoredSecret("secret", now.AddDays(1), null, null, 1, [], PasswordSalt: "salt"));
        await repository.ReserveUnlockAttemptAsync("secret", now, 1, TimeSpan.FromMinutes(15), TimeSpan.FromMinutes(15));
        Assert.False((await repository.ReserveUnlockAttemptAsync("secret", now, 1, TimeSpan.FromMinutes(15), TimeSpan.FromMinutes(15))).Allowed);

        await repository.ResetUnlockAttemptsAsync("secret");

        Assert.True((await repository.ReserveUnlockAttemptAsync("secret", now, 1, TimeSpan.FromMinutes(15), TimeSpan.FromMinutes(15))).Allowed);
    }
}
