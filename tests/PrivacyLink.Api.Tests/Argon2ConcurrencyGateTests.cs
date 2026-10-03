using PrivacyLink.Api;

public sealed class Argon2ConcurrencyGateTests
{
    [Fact]
    public async Task ProtectedCreationIsRejectedInsteadOfQueuedWhenBusy()
    {
        var gate = new Argon2ConcurrencyGate(maxConcurrent: 1, maxQueuedUnlocks: 2, unlockQueueTimeout: TimeSpan.FromSeconds(1));
        using var active = await gate.AcquireAsync(queueWhenBusy: false, CancellationToken.None);

        await Assert.ThrowsAsync<PasswordEnvelopeCapacityException>(() => gate.AcquireAsync(queueWhenBusy: false, CancellationToken.None));
        Assert.Equal(0, gate.QueuedUnlocks);
    }

    [Fact]
    public async Task UnlockWaitsForAvailableSlotAndQueueHasConfiguredCapacity()
    {
        var gate = new Argon2ConcurrencyGate(maxConcurrent: 1, maxQueuedUnlocks: 1, unlockQueueTimeout: TimeSpan.FromSeconds(2));
        using var active = await gate.AcquireAsync(queueWhenBusy: false, CancellationToken.None);
        var queuedUnlock = gate.AcquireAsync(queueWhenBusy: true, CancellationToken.None);
        Assert.True(SpinWait.SpinUntil(() => gate.QueuedUnlocks == 1, TimeSpan.FromSeconds(1)));

        await Assert.ThrowsAsync<PasswordEnvelopeCapacityException>(() => gate.AcquireAsync(queueWhenBusy: true, CancellationToken.None));
        Assert.Equal(1, gate.QueuedUnlocks);

        active.Dispose();
        using var unlocked = await queuedUnlock;
        Assert.Equal(0, gate.QueuedUnlocks);
    }

    [Fact]
    public async Task UnlockQueueTimeoutReturnsCapacityErrorAndReleasesQueueCount()
    {
        var gate = new Argon2ConcurrencyGate(maxConcurrent: 1, maxQueuedUnlocks: 1, unlockQueueTimeout: TimeSpan.FromMilliseconds(50));
        using var active = await gate.AcquireAsync(queueWhenBusy: false, CancellationToken.None);

        await Assert.ThrowsAsync<PasswordEnvelopeCapacityException>(() => gate.AcquireAsync(queueWhenBusy: true, CancellationToken.None));
        Assert.Equal(0, gate.QueuedUnlocks);
    }

    [Fact]
    public async Task CancellingQueuedUnlockRemovesItWithoutConsumingCapacity()
    {
        var gate = new Argon2ConcurrencyGate(maxConcurrent: 1, maxQueuedUnlocks: 1, unlockQueueTimeout: TimeSpan.FromSeconds(2));
        using var active = await gate.AcquireAsync(queueWhenBusy: false, CancellationToken.None);
        using var cancellation = new CancellationTokenSource();
        var queuedUnlock = gate.AcquireAsync(queueWhenBusy: true, cancellation.Token);
        Assert.True(SpinWait.SpinUntil(() => gate.QueuedUnlocks == 1, TimeSpan.FromSeconds(1)));

        cancellation.Cancel();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => queuedUnlock);
        Assert.Equal(0, gate.QueuedUnlocks);
        active.Dispose();
        using var nextUnlock = await gate.AcquireAsync(queueWhenBusy: true, CancellationToken.None);
    }
}
