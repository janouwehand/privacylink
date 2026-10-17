using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using PrivacyLink.Services;

namespace PrivacyLink.Infrastructure;

internal sealed class EmailVerificationDeliveryWorker(
    IEmailSender sender,
    IEmailVerificationStore store,
    EmailVerificationOptions options,
    TimeProvider clock,
    ILogger<EmailVerificationDeliveryWorker> logger) : BackgroundService
{
    private static readonly TimeSpan LeaseDuration = TimeSpan.FromMinutes(2);
    private static readonly TimeSpan PollInterval = TimeSpan.FromSeconds(1);

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            ClaimedEmailDelivery? delivery;
            try
            {
                delivery = await store.ClaimDeliveryAsync(clock.GetUtcNow(), LeaseDuration, stoppingToken);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                return;
            }
            catch
            {
                logger.LogWarning("Email verification outbox claim failed");
                if (!await DelayAsync(stoppingToken)) return;
                continue;
            }

            if (delivery is null)
            {
                if (!await DelayAsync(stoppingToken)) return;
                continue;
            }

            bool isCurrent;
            try
            {
                isCurrent = await store.IsDeliveryCurrentAsync(delivery, clock.GetUtcNow(), stoppingToken);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                return;
            }
            catch
            {
                // Leave the lease in place after a database error. The row is recoverable
                // after the lease expires.
                logger.LogWarning("Email verification outbox state could not be checked");
                continue;
            }

            if (!isCurrent)
            {
                try { await store.DiscardDeliveryAsync(delivery, stoppingToken); }
                catch { logger.LogWarning("Stale email verification outbox item could not be removed"); }
                continue;
            }

            string code;
            try { code = options.DecryptCode(delivery); }
            catch
            {
                await FailOwnedDeliveryAsync(delivery);
                logger.LogWarning("Email verification outbox item could not be decrypted");
                continue;
            }

            try
            {
                if (!options.HasSenderConfiguration) throw new InvalidOperationException("Email delivery is not configured.");
                await sender.SendAsync(EmailVerificationService.CreateMessage(delivery.Recipient, code), stoppingToken);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                // Keep the lease. Another worker can reclaim this row when it expires.
                return;
            }
            catch
            {
                // Resend rejection, provider timeout, and transport exceptions are
                // terminal for this challenge. Only host cancellation/crash retains the
                // row for a same-code retry.
                await FailOwnedDeliveryAsync(delivery);
                logger.LogWarning("Email verification send failed and the challenge was invalidated");
                continue;
            }

            try
            {
                // Activating the challenge and deleting its outbox item are one database
                // transaction. If completion fails, the lease eventually yields a retry.
                await store.CompleteDeliveryAsync(delivery, clock.GetUtcNow(), stoppingToken);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                return;
            }
            catch
            {
                logger.LogWarning("Email verification delivery completion failed; the outbox item will be retried");
            }
        }
    }

    private async Task FailOwnedDeliveryAsync(ClaimedEmailDelivery delivery)
    {
        try { await store.FailDeliveryAsync(delivery, CancellationToken.None); }
        catch { logger.LogWarning("Email verification delivery failure could not be recorded"); }
    }

    private static async Task<bool> DelayAsync(CancellationToken cancellationToken)
    {
        try
        {
            await Task.Delay(PollInterval, cancellationToken);
            return true;
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            return false;
        }
    }
}
