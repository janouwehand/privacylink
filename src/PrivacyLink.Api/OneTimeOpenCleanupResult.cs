using Microsoft.AspNetCore.Http;
using PrivacyLink.Services;

namespace PrivacyLink.Api;

internal static class SecretResponseDrain
{
    private static readonly object DrainSucceededKey = new();
    private static readonly object CleanupActionKey = new();

    public static void MarkSucceeded(HttpContext context) => context.Items[DrainSucceededKey] = true;

    public static void RegisterCleanup(HttpContext context, Func<Task> cleanup) => context.Items[CleanupActionKey] = cleanup;

    public static bool HasPendingCleanup(HttpContext context) => context.Items.TryGetValue(CleanupActionKey, out var cleanup) && cleanup is Func<Task>;

    public static bool Succeeded(HttpContext context) =>
        context.Items.TryGetValue(DrainSucceededKey, out var succeeded) && succeeded is true;

    public static async Task CompleteAsync(HttpContext context)
    {
        if (!Succeeded(context) || context.RequestAborted.IsCancellationRequested ||
            context.Response.StatusCode is < StatusCodes.Status200OK or >= StatusCodes.Status300MultipleChoices ||
            !context.Items.TryGetValue(CleanupActionKey, out var cleanup) || cleanup is not Func<Task> action)
            return;

        context.Items.Remove(CleanupActionKey);
        await action();
    }
}

internal sealed class OneTimeOpenCleanupResult(
    IResult inner,
    SecretApplicationService service,
    string secretId,
    ILogger logger) : IResult
{
    public async Task ExecuteAsync(HttpContext context)
    {
        await inner.ExecuteAsync(context);
        SecretResponseDrain.RegisterCleanup(context, async () =>
        {
            try
            {
                await service.CleanupConsumedOneTimeAsync(secretId, CancellationToken.None);
            }
            catch (Exception exception)
            {
                logger.LogError(exception, "One-time secret cleanup failed after successful response for {SecretId}", secretId);
            }
        });
    }
}
