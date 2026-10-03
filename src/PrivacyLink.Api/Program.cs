using System.Text.Json.Serialization;
using System.Diagnostics;
using System.Net;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.AspNetCore.HttpOverrides;
using PrivacyLink.Api;
using PrivacyLink.Contracts;
using System.Threading.RateLimiting;

if (args.Length == 1 && args[0] == "--healthcheck")
    return await ContainerHealthCheck.RunAsync();

var builder = WebApplication.CreateSlimBuilder(args);
SecretStoreConfiguration.ApplyFileSecrets(builder.Configuration);
ProductionConfiguration.Validate(builder.Configuration, builder.Environment.IsProduction());
builder.Services.ConfigureHttpJsonOptions(options =>
    options.SerializerOptions.TypeInfoResolverChain.Insert(0, PrivacyLinkJsonContext.Default));
var maxRequestBytes = int.TryParse(builder.Configuration["Limits:MaxRequestBytes"], out var configuredRequestBytes) && configuredRequestBytes > 0 ? configuredRequestBytes : 384 * 1024;
builder.WebHost.ConfigureKestrel(options =>
{
    options.Limits.MaxRequestBodySize = maxRequestBytes;
    options.AddServerHeader = false;
});
builder.Services.Configure<ForwardedHeadersOptions>(options =>
{
    options.ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto;
    options.KnownIPNetworks.Clear();
    options.KnownProxies.Clear();
    foreach (var value in builder.Configuration.GetSection("Security:TrustedProxies").GetChildren().Select(section => section.Value).OfType<string>())
        if (IPAddress.TryParse(value, out var address)) options.KnownProxies.Add(address);
});
builder.Services.AddSingleton(TimeProvider.System);
builder.Services.AddSingleton<StorageHealth>();
builder.Services.AddSingleton<PasswordEnvelopeService>();
builder.Services.AddSingleton<StatisticsRecorder>();
if (builder.Configuration.GetConnectionString("PrivacyLink") is not null)
{
    builder.Services.AddSingleton<ISecretRepository, PostgresSecretRepository>();
    builder.Services.AddSingleton<IBlobStorage, FileBlobStorage>();
}
else
{
    builder.Services.AddSingleton<ISecretRepository, InMemorySecretRepository>();
    builder.Services.AddSingleton<IBlobStorage, InMemoryBlobStorage>();
}
builder.Services.AddHostedService<StorageInitializer>();
builder.Services.AddHostedService<ExpiredSecretCleanup>();
builder.Services.AddHostedService<StatisticsFinalizer>();
builder.Services.AddRateLimiter(options =>
{
    var createPerHour = int.TryParse(builder.Configuration["RateLimiting:CreatePerIpPerHour"], out var hour) && hour > 0 ? hour : 20;
    var createPerDay = int.TryParse(builder.Configuration["RateLimiting:CreatePerIpPerDay"], out var day) && day > 0 ? day : 100;
    var openPerMinute = int.TryParse(builder.Configuration["RateLimiting:OpenPerIpPerMinute"], out var minute) && minute > 0 ? minute : 30;
    // Legacy PerSecret keys remain accepted; when both names are configured, the legacy key wins.
    var unlockPerMinute = PositiveLimit(builder.Configuration, 5, "RateLimiting:UnlockPerIpPerSecretPerMinute", "RateLimiting:UnlockPerIpPerMinute");
    var unlockPerHour = PositiveLimit(builder.Configuration, 20, "RateLimiting:UnlockPerIpPerSecretPerHour", "RateLimiting:UnlockPerIpPerHour");
    var revokePerMinute = PositiveLimit(builder.Configuration, 5, "RateLimiting:RevokePerIpPerSecretPerMinute", "RateLimiting:RevokePerIpPerMinute");
    var revokePerHour = PositiveLimit(builder.Configuration, 20, "RateLimiting:RevokePerIpPerSecretPerHour", "RateLimiting:RevokePerIpPerHour");
    options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
    options.OnRejected = (context, _) =>
    {
        context.HttpContext.Response.ContentType = "application/json";
        if (context.Lease.TryGetMetadata(MetadataName.RetryAfter, out var retryAfter))
        {
            var retryAfterSeconds = Math.Max(1, (int)Math.Ceiling(retryAfter.TotalSeconds));
            context.HttpContext.Response.Headers.RetryAfter = retryAfterSeconds.ToString(System.Globalization.CultureInfo.InvariantCulture);
        }
        PrivacyAudit.Log(context.HttpContext, "rate_limited");
        return new ValueTask(context.HttpContext.Response.WriteAsync("{\"code\":\"rate_limited\"}"));
    };
    options.AddPolicy("create", context => RateLimitPartition.Get(PrivacyAudit.ClientAddress(context), _ =>
        RateLimiter.CreateChained(
            new FixedWindowRateLimiter(new FixedWindowRateLimiterOptions { PermitLimit = createPerHour, Window = TimeSpan.FromHours(1), QueueLimit = 0 }),
            new FixedWindowRateLimiter(new FixedWindowRateLimiterOptions { PermitLimit = createPerDay, Window = TimeSpan.FromDays(1), QueueLimit = 0 }))));
    options.AddPolicy("open", context => RateLimitPartition.GetFixedWindowLimiter(
        PrivacyAudit.ClientAddress(context),
        _ => new FixedWindowRateLimiterOptions { PermitLimit = openPerMinute, Window = TimeSpan.FromMinutes(1), QueueLimit = 0 }));
    // Do not include the route ID here: middleware runs before endpoint validation,
    // so attacker-controlled IDs would allocate an unbounded number of partitions.
    options.AddPolicy("unlock", context => RateLimitPartition.Get(PrivacyAudit.ClientAddress(context), _ =>
        RateLimiter.CreateChained(
            new FixedWindowRateLimiter(new FixedWindowRateLimiterOptions { PermitLimit = unlockPerMinute, Window = TimeSpan.FromMinutes(1), QueueLimit = 0 }),
            new FixedWindowRateLimiter(new FixedWindowRateLimiterOptions { PermitLimit = unlockPerHour, Window = TimeSpan.FromHours(1), QueueLimit = 0 }))));
    options.AddPolicy("revoke", context => RateLimitPartition.Get(PrivacyAudit.ClientAddress(context), _ =>
        RateLimiter.CreateChained(
            new FixedWindowRateLimiter(new FixedWindowRateLimiterOptions { PermitLimit = revokePerMinute, Window = TimeSpan.FromMinutes(1), QueueLimit = 0 }),
            new FixedWindowRateLimiter(new FixedWindowRateLimiterOptions { PermitLimit = revokePerHour, Window = TimeSpan.FromHours(1), QueueLimit = 0 }))));
});

var app = builder.Build();
app.UseExceptionHandler(errorApp => errorApp.Run(async context =>
{
    PrivacyAudit.Log(context, "unhandled_error");
    context.Response.StatusCode = StatusCodes.Status500InternalServerError;
    await context.Response.WriteAsJsonAsync(new ErrorResponse("server_error"), PrivacyLinkJsonContext.Default.ErrorResponse);
}));
app.UseForwardedHeaders();
app.Use(async (context, next) =>
{
    var requireHttps = builder.Environment.IsProduction() && (!bool.TryParse(builder.Configuration["Security:RequireHttps"], out var configuredRequireHttps) || configuredRequireHttps);
    var remoteAddress = context.Connection.RemoteIpAddress;
    var isLoopback = remoteAddress is not null &&
        (IPAddress.IsLoopback(remoteAddress) || remoteAddress.IsIPv4MappedToIPv6 && IPAddress.IsLoopback(remoteAddress.MapToIPv4()));
    var isLocalHealthProbe = isLoopback &&
        (context.Request.Path == "/health" || context.Request.Path == "/health/ready");
    if (requireHttps && !context.Request.IsHttps && !isLocalHealthProbe)
    {
        context.Response.StatusCode = StatusCodes.Status400BadRequest;
        await context.Response.WriteAsJsonAsync(new ErrorResponse("https_required"), PrivacyLinkJsonContext.Default.ErrorResponse);
        return;
    }
    await next(context);
});
app.Use(async (context, next) =>
{
    context.Response.Headers.CacheControl = "no-store";
    context.Response.Headers["Referrer-Policy"] = "no-referrer";
    context.Response.Headers.XContentTypeOptions = "nosniff";
    // Keep the server policy aligned with the Angular document policy. The SPA
    // needs same-origin scripts/styles/assets and its root base href to load.
    context.Response.Headers["Content-Security-Policy"] = "default-src 'self'; base-uri 'self'; form-action 'self'; object-src 'none'; frame-ancestors 'none'; img-src 'self' data:; connect-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self'";
    context.Response.Headers["X-Frame-Options"] = "DENY";
    context.Response.Headers["Cross-Origin-Resource-Policy"] = "same-origin";
    context.Response.Headers["Cross-Origin-Opener-Policy"] = "same-origin";
    context.Response.Headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=(), payment=()";
    context.Response.Headers["X-Robots-Tag"] = "noindex, nofollow, noarchive";
    var enableHsts = !bool.TryParse(builder.Configuration["Security:EnableHsts"], out var configuredHsts) || configuredHsts;
    if (context.Request.IsHttps && enableHsts)
        context.Response.Headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains";
    var started = Stopwatch.GetTimestamp();
    try
    {
        await next(context);
    }
    finally
    {
        if (PrivacyAudit.IsAudited(context.Request)) PrivacyAudit.Log(context, PrivacyAudit.Operation(context.Request), Stopwatch.GetElapsedTime(started));
    }
});
app.Use(async (context, next) =>
{
    if (HttpMethods.IsPost(context.Request.Method) &&
        (context.Request.Headers.TryGetValue("Origin", out var origin) &&
         !string.Equals(origin.ToString(), $"{context.Request.Scheme}://{context.Request.Host}", StringComparison.OrdinalIgnoreCase) ||
         context.Request.Headers.TryGetValue("Sec-Fetch-Site", out var site) && site == "cross-site"))
    {
        context.Response.StatusCode = 403;
        await context.Response.WriteAsJsonAsync(new ErrorResponse("forbidden"), PrivacyLinkJsonContext.Default.ErrorResponse);
        return;
    }
    await next(context);
});
app.Use(async (context, next) =>
{
    await next(context);
    var category = context.Items["PrivacyLink.StatisticsErrorCategory"] as string ?? context.Response.StatusCode switch
    {
        StatusCodes.Status429TooManyRequests => "rate_limit",
        >= 500 => "server_error",
        >= 400 and not StatusCodes.Status404NotFound => "validation",
        _ => null
    };
    if (category is not null && context.Request.Path.StartsWithSegments("/api/v1/secrets"))
    {
        var statistics = context.RequestServices.GetRequiredService<StatisticsRecorder>();
        await statistics.RecordAsync(statistics.Event(context, "errors", "category", category), context.RequestAborted);
    }
});
app.UseRateLimiter();

// The production image contains the Angular bundle in wwwroot. Serving it from
// the API keeps the browser and API same-origin and avoids a separate CORS setup.
app.UseDefaultFiles();
app.UseStaticFiles();

app.MapGet("/health", () => new HealthResponse("ok"));
app.MapGet("/health/ready", async (StorageHealth health, ISecretRepository repository, IBlobStorage blobs, HttpContext context) =>
    await health.CheckReadinessAsync(repository, blobs, context.RequestAborted)
        ? Results.Ok(new HealthResponse("ready"))
        : Results.Json(new ErrorResponse("not_ready"), PrivacyLinkJsonContext.Default.ErrorResponse, statusCode: StatusCodes.Status503ServiceUnavailable));
app.MapGet("/api/v1/capabilities", (IConfiguration configuration) => SecretEndpoints.Capabilities(configuration));
app.MapGet("/api/v1/stats", async (StatisticsRecorder statistics, HttpContext context) =>
    Results.Json(await statistics.GetDailyStatisticsAsync(context.RequestAborted), PrivacyLinkJsonContext.Default.DailyStatisticResponseArray));
app.MapPost("/api/v1/secrets", (HttpRequest request, ISecretRepository repository, IBlobStorage blobs, PasswordEnvelopeService envelopes, TimeProvider clock, IConfiguration configuration, StatisticsRecorder statistics) => SecretEndpoints.Create(request, repository, blobs, envelopes, clock, configuration, statistics)).RequireRateLimiting("create");
app.MapGet("/api/v1/secrets/{id}", (string id, ISecretRepository repository, TimeProvider clock) => SecretEndpoints.Metadata(id, repository, clock));
app.MapPost("/api/v1/secrets/{id}/revoke", (string id, HttpRequest request, ISecretRepository repository, IBlobStorage blobs) => SecretEndpoints.Revoke(id, request, repository, blobs)).RequireRateLimiting("revoke");
app.MapPost("/api/v1/secrets/{id}/open", (string id, HttpRequest request, ISecretRepository repository, IBlobStorage blobs, TimeProvider clock, StatisticsRecorder statistics) => SecretEndpoints.Open(id, request, repository, blobs, clock, statistics)).RequireRateLimiting("open");
app.MapPost("/api/v1/secrets/{id}/unlock", (string id, HttpRequest request, ISecretRepository repository, IBlobStorage blobs, PasswordEnvelopeService envelopes, TimeProvider clock, IConfiguration configuration, StatisticsRecorder statistics) => SecretEndpoints.Unlock(id, request, repository, blobs, envelopes, clock, configuration, statistics)).RequireRateLimiting("unlock");
app.MapPost("/api/v1/secrets/{id}/files/{fileId}/open", (string id, string fileId, HttpRequest request, ISecretRepository repository, IBlobStorage blobs, TimeProvider clock, StatisticsRecorder statistics) => SecretEndpoints.OpenFile(id, fileId, request, repository, blobs, clock, statistics)).RequireRateLimiting("open");
app.MapFallbackToFile("index.html");

app.Run();
return 0;

static int PositiveLimit(IConfiguration configuration, int fallback, params string[] keys)
{
    foreach (var key in keys)
        if (int.TryParse(configuration[key], out var value) && value > 0)
            return value;
    return fallback;
}

[JsonSourceGenerationOptions(System.Text.Json.JsonSerializerDefaults.Web)]
[JsonSerializable(typeof(HealthResponse))]
[JsonSerializable(typeof(DailyStatisticResponse[]))]
[JsonSerializable(typeof(FileUploadPolicyResponse))]
[JsonSerializable(typeof(CreateSecretResponse))]
[JsonSerializable(typeof(SecretMetadataResponse))]
[JsonSerializable(typeof(OpenSecretResponse))]
[JsonSerializable(typeof(OpenFileResponse))]
[JsonSerializable(typeof(OpenedFileResponse))]
[JsonSerializable(typeof(List<StoredFile>))]
[JsonSerializable(typeof(IReadOnlyList<StoredFile>))]
[JsonSerializable(typeof(ErrorResponse))]
[JsonSerializable(typeof(UnlockSecretRequest))]
[JsonSerializable(typeof(CreateSecretRequest))]
internal partial class PrivacyLinkJsonContext : JsonSerializerContext;

public partial class Program;

internal static class ContainerHealthCheck
{
    public static async Task<int> RunAsync()
    {
        using var handler = new SocketsHttpHandler { UseProxy = false };
        using var client = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(2) };
        var allowedHost = (Environment.GetEnvironmentVariable("AllowedHosts") ?? "localhost")
            .Split(';', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries)
            .FirstOrDefault() ?? "localhost";
        client.DefaultRequestHeaders.Host = allowedHost;
        try
        {
            using var response = await client.GetAsync("http://127.0.0.1:8080/health/ready");
            return response.IsSuccessStatusCode ? 0 : 1;
        }
        catch (HttpRequestException)
        {
            return 1;
        }
        catch (TaskCanceledException)
        {
            return 1;
        }
    }
}
