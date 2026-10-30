using System.Text.Json.Serialization;
using System.Diagnostics;
using System.Net;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using PrivacyLink.Api;
using PrivacyLink.Contracts;
using PrivacyLink.Infrastructure;
using PrivacyLink.Services;
using System.Threading.RateLimiting;

if (args.Length == 1 && args[0] == "--healthcheck")
    return await ContainerHealthCheck.RunAsync();

var builder = WebApplication.CreateSlimBuilder(args);
SecretStoreConfiguration.ApplyFileSecrets(builder.Configuration);
builder.Services.ConfigureHttpJsonOptions(options =>
    options.SerializerOptions.TypeInfoResolverChain.Insert(0, PrivacyLinkJsonContext.Default));
builder.Services.AddSingleton<AdminPasswordVerifier>();
builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme).AddCookie(options =>
{
    options.Cookie.Name = builder.Environment.IsProduction() ? "__Host-PrivacyLink.Admin" : "PrivacyLink.Admin";
    options.Cookie.HttpOnly = true;
    options.Cookie.IsEssential = true;
    options.Cookie.SameSite = SameSiteMode.Strict;
    options.Cookie.SecurePolicy = builder.Environment.IsProduction() ? CookieSecurePolicy.Always : CookieSecurePolicy.SameAsRequest;
    options.Cookie.Path = "/";
    options.ExpireTimeSpan = TimeSpan.FromHours(8);
    options.SlidingExpiration = false;
    options.Events.OnRedirectToLogin = context => { context.Response.StatusCode = StatusCodes.Status401Unauthorized; return Task.CompletedTask; };
    options.Events.OnRedirectToAccessDenied = context => { context.Response.StatusCode = StatusCodes.Status403Forbidden; return Task.CompletedTask; };
});
builder.Services.AddAuthorization();
var maxRequestBytes = int.TryParse(builder.Configuration["Limits:MaxRequestBytes"], out var configuredRequestBytes) && configuredRequestBytes > 0 ? configuredRequestBytes : 110 * 1024 * 1024;
builder.WebHost.ConfigureKestrel(options =>
{
    options.Limits.MaxRequestBodySize = maxRequestBytes;
    options.AddServerHeader = false;
});
builder.Services.Configure<ForwardedHeadersOptions>(options =>
{
    var trustedProxyAddresses = builder.Configuration.GetSection("Security:TrustedProxies").GetChildren().Select(section => section.Value).OfType<string>()
        .Where(value => IPAddress.TryParse(value, out _)).Select(value => IPAddress.Parse(value)).ToArray();
    options.ForwardedHeaders = trustedProxyAddresses.Length == 0 ? ForwardedHeaders.None : ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto;
    options.KnownIPNetworks.Clear();
    options.KnownProxies.Clear();
    foreach (var address in trustedProxyAddresses) options.KnownProxies.Add(address);
});
builder.Services.AddSingleton(TimeProvider.System);
builder.Services.AddSingleton(sp => new PasswordEnvelopeService(new PasswordEnvelopeOptions(
    SecretStoreConfiguration.ReadPasswordPepper(builder.Configuration, isProduction: false),
    BoundedLimit(builder.Configuration, "Security:Argon2:MemorySizeKb", 65536, 8192, 1024 * 1024),
    BoundedLimit(builder.Configuration, "Security:Argon2:Iterations", 3, 1, 20),
    BoundedLimit(builder.Configuration, "Security:Argon2:DegreeOfParallelism", 2, 1, 16),
    BoundedLimit(builder.Configuration, "Security:Argon2:MaxConcurrentOperations", 2, 1, 8),
    BoundedLimit(builder.Configuration, "Security:Argon2:MaxQueuedUnlocks", 8, 0, 64),
    BoundedLimit(builder.Configuration, "Security:Argon2:UnlockQueueTimeoutSeconds", 30, 1, 120))));
builder.Services.AddSingleton<SecretApplicationService>();
builder.Services.AddSingleton<EmailVerificationService>();
builder.Services.AddSingleton<CreateProofOfWork>();
builder.Services.AddTransient<SecretRequestAuditMiddleware>();
builder.Services.AddPrivacyLinkInfrastructure(builder.Configuration);
builder.Services.AddRateLimiter(options =>
{
    var createPerHour = int.TryParse(builder.Configuration["RateLimiting:CreatePerIpPerHour"], out var hour) && hour > 0 ? hour : 20;
    var createPerDay = int.TryParse(builder.Configuration["RateLimiting:CreatePerIpPerDay"], out var day) && day > 0 ? day : 100;
    var challengePerHour = Math.Max(20L, (long)createPerHour * 2);
    var challengePerDay = Math.Max(400L, (long)createPerDay * 4);
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
    options.AddPolicy("create-challenge", context => RateLimitPartition.Get(PrivacyAudit.ClientAddress(context), _ =>
        RateLimiter.CreateChained(
            new FixedWindowRateLimiter(new FixedWindowRateLimiterOptions { PermitLimit = (int)Math.Min(int.MaxValue, challengePerHour), Window = TimeSpan.FromHours(1), QueueLimit = 0 }),
            new FixedWindowRateLimiter(new FixedWindowRateLimiterOptions { PermitLimit = (int)Math.Min(int.MaxValue, challengePerDay), Window = TimeSpan.FromDays(1), QueueLimit = 0 }))));
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
    options.AddPolicy("admin-login", context => RateLimitPartition.GetFixedWindowLimiter(
        PrivacyAudit.ClientAddress(context),
        _ => new FixedWindowRateLimiterOptions { PermitLimit = 5, Window = TimeSpan.FromMinutes(15), QueueLimit = 0 }));
});

var app = builder.Build();
ProductionConfiguration.Validate(app.Configuration, app.Environment.IsProduction());
var configuredChromeExtensionOrigin = ChromeExtensionOrigin.Read(app.Configuration);
app.UseExceptionHandler(errorApp => errorApp.Run(async context =>
{
    PrivacyAudit.Log(context, "unhandled_error");
    var error = context.Features.Get<Microsoft.AspNetCore.Diagnostics.IExceptionHandlerFeature>()?.Error ?? new InvalidOperationException();
    var failure = PrivacyAudit.Failure(error);
    if (error is SecretAuditUnavailableException)
        context.Items[PrivacyAudit.ErrorCodeItem] = failure.ErrorCode;
    context.Response.StatusCode = failure.StatusCode;
    await context.Response.WriteAsJsonAsync(new ErrorResponse(failure.ErrorCode), PrivacyLinkJsonContext.Default.ErrorResponse);
}));
app.UseForwardedHeaders();
app.UseMiddleware<SecretRequestAuditMiddleware>();
app.UseAuthentication();
app.UseAuthorization();
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
    context.Response.Headers["Content-Security-Policy"] = "default-src 'self'; base-uri 'self'; form-action 'self'; object-src 'none'; frame-ancestors 'none'; img-src 'self' data:; connect-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'wasm-unsafe-eval'";
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
    var request = context.Request;
    var isCreate = request.Path.Equals("/api/v1/secrets", StringComparison.OrdinalIgnoreCase);
    var isCreateChallenge = request.Path.Equals("/api/v1/secrets/create-challenge", StringComparison.OrdinalIgnoreCase);
    var isCapabilities = request.Path.Equals("/api/v1/capabilities", StringComparison.OrdinalIgnoreCase);
    var hasOrigin = request.Headers.TryGetValue("Origin", out var originHeader);
    var origin = hasOrigin ? originHeader.ToString() : null;
    var isExtensionOrigin = origin is not null && ChromeExtensionOrigin.IsExtensionOrigin(origin);

    if (isExtensionOrigin)
    {
        var allowedExtensionRequest = string.Equals(origin, configuredChromeExtensionOrigin, StringComparison.Ordinal) &&
            (HttpMethods.IsGet(request.Method) && (isCreateChallenge || isCapabilities) || HttpMethods.IsPost(request.Method) && isCreate);
        if (!allowedExtensionRequest)
        {
            context.Response.StatusCode = StatusCodes.Status403Forbidden;
            await context.Response.WriteAsJsonAsync(new ErrorResponse("forbidden"), PrivacyLinkJsonContext.Default.ErrorResponse);
            return;
        }

        await next();
        return;
    }

    var isSameOrigin = origin is not null &&
        string.Equals(origin, $"{request.Scheme}://{request.Host}", StringComparison.OrdinalIgnoreCase);
    var isCrossSite = request.Headers.TryGetValue("Sec-Fetch-Site", out var site) &&
        string.Equals(site.ToString(), "cross-site", StringComparison.OrdinalIgnoreCase);
    var rejectPost = HttpMethods.IsPost(request.Method) &&
        (hasOrigin && !isSameOrigin || isCrossSite);
    var rejectChallenge = HttpMethods.IsGet(request.Method) && isCreateChallenge &&
        (hasOrigin && !isSameOrigin || isCrossSite);
    if (rejectPost || rejectChallenge)
    {
        context.Response.StatusCode = 403;
        await context.Response.WriteAsJsonAsync(new ErrorResponse("forbidden"), PrivacyLinkJsonContext.Default.ErrorResponse);
        return;
    }
    await next();
});
app.UseRateLimiter();

// The production image contains the Angular bundle in wwwroot. Serving it from
// the API keeps the browser and API same-origin and avoids a separate CORS setup.
app.UseDefaultFiles();
app.UseStaticFiles();

app.MapGet("/health", () => new HealthResponse("ok"));
app.MapGet("/health/ready", async (IStorageReadiness health, HttpContext context) =>
    await health.CheckReadinessAsync(context.RequestAborted)
        ? Results.Ok(new HealthResponse("ready"))
        : Results.Json(new ErrorResponse("not_ready"), PrivacyLinkJsonContext.Default.ErrorResponse, statusCode: StatusCodes.Status503ServiceUnavailable));
app.MapGet("/api/v1/capabilities", (IConfiguration configuration) => SecretEndpoints.Capabilities(configuration));
app.MapGet("/api/v1/secrets/create-challenge", (CreateProofOfWork proof) => SecretEndpoints.CreateChallenge(proof)).RequireRateLimiting("create-challenge");
app.MapGet("/api/v1/stats", () => Results.Json(new ErrorResponse("statistics_retired"), PrivacyLinkJsonContext.Default.ErrorResponse, statusCode: StatusCodes.Status410Gone));
var adminApi = app.MapGroup("/api/v1/admin");
adminApi.MapPost("/login", (Delegate)AdminEndpoints.Login).RequireRateLimiting("admin-login");
adminApi.MapGet("/session", (Delegate)AdminEndpoints.Session).RequireAuthorization();
adminApi.MapPost("/logout", (Delegate)AdminEndpoints.Logout).RequireAuthorization();
adminApi.MapGet("/audit", (Delegate)AdminEndpoints.Audit).RequireAuthorization();
app.MapPost("/api/v1/secrets", (HttpRequest request, HttpContext context, SecretApplicationService service, IConfiguration configuration, CreateProofOfWork proof) => SecretEndpoints.Create(request, context, service, configuration, proof)).RequireRateLimiting("create");
app.MapGet("/api/v1/secrets/{id}", (string id, SecretApplicationService service, TimeProvider clock) => SecretEndpoints.Metadata(id, service, clock));
app.MapPost("/api/v1/secrets/{id}/email-verification/request", (string id, HttpRequest request, EmailVerificationService verification) => SecretEndpoints.RequestEmailCode(id, request, verification)).WithMetadata(new Microsoft.AspNetCore.Mvc.RequestSizeLimitAttribute(1024));
app.MapPost("/api/v1/secrets/{id}/email-verification/verify", (string id, HttpRequest request, EmailVerificationService verification, TimeProvider clock, IWebHostEnvironment environment) => SecretEndpoints.VerifyEmailCode(id, request, verification, clock, environment)).WithMetadata(new Microsoft.AspNetCore.Mvc.RequestSizeLimitAttribute(2048));
app.MapPost("/api/v1/secrets/{id}/revoke", (string id, HttpRequest request, SecretApplicationService service, ILoggerFactory loggerFactory) => SecretEndpoints.Revoke(id, request, service, loggerFactory)).RequireRateLimiting("revoke");
app.MapPost("/api/v1/secrets/{id}/open", (string id, HttpRequest request, SecretApplicationService service, TimeProvider clock, EmailVerificationService verification, IWebHostEnvironment environment) => SecretEndpoints.Open(id, request, service, clock, verification, environment)).RequireRateLimiting("open");
app.MapPost("/api/v1/secrets/{id}/unlock", (string id, HttpRequest request, SecretApplicationService service, TimeProvider clock, IConfiguration configuration, EmailVerificationService verification, IWebHostEnvironment environment) => SecretEndpoints.Unlock(id, request, service, clock, configuration, verification, environment)).RequireRateLimiting("unlock");
app.MapPost("/api/v1/secrets/{id}/files/{fileId}/open", (string id, string fileId, HttpRequest request, SecretApplicationService service, TimeProvider clock, EmailVerificationService verification, IWebHostEnvironment environment) => SecretEndpoints.OpenFile(id, fileId, request, service, clock, verification, environment)).RequireRateLimiting("open");
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

static int BoundedLimit(IConfiguration configuration, string key, int fallback, int minimum, int maximum) =>
    int.TryParse(configuration[key], out var value) && value >= minimum && value <= maximum ? value : fallback;

[JsonSourceGenerationOptions(System.Text.Json.JsonSerializerDefaults.Web)]
[JsonSerializable(typeof(HealthResponse))]
[JsonSerializable(typeof(FileUploadPolicyResponse))]
[JsonSerializable(typeof(CreateSecretResponse))]
[JsonSerializable(typeof(CreateChallengeResponse))]
[JsonSerializable(typeof(SecretMetadataResponse))]
[JsonSerializable(typeof(OpenSecretResponse))]
[JsonSerializable(typeof(OpenFileResponse))]
[JsonSerializable(typeof(OpenedFileResponse))]
[JsonSerializable(typeof(ErrorResponse))]
[JsonSerializable(typeof(UnlockSecretRequest))]
[JsonSerializable(typeof(EmailCodeRequestResponse))]
[JsonSerializable(typeof(VerifyEmailCodeRequest))]
[JsonSerializable(typeof(CreateSecretRequest))]
[JsonSerializable(typeof(AdminLoginRequest))]
[JsonSerializable(typeof(AdminSessionResponse))]
[JsonSerializable(typeof(AdminAuditPageResponse))]
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
