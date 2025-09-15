using AuthenticationAPI.Data;
using Microsoft.AspNetCore.DataProtection;
using System.IO;
using AuthenticationAPI.Models;
using AuthenticationAPI.Infrastructure.Middleware;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.OpenApi.Models;
using Microsoft.AspNetCore.Mvc.ApiExplorer;
using AuthenticationAPI.Services;
using AuthenticationAPI.Services.Email;
using Microsoft.Extensions.Options;
using AuthenticationAPI.Infrastructure.Swagger;
using Microsoft.AspNetCore.Diagnostics.HealthChecks;
using System.Text.Json;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using Microsoft.AspNetCore.RateLimiting;
using System.Threading.RateLimiting;
using Microsoft.AspNetCore.Mvc;
using AuthenticationAPI.Infrastructure.Security;
using Microsoft.AspNetCore.Authorization;
using DotNetEnv;
using AuthenticationAPI.Models.Options;
using Microsoft.AspNetCore.HttpOverrides;
using System.Runtime.InteropServices;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.CookiePolicy;
using Azure.Identity;
using Azure.Storage.Blobs;
using Azure.Extensions.AspNetCore.Configuration.Secrets;
using Azure.Extensions.AspNetCore.DataProtection.Blobs;
using Azure.Extensions.AspNetCore.DataProtection.Keys;
using FluentValidation.AspNetCore;
using FluentValidation;

var builder = WebApplication.CreateBuilder(args);
// Load .env explicitly from content root so env vars are available to configuration
try
{
    var envPath = Path.Combine(builder.Environment.ContentRootPath, ".env");
    if (File.Exists(envPath)) Env.Load(envPath);
}
catch { /* optional */ }
var configurationBuilder = new ConfigurationBuilder()
    .AddConfiguration(builder.Configuration)
    .AddEnvironmentVariables();

// Optional: Azure Key Vault integration for configuration secrets
var keyVaultUrl = builder.Configuration["Azure:KeyVault:VaultUrl"];
if (!string.IsNullOrWhiteSpace(keyVaultUrl))
{
    try
    {
        var cred = new Azure.Identity.DefaultAzureCredential();
        configurationBuilder.AddAzureKeyVault(new Uri(keyVaultUrl), cred);
    }
    catch (Exception ex)
    {
        Console.WriteLine($"[Startup] Azure Key Vault not added: {ex.Message}");
    }
}

var configuration = configurationBuilder.Build();

// Structured logging (basic JSON via built-in) - Serilog can replace later
builder.Logging.ClearProviders();
builder.Logging.AddJsonConsole(options =>
{
    options.IncludeScopes = true;
    options.TimestampFormat = "yyyy-MM-ddTHH:mm:ss.fffZ";
});

// Options
builder.Services.Configure<JwtOptions>(configuration.GetSection(JwtOptions.SectionName));
builder.Services.Configure<RateLimitOptions>(configuration.GetSection(RateLimitOptions.SectionName));
builder.Services.Configure<KeyRotationOptions>(configuration.GetSection(KeyRotationOptions.SectionName));
builder.Services.Configure<AuthenticationAPI.Models.Options.BridgeOptions>(
    configuration.GetSection(AuthenticationAPI.Models.Options.BridgeOptions.SectionName));
builder.Services.Configure<AuthenticationAPI.Models.Options.ThrottleOptions>(
    configuration.GetSection(AuthenticationAPI.Models.Options.ThrottleOptions.SectionName));

builder.Services.AddDbContext<ApplicationDbContext>(options =>
{
    var cs = configuration.GetConnectionString("DefaultConnection");
    options.UseSqlServer(cs, sql => sql.EnableRetryOnFailure(maxRetryCount: 5, maxRetryDelay: TimeSpan.FromSeconds(10), errorNumbersToAdd: null));
});
builder.Services.AddDbContext<AppDbContext>(options =>
{
    var cs = configuration.GetConnectionString("AppDb");
    options.UseSqlServer(cs, sql => sql.EnableRetryOnFailure(maxRetryCount: 5, maxRetryDelay: TimeSpan.FromSeconds(10), errorNumbersToAdd: null));
});

builder.Services.AddIdentity<ApplicationUser, IdentityRole>(options =>
    {
        if (!options.User.AllowedUserNameCharacters.Contains(' '))
        {
            options.User.AllowedUserNameCharacters += " ";
        }
        options.User.RequireUniqueEmail = true;
        options.SignIn.RequireConfirmedEmail = true;
    // Enforce strong password policy in all environments
    options.Password.RequireDigit = true;
    options.Password.RequireLowercase = true;
    options.Password.RequireUppercase = true;
    options.Password.RequireNonAlphanumeric = true;
    options.Password.RequiredLength = 12;
        // Lockout policy
        options.Lockout.AllowedForNewUsers = true;
        options.Lockout.MaxFailedAccessAttempts = 10;
        options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(15);
    })
    .AddEntityFrameworkStores<ApplicationDbContext>()
    .AddDefaultTokenProviders();

builder.Services.AddScoped<IPasswordHasher<ApplicationUser>, AuthenticationAPI.Infrastructure.Security.Argon2PasswordHasher<ApplicationUser>>();

builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultScheme = JwtBearerDefaults.AuthenticationScheme;
}).AddJwtBearer();
builder.Services.AddTransient<IConfigureOptions<JwtBearerOptions>, ConfigureJwtBearerOptions>();
// HSTS configuration for production
builder.Services.AddHsts(options =>
{
    options.Preload = true;
    options.IncludeSubDomains = true;
    options.MaxAge = TimeSpan.FromDays(180);
});

builder.Services.AddControllersWithViews(o =>
{
    o.Filters.Add<AuthenticationAPI.Infrastructure.Filters.InputNormalizationFilter>();
})
    .AddJsonOptions(opts =>
    {
        opts.JsonSerializerOptions.ReadCommentHandling = System.Text.Json.JsonCommentHandling.Disallow;
        opts.JsonSerializerOptions.AllowTrailingCommas = false;
        opts.JsonSerializerOptions.IgnoreReadOnlyFields = false;
        // Unknown properties should not be ignored; captured via [JsonExtensionData]
        opts.JsonSerializerOptions.UnknownTypeHandling = System.Text.Json.Serialization.JsonUnknownTypeHandling.JsonNode; // keep strict parsing
    });

// FluentValidation (new recommended API)
builder.Services.AddFluentValidationAutoValidation();
builder.Services.AddFluentValidationClientsideAdapters();
builder.Services.AddValidatorsFromAssemblyContaining<AuthenticationAPI.Validators.RegisterModelValidator>();

// API versioning
builder.Services.AddApiVersioning(o =>
{
    o.AssumeDefaultVersionWhenUnspecified = true;
    o.DefaultApiVersion = new ApiVersion(1, 0);
    o.ReportApiVersions = true;
});
builder.Services.AddVersionedApiExplorer(o =>
{
    o.GroupNameFormat = "'v'VVV"; // e.g., v1, v1.0
    o.SubstituteApiVersionInUrl = true;
});
builder.Services.Configure<ApiBehaviorOptions>(options =>
{
    options.InvalidModelStateResponseFactory = ctx =>
    {
        var problem = new ValidationProblemDetails(ctx.ModelState)
        {
            Title = "Validation failed",
            Status = StatusCodes.Status400BadRequest,
            Type = "https://tools.ietf.org/html/rfc7231#section-6.5.1",
            Instance = ctx.HttpContext.Request.Path
        };
        if (ctx.HttpContext.Items.TryGetValue("X-Correlation-ID", out var cid) && cid is string s && !string.IsNullOrWhiteSpace(s))
        {
            problem.Extensions["correlationId"] = s;
        }
        return new ObjectResult(problem) { StatusCode = problem.Status };
    };
});

builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(c =>
{
    // NOTE: SwaggerDoc entries will be added dynamically per API version below
    var jwtScheme = new OpenApiSecurityScheme
    {
        Name = "Authorization",
        Description = "JWT Authorization header using the Bearer scheme. Example: Bearer {token}",
        In = ParameterLocation.Header,
        Type = SecuritySchemeType.Http,
        Scheme = "bearer",
        BearerFormat = "JWT",
        Reference = new OpenApiReference
        {
            Type = ReferenceType.SecurityScheme,
            Id = "Bearer"
        }
    };
    c.AddSecurityDefinition("Bearer", jwtScheme);
    c.AddSecurityRequirement(new OpenApiSecurityRequirement
    {
        { jwtScheme, Array.Empty<string>() }
    });
});
builder.Services.AddTransient<IConfigureOptions<Swashbuckle.AspNetCore.SwaggerGen.SwaggerGenOptions>, ConfigureSwaggerOptions>();

var rlOptions = configuration.GetSection(RateLimitOptions.SectionName).Get<RateLimitOptions>() ?? new RateLimitOptions();
builder.Services.AddRateLimiter(options =>
{
    options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
    options.OnRejected = async (ctx, token) =>
    {
        ctx.HttpContext.Response.ContentType = "application/problem+json";
        var problem = System.Text.Json.JsonSerializer.Serialize(new
        {
            type = "https://httpstatuses.io/429",
            title = "Too Many Requests",
            status = 429,
            detail = "Rate limit exceeded. Please retry later.",
            traceId = ctx.HttpContext.TraceIdentifier
        });
        await ctx.HttpContext.Response.WriteAsync(problem, token);
    };
    options.AddFixedWindowLimiter(rlOptions.PolicyName, opt =>
    {
        opt.PermitLimit = rlOptions.PermitLimit;
        opt.Window = TimeSpan.FromSeconds(rlOptions.WindowSeconds);
        opt.QueueLimit = rlOptions.QueueLimit;
    });
    // Route-specific fixed window policies by IP
    options.AddPolicy("login", httpContext =>
        RateLimitPartition.GetFixedWindowLimiter(
            partitionKey: $"{httpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown"}:{httpContext.Request.Headers["X-Login-Id"].ToString()}",
            factory: _ => new FixedWindowRateLimiterOptions
            {
                PermitLimit = 10,
                Window = TimeSpan.FromMinutes(15),
                QueueLimit = 0
            }));
    options.AddPolicy("register", httpContext =>
        RateLimitPartition.GetFixedWindowLimiter(
            partitionKey: httpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown",
            factory: _ => new FixedWindowRateLimiterOptions
            {
                PermitLimit = 5,
                Window = TimeSpan.FromHours(1),
                QueueLimit = 0
            }));
    options.AddPolicy("otp", httpContext =>
        RateLimitPartition.GetFixedWindowLimiter(
            partitionKey: httpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown",
            factory: _ => new FixedWindowRateLimiterOptions
            {
                PermitLimit = 5,
                Window = TimeSpan.FromMinutes(5),
                QueueLimit = 0
            }));
    options.AddPolicy("refresh", httpContext =>
        RateLimitPartition.GetFixedWindowLimiter(
            partitionKey: httpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown",
            factory: _ => new FixedWindowRateLimiterOptions
            {
                PermitLimit = 60,
                Window = TimeSpan.FromMinutes(1),
                QueueLimit = 0
            }));
});

var useRefreshCookie = string.Equals(configuration["RefreshTokens:UseCookie"], "true", StringComparison.OrdinalIgnoreCase);
builder.Services.AddCors(policy =>
{
    var origins = (configuration["Cors:AllowedOrigins"] ?? string.Empty)
        .Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
    policy.AddPolicy("Default", p =>
    {
        p.SetIsOriginAllowed(origin => origins.Contains(origin));
        p.AllowAnyHeader();
        p.AllowAnyMethod();
        if (useRefreshCookie) p.AllowCredentials();
    });
});

builder.Services.AddHealthChecks()
    .AddCheck<AuthenticationAPI.Infrastructure.Health.DatabaseHealthCheck>("db")
    .AddCheck<AuthenticationAPI.Infrastructure.Health.KeyRingHealthCheck>("keys");

builder.Services.AddScoped<IRefreshTokenService, RefreshTokenService>();
builder.Services.AddScoped<IKeyRingService, KeyRingService>();
builder.Services.AddScoped<IClientAppService, ClientAppService>();
builder.Services.AddScoped<IRecoveryCodeService, RecoveryCodeService>();
builder.Services.AddScoped<ISessionService, SessionService>();
builder.Services.AddSingleton<IKeyRingCache, KeyRingCache>();
builder.Services.AddSingleton<ITotpService, TotpService>();
builder.Services.AddSingleton<IPasswordBreachChecker, NoOpPasswordBreachChecker>();
builder.Services.AddSingleton<IEmailTemplateRenderer, EmailTemplateRenderer>();
builder.Services.AddHostedService<KeyRotationHostedService>();
// Data Protection keys persistence (so MFA secrets survive restarts)
var dpBuilder = builder.Services.AddDataProtection()
    .SetApplicationName("AuthenticationAPI")
    .SetDefaultKeyLifetime(TimeSpan.FromDays(90));
var dpStorage = (configuration["DataProtection:Storage"] ?? "file").ToLowerInvariant();
if (dpStorage == "file")
{
    var path = configuration["DataProtection:FileSystemPath"] ?? Path.Combine(builder.Environment.ContentRootPath, "keys");
    Directory.CreateDirectory(path);
    dpBuilder.PersistKeysToFileSystem(new DirectoryInfo(path));

    // Encrypt keys at rest when safe to do so (no breaking change for existing keys)
    if (OperatingSystem.IsWindows())
    {
        // Use user profile scope in Development; production can switch to certificate/KeyVault via config
        dpBuilder.ProtectKeysWithDpapi();
    }
}
else if (dpStorage == "azure")
{
    // Protect keys with a Key Vault key and persist to Blob Storage
    var blobConn = configuration["Azure:Blob:ConnectionString"];
    var containerName = configuration["Azure:Blob:Container"] ?? "dataprotection";
    var keyId = configuration["Azure:KeyVault:KeyId"]; // e.g., https://<vault>.vault.azure.net/keys/<keyname>/<version>
    var vaultUrlCfg = configuration["Azure:KeyVault:VaultUrl"];
    if (string.IsNullOrWhiteSpace(blobConn) || string.IsNullOrWhiteSpace(keyId) || string.IsNullOrWhiteSpace(vaultUrlCfg))
    {
        throw new InvalidOperationException("DataProtection storage 'azure' requires Azure:Blob:ConnectionString, Azure:Blob:Container, Azure:KeyVault:VaultUrl and Azure:KeyVault:KeyId.");
    }
    try
    {
        var blobServiceClient = new Azure.Storage.Blobs.BlobServiceClient(blobConn);
        var container = blobServiceClient.GetBlobContainerClient(containerName);
        container.CreateIfNotExists();

        var cred = new Azure.Identity.DefaultAzureCredential();
        var blobUri = new Uri($"{container.Uri}/keys.xml");
        dpBuilder.PersistKeysToAzureBlobStorage(blobUri, cred);
        dpBuilder.ProtectKeysWithAzureKeyVault(new Uri(keyId), cred);
    }
    catch (Exception ex)
    {
        Console.WriteLine($"[Startup] Azure DP config failed: {ex.Message}");
        throw;
    }
}
// Future options (placeholders): other providers can be plugged in here based on config
builder.Services.AddSingleton<IMfaSecretProtector, DataProtectionMfaSecretProtector>();
builder.Services.AddHttpClient();
// Optional: enable HIBP password breach checks if configured
var useHibp = string.Equals(configuration["PasswordBreach:Provider"], "hibp", StringComparison.OrdinalIgnoreCase)
              || string.Equals(configuration["PasswordBreach:UseHibp"], "true", StringComparison.OrdinalIgnoreCase);
if (useHibp)
{
    builder.Services.AddSingleton<IPasswordBreachChecker, HibpPasswordBreachChecker>();
}
// Shorten default Identity token lifetime to limit replay window
builder.Services.Configure<DataProtectionTokenProviderOptions>(o => o.TokenLifespan = TimeSpan.FromMinutes(30));
// Email provider: require SMTP in Production; support mapping from legacy env names
var smtpSection = configuration.GetSection(SmtpOptions.SectionName);
var smtpOpts = smtpSection.Get<SmtpOptions>() ?? new SmtpOptions();
// Map legacy flat env vars if Smtp section not fully provided
Func<string,string?> EnvOrCfg = key => configuration[key] ?? Environment.GetEnvironmentVariable(key);
if (string.IsNullOrWhiteSpace(smtpOpts.Host)) smtpOpts.Host = EnvOrCfg("SMTPServer") ?? EnvOrCfg("SMTPIP") ?? smtpOpts.Host;
if (smtpOpts.Port <= 0 && int.TryParse(EnvOrCfg("SMTPPort"), out var p)) smtpOpts.Port = p;
if (string.IsNullOrWhiteSpace(smtpOpts.From)) smtpOpts.From = EnvOrCfg("SMTPFrom") ?? smtpOpts.From;
if (string.IsNullOrWhiteSpace(smtpOpts.Username)) smtpOpts.Username = EnvOrCfg("SMTPUsername") ?? smtpOpts.From;
if (string.IsNullOrWhiteSpace(smtpOpts.Password)) smtpOpts.Password = EnvOrCfg("SMTPPassword") ?? smtpOpts.Password;
var useSslRaw = configuration["Smtp:UseSsl"] ?? EnvOrCfg("SMTPUseSsl");
if (string.IsNullOrWhiteSpace(useSslRaw) && smtpOpts.Port == 25) smtpOpts.UseSsl = false;
// Normalize whitespace
smtpOpts.Host = smtpOpts.Host?.Trim() ?? string.Empty;
smtpOpts.From = smtpOpts.From?.Trim() ?? string.Empty;
smtpOpts.Username = smtpOpts.Username?.Trim();
if (string.IsNullOrWhiteSpace(smtpOpts.Host) || smtpOpts.Port <= 0 || string.IsNullOrWhiteSpace(smtpOpts.From))
{
    Console.WriteLine($"[SMTP] Missing config. Host='{(string.IsNullOrEmpty(smtpOpts.Host)?"(empty)":smtpOpts.Host)}' Port='{smtpOpts.Port}' From='{(string.IsNullOrEmpty(smtpOpts.From)?"(empty)":smtpOpts.From)}'");
    throw new InvalidOperationException("SMTP is not configured. Set Smtp:Host, Smtp:Port, Smtp:From (or legacy SMTPServer/SMTPPort/SMTPFrom).");
}

builder.Services.AddSingleton<IEmailSender>(new AuthenticationAPI.Services.Email.SmtpEmailSender(smtpOpts));
Console.WriteLine($"[Startup] Using SMTP for email: {smtpOpts.Host}:{smtpOpts.Port} as {smtpOpts.FromName ?? smtpOpts.From}");

builder.Services.AddAuthorization(options =>
{
    // Require that the current access token was issued after a successful MFA step
    // This is indicated by the presence of the "amr" (Authentication Methods Reference) claim with value "mfa".
    options.AddPolicy("mfa", policy => policy.RequireClaim("amr", "mfa"));
});
builder.Services.AddMemoryCache();
// Choose throttle provider
var throttleOpts = configuration.GetSection(AuthenticationAPI.Models.Options.ThrottleOptions.SectionName).Get<AuthenticationAPI.Models.Options.ThrottleOptions>()
                  ?? new AuthenticationAPI.Models.Options.ThrottleOptions();
if (string.Equals(throttleOpts.Provider, "redis", StringComparison.OrdinalIgnoreCase))
{
    if (string.IsNullOrWhiteSpace(throttleOpts.RedisConnectionString))
        throw new InvalidOperationException("Throttle:RedisConnectionString is required when Provider=redis.");
    builder.Services.AddSingleton<AuthenticationAPI.Services.Throttle.IThrottleService>(sp =>
        new AuthenticationAPI.Services.Throttle.RedisThrottleService(throttleOpts.RedisConnectionString!));
}
else
{
    builder.Services.AddSingleton<AuthenticationAPI.Services.Throttle.IThrottleService, AuthenticationAPI.Services.Throttle.MemoryThrottleService>();
}
builder.Services.AddSingleton<IAuthorizationPolicyProvider, DynamicPermissionPolicyProvider>();

// Global server-side request size ceiling (defense-in-depth)
builder.WebHost.ConfigureKestrel(o =>
{
    o.Limits.MaxRequestBodySize = 20 * 1024;
    // Remove the 'Server: Kestrel' header to reduce fingerprinting
    o.AddServerHeader = false;
});

var app = builder.Build();

// Configure the HTTP request pipeline.
// Swagger: enabled by default in Development; disable in Production unless explicitly turned on
if (app.Environment.IsDevelopment() || string.Equals(configuration["Features:Swagger"], "true", StringComparison.OrdinalIgnoreCase))
{
    app.UseSwagger();
    // Wire Swagger to API versions
    var apiVersionProvider = app.Services.GetRequiredService<IApiVersionDescriptionProvider>();
    app.UseSwaggerUI(options =>
    {
        foreach (var description in apiVersionProvider.ApiVersionDescriptions)
        {
            var group = description.GroupName; // e.g., v1
            options.SwaggerEndpoint($"/swagger/{group}/swagger.json", $"Authentication API {group.ToUpperInvariant()}");
        }
    });
}

// Security headers (basic set)
app.Use(async (ctx, next) =>
{
    ctx.Response.Headers["X-Content-Type-Options"] = "nosniff";
    ctx.Response.Headers["X-Frame-Options"] = "DENY";
    ctx.Response.Headers["X-XSS-Protection"] = "0";
    ctx.Response.Headers["Referrer-Policy"] = "strict-origin-when-cross-origin";
    ctx.Response.Headers["Permissions-Policy"] = "geolocation=(), microphone=()";

    // CSP differs slightly by environment
    var csp = "default-src 'self'; script-src 'self'; style-src 'self' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; font-src 'self' https://cdnjs.cloudflare.com; img-src 'self' data:; connect-src 'self';";
    if (app.Environment.IsDevelopment())
    {
        csp = "default-src 'self'; script-src 'self'; style-src 'self' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; font-src 'self' https://cdnjs.cloudflare.com; img-src 'self' data:; connect-src 'self' https://cdn.jsdelivr.net ws://localhost:* wss://localhost:*;";
    }
    ctx.Response.Headers["Content-Security-Policy"] = csp;

    await next();
});
app.UseGlobalExceptionHandling();
app.UseCorrelationId();
// HSTS in non-development environments
if (!app.Environment.IsDevelopment())
{
    app.UseHsts();
}
// Respect proxy headers when enabled via config or env
var enableForwarded = !app.Environment.IsDevelopment()
    || string.Equals(configuration["ReverseProxy:Enabled"], "true", StringComparison.OrdinalIgnoreCase)
    || string.Equals(Environment.GetEnvironmentVariable("ASPNETCORE_FORWARDEDHEADERS_ENABLED"), "true", StringComparison.OrdinalIgnoreCase);
if (enableForwarded)
{
    app.UseForwardedHeaders(new ForwardedHeadersOptions
    {
        ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto | ForwardedHeaders.XForwardedHost
    });
}
app.UseHttpsRedirection();
// Enforce content type for JSON APIs
app.Use(async (ctx, next) =>
{
    if (ctx.Request.Method == HttpMethods.Post || ctx.Request.Method == HttpMethods.Put || ctx.Request.Method == HttpMethods.Patch)
    {
        var hasBody = ctx.Request.ContentLength.GetValueOrDefault() > 0 || ctx.Request.Headers.ContainsKey("Content-Length");
        var ct = ctx.Request.ContentType ?? string.Empty;
        if (hasBody && !ct.StartsWith("application/json", StringComparison.OrdinalIgnoreCase))
        {
            ctx.Response.StatusCode = StatusCodes.Status415UnsupportedMediaType;
            await ctx.Response.WriteAsync("Unsupported Media Type");
            return;
        }
    }
    await next();
});
app.UseStaticFiles();
app.UseCors("Default");

// Enforce explicit CORS origins in production
if (!app.Environment.IsDevelopment())
{
    var configuredOrigins = (configuration["Cors:AllowedOrigins"] ?? string.Empty)
        .Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
    if (configuredOrigins.Length == 0)
    {
        throw new InvalidOperationException("CORS is not configured. Set Cors:AllowedOrigins for production (semicolon-separated).");
    }

    // Block access to any /dev assets in production
    app.Use(async (ctx, next) =>
    {
        if (ctx.Request.Path.StartsWithSegments("/dev", StringComparison.OrdinalIgnoreCase))
        {
            ctx.Response.StatusCode = StatusCodes.Status404NotFound;
            return;
        }
        await next();
    });
}

// Do not cache authentication-related responses
app.Use(async (ctx, next) =>
{
    var path = ctx.Request.Path.Value ?? string.Empty;
    if (path.StartsWith("/api/authenticate", StringComparison.OrdinalIgnoreCase) ||
        path.StartsWith("/api/token", StringComparison.OrdinalIgnoreCase))
    {
        ctx.Response.Headers["Cache-Control"] = "no-store";
        ctx.Response.Headers["Pragma"] = "no-cache";
        ctx.Response.Headers["Expires"] = "0";
    }
    await next();
});

// Enforce secure cookie defaults for any cookie usage
// Cookies are not used for auth; cookie policy middleware removed.

app.UseAuthentication();
app.UseAuthorization();
var enableRateLimit = builder.Environment.IsDevelopment()
    ? string.Equals(configuration["Features:RateLimit"], "true", StringComparison.OrdinalIgnoreCase)
    : true;
if (enableRateLimit)
{
    app.UseRateLimiter();
}
// In Development, disable audit/idempotency unless explicitly enabled to avoid masking errors
var enableAudit = builder.Environment.IsDevelopment()
    ? string.Equals(configuration["Features:AuditAndIdempotency"], "true", StringComparison.OrdinalIgnoreCase)
    : true;
if (enableAudit)
{
    app.UseAuditAndIdempotency();
}

app.MapControllers();
app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Ui}/{action=Index}/{id?}");

// Health endpoints
app.MapHealthChecks("/health/live", new HealthCheckOptions
{
    Predicate = _ => false, // always healthy if app is running
    ResponseWriter = WriteHealthResponse
});
app.MapHealthChecks("/health/ready", new HealthCheckOptions
{
    Predicate = _ => true,
    ResponseWriter = WriteHealthResponse
});

// MVC handles UI routes now via UiController
// Lightweight ping that does not touch the database (useful for quick 200 check)
app.MapGet("/api/ping", () => Results.Ok(new { ok = true, time = DateTime.UtcNow }));

using (var scope = app.Services.CreateScope())
{
    // Ensure database is up-to-date in Development to avoid 500s from schema drift
    var autoMigrate = app.Environment.IsDevelopment() ?
        string.Equals(configuration["Features:AutoMigrate"], "true", StringComparison.OrdinalIgnoreCase) :
        string.Equals(configuration["Features:AutoMigrate"], "true", StringComparison.OrdinalIgnoreCase);
    if (autoMigrate)
    {
        try
        {
            var dbCtx = scope.ServiceProvider.GetRequiredService<AuthenticationAPI.Data.ApplicationDbContext>();
            await dbCtx.Database.MigrateAsync();
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[Startup] Migration failed: {ex.Message}");
        }

        try
        {
            var appDbCtx = scope.ServiceProvider.GetRequiredService<AuthenticationAPI.Data.AppDbContext>();
            await appDbCtx.Database.MigrateAsync();
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[Startup] AppDb migration failed: {ex.Message}");
        }
    }

    var doSeed = string.Equals(configuration["Features:Seed"], "true", StringComparison.OrdinalIgnoreCase);
    if (doSeed)
    {
        try
        {
            await Seed.SeedRoles(scope.ServiceProvider);
            await Seed.SeedPermissions(scope.ServiceProvider);
            // Only seed admin user if credentials are provided
            var adminEmail = configuration["SeedAdmin:Email"];
            var adminPassword = configuration["SeedAdmin:Password"];
            if (!string.IsNullOrWhiteSpace(adminEmail) && !string.IsNullOrWhiteSpace(adminPassword))
            {
                await Seed.SeedAdminUser(scope.ServiceProvider, adminEmail, adminPassword);
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[Startup] Seeding failed: {ex.Message}");
        }
    }
    // Seed signing key if none
    var db = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
    if (!db.SigningKeys.Any())
    {
        var keyRing = scope.ServiceProvider.GetRequiredService<IKeyRingService>();
        await keyRing.RotateAsync();
    }
    // Warm key cache
    var cache = scope.ServiceProvider.GetRequiredService<IKeyRingCache>();
    var allKeys = await scope.ServiceProvider.GetRequiredService<IKeyRingService>().GetAllActiveKeysAsync();
    cache.Set(allKeys);

}

app.Run();

static Task WriteHealthResponse(HttpContext context, HealthReport report)
{
    context.Response.ContentType = "application/json";
    var json = JsonSerializer.Serialize(new
    {
        status = report.Status.ToString(),
        details = report.Entries.Select(e => new { key = e.Key, status = e.Value.Status.ToString(), duration = e.Value.Duration.TotalMilliseconds }),
        timestamp = DateTime.UtcNow
    });
    return context.Response.WriteAsync(json);
}

// Make Program visible to WebApplicationFactory in tests
public partial class Program { }
