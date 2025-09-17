using AuthenticationAPI.Data;
using Microsoft.AspNetCore.DataProtection;
using System.IO;
using AuthenticationAPI.Models;
using AuthenticationAPI.Infrastructure.Middleware;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authentication.Cookies;
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
using AuthenticationAPI.Infrastructure.Filters;

using Microsoft.AspNetCore.RateLimiting;
using System.Threading.RateLimiting;
using Microsoft.AspNetCore.Mvc;
using AuthenticationAPI.Infrastructure.Security;
using Microsoft.AspNetCore.Authorization;
using AuthenticationAPI.Models.Options;
using Microsoft.AspNetCore.HttpOverrides;
using FluentValidation.AspNetCore;
using FluentValidation;
using Hangfire;
using Hangfire.SqlServer;
using Microsoft.Extensions.Logging;
using AuthenticationAPI.Validators;
using AuthenticationAPI.Infrastructure.Health;
using AuthenticationAPI.Services.Throttle;
using Microsoft.Extensions.Diagnostics.HealthChecks;

var builder = WebApplication.CreateBuilder(args);

// Use the host configuration so test overrides (WebApplicationFactory) apply
builder.Configuration
    .AddJsonFile("appsettings.json", optional: false, reloadOnChange: true)
    ;
var configuration = builder.Configuration;

builder.Logging.ClearProviders();
builder.Logging.AddJsonConsole(options =>
{
    options.IncludeScopes = true;
    options.TimestampFormat = "yyyy-MM-ddTHH:mm:ss.fffZ";
});

builder.Services.Configure<JwtOptions>(configuration.GetSection(JwtOptions.SectionName));
builder.Services.Configure<RateLimitOptions>(configuration.GetSection(RateLimitOptions.SectionName));
builder.Services.Configure<KeyRotationOptions>(configuration.GetSection(KeyRotationOptions.SectionName));
builder.Services.Configure<BridgeOptions>(
    configuration.GetSection(BridgeOptions.SectionName));
builder.Services.Configure<ThrottleOptions>(
    configuration.GetSection(ThrottleOptions.SectionName));

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
    options.Password.RequireDigit = true;
    options.Password.RequireLowercase = true;
    options.Password.RequireUppercase = true;
    options.Password.RequireNonAlphanumeric = true;
    options.Password.RequiredLength = 12;
        options.Lockout.AllowedForNewUsers = true;
        options.Lockout.MaxFailedAccessAttempts = 10;
        options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(15);
    })
    .AddEntityFrameworkStores<ApplicationDbContext>()
    .AddDefaultTokenProviders();

builder.Services.AddScoped<IPasswordHasher<ApplicationUser>, Argon2PasswordHasher<ApplicationUser>>();

// Authentication: Use Identity (cookie) as default for MVC, still register JWT for API endpoints
builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = IdentityConstants.ApplicationScheme;
    options.DefaultChallengeScheme = IdentityConstants.ApplicationScheme;
    options.DefaultScheme = IdentityConstants.ApplicationScheme;
})
    .AddJwtBearer();
// Harden Identity application cookie
builder.Services.ConfigureApplicationCookie(options =>
{
    options.Cookie.Name = "bcm_auth";
    options.Cookie.HttpOnly = true;
    options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
    options.Cookie.SameSite = SameSiteMode.Strict;
    options.SlidingExpiration = true;
    options.ExpireTimeSpan = TimeSpan.FromMinutes(60);
    options.Events.OnRedirectToLogin = ctx =>
    {
        // Keep default for HTML, suppress for API
        if (ctx.Request.Path.StartsWithSegments("/api"))
        {
            ctx.Response.StatusCode = StatusCodes.Status401Unauthorized;
            return Task.CompletedTask;
        }
        ctx.Response.Redirect(ctx.RedirectUri);
        return Task.CompletedTask;
    };
    options.Events.OnRedirectToAccessDenied = ctx =>
    {
        if (ctx.Request.Path.StartsWithSegments("/api"))
        {
            ctx.Response.StatusCode = StatusCodes.Status403Forbidden;
            return Task.CompletedTask;
        }
        ctx.Response.Redirect(ctx.RedirectUri);
        return Task.CompletedTask;
    };
});
builder.Services.AddTransient<IConfigureOptions<JwtBearerOptions>, ConfigureJwtBearerOptions>();
builder.Services.AddHsts(options =>
{
    options.Preload = true;
    options.IncludeSubDomains = true;
    options.MaxAge = TimeSpan.FromDays(180);
});

builder.Services.AddControllersWithViews(o =>
{
    o.Filters.Add<InputNormalizationFilter>();
})
    .AddJsonOptions(opts =>
    {
        opts.JsonSerializerOptions.ReadCommentHandling = System.Text.Json.JsonCommentHandling.Disallow;
        opts.JsonSerializerOptions.AllowTrailingCommas = false;
        opts.JsonSerializerOptions.IgnoreReadOnlyFields = false;
        opts.JsonSerializerOptions.UnknownTypeHandling = System.Text.Json.Serialization.JsonUnknownTypeHandling.JsonNode;
    });

builder.Services.AddFluentValidationAutoValidation();
builder.Services.AddFluentValidationClientsideAdapters();
builder.Services.AddValidatorsFromAssemblyContaining<RegisterModelValidator>();

builder.Services.AddApiVersioning(o =>
{
    o.AssumeDefaultVersionWhenUnspecified = true;
    o.DefaultApiVersion = new ApiVersion(1, 0);
    o.ReportApiVersions = true;
});
builder.Services.AddVersionedApiExplorer(o =>
{
    o.GroupNameFormat = "'v'VVV";
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

// Session for wizard state (role & scheme selection)
builder.Services.AddSession(options =>
{
    options.Cookie.HttpOnly = true;
    options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
    options.Cookie.SameSite = SameSiteMode.Strict;
    options.Cookie.Name = "bcm_sess";
    options.IdleTimeout = TimeSpan.FromMinutes(30);
});

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
    .AddCheck<DatabaseHealthCheck>("db")
    .AddCheck<KeyRingHealthCheck>("keys");

builder.Services.AddScoped<IRefreshTokenService, RefreshTokenService>();
builder.Services.AddScoped<IKeyRingService, KeyRingService>();
builder.Services.AddScoped<IClientAppService, ClientAppService>();
builder.Services.AddScoped<IUserAccountService, UserAccountService>();
builder.Services.AddScoped<IOnboardingService, OnboardingService>();
builder.Services.AddScoped<ITenantService, TenantService>();
builder.Services.AddScoped<IAuditService, AuditService>();
builder.Services.AddHttpContextAccessor();
builder.Services.AddScoped<IRecoveryCodeService, RecoveryCodeService>();
builder.Services.AddScoped<ISessionService, SessionService>();
builder.Services.AddSingleton<IKeyRingCache, KeyRingCache>();
builder.Services.AddSingleton<ITotpService, TotpService>();
builder.Services.AddSingleton<IPasswordBreachChecker, NoOpPasswordBreachChecker>();
builder.Services.AddSingleton<IEmailTemplateRenderer, EmailTemplateRenderer>();
builder.Services.AddHostedService<KeyRotationHostedService>();

var dpBuilder = builder.Services.AddDataProtection()
    .SetApplicationName("AuthenticationAPI")
    .SetDefaultKeyLifetime(TimeSpan.FromDays(90));
var path = configuration["DataProtection:FileSystemPath"] ?? Path.Combine(builder.Environment.ContentRootPath, "keys");
Directory.CreateDirectory(path);
dpBuilder.PersistKeysToFileSystem(new DirectoryInfo(path));
if (OperatingSystem.IsWindows()) dpBuilder.ProtectKeysWithDpapi();
builder.Services.AddSingleton<IMfaSecretProtector, DataProtectionMfaSecretProtector>();
builder.Services.AddHttpClient();
var useHibp = string.Equals(configuration["PasswordBreach:Provider"], "hibp", StringComparison.OrdinalIgnoreCase)
              || string.Equals(configuration["PasswordBreach:UseHibp"], "true", StringComparison.OrdinalIgnoreCase);
if (useHibp)
{
    builder.Services.AddSingleton<IPasswordBreachChecker, HibpPasswordBreachChecker>();
}
builder.Services.Configure<DataProtectionTokenProviderOptions>(o => o.TokenLifespan = TimeSpan.FromMinutes(30));
var smtpOpts = configuration.GetSection(SmtpOptions.SectionName).Get<SmtpOptions>() ?? new SmtpOptions();

if (string.IsNullOrWhiteSpace(smtpOpts.Host) || smtpOpts.Port <= 0 || string.IsNullOrWhiteSpace(smtpOpts.From))
{
    throw new InvalidOperationException("SMTP is not configured in appsettings. Set Smtp:Host, Smtp:Port, Smtp:From (optional: Smtp:FromName, Smtp:Username, Smtp:Password, Smtp:UseSsl).");
}

builder.Services.AddSingleton<IEmailSender, SmtpEmailSender>();
builder.Services.AddTransient<IEmailJob, EmailJob>();

builder.Services.AddAuthorization(options =>
{
    options.AddPolicy(AuthConstants.Policies.Mfa, policy => policy.RequireClaim(AuthConstants.ClaimTypes.Amr, AuthConstants.AmrValues.Mfa));
});
builder.Services.AddMemoryCache();
var throttleOpts = configuration.GetSection(AuthenticationAPI.Models.Options.ThrottleOptions.SectionName).Get<AuthenticationAPI.Models.Options.ThrottleOptions>()
                  ?? new AuthenticationAPI.Models.Options.ThrottleOptions();
if (string.Equals(throttleOpts.Provider, "redis", StringComparison.OrdinalIgnoreCase))
{
    if (string.IsNullOrWhiteSpace(throttleOpts.RedisConnectionString))
        throw new InvalidOperationException("Throttle:RedisConnectionString is required when Provider=redis.");
    builder.Services.AddSingleton<IThrottleService>(sp =>
        new RedisThrottleService(throttleOpts.RedisConnectionString!));
}
else
{
    builder.Services.AddSingleton<IThrottleService, MemoryThrottleService>();
}
builder.Services.AddSingleton<IAuthorizationPolicyProvider, DynamicPermissionPolicyProvider>();

builder.Services.AddHangfire(configuration => configuration
    .SetDataCompatibilityLevel(CompatibilityLevel.Version_170)
    .UseSimpleAssemblyNameTypeSerializer()
    .UseRecommendedSerializerSettings()
    .UseSqlServerStorage(builder.Configuration.GetConnectionString("DefaultConnection"), new SqlServerStorageOptions
    {
        CommandBatchMaxTimeout = TimeSpan.FromMinutes(5),
        SlidingInvisibilityTimeout = TimeSpan.FromMinutes(5),
        QueuePollInterval = TimeSpan.Zero,
        UseRecommendedIsolationLevel = true,
        DisableGlobalLocks = true
    }));

builder.Services.AddHangfireServer();

builder.WebHost.ConfigureKestrel(o =>
{
    o.Limits.MaxRequestBodySize = 20 * 1024;
    o.AddServerHeader = false;
});

var app = builder.Build();

var logger = app.Services.GetRequiredService<ILogger<Program>>();

if (app.Environment.IsDevelopment() || string.Equals(configuration["Features:Swagger"], "true", StringComparison.OrdinalIgnoreCase))
{
    app.UseSwagger();
    var apiVersionProvider = app.Services.GetRequiredService<IApiVersionDescriptionProvider>();
    app.UseSwaggerUI(options =>
    {
        foreach (var description in apiVersionProvider.ApiVersionDescriptions)
        {
            var group = description.GroupName;
            options.SwaggerEndpoint($"/swagger/{group}/swagger.json", $"Authentication API {group.ToUpperInvariant()}");
        }
    });
    app.UseHangfireDashboard();
}

app.Use(async (ctx, next) =>
{
    ctx.Response.Headers["X-Content-Type-Options"] = "nosniff";
    ctx.Response.Headers["X-Frame-Options"] = "DENY";
    ctx.Response.Headers["X-XSS-Protection"] = "0";
    ctx.Response.Headers["Referrer-Policy"] = "strict-origin-when-cross-origin";
    ctx.Response.Headers["Permissions-Policy"] = "geolocation=(), microphone=()";

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
if (!app.Environment.IsDevelopment())
{
    app.UseHsts();
}
var enableForwarded = !app.Environment.IsDevelopment()
    || string.Equals(configuration["ReverseProxy:Enabled"], "true", StringComparison.OrdinalIgnoreCase);
if (enableForwarded)
{
    app.UseForwardedHeaders(new ForwardedHeadersOptions
    {
        ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto | ForwardedHeaders.XForwardedHost
    });
}
if (!app.Environment.IsDevelopment() || string.Equals(configuration["Features:HttpsRedirect"], "true", StringComparison.OrdinalIgnoreCase))
{
    app.UseHttpsRedirection();
}
// Allow standard form posts (x-www-form-urlencoded & multipart) in addition to JSON
app.Use(async (ctx, next) =>
{
    if (HttpMethods.IsPost(ctx.Request.Method) || HttpMethods.IsPut(ctx.Request.Method) || HttpMethods.IsPatch(ctx.Request.Method))
    {
        var hasBody = ctx.Request.ContentLength.GetValueOrDefault() > 0;
        if (hasBody)
        {
            var ct = ctx.Request.ContentType ?? string.Empty;
            if (!(ct.StartsWith("application/json", StringComparison.OrdinalIgnoreCase)
                  || ct.StartsWith("application/x-www-form-urlencoded", StringComparison.OrdinalIgnoreCase)
                  || ct.StartsWith("multipart/form-data", StringComparison.OrdinalIgnoreCase)))
            {
                ctx.Response.StatusCode = StatusCodes.Status415UnsupportedMediaType;
                await ctx.Response.WriteAsync("Unsupported Media Type");
                return;
            }
        }
    }
    await next();
});
app.UseStaticFiles();
app.UseSession();
app.UseCors("Default");

if (!app.Environment.IsDevelopment())
{
    var configuredOrigins = (configuration["Cors:AllowedOrigins"] ?? string.Empty)
        .Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
    if (configuredOrigins.Length == 0)
    {
        throw new InvalidOperationException("CORS is not configured. Set Cors:AllowedOrigins for production (semicolon-separated).");
    }

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

app.UseAuthentication();
app.UseAuthorization();
var enableRateLimit = builder.Environment.IsDevelopment()
    ? string.Equals(configuration["Features:RateLimit"], "true", StringComparison.OrdinalIgnoreCase)
    : true;
if (enableRateLimit)
{
    app.UseRateLimiter();
}
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

app.MapHealthChecks("/health/live", new HealthCheckOptions
{
    Predicate = _ => false,
    ResponseWriter = WriteHealthResponse
});
app.MapHealthChecks("/health/ready", new HealthCheckOptions
{
    Predicate = _ => true,
    ResponseWriter = WriteHealthResponse
});

app.MapGet("/api/ping", () => Results.Ok(new { ok = true, time = DateTime.UtcNow }));

using (var scope = app.Services.CreateScope())
{
    var autoMigrate = app.Environment.IsDevelopment() ?
        string.Equals(configuration["Features:AutoMigrate"], "true", StringComparison.OrdinalIgnoreCase) :
        string.Equals(configuration["Features:AutoMigrate"], "true", StringComparison.OrdinalIgnoreCase);
    if (autoMigrate)
    {
        try
        {
            var dbCtx = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
            await dbCtx.Database.MigrateAsync();
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "[Startup] Migration failed.");
        }

        try
        {
            var appDbCtx = scope.ServiceProvider.GetRequiredService<AppDbContext>();
            await appDbCtx.Database.MigrateAsync();
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "[Startup] AppDb migration failed.");
        }
    }

    var doSeed = string.Equals(configuration["Features:Seed"], "true", StringComparison.OrdinalIgnoreCase);
    if (doSeed)
    {
        try
        {
            await Seed.SeedRoles(scope.ServiceProvider);
            await Seed.SeedPermissions(scope.ServiceProvider);
            var adminEmail = configuration["SeedAdmin:Email"];
            var adminPassword = configuration["SeedAdmin:Password"];
            if (!string.IsNullOrWhiteSpace(adminEmail) && !string.IsNullOrWhiteSpace(adminPassword))
            {
                await Seed.SeedAdminUser(scope.ServiceProvider, adminEmail, adminPassword);
            }
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "[Startup] Seeding failed.");
        }
    }
    var db = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
    if (!db.SigningKeys.Any())
    {
        var keyRing = scope.ServiceProvider.GetRequiredService<IKeyRingService>();
        await keyRing.RotateAsync();
    }
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

public partial class Program { }
