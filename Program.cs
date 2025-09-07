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
using AuthenticationAPI.Models.Options;
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

// Load .env if present (supports local dev and on-server env-file usage) BEFORE building configuration
try { Env.Load(); } catch { /* optional */ }

var builder = WebApplication.CreateBuilder(args);
var configuration = builder.Configuration;

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

builder.Services.AddDbContext<ApplicationDbContext>(options => options.UseSqlServer(configuration.GetConnectionString("DefaultConnection")));

builder.Services.AddIdentity<ApplicationUser, IdentityRole>(options =>
    {
        if (!options.User.AllowedUserNameCharacters.Contains(' '))
        {
            options.User.AllowedUserNameCharacters += " ";
        }
    // Enforce strong password policy in all environments
    options.Password.RequireDigit = true;
    options.Password.RequireLowercase = true;
    options.Password.RequireUppercase = true;
    options.Password.RequireNonAlphanumeric = true;
    options.Password.RequiredLength = 8;
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

builder.Services.AddControllers();

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
    options.AddFixedWindowLimiter(rlOptions.PolicyName, opt =>
    {
        opt.PermitLimit = rlOptions.PermitLimit;
        opt.Window = TimeSpan.FromSeconds(rlOptions.WindowSeconds);
        opt.QueueLimit = rlOptions.QueueLimit;
    });
    // Route-specific fixed window policies by IP
    options.AddPolicy("login", httpContext =>
        RateLimitPartition.GetFixedWindowLimiter(
            partitionKey: httpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown",
            factory: _ => new FixedWindowRateLimiterOptions
            {
                PermitLimit = 5,
                Window = TimeSpan.FromMinutes(1),
                QueueLimit = 0
            }));
    options.AddPolicy("register", httpContext =>
        RateLimitPartition.GetFixedWindowLimiter(
            partitionKey: httpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown",
            factory: _ => new FixedWindowRateLimiterOptions
            {
                PermitLimit = 2,
                Window = TimeSpan.FromMinutes(1),
                QueueLimit = 0
            }));
    options.AddPolicy("otp", httpContext =>
        RateLimitPartition.GetFixedWindowLimiter(
            partitionKey: httpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown",
            factory: _ => new FixedWindowRateLimiterOptions
            {
                PermitLimit = 3,
                Window = TimeSpan.FromMinutes(1),
                QueueLimit = 0
            }));
});

builder.Services.AddCors(policy =>
{
    var origins = (configuration["Cors:AllowedOrigins"] ?? "http://localhost:4200").Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
    policy.AddPolicy("Default", p => p
        .WithOrigins(origins)
        .AllowAnyHeader()
        .AllowAnyMethod());
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
builder.Services.AddHostedService<KeyRotationHostedService>();
// Data Protection keys persistence (so MFA secrets survive restarts)
var dpBuilder = builder.Services.AddDataProtection().SetApplicationName("AuthenticationAPI");
var dpStorage = (configuration["DataProtection:Storage"] ?? "file").ToLowerInvariant();
if (dpStorage == "file")
{
    var path = configuration["DataProtection:FileSystemPath"] ?? Path.Combine(builder.Environment.ContentRootPath, "keys");
    Directory.CreateDirectory(path);
    dpBuilder.PersistKeysToFileSystem(new DirectoryInfo(path));
}
// Future options (placeholders): azureblob/keyvault can be plugged in here based on config
builder.Services.AddSingleton<IMfaSecretProtector, DataProtectionMfaSecretProtector>();
builder.Services.AddHttpClient();
// SendGrid email provider (exclusive)
var sgApiKey = configuration["SendGrid:ApiKey"] ?? configuration["SENDGRID_API_KEY"] ?? string.Empty;
var sgFrom = configuration["SendGrid:From"] ?? string.Empty;
var sgFromName = configuration["SendGrid:FromName"] ?? string.Empty;
if (string.IsNullOrWhiteSpace(sgApiKey) || string.IsNullOrWhiteSpace(sgFrom))
{
    throw new InvalidOperationException("Email is not configured. Set SendGrid:ApiKey and SendGrid:From (or SENDGRID_API_KEY env var).");
}
builder.Services.AddSingleton<IEmailSender>(sp =>
    new SendGridEmailSender(
        sp.GetRequiredService<IHttpClientFactory>(),
        sgApiKey,
        sgFrom,
        string.IsNullOrWhiteSpace(sgFromName) ? "Authentication API" : sgFromName));

builder.Services.AddAuthorization();
builder.Services.AddSingleton<IAuthorizationPolicyProvider, DynamicPermissionPolicyProvider>();

var app = builder.Build();

// Configure the HTTP request pipeline.
// Enable Swagger in all environments for now (prod testing). Protect behind auth later if needed.
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

// Security headers (basic set)
app.Use(async (ctx, next) =>
{
    ctx.Response.Headers["X-Content-Type-Options"] = "nosniff";
    ctx.Response.Headers["X-Frame-Options"] = "DENY";
    ctx.Response.Headers["X-XSS-Protection"] = "0"; // modern browsers ignore/obsolete
    ctx.Response.Headers["Referrer-Policy"] = "strict-origin-when-cross-origin";
    ctx.Response.Headers["Permissions-Policy"] = "geolocation=(), microphone=()";
    // CSP: strict by default; allow basic inline for the dev console under /dev
    var path = ctx.Request.Path.Value ?? string.Empty;
    if (path.StartsWith("/dev", StringComparison.OrdinalIgnoreCase))
    {
        ctx.Response.Headers["Content-Security-Policy"] = "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'";
    }
    else
    {
        ctx.Response.Headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'; base-uri 'none';";
    }
    await next();
});
app.UseGlobalExceptionHandling();
app.UseCorrelationId();
app.UseHttpsRedirection();
app.UseStaticFiles();
app.UseCors("Default");

app.UseAuthentication();
app.UseAuthorization();
app.UseRateLimiter();
app.UseAuditAndIdempotency();

app.MapControllers();

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

// Convenience root redirect to Swagger UI
app.MapGet("/", () => Results.Redirect("/swagger"));
// Dev console entry
app.MapGet("/dev", () => Results.Redirect("/dev/index.html"));

using (var scope = app.Services.CreateScope())
{
    await Seed.SeedRoles(scope.ServiceProvider);
    await Seed.SeedPermissions(scope.ServiceProvider);
    // Admin user seed. In non-Development, require env/user-secrets to provide credentials.
    // Environment variables keys: SeedAdmin__Email and SeedAdmin__Password (double underscore)
    var env = app.Environment;
    var adminEmail = configuration["SeedAdmin:Email"];
    var adminPassword = configuration["SeedAdmin:Password"];
    if (string.IsNullOrWhiteSpace(adminEmail) || string.IsNullOrWhiteSpace(adminPassword))
    {
        if (!env.IsDevelopment())
        {
            throw new InvalidOperationException("Missing SeedAdmin__Email/SeedAdmin__Password. Set them via environment variables or user-secrets.");
        }
        // Development fallback
        adminEmail ??= "admin@local";
        adminPassword ??= "Change_this_Admin1!";
    }
    await Seed.SeedAdminUser(scope.ServiceProvider, adminEmail!, adminPassword!);
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
