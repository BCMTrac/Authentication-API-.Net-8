using System.Text;
using AuthenticationAPI.Data;
using AuthenticationAPI.Models;
using AuthenticationAPI.Infrastructure.Middleware;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.OpenApi.Models;
using AuthenticationAPI.Services;
using AuthenticationAPI.Models.Options;
using Microsoft.Extensions.Options;
using Microsoft.AspNetCore.Diagnostics.HealthChecks;
using System.Text.Json;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using Microsoft.AspNetCore.RateLimiting;
using System.Threading.RateLimiting;
using Microsoft.AspNetCore.Mvc;
using AuthenticationAPI.Infrastructure.Security;
using Microsoft.AspNetCore.Authorization;
using AuthenticationAPI.Services.Email;

var builder = WebApplication.CreateBuilder(args);
var configuration = builder.Configuration;

// Structured logging (basic JSON via built-in) - Serilog can replace later
builder.Logging.ClearProviders();
builder.Logging.AddJsonConsole(options =>
{
    options.IncludeScopes = true;
    options.TimestampFormat = "yyyy-MM-ddTHH:mm:ss.fffZ";
});

// Add services to the container.

// Strongly typed options
builder.Services.Configure<JwtOptions>(configuration.GetSection(JwtOptions.SectionName));
builder.Services.Configure<RateLimitOptions>(configuration.GetSection(RateLimitOptions.SectionName));

// For Entity Framework (SQL Server)
builder.Services.AddDbContext<ApplicationDbContext>(options => options.UseSqlServer(configuration.GetConnectionString("DefaultConnection")));

// For Identity (allow space in usernames for your scenario)
builder.Services.AddIdentity<ApplicationUser, IdentityRole>(options =>
    {
        if (!options.User.AllowedUserNameCharacters.Contains(' '))
        {
            options.User.AllowedUserNameCharacters += " ";
        }
        // Adjust password rules here if needed
    })
    .AddEntityFrameworkStores<ApplicationDbContext>()
    .AddDefaultTokenProviders();

// Authentication (detailed options configured via IConfigureOptions implementation)
builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultScheme = JwtBearerDefaults.AuthenticationScheme;
}).AddJwtBearer();
builder.Services.AddTransient<IConfigureOptions<JwtBearerOptions>, ConfigureJwtBearerOptions>();

builder.Services.AddControllers();
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
    c.SwaggerDoc("v1", new OpenApiInfo { Title = "Authentication API", Version = "v1" });

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

var rlOptions = configuration.GetSection(RateLimitOptions.SectionName).Get<RateLimitOptions>() ?? new RateLimitOptions();
builder.Services.AddRateLimiter(options =>
{
    options.AddFixedWindowLimiter(rlOptions.PolicyName, opt =>
    {
        opt.PermitLimit = rlOptions.PermitLimit;
        opt.Window = TimeSpan.FromSeconds(rlOptions.WindowSeconds);
        opt.QueueLimit = rlOptions.QueueLimit;
    });
});

// CORS (locked down placeholder)
builder.Services.AddCors(policy =>
{
    policy.AddPolicy("Default", p => p
        .WithOrigins("http://localhost:4200")
        .AllowAnyHeader()
        .AllowAnyMethod());
});

// Health checks (custom DB check)
builder.Services.AddHealthChecks().AddCheck<AuthenticationAPI.Infrastructure.Health.DatabaseHealthCheck>("db");

builder.Services.AddScoped<IRefreshTokenService, RefreshTokenService>();
builder.Services.AddScoped<IKeyRingService, KeyRingService>();
builder.Services.AddScoped<IClientAppService, ClientAppService>();
builder.Services.AddSingleton<IMfaSecretProtector, MfaSecretProtector>();
builder.Services.AddSingleton<IEmailSender, ConsoleEmailSender>();
builder.Services.AddSingleton<IKeyRingCache, KeyRingCache>();
builder.Services.AddSingleton<ITotpService, TotpService>();

// Authorization policies (example)
builder.Services.AddAuthorization();
builder.Services.AddSingleton<IAuthorizationPolicyProvider, DynamicPermissionPolicyProvider>();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

// Security headers (basic set)
app.Use(async (ctx, next) =>
{
    ctx.Response.Headers["X-Content-Type-Options"] = "nosniff";
    ctx.Response.Headers["X-Frame-Options"] = "DENY";
    ctx.Response.Headers["X-XSS-Protection"] = "0"; // modern browsers ignore/obsolete
    ctx.Response.Headers["Referrer-Policy"] = "strict-origin-when-cross-origin";
    ctx.Response.Headers["Permissions-Policy"] = "geolocation=(), microphone=()";
    // Minimal CSP (adjust later)
    ctx.Response.Headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'; base-uri 'none';";
    await next();
});
app.UseGlobalExceptionHandling();
app.UseCorrelationId();
app.UseHttpsRedirection();
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

using (var scope = app.Services.CreateScope())
{
    await Seed.SeedRoles(scope.ServiceProvider);
    await Seed.SeedPermissions(scope.ServiceProvider);
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
