using System;
using System.Linq;
using AuthenticationAPI.Data;
using AuthenticationAPI.Models;
using AuthenticationAPI.Services;
using AuthenticationAPI.Services.Email;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Hosting;

namespace IntegrationTests;

public class TestEmailSender : IEmailSender
{
    public record SentEmail(string To, string Subject, string Html);
    private readonly List<SentEmail> _sent = new();
    public IReadOnlyList<SentEmail> Sent => _sent;
    public void QueueSendAsync(string to, string subject, string html)
    {
        _sent.Add(new SentEmail(to, subject, html));
    }
}

public class TestApplicationFactory : WebApplicationFactory<Program>
{
    public TestEmailSender EmailSender { get; } = new();
    private SqliteConnection? _identityConn;
    private SqliteConnection? _appConn;

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.ConfigureAppConfiguration((ctx, cfg) =>
        {
            var dict = new Dictionary<string, string?>
            {
                ["Logging:LogLevel:Default"] = "Warning",
                ["Features:Swagger"] = "false",
                ["Features:AuditAndIdempotency"] = "false",
                ["Features:RateLimit"] = "false",
                ["Features:HttpsRedirect"] = "false",
                ["Bridge:Enabled"] = "true",
                ["Bridge:ApiKey"] = "test-bridge-key",
                ["Bridge:ApiKeyHeader"] = "X-Bridge-Key",
                ["Bridge:HeaderNames:0"] = "X-Session-Id",
                ["Bridge:HeaderNames:1"] = "X-SessionID",
                ["Bridge:JwtHeaderName"] = "X-Auth-JWT",
                ["Smtp:Host"] = "localhost",
                ["Smtp:Port"] = "25",
                ["Smtp:From"] = "test@example.com",
                ["PasswordBreach:UseHibp"] = "false",
                ["RefreshTokens:UseCookie"] = "false",
                ["JWT:ValidIssuer"] = "https://test",
                ["JWT:ValidAudience"] = "https://test",
                ["JWT:AccessTokenMinutes"] = "5"
            };
            cfg.AddInMemoryCollection(dict!);
        });

        builder.ConfigureServices(services =>
        {
            // Remove real DB contexts
            var descriptor1 = services.SingleOrDefault(d => d.ServiceType == typeof(DbContextOptions<ApplicationDbContext>));
            if (descriptor1 != null) services.Remove(descriptor1);
            var descriptor2 = services.SingleOrDefault(d => d.ServiceType == typeof(DbContextOptions<AppDbContext>));
            if (descriptor2 != null) services.Remove(descriptor2);

            _identityConn = new SqliteConnection("DataSource=:memory:");
            _identityConn.Open();
            _appConn = new SqliteConnection("DataSource=:memory:");
            _appConn.Open();

            services.AddDbContext<ApplicationDbContext>(options => options.UseSqlite(_identityConn));
            services.AddDbContext<AppDbContext>(options => options.UseSqlite(_appConn));

            // Replace email sender
            var existingEmail = services.SingleOrDefault(s => s.ServiceType == typeof(IEmailSender));
            if (existingEmail != null) services.Remove(existingEmail);
            services.AddSingleton<IEmailSender>(EmailSender);

            // Prevent Hangfire background server from starting, keep core services for dashboard registration
            var hostedToRemove = services.Where(s => s.ServiceType == typeof(IHostedService)
                                                     && (s.ImplementationType?.FullName?.Contains("Hangfire") == true))
                                         .ToList();
            foreach (var h in hostedToRemove) services.Remove(h);

            // Ensure DBs are created and roles exist
            var sp = services.BuildServiceProvider();
            using var scope = sp.CreateScope();
            var idCtx = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
            idCtx.Database.EnsureCreated();
            var appCtx = scope.ServiceProvider.GetRequiredService<AppDbContext>();
            appCtx.Database.EnsureCreated();
            var roleMgr = scope.ServiceProvider.GetRequiredService<RoleManager<IdentityRole>>();
            if (!roleMgr.RoleExistsAsync("User").GetAwaiter().GetResult())
            {
                roleMgr.CreateAsync(new IdentityRole("User")).GetAwaiter().GetResult();
            }
            if (!roleMgr.RoleExistsAsync("Admin").GetAwaiter().GetResult())
            {
                roleMgr.CreateAsync(new IdentityRole("Admin")).GetAwaiter().GetResult();
            }

            // Force NoOp password breach checker in tests regardless of appsettings
            var breachDescriptors = services.Where(s => s.ServiceType == typeof(IPasswordBreachChecker)).ToList();
            foreach (var d in breachDescriptors) services.Remove(d);
            services.AddSingleton<IPasswordBreachChecker, NoOpPasswordBreachChecker>();
        });
    }

    protected override void Dispose(bool disposing)
    {
        base.Dispose(disposing);
        _identityConn?.Dispose();
        _appConn?.Dispose();
    }
}
