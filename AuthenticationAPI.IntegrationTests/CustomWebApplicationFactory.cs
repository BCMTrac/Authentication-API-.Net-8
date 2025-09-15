using System.Linq;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using AuthenticationAPI.Data;

public class CustomWebApplicationFactory : WebApplicationFactory<Program>
{
    private SqliteConnection _authConn = default!;
    private SqliteConnection _appConn = default!;

    protected override void ConfigureWebHost(Microsoft.AspNetCore.Hosting.IWebHostBuilder builder)
    {
        builder.UseEnvironment("Test");
        builder.ConfigureServices(services =>
        {
            var authDb = services.SingleOrDefault(d => d.ServiceType == typeof(DbContextOptions<ApplicationDbContext>));
            if (authDb is not null) services.Remove(authDb);
            var appDb = services.SingleOrDefault(d => d.ServiceType == typeof(DbContextOptions<AppDbContext>));
            if (appDb is not null) services.Remove(appDb);

            _authConn = new SqliteConnection("DataSource=:memory:");
            _authConn.Open();
            _appConn = new SqliteConnection("DataSource=:memory:");
            _appConn.Open();

            services.AddDbContext<ApplicationDbContext>(o => o.UseSqlite(_authConn));
            services.AddDbContext<AppDbContext>(o => o.UseSqlite(_appConn));

            var sp = services.BuildServiceProvider();
            using var scope = sp.CreateScope();
            scope.ServiceProvider.GetRequiredService<ApplicationDbContext>().Database.EnsureCreated();
            scope.ServiceProvider.GetRequiredService<AppDbContext>().Database.EnsureCreated();

            // Seed a basic admin user for login tests
            var userManager = scope.ServiceProvider.GetRequiredService<Microsoft.AspNetCore.Identity.UserManager<AuthenticationAPI.Models.ApplicationUser>>();
            var existing = await userManager.FindByNameAsync("testAdmin");
            if (existing == null)
            {
                var admin = new AuthenticationAPI.Models.ApplicationUser
                {
                    UserName = "testAdmin",
                    Email = "testadmin@example.com",
                    EmailConfirmed = true
                };
                await userManager.CreateAsync(admin, "SuperSecretPassword123!");
            }
        });
    }

    protected override void Dispose(bool disposing)
    {
        base.Dispose(disposing);
        _authConn?.Dispose();
        _appConn?.Dispose();
    }
}
