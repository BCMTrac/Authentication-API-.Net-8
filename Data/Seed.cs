using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using AuthenticationAPI.Models;
using Microsoft.Extensions.Configuration;

namespace AuthenticationAPI.Data;

public static class Seed
{
    private static readonly string[] Roles = ["User", "Admin"];
    private static readonly (string name, string description)[] Permissions = new[]
    {
        ("users.read", "Read user data"),
        ("users.write", "Modify user data")
    };

    public static async Task SeedRoles(IServiceProvider serviceProvider)
    {
        using var scope = serviceProvider.CreateScope();
        var roleManager = scope.ServiceProvider.GetRequiredService<RoleManager<IdentityRole>>();

        foreach (var role in Roles)
        {
            if (!await roleManager.RoleExistsAsync(role))
            {
                await roleManager.CreateAsync(new IdentityRole(role));
            }
        }
    }

    public static async Task SeedPermissions(IServiceProvider serviceProvider)
    {
        using var scope = serviceProvider.CreateScope();
        var appDb = scope.ServiceProvider.GetRequiredService<AppDbContext>();
        var roleManager = scope.ServiceProvider.GetRequiredService<RoleManager<IdentityRole>>();

        // Ensure permissions
        foreach (var perm in Permissions)
        {
            if (!await appDb.Permissions.AnyAsync(p => p.Name == perm.name))
            {
                appDb.Permissions.Add(new Permission { Name = perm.name, Description = perm.description });
            }
        }
        await appDb.SaveChangesAsync();

        // Assign all permissions to Admin role
        var adminRole = await roleManager.FindByNameAsync("Admin");
        if (adminRole != null)
        {
            var allPerms = await appDb.Permissions.ToListAsync();
            foreach (var p in allPerms)
            {
                if (!await appDb.RolePermissions.AnyAsync(rp => rp.RoleId == adminRole.Id && rp.PermissionId == p.Id))
                {
                    appDb.RolePermissions.Add(new RolePermission { RoleId = adminRole.Id, PermissionId = p.Id });
                }
            }
            await appDb.SaveChangesAsync();
        }
    }

    public static async Task SeedAdminUser(IServiceProvider serviceProvider, string email, string password)
    {
        using var scope = serviceProvider.CreateScope();
        var userManager = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
        var roleManager = scope.ServiceProvider.GetRequiredService<RoleManager<IdentityRole>>();
        var appDb = scope.ServiceProvider.GetRequiredService<AppDbContext>();
        var authDb = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
        var normalizer = scope.ServiceProvider.GetRequiredService<ILookupNormalizer>();
        var configuration = scope.ServiceProvider.GetRequiredService<IConfiguration>();
        var fullNameFromEnv = configuration["SeedAdmin:FullName"];
        var phoneFromEnv = configuration["SeedAdmin:Phone"];
        var userNameFromEnv = configuration["SeedAdmin:Username"];

        // Ensure Admin role exists
        if (!await roleManager.RoleExistsAsync("Admin"))
        {
            await roleManager.CreateAsync(new IdentityRole("Admin"));
        }

        // Handle duplicates gracefully: query directly to avoid SingleOrDefault in FindByEmailAsync
        var normalizedEmail = normalizer.NormalizeEmail(email) ?? email.ToUpperInvariant();
        var matches = await authDb.Users.Where(u => u.NormalizedEmail == normalizedEmail).ToListAsync();
        ApplicationUser? admin = matches.FirstOrDefault();

        if (matches.Count > 1)
        {
            // Deduplicate by renaming extras so future runs won't crash; keep the first match as the canonical admin
            foreach (var dupe in matches.Skip(1))
            {
                try
                {
                    var at = (dupe.Email ?? email).IndexOf('@');
                    var local = at >= 0 ? (dupe.Email ?? email).Substring(0, at) : (dupe.Email ?? email);
                    var domain = at >= 0 ? (dupe.Email ?? email).Substring(at) : "";
                    var newEmail = $"{local}+dupe-{Guid.NewGuid():N}{domain}";
                    dupe.Email = newEmail;
                    dupe.NormalizedEmail = normalizer.NormalizeEmail(newEmail);
                }
                catch { /* best-effort clean-up */ }
            }
            await authDb.SaveChangesAsync();
        }

        if (admin == null)
        {
            admin = new ApplicationUser
            {
                UserName = string.IsNullOrWhiteSpace(userNameFromEnv) ? email : userNameFromEnv,
                Email = email,
                EmailConfirmed = true,
                FullName = string.IsNullOrWhiteSpace(fullNameFromEnv) ? null : fullNameFromEnv,
                PhoneNumber = string.IsNullOrWhiteSpace(phoneFromEnv) ? null : phoneFromEnv
            };
            var createResult = await userManager.CreateAsync(admin, password);
            if (!createResult.Succeeded)
            {
                throw new InvalidOperationException("Failed to create seed admin user: " + string.Join(",", createResult.Errors.Select(e => e.Description)));
            }
        }
        // In production, do not reset password or update profile details automatically for existing admin.
        // Ensure permissions assigned to role (reuse existing logic lightly)
        var allPerms = await appDb.Permissions.ToListAsync();
        var adminRole = await roleManager.FindByNameAsync("Admin");
        if (adminRole != null)
        {
            foreach (var p in allPerms)
            {
                if (!await appDb.RolePermissions.AnyAsync(rp => rp.RoleId == adminRole.Id && rp.PermissionId == p.Id))
                {
                    appDb.RolePermissions.Add(new RolePermission { RoleId = adminRole.Id, PermissionId = p.Id });
                }
            }
            await appDb.SaveChangesAsync();
        }
    }
}
