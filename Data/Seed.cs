using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using AuthenticationAPI.Models;

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
        var context = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
        var roleManager = scope.ServiceProvider.GetRequiredService<RoleManager<IdentityRole>>();

        // Ensure permissions
        foreach (var perm in Permissions)
        {
            if (!await context.Permissions.AnyAsync(p => p.Name == perm.name))
            {
                context.Permissions.Add(new Permission { Name = perm.name, Description = perm.description });
            }
        }
        await context.SaveChangesAsync();

        // Assign all permissions to Admin role
        var adminRole = await roleManager.FindByNameAsync("Admin");
        if (adminRole != null)
        {
            var allPerms = await context.Permissions.ToListAsync();
            foreach (var p in allPerms)
            {
                if (!await context.RolePermissions.AnyAsync(rp => rp.RoleId == adminRole.Id && rp.PermissionId == p.Id))
                {
                    context.RolePermissions.Add(new RolePermission { RoleId = adminRole.Id, PermissionId = p.Id });
                }
            }
            await context.SaveChangesAsync();
        }
    }
}
