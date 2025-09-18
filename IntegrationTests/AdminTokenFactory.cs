using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Threading.Tasks;
using AuthenticationAPI.Models;
using Microsoft.AspNetCore.Identity;
using System.Net.Http.Json;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;

namespace IntegrationTests;

public static class AdminTokenFactory
{
    public static async Task<string> CreateAdminAsync(TestApplicationFactory factory, string? existingUserName = null)
    {
        var client = factory.CreateClient();
        string email = existingUserName == null ? $"admin_{Guid.NewGuid():N}@example.com" : existingUserName + "@example.com";
        string password = "Adm1n$tr0ngP@ss!";

        // Create admin user through invitation (we need to create an initial admin first)
        // For now, we'll create the admin directly in the database since we don't have a bootstrap admin
        using (var scope = factory.Services.CreateScope())
        {
            var userMgr = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
            var roleMgr = scope.ServiceProvider.GetRequiredService<RoleManager<IdentityRole>>();

            // Ensure Admin role exists
            if (!await roleMgr.RoleExistsAsync("Admin"))
                await roleMgr.CreateAsync(new IdentityRole("Admin"));

            // Create admin user directly
            var adminUser = new ApplicationUser
            {
                UserName = email,
                Email = email,
                EmailConfirmed = true
            };

            var createResult = await userMgr.CreateAsync(adminUser, password);
            if (!createResult.Succeeded)
            {
                throw new Exception("Failed to create admin user: " + string.Join(";", createResult.Errors.Select(e => e.Code + ":" + e.Description)));
            }

            // Add to Admin role
            var roleResult = await userMgr.AddToRoleAsync(adminUser, "Admin");
            if (!roleResult.Succeeded)
            {
                throw new Exception("Failed to assign Admin role: " + string.Join(";", roleResult.Errors.Select(e => e.Code + ":" + e.Description)));
            }
        }

        // Login to get token
        var loginResponse = await client.PostAsJsonAsync("/api/v1/authenticate/login", new { Identifier = email, Password = password });
        loginResponse.EnsureSuccessStatusCode();

        var loginJson = await loginResponse.Content.ReadAsStringAsync();
        using var doc = System.Text.Json.JsonDocument.Parse(loginJson);
        return doc.RootElement.GetProperty("token").GetString()!;
    }
}
