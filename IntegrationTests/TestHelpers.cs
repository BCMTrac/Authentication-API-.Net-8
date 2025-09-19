using System.Net.Http;
using System.Net.Http.Json;
using System.Text.Json;
using System.Threading.Tasks;
using AuthenticationAPI.Models;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.AspNetCore.Identity;

namespace IntegrationTests;

public static class TestHelpers
{


    public static async Task<(string token, string refresh)> InviteActivateAndLoginAsync(TestApplicationFactory factory, HttpClient client, string email, string password, string[]? roles = null)
    {
        // First, we need an admin to invite the user
        var adminClient = factory.CreateClient();
        var adminEmail = $"admin_{System.Guid.NewGuid():N}@example.com";
        var adminPassword = "Adm1n$tr0ngP@ss!";
        
        // Create admin through direct database manipulation (since we can't register anymore)
        using (var scope = factory.Services.CreateScope())
        {
            var userMgr = scope.ServiceProvider.GetRequiredService<UserManager<AuthenticationAPI.Models.ApplicationUser>>();
            var roleMgr = scope.ServiceProvider.GetRequiredService<RoleManager<IdentityRole>>();
            
            // Ensure Admin role exists
            if (!await roleMgr.RoleExistsAsync("Admin")) 
                await roleMgr.CreateAsync(new IdentityRole("Admin"));
            
            // Create admin user directly
            var adminUser = new AuthenticationAPI.Models.ApplicationUser 
            { 
                UserName = adminEmail, 
                Email = adminEmail, 
                EmailConfirmed = true 
            };
            var createResult = await userMgr.CreateAsync(adminUser, adminPassword);
            if (createResult.Succeeded)
            {
                await userMgr.AddToRoleAsync(adminUser, "Admin");
            }
        }
        
        // Login as admin
        var (adminToken, _) = await LoginAsync(adminClient, adminEmail, adminPassword);
        adminClient.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", adminToken);
        
        // Invite the user
        var inviteResp = await adminClient.PostAsJsonAsync("/api/v1/authenticate/invite", new { Email = email, FullName = "Test User", Roles = roles ?? new[] { "User" } });
        inviteResp.EnsureSuccessStatusCode();
        
        // Get activation token
        string activationToken;
        using (var scope = factory.Services.CreateScope())
        {
            var userMgr = scope.ServiceProvider.GetRequiredService<UserManager<AuthenticationAPI.Models.ApplicationUser>>();
            var user = await userMgr.FindByEmailAsync(email);
            activationToken = await userMgr.GenerateEmailConfirmationTokenAsync(user!);
        }
        
        // Activate the user
        var activateResp = await client.PostAsJsonAsync("/api/v1/authenticate/activate", new { Email = email, Token = activationToken, Password = password, FullName = "Test User" });
        activateResp.EnsureSuccessStatusCode();
        
        // Login as the activated user
        return await LoginAsync(client, email, password);
    }

    public static async Task<(string token, string refresh)> LoginAsync(HttpClient client, string identifier, string password)
    {
        var req = new LoginModel { Identifier = identifier, Password = password };
        var resp = await client.PostAsJsonAsync("/api/v1/authenticate/login", req);
        resp.EnsureSuccessStatusCode();
        var json = await resp.Content.ReadAsStringAsync();
        using var doc = JsonDocument.Parse(json);
        var token = doc.RootElement.GetProperty("token").GetString()!;
        var refresh = doc.RootElement.GetProperty("refreshToken").GetString()!;
        return (token, refresh);
    }
}
