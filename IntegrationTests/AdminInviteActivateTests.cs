using System;
using System.Linq;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using System.Threading.Tasks;
using AuthenticationAPI.Data;
using AuthenticationAPI.Models;
using FluentAssertions;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace IntegrationTests;

public class AdminInviteActivateTests : IClassFixture<TestApplicationFactory>
{
    private readonly TestApplicationFactory _factory;
    public AdminInviteActivateTests(TestApplicationFactory factory) { _factory = factory; }

    private static string NewEmail() => $"user_{Guid.NewGuid():N}@example.com";
    private static string NewUser() => $"admin_{Guid.NewGuid():N}";

    private async Task<(string token, string refresh)> CreateSeededAdminAsync()
    {
        var client = _factory.CreateClient();
        var email = NewEmail();
        var password = "Adm1n$tr0ngP@ss!";
        
        // Create admin through direct database manipulation (since we can't register anymore)
        using (var scope = _factory.Services.CreateScope())
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
            if (createResult.Succeeded)
            {
                await userMgr.AddToRoleAsync(adminUser, "Admin");
            }
        }
        
        // Login as admin
        return await TestHelpers.LoginAsync(client, email, password);
    }

    [Fact]
    public async Task Admin_Invites_User_User_Activates_With_Roles()
    {
        var (adminToken, _) = await CreateSeededAdminAsync();
        var adminClient = _factory.CreateClient();
        adminClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", adminToken);

        var invitedEmail = NewEmail();
        var inviteResp = await adminClient.PostAsJsonAsync("/api/v1/authenticate/invite", new { Email = invitedEmail, FullName = "Invited User", Roles = new[] { "User" } });
        inviteResp.StatusCode.Should().Be(HttpStatusCode.OK);

        string activationToken;
        using (var scope = _factory.Services.CreateScope())
        {
            var userMgr = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
            var user = await userMgr.FindByEmailAsync(invitedEmail);
            user.Should().NotBeNull();
            activationToken = await userMgr.GenerateEmailConfirmationTokenAsync(user!);
        }

        var activateClient = _factory.CreateClient();
        var newPassword = "UserAct1vat3d!";
        var activateResp = await activateClient.PostAsJsonAsync("/api/v1/authenticate/activate", new { Email = invitedEmail, Token = activationToken, Password = newPassword, FullName = "Invited User" });
        activateResp.StatusCode.Should().Be(HttpStatusCode.OK);

        // Login as invited user
        var login = await activateClient.PostAsJsonAsync("/api/v1/authenticate/login", new { Identifier = invitedEmail, Password = newPassword });
        login.StatusCode.Should().Be(HttpStatusCode.OK);
        var loginJson = await login.Content.ReadAsStringAsync();
        using var loginDoc = JsonDocument.Parse(loginJson);
        var token = loginDoc.RootElement.GetProperty("token").GetString();
        token.Should().NotBeNullOrEmpty();
    }
}
