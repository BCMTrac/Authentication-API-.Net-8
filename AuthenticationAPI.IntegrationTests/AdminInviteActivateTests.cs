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

namespace AuthenticationAPI.IntegrationTests;

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
        var username = NewUser();
        var password = "Adm1n$tr0ngP@ss!";
        (await client.PostAsJsonAsync("/api/v1/authenticate/register", new RegisterModel { Email = email, Username = username, Password = password, TermsAccepted = true })).EnsureSuccessStatusCode();
        string confirmToken;
        using (var scope = _factory.Services.CreateScope())
        {
            var userMgr = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
            var roleMgr = scope.ServiceProvider.GetRequiredService<RoleManager<IdentityRole>>();
            if (!await roleMgr.RoleExistsAsync("Admin")) await roleMgr.CreateAsync(new IdentityRole("Admin"));
            var user = await userMgr.FindByEmailAsync(email);
            confirmToken = await userMgr.GenerateEmailConfirmationTokenAsync(user!);
        }
        (await client.PostAsJsonAsync("/api/v1/authenticate/confirm-email", new { email, token = confirmToken })).EnsureSuccessStatusCode();
        // New scope after confirmation so concurrency stamp matches
        using (var scope2 = _factory.Services.CreateScope())
        {
            var userMgr2 = scope2.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
            var user2 = await userMgr2.FindByEmailAsync(email);
            var addResult = await userMgr2.AddToRoleAsync(user2!, "Admin");
            if (!addResult.Succeeded)
            {
                var errors = string.Join(";", addResult.Errors.Select(e => e.Code + ":" + e.Description));
                var roles = await userMgr2.GetRolesAsync(user2!);
                throw new Exception("Failed to add admin role: " + errors + " | existing roles: " + string.Join(",", roles));
            }
        }
        var login = await client.PostAsJsonAsync("/api/v1/authenticate/login", new { Identifier = username, Password = password });
        login.StatusCode.Should().Be(HttpStatusCode.OK);
        var json = await login.Content.ReadAsStringAsync();
        using var doc = JsonDocument.Parse(json);
        var tokenStr = doc.RootElement.GetProperty("token").GetString()!;
        var refresh = doc.RootElement.GetProperty("refreshToken").GetString()!;
        return (tokenStr, refresh);
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
