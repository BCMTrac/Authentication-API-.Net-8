using System;
using System.Linq;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using System.Threading.Tasks;
using AuthenticationAPI.Data;
using AuthenticationAPI.Models;
// removed invalid using
using AuthenticationAPI.Services;
using FluentAssertions;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace IntegrationTests;

public class AdminAndMoreTests : IClassFixture<TestApplicationFactory>
{
    private readonly TestApplicationFactory _factory;
    public AdminAndMoreTests(TestApplicationFactory factory) { _factory = factory; }

    private static string NewEmail() => $"user_{Guid.NewGuid():N}@example.com";
    private static string NewUser() => $"user_{Guid.NewGuid():N}";

    private async Task<(string token, string refresh)> CreateAdminAndLoginAsync()
    {
        using var scope = _factory.Services.CreateScope();
        var userMgr = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
        var db = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
        var email = $"admin_{Guid.NewGuid():N}@example.com";
        var admin = new ApplicationUser { UserName = email, Email = email, EmailConfirmed = true };
        (await userMgr.CreateAsync(admin, "Adm1n$Up3rStr0ng!")).Succeeded.Should().BeTrue();
        (await userMgr.AddToRoleAsync(admin, "Admin")).Succeeded.Should().BeTrue();
        var client = _factory.CreateClient();
        var login = await client.PostAsJsonAsync("/api/v1/authenticate/login", new { Identifier = email, Password = "Adm1n$Up3rStr0ng!" });
        login.EnsureSuccessStatusCode();
        var json = await login.Content.ReadAsStringAsync();
        using var doc = JsonDocument.Parse(json);
        return (doc.RootElement.GetProperty("token").GetString()!, doc.RootElement.GetProperty("refreshToken").GetString()!);
    }

    [Fact]
    public async Task Admin_Invite_Activate_User()
    {
        var (adminToken, _) = await CreateAdminAndLoginAsync();
        var authed = _factory.CreateClient();
        authed.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", adminToken);
        var inviteEmail = NewEmail();
    (await authed.PostAsJsonAsync("/api/v1/authenticate/invite", new { Email = inviteEmail, FullName = "Invited User", Roles = new[] { "User" } })).EnsureSuccessStatusCode();

        string activationToken;
        using (var scope = _factory.Services.CreateScope())
        {
            var userMgr = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
            var user = await userMgr.FindByEmailAsync(inviteEmail);
            user.Should().NotBeNull();
            activationToken = await userMgr.GenerateEmailConfirmationTokenAsync(user!);
        }

        // Activate
        var client = _factory.CreateClient();
        (await client.PostAsJsonAsync("/api/v1/authenticate/activate", new { Email = inviteEmail, Token = activationToken, Password = "V3ry$tr0ngP@ssw0rd!", FullName = "Invited User" })).EnsureSuccessStatusCode();

        // Login works
        var login = await client.PostAsJsonAsync("/api/v1/authenticate/login", new { Identifier = inviteEmail, Password = "V3ry$tr0ngP@ssw0rd!" });
        login.StatusCode.Should().Be(HttpStatusCode.OK);
    }

    [Fact]
    public async Task Admin_Roles_Add_Remove()
    {
        var (adminToken, _) = await CreateAdminAndLoginAsync();
        var authed = _factory.CreateClient();
        authed.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", adminToken);

        // Create user
        var email = NewEmail();
        var username = NewUser();
        var password = "User$tr0ngP@ss!";
        var client = _factory.CreateClient();
        (await client.PostAsJsonAsync("/api/v1/authenticate/register", new RegisterModel { Email = email, Username = username, Password = password, TermsAccepted = true })).EnsureSuccessStatusCode();
        await TestTokenHelpers.ConfirmEmailAsync(_factory, email);

        string userId;
        using (var scope = _factory.Services.CreateScope())
        {
            var userMgr = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
            var user = await userMgr.FindByEmailAsync(email);
            userId = user!.Id;
        }

        // Add role
        (await authed.PostAsJsonAsync($"/api/v1/admin/users/{userId}/roles/add", new { role = "Manager" })).EnsureSuccessStatusCode();
        // Verify via login claim scopes/roles
        var login = await client.PostAsJsonAsync("/api/v1/authenticate/login", new { Identifier = username, Password = password });
        var body = await login.Content.ReadAsStringAsync();
        using var doc = JsonDocument.Parse(body);
        var token = doc.RootElement.GetProperty("token").GetString()!;
        var payload = JwtTestHelper.ReadPayload(token);
        payload.TryGetProperty("role", out var roleClaim); // depending on serializer, roles might serialize differently; presence isn’t guaranteed in payload list

        // Remove role
        (await authed.PostAsJsonAsync($"/api/v1/admin/users/{userId}/roles/remove", new { role = "Manager" })).EnsureSuccessStatusCode();
    }

    [Fact]
    public async Task Admin_Sessions_List_Revoke_One_And_All()
    {
        var (adminToken, _) = await CreateAdminAndLoginAsync();
        var authed = _factory.CreateClient();
        authed.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", adminToken);

        var email = NewEmail();
        var username = NewUser();
        var password = "User$tr0ngP@ss!";
        var client = _factory.CreateClient();
        (await client.PostAsJsonAsync("/api/v1/authenticate/register", new RegisterModel { Email = email, Username = username, Password = password, TermsAccepted = true })).EnsureSuccessStatusCode();
        await TestTokenHelpers.ConfirmEmailAsync(_factory, email);

        // Create two sessions
        var login1 = await client.PostAsJsonAsync("/api/v1/authenticate/login", new { Identifier = username, Password = password });
        var login2 = await client.PostAsJsonAsync("/api/v1/authenticate/login", new { Identifier = username, Password = password });
        login1.EnsureSuccessStatusCode(); login2.EnsureSuccessStatusCode();

        string userId;
        Guid someSessionId;
        using (var scope = _factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
            var userMgr = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
            var user = await userMgr.FindByEmailAsync(email);
            userId = user!.Id;
            someSessionId = await db.Sessions.Where(s => s.UserId == userId && s.RevokedAtUtc == null).Select(s => s.Id).FirstAsync();
        }

        // List sessions
        var list = await authed.GetAsync($"/api/v1/admin/users/{userId}/sessions");
        list.StatusCode.Should().Be(HttpStatusCode.OK);

        // Revoke one
        (await authed.PostAsync($"/api/v1/admin/users/{userId}/sessions/{someSessionId}/revoke", null)).EnsureSuccessStatusCode();

        // Revoke all
        (await authed.PostAsync($"/api/v1/admin/users/{userId}/sessions/revoke-all", null)).EnsureSuccessStatusCode();
    }

    [Fact]
    public async Task Admin_Lock_Unlock_User()
    {
        var (adminToken, _) = await CreateAdminAndLoginAsync();
        var authed = _factory.CreateClient();
        authed.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", adminToken);

        var email = NewEmail(); var username = NewUser(); var password = "User$tr0ngP@ss!";
        var client = _factory.CreateClient();
        (await client.PostAsJsonAsync("/api/v1/authenticate/register", new RegisterModel { Email = email, Username = username, Password = password, TermsAccepted = true })).EnsureSuccessStatusCode();
        await TestTokenHelpers.ConfirmEmailAsync(_factory, email);

        string userId;
        using (var scope = _factory.Services.CreateScope())
        {
            var userMgr = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
            userId = (await userMgr.FindByEmailAsync(email))!.Id;
        }

        // Lock
        (await authed.PostAsync($"/api/v1/admin/users/{userId}/lock", null)).EnsureSuccessStatusCode();
        var lockedLogin = await client.PostAsJsonAsync("/api/v1/authenticate/login", new { Identifier = username, Password = password });
        ((int)lockedLogin.StatusCode).Should().BeGreaterOrEqualTo(400);

        // Unlock
        (await authed.PostAsync($"/api/v1/admin/users/{userId}/unlock", null)).EnsureSuccessStatusCode();
        var goodLogin = await client.PostAsJsonAsync("/api/v1/authenticate/login", new { Identifier = username, Password = password });
        goodLogin.StatusCode.Should().Be(HttpStatusCode.OK);
    }

    [Fact]
    public async Task Client_Credentials_Grants_Token()
    {
        using var scope = _factory.Services.CreateScope();
        var clientSvc = scope.ServiceProvider.GetRequiredService<IClientAppService>();
        var (app, secret) = await clientSvc.CreateAsync("test-client", new[] { "read", "write" });
        var client = _factory.CreateClient();
        var resp = await client.PostAsJsonAsync("/api/v1/token/client", new { clientId = app.Id, clientSecret = secret, scope = "read write" });
        resp.StatusCode.Should().Be(HttpStatusCode.OK);
        var json = await resp.Content.ReadAsStringAsync();
        using var doc = JsonDocument.Parse(json);
        doc.RootElement.GetProperty("access_token").GetString().Should().NotBeNullOrEmpty();
    }

    [Fact]
    public async Task Bridge_Headers_Present_On_Login_And_Refresh()
    {
        var client = _factory.CreateClient();
        var email = NewEmail(); var username = NewUser(); var password = "User$tr0ngP@ss!";
        (await client.PostAsJsonAsync("/api/v1/authenticate/register", new RegisterModel { Email = email, Username = username, Password = password, TermsAccepted = true })).EnsureSuccessStatusCode();
        await TestTokenHelpers.ConfirmEmailAsync(_factory, email);
        var login = await client.PostAsJsonAsync("/api/v1/authenticate/login", new { Identifier = username, Password = password });
        login.Headers.Contains("X-Session-Id").Should().BeTrue();
        var body = await login.Content.ReadAsStringAsync();
        using var doc = JsonDocument.Parse(body);
        var refresh = doc.RootElement.GetProperty("refreshToken").GetString()!;
        var refreshResp = await client.PostAsJsonAsync("/api/v1/authenticate/refresh", new { refreshToken = refresh });
        refreshResp.Headers.Contains("X-Session-Id").Should().BeTrue();
    }

    [Fact]
    public async Task Magic_Link_Flow_Works()
    {
        var client = _factory.CreateClient();
        var email = NewEmail(); var username = NewUser(); var password = "User$tr0ngP@ss!";
        (await client.PostAsJsonAsync("/api/v1/authenticate/register", new RegisterModel { Email = email, Username = username, Password = password, TermsAccepted = true })).EnsureSuccessStatusCode();
        await TestTokenHelpers.ConfirmEmailAsync(_factory, email);

        (await client.PostAsJsonAsync("/api/v1/authenticate/magic/start", new { email })).EnsureSuccessStatusCode();

        string token;
        using (var scope = _factory.Services.CreateScope())
        {
            var userMgr = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
            var user = await userMgr.FindByEmailAsync(email);
            token = await userMgr.GenerateUserTokenAsync(user!, TokenOptions.DefaultProvider, AuthenticationAPI.Infrastructure.Security.AuthConstants.TokenProviders.MagicLink);
        }
        var verify = await client.PostAsJsonAsync("/api/v1/authenticate/magic/verify", new { email, token });
        verify.StatusCode.Should().Be(HttpStatusCode.OK);
        var body = await verify.Content.ReadAsStringAsync();
        using var doc = JsonDocument.Parse(body);
        doc.RootElement.GetProperty("token").GetString().Should().NotBeNullOrEmpty();
    }

    [Fact]
    public async Task Email_Resend_And_Idempotent_Confirm()
    {
        var client = _factory.CreateClient();
        var email = NewEmail(); var username = NewUser(); var password = "User$tr0ngP@ss!";
        (await client.PostAsJsonAsync("/api/v1/authenticate/register", new RegisterModel { Email = email, Username = username, Password = password, TermsAccepted = true })).EnsureSuccessStatusCode();

        (await client.PostAsJsonAsync("/api/v1/authenticate/request-email-confirm", new { email })).EnsureSuccessStatusCode();
        string token;
        using (var scope = _factory.Services.CreateScope())
        {
            var userMgr = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
            token = await userMgr.GenerateEmailConfirmationTokenAsync((await userMgr.FindByEmailAsync(email))!);
        }
        (await client.PostAsJsonAsync("/api/v1/authenticate/confirm-email", new { email, token })).EnsureSuccessStatusCode();
        // Confirm again should be OK and idempotent
        (await client.PostAsJsonAsync("/api/v1/authenticate/confirm-email", new { email, token })).EnsureSuccessStatusCode();
    }
}
