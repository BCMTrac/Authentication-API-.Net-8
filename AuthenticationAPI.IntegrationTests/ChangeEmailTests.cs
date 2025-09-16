using System;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using System.Threading.Tasks;
using AuthenticationAPI.Models;
using FluentAssertions;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace AuthenticationAPI.IntegrationTests;

public class ChangeEmailTests : IClassFixture<TestApplicationFactory>
{
    private readonly TestApplicationFactory _factory;
    public ChangeEmailTests(TestApplicationFactory factory) { _factory = factory; }

    private static string NewEmail() => $"user_{Guid.NewGuid():N}@example.com";
    private static string NewUser() => $"user_{Guid.NewGuid():N}";

    [Fact]
    public async Task Change_Email_Bumps_TokenVersion_And_Revokes_Refresh()
    {
        var client = _factory.CreateClient();
        var email = NewEmail();
        var username = NewUser();
        var password = "V3ry$tr0ngP@ssw0rd!";
        (await client.PostAsJsonAsync("/api/v1/authenticate/register", new RegisterModel { Email = email, Username = username, Password = password, TermsAccepted = true })).EnsureSuccessStatusCode();
        await TestTokenHelpers.ConfirmEmailAsync(_factory, email);

        var login = await client.PostAsJsonAsync("/api/v1/authenticate/login", new { Identifier = username, Password = password });
        var loginJson = await login.Content.ReadAsStringAsync();
        using var loginDoc = JsonDocument.Parse(loginJson);
        var token = loginDoc.RootElement.GetProperty("token").GetString()!;
        var refresh = loginDoc.RootElement.GetProperty("refreshToken").GetString()!;

        var authed = _factory.CreateClient();
        authed.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
        var newEmail = NewEmail();
        (await authed.PostAsJsonAsync("/api/v1/authenticate/change-email/start", new { newEmail })).EnsureSuccessStatusCode();

        string changeToken;
        using (var scope = _factory.Services.CreateScope())
        {
            var userMgr = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
            var user = await userMgr.FindByEmailAsync(email);
            changeToken = await userMgr.GenerateChangeEmailTokenAsync(user!, newEmail);
        }

        var confirm = await authed.PostAsJsonAsync("/api/v1/authenticate/change-email/confirm", new { newEmail, token = changeToken });
        confirm.StatusCode.Should().Be(HttpStatusCode.OK);

        // Old access token should be invalid now
        var me = await authed.GetAsync("/api/v1/users/me");
        me.StatusCode.Should().Be(HttpStatusCode.Unauthorized);

        // Old refresh should be unusable
        var r = await client.PostAsJsonAsync("/api/v1/authenticate/refresh", new { refreshToken = refresh });
        r.StatusCode.Should().BeOneOf(HttpStatusCode.BadRequest, HttpStatusCode.Unauthorized);

        // Login using new email
        var ok = await client.PostAsJsonAsync("/api/v1/authenticate/login", new { Identifier = newEmail, Password = password });
        ok.StatusCode.Should().Be(HttpStatusCode.OK);
    }
}
