using System;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using System.Threading.Tasks;
using AuthenticationAPI.Models;
using FluentAssertions;
using Xunit;

namespace AuthenticationAPI.IntegrationTests;

public class LogoutAllTests : IClassFixture<TestApplicationFactory>
{
    private readonly TestApplicationFactory _factory;
    public LogoutAllTests(TestApplicationFactory factory) { _factory = factory; }

    private static string NewEmail() => $"user_{Guid.NewGuid():N}@example.com";
    private static string NewUser() => $"user_{Guid.NewGuid():N}";

    [Fact]
    public async Task LogoutAll_Revokes_Sessions_And_Invalidates_Tokens()
    {
        var client = _factory.CreateClient();
        var email = NewEmail();
        var username = NewUser();
        var password = "V3ry$tr0ngP@ssw0rd!";
        (await client.PostAsJsonAsync("/api/v1/authenticate/register", new RegisterModel { Email = email, Username = username, Password = password, TermsAccepted = true })).EnsureSuccessStatusCode();
        await TestTokenHelpers.ConfirmEmailAsync(_factory, email);

        var login = await client.PostAsJsonAsync("/api/v1/authenticate/login", new { Identifier = username, Password = password });
        login.StatusCode.Should().Be(HttpStatusCode.OK);
        var body = await login.Content.ReadAsStringAsync();
        using var doc = JsonDocument.Parse(body);
        var token = doc.RootElement.GetProperty("token").GetString()!;
        var refresh = doc.RootElement.GetProperty("refreshToken").GetString()!;

        var authed = _factory.CreateClient();
        authed.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
        var logoutAll = await authed.PostAsync("/api/v1/authenticate/logout-all", content: null);
        logoutAll.StatusCode.Should().Be(HttpStatusCode.OK);

        // Old access token is now invalid
        var me = await authed.GetAsync("/api/v1/users/me");
        me.StatusCode.Should().Be(HttpStatusCode.Unauthorized);

        // Refresh token should also be unusable
        var r = await client.PostAsJsonAsync("/api/v1/authenticate/refresh", new { refreshToken = refresh });
        r.StatusCode.Should().BeOneOf(HttpStatusCode.BadRequest, HttpStatusCode.Unauthorized);
    }
}
