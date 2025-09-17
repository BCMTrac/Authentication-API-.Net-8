using System;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using System.Threading.Tasks;
using AuthenticationAPI.Models;
using FluentAssertions;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.AspNetCore.Identity;
using Xunit;

namespace IntegrationTests;

public class RefreshReuseTests : IClassFixture<TestApplicationFactory>
{
    private readonly TestApplicationFactory _factory;
    public RefreshReuseTests(TestApplicationFactory factory) { _factory = factory; }

    private static string NewEmail() => $"user_{Guid.NewGuid():N}@example.com";
    private static string NewUser() => $"user_{Guid.NewGuid():N}";

    [Fact]
    public async Task Reusing_Rotated_Refresh_Revokes_All_And_Bumps_TokenVersion()
    {
        var client = _factory.CreateClient();
        var email = NewEmail();
        var username = NewUser();
        var password = "V3ry$tr0ngP@ssw0rd!";
        (await client.PostAsJsonAsync("/api/v1/authenticate/register", new RegisterModel { Email = email, Username = username, Password = password, TermsAccepted = true })).EnsureSuccessStatusCode();
        await TestTokenHelpers.ConfirmEmailAsync(_factory, email);

        // Login baseline
        var login = await client.PostAsJsonAsync("/api/v1/authenticate/login", new { Identifier = username, Password = password });
        login.StatusCode.Should().Be(HttpStatusCode.OK);
        var body = await login.Content.ReadAsStringAsync();
        using var doc = JsonDocument.Parse(body);
        var token = doc.RootElement.GetProperty("token").GetString()!;
        var refresh1 = doc.RootElement.GetProperty("refreshToken").GetString()!;

        // Rotate refresh
        var r1 = await client.PostAsJsonAsync("/api/v1/authenticate/refresh", new { refreshToken = refresh1 });
        r1.StatusCode.Should().Be(HttpStatusCode.OK);
        var j1 = await r1.Content.ReadAsStringAsync();
        using var d1 = JsonDocument.Parse(j1);
        var refresh2 = d1.RootElement.GetProperty("refreshToken").GetString()!;

        // Reuse the old refresh1 (should trigger reuse path and bump token version)
        var reuse = await client.PostAsJsonAsync("/api/v1/authenticate/refresh", new { refreshToken = refresh1 });
        reuse.StatusCode.Should().BeOneOf(HttpStatusCode.BadRequest, HttpStatusCode.Unauthorized);

        // The original access token should now be invalid due to token_version bump
        var authed = _factory.CreateClient();
        authed.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
        var me = await authed.GetAsync("/api/v1/users/me");
        me.StatusCode.Should().Be(HttpStatusCode.Unauthorized);

        // Further attempting refresh2 should also be invalid after global revoke
        var r2 = await client.PostAsJsonAsync("/api/v1/authenticate/refresh", new { refreshToken = refresh2 });
        r2.StatusCode.Should().BeOneOf(HttpStatusCode.BadRequest, HttpStatusCode.Unauthorized);
    }
}
