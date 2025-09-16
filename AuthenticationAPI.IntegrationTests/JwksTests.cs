using System;
using System.Linq;
using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using System.Threading.Tasks;
using AuthenticationAPI.Models;
using FluentAssertions;
using Xunit;
using Microsoft.Extensions.DependencyInjection;

namespace AuthenticationAPI.IntegrationTests;

public class JwksTests : IClassFixture<TestApplicationFactory>
{
    private readonly TestApplicationFactory _factory;
    public JwksTests(TestApplicationFactory factory) { _factory = factory; }

    private static string NewEmail() => $"user_{Guid.NewGuid():N}@example.com";
    private static string NewUser() => $"user_{Guid.NewGuid():N}";

    [Fact]
    public async Task Jwks_Lists_Active_RSA_Keys_And_Kid_Matches_Token()
    {
        var client = _factory.CreateClient();
        var email = NewEmail();
        var username = NewUser();
        var password = "V3ry$tr0ngP@ssw0rd!";

        (await client.PostAsJsonAsync("/api/v1/authenticate/register", new RegisterModel { Email = email, Username = username, Password = password, TermsAccepted = true })).EnsureSuccessStatusCode();
        // Confirm email
        var token = await TestTokenHelpers.ConfirmEmailAsync(_factory, email);

        var login = await client.PostAsJsonAsync("/api/v1/authenticate/login", new { Identifier = username, Password = password });
        login.StatusCode.Should().Be(HttpStatusCode.OK);
        var body = await login.Content.ReadAsStringAsync();
        using var doc = JsonDocument.Parse(body);
        var jwt = doc.RootElement.GetProperty("token").GetString()!;
        var header = JwtTestHelper.ReadHeader(jwt);
        var kid = header.GetProperty("kid").GetString();

        var jwksResp = await client.GetAsync("/.well-known/jwks.json");
        jwksResp.StatusCode.Should().Be(HttpStatusCode.OK);
        var jwksJson = await jwksResp.Content.ReadAsStringAsync();
        using var jwksDoc = JsonDocument.Parse(jwksJson);
        var keys = jwksDoc.RootElement.GetProperty("keys");
        keys.GetArrayLength().Should().BeGreaterThan(0);
        var hasKid = keys.EnumerateArray().Any(k => k.TryGetProperty("kid", out var kide) && kide.GetString() == kid);
        hasKid.Should().BeTrue();
    }
}

internal static class TestTokenHelpers
{
    public static async Task<string> ConfirmEmailAsync(TestApplicationFactory factory, string email)
    {
        using var scope = factory.Services.CreateScope();
        var userMgr = scope.ServiceProvider.GetRequiredService<Microsoft.AspNetCore.Identity.UserManager<AuthenticationAPI.Models.ApplicationUser>>();
        var client = factory.CreateClient();
        var user = await userMgr.FindByEmailAsync(email);
        var token = await userMgr.GenerateEmailConfirmationTokenAsync(user!);
        (await client.PostAsJsonAsync("/api/v1/authenticate/confirm-email", new { email, token })).EnsureSuccessStatusCode();
        return token;
    }
}
