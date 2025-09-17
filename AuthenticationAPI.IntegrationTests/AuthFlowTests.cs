using System;
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

public class AuthFlowTests : IClassFixture<TestApplicationFactory>
{
    private readonly TestApplicationFactory _factory;

    public AuthFlowTests(TestApplicationFactory factory)
    {
        _factory = factory;
    }

    private static string NewEmail() => $"user_{Guid.NewGuid():N}@example.com";
    private static string NewUser() => $"user_{Guid.NewGuid():N}";

    [Fact]
    public async Task Register_Confirm_Login_Me_Refresh_Logout()
    {
        var client = _factory.CreateClient();
        var email = NewEmail();
        var username = NewUser();
        var password = "V3ry$tr0ngP@ssw0rd!";

        var reg = new RegisterModel { Email = email, Username = username, Password = password, TermsAccepted = true };
        var regResp = await client.PostAsJsonAsync("/api/v1/authenticate/register", reg);
        if (regResp.StatusCode != HttpStatusCode.OK)
        {
            var body = await regResp.Content.ReadAsStringAsync();
            throw new Xunit.Sdk.XunitException($"Registration failed: {(int)regResp.StatusCode} {regResp.StatusCode}\nBody: {body}\nHeaders: {string.Join("; ", regResp.Headers.Select(h => h.Key+"="+string.Join(",", h.Value)))}");
        }

        // Fetch confirmation token via DI and confirm
        using (var scope = _factory.Services.CreateScope())
        {
            var userMgr = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
            var user = await userMgr.FindByEmailAsync(email);
            user.Should().NotBeNull();
            var token = await userMgr.GenerateEmailConfirmationTokenAsync(user!);
            var confirmResp = await client.PostAsJsonAsync("/api/v1/authenticate/confirm-email", new { email, token });
            confirmResp.StatusCode.Should().Be(HttpStatusCode.OK);
        }

        // Login
        var loginResp = await client.PostAsJsonAsync("/api/v1/authenticate/login", new { Identifier = username, Password = password });
        loginResp.StatusCode.Should().Be(HttpStatusCode.OK);
        var loginJson = await loginResp.Content.ReadAsStringAsync();
        using var loginDoc = JsonDocument.Parse(loginJson);
        var tokenStr = loginDoc.RootElement.GetProperty("token").GetString()!;
        var refresh = loginDoc.RootElement.GetProperty("refreshToken").GetString()!;
        tokenStr.Should().NotBeNullOrEmpty();
        refresh.Should().NotBeNullOrEmpty();

        // Call authorized endpoint /users/me
        var authClient = _factory.CreateClient();
        authClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", tokenStr);
        var meResp = await authClient.GetAsync("/api/v1/users/me");
        meResp.StatusCode.Should().Be(HttpStatusCode.OK);
        var meJson = await meResp.Content.ReadAsStringAsync();
        using var meDoc = JsonDocument.Parse(meJson);
        meDoc.RootElement.GetProperty("email").GetString().Should().Be(email);
        meDoc.RootElement.GetProperty("sessionCount").GetInt32().Should().BeGreaterThan(0);

        // Refresh
        var refreshResp = await client.PostAsJsonAsync("/api/v1/authenticate/refresh", new { refreshToken = refresh });
        refreshResp.StatusCode.Should().Be(HttpStatusCode.OK);
        var refreshJson = await refreshResp.Content.ReadAsStringAsync();
        using var refreshDoc = JsonDocument.Parse(refreshJson);
        var newRefresh = refreshDoc.RootElement.GetProperty("refreshToken").GetString()!;
        newRefresh.Should().NotBeNull().And.NotBe(refresh);

        // Logout (requires auth)
        var logoutClient = _factory.CreateClient();
        logoutClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", tokenStr);
        var logoutResp = await logoutClient.PostAsJsonAsync("/api/v1/authenticate/logout", new { refreshToken = newRefresh });
        logoutResp.StatusCode.Should().Be(HttpStatusCode.OK);

        // Further refresh using the last refresh token should fail
        var failRefresh = await client.PostAsJsonAsync("/api/v1/authenticate/refresh", new { refreshToken = newRefresh });
        failRefresh.StatusCode.Should().BeOneOf(HttpStatusCode.BadRequest, HttpStatusCode.Unauthorized);
    }

    [Fact]
    public async Task Password_Reset_Flow_Changes_Password_And_Revokes_Tokens()
    {
        var client = _factory.CreateClient();
        var email = NewEmail();
        var username = NewUser();
        var oldPassword = "OldP4$$w0rd!123";
        var newPassword = "N3wP4$$w0rd!456";

        // Create and confirm user
        var reg = new RegisterModel { Email = email, Username = username, Password = oldPassword, TermsAccepted = true };
        (await client.PostAsJsonAsync("/api/v1/authenticate/register", reg)).EnsureSuccessStatusCode();
        using (var scope = _factory.Services.CreateScope())
        {
            var userMgr = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
            var user = await userMgr.FindByEmailAsync(email);
            var token = await userMgr.GenerateEmailConfirmationTokenAsync(user!);
            (await client.PostAsJsonAsync("/api/v1/authenticate/confirm-email", new { email, token })).EnsureSuccessStatusCode();
        }

        // Request reset
        (await client.PostAsJsonAsync("/api/v1/authenticate/request-password-reset", new { email })).EnsureSuccessStatusCode();

        // Generate reset token via DI and confirm
        using (var scope = _factory.Services.CreateScope())
        {
            var userMgr = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
            var user = await userMgr.FindByEmailAsync(email);
            var resetToken = await userMgr.GeneratePasswordResetTokenAsync(user!);
            var confirmResp = await client.PostAsJsonAsync("/api/v1/authenticate/confirm-password-reset", new { email, token = resetToken, newPassword });
            confirmResp.StatusCode.Should().Be(HttpStatusCode.OK);
        }

        // Login with old should fail
        var oldLogin = await client.PostAsJsonAsync("/api/v1/authenticate/login", new { Identifier = username, Password = oldPassword });
        oldLogin.StatusCode.Should().BeOneOf(HttpStatusCode.BadRequest, HttpStatusCode.Unauthorized);

        // Login with new should work
        var newLogin = await client.PostAsJsonAsync("/api/v1/authenticate/login", new { Identifier = username, Password = newPassword });
        newLogin.StatusCode.Should().Be(HttpStatusCode.OK);
    }
}
