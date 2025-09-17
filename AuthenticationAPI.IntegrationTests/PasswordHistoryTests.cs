using System;
using System.Net;
using System.Net.Http.Json;
using System.Threading.Tasks;
using AuthenticationAPI.Models;
using FluentAssertions;
using Xunit;
using Microsoft.Extensions.DependencyInjection;

namespace AuthenticationAPI.IntegrationTests;

public class PasswordHistoryTests : IClassFixture<TestApplicationFactory>
{
    private readonly TestApplicationFactory _factory;
    public PasswordHistoryTests(TestApplicationFactory factory) { _factory = factory; }
    private static string NewEmail() => $"ph_{Guid.NewGuid():N}@example.com";
    private static string NewUser() => $"ph_{Guid.NewGuid():N}";

    [Fact]
    public async Task Password_Reset_Prevents_Reuse()
    {
        var client = _factory.CreateClient();
        var email = NewEmail();
        var username = NewUser();
        var password = "Sup3r$tr0ngP@ss!";
        (await client.PostAsJsonAsync("/api/v1/authenticate/register", new RegisterModel { Email = email, Username = username, Password = password, TermsAccepted = true })).EnsureSuccessStatusCode();
        string token;
        using (var scope = _factory.Services.CreateScope())
        {
            var userMgr = scope.ServiceProvider.GetRequiredService<Microsoft.AspNetCore.Identity.UserManager<AuthenticationAPI.Models.ApplicationUser>>();
            var user = await userMgr.FindByEmailAsync(email);
            token = await userMgr.GenerateEmailConfirmationTokenAsync(user!);
        }
        (await client.PostAsJsonAsync("/api/v1/authenticate/confirm-email", new { email, token })).EnsureSuccessStatusCode();
        // Request password reset
        (await client.PostAsJsonAsync("/api/v1/authenticate/request-password-reset", new { Email = email })).EnsureSuccessStatusCode();
        string resetToken;
        using (var scope = _factory.Services.CreateScope())
        {
            var userMgr = scope.ServiceProvider.GetRequiredService<Microsoft.AspNetCore.Identity.UserManager<AuthenticationAPI.Models.ApplicationUser>>();
            var user = await userMgr.FindByEmailAsync(email);
            resetToken = await userMgr.GeneratePasswordResetTokenAsync(user!);
        }
        var newPassword = "Sup3r$tr0ngP@ss!_NEW1";
        (await client.PostAsJsonAsync("/api/v1/authenticate/confirm-password-reset", new { Email = email, Token = resetToken, NewPassword = newPassword })).EnsureSuccessStatusCode();
        // Attempt reuse of original password
        using (var scope = _factory.Services.CreateScope())
        {
            var userMgr = scope.ServiceProvider.GetRequiredService<Microsoft.AspNetCore.Identity.UserManager<AuthenticationAPI.Models.ApplicationUser>>();
            var user = await userMgr.FindByEmailAsync(email);
            var reuseToken = await userMgr.GeneratePasswordResetTokenAsync(user!);
            var reuseResp = await client.PostAsJsonAsync("/api/v1/authenticate/confirm-password-reset", new { Email = email, Token = reuseToken, NewPassword = password });
            reuseResp.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        }
    }
}
