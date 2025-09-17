using System;
using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using System.Threading.Tasks;
using AuthenticationAPI.Models;
using FluentAssertions;
using Xunit;
using Microsoft.Extensions.DependencyInjection;

namespace AuthenticationAPI.IntegrationTests;

public class UserCrudTests : IClassFixture<TestApplicationFactory>
{
    private readonly TestApplicationFactory _factory;
    public UserCrudTests(TestApplicationFactory factory) { _factory = factory; }

    private static string NewEmail() => $"user_{Guid.NewGuid():N}@example.com";
    private static string NewUser() => $"user_{Guid.NewGuid():N}";

    [Fact]
    public async Task User_Can_Register_Confirm_Get_Profile()
    {
        var client = _factory.CreateClient();
        var email = NewEmail();
        var username = NewUser();
        var password = "Sup3r$tr0ngP@ss!";
        (await client.PostAsJsonAsync("/api/v1/authenticate/register", new RegisterModel { Email = email, Username = username, Password = password, TermsAccepted = true })).EnsureSuccessStatusCode();
        // confirm email
        string token;
        using (var scope = _factory.Services.CreateScope())
        {
            var userMgr = scope.ServiceProvider.GetRequiredService<Microsoft.AspNetCore.Identity.UserManager<AuthenticationAPI.Models.ApplicationUser>>();
            var user = await userMgr.FindByEmailAsync(email);
            token = await userMgr.GenerateEmailConfirmationTokenAsync(user!);
        }
        (await client.PostAsJsonAsync("/api/v1/authenticate/confirm-email", new { email, token })).EnsureSuccessStatusCode();
        // login
        var login = await client.PostAsJsonAsync("/api/v1/authenticate/login", new { Identifier = username, Password = password });
        login.StatusCode.Should().Be(HttpStatusCode.OK);
        var json = await login.Content.ReadAsStringAsync();
        using var doc = JsonDocument.Parse(json);
        var tokenStr = doc.RootElement.GetProperty("token").GetString();
        tokenStr.Should().NotBeNullOrEmpty();
    }
}
