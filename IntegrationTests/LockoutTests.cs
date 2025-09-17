using System;
using System.Net;
using System.Net.Http.Json;
using System.Threading.Tasks;
using AuthenticationAPI.Models;
using FluentAssertions;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace IntegrationTests;

public class LockoutTests : IClassFixture<TestApplicationFactory>
{
    private readonly TestApplicationFactory _factory;
    public LockoutTests(TestApplicationFactory factory) { _factory = factory; }

    private static string NewEmail() => $"user_{Guid.NewGuid():N}@example.com";
    private static string NewUser() => $"user_{Guid.NewGuid():N}";

    [Fact]
    public async Task Multiple_Failed_Logins_Trigger_Lockout_Then_Unlock()
    {
        var client = _factory.CreateClient();
        var email = NewEmail();
        var username = NewUser();
        var password = "V3ry$tr0ngP@ssw0rd!";
        (await client.PostAsJsonAsync("/api/v1/authenticate/register", new RegisterModel { Email = email, Username = username, Password = password, TermsAccepted = true })).EnsureSuccessStatusCode();
        await TestTokenHelpers.ConfirmEmailAsync(_factory, email);

        // Make repeated bad attempts (more than MaxFailedAccessAttempts=10)
        for (int i = 0; i < 11; i++)
        {
            var bad = await client.PostAsJsonAsync("/api/v1/authenticate/login", new { Identifier = username, Password = password + "X" });
            bad.StatusCode.Should().BeOneOf(HttpStatusCode.BadRequest, HttpStatusCode.Unauthorized);
        }

        // Good attempt now should produce lockout response (mapped to 423 or 400/401 by middleware). We'll accept 400-423
        var locked = await client.PostAsJsonAsync("/api/v1/authenticate/login", new { Identifier = username, Password = password });
        ((int)locked.StatusCode).Should().BeGreaterOrEqualTo(400);

        // Manually unlock via UserManager to complete flow
        using (var scope = _factory.Services.CreateScope())
        {
            var userMgr = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
            var user = await userMgr.FindByEmailAsync(email);
            user!.LockoutEnd = null;
            await userMgr.UpdateAsync(user);
        }

        // Login should succeed again
        var good = await client.PostAsJsonAsync("/api/v1/authenticate/login", new { Identifier = username, Password = password });
        good.StatusCode.Should().Be(HttpStatusCode.OK);
    }
}
