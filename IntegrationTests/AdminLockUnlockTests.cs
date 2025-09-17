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

namespace IntegrationTests;

public class AdminLockUnlockTests : IClassFixture<TestApplicationFactory>
{
    private readonly TestApplicationFactory _factory;
    public AdminLockUnlockTests(TestApplicationFactory factory) { _factory = factory; }

    private static string NewEmail() => $"user_{Guid.NewGuid():N}@example.com";
    private static string NewUser() => $"user_{Guid.NewGuid():N}";

    private Task<string> EnsureAdminAsync() => AdminTokenFactory.CreateAdminAsync(_factory);

    [Fact]
    public async Task Admin_Locks_And_Unlocks_User()
    {
        var adminToken = await EnsureAdminAsync();
        var adminClient = _factory.CreateClient();
        adminClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", adminToken);

        // Create target user
        var email = NewEmail();
        var userName = NewUser();
        var password = "User$tr0ngP@ss!";
        (await adminClient.PostAsJsonAsync("/api/v1/authenticate/register", new RegisterModel { Email = email, Username = userName, Password = password, TermsAccepted = true })).EnsureSuccessStatusCode();
        using (var scope = _factory.Services.CreateScope())
        {
            var userMgr = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
            var user = await userMgr.FindByEmailAsync(email);
            var token = await userMgr.GenerateEmailConfirmationTokenAsync(user!);
            (await adminClient.PostAsJsonAsync("/api/v1/authenticate/confirm-email", new { email, token })).EnsureSuccessStatusCode();
        }
        string userId;
        using (var scope = _factory.Services.CreateScope())
        {
            var userMgr = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
            var user = await userMgr.FindByEmailAsync(email);
            userId = user!.Id;
        }

        // Lock
        (await adminClient.PostAsync($"/api/v1/admin/users/{userId}/lock", null)).EnsureSuccessStatusCode();
        var loginLocked = await adminClient.PostAsJsonAsync("/api/v1/authenticate/login", new { Identifier = userName, Password = password });
        loginLocked.StatusCode.Should().BeOneOf(HttpStatusCode.BadRequest, HttpStatusCode.Unauthorized, HttpStatusCode.Forbidden);

        // Unlock
        (await adminClient.PostAsync($"/api/v1/admin/users/{userId}/unlock", null)).EnsureSuccessStatusCode();
        var loginAfter = await adminClient.PostAsJsonAsync("/api/v1/authenticate/login", new { Identifier = userName, Password = password });
        loginAfter.StatusCode.Should().Be(HttpStatusCode.OK);
    }
}
