using System;
using System.Linq;
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

public class AdminRoleManagementTests : IClassFixture<TestApplicationFactory>
{
    private readonly TestApplicationFactory _factory;
    public AdminRoleManagementTests(TestApplicationFactory factory) { _factory = factory; }

    private static string NewEmail() => $"user_{Guid.NewGuid():N}@example.com";
    private static string NewUser() => $"user_{Guid.NewGuid():N}";

    private async Task<string> EnsureAdminAsync()
    {
        var client = _factory.CreateClient();
        var email = NewEmail();
        var username = NewUser();
        var password = "Adm1n$tr0ngP@ss!";
        (await client.PostAsJsonAsync("/api/v1/authenticate/register", new RegisterModel { Email = email, Username = username, Password = password, TermsAccepted = true })).EnsureSuccessStatusCode();
        using (var scope = _factory.Services.CreateScope())
        {
            var userMgr = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
            var roleMgr = scope.ServiceProvider.GetRequiredService<RoleManager<IdentityRole>>();
            if (!await roleMgr.RoleExistsAsync("Admin")) await roleMgr.CreateAsync(new IdentityRole("Admin"));
            var user = await userMgr.FindByEmailAsync(email);
            var token = await userMgr.GenerateEmailConfirmationTokenAsync(user!);
            (await client.PostAsJsonAsync("/api/v1/authenticate/confirm-email", new { email, token })).EnsureSuccessStatusCode();
            (await userMgr.AddToRoleAsync(user!, "Admin")).Succeeded.Should().BeTrue();
        }
        var login = await client.PostAsJsonAsync("/api/v1/authenticate/login", new { Identifier = username, Password = password });
        login.StatusCode.Should().Be(HttpStatusCode.OK);
        var json = await login.Content.ReadAsStringAsync();
        using var doc = JsonDocument.Parse(json);
        return doc.RootElement.GetProperty("token").GetString()!;
    }

    [Fact]
    public async Task Admin_Adds_And_Removes_Role()
    {
        var token = await EnsureAdminAsync();
        var adminClient = _factory.CreateClient();
        adminClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);

        // Create target user
        var targetEmail = NewEmail();
        var targetUser = NewUser();
        var password = "User$tr0ngP@ss!";
        (await adminClient.PostAsJsonAsync("/api/v1/authenticate/register", new RegisterModel { Email = targetEmail, Username = targetUser, Password = password, TermsAccepted = true })).EnsureSuccessStatusCode();
        using (var scope = _factory.Services.CreateScope())
        {
            var userMgr = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
            var user = await userMgr.FindByEmailAsync(targetEmail);
            var tokenC = await userMgr.GenerateEmailConfirmationTokenAsync(user!);
            (await adminClient.PostAsJsonAsync("/api/v1/authenticate/confirm-email", new { email = targetEmail, token = tokenC })).EnsureSuccessStatusCode();
        }

        string targetId;
        // Search user
        var search = await adminClient.GetAsync($"/api/v1/admin/users/search?q={targetUser}");
        search.StatusCode.Should().Be(HttpStatusCode.OK);
        var searchJson = await search.Content.ReadAsStringAsync();
        using (var searchDoc = JsonDocument.Parse(searchJson))
        {
            var arr = searchDoc.RootElement;
            arr.GetArrayLength().Should().BeGreaterOrEqualTo(1);
            targetId = arr.EnumerateArray().First().GetProperty("id").GetString()!;
        }

        // Add role
        (await adminClient.PostAsJsonAsync($"/api/v1/admin/users/{targetId}/roles/add", new { role = "Manager" })).EnsureSuccessStatusCode();
        // Remove role
        (await adminClient.PostAsJsonAsync($"/api/v1/admin/users/{targetId}/roles/remove", new { role = "Manager" })).EnsureSuccessStatusCode();

        // Get user details
        var detail = await adminClient.GetAsync($"/api/v1/admin/users/{targetId}");
        detail.StatusCode.Should().Be(HttpStatusCode.OK);
    }
}
