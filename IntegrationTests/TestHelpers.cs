using System.Net.Http;
using System.Net.Http.Json;
using System.Text.Json;
using System.Threading.Tasks;
using AuthenticationAPI.Models;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.AspNetCore.Identity;

namespace IntegrationTests;

public static class TestHelpers
{
    public static async Task<(string token, string refresh)> RegisterConfirmAndLoginAsync(TestApplicationFactory factory, HttpClient client, string email, string username, string password)
    {
        var reg = new { Email = email, Username = username, Password = password, TermsAccepted = true };
        (await client.PostAsJsonAsync("/api/v1/authenticate/register", reg)).EnsureSuccessStatusCode();
        // Generate confirmation token directly
        using (var scope = factory.Services.CreateScope())
        {
            var userMgr = scope.ServiceProvider.GetRequiredService<UserManager<AuthenticationAPI.Models.ApplicationUser>>();
            var user = await userMgr.FindByEmailAsync(email);
            var token = await userMgr.GenerateEmailConfirmationTokenAsync(user!);
            (await client.PostAsJsonAsync("/api/v1/authenticate/confirm-email", new { email, token })).EnsureSuccessStatusCode();
        }
        // Login
        return await LoginAsync(client, username, password);
    }

    public static async Task<(string token, string refresh)> LoginAsync(HttpClient client, string identifier, string password)
    {
        var req = new LoginModel { Identifier = identifier, Password = password };
        var resp = await client.PostAsJsonAsync("/api/v1/authenticate/login", req);
        resp.EnsureSuccessStatusCode();
        var json = await resp.Content.ReadAsStringAsync();
        using var doc = JsonDocument.Parse(json);
        var token = doc.RootElement.GetProperty("token").GetString()!;
        var refresh = doc.RootElement.GetProperty("refreshToken").GetString()!;
        return (token, refresh);
    }
}
