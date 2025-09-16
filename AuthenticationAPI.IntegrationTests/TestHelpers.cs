using System.Net.Http;
using System.Net.Http.Json;
using System.Text.Json;
using System.Threading.Tasks;
using AuthenticationAPI.Models;

namespace AuthenticationAPI.IntegrationTests;

public static class TestHelpers
{
    public static async Task<(string token, string refresh)> RegisterConfirmAndLoginAsync(HttpClient client, string email, string username, string password)
    {
        var reg = new RegisterModel { Email = email, Username = username, Password = password, TermsAccepted = true };
        var regResp = await client.PostAsJsonAsync("/api/v1/authenticate/register", reg);
        regResp.EnsureSuccessStatusCode();

        // Request email confirm token
        var sentReq = new EmailRequestDto { Email = email };
        var sentResp = await client.PostAsJsonAsync("/api/v1/authenticate/request-email-confirm", sentReq);
        sentResp.EnsureSuccessStatusCode();

        // We can't capture token via email; instead call confirm directly by fetching from identity token generator via a test endpoint
        // For simplicity in this helper, expect tests to retrieve token via DI
        throw new NotImplementedException();
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
