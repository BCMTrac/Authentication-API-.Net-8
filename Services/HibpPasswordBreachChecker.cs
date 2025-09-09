using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;

namespace AuthenticationAPI.Services;

public sealed class HibpPasswordBreachChecker : IPasswordBreachChecker
{
    private readonly IHttpClientFactory _httpFactory;
    private const string Endpoint = "https://api.pwnedpasswords.com/range/";
    public HibpPasswordBreachChecker(IHttpClientFactory httpFactory) { _httpFactory = httpFactory; }

    public async Task<bool> IsCompromisedAsync(string password, CancellationToken ct = default)
    {
        if (string.IsNullOrEmpty(password)) return false;
        // SHA1 hash upper-case hex
        using var sha1 = SHA1.Create();
        var hash = sha1.ComputeHash(Encoding.UTF8.GetBytes(password));
        var hex = string.Concat(hash.Select(b => b.ToString("X2")));
        var prefix = hex.Substring(0, 5);
        var suffix = hex.Substring(5);
        var client = _httpFactory.CreateClient("hibp");
        client.DefaultRequestHeaders.UserAgent.Add(new ProductInfoHeaderValue("AuthAPI", "1.0"));
        using var resp = await client.GetAsync(Endpoint + prefix, ct);
        if (!resp.IsSuccessStatusCode) return false; // fail-open by default
        var body = await resp.Content.ReadAsStringAsync(ct);
        foreach (var line in body.Split('\n'))
        {
            var parts = line.Trim().Split(':');
            if (parts.Length >= 2 && parts[0].Equals(suffix, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }
        return false;
    }
}

