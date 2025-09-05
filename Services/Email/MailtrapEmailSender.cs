using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;

namespace AuthenticationAPI.Services.Email;

public sealed class MailtrapEmailSender : IEmailSender
{
    private readonly IHttpClientFactory _httpFactory;
    private readonly string _apiToken;
    private readonly string _fromEmail;
    private readonly string _fromName;
    private const string Endpoint = "https://send.api.mailtrap.io/api/send";

    public MailtrapEmailSender(IHttpClientFactory httpFactory, string apiToken, string fromEmail, string fromName)
    {
        _httpFactory = httpFactory;
        _apiToken = apiToken;
        _fromEmail = fromEmail;
        _fromName = fromName;
    }

    public async Task SendAsync(string to, string subject, string body, CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(_apiToken))
        {
            // Fallback to console logging if token missing
            Console.WriteLine($"[EMAIL-FAKE] To={to} Subject={subject}\n{body}");
            return;
        }

        var client = _httpFactory.CreateClient("mailtrap");
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", _apiToken);

        var payload = new
        {
            from = new { email = _fromEmail, name = _fromName },
            to = new[] { new { email = to } },
            subject,
            text = body
        };
        var json = JsonSerializer.Serialize(payload);
        using var content = new StringContent(json, Encoding.UTF8, "application/json");
        using var resp = await client.PostAsync(Endpoint, content, ct);
        if (!resp.IsSuccessStatusCode)
        {
            var respText = await resp.Content.ReadAsStringAsync(ct);
            Console.WriteLine($"[EMAIL-ERR] Mailtrap send failed: {(int)resp.StatusCode} {resp.ReasonPhrase} => {respText}");
        }
    }
}
