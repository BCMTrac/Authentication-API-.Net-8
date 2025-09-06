using System.Net.Http.Headers;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;

namespace AuthenticationAPI.Services.Email;

/// <summary>
/// Minimal SendGrid sender using REST API (no SDK dependency).
/// Requires: ApiKey, From, FromName.
/// </summary>
public sealed class SendGridEmailSender : IEmailSender
{
    private readonly IHttpClientFactory _httpFactory;
    private readonly string _apiKey;
    private readonly string _fromEmail;
    private readonly string _fromName;
    private const string Endpoint = "https://api.sendgrid.com/v3/mail/send";

    public SendGridEmailSender(IHttpClientFactory httpFactory, string apiKey, string fromEmail, string fromName)
    {
        _httpFactory = httpFactory;
        _apiKey = apiKey;
        _fromEmail = fromEmail;
        _fromName = string.IsNullOrWhiteSpace(fromName) ? fromEmail : fromName;
    }

    public async Task SendAsync(string to, string subject, string body, CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(_apiKey))
        {
            // Fallback for local dev if no key is set
            Console.WriteLine($"[EMAIL-FAKE] To={to} Subject={subject}\n{body}");
            return;
        }

        var client = _httpFactory.CreateClient("sendgrid");
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", _apiKey);

        // Send both text and HTML; HTML is an encoded pre block
        var payload = new
        {
            from = new { email = _fromEmail, name = _fromName },
            personalizations = new[]
            {
                new { to = new[] { new { email = to } }, subject }
            },
            content = new[]
            {
                new { type = "text/plain", value = body },
                new { type = "text/html", value = $"<pre>{HtmlEncoder.Default.Encode(body)}</pre>" }
            }
        };

        var json = JsonSerializer.Serialize(payload);
        using var content = new StringContent(json, Encoding.UTF8, "application/json");
        using var resp = await client.PostAsync(Endpoint, content, ct);
        if (!resp.IsSuccessStatusCode)
        {
            var respText = await resp.Content.ReadAsStringAsync(ct);
            Console.WriteLine($"[EMAIL-ERR] SendGrid send failed: {(int)resp.StatusCode} {resp.ReasonPhrase} => {respText}");
            throw new HttpRequestException($"SendGrid send failed with status {(int)resp.StatusCode}: {resp.ReasonPhrase}");
        }
    }
}
