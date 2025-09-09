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
            throw new InvalidOperationException("SendGrid API key is not configured.");
        if (string.IsNullOrWhiteSpace(_fromEmail))
            throw new InvalidOperationException("SendGrid From address is not configured.");

        var client = _httpFactory.CreateClient("sendgrid");
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", _apiKey);

        var looksHtml = !string.IsNullOrWhiteSpace(body) && (body.TrimStart().StartsWith("<html", StringComparison.OrdinalIgnoreCase) || body.TrimStart().StartsWith("<!doctype html", StringComparison.OrdinalIgnoreCase));
        string text = looksHtml ? StripTags(body) : body;
        string html = looksHtml ? body : $"<pre>{HtmlEncoder.Default.Encode(body)}</pre>";
        var payload = new
        {
            from = new { email = _fromEmail, name = _fromName },
            personalizations = new[]
            {
                new { to = new[] { new { email = to } }, subject }
            },
            content = new[]
            {
                new { type = "text/plain", value = text },
                new { type = "text/html", value = html }
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

    private static string StripTags(string html)
    {
        var sb = new StringBuilder(html.Length);
        bool inside = false;
        foreach (var ch in html)
        {
            if (ch == '<') { inside = true; continue; }
            if (ch == '>') { inside = false; continue; }
            if (!inside) sb.Append(ch);
        }
        return System.Net.WebUtility.HtmlDecode(sb.ToString());
    }
}
